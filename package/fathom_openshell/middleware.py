#!/usr/bin/env python3
"""fathom-capture: an OpenShell supervisor middleware that records model traffic and never alters it.

Implements SupervisorMiddleware (Describe, ValidateConfig, EvaluateHttpRequest) and
HttpResponsePreReturn.Evaluate. Every request is allowed unchanged and every response body unit
passes through unchanged. One JSON line per request and one per response go to
<capture-dir>/<sandbox_id>/http_capture.jsonl. Nothing here computes a verdict.

Response bodies: WHOLE_BODY_BYTES for ordinary responses, STREAM_BYTES for text/event-stream
(the SSE deltas are reassembled into one message before the line is written). When OpenShell
offers only HEADERS_ONLY (encoded, partial, no-transform, bodyless or over the cap), or the body
ends early, the line is a stub with a reason, never a silent gap.

    python -m fathom_openshell.middleware --port 50051 --capture-dir captures
"""
import argparse
import json
import os
import sys
import threading
import time
from concurrent import futures

import grpc

from fathom_openshell._proto import extension_pb2 as ext
from fathom_openshell._proto import supervisor_middleware_pb2 as mw
from fathom_openshell._proto import supervisor_middleware_pb2_grpc as mw_grpc

NAME = "fathom-capture"
VERSION = "0.1.0"
CONTRACT = "openshell.supervisor-middleware.contract"
MAX_PAYLOAD = 4 * 1024 * 1024

WHOLE = mw.HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES
STREAM = mw.HTTP_RESPONSE_BODY_MODE_STREAM_BYTES
HEADERS_ONLY = mw.HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY


def _now():
    t = time.time_ns()
    return {"ts_ns": t, "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t / 1e9)) + ".%06dZ" % (t // 1000 % 1_000_000)}


def _header(headers, name):
    for h in headers:
        if h.name == name:
            return h.value
    return None


def _body(raw):
    """(parsed JSON or None, raw text or None) for a body; bytes that are not UTF-8 go out as a length only."""
    if not raw:
        return None, None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, None
    try:
        return json.loads(text), None
    except ValueError:
        return None, text


def reassemble_sse(text):
    """One chat message from OpenAI-style SSE chunks: content concatenated, tool_calls merged by index."""
    events, msg, calls, finish, model, usage, bad = 0, {"role": "assistant", "content": ""}, {}, None, None, None, 0
    for line in text.splitlines():
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            continue
        events += 1
        try:
            c = json.loads(data)
        except ValueError:
            bad += 1
            continue
        model = c.get("model", model)
        usage = c.get("usage") or usage
        for ch in c.get("choices") or []:
            d = ch.get("delta") or {}
            if d.get("role"):
                msg["role"] = d["role"]
            if d.get("content"):
                msg["content"] += d["content"]
            for tc in d.get("tool_calls") or []:
                slot = calls.setdefault(tc.get("index", 0), {"id": None, "type": "function", "function": {"name": "", "arguments": ""}})
                if tc.get("id"):
                    slot["id"] = tc["id"]
                f = tc.get("function") or {}
                slot["function"]["name"] += f.get("name") or ""
                slot["function"]["arguments"] += f.get("arguments") or ""
            finish = ch.get("finish_reason") or finish
    if calls:
        msg["tool_calls"] = [calls[i] for i in sorted(calls)]
    if not msg["content"]:
        msg["content"] = None
    return {"message": msg, "finish_reason": finish, "model": model, "usage": usage,
            "sse_events": events, "sse_unparsed": bad}


class Capture:
    """Append-only JSONL writer, one file per sandbox, safe across gRPC worker threads."""

    def __init__(self, root):
        self.root = root
        self.lock = threading.Lock()

    def write(self, sandbox_id, rec):
        d = os.path.join(self.root, sandbox_id or "_no_sandbox_id")
        with self.lock:
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "http_capture.jsonl"), "a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")


def _context(ctx):
    p = ctx.originating_process
    return {"request_id": ctx.request_id, "sandbox_id": ctx.sandbox_id, "sandbox": ctx.sandbox,
            "originating_process": {"binary": p.binary, "pid": p.pid, "ancestors": list(p.ancestors)}}


def _target(t):
    return {"method": t.method, "host": t.host, "port": t.port, "path": t.path}


class Middleware(mw_grpc.SupervisorMiddlewareServicer, mw_grpc.HttpResponsePreReturnServicer):
    def __init__(self, capture, max_payload=MAX_PAYLOAD):
        self.capture = capture
        self.max_payload = max_payload

    def Describe(self, request, context):
        binding = lambda op, phase: mw.MiddlewareBinding(operation=op, phase=phase, max_payload_bytes=self.max_payload)
        return mw.MiddlewareManifest(
            name=NAME, service_version=VERSION,
            bindings=[binding(mw.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST, mw.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS),
                      binding(mw.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE, mw.SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN)],
            extension=ext.PeerMetadata(protocol_version=ext.ProtocolVersion(major=1, minor=0),
                                       implementation_name=NAME, implementation_version=VERSION,
                                       supported_capabilities=[CONTRACT], required_capabilities=[CONTRACT]))

    def ValidateConfig(self, request, context):
        return mw.ValidateConfigResponse(valid=True)

    def EvaluateHttpRequest(self, request, context):
        rec = {"kind": "request", **_now(), **_context(request.context), **_target(request.target)}
        raw = request.body
        declared = _header(request.headers, "content-length")
        if _header(request.headers, "content-encoding") not in (None, "identity"):
            rec.update(stub=True, stub_reason="compressed", body_bytes=len(raw))
        elif declared is not None and declared.isdigit() and int(declared) != len(raw):
            rec.update(stub=True, stub_reason="partial", body_bytes=len(raw), declared_bytes=int(declared))
        else:
            parsed, text = _body(raw)
            rec.update(stub=False, body_bytes=len(raw), body=parsed, body_raw=text)
        self.capture.write(request.context.sandbox_id, rec)
        return mw.HttpRequestResult(decision=mw.DECISION_ALLOW)

    def EvaluateWebSocketSession(self, request_iterator, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "fathom-capture binds no WebSocket operation")

    def Evaluate(self, request_iterator, context):
        """One response: preflight, then body units, then optional trailers and session_end."""
        state = None
        try:
            for ev in request_iterator:
                which = ev.WhichOneof("event")
                if which == "preflight":
                    state = self._preflight(ev.preflight)
                    if state["mode"] == HEADERS_ONLY:
                        yield mw.HttpResponseEventResult(preflight_result=mw.HttpResponsePreflightResult(skip=mw.HttpResponsePreflightSkip()))
                    else:
                        yield mw.HttpResponseEventResult(preflight_result=mw.HttpResponsePreflightResult(
                            inspect=mw.HttpResponsePreflightInspect(body_mode=state["mode"])))
                elif which == "body":
                    u = ev.body
                    state["chunks"].append(u.data)
                    state["units"] += 1
                    if u.end_of_stream:
                        state["ended"] = True
                        self._finish(state)
                    yield mw.HttpResponseEventResult(body_result=mw.HttpResponseBodyResult(
                        sequence=u.sequence, pass_through=mw.HttpResponseBodyPassThrough()))
                elif which == "trailers":
                    yield mw.HttpResponseEventResult(trailers_result=mw.HttpResponseTrailersResult())
                elif which == "session_end":
                    if state is not None:
                        state["end_reason"] = mw.MiddlewareSessionEndReason.Name(ev.session_end.reason)
        finally:
            if state is not None and not state["written"]:
                self._finish(state)

    def _preflight(self, pf):
        ctype = _header(pf.headers, "content-type") or ""
        permitted = set(pf.permitted_body_modes)
        streaming = ctype.startswith("text/event-stream")
        if streaming and STREAM in permitted:
            mode = STREAM
        elif WHOLE in permitted:
            mode = WHOLE
        else:
            mode = HEADERS_ONLY
        rec = {"kind": "response", **_now(), **_context(pf.context), **_target(pf.target),
               "status_code": pf.status_code, "content_type": ctype,
               "body_mode": mw.HttpResponseBodyMode.Name(mode),
               "permitted_body_modes": sorted(mw.HttpResponseBodyMode.Name(m) for m in permitted)}
        if mode == HEADERS_ONLY:
            enc, rng = _header(pf.headers, "content-encoding"), _header(pf.headers, "content-range")
            clen = _header(pf.headers, "content-length")
            if enc not in (None, "identity"):
                reason = "compressed"
            elif rng is not None or pf.status_code == 206:
                reason = "partial"
            elif clen is not None and clen.isdigit() and int(clen) > pf.max_payload_bytes:
                reason = "over_cap"
            elif clen == "0" or pf.status_code in (204, 304):
                reason = "bodyless"
            else:
                reason = "headers_only_offered"
            rec.update(stub=True, stub_reason=reason, declared_bytes=int(clen) if clen and clen.isdigit() else None)
        return {"rec": rec, "mode": mode, "streaming": streaming, "chunks": [], "units": 0,
                "ended": False, "written": False, "end_reason": None}

    def _finish(self, state):
        rec = state["rec"]
        state["written"] = True
        if state["mode"] != HEADERS_ONLY:
            raw = b"".join(state["chunks"])
            rec.update(body_bytes=len(raw), body_units=state["units"], ts_end_ns=time.time_ns())
            if not state["ended"]:
                rec.update(stub=True, stub_reason="partial", end_reason=state["end_reason"])
            elif state["streaming"]:
                text = raw.decode("utf-8", errors="replace")
                rec.update(stub=False, body=reassemble_sse(text), body_raw=text)
            else:
                parsed, text = _body(raw)
                rec.update(stub=False, body=parsed, body_raw=text)
        self.capture.write(rec.get("sandbox_id"), rec)


def serve(port, capture_dir, max_payload=MAX_PAYLOAD, host="0.0.0.0"):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16),
                         options=[("grpc.max_receive_message_length", max_payload + (1 << 20)),
                                  ("grpc.max_send_message_length", max_payload + (1 << 20))])
    m = Middleware(Capture(capture_dir), max_payload)
    mw_grpc.add_SupervisorMiddlewareServicer_to_server(m, server)
    mw_grpc.add_HttpResponsePreReturnServicer_to_server(m, server)
    bound = server.add_insecure_port(f"{host}:{port}")
    server.start()
    return server, bound


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--port", type=int, default=50051)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--capture-dir", required=True)
    ap.add_argument("--max-payload", type=int, default=MAX_PAYLOAD)
    a = ap.parse_args(argv)
    server, bound = serve(a.port, a.capture_dir, a.max_payload, a.host)
    print(f"{NAME} {VERSION} listening on {a.host}:{bound}, capture dir {os.path.abspath(a.capture_dir)}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    sys.exit(main())
