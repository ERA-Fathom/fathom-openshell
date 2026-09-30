"""A fathom-openshell ocsf_stream.jsonl (the WatchSandbox record) as delivery ops.

load_stream(path) returns plain dicts, one per event, in stream order. They are the delivery record for the
join to the model traffic and are not sent to the hosted read.

  * NET:OPEN / NET:REFUSE / HTTP:<method> with a decision (ALLOWED, DENIED, OTHER)
                        -> {"op": "delivery", "event", "decision", "binary", "method", "host", "port", "path",
                            "endpoint" (host:port+path, never scheme), "policy", "engine", "reasons", "attrs", ...}
    A NET:REFUSE at DNS and the NET:OPEN DENIED at TCP for the same host collapse into one op carrying both
    reasons. Supervisor bookkeeping lines with no decision (NET:LISTEN, the supervisor's own connection to the
    gateway) are counted, not emitted.
  * middleware-stage lines (engine:middleware, engine:supervisor-middleware)
                        -> attributes on the matching HTTP delivery op (request_stage / response_stage:
                           failed, transformed, response_middleware_outcome, input_bytes, ...), not ops of their own
  * FINDING:CREATE of type openshell.middleware.*, or a stream status line that reads incomplete
                        -> {"op": "record_incomplete", "reasons": [...]} (one op, at the end), so the join refuses
                           a verdict on that run
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

HEAD = re.compile(r"^(?P<cls>NET|HTTP|FINDING|SSH|CONFIG|PROC|EVENT)(?::(?P<act>\S+))?\s+\[(?P<sev>[A-Z]+)\]\s*(?P<rest>.*)$")
BRACKETS = re.compile(r"\[([^\[\]]*)\]")
DECISION = re.compile(r"^(ALLOWED|DENIED|OTHER)\b\s*(.*)$")
NET_DST = re.compile(r"^(?:(?P<bin>\S+?)\((?P<pid>\d+)\)\s*->\s*)?(?P<host>[^\s:\[]+)(?::(?P<port>\d+))?")
HTTP_DST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<scheme>[a-z]+)://(?P<host>[^/:\s]+)(?::(?P<port>\d+))?(?P<path>/\S*)?")
FINDING_TITLE = re.compile(r'^"([^"]*)"')
MIDDLEWARE_ENGINES = ("middleware", "supervisor-middleware")


def _kv(block: str) -> Dict[str, str]:
    out = {}
    for tok in block.split():
        if ":" in tok:
            k, v = tok.split(":", 1)
            out[k] = v
    return out


def _brackets(rest: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for b in BRACKETS.findall(rest):
        kv.update(_kv(b))
    return kv


def parse_line(msg: str) -> Optional[Dict[str, Any]]:
    """One OCSF shorthand line as a dict, or None for a line that is not OCSF shorthand."""
    m = HEAD.match(msg or "")
    if not m:
        return None
    cls, act, sev, rest = m.group("cls"), m.group("act") or "", m.group("sev"), m.group("rest")
    ev: Dict[str, Any] = {"class": cls, "activity": act, "severity": sev, "event": f"{cls}:{act}" if act else cls}
    kv = _brackets(rest)
    head = BRACKETS.split(rest)[0] if "[" in rest else rest
    head = rest[: rest.find("[")].strip() if "[" in rest else rest.strip()
    ev["kv"] = kv
    if cls == "FINDING":
        t = FINDING_TITLE.match(head)
        ev["title"] = t.group(1) if t else head
        return ev
    d = DECISION.match(head)
    ev["decision"] = d.group(1) if d else None
    target = d.group(2) if d else head
    if cls == "NET":
        n = NET_DST.match(target)
        if n:
            ev.update(binary=n.group("bin"), pid=int(n.group("pid")) if n.group("pid") else None,
                      host=n.group("host"), port=int(n.group("port")) if n.group("port") else None)
    elif cls == "HTTP":
        h = HTTP_DST.match(target)
        if h:
            ev.update(method=h.group("method"), scheme=h.group("scheme"), host=h.group("host"),
                      port=int(h.group("port")) if h.group("port") else None, path=h.group("path") or "/")
    return ev


def _endpoint(ev: Dict[str, Any]) -> Optional[str]:
    if not ev.get("host"):
        return None
    return f"{ev['host']}:{ev.get('port') or ''}{ev.get('path') or ''}"


def load_stream(path: str) -> List[Dict[str, Any]]:
    ops: List[Dict[str, Any]] = []
    incomplete: List[str] = []
    counts = {"log_lines": 0, "ocsf_lines": 0, "bookkeeping": 0, "unparsed": 0}
    last_http: Dict[str, Dict[str, Any]] = {}          # endpoint -> latest HTTP delivery op
    refused: Dict[str, Dict[str, Any]] = {}            # host -> NET:REFUSE op awaiting its TCP denial
    status = None
    with open(path) as fh:
        for raw in fh:
            if not raw.strip():
                continue
            line = json.loads(raw)
            k = line.get("kind")
            if k == "stream_status":
                status = line
                continue
            if k == "warning":
                incomplete.append(f"stream_warning: {line.get('message')}")
                continue
            if k != "log":
                continue
            counts["log_lines"] += 1
            ev = parse_line(line.get("message", ""))
            if ev is None:
                continue
            counts["ocsf_lines"] += 1
            base = {"cursor": line.get("cursor"), "event_time_ns": line.get("event_time_ns"), "severity": ev["severity"]}
            if ev["class"] == "FINDING":
                t = ev["kv"].get("type", "")
                if t.startswith("openshell.middleware."):
                    incomplete.append(f"finding {t}: {ev.get('title')}")
                continue
            if ev["class"] not in ("NET", "HTTP"):
                continue
            engine = ev["kv"].get("engine")
            if ev["class"] == "HTTP" and engine in MIDDLEWARE_ENGINES:
                target = last_http.get(_endpoint(ev) or "")
                stage = "response_stage" if engine == "supervisor-middleware" else "request_stage"
                attrs = {k2: v for k2, v in ev["kv"].items() if k2 not in ("policy", "engine")}
                attrs["decision"] = ev.get("decision")
                if target is None:
                    counts["unparsed"] += 1
                    continue
                target["attrs"].setdefault(stage, []).append(attrs)
                if attrs.get("failed") == "true":
                    target["attrs"]["middleware_failed"] = True
                continue
            if ev.get("decision") is None:
                counts["bookkeeping"] += 1
                continue
            reasons = [ev["kv"]["reason"]] if ev["kv"].get("reason") else []
            op = {"op": "delivery", **base, "event": ev["event"], "decision": ev["decision"],
                  "binary": ev.get("binary"), "method": ev.get("method"), "host": ev.get("host"),
                  "port": ev.get("port"), "path": ev.get("path"), "endpoint": _endpoint(ev),
                  "policy": ev["kv"].get("policy"), "engine": engine, "reasons": reasons, "attrs": {}}
            if ev["event"] == "NET:REFUSE":
                refused[ev.get("host") or ""] = op
                ops.append(op)
                continue
            if ev["event"] == "NET:OPEN" and ev["decision"] == "DENIED" and (ev.get("host") or "") in refused:
                prior = refused.pop(ev["host"])
                prior.update(event="NET:REFUSE+NET:OPEN", binary=op["binary"] or prior["binary"], port=op["port"],
                             endpoint=op["endpoint"], reasons=prior["reasons"] + reasons)
                continue
            ops.append(op)
            if ev["class"] == "HTTP":
                last_http[op["endpoint"]] = op
    if status is None:
        incomplete.append("no_status_line")
    elif status.get("status") != "complete":
        incomplete.extend(f"stream: {r}" for r in status.get("reasons") or ["incomplete"])
    for i, op in enumerate(ops):
        op["step"] = i
    if incomplete:
        ops.append({"op": "record_incomplete", "step": len(ops), "reasons": incomplete})
    ops.append({"op": "stream_summary", "counts": counts,
                "status": (status or {}).get("status"), "sandbox_id": (status or {}).get("sandbox_id")})
    return ops
