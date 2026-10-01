#!/usr/bin/env python3
"""Record one sandbox's OpenShell watch stream (the OCSF delivery record) with loss detection.

Opens WatchSandbox on the active gateway (the openshell SDK's connection and stubs), following
logs and platform events, keeps the highest cursor, and writes every SandboxLogLine with all its
fields to <capture-dir>/<sandbox>/ocsf_stream.jsonl. The last line is a status line: complete, or
incomplete with the reasons. Any SandboxStreamWarning or an OUT_OF_RANGE status makes the record
incomplete; so does an unrecovered disconnect. One resume after a disconnect uses the highest
cursor.

Starting before the sandbox exists: until the gateway knows the name, the watch is retried
(NOT_FOUND) every --poll seconds, for at most --wait-create seconds.

    python -m right_rudder_openshell.stream --sandbox my-sandbox --capture-dir captures --until-deleted
"""
import argparse
import json
import os
import signal
import sys
import threading
import time

import grpc
from google.protobuf.json_format import MessageToDict

STATUS_KIND = "stream_status"


def _ts(pb_ts):
    return pb_ts.seconds * 1_000_000_000 + pb_ts.nanos if pb_ts and (pb_ts.seconds or pb_ts.nanos) else None


class Recorder:
    def __init__(self, stub, pb, sandbox, workspace, out_path, *, poll=0.5, wait_create=120.0,
                 until_deleted=False, rpc_timeout=None):
        self.stub, self.pb = stub, pb
        self.sandbox, self.workspace = sandbox, workspace
        self.out_path = out_path
        self.poll, self.wait_create = poll, wait_create
        self.until_deleted = until_deleted
        self.rpc_timeout = rpc_timeout
        self.cursor = ""
        self.lines = 0
        self.events = 0
        self.warnings = []
        self.incomplete = []
        self.resumes = 0
        self.sandbox_id = None
        self.last_phase = None
        self.stop = threading.Event()
        self._call = None

    # -- output
    def _write(self, fh, rec):
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()

    def _request(self):
        from openshell._proto import datamodel_pb2
        return self.pb.WatchSandboxRequest(
            workspace_scope=datamodel_pb2.WorkspaceSelector(workspace=self.workspace),
            sandbox=self.sandbox, follow_status=True, follow_logs=True, follow_events=True,
            log_tail_lines=10_000 if not self.cursor else 0, event_tail=10_000 if not self.cursor else 0,
            resume_after_cursor=self.cursor)

    def _keep(self, cursor):
        if cursor and cursor > self.cursor:   # byte-wise comparison is the documented contract
            self.cursor = cursor

    def _consume(self, fh):
        """Run one watch call until the stream ends. Returns a grpc.StatusCode or None for a clean end."""
        self._call = self.stub.WatchSandbox(self._request(), timeout=self.rpc_timeout)
        try:
            for ev in self._call:
                which = ev.WhichOneof("payload")
                if which == "log":
                    lg = ev.log
                    self.sandbox_id = self.sandbox_id or lg.sandbox_id
                    self._write(fh, {"kind": "log", "cursor": ev.cursor, "sandbox_id": lg.sandbox_id,
                                     "event_time_ns": _ts(lg.event_time), "level": lg.level, "target": lg.target,
                                     "source": lg.source or "gateway", "message": lg.message, "fields": dict(lg.fields)})
                    self.lines += 1
                elif which == "event":
                    self._write(fh, {"kind": "platform_event", "cursor": ev.cursor,
                                     "event": MessageToDict(ev.event, preserving_proto_field_name=True)})
                    self.events += 1
                elif which == "warning":
                    self.warnings.append(ev.warning.message)
                    self._write(fh, {"kind": "warning", "message": ev.warning.message, "ts_ns": time.time_ns()})
                elif which == "sandbox":
                    sb = ev.sandbox
                    self.sandbox_id = self.sandbox_id or sb.metadata.id or None
                    phase = MessageToDict(sb.status, preserving_proto_field_name=True).get("phase")
                    if phase != self.last_phase:
                        self._write(fh, {"kind": "sandbox_status", "phase": phase, "ts_ns": time.time_ns()})
                        self.last_phase = phase
                self._keep(ev.cursor)
                if self.stop.is_set():
                    break
            return None
        except grpc.RpcError as e:
            return e.code(), e.details()

    def run(self):
        os.makedirs(os.path.dirname(self.out_path), exist_ok=True)
        started = time.time()
        with open(self.out_path, "a") as fh:
            self._write(fh, {"kind": "stream_start", "sandbox": self.sandbox, "workspace": self.workspace, "ts_ns": time.time_ns()})
            seen = False
            while not self.stop.is_set():
                res = self._consume(fh)
                if self.stop.is_set():
                    break
                code = res[0] if res else None
                if code == grpc.StatusCode.NOT_FOUND and not seen and not self.cursor:
                    if time.time() - started > self.wait_create:
                        self.incomplete.append("sandbox_never_appeared")
                        break
                    time.sleep(self.poll)
                    continue
                seen = True
                if code == grpc.StatusCode.OUT_OF_RANGE:
                    self.incomplete.append(f"out_of_range: {res[1]}")
                    break
                if code == grpc.StatusCode.NOT_FOUND:      # the sandbox was deleted: the natural end
                    break
                if code is None and not self.until_deleted:
                    break
                # a disconnect (or a clean end while the sandbox still exists): resume once from the cursor
                if self.resumes >= 1:
                    self.incomplete.append(f"disconnect_after_resume: {code.name if code else 'stream_ended'}")
                    break
                self.resumes += 1
                self._write(fh, {"kind": "resume", "after_cursor": self.cursor,
                                 "cause": code.name if code else "stream_ended", "ts_ns": time.time_ns()})
                time.sleep(self.poll)
            if self.warnings:
                self.incomplete.append(f"warnings: {len(self.warnings)}")
            self._write(fh, {"kind": STATUS_KIND, "status": "incomplete" if self.incomplete else "complete",
                             "reasons": self.incomplete, "log_lines": self.lines, "platform_events": self.events,
                             "warnings": len(self.warnings), "resumes": self.resumes, "last_cursor": self.cursor,
                             "sandbox_id": self.sandbox_id, "ts_ns": time.time_ns()})
        return not self.incomplete

    def request_stop(self):
        self.stop.set()
        if self._call is not None:
            self._call.cancel()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sandbox", required=True)
    ap.add_argument("--capture-dir", required=True)
    ap.add_argument("--workspace", default="default")
    ap.add_argument("--gateway", default=None, help="gateway name (default: the active one)")
    ap.add_argument("--poll", type=float, default=0.5)
    ap.add_argument("--wait-create", type=float, default=120.0)
    ap.add_argument("--until-deleted", action="store_true",
                    help="resume through stream ends until the sandbox is deleted (NOT_FOUND)")
    a = ap.parse_args(argv)
    from openshell.sandbox import SandboxClient
    from openshell._proto import openshell_pb2
    client = SandboxClient.from_active_cluster(cluster=a.gateway)
    rec = Recorder(client._stub, openshell_pb2, a.sandbox, a.workspace,
                   os.path.join(a.capture_dir, a.sandbox, "ocsf_stream.jsonl"),
                   poll=a.poll, wait_create=a.wait_create, until_deleted=a.until_deleted)
    signal.signal(signal.SIGTERM, lambda *_: rec.request_stop())
    signal.signal(signal.SIGINT, lambda *_: rec.request_stop())
    ok = rec.run()
    out = rec.out_path
    if rec.sandbox_id:          # file beside the middleware's capture, which is keyed by sandbox_id
        dest = os.path.join(a.capture_dir, rec.sandbox_id, "ocsf_stream.jsonl")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest):          # another recorder already filed this sandbox: keep both, never overwrite
            dest = dest.replace("ocsf_stream.jsonl", f"ocsf_stream.{os.getpid()}.jsonl")
        try:
            os.replace(out, dest)
            out = dest
        except OSError as e:
            print(f"stream: could not move {out} to {dest}: {e}; left in place", file=sys.stderr)
        try:
            os.rmdir(os.path.dirname(rec.out_path))
        except OSError:
            pass
    print(f"stream {a.sandbox}: {'complete' if ok else 'incomplete ' + '; '.join(rec.incomplete)}; "
          f"{rec.lines} log lines, {rec.events} platform events -> {out}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
