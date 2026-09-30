#!/usr/bin/env python3
"""Read one sandbox's captures: both adapters, op counts, and the hosted read over the chat-completions ops.

    python -m fathom_openshell.read <captures/sandbox_id>
    python -m fathom_openshell.read --http <http_capture.jsonl> [--ocsf <ocsf_stream.jsonl>] [--no-read]
    python -m fathom_openshell.read <captures/sandbox_id> [<captures/other_sandbox_id> ...] --join --tool-map '{"tool": "host:port"}'

The model-traffic ops (gaps removed) go to the hosted read (fathom_read.client.read: FATHOM_API_KEY or the demo
key, FATHOM_ENDPOINT or https://read.embeddedriskanalytics.com/v1/read). The delivery-record ops are printed only.
Claim and write patterns come from FATHOM_FACTS, FATHOM_KIND and FATHOM_WRITES, or the matching flags.

--join sends the joined read (fathom-read 0.6.0): the model-traffic ops of one or more sandboxes, merged in time order,
together with each sandbox's delivery record (the WatchSandbox stream's delivery events, its provider request windows and
its tool-call timing) and the tool map (FATHOM_TOOL_MAP or --tool-map: where each tool writes, "[METHOD ]host:port[/path]").
The service lines the record up with the ops and reads a write whose delivery was denied or never happened as a write that
did not land; the response's join block is printed after the findings. A sandbox whose record is incomplete is refused
(HTTP 422, exit 3). The package only gathers and sends the data; the alignment runs in the service.
"""
import argparse
import collections
import json
import os
import sys
import urllib.error
import urllib.request

from fathom_openshell.adapters import chat_completions as C
from fathom_openshell.adapters import ocsf as O


DEFAULT_ENDPOINT = "https://read.embeddedriskanalytics.com/v1/read"
USER_AGENT = "fathom-openshell/0.2.1"


def load_tool_map(arg=None):
    """--tool-map as JSON text or a path to a JSON file; else FATHOM_TOOL_MAP (same forms); else {}."""
    raw = arg if arg is not None else os.environ.get("FATHOM_TOOL_MAP")
    if not raw:
        return {}
    if os.path.exists(raw):
        with open(raw) as fh:
            return json.load(fh)
    return json.loads(raw)


def join_request(dirs, tool_map, facts=None, kind=None, names=None):
    """The /v1/read request body with `join` for one or more captures/<sandbox_id> directories.

    Ops from every sandbox are merged in time order (then sandbox, then position), gaps dropped, steps numbered from 0;
    the ok bits are the adapter's own (the service applies the delivery record). Every time is integer ns relative to
    t0_ns (the earliest time minus 1, sent as a string), so values stay exact in any JSON reader. A sandbox with no
    delivery record, or an incomplete one, is sent as incomplete."""
    per, timed = [], []
    for k, d in enumerate(dirs):
        http, ocsf = os.path.join(d, "http_capture.jsonl"), os.path.join(d, "ocsf_stream.jsonl")
        detail = C.load_capture_detail(http, facts=facts, kind=kind)
        dops = O.load_stream(ocsf) if os.path.exists(ocsf) else [{"op": "record_incomplete", "reasons": ["no delivery record"]}]
        inc = next((x["reasons"] for x in dops if x["op"] == "record_incomplete"), [])
        per.append((detail, [x for x in dops if x["op"] == "delivery"], inc))
        for i, (ts, o) in enumerate(detail["timed"]):
            if o.op != C.GAP:
                timed.append((ts, k, i, o))
    timed.sort(key=lambda x: (x[0], x[1], x[2]))
    step_of = {(k, i): n for n, (_, k, i, _) in enumerate(timed)}
    times = [ts for ts, _, _, _ in timed]
    for detail, dels, _ in per:
        times += [x for p in detail["pairs"] for x in (p["request_ts"], p["response_ts"]) if x]
        times += [x for c in detail["calls"].values() for x in (c.get("call_ts"), c.get("result_ts")) if x]
        times += [x["event_time_ns"] for x in dels if x.get("event_time_ns")]
    t0 = min(times) - 1 if times else 0

    def rel(x):
        return None if x is None else int(x) - t0

    ops = []
    for n, (ts, _, _, o) in enumerate(timed):
        d = o.as_dict()
        d["step"] = n
        d["ts_ns"] = rel(ts)
        ops.append(d)
    sandboxes = []
    for k, (detail, dels, inc) in enumerate(per):
        sandboxes.append({
            "sandbox_id": names[k] if names else os.path.basename(os.path.normpath(dirs[k])),
            "record": {"status": "incomplete" if inc else "complete", "reasons": list(inc)},
            "pairs": [{"request_id": p["request_id"], "endpoint": p["endpoint"], "request_ts": rel(p["request_ts"]),
                       "response_ts": rel(p["response_ts"])} for p in detail["pairs"]],
            "calls": [{"tool_call_id": cid, "tool": c.get("tool"), "call_ts": rel(c.get("call_ts")),
                       "result_ts": rel(c.get("result_ts")),
                       "result_steps": [step_of[(k, i)] for i in c.get("result_ops", []) if (k, i) in step_of]}
                      for cid, c in detail["calls"].items()],
            "deliveries": [{f: (rel(x.get(f)) if f == "event_time_ns" else x.get(f)) for f in
                            ("cursor", "event", "decision", "method", "host", "port", "path", "endpoint", "event_time_ns", "reasons")}
                           for x in dels],
        })
    return {"ops": ops, "supersede": [], "format": "openshell",
            "join": {"t0_ns": str(t0), "tool_map": tool_map or {}, "sandboxes": sandboxes}}


def post_read(body, endpoint=None, key=None, timeout=60.0):
    """POST a request body to the hosted read (FATHOM_ENDPOINT, FATHOM_API_KEY or the demo key). (status, payload)."""
    endpoint = endpoint or os.environ.get("FATHOM_ENDPOINT") or DEFAULT_ENDPOINT
    key = key or os.environ.get("FATHOM_API_KEY") or "demo"
    req = urllib.request.Request(endpoint, data=json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + key, "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw or "{}")
        except ValueError:
            return e.code, {"error": raw.strip()[:200]}
    except urllib.error.URLError as e:
        return 0, {"error": f"could not reach the read at {endpoint}: {e.reason}"}


def _joined(a):
    dirs = [d for d in a.dir]
    if not dirs:
        print("--join needs one or more captures/<sandbox_id> directories")
        return 2
    body = join_request(dirs, load_tool_map(a.tool_map), facts=a.facts, kind=a.kind)
    n_del = sum(len(s["deliveries"]) for s in body["join"]["sandboxes"])
    print(f"joined read: {len(dirs)} sandbox(es), {len(body['ops'])} ops, {n_del} delivery events")
    if a.no_read:
        print(json.dumps(body)[:2000] if a.ops else "  (--no-read: nothing sent)")
        return 0
    status, v = post_read(body)
    if status == 422:
        print(f"  record incomplete: nothing read ({v.get('error')})")
        for r in v.get("reasons", []):
            print(f"    {r.get('sandbox_id')}: {r.get('reason')}")
        return 3
    if status != 200:
        print(f"  read failed: HTTP {status} {v.get('error', '')}")
        return 2
    print("  " + json.dumps({k: v[k] for k in v if k != "join"}, sort_keys=True))
    for f in v.get("findings", []):
        print(f"    {f['kind']} step {f['step']} key {f['key']}: {f['detail']}")
    j = v.get("join") or {}
    print(f"  join: record {j.get('record', {}).get('status')}, skew {j.get('skew_ms')} ms, "
          f"{json.dumps(j.get('summary'), sort_keys=True)}, flipped steps {j.get('flipped_steps')}")
    for r in j.get("rows", []):
        if a.ops or r.get("row") == "tool_result":
            what = r.get("tool_call_id") if r.get("row") == "tool_result" else r.get("request_id")
            print(f"    {r.get('sandbox_id')} {r.get('row')} {r.get('tool') or r.get('endpoint')} {what}: {r.get('status')}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir", nargs="*", help="captures/<sandbox_id> directories (one, or several with --join)")
    ap.add_argument("--http", help="http_capture.jsonl (default <dir>/http_capture.jsonl)")
    ap.add_argument("--ocsf", help="ocsf_stream.jsonl (default <dir>/ocsf_stream.jsonl)")
    ap.add_argument("--facts", help="claim key regex (default FATHOM_FACTS)")
    ap.add_argument("--kind", help="claim kind (default FATHOM_KIND or fact)")
    ap.add_argument("--writes", help="JSON list of {regex, kind} (default FATHOM_WRITES)")
    ap.add_argument("--no-read", action="store_true", help="print the ops without calling the hosted read")
    ap.add_argument("--ops", action="store_true", help="print every op")
    ap.add_argument("--join", action="store_true", help="the joined read: send the delivery record with the ops (fathom-read 0.6.0)")
    ap.add_argument("--tool-map", help='with --join: {"tool": "[METHOD ]host:port[/path]"} as JSON or a file (default FATHOM_TOOL_MAP)')
    a = ap.parse_args(argv)
    if a.writes:
        os.environ["FATHOM_WRITES"] = a.writes
    if a.join:
        return _joined(a)
    d0 = a.dir[0] if a.dir else None
    http = a.http or (os.path.join(d0, "http_capture.jsonl") if d0 else None)
    ocsf = a.ocsf or (os.path.join(d0, "ocsf_stream.jsonl") if d0 else None)

    rc = 0
    if http and os.path.exists(http):
        ops = C.load_capture(http, facts=a.facts, kind=a.kind)
        gaps = [o for o in ops if o.op == C.GAP]
        counts = collections.Counter(f"{o.op} {o.kind}" for o in ops)
        print(f"chat-completions  {http}")
        print(f"  ops {len(ops)}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
        if a.ops:
            for o in ops:
                print("   ", json.dumps(o.as_dict()))
        for g in gaps:
            print(f"  gap: {g.key} {g.value}")
        if not a.no_read:
            from fathom_read.client import read, ReadError
            sent = C.read_ops(ops)
            if gaps:
                print(f"  NOTE: the capture has {len(gaps)} gap(s); the read below covers the captured traffic only")
            try:
                v = read(sent)
            except ReadError as e:
                print(f"  read failed: {e}")
                return 2
            print(f"  hosted read ({len(sent)} ops sent):")
            print("  " + json.dumps(v.as_dict(), sort_keys=True))
            for f in v.findings:
                print(f"    {f.kind} step {f.step} key {f.key}: {f.detail}")
    else:
        print(f"chat-completions  (no capture at {http})")

    if ocsf and os.path.exists(ocsf):
        dops = O.load_stream(ocsf)
        summary = dops[-1]
        body = [o for o in dops if o["op"] not in ("stream_summary",)]
        counts = collections.Counter(o["op"] if o["op"] != "delivery" else f"delivery {o['event']} {o['decision']}" for o in body)
        print(f"ocsf  {ocsf}")
        print(f"  stream status {summary['status']}; lines {summary['counts']}")
        print(f"  ops {len(body)}: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
        for o in body:
            if a.ops or o["op"] == "record_incomplete":
                print("   ", json.dumps(o, sort_keys=True))
        if any(o["op"] == "record_incomplete" for o in body):
            rc = rc or 3
    else:
        print(f"ocsf  (no stream at {ocsf})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
