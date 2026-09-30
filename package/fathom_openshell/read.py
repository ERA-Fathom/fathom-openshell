#!/usr/bin/env python3
"""Read one sandbox's captures: both adapters, op counts, and the hosted read over the chat-completions ops.

    python -m fathom_openshell.read <captures/sandbox_id>
    python -m fathom_openshell.read --http <http_capture.jsonl> [--ocsf <ocsf_stream.jsonl>] [--no-read]

The model-traffic ops (gaps removed) go to the hosted read (fathom_read.client.read: FATHOM_API_KEY or the demo
key, FATHOM_ENDPOINT or https://read.embeddedriskanalytics.com/v1/read). The delivery-record ops are printed only.
Claim and write patterns come from FATHOM_FACTS, FATHOM_KIND and FATHOM_WRITES, or the matching flags.
"""
import argparse
import collections
import json
import os
import sys

from fathom_openshell.adapters import chat_completions as C
from fathom_openshell.adapters import ocsf as O


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("dir", nargs="?", help="a captures/<sandbox_id> directory")
    ap.add_argument("--http", help="http_capture.jsonl (default <dir>/http_capture.jsonl)")
    ap.add_argument("--ocsf", help="ocsf_stream.jsonl (default <dir>/ocsf_stream.jsonl)")
    ap.add_argument("--facts", help="claim key regex (default FATHOM_FACTS)")
    ap.add_argument("--kind", help="claim kind (default FATHOM_KIND or fact)")
    ap.add_argument("--writes", help="JSON list of {regex, kind} (default FATHOM_WRITES)")
    ap.add_argument("--no-read", action="store_true", help="print the ops without calling the hosted read")
    ap.add_argument("--ops", action="store_true", help="print every op")
    a = ap.parse_args(argv)
    http = a.http or (os.path.join(a.dir, "http_capture.jsonl") if a.dir else None)
    ocsf = a.ocsf or (os.path.join(a.dir, "ocsf_stream.jsonl") if a.dir else None)
    if a.writes:
        os.environ["FATHOM_WRITES"] = a.writes

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
