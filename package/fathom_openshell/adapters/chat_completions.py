"""A fathom-capture http_capture.jsonl (OpenAI-style chat completions) as a fathom op stream.

load_capture(path) walks the request/response pairs in time order and emits ops only for what is new in each
pair; a request's messages array is history the adapter has already seen, except where a capture stub left a
gap, which the history fills.

Mapping:
  * an assistant tool_call              -> add call <tool name>, value = the arguments as canonical JSON
                                           (a call repeated with identical arguments is an entity the
                                           collection already holds); ok comes from the paired result
  * a tool the fathom_read default map knows (write_file, set_value, ...)
                                        -> also that tool's own op (set/remove/rename/add/commit)
  * a tool-role message                 -> pairs to its call by tool_call_id and supplies the result and ok
                                           (ok is false when the result reads as an error)
  * FATHOM_WRITES matches in a tool result
                                        -> set <kind> <key> = <value>   (not in a call's arguments: an argument is
                                           the agent's intent, and the result or the landed write is the commit)
  * FATHOM_FACTS matches in assistant text
                                        -> answer <FATHOM_KIND> <key>, with the stated value when one is given; only
                                           from a message that carries no tool call (text beside a call states what
                                           the agent is about to do, as the call's arguments do)
  * a stub line in the capture          -> gap capture <request_id>, value = the stub reason (not a read op;
                                           read.py keeps gaps out of what it sends and reports them)
  * an assistant message first seen in a later request's history (its response was a gap, or it predates
    the capture)                        -> the same ops, source "history"
  * a GitHub contents PUT (e.g. the multi-agent notepad example's shared notes, PUT /repos/<o>/<r>/contents/<path>)
                                        -> set note <path> = the decoded content, ok when GitHub answered 200/201
                                           (a 409 or any other status is a write that did not land). For a note file
                                           (path matching FATHOM_NOTE_PATHS, default "(^|/)notes/"), FATHOM_WRITES
                                           matches inside become set ops with the same ok; for any other file (the
                                           synthesis summary) the FATHOM_FACTS statements inside become answer ops:
                                           a report makes claims about committed state, it does not commit facts
  * a contents PUT whose response never came back (a connection closed in flight) is a gap, unless a later 200 GET of
    the same path in the same capture returns exactly the content sent: then the write landed, at that GET
    (source github_put:verified_by_get)
  * one statement counts once: an assistant final message whose text (whitespace-
    normalized) was also PUT as a file contributes no claims; the file does. A non-note file's set note op carries
    value None (the landing is recorded; its content is carried by the answer ops)
  * FATHOM_COMMIT_CALLS (optional regex over a call's name + arguments): a committing call, e.g. a shell command
    running a note-writing helper. When its result does not match FATHOM_COMMIT_OK (default "HTTP (200|201)\b"), the
    FATHOM_WRITES matches in its arguments become set ops with ok=false at the result: the write the agent attempted
    and the tool reported failed (an L7 denial never reaches the middleware, so this is the only trace of it). A
    successful committing call adds nothing here; the captured PUT carries the landed write.
    The call failed only on a definite failure in its output, FATHOM_COMMIT_FAIL
    (default an exit code other than 0 or an HTTP status other than 200/201) with no FATHOM_COMMIT_OK match; a result
    with neither (a command still running when the tool returned) is unknown and adds no op.
    When the committing command reads a file (cat PATH | ..., helper X < PATH) that this agent wrote
    earlier by a heredoc or a quoted echo/printf redirect in a call that ran, the last content written to that path is
    part of the attempted write.
  * FATHOM_CLAIMS_FROM (optional regex): claims are read only from responses whose request's first message
    (system or user) matches it, e.g. the synthesis turn, so a worker drafting a new fact is not read as an
    assertion about committed state

Endpoints are keyed on host:port plus path, never scheme (OpenShell 0.1.2 prints https:// on some response-stage
lines for plain-http upstreams). Environment, same names as fathom-prime-agent: FATHOM_FACTS (key regex),
FATHOM_KIND (default "fact"), FATHOM_WRITES (JSON list of {"regex", "kind"} with named groups key and value;
JavaScript-style (?<name>...) groups are accepted).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

try:
    from fathom_read.ops import Op
    from fathom_read.adapters._tools import DEFAULT_MAP, op_from_tool
except ImportError:  # pragma: no cover
    from dataclasses import asdict, dataclass, field

    @dataclass
    class Op:  # the fathom op contract, for use without fathom-read installed
        op: str
        kind: str
        key: str
        value: Optional[str] = None
        to: Optional[str] = None
        ok: bool = True
        refs: List[Tuple[str, str]] = field(default_factory=list)
        step: Optional[int] = None
        source: Optional[str] = None

        def as_dict(self) -> Dict[str, Any]:
            d = asdict(self)
            d["refs"] = [list(r) for r in self.refs]
            return d

    DEFAULT_MAP = {}

    def op_from_tool(*a, **k):
        return None

GAP = "gap"
CALL = "call"
ERROR_RE = re.compile(r"^\s*(error\b|exception\b|traceback\b)", re.I)
# prime-agent's claim verbs, plus a few plain-English ones ("A-17 holds 412")
# "|" reads a markdown table cell pair ("| sla_hours | 24 | agent-2 |"): the synthesis summary's Facts table
CLAIM_VERBS = r"(?:=|:|\||is|->|→|holds|has|equals)"


def endpoint_key(host: str, port: Any, path: str) -> str:
    return f"{host}:{port}{path}"


def _js_groups(rx: str) -> str:
    return re.sub(r"\(\?<(?![=!])", "(?P<", rx)


def env_writes() -> List[Tuple[Pattern[str], str]]:
    raw = os.environ.get("FATHOM_WRITES")
    if not raw:
        return []
    return [(re.compile(_js_groups(w["regex"])), w.get("kind", "fact")) for w in json.loads(raw)]


# Placeholder words are not values, in writes and in claims alike: a line that gives a key as "none", "not stated",
# "not reported", "n/a", ... says the value is absent and asserts nothing. One list for both.
PLACEHOLDER_WORDS = ("none", "not", "n/a", "na", "unknown", "null", "unspecified", "missing")
# for a FATHOM_WRITES value group: (?<value>...) preceded by this refuses a placeholder word
PLACEHOLDER_LOOKAHEAD = r"(?!(?i:" + "|".join(re.escape(w) for w in PLACEHOLDER_WORDS) + r")(?![A-Za-z0-9._-]))"


def is_placeholder(value: Optional[str]) -> bool:
    return value is not None and value.strip().lower() in PLACEHOLDER_WORDS


class Claims:
    """Finds the named facts a piece of assistant text states (prime-agent's resolver, facts only)."""

    def __init__(self, key_pattern: Optional[str], kind: str):
        self.kind = kind
        self.key_re = re.compile(key_pattern) if key_pattern else None
        self.fact_re = (re.compile(r"(?<![\w.])['\"]?(" + key_pattern + r")['\"]?\s*" + CLAIM_VERBS + r"\s*(-?\d+(?:\.\d+)?|[\w./-]+)")
                        if key_pattern else None)

    def ops(self, text: str, source: str) -> List[Op]:
        out: List[Op] = []
        if self.fact_re is None or not text:
            return out
        # one message states one current value per key: the last value stated for a key is the claim (a note that
        # records a correction lists the figure as first stated, then the revised one, and a reply restating the
        # note's lines must not read as asserting the corrected figure)
        last: Dict[str, str] = {}
        blank = set()          # keys whose last statement is a placeholder: absent, so no claim and no bare reference
        for m in self.fact_re.finditer(text):
            key, val = m.group(1), m.group(m.lastindex)
            if self.key_re.fullmatch(val):
                continue
            last.pop(key, None)
            if is_placeholder(val):
                blank.add(key)
                continue
            blank.discard(key)
            last[key] = val
        for key, val in last.items():
            out.append(Op("answer", self.kind, key, value=val, refs=[(self.kind, key)], source=source))
        named = set(last) | blank
        for m in self.key_re.finditer(text):
            if m.group(0) not in named:
                named.add(m.group(0))
                out.append(Op("answer", self.kind, m.group(0), value=None, refs=[(self.kind, m.group(0))], source=source))
        return out


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def canonical_args(arguments: Any) -> str:
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments) if arguments.strip() else {}
        except ValueError:
            return arguments
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"))


def _result_ok(content: str) -> bool:
    if ERROR_RE.match(content or ""):
        return False
    try:
        d = json.loads(content)
    except (TypeError, ValueError):
        return True
    return not (isinstance(d, dict) and (d.get("error") or d.get("is_error")))


GITHUB_CONTENTS = re.compile(r"^/repos/[^/]+/[^/]+/contents/(?P<path>[^?]+)")


def _github_put(req: Dict[str, Any]) -> Optional[Tuple[str, Optional[str]]]:
    """(path, decoded content) for a GitHub contents PUT request line, else None."""
    if (req.get("method") or "").upper() != "PUT" or "github" not in (req.get("host") or ""):
        return None
    m = GITHUB_CONTENTS.match(req.get("path") or "")
    if not m:
        return None
    body = req.get("body") or {}
    content = None
    if isinstance(body, dict) and body.get("content") is not None:
        import base64
        try:
            content = base64.b64decode(body["content"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            content = None
    return m.group("path"), content


def _github_get_content(req: Dict[str, Any], resp: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
    """(path, decoded content) for a GitHub contents GET answered 200 with a file body, else None."""
    if (req.get("method") or "").upper() != "GET" or "github" not in (req.get("host") or "") or resp is None \
            or resp.get("stub") or resp.get("status_code") != 200:
        return None
    m = GITHUB_CONTENTS.match(req.get("path") or "")
    body = resp.get("body")
    if not m or not isinstance(body, dict) or not isinstance(body.get("content"), str):
        return None
    import base64
    try:
        return m.group("path"), base64.b64decode("".join(body["content"].split())).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _first_text(body: Dict[str, Any]) -> str:
    msgs = (body or {}).get("messages") or []
    return _text(msgs[0].get("content")) if msgs else ""


def _msg_sig(msg: Dict[str, Any]) -> str:
    ids = [tc.get("id") for tc in msg.get("tool_calls") or [] if tc.get("id")]
    if ids:
        return "calls:" + ",".join(ids)
    return "text:" + hashlib.sha256(_text(msg.get("content")).encode()).hexdigest()


def _response_message(line: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    body = line.get("body") or {}
    if not isinstance(body, dict):          # a JSON list or scalar (e.g. a directory listing) is no chat response
        return None
    if "message" in body and "choices" not in body:        # reassembled SSE
        return body["message"]
    choices = body.get("choices") or []
    if choices and isinstance(choices[0], dict):
        return choices[0].get("message")
    if body.get("type") == "message" and body.get("role") == "assistant":     # Anthropic-style
        text = "".join(c.get("text", "") for c in body.get("content") or [] if c.get("type") == "text")
        calls = [{"id": c.get("id"), "function": {"name": c.get("name"), "arguments": json.dumps(c.get("input") or {})}}
                 for c in body.get("content") or [] if c.get("type") == "tool_use"]
        return {"role": "assistant", "content": text or None, "tool_calls": calls or None}
    return None


def read_capture(path: str) -> List[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]:
    """(request line, response line or None) per request_id, ordered by the request's timestamp."""
    reqs: Dict[str, Dict[str, Any]] = {}
    resps: Dict[str, Dict[str, Any]] = {}
    with open(path) as fh:
        for raw in fh:
            if not raw.strip():
                continue
            line = json.loads(raw)
            (reqs if line.get("kind") == "request" else resps)[line.get("request_id", "")] = line
    orphans = [(None, r) for rid, r in resps.items() if rid not in reqs]
    pairs = [(reqs[rid], resps.get(rid)) for rid in reqs]
    pairs.sort(key=lambda p: p[0].get("ts_ns", 0))
    return pairs + [(o[1], None) for o in orphans] if orphans else pairs


_HEREDOC_TO = [   # cat > PATH <<'EOF' ... EOF   and   cat <<EOF > PATH ... EOF   (optionally quoted terminators)
    re.compile(r"cat\s*>\s*(?P<path>[\w./-]+)\s*<<-?\s*['\"]?(?P<tag>\w+)['\"]?[^\n]*\n(?P<body>.*?)\n(?P=tag)\s*(?:\n|$)", re.S),
    re.compile(r"cat\s*<<-?\s*['\"]?(?P<tag>\w+)['\"]?\s*>\s*(?P<path>[\w./-]+)[^\n]*\n(?P<body>.*?)\n(?P=tag)\s*(?:\n|$)", re.S),
]
_ECHO_TO = re.compile(r"(?:echo|printf)\s+(?:-e\s+)?(?P<q>['\"])(?P<body>.*?)(?P=q)\s*>\s*(?P<path>[\w./-]+)", re.S)
_COMMIT_READS = [re.compile(r"cat\s+(?P<path>[\w./-]+)\s*\|"), re.compile(r"(?<![<\d])<(?!<)\s*(?P<path>[\w./-]+)")]


def _cmd(arguments: Any) -> str:
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            return arguments
    if isinstance(arguments, dict):
        c = arguments.get("cmd") or arguments.get("command") or ""
        return " ".join(c) if isinstance(c, list) else str(c)
    return ""


def _norm_path(p: str) -> str:
    p = p.strip()
    for pre in ("/sandbox/", "./"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p


def _file_writes(arguments: Any) -> List[Tuple[str, str]]:
    """(path, content) for each heredoc or quoted echo/printf redirected into a path by this command."""
    cmd, out = _cmd(arguments), []
    for rx in _HEREDOC_TO:
        out += [(_norm_path(m.group("path")), m.group("body")) for m in rx.finditer(cmd)]
    out += [(_norm_path(m.group("path")), m.group("body").replace("\\n", "\n")) for m in _ECHO_TO.finditer(cmd)]
    return out


def _commit_reads(arguments: Any) -> Optional[str]:
    """The path a committing command reads its content from (cat PATH | ..., helper X < PATH), or None."""
    cmd = _cmd(arguments)
    for rx in _COMMIT_READS:
        m = rx.search(cmd)
        if m:
            return _norm_path(m.group("path"))
    return None


# A final message that reports a failure beside its facts (a non-2xx status on its own or after "HTTP", a non-zero exit,
# a helper's failure line) is a failure report; its facts are not claims of committed state. FATHOM_FAILURE_REPORT
# overrides it (matched case-insensitively, ^ and $ per line).
# a line that is only a file path (a write's block starts with it), e.g. runs/r/notes/agent-2/max_agents.md
PATH_LINE = re.compile(r"^\s*[\w.-]*(?:/[\w.-]+)+\.\w{1,6}\s*:?\s*$")

FAILURE_REPORT = (r"HTTP [45]\d\d\b|^\s*[45]\d\d\s*$|exit(?:ed with)? code [1-9]|\bfailed\b|\bdenied\b|\bnot sent\b")


def _call_texts(captured) -> set:
    """Normalized texts of every assistant message that carries a tool call, from responses and request histories."""
    from fathom_openshell.adapters import responses as RSP
    out = set()
    for req, resp in captured:
        path = (req.get("path") or "").rstrip("/")
        if not (path.endswith("/responses") or path.endswith("/chat/completions")):
            continue                     # only model traffic carries assistant messages (a GitHub listing is a JSON list)
        msgs = []
        body = req.get("body") if req.get("kind") == "request" else None
        if isinstance(body, dict):
            if (req.get("path") or "").rstrip("/").endswith("/responses"):
                msgs += RSP.to_chat_request(body)["messages"]
            else:
                msgs += body.get("messages") or []
        if resp is not None and not resp.get("stub"):
            m = RSP.response_message(resp) if (req.get("path") or "").rstrip("/").endswith("/responses") \
                else _response_message(resp)
            if m:
                msgs.append(m)
        for m in msgs:
            if isinstance(m, dict) and m.get("role") == "assistant" and m.get("tool_calls"):
                t = " ".join(_text(m.get("content")).split())
                if t:
                    out.add(t)
    return out


class _Walker:
    def __init__(self, facts: Optional[str], kind: str, writes, tool_map, call_texts=None):
        self.claims = Claims(facts, kind)
        self.writes = writes
        self.tool_map = tool_map
        self.out: List[Tuple[int, Op]] = []
        self.seen_msgs: set = set()
        self.seen_results: set = set()
        self.calls: Dict[str, Tuple[str, List[Op]]] = {}     # tool_call_id -> (tool name, ops to mark ok)
        # tool_call_id -> {tool, call_ts, result_ts, result_ok, call_ops, result_ops} (op indices), for the join
        self.timing: Dict[str, Dict[str, Any]] = {}
        cc = os.environ.get("FATHOM_COMMIT_CALLS")
        self.commit_re = re.compile(cc) if cc else None
        self.commit_ok_re = re.compile(os.environ.get("FATHOM_COMMIT_OK") or r"HTTP (200|201)\b")
        # a committing call failed only on a definite failure in its output
        self.commit_fail_re = re.compile(os.environ.get("FATHOM_COMMIT_FAIL")
                                         or r"Process exited with code [1-9]\d*\b|HTTP (?!200\b|201\b)\d{3}\b")
        self.call_texts = call_texts or set()   # normalized texts of assistant messages that carry tool calls
        self.failure_re = re.compile(os.environ.get("FATHOM_FAILURE_REPORT") or FAILURE_REPORT, re.I | re.M)
        self.files: Dict[str, str] = {}      # path -> last content this agent wrote to it (by a call that ran)

    def emit(self, ts: int, op: Op) -> Op:
        self.out.append((ts, op))
        return op

    def _writes(self, ts: int, text: str, source: str) -> List[int]:
        idx = []
        for rx, kind in self.writes:
            for m in rx.finditer(text or ""):
                gd = m.groupdict()
                if gd.get("key") is not None:
                    self.emit(ts, Op("set", kind, str(gd["key"]), value=gd.get("value"), source=source))
                    idx.append(len(self.out) - 1)
        return idx

    def assistant(self, ts: int, msg: Dict[str, Any], source: str, dedup: bool = False, claims: bool = True):
        """A response is always new; a history message is skipped when a response already carried it."""
        sig = _msg_sig(msg)
        if dedup and sig in self.seen_msgs:
            return
        self.seen_msgs.add(sig)
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            name, args = fn.get("name") or "", fn.get("arguments")
            cid = tc.get("id") or f"anon:{len(self.calls)}"
            ops = [self.emit(ts, Op("add", CALL, name, value=canonical_args(args), source=f"{source}:{cid}"))]
            first = len(self.out) - 1
            mapped = op_from_tool(name, args, True, 0, self.tool_map, source=f"{source}:{cid}")
            if mapped is not None:
                mapped.step = None
                ops.append(self.emit(ts, mapped))
            self.calls[cid] = (name, ops)
            self.timing[cid] = {"tool": name, "call_ts": ts, "call_source": source, "result_ts": None, "result_ok": None,
                                "call_ops": list(range(first, len(self.out))), "result_ops": [],
                                "call_text": f"{name} {args if isinstance(args, str) else json.dumps(args)}",
                                "file_writes": _file_writes(args)}
            # a committing call that reads a file this agent wrote carries that file's content
            read_path = _commit_reads(args) if self.commit_re is not None and self.commit_re.search(
                self.timing[cid]["call_text"]) else None
            if read_path is not None and read_path in self.files:
                self.timing[cid]["call_text"] += "\n" + self.files[read_path]
        # prose in a message that carries a tool call states what the agent is about to do, like the call's
        # arguments, so it is not a claim; claims come only from messages
        # that carry no tool call
        text = _text(msg.get("content"))
        said = " ".join(text.split())
        if claims and not msg.get("tool_calls") and said in self.call_texts:
            claims = False    # a copy of a message whose tool call had not arrived yet (a cut stream): same message
        if claims and not msg.get("tool_calls"):
            text = self._claimable(text)      # a failure report's facts are not claims of committed state
        if claims and not msg.get("tool_calls") and text:
            for op in self.claims.ops(text, source):
                self.emit(ts, op)

    def _claimable(self, text: str) -> str:
        """The part of a final message whose facts are claims. No failure statement: all of it. A failure statement in
        a message with no path lines: none of it (the failure governs the whole message). A message laid out by path
        lines (path, status, facts, per write): a failure statement governs only the lines after it in its own path's
        block, so a fact line with no failing status above it in its block is a claim."""
        if not self.failure_re.search(text):
            return text
        lines = text.splitlines()
        if not any(PATH_LINE.match(ln) for ln in lines):
            return ""
        keep, failed = [], False
        for ln in lines:
            if PATH_LINE.match(ln):
                failed = False
                continue
            if self.failure_re.search(ln):
                failed = True
                continue
            if not failed:
                keep.append(ln)
        return "\n".join(keep)

    def history(self, ts: int, messages: Iterable[Dict[str, Any]]):
        for m in messages:
            role = m.get("role")
            if role == "assistant":
                self.assistant(ts, m, "history", dedup=True)
            elif role == "tool":
                cid = m.get("tool_call_id") or ""
                if cid in self.seen_results:
                    continue
                self.seen_results.add(cid)
                content = _text(m.get("content"))
                ok = _result_ok(content)
                name, ops = self.calls.get(cid, ("", []))
                for op in ops:
                    op.ok = op.ok and ok
                t = self.timing.setdefault(cid, {"tool": name, "call_ts": None, "call_source": None, "call_ops": []})
                t.update(result_ts=ts, result_ok=ok, result_ops=self._writes(ts, content, f"result:{cid}") if ok else [])
                if not self.commit_fail_re.search(content or ""):
                    for fp, fc in t.get("file_writes") or []:     # the write ran (no definite failure): remember it
                        self.files[fp] = fc
                if self.commit_re is not None and self.commit_re.search(t.get("call_text") or "") \
                        and self.commit_fail_re.search(content or "") and not self.commit_ok_re.search(content or ""):
                    for rx, wkind in self.writes:
                        for m in rx.finditer(t.get("call_text") or ""):
                            gd = m.groupdict()
                            if gd.get("key") is not None:
                                self.emit(ts, Op("set", wkind, str(gd["key"]), value=gd.get("value"), ok=False,
                                                 source=f"commit_call:{cid}"))
                                t["result_ops"].append(len(self.out) - 1)


def load_capture_detail(path: str, facts: Optional[str] = None, kind: Optional[str] = None,
                        writes: Optional[List[Tuple[Pattern[str], str]]] = None,
                        tool_map: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """{"timed": [(ts ns, op)], "calls": {tool_call_id: timing}, "pairs": [provider pair windows]}.
    facts/kind/writes default to FATHOM_FACTS / FATHOM_KIND / FATHOM_WRITES."""
    facts = facts if facts is not None else os.environ.get("FATHOM_FACTS")
    kind = kind or os.environ.get("FATHOM_KIND") or "fact"
    writes = writes if writes is not None else env_writes()
    w = _Walker(facts, kind, writes, tool_map if tool_map is not None else DEFAULT_MAP)
    note_paths = re.compile(os.environ.get("FATHOM_NOTE_PATHS") or r"(^|/)notes/")
    claims_from = os.environ.get("FATHOM_CLAIMS_FROM")
    claims_re = re.compile(claims_from) if claims_from else None
    pairs: List[Dict[str, Any]] = []
    captured = read_capture(path)
    w.call_texts = _call_texts(captured)
    put_texts = set()                  # one statement counts once: normalized bodies of every GitHub contents PUT in the capture
    for rq, _ in captured:
        g = _github_put(rq) if rq.get("kind") == "request" and not rq.get("stub") else None
        if g is not None and g[1]:
            put_texts.add(" ".join(g[1].split()))
    for req, resp in captured:
        rid = req.get("request_id", "")
        t_req = req.get("ts_ns", 0)
        pair = {"request_id": rid, "request_ts": t_req if req.get("kind") == "request" else None,
                "response_ts": None, "endpoint": endpoint_key(req.get("host", ""), req.get("port", ""), req.get("path", "")),
                "method": req.get("method")}
        pairs.append(pair)
        if resp is not None:
            pair["response_ts"] = resp.get("ts_end_ns") or resp.get("ts_ns")
        gh = _github_put(req) if req.get("kind") == "request" and not req.get("stub") else None
        if gh is not None:
            path, content = gh
            t_resp = (resp or {}).get("ts_end_ns") or (resp or {}).get("ts_ns") or t_req
            status = (resp or {}).get("status_code")
            if resp is None and content:
                # the PUT went upstream but its response never came back (OpenShell closes a connection in flight when it
                # republishes policy). It landed when a later 200 GET of the same path in this capture returns
                # exactly the content sent (a client that checks before retrying makes that GET); the set is placed there
                later = [(r2.get("ts_end_ns") or r2.get("ts_ns") or 0) for q2, r2 in captured
                         if q2.get("ts_ns", 0) > t_req and _github_get_content(q2, r2) == (path, content)]
                if later:
                    t_resp, status = min(later), "verified_by_get"
            if status is None or (resp is not None and resp.get("stub")):
                w.emit(t_resp, Op(GAP, "capture", rid, value=f"response:{'missing' if resp is None else resp.get('stub_reason')}",
                                  ok=False, source="stub"))
                continue
            landed = status in (200, 201, "verified_by_get")
            is_note = bool(note_paths.search(path))
            w.emit(t_resp, Op("set", "note", path, value=content if is_note else None, ok=landed,
                              source=f"github_put:{status}"))
            if is_note:
                for rx, wkind in w.writes:
                    for m in rx.finditer(content or ""):
                        gd = m.groupdict()
                        if gd.get("key") is not None:
                            w.emit(t_resp, Op("set", wkind, str(gd["key"]), value=gd.get("value"), ok=landed,
                                              source=f"note:{path}"))
            else:
                for op in w.claims.ops(content or "", f"report:{path}"):
                    op.ok = landed
                    w.emit(t_resp, op)
            continue
        if req.get("kind") == "request" and "github" in (req.get("host") or ""):
            continue                   # other GitHub traffic (GET of notes) carries no op
        wire_responses = (req.get("path") or "").rstrip("/").endswith("/responses")
        req_body = req.get("body") or {}
        if wire_responses and isinstance(req_body, dict):
            from fathom_openshell.adapters import responses as RSP
            req_body = RSP.to_chat_request(req_body)
        if req.get("kind") == "request":
            if req.get("stub"):
                w.emit(t_req, Op(GAP, "capture", rid, value=f"request:{req.get('stub_reason')}", ok=False, source="stub"))
            else:
                w.history(t_req, (req_body or {}).get("messages") or [])
        else:                      # a response with no request line
            resp, t_req = req, req.get("ts_ns", 0)
            w.emit(t_req, Op(GAP, "capture", rid, value="request:missing", ok=False, source="stub"))
        if resp is None:
            w.emit(t_req, Op(GAP, "capture", rid, value="response:missing", ok=False, source="stub"))
            continue
        t_resp = resp.get("ts_end_ns") or resp.get("ts_ns", t_req)
        if resp.get("stub"):
            w.emit(t_resp, Op(GAP, "capture", rid, value=f"response:{resp.get('stub_reason')}", ok=False, source="stub"))
            continue
        if wire_responses:
            from fathom_openshell.adapters import responses as RSP
            msg = RSP.response_message(resp)
        else:
            msg = _response_message(resp)
        if msg is None:
            w.emit(t_resp, Op(GAP, "capture", rid, value="response:unparsed", ok=False, source="stub"))
            continue
        said = " ".join(_text(msg.get("content")).split())
        w.assistant(t_resp, msg, "assistant",
                    claims=(claims_re is None or bool(claims_re.search(_first_text(req_body or {}))))
                    and not (said and said in put_texts))
    for i, (_, op) in enumerate(w.out):
        op.step = i
    return {"timed": w.out, "calls": w.timing, "pairs": pairs}


def load_capture_timed(path: str, **kw) -> List[Tuple[int, Op]]:
    """(timestamp ns, op) in stream order."""
    return load_capture_detail(path, **kw)["timed"]


def load_capture(path: str, **kw) -> List[Op]:
    return [op for _, op in load_capture_timed(path, **kw)]


def read_ops(ops: Iterable[Op]) -> List[Op]:
    """The ops the hosted read accepts (gaps removed), renumbered."""
    out = [Op(o.op, o.kind, o.key, value=o.value, to=o.to, ok=o.ok, refs=list(o.refs), source=o.source)
           for o in ops if o.op != GAP]
    for i, o in enumerate(out):
        o.step = i
    return out
