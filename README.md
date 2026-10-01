# fathom-openshell

Capture what an agent running in an [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandbox sends to its
model and to the services it writes to, next to OpenShell's own delivery record, without changing the agent.

**The joined read is live.** `fathom_openshell.read --join` sends the model traffic together with the sandbox's delivery
record, and the hosted read (0.6.0) lines them up, so a write the agent believed it made but whose delivery OpenShell
denied, or never saw, counts as a write that did not land. Without `--join` the read covers the model traffic alone.
A sandbox whose delivery record is incomplete (a dropped watch stream, a middleware that failed open) is refused rather
than read on partial evidence.

## What it captures

- **Model traffic and writes, through the supervisor middleware hook.** `fathom_openshell.middleware` is a
  supervisor middleware (RFC 0009) that allows every request unchanged and writes one JSON line per request and
  one per response to `<capture-dir>/<sandbox_id>/http_capture.jsonl`: method, host, path, timestamps, the body
  (parsed when it is JSON; SSE streams reassembled into one message), and a stub line with a reason whenever
  OpenShell offers headers only or a body ends early. Register it with `on_error: fail_open`, bound to the
  endpoints you want to see.
- **The delivery record, through `WatchSandbox`.** `fathom_openshell.stream` follows one sandbox's watch stream
  and writes every log line, OCSF included, to `<capture-dir>/<sandbox>/ocsf_stream.jsonl`, ending with a status
  line that says whether the record is complete (stream warnings, out-of-range cursors and unrecovered
  disconnects mark it incomplete).

```
python -m fathom_openshell.middleware --port 50051 --capture-dir captures
python -m fathom_openshell.stream --sandbox my-sandbox --capture-dir captures --until-deleted
```

## What the adapters emit

- `adapters.chat_completions` turns a capture into an ordered list of ops: each tool call, each tool result paired
  to its call, each write that landed (with its values), each write that was refused, each claim the agent makes
  in a final message, and a gap op wherever the capture could not see a body.
- `adapters.responses` reads OpenAI Responses API traffic (as Codex sends it) into the same shape, so both wire
  formats produce the same ops.
- `adapters.ocsf` turns the watch stream into delivery ops (allowed, denied, refused, per destination) and marks
  the record incomplete when OpenShell reports a middleware that failed open.

Which keys count as facts and which lines in a written file record them is configuration (`FATHOM_FACTS`,
`FATHOM_KIND`, `FATHOM_WRITES`, `FATHOM_COMMIT_CALLS`), not code.

## Sending ops to the hosted read

```
pip install fathom-read
python -m fathom_openshell.read captures/<sandbox_id>
```

`fathom_openshell.read` prints the op counts for both files and sends the model-traffic ops to the hosted read
(`FATHOM_API_KEY`, or the demo key with its daily limit; get a free key with `fathom key you@example.com`).

The joined read, for one sandbox or several (a multi-agent run is read as one merged history):

```
python -m fathom_openshell.read captures/<sandbox_id> [captures/<other_sandbox_id> ...] --join \
    --tool-map '{"exec_command": "PUT api.github.com:443/repos/"}'
```

The tool map says where each tool writes (`[METHOD ]host:port[/path]`), so a tool's result can be matched to its
delivery; `FATHOM_TOOL_MAP` works too. Each call's arguments go with the request, so when an agent runs several writes
to one destination at once, each call is matched to the deliveries for the path it names (hosted read 0.6.1). The
response adds a join block after the findings: the record's status, the per-call delivery status (delivered, denied,
absent, or no_map for a tool with no destination), and the steps read as writes that did not land. It exits 3 when a
record is incomplete.

"Delivered" is OpenShell's decision to let a request through; whether the destination accepted the write (a 201, or a
409 refusal) comes from the captured response, not from the join, so delivered is not landed.

## What to expect from OpenShell 0.1.2

Observed with the Homebrew build and the Docker driver:

- The middleware's `RequestContext.originating_process` arrives empty (binary "", pid 0).
- The gateway calls `Describe` on every registered middleware at startup, and policy creation calls
  `ValidateConfig`: a registered middleware that is down stops the gateway from starting and rejects new policies,
  whatever `on_error` says.
- Response-stage OCSF lines print `https://` for plain-http upstreams; key endpoints on host, port and path.
- The OCSF log file sits on a tmpfs inside the supervisor sidecar and is not reachable from the host; the watch
  stream is the way to read the record.
- OCSF event times precede the middleware's request time by a few milliseconds (a different clock, truncated to
  the millisecond).
- A policy republish (for example a new DNS mapping) closes connections in flight, before or after the request
  went upstream; clients see a connection reset (curl reports HTTP 000) even when the write landed.
- Opening a PTY needs `/dev/ptmx` and `/dev/pts` in the filesystem policy's `read_write`; without them `openpty` fails
  with EACCES (Codex's `tty` exec among them).
- Unprivileged user namespaces are unavailable (as in a plain `docker run`), so bubblewrap-based sandboxes, such as
  Codex's `workspace-write` mode, fail inside the sandbox.
- `openshell sandbox create --upload … -- <command>` is refused; create detached, upload, then exec.
- A watch stream ends when the sandbox enters DELETING.

## Layout

- `package/fathom_openshell/middleware.py`, `stream.py`, `read.py`
- `package/fathom_openshell/adapters/` (`chat_completions.py`, `responses.py`, `ocsf.py`)
- `package/fathom_openshell/_proto/`: Python generated from OpenShell's protos (Apache-2.0; see
  `VENDORED_FROM.txt`)

MIT license, except `_proto/` (Apache-2.0).


---

If the read caught something in your own run, a star on this repository helps other teams find it.
