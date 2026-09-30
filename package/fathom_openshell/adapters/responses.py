"""OpenAI Responses API traffic (as Codex 0.159.2 emits it) in the chat-completions adapter's terms.

Codex speaks only the Responses API (codex-rs/model-provider-info/src/lib.rs:104-129, wire_api = "responses"). Rather
than a second op mapping, this module translates each captured Responses request and response into the chat shape
chat_completions.py already reads, so both wire formats share one set of rules (FATHOM_* conventions, claims scope,
gap handling, tool-call pairing). chat_completions.load_capture_detail dispatches here for any request whose path
ends in /responses.

Request (ResponsesApiRequest, codex-rs/core/src/client.rs:989-1005): `instructions` becomes the first (system)
message; `input` items (codex-rs/protocol/src/models.rs, ResponseItem, tag "type"):
  message {role, content: [{type: input_text|output_text, text}]}  -> a user / assistant / system message
  function_call {call_id, name, arguments}                          -> an assistant message with one tool call
  custom_tool_call {call_id, name, input}                           -> the same, arguments = input
  local_shell_call {call_id, action}                                -> the same, name "local_shell", arguments = action
  function_call_output / custom_tool_call_output {call_id, output}  -> a tool message; output is a string or a list
                                                                       of content items (FunctionCallOutputPayload)
  anything else (reasoning, web_search_call, ...)                   -> skipped
  a call item directly after an assistant message (one response's output, split into items in the history) joins
  that message's tool_calls, as on the chat wire
Response: the `response.completed` event's `response.output` in the SSE stream (or a non-streamed JSON body with
`output`; failing both, the `response.output_item.done` items), with the same item mapping; output_text parts become
the assistant message text.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def _parts_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") in
                       ("input_text", "output_text", "text"))
    return ""


def _output_text(output: Any) -> str:
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        return "".join(p.get("text", "") for p in output if isinstance(p, dict))
    if isinstance(output, dict):
        return _output_text(output.get("content") or output.get("body") or "")
    return ""


def _call_msg(call_id: str, name: str, arguments: Any) -> Dict[str, Any]:
    args = arguments if isinstance(arguments, str) else json.dumps(arguments)
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": call_id, "type": "function", "function": {"name": name, "arguments": args}}]}


def item_to_message(it: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    t = it.get("type")
    if t == "message":
        return {"role": it.get("role") or "user", "content": _parts_text(it.get("content"))}
    if t == "function_call":
        return _call_msg(it.get("call_id") or it.get("id") or "", it.get("name") or "", it.get("arguments") or "")
    if t == "custom_tool_call":
        return _call_msg(it.get("call_id") or "", it.get("name") or "", it.get("input") or "")
    if t == "local_shell_call":
        return _call_msg(it.get("call_id") or it.get("id") or "", "local_shell", it.get("action") or {})
    if t in ("function_call_output", "custom_tool_call_output"):
        return {"role": "tool", "tool_call_id": it.get("call_id") or "", "content": _output_text(it.get("output"))}
    return None


def to_chat_request(body: Dict[str, Any]) -> Dict[str, Any]:
    """A Responses request body as {"messages": [...]} (instructions first)."""
    msgs: List[Dict[str, Any]] = []
    if body.get("instructions"):
        msgs.append({"role": "system", "content": str(body["instructions"])})
    inp = body.get("input")
    if isinstance(inp, str):
        msgs.append({"role": "user", "content": inp})
    for it in inp or [] if not isinstance(inp, str) else []:
        m = item_to_message(it) if isinstance(it, dict) else None
        if m is None:
            continue
        prev = msgs[-1] if msgs else None
        if m.get("tool_calls") and prev is not None and prev.get("role") == "assistant":
            # one response's output arrives in the next request's history as separate items (its text, then each call);
            # regroup them into one assistant message, the chat wire's shape, so the history copy matches the response
            # that carried it (same signature) and the text is read as beside its call
            prev["tool_calls"] = (prev.get("tool_calls") or []) + m["tool_calls"]
            continue
        msgs.append(m)
    return {"messages": msgs, "tools": body.get("tools")}


def _sse_events(raw: str) -> List[Dict[str, Any]]:
    out = []
    for block in (raw or "").split("\n\n"):
        data = "".join(line[5:].strip() for line in block.splitlines() if line.startswith("data:"))
        if not data or data == "[DONE]":
            continue
        try:
            out.append(json.loads(data))
        except ValueError:
            pass
    return out


def output_items(line: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """The response's output items from a captured response line, or None when they cannot be recovered."""
    body = line.get("body")
    if isinstance(body, dict) and isinstance(body.get("output"), list):          # non-streamed JSON response
        return body["output"]
    events = _sse_events(line.get("body_raw") or "")
    for ev in events:
        if ev.get("type") == "response.completed" and isinstance((ev.get("response") or {}).get("output"), list):
            return ev["response"]["output"]
    done = [ev["item"] for ev in events if ev.get("type") == "response.output_item.done" and isinstance(ev.get("item"), dict)]
    return done or None


def response_message(line: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One assistant message (text + tool_calls) from a Responses response line, or None."""
    items = output_items(line)
    if items is None:
        return None
    text, calls = [], []
    for it in items:
        m = item_to_message(it)
        if m is None:
            continue
        if m.get("tool_calls"):
            calls += m["tool_calls"]
        elif m.get("role") == "assistant":
            text.append(m.get("content") or "")
    return {"role": "assistant", "content": "".join(text) or None, "tool_calls": calls or None}
