"""
Event streamer — pushes LLM-level events to P5's process viewer.

CONFIRMED INTERFACE (P5 response to interface_assumptions.md §3):
  - Transport: WebSocket. P5 owns the server at ws://localhost:8765.
    Orchestrator is the client. Pass --ws-url to override.
  - Kernel-level events: P2 streams these to P5 directly. We only send LLM-level.
  - tool_call data: structured (tool name + args extracted), raw line also included.

Event envelope (NDJSON):
  {"agent": "<name>", "type": "<type>", "ts": <unix float>, "data": {...},
   "session_id": "<run id>", "scenario_id": "<multi-agent run id?>",
   "agent_id": "<daemon id?>"}

Event types emitted:
  session_start — orchestrator launched an agent  data: {"launch_mode": "...", ...}
  user_input  — agent received user task       data: {"text": "..."}
  stdout      — every line of agent output     data: {"line": "..."}
  tool_call   — line starts with [TOOL]        data: {"raw": "...", "tool": "...", "args": {...}}
  tool_result — line starts with [RESULT]      data: {"tool": "...", "ok": true|false, ...}
  agent_output — final assistant output        data: {"text": "..."}
  stopped     — agent exits 0                  data: {"exit_code": 0}
  crashed     — agent exits non-zero           data: {"exit_code": N}
"""
from __future__ import annotations
import json
import re
import time


WS_URL_DEFAULT = "ws://localhost:8765"

_TOOL_CALL_RE = re.compile(r'\[TOOL\]\s+(\w+)\s+called with:\s+(.+)')
_RESULT_RE = re.compile(r'\[RESULT\]\s+(.+)')
_USER_RE = re.compile(r'\[USER\]\s+(.+)')
_AGENT_RE = re.compile(r'\[AGENT\]\s+(.+)')


def parse_tool_call_line(raw: str) -> dict:
    """Parse '[TOOL] <name> called with: <args>' into structured data for P5."""
    m = _TOOL_CALL_RE.match(raw)
    if not m:
        return {"raw": raw}
    tool_name, args_str = m.group(1), m.group(2).strip()
    # fetch_url args are a bare URL string; other tools use raw_args as fallback
    args = {"url": args_str} if tool_name == "fetch_url" else {"raw_args": args_str}
    return {"raw": raw, "tool": tool_name, "args": args}


def parse_tool_result_line(raw: str) -> dict:
    """Parse '[RESULT] <json>' into structured data for P5 and logs."""
    m = _RESULT_RE.match(raw)
    if not m:
        return {"raw": raw}
    payload = m.group(1).strip()
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return {"raw": raw, "payload": payload}
    if isinstance(data, dict):
        data.setdefault("raw", raw)
        return data
    return {"raw": raw, "value": data}


def parse_user_input_line(raw: str) -> dict | None:
    m = _USER_RE.match(raw)
    if not m:
        return None
    return {"text": m.group(1).strip(), "raw": raw}


def parse_agent_output_line(raw: str) -> dict | None:
    m = _AGENT_RE.match(raw)
    if not m:
        return None
    return {"text": m.group(1).strip(), "raw": raw}


class EventStreamer:
    def __init__(self, ws_url: str | None = None):
        self._ws = None
        if ws_url:
            self._connect(ws_url)

    def _connect(self, url: str):
        try:
            import websocket
            self._ws = websocket.create_connection(url, timeout=3)
            print(f"[events] connected to {url}")
        except Exception as e:
            print(f"[events] WebSocket unavailable ({e}), logging locally")

    def emit(
        self,
        agent: str,
        event_type: str,
        data: dict,
        *,
        session_id: str | None = None,
        scenario_id: str | None = None,
        agent_id: str | None = None,
    ):
        event = {"agent": agent, "type": event_type, "ts": time.time(), "data": data}
        if session_id:
            event["session_id"] = session_id
        if scenario_id:
            event["scenario_id"] = scenario_id
        if agent_id:
            event["agent_id"] = agent_id
        if self._ws:
            try:
                self._ws.send(json.dumps(event))
                return
            except Exception:
                self._ws = None
        if event_type in ("session_start", "user_input", "tool_call", "tool_result", "agent_output", "crashed"):
            print(f"[events] {agent} -> {event_type}: {data}", flush=True)
