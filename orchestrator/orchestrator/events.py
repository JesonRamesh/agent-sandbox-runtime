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
import queue
import re
import threading
import time

from .log import logger


WS_URL_DEFAULT = "ws://localhost:8765"
SENDER_NAME = "p4-orchestrator"

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
    request_id = None
    if " | request_id=" in args_str:
        args_str, request_id = args_str.rsplit(" | request_id=", 1)
        args_str = args_str.strip()
        request_id = request_id.strip() or None
    # fetch_url args are a bare URL string; other tools use raw_args as fallback
    args = {"url": args_str} if tool_name == "fetch_url" else {"raw_args": args_str}
    parsed = {"raw": raw, "tool": tool_name, "args": args}
    if request_id:
        parsed["request_id"] = request_id
    return parsed


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
    def __init__(
        self,
        ws_url: str | None = None,
        *,
        max_buffered_events: int = 256,
        reconnect_base_seconds: float = 0.5,
        reconnect_max_seconds: float = 5.0,
    ):
        self._ws = None
        self._ws_url = ws_url
        self._queue: queue.Queue[dict] | None = None
        self._stop = threading.Event()
        self._sender_thread: threading.Thread | None = None
        self._max_buffered_events = max_buffered_events
        self._reconnect_base_seconds = reconnect_base_seconds
        self._reconnect_max_seconds = reconnect_max_seconds
        self._drop_warnings = 0
        if ws_url:
            self._queue = queue.Queue(maxsize=max_buffered_events)
            self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
            self._sender_thread.start()

    def _connect(self, url: str) -> bool:
        try:
            import websocket
            self._ws = websocket.create_connection(url, timeout=3)
            self._ws.send(json.dumps({"role": "sender", "name": SENDER_NAME}))
            logger.info("connected to viewer relay at %s", url)
            return True
        except Exception as e:
            self._ws = None
            logger.warning("viewer relay unavailable (%s); falling back to local logging", e)
            return False

    def close(self) -> None:
        self._stop.set()
        if self._sender_thread is not None:
            self._sender_thread.join(timeout=1)
        self._close_socket()

    def _close_socket(self) -> None:
        if self._ws is None:
            return
        try:
            self._ws.close()
        except Exception:
            pass
        self._ws = None

    def _sender_loop(self) -> None:
        if self._queue is None or not self._ws_url:
            return

        pending: dict | None = None
        backoff = self._reconnect_base_seconds
        while not self._stop.is_set():
            if self._ws is None and not self._connect(self._ws_url):
                self._stop.wait(backoff)
                backoff = min(backoff * 2, self._reconnect_max_seconds)
                continue

            if pending is None:
                try:
                    pending = self._queue.get(timeout=0.25)
                except queue.Empty:
                    backoff = self._reconnect_base_seconds
                    continue

            try:
                self._ws.send(json.dumps(pending))
                pending = None
                backoff = self._reconnect_base_seconds
            except Exception as exc:
                logger.warning("viewer relay send failed: %s", exc)
                self._close_socket()
                self._stop.wait(backoff)
                backoff = min(backoff * 2, self._reconnect_max_seconds)

    def _enqueue(self, event: dict) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(event)
            return
        except queue.Full:
            pass

        try:
            dropped = self._queue.get_nowait()
        except queue.Empty:
            dropped = None
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            return

        self._drop_warnings += 1
        logger.warning(
            "viewer relay queue full; dropped oldest event type=%s agent=%s (drop_count=%d)",
            dropped.get("type") if isinstance(dropped, dict) else "?",
            dropped.get("agent") if isinstance(dropped, dict) else "?",
            self._drop_warnings,
        )

    @staticmethod
    def _should_log_locally(event_type: str) -> bool:
        return event_type in (
            "session_start",
            "user_input",
            "tool_call",
            "tool_result",
            "agent_output",
            "injection_suspected",
            "crashed",
        )

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
        if self._queue is not None:
            self._enqueue(event)
        if self._should_log_locally(event_type):
            logger.info("%s -> %s: %s", agent, event_type, data)
