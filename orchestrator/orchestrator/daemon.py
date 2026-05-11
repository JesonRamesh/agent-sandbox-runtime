"""
Sandbox daemon client — sends agent launch/stop requests to P2's daemon.

CONFIRMED INTERFACE (P2 response to interface_assumptions.md §2):
  Option B: daemon spawns the agent atomically into its cgroup+eBPF sandbox.
  No Popen() in the orchestrator. The daemon handles clone3+execve inside the
  cgroup via SysProcAttr.UseCgroupFD (Linux 5.7+) — zero race window.

PROTOCOL:
  Unix socket at /run/agent-sandbox.sock (mode 0600, root-owned)
  Length-prefixed JSON frames (4-byte big-endian length header).
  Full spec: api/proto.md

  RunAgent   → {"method": "RunAgent",   "params": {"manifest": <Manifest>}}
            ← {"ok": true, "result": {"agent_id": "agt_xxxxxxxx"}}

  StopAgent  → {"method": "StopAgent",  "params": {"agent_id": "agt_..."}}
            ← {"ok": true}

  ListAgents → {"method": "ListAgents", "params": {}}
            ← {"ok": true, "result": {"agents": [...]}}

  StreamEvents → {"method": "StreamEvents", "params": {"agent_id": "agt_..."}}
              ← persistent stream of per-event JSON frames

  IngestEvent → {"method": "IngestEvent", "params": {
                   "agent_id": "agt_...",
                   "event": {"type": "llm.<subtype>", "ts": "<RFC3339Nano>", "details": {...}}
                 }}
             ← {"ok": true, "result": {}}
  event.type MUST be prefixed "llm." — daemon rejects anything else with INVALID_MANIFEST.
  P4 owns the details subschema. See INTERFACES §3.2.

  Also available via ws://127.0.0.1:7443/events if WebSocket transport preferred.

STATUS: stub. When daemon socket is absent, logs intent and continues in local mode.
"""
from __future__ import annotations
import json
import os
import socket
import struct
import threading
from datetime import datetime, timezone
from .log import logger
from .manifest import AgentManifest


SOCKET_PATH = os.environ.get("AGENT_SANDBOX_SOCKET", "/run/agent-sandbox.sock")


class DaemonClient:
    def __init__(self, socket_path: str = SOCKET_PATH):
        self._path = socket_path
        # _was_available_at_startup is set once and never changes; it lets us
        # distinguish "daemon was never there → fall back to local mode" from
        # "daemon was reachable then vanished → real bug, log loudly".
        self._was_available_at_startup = self._probe()
        self._available = self._was_available_at_startup

    def _probe(self) -> bool:
        if not hasattr(socket, "AF_UNIX"):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self._path)
            s.close()
            return True
        except OSError:
            return False

    @property
    def disappeared(self) -> bool:
        """True if the daemon was reachable at startup but is no longer.

        Callers should treat this as a serious condition: agents started in
        daemon mode now have no enforcement plane to talk to. Fresh launches
        will silently fall back to local mode unless callers refuse.
        """
        return self._was_available_at_startup and not self._available

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        """Read exactly n bytes or raise ConnectionError on early EOF."""
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError(
                    f"daemon closed connection after {len(buf)}/{n} bytes"
                )
            buf.extend(chunk)
        return bytes(buf)

    def _rpc(self, method: str, params: dict) -> dict | None:
        if not self._available:
            label = (params.get("manifest") or {}).get("name") or params.get("agent_id", "")
            logger.debug("daemon-stub: %s %s", method, label)
            return None
        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self._path)
            payload = json.dumps({"method": method, "params": params}).encode()
            s.sendall(struct.pack(">I", len(payload)) + payload)
            length = struct.unpack(">I", self._recv_exact(s, 4))[0]
            resp = json.loads(self._recv_exact(s, length))
            if not resp.get("ok"):
                err = resp.get("error", {})
                logger.warning(
                    "daemon %s error %s: %s",
                    method,
                    err.get("code", "?"),
                    err.get("message", resp),
                )
            return resp
        except (OSError, ConnectionError, struct.error, json.JSONDecodeError) as e:
            # A failed RPC after the daemon was previously reachable means
            # it has crashed or been restarted. Mark unavailable so the
            # orchestrator can detect the drop via .disappeared rather than
            # silently degrading new launches to local (unsandboxed) mode.
            if self._available and isinstance(e, (OSError, ConnectionError)):
                self._available = self._probe()
            if self.disappeared:
                logger.error(
                    "daemon RPC %s failed and daemon socket %s is no longer reachable: %s",
                    method,
                    self._path,
                    e,
                )
            else:
                logger.warning("daemon RPC %s failed: %s", method, e)
            return None
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    def run_agent(self, manifest: AgentManifest) -> str | None:
        """Launch agent in sandbox. Returns opaque agent_id, or None if daemon unavailable."""
        manifest_dict = {
            "name": manifest.name,
            "command": manifest.command,
            "mode": manifest.mode,
            "allowed_hosts": manifest.allowed_hosts,
            "allowed_paths": manifest.allowed_paths,
            "allowed_bins": manifest.allowed_bins,
            "forbidden_caps": manifest.forbidden_caps,
            "env": manifest.env,
        }
        if manifest.working_dir:
            manifest_dict["working_dir"] = manifest.working_dir
        resp = self._rpc("RunAgent", {"manifest": manifest_dict})
        if resp and resp.get("ok"):
            return resp["result"]["agent_id"]
        return None

    def stop_agent(self, agent_id: str) -> bool:
        resp = self._rpc("StopAgent", {"agent_id": agent_id})
        return resp is None or resp.get("ok", False)

    def list_agents(self) -> list:
        resp = self._rpc("ListAgents", {})
        if resp and resp.get("ok"):
            return resp["result"]["agents"]
        return []

    def stream_events(
        self,
        agent_id: str,
        on_event,
        *,
        stop_event: threading.Event | None = None,
    ) -> None:
        """Subscribe to daemon events for one agent and invoke on_event(event)."""
        if not self._available:
            return
        s = None
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(self._path)
            payload = json.dumps({
                "method": "StreamEvents",
                "params": {"agent_id": agent_id},
            }).encode()
            s.sendall(struct.pack(">I", len(payload)) + payload)
            while not (stop_event and stop_event.is_set()):
                frame = self._read_stream_frame(s, stop_event)
                if frame is None:
                    return
                if not frame.get("ok"):
                    err = frame.get("error", {})
                    logger.warning(
                        "daemon StreamEvents error %s: %s",
                        err.get("code", "?"),
                        err.get("message", frame),
                    )
                    return
                event = frame.get("result")
                if isinstance(event, dict) and isinstance(event.get("event"), dict):
                    event = event["event"]
                if isinstance(event, dict):
                    on_event(event)
        except OSError as e:
            if not (stop_event and stop_event.is_set()):
                logger.warning("daemon StreamEvents failed: %s", e)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass

    def _read_stream_frame(
        self,
        sock: socket.socket,
        stop_event: threading.Event | None = None,
    ) -> dict | None:
        try:
            header = self._recv_exact_stream(sock, 4, stop_event)
            if header is None:
                return None
            length = struct.unpack(">I", header)[0]
            body = self._recv_exact_stream(sock, length, stop_event)
            if body is None:
                return None
            return json.loads(body)
        except (ConnectionError, struct.error, json.JSONDecodeError) as e:
            if not (stop_event and stop_event.is_set()):
                logger.warning("daemon StreamEvents read failed: %s", e)
            return None

    def _recv_exact_stream(
        self,
        sock: socket.socket,
        n: int,
        stop_event: threading.Event | None = None,
    ) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            if stop_event and stop_event.is_set():
                return None
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                continue
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def ingest_event(self, agent_id: str, event_type: str, details: dict) -> bool:
        """Push an llm.* event into the daemon's unified pipeline (IngestEvent RPC).

        event_type must be prefixed 'llm.' (e.g. 'llm.tool_call', 'llm.completion').
        Called from the orchestrator's model loop wrapper in daemon mode; not used in
        stub/local mode where events go directly to P5 via EventStreamer/WebSocket.
        """
        if not event_type.startswith("llm."):
            raise ValueError(f"IngestEvent type must be prefixed 'llm.', got '{event_type}'")
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
        resp = self._rpc("IngestEvent", {
            "agent_id": agent_id,
            "event": {"type": event_type, "ts": ts, "details": details},
        })
        return resp is None or resp.get("ok", False)
