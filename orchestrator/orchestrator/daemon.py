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
from datetime import datetime, timezone
from .manifest import AgentManifest


SOCKET_PATH = os.environ.get("AGENT_SANDBOX_SOCKET", "/run/agent-sandbox.sock")


class DaemonClient:
    def __init__(self, socket_path: str = SOCKET_PATH):
        self._path = socket_path
        self._available = self._probe()

    def _probe(self) -> bool:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self._path)
            s.close()
            return True
        except OSError:
            return False

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        """Read exactly n bytes or raise ConnectionError on early EOF.

        socket.recv() may return fewer bytes than requested even on a
        well-behaved peer — TCP/Unix sockets only guarantee byte ordering,
        not message boundaries. The frame protocol is length-prefixed, so
        a single short recv corrupts every subsequent message; loop until
        we have everything.
        """
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
            print(f"[daemon-stub] {method} {label}")
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
                print(f"[daemon] {method} error {err.get('code', '?')}: {err.get('message', resp)}")
            return resp
        except (OSError, ConnectionError, struct.error, json.JSONDecodeError) as e:
            # Without struct.error / JSONDecodeError in this catch list the
            # outer caller saw a Python traceback on any short read and the
            # socket FD leaked. Now: log, return None, finally close.
            print(f"[daemon] RPC failed: {e}")
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
