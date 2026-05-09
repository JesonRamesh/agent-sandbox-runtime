from __future__ import annotations
import os
import subprocess
import threading
import time
import uuid
from enum import Enum
from .manifest import AgentManifest
from .events import (
    EventStreamer,
    parse_agent_output_line,
    parse_tool_call_line,
    parse_tool_result_line,
    parse_user_input_line,
)


class AgentState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPED = "stopped"
    CRASHED = "crashed"


class AgentProcess:
    def __init__(self, manifest: AgentManifest, streamer: EventStreamer, daemon=None, scenario_id: str | None = None):
        self.manifest = manifest
        self.streamer = streamer
        self._daemon = daemon
        self._scenario_id = scenario_id
        self.state = AgentState.PENDING
        self._proc: subprocess.Popen | None = None
        self._daemon_pid: int | None = None
        self._agent_id: str | None = None
        self._session_id: str | None = None
        self._restart_count = 0
        self.started_at: float | None = None
        self._exit_code: int | None = None
        self._done = threading.Event()
        self._stream_stop: threading.Event | None = None

    @property
    def pid(self) -> int | None:
        if self._proc:
            return self._proc.pid
        return self._daemon_pid

    @property
    def agent_id(self) -> str | None:
        return self._agent_id

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def scenario_id(self) -> str | None:
        return self._scenario_id

    @property
    def name(self) -> str:
        return self.manifest.name

    def start(self) -> None:
        if self._stream_stop is not None:
            self._stream_stop.set()
        self.state = AgentState.RUNNING
        self.started_at = time.time()
        self._session_id = self._build_session_id()
        self._exit_code = None
        self._done = threading.Event()
        self._daemon_pid = None
        if self._daemon and self._daemon._available:
            self._agent_id = self._daemon.run_agent(self.manifest)
            if self._agent_id:
                self._stream_stop = threading.Event()
                threading.Thread(target=self._watch_daemon_events, daemon=True).start()
                self.streamer.emit(
                    self.name,
                    "session_start",
                    {
                        "launch_mode": "daemon",
                        "command": self.manifest.command,
                        "allowed_hosts": self.manifest.allowed_hosts,
                        "mode": self.manifest.mode,
                    },
                    session_id=self._session_id,
                    scenario_id=self._scenario_id,
                    agent_id=self._agent_id,
                )
                print(f"[orchestrator] '{self.name}' running in daemon sandbox (id={self._agent_id})", flush=True)
                # Daemon mode now tracks lifecycle via StreamEvents. If the daemon
                # emits agent.stdout / agent.stderr in a newer build, we forward
                # those lines through the same event parsing path as local mode.
                return
        self._agent_id = None
        self._stream_stop = None
        self._start_local()

    def _start_local(self):
        """Fallback: spawn directly when daemon is unavailable (stub / local dev)."""
        env = {**os.environ, **self.manifest.env}
        self._proc = subprocess.Popen(
            self.manifest.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        self.streamer.emit(
            self.name,
            "session_start",
            {
                "launch_mode": "local",
                "command": self.manifest.command,
                "allowed_hosts": self.manifest.allowed_hosts,
                "mode": self.manifest.mode,
                "pid": self.pid,
            },
            session_id=self._session_id,
            scenario_id=self._scenario_id,
        )
        threading.Thread(target=self._read_output, daemon=True).start()

    def stop(self):
        if self._agent_id and self._daemon:
            self._daemon.stop_agent(self._agent_id)
            if self._stream_stop is not None:
                self._stream_stop.set()
        elif self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self.state = AgentState.STOPPED
        self._done.set()

    def is_alive(self) -> bool:
        if self._agent_id:
            return self.state == AgentState.RUNNING
        return self._proc is not None and self._proc.poll() is None

    def wait(self, timeout: float | None = None) -> int | None:
        if self._proc:
            return self._proc.wait(timeout=timeout)
        if self._agent_id:
            finished = self._done.wait(timeout=timeout)
            return self._exit_code if finished else None
        return None

    def _build_session_id(self) -> str:
        return f"{self.name}-{uuid.uuid4().hex[:12]}"

    def _read_output(self):
        for line in self._proc.stdout:
            line = line.rstrip()
            print(f"[{self.name}] {line}", flush=True)
            self._emit_line_events(line)
        rc = self._proc.wait()
        self._exit_code = rc
        if rc != 0:
            self.state = AgentState.CRASHED
            self.streamer.emit(
                self.name,
                "crashed",
                {"exit_code": rc},
                session_id=self._session_id,
                scenario_id=self._scenario_id,
                agent_id=self._agent_id,
            )
        else:
            self.state = AgentState.STOPPED
            self.streamer.emit(
                self.name,
                "stopped",
                {"exit_code": rc},
                session_id=self._session_id,
                scenario_id=self._scenario_id,
                agent_id=self._agent_id,
            )
        self._done.set()

    def _emit_line_events(self, line: str) -> None:
        self.streamer.emit(
            self.name,
            "stdout",
            {"line": line},
            session_id=self._session_id,
            scenario_id=self._scenario_id,
            agent_id=self._agent_id,
        )
        user_input = parse_user_input_line(line)
        if user_input:
            self.streamer.emit(
                self.name,
                "user_input",
                user_input,
                session_id=self._session_id,
                scenario_id=self._scenario_id,
                agent_id=self._agent_id,
            )
        elif line.startswith("[TOOL]"):
            self.streamer.emit(
                self.name,
                "tool_call",
                parse_tool_call_line(line),
                session_id=self._session_id,
                scenario_id=self._scenario_id,
                agent_id=self._agent_id,
            )
        elif line.startswith("[RESULT]"):
            self.streamer.emit(
                self.name,
                "tool_result",
                parse_tool_result_line(line),
                session_id=self._session_id,
                scenario_id=self._scenario_id,
                agent_id=self._agent_id,
            )
        else:
            agent_output = parse_agent_output_line(line)
            if agent_output:
                self.streamer.emit(
                    self.name,
                    "agent_output",
                    agent_output,
                    session_id=self._session_id,
                    scenario_id=self._scenario_id,
                    agent_id=self._agent_id,
                )

    def _watch_daemon_events(self) -> None:
        if not self._daemon or not self._agent_id:
            return
        self._daemon.stream_events(
            self._agent_id,
            self._handle_daemon_event,
            stop_event=self._stream_stop,
        )

    def _handle_daemon_event(self, event: dict) -> None:
        event_type = self._event_type(event)
        if not event_type or event_type.startswith("llm."):
            return
        details = event.get("details")
        if not isinstance(details, dict):
            details = event.get("data")
        if not isinstance(details, dict):
            details = {}

        if event_type == "agent.started":
            pid = event.get("pid")
            if isinstance(pid, int):
                self._daemon_pid = pid
            return

        if event_type in ("agent.stdout", "agent.stderr"):
            line = details.get("line")
            if isinstance(line, str) and line:
                print(f"[{self.name}] {line}", flush=True)
                self._emit_line_events(line)
            return

        if event_type == "agent.exited":
            self.state = AgentState.STOPPED
            self._exit_code = self._extract_exit_code(details)
            if self._stream_stop is not None:
                self._stream_stop.set()
            self._done.set()
            return

        if event_type == "agent.crashed":
            self.state = AgentState.CRASHED
            self._exit_code = self._extract_exit_code(details)
            if self._stream_stop is not None:
                self._stream_stop.set()
            self._done.set()

    def _event_type(self, event: dict) -> str:
        event_type = event.get("type")
        category = event.get("category")
        if isinstance(event_type, str) and "." in event_type:
            return event_type
        if isinstance(category, str) and isinstance(event_type, str):
            return f"{category}.{event_type}"
        return event_type if isinstance(event_type, str) else ""

    def _extract_exit_code(self, details: dict) -> int | None:
        exit_code = details.get("exit_code")
        return exit_code if isinstance(exit_code, int) else None
