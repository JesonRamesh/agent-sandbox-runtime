from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import threading
import tempfile
import time
import uuid
from enum import Enum
from .log import logger
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
        self._log_path: Path | None = None
        self._log_lock = threading.Lock()
        self._stream_threads: list[threading.Thread] = []

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
        self._log_path = self._build_log_path()
        self._stream_threads = []
        if self._daemon and self._daemon._available:
            manifest = self.manifest
            model_vars = manifest.model_env_vars()
            if model_vars:
                from dataclasses import replace
                manifest = replace(manifest, env={**model_vars, **manifest.env})
            self._agent_id = self._daemon.run_agent(manifest)
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
                logger.info("'%s' running in daemon sandbox (id=%s)", self.name, self._agent_id)
                return
        self._agent_id = None
        self._stream_stop = None
        if self._daemon is not None and getattr(self._daemon, "disappeared", False):
            # Daemon was reachable when the Orchestrator was constructed but
            # is now gone. Falling back to local mode here means the agent
            # runs without kernel enforcement — the operator must know.
            logger.error(
                "daemon was reachable at startup but is now unreachable; "
                "'%s' will run locally WITHOUT sandbox enforcement",
                self.name,
            )
        self._start_local()

    def _start_local(self):
        """Fallback: spawn directly when daemon is unavailable (stub / local dev)."""
        env = {**os.environ, **self.manifest.model_env_vars(), **self.manifest.env}
        cwd = None
        working_dir = getattr(self.manifest, "working_dir", None)
        if working_dir:
            os.makedirs(working_dir, exist_ok=True)
            cwd = working_dir
        self._proc = subprocess.Popen(
            self.manifest.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
            cwd=cwd,
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
        stdout_thread = threading.Thread(
            target=self._read_output_stream,
            args=(self._proc.stdout, "stdout"),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=self._read_output_stream,
            args=(self._proc.stderr, "stderr"),
            daemon=True,
        )
        self._stream_threads = [stdout_thread, stderr_thread]
        stdout_thread.start()
        stderr_thread.start()
        threading.Thread(target=self._watch_local_exit, daemon=True).start()

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

    def wait(
        self,
        timeout: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> int | None:
        if cancel_event is None:
            if self._proc:
                finished = self._done.wait(timeout=timeout)
                return self._exit_code if finished else None
            if self._agent_id:
                finished = self._done.wait(timeout=timeout)
                return self._exit_code if finished else None
            return None

        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if cancel_event.is_set():
                return None
            if self._proc:
                exit_code = self._proc.poll()
                if exit_code is not None:
                    return exit_code
            elif self._agent_id and self._done.is_set():
                return self._exit_code
            elif not self._proc and not self._agent_id:
                return None

            if deadline is not None and time.monotonic() >= deadline:
                return None

            slice_timeout = 0.1
            if deadline is not None:
                slice_timeout = min(slice_timeout, max(0.0, deadline - time.monotonic()))
            if self._agent_id:
                self._done.wait(timeout=slice_timeout)
            else:
                time.sleep(slice_timeout)

    def _build_session_id(self) -> str:
        return f"{self.name}-{uuid.uuid4().hex[:12]}"

    def _read_output_stream(self, pipe, raw_event_type: str) -> None:
        if pipe is None:
            return
        for line in pipe:
            line = line.rstrip()
            print(f"[{self.name}] {line}", flush=True)
            self._write_agent_log(raw_event_type, line)
            self._emit_line_events(line, raw_event_type=raw_event_type)
        try:
            pipe.close()
        except Exception:
            pass

    def _watch_local_exit(self) -> None:
        rc = self._proc.wait()
        for thread in self._stream_threads:
            thread.join(timeout=1)
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

    # event types that get forwarded to the daemon's unified pipeline as
    # llm.* IngestEvents (in daemon mode). "stdout" is intentionally excluded
    # — the daemon already emits agent.stdout for every line, so re-ingesting
    # would double the event volume and create a self-referential loop.
    _DAEMON_INGEST_TYPES = frozenset({
        "tool_call", "tool_result", "user_input", "agent_output", "injection_suspected",
    })

    def _emit_line_events(self, line: str, *, raw_event_type: str = "stdout") -> None:
        self._emit(raw_event_type, {"line": line})
        user_input = parse_user_input_line(line)
        if user_input:
            self._emit("user_input", user_input)
        elif line.startswith("[TOOL]"):
            self._emit("tool_call", parse_tool_call_line(line))
        elif line.startswith("[RESULT]"):
            self._emit("tool_result", parse_tool_result_line(line))
        else:
            agent_output = parse_agent_output_line(line)
            if agent_output:
                self._emit("agent_output", agent_output)

    def _emit(self, event_type: str, data: dict) -> None:
        """Fan an LLM-level event to P5 via the streamer and, in daemon mode,
        also push it into the daemon's pipeline so subscribers of the unified
        event stream (agentctl tail, alternate dashboards) see it too."""
        self.streamer.emit(
            self.name,
            event_type,
            data,
            session_id=self._session_id,
            scenario_id=self._scenario_id,
            agent_id=self._agent_id,
        )
        if event_type == "tool_result":
            heuristic = self._detect_injection_suspected(data)
            if heuristic:
                self._emit("injection_suspected", heuristic)
        if event_type not in self._DAEMON_INGEST_TYPES:
            return
        if not self._agent_id or self._daemon is None:
            return
        if not getattr(self._daemon, "_available", False):
            return
        try:
            self._daemon.ingest_event(self._agent_id, f"llm.{event_type}", data)
        except Exception as exc:  # daemon transient failure shouldn't break the agent
            logger.warning("ingest_event '%s' failed: %s", event_type, exc)

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
                raw_event_type = "stderr" if event_type == "agent.stderr" else "stdout"
                self._write_agent_log(raw_event_type, line)
                self._emit_line_events(line, raw_event_type=raw_event_type)
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

    def _build_log_path(self) -> Path:
        run_id = self._scenario_id or self._session_id or self.name
        root_override = os.environ.get("AGENT_SANDBOX_ORCH_LOG_DIR")
        if root_override:
            roots = [Path(root_override)]
        elif os.name == "nt":
            local_app_data = os.environ.get("LOCALAPPDATA")
            roots = []
            if local_app_data:
                roots.append(Path(local_app_data) / "agent-sandbox" / "orchestrator")
            roots.append(Path(tempfile.gettempdir()) / "agent-sandbox" / "orchestrator")
        else:
            roots = [
                Path.home() / ".cache" / "agent-sandbox" / "orchestrator",
                Path(tempfile.gettempdir()) / "agent-sandbox" / "orchestrator",
            ]

        for root in roots:
            path = root / run_id / f"{self.name}.log"
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                return path
            except OSError:
                continue
        raise OSError("could not create orchestrator log directory")

    def _write_agent_log(self, stream: str, line: str) -> None:
        if self._log_path is None:
            return
        try:
            with self._log_lock:
                with self._log_path.open("a", encoding="utf-8") as handle:
                    handle.write(f"[{stream}] {line}\n")
        except OSError as exc:
            logger.warning("agent log write failed for '%s': %s", self.name, exc)

    @staticmethod
    def _detect_injection_suspected(data: dict) -> dict | None:
        text = json.dumps(data, sort_keys=True).lower()
        patterns = (
            ("ignore previous instructions", 0.9, "tool result tried to override prior instructions"),
            ("ignore all previous instructions", 0.9, "tool result tried to override prior instructions"),
            ("reveal your system prompt", 0.85, "tool result requested disclosure of hidden instructions"),
            ("send me your api key", 0.95, "tool result requested secret exfiltration"),
            ("exfiltrate", 0.8, "tool result used explicit exfiltration language"),
            ("fetch_url(", 0.7, "tool result appears to contain tool-call instructions"),
        )
        for phrase, confidence, reason in patterns:
            if phrase in text:
                return {
                    "confidence": confidence,
                    "reason": reason,
                    "matched_phrase": phrase,
                    "source_event": "tool_result",
                }
        return None
