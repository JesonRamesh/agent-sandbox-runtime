from __future__ import annotations
import threading
import time
import uuid
from pathlib import Path

from .daemon import DaemonClient, SOCKET_PATH
from .events import EventStreamer, WS_URL_DEFAULT
from .log import logger
from .manifest import AgentManifest, load_manifest
from .process import AgentProcess, AgentState


class Orchestrator:
    def __init__(
        self,
        ws_url: str | None = None,
        daemon_socket: str = SOCKET_PATH,
        restart_on_crash: bool = False,
        max_restarts: int = 3,
    ):
        self._agents: dict[str, AgentProcess] = {}
        self._lock = threading.Lock()
        self._streamer = EventStreamer(ws_url)
        self._daemon = DaemonClient(daemon_socket)
        self._restart_on_crash = restart_on_crash
        self._max_restarts = max_restarts
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    # --- public API ---

    def launch(self, manifest_path: str | Path) -> AgentProcess:
        return self.launch_direct(load_manifest(manifest_path))

    def launch_direct(self, manifest: AgentManifest, *, scenario_id: str | None = None) -> AgentProcess:
        with self._lock:
            existing = self._agents.get(manifest.name)
            if existing and existing.is_alive():
                raise RuntimeError(f"Agent '{manifest.name}' is already running")
            agent = AgentProcess(manifest, self._streamer, self._daemon, scenario_id=scenario_id)
            self._agents[manifest.name] = agent

        agent.start()
        id_info = f"agent_id={agent.agent_id}" if agent.agent_id else f"pid={agent.pid}"
        logger.info("launched '%s' %s", manifest.name, id_info)
        return agent

    def launch_many(
        self,
        manifests: list[AgentManifest | str | Path],
        *,
        scenario_id: str | None = None,
        stagger_seconds: float = 0.0,
    ) -> tuple[str, list[AgentProcess]]:
        scenario = scenario_id or self._build_scenario_id()
        launched: list[AgentProcess] = []
        for item in manifests:
            manifest = load_manifest(item) if isinstance(item, (str, Path)) else item
            launched.append(self.launch_direct(manifest, scenario_id=scenario))
            if stagger_seconds > 0:
                time.sleep(stagger_seconds)
        return scenario, launched

    def stop(self, name: str):
        with self._lock:
            agent = self._agents.get(name)
        if not agent:
            raise KeyError(f"No agent named '{name}'")
        agent.stop()
        logger.info("stopped '%s'", name)

    def stop_all(self):
        with self._lock:
            names = list(self._agents.keys())
        for name in names:
            try:
                self.stop(name)
            except KeyError:
                # Agent removed concurrently — nothing to do.
                continue
            except Exception as exc:
                # Don't let a single transient stop failure abort the rest.
                # Log loudly so a real daemon-side bug surfaces.
                logger.warning("stop '%s' failed: %s", name, exc)

    def list_agents(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "name": a.name,
                    "agent_id": a.agent_id,
                    "pid": a.pid,
                    "state": a.state.value,
                    "uptime": round(time.time() - a.started_at, 1) if a.started_at else None,
                    "allowed_hosts": a.manifest.allowed_hosts,
                }
                for a in self._agents.values()
            ]

    def wait_for(
        self,
        name: str,
        timeout: float | None = None,
        *,
        cancel_event: threading.Event | None = None,
    ) -> int | None:
        with self._lock:
            agent = self._agents.get(name)
        if not agent:
            raise KeyError(f"No agent named '{name}'")
        return agent.wait(timeout=timeout, cancel_event=cancel_event)

    # --- internal ---

    def _monitor_loop(self):
        while True:
            time.sleep(2)
            with self._lock:
                agents = list(self._agents.values())
            for agent in agents:
                if (
                    agent.state == AgentState.CRASHED
                    and self._restart_on_crash
                    and agent._restart_count < self._max_restarts
                ):
                    agent._restart_count += 1
                    logger.info(
                        "restarting '%s' (attempt %d/%d)",
                        agent.name,
                        agent._restart_count,
                        self._max_restarts,
                    )
                    agent.start()

    def _build_scenario_id(self) -> str:
        return f"scn_{uuid.uuid4().hex[:12]}"
