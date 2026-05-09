from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import time

from .core import Orchestrator
from .process import AgentProcess
from .scenario import Scenario, ScenarioAgent


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def build_scenario_id(name: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{name}-{stamp}"


@dataclass
class AgentRunSummary:
    id: str
    name: str | None
    manifest_path: str
    depends_on: list[str]
    launch_when: str
    launched: bool
    skipped: bool
    skipped_reason: str | None
    state: str
    exit_code: int | None
    started_at: str | None
    finished_at: str | None
    duration_sec: float | None
    agent_id: str | None
    pid: int | None


@dataclass
class ScenarioRunSummary:
    scenario_name: str
    scenario_id: str
    status: str
    started_at: str
    finished_at: str
    duration_sec: float
    launched_agents: int
    skipped_agents: int
    failed_agents: int
    agents: list[AgentRunSummary]

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class ScenarioRunner:
    def __init__(self, orchestrator: Orchestrator, *, poll_interval: float = 0.1):
        self._orchestrator = orchestrator
        self._poll_interval = poll_interval

    def run(self, scenario: Scenario) -> ScenarioRunSummary:
        scenario_started_at = utc_now()
        scenario_started_monotonic = time.time()
        scenario_id = build_scenario_id(scenario.name)

        pending = list(scenario.agents)
        running: dict[str, tuple[ScenarioAgent, AgentProcess, float]] = {}
        summaries: dict[str, AgentRunSummary] = {}

        while pending or running:
            ready = self._ready_agents(pending, summaries)
            if ready:
                for agent in ready:
                    pending.remove(agent)
                    manifest = agent.load_manifest()
                    process = self._orchestrator.launch_direct(
                        manifest,
                        scenario_id=scenario_id,
                    )
                    launched_at = time.time()
                    running[agent.id] = (agent, process, launched_at)
                    summaries[agent.id] = AgentRunSummary(
                        id=agent.id,
                        name=process.name,
                        manifest_path=str(agent.manifest_path),
                        depends_on=list(agent.depends_on),
                        launch_when=agent.launch_when,
                        launched=True,
                        skipped=False,
                        skipped_reason=None,
                        state=process.state.value,
                        exit_code=None,
                        started_at=utc_now(),
                        finished_at=None,
                        duration_sec=None,
                        agent_id=process.agent_id,
                        pid=process.pid,
                    )
                    if scenario.stagger_seconds > 0:
                        time.sleep(scenario.stagger_seconds)
                continue

            blocked = self._blocked_agents(pending, summaries)
            if blocked:
                for agent, reason in blocked:
                    pending.remove(agent)
                    summaries[agent.id] = AgentRunSummary(
                        id=agent.id,
                        name=None,
                        manifest_path=str(agent.manifest_path),
                        depends_on=list(agent.depends_on),
                        launch_when=agent.launch_when,
                        launched=False,
                        skipped=True,
                        skipped_reason=reason,
                        state="skipped",
                        exit_code=None,
                        started_at=None,
                        finished_at=utc_now(),
                        duration_sec=None,
                        agent_id=None,
                        pid=None,
                    )
                continue

            completed_any = False
            for agent_id, (agent, process, launched_at) in list(running.items()):
                exit_code = process.wait(timeout=0)
                if exit_code is None and process.state.value not in {"stopped", "crashed"}:
                    continue

                summaries[agent_id] = AgentRunSummary(
                    id=agent.id,
                    name=process.name,
                    manifest_path=str(agent.manifest_path),
                    depends_on=list(agent.depends_on),
                    launch_when=agent.launch_when,
                    launched=True,
                    skipped=False,
                    skipped_reason=None,
                    state=process.state.value,
                    exit_code=exit_code,
                    started_at=summaries[agent_id].started_at,
                    finished_at=utc_now(),
                    duration_sec=round(time.time() - launched_at, 3),
                    agent_id=process.agent_id,
                    pid=process.pid,
                )
                del running[agent_id]
                completed_any = True

            if not completed_any:
                time.sleep(self._poll_interval)

        ordered = [summaries[agent.id] for agent in scenario.agents]
        finished_at = utc_now()
        duration_sec = round(time.time() - scenario_started_monotonic, 3)
        failed_agents = sum(
            1
            for summary in ordered
            if summary.state == "crashed" or (summary.exit_code not in (0, None))
        )
        skipped_agents = sum(1 for summary in ordered if summary.skipped)
        launched_agents = sum(1 for summary in ordered if summary.launched)
        status = "success" if failed_agents == 0 and skipped_agents == 0 else "failed"

        return ScenarioRunSummary(
            scenario_name=scenario.name,
            scenario_id=scenario_id,
            status=status,
            started_at=scenario_started_at,
            finished_at=finished_at,
            duration_sec=duration_sec,
            launched_agents=launched_agents,
            skipped_agents=skipped_agents,
            failed_agents=failed_agents,
            agents=ordered,
        )

    def _ready_agents(
        self,
        pending: list[ScenarioAgent],
        summaries: dict[str, AgentRunSummary],
    ) -> list[ScenarioAgent]:
        ready: list[ScenarioAgent] = []
        for agent in pending:
            if not agent.depends_on:
                ready.append(agent)
                continue
            dep_summaries = [summaries.get(dep_id) for dep_id in agent.depends_on]
            if any(summary is None for summary in dep_summaries):
                continue
            if agent.launch_when == "complete":
                ready.append(agent)
                continue
            if all(self._summary_succeeded(summary) for summary in dep_summaries):
                ready.append(agent)
        return ready

    def _blocked_agents(
        self,
        pending: list[ScenarioAgent],
        summaries: dict[str, AgentRunSummary],
    ) -> list[tuple[ScenarioAgent, str]]:
        blocked: list[tuple[ScenarioAgent, str]] = []
        for agent in pending:
            if not agent.depends_on or agent.launch_when != "success":
                continue
            dep_summaries = [summaries.get(dep_id) for dep_id in agent.depends_on]
            if any(summary is None for summary in dep_summaries):
                continue
            if any(not self._summary_succeeded(summary) for summary in dep_summaries):
                blocked.append((agent, "dependency_failed"))
        return blocked

    @staticmethod
    def _summary_succeeded(summary: AgentRunSummary) -> bool:
        return summary.launched and not summary.skipped and summary.state == "stopped" and summary.exit_code in (0, None)
