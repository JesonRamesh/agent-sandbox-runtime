from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .manifest import AgentManifest, load_manifest


class ScenarioError(ValueError):
    """Raised when a scenario file is malformed or internally inconsistent."""


@dataclass(frozen=True)
class ScenarioAgent:
    id: str
    manifest_path: Path
    depends_on: tuple[str, ...] = ()
    launch_when: str = "success"
    description: str = ""

    def load_manifest(self) -> AgentManifest:
        return load_manifest(self.manifest_path)


@dataclass(frozen=True)
class Scenario:
    name: str
    agents: tuple[ScenarioAgent, ...]
    stagger_seconds: float = 0.0
    description: str = ""

    @property
    def has_dependencies(self) -> bool:
        return any(agent.depends_on for agent in self.agents)

    def agent_ids(self) -> tuple[str, ...]:
        return tuple(agent.id for agent in self.agents)


def load_scenario(path: str | Path) -> Scenario:
    scenario_path = Path(path).resolve()
    try:
        with open(scenario_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise ScenarioError(f"scenario '{scenario_path}' not found") from e
    except OSError as e:
        raise ScenarioError(f"scenario '{scenario_path}' could not be read: {e}") from e
    except yaml.YAMLError as e:
        raise ScenarioError(f"scenario '{scenario_path}' is not valid YAML: {e}") from e

    if not isinstance(data, dict):
        raise ScenarioError(f"scenario '{scenario_path}' must be a YAML mapping")

    scenario_name = _parse_name(data.get("name"), scenario_path)
    description = _parse_description(data.get("description"), scenario_path)
    stagger_seconds = _parse_stagger_seconds(data.get("stagger_seconds", 0.0), scenario_path)
    agents = _parse_agents(data.get("agents"), scenario_path)
    _validate_graph(agents, scenario_path)

    return Scenario(
        name=scenario_name,
        description=description,
        agents=tuple(agents),
        stagger_seconds=stagger_seconds,
    )


def _parse_name(value, scenario_path: Path) -> str:
    if value is None:
        return scenario_path.stem
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(f"scenario '{scenario_path}' has an invalid 'name'")
    return value.strip()


def _parse_description(value, scenario_path: Path) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ScenarioError(f"scenario '{scenario_path}' has an invalid 'description'")
    return value.strip()


def _parse_stagger_seconds(value, scenario_path: Path) -> float:
    if not isinstance(value, (int, float)) or value < 0:
        raise ScenarioError(f"scenario '{scenario_path}' has an invalid 'stagger_seconds'")
    return float(value)


def _parse_agents(value, scenario_path: Path) -> list[ScenarioAgent]:
    if not isinstance(value, list) or not value:
        raise ScenarioError(f"scenario '{scenario_path}' must define a non-empty 'agents' list")

    base_dir = scenario_path.parent
    agents: list[ScenarioAgent] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ScenarioError(
                f"scenario '{scenario_path}' agent #{index + 1} must be a mapping"
            )

        agent_id = _parse_agent_id(item.get("id"), index, scenario_path)
        if agent_id in seen_ids:
            raise ScenarioError(
                f"scenario '{scenario_path}' declares duplicate agent id '{agent_id}'"
            )
        seen_ids.add(agent_id)

        manifest_value = item.get("manifest")
        if not isinstance(manifest_value, str) or not manifest_value.strip():
            raise ScenarioError(
                f"scenario '{scenario_path}' agent '{agent_id}' is missing 'manifest'"
            )

        depends_on = _parse_depends_on(item.get("depends_on", []), agent_id, scenario_path)
        launch_when = _parse_launch_when(item.get("launch_when", "success"), agent_id, scenario_path)
        description = _parse_agent_description(item.get("description", ""), agent_id, scenario_path)

        agents.append(
            ScenarioAgent(
                id=agent_id,
                manifest_path=(base_dir / manifest_value).resolve(),
                depends_on=depends_on,
                launch_when=launch_when,
                description=description,
            )
        )
    return agents


def _parse_agent_id(value, index: int, scenario_path: Path) -> str:
    if value is None:
        return f"agent-{index + 1}"
    if not isinstance(value, str) or not value.strip():
        raise ScenarioError(
            f"scenario '{scenario_path}' agent #{index + 1} has an invalid 'id'"
        )
    return value.strip()


def _parse_depends_on(value, agent_id: str, scenario_path: Path) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ScenarioError(
            f"scenario '{scenario_path}' agent '{agent_id}' has an invalid 'depends_on'"
        )
    deps: list[str] = []
    for dep in value:
        if not isinstance(dep, str) or not dep.strip():
            raise ScenarioError(
                f"scenario '{scenario_path}' agent '{agent_id}' has a blank dependency"
            )
        deps.append(dep.strip())
    return tuple(deps)


def _parse_launch_when(value, agent_id: str, scenario_path: Path) -> str:
    if not isinstance(value, str):
        raise ScenarioError(
            f"scenario '{scenario_path}' agent '{agent_id}' has an invalid 'launch_when'"
        )
    normalized = value.strip().lower()
    if normalized not in {"success", "complete"}:
        raise ScenarioError(
            f"scenario '{scenario_path}' agent '{agent_id}' has unsupported "
            f"launch_when '{value}' (expected 'success' or 'complete')"
        )
    return normalized


def _parse_agent_description(value, agent_id: str, scenario_path: Path) -> str:
    if not isinstance(value, str):
        raise ScenarioError(
            f"scenario '{scenario_path}' agent '{agent_id}' has an invalid 'description'"
        )
    return value.strip()


def _validate_graph(agents: list[ScenarioAgent], scenario_path: Path) -> None:
    ids = {agent.id for agent in agents}
    for agent in agents:
        if agent.id in agent.depends_on:
            raise ScenarioError(
                f"scenario '{scenario_path}' agent '{agent.id}' cannot depend on itself"
            )
        for dep in agent.depends_on:
            if dep not in ids:
                raise ScenarioError(
                    f"scenario '{scenario_path}' agent '{agent.id}' depends on unknown agent '{dep}'"
                )

    graph = {agent.id: agent.depends_on for agent in agents}
    visiting: set[str] = set()
    visited: set[str] = set()

    def dfs(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            raise ScenarioError(
                f"scenario '{scenario_path}' contains a dependency cycle involving '{node}'"
            )
        visiting.add(node)
        for dep in graph[node]:
            dfs(dep)
        visiting.remove(node)
        visited.add(node)

    for agent in agents:
        dfs(agent.id)
