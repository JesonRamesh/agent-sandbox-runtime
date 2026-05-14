"""Compatibility facade for repo-root imports and module execution."""

from importlib import import_module
import sys

from .orchestrator import (
    AgentManifest,
    AgentRunSummary,
    Orchestrator,
    Scenario,
    ScenarioAgent,
    ScenarioRunSummary,
    ScenarioRunner,
    emit_agent_output,
    emit_user_input,
    load_manifest,
    load_scenario,
    tool_tracer,
)

__all__ = [
    "Orchestrator",
    "AgentManifest",
    "AgentRunSummary",
    "Scenario",
    "ScenarioAgent",
    "ScenarioRunSummary",
    "ScenarioRunner",
    "emit_agent_output",
    "emit_user_input",
    "load_manifest",
    "load_scenario",
    "tool_tracer",
]

for _name in (
    "core",
    "daemon",
    "events",
    "log",
    "manifest",
    "process",
    "runner",
    "scenario",
    "tracer",
):
    _module = import_module(f".orchestrator.{_name}", __name__)
    sys.modules[f"{__name__}.{_name}"] = _module
    globals()[_name] = _module
