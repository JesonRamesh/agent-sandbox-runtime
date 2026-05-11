from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

from .core import Orchestrator
from .daemon import SOCKET_PATH
from .events import WS_URL_DEFAULT
from .log import configure as configure_logger, logger
from .manifest import ManifestError
from .runner import ScenarioRunner
from .scenario import ScenarioError, load_scenario


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orchestrator",
        description="Launch one or more sandboxed agents through the P4 orchestrator.",
    )
    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress orchestrator log output (warnings/errors still print)",
    )
    verbosity.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="emit DEBUG-level logs with timestamps",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="launch every manifest listed in a scenario YAML",
    )
    run_parser.add_argument("-f", "--file", required=True, help="scenario YAML path")
    run_parser.add_argument("--ws-url", default=WS_URL_DEFAULT, help="viewer relay URL")
    run_parser.add_argument(
        "--daemon-socket",
        default=SOCKET_PATH,
        help="daemon Unix socket path",
    )
    run_parser.add_argument(
        "--restart-on-crash",
        action="store_true",
        help="restart crashed agents up to --max-restarts",
    )
    run_parser.add_argument(
        "--max-restarts",
        type=int,
        default=3,
        help="restart cap when --restart-on-crash is enabled",
    )
    run_parser.add_argument(
        "--no-wait",
        action="store_true",
        help="launch immediately and return (only for scenarios with no dependencies)",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="print the final scenario summary as JSON",
    )
    run_parser.add_argument(
        "--summary-file",
        help="optional path to write the final scenario summary JSON",
    )

    validate_parser = subparsers.add_parser(
        "validate",
        help="validate a scenario YAML and every referenced manifest",
    )
    validate_parser.add_argument("-f", "--file", required=True, help="scenario YAML path")
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="print validation result as JSON",
    )

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.verbose:
        configure_logger(level=logging.DEBUG, verbose=True)
    elif args.quiet:
        configure_logger(level=logging.WARNING)
    else:
        configure_logger(level=logging.INFO)

    try:
        if args.command == "run":
            return _run_scenario(args)
        if args.command == "validate":
            return _validate_scenario(args)
    except (ScenarioError, ManifestError) as e:
        return _print_error(str(e), json_mode=getattr(args, "json", False))
    except Exception as e:  # pragma: no cover - final safety net for CLI UX
        return _print_error(str(e), json_mode=getattr(args, "json", False))

    parser.error(f"unknown command {args.command!r}")
    return 2


def _run_scenario(args) -> int:
    scenario = load_scenario(args.file)
    _validate_referenced_manifests(scenario)

    orchestrator = Orchestrator(
        ws_url=args.ws_url,
        daemon_socket=args.daemon_socket,
        restart_on_crash=args.restart_on_crash,
        max_restarts=args.max_restarts,
    )

    if args.no_wait:
        if scenario.has_dependencies:
            raise ScenarioError(
                "--no-wait is only supported for scenarios with no dependencies"
            )
        manifests = [agent.load_manifest() for agent in scenario.agents]
        scenario_id, launched = orchestrator.launch_many(
            manifests,
            scenario_id=scenario.name,
            stagger_seconds=scenario.stagger_seconds,
        )
        payload = {
            "scenario_name": scenario.name,
            "scenario_id": scenario_id,
            "status": "running",
            "launched_agents": [
                {
                    "id": agent_cfg.id,
                    "name": process.name,
                    "agent_id": process.agent_id,
                    "pid": process.pid,
                }
                for agent_cfg, process in zip(scenario.agents, launched)
            ],
        }
        _print_payload(payload, json_mode=args.json)
        return 0

    runner = ScenarioRunner(orchestrator)
    try:
        summary = runner.run(scenario)
    except KeyboardInterrupt:
        print("[scenario] interrupted, stopping all agents", flush=True)
        orchestrator.stop_all()
        return 130
    finally:
        orchestrator.stop_all()

    if args.summary_file:
        summary_path = Path(args.summary_file).resolve()
        summary_path.write_text(summary.to_json() + "\n", encoding="utf-8")

    _print_payload(summary.to_dict(), json_mode=args.json)
    return 0 if summary.status == "success" else 1


def _validate_scenario(args) -> int:
    scenario = load_scenario(args.file)
    manifests = _validate_referenced_manifests(scenario)
    payload = {
        "ok": True,
        "scenario_name": scenario.name,
        "description": scenario.description,
        "stagger_seconds": scenario.stagger_seconds,
        "agents": [
            {
                "id": agent.id,
                "manifest_path": str(agent.manifest_path),
                "manifest_name": manifest.name,
                "depends_on": list(agent.depends_on),
                "launch_when": agent.launch_when,
            }
            for agent, manifest in zip(scenario.agents, manifests)
        ],
    }
    _print_payload(payload, json_mode=args.json)
    return 0


def _validate_referenced_manifests(scenario):
    manifests = []
    for agent in scenario.agents:
        manifests.append(agent.load_manifest())
    return manifests


def _print_payload(payload: dict, *, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(payload, indent=2), flush=True)
        return
    if payload.get("status") == "running":
        print(
            f"[scenario] launched '{payload['scenario_name']}' as {payload['scenario_id']} "
            f"with {len(payload['launched_agents'])} running agent(s)",
            flush=True,
        )
        return
    if payload.get("ok") is True:
        print(
            f"[validate] scenario '{payload['scenario_name']}' is valid "
            f"with {len(payload['agents'])} agent(s)",
            flush=True,
        )
        return
    print(
        f"[scenario] '{payload['scenario_name']}' finished status={payload['status']} "
        f"launched={payload['launched_agents']} skipped={payload['skipped_agents']} "
        f"failed={payload['failed_agents']} duration={payload['duration_sec']}s",
        flush=True,
    )
    for agent in payload["agents"]:
        if agent["skipped"]:
            print(
                f"[scenario] agent '{agent['id']}' skipped reason={agent['skipped_reason']}",
                flush=True,
            )
            continue
        print(
            f"[scenario] agent '{agent['id']}' name={agent['name']} "
            f"state={agent['state']} exit_code={agent['exit_code']}",
            flush=True,
        )


def _print_error(message: str, *, json_mode: bool) -> int:
    if json_mode:
        print(json.dumps({"ok": False, "error": message}, indent=2), flush=True)
    else:
        print(f"[error] {message}", file=sys.stderr, flush=True)
    return 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
