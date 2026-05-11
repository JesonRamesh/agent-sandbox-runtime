from __future__ import annotations

import contextlib
import json
import io
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.cli import run as cli_run
from orchestrator.daemon import DaemonClient
from orchestrator.events import EventStreamer, parse_tool_call_line
from orchestrator.manifest import ManifestError, load_manifest
from orchestrator.process import AgentProcess, AgentState
from orchestrator.runner import ScenarioRunner
from orchestrator.scenario import ScenarioError, load_scenario


class RecordingStreamer:
    def __init__(self):
        self.events = []

    def emit(self, agent, event_type, data, **kwargs):
        self.events.append(
            {
                "agent": agent,
                "type": event_type,
                "data": data,
                "meta": kwargs,
            }
        )


class FakeDaemon:
    def __init__(self, events):
        self._available = True
        self._events = events
        self.stopped = []
        self.ingested: list[tuple[str, str, dict]] = []

    def run_agent(self, manifest):
        return "agt_test1234"

    def stop_agent(self, agent_id):
        self.stopped.append(agent_id)
        return True

    def stream_events(self, agent_id, on_event, *, stop_event=None):
        for event in self._events:
            if stop_event and stop_event.is_set():
                return
            on_event(event)

    def ingest_event(self, agent_id, event_type, details):
        if not event_type.startswith("llm."):
            raise ValueError(f"IngestEvent type must be prefixed 'llm.', got '{event_type}'")
        self.ingested.append((agent_id, event_type, details))
        return True


class EventParsingTests(unittest.TestCase):
    def test_parse_tool_call_line_extracts_request_id(self):
        parsed = parse_tool_call_line(
            "[TOOL] fetch_url called with: https://example.com | request_id=call_123"
        )
        self.assertEqual(parsed["tool"], "fetch_url")
        self.assertEqual(parsed["args"], {"url": "https://example.com"})
        self.assertEqual(parsed["request_id"], "call_123")

    def test_event_streamer_sends_sender_handshake(self):
        sent = []

        class FakeSocket:
            def send(self, payload):
                sent.append(json.loads(payload))

        fake_websocket = types.SimpleNamespace(
            create_connection=lambda url, timeout=3: FakeSocket()
        )
        original = sys.modules.get("websocket")
        sys.modules["websocket"] = fake_websocket
        try:
            EventStreamer("ws://localhost:8765")
        finally:
            if original is None:
                del sys.modules["websocket"]
            else:
                sys.modules["websocket"] = original

        self.assertEqual(
            sent[0],
            {"role": "sender", "name": "p4-orchestrator"},
        )


class ManifestTests(unittest.TestCase):
    def test_load_manifest_raises_clean_error_for_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.yaml"
            path.write_text("", encoding="utf-8")
            with self.assertRaises(ManifestError) as ctx:
                load_manifest(path)
        self.assertIn("is empty", str(ctx.exception))

    def test_load_manifest_invalid_yaml_includes_line_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            # Invalid: tab indentation in a block sequence makes PyYAML mark
            # the offending location.
            path.write_text("name: demo\ncommand:\n\t- python\n", encoding="utf-8")
            with self.assertRaises(ManifestError) as ctx:
                load_manifest(path)
        msg = str(ctx.exception)
        self.assertIn(str(path), msg)
        # path:line:col prefix means a colon-separated line and column appear
        # after the path. We don't pin exact numbers because PyYAML versions
        # differ — but the marker must be present.
        location_suffix = msg.split(str(path), 1)[1]
        self.assertRegex(location_suffix, r"^:\d+:\d+:")

    def test_load_manifest_raises_clean_error_for_missing_required_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("name: demo-agent\ncommand: ['python']\n", encoding="utf-8")
            with self.assertRaises(ManifestError) as ctx:
                load_manifest(path)
        self.assertIn("missing required field 'allowed_hosts'", str(ctx.exception))


class ScenarioTests(unittest.TestCase):
    def test_load_scenario_resolves_manifest_paths_relative_to_scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifests = root / "manifests"
            manifests.mkdir()
            manifest_path = manifests / "agent.yaml"
            manifest_path.write_text(
                "\n".join(
                    [
                        "name: agent-a",
                        "command: ['python', 'agent.py']",
                        "allowed_hosts: []",
                        "allowed_paths: []",
                    ]
                ),
                encoding="utf-8",
            )
            scenario_path = root / "scenario.yaml"
            scenario_path.write_text(
                "\n".join(
                    [
                        "name: test-scenario",
                        "stagger_seconds: 0.25",
                        "agents:",
                        "  - manifest: ./manifests/agent.yaml",
                    ]
                ),
                encoding="utf-8",
            )

            scenario = load_scenario(scenario_path)

        self.assertEqual(scenario.name, "test-scenario")
        self.assertEqual(scenario.stagger_seconds, 0.25)
        self.assertEqual(len(scenario.agents), 1)
        self.assertEqual(scenario.agents[0].manifest_path, manifest_path.resolve())
        self.assertEqual(scenario.agents[0].id, "agent-1")

    def test_load_scenario_rejects_unknown_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "agent.yaml"
            manifest_path.write_text(
                "\n".join(
                    [
                        "name: agent-a",
                        "command: ['python', 'agent.py']",
                        "allowed_hosts: []",
                        "allowed_paths: []",
                    ]
                ),
                encoding="utf-8",
            )
            scenario_path = root / "scenario.yaml"
            scenario_path.write_text(
                "\n".join(
                    [
                        "name: bad-scenario",
                        "agents:",
                        "  - id: a",
                        "    manifest: ./agent.yaml",
                        "    depends_on: [missing]",
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ScenarioError) as ctx:
                load_scenario(scenario_path)

        self.assertIn("depends on unknown agent 'missing'", str(ctx.exception))


class FakeProcess:
    def __init__(self, name: str, state: AgentState, exit_code: int | None):
        self.name = name
        self.state = state
        self._exit_code = exit_code
        self.agent_id = f"agt_{name}"
        self.pid = 1000 + len(name)

    def wait(self, timeout=None):
        return self._exit_code


class FakeOrchestratorForRunner:
    def __init__(self, outcomes: dict[str, tuple[AgentState, int | None]]):
        self.outcomes = outcomes
        self.launched = []
        self.stopped = False

    def launch_direct(self, manifest, *, scenario_id=None):
        self.launched.append((manifest.name, scenario_id))
        state, exit_code = self.outcomes[manifest.name]
        return FakeProcess(manifest.name, state, exit_code)

    def stop_all(self):
        self.stopped = True


class RunnerTests(unittest.TestCase):
    def _write_manifest(self, root: Path, filename: str, agent_name: str) -> Path:
        path = root / filename
        path.write_text(
            "\n".join(
                [
                    f"name: {agent_name}",
                    "command: ['python', 'agent.py']",
                    "allowed_hosts: []",
                    "allowed_paths: []",
                ]
            ),
            encoding="utf-8",
        )
        return path

    def test_runner_skips_success_dependent_agent_after_failed_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, "a.yaml", "agent-a")
            self._write_manifest(root, "b.yaml", "agent-b")
            scenario_path = root / "scenario.yaml"
            scenario_path.write_text(
                "\n".join(
                    [
                        "name: dependency-scenario",
                        "agents:",
                        "  - id: a",
                        "    manifest: ./a.yaml",
                        "  - id: b",
                        "    manifest: ./b.yaml",
                        "    depends_on: [a]",
                    ]
                ),
                encoding="utf-8",
            )
            scenario = load_scenario(scenario_path)
            runner = ScenarioRunner(
                FakeOrchestratorForRunner(
                    {
                        "agent-a": (AgentState.CRASHED, 9),
                        "agent-b": (AgentState.STOPPED, 0),
                    }
                ),
                poll_interval=0,
            )
            summary = runner.run(scenario)

            self.assertEqual(summary.status, "failed")
            self.assertEqual(summary.launched_agents, 1)
            self.assertEqual(summary.skipped_agents, 1)
            agent_b = next(item for item in summary.agents if item.id == "b")
            self.assertTrue(agent_b.skipped)
            self.assertEqual(agent_b.skipped_reason, "dependency_failed")

    def test_runner_launches_complete_dependency_even_when_parent_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, "a.yaml", "agent-a")
            self._write_manifest(root, "b.yaml", "agent-b")
            scenario_path = root / "scenario.yaml"
            scenario_path.write_text(
                "\n".join(
                    [
                        "name: complete-scenario",
                        "agents:",
                        "  - id: a",
                        "    manifest: ./a.yaml",
                        "  - id: b",
                        "    manifest: ./b.yaml",
                        "    depends_on: [a]",
                        "    launch_when: complete",
                    ]
                ),
                encoding="utf-8",
            )
            scenario = load_scenario(scenario_path)
            orchestrator = FakeOrchestratorForRunner(
                {
                    "agent-a": (AgentState.CRASHED, 1),
                    "agent-b": (AgentState.STOPPED, 0),
                }
            )
            runner = ScenarioRunner(orchestrator, poll_interval=0)
            summary = runner.run(scenario)

            self.assertEqual([name for name, _ in orchestrator.launched], ["agent-a", "agent-b"])
            self.assertEqual(summary.launched_agents, 2)
            agent_b = next(item for item in summary.agents if item.id == "b")
            self.assertFalse(agent_b.skipped)


class DaemonClientTests(unittest.TestCase):
    def test_disappeared_flag_is_false_when_daemon_never_existed(self):
        # A path that doesn't exist (and never will) — startup probe fails,
        # so .disappeared should be False (it means "vanished after being
        # there", not "never there").
        client = DaemonClient(socket_path="/tmp/no-such-socket-orchestrator-test")
        self.assertFalse(client._was_available_at_startup)
        self.assertFalse(client.disappeared)

    def test_disappeared_flag_flips_after_socket_loss(self):
        client = DaemonClient(socket_path="/tmp/no-such-socket-orchestrator-test")
        # Simulate "daemon was there at startup, now isn't" without touching
        # a real socket. The internal flags are the public contract for the
        # orchestrator's loud-fallback logic.
        client._was_available_at_startup = True
        client._available = False
        self.assertTrue(client.disappeared)


class CliTests(unittest.TestCase):
    def test_cli_validate_emits_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_path = root / "agent.yaml"
            manifest_path.write_text(
                "\n".join(
                    [
                        "name: validate-agent",
                        "command: ['python', 'agent.py']",
                        "allowed_hosts: []",
                        "allowed_paths: []",
                    ]
                ),
                encoding="utf-8",
            )
            scenario_path = root / "scenario.yaml"
            scenario_path.write_text(
                "\n".join(
                    [
                        "name: validate-scenario",
                        "agents:",
                        "  - id: a",
                        "    manifest: ./agent.yaml",
                    ]
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = cli_run(["validate", "-f", str(scenario_path), "--json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["scenario_name"], "validate-scenario")
        self.assertEqual(payload["agents"][0]["id"], "a")


class AgentProcessDaemonModeTests(unittest.TestCase):
    def test_daemon_mode_tracks_lifecycle_and_parses_streamed_stdout(self):
        streamer = RecordingStreamer()
        daemon = FakeDaemon(
            [
                {"type": "agent.started", "pid": 4321, "details": {}},
                {
                    "type": "agent.stdout",
                    "pid": 4321,
                    "details": {
                        "line": "[TOOL] fetch_url called with: https://example.com | request_id=req_1"
                    },
                },
                {
                    "type": "agent.stdout",
                    "pid": 4321,
                    "details": {
                        "line": '[RESULT] {"tool":"fetch_url","ok":true,"request_id":"req_1"}'
                    },
                },
                {
                    "type": "agent.stdout",
                    "pid": 4321,
                    "details": {"line": "[AGENT] done"},
                },
                {
                    "type": "agent.exited",
                    "pid": 4321,
                    "details": {"exit_code": 0},
                },
            ]
        )
        manifest = types.SimpleNamespace(
            name="demo-agent",
            command=["python", "demo_agent.py"],
            allowed_hosts=["example.com"],
            allowed_paths=[],
            env={},
            mode="enforce",
        )

        agent = AgentProcess(manifest, streamer, daemon)
        agent.start()
        exit_code = agent.wait(timeout=1)

        self.assertEqual(exit_code, 0)
        self.assertEqual(agent.state, AgentState.STOPPED)
        self.assertEqual(agent.pid, 4321)

        event_types = [event["type"] for event in streamer.events]
        self.assertIn("session_start", event_types)
        self.assertIn("tool_call", event_types)
        self.assertIn("tool_result", event_types)
        self.assertIn("agent_output", event_types)

        tool_call = next(event for event in streamer.events if event["type"] == "tool_call")
        self.assertEqual(tool_call["data"]["request_id"], "req_1")
        self.assertEqual(tool_call["data"]["args"]["url"], "https://example.com")

    def test_daemon_mode_forwards_llm_events_via_ingest_event(self):
        streamer = RecordingStreamer()
        daemon = FakeDaemon(
            [
                {"type": "agent.started", "pid": 4321, "details": {}},
                {
                    "type": "agent.stdout",
                    "pid": 4321,
                    "details": {
                        "line": "[TOOL] fetch_url called with: https://example.com | request_id=req_1"
                    },
                },
                {
                    "type": "agent.stdout",
                    "pid": 4321,
                    "details": {
                        "line": '[RESULT] {"tool":"fetch_url","ok":true,"request_id":"req_1"}'
                    },
                },
                {
                    "type": "agent.stdout",
                    "pid": 4321,
                    "details": {"line": "[AGENT] done"},
                },
                {
                    "type": "agent.exited",
                    "pid": 4321,
                    "details": {"exit_code": 0},
                },
            ]
        )
        manifest = types.SimpleNamespace(
            name="demo-agent",
            command=["python", "demo_agent.py"],
            allowed_hosts=["example.com"],
            allowed_paths=[],
            env={},
            mode="enforce",
        )

        agent = AgentProcess(manifest, streamer, daemon)
        agent.start()
        agent.wait(timeout=1)

        ingested_types = [event_type for _, event_type, _ in daemon.ingested]
        self.assertIn("llm.tool_call", ingested_types)
        self.assertIn("llm.tool_result", ingested_types)
        self.assertIn("llm.agent_output", ingested_types)
        # stdout lines must NOT be re-ingested (daemon already emits agent.stdout).
        self.assertNotIn("llm.stdout", ingested_types)

        tool_call_agent_id, _, tool_call_details = next(
            entry for entry in daemon.ingested if entry[1] == "llm.tool_call"
        )
        self.assertEqual(tool_call_agent_id, "agt_test1234")
        self.assertEqual(tool_call_details["tool"], "fetch_url")
        self.assertEqual(tool_call_details["request_id"], "req_1")

    def test_local_mode_does_not_call_ingest_event(self):
        streamer = RecordingStreamer()

        class UnavailableDaemon:
            _available = False

            def ingest_event(self, *_args, **_kwargs):  # pragma: no cover - guard
                raise AssertionError("ingest_event should not be called in local mode")

        manifest = types.SimpleNamespace(
            name="local-agent",
            command=["python", "-c", "print('[TOOL] noop called with: x')"],
            allowed_hosts=[],
            allowed_paths=[],
            env={},
            mode="enforce",
        )
        agent = AgentProcess(manifest, streamer, UnavailableDaemon())
        agent.start()
        agent.wait(timeout=2)

        # Sanity: events still flowed to the streamer; nothing tried the daemon.
        event_types = [event["type"] for event in streamer.events]
        self.assertIn("tool_call", event_types)

    def test_daemon_mode_wait_returns_none_until_stream_finishes(self):
        streamer = RecordingStreamer()

        class SlowDaemon(FakeDaemon):
            def stream_events(self, agent_id, on_event, *, stop_event=None):
                on_event({"type": "agent.started", "pid": 1234, "details": {}})
                time.sleep(0.2)
                on_event({"type": "agent.crashed", "pid": 1234, "details": {"exit_code": 7}})

        manifest = types.SimpleNamespace(
            name="demo-agent",
            command=["python", "demo_agent.py"],
            allowed_hosts=["example.com"],
            allowed_paths=[],
            env={},
            mode="enforce",
        )
        agent = AgentProcess(manifest, streamer, SlowDaemon([]))
        agent.start()

        self.assertIsNone(agent.wait(timeout=0.05))
        self.assertEqual(agent.wait(timeout=1), 7)
        self.assertEqual(agent.state, AgentState.CRASHED)


if __name__ == "__main__":
    unittest.main()
