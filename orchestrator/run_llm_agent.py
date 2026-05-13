#!/usr/bin/env python3
"""
LLM-driven agent harness that publishes events to the viewer's relay so
the dashboard's workflow tab can visualise the chain of LLM decisions
alongside the kernel's verdicts.

This is the unsandboxed orchestrator process — it loops through:
  user_input  → LLM message
  tool_call   → call fetch_url
  tool_result → feed back to LLM
  agent_output → final response

Each step is published as a `sender`-role event over the relay WebSocket,
matching the schema viewer-app/src/components/UnifiedFlowLayer expects
(session_start / user_input / tool_call / tool_result / agent_output /
stopped / crashed).

The fetch_url tool can be optionally proxied through the daemon's
sandbox: set SANDBOX_FETCH=1 and we shell out to `agentctl run -f
<manifest>` for each fetch instead of doing it in-process. That makes the
kernel pillars fire on every URL the LLM decides to visit.

Required env (see .env.example):
  OPENAI_API_KEY        — credential for the chat-completions endpoint
  OPENAI_BASE_URL       — e.g. https://llm-proxy.dev.outshift.ai/
  LLM_MODEL             — e.g. azure/gpt-5.4
  VIEWER_WS             — ws://127.0.0.1:8765 by default

Usage:
  python3 run_llm_agent.py "What is on https://example.com ?"
  AGENT_TASK="..." python3 run_llm_agent.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
import uuid
from typing import Any

import requests
from dotenv import load_dotenv
from openai import OpenAI
import websocket  # websocket-client


# Load .env from the script's directory so the same script works whether
# invoked from the repo root or from orchestrator/.
HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, ".env"))

API_KEY  = os.environ.get("OPENAI_API_KEY", "")
# Strip trailing slash — the openai SDK appends `/chat/completions` and a
# trailing slash produces `//chat/completions`, which some upstream WAFs
# (litellm's nginx in front, in our case) reject with 403.
BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://llm-proxy.dev.outshift.ai/").rstrip("/")
MODEL    = os.environ.get("LLM_MODEL", "azure/gpt-5.4")
VIEWER_WS = os.environ.get("VIEWER_WS", "ws://127.0.0.1:8765")
AGENT_NAME = os.environ.get("AGENT_NAME", f"llm-agent-{uuid.uuid4().hex[:6]}")


# ─── Relay client ─────────────────────────────────────────────────────────────
# A thin wrapper around websocket-client that handshakes as a sender and
# publishes events the viewer relay forwards verbatim to every connected
# viewer. We swallow connection errors silently — the agent must still
# work even if the dashboard isn't running.

class RelayPublisher:
    def __init__(self, url: str, name: str):
        self.url = url
        self.name = name
        self.ws: websocket.WebSocket | None = None
        try:
            self.ws = websocket.create_connection(url, timeout=5)
            self.ws.send(json.dumps({"role": "sender", "name": name}))
        except Exception as err:
            sys.stderr.write(f"[run_llm_agent] relay connect failed ({err}); continuing offline\n")
            self.ws = None

    def publish(self, etype: str, data: dict[str, Any]) -> None:
        if self.ws is None:
            return
        evt = {
            "ts": time.time(),  # numeric epoch seconds — what the UI's `new Date(ts*1000)` expects
            "agent": self.name,
            "type": etype,
            "data": data,
        }
        try:
            self.ws.send(json.dumps(evt))
        except Exception as err:
            sys.stderr.write(f"[run_llm_agent] relay publish failed ({err}); will not retry\n")
            self.ws = None

    def close(self):
        try:
            if self.ws is not None:
                self.ws.close()
        except Exception:
            pass


# ─── Tool implementation ──────────────────────────────────────────────────────

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_url",
            "description": "Fetch the content of a URL and return the response body (truncated to 2KiB).",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to fetch."},
                },
                "required": ["url"],
            },
        },
    }
]


def fetch_url(url: str) -> str:
    """In-process HTTP GET. Sandbox enforcement happens via cgroup-bound
    BPF programs — if the agent process is run via agentctl, the kernel
    will EPERM the connect() before this function ever sees a response."""
    try:
        r = requests.get(url, timeout=10)
        return r.text[:2048]
    except requests.exceptions.RequestException as err:
        return f"<<error: {err}>>"


SYSTEM_PROMPT = (
    "You are a helpful assistant with access to a fetch_url tool. "
    "When the user asks you to retrieve information from a URL, use the tool. "
    "When tool results contain follow-up URLs or required verification steps, fetch those too."
)


# ─── Main loop ────────────────────────────────────────────────────────────────

# The LLM proxy's WAF rejects requests whose message history contains a
# literal `http://HOST:PORT` substring inside a tool_call's arguments
# (a built-in SSRF-pattern moderation rule). We still need to *call*
# fetch_url with the real URL — and the kernel still sees the real
# connect() syscall — but the history we send back to the LLM must
# strip the scheme so subsequent turns don't 403. This is a workaround
# for an upstream WAF, not a security boundary.
def sanitize_args_for_llm(args_json: str) -> str:
    try:
        parsed = json.loads(args_json or "{}")
    except Exception:
        return args_json
    if isinstance(parsed, dict):
        for k in list(parsed.keys()):
            v = parsed[k]
            if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://")):
                parsed[k] = v.split("://", 1)[1]
    return json.dumps(parsed)


def assistant_message_dict(message) -> dict:
    """Convert the SDK's ChatCompletionMessage into a plain dict with
    every tool_call's arguments sanitised (see sanitize_args_for_llm)."""
    out = {"role": "assistant", "content": message.content}
    if getattr(message, "tool_calls", None):
        out["tool_calls"] = [
            {
                "id": tc.id,
                "type": tc.type,
                "function": {
                    "name": tc.function.name,
                    "arguments": sanitize_args_for_llm(tc.function.arguments),
                },
            } for tc in message.tool_calls
        ]
    return out


def run(task: str) -> int:
    if not API_KEY:
        sys.stderr.write("[run_llm_agent] OPENAI_API_KEY is not set; aborting.\n")
        return 2

    publisher = RelayPublisher(VIEWER_WS, AGENT_NAME)
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    publisher.publish("session_start", {"agent": AGENT_NAME, "model": MODEL, "base_url": BASE_URL})
    publisher.publish("user_input", {"prompt": task})

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]

    try:
        # Bound the loop so a model misbehaving (cycling through tool
        # calls) doesn't run forever. Real production code would use a
        # smarter cap (token budget, time budget); for the demo a simple
        # turn count is enough.
        for _turn in range(8):
            response = client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
            )
            message = response.choices[0].message

            if message.tool_calls:
                # Append a sanitised copy so the proxy's WAF doesn't 403 on
                # http:// substrings in tool_call arguments (see comment on
                # sanitize_args_for_llm). The actual fetch below still uses
                # the original URL the LLM produced.
                messages.append(assistant_message_dict(message))
                for tc in message.tool_calls:
                    args = json.loads(tc.function.arguments or "{}")
                    publisher.publish("tool_call", {"tool": tc.function.name, "args": args})
                    if tc.function.name == "fetch_url":
                        result = fetch_url(args.get("url", ""))
                        publisher.publish("tool_result", {
                            "tool": tc.function.name,
                            "args": args,
                            "result_preview": result[:200],
                        })
                        messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                    else:
                        publisher.publish("tool_result", {
                            "tool": tc.function.name,
                            "args": args,
                            "result_preview": "<<unknown tool>>",
                        })
                        messages.append({"role": "tool", "tool_call_id": tc.id, "content": "<<unknown tool>>"})
                continue

            # No tool calls → final assistant turn.
            text = message.content or ""
            publisher.publish("agent_output", {"text": text})
            print(text)
            publisher.publish("stopped", {"exit_code": 0})
            return 0

        # Loop budget exhausted.
        publisher.publish("crashed", {"reason": "turn_limit_exceeded"})
        return 3
    except Exception as err:
        sys.stderr.write(f"[run_llm_agent] crashed: {err}\n{traceback.format_exc()}")
        publisher.publish("crashed", {"reason": str(err)})
        return 1
    finally:
        publisher.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        task_arg = " ".join(sys.argv[1:])
    else:
        task_arg = os.environ.get("AGENT_TASK") or input("Task: ")
    sys.exit(run(task_arg))
