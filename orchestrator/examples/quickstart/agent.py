"""
Quickstart agent — zero-to-running on any OS in under 2 minutes.

Without MODEL set: runs a simulation showing the full event flow.
With MODEL set (via agent.yaml or env var): makes real LLM tool calls.

Edit agent.yaml to pick your model and provider — the orchestrator
injects MODEL, API_BASE_URL, and API_KEY automatically.
"""
from __future__ import annotations

import json
import os

from orchestrator import emit_agent_output, emit_user_input, tool_tracer


@tool_tracer
def get_weather(city: str) -> str:
    """Return simulated weather for a city (no real API needed)."""
    data = {"city": city, "temp_c": 22, "condition": "sunny", "note": "simulated"}
    return json.dumps(data)


@tool_tracer
def add_numbers(a: float, b: float) -> float:
    """Add two numbers and return the result."""
    return a + b


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a city.",
            "parameters": {
                "type": "object",
                "properties": {"city": {"type": "string", "description": "City name"}},
                "required": ["city"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_numbers",
            "description": "Add two numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                },
                "required": ["a", "b"],
            },
        },
    },
]

_TOOL_FNS = {"get_weather": get_weather, "add_numbers": add_numbers}


def _run_simulated() -> None:
    task = "What's the weather in London? Also what is 10 + 32?"
    print("[quickstart] No MODEL set — running simulation mode", flush=True)
    emit_user_input(task)
    weather = get_weather("London")
    total = add_numbers(10, 32)
    emit_agent_output(
        f"In London it is sunny at 22°C (simulated). 10 + 32 = {total}."
    )


def _run_with_llm(model: str) -> None:
    from openai import OpenAI

    client = OpenAI(
        api_key=os.environ.get("API_KEY") or os.environ.get("OPENAI_API_KEY", ""),
        base_url=os.environ.get("API_BASE_URL", "https://api.openai.com/v1"),
    )

    task = "What's the weather in London? Also what is 10 + 32?"
    emit_user_input(task)
    messages = [{"role": "user", "content": task}]

    while True:
        response = client.chat.completions.create(
            model=model, messages=messages, tools=TOOLS, tool_choice="auto"
        )
        msg = response.choices[0].message
        if msg.tool_calls:
            messages.append(msg)
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments)
                result = _TOOL_FNS[tc.function.name](**args)
                messages.append(
                    {"role": "tool", "tool_call_id": tc.id, "content": str(result)}
                )
        else:
            emit_agent_output(msg.content or "")
            break


def main() -> None:
    model = os.environ.get("MODEL")
    if model:
        _run_with_llm(model)
    else:
        _run_simulated()


if __name__ == "__main__":
    main()
