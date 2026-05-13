"""
tool_tracer — zero-rewrite observability for any agent tool.

Decorate your tool functions with @tool_tracer and the orchestrator
automatically captures every call and result in the event stream.
Works with sync and async functions, any SDK (OpenAI, Anthropic, etc.).

Usage::

    from orchestrator import tool_tracer, emit_user_input, emit_agent_output

    @tool_tracer
    def fetch_url(url: str) -> str:
        return requests.get(url).text

    @tool_tracer
    def read_file(path: str) -> str:
        return Path(path).read_text()

    # In your agent loop:
    emit_user_input("Summarise the homepage of example.com")
    response = run_agent_loop(...)
    emit_agent_output(response)

The decorator emits the [TOOL] / [RESULT] markers the orchestrator
parses for event streaming — no manual print statements needed.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import json
import sys
from typing import Any, Callable


def tool_tracer(fn: Callable) -> Callable:
    """Decorator that emits [TOOL] and [RESULT] markers for any tool function.

    Drop it on any tool and the orchestrator dashboard will show every call
    and result without any other changes to your agent code.
    """
    sig = inspect.signature(fn)

    if asyncio.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            _emit_tool_call(fn.__name__, sig, args, kwargs)
            try:
                result = await fn(*args, **kwargs)
                _emit_tool_result(fn.__name__, ok=True, result=result)
                return result
            except Exception as exc:
                _emit_tool_result(fn.__name__, ok=False, error=str(exc))
                raise
        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        _emit_tool_call(fn.__name__, sig, args, kwargs)
        try:
            result = fn(*args, **kwargs)
            _emit_tool_result(fn.__name__, ok=True, result=result)
            return result
        except Exception as exc:
            _emit_tool_result(fn.__name__, ok=False, error=str(exc))
            raise
    return sync_wrapper


def emit_user_input(text: str) -> None:
    """Emit a [USER] marker — records the task the user gave the agent."""
    print(f"[USER] {text}", flush=True)


def emit_agent_output(text: str) -> None:
    """Emit an [AGENT] marker — records the agent's final response."""
    print(f"[AGENT] {text}", flush=True)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _emit_tool_call(
    name: str,
    sig: inspect.Signature,
    args: tuple,
    kwargs: dict,
) -> None:
    args_dict = _bind_args(sig, args, kwargs)
    args_str = json.dumps(args_dict, separators=(",", ":"), default=_json_default)
    print(f"[TOOL] {name} called with: {args_str}", flush=True)


def _emit_tool_result(
    name: str,
    *,
    ok: bool,
    result: Any = None,
    error: str | None = None,
) -> None:
    payload: dict[str, Any] = {"tool": name, "ok": ok}
    if ok:
        payload["result"] = (
            result
            if isinstance(result, (str, int, float, bool, type(None)))
            else str(result)
        )
    else:
        payload["error"] = error
    print(
        f"[RESULT] {json.dumps(payload, separators=(',', ':'), default=_json_default)}",
        flush=True,
    )


def _bind_args(
    sig: inspect.Signature,
    args: tuple,
    kwargs: dict,
) -> dict:
    """Map positional + keyword args to their parameter names using the signature."""
    try:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return {
            k: _safe_value(v)
            for k, v in bound.arguments.items()
        }
    except TypeError:
        # Signature bind failed (e.g. *args/**kwargs in the original) — best effort.
        result: dict[str, Any] = {}
        if args:
            result["args"] = [_safe_value(a) for a in args]
        result.update({k: _safe_value(v) for k, v in kwargs.items()})
        return result


def _safe_value(v: Any) -> Any:
    """Return v if JSON-serialisable as-is, otherwise stringify it."""
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [_safe_value(i) for i in v]
    if isinstance(v, dict):
        return {str(k): _safe_value(val) for k, val in v.items()}
    return str(v)


def _json_default(obj: Any) -> str:
    return str(obj)
