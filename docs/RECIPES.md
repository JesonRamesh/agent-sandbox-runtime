# Recipes

Common orchestrator and manifest patterns that turn the runtime from a
demo into a useful developer tool.

## Agent With LLM-Only Network Access

```yaml
name: llm-only-agent
command: ["/usr/bin/python3", "agent.py"]
allowed_hosts:
  - api.openai.com:443
allowed_paths: []
```

Use this when the agent should call an LLM API but should not browse the
arbitrary internet.

## Agent With Read-Only `/etc`

```yaml
name: inspect-host
command: ["/usr/bin/python3", "inspect.py"]
allowed_hosts: []
allowed_paths:
  - /etc/
```

Keep writes somewhere else such as `/tmp/agent-workdir`.

## Agent That Can Exec One Subprocess

```yaml
name: python-runner
command: ["/usr/bin/python3", "agent.py"]
allowed_hosts: []
allowed_paths:
  - /tmp/sandbox
allowed_bins:
  - /usr/bin/python3
working_dir: /tmp/sandbox
```

See [`orchestrator/examples/code_exec/`](../orchestrator/examples/code_exec/).

## Two Agents Handing Off Via File

```yaml
name: research-writer
agents:
  - id: research
    manifest: ./research-agent.yaml
  - id: writer
    manifest: ./writer-agent.yaml
    depends_on: [research]
```

See [`orchestrator/examples/two_agent/`](../orchestrator/examples/two_agent/).

## Fan-Out With Independent Policies

```yaml
name: fanout-demo
agents:
  - id: alpha
    manifest: ./alpha.yaml
  - id: beta
    manifest: ./beta.yaml
  - id: gamma
    manifest: ./gamma.yaml
```

Each manifest can advertise a different `allowed_hosts` list while the
orchestrator still treats them as one scenario.

---

## Using `@tool_tracer` with your framework

`@tool_tracer` is a plain Python decorator — it wraps any callable and emits
`[TOOL]` / `[RESULT]` markers that the orchestrator parses into the event
stream. It works with every SDK; the only thing that varies is where you
dispatch tool calls back to your function.

### Plain OpenAI SDK

```python
from orchestrator import tool_tracer, emit_user_input, emit_agent_output
from openai import OpenAI
import json

@tool_tracer
def search(query: str) -> str:
    return my_search_backend(query)

client = OpenAI()
messages = [{"role": "user", "content": "Find recent news on climate change"}]

while True:
    response = client.chat.completions.create(
        model="gpt-4o", messages=messages, tools=TOOLS, tool_choice="auto"
    )
    msg = response.choices[0].message
    if msg.tool_calls:
        messages.append(msg)
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments)
            result = search(**args)          # @tool_tracer fires here
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": str(result)})
    else:
        emit_agent_output(msg.content or "")
        break
```

See [`orchestrator/examples/quickstart/agent.py`](../orchestrator/examples/quickstart/agent.py)
for the complete working version.

### Anthropic Claude SDK

The pattern is the same — `@tool_tracer` on the function, then dispatch
`tool_use` content blocks to it:

```python
from orchestrator import tool_tracer, emit_agent_output
import anthropic, json

@tool_tracer
def search(query: str) -> str:
    return my_search_backend(query)

client = anthropic.Anthropic()
messages = [{"role": "user", "content": "Find recent news on climate change"}]

while True:
    response = client.messages.create(
        model="claude-sonnet-4-6", messages=messages, tools=TOOLS, max_tokens=1024
    )
    if response.stop_reason == "tool_use":
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = search(**block.input)   # @tool_tracer fires here
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": str(result),
                })
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})
    else:
        text = next((b.text for b in response.content if hasattr(b, "text")), "")
        emit_agent_output(text)
        break
```

### LangChain

Decorator order matters. Put `@tool` **outermost** and `@tool_tracer`
**inner** — that way LangChain stores the already-traced function and the
tracer fires when LangChain calls it:

```python
from orchestrator import tool_tracer
from langchain.tools import tool

@tool                # outermost: makes this a LangChain BaseTool
@tool_tracer         # inner: wraps the raw function — fires on every invocation
def search(query: str) -> str:
    """Search the web for a query."""
    return my_search_backend(query)
```

**Wrong order** — do not do this:

```python
@tool_tracer   # wraps the BaseTool object, not the function — tracer never fires
@tool
def search(query: str) -> str: ...
```

Pass `search` to your LangChain agent as normal; the orchestrator will see
every call and result in the event stream without any other changes.
