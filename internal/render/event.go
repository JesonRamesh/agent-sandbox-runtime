package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/agent-sandbox/runtime/internal/client"
)

// HumanEvent renders one event in the colon-prefixed line format used by
// `agentctl logs`. The format is:
//
//	HH:MM:SS  agent  category.type  <type-specific summary>
//
// Type-specific summarisers are registered via the `summarisers` table; an
// unknown subtype falls back to the raw JSON of `data`.
func HumanEvent(w io.Writer, ev *client.Event) {
	t := timeOf(ev.TS)
	fmt.Fprintf(w, "%s  %s  %s.%s  %s\n",
		t, ev.Agent, ev.Category, ev.Type, summariseEvent(ev))
}

func timeOf(ts string) string {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.UTC().Format("15:04:05")
	}
	return "--:--:--"
}

func summariseEvent(ev *client.Event) string {
	key := ev.Category + "." + ev.Type
	if fn, ok := summarisers[key]; ok {
		if s, ok := fn(ev.Data); ok {
			return s
		}
	}
	// Fallback: compact JSON of data, max 200 chars.
	if len(ev.Data) == 0 {
		return ""
	}
	s := string(ev.Data)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

type summariser func(json.RawMessage) (string, bool)

var summarisers = map[string]summariser{
	"llm.stdout":             llmStdout,
	"llm.tool_call":          llmToolCall,
	"llm.tool_result":        llmToolResult,
	"kernel.connect_allowed": kernelConnectAllowed,
	"kernel.connect_blocked": kernelConnectBlocked,
	"agent.stdout":           agentStdout,
	"agent.stderr":           agentStdout, // identical line-shape
	"lifecycle.spawned":      lifecycleSpawned,
	"lifecycle.exit":         lifecycleExit,
	"lifecycle.crash":        lifecycleCrash,
	"lifecycle.signal":       lifecycleSignal,
}

// llm.stdout {"line": "...."} → quoted line
func llmStdout(raw json.RawMessage) (string, bool) {
	var d struct {
		Line string `json:"line"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return quote(d.Line), true
}

// llm.tool_call {"name": "...", "args": {...}} → name(args-json)
func llmToolCall(raw json.RawMessage) (string, bool) {
	var d struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	args := strings.TrimSpace(string(d.Args))
	if args == "" || args == "null" {
		args = "{}"
	}
	return fmt.Sprintf("%s(%s)", d.Name, args), true
}

// llm.tool_result {"name": "...", "ok": true, "result_summary": "..."} →
// name → ok=true ("summary")
func llmToolResult(raw json.RawMessage) (string, bool) {
	var d struct {
		Name    string `json:"name"`
		Ok      bool   `json:"ok"`
		Summary string `json:"result_summary"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	if d.Summary != "" {
		return fmt.Sprintf("%s -> ok=%v %s", d.Name, d.Ok, quote(d.Summary)), true
	}
	return fmt.Sprintf("%s -> ok=%v", d.Name, d.Ok), true
}

// kernel.connect_allowed {"host": "...", "port": N, "rule": "..."} → host:port (rule)
func kernelConnectAllowed(raw json.RawMessage) (string, bool) {
	var d struct {
		Host string `json:"host"`
		Port int    `json:"port"`
		Rule string `json:"rule"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	if d.Rule != "" {
		return fmt.Sprintf("%s:%d (%s)", d.Host, d.Port, d.Rule), true
	}
	return fmt.Sprintf("%s:%d", d.Host, d.Port), true
}

// kernel.connect_blocked {"host":..., "port":..., "reason": "..."} → host:port BLOCKED reason
func kernelConnectBlocked(raw json.RawMessage) (string, bool) {
	var d struct {
		Host   string `json:"host"`
		Port   int    `json:"port"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return fmt.Sprintf("%s:%d BLOCKED %s", d.Host, d.Port, d.Reason), true
}

// agent.stdout / agent.stderr {"line": "..."} → quoted line
func agentStdout(raw json.RawMessage) (string, bool) {
	var d struct {
		Line string `json:"line"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return quote(d.Line), true
}

// lifecycle.spawned {"pid": N, "argv": [...]} → pid=N argv=[a b c]
func lifecycleSpawned(raw json.RawMessage) (string, bool) {
	var d struct {
		PID  int      `json:"pid"`
		Argv []string `json:"argv"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return fmt.Sprintf("pid=%d argv=[%s]", d.PID, strings.Join(d.Argv, " ")), true
}

// lifecycle.exit {"exit_code": N} → exit=N
func lifecycleExit(raw json.RawMessage) (string, bool) {
	var d struct {
		ExitCode int `json:"exit_code"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return fmt.Sprintf("exit=%d", d.ExitCode), true
}

// lifecycle.crash {"signal": "...", "core_dumped": bool} → signal=X core=bool
func lifecycleCrash(raw json.RawMessage) (string, bool) {
	var d struct {
		Signal string `json:"signal"`
		Core   bool   `json:"core_dumped"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return fmt.Sprintf("signal=%s core=%v", d.Signal, d.Core), true
}

// lifecycle.signal {"signal": "...", "from": "..."} → signal=X from=Y
func lifecycleSignal(raw json.RawMessage) (string, bool) {
	var d struct {
		Signal string `json:"signal"`
		From   string `json:"from"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", false
	}
	return fmt.Sprintf("signal=%s from=%s", d.Signal, d.From), true
}
