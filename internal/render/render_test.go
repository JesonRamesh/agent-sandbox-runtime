package render_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/agent-sandbox/runtime/internal/client"
	"github.com/agent-sandbox/runtime/internal/render"
)

func TestHumanList_RoundsAndAligns(t *testing.T) {
	exit := 0
	agents := []client.AgentInfo{
		{Name: "agent-x", AgentID: "01H8X0", Status: "running", PID: 4242, UptimeNS: int64(192e9), PolicySummary: "hosts:1 paths:0 timeout:0"},
		{Name: "gone", AgentID: "01F00B", Status: "exited", PID: 0, UptimeNS: 0, PolicySummary: "hosts:0 paths:1 timeout:30s", ExitCode: &exit},
	}
	var buf bytes.Buffer
	render.HumanList(&buf, agents)
	out := buf.String()
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "agent-x") || !strings.Contains(out, "gone") {
		t.Errorf("unexpected list output:\n%s", out)
	}
	if !strings.Contains(out, "exit=0") {
		t.Errorf("expected exit code in exited row:\n%s", out)
	}
}

func TestJSON_OutputShape(t *testing.T) {
	var buf bytes.Buffer
	if err := render.JSON(&buf, map[string]any{"name": "x", "n": 1}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if got["name"] != "x" {
		t.Errorf("name: got %v", got["name"])
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("JSON output should end with newline")
	}
}

func TestHumanEvent_TypeSpecificSummarisers(t *testing.T) {
	cases := []struct {
		category string
		typ      string
		data     string
		want     string
	}{
		{"llm", "stdout", `{"line":"hello"}`, "hello"},
		{"llm", "tool_call", `{"name":"http.get","args":{"url":"https://x"}}`, `http.get({"url":"https://x"})`},
		{"llm", "tool_result", `{"name":"http.get","ok":true,"result_summary":"200 OK"}`, `http.get -> ok=true "200 OK"`},
		{"kernel", "connect_allowed", `{"host":"api.x.com","port":443,"rule":"api.x.com"}`, "api.x.com:443 (api.x.com)"},
		{"kernel", "connect_blocked", `{"host":"evil.example","port":443,"reason":"not in allowed_hosts"}`, "evil.example:443 BLOCKED not in allowed_hosts"},
		{"agent", "stdout", `{"line":"hello world"}`, `"hello world"`},
		{"lifecycle", "exit", `{"exit_code":2}`, "exit=2"},
		{"lifecycle", "spawned", `{"pid":4242,"argv":["/bin/agent","--flag"]}`, "pid=4242 argv=[/bin/agent --flag]"},
	}

	for _, tc := range cases {
		t.Run(tc.category+"."+tc.typ, func(t *testing.T) {
			var buf bytes.Buffer
			ev := &client.Event{
				Schema:   "v1",
				TS:       "2026-04-29T12:34:56Z",
				Agent:    "agent",
				AgentID:  "01A",
				Category: tc.category,
				Type:     tc.typ,
				Data:     json.RawMessage(tc.data),
			}
			render.HumanEvent(&buf, ev)
			out := buf.String()
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing summary %q in:\n%s", tc.want, out)
			}
			if !strings.Contains(out, "12:34:56") {
				t.Errorf("missing timestamp HH:MM:SS in:\n%s", out)
			}
		})
	}
}

// Event payloads can carry raw control bytes from agent stdout, LLM tool
// output, or (in misconfigured deployments) the network. They MUST NOT
// reach the operator's terminal as live ANSI sequences — `agentctl logs`
// would otherwise be a remote message-spoof vector.
func TestHumanEvent_EscapesAnsiControlSequences(t *testing.T) {
	ev := &client.Event{
		Schema:   "v1",
		TS:       "2026-04-29T12:34:56Z",
		Agent:    "agent",
		AgentID:  "01A",
		Category: "agent",
		Type:     "stdout",
		// JSON \u001b becomes byte 0x1b once unmarshalled — exactly the form
		// a hostile event source would use to slip ANSI escapes through.
		Data: json.RawMessage(`{"line":"\u001b[2J\u001b[31mFAKE\u001b[0m"}`),
	}
	var buf bytes.Buffer
	render.HumanEvent(&buf, ev)
	out := buf.String()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("rendered output leaks raw ESC byte:\n%q", out)
	}
}

func TestHumanEvent_UnknownTypeFallsBackToJSON(t *testing.T) {
	ev := &client.Event{
		Schema:   "v1",
		TS:       "2026-04-29T12:34:56Z",
		Agent:    "agent",
		AgentID:  "01A",
		Category: "novel",
		Type:     "thing",
		Data:     json.RawMessage(`{"foo":"bar"}`),
	}
	var buf bytes.Buffer
	render.HumanEvent(&buf, ev)
	out := buf.String()
	if !strings.Contains(out, `{"foo":"bar"}`) {
		t.Errorf("expected raw JSON fallback, got:\n%s", out)
	}
}
