// Package e2e holds the testscript suite that drives the compiled agentctl
// binary against an in-process mock daemon. Each .txt fixture under
// testdata/script/ is a self-contained scenario.
//
// Provided commands within scripts:
//   - agentctl ...        the compiled binary, with --socket auto-injected
//   - mockd start [opts]  start an in-process mock daemon listening on $SOCKET
//   - mockd push CATEGORY TYPE JSONDATA   push one event to the live stream
//   - mockd end            close the streaming subscription cleanly
//   - mockd assert-method-called METHOD [N]   fail unless METHOD was called
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rogpeppe/go-internal/testscript"

	"github.com/agent-sandbox/runtime/cmd/agentctl/app"
	"github.com/agent-sandbox/runtime/internal/client"
	"github.com/agent-sandbox/runtime/internal/testutil"
)

// TestMain forwards to testscript.Main so the test binary doubles as the
// `agentctl` executable when invoked from a script. Note: we deliberately do
// NOT call flag.Parse() here — testscript hands the script's argv straight to
// the registered Main, and a stray flag.Parse() would barf on cobra flags
// like --json that the standard library knows nothing about.
//
// testscript.Main always calls os.Exit, so the wrapper does not return.
// Each registered command is responsible for its own os.Exit.
func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"agentctl": func() { os.Exit(app.Main()) },
	})
}

func TestScripts(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/script",
		RequireExplicitExec: false,
		Setup: func(env *testscript.Env) error {
			// Each script gets a fresh mock daemon socket path under WORK.
			sockPath := filepath.Join(env.WorkDir, "agentd.sock")
			env.Setenv("SOCKET", sockPath)
			env.Setenv("AGENT_SANDBOX_SOCKET", sockPath)
			return nil
		},
		Cmds: map[string]func(*testscript.TestScript, bool, []string){
			"mockd": mockdCmd,
		},
	})
}

// scriptMockState carries the per-script mock instance. testscript creates
// a fresh Env per script; we store the mock in a package-level map keyed by
// the env's WorkDir so subsequent `mockd` invocations within the same script
// can find it.
var (
	mocksMu sync.Mutex
	mocks   = map[string]*scriptMock{}
)

type scriptMock struct {
	server *scriptMockServer
}

func mockdCmd(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) == 0 {
		ts.Fatalf("mockd: usage: mockd <subcommand> [args...]")
	}
	wd := ts.Getenv("WORK")
	mocksMu.Lock()
	state := mocks[wd]
	mocksMu.Unlock()

	switch args[0] {
	case "start":
		if state != nil {
			ts.Fatalf("mockd: already started")
		}
		sock := ts.Getenv("SOCKET")
		srv, err := newScriptMockServer(sock)
		if err != nil {
			ts.Fatalf("mockd start: %v", err)
		}
		// Apply remaining args as configuration: KEY=VALUE
		for _, kv := range args[1:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				ts.Fatalf("mockd start: bad arg %q (want KEY=VALUE)", kv)
			}
			srv.configure(parts[0], parts[1])
		}
		mocksMu.Lock()
		mocks[wd] = &scriptMock{server: srv}
		mocksMu.Unlock()
		ts.Defer(func() {
			mocksMu.Lock()
			delete(mocks, wd)
			mocksMu.Unlock()
			srv.stop()
		})
	case "push":
		if state == nil {
			ts.Fatalf("mockd push: no running mock; call `mockd start` first")
		}
		if len(args) < 4 {
			ts.Fatalf("mockd push: usage: mockd push CATEGORY TYPE JSONDATA")
		}
		ev := client.Event{
			Schema:   "v1",
			TS:       time.Now().UTC().Format(time.RFC3339Nano),
			Agent:    "test",
			AgentID:  "01TEST",
			Category: args[1],
			Type:     args[2],
			Data:     json.RawMessage(args[3]),
		}
		state.server.pushEvent(ev)
	case "end":
		if state == nil {
			ts.Fatalf("mockd end: no running mock")
		}
		state.server.endStream()
	case "assert-method-called":
		if state == nil {
			ts.Fatalf("mockd assert-method-called: no running mock")
		}
		if len(args) < 2 {
			ts.Fatalf("mockd assert-method-called: usage: mockd assert-method-called METHOD [N]")
		}
		want := 1
		if len(args) >= 3 {
			n, err := strconv.Atoi(args[2])
			if err != nil {
				ts.Fatalf("mockd assert-method-called: bad N: %v", err)
			}
			want = n
		}
		got := state.server.callCount(args[1])
		if got != want {
			ts.Fatalf("mockd: expected %d calls to %q, got %d", want, args[1], got)
		}
	default:
		ts.Fatalf("mockd: unknown subcommand %q", args[0])
	}
	if neg {
		// We don't expect any of these to fail under normal use.
		ts.Fatalf("mockd: ! prefix not supported")
	}
}

// scriptMockServer wraps testutil.MockDaemon to expose the bits the script
// helpers need (start/stop/push/end/configure).
type scriptMockServer struct {
	mock     *testutil.MockDaemon
	stopFn   func()
	mu       sync.Mutex
	cfg      map[string]string
	calls    map[string]int
	streamCh chan client.Event
	streamMu sync.Mutex
}

// newScriptMockServer is similar to testutil.New but doesn't require *testing.T;
// it creates the listener directly.
func newScriptMockServer(sock string) (*scriptMockServer, error) {
	if err := os.RemoveAll(sock); err != nil {
		return nil, fmt.Errorf("clear stale socket: %w", err)
	}
	srv := &scriptMockServer{
		cfg:   map[string]string{},
		calls: map[string]int{},
	}
	t := newScriptTesting()
	srv.mock = testutil.NewWithSocket(t, sock)
	srv.stopFn = srv.mock.Stop
	srv.installDefaults()
	return srv, nil
}

func (s *scriptMockServer) configure(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg[k] = v
	s.installDefaults()
}

func (s *scriptMockServer) installDefaults() {
	s.mock.OnRunAgent(func(req *client.RunAgentRequest) (*client.RunAgentResult, *client.WireError) {
		s.bump("RunAgent")
		// Honour configured failure modes.
		if code := s.cfg["run_error_code"]; code != "" {
			return nil, &client.WireError{Code: code, Message: s.cfg["run_error_message"]}
		}
		name := req.Manifest.Name
		if name == "" {
			name = "agent"
		}
		return &client.RunAgentResult{
			Name:          name,
			AgentID:       "01H8X0",
			PID:           4242,
			CgroupPath:    "/sys/fs/cgroup/agent/" + name,
			StartedAt:     "2026-04-29T12:00:00Z",
			PolicySummary: fmt.Sprintf("hosts:%d paths:%d timeout:0", len(req.Manifest.AllowedHosts), len(req.Manifest.AllowedPaths)),
		}, nil
	})
	s.mock.OnList(func() (*client.ListAgentsResult, *client.WireError) {
		s.bump("ListAgents")
		exit0 := 0
		return &client.ListAgentsResult{Agents: []client.AgentInfo{
			{Name: "agent-x", AgentID: "01H8X0", Status: "running", PID: 4242, UptimeNS: int64(192e9), PolicySummary: "hosts:1 paths:0 timeout:0"},
			{Name: "gone", AgentID: "01F00B", Status: "exited", PID: 0, UptimeNS: 0, PolicySummary: "hosts:0 paths:1 timeout:30s", ExitCode: &exit0},
		}}, nil
	})
	s.mock.OnStop(func(req *client.StopAgentRequest) (*client.StopAgentResult, *client.WireError) {
		s.bump("StopAgent")
		if s.cfg["stop_error_code"] != "" {
			return nil, &client.WireError{Code: s.cfg["stop_error_code"], Message: s.cfg["stop_error_message"]}
		}
		return &client.StopAgentResult{Name: req.Name, ExitCode: 0, Signal: "SIGTERM", DurationNS: int64(123 * time.Millisecond)}, nil
	})
	s.mock.OnLogs(func(req *client.AgentLogsRequest) (*client.AgentLogsResult, *client.WireError) {
		s.bump("AgentLogs")
		// Five canned events so a slice by req.TailN is observable.
		evs := []client.Event{
			{Schema: "v1", TS: "2026-04-29T12:00:00Z", Agent: req.Name, AgentID: "01H8X0", Category: "agent", Type: "stdout", Data: json.RawMessage(`{"line":"first"}`)},
			{Schema: "v1", TS: "2026-04-29T12:00:01Z", Agent: req.Name, AgentID: "01H8X0", Category: "agent", Type: "stdout", Data: json.RawMessage(`{"line":"second"}`)},
			{Schema: "v1", TS: "2026-04-29T12:00:02Z", Agent: req.Name, AgentID: "01H8X0", Category: "agent", Type: "stdout", Data: json.RawMessage(`{"line":"third"}`)},
			{Schema: "v1", TS: "2026-04-29T12:00:03Z", Agent: req.Name, AgentID: "01H8X0", Category: "agent", Type: "stdout", Data: json.RawMessage(`{"line":"fourth"}`)},
			{Schema: "v1", TS: "2026-04-29T12:00:04Z", Agent: req.Name, AgentID: "01H8X0", Category: "lifecycle", Type: "exit", Data: json.RawMessage(`{"exit_code":0}`)},
		}
		// Mirror the daemon contract: TailN > 0 trims to the most recent N.
		if n := req.TailN; n > 0 && n < len(evs) {
			evs = evs[len(evs)-n:]
		}
		return &client.AgentLogsResult{Events: evs}, nil
	})
	s.mock.OnStatus(func() (*client.DaemonStatusResult, *client.WireError) {
		s.bump("DaemonStatus")
		return &client.DaemonStatusResult{ProtocolVersion: "v1", Build: "mock-1.0", UptimeNS: int64(time.Hour), AgentsRunning: 2}, nil
	})
	s.mock.OnStreamEvents(func(req *client.StreamEventsRequest, sink chan<- client.Event) {
		s.bump("StreamEvents")
		s.streamMu.Lock()
		s.streamCh = make(chan client.Event, 64)
		ch := s.streamCh
		s.streamMu.Unlock()
		for ev := range ch {
			sink <- ev
		}
	})
}

func (s *scriptMockServer) pushEvent(ev client.Event) {
	// Wait briefly for the script to call `agentctl logs --follow`.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.streamMu.Lock()
		ch := s.streamCh
		s.streamMu.Unlock()
		if ch != nil {
			select {
			case ch <- ev:
				return
			default:
				// Buffer full; retry.
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *scriptMockServer) endStream() {
	s.streamMu.Lock()
	ch := s.streamCh
	s.streamCh = nil
	s.streamMu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (s *scriptMockServer) bump(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[method]++
}

func (s *scriptMockServer) callCount(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

func (s *scriptMockServer) stop() {
	s.endStream()
	s.stopFn()
}

// scriptTesting is the tiny stub that lets us call testutil.NewWithSocket
// without an actual *testing.T.
type scriptTesting struct{}

func newScriptTesting() *scriptTesting { return &scriptTesting{} }

func (s *scriptTesting) Helper()                           {}
func (s *scriptTesting) Fatalf(format string, args ...any) { panic(fmt.Sprintf(format, args...)) }
func (s *scriptTesting) Errorf(format string, args ...any) { panic(fmt.Sprintf(format, args...)) }
func (s *scriptTesting) Cleanup(fn func())                 { /* tests handle stop manually */ }
func (s *scriptTesting) TempDir() string                   { return os.TempDir() }
