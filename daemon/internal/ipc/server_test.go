package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mockHandler is a configurable Handler stub. Each field overrides the
// corresponding method's behavior; nil fields fall back to a benign default.
type mockHandler struct {
	runAgent     func(ctx context.Context, m Manifest) (string, error)
	stopAgent    func(ctx context.Context, id string) error
	listAgents   func(ctx context.Context) ([]AgentSummary, error)
	agentLogs    func(ctx context.Context, id string, tailN int) ([]Event, error)
	streamEvents func(ctx context.Context, id string, sink func(Event) error) error
	daemonStatus func(ctx context.Context) (DaemonStatusResult, error)
}

func (h *mockHandler) RunAgent(ctx context.Context, m Manifest) (string, error) {
	if h.runAgent != nil {
		return h.runAgent(ctx, m)
	}
	return "agt_test", nil
}
func (h *mockHandler) StopAgent(ctx context.Context, id string) error {
	if h.stopAgent != nil {
		return h.stopAgent(ctx, id)
	}
	return nil
}
func (h *mockHandler) ListAgents(ctx context.Context) ([]AgentSummary, error) {
	if h.listAgents != nil {
		return h.listAgents(ctx)
	}
	return nil, nil
}
func (h *mockHandler) AgentLogs(ctx context.Context, id string, tailN int) ([]Event, error) {
	if h.agentLogs != nil {
		return h.agentLogs(ctx, id, tailN)
	}
	return nil, nil
}
func (h *mockHandler) StreamEvents(ctx context.Context, id string, sink func(Event) error) error {
	if h.streamEvents != nil {
		return h.streamEvents(ctx, id, sink)
	}
	return nil
}
func (h *mockHandler) DaemonStatus(ctx context.Context) (DaemonStatusResult, error) {
	if h.daemonStatus != nil {
		return h.daemonStatus(ctx)
	}
	return DaemonStatusResult{Version: "test"}, nil
}

// startServer spins up a server on a temp socket and returns its path plus
// a shutdown func. The server runs until the returned cancel is called.
func startServer(t *testing.T, h Handler) (socketPath string, shutdown func()) {
	t.Helper()
	socketPath = filepath.Join(t.TempDir(), "ipc.sock")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(socketPath, h, logger)
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()
	return socketPath, func() {
		cancel()
		<-done
		_ = srv.Stop()
	}
}

func dial(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return c
}

func TestRunAgentRoundTrip(t *testing.T) {
	var gotManifest Manifest
	h := &mockHandler{
		runAgent: func(_ context.Context, m Manifest) (string, error) {
			gotManifest = m
			return "agt_abc12345", nil
		},
	}
	sock, stop := startServer(t, h)
	defer stop()

	c := dial(t, sock)
	defer c.Close()

	params, _ := json.Marshal(RunAgentParams{Manifest: Manifest{
		Name:    "test",
		Command: []string{"sh", "-c", "echo hi"},
	}})
	if err := WriteFrame(c, Request{Method: MethodRunAgent, Params: params}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	var resp Response
	if err := ReadFrame(c, &resp); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok, got error: %+v", resp.Error)
	}
	var res RunAgentResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if res.AgentID != "agt_abc12345" {
		t.Fatalf("agent id mismatch: %s", res.AgentID)
	}
	if gotManifest.Name != "test" || len(gotManifest.Command) != 3 {
		t.Fatalf("handler saw wrong manifest: %+v", gotManifest)
	}
}

func TestRunAgentRejectsEmptyCommand(t *testing.T) {
	h := &mockHandler{
		runAgent: func(_ context.Context, _ Manifest) (string, error) {
			t.Fatal("handler must not be invoked for an invalid manifest")
			return "", nil
		},
	}
	sock, stop := startServer(t, h)
	defer stop()
	c := dial(t, sock)
	defer c.Close()

	params, _ := json.Marshal(RunAgentParams{Manifest: Manifest{Name: "x"}})
	if err := WriteFrame(c, Request{Method: MethodRunAgent, Params: params}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var resp Response
	if err := ReadFrame(c, &resp); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if resp.OK {
		t.Fatalf("expected error response, got ok")
	}
	if resp.Error == nil || resp.Error.Code != ErrInvalidManifest {
		t.Fatalf("expected INVALID_MANIFEST, got %+v", resp.Error)
	}
}

func TestUnknownMethod(t *testing.T) {
	sock, stop := startServer(t, &mockHandler{})
	defer stop()
	c := dial(t, sock)
	defer c.Close()

	if err := WriteFrame(c, Request{Method: "Bogus", Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var resp Response
	if err := ReadFrame(c, &resp); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if resp.OK {
		t.Fatalf("expected error, got ok")
	}
	if resp.Error == nil || resp.Error.Code != ErrInternal {
		t.Fatalf("expected INTERNAL, got %+v", resp.Error)
	}
	if resp.Error.Message == "" {
		t.Fatalf("expected non-empty message")
	}
}

func TestSentinelErrorMapping(t *testing.T) {
	h := &mockHandler{
		stopAgent: func(_ context.Context, _ string) error {
			return ErrAgentNotFoundErr
		},
	}
	sock, stop := startServer(t, h)
	defer stop()
	c := dial(t, sock)
	defer c.Close()

	params, _ := json.Marshal(StopAgentParams{AgentID: "missing"})
	if err := WriteFrame(c, Request{Method: MethodStopAgent, Params: params}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var resp Response
	if err := ReadFrame(c, &resp); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if resp.OK || resp.Error == nil || resp.Error.Code != ErrAgentNotFound {
		t.Fatalf("expected AGENT_NOT_FOUND, got %+v / %+v", resp.OK, resp.Error)
	}
}

func TestStreamEventsAndCancel(t *testing.T) {
	// streamEvents pushes 3 events then blocks on ctx; we test both that
	// frames arrive and that cancelling the server unblocks the handler.
	released := make(chan struct{})
	h := &mockHandler{
		streamEvents: func(ctx context.Context, _ string, sink func(Event) error) error {
			defer close(released)
			for i := 0; i < 3; i++ {
				details, _ := json.Marshal(map[string]int{"n": i})
				if err := sink(Event{
					Ts:      time.Now(),
					AgentID: "agt_test",
					Type:    "agent.started",
					PID:     1234,
					Details: details,
				}); err != nil {
					return err
				}
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}
	sock, stop := startServer(t, h)
	// stop is also called explicitly below to assert ctx-driven shutdown
	// unblocks the handler; sync.Once makes the deferred call a no-op.
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(stop) }
	defer stopFn()

	c := dial(t, sock)
	defer c.Close()

	params, _ := json.Marshal(StreamEventsParams{AgentID: "agt_test"})
	if err := WriteFrame(c, Request{Method: MethodStreamEvents, Params: params}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Read the 3 expected event frames.
	for i := 0; i < 3; i++ {
		var resp Response
		if err := ReadFrame(c, &resp); err != nil {
			t.Fatalf("ReadFrame %d: %v", i, err)
		}
		if !resp.OK {
			t.Fatalf("frame %d not ok: %+v", i, resp.Error)
		}
		var ev Event
		if err := json.Unmarshal(resp.Result, &ev); err != nil {
			t.Fatalf("unmarshal event %d: %v", i, err)
		}
		if ev.AgentID != "agt_test" {
			t.Fatalf("frame %d wrong agent id: %s", i, ev.AgentID)
		}
	}

	// Trigger shutdown; the streamEvents goroutine must release.
	stopFn()
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("stream handler did not exit on ctx cancel")
	}
}

func TestStopAgentSuccess(t *testing.T) {
	called := false
	h := &mockHandler{
		stopAgent: func(_ context.Context, id string) error {
			called = true
			if id != "agt_xyz" {
				t.Errorf("wrong id: %s", id)
			}
			return nil
		},
	}
	sock, stop := startServer(t, h)
	defer stop()
	c := dial(t, sock)
	defer c.Close()

	params, _ := json.Marshal(StopAgentParams{AgentID: "agt_xyz"})
	if err := WriteFrame(c, Request{Method: MethodStopAgent, Params: params}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var resp Response
	if err := ReadFrame(c, &resp); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok, got %+v", resp.Error)
	}
	var res StopAgentResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected inner ok=true")
	}
	if !called {
		t.Fatal("handler not invoked")
	}
}

func TestListAgentsEmpty(t *testing.T) {
	sock, stop := startServer(t, &mockHandler{})
	defer stop()
	c := dial(t, sock)
	defer c.Close()

	if err := WriteFrame(c, Request{Method: MethodListAgents, Params: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var resp Response
	if err := ReadFrame(c, &resp); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !resp.OK {
		t.Fatalf("expected ok, got %+v", resp.Error)
	}
	var res ListAgentsResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Agents == nil {
		t.Fatal("expected non-nil empty slice (JSON: []), got null")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	// Pure unit test for WriteFrame/ReadFrame without a server.
	var buf bytesBuffer
	in := map[string]any{"hello": "world", "n": 42}
	if err := WriteFrame(&buf, in); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	var out map[string]any
	if err := ReadFrame(&buf, &out); err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if out["hello"] != "world" {
		t.Fatalf("roundtrip mismatch: %+v", out)
	}
}

func TestReadFrameEOFAtBoundary(t *testing.T) {
	var buf bytesBuffer
	var out map[string]any
	err := ReadFrame(&buf, &out)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF on empty buffer, got %v", err)
	}
}

// bytesBuffer is a minimal io.ReadWriter — we can't use bytes.Buffer
// directly because we want to exercise ReadFrame's io.ReadFull on a stream
// that returns 0,EOF cleanly at a frame boundary, which bytes.Buffer does.
type bytesBuffer struct {
	data []byte
}

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bytesBuffer) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	return n, nil
}
