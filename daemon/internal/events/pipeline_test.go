package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

// silentLogger discards everything; tests assert on behavior, not log output.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mkEvent(agentID, kind string) ipc.Event {
	return ipc.Event{
		Ts:      time.Now().UTC(),
		AgentID: agentID,
		Type:    kind,
		PID:     1234,
		Details: json.RawMessage(`{}`),
	}
}

func newTestPipeline(t *testing.T, cfg Config) *Pipeline {
	t.Helper()
	if cfg.LogDir == "" {
		cfg.LogDir = t.TempDir()
	}
	p, err := NewPipeline(cfg, silentLogger())
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestSubmitDeliversToSubscriber(t *testing.T) {
	p := newTestPipeline(t, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	got := make(chan ipc.Event, 1)
	unsub := p.Subscribe("", func(ev ipc.Event) error {
		got <- ev
		return nil
	})
	defer unsub()

	want := mkEvent("agt_1", "agent.started")
	p.Submit(want)

	select {
	case ev := <-got:
		if ev.AgentID != want.AgentID || ev.Type != want.Type {
			t.Fatalf("unexpected event: got %+v, want %+v", ev, want)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber never received event")
	}
}

func TestAgentFilter(t *testing.T) {
	p := newTestPipeline(t, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	var aMu, allMu sync.Mutex
	var aGot, allGot []ipc.Event

	unsubA := p.Subscribe("agt_A", func(ev ipc.Event) error {
		aMu.Lock()
		aGot = append(aGot, ev)
		aMu.Unlock()
		return nil
	})
	defer unsubA()

	unsubAll := p.Subscribe("", func(ev ipc.Event) error {
		allMu.Lock()
		allGot = append(allGot, ev)
		allMu.Unlock()
		return nil
	})
	defer unsubAll()

	p.Submit(mkEvent("agt_A", "network.block"))
	p.Submit(mkEvent("agt_B", "network.block"))

	// Wait for both to land in allGot. Polling rather than sleeping —
	// fan-out is synchronous in Run's goroutine but Submit hands off via
	// a channel.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		allMu.Lock()
		n := len(allGot)
		allMu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	aMu.Lock()
	defer aMu.Unlock()
	allMu.Lock()
	defer allMu.Unlock()

	if len(aGot) != 1 || aGot[0].AgentID != "agt_A" {
		t.Fatalf("filtered subscriber got %+v, want exactly one agt_A event", aGot)
	}
	if len(allGot) != 2 {
		t.Fatalf("all-subscriber got %d events, want 2", len(allGot))
	}
}

func TestSubscriberErrorRemoval(t *testing.T) {
	p := newTestPipeline(t, Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	var calls atomic.Int32
	unsub := p.Subscribe("", func(ev ipc.Event) error {
		calls.Add(1)
		return errors.New("client gone")
	})
	defer unsub()

	p.Submit(mkEvent("agt_1", "agent.started"))
	// Give fanOut a chance to deliver and remove.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Submit a second event — the bad subscriber should not be called again.
	p.Submit(mkEvent("agt_1", "agent.exited"))
	time.Sleep(100 * time.Millisecond)

	if got := calls.Load(); got != 1 {
		t.Fatalf("erroring sink was called %d times, want 1 (then removed)", got)
	}
}

func TestAgentLogTail(t *testing.T) {
	dir := t.TempDir()
	p := newTestPipeline(t, Config{LogDir: dir})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	for i := 0; i < 5; i++ {
		p.Submit(mkEvent("agt_T", fmt.Sprintf("evt.%d", i)))
	}

	// Wait for the file to have all 5 lines.
	logPath := filepath.Join(dir, "agt_T.log")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		evs, _ := p.AgentLogTail("agt_T", 0)
		if len(evs) == 5 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	tail, err := p.AgentLogTail("agt_T", 2)
	if err != nil {
		t.Fatalf("AgentLogTail: %v", err)
	}
	if len(tail) != 2 {
		t.Fatalf("tail returned %d events, want 2 (file: %s)", len(tail), logPath)
	}
	if tail[0].Type != "evt.3" || tail[1].Type != "evt.4" {
		t.Fatalf("tail order wrong: got [%s, %s], want [evt.3, evt.4]",
			tail[0].Type, tail[1].Type)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	// 4 KiB cap, 2 files: expect .log + .log.1 to exist, .log.2 to never appear.
	p, err := NewPipeline(Config{
		LogDir:       dir,
		MaxFileBytes: 4 * 1024,
		MaxFiles:     2,
		BufferSize:   1024,
	}, silentLogger())
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)

	// Generate ~12 KiB worth of events. mkEvent JSON is ~120 bytes; pad
	// details to make per-event size predictable.
	bigDetails := make([]byte, 200)
	for i := range bigDetails {
		bigDetails[i] = 'x'
	}
	pad, _ := json.Marshal(map[string]string{"pad": string(bigDetails)})

	for i := 0; i < 80; i++ {
		ev := mkEvent("agt_R", "filler")
		ev.Details = pad
		p.Submit(ev)
	}

	// Wait for file activity to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "agt_R.log.1")); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if _, err := os.Stat(filepath.Join(dir, "agt_R.log")); err != nil {
		t.Fatalf("expected current .log to exist: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agt_R.log.1")); err != nil {
		t.Fatalf("expected .log.1 to exist after rotation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agt_R.log.2")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".log.2 should not exist with MaxFiles=2 (err=%v)", err)
	}
}

func TestSubmitDoesNotBlockWhenBufferFull(t *testing.T) {
	// BufferSize=1, no Run goroutine — every Submit past the first fills the
	// buffer. The contract says Submit drops rather than blocks; if it
	// blocks, this test deadlocks (and the test runner's timeout catches it).
	p, err := NewPipeline(Config{
		LogDir:     t.TempDir(),
		BufferSize: 1,
	}, silentLogger())
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			p.Submit(mkEvent("agt_X", "net.block"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Submit blocked when buffer was full")
	}
}

func TestNewWSServerRejectsNonLoopback(t *testing.T) {
	p := newTestPipeline(t, Config{})
	cases := []string{
		"0.0.0.0:7443",
		"8.8.8.8:7443",
		":7443", // wildcard
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			s := NewWSServer(addr, p, silentLogger())
			if err := s.Start(); err == nil {
				_ = s.Stop(context.Background())
				t.Fatalf("Start(%q) returned nil; want non-loopback rejection", addr)
			}
		})
	}

	// Sanity: a loopback addr should at least pass the validation step.
	// We pick :0 isn't allowed (loopback only), so use 127.0.0.1:0 which
	// asks the OS to choose a free port — verifies validation, then we stop.
	s := NewWSServer("127.0.0.1:0", p, silentLogger())
	if err := s.Start(); err != nil {
		t.Fatalf("loopback Start failed: %v", err)
	}
	_ = s.Stop(context.Background())
}
