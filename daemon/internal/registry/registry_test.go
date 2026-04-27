package registry

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

func newTestAgent(id string) *Agent {
	return &Agent{
		ID:        id,
		Name:      "test-" + id,
		Manifest:  ipc.Manifest{Name: "test-" + id, Command: []string{"/bin/true"}},
		PID:       1000,
		StartedAt: time.Now(),
	}
}

func TestAddGetRemoveRoundTrip(t *testing.T) {
	r := New()
	a := newTestAgent("a1")

	if err := r.Add(a); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := r.Get("a1")
	if !ok {
		t.Fatal("Get(a1) not found after Add")
	}
	if got != a {
		t.Fatal("Get returned different pointer than Add")
	}
	if got.Status() != StatusRunning {
		t.Errorf("expected default status running, got %v", got.Status())
	}

	removed, ok := r.Remove("a1")
	if !ok {
		t.Fatal("Remove(a1) returned !ok")
	}
	if removed != a {
		t.Fatal("Remove returned different pointer")
	}

	if _, ok := r.Get("a1"); ok {
		t.Fatal("Get(a1) still found after Remove")
	}
	if _, ok := r.Remove("a1"); ok {
		t.Fatal("second Remove(a1) returned ok")
	}
}

func TestAddDuplicateID(t *testing.T) {
	r := New()
	if err := r.Add(newTestAgent("dup")); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := r.Add(newTestAgent("dup")); err == nil {
		t.Fatal("expected error on duplicate ID, got nil")
	}
}

func TestAddNilAndEmptyID(t *testing.T) {
	r := New()
	if err := r.Add(nil); err == nil {
		t.Error("expected error adding nil agent")
	}
	if err := r.Add(&Agent{}); err == nil {
		t.Error("expected error adding agent with empty ID")
	}
}

func TestStatusTransitions(t *testing.T) {
	a := newTestAgent("s1")
	if a.Status() != StatusRunning {
		// Note: a freshly constructed Agent has status==0 which equals
		// StatusRunning by iota assignment. This relationship is load-bearing
		// for the registry: Add() relies on it to leave new agents in the
		// running state without an explicit setter call.
		t.Errorf("zero value status = %v, want StatusRunning", a.Status())
	}
	if _, ok := a.ExitedAt(); ok {
		t.Error("ExitedAt should be !ok while running")
	}

	a.MarkExited(0)
	if a.Status() != StatusExited {
		t.Errorf("after MarkExited: %v", a.Status())
	}
	if a.ExitCode() != 0 {
		t.Errorf("exit code: %v", a.ExitCode())
	}
	if _, ok := a.ExitedAt(); !ok {
		t.Error("ExitedAt should be ok after MarkExited")
	}

	b := newTestAgent("s2")
	b.MarkCrashed(137)
	if b.Status() != StatusCrashed {
		t.Errorf("after MarkCrashed: %v", b.Status())
	}
	if b.ExitCode() != 137 {
		t.Errorf("crashed exit code: %v", b.ExitCode())
	}
}

func TestStatusString(t *testing.T) {
	cases := map[Status]string{
		StatusRunning: "running",
		StatusExited:  "exited",
		StatusCrashed: "crashed",
		Status(99):    "unknown",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", s, got, want)
		}
	}
}

func TestSnapshot(t *testing.T) {
	a := newTestAgent("snap")
	a.PID = 4242
	snap := a.Snapshot()
	if snap.AgentID != "snap" || snap.PID != 4242 || snap.Status != "running" {
		t.Fatalf("snapshot mismatch: %+v", snap)
	}

	// Mutating the agent must not retroactively change the snapshot.
	a.MarkExited(0)
	if snap.Status != "running" {
		t.Errorf("snapshot mutated after MarkExited: %v", snap.Status)
	}
}

func TestSummariesIsImmutable(t *testing.T) {
	r := New()
	for _, id := range []string{"x", "y", "z"} {
		if err := r.Add(newTestAgent(id)); err != nil {
			t.Fatal(err)
		}
	}
	summaries := r.Summaries()
	if len(summaries) != 3 {
		t.Fatalf("expected 3 summaries, got %d", len(summaries))
	}

	// Snapshot is captured at call time; later mutations should not change it.
	x, _ := r.Get("x")
	x.MarkCrashed(1)
	for _, s := range summaries {
		if s.AgentID == "x" && s.Status != "running" {
			t.Errorf("summary for x mutated: %v", s.Status)
		}
	}
}

func TestList(t *testing.T) {
	r := New()
	if got := r.List(); len(got) != 0 {
		t.Errorf("empty registry list len = %d", len(got))
	}
	for _, id := range []string{"a", "b", "c"} {
		_ = r.Add(newTestAgent(id))
	}
	got := r.List()
	if len(got) != 3 {
		t.Fatalf("want 3 agents, got %d", len(got))
	}
	// Mutating returned slice must not affect the registry.
	got[0] = nil
	if r2 := r.List(); len(r2) != 3 || r2[0] == nil {
		t.Error("List did not return an independent slice")
	}
}

func TestReap(t *testing.T) {
	r := New()
	running := newTestAgent("running")
	exited := newTestAgent("exited")
	crashed := newTestAgent("crashed")
	for _, a := range []*Agent{running, exited, crashed} {
		if err := r.Add(a); err != nil {
			t.Fatal(err)
		}
	}

	// Backdate exit times to 100ms ago by manipulating fields directly under
	// the lock. This avoids a sleep in the test.
	past := time.Now().Add(-100 * time.Millisecond)
	exited.mu.Lock()
	exited.status = StatusExited
	exited.exitedAt = past
	exited.mu.Unlock()
	crashed.mu.Lock()
	crashed.status = StatusCrashed
	crashed.exitedAt = past
	crashed.mu.Unlock()

	removed := r.Reap(50 * time.Millisecond)
	if len(removed) != 2 {
		t.Fatalf("expected 2 removed, got %d: %v", len(removed), removed)
	}
	want := map[string]bool{"exited": true, "crashed": true}
	for _, id := range removed {
		if !want[id] {
			t.Errorf("unexpected reap of %q", id)
		}
	}
	if _, ok := r.Get("running"); !ok {
		t.Error("running agent was reaped")
	}
	if _, ok := r.Get("exited"); ok {
		t.Error("exited agent still present")
	}
}

func TestReapRetentionNotElapsed(t *testing.T) {
	r := New()
	a := newTestAgent("recent")
	_ = r.Add(a)
	a.MarkExited(0) // exitedAt = now

	if removed := r.Reap(time.Hour); len(removed) != 0 {
		t.Errorf("should not reap within retention: %v", removed)
	}
}

func TestReapEmpty(t *testing.T) {
	r := New()
	if got := r.Reap(time.Second); got != nil {
		t.Errorf("empty registry Reap returned %v", got)
	}
}

// TestConcurrentAddRemove exercises the locking discipline with the race
// detector. Run with `go test -race ./internal/registry`.
func TestConcurrentAddRemove(t *testing.T) {
	r := New()
	const workers = 16
	const perWorker = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := fmt.Sprintf("w%d-%d", w, i)
				a := newTestAgent(id)
				if err := r.Add(a); err != nil {
					t.Errorf("add: %v", err)
					return
				}
				// Mix in reads from other goroutines' work — exercises the
				// RLock path.
				_ = r.List()
				_ = r.Summaries()
				if got, ok := r.Get(id); !ok || got != a {
					t.Errorf("get after add: %v %v", got, ok)
					return
				}
				if i%2 == 0 {
					a.MarkExited(0)
				} else {
					a.MarkCrashed(1)
				}
				if _, ok := r.Remove(id); !ok {
					t.Errorf("remove after add: %s", id)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if got := r.List(); len(got) != 0 {
		t.Errorf("expected empty registry, have %d agents", len(got))
	}
}

// TestConcurrentReap runs Reap concurrently with Add/Remove to verify the
// double-check-under-write-lock guard against double-reporting.
func TestConcurrentReap(t *testing.T) {
	r := New()
	const n = 100
	for i := 0; i < n; i++ {
		a := newTestAgent(fmt.Sprintf("a%d", i))
		_ = r.Add(a)
		a.MarkExited(0)
		// Backdate so all are reapable.
		a.mu.Lock()
		a.exitedAt = time.Now().Add(-time.Hour)
		a.mu.Unlock()
	}

	var wg sync.WaitGroup
	seen := make(map[string]int)
	var seenMu sync.Mutex
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids := r.Reap(time.Minute)
			seenMu.Lock()
			for _, id := range ids {
				seen[id]++
			}
			seenMu.Unlock()
		}()
	}
	wg.Wait()

	if len(seen) != n {
		t.Errorf("expected %d distinct reaped ids, got %d", n, len(seen))
	}
	for id, c := range seen {
		if c != 1 {
			t.Errorf("id %s reaped %d times (want 1)", id, c)
		}
	}
}
