//go:build linux

package bpf

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// deliver must complete promptly when ac.done is closed before the send,
// even if the data channel has no receiver and is full. Without the
// done-case the send would block forever; without it being safe to send
// concurrently with cleanup the program would have panicked previously.
func TestRuntime_deliver_completesAfterDone(t *testing.T) {
	rt := &Runtime{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ac := &agentChan{ch: make(chan Event), done: make(chan struct{})}
	close(ac.done)
	got := make(chan struct{})
	go func() {
		rt.deliver(ac, Event{CgroupID: 42})
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("deliver blocked after done was closed")
	}
}

// deliver delivers normally when done is open and the buffer has space.
func TestRuntime_deliver_deliversWhenOpen(t *testing.T) {
	rt := &Runtime{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ac := &agentChan{ch: make(chan Event, 1), done: make(chan struct{})}
	rt.deliver(ac, Event{CgroupID: 7})
	select {
	case ev := <-ac.ch:
		if ev.CgroupID != 7 {
			t.Fatalf("got cgroup_id %d, want 7", ev.CgroupID)
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered")
	}
}

// Concurrent close(done) and deliver must be race-free under -race. With
// the new design the data channel is never closed, so send is always safe;
// done is closed exactly once and only observed via select.
func TestRuntime_deliver_raceCleanupDuringSend(t *testing.T) {
	rt := &Runtime{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	const channels = 200
	var wg sync.WaitGroup
	for i := 0; i < channels; i++ {
		ac := &agentChan{ch: make(chan Event, 1), done: make(chan struct{})}
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				rt.deliver(ac, Event{CgroupID: uint64(j)})
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Microsecond)
			close(ac.done)
		}()
	}
	wg.Wait()
}
