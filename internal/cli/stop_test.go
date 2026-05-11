package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agent-sandbox/runtime/internal/client"
)

// TestStop_RejectsNegativeGrace verifies M9: a negative --grace is a usage
// error caught at the CLI before any IPC is opened. A daemon that naively
// did time.Sleep(grace) on a negative value would skip SIGTERM entirely,
// so we refuse it here rather than punt the question downstream.
func TestStop_RejectsNegativeGrace(t *testing.T) {
	cmd := newStopCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"foo", "--grace", "-1s"})

	rt := &appRuntime{
		Stdout:      out,
		Stderr:      out,
		DialTimeout: client.DefaultDialTimeout,
	}
	cmd.SetContext(withRuntime(context.Background(), rt))

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for negative --grace; got nil")
	}
	if !strings.Contains(err.Error(), ">= 0") {
		t.Errorf("error %q should mention non-negative requirement", err)
	}
}

// TestStop_RejectsExcessiveGrace verifies the upper bound (1h). A multi-hour
// grace would let one stuck agent block the daemon's outer shutdown deadline
// — refuse it at the validator.
func TestStop_RejectsExcessiveGrace(t *testing.T) {
	cmd := newStopCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"foo", "--grace", "2h"})

	rt := &appRuntime{
		Stdout:      out,
		Stderr:      out,
		DialTimeout: client.DefaultDialTimeout,
	}
	cmd.SetContext(withRuntime(context.Background(), rt))

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for excessive --grace; got nil")
	}
	if !strings.Contains(err.Error(), "1h0m0s") && !strings.Contains(err.Error(), "must be <=") {
		t.Errorf("error %q should mention the 1h cap", err)
	}
}

// TestMaxStopGrace_Sanity guards the constant from drifting silently.
func TestMaxStopGrace_Sanity(t *testing.T) {
	if MaxStopGrace != time.Hour {
		t.Errorf("MaxStopGrace = %s, want 1h", MaxStopGrace)
	}
}
