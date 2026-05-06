package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/agent-sandbox/runtime/internal/client"
)

// TestLogs_RejectsNegativeTailBeforeDial verifies L4: --tail < 0 must be
// rejected before opening the daemon socket. The CLI no longer dials when
// the user typo'd a flag — the runtime ctx never reaches the client.
//
// We use a deliberately-bad socket path so any dial attempt would surface
// as a different error than the usage one. If the validator order is wrong
// (dial first, then validate), the test fails because the surfaced error
// will mention the socket, not the flag.
func TestLogs_RejectsNegativeTailBeforeDial(t *testing.T) {
	cmd := newLogsCmd()
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetArgs([]string{"foo", "--tail", "-5"})

	rt := &appRuntime{
		Stdout:      out,
		Stderr:      out,
		Socket:      "/nonexistent/asb-test-no-daemon.sock",
		DialTimeout: client.DefaultDialTimeout,
	}
	cmd.SetContext(withRuntime(context.Background(), rt))

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for negative --tail; got nil")
	}
	if !strings.Contains(err.Error(), "--tail must be >= 0") {
		t.Errorf("error %q should mention --tail must be >= 0; an error mentioning the socket means we dialed before validating", err)
	}
	// Also ensure we didn't surface a daemon-unreachable error — the validator
	// must short-circuit before any IPC.
	if errors.Is(err, client.ErrDaemonUnreachable) {
		t.Errorf("error reached ErrDaemonUnreachable; validator must short-circuit before dial")
	}
}
