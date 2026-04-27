//go:build linux && e2e

// Package e2e runs the daemon binary against the test-client to validate
// brief Phase 3 acceptance bullets. Build the binaries first (`make build`)
// and run with `sudo make test-e2e`.
//
// These tests are gated `e2e` because they:
//   - require root for cgroup + BPF;
//   - bind a real Unix socket and websocket port;
//   - exec real commands (curl) that hit the network.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

const (
	daemonBin = "../../bin/agent-sandbox-daemon"
	clientBin = "../../bin/test-client"
)

func TestE2E_BlockedHostFails(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("e2e requires root")
	}
	if _, err := os.Stat(daemonBin); err != nil {
		t.Skipf("daemon binary not built (%s): run `make build` first", daemonBin)
	}

	tmp := t.TempDir()
	socket := filepath.Join(tmp, "sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, daemonBin,
		"--socket", socket,
		"--log-dir", tmp,
		"--ws-addr", "127.0.0.1:0", // 0 = pick free, but our server insists on a real port; 7443 might collide. CAVEATS.
		"--keep-crashed", "1s",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting daemon: %v", err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	}()

	if err := waitForSocket(socket, 5*time.Second); err != nil {
		t.Fatalf("socket never appeared: %v", err)
	}

	// Send a RunAgent that curls a blocked host (1.1.1.1 isn't in allowed_hosts → LSM denies).
	// Mode defaults to "enforce". The file pillar would otherwise block libc.so etc., so
	// allow / for paths to keep the test focused on the network pillar.
	manifest := ipc.Manifest{
		Name:         "e2e-blocked",
		Command:      []string{"curl", "-s", "-m", "3", "http://1.1.1.1"},
		Mode:         "enforce",
		AllowedHosts: []string{"127.0.0.1:1"}, // arbitrary non-empty allowlist
		AllowedPaths: []string{"/"},
	}
	resp, err := callRun(socket, manifest)
	if err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	if resp.AgentID == "" {
		t.Fatalf("RunAgent returned empty agent_id")
	}

	// Wait for curl to time out and the agent to exit. With `-m 3` curl
	// should return within ~4s; daemon emits agent.exited then.
	time.Sleep(6 * time.Second)

	// AgentLogs should contain a net.connect event with verdict=deny and daddr=1.1.1.1.
	logs, err := callLogs(socket, resp.AgentID, 200)
	if err != nil {
		t.Fatalf("AgentLogs: %v", err)
	}
	found := false
	for _, ev := range logs {
		if ev.Type != "net.connect" {
			continue
		}
		if bytes.Contains(ev.Details, []byte(`"daddr":"1.1.1.1"`)) &&
			bytes.Contains(ev.Details, []byte(`"verdict":"deny"`)) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no net.connect/deny event for 1.1.1.1; got %d events", len(logs))
	}
}

func waitForSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("socket %s did not appear within %v", path, timeout)
}

func dial(socket string) (net.Conn, error) {
	return net.Dial("unix", socket)
}

func callRun(socket string, m ipc.Manifest) (*ipc.RunAgentResult, error) {
	conn, err := dial(socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	params, _ := json.Marshal(ipc.RunAgentParams{Manifest: m})
	if err := ipc.WriteFrame(conn, ipc.Request{Method: ipc.MethodRunAgent, Params: params}); err != nil {
		return nil, err
	}
	var resp ipc.Response
	if err := ipc.ReadFrame(conn, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("server error: %s", resp.Error.Message)
	}
	var out ipc.RunAgentResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func callLogs(socket, id string, n int) ([]ipc.Event, error) {
	conn, err := dial(socket)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	params, _ := json.Marshal(ipc.AgentLogsParams{AgentID: id, TailN: n})
	if err := ipc.WriteFrame(conn, ipc.Request{Method: ipc.MethodAgentLogs, Params: params}); err != nil {
		return nil, err
	}
	var resp ipc.Response
	if err := ipc.ReadFrame(conn, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("server error: %s", resp.Error.Message)
	}
	var out ipc.AgentLogsResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return nil, err
	}
	return out.Lines, nil
}
