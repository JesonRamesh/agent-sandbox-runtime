//go:build linux && integration

package cgroup

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const testNamespace = "agent-sandbox-test"

func requireCgroup2(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("integration test requires root")
	}
	// cgroup2 mounts expose cgroup.controllers at the root.
	if _, err := os.Stat(filepath.Join(Root, "cgroup.controllers")); err != nil {
		t.Skipf("cgroup2 not mounted at %s: %v", Root, err)
	}
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	requireCgroup2(t)
	m := NewManager(Root, testNamespace)
	t.Cleanup(func() {
		_ = os.RemoveAll(m.parentDir())
	})
	return m
}

func TestCreateDestroyRoundTrip(t *testing.T) {
	m := newTestManager(t)
	cg, err := m.Create("round-trip")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := os.Stat(cg.Path()); err != nil {
		t.Fatalf("expected cgroup dir to exist: %v", err)
	}
	if err := cg.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := os.Stat(cg.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cgroup dir gone, got err=%v", err)
	}
}

func TestCreateDuplicateErrors(t *testing.T) {
	m := newTestManager(t)
	cg, err := m.Create("dup")
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	defer cg.Destroy()

	_, err = m.Create("dup")
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected os.ErrExist on duplicate, got %v", err)
	}
}

func TestDestroyKillsLiveProcess(t *testing.T) {
	m := newTestManager(t)
	cg, err := m.Create("killer")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    cg.FD(),
	}
	if err := cmd.Start(); err != nil {
		cg.Destroy()
		t.Fatalf("starting sleep: %v", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()

	if err := cg.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	select {
	case <-waitErr:
		// child died as expected
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("child sleep was not killed by cgroup.kill within 5s")
	}

	if _, err := os.Stat(cg.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected cgroup dir gone after Destroy, got err=%v", err)
	}
}

func TestListReturnsCreatedExcludesUnrelated(t *testing.T) {
	m := newTestManager(t)

	a, err := m.Create("alpha")
	if err != nil {
		t.Fatalf("Create alpha: %v", err)
	}
	defer a.Destroy()
	b, err := m.Create("bravo")
	if err != nil {
		t.Fatalf("Create bravo: %v", err)
	}
	defer b.Destroy()

	// A regular file in the namespace dir must be skipped by List.
	stray := filepath.Join(m.parentDir(), "not-a-cgroup")
	if err := os.WriteFile(stray, []byte("x"), 0o644); err != nil {
		t.Fatalf("writing stray file: %v", err)
	}

	got, err := m.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	defer func() {
		for _, c := range got {
			_ = syscall.Close(c.FD())
		}
	}()

	names := map[string]bool{}
	for _, c := range got {
		names[c.Name()] = true
		if c.FD() < 0 {
			t.Errorf("expected open fd for %s, got %d", c.Name(), c.FD())
		}
	}
	if !names["alpha"] || !names["bravo"] {
		t.Fatalf("expected alpha and bravo in list, got %v", names)
	}
	if names["not-a-cgroup"] {
		t.Fatalf("List included stray file")
	}
}
