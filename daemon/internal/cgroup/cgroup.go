//go:build linux

package cgroup

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// Root is the cgroup v2 unified hierarchy mount point.
	Root = "/sys/fs/cgroup"
	// Namespace is the parent directory under Root that contains all
	// daemon-managed cgroups. Tests override this via NewManager.
	Namespace = "agent-sandbox"
)

type Cgroup struct {
	name string
	path string
	// fd is held open for the lifetime of the Cgroup so it can be passed
	// to exec.Cmd via SysProcAttr.UseCgroupFD without races against rmdir.
	fd int
}

// ID returns the cgroup ID, which on cgroup v2 equals the inode number of
// the cgroup directory. The kernel exposes the same value via
// bpf_get_current_cgroup_id() inside BPF programs, so userspace can match
// policy entries to the BPF-side cgroup id by fstat'ing this fd.
func (c *Cgroup) ID() (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(c.fd, &st); err != nil {
		return 0, fmt.Errorf("fstat cgroup fd for %s: %w", c.path, err)
	}
	return st.Ino, nil
}

// Adopt opens an existing cgroup directory and returns a *Cgroup pointing
// at it. Used by daemon startup reconciliation to pick up cgroups that
// outlived the prior daemon process. Errors if name doesn't exist.
func Adopt(name string) (*Cgroup, error) {
	return defaultManager().Adopt(name)
}

func (m *Manager) Adopt(name string) (*Cgroup, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("adopting cgroup %q: invalid name", name)
	}
	path := filepath.Join(m.parentDir(), name)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("adopting cgroup %s: %w", name, err)
	}
	fd, err := syscall.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening cgroup dir %s: %w", path, err)
	}
	return &Cgroup{name: name, path: path, fd: fd}, nil
}

// Manager parameterizes the parent namespace so integration tests can use
// a sibling directory (e.g. agent-sandbox-test) without colliding with the
// production hierarchy.
type Manager struct {
	root      string
	namespace string
}

func NewManager(root, namespace string) *Manager {
	return &Manager{root: root, namespace: namespace}
}

func defaultManager() *Manager {
	return &Manager{root: Root, namespace: Namespace}
}

func (m *Manager) parentDir() string {
	return filepath.Join(m.root, m.namespace)
}

func Create(name string) (*Cgroup, error) {
	return defaultManager().Create(name)
}

func List() ([]*Cgroup, error) {
	return defaultManager().List()
}

func (m *Manager) Create(name string) (*Cgroup, error) {
	if name == "" || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("creating cgroup %q: invalid name", name)
	}

	parent := m.parentDir()
	// MkdirAll is safe here: the parent namespace dir is created on first
	// use and reused thereafter; only the leaf is required to be fresh.
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("creating cgroup parent %s: %w", parent, err)
	}

	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("creating cgroup %s: %w", name, os.ErrExist)
		}
		return nil, fmt.Errorf("creating cgroup %s: %w", name, err)
	}

	// O_DIRECTORY guards against following a symlink-replacement attack on
	// /sys/fs/cgroup; O_RDONLY is sufficient — the kernel only inspects the
	// fd's referenced inode for UseCgroupFD, not its access mode.
	fd, err := syscall.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("opening cgroup dir %s: %w", path, err)
	}

	return &Cgroup{name: name, path: path, fd: fd}, nil
}

func (m *Manager) List() ([]*Cgroup, error) {
	parent := m.parentDir()
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing cgroup parent %s: %w", parent, err)
	}

	var out []*Cgroup
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(parent, e.Name())
		fd, err := syscall.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			slog.Warn("cgroup: skipping entry, cannot open",
				slog.String("path", path),
				slog.String("err", err.Error()))
			continue
		}
		out = append(out, &Cgroup{name: e.Name(), path: path, fd: fd})
	}
	return out, nil
}

func (c *Cgroup) FD() int {
	return c.fd
}

func (c *Cgroup) Path() string {
	return c.path
}

func (c *Cgroup) Name() string {
	return c.name
}

func (c *Cgroup) Destroy() error {
	// cgroup.kill (kernel 5.14+) atomically SIGKILLs every pid in the
	// cgroup and its descendants. This is racier and uglier to do from
	// userspace by reading cgroup.procs and signalling each pid.
	killPath := filepath.Join(c.path, "cgroup.kill")
	var killErr error
	if err := os.WriteFile(killPath, []byte("1"), 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		killErr = fmt.Errorf("writing %s: %w", killPath, err)
	}

	// Close the directory fd before rmdir so the kernel can release the
	// inode. Guard against double-close on subsequent Destroy calls.
	if c.fd >= 0 {
		if err := syscall.Close(c.fd); err != nil && killErr == nil {
			killErr = fmt.Errorf("closing cgroup fd for %s: %w", c.name, err)
		}
		c.fd = -1
	}

	if err := os.Remove(c.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return killErr
		}
		return fmt.Errorf("removing cgroup %s: %w", c.path, err)
	}
	return killErr
}
