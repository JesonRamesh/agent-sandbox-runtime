//go:build !linux

package cgroup

import "errors"

const (
	Root      = "/sys/fs/cgroup"
	Namespace = "agent-sandbox"
)

var errUnsupported = errors.New("cgroup: only supported on Linux")

type Cgroup struct {
	name string
	path string
	fd   int
}

type Manager struct{}

func NewManager(root, namespace string) *Manager { return &Manager{} }

func Create(name string) (*Cgroup, error) { return nil, errUnsupported }

func List() ([]*Cgroup, error) { return nil, errUnsupported }

func (m *Manager) Create(name string) (*Cgroup, error) { return nil, errUnsupported }

func (m *Manager) List() ([]*Cgroup, error) { return nil, errUnsupported }

func (c *Cgroup) FD() int { return -1 }

func (c *Cgroup) Path() string { return c.path }

func (c *Cgroup) Name() string { return c.name }

func (c *Cgroup) Destroy() error { return errUnsupported }

func (c *Cgroup) ID() (uint64, error) { return 0, errUnsupported }

func Adopt(name string) (*Cgroup, error) { return nil, errUnsupported }

func (m *Manager) Adopt(name string) (*Cgroup, error) { return nil, errUnsupported }
