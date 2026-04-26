// Package policy holds the in-memory store of YAML guardrail policies
// and notifies subscribers when they change. The loader package
// translates Snapshot into BPF map writes.
package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Policy is the YAML-facing schema. Mirrors the README example.
type Policy struct {
	ID             uint32   `yaml:"id"             json:"id"`
	Name           string   `yaml:"name"           json:"name"`
	Mode           string   `yaml:"mode"           json:"mode"`            // "audit" | "enforce"
	AllowedHosts   []string `yaml:"allowed_hosts"  json:"allowed_hosts"`
	AllowedPaths   []string `yaml:"allowed_paths"  json:"allowed_paths"`
	AllowedBins    []string `yaml:"allowed_bins"   json:"allowed_bins"`
	ForbiddenCaps  []string `yaml:"forbidden_caps" json:"forbidden_caps"`
}

// Snapshot is the immutable view passed to subscribers.
type Snapshot struct {
	Policies map[uint32]Policy
	// CgroupID -> PolicyID. The daemon updates this map when an
	// agent is launched or torn down.
	Bindings map[uint64]uint32
}

type Store struct {
	mu        sync.RWMutex
	policies  map[uint32]Policy
	bindings  map[uint64]uint32
	listeners []func(Snapshot)
}

func NewStore() *Store {
	return &Store{
		policies: map[uint32]Policy{},
		bindings: map[uint64]uint32{},
	}
}

func (s *Store) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		var p Policy
		if err := yaml.Unmarshal(b, &p); err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		if p.ID == 0 {
			return fmt.Errorf("%s: id must be > 0", e.Name())
		}
		s.policies[p.ID] = p
	}
	return nil
}

func (s *Store) Put(p Policy) {
	s.mu.Lock()
	s.policies[p.ID] = p
	snap := s.snapshotLocked()
	listeners := append([]func(Snapshot){}, s.listeners...)
	s.mu.Unlock()
	for _, l := range listeners {
		l(snap)
	}
}

func (s *Store) Bind(cgroupID uint64, policyID uint32) {
	s.mu.Lock()
	if policyID == 0 {
		delete(s.bindings, cgroupID)
	} else {
		s.bindings[cgroupID] = policyID
	}
	snap := s.snapshotLocked()
	listeners := append([]func(Snapshot){}, s.listeners...)
	s.mu.Unlock()
	for _, l := range listeners {
		l(snap)
	}
}

func (s *Store) List() []Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	return out
}

func (s *Store) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() Snapshot {
	snap := Snapshot{
		Policies: make(map[uint32]Policy, len(s.policies)),
		Bindings: make(map[uint64]uint32, len(s.bindings)),
	}
	for k, v := range s.policies {
		snap.Policies[k] = v
	}
	for k, v := range s.bindings {
		snap.Bindings[k] = v
	}
	return snap
}

func (s *Store) OnChange(fn func(Snapshot)) {
	s.mu.Lock()
	s.listeners = append(s.listeners, fn)
	s.mu.Unlock()
}

// HostRule and PathRule are the daemon-facing parsed forms; the
// loader package converts these into the C structs in bpf/common.h.

type HostRule struct {
	AddrV4    uint32
	PrefixLen uint32
	Port      uint16
}

func ParseHost(spec string) (HostRule, error) {
	// Accept "1.2.3.4", "1.2.3.0/24", "1.2.3.4:443", "host.tld:443".
	port := uint16(0)
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		if p, err := strconv.Atoi(spec[i+1:]); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
			spec = spec[:i]
		}
	}
	prefix := uint32(32)
	if i := strings.Index(spec, "/"); i >= 0 {
		if p, err := strconv.Atoi(spec[i+1:]); err == nil && p >= 0 && p <= 32 {
			prefix = uint32(p)
			spec = spec[:i]
		}
	}
	ip := net.ParseIP(spec)
	if ip == nil {
		// DNS resolve the hostname to its A records. Multiple addrs
		// produce multiple HostRules; here we return the first.
		ips, err := net.LookupIP(spec)
		if err != nil || len(ips) == 0 {
			return HostRule{}, fmt.Errorf("cannot resolve host %q", spec)
		}
		ip = ips[0]
	}
	v4 := ip.To4()
	if v4 == nil {
		return HostRule{}, fmt.Errorf("ipv6 not supported in v0: %q", spec)
	}
	return HostRule{
		AddrV4:    uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24,
		PrefixLen: prefix,
		Port:      port,
	}, nil
}

// CapBit returns the bit position of a capability name like
// "CAP_SYS_ADMIN". See `man capabilities`.
var capBits = map[string]uint64{
	"CAP_CHOWN":             0,
	"CAP_DAC_OVERRIDE":      1,
	"CAP_DAC_READ_SEARCH":   2,
	"CAP_FOWNER":            3,
	"CAP_FSETID":            4,
	"CAP_KILL":              5,
	"CAP_SETGID":            6,
	"CAP_SETUID":            7,
	"CAP_SETPCAP":           8,
	"CAP_NET_BIND_SERVICE":  10,
	"CAP_NET_RAW":           13,
	"CAP_IPC_LOCK":          14,
	"CAP_SYS_MODULE":        16,
	"CAP_SYS_RAWIO":         17,
	"CAP_SYS_CHROOT":        18,
	"CAP_SYS_PTRACE":        19,
	"CAP_SYS_ADMIN":         21,
	"CAP_SYS_BOOT":          22,
	"CAP_SYS_NICE":          23,
	"CAP_SYS_TIME":          25,
	"CAP_MKNOD":             27,
	"CAP_AUDIT_WRITE":       29,
	"CAP_AUDIT_CONTROL":     30,
	"CAP_BPF":               39,
}

func ForbiddenCapsMask(names []string) (uint64, error) {
	var mask uint64
	for _, n := range names {
		bit, ok := capBits[strings.ToUpper(n)]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		mask |= 1 << bit
	}
	return mask, nil
}
