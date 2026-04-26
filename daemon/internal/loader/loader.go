// Package loader handles eBPF object loading, program attachment,
// ringbuf consumption, and BPF-map synchronisation from the policy
// store. It is the only package that imports cilium/ebpf.
package loader

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"path/filepath"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cisco-agentsandbox/runtime/daemon/internal/events"
	"github.com/cisco-agentsandbox/runtime/daemon/internal/policy"
)

// Mirrors `struct policy` from bpf/common.h. Field order matters.
const (
	maxHosts    = 64
	maxPaths    = 64
	maxBins     = 32
	maxPolicies = 32
	maxPath     = 256
)

type cHostRule struct {
	AddrV4    uint32
	PrefixLen uint32
	Port      uint16
	_pad      uint16
}

type cPathRule struct {
	Prefix [maxPath]byte
}

type cBinaryRule struct {
	Path [maxPath]byte
}

type cPolicy struct {
	Mode          uint32
	NHosts        uint32
	NPaths        uint32
	NBins         uint32
	ForbiddenCaps uint64
	Hosts         [maxHosts]cHostRule
	Paths         [maxPaths]cPathRule
	Bins          [maxBins]cBinaryRule
}

type Runtime struct {
	colls map[string]*ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader

	cgroupPolicy *ebpf.Map
	policies     *ebpf.Map
}

func Load(dir string) (*Runtime, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("rlimit: %w", err)
	}

	rt := &Runtime{colls: map[string]*ebpf.Collection{}}

	for _, name := range []string{"network", "file", "creds", "exec"} {
		path := filepath.Join(dir, name+".bpf.o")
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			rt.Close()
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
		// All four objects declare the same `events`, `cgroup_policy`,
		// and `policies` maps. Pin them under one BPF FS path so each
		// collection reuses the same kernel maps.
		for _, m := range []string{"events", "cgroup_policy", "policies"} {
			if ms, ok := spec.Maps[m]; ok {
				ms.Pinning = ebpf.PinByName
			}
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf/agentsandbox"},
		})
		if err != nil {
			rt.Close()
			return nil, fmt.Errorf("new %s: %w", name, err)
		}
		rt.colls[name] = coll
		if rt.cgroupPolicy == nil {
			rt.cgroupPolicy = coll.Maps["cgroup_policy"]
			rt.policies = coll.Maps["policies"]
		}
	}

	if err := rt.attachAll(); err != nil {
		rt.Close()
		return nil, err
	}

	rb, err := ringbuf.NewReader(rt.colls["network"].Maps["events"])
	if err != nil {
		rt.Close()
		return nil, fmt.Errorf("ringbuf: %w", err)
	}
	rt.rb = rb
	return rt, nil
}

func (r *Runtime) attachAll() error {
	type attachSpec struct {
		coll, prog string
		fn         func(*ebpf.Program) (link.Link, error)
	}
	specs := []attachSpec{
		{"network", "asb_socket_connect", lsmAttach},
		{"network", "asb_sendto",         tracepointAttach("syscalls", "sys_enter_sendto")},
		{"file",    "asb_file_open",      lsmAttach},
		{"creds",   "asb_setuid",         lsmAttach},
		{"creds",   "asb_setgid",         lsmAttach},
		{"creds",   "asb_capset",         lsmAttach},
		{"exec",    "asb_sched_exec",     tracepointAttach("sched", "sched_process_exec")},
		{"exec",    "asb_bprm_check",     lsmAttach},
	}
	for _, s := range specs {
		prog, ok := r.colls[s.coll].Programs[s.prog]
		if !ok {
			return fmt.Errorf("program %s/%s missing from object", s.coll, s.prog)
		}
		l, err := s.fn(prog)
		if err != nil {
			return fmt.Errorf("attach %s/%s: %w", s.coll, s.prog, err)
		}
		r.links = append(r.links, l)
	}
	return nil
}

func lsmAttach(prog *ebpf.Program) (link.Link, error) {
	return link.AttachLSM(link.LSMOptions{Program: prog})
}

func tracepointAttach(group, name string) func(*ebpf.Program) (link.Link, error) {
	return func(prog *ebpf.Program) (link.Link, error) {
		return link.Tracepoint(group, name, prog, nil)
	}
}

// Run reads ringbuf records until ctx is cancelled, decodes them,
// and forwards each to broadcast.
func (r *Runtime) Run(ctx context.Context, broadcast func(*events.Event)) error {
	go func() {
		<-ctx.Done()
		_ = r.rb.Close()
	}()
	for {
		rec, err := r.rb.Read()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}
		evt, err := events.Decode(rec.RawSample)
		if err != nil {
			log.Printf("decode: %v", err)
			continue
		}
		broadcast(evt)
	}
}

// SyncPolicies overwrites the kernel `policies` array map and
// `cgroup_policy` hash map with the contents of snap.
func (r *Runtime) SyncPolicies(snap policy.Snapshot) error {
	for id, p := range snap.Policies {
		c, err := buildC(p)
		if err != nil {
			return fmt.Errorf("policy %d: %w", id, err)
		}
		key := id
		if err := r.policies.Update(key, unsafe.Pointer(&c), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update policy %d: %w", id, err)
		}
	}

	// Refresh cgroup -> policy bindings. We don't bother diffing;
	// at v0 scale (≤ a few hundred agents) full rewrite is fine.
	iter := r.cgroupPolicy.Iterate()
	var k uint64
	var v uint32
	var stale []uint64
	for iter.Next(&k, &v) {
		if _, ok := snap.Bindings[k]; !ok {
			stale = append(stale, k)
		}
	}
	for _, k := range stale {
		_ = r.cgroupPolicy.Delete(k)
	}
	for k, v := range snap.Bindings {
		key := k
		val := v
		if err := r.cgroupPolicy.Update(key, val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("bind cgroup %d: %w", k, err)
		}
	}
	return nil
}

// Close detaches every program and frees collections.
func (r *Runtime) Close() {
	if r.rb != nil {
		_ = r.rb.Close()
	}
	for _, l := range r.links {
		_ = l.Close()
	}
	for _, c := range r.colls {
		c.Close()
	}
}

// buildC translates a YAML Policy into its C representation.
func buildC(p policy.Policy) (cPolicy, error) {
	var c cPolicy
	if p.Mode == "enforce" {
		c.Mode = 1
	}
	for _, h := range p.AllowedHosts {
		if int(c.NHosts) >= maxHosts {
			break
		}
		hr, err := policy.ParseHost(h)
		if err != nil {
			return c, err
		}
		c.Hosts[c.NHosts] = cHostRule{
			AddrV4: hr.AddrV4, PrefixLen: hr.PrefixLen, Port: hr.Port,
		}
		c.NHosts++
	}
	for _, path := range p.AllowedPaths {
		if int(c.NPaths) >= maxPaths {
			break
		}
		if len(path) >= maxPath {
			return c, fmt.Errorf("path too long: %q (B-004)", path)
		}
		copy(c.Paths[c.NPaths].Prefix[:], path)
		c.NPaths++
	}
	for _, bin := range p.AllowedBins {
		if int(c.NBins) >= maxBins {
			break
		}
		copy(c.Bins[c.NBins].Path[:], bin)
		c.NBins++
	}
	mask, err := policy.ForbiddenCapsMask(p.ForbiddenCaps)
	if err != nil {
		return c, err
	}
	c.ForbiddenCaps = mask
	return c, nil
}

// Convenience: byte order check at startup so we fail loudly
// rather than silently mis-encoding events.
func init() {
	var x uint16 = 1
	if *(*byte)(unsafe.Pointer(&x)) != 1 {
		panic("agent-sandbox-runtime requires a little-endian host")
	}
	_ = binary.LittleEndian
}
