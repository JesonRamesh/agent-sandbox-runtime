// Package policy translates an ipc.Manifest into the kernel-side
// `struct policy` value defined in bpf/common.h.reference. The result
// (Compiled) is a byte-for-byte mirror of the C struct — internal/bpf's
// loader writes it straight into the per-cgroup entry of the BPF
// `policies` ARRAY map.
//
// Field order, sizes, and pads here must stay in lockstep with
// bpf/common.h.reference. Drift corrupts every kernel-side decision
// silently (the verifier doesn't catch ABI mismatches between userspace
// writes and kernel reads).
package policy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

// Constants must match bpf/common.h.reference.
const (
	MaxHosts    = 64
	MaxPaths    = 64
	MaxBins     = 32
	MaxPath     = 256
	MaxPolicies = 32

	// Mode values for `cPolicy.Mode` (matches enum in common.h).
	ModeAudit   uint32 = 0
	ModeEnforce uint32 = 1

	defaultPort = 443
)

// HostRule mirrors `struct host_rule` from bpf/common.h.reference.
//
// AddrV4 is host-byte-order on the kernel side: common.h does
// `(daddr & mask) == (r->addr_v4 & mask)` where `daddr` comes from
// `ctx->user_ip4` (network order) — but the comparison is bitwise,
// so as long as both sides agree on byte order it works. We pick
// network order (big-endian when written into the struct) to match
// `daddr_v4` directly. See cidrMaskBE() below.
type HostRule struct {
	AddrV4    uint32
	PrefixLen uint32
	Port      uint16
	Pad       uint16
}

// PathRule mirrors `struct path_rule`. Fixed-size NUL-terminated string.
type PathRule struct {
	Prefix [MaxPath]byte
}

// BinaryRule mirrors `struct binary_rule`.
type BinaryRule struct {
	Path [MaxPath]byte
}

// Compiled is the byte-for-byte mirror of `struct policy` from common.h.
// One value per agent. The loader writes it into policies[policy_id].
type Compiled struct {
	Mode          uint32
	NHosts        uint32
	NPaths        uint32
	NBins         uint32
	ForbiddenCaps uint64
	Hosts         [MaxHosts]HostRule
	Paths         [MaxPaths]PathRule
	Bins          [MaxBins]BinaryRule
}

// Compile produces a Compiled from a manifest. Any host that fails to
// resolve, any path/binary that exceeds MaxPath, or any unknown
// capability name is a hard error — we want a noisy failure rather
// than a silently-truncated policy that lets an agent through.
func Compile(m ipc.Manifest) (Compiled, error) {
	var c Compiled

	switch strings.ToLower(strings.TrimSpace(m.Mode)) {
	case "", "enforce":
		c.Mode = ModeEnforce
	case "audit":
		c.Mode = ModeAudit
	default:
		return c, fmt.Errorf("policy: unknown mode %q (want \"audit\" or \"enforce\")", m.Mode)
	}

	for _, raw := range m.AllowedHosts {
		hr, err := ParseHost(raw)
		if err != nil {
			return c, fmt.Errorf("policy: parse host %q: %w", raw, err)
		}
		// One manifest entry can resolve to several IPs; ParseHost
		// returns one per resolved A record.
		for _, h := range hr {
			if int(c.NHosts) >= MaxHosts {
				return c, fmt.Errorf("policy: too many host rules (max %d)", MaxHosts)
			}
			c.Hosts[c.NHosts] = h
			c.NHosts++
		}
	}

	for _, p := range m.AllowedPaths {
		if int(c.NPaths) >= MaxPaths {
			return c, fmt.Errorf("policy: too many path rules (max %d)", MaxPaths)
		}
		if len(p) >= MaxPath {
			return c, fmt.Errorf("policy: path too long (max %d): %q", MaxPath-1, p)
		}
		copy(c.Paths[c.NPaths].Prefix[:], p)
		c.NPaths++
	}

	for _, b := range m.AllowedBins {
		if int(c.NBins) >= MaxBins {
			return c, fmt.Errorf("policy: too many binary rules (max %d)", MaxBins)
		}
		if len(b) >= MaxPath {
			return c, fmt.Errorf("policy: binary path too long (max %d): %q", MaxPath-1, b)
		}
		copy(c.Bins[c.NBins].Path[:], b)
		c.NBins++
	}

	mask, err := ForbiddenCapsMask(m.ForbiddenCaps)
	if err != nil {
		return c, fmt.Errorf("policy: %w", err)
	}
	c.ForbiddenCaps = mask

	return c, nil
}

// ParseHost accepts the four documented forms and returns one HostRule
// per resolved address:
//
//	"host[:port]"             — DNS-resolved; one rule per A record
//	"1.2.3.4[:port]"          — literal IPv4
//	"1.2.3.0/24[:port]"       — IPv4 CIDR
//	"[2001:db8::1]:port"      — literal IPv6 (rejected — v0 is v4-only)
//
// Default port is 443. CIDR prefix defaults to 32 (single host).
//
// IPv6 is rejected at this layer: bpf/network.bpf.c only enforces
// AF_INET (see common.h.reference §host_allowed). v6 hosts in the
// manifest become an error rather than silently being ignored.
func ParseHost(spec string) ([]HostRule, error) {
	if spec == "" {
		return nil, errors.New("empty host entry")
	}

	// Bracketed IPv6 with port — explicit reject.
	if strings.HasPrefix(spec, "[") {
		return nil, errors.New("ipv6 hosts not supported in v0 (network.bpf.c is AF_INET only)")
	}

	// Optional :port suffix. We split on the LAST colon — but bare IPv6
	// literals contain colons, and we've already rejected those above.
	port := uint16(defaultPort)
	host := spec
	if i := strings.LastIndex(spec, ":"); i >= 0 {
		// Only treat as host:port if the right side parses as a number.
		// "1.2.3.4:443" → port; bare "1.2.3.4" stays unchanged.
		if n, err := strconv.ParseUint(spec[i+1:], 10, 16); err == nil {
			if n == 0 {
				return nil, errors.New("port 0 is reserved")
			}
			port = uint16(n)
			host = spec[:i]
		}
	}

	// Optional /cidr suffix on the host part.
	prefix := uint32(32)
	if i := strings.Index(host, "/"); i >= 0 {
		n, err := strconv.ParseUint(host[i+1:], 10, 32)
		if err != nil || n > 32 {
			return nil, fmt.Errorf("invalid CIDR prefix %q", host[i+1:])
		}
		prefix = uint32(n)
		host = host[:i]
	}

	// Literal IP path.
	if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, errors.New("ipv6 hosts not supported in v0")
		}
		return []HostRule{{
			AddrV4:    v4ToBE(v4),
			PrefixLen: prefix,
			Port:      port,
		}}, nil
	}

	// DNS path.
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil, fmt.Errorf("lookup %q: %w", host, err)
	}
	var out []HostRule
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			return nil, fmt.Errorf("resolver returned non-IP %q for %q", a, host)
		}
		v4 := ip.To4()
		if v4 == nil {
			// Skip v6 records silently — common for hostnames with both A and AAAA.
			continue
		}
		out = append(out, HostRule{
			AddrV4:    v4ToBE(v4),
			PrefixLen: prefix,
			Port:      port,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses for %q", host)
	}
	return out, nil
}

// v4ToBE packs four bytes (in.s_addr / ctx->user_ip4 / network-byte order)
// into a uint32 such that the low byte holds the first octet — matching
// how the kernel reads `__u32 daddr_v4` from `struct sockaddr_in`.
//
// This is the same packing Mehul's daemon/internal/policy/policy.go uses,
// kept verbatim so events and policies agree on byte order at runtime.
func v4ToBE(v4 net.IP) uint32 {
	return uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24
}

// capBits maps a capability name to its bit position in the kernel
// capability bitmask (man 7 capabilities). Add entries as needed —
// bpf/creds.bpf.c just bitwise-ANDs `pol->forbidden_caps` against the
// effective set, so any bit position is valid.
var capBits = map[string]uint64{
	"CAP_CHOWN":            0,
	"CAP_DAC_OVERRIDE":     1,
	"CAP_DAC_READ_SEARCH":  2,
	"CAP_FOWNER":           3,
	"CAP_FSETID":           4,
	"CAP_KILL":             5,
	"CAP_SETGID":           6,
	"CAP_SETUID":           7,
	"CAP_SETPCAP":          8,
	"CAP_NET_BIND_SERVICE": 10,
	"CAP_NET_RAW":          13,
	"CAP_IPC_LOCK":         14,
	"CAP_SYS_MODULE":       16,
	"CAP_SYS_RAWIO":        17,
	"CAP_SYS_CHROOT":       18,
	"CAP_SYS_PTRACE":       19,
	"CAP_SYS_ADMIN":        21,
	"CAP_SYS_BOOT":         22,
	"CAP_SYS_NICE":         23,
	"CAP_SYS_TIME":         25,
	"CAP_MKNOD":            27,
	"CAP_AUDIT_WRITE":      29,
	"CAP_AUDIT_CONTROL":    30,
	"CAP_BPF":              39,
	"CAP_PERFMON":          38,
	"CAP_NET_ADMIN":        12,
}

// ForbiddenCapsMask returns the OR of every named capability's bit.
// Unknown names are a hard error so a typo in the YAML doesn't silently
// downgrade enforcement to "no caps forbidden".
func ForbiddenCapsMask(names []string) (uint64, error) {
	var mask uint64
	for _, n := range names {
		bit, ok := capBits[strings.ToUpper(strings.TrimSpace(n))]
		if !ok {
			return 0, fmt.Errorf("unknown capability %q", n)
		}
		mask |= 1 << bit
	}
	return mask, nil
}
