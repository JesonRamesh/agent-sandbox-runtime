// Package policy: post-hoc explanation of kernel verdicts.
//
// The kernel makes the actual allow/deny decision; userspace can't observe
// which rule matched (or which one didn't) from the eBPF event alone. For
// observability, however, the daemon does have the source manifest in memory
// — so we can re-run a *userspace approximation* of the match and surface a
// human-readable reason for the dashboard, the event log, and the per-agent
// log file.
//
// Important: this is for explanation only. The kernel's verdict is the
// source of truth. If this code disagrees with the kernel (e.g. due to DNS
// re-resolution or a CIDR edge case), the reason string may be imprecise,
// but the verdict on the wire is still correct.
package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agent-sandbox/runtime/internal/ipc"
)

// AccessKind enumerates the pillars the kernel can emit verdicts for.
// Strings are stable wire identifiers (see docs/INTERFACES.md §4.1).
type AccessKind string

const (
	KindNetConnect   AccessKind = "net.connect"
	KindNetSendto    AccessKind = "net.sendto"
	KindFileOpen     AccessKind = "file.open"
	KindExec         AccessKind = "exec"
	KindExecBprm     AccessKind = "exec.bprm"
	KindCredsSetuid  AccessKind = "creds.setuid"
	KindCredsSetgid  AccessKind = "creds.setgid"
	KindCredsCapset  AccessKind = "creds.capset"
)

// Pillar groups the access kinds into the four buckets the dashboard
// renders. "net" / "file" / "exec" / "cred" are the stable wire values for
// `details.pillar`.
func Pillar(k AccessKind) string {
	switch k {
	case KindNetConnect, KindNetSendto:
		return "net"
	case KindFileOpen:
		return "file"
	case KindExec, KindExecBprm:
		return "exec"
	case KindCredsSetuid, KindCredsSetgid, KindCredsCapset:
		return "cred"
	default:
		return "unknown"
	}
}

// AccessFacts is everything the kernel told us about the access attempt.
// Only the fields relevant to the kind are populated; the rest stay zero.
type AccessFacts struct {
	Kind    AccessKind
	Verdict string // "allow" | "deny" | "audit"

	// net.*
	DstIP   string
	DstPort uint16

	// file.open
	Path string

	// exec / exec.bprm
	Filename string

	// creds.*
	CapEffective uint64
	OldID        uint32
	NewID        uint32
}

// Reason is the result of a userspace explanation pass. ReasonCode is a
// stable, machine-comparable identifier; ReasonMessage is human prose.
// MatchedRule is set when an allow-list entry covered the access.
type Reason struct {
	ReasonCode    string
	ReasonMessage string
	MatchedRule   string
}

// Explain returns a human + machine reason describing why the kernel almost
// certainly produced this verdict given the agent's manifest. The same
// function handles both allow and deny; the caller just reads ReasonMessage.
func Explain(m ipc.Manifest, f AccessFacts) Reason {
	switch f.Kind {
	case KindNetConnect, KindNetSendto:
		return explainNetWithFlags(m.AllowedHosts, m.DenyCleartextEgress, f)
	case KindFileOpen:
		return explainFile(m.AllowedPaths, f)
	case KindExec, KindExecBprm:
		return explainExec(m.AllowedBins, f)
	case KindCredsSetuid, KindCredsSetgid, KindCredsCapset:
		return explainCreds(m.ForbiddenCaps, f)
	}
	return Reason{
		ReasonCode:    "unknown_kind",
		ReasonMessage: fmt.Sprintf("unknown access kind %q", f.Kind),
	}
}

func explainNet(allowed []string, f AccessFacts) Reason {
	return explainNetWithFlags(allowed, false, f)
}

// explainNetWithFlags is the real implementation; the bool-less wrapper
// preserves the public API for callers that don't care about the
// deny_cleartext_egress gate. When `denyCleartext` is set and the verdict
// is deny but the destination IS in allowed_hosts, the reason is
// rewritten to make the cleartext-port cause explicit — otherwise the
// dashboard would render "8.8.8.8:80 not in allowed_hosts" which is a
// lie (the host was on the list; the port disqualified it).
func explainNetWithFlags(allowed []string, denyCleartext bool, f AccessFacts) Reason {
	target := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)

	for _, entry := range allowed {
		if hostEntryCovers(entry, f.DstIP, f.DstPort) {
			if f.Verdict == "deny" {
				if denyCleartext && !TLSPorts[f.DstPort] {
					return Reason{
						ReasonCode:    "cleartext_egress_denied",
						ReasonMessage: fmt.Sprintf("%s is on allowed_hosts but port %d is not a TLS port; deny_cleartext_egress=true forbids plaintext egress so credentials in env never leave the host unencrypted", target, f.DstPort),
						MatchedRule:   entry,
					}
				}
				// Mismatch between userspace match and kernel deny — usually
				// means DNS re-resolved differently. Surface honestly.
				return Reason{
					ReasonCode:    "host_match_disagrees_kernel",
					ReasonMessage: fmt.Sprintf("%s superficially matches %q but kernel still denied — possibly stale DNS or CIDR boundary", target, entry),
					MatchedRule:   entry,
				}
			}
			return Reason{
				ReasonCode:    "host_allowed",
				ReasonMessage: fmt.Sprintf("%s matches %q", target, entry),
				MatchedRule:   entry,
			}
		}
	}

	if f.Verdict == "deny" {
		return Reason{
			ReasonCode:    "host_not_in_allowlist",
			ReasonMessage: fmt.Sprintf("%s not in allowed_hosts %v", target, formatList(allowed)),
		}
	}
	// Allow with no userspace match — kernel let it through; we just can't
	// pin the rule (e.g. DNS path resolved differently here).
	return Reason{
		ReasonCode:    "host_allowed_unexplained",
		ReasonMessage: fmt.Sprintf("%s allowed but no manifest entry matched here", target),
	}
}

// hostEntryCovers does a *string-level* check against an entry like
// "1.1.1.1:80" or "10.0.0.0/24:443" or "api.example.com:443". This is
// deliberately fuzzy (no DNS, no CIDR math) — for explanation only.
func hostEntryCovers(entry string, ip string, port uint16) bool {
	host, entryPort, hadPort := splitHostPort(entry)
	if hadPort && entryPort != port {
		return false
	}
	if strings.Contains(host, "/") {
		// Strip CIDR — explanation pretends a CIDR matches if the entry IP
		// equals the access IP. Imperfect but informative.
		host = strings.SplitN(host, "/", 2)[0]
	}
	return host == ip
}

// splitHostPort parses "host:port", "host", or "host/cidr:port" into parts.
// Different from net.SplitHostPort because we want to tolerate missing port.
func splitHostPort(spec string) (host string, port uint16, hadPort bool) {
	i := strings.LastIndex(spec, ":")
	if i < 0 {
		return spec, 0, false
	}
	right := spec[i+1:]
	var p uint16
	for _, r := range right {
		if r < '0' || r > '9' {
			return spec, 0, false
		}
		p = p*10 + uint16(r-'0')
	}
	return spec[:i], p, true
}

func explainFile(allowed []string, f AccessFacts) Reason {
	for _, entry := range allowed {
		if pathEntryCovers(entry, f.Path) {
			if f.Verdict == "deny" {
				return Reason{
					ReasonCode:    "path_match_disagrees_kernel",
					ReasonMessage: fmt.Sprintf("%s superficially matches %q but kernel denied — check trailing-slash semantics", f.Path, entry),
					MatchedRule:   entry,
				}
			}
			return Reason{
				ReasonCode:    "path_allowed",
				ReasonMessage: fmt.Sprintf("%s matches %q", f.Path, entry),
				MatchedRule:   entry,
			}
		}
	}
	if f.Verdict == "deny" {
		return Reason{
			ReasonCode:    "path_not_in_allowlist",
			ReasonMessage: fmt.Sprintf("%s not in allowed_paths %v", f.Path, formatList(allowed)),
		}
	}
	return Reason{
		ReasonCode:    "path_allowed_unexplained",
		ReasonMessage: fmt.Sprintf("%s allowed but no manifest entry matched here", f.Path),
	}
}

// pathEntryCovers approximates the kernel's path matcher: a trailing "/"
// is a tree, "*" is a glob, otherwise it's an exact match.
func pathEntryCovers(entry, target string) bool {
	if strings.ContainsAny(entry, "*?[") {
		ok, _ := filepath.Match(entry, target)
		return ok
	}
	if strings.HasSuffix(entry, "/") {
		return strings.HasPrefix(target, entry)
	}
	return entry == target
}

func explainExec(allowed []string, f AccessFacts) Reason {
	if len(allowed) == 0 {
		// Empty allowed_bins means "any binary" per the schema.
		if f.Verdict == "deny" {
			return Reason{
				ReasonCode:    "exec_denied_with_empty_allowlist",
				ReasonMessage: fmt.Sprintf("%s denied; allowed_bins is empty (which means \"any\") — verify policy load", f.Filename),
			}
		}
		return Reason{
			ReasonCode:    "exec_allowed_open_policy",
			ReasonMessage: fmt.Sprintf("%s allowed; allowed_bins is empty (any binary)", f.Filename),
		}
	}
	for _, entry := range allowed {
		if entry == f.Filename {
			return Reason{
				ReasonCode:    "exec_allowed",
				ReasonMessage: fmt.Sprintf("%s matches %q", f.Filename, entry),
				MatchedRule:   entry,
			}
		}
	}
	if f.Verdict == "deny" {
		return Reason{
			ReasonCode:    "exec_not_in_allowlist",
			ReasonMessage: fmt.Sprintf("%s not in allowed_bins %v", f.Filename, formatList(allowed)),
		}
	}
	return Reason{
		ReasonCode:    "exec_allowed_unexplained",
		ReasonMessage: fmt.Sprintf("%s allowed but no manifest entry matched here", f.Filename),
	}
}

func explainCreds(forbidden []string, f AccessFacts) Reason {
	if f.Verdict == "deny" {
		mask, _ := ForbiddenCapsMask(forbidden)
		offending := mask & f.CapEffective
		if offending != 0 {
			return Reason{
				ReasonCode: "cap_in_forbidden_set",
				ReasonMessage: fmt.Sprintf(
					"capset cap_effective=0x%x intersects forbidden_caps mask 0x%x; forbidden: %v",
					f.CapEffective, mask, formatList(forbidden),
				),
			}
		}
		return Reason{
			ReasonCode:    "cred_op_denied",
			ReasonMessage: fmt.Sprintf("creds op denied; forbidden_caps: %v", formatList(forbidden)),
		}
	}
	return Reason{
		ReasonCode:    "cred_op_allowed",
		ReasonMessage: fmt.Sprintf("creds op allowed; forbidden_caps: %v", formatList(forbidden)),
	}
}

// formatList prints a slice as "[a, b, c]" with a stable cap so the reason
// string doesn't blow up for agents with hundreds of allow-list entries.
func formatList(xs []string) string {
	const cap = 8
	if len(xs) == 0 {
		return "[]"
	}
	if len(xs) <= cap {
		return "[" + strings.Join(xs, ", ") + "]"
	}
	return fmt.Sprintf("[%s, …+%d more]", strings.Join(xs[:cap], ", "), len(xs)-cap)
}
