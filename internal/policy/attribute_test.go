package policy

import (
	"strings"
	"testing"

	"github.com/agent-sandbox/runtime/internal/ipc"
)

func TestPillar(t *testing.T) {
	cases := map[AccessKind]string{
		KindNetConnect:  "net",
		KindNetSendto:   "net",
		KindFileOpen:    "file",
		KindExec:        "exec",
		KindExecBprm:    "exec",
		KindCredsSetuid: "cred",
		KindCredsCapset: "cred",
		AccessKind("nope"): "unknown",
	}
	for k, want := range cases {
		if got := Pillar(k); got != want {
			t.Errorf("Pillar(%q) = %q, want %q", k, got, want)
		}
	}
}

func TestExplainNet_DenyNotInAllowlist(t *testing.T) {
	m := ipc.Manifest{AllowedHosts: []string{"1.1.1.1:80"}}
	r := Explain(m, AccessFacts{
		Kind: KindNetConnect, Verdict: "deny",
		DstIP: "8.8.8.8", DstPort: 53,
	})
	if r.ReasonCode != "host_not_in_allowlist" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
	if !strings.Contains(r.ReasonMessage, "8.8.8.8:53") {
		t.Errorf("message missing target: %q", r.ReasonMessage)
	}
	if !strings.Contains(r.ReasonMessage, "1.1.1.1:80") {
		t.Errorf("message missing allow-list: %q", r.ReasonMessage)
	}
	if r.MatchedRule != "" {
		t.Errorf("expected no MatchedRule, got %q", r.MatchedRule)
	}
}

func TestExplainNet_AllowExactMatch(t *testing.T) {
	m := ipc.Manifest{AllowedHosts: []string{"1.1.1.1:80"}}
	r := Explain(m, AccessFacts{
		Kind: KindNetConnect, Verdict: "allow",
		DstIP: "1.1.1.1", DstPort: 80,
	})
	if r.ReasonCode != "host_allowed" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
	if r.MatchedRule != "1.1.1.1:80" {
		t.Errorf("MatchedRule = %q", r.MatchedRule)
	}
}

func TestExplainNet_CleartextEgressDeniesAllowlistedHostOnPort80(t *testing.T) {
	// Use an IP-literal allow-list entry so userspace hostEntryCovers()
	// matches deterministically (we don't do DNS in the explainer — the
	// daemon resolves at policy-compile time, but unit tests run without
	// it). The behaviour under test is "host check passed AND cleartext
	// egress flag is set AND port is non-TLS → cleartext_egress_denied".
	m := ipc.Manifest{
		AllowedHosts:        []string{"93.184.216.34:80"},
		DenyCleartextEgress: true,
	}
	r := Explain(m, AccessFacts{
		Kind: KindNetConnect, Verdict: "deny",
		DstIP: "93.184.216.34", DstPort: 80,
	})
	if r.ReasonCode != "cleartext_egress_denied" {
		t.Fatalf("ReasonCode = %q, want cleartext_egress_denied", r.ReasonCode)
	}
	for _, sub := range []string{"port 80", "deny_cleartext_egress"} {
		if !strings.Contains(r.ReasonMessage, sub) {
			t.Errorf("ReasonMessage missing %q: %s", sub, r.ReasonMessage)
		}
	}
}

func TestExplainNet_CleartextEgressIsSilentForTLSPort(t *testing.T) {
	// Same flag, but destination is :443 — should not produce the
	// cleartext-egress reason because :443 is TLS-encrypted.
	m := ipc.Manifest{
		AllowedHosts:        []string{"93.184.216.34:443"},
		DenyCleartextEgress: true,
	}
	r := Explain(m, AccessFacts{
		Kind: KindNetConnect, Verdict: "allow",
		DstIP: "93.184.216.34", DstPort: 443,
	})
	if r.ReasonCode != "host_allowed" {
		t.Errorf("ReasonCode = %q, want host_allowed", r.ReasonCode)
	}
}

func TestIsTLSPort_KnownAndUnknown(t *testing.T) {
	for _, p := range []uint16{443, 465, 587, 636, 993, 995, 8443, 22, 5223} {
		if !IsTLSPort(p) {
			t.Errorf("IsTLSPort(%d) = false, want true", p)
		}
	}
	for _, p := range []uint16{80, 21, 23, 25, 110, 143, 3306, 6379} {
		if IsTLSPort(p) {
			t.Errorf("IsTLSPort(%d) = true, want false", p)
		}
	}
}

func TestExplainNet_PortMismatchIsDeny(t *testing.T) {
	m := ipc.Manifest{AllowedHosts: []string{"1.1.1.1:80"}}
	r := Explain(m, AccessFacts{
		Kind: KindNetConnect, Verdict: "deny",
		DstIP: "1.1.1.1", DstPort: 443, // same IP, different port
	})
	if r.ReasonCode != "host_not_in_allowlist" {
		t.Errorf("ReasonCode = %q (expected port mismatch to count as not-in-allowlist)", r.ReasonCode)
	}
}

func TestExplainFile_DenyNotInAllowlist(t *testing.T) {
	m := ipc.Manifest{AllowedPaths: []string{"/etc/hostname"}}
	r := Explain(m, AccessFacts{
		Kind: KindFileOpen, Verdict: "deny",
		Path: "/etc/shadow",
	})
	if r.ReasonCode != "path_not_in_allowlist" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
	if !strings.Contains(r.ReasonMessage, "/etc/shadow") {
		t.Errorf("message missing path: %q", r.ReasonMessage)
	}
}

func TestExplainFile_TreeAllow(t *testing.T) {
	m := ipc.Manifest{AllowedPaths: []string{"/tmp/work/"}}
	r := Explain(m, AccessFacts{
		Kind: KindFileOpen, Verdict: "allow",
		Path: "/tmp/work/foo.log",
	})
	if r.ReasonCode != "path_allowed" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
	if r.MatchedRule != "/tmp/work/" {
		t.Errorf("MatchedRule = %q", r.MatchedRule)
	}
}

func TestExplainFile_GlobAllow(t *testing.T) {
	m := ipc.Manifest{AllowedPaths: []string{"/var/log/*.log"}}
	r := Explain(m, AccessFacts{
		Kind: KindFileOpen, Verdict: "allow",
		Path: "/var/log/syslog.log",
	})
	if r.MatchedRule != "/var/log/*.log" {
		t.Errorf("MatchedRule = %q", r.MatchedRule)
	}
}

func TestExplainExec_DenyNotInAllowlist(t *testing.T) {
	m := ipc.Manifest{AllowedBins: []string{"/bin/sh", "/bin/echo"}}
	r := Explain(m, AccessFacts{
		Kind: KindExecBprm, Verdict: "deny",
		Filename: "/usr/bin/curl",
	})
	if r.ReasonCode != "exec_not_in_allowlist" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
	if !strings.Contains(r.ReasonMessage, "/usr/bin/curl") {
		t.Errorf("message missing filename: %q", r.ReasonMessage)
	}
}

func TestExplainExec_EmptyAllowlistMeansAny(t *testing.T) {
	m := ipc.Manifest{AllowedBins: []string{}}
	r := Explain(m, AccessFacts{
		Kind: KindExec, Verdict: "allow",
		Filename: "/usr/bin/anything",
	})
	if r.ReasonCode != "exec_allowed_open_policy" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
}

func TestExplainCreds_CapsetIntersectsForbidden(t *testing.T) {
	// CAP_SYS_ADMIN bit is 21 → 1<<21 = 0x200000.
	m := ipc.Manifest{ForbiddenCaps: []string{"CAP_SYS_ADMIN"}}
	r := Explain(m, AccessFacts{
		Kind: KindCredsCapset, Verdict: "deny",
		CapEffective: 1 << 21,
	})
	if r.ReasonCode != "cap_in_forbidden_set" {
		t.Errorf("ReasonCode = %q", r.ReasonCode)
	}
	if !strings.Contains(r.ReasonMessage, "CAP_SYS_ADMIN") {
		t.Errorf("message missing cap name: %q", r.ReasonMessage)
	}
}

func TestFormatListTruncates(t *testing.T) {
	long := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	got := formatList(long)
	if !strings.Contains(got, "+2 more") {
		t.Errorf("expected truncation marker, got %q", got)
	}
}
