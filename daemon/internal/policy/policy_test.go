package policy

import (
	"strings"
	"testing"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

func TestCompile_Empty(t *testing.T) {
	got, err := Compile(ipc.Manifest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NHosts != 0 || got.NPaths != 0 || got.NBins != 0 {
		t.Fatalf("empty manifest produced entries: %+v", got)
	}
	if got.Mode != ModeEnforce {
		t.Errorf("default Mode = %d, want ModeEnforce(%d)", got.Mode, ModeEnforce)
	}
}

func TestCompile_ModeAudit(t *testing.T) {
	got, err := Compile(ipc.Manifest{Mode: "audit"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Mode != ModeAudit {
		t.Errorf("Mode = %d, want ModeAudit(%d)", got.Mode, ModeAudit)
	}
}

func TestCompile_ModeUnknown(t *testing.T) {
	_, err := Compile(ipc.Manifest{Mode: "yolo"})
	if err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestCompile_LiteralIPv4WithPort(t *testing.T) {
	got, err := Compile(ipc.Manifest{AllowedHosts: []string{"1.2.3.4:80"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NHosts != 1 {
		t.Fatalf("want 1 host, got %d", got.NHosts)
	}
	h := got.Hosts[0]
	// v4ToBE packs [1,2,3,4] into low-to-high bytes.
	wantAddr := uint32(1) | uint32(2)<<8 | uint32(3)<<16 | uint32(4)<<24
	if h.AddrV4 != wantAddr {
		t.Errorf("AddrV4 = %#x, want %#x", h.AddrV4, wantAddr)
	}
	if h.Port != 80 {
		t.Errorf("Port = %d, want 80", h.Port)
	}
	if h.PrefixLen != 32 {
		t.Errorf("PrefixLen = %d, want 32", h.PrefixLen)
	}
}

func TestCompile_LiteralIPv4DefaultPort(t *testing.T) {
	got, err := Compile(ipc.Manifest{AllowedHosts: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NHosts != 1 {
		t.Fatalf("want 1 host, got %d", got.NHosts)
	}
	if got.Hosts[0].Port != 443 {
		t.Errorf("default Port = %d, want 443", got.Hosts[0].Port)
	}
}

func TestCompile_CIDR(t *testing.T) {
	got, err := Compile(ipc.Manifest{AllowedHosts: []string{"10.0.0.0/8:443"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NHosts != 1 {
		t.Fatalf("want 1 host, got %d", got.NHosts)
	}
	if got.Hosts[0].PrefixLen != 8 {
		t.Errorf("PrefixLen = %d, want 8", got.Hosts[0].PrefixLen)
	}
}

func TestCompile_IPv6Rejected(t *testing.T) {
	_, err := Compile(ipc.Manifest{AllowedHosts: []string{"[2001:db8::1]:80"}})
	if err == nil {
		t.Fatal("expected ipv6 to be rejected")
	}
}

func TestCompile_HostnameLocalhost(t *testing.T) {
	// localhost has an A record (127.0.0.1) on every supported platform.
	got, err := Compile(ipc.Manifest{AllowedHosts: []string{"localhost:8080"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NHosts == 0 {
		t.Fatalf("localhost resolved to nothing")
	}
	for i := uint32(0); i < got.NHosts; i++ {
		if got.Hosts[i].Port != 8080 {
			t.Errorf("Port = %d, want 8080", got.Hosts[i].Port)
		}
	}
}

func TestCompile_AllowedPaths(t *testing.T) {
	got, err := Compile(ipc.Manifest{AllowedPaths: []string{"/tmp/work", "/usr/lib"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NPaths != 2 {
		t.Fatalf("want 2 paths, got %d", got.NPaths)
	}
	if string(got.Paths[0].Prefix[:len("/tmp/work")]) != "/tmp/work" {
		t.Errorf("Path[0] not stored verbatim: %q", got.Paths[0].Prefix[:len("/tmp/work")])
	}
}

func TestCompile_AllowedBins(t *testing.T) {
	got, err := Compile(ipc.Manifest{AllowedBins: []string{"/usr/bin/python3"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.NBins != 1 {
		t.Fatalf("want 1 bin, got %d", got.NBins)
	}
}

func TestCompile_PathTooLong(t *testing.T) {
	long := "/" + strings.Repeat("a", MaxPath)
	_, err := Compile(ipc.Manifest{AllowedPaths: []string{long}})
	if err == nil {
		t.Fatal("expected error for over-long path")
	}
}

func TestCompile_ForbiddenCaps(t *testing.T) {
	got, err := Compile(ipc.Manifest{ForbiddenCaps: []string{"CAP_SYS_ADMIN", "CAP_BPF"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := uint64(1)<<21 | uint64(1)<<39
	if got.ForbiddenCaps != want {
		t.Errorf("ForbiddenCaps = %#x, want %#x", got.ForbiddenCaps, want)
	}
}

func TestCompile_UnknownCapRejected(t *testing.T) {
	_, err := Compile(ipc.Manifest{ForbiddenCaps: []string{"CAP_NOT_A_THING"}})
	if err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

func TestCompile_PortZeroRejected(t *testing.T) {
	_, err := Compile(ipc.Manifest{AllowedHosts: []string{"1.2.3.4:0"}})
	if err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestCompile_LookupFailureIsFatal(t *testing.T) {
	_, err := Compile(ipc.Manifest{AllowedHosts: []string{"this-host-does-not-exist.invalid"}})
	if err == nil {
		t.Fatal("expected lookup failure to surface as error")
	}
}

func TestCompile_TooManyHosts(t *testing.T) {
	hosts := make([]string, 0, MaxHosts+1)
	for i := 0; i <= MaxHosts; i++ {
		hosts = append(hosts, "1.2.3.4")
	}
	_, err := Compile(ipc.Manifest{AllowedHosts: hosts})
	if err == nil {
		t.Fatal("expected error for too many hosts")
	}
}
