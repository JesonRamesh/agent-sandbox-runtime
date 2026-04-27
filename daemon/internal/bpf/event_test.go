package bpf

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
)

func TestEventJSONShape(t *testing.T) {
	ev := Event{
		TimeNs:   1234567890,
		PID:      4242,
		TGID:     4242,
		UID:      1000,
		GID:      1000,
		CgroupID: 99,
		Kind:     "net.connect",
		Verdict:  "deny",
		Comm:     "curl",
		Net:      &NetPayload{Family: 2, Dport: 443, Daddr: "1.1.1.1"},
	}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"time_ns":1234567890,"pid":4242,"tgid":4242,"uid":1000,"gid":1000,"cgroup_id":99,"kind":"net.connect","verdict":"deny","comm":"curl","net":{"family":2,"dport":443,"daddr":"1.1.1.1"}}`
	if string(got) != want {
		t.Fatalf("Event JSON mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestKindString(t *testing.T) {
	cases := []struct {
		in   uint32
		want string
	}{
		{KindNetConnect, "net.connect"},
		{KindNetSendto, "net.sendto"},
		{KindFileOpen, "file.open"},
		{KindCredsSetuid, "creds.setuid"},
		{KindCredsSetgid, "creds.setgid"},
		{KindCredsCapset, "creds.capset"},
		{KindExec, "exec"},
	}
	for _, c := range cases {
		if got := kindString(c.in); got != c.want {
			t.Errorf("kindString(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVerdictString(t *testing.T) {
	if got := verdictString(verdictAllow); got != "allow" {
		t.Errorf("allow: %q", got)
	}
	if got := verdictString(verdictDeny); got != "deny" {
		t.Errorf("deny: %q", got)
	}
	if got := verdictString(verdictAudit); got != "audit" {
		t.Errorf("audit: %q", got)
	}
}

// TestDecode_NetConnect builds a synthetic kernel record (header +
// rawNet body) and verifies the decoder produces the expected typed
// event. Catches any layout drift before it corrupts real events.
func TestDecode_NetConnect(t *testing.T) {
	hdr := rawHeader{
		TsNs:     42,
		PID:      100,
		TGID:     100,
		UID:      1000,
		GID:      1000,
		CgroupID: 555,
		Kind:     KindNetConnect,
		Verdict:  verdictDeny,
	}
	copy(hdr.Comm[:], "curl")
	body := rawNet{
		Family:  2,
		Dport:   443,
		DaddrV4: 0x01010101, // 1.1.1.1 in network byte order — bytes [01,01,01,01]
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, hdr)
	_ = binary.Write(&buf, binary.LittleEndian, body)

	ev, err := decode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ev.Kind != "net.connect" {
		t.Errorf("Kind = %q", ev.Kind)
	}
	if ev.Verdict != "deny" {
		t.Errorf("Verdict = %q", ev.Verdict)
	}
	if ev.CgroupID != 555 {
		t.Errorf("CgroupID = %d", ev.CgroupID)
	}
	if ev.Comm != "curl" {
		t.Errorf("Comm = %q", ev.Comm)
	}
	if ev.Net == nil {
		t.Fatal("Net payload is nil")
	}
	if ev.Net.Daddr != "1.1.1.1" {
		t.Errorf("Daddr = %q, want 1.1.1.1", ev.Net.Daddr)
	}
	if ev.Net.Dport != 443 {
		t.Errorf("Dport = %d", ev.Net.Dport)
	}
}

func TestDecode_ShortBuffer(t *testing.T) {
	if _, err := decode([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected short-buffer error")
	}
}
