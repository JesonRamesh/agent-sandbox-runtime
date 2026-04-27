// Event types and decoder. The wire format on the kernel side is:
// `struct event_hdr` followed by exactly one of struct net_event,
// struct file_event, struct creds_event, struct exec_event — the
// concrete payload is selected by event_hdr.kind.
//
// All field offsets, sizes, and pads here MUST stay in lockstep with
// daemon/bpf/common.h.reference. Mismatched layout silently corrupts
// every decoded event (the BPF verifier doesn't catch user/kernel ABI
// drift between sender and receiver).
package bpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Event kinds — values mirror enum event_kind in common.h.reference.
const (
	KindNetConnect  uint32 = 1
	KindNetSendto   uint32 = 2
	KindFileOpen    uint32 = 3
	KindCredsSetuid uint32 = 4
	KindCredsSetgid uint32 = 5
	KindCredsCapset uint32 = 6
	KindExec        uint32 = 7
)

// Verdict values — mirror enum verdict in common.h.reference.
const (
	verdictAllow uint32 = 0
	verdictDeny  uint32 = 1
	verdictAudit uint32 = 2
)

// Sizes from common.h.reference.
const (
	maxPath = 256
	commLen = 16
)

// Event is the decoded form of one ringbuf record. JSON tags are the
// stable wire shape consumers (websocket, log files) read.
type Event struct {
	AgentID  string `json:"-"`
	TimeNs   uint64 `json:"time_ns"`
	PID      uint32 `json:"pid"`
	TGID     uint32 `json:"tgid"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	CgroupID uint64 `json:"cgroup_id"`
	Kind     string `json:"kind"`    // "net.connect", "file.open", ...
	Verdict  string `json:"verdict"` // "allow", "deny", "audit"
	Comm     string `json:"comm"`

	// Exactly one of these is non-nil per Kind.
	Net   *NetPayload   `json:"net,omitempty"`
	File  *FilePayload  `json:"file,omitempty"`
	Creds *CredsPayload `json:"creds,omitempty"`
	Exec  *ExecPayload  `json:"exec,omitempty"`
}

// NetPayload mirrors `struct net_event`.
type NetPayload struct {
	Family uint32 `json:"family"` // AF_INET=2, AF_INET6=10
	Dport  uint16 `json:"dport"`
	Daddr  string `json:"daddr"` // dotted v4 string for now (v0 is AF_INET only)
}

// FilePayload mirrors `struct file_event`.
type FilePayload struct {
	Flags int32  `json:"flags"`
	Path  string `json:"path"`
}

// CredsPayload mirrors `struct creds_event`.
type CredsPayload struct {
	OldID  uint32 `json:"old_id"`
	NewID  uint32 `json:"new_id"`
	CapEff uint64 `json:"cap_effective"`
}

// ExecPayload mirrors `struct exec_event`.
type ExecPayload struct {
	PPID     uint32 `json:"ppid"`
	Filename string `json:"filename"`
}

// rawHeader mirrors `struct event_hdr`. Field order, types, and array
// sizes must match common.h.reference exactly.
type rawHeader struct {
	TsNs     uint64
	PID      uint32
	TGID     uint32
	UID      uint32
	GID      uint32
	CgroupID uint64
	Kind     uint32
	Verdict  uint32
	Comm     [commLen]byte
}

// rawNet mirrors `struct net_event`.
type rawNet struct {
	Family   uint32
	Dport    uint16
	Pad      uint16
	DaddrV4  uint32
	DaddrV6  [16]byte
}

// rawFile mirrors `struct file_event`.
type rawFile struct {
	Flags int32
	Path  [maxPath]byte
}

// rawCreds mirrors `struct creds_event`.
type rawCreds struct {
	OldID  uint32
	NewID  uint32
	CapEff uint64
}

// rawExec mirrors `struct exec_event`.
type rawExec struct {
	PPID     uint32
	Pad      uint32
	Filename [maxPath]byte
}

// decode parses one ringbuf record into an Event. Bad records produce
// errors that the caller logs; the fan-out loop continues either way.
func decode(buf []byte) (Event, error) {
	hdrSize := binary.Size(rawHeader{})
	if len(buf) < hdrSize {
		return Event{}, fmt.Errorf("short event: %d bytes, want >= %d", len(buf), hdrSize)
	}
	var hdr rawHeader
	if err := binary.Read(bytes.NewReader(buf[:hdrSize]), binary.LittleEndian, &hdr); err != nil {
		return Event{}, fmt.Errorf("decode header: %w", err)
	}

	ev := Event{
		TimeNs:   hdr.TsNs,
		PID:      hdr.PID,
		TGID:     hdr.TGID,
		UID:      hdr.UID,
		GID:      hdr.GID,
		CgroupID: hdr.CgroupID,
		Kind:     kindString(hdr.Kind),
		Verdict:  verdictString(hdr.Verdict),
		Comm:     cstring(hdr.Comm[:]),
	}

	tail := buf[hdrSize:]
	switch hdr.Kind {
	case KindNetConnect, KindNetSendto:
		ev.Net = decodeNet(tail)
	case KindFileOpen:
		ev.File = decodeFile(tail)
	case KindCredsSetuid, KindCredsSetgid, KindCredsCapset:
		ev.Creds = decodeCreds(tail)
	case KindExec:
		ev.Exec = decodeExec(tail)
	}
	return ev, nil
}

func decodeNet(b []byte) *NetPayload {
	if len(b) < binary.Size(rawNet{}) {
		return nil
	}
	var raw rawNet
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &raw); err != nil {
		return nil
	}
	// daddr_v4 is in network byte order (matches sin_addr.s_addr). Each
	// byte maps to a dotted-quad octet starting at the low byte.
	addr := net.IPv4(byte(raw.DaddrV4), byte(raw.DaddrV4>>8), byte(raw.DaddrV4>>16), byte(raw.DaddrV4>>24))
	return &NetPayload{
		Family: raw.Family,
		Dport:  raw.Dport,
		Daddr:  addr.String(),
	}
}

func decodeFile(b []byte) *FilePayload {
	if len(b) < binary.Size(rawFile{}) {
		return nil
	}
	var raw rawFile
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &raw); err != nil {
		return nil
	}
	return &FilePayload{Flags: raw.Flags, Path: cstring(raw.Path[:])}
}

func decodeCreds(b []byte) *CredsPayload {
	if len(b) < binary.Size(rawCreds{}) {
		return nil
	}
	var raw rawCreds
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &raw); err != nil {
		return nil
	}
	return &CredsPayload{OldID: raw.OldID, NewID: raw.NewID, CapEff: raw.CapEff}
}

func decodeExec(b []byte) *ExecPayload {
	if len(b) < binary.Size(rawExec{}) {
		return nil
	}
	var raw rawExec
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &raw); err != nil {
		return nil
	}
	return &ExecPayload{PPID: raw.PPID, Filename: cstring(raw.Filename[:])}
}

func kindString(k uint32) string {
	switch k {
	case KindNetConnect:
		return "net.connect"
	case KindNetSendto:
		return "net.sendto"
	case KindFileOpen:
		return "file.open"
	case KindCredsSetuid:
		return "creds.setuid"
	case KindCredsSetgid:
		return "creds.setgid"
	case KindCredsCapset:
		return "creds.capset"
	case KindExec:
		return "exec"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
}

func verdictString(v uint32) string {
	switch v {
	case verdictAllow:
		return "allow"
	case verdictDeny:
		return "deny"
	case verdictAudit:
		return "audit"
	default:
		return "unknown"
	}
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
