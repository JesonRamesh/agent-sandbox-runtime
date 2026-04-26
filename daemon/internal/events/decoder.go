// Package events decodes raw ringbuf bytes from the kernel into
// typed Go structs. The wire format is: event_hdr followed by one
// of net_event / file_event / creds_event / exec_event, depending
// on hdr.Kind. See bpf/common.h for the C-side declarations.
package events

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const (
	KindNetConnect  = 1
	KindNetSendto   = 2
	KindFileOpen    = 3
	KindCredsSetuid = 4
	KindCredsSetgid = 5
	KindCredsCapset = 6
	KindExec        = 7
)

const (
	VerdictAllow = 0
	VerdictDeny  = 1
	VerdictAudit = 2
)

const maxPath = 256
const commLen = 16

// Header mirrors `struct event_hdr`.
type Header struct {
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

type Event struct {
	Time     time.Time `json:"time"`
	PID      uint32    `json:"pid"`
	TGID     uint32    `json:"tgid"`
	UID      uint32    `json:"uid"`
	GID      uint32    `json:"gid"`
	CgroupID uint64    `json:"cgroup_id"`
	Kind     string    `json:"kind"`
	Verdict  string    `json:"verdict"`
	Comm     string    `json:"comm"`

	// At most one of these is populated, matching Kind.
	Net   *NetPayload   `json:"net,omitempty"`
	File  *FilePayload  `json:"file,omitempty"`
	Creds *CredsPayload `json:"creds,omitempty"`
	Exec  *ExecPayload  `json:"exec,omitempty"`
}

type NetPayload struct {
	Family uint32 `json:"family"`
	Dport  uint16 `json:"dport"`
	Daddr  string `json:"daddr"`
}

type FilePayload struct {
	Flags int32  `json:"flags"`
	Path  string `json:"path"`
}

type CredsPayload struct {
	OldID    uint32 `json:"old_id"`
	NewID    uint32 `json:"new_id"`
	CapEff   uint64 `json:"cap_effective"`
}

type ExecPayload struct {
	PPID     uint32 `json:"ppid"`
	Filename string `json:"filename"`
}

func (e Event) MarshalJSON() ([]byte, error) {
	type alias Event
	return json.Marshal((alias)(e))
}

// Decode parses one ringbuf record.
func Decode(buf []byte) (*Event, error) {
	if len(buf) < binary.Size(Header{}) {
		return nil, fmt.Errorf("short event: %d bytes", len(buf))
	}
	var hdr Header
	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	evt := &Event{
		Time:     time.Unix(0, int64(hdr.TsNs)),
		PID:      hdr.PID,
		TGID:     hdr.TGID,
		UID:      hdr.UID,
		GID:      hdr.GID,
		CgroupID: hdr.CgroupID,
		Kind:     kindString(hdr.Kind),
		Verdict:  verdictString(hdr.Verdict),
		Comm:     cstring(hdr.Comm[:]),
	}

	tail := buf[binary.Size(Header{}):]
	switch hdr.Kind {
	case KindNetConnect, KindNetSendto:
		evt.Net = decodeNet(tail)
	case KindFileOpen:
		evt.File = decodeFile(tail)
	case KindCredsSetuid, KindCredsSetgid, KindCredsCapset:
		evt.Creds = decodeCreds(tail)
	case KindExec:
		evt.Exec = decodeExec(tail)
	}
	return evt, nil
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
	}
	return fmt.Sprintf("unknown(%d)", k)
}

func verdictString(v uint32) string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictDeny:
		return "deny"
	case VerdictAudit:
		return "audit"
	}
	return "unknown"
}

func decodeNet(b []byte) *NetPayload {
	if len(b) < 4+2+2+4+16 {
		return nil
	}
	family := binary.LittleEndian.Uint32(b[0:4])
	dport := binary.LittleEndian.Uint16(b[4:6])
	v4 := binary.LittleEndian.Uint32(b[8:12])
	addr := net.IPv4(byte(v4), byte(v4>>8), byte(v4>>16), byte(v4>>24))
	return &NetPayload{Family: family, Dport: dport, Daddr: addr.String()}
}

func decodeFile(b []byte) *FilePayload {
	if len(b) < 4+maxPath {
		return nil
	}
	flags := int32(binary.LittleEndian.Uint32(b[0:4]))
	return &FilePayload{Flags: flags, Path: cstring(b[4 : 4+maxPath])}
}

func decodeCreds(b []byte) *CredsPayload {
	if len(b) < 4+4+8 {
		return nil
	}
	return &CredsPayload{
		OldID:  binary.LittleEndian.Uint32(b[0:4]),
		NewID:  binary.LittleEndian.Uint32(b[4:8]),
		CapEff: binary.LittleEndian.Uint64(b[8:16]),
	}
}

func decodeExec(b []byte) *ExecPayload {
	if len(b) < 4+4+maxPath {
		return nil
	}
	return &ExecPayload{
		PPID:     binary.LittleEndian.Uint32(b[0:4]),
		Filename: cstring(b[8 : 8+maxPath]),
	}
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
