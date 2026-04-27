// Package ipc implements the wire protocol and Unix-socket server for the
// sandbox daemon. The contract lives in api/proto.md; this file is the
// machine-readable mirror of it. Keep them in sync.
package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Stable error codes. Match api/proto.md "Error codes" table verbatim — the
// CLI/UI keys behavior off these strings, so renaming any constant is a
// breaking change.
const (
	ErrInvalidManifest = "INVALID_MANIFEST"
	ErrAgentNotFound   = "AGENT_NOT_FOUND"
	ErrCgroupFailed    = "CGROUP_FAILED"
	ErrBPFLoadFailed   = "BPF_LOAD_FAILED"
	ErrLaunchFailed    = "LAUNCH_FAILED"
	ErrInternal        = "INTERNAL"
)

// Sentinel errors handlers may return so the server can map them to a stable
// wire code without each handler hand-rolling JSON. Anything that doesn't
// match here becomes ErrInternal — that keeps unexpected panics/bugs from
// leaking implementation details over the socket.
var (
	ErrInvalidManifestErr = errors.New("invalid manifest")
	ErrAgentNotFoundErr   = errors.New("agent not found")
	ErrCgroupFailedErr    = errors.New("cgroup operation failed")
	ErrBPFLoadFailedErr   = errors.New("bpf load failed")
	ErrLaunchFailedErr    = errors.New("agent launch failed")
)

// CodeForError maps a handler error to a wire code. Order matters: more
// specific sentinels first.
func CodeForError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidManifestErr):
		return ErrInvalidManifest
	case errors.Is(err, ErrAgentNotFoundErr):
		return ErrAgentNotFound
	case errors.Is(err, ErrCgroupFailedErr):
		return ErrCgroupFailed
	case errors.Is(err, ErrBPFLoadFailedErr):
		return ErrBPFLoadFailed
	case errors.Is(err, ErrLaunchFailedErr):
		return ErrLaunchFailed
	default:
		return ErrInternal
	}
}

// Request is the wire envelope for any client→server message.
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Response is the wire envelope for any server→client message.
// Result and Error are mutually exclusive: OK true ⇒ Result populated,
// OK false ⇒ Error populated.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is the structured error body. Code is stable; Message is human-readable.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Manifest matches api/proto.md §Manifest. The four guardrail fields
// (allowed_hosts, allowed_paths, allowed_bins, forbidden_caps) feed
// directly into the kernel-side `struct policy` defined in
// bpf/common.h.reference — adding fields here means matching them in
// internal/policy/policy.go's Compile().
type Manifest struct {
	Name          string            `json:"name"`
	Command       []string          `json:"command"`
	Mode          string            `json:"mode,omitempty"`           // "audit" | "enforce" (default "enforce")
	AllowedHosts  []string          `json:"allowed_hosts,omitempty"`  // "host[:port]" or "ip[/cidr][:port]"
	AllowedPaths  []string          `json:"allowed_paths,omitempty"`  // path prefixes; bpf_d_path-resolved at file_open
	AllowedBins   []string          `json:"allowed_bins,omitempty"`   // exec allow-list (full path); empty = allow all
	ForbiddenCaps []string          `json:"forbidden_caps,omitempty"` // e.g. "CAP_SYS_ADMIN"
	Env           map[string]string `json:"env,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
}

// Validate enforces the v0.1 minimum: a name and at least one argv entry.
// More elaborate validation (host parsing, path canonicalization) lives in
// internal/policy in v0.2.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("%w: nil manifest", ErrInvalidManifestErr)
	}
	if m.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidManifestErr)
	}
	if len(m.Command) == 0 {
		return fmt.Errorf("%w: command must have at least one argument", ErrInvalidManifestErr)
	}
	return nil
}

// AgentSummary is the per-agent listing entry returned by ListAgents.
type AgentSummary struct {
	AgentID   string    `json:"agent_id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	PID       int       `json:"pid"`
}

// Event mirrors api/proto.md §Event. Details is type-specific JSON kept raw
// here so the daemon can emit any of the documented shapes without a tagged
// union type per kind.
type Event struct {
	Ts      time.Time       `json:"ts"`
	AgentID string          `json:"agent_id"`
	Type    string          `json:"type"`
	PID     uint32          `json:"pid"`
	Details json.RawMessage `json:"details"`
}

// Method-specific param/result types. Empty-param structs (ListAgents,
// DaemonStatus) still exist as types so callers don't have to remember
// "send {}" vs "send null" — Marshal will produce {} for either.

type RunAgentParams struct {
	Manifest Manifest `json:"manifest"`
}

type RunAgentResult struct {
	AgentID string `json:"agent_id"`
}

type StopAgentParams struct {
	AgentID string `json:"agent_id"`
}

// StopAgentResult mirrors the proto's `{ ok: bool }` body. The outer
// Response.OK is the protocol-level success bit; this inner OK is the
// idempotent-stop semantics ("we have ensured it's stopped").
type StopAgentResult struct {
	OK bool `json:"ok"`
}

type ListAgentsParams struct{}

type ListAgentsResult struct {
	Agents []AgentSummary `json:"agents"`
}

type AgentLogsParams struct {
	AgentID string `json:"agent_id"`
	TailN   int    `json:"tail_n"`
}

type AgentLogsResult struct {
	Lines []Event `json:"lines"`
}

// StreamEventsParams.AgentID is optional; empty string means "all agents".
// There is no result type — frames carry one Event each in Response.Result.
type StreamEventsParams struct {
	AgentID string `json:"agent_id,omitempty"`
}

type DaemonStatusParams struct{}

type DaemonStatusResult struct {
	Version    string `json:"version"`
	UptimeSec  int64  `json:"uptime_sec"`
	AgentCount int    `json:"agent_count"`
}

// Method names — string-typed because the protocol is stringly-typed and
// we want a single canonical spelling everywhere.
const (
	MethodRunAgent     = "RunAgent"
	MethodStopAgent    = "StopAgent"
	MethodListAgents   = "ListAgents"
	MethodAgentLogs    = "AgentLogs"
	MethodStreamEvents = "StreamEvents"
	MethodDaemonStatus = "DaemonStatus"
)

// maxFrameBytes caps a single frame to keep a malicious or buggy peer from
// asking us to allocate gigabytes. 16 MiB is far above any legitimate
// request (manifests are tiny) and any single Event.
const maxFrameBytes = 16 * 1024 * 1024

// WriteFrame writes a length-prefixed JSON frame to w. The 4-byte big-endian
// prefix is fixed by api/proto.md.
func WriteFrame(w io.Writer, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(body) > maxFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", len(body))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed JSON frame from r and unmarshals into v.
// Returns io.EOF cleanly when the peer closes between frames.
func ReadFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// Surface io.EOF unwrapped so callers can distinguish "clean close
		// at frame boundary" from "truncated frame".
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrameBytes {
		return fmt.Errorf("frame too large: %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("read frame body: %w", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("unmarshal frame: %w", err)
	}
	return nil
}

// WriteOK marshals result and writes a successful Response frame.
func WriteOK(w io.Writer, result any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	return WriteFrame(w, Response{OK: true, Result: raw})
}

// WriteErr writes a failed Response frame with the given code and message.
func WriteErr(w io.Writer, code, message string) error {
	return WriteFrame(w, Response{OK: false, Error: &Error{Code: code, Message: message}})
}
