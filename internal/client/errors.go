package client

import (
	"errors"
	"fmt"
)

// Server error codes (INTERFACES §2.9). Strings are exactly what the daemon
// emits on the wire.
const (
	CodeInvalidManifest  = "INVALID_MANIFEST"
	CodeAgentNotFound    = "AGENT_NOT_FOUND"
	CodeCgroupFailed     = "CGROUP_FAILED"
	CodeBPFLoadFailed    = "BPF_LOAD_FAILED"
	CodeLaunchFailed     = "LAUNCH_FAILED"
	CodePermissionDenied = "PERMISSION_DENIED"
	CodeInternal         = "INTERNAL"

	// Client-synthesized (lowercase per DEC-009 / INTERFACES §2.9).
	CodeDaemonUnreachable = "daemon_unreachable"
	CodeManifestParse     = "manifest_parse_failed"
)

// Sentinel errors. Callers can use errors.Is to branch.
var (
	ErrAgentNotFound     = errors.New("agent not found")
	ErrInvalidManifest   = errors.New("invalid manifest")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrCgroupFailed      = errors.New("cgroup setup failed")
	ErrBPFLoadFailed     = errors.New("bpf load failed")
	ErrLaunchFailed      = errors.New("agent launch failed")
	ErrDaemonUnreachable = errors.New("daemon unreachable")
	ErrInternal          = errors.New("internal daemon error")
	ErrFrameOversize     = errors.New("daemon frame exceeds 16 MiB cap")
)

// ServerError wraps a daemon-side error and carries the wire fields. It also
// implements errors.Is against the matching sentinel so callers can branch on
// either the typed sentinel or the wire code.
type ServerError struct {
	Code    string
	Message string
}

// Error renders "<code>: <message>".
func (s *ServerError) Error() string {
	if s.Message == "" {
		return s.Code
	}
	return fmt.Sprintf("%s: %s", s.Code, s.Message)
}

// Is wires the wire code to the matching sentinel so errors.Is works
// uniformly across CLI subcommands.
func (s *ServerError) Is(target error) bool {
	switch target {
	case ErrAgentNotFound:
		return s.Code == CodeAgentNotFound
	case ErrInvalidManifest:
		return s.Code == CodeInvalidManifest
	case ErrPermissionDenied:
		return s.Code == CodePermissionDenied
	case ErrCgroupFailed:
		return s.Code == CodeCgroupFailed
	case ErrBPFLoadFailed:
		return s.Code == CodeBPFLoadFailed
	case ErrLaunchFailed:
		return s.Code == CodeLaunchFailed
	case ErrInternal:
		return s.Code == CodeInternal
	}
	return false
}

// fromWire converts a wire WireError into a typed *ServerError.
func fromWire(w *WireError) *ServerError {
	if w == nil {
		return nil
	}
	return &ServerError{Code: w.Code, Message: w.Message}
}
