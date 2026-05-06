// Package client implements the CLI side of the agentd Unix-socket protocol
// (INTERFACES §2): length-prefixed JSON request/response with seven methods.
//
// This file holds the wire types. The methods (Dial, RunAgent, ...) live in
// client.go. The framing helpers live in stream.go.
package client

import (
	"encoding/json"
	"time"
)

// MethodName values are exactly the strings on the wire (INTERFACES §2.1).
const (
	MethodRunAgent     = "RunAgent"
	MethodStopAgent    = "StopAgent"
	MethodListAgents   = "ListAgents"
	MethodAgentLogs    = "AgentLogs"
	MethodStreamEvents = "StreamEvents"
	MethodDaemonStatus = "DaemonStatus"
	MethodIngestEvent  = "IngestEvent"
)

// MaxFrameBytes caps any single frame body at 16 MiB (DEC-011). Frames larger
// than this are rejected and the connection is closed.
const MaxFrameBytes = 16 << 20

// StreamFrameTimeout matches P2's per-frame server write deadline. The CLI's
// Read side does not actively enforce this — it's documentation that informs
// the cancellation budget.
const StreamFrameTimeout = 1 * time.Second

// RequestEnvelope is the wire shape of a single request frame body.
type RequestEnvelope struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// ResponseEnvelope is the wire shape of a single response frame body.
//
// On success: Ok=true, Result holds the method-specific JSON.
// On failure: Ok=false, Error holds the typed error.
type ResponseEnvelope struct {
	Ok     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *WireError      `json:"error,omitempty"`
}

// WireError is the on-the-wire error shape (INTERFACES §2.1).
type WireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// --- RunAgent ---

// RunAgentRequest is the params shape for MethodRunAgent.
//
// Fields outside `manifest` (like restart_on_crash and max_restarts) are
// adjacent to the resolved manifest, not nested in it (DEC-012).
type RunAgentRequest struct {
	Manifest       ManifestPayload `json:"manifest"`
	ManifestSource ManifestSource  `json:"manifest_source"`
	RestartOnCrash bool            `json:"restart_on_crash"`
	MaxRestarts    int             `json:"max_restarts"`
}

// ManifestPayload mirrors the manifest.Manifest JSON shape so the daemon can
// decode it without re-parsing YAML. Field tags must match those in
// manifest.Manifest.
type ManifestPayload struct {
	Name          string            `json:"name"`
	Command       []string          `json:"command"`
	Mode          string            `json:"mode,omitempty"`
	AllowedHosts  []string          `json:"allowed_hosts"`
	AllowedPaths  []string          `json:"allowed_paths"`
	AllowedBins   []string          `json:"allowed_bins,omitempty"`
	ForbiddenCaps []string          `json:"forbidden_caps,omitempty"`
	WorkingDir    string            `json:"working_dir"`
	Env           map[string]string `json:"env"`
	User          string            `json:"user"`
	Stdin         string            `json:"stdin"`
	TimeoutNS     int64             `json:"timeout_ns"`
	Description   string            `json:"description"`
}

// ManifestSource is metadata only — used by the daemon for audit logs.
type ManifestSource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// RunAgentResult is the success result for MethodRunAgent.
type RunAgentResult struct {
	Name          string `json:"name"`
	AgentID       string `json:"agent_id"`
	PID           int    `json:"pid"`
	CgroupPath    string `json:"cgroup_path"`
	StartedAt     string `json:"started_at"`
	PolicySummary string `json:"policy_summary"`
}

// --- ListAgents ---

// ListAgentsRequest has empty params; the wire body is `{}`.
type ListAgentsRequest struct{}

// ListAgentsResult is the success result for MethodListAgents.
type ListAgentsResult struct {
	Agents []AgentInfo `json:"agents"`
}

// AgentInfo describes one agent in `ListAgents` output. `ExitCode` is *int so
// JSON `null` for "still running" round-trips correctly.
type AgentInfo struct {
	Name          string `json:"name"`
	AgentID       string `json:"agent_id"`
	PID           int    `json:"pid"`
	Status        string `json:"status"` // "running" | "exited" | "killed"
	ExitCode      *int   `json:"exit_code"`
	StartedAt     string `json:"started_at"`
	UptimeNS      int64  `json:"uptime_ns"`
	PolicySummary string `json:"policy_summary"`
}

// --- StopAgent ---

// StopAgentRequest is params for MethodStopAgent.
type StopAgentRequest struct {
	Name          string `json:"name"`
	GracePeriodNS int64  `json:"grace_period_ns"`
}

// StopAgentResult is the success result for MethodStopAgent.
type StopAgentResult struct {
	Name       string `json:"name"`
	ExitCode   int    `json:"exit_code"`
	Signal     string `json:"signal"`
	DurationNS int64  `json:"duration_ns"`
}

// --- AgentLogs ---

// AgentLogsRequest is params for MethodAgentLogs.
type AgentLogsRequest struct {
	Name  string `json:"name"`
	TailN int    `json:"tail_n"`
}

// AgentLogsResult is the success result for MethodAgentLogs.
type AgentLogsResult struct {
	Events []Event `json:"events"`
}

// --- StreamEvents ---

// StreamEventsRequest is params for MethodStreamEvents.
type StreamEventsRequest struct {
	Name    string   `json:"name,omitempty"`
	Include []string `json:"include,omitempty"`
}

// StreamEventsFrame is the per-frame body for streamed responses
// (INTERFACES §2.6).
type StreamEventsFrame struct {
	Event Event `json:"event"`
}

// --- DaemonStatus ---

// DaemonStatusRequest has empty params.
type DaemonStatusRequest struct{}

// DaemonStatusResult is the success result for MethodDaemonStatus.
type DaemonStatusResult struct {
	ProtocolVersion string `json:"protocol_version"`
	Build           string `json:"build"`
	UptimeNS        int64  `json:"uptime_ns"`
	AgentsRunning   int    `json:"agents_running"`
	// EventsDropped reports the number of events the daemon's pipeline
	// has dropped (full input buffer). Non-zero means the audit trail
	// has gaps — surface it in HumanDaemonStatus so operators notice.
	EventsDropped uint64 `json:"events_dropped,omitempty"`
}

// --- IngestEvent ---

// IngestEventRequest is params for MethodIngestEvent. The CLI does not normally
// call this — the orchestrator does — but we expose the type for completeness
// so other packages can construct it without round-tripping JSON.
type IngestEventRequest struct {
	AgentID string         `json:"agent_id"`
	Event   IngestEventDoc `json:"event"`
}

// IngestEventDoc is the inner event shape pushed by IngestEvent. The daemon
// stamps category and agent_id on top of this before fan-out.
type IngestEventDoc struct {
	Type    string          `json:"type"`
	TS      string          `json:"ts"`
	Details json.RawMessage `json:"details"`
}

// --- Event (unified envelope across categories) ---

// Event is the unified event envelope (INTERFACES §3.1).
//
// Data is left as RawMessage so callers can decode into a category-specific
// struct lazily (and so unknown subtypes pass through untouched).
type Event struct {
	Schema   string          `json:"schema"`
	TS       string          `json:"ts"`
	Agent    string          `json:"agent"`
	AgentID  string          `json:"agent_id"`
	Category string          `json:"category"`
	Type     string          `json:"type"`
	Data     json.RawMessage `json:"data"`
}
