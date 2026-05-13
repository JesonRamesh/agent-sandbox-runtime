// Package manifest implements the v1 agentctl YAML manifest: typed schema,
// two-pass parser with line/column-precise errors, and field validation.
//
// The wire types in this file are what gets marshalled into RunAgent.params.manifest
// after defaults, env interpolation, and duration parsing have all been applied.
package manifest

// Manifest is the fully resolved, validated manifest as accepted by the daemon.
//
// "Resolved" means: defaults filled in, ${VAR} substitutions performed, durations
// parsed to nanoseconds. The daemon does not re-parse YAML.
type Manifest struct {
	Name                string            `json:"name"           yaml:"name"`
	Command             []string          `json:"command"        yaml:"command"`
	Mode                string            `json:"mode,omitempty" yaml:"mode"`
	AllowedHosts        []string          `json:"allowed_hosts"  yaml:"allowed_hosts"`
	AllowedPaths        []string          `json:"allowed_paths"  yaml:"allowed_paths"`
	AllowedBins         []string          `json:"allowed_bins,omitempty"   yaml:"allowed_bins"`
	ForbiddenCaps       []string          `json:"forbidden_caps,omitempty" yaml:"forbidden_caps"`
	// Deny outbound connections to non-TLS ports (anything other than the
	// transport-encrypted ports listed in bpf/common.h's IS_TLS_PORT).
	// Use this on any manifest whose agent has access to credentials in
	// env, .env files, or the filesystem: it makes "no credentials in
	// plaintext on the wire" a structural property of the policy.
	DenyCleartextEgress bool              `json:"deny_cleartext_egress,omitempty" yaml:"deny_cleartext_egress"`
	WorkingDir          string            `json:"working_dir"    yaml:"working_dir"`
	Env                 map[string]string `json:"env"            yaml:"env"`
	User                string            `json:"user"           yaml:"user"`
	Stdin               string            `json:"stdin"          yaml:"stdin"`
	TimeoutNS           int64             `json:"timeout_ns"     yaml:"-"`
	Description         string            `json:"description"    yaml:"description"`
}

// KnownTopLevelKeys is the canonical, ordered list of accepted top-level keys.
// The order is the user-facing render order (used in error messages and the
// `valid keys: ...` hint).
var KnownTopLevelKeys = []string{
	"name",
	"command",
	"mode",
	"allowed_hosts",
	"allowed_paths",
	"allowed_bins",
	"forbidden_caps",
	"deny_cleartext_egress",
	"working_dir",
	"env",
	"user",
	"stdin",
	"timeout",
	"description",
}

func isKnownTopLevelKey(k string) bool {
	for _, v := range KnownTopLevelKeys {
		if v == k {
			return true
		}
	}
	return false
}

// PolicySummary returns the human "hosts:N paths:M timeout:T" rendering used in
// `agentctl run` output and `agentctl list`.
func (m *Manifest) PolicySummary() string {
	return formatPolicySummary(len(m.AllowedHosts), len(m.AllowedPaths), m.TimeoutNS)
}
