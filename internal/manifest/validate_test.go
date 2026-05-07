package manifest

import (
	"strings"
	"testing"
)

// TestSuggestCapability checks that a single-letter typo of a known CAP name
// produces the corrected suggestion. Regression: M3 — a stricter closed-set
// validator was useful for security but a flat "unknown capability" error
// made operators give up on forbidden_caps.
func TestSuggestCapability(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"CAP_SYS_ADIM", "CAP_SYS_ADMIN"},
		{"CAP_DAC_OVRRIDE", "CAP_DAC_OVERRIDE"},
		{"cap_sys_admin", "CAP_SYS_ADMIN"}, // case-insensitive input
		{"CAP_NET_RWA", "CAP_NET_RAW"},
	}
	for _, tc := range cases {
		got := suggestCapability(tc.input)
		if got != tc.want {
			t.Errorf("suggestCapability(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestSuggestCapability_NoMatch verifies we don't hallucinate a suggestion
// for input that's not close to any known cap.
func TestSuggestCapability_NoMatch(t *testing.T) {
	if got := suggestCapability("totally_unrelated"); got != "" {
		t.Errorf("suggestCapability(totally_unrelated) = %q, want empty", got)
	}
}

// TestValidateForbiddenCaps_IncludesSuggestion confirms the validator embeds
// the did-you-mean hint into the user-facing error. This is the path an
// operator actually sees on `agentctl manifest validate`.
func TestValidateForbiddenCaps_IncludesSuggestion(t *testing.T) {
	yaml := []byte(`name: x
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
forbidden_caps: ["CAP_SYS_ADIM"]
`)
	_, err := ParseBytes("inline", yaml)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "CAP_SYS_ADMIN") {
		t.Errorf("error %q should suggest CAP_SYS_ADMIN", msg)
	}
}
