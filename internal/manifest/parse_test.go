package manifest

import (
	"errors"
	"strings"
	"testing"
)

// fakeEnv produces an envLookup that succeeds only for the keys in m.
func fakeEnv(m map[string]string) envLookup {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestParse_OKWebFetcher(t *testing.T) {
	m, err := Parse("testdata/ok-web-fetcher.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Name != "web-fetcher" {
		t.Errorf("name = %q, want %q", m.Name, "web-fetcher")
	}
	if len(m.AllowedHosts) != 1 || m.AllowedHosts[0] != "api.openai.com:443" {
		t.Errorf("allowed_hosts = %v", m.AllowedHosts)
	}
	if m.WorkingDir != "/tmp/agentctl/web-fetcher" {
		t.Errorf("working_dir default = %q", m.WorkingDir)
	}
	if m.Stdin != "close" {
		t.Errorf("stdin default = %q", m.Stdin)
	}
	if m.PolicySummary() != "hosts:1 paths:0 timeout:0" {
		t.Errorf("policy summary = %q", m.PolicySummary())
	}
}

func TestParse_OKLLMAgentWithEnv(t *testing.T) {
	data := []byte(`name: llm-agent
command: ["/usr/bin/python3", "/opt/agents/demo.py"]
allowed_hosts: ["api.openai.com:443"]
allowed_paths: ["/opt/agents/"]
env:
  KEY: "${TEST_API_KEY}"
timeout: "5m"
`)
	m, err := parseAndValidate("inline.yaml", data, fakeEnv(map[string]string{
		"TEST_API_KEY": "secret-value",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Env["KEY"] != "secret-value" {
		t.Errorf("env interpolation: KEY = %q", m.Env["KEY"])
	}
	if m.TimeoutNS != int64(5*60*1e9) {
		t.Errorf("timeout = %d ns", m.TimeoutNS)
	}
}

func TestParse_TypoAllowedPots(t *testing.T) {
	_, err := Parse("testdata/bad-typo.yaml")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if e.Code != CodeUnknownField {
		t.Errorf("code = %q, want %q", e.Code, CodeUnknownField)
	}
	// "allowed_paths" must appear; "allowed_hosts" is also at distance 2.
	// The catalogue says: list all candidates when there are ties.
	if !strings.Contains(e.Error(), "did you mean") || !strings.Contains(e.Error(), "allowed_paths") {
		t.Errorf("did-you-mean missing in: %s", e.Error())
	}
	if !strings.Contains(e.Error(), "bad-typo.yaml") {
		t.Errorf("filename missing in: %s", e.Error())
	}
	// The unknown key sits on line 4 col 1 of the fixture.
	if e.Line != 4 || e.Column != 1 {
		t.Errorf("line:col = %d:%d, want 4:1", e.Line, e.Column)
	}
}

func TestParse_BadPathsGlob(t *testing.T) {
	_, err := Parse("testdata/bad-paths.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if e.Code != CodeInvalidPathPattern {
		t.Errorf("code = %q, want %q", e.Code, CodeInvalidPathPattern)
	}
	if !strings.Contains(e.Error(), "/foo/**") {
		t.Errorf("offending value missing in: %s", e.Error())
	}
}

func TestParse_BadCIDRMask(t *testing.T) {
	_, err := Parse("testdata/bad-cidr.yaml")
	if err == nil {
		t.Fatal("expected error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if e.Code != CodeInvalidHostPattern {
		t.Errorf("code = %q, want %q", e.Code, CodeInvalidHostPattern)
	}
	if !strings.Contains(e.Error(), "10.0.0.0/33") {
		t.Errorf("offending value missing in: %s", e.Error())
	}
}

func TestParse_HostBitsSetCIDR(t *testing.T) {
	data := []byte(`name: bad-host-bits
command: ["/bin/true"]
allowed_hosts: ["10.0.0.5/8"]
allowed_paths: []
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	if err == nil {
		t.Fatal("expected error")
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeInvalidHostPattern {
		t.Errorf("expected invalid_host_pattern, got %v", err)
	}
}

// working_dir must reject traversal so the daemon can't be tricked into
// MkdirAll-ing into /etc, /sys, etc. via a normalized-but-misleading path.
// Each case is the YAML source for the working_dir scalar (so we can control
// whether YAML's quoted-string escape decoder fires); the literal `\n`
// becomes an LF only after YAML unescapes the double-quoted form.
func TestParse_RejectsWorkingDirTraversal(t *testing.T) {
	cases := []struct {
		name        string
		yamlValue   string // appears verbatim after `working_dir: ` in the manifest
		description string
	}{
		{"traversal-into-etc", `"/tmp/agent/../../etc/foo"`, "embedded .."},
		{"trailing-dotdot", `"/tmp/foo/.."`, "trailing /.."},
		{"system-etc", `"/etc/agent"`, "sensitive prefix /etc"},
		{"system-proc", `"/proc/1/agent"`, "sensitive prefix /proc"},
		{"system-sys", `"/sys/kernel/agent"`, "sensitive prefix /sys"},
		{"relative", `"relative/path"`, "not absolute"},
		// `\n` in a YAML double-quoted scalar decodes to a literal LF byte
		// — the form a hostile manifest would use to smuggle a newline
		// past a naive prefix check.
		{"embedded-newline", `"/tmp/agent\nfoo"`, "control character in path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`name: traversal
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
working_dir: ` + tc.yamlValue + "\n")
			_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
			if err == nil {
				t.Fatalf("expected rejection (%s) for working_dir=%s", tc.description, tc.yamlValue)
			}
		})
	}
}

// envVarRe must match envKeyRe; lowercase env-var references in values
// were silently passing through unexpanded (C4 in the audit).
func TestParse_LowercaseEnvVarSubstitution(t *testing.T) {
	data := []byte(`name: env-lower
command: ["/bin/sh", "-c", "echo $X"]
allowed_hosts: []
allowed_paths: []
env:
  API_KEY: "${lower_var}"
`)
	m, err := parseAndValidate("inline.yaml", data, fakeEnv(map[string]string{"lower_var": "secret"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := m.Env["API_KEY"]; got != "secret" {
		t.Errorf("API_KEY = %q, want %q (substitution should accept lowercase)", got, "secret")
	}
}

func TestParse_UnsetEnvVar(t *testing.T) {
	data := []byte(`name: env-bad
command: ["/bin/sh", "-c", "echo $X"]
allowed_hosts: []
allowed_paths: []
env:
  X: "${UNSET_VAR_FOR_TEST}"
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(map[string]string{}))
	if err == nil {
		t.Fatal("expected error")
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeUnsetEnvVar {
		t.Errorf("expected unset_env_var, got %v", err)
	}
	if !strings.Contains(e.Error(), "${UNSET_VAR_FOR_TEST}") {
		t.Errorf("var name missing in: %s", e.Error())
	}
}

func TestParse_MissingRequired(t *testing.T) {
	data := []byte(`name: missing-bits
command: ["/bin/true"]
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	if err == nil {
		t.Fatal("expected error")
	}
	// Two missing fields → MultiError.
	var me *MultiError
	if !errors.As(err, &me) {
		t.Fatalf("expected MultiError, got %T: %v", err, err)
	}
	if len(me.Errors) != 2 {
		t.Errorf("got %d errors, want 2: %v", len(me.Errors), me.Errors)
	}
	for _, ee := range me.Errors {
		if ee.Code != CodeMissingRequired {
			t.Errorf("code = %q, want missing_required", ee.Code)
		}
	}
}

func TestParse_BadYAML(t *testing.T) {
	data := []byte("name: foo\n  command: [bad indent\n")
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	if err == nil {
		t.Fatal("expected yaml error")
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeYAMLParse {
		t.Fatalf("expected yaml_parse, got %v", err)
	}
}

func TestParse_BadDuration(t *testing.T) {
	data := []byte(`name: bad-dur
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
timeout: "not-a-duration"
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeBadDuration {
		t.Fatalf("expected bad_duration, got %v", err)
	}
}

func TestParse_BadStdin(t *testing.T) {
	data := []byte(`name: bad-stdin
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
stdin: "open"
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeBadStdin {
		t.Fatalf("expected bad_stdin, got %v", err)
	}
}

func TestParse_BadName(t *testing.T) {
	data := []byte(`name: HasUpperCase
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeInvalidName {
		t.Fatalf("expected invalid_name, got %v", err)
	}
}

func TestParse_NonAbsoluteWorkingDir(t *testing.T) {
	data := []byte(`name: rel-cwd
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
working_dir: "relative/path"
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeNonAbsolutePath {
		t.Fatalf("expected non_absolute_path, got %v", err)
	}
}

func TestParse_EmptyCommand(t *testing.T) {
	data := []byte(`name: empty-cmd
command: []
allowed_hosts: []
allowed_paths: []
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeEmptyCommand {
		t.Fatalf("expected empty_command, got %v", err)
	}
}

func TestParse_DuplicateKey(t *testing.T) {
	data := []byte(`name: dup
command: ["/bin/true"]
allowed_hosts: []
allowed_hosts: ["api.example.com"]
allowed_paths: []
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	if err == nil {
		t.Fatal("expected duplicate_key error")
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeDuplicateKey {
		t.Fatalf("expected duplicate_key, got %v", err)
	}
	if e.Field != "allowed_hosts" {
		t.Errorf("field = %q, want allowed_hosts", e.Field)
	}
	if e.Line != 4 {
		t.Errorf("line = %d, want 4 (the second occurrence)", e.Line)
	}
}

func TestParse_BadEnvKey(t *testing.T) {
	cases := []struct {
		name, key string
	}{
		{"equals-in-key", "K=V"},
		{"newline-in-key", "K\nL"},
		{"empty-key", ""},
		{"leading-digit", "1KEY"},
		{"hyphen", "K-EY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte("name: env-bad-key\ncommand: [\"/bin/true\"]\nallowed_hosts: []\nallowed_paths: []\nenv:\n  " +
				yamlQuote(tc.key) + ": \"v\"\n")
			_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
			if err == nil {
				t.Fatalf("expected bad_env_key for %q", tc.key)
			}
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeBadEnvKey {
				t.Fatalf("expected bad_env_key, got %v", err)
			}
		})
	}
}

// yamlQuote double-quotes a string and emits YAML escape sequences for any
// control bytes. The yaml.v3 lexer rejects raw control bytes in scalars, but
// the double-quoted escape forms decode to the literal byte in .Value, which
// is exactly what we need to drive validator-boundary tests.
func yamlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case 0:
			b.WriteString(`\0`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestParse_PathControlChars(t *testing.T) {
	cases := []string{
		"/etc/x\x00y",
		"/etc/x\ny",
		"/etc/x\ry",
		"/etc/x\ty",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			data := []byte("name: ctl\ncommand: [\"/bin/true\"]\nallowed_hosts: []\nallowed_paths:\n  - " + yamlQuote(p) + "\n")
			_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
			if err == nil {
				t.Fatalf("expected invalid_path_pattern for %q", p)
			}
			var e *Error
			if !errors.As(err, &e) || e.Code != CodeInvalidPathPattern {
				t.Fatalf("expected invalid_path_pattern, got %v", err)
			}
		})
	}
}

func TestParse_StdinControlChars(t *testing.T) {
	data := []byte("name: stdin-ctl\ncommand: [\"/bin/true\"]\nallowed_hosts: []\nallowed_paths: []\nstdin: " +
		yamlQuote("file:/etc/x\nbad") + "\n")
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	if err == nil {
		t.Fatal("expected bad_stdin error for control char in stdin path")
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeBadStdin {
		t.Fatalf("expected bad_stdin, got %v", err)
	}
}

func TestParse_NegativeUID(t *testing.T) {
	data := []byte(`name: neg-uid
command: ["/bin/true"]
allowed_hosts: []
allowed_paths: []
user: "-1"
`)
	_, err := parseAndValidate("inline.yaml", data, fakeEnv(nil))
	if err == nil {
		t.Fatal("expected bad_user for negative uid")
	}
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeBadUser {
		t.Fatalf("expected bad_user, got %v", err)
	}
}

func TestSuggest_Levenshtein(t *testing.T) {
	// Both "allowed_paths" and "allowed_hosts" are at distance 2 from
	// "allowed_pots" → both returned (DEC-005: "if more than one candidate, list all").
	got := Suggest("allowed_pots", KnownTopLevelKeys, 2)
	if len(got) != 2 {
		t.Errorf("Suggest('allowed_pots') = %v, want 2 candidates", got)
	}
	containsAll := func(have, want []string) bool {
		for _, w := range want {
			found := false
			for _, h := range have {
				if h == w {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}
	if !containsAll(got, []string{"allowed_paths", "allowed_hosts"}) {
		t.Errorf("Suggest('allowed_pots') = %v, want both allowed_paths and allowed_hosts", got)
	}
	got = Suggest("comand", KnownTopLevelKeys, 2)
	if len(got) != 1 || got[0] != "command" {
		t.Errorf("Suggest('comand') = %v, want [command]", got)
	}
	got = Suggest("xyzzy", KnownTopLevelKeys, 2)
	if len(got) != 0 {
		t.Errorf("Suggest('xyzzy') = %v, want empty", got)
	}
}
