package manifest

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Parse reads `path`, runs the two-pass validator, fills defaults, resolves
// ${VAR} env interpolation, and returns a fully resolved Manifest ready to send
// to the daemon.
//
// On failure returns an *Error or *MultiError with line/column-precise context.
func Parse(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{
			Code:    CodeYAMLParse,
			Message: fmt.Sprintf("cannot read manifest: %s", err.Error()),
			Path:    path,
		}
	}
	return ParseBytes(path, data)
}

// ParseBytes is Parse but reads from a buffer. The `path` argument is purely
// for error rendering (it never touches the filesystem).
func ParseBytes(path string, data []byte) (*Manifest, error) {
	m, err := parseAndValidate(path, data, os.LookupEnv)
	return m, err
}

// envLookup is the signature of os.LookupEnv; broken out so tests can inject.
type envLookup func(string) (string, bool)

// parseAndValidate is the testable workhorse.
func parseAndValidate(path string, data []byte, lookup envLookup) (*Manifest, error) {
	eb := newErrBuilder(path)

	// Pass 1: YAML syntax. yaml.Unmarshal into a *yaml.Node always succeeds for
	// syntactically valid YAML; if it fails, we extract line/col with a regex.
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		line, col := extractYAMLLineCol(err.Error())
		eb.add(&Error{
			Code:    CodeYAMLParse,
			Message: "yaml: " + scrubYAMLError(err.Error()),
			Line:    line,
			Column:  col,
		})
		return nil, eb.result()
	}

	// Empty document → all required fields missing.
	if root.Kind == 0 || (root.Kind == yaml.DocumentNode && len(root.Content) == 0) {
		eb.addf(CodeMissingRequired, 1, 1, "name", "required field %q is missing", "name")
		return nil, eb.result()
	}

	// Unwrap document → mapping.
	doc := &root
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			eb.addf(CodeMissingRequired, 1, 1, "name", "required field %q is missing", "name")
			return nil, eb.result()
		}
		doc = root.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		eb.addf(CodeWrongKind, doc.Line, doc.Column, "",
			"manifest root must be a mapping, got %s", kindName(doc.Kind))
		return nil, eb.result()
	}

	// Pass 2: walk top-level keys.
	seen := map[string]*yaml.Node{}
	suggestedTo := map[string]bool{} // suppresses missing_required when typo's
	// did-you-mean already pointed at the same field
	for i := 0; i < len(doc.Content); i += 2 {
		key := doc.Content[i]
		val := doc.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			eb.addf(CodeWrongKind, key.Line, key.Column, "",
				"manifest keys must be strings, got %s", kindName(key.Kind))
			continue
		}
		if !isKnownTopLevelKey(key.Value) {
			candidates := Suggest(key.Value, KnownTopLevelKeys, 2)
			for _, c := range candidates {
				suggestedTo[c] = true
			}
			eb.add(&Error{
				Code:       CodeUnknownField,
				Message:    formatUnknownFieldWithSuggestion(key.Value, candidates),
				Field:      key.Value,
				Line:       key.Line,
				Column:     key.Column,
				Suggestion: strings.Join(candidates, ","),
			})
			continue
		}
		if _, dup := seen[key.Value]; dup {
			// yaml.v3 silently lets the last occurrence win; reject so the
			// audit log (manifest source) matches what the daemon enforces.
			eb.addf(CodeDuplicateKey, key.Line, key.Column, key.Value,
				"duplicate key %q; YAML allows it but agentctl forbids it to keep the audit trail and enforced policy in sync",
				key.Value)
			continue
		}
		seen[key.Value] = val
	}

	// Required fields. Skip emitting missing_required if a misspelled key was
	// already suggested as this field — the unknown_field error is enough UX.
	for _, req := range []string{"name", "command", "allowed_hosts", "allowed_paths"} {
		if _, ok := seen[req]; ok {
			continue
		}
		if suggestedTo[req] {
			continue
		}
		// Place the error at the doc root; we don't have a precise line.
		line, col := doc.Line, doc.Column
		eb.addf(CodeMissingRequired, line, col, req,
			"required field %q is missing", req)
	}

	m := &Manifest{
		Env: map[string]string{},
	}

	// name
	if n := seen["name"]; n != nil {
		if v, ok := scalarString(eb, n, "name"); ok {
			validateName(eb, n, v)
			m.Name = v
		}
	}

	// command
	if n := seen["command"]; n != nil {
		if v, ok := stringSequence(eb, n, "command"); ok {
			if len(v) == 0 {
				eb.addf(CodeEmptyCommand, n.Line, n.Column, "command",
					"%q must be a non-empty list of argv elements", "command")
			} else {
				m.Command = v
			}
		}
	}

	// allowed_hosts
	if n := seen["allowed_hosts"]; n != nil {
		if v, ok := stringSequence(eb, n, "allowed_hosts"); ok {
			validateHosts(eb, n, v)
			m.AllowedHosts = v
		}
	} else {
		m.AllowedHosts = []string{}
	}

	// allowed_paths
	if n := seen["allowed_paths"]; n != nil {
		if v, ok := stringSequence(eb, n, "allowed_paths"); ok {
			validatePaths(eb, n, v)
			m.AllowedPaths = v
		}
	} else {
		m.AllowedPaths = []string{}
	}

	// mode (optional enum: "audit" | "enforce", default "enforce" — set by daemon)
	if n := seen["mode"]; n != nil {
		if v, ok := scalarString(eb, n, "mode"); ok {
			if !validMode(v) {
				eb.addf(CodeBadMode, n.Line, n.Column, "mode",
					"%q must be 'audit' or 'enforce'; got %q", "mode", v)
			} else {
				m.Mode = v
			}
		}
	}

	// allowed_bins (optional, list of absolute paths; empty list = allow any binary)
	if n := seen["allowed_bins"]; n != nil {
		if v, ok := stringSequence(eb, n, "allowed_bins"); ok {
			validateAllowedBins(eb, n, v)
			m.AllowedBins = v
		}
	}

	// forbidden_caps (optional, list of capability names like "CAP_SYS_ADMIN")
	if n := seen["forbidden_caps"]; n != nil {
		if v, ok := stringSequence(eb, n, "forbidden_caps"); ok {
			validateForbiddenCaps(eb, n, v)
			m.ForbiddenCaps = v
		}
	}

	// working_dir (optional, abs path)
	if n := seen["working_dir"]; n != nil {
		if v, ok := scalarString(eb, n, "working_dir"); ok {
			if err := validWorkingDir(v); err != nil {
				eb.addf(err.code, n.Line, n.Column, "working_dir", "%s", err.msg)
			} else {
				m.WorkingDir = v
			}
		}
	}

	// env (optional, map of strings, ${VAR} interpolated)
	if n := seen["env"]; n != nil {
		validateEnv(eb, n, m.Env, lookup)
	}

	// user (optional, string or numeric uid)
	if n := seen["user"]; n != nil {
		if v, ok := scalarString(eb, n, "user"); ok {
			if !validUser(v) {
				eb.addf(CodeBadUser, n.Line, n.Column, "user",
					"user %q is not a known account", v)
			} else {
				m.User = v
			}
		}
	}

	// stdin (optional, enum)
	if n := seen["stdin"]; n != nil {
		if v, ok := scalarString(eb, n, "stdin"); ok {
			if !validStdin(v) {
				eb.addf(CodeBadStdin, n.Line, n.Column, "stdin",
					"%q must be 'inherit', 'close', or 'file:<path>'; got %q", "stdin", v)
			} else {
				m.Stdin = v
			}
		}
	}

	// timeout (optional, duration string → ns)
	if n := seen["timeout"]; n != nil {
		if v, ok := scalarString(eb, n, "timeout"); ok {
			if v == "0" || v == "" {
				m.TimeoutNS = 0
			} else {
				d, err := time.ParseDuration(v)
				if err != nil {
					eb.addf(CodeBadDuration, n.Line, n.Column, "timeout",
						"%q must be a duration like 30s, 5m, 1h; got %q", "timeout", v)
				} else if d < 0 {
					eb.addf(CodeBadDuration, n.Line, n.Column, "timeout",
						"%q must be non-negative; got %q", "timeout", v)
				} else {
					m.TimeoutNS = d.Nanoseconds()
				}
			}
		}
	}

	// description (optional, string)
	if n := seen["description"]; n != nil {
		if v, ok := scalarString(eb, n, "description"); ok {
			m.Description = v
		}
	}

	if err := eb.result(); err != nil {
		return nil, err
	}

	// Defaults (only after successful validation).
	if m.WorkingDir == "" {
		m.WorkingDir = "/tmp/agentctl/" + m.Name
	}
	if m.User == "" {
		m.User = strconv.Itoa(os.Getuid())
	}
	if m.Stdin == "" {
		m.Stdin = "close"
	}
	if m.AllowedHosts == nil {
		m.AllowedHosts = []string{}
	}
	if m.AllowedPaths == nil {
		m.AllowedPaths = []string{}
	}
	return m, nil
}

// scalarString unwraps a yaml.ScalarNode value or files a wrong_kind error.
func scalarString(eb *errBuilder, n *yaml.Node, field string) (string, bool) {
	if n.Kind != yaml.ScalarNode {
		eb.addf(CodeWrongKind, n.Line, n.Column, field,
			"field %q must be a string, got %s", field, kindName(n.Kind))
		return "", false
	}
	return n.Value, true
}

// stringSequence unwraps a yaml.SequenceNode of scalar strings.
func stringSequence(eb *errBuilder, n *yaml.Node, field string) ([]string, bool) {
	if n.Kind != yaml.SequenceNode {
		eb.addf(CodeWrongKind, n.Line, n.Column, field,
			"field %q must be a list, got %s", field, kindName(n.Kind))
		return nil, false
	}
	out := make([]string, 0, len(n.Content))
	ok := true
	for i, item := range n.Content {
		if item.Kind != yaml.ScalarNode {
			eb.addf(CodeWrongKind, item.Line, item.Column,
				fmt.Sprintf("%s[%d]", field, i),
				"%s[%d] must be a string, got %s", field, i, kindName(item.Kind))
			ok = false
			continue
		}
		out = append(out, item.Value)
	}
	return out, ok
}

// validateEnv walks an env: mapping, validating ${VAR} resolution.
func validateEnv(eb *errBuilder, n *yaml.Node, dst map[string]string, lookup envLookup) {
	if n.Kind != yaml.MappingNode {
		eb.addf(CodeWrongKind, n.Line, n.Column, "env",
			"field %q must be a mapping, got %s", "env", kindName(n.Kind))
		return
	}
	for i := 0; i < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			eb.addf(CodeWrongKind, k.Line, k.Column, "env."+k.Value,
				"env entries must be string→string scalars")
			continue
		}
		if !validEnvKey(k.Value) {
			eb.addf(CodeBadEnvKey, k.Line, k.Column, "env."+k.Value,
				"env key %q is invalid: must match POSIX portable name [A-Za-z_][A-Za-z0-9_]*",
				k.Value)
			continue
		}
		resolved, err := resolveEnvValue(v.Value, lookup)
		if err != nil {
			eb.add(&Error{
				Code:    CodeUnsetEnvVar,
				Message: fmt.Sprintf("env value %q references unset variable; export it or remove the entry", err.Error()),
				Field:   "env." + k.Value,
				Line:    v.Line,
				Column:  v.Column,
			})
			continue
		}
		dst[k.Value] = resolved
	}
}

// envVarRe and envKeyRe must agree on what names are valid. Earlier the
// substitution regex was uppercase-only while the key validator accepted
// mixed case, so `${lower_case_var}` in a value silently passed through
// as a literal string and the operator's secret never reached the agent.
var envVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validEnvKey enforces the POSIX portable-name regex on env keys.
//
// Without this check, manifests with `env: { "K=V": "x" }` or `env: { "K\nL": "x" }`
// parse cleanly and corrupt the envp passed to execve in the daemon.
func validEnvKey(s string) bool {
	if s == "" {
		return false
	}
	return envKeyRe.MatchString(s)
}

// resolveEnvValue replaces ${VAR} references in s using lookup. If any reference
// is unset, returns an error whose message is the offending `${VAR}` literal.
func resolveEnvValue(s string, lookup envLookup) (string, error) {
	var firstMissing string
	out := envVarRe.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1]
		if v, ok := lookup(name); ok {
			return v
		}
		if firstMissing == "" {
			firstMissing = match
		}
		return match
	})
	if firstMissing != "" {
		return "", &envMissingErr{Var: firstMissing}
	}
	return out, nil
}

type envMissingErr struct{ Var string }

func (e *envMissingErr) Error() string { return e.Var }

// kindName returns a human label for a yaml.Node.Kind.
func kindName(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "list"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "string"
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

// extractYAMLLineCol pulls the first "line N" from a yaml.v3 error string.
// yaml.v3 errors are formatted like "yaml: line 5: ..." or
// "yaml: line 5: column 3: ...". We grep for both.
//
// If neither is present, returns (0, 0).
var (
	yamlLineCol = regexp.MustCompile(`yaml: line (\d+): column (\d+):`)
	yamlLine    = regexp.MustCompile(`yaml: line (\d+):`)
)

func extractYAMLLineCol(s string) (int, int) {
	if m := yamlLineCol.FindStringSubmatch(s); m != nil {
		l, _ := strconv.Atoi(m[1])
		c, _ := strconv.Atoi(m[2])
		return l, c
	}
	if m := yamlLine.FindStringSubmatch(s); m != nil {
		l, _ := strconv.Atoi(m[1])
		return l, 1
	}
	return 0, 0
}

// scrubYAMLError trims yaml.v3's "yaml: line N: " prefix so the message renders
// once (we already include line/col via the Error's Path/Line/Column).
func scrubYAMLError(s string) string {
	s = bytes.NewBufferString(s).String()
	if i := strings.Index(s, ": "); i > 0 && strings.HasPrefix(s, "yaml") {
		// strip up to and including the last "line N: column M: " block
		stripped := yamlLineCol.ReplaceAllString(s, "")
		stripped = yamlLine.ReplaceAllString(stripped, "")
		stripped = strings.TrimPrefix(stripped, "yaml:")
		return strings.TrimSpace(stripped)
	}
	return s
}
