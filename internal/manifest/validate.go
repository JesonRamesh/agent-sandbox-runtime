package manifest

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var nameRe = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// validateName checks the DNS-label compatibility rule.
func validateName(eb *errBuilder, n *yaml.Node, v string) {
	if !nameRe.MatchString(v) {
		eb.addf(CodeInvalidName, n.Line, n.Column, "name",
			"name %q is invalid: must match [a-z0-9-]{1,63}", v)
	}
}

// validateHosts validates each entry in allowed_hosts against the v1 host
// pattern grammar (INTERFACES §1.3):
//
//   - hostname literal: api.openai.com
//   - wildcard left-most label: *.openai.com
//   - IP literal: 203.0.113.5 / 2001:db8::1
//   - CIDR: 10.0.0.0/8 / 2001:db8::/32
//   - any of the above with optional :port suffix.
func validateHosts(eb *errBuilder, n *yaml.Node, hosts []string) {
	for i, h := range hosts {
		if !validHostPattern(h) {
			line, col := childLineCol(n, i)
			eb.addf(CodeInvalidHostPattern, line, col,
				fmt.Sprintf("allowed_hosts[%d]", i),
				"%q is not a valid host pattern; expected hostname (api.example.com), IP, or wildcard (*.example.com), optionally with :port",
				h)
		}
	}
}

// validHostPattern returns true if h matches the v1 host pattern grammar.
func validHostPattern(h string) bool {
	if h == "" {
		return false
	}
	host, port, hasPort := splitHostPort(h)
	if hasPort {
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			return false
		}
	}
	return validHostBody(host)
}

// validHostBody checks the host portion (without :port). Order matters:
// CIDR check must precede IP check (IP literal can be a CIDR's prefix).
func validHostBody(s string) bool {
	if s == "" {
		return false
	}
	// CIDR (with /N).
	if strings.Contains(s, "/") {
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			return false
		}
		// ParseCIDR also rejects /33 (etc.) and host-bits-set automatically:
		// the canonical form must equal the input's masked address.
		// Verify host bits are zero by comparing the parsed network to the input IP.
		ipPart := strings.SplitN(s, "/", 2)[0]
		ip := net.ParseIP(ipPart)
		if ip == nil {
			return false
		}
		// Compare masked vs raw: host bits set ⇒ they differ.
		masked := ip.Mask(ipnet.Mask)
		if !masked.Equal(ip) {
			return false
		}
		return true
	}
	// Plain IP.
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	// Wildcard left-most label: *.<rest>
	if strings.HasPrefix(s, "*.") {
		return validHostnameLiteral(s[2:])
	}
	// Hostname literal.
	return validHostnameLiteral(s)
}

var hostnameLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validHostnameLiteral checks RFC 1123-ish hostname syntax.
func validHostnameLiteral(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !hostnameLabelRe.MatchString(label) {
			return false
		}
	}
	return true
}

// splitHostPort splits "<host>:<port>" while tolerating IPv6 literals (which
// must be wrapped in [] when a port is present).
func splitHostPort(s string) (host, port string, hasPort bool) {
	// Bracketed IPv6 with port: [::1]:443
	if strings.HasPrefix(s, "[") {
		closeIdx := strings.Index(s, "]")
		if closeIdx == -1 {
			return s, "", false
		}
		host = s[1:closeIdx]
		rest := s[closeIdx+1:]
		if strings.HasPrefix(rest, ":") {
			return host, rest[1:], true
		}
		return host, "", false
	}
	// IPv6 literal without brackets and without port (contains multiple ':').
	if strings.Count(s, ":") > 1 {
		return s, "", false
	}
	if i := strings.LastIndex(s, ":"); i != -1 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// validatePaths checks each entry in allowed_paths against the v1 grammar
// (INTERFACES §1.3): absolute path, optionally trailing-slash directory, or a
// path containing exactly one '*' glob (no '**', '?', or character classes).
func validatePaths(eb *errBuilder, n *yaml.Node, paths []string) {
	for i, p := range paths {
		if !validPathPattern(p) {
			line, col := childLineCol(n, i)
			eb.addf(CodeInvalidPathPattern, line, col,
				fmt.Sprintf("allowed_paths[%d]", i),
				"%q is not a valid path pattern; expected absolute path, '/dir/' for tree, or single '*' glob",
				p)
		}
	}
}

// validPathPattern enforces the v1 grammar:
//
//   - must be absolute (start with '/')
//   - no embedded NUL/LF/CR/TAB (BPF allowlist key behaviour with these is
//     kernel-implementation-defined; reject up front)
//   - no '**', '?', '[', ']'
//   - at most one '*' wildcard
func validPathPattern(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.ContainsAny(p, "\x00\n\r\t") {
		return false
	}
	if strings.Contains(p, "**") {
		return false
	}
	if strings.ContainsAny(p, "?[]") {
		return false
	}
	if strings.Count(p, "*") > 1 {
		return false
	}
	return true
}

// validUser accepts a numeric uid (>= 0, <= MaxInt32) or a non-empty
// username/groupname-style string. We don't verify the uid exists at validation
// time — that's a daemon concern (the daemon resolves via NSS at clone3 time).
// We just check shape and reject negatives so users get a useful error before
// the kernel rejects setuid(-1).
func validUser(s string) bool {
	if s == "" {
		return false
	}
	if uid, err := strconv.Atoi(s); err == nil {
		return uid >= 0 && uid <= 2147483647
	}
	return regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`).MatchString(s)
}

// validMode accepts the two enforcement modes the daemon understands. Empty
// is allowed at parse time and means "let the daemon apply its default"
// (enforce).
func validMode(s string) bool {
	return s == "" || s == "audit" || s == "enforce"
}

// validateAllowedBins checks every entry is an absolute path with no NUL or
// newline characters. Path-prefix semantics are documented in
// bpf/exec.bpf.c: a binary is allowed if its filename has any allowed_bins
// entry as a prefix.
func validateAllowedBins(eb *errBuilder, n *yaml.Node, bins []string) {
	for i, b := range bins {
		line, col := childLineCol(n, i)
		if b == "" {
			eb.addf(CodeNonAbsolutePath, line, col, fmt.Sprintf("allowed_bins[%d]", i),
				"allowed_bins entries must not be empty")
			continue
		}
		if !strings.HasPrefix(b, "/") {
			eb.addf(CodeNonAbsolutePath, line, col, fmt.Sprintf("allowed_bins[%d]", i),
				"allowed_bins entries must be absolute paths; got %q", b)
			continue
		}
		if strings.ContainsAny(b, "\x00\n\r") {
			eb.addf(CodeInvalidPathPattern, line, col, fmt.Sprintf("allowed_bins[%d]", i),
				"allowed_bins entries must not contain control characters; got %q", b)
		}
	}
}

// knownCapabilities is the closed set of Linux capability names the daemon
// understands (see daemon/internal/policy.ForbiddenCapsMask). Anything else
// is rejected at validation time so a typo like "CAP_SYS_ADIM" doesn't
// silently shrink the deny list.
var knownCapabilities = map[string]struct{}{
	"CAP_AUDIT_CONTROL": {}, "CAP_AUDIT_READ": {}, "CAP_AUDIT_WRITE": {},
	"CAP_BLOCK_SUSPEND": {}, "CAP_BPF": {}, "CAP_CHECKPOINT_RESTORE": {},
	"CAP_CHOWN": {}, "CAP_DAC_OVERRIDE": {}, "CAP_DAC_READ_SEARCH": {},
	"CAP_FOWNER": {}, "CAP_FSETID": {}, "CAP_IPC_LOCK": {},
	"CAP_IPC_OWNER": {}, "CAP_KILL": {}, "CAP_LEASE": {},
	"CAP_LINUX_IMMUTABLE": {}, "CAP_MAC_ADMIN": {}, "CAP_MAC_OVERRIDE": {},
	"CAP_MKNOD": {}, "CAP_NET_ADMIN": {}, "CAP_NET_BIND_SERVICE": {},
	"CAP_NET_BROADCAST": {}, "CAP_NET_RAW": {}, "CAP_PERFMON": {},
	"CAP_SETGID": {}, "CAP_SETFCAP": {}, "CAP_SETPCAP": {},
	"CAP_SETUID": {}, "CAP_SYS_ADMIN": {}, "CAP_SYS_BOOT": {},
	"CAP_SYS_CHROOT": {}, "CAP_SYS_MODULE": {}, "CAP_SYS_NICE": {},
	"CAP_SYS_PACCT": {}, "CAP_SYS_PTRACE": {}, "CAP_SYS_RAWIO": {},
	"CAP_SYS_RESOURCE": {}, "CAP_SYS_TIME": {}, "CAP_SYS_TTY_CONFIG": {},
	"CAP_SYSLOG": {}, "CAP_WAKE_ALARM": {},
}

// validateForbiddenCaps rejects entries that aren't a known capability name.
// We use a strict closed set so a typo can't silently disable a deny rule.
// On unknown names we run a Levenshtein suggest against the closed set so
// "CAP_SYS_ADIM" hints at "CAP_SYS_ADMIN" rather than dead-ending.
func validateForbiddenCaps(eb *errBuilder, n *yaml.Node, caps []string) {
	for i, c := range caps {
		line, col := childLineCol(n, i)
		if _, ok := knownCapabilities[c]; ok {
			continue
		}
		msg := fmt.Sprintf("unknown capability %q (expected one of CAP_*; see capabilities(7))", c)
		if hint := suggestCapability(c); hint != "" {
			msg = fmt.Sprintf("%s; did you mean %q?", msg, hint)
		}
		eb.addf(CodeBadCapability, line, col, fmt.Sprintf("forbidden_caps[%d]", i), "%s", msg)
	}
}

// suggestCapability returns the closest known CAP_ name within edit distance 2
// of input, or "" if nothing is close enough. Uppercases the input first so
// "cap_sys_adim" still suggests "CAP_SYS_ADMIN".
func suggestCapability(input string) string {
	if input == "" {
		return ""
	}
	candidates := make([]string, 0, len(knownCapabilities))
	for k := range knownCapabilities {
		candidates = append(candidates, k)
	}
	matches := Suggest(strings.ToUpper(input), candidates, 2)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// workingDirError is the typed error returned by validWorkingDir so the
// caller can route to the right error code without re-deriving it.
type workingDirError struct {
	code Code
	msg  string
}

// sensitiveWorkingDirPrefixes blocks manifests from steering the daemon's
// chdir / MkdirAll into system directories. Even with restrictive
// permissions a typo here is a foot-gun; the daemon runs with
// CAP_SYS_ADMIN so MkdirAll can land places the operator did not intend.
var sensitiveWorkingDirPrefixes = []string{
	"/etc/", "/proc/", "/sys/", "/dev/", "/boot/", "/root/",
	"/usr/", "/lib/", "/lib64/", "/sbin/", "/bin/",
}

// validWorkingDir checks that v is an absolute, normalized path with no
// traversal segments and not a system directory. The daemon AND the CLI
// both pre-create this directory; an unvalidated path turns into a
// silent MkdirAll on whatever traversal resolves to.
func validWorkingDir(v string) *workingDirError {
	if !strings.HasPrefix(v, "/") {
		return &workingDirError{
			code: CodeNonAbsolutePath,
			msg:  fmt.Sprintf("%q must be an absolute path; got %q", "working_dir", v),
		}
	}
	if strings.ContainsAny(v, "\x00\n\r\t") {
		return &workingDirError{
			code: CodeInvalidPathPattern,
			msg:  fmt.Sprintf("%q must not contain control characters; got %q", "working_dir", v),
		}
	}
	cleaned := filepath.Clean(v)
	if cleaned != v && cleaned+"/" != v {
		return &workingDirError{
			code: CodeInvalidPathPattern,
			msg:  fmt.Sprintf("%q must be a normalized path; got %q (canonical form: %q)", "working_dir", v, cleaned),
		}
	}
	if strings.Contains(v, "/../") || strings.HasSuffix(v, "/..") {
		return &workingDirError{
			code: CodeInvalidPathPattern,
			msg:  fmt.Sprintf("%q must not contain '..' segments; got %q", "working_dir", v),
		}
	}
	for _, prefix := range sensitiveWorkingDirPrefixes {
		if strings.HasPrefix(cleaned+"/", prefix) {
			return &workingDirError{
				code: CodeInvalidPathPattern,
				msg:  fmt.Sprintf("%q must not point inside system directory %q; got %q", "working_dir", strings.TrimSuffix(prefix, "/"), v),
			}
		}
	}
	return nil
}

// validStdin accepts "inherit", "close", or "file:<abs-path>". The file:
// variant rejects embedded NUL/LF/CR/TAB so the path can't smuggle control
// characters into the daemon's open(2) call.
func validStdin(s string) bool {
	if s == "inherit" || s == "close" {
		return true
	}
	if strings.HasPrefix(s, "file:") && strings.HasPrefix(s[5:], "/") {
		if strings.ContainsAny(s[5:], "\x00\n\r\t") {
			return false
		}
		return true
	}
	return false
}

// childLineCol returns the line/col of the i'th child in a yaml.SequenceNode,
// falling back to the sequence's own line/col if the index is out of range.
func childLineCol(n *yaml.Node, i int) (int, int) {
	if n == nil {
		return 0, 0
	}
	if i >= 0 && i < len(n.Content) {
		c := n.Content[i]
		return c.Line, c.Column
	}
	return n.Line, n.Column
}
