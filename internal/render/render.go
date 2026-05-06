// Package render formats CLI output. Two modes:
//
//   - Human (default): tab-aligned tables, colourless, designed to be diff-able.
//   - JSON (--json): newline-delimited JSON objects, one per logical row.
//
// All public functions take an io.Writer so tests can capture output cleanly.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/agent-sandbox/runtime/internal/client"
)

// JSON marshals v as one line of JSON to w followed by a newline. Used by all
// subcommands when --json is set.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// HumanRunResult prints the post-run summary used by `agentctl run`.
//
//	Started agent-x  pid=4242  cgroup=/sys/fs/cgroup/agent/agent-x
//	policy: hosts:1 paths:0 timeout:0
func HumanRunResult(w io.Writer, r *client.RunAgentResult) {
	fmt.Fprintf(w, "Started %s  pid=%d  cgroup=%s\n", r.Name, r.PID, r.CgroupPath)
	if r.PolicySummary != "" {
		fmt.Fprintf(w, "policy: %s\n", r.PolicySummary)
	}
}

// HumanStopResult prints the summary used by `agentctl stop`.
func HumanStopResult(w io.Writer, r *client.StopAgentResult) {
	dur := time.Duration(r.DurationNS).Round(time.Millisecond)
	fmt.Fprintf(w, "Stopped %s  signal=%s  exit=%d  in=%s\n", r.Name, r.Signal, r.ExitCode, dur)
}

// HumanList prints `agentctl list` rows in a tab-aligned table.
//
//	NAME      ID      STATUS   PID    UPTIME    POLICY
//	agent-x   01H8X0  running  4242   3m12s     hosts:1 paths:0 timeout:0
//	gone      01F00B  exited   -      -         hosts:0 paths:1 timeout:30s   exit=0
func HumanList(w io.Writer, agents []client.AgentInfo) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintln(tw, "NAME\tID\tSTATUS\tPID\tUPTIME\tPOLICY")
	for _, a := range agents {
		pid := "-"
		if a.PID > 0 {
			pid = fmt.Sprintf("%d", a.PID)
		}
		uptime := "-"
		if a.UptimeNS > 0 {
			uptime = compactDuration(time.Duration(a.UptimeNS))
		}
		policy := a.PolicySummary
		if a.Status != "running" && a.ExitCode != nil {
			policy = fmt.Sprintf("%s\texit=%d", policy, *a.ExitCode)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			a.Name, a.AgentID, a.Status, pid, uptime, policy)
	}
}

// HumanDaemonStatus prints `agentctl daemon status`.
func HumanDaemonStatus(w io.Writer, s *client.DaemonStatusResult) {
	uptime := compactDuration(time.Duration(s.UptimeNS))
	fmt.Fprintf(w, "protocol: %s\nbuild: %s\nuptime: %s\nagents: %d\n",
		s.ProtocolVersion, s.Build, uptime, s.AgentsRunning)
	if s.EventsDropped > 0 {
		fmt.Fprintf(w, "events_dropped: %d  (audit trail has gaps — pipeline buffer overflowed)\n", s.EventsDropped)
	}
}

func compactDuration(d time.Duration) string {
	if d < time.Second {
		return d.String()
	}
	d = d.Round(time.Second)
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}

// JSONErr renders a wire-shaped error envelope (for `--json` failure output).
func JSONErr(w io.Writer, code, message string) error {
	return JSON(w, struct {
		Ok    bool   `json:"ok"`
		Code  string `json:"code"`
		Error string `json:"error"`
	}{Ok: false, Code: code, Error: message})
}

// quote wraps s in double quotes if it contains whitespace, a quote, or any
// C0 control byte. Event payloads originate from agent stdout / LLM tool
// output / (when authenticated relays are off) the network — none of which
// is trusted to be free of ANSI terminal escapes. strconv.Quote turns every
// non-printable byte into its \xNN form so a raw "\x1b[2J" cannot clear the
// operator's terminal.
func quote(s string) string {
	if hasControl(s) {
		return strconv.Quote(s)
	}
	if strings.ContainsAny(s, " \t\"") {
		b, _ := json.Marshal(s)
		return string(b)
	}
	return s
}

// hasControl reports whether s contains any C0 control byte (0x00–0x1F) or
// DEL (0x7F). Newline and tab are deliberately included — quote() needs to
// escape them too when they appear in an otherwise printable string, since
// the existing whitespace branch would lose the literal.
func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7F {
			return true
		}
	}
	return false
}
