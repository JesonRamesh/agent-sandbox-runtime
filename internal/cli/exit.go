package cli

import (
	"errors"

	"github.com/agent-sandbox/runtime/internal/client"
	"github.com/agent-sandbox/runtime/internal/manifest"
	"github.com/agent-sandbox/runtime/internal/render"
)

// Exit codes (DEC-009).
const (
	ExitOK                = 0
	ExitGenericError      = 1
	ExitUsageError        = 2
	ExitManifestInvalid   = 3
	ExitDaemonUnreachable = 4
	ExitDaemonError       = 5
	ExitAgentNotFound     = 6
	ExitInterrupted       = 130
)

// printedErr wraps an error that has already been rendered to stderr/stdout.
// The main entry point checks this so it doesn't double-print.
type printedErr struct{ err error }

func (p *printedErr) Error() string { return p.err.Error() }
func (p *printedErr) Unwrap() error { return p.err }

// AlreadyPrinted marks an error as having been printed already.
func AlreadyPrinted(err error) error {
	if err == nil {
		return nil
	}
	return &printedErr{err: err}
}

// ErrorAlreadyPrinted reports whether err was wrapped with AlreadyPrinted.
func ErrorAlreadyPrinted(err error) bool {
	var p *printedErr
	return errors.As(err, &p)
}

// usageErr signals a usage / argument-shape error (cobra default exits 2).
type usageErr struct{ err error }

func (u *usageErr) Error() string { return u.err.Error() }
func (u *usageErr) Unwrap() error { return u.err }

// UsageError tags an error as a usage error so MapExitCode returns 2.
func UsageError(err error) error { return &usageErr{err: err} }

// MapExitCode translates an error returned from a cobra Execute into a CLI exit code.
func MapExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	if errors.Is(err, ErrInterrupted) {
		return ExitInterrupted
	}
	var ue *usageErr
	if errors.As(err, &ue) {
		return ExitUsageError
	}
	var me *manifest.Error
	if errors.As(err, &me) {
		return ExitManifestInvalid
	}
	if errors.Is(err, client.ErrDaemonUnreachable) {
		return ExitDaemonUnreachable
	}
	if errors.Is(err, client.ErrAgentNotFound) {
		return ExitAgentNotFound
	}
	var de *client.ServerError
	if errors.As(err, &de) {
		if de.Code == client.CodeAgentNotFound {
			return ExitAgentNotFound
		}
		if de.Code == client.CodeInvalidManifest {
			return ExitManifestInvalid
		}
		return ExitDaemonError
	}
	return ExitGenericError
}

// ErrInterrupted is returned when execution is cancelled by SIGINT/SIGTERM.
var ErrInterrupted = errors.New("interrupted")

// renderDaemonErr routes daemon-side errors through the JSON envelope when
// rt.JSON is set, emitting to stdout (per ASSUMPTIONS.md) and tagging the
// error as already-printed so Main skips its "Error: ..." prefix on stderr.
//
// Non-daemon errors (and human-mode invocations) are returned unchanged so the
// caller's existing error path stays intact. Pass any error here at each
// subcommand's daemon-call boundary; usage errors and manifest validation
// errors are routed elsewhere.
func renderDaemonErr(rt *appRuntime, err error) error {
	if err == nil {
		return nil
	}
	if !rt.JSON {
		return err
	}
	code, msg, ok := classifyDaemonErr(err)
	if !ok {
		return err
	}
	_ = render.JSONErr(rt.Stdout, code, msg)
	return AlreadyPrinted(err)
}

// classifyDaemonErr returns the wire code, message, and a bool indicating
// whether err is a recognised daemon-side error.
func classifyDaemonErr(err error) (code, message string, ok bool) {
	var se *client.ServerError
	if errors.As(err, &se) {
		return se.Code, se.Message, true
	}
	if errors.Is(err, client.ErrDaemonUnreachable) {
		return client.CodeDaemonUnreachable, err.Error(), true
	}
	if errors.Is(err, client.ErrAgentNotFound) {
		return client.CodeAgentNotFound, err.Error(), true
	}
	return "", "", false
}
