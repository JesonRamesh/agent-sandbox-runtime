package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/agent-sandbox/runtime/internal/client"
	"github.com/agent-sandbox/runtime/internal/manifest"
	"github.com/agent-sandbox/runtime/internal/render"
)

func newRunCmd() *cobra.Command {
	var (
		manifestPath   string
		restartOnCrash bool
		maxRestarts    int
	)
	cmd := &cobra.Command{
		Use:   "run [-f manifest.yaml]",
		Short: "Validate a manifest and ask the daemon to spawn a sandboxed agent",
		Long: "Reads a manifest YAML, validates it against the v1 schema with " +
			"line/column-precise errors, and submits it to the daemon. The daemon " +
			"applies cgroup, BPF, and namespace policy and execs the configured " +
			"command.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			rt := appRuntimeFrom(c.Context())
			if manifestPath == "" {
				return UsageError(fmt.Errorf("missing --file/-f manifest path"))
			}
			abs, err := filepath.Abs(manifestPath)
			if err != nil {
				return fmt.Errorf("resolve manifest path: %w", err)
			}

			data, err := os.ReadFile(abs)
			if err != nil {
				return fmt.Errorf("read manifest: %w", err)
			}
			m, err := manifest.ParseBytes(abs, data)
			if err != nil {
				return printManifestError(rt, err)
			}

			payload := manifestToPayload(m)

			// The daemon will chdir into payload.WorkingDir before exec(); if the
			// directory doesn't exist clone3() returns ENOENT and Go's os/exec
			// surfaces that as a misleading "fork/exec <cmd>: no such file or
			// directory". Pre-create it here so the manifest's default of
			// /tmp/agentctl/<name> Just Works. Failure is non-fatal — the daemon
			// will still report a clean error if it really can't chdir.
			if payload.WorkingDir != "" {
				_ = os.MkdirAll(payload.WorkingDir, 0o755)
			}

			source := client.ManifestSource{Path: abs, SHA256: sha256Hex(data)}
			req := &client.RunAgentRequest{
				Manifest:       payload,
				ManifestSource: source,
				RestartOnCrash: restartOnCrash,
				MaxRestarts:    maxRestarts,
			}

			rt.printlnIf("submitting manifest %q to daemon at %s", abs, client.ResolveSocketPath(rt.Socket))
			cl := rt.newClient()
			res, err := cl.RunAgent(c.Context(), req)
			if err != nil {
				return renderDaemonErr(rt, err)
			}

			if rt.JSON {
				return render.JSON(rt.Stdout, res)
			}
			render.HumanRunResult(rt.Stdout, res)
			return nil
		},
	}
	cmd.Flags().StringVarP(&manifestPath, "file", "f", "", "manifest YAML path (required)")
	cmd.Flags().BoolVar(&restartOnCrash, "restart-on-crash", false, "ask the daemon to relaunch this agent if it exits non-zero")
	cmd.Flags().IntVar(&maxRestarts, "max-restarts", 0, "cap on restart-on-crash relaunches (0 = no cap)")
	return cmd
}

// manifestToPayload converts the parsed manifest into the wire shape expected
// by the daemon. The two structs share field tags but live in different
// packages so we copy explicitly.
func manifestToPayload(m *manifest.Manifest) client.ManifestPayload {
	return client.ManifestPayload{
		Name:                m.Name,
		Command:             m.Command,
		Mode:                m.Mode,
		AllowedHosts:        m.AllowedHosts,
		AllowedPaths:        m.AllowedPaths,
		AllowedBins:         m.AllowedBins,
		ForbiddenCaps:       m.ForbiddenCaps,
		DenyCleartextEgress: m.DenyCleartextEgress,
		WorkingDir:          m.WorkingDir,
		Env:                 m.Env,
		User:                m.User,
		Stdin:               m.Stdin,
		TimeoutNS:           m.TimeoutNS,
		Description:         m.Description,
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// printManifestError renders a manifest validation error in human or JSON mode
// then returns AlreadyPrinted so main.go skips its default "Error: ..." prefix.
func printManifestError(rt *appRuntime, err error) error {
	if rt.JSON {
		// Emit a JSON envelope listing every offending field with code/line/col.
		// Stdout per ASSUMPTIONS.md so callers can pipe into jq.
		payload := manifestErrorJSON(err)
		_ = render.JSON(rt.Stdout, payload)
		return AlreadyPrinted(err)
	}
	switch v := err.(type) {
	case *manifest.MultiError:
		for _, e := range v.Errors {
			fmt.Fprintln(rt.Stderr, e.Error())
		}
	default:
		fmt.Fprintln(rt.Stderr, err.Error())
	}
	return AlreadyPrinted(err)
}

func manifestErrorJSON(err error) any {
	type entry struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		Field      string `json:"field,omitempty"`
		Path       string `json:"path,omitempty"`
		Line       int    `json:"line,omitempty"`
		Column     int    `json:"column,omitempty"`
		Suggestion string `json:"suggestion,omitempty"`
	}
	conv := func(e *manifest.Error) entry {
		return entry{
			Code:       string(e.Code),
			Message:    e.Message,
			Field:      e.Field,
			Path:       e.Path,
			Line:       e.Line,
			Column:     e.Column,
			Suggestion: e.Suggestion,
		}
	}
	switch v := err.(type) {
	case *manifest.MultiError:
		out := struct {
			Ok     bool    `json:"ok"`
			Errors []entry `json:"errors"`
		}{Ok: false}
		for _, e := range v.Errors {
			out.Errors = append(out.Errors, conv(e))
		}
		return out
	case *manifest.Error:
		return struct {
			Ok    bool  `json:"ok"`
			Error entry `json:"error"`
		}{Ok: false, Error: conv(v)}
	default:
		return struct {
			Ok    bool   `json:"ok"`
			Error string `json:"error"`
		}{Ok: false, Error: err.Error()}
	}
}
