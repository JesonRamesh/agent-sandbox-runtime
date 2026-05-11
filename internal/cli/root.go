// Package cli wires the cobra command tree for `agentctl`. Each subcommand
// lives in its own file (run.go, list.go, stop.go, ...). The root command
// holds the persistent flags (--socket, --json, --verbose) and exposes them
// via a small `appRuntime` value passed down through cobra's context.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/agent-sandbox/runtime/internal/client"
)

// dialTimeout is the single CLI-side default for socket dials. We use the
// client package's exported value so tweaking it for a slow CI environment
// only requires editing one place.
var dialTimeout = client.DefaultDialTimeout

// Build is overridden at link time via -ldflags="-X .../internal/cli.Build=...".
var Build = "dev"

// appRuntimeKey is the context.Context key that carries the per-invocation
// resolved settings (socket, json mode, verbosity, IO writers).
type appRuntimeKey struct{}

// appRuntime carries CLI-level configuration shared across subcommands.
type appRuntime struct {
	Socket  string
	JSON    bool
	Verbose bool
	Stdout  io.Writer
	Stderr  io.Writer
	// DialTimeout is overridable in tests.
	DialTimeout time.Duration
}

// withRuntime stores rt in the cobra command's context.
func withRuntime(ctx context.Context, rt *appRuntime) context.Context {
	return context.WithValue(ctx, appRuntimeKey{}, rt)
}

// appRuntimeFrom fetches the *appRuntime injected by the root command.
func appRuntimeFrom(ctx context.Context) *appRuntime {
	if rt, ok := ctx.Value(appRuntimeKey{}).(*appRuntime); ok {
		return rt
	}
	// Fallback for direct subcommand invocations in tests.
	return &appRuntime{Stdout: os.Stdout, Stderr: os.Stderr, DialTimeout: dialTimeout}
}

// newClient builds a client.Client from the appRuntime, resolving the socket
// path via discovery if --socket was empty.
func (rt *appRuntime) newClient() *client.Client {
	sock := rt.Socket
	if sock == "" {
		sock = client.ResolveSocketPath("")
	}
	return client.New(sock, client.WithDialTimeout(rt.DialTimeout))
}

// NewRoot constructs the top-level `agentctl` command.
func NewRoot() *cobra.Command {
	rt := &appRuntime{
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		DialTimeout: dialTimeout,
	}
	cmd := &cobra.Command{
		Use:           "agentctl",
		Short:         "Sandbox agents with manifest-driven kernel-enforced policy",
		Long:          "agentctl is the user-facing CLI for the agent-sandbox runtime. It validates manifests, talks to the agentd daemon over a Unix socket, and renders agent state and events.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Build,
	}
	cmd.PersistentFlags().StringVar(&rt.Socket, "socket", "", "path to the agentd Unix socket (overrides AGENT_SANDBOX_SOCKET)")
	cmd.PersistentFlags().BoolVar(&rt.JSON, "json", false, "emit machine-readable JSON output")
	cmd.PersistentFlags().BoolVar(&rt.Verbose, "verbose", false, "emit verbose human-facing diagnostics")

	cmd.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		c.SetContext(withRuntime(c.Context(), rt))
		c.SetOut(rt.Stdout)
		c.SetErr(rt.Stderr)
		return nil
	}

	cmd.AddCommand(
		newRunCmd(),
		newListCmd(),
		newStopCmd(),
		newLogsCmd(),
		newDaemonCmd(),
		newManifestCmd(),
		newCompletionCmd(),
		newVersionCmd(),
	)
	return cmd
}

// printlnIf prints to w when verbose is on. Helper avoids littering subcommands
// with `if rt.Verbose { ... }` blocks.
func (rt *appRuntime) printlnIf(format string, args ...any) {
	if !rt.Verbose {
		return
	}
	fmt.Fprintf(rt.Stderr, format+"\n", args...)
}
