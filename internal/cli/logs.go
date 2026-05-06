package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/agent-sandbox/runtime/internal/client"
	"github.com/agent-sandbox/runtime/internal/render"
)

func newLogsCmd() *cobra.Command {
	var (
		follow  bool
		tail    int
		include []string
	)
	cmd := &cobra.Command{
		Use:   "logs <name>",
		Short: "Print or follow events from a sandboxed agent",
		Long: "Without --follow, prints the last --tail events. With --follow, opens a " +
			"persistent subscription and streams events until the agent exits or " +
			"the user presses Ctrl-C. Cancellation is observed in well under 100ms.",
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			rt := appRuntimeFrom(c.Context())
			name := args[0]
			if name == "" {
				return UsageError(fmt.Errorf("agent name required"))
			}
			if follow && c.Flags().Changed("tail") {
				return UsageError(fmt.Errorf("--follow and --tail are mutually exclusive"))
			}
			if !follow && len(include) > 0 {
				// Daemon-side filtering for AgentLogs is not on the wire; --include
				// only flows through StreamEvents. Reject so the apparent filter
				// doesn't silently fetch and discard.
				return UsageError(fmt.Errorf("--include requires --follow"))
			}
			// Validate --tail before opening an IPC connection. Bad input is a
			// usage error and shouldn't burn a daemon dial.
			if !follow && tail < 0 {
				return UsageError(fmt.Errorf("--tail must be >= 0"))
			}

			cl := rt.newClient()
			if !follow {
				return runLogsTail(c.Context(), rt, cl, name, tail, include)
			}
			return runLogsFollow(c.Context(), rt, cl, name, include)
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "stream events as they arrive")
	cmd.Flags().IntVar(&tail, "tail", 100, "number of historical events to fetch when not following")
	cmd.Flags().StringSliceVar(&include, "include", nil, "comma-separated list of categories to include (default: all; requires --follow)")
	return cmd
}

func runLogsTail(ctx context.Context, rt *appRuntime, cl *client.Client, name string, tail int, include []string) error {
	res, err := cl.AgentLogs(ctx, name, tail)
	if err != nil {
		return renderDaemonErr(rt, err)
	}
	for i := range res.Events {
		ev := &res.Events[i]
		if !categoryAllowed(ev.Category, include) {
			continue
		}
		emitEvent(rt, ev)
	}
	return nil
}

func runLogsFollow(ctx context.Context, rt *appRuntime, cl *client.Client, name string, include []string) error {
	stream, err := cl.StreamEvents(ctx, &client.StreamEventsRequest{Name: name, Include: include})
	if err != nil {
		return renderDaemonErr(rt, err)
	}
	defer stream.Close()

	for {
		select {
		case ev, ok := <-stream.Events:
			if !ok {
				// Drain Errors before returning.
				select {
				case e := <-stream.Errors:
					if e != nil {
						return renderDaemonErr(rt, e)
					}
				default:
				}
				return nil
			}
			if !categoryAllowed(ev.Category, include) {
				continue
			}
			emitEvent(rt, &ev)
		case e := <-stream.Errors:
			if e != nil {
				return renderDaemonErr(rt, e)
			}
		case <-ctx.Done():
			// signal-driven cancel; return ErrInterrupted so MapExitCode → 130.
			return ErrInterrupted
		}
	}
}

func emitEvent(rt *appRuntime, ev *client.Event) {
	if rt.JSON {
		_ = render.JSON(rt.Stdout, ev)
		return
	}
	render.HumanEvent(rt.Stdout, ev)
}

func categoryAllowed(category string, include []string) bool {
	if len(include) == 0 {
		return true
	}
	for _, want := range include {
		if want == category {
			return true
		}
	}
	return false
}
