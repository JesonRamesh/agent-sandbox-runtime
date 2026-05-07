package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// DefaultDialTimeout is the per-call deadline for opening the Unix-socket
// connection to the daemon. Single source of truth: the CLI and any other
// in-process consumer should reference this rather than re-defining 5s
// inline. Tweaking the timeout for a CI environment now means changing one
// constant.
const DefaultDialTimeout = 5 * time.Second

// Client talks to a single agentd Unix socket connection.
//
// One Client per CLI invocation. Unary methods open a fresh connection per call
// (since the daemon closes after writing the response). StreamEvents holds the
// connection for the lifetime of the stream.
type Client struct {
	socketPath  string
	dialTimeout time.Duration
}

// DialOption configures a Client.
type DialOption func(*Client)

// WithDialTimeout sets the per-Dial timeout. Default is DefaultDialTimeout.
func WithDialTimeout(d time.Duration) DialOption {
	return func(c *Client) { c.dialTimeout = d }
}

// New constructs a Client. socketPath must be the absolute path to the daemon's
// Unix domain socket; use ResolveSocketPath to compute it.
func New(socketPath string, opts ...DialOption) *Client {
	c := &Client{socketPath: socketPath, dialTimeout: DefaultDialTimeout}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SocketPath returns the configured socket path.
func (c *Client) SocketPath() string { return c.socketPath }

// dial opens a Unix-socket connection and binds it to ctx for cancellation
// during the Dial phase. The returned conn must be Closed by the caller.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: c.dialTimeout}
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		// Wrap with our typed sentinel so callers can errors.Is.
		return nil, fmt.Errorf("%w: %s: %v", ErrDaemonUnreachable, c.socketPath, err)
	}
	return conn, nil
}

// roundTrip performs a single request → response cycle on a fresh connection.
// Used for all unary methods.
func (c *Client) roundTrip(ctx context.Context, method string, params any, out any) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Wire ctx → conn deadline so a cancelled context unblocks the read.
	go contextCloser(ctx, conn)

	if err := writeRequest(conn, method, params); err != nil {
		return fmt.Errorf("write %s: %w", method, err)
	}
	// Half-close write side so the server knows end-of-request. unix-domain
	// sockets via *net.UnixConn support CloseWrite.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	body, err := ReadFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s: daemon closed before response", method)
		}
		return fmt.Errorf("read %s response: %w", method, err)
	}
	var env ResponseEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("decode %s response: %w", method, err)
	}
	if !env.Ok {
		return fromWire(env.Error)
	}
	if out != nil && len(env.Result) > 0 {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return fmt.Errorf("decode %s result: %w", method, err)
		}
	}
	return nil
}

// writeRequest marshals the request envelope and ships one frame.
func writeRequest(w io.Writer, method string, params any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("marshal %s params: %w", method, err)
		}
		raw = b
	} else {
		raw = json.RawMessage(`{}`)
	}
	body, err := json.Marshal(RequestEnvelope{Method: method, Params: raw})
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return WriteFrame(w, body)
}

// contextCloser watches ctx; when it fires, it sets a past read deadline on
// conn so any blocked Read returns immediately. This is how DEC-007 turns
// "Ctrl-C at the user" into "wake up the streaming read".
func contextCloser(ctx context.Context, conn net.Conn) {
	<-ctx.Done()
	_ = conn.SetReadDeadline(time.Unix(1, 0))
	_ = conn.Close()
}

// --- Unary methods ---

// RunAgent submits a manifest to the daemon. Returns the daemon's record once
// the agent has been launched.
func (c *Client) RunAgent(ctx context.Context, req *RunAgentRequest) (*RunAgentResult, error) {
	var out RunAgentResult
	if err := c.roundTrip(ctx, MethodRunAgent, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgents queries the daemon for all known agents.
func (c *Client) ListAgents(ctx context.Context) (*ListAgentsResult, error) {
	var out ListAgentsResult
	if err := c.roundTrip(ctx, MethodListAgents, &ListAgentsRequest{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StopAgent SIGTERM-then-SIGKILLs an agent. graceNS=0 maps to the daemon's
// default grace period (5s); the CLI's stop subcommand passes graceNS explicitly.
func (c *Client) StopAgent(ctx context.Context, name string, graceNS int64) (*StopAgentResult, error) {
	var out StopAgentResult
	req := &StopAgentRequest{Name: name, GracePeriodNS: graceNS}
	if err := c.roundTrip(ctx, MethodStopAgent, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AgentLogs fetches the last `tailN` events from the daemon's per-agent file.
func (c *Client) AgentLogs(ctx context.Context, name string, tailN int) (*AgentLogsResult, error) {
	var out AgentLogsResult
	req := &AgentLogsRequest{Name: name, TailN: tailN}
	if err := c.roundTrip(ctx, MethodAgentLogs, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DaemonStatus probes the daemon for liveness and version.
func (c *Client) DaemonStatus(ctx context.Context) (*DaemonStatusResult, error) {
	var out DaemonStatusResult
	if err := c.roundTrip(ctx, MethodDaemonStatus, &DaemonStatusRequest{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IngestEvent is exposed for completeness; the CLI does not normally invoke it.
func (c *Client) IngestEvent(ctx context.Context, req *IngestEventRequest) error {
	return c.roundTrip(ctx, MethodIngestEvent, req, nil)
}

// --- Streaming method ---

// EventStream wraps an open StreamEvents subscription.
//
// Read events from Events; when it closes, drain Errors for any read error
// (nil if the stream ended normally via EOF).
type EventStream struct {
	Events <-chan Event
	Errors <-chan error

	cancel context.CancelFunc
	conn   net.Conn
	wg     sync.WaitGroup
}

// Close terminates the stream by closing the connection. Blocks until the
// reader goroutine drains.
func (s *EventStream) Close() error {
	s.cancel()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.wg.Wait()
	return nil
}

// StreamEvents opens a persistent subscription. The returned EventStream's
// Events channel emits per-event frames; Errors emits at most one error and
// then closes. Both channels close when the stream terminates.
//
// Cancel by either calling EventStream.Close() or by cancelling ctx.
func (c *Client) StreamEvents(ctx context.Context, req *StreamEventsRequest) (*EventStream, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeRequest(conn, MethodStreamEvents, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write StreamEvents: %w", err)
	}
	// Note: do NOT half-close the write side; the server may keep writing
	// indefinitely (INTERFACES §2.6 + DEC-011).

	streamCtx, cancel := context.WithCancel(ctx)
	go contextCloser(streamCtx, conn)

	events := make(chan Event, 256)
	errs := make(chan error, 1)
	stream := &EventStream{Events: events, Errors: errs, cancel: cancel, conn: conn}
	stream.wg.Add(1)

	go func() {
		defer stream.wg.Done()
		defer close(events)
		defer close(errs)
		for {
			body, err := ReadFrame(conn)
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					// Normal termination: the server closed.
					return
				}
				if isDeadlineError(err) {
					// Cancelled by ctx (we set a past deadline). Quiet exit.
					return
				}
				errs <- fmt.Errorf("read stream frame: %w", err)
				return
			}
			var env ResponseEnvelope
			if err := json.Unmarshal(body, &env); err != nil {
				errs <- fmt.Errorf("decode stream envelope: %w", err)
				return
			}
			if !env.Ok {
				errs <- fromWire(env.Error)
				return
			}
			var f StreamEventsFrame
			if err := json.Unmarshal(env.Result, &f); err != nil {
				errs <- fmt.Errorf("decode stream event: %w", err)
				return
			}
			select {
			case events <- f.Event:
			case <-streamCtx.Done():
				return
			}
		}
	}()

	return stream, nil
}

// isDeadlineError checks for the timeout-style error that comes back when a
// past deadline interrupts a Read (used by contextCloser cancellation).
func isDeadlineError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return false
}
