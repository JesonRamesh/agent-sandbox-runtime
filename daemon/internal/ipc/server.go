package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// DefaultSocketPath is the on-disk address for the daemon socket. Brief §4
// pins this; only override in tests.
const DefaultSocketPath = "/run/agent-sandbox.sock"

// Handler is the business-logic interface the IPC server dispatches to.
// Implementations live elsewhere (Phase 3 wires registry+cgroup+bpf into
// this); the IPC layer owns wire framing and dispatch only.
type Handler interface {
	RunAgent(ctx context.Context, m Manifest) (string, error)
	StopAgent(ctx context.Context, agentID string) error
	ListAgents(ctx context.Context) ([]AgentSummary, error)
	AgentLogs(ctx context.Context, agentID string, tailN int) ([]Event, error)
	// StreamEvents is long-lived. It calls sink(event) for each event.
	// sink returning a non-nil error means the client went away — the
	// handler should clean up and return.
	StreamEvents(ctx context.Context, agentID string, sink func(Event) error) error
	DaemonStatus(ctx context.Context) (DaemonStatusResult, error)
}

// Server is the Unix-socket IPC front-end. One per daemon process.
type Server struct {
	socketPath string
	handler    Handler
	log        *slog.Logger

	listener net.Listener

	// wg tracks in-flight handler goroutines so Stop() waits for them. We
	// need this so a slow StreamEvents can't outlive shutdown and write to
	// a closed socket.
	wg sync.WaitGroup
}

// NewServer constructs a Server. It does not touch the filesystem until Start.
func NewServer(socketPath string, h Handler, log *slog.Logger) *Server {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		socketPath: socketPath,
		handler:    h,
		log:        log,
	}
}

// Start creates the listener, ensures the parent directory exists, and
// chmods the socket to 0600. If a stale socket file is present from a prior
// crash we unlink it — but log a warning first so an admin notices repeated
// crashes.
func (s *Server) Start() error {
	parent := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create socket parent %s: %w", parent, err)
	}
	if _, err := os.Stat(s.socketPath); err == nil {
		s.log.Warn("removing stale socket file (likely leftover from a previous crash)",
			slog.String("path", s.socketPath))
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("remove stale socket %s: %w", s.socketPath, err)
		}
	}
	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", s.socketPath, err)
	}
	// chmod after listen — Listen creates the inode, so we need the file
	// to exist before chmod can find it.
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = l.Close()
		return fmt.Errorf("chmod socket %s: %w", s.socketPath, err)
	}
	s.listener = l
	s.log.Info("ipc server listening", slog.String("socket", s.socketPath))
	return nil
}

// Serve runs the accept loop until ctx is cancelled or the listener closes.
// Returns nil on a clean ctx-driven shutdown.
func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		return errors.New("ipc server: Start must be called before Serve")
	}
	// Closing the listener is how we unblock Accept on shutdown — the
	// goroutine below watches ctx and triggers it.
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// errClosed is returned after Stop; treat that as clean too.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Error("accept error", slog.String("err", err.Error()))
			return fmt.Errorf("accept: %w", err)
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.handleConn(ctx, c)
		}(conn)
	}
}

// Stop closes the listener, removes the socket file, and waits for in-flight
// handlers. Idempotent.
func (s *Server) Stop() error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
	if s.socketPath != "" {
		if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove socket %s: %w", s.socketPath, err)
		}
	}
	return nil
}

// handleConn reads one request frame, dispatches, writes the appropriate
// response(s), and closes. StreamEvents is the only persistent method.
func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	remote := c.RemoteAddr().String()
	logger := s.log.With(slog.String("remote_addr", remote))

	var req Request
	if err := ReadFrame(c, &req); err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Warn("read request", slog.String("err", err.Error()))
		}
		return
	}
	logger = logger.With(slog.String("method", req.Method))

	// Per-request context derived from the server context so a daemon
	// shutdown cancels in-flight handlers.
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	switch req.Method {
	case MethodRunAgent:
		s.handleRunAgent(reqCtx, c, req, logger)
	case MethodStopAgent:
		s.handleStopAgent(reqCtx, c, req, logger)
	case MethodListAgents:
		s.handleListAgents(reqCtx, c, logger)
	case MethodAgentLogs:
		s.handleAgentLogs(reqCtx, c, req, logger)
	case MethodStreamEvents:
		s.handleStreamEvents(reqCtx, c, req, logger)
	case MethodDaemonStatus:
		s.handleDaemonStatus(reqCtx, c, logger)
	default:
		logger.Warn("unknown method")
		_ = WriteErr(c, ErrInternal, fmt.Sprintf("unknown method %q", req.Method))
	}
}

func (s *Server) handleRunAgent(ctx context.Context, c net.Conn, req Request, logger *slog.Logger) {
	var p RunAgentParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		_ = WriteErr(c, ErrInvalidManifest, fmt.Sprintf("decode params: %v", err))
		return
	}
	if err := p.Manifest.Validate(); err != nil {
		_ = WriteErr(c, ErrInvalidManifest, err.Error())
		return
	}
	logger = logger.With(slog.String("phase", "run"), slog.String("agent_name", p.Manifest.Name))
	logger.Info("dispatching RunAgent")
	id, err := s.handler.RunAgent(ctx, p.Manifest)
	if err != nil {
		code := CodeForError(err)
		logger.Error("RunAgent failed", slog.String("code", code), slog.String("err", err.Error()))
		_ = WriteErr(c, code, err.Error())
		return
	}
	_ = WriteOK(c, RunAgentResult{AgentID: id})
}

func (s *Server) handleStopAgent(ctx context.Context, c net.Conn, req Request, logger *slog.Logger) {
	var p StopAgentParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		_ = WriteErr(c, ErrInvalidManifest, fmt.Sprintf("decode params: %v", err))
		return
	}
	logger = logger.With(slog.String("agent_id", p.AgentID), slog.String("phase", "stop"))
	if err := s.handler.StopAgent(ctx, p.AgentID); err != nil {
		code := CodeForError(err)
		logger.Error("StopAgent failed", slog.String("code", code), slog.String("err", err.Error()))
		_ = WriteErr(c, code, err.Error())
		return
	}
	// Inner OK true matches proto.md; idempotent semantics live in the handler.
	_ = WriteOK(c, StopAgentResult{OK: true})
}

func (s *Server) handleListAgents(ctx context.Context, c net.Conn, logger *slog.Logger) {
	agents, err := s.handler.ListAgents(ctx)
	if err != nil {
		code := CodeForError(err)
		logger.Error("ListAgents failed", slog.String("code", code), slog.String("err", err.Error()))
		_ = WriteErr(c, code, err.Error())
		return
	}
	if agents == nil {
		// JSON null vs [] matters to clients iterating the list.
		agents = []AgentSummary{}
	}
	_ = WriteOK(c, ListAgentsResult{Agents: agents})
}

func (s *Server) handleAgentLogs(ctx context.Context, c net.Conn, req Request, logger *slog.Logger) {
	var p AgentLogsParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		_ = WriteErr(c, ErrInvalidManifest, fmt.Sprintf("decode params: %v", err))
		return
	}
	logger = logger.With(slog.String("agent_id", p.AgentID))
	lines, err := s.handler.AgentLogs(ctx, p.AgentID, p.TailN)
	if err != nil {
		code := CodeForError(err)
		logger.Error("AgentLogs failed", slog.String("code", code), slog.String("err", err.Error()))
		_ = WriteErr(c, code, err.Error())
		return
	}
	if lines == nil {
		lines = []Event{}
	}
	_ = WriteOK(c, AgentLogsResult{Lines: lines})
}

func (s *Server) handleStreamEvents(ctx context.Context, c net.Conn, req Request, logger *slog.Logger) {
	var p StreamEventsParams
	// Empty params is allowed (subscribe-all). Only fail on malformed JSON.
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			_ = WriteErr(c, ErrInvalidManifest, fmt.Sprintf("decode params: %v", err))
			return
		}
	}
	logger = logger.With(slog.String("agent_id", p.AgentID), slog.String("phase", "stream"))
	logger.Info("starting event stream")

	// sink wraps WriteOK so each event becomes one frame. A write error
	// (peer disconnect) propagates up and ends the stream.
	sink := func(e Event) error {
		return WriteOK(c, e)
	}
	if err := s.handler.StreamEvents(ctx, p.AgentID, sink); err != nil {
		// Peer disconnect is the common case — log at debug. Other
		// errors get a real error log.
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			logger.Debug("stream ended", slog.String("err", err.Error()))
			return
		}
		logger.Warn("stream ended with error", slog.String("err", err.Error()))
	}
}

func (s *Server) handleDaemonStatus(ctx context.Context, c net.Conn, logger *slog.Logger) {
	res, err := s.handler.DaemonStatus(ctx)
	if err != nil {
		code := CodeForError(err)
		logger.Error("DaemonStatus failed", slog.String("code", code), slog.String("err", err.Error()))
		_ = WriteErr(c, code, err.Error())
		return
	}
	_ = WriteOK(c, res)
}
