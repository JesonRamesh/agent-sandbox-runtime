package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

// DefaultWSAddr is the brief-mandated WebSocket bind address (api/proto.md
// §WebSocket). Localhost only; no auth, no TLS in v0.1.
const DefaultWSAddr = "127.0.0.1:7443"

// wsWriteTimeout bounds each per-event write so a stalled client cannot
// hold up fan-out indefinitely. The pipeline drops the subscription on
// timeout via the sink-error mechanism.
const wsWriteTimeout = time.Second

// WSServer serves /events on a localhost-only TCP port. Brief §6 Phase 3
// task 5: ws://127.0.0.1:7443/events?agent=<id>. No auth, no TLS.
type WSServer struct {
	addr     string
	pipeline *Pipeline
	log      *slog.Logger

	server *http.Server
}

// NewWSServer constructs a server. Pass empty addr to bind DefaultWSAddr.
// No network I/O happens until Start.
func NewWSServer(addr string, p *Pipeline, log *slog.Logger) *WSServer {
	if addr == "" {
		addr = DefaultWSAddr
	}
	if log == nil {
		log = slog.Default()
	}
	return &WSServer{
		addr:     addr,
		pipeline: p,
		log:      log,
	}
}

// Start begins listening. Returns immediately; serving happens in a goroutine.
// Refuses to bind to non-loopback addresses — the brief mandates localhost
// only and there's no auth, so binding outward would expose unauthenticated
// event streaming to the network.
func (w *WSServer) Start() error {
	if err := assertLoopback(w.addr); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/events", w.handleEvents)

	w.server = &http.Server{
		Addr:              w.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", w.addr)
	if err != nil {
		return fmt.Errorf("websocket listen %q: %w", w.addr, err)
	}

	go func() {
		if err := w.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			w.log.Error("websocket server exited", "err", err)
		}
	}()
	w.log.Info("websocket server started", "addr", w.addr)
	return nil
}

// Stop gracefully shuts down with a timeout supplied via ctx.
func (w *WSServer) Stop(ctx context.Context) error {
	if w.server == nil {
		return nil
	}
	return w.server.Shutdown(ctx)
}

func (w *WSServer) handleEvents(rw http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")

	// InsecureSkipVerify is OK here because Start refuses to bind anything
	// other than loopback — origin spoofing across loopback requires local
	// code execution, at which point the attacker has bigger options than
	// reading event JSON.
	conn, err := websocket.Accept(rw, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		w.log.Warn("websocket accept failed", "err", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "server closing")

	ctx := r.Context()

	unsubscribe := w.pipeline.Subscribe(agent, func(ev ipc.Event) error {
		writeCtx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
		defer cancel()
		return wsjson.Write(writeCtx, conn, ev)
	})
	defer unsubscribe()

	w.log.Info("websocket client connected", "agent", agent, "remote", r.RemoteAddr)

	// Block until the client disconnects or the request ctx is cancelled.
	// We don't read application messages — the protocol is server-push only
	// — but a Read is required to observe close frames.
	_, _, err = conn.Read(ctx)
	if err != nil {
		var ce websocket.CloseError
		if !errors.As(err, &ce) {
			w.log.Debug("websocket read ended", "err", err)
		}
	}
	conn.Close(websocket.StatusNormalClosure, "")
	w.log.Info("websocket client disconnected", "agent", agent)
}

// assertLoopback parses addr and returns an error if the host portion is
// not a loopback address. The brief mandates localhost binding; this is a
// guardrail against accidental wildcard / public-interface misconfiguration.
func assertLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse websocket addr %q: %w", addr, err)
	}
	if host == "" {
		// Empty host means "all interfaces" — explicitly forbidden.
		return fmt.Errorf("websocket addr %q must bind a loopback address; refusing wildcard bind", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("websocket addr host %q is not an IP", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("websocket addr %q must bind a loopback address (got %s)", addr, host)
	}
	return nil
}
