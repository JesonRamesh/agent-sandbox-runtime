// Package events implements the daemon-wide event bus. Every kernel-level
// or daemon lifecycle event (network.block, agent.started, etc.) flows
// through Pipeline.Submit and is fanned out to slog, per-agent log files,
// and live subscribers (IPC StreamEvents handlers, WebSocket clients).
//
// The Event schema is owned by api/proto.md and mirrored in internal/ipc.
// This package never reshapes events — it only routes them.
package events

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

// Sink receives one event. Returning an error signals the pipeline to drop
// this subscriber — used by websocket clients that have gone away or by IPC
// stream handlers whose client closed the connection.
type Sink func(ipc.Event) error

// Pipeline is the daemon-wide event bus. Every kernel-level or daemon
// lifecycle event flows through Submit, then fans out to:
//  1. The slog logger (always-on)
//  2. Per-agent log files at logDir/<agent-id>.log (size-rotated)
//  3. Active subscribers added via Subscribe (websocket clients, IPC
//     StreamEvents handlers)
type Pipeline struct {
	log    *slog.Logger
	logDir string

	maxFileBytes int64
	maxFiles     int

	in chan ipc.Event

	subMu  sync.RWMutex
	subs   map[uint64]subscriber
	nextID uint64

	fileMu sync.Mutex
	files  map[string]*rotatingWriter

	closeOnce sync.Once
	closed    chan struct{}
}

// Config — bring-your-own log dir and rotation parameters.
type Config struct {
	LogDir       string // e.g., /var/log/agent-sandbox
	MaxFileBytes int64  // default 10 MiB
	MaxFiles     int    // default 3 (current + 2 rotated)
	BufferSize   int    // input chan buffer; default 1024
}

// subscriber bundles a Sink with its agent filter so fanOut can decide
// without an extra map lookup.
type subscriber struct {
	filterAgentID string
	sink          Sink
}

const (
	defaultMaxFileBytes = 10 * 1024 * 1024 // 10 MiB
	defaultMaxFiles     = 3
	defaultBufferSize   = 1024
)

// NewPipeline constructs a Pipeline. It creates LogDir if missing — the
// caller is expected to have permission (the daemon runs with the
// capabilities to create /var/log/agent-sandbox at startup).
func NewPipeline(cfg Config, log *slog.Logger) (*Pipeline, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.LogDir == "" {
		return nil, errors.New("events: LogDir is required")
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = defaultMaxFileBytes
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = defaultMaxFiles
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = defaultBufferSize
	}
	if err := os.MkdirAll(cfg.LogDir, 0o755); err != nil {
		return nil, fmt.Errorf("events: create log dir %q: %w", cfg.LogDir, err)
	}
	return &Pipeline{
		log:          log,
		logDir:       cfg.LogDir,
		maxFileBytes: cfg.MaxFileBytes,
		maxFiles:     cfg.MaxFiles,
		in:           make(chan ipc.Event, cfg.BufferSize),
		subs:         make(map[uint64]subscriber),
		files:        make(map[string]*rotatingWriter),
		closed:       make(chan struct{}),
	}, nil
}

// Run reads from the input channel and fans out until ctx is cancelled or
// Close is called. Blocks; the daemon launches it in a goroutine.
func (p *Pipeline) Run(ctx context.Context) {
	// A separate goroutine watches for ctx cancellation and triggers Close,
	// so the main loop only has one termination condition (range exit).
	stopWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = p.Close()
		case <-stopWatch:
		}
	}()
	defer close(stopWatch)

	for ev := range p.in {
		p.fanOut(ev)
	}
}

// Submit pushes one event. Non-blocking: if the input buffer is full the
// event is logged at warn and dropped. Losing a log line is preferable to
// back-pressuring the kernel ring-buffer reader.
//
// A panic from sending on a closed channel after Close is recovered here:
// it is racier to take a lock on every Submit (hot path) than to swallow
// the rare close-vs-submit race.
func (p *Pipeline) Submit(ev ipc.Event) {
	defer func() {
		// Send-on-closed-channel becomes a panic; the only way Submit and
		// Close race is during shutdown, where the event is fine to drop.
		_ = recover()
	}()
	select {
	case <-p.closed:
		return
	default:
	}
	select {
	case p.in <- ev:
	default:
		p.log.Warn("event pipeline buffer full; dropping event",
			"agent_id", ev.AgentID, "type", ev.Type)
	}
}

// Subscribe adds a sink. filterAgentID == "" means all agents. The returned
// function unsubscribes; callers MUST call it (typically via defer).
func (p *Pipeline) Subscribe(filterAgentID string, s Sink) (unsubscribe func()) {
	p.subMu.Lock()
	id := p.nextID
	p.nextID++
	p.subs[id] = subscriber{filterAgentID: filterAgentID, sink: s}
	p.subMu.Unlock()

	return func() {
		p.subMu.Lock()
		delete(p.subs, id)
		p.subMu.Unlock()
	}
}

// AgentLogTail reads the last n events from the per-agent log file.
// n == 0 returns all events. Events are returned in chronological order.
//
// v0.1: reads the whole file and slices. Fine for 10 MiB; bound this if the
// rotation cap ever grows.
func (p *Pipeline) AgentLogTail(agentID string, n int) ([]ipc.Event, error) {
	if agentID == "" {
		return nil, errors.New("events: agent_id is required")
	}
	path := p.logPath(agentID)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("events: open agent log %q: %w", path, err)
	}
	defer f.Close()

	var out []ipc.Event
	scanner := bufio.NewScanner(f)
	// One event per line — events are tiny; use a generous buffer to handle
	// pathological details payloads without truncating.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev ipc.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			// Skip malformed lines rather than fail the whole tail — a
			// truncated trailing line during rotation shouldn't blank the UI.
			p.log.Warn("skipping malformed agent log line",
				"agent_id", agentID, "err", err)
			continue
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("events: scan agent log %q: %w", path, err)
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// Close shuts down the pipeline (drains input, closes files). Safe to call
// multiple times; only the first call has an effect.
func (p *Pipeline) Close() error {
	var firstErr error
	p.closeOnce.Do(func() {
		close(p.closed)
		close(p.in)
		// Run will exit when its for-range sees the closed channel drained.
		// We don't synchronize with that exit here; the daemon owns Run's
		// goroutine lifecycle and will join it via its own mechanism.

		p.fileMu.Lock()
		for _, w := range p.files {
			if err := w.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		p.files = nil
		p.fileMu.Unlock()
	})
	return firstErr
}

// fanOut delivers one event to slog, the per-agent file, and all matching
// subscribers. Subscribers whose Sink returns an error are removed.
func (p *Pipeline) fanOut(ev ipc.Event) {
	p.log.Info("event",
		"agent_id", ev.AgentID,
		"type", ev.Type,
		"pid", ev.PID)

	if ev.AgentID != "" {
		if err := p.appendAgentLog(ev); err != nil {
			p.log.Warn("agent log append failed",
				"agent_id", ev.AgentID, "err", err)
		}
	}

	// Hold the read lock only for the duration of the iteration; collect
	// stale ids and remove them under a write lock afterwards. Brief §7
	// forbids holding a lock across a channel send — sinks here are direct
	// function calls, not sends, but a slow sink will block fan-out. v0.1
	// accepts that trade-off (simpler than per-sub goroutines + queues).
	var stale []uint64
	p.subMu.RLock()
	for id, sub := range p.subs {
		if sub.filterAgentID != "" && sub.filterAgentID != ev.AgentID {
			continue
		}
		if err := sub.sink(ev); err != nil {
			stale = append(stale, id)
		}
	}
	p.subMu.RUnlock()

	if len(stale) > 0 {
		p.subMu.Lock()
		for _, id := range stale {
			delete(p.subs, id)
		}
		p.subMu.Unlock()
	}
}

// appendAgentLog writes one JSON line to the per-agent log file, opening
// and tracking a rotatingWriter on first use.
func (p *Pipeline) appendAgentLog(ev ipc.Event) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	body = append(body, '\n')

	p.fileMu.Lock()
	defer p.fileMu.Unlock()
	if p.files == nil {
		// Pipeline already Closed; skip silently.
		return nil
	}
	w, ok := p.files[ev.AgentID]
	if !ok {
		w, err = newRotatingWriter(p.logPath(ev.AgentID), p.maxFileBytes, p.maxFiles)
		if err != nil {
			return err
		}
		p.files[ev.AgentID] = w
	}
	_, err = w.Write(body)
	return err
}

func (p *Pipeline) logPath(agentID string) string {
	return filepath.Join(p.logDir, agentID+".log")
}

// rotatingWriter is a size-rotated file writer. Not thread-safe on its own
// — Pipeline serializes writes through fileMu. We keep the lock external so
// rotation across multiple agents stays cheap (no per-file goroutine).
type rotatingWriter struct {
	path     string
	maxBytes int64
	maxFiles int

	f    *os.File
	size int64
}

func newRotatingWriter(path string, maxBytes int64, maxFiles int) (*rotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log %q: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat log %q: %w", path, err)
	}
	return &rotatingWriter{
		path:     path,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
		f:        f,
		size:     st.Size(),
	}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	if w.f == nil {
		return 0, errors.New("rotatingWriter: closed")
	}
	if w.size+int64(len(p)) > w.maxBytes && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the active file, shifts .log -> .log.1 -> ... -> .log.<N-1>,
// drops anything past the cap, and reopens .log fresh. maxFiles=N means N
// total files exist after rotation: .log + .log.1 ... .log.<N-1>.
func (w *rotatingWriter) rotate() error {
	if err := w.f.Close(); err != nil {
		return fmt.Errorf("close before rotate: %w", err)
	}
	w.f = nil

	// Drop the oldest if present.
	oldest := fmt.Sprintf("%s.%d", w.path, w.maxFiles-1)
	if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove oldest rotated log %q: %w", oldest, err)
	}
	// Shift .log.<i> -> .log.<i+1> from highest-but-one down to .log.1.
	for i := w.maxFiles - 2; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		if err := os.Rename(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("shift rotated log %q -> %q: %w", src, dst, err)
		}
	}
	// Move current .log to .log.1
	if err := os.Rename(w.path, w.path+".1"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("rotate %q: %w", w.path, err)
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("reopen %q after rotate: %w", w.path, err)
	}
	w.f = f
	w.size = 0
	return nil
}

func (w *rotatingWriter) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
