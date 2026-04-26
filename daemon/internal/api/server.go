// Package api exposes the daemon's HTTP+SSE control surface and
// serves the static web GUI. See decision D-007.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/cisco-agentsandbox/runtime/daemon/internal/events"
	"github.com/cisco-agentsandbox/runtime/daemon/internal/loader"
	"github.com/cisco-agentsandbox/runtime/daemon/internal/policy"
)

type Server struct {
	store *policy.Store
	rt    *loader.Runtime
	uiDir string

	mu          sync.RWMutex
	subscribers map[chan *events.Event]struct{}

	recent     []*events.Event
	recentSize int
}

func New(store *policy.Store, rt *loader.Runtime, uiDir string) *Server {
	return &Server{
		store:       store,
		rt:          rt,
		uiDir:       uiDir,
		subscribers: map[chan *events.Event]struct{}{},
		recentSize:  256,
	}
}

func (s *Server) ListenAndServe(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/policies/", s.handlePolicy)
	mux.HandleFunc("/api/bindings", s.handleBindings)
	mux.HandleFunc("/api/events", s.handleEventStream)
	mux.HandleFunc("/api/events/recent", s.handleRecentEvents)
	mux.HandleFunc("/api/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	if s.uiDir != "" {
		mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.Dir(s.uiDir))))
		mux.Handle("/", http.RedirectHandler("/ui/", http.StatusFound))
	}
	return http.ListenAndServe(addr, mux)
}

// Broadcast is the callback the loader hands every decoded event.
func (s *Server) Broadcast(evt *events.Event) {
	s.mu.Lock()
	s.recent = append(s.recent, evt)
	if len(s.recent) > s.recentSize {
		s.recent = s.recent[len(s.recent)-s.recentSize:]
	}
	for ch := range s.subscribers {
		select {
		case ch <- evt:
		default:
			// Slow consumer; drop rather than block the kernel reader.
		}
	}
	s.mu.Unlock()
}

// ----- handlers -------------------------------------------------------

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.store.List())
	case http.MethodPost:
		var p policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if p.ID == 0 {
			http.Error(w, "id must be > 0", http.StatusBadRequest)
			return
		}
		s.store.Put(p)
		writeJSON(w, p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/policies/"):]
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var p policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		p.ID = uint32(id)
		s.store.Put(p)
		writeJSON(w, p)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type bindingReq struct {
	CgroupID uint64 `json:"cgroup_id"`
	PolicyID uint32 `json:"policy_id"`
}

func (s *Server) handleBindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req bindingReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.store.Bind(req.CgroupID, req.PolicyID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRecentEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	out := append([]*events.Event{}, s.recent...)
	s.mu.RUnlock()
	writeJSON(w, out)
}

func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan *events.Event, 64)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		s.mu.Unlock()
	}()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case evt := <-ch:
			b, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
