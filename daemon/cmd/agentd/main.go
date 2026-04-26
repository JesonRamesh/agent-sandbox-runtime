// Command agentd is the agent-sandbox-runtime control-plane daemon.
//
// It loads the four eBPF objects (network/file/creds/exec), reads
// events from the shared ringbuf, exposes an HTTP+SSE API, serves
// the web GUI, and translates UI/CLI requests into BPF map updates.
//
// Run as root (or with CAP_BPF + CAP_SYS_ADMIN + CAP_PERFMON).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cisco-agentsandbox/runtime/daemon/internal/api"
	"github.com/cisco-agentsandbox/runtime/daemon/internal/loader"
	"github.com/cisco-agentsandbox/runtime/daemon/internal/policy"
)

func main() {
	bpfDir := flag.String("bpf-dir", "/usr/lib/agentsandbox/bpf",
		"directory containing the compiled .bpf.o objects")
	addr := flag.String("listen", "127.0.0.1:9000", "HTTP listen address")
	uiDir := flag.String("ui-dir", "/usr/share/agentsandbox/ui",
		"directory containing the static web GUI")
	policyDir := flag.String("policy-dir", "/etc/agentsandbox/policies",
		"directory of YAML policies to load on startup")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	store := policy.NewStore()
	if err := store.LoadDir(*policyDir); err != nil {
		log.Printf("policy load: %v (continuing with empty store)", err)
	}

	rt, err := loader.Load(*bpfDir)
	if err != nil {
		log.Fatalf("load eBPF: %v", err)
	}
	defer rt.Close()

	if err := rt.SyncPolicies(store.Snapshot()); err != nil {
		log.Fatalf("sync policies: %v", err)
	}
	store.OnChange(func(snap policy.Snapshot) {
		if err := rt.SyncPolicies(snap); err != nil {
			log.Printf("re-sync policies: %v", err)
		}
	})

	srv := api.New(store, rt, *uiDir)
	go func() {
		log.Printf("agentd listening on http://%s", *addr)
		if err := srv.ListenAndServe(*addr); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	if err := rt.Run(ctx, srv.Broadcast); err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
}
