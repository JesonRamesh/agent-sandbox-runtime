# Agent Sandbox Runtime — top-level Makefile
#
# Layout: a single Go module rooted at the repo with three binaries under cmd/
# and four eBPF objects produced by bpf/Makefile. Build artifacts land in
# bin/ at the repo root and are gitignored.
#
# Common targets:
#   make all            build everything (bpf + go binaries)
#   make agentd         build just the daemon
#   make agentctl       build just the CLI
#   make test-client    build the IPC test client
#   make bpf            (re)compile the eBPF objects
#   make test           run all Go unit tests
#   make integration    run integration tests (requires Linux + root)
#   make install        install binaries + bpf objects + systemd unit
#   make uninstall      reverse install
#   make clean          remove built artifacts
#
# After a fresh `make all` you can run the daemon directly:
#   sudo ./bin/agentd -bpf-dir=$(pwd)/bpf
# and the CLI in another terminal:
#   sudo ./bin/agentctl run -f examples/blocked-net.yaml

PREFIX ?= /usr/local
BIN_DIR := bin

GO_FLAGS ?=
GO_BUILD := go build $(GO_FLAGS)

.PHONY: all bpf agentd agentctl test-client \
        test integration e2e demo \
        install uninstall fmt vet lint clean help

all: bpf agentd agentctl test-client

bpf:
	$(MAKE) -C bpf

agentd: $(BIN_DIR)
	$(GO_BUILD) -o $(BIN_DIR)/agentd ./cmd/agentd

agentctl: $(BIN_DIR)
	$(GO_BUILD) -o $(BIN_DIR)/agentctl ./cmd/agentctl

test-client: $(BIN_DIR)
	$(GO_BUILD) -o $(BIN_DIR)/test-client ./cmd/test-client

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Excludes node_modules so the bundled flatted Go file in viewer/viewer-app
# doesn't pollute the test set.
GO_PKGS := $(shell go list ./... 2>/dev/null | grep -v '/node_modules/')

test:
	go test $(GO_PKGS)

integration:
	@echo "Integration tests must run on Linux as root (eBPF + cgroup v2)."
	sudo -E go test -tags=integration $(GO_PKGS)

e2e: agentctl
	go test ./e2e/...

demo:
	bash scripts/quickstart.sh

install: all
	bash deploy/install.sh

uninstall:
	bash deploy/uninstall.sh

fmt:
	gofmt -w $(shell find . -type f -name '*.go' -not -path '*/node_modules/*')

vet:
	go vet $(GO_PKGS)

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; brew install golangci-lint or see https://golangci-lint.run"; exit 1; }
	golangci-lint run

clean:
	rm -rf $(BIN_DIR)
	$(MAKE) -C bpf clean

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*' Makefile | sed 's/:.*//' | sort -u
