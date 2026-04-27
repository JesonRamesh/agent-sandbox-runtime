SHELL := /bin/bash

GO            ?= go
GOFLAGS       ?=
PKG           := ./...
BIN_DIR       := bin
DAEMON_BIN    := $(BIN_DIR)/agent-sandbox-daemon
TEST_CLIENT   := $(BIN_DIR)/test-client

# eBPF C is owned by Mehul (../bpf/ on his branch). The daemon loads
# the prebuilt .bpf.o objects at runtime via cilium/ebpf — there is no
# bpf2go generation step here. See docs/integration-with-mehul-ebpf.md.

.PHONY: all build daemon test-client test test-integration test-e2e lint clean install uninstall

all: build

build: daemon test-client

daemon:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(DAEMON_BIN) ./cmd/daemon

test-client:
	mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(TEST_CLIENT) ./cmd/test-client

test:
	$(GO) test $(GOFLAGS) -race $(PKG)

# Integration tests touch /sys/fs/cgroup and load BPF — must run as root on Linux.
test-integration:
	sudo $(GO) test $(GOFLAGS) -tags=integration ./internal/cgroup/... ./internal/bpf/...

test-e2e:
	sudo $(GO) test $(GOFLAGS) -tags=e2e ./tests/e2e/...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint not installed. Install: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	}
	golangci-lint run ./...

clean:
	rm -rf $(BIN_DIR)

install: build
	sudo deploy/install.sh

uninstall:
	sudo deploy/uninstall.sh
