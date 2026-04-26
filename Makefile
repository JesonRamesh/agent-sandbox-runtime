# Top-level orchestration. Run `make` inside the Vagrant VM.
#
#   make             -> bpf + daemon + cli
#   make install     -> copy binaries + UI + policies into /usr/local + /etc
#   make run         -> launch agentd in foreground (dev)
#   make clean

PREFIX     ?= /usr/local
BPF_OUT    := bpf
DAEMON_OUT := daemon/agentd
CLI_OUT    := cli/agentctl/agentctl

.PHONY: all bpf daemon cli install run clean

all: bpf daemon cli

bpf:
	$(MAKE) -C bpf

daemon:
	cd daemon && go mod tidy && go build -o agentd ./cmd/agentd

cli:
	cd cli/agentctl && go mod tidy && go build -o agentctl .

install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)/usr/lib/agentsandbox/bpf
	install -d $(DESTDIR)/usr/share/agentsandbox/ui
	install -d $(DESTDIR)/etc/agentsandbox/policies
	install -m 0755 $(DAEMON_OUT) $(DESTDIR)$(PREFIX)/bin/agentd
	install -m 0755 $(CLI_OUT)    $(DESTDIR)$(PREFIX)/bin/agentctl
	install -m 0644 bpf/*.bpf.o   $(DESTDIR)/usr/lib/agentsandbox/bpf/
	install -m 0644 gui/*         $(DESTDIR)/usr/share/agentsandbox/ui/
	install -m 0644 policies/*.yaml $(DESTDIR)/etc/agentsandbox/policies/
	install -m 0644 systemd/agentsandbox.service \
	        $(DESTDIR)/etc/systemd/system/agentsandbox.service

run: all
	sudo ./$(DAEMON_OUT) \
	    --bpf-dir=$(PWD)/bpf \
	    --ui-dir=$(PWD)/gui \
	    --policy-dir=$(PWD)/policies

clean:
	$(MAKE) -C bpf clean
	rm -f $(DAEMON_OUT) $(CLI_OUT)
