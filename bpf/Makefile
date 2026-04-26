# Build the four eBPF objects. Run `make` inside the Vagrant VM
# (or any host with clang ≥ 14, libbpf-dev, and bpftool).
#
# vmlinux.h is generated once from the running kernel's BTF.

CLANG     ?= clang
BPFTOOL   ?= bpftool
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -O2 -g -Wall -Werror \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I. -Iinclude

OBJS := network.bpf.o file.bpf.o creds.bpf.o exec.bpf.o

.PHONY: all clean vmlinux

all: vmlinux.h $(OBJS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c common.h vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.bpf.o vmlinux.h
