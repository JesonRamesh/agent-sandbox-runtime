#!/usr/bin/env bash
# verify-host.sh — runs the four Phase 1 verification commands from the brief
# and prints PASS/FAIL for each. Run this on the Ubuntu host before starting
# any work that requires the kernel to support cgroup v2 + cgroup-attach BPF.
#
# Target: Ubuntu 22.04 with kernel 6.x (linux-generic-hwe-22.04 recommended).
# The brief asks for 6.8+; 6.5 (HWE 22.04) is usually sufficient for the
# features we need but flag any failures here before Phase 2.

set -u

pass=0
fail=0

check() {
    local label=$1
    local cmd=$2
    local expect=$3  # human-readable expected substring or "nonempty"
    local out
    if ! out=$(eval "$cmd" 2>&1); then
        printf '[FAIL] %-40s -- command errored: %s\n' "$label" "$out"
        fail=$((fail+1))
        return
    fi

    if [ "$expect" = "nonempty" ]; then
        if [ -n "$out" ]; then
            printf '[PASS] %-40s\n' "$label"
            pass=$((pass+1))
        else
            printf '[FAIL] %-40s -- empty output\n' "$label"
            fail=$((fail+1))
        fi
    else
        if echo "$out" | grep -qF -- "$expect"; then
            printf '[PASS] %-40s\n' "$label"
            pass=$((pass+1))
        else
            printf '[FAIL] %-40s -- expected substring %q not found\n' "$label" "$expect"
            printf '       output: %s\n' "$out"
            fail=$((fail+1))
        fi
    fi
}

echo "=== agent-sandbox host verification ==="
echo

check "kernel version (uname -r)"               "uname -r"                                          "nonempty"
check "cgroup v2 unified hierarchy mounted"     "mount | grep cgroup2"                              "cgroup2"
check "BTF available (vmlinux)"                 "ls /sys/kernel/btf/vmlinux"                        "/sys/kernel/btf/vmlinux"
check "BPF cgroup_sock attach supported"        "sudo bpftool feature probe 2>/dev/null | grep cgroup_sock" "cgroup_sock"

echo
echo "=== summary: $pass passed, $fail failed ==="
if [ "$fail" -ne 0 ]; then
    echo
    echo "If a check failed, see docs/operations.md for fixes."
    echo "Most common: install HWE kernel — sudo apt install linux-generic-hwe-22.04 && reboot."
    exit 1
fi
