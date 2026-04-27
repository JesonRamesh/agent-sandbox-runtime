#!/usr/bin/env bash
# phase2.sh — manual reproduction of the Phase 2 acceptance test.
#
# What it proves: starting the daemon, sending a hardcoded RunAgent request
# via the test-client, observing the curl inside the agent fail with
# "Operation not permitted", and seeing a `network.block` event in the
# daemon's stderr log. Cleanup leaves no /sys/fs/cgroup/agent-sandbox/* dirs.
#
# Run on Ubuntu as root (or with sudo). The script does not start/stop the
# daemon for you — keep that in a separate terminal so you can read its log.

set -uo pipefail

SOCKET=${SOCKET:-/run/agent-sandbox.sock}
DAEMON=${DAEMON:-./bin/agent-sandbox-daemon}
CLIENT=${CLIENT:-./bin/test-client}
MANIFEST=${MANIFEST:-examples/curl-blocked.json}

if [ ! -x "$DAEMON" ] || [ ! -x "$CLIENT" ]; then
    echo "missing binaries — run: make build" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root (cgroup writes + BPF load)" >&2
    exit 1
fi

echo "=== Phase 2 manual reproduction ==="
echo
echo "Terminal 1 (start the daemon, leave it running, watch stderr):"
echo "  sudo $DAEMON --log-json"
echo
echo "Terminal 2 (this script): we'll send one RunAgent request and watch the cgroup."
read -p "Daemon running in another terminal? press enter to continue: " _
echo

echo "[1/4] sending RunAgent with $MANIFEST ..."
$CLIENT --socket "$SOCKET" run "$MANIFEST"
RC=$?
if [ $RC -ne 0 ]; then
    echo "test-client failed; check daemon log" >&2
    exit 1
fi

echo
echo "[2/4] cgroup directory should now exist:"
ls -la /sys/fs/cgroup/agent-sandbox/ || true

echo
echo "[3/4] expected daemon-side events (search the daemon log):"
echo "      - agent.started"
echo "      - net.connect with verdict=deny daddr=1.1.1.1 (the curl in curl-blocked.json)"
echo "      - agent.exited with non-zero exit_code"

echo
echo "[4/4] waiting for the agent to exit (curl has a 3s timeout) ..."
sleep 5

echo
echo "after exit, /sys/fs/cgroup/agent-sandbox/ should be empty:"
ls -la /sys/fs/cgroup/agent-sandbox/ 2>/dev/null || echo "  (parent dir absent — that's fine if the daemon was the first to use it)"

echo
echo "=== Phase 2 acceptance checklist ==="
echo "  [ ] curl inside the agent failed with 'Operation not permitted'"
echo "  [ ] daemon logged a net.connect/deny event with daddr=1.1.1.1"
echo "  [ ] no leftover cgroup dirs"
echo "  [ ] Ctrl-C on the daemon shuts down cleanly"
echo "  [ ] restart the daemon after a forced kill — startup reconciliation cleans leaks"
echo
echo "If any line above failed, see docs/operations.md."
