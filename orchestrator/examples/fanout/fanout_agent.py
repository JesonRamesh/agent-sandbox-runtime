from __future__ import annotations

import os


def main() -> None:
    label = os.environ.get("AGENT_LABEL", "fanout")
    host_summary = os.environ.get("ALLOWED_HOSTS_LABEL", "none")
    print(f"[AGENT] {label} started", flush=True)
    print(f"[AGENT] allowed_hosts={host_summary}", flush=True)


if __name__ == "__main__":
    main()
