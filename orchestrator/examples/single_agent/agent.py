from __future__ import annotations

import os


def main() -> None:
    name = os.environ.get("AGENT_NAME", "single-agent")
    print("[USER] Summarize your startup state.", flush=True)
    print(f"[AGENT] {name} started in local example mode", flush=True)


if __name__ == "__main__":
    main()
