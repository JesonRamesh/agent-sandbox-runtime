from __future__ import annotations

import subprocess


def main() -> None:
    cmd = [
        "/usr/bin/python3",
        "-c",
        "from pathlib import Path; "
        "Path('/tmp/sandbox').mkdir(parents=True, exist_ok=True); "
        "Path('/tmp/sandbox/hello.txt').write_text('sandbox hello\\n', encoding='utf-8'); "
        "print('child wrote /tmp/sandbox/hello.txt')",
    ]
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    print(f"[TOOL] run_command called with: {' '.join(cmd)}", flush=True)
    print(
        '[RESULT] {"tool":"run_command","ok":true,"request_id":"code_exec_demo"}',
        flush=True,
    )
    print(f"[AGENT] {completed.stdout.strip()}", flush=True)


if __name__ == "__main__":
    main()
