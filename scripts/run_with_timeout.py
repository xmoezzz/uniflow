#!/usr/bin/env python3
"""Run a command with a portable wall-clock timeout."""
from __future__ import annotations
import os
import signal
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: run_with_timeout.py SECONDS COMMAND [ARGS...]", file=sys.stderr)
        return 2
    timeout = float(sys.argv[1])
    command = sys.argv[2:]
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        # subprocess.run terminates the direct child, but build tools commonly
        # leave the actual test binary running. Kill the dedicated process
        # group so a short focused test can never leak an orphan worker.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        print(f"command exceeded {timeout:g}s: {' '.join(command)}", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
