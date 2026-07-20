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
    try:
        completed = subprocess.run(command, timeout=timeout, check=False)
        return completed.returncode
    except subprocess.TimeoutExpired:
        print(f"command exceeded {timeout:g}s: {' '.join(command)}", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
