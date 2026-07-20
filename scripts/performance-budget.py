#!/usr/bin/env python3
"""Small deterministic release performance and memory regression gate."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

try:
    import resource
except ImportError:  # Windows
    resource = None

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "c-source": ["analyze-source", "--language", "c", "--input", "examples/smoke/command_flow.c", "--use-default-models"],
    "cpp-source": ["analyze-source", "--language", "cpp", "--input", "examples/smoke/command_flow.cpp", "--use-default-models"],
    "java-project": ["analyze-project", "--language", "java", "--input", "examples/smoke/java_project", "--use-default-models"],
    "python-project": ["analyze-project", "--language", "python", "--input", "examples/smoke/python_project", "--use-default-models"],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True)
    parser.add_argument("--output")
    parser.add_argument("--case-seconds", type=float, default=60.0)
    parser.add_argument("--total-seconds", type=float, default=180.0)
    parser.add_argument("--max-rss-mb", type=float, default=2048.0)
    args = parser.parse_args()
    binary = str(Path(args.bin).resolve())
    start_total = time.perf_counter()
    rows = []
    baseline_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss if resource else 0
    for name, command in CASES.items():
        start = time.perf_counter()
        result = subprocess.run([binary, *command], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=args.case_seconds, check=False)
        elapsed = time.perf_counter() - start
        if result.returncode != 0:
            raise SystemExit(f"performance case {name} failed: {result.stderr}")
        if elapsed > args.case_seconds:
            raise SystemExit(f"performance case {name} exceeded {args.case_seconds}s")
        rows.append({"case": name, "elapsed_seconds": elapsed})
    total = time.perf_counter() - start_total
    if total > args.total_seconds:
        raise SystemExit(f"performance suite exceeded {args.total_seconds}s: {total:.3f}s")
    peak_mb = None
    if resource:
        raw = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        # Linux reports KiB; macOS reports bytes.
        peak_mb = raw / (1024.0 * 1024.0) if sys.platform == "darwin" else raw / 1024.0
        if peak_mb > args.max_rss_mb:
            raise SystemExit(f"child peak RSS exceeded {args.max_rss_mb} MiB: {peak_mb:.1f} MiB")
    report = {"total_seconds": total, "peak_rss_mb": peak_mb, "budgets": {"case_seconds": args.case_seconds, "total_seconds": args.total_seconds, "max_rss_mb": args.max_rss_mb}, "cases": rows}
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"performance budget ok: total={total:.3f}s peak_rss_mb={peak_mb}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
