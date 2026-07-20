#!/usr/bin/env python3
"""Validate the SARIF fields UniFlow promises to downstream consumers."""
from __future__ import annotations
import json
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> int:
    if len(sys.argv) < 2:
        fail("usage: validate-sarif.py FILE [FILE ...]")
    for raw in sys.argv[1:]:
        path = Path(raw)
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != "2.1.0":
            fail(f"{path}: SARIF version is not 2.1.0")
        if not isinstance(data.get("runs"), list) or not data["runs"]:
            fail(f"{path}: runs is empty")
        for run_index, run in enumerate(data["runs"]):
            driver = run.get("tool", {}).get("driver", {})
            if not driver.get("name"):
                fail(f"{path}: run {run_index} has no driver name")
            for result_index, result in enumerate(run.get("results", [])):
                if not result.get("ruleId"):
                    fail(f"{path}: result {result_index} has no ruleId")
                message = result.get("message", {}).get("text")
                if not message:
                    fail(f"{path}: result {result_index} has no message")
                locations = result.get("locations") or []
                if not locations:
                    fail(f"{path}: result {result_index} has no location")
                physical = locations[0].get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri")
                region = physical.get("region", {})
                if not uri or region.get("startLine", 0) < 1 or region.get("startColumn", 0) < 1:
                    fail(f"{path}: result {result_index} has an invalid physical location")
    print(f"SARIF validation ok: {len(sys.argv) - 1} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
