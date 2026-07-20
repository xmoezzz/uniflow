#!/usr/bin/env python3
"""Dependency-free structural validation for the built-in baseline catalog."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "rules" / "baseline"
ID_LINE = re.compile(r"^\s*-\s+id:\s*([^\s#]+)\s*$", re.MULTILINE)


def main() -> int:
    manifest = json.loads((BASE / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != "1.0.0":
        raise SystemExit("baseline manifest version must be 1.0.0")
    expected_rules = manifest.get("rule_count")
    if not isinstance(expected_rules, int) or expected_rules <= 0:
        raise SystemExit("baseline manifest must declare a positive rule_count")
    packs = manifest.get("packs") or []
    if len(packs) != 4:
        raise SystemExit(f"expected 4 baseline packs, found {len(packs)}")
    ids: set[str] = set()
    total = 0
    for entry in packs:
        path = BASE / entry["file"]
        if not path.is_file():
            raise SystemExit(f"missing baseline pack: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        found = ID_LINE.findall(text)
        declared = entry.get("rule_count")
        if declared != len(found):
            raise SystemExit(f"{path.relative_to(ROOT)} declares {declared} rules but contains {len(found)}")
        if not found:
            raise SystemExit(f"no rules in {path.relative_to(ROOT)}")
        for rule_id in found:
            if rule_id in ids:
                raise SystemExit(f"duplicate baseline rule id: {rule_id}")
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]*", rule_id):
                raise SystemExit(f"invalid baseline rule id: {rule_id}")
            ids.add(rule_id)
        total += len(found)
    extra = sorted(p.name for p in BASE.glob("*.yml") if p.name not in {x["file"] for x in packs})
    if extra:
        raise SystemExit(f"unlisted baseline YAML files: {', '.join(extra)}")
    if total != expected_rules:
        raise SystemExit(f"expected {expected_rules} baseline rules, found {total}")
    print(f"baseline catalog ok: {len(packs)} packs, {total} unique rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
