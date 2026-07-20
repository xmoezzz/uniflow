#!/usr/bin/env python3
from __future__ import annotations
import json
import sys
from pathlib import Path

EXPECTED = {
    "c": {"UF-C-STR-GETS", "UF-COMMON-HTTP-URL"},
    "cpp": {"UF-C-ENV-SYSTEM", "UF-COMMON-HTTP-URL"},
    "java": {"UF-JAVA-WEAK-HASH", "UF-COMMON-HTTP-URL"},
    "python": {"UF-PY-HASHLIB-NEW-WEAK", "UF-COMMON-HTTP-URL"},
}


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: validate-baseline-output.py LANGUAGE JSON")
    language, path = sys.argv[1], Path(sys.argv[2])
    findings = json.loads(path.read_text(encoding="utf-8"))
    ids = {finding.get("rule_id") for finding in findings}
    missing = EXPECTED[language] - ids
    if missing:
        raise SystemExit(f"{language}: missing baseline findings: {sorted(missing)}; got {sorted(ids)}")
    print(f"{language} baseline smoke ok: {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
