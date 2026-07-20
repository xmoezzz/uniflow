#!/usr/bin/env python3
"""Run the curated baseline corpus and report exact micro precision/recall."""
from __future__ import annotations
import argparse
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    binary = Path(args.bin).resolve()
    corpus = ROOT / "tests" / "quality_corpus"
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    tp = fp = fn = 0
    details = []
    with tempfile.TemporaryDirectory(prefix="uniflow-quality-") as temporary:
        for index, case in enumerate(manifest["cases"]):
            output = Path(temporary) / f"{index}.json"
            completed = subprocess.run(
                [str(binary), "check-baseline", "--language", case["language"], "--input", str(corpus / case["file"]), "--json-out", str(output)],
                capture_output=True, text=True, check=False, timeout=30,
            )
            if completed.returncode != 0:
                raise SystemExit(f"quality case {case['file']} failed: {completed.stderr}")
            actual = {item["rule_id"] for item in json.loads(output.read_text(encoding="utf-8"))}
            expected = set(case["expected"])
            case_tp = len(actual & expected)
            case_fp = len(actual - expected)
            case_fn = len(expected - actual)
            tp += case_tp; fp += case_fp; fn += case_fn
            details.append({"file": case["file"], "language": case["language"], "expected": sorted(expected), "actual": sorted(actual), "tp": case_tp, "fp": case_fp, "fn": case_fn})
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    report = {"cases": len(details), "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "details": details}
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(f"quality corpus: precision={precision:.3f} recall={recall:.3f} tp={tp} fp={fp} fn={fn}")
    if fp or fn:
        print(text)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
