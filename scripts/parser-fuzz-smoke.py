#!/usr/bin/env python3
"""Deterministic mutation smoke test for all source frontends.

Malformed input may be rejected, but UniFlow must not panic, abort, or hang.
"""
from __future__ import annotations
import argparse
import subprocess
import tempfile
from pathlib import Path

SEEDS = {
    "c": ("c", "int main(void) { char b[8]; gets(b); return 0; }\n"),
    "cpp": ("cpp", "int main() { auto x = 1; return x; }\n"),
    "java": ("java", "class Main { public static void main(String[] a) { System.out.println(1); } }\n"),
    "python": ("py", "def main(x):\n    return eval(x)\n"),
}
MUTATIONS = (
    lambda s: s,
    lambda s: "/* leading */\n" + s,
    lambda s: s + "\n// trailing delimiters {[(\n",
    lambda s: s.replace("(", "((", 1),
    lambda s: s.replace("{", "{{", 1),
    lambda s: s[: max(1, len(s) // 2)],
    lambda s: s.replace(";", ";;;;;"),
    lambda s: s.replace(" ", "\t"),
    lambda s: "#" * 128 + "\n" + s,
    lambda s: s + "\n" + ("x" * 4096),
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    binary = Path(args.bin).resolve()
    if not binary.is_file():
        raise SystemExit(f"missing UniFlow binary: {binary}")
    executed = 0
    with tempfile.TemporaryDirectory(prefix="uniflow-fuzz-") as directory:
        root = Path(directory)
        for language, (extension, seed) in SEEDS.items():
            for index, mutate in enumerate(MUTATIONS):
                path = root / f"{language}-{index}.{extension}"
                path.write_text(mutate(seed), encoding="utf-8")
                try:
                    result = subprocess.run(
                        [str(binary), "analyze-source", "--language", language, "--input", str(path)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=args.timeout,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    raise SystemExit(f"frontend hang: {language} mutation {index}")
                if result.returncode < 0 or result.returncode == 101:
                    raise SystemExit(
                        f"frontend crash/panic: {language} mutation {index}, exit {result.returncode}"
                    )
                executed += 1
    print(f"parser mutation smoke ok: {executed} inputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
