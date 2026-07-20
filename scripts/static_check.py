#!/usr/bin/env python3
"""Compiler-independent structural checks for the uniflow workspace.

This catches malformed Cargo manifests, missing workspace/path members, broken
include! paths, dangling attributes at fragment boundaries, and unbalanced Rust
source delimiters. It complements, but never replaces, cargo check and tests.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
CLOSE_TO_OPEN = {value: key for key, value in OPEN_TO_CLOSE.items()}
INCLUDE_RE = re.compile(r'include!\(\s*"([^"]+)"\s*\)')
DANGLING_ATTRIBUTE_RE = re.compile(r"^\s*#\s*!?\[")
DUPLICATE_ELSE_RE = re.compile(r"}\s*else\s*{\s*}\s*else\s*{", re.DOTALL)


def fail(message: str) -> None:
    raise RuntimeError(message)


def load_toml(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except Exception as exc:  # noqa: BLE001 - report exact file context
        fail(f"invalid TOML {path.relative_to(ROOT)}: {exc}")


def check_manifests() -> None:
    root_manifest = load_toml(ROOT / "Cargo.toml")
    members = root_manifest.get("workspace", {}).get("members", [])
    if not members:
        fail("workspace has no members")

    for member in members:
        member_dir = ROOT / member
        manifest_path = member_dir / "Cargo.toml"
        if not member_dir.is_dir():
            fail(f"missing workspace member directory: {member}")
        if not manifest_path.is_file():
            fail(f"missing workspace manifest: {manifest_path.relative_to(ROOT)}")
        manifest = load_toml(manifest_path)
        dependencies = {}
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependencies.update(manifest.get(section, {}))
        for name, spec in dependencies.items():
            if isinstance(spec, dict) and "path" in spec:
                dependency_path = (member_dir / spec["path"]).resolve()
                if not (dependency_path / "Cargo.toml").is_file():
                    fail(
                        f"broken path dependency {name} in "
                        f"{manifest_path.relative_to(ROOT)}: {spec['path']}"
                    )


def raw_string_start(text: str, index: int) -> tuple[int, str] | None:
    start = index
    if text.startswith("br", index):
        index += 2
    elif text.startswith("r", index):
        index += 1
    else:
        return None
    hashes = 0
    while index < len(text) and text[index] == "#":
        hashes += 1
        index += 1
    if index >= len(text) or text[index] != '"':
        return None
    terminator = '"' + ("#" * hashes)
    return index + 1 - start, terminator


def likely_char_literal(text: str, index: int) -> int | None:
    # Lifetimes such as 'a are not character literals. Accept a closing quote
    # only within a small escape-aware window.
    cursor = index + 1
    if cursor >= len(text) or text[cursor] in "\r\n":
        return None
    if text[cursor] == "\\":
        cursor += 2
    else:
        cursor += 1
    if cursor < len(text) and text[cursor] == "'":
        return cursor + 1
    return None


def check_rust_delimiters(path: Path, text: str) -> None:
    stack: list[tuple[str, int]] = []
    index = 0
    block_comment_depth = 0
    while index < len(text):
        if block_comment_depth:
            if text.startswith("/*", index):
                block_comment_depth += 1
                index += 2
            elif text.startswith("*/", index):
                block_comment_depth -= 1
                index += 2
            else:
                index += 1
            continue

        if text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
            continue
        if text.startswith("/*", index):
            block_comment_depth = 1
            index += 2
            continue

        raw = raw_string_start(text, index)
        if raw is not None:
            prefix_length, terminator = raw
            content_start = index + prefix_length
            end = text.find(terminator, content_start)
            if end < 0:
                fail(f"unterminated raw string in {path.relative_to(ROOT)}")
            index = end + len(terminator)
            continue

        if text[index] == '"':
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
            else:
                fail(f"unterminated string in {path.relative_to(ROOT)}")
            continue

        if text[index] == "'":
            char_end = likely_char_literal(text, index)
            if char_end is not None:
                index = char_end
                continue

        char = text[index]
        if char in OPEN_TO_CLOSE:
            stack.append((char, index))
        elif char in CLOSE_TO_OPEN:
            if not stack or stack[-1][0] != CLOSE_TO_OPEN[char]:
                fail(
                    f"unmatched {char!r} in {path.relative_to(ROOT)} "
                    f"at byte {index}"
                )
            stack.pop()
        index += 1

    if block_comment_depth:
        fail(f"unterminated block comment in {path.relative_to(ROOT)}")
    if stack:
        char, position = stack[-1]
        fail(
            f"unclosed {char!r} in {path.relative_to(ROOT)} "
            f"at byte {position}"
        )


def check_rust_sources() -> None:
    rust_files = sorted(ROOT.glob("crates/**/*.rs"))
    if not rust_files:
        fail("no Rust source files found")

    for path in rust_files:
        text = path.read_text(encoding="utf-8")
        check_rust_delimiters(path, text)
        if DUPLICATE_ELSE_RE.search(text):
            fail(f"duplicate else branch in {path.relative_to(ROOT)}")

        for relative in INCLUDE_RE.findall(text):
            included = (path.parent / relative).resolve()
            if not included.is_file():
                fail(
                    f"missing include target from {path.relative_to(ROOT)}: {relative}"
                )
            lines = [line for line in included.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines and DANGLING_ATTRIBUTE_RE.match(lines[-1]):
                fail(
                    f"dangling Rust attribute at end of included fragment: "
                    f"{included.relative_to(ROOT)}"
                )


def check_required_product_files() -> None:
    required = [
        "README.md",
        "ARCHITECTURE.md",
        "LICENSE",
        "rust-toolchain.toml",
        ".github/workflows/ci.yml",
        "scripts/quick-ci.sh",
        "scripts/verify.sh",
        "scripts/verify.ps1",
        "scripts/validate-checker-sdk.sh",
        "scripts/validate-checker-sdk.ps1",
        "scripts/validate-baseline.py",
        "scripts/validate-sarif.py",
        "scripts/parser-fuzz-smoke.py",
        "scripts/run-quality-corpus.py",
        "scripts/performance-budget.py",
        "scripts/package-release.py",
        ".github/workflows/release.yml",
        "rules/baseline/manifest.json",
    ]
    for relative in required:
        if not (ROOT / relative).is_file():
            fail(f"missing product file: {relative}")



def check_release_consistency() -> None:
    root_manifest = load_toml(ROOT / "Cargo.toml")
    package = root_manifest.get("workspace", {}).get("package", {})
    if package.get("version") != "1.0.0":
        fail("workspace version must be 1.0.0")
    if package.get("rust-version") != "1.97":
        fail("workspace rust-version must be 1.97")
    toolchain = load_toml(ROOT / "rust-toolchain.toml")
    if toolchain.get("toolchain", {}).get("channel") != "1.97.1":
        fail("rust-toolchain.toml must pin 1.97.1")
    forbidden = ("1." + "90.0", "version 0.1.0", "version 0.2.0")
    for path in list(ROOT.glob("*.md")) + list((ROOT / "scripts").glob("*")):
        if path.resolve() == Path(__file__).resolve():
            continue
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in forbidden:
            if token in text:
                fail(f"stale release token {token!r} in {path.relative_to(ROOT)}")
    for path in ROOT.glob("crates/**/*.rs"):
        text = path.read_text(encoding="utf-8")
        if 'cfg(feature = "experimental-python-semantics")' in text or 'cfg(feature = "experimental-advanced-value-flow")' in text:
            fail(f"semantic test remains feature-gated: {path.relative_to(ROOT)}")



def check_cargo_source_configuration() -> None:
    config_path = ROOT / ".cargo" / "config.toml"
    if not config_path.is_file():
        return
    config = load_toml(config_path)
    sources = config.get("source", {})
    crates_io = sources.get("crates-io", {})
    if isinstance(crates_io, dict) and crates_io.get("replace-with"):
        fail(".cargo/config.toml must not replace crates.io")
    if any("artifactory" in str(name).lower() for name in sources):
        fail(".cargo/config.toml must not enable an Artifactory source")
    registries = config.get("registries", {})
    if any("artifactory" in str(name).lower() for name in registries):
        fail(".cargo/config.toml must not enable an Artifactory registry")

def check_baseline_catalog() -> None:
    base = ROOT / "rules" / "baseline"
    manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
    packs = manifest.get("packs", [])
    files = {entry["file"] for entry in packs}
    if len(files) != 4 or len(packs) != 4:
        fail("baseline manifest must contain four unique packs")
    expected = manifest.get("rule_count")
    if not isinstance(expected, int) or expected <= 0:
        fail("baseline manifest must declare a positive rule_count")
    ids: set[str] = set()
    count = 0
    rule_re = re.compile(r"^\s*-\s+id:\s*([^\s#]+)\s*$", re.MULTILINE)
    for entry in packs:
        filename = entry["file"]
        path = base / filename
        if not path.is_file():
            fail(f"missing baseline pack: {path.relative_to(ROOT)}")
        found = rule_re.findall(path.read_text(encoding="utf-8"))
        if entry.get("rule_count") != len(found):
            fail(f"baseline pack {filename} count does not match manifest")
        for rule_id in found:
            if rule_id in ids:
                fail(f"duplicate baseline rule id: {rule_id}")
            ids.add(rule_id)
            count += 1
    if count != expected:
        fail(f"baseline catalog must contain {expected} rules, found {count}")
    extras = {path.name for path in base.glob("*.yml")} - files
    if extras:
        fail(f"unlisted baseline packs: {sorted(extras)}")



def check_json_and_model_catalog() -> None:
    for path in sorted(ROOT.rglob("*.json")):
        if "target" in path.parts:
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    manifest = json.loads((ROOT / "rules" / "mit" / "manifest.json").read_text(encoding="utf-8"))
    total = 0
    for pack in manifest.get("packs", []):
        path = ROOT / "rules" / "mit" / pack["file"]
        if not path.is_file():
            fail(f"missing MIT model pack: {path.relative_to(ROOT)}")
        total += sum(int(value) for value in pack.get("counts", {}).values())
    if total != 275:
        fail(f"MIT model manifest must describe 275 models, found {total}")


def check_python_scripts() -> None:
    for path in sorted((ROOT / "scripts").glob("*.py")):
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            fail(f"invalid Python script {path.relative_to(ROOT)}: {exc}")


def main() -> int:
    try:
        check_manifests()
        check_rust_sources()
        check_required_product_files()
        check_release_consistency()
        check_cargo_source_configuration()
        check_baseline_catalog()
        check_json_and_model_catalog()
        check_python_scripts()
    except RuntimeError as exc:
        print(f"static check failed: {exc}", file=sys.stderr)
        return 1
    print("static check ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
