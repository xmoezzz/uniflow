#!/usr/bin/env python3
"""Create a reproducible UniFlow binary archive and SHA-256 checksum."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_tree_file(stage: Path, relative: str) -> None:
    src = ROOT / relative
    dst = stage / relative
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out-dir", default="dist")
    parser.add_argument("--format", choices=("tar.gz", "zip"))
    args = parser.parse_args()
    binary = Path(args.bin).resolve()
    if not binary.is_file():
        raise SystemExit(f"missing release binary: {binary}")
    out_dir = (ROOT / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    archive_format = args.format or ("zip" if binary.suffix.lower() == ".exe" else "tar.gz")
    base_name = f"uniflow-{VERSION}-{args.target}"
    archive = out_dir / f"{base_name}.{archive_format}"
    with tempfile.TemporaryDirectory(prefix="uniflow-package-") as tmp:
        stage_root = Path(tmp) / base_name
        stage_root.mkdir()
        shutil.copy2(binary, stage_root / binary.name)
        for relative in (
            "README.md",
            "LICENSE",
            "CHANGELOG.md",
            "RELEASE_NOTES_1.0.0.md",
            "THIRD_PARTY_NOTICES.md",
            "THIRD_PARTY_LICENSES",
            "include",
            "rules",
            "docs/CHECKER_SDK.md",
        ):
            copy_tree_file(stage_root, relative)
        status = ROOT / "target" / "uniflow-validation" / "validation-summary.json"
        if status.is_file():
            dst = stage_root / "validation-summary.json"
            shutil.copy2(status, dst)
        if archive_format == "zip":
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
                for path in sorted(stage_root.rglob("*")):
                    if path.is_file():
                        output.write(path, path.relative_to(stage_root.parent))
        else:
            with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as output:
                output.add(stage_root, arcname=base_name, recursive=True)
    checksum = sha256(archive)
    checksum_path = Path(str(archive) + ".sha256")
    checksum_path.write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
    manifest = {
        "product": "uniflow",
        "version": VERSION,
        "target": args.target,
        "archive": archive.name,
        "sha256": checksum,
    }
    Path(str(archive) + ".json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(archive)
    print(checksum_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
