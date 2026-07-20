#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cargo fmt --all -- --check
"$PYTHON_BIN" scripts/static_check.py
"$PYTHON_BIN" scripts/validate-baseline.py
cargo check --locked --workspace
"$PYTHON_BIN" scripts/run_with_timeout.py 300 \
  cargo test --locked \
    -p uniflow-baseline \
    -p uniflow-checker-api \
    -p uniflow-rules \
    --lib --tests --no-fail-fast

echo "quick CI gate ok"
