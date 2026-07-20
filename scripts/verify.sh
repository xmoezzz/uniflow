#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
TIMEOUT_RUNNER=("$PYTHON_BIN" scripts/run_with_timeout.py)
VALIDATION_DIR="target/uniflow-validation"
SMOKE_DIR="$VALIDATION_DIR/smoke"
DIST_DIR="dist"
rm -rf "$VALIDATION_DIR" "$DIST_DIR"
mkdir -p "$SMOKE_DIR"

cargo fmt --all -- --check
"$PYTHON_BIN" scripts/static_check.py
"$PYTHON_BIN" scripts/validate-baseline.py
cargo check --locked --workspace --all-targets --all-features
"${TIMEOUT_RUNNER[@]}" 90 cargo test --locked -p uniflow-value-flow contextual_function_heap_effect_summary_carries_context_metadata -- --nocapture
"${TIMEOUT_RUNNER[@]}" 1200 cargo test --locked --workspace --all-features --no-fail-fast
cargo build --locked --release -p uniflow-cli --bin uniflow

BIN="target/release/uniflow"
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* || "$(uname -s)" == CYGWIN* ]]; then
  BIN="target/release/uniflow.exe"
fi

"$BIN" --version > "$SMOKE_DIR/version.txt"
grep -q '^uniflow 1\.0\.0$' "$SMOKE_DIR/version.txt"

"$BIN" analyze-source --language c --input examples/smoke/command_flow.c \
  --use-default-models --pretty-findings \
  --sarif-out "$SMOKE_DIR/c.sarif.json" --dot-out "$SMOKE_DIR/c.dot" \
  --markdown-out "$SMOKE_DIR/c.md" > "$SMOKE_DIR/c.txt"
grep -q 'source_rule: c-getenv' "$SMOKE_DIR/c.txt"
grep -q 'sink_rule: c-system' "$SMOKE_DIR/c.txt"
test "$(grep -c '^finding ' "$SMOKE_DIR/c.txt")" -eq 1
grep -q '^digraph uniflow {' "$SMOKE_DIR/c.dot"
grep -q 'Source rule: `c-getenv`' "$SMOKE_DIR/c.md"

"$BIN" analyze-source --language cpp --input examples/smoke/command_flow.cpp \
  --use-default-models --pretty-findings > "$SMOKE_DIR/cpp.txt"
grep -q 'source_rule: c-getenv' "$SMOKE_DIR/cpp.txt"
grep -q 'sink_rule: c-system' "$SMOKE_DIR/cpp.txt"
test "$(grep -c '^finding ' "$SMOKE_DIR/cpp.txt")" -eq 1

"$BIN" analyze-project --language java --input examples/smoke/java_project \
  --use-default-models --pretty-findings > "$SMOKE_DIR/java.txt"
grep -q 'source_rule: java-http-request-param' "$SMOKE_DIR/java.txt"
grep -q 'sink_rule: java-sql-statement-executequery' "$SMOKE_DIR/java.txt"
test "$(grep -c '^finding ' "$SMOKE_DIR/java.txt")" -eq 1

"$BIN" analyze-project --language python --input examples/smoke/python_project \
  --use-default-models --cache-out "$SMOKE_DIR/python-cache.json" \
  --pretty-findings > "$SMOKE_DIR/python.txt"
grep -q 'source_rule: python-os-getenv' "$SMOKE_DIR/python.txt"
grep -q 'sink_rule: python-os-system' "$SMOKE_DIR/python.txt"
test "$(grep -c '^finding ' "$SMOKE_DIR/python.txt")" -eq 1

"$BIN" analyze-project --language python --input examples/smoke/python_project \
  --use-default-models --cache-in "$SMOKE_DIR/python-cache.json" \
  --dump-cache-plan --pretty-findings > "$SMOKE_DIR/python-cached.txt"
grep -q '"reused": \[' "$SMOKE_DIR/python-cached.txt"
grep -q 'app.py' "$SMOKE_DIR/python-cached.txt"
test "$(grep -c '^finding ' "$SMOKE_DIR/python-cached.txt")" -eq 1

"$BIN" analyze-source --language c --platform windows-x86_64-msvc \
  --input examples/platform_profiles/demo.c --use-default-models --dump-hir \
  --pretty-findings > "$SMOKE_DIR/platform-windows.txt"
grep -q 'COMSPEC' "$SMOKE_DIR/platform-windows.txt"
! grep -q 'SHELL' "$SMOKE_DIR/platform-windows.txt"

"$BIN" analyze-source --language c --platform linux-x86_64-gnu \
  --input examples/platform_profiles/demo.c --use-default-models --dump-hir \
  --pretty-findings > "$SMOKE_DIR/platform-linux.txt"
grep -q 'SHELL' "$SMOKE_DIR/platform-linux.txt"
! grep -q 'COMSPEC' "$SMOKE_DIR/platform-linux.txt"

"$BIN" list-rule-packs > "$SMOKE_DIR/model-manifest.json"
"$BIN" list-baseline-packs > "$SMOKE_DIR/baseline-manifest.json"
"$BIN" dump-mit-rules --language python --output "$SMOKE_DIR/python-mit-rules.yml"
"$BIN" check-rules --rules "$SMOKE_DIR/python-mit-rules.yml"

for language in c cpp java python; do
  "$BIN" check-baseline --language "$language" \
    --input "examples/baseline_smoke/$language" \
    --json-out "$SMOKE_DIR/baseline-$language.json"
  "$PYTHON_BIN" scripts/validate-baseline-output.py "$language" \
    "$SMOKE_DIR/baseline-$language.json"
done

"$PYTHON_BIN" scripts/validate-sarif.py "$SMOKE_DIR/c.sarif.json"
"$PYTHON_BIN" scripts/parser-fuzz-smoke.py --bin "$BIN" --timeout 10
"$PYTHON_BIN" scripts/run-quality-corpus.py --bin "$BIN" --output "$VALIDATION_DIR/quality-corpus.json"
"$PYTHON_BIN" scripts/performance-budget.py --bin "$BIN" --output "$VALIDATION_DIR/performance.json"
./scripts/validate-checker-sdk.sh
"$PYTHON_BIN" scripts/validate-sarif.py target/checker-sdk-validation/*.sarif

HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
"$PYTHON_BIN" - "$VALIDATION_DIR/validation-summary.json" "$HOST_TARGET" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "product": "uniflow",
    "version": "1.0.0",
    "rust_toolchain": "1.97.1",
    "host_target": sys.argv[2],
    "status": "passed",
    "gates": [
        "format", "static", "all-targets-all-features-check", "workspace-tests",
        "release-build", "four-language-smoke", "cache", "platform-profiles",
        "baseline-200", "sarif", "checker-sdk-rust-c-cpp", "parser-mutation",
        "quality-corpus", "performance-memory-budget"
    ]
}, indent=2) + "\n", encoding="utf-8")
PY
"$PYTHON_BIN" scripts/package-release.py --bin "$BIN" --target "$HOST_TARGET" --out-dir "$DIST_DIR"

echo "verification ok"
