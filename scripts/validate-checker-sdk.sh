#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULT_DIR="$ROOT/target/checker-sdk-validation"
BUILD_DIR="$RESULT_DIR/plugins"
PLUGIN_MANIFEST="$ROOT/examples/checkers/banned_function_checker/Cargo.toml"
PLUGIN_TARGET="$ROOT/examples/checkers/banned_function_checker/target/debug"
mkdir -p "$BUILD_DIR"
rm -f "$RESULT_DIR"/*.out "$RESULT_DIR"/*.err "$RESULT_DIR"/*.sarif 2>/dev/null || true
cd "$ROOT"

find_compiler() {
  local requested="$1"
  shift
  if [[ -n "$requested" ]] && command -v "$requested" >/dev/null 2>&1; then
    printf '%s\n' "$requested"
    return
  fi
  local candidate
  for candidate in "$@"; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "required compiler not found: $*" >&2
  exit 1
}

CC_BIN="$(find_compiler "${CC:-}" cc clang gcc)"
CXX_BIN="$(find_compiler "${CXX:-}" c++ clang++ g++)"

case "$(uname -s)" in
  Linux*)
    EXT="so"
    PREFIX="lib"
    SHARED_FLAGS=(-shared -fPIC)
    RUST_PLUGIN="$PLUGIN_TARGET/libuniflow_example_banned_function_checker.so"
    BIN="$ROOT/target/debug/uniflow"
    ;;
  Darwin*)
    EXT="dylib"
    PREFIX="lib"
    SHARED_FLAGS=(-dynamiclib -fPIC)
    RUST_PLUGIN="$PLUGIN_TARGET/libuniflow_example_banned_function_checker.dylib"
    BIN="$ROOT/target/debug/uniflow"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    EXT="dll"
    PREFIX=""
    SHARED_FLAGS=(-shared)
    RUST_PLUGIN="$PLUGIN_TARGET/uniflow_example_banned_function_checker.dll"
    BIN="$ROOT/target/debug/uniflow.exe"
    ;;
  *)
    echo "unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

shared_path() {
  printf '%s/%s%s.%s\n' "$BUILD_DIR" "$PREFIX" "$1" "$EXT"
}

compile_c() {
  local output="$1"
  shift
  "$CC_BIN" -std=c11 -Wall -Wextra -Werror "${SHARED_FLAGS[@]}" -I"$ROOT/include" "$@" -o "$output"
}

compile_cpp() {
  local output="$1"
  shift
  "$CXX_BIN" -std=c++17 -Wall -Wextra -Werror "${SHARED_FLAGS[@]}" -I"$ROOT/include" "$@" -o "$output"
}

compile_fixture() {
  local name="$1"
  local macro="$2"
  local output
  output="$(shared_path "$name")"
  compile_c "$output" -D"$macro" "$ROOT/examples/checkers/fixtures/checker_fixture.c"
  printf '%s\n' "$output"
}

cargo build --locked -p uniflow-cli --bin uniflow
cargo build --manifest-path "$PLUGIN_MANIFEST"

C_PLUGIN="$(shared_path c_banned_checker)"
CPP_PLUGIN="$(shared_path cpp_banned_checker)"
C_V1_PLUGIN="$(shared_path c_v1_checker)"
MISSING_SYMBOL_PLUGIN="$(shared_path missing_symbol)"
compile_c "$C_PLUGIN" "$ROOT/examples/checkers/c_banned_function_checker/checker.c"
compile_cpp "$CPP_PLUGIN" "$ROOT/examples/checkers/cpp_banned_function_checker/checker.cpp"
compile_c "$C_V1_PLUGIN" -DCHECKER_V1_ONLY "$ROOT/examples/checkers/c_banned_function_checker/checker.c"
compile_c "$MISSING_SYMBOL_PLUGIN" "$ROOT/examples/checkers/fixtures/missing_symbol.c"

NULL_TABLE_PLUGIN="$(compile_fixture null_table FIXTURE_NULL_TABLE)"
WRONG_ABI_PLUGIN="$(compile_fixture wrong_abi FIXTURE_WRONG_ABI)"
TRUNCATED_PLUGIN="$(compile_fixture truncated FIXTURE_TRUNCATED_TABLE)"
NO_CAPABILITY_PLUGIN="$(compile_fixture no_capability FIXTURE_NO_CAPABILITY)"
NULL_CALLBACK_PLUGIN="$(compile_fixture null_callback FIXTURE_NULL_CALLBACK)"
INVALID_MANIFEST_PLUGIN="$(compile_fixture invalid_manifest FIXTURE_INVALID_MANIFEST)"
WRONG_MANIFEST_ABI_PLUGIN="$(compile_fixture wrong_manifest_abi FIXTURE_WRONG_MANIFEST_ABI)"
EMPTY_ID_PLUGIN="$(compile_fixture empty_id FIXTURE_EMPTY_ID)"
DUPLICATE_ID_PLUGIN="$(compile_fixture duplicate_id FIXTURE_DUPLICATE_ID)"
INVALID_RESPONSE_PLUGIN="$(compile_fixture invalid_response FIXTURE_INVALID_RESPONSE)"
ERROR_RESPONSE_PLUGIN="$(compile_fixture error_response FIXTURE_ERROR_RESPONSE)"
INVALID_FINDING_PLUGIN="$(compile_fixture invalid_finding FIXTURE_INVALID_FINDING)"
HANG_PLUGIN="$(compile_fixture hang FIXTURE_HANG)"
CRASH_PLUGIN="$(compile_fixture crash FIXTURE_CRASH)"

run_checker() {
  local name="$1"
  shift
  "$BIN" analyze-source \
    --language c \
    --input examples/checker_demo/demo.c \
    --checker-timeout-ms 750 \
    --checker-isolation process \
    "$@" \
    --sarif-out "$RESULT_DIR/$name.sarif" \
    >"$RESULT_DIR/$name.out" 2>"$RESULT_DIR/$name.err"
}

run_checker rust --checker "$RUST_PLUGIN"
run_checker c --checker "$C_PLUGIN"
run_checker cpp --checker "$CPP_PLUGIN"
run_checker c-v1 --checker "$C_V1_PLUGIN"
run_checker combined --checker "$RUST_PLUGIN" --checker "$C_PLUGIN" --checker "$CPP_PLUGIN"

python3 - "$RESULT_DIR" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected = {
    "rust": {"example.banned-function.dangerous-call": 1},
    "c": {"example.c-banned-function.dangerous-call": 1},
    "cpp": {"example.cpp-banned-function.dangerous-call": 1},
    "c-v1": {"example.c-banned-function.dangerous-call": 1},
    "combined": {
        "example.banned-function.dangerous-call": 1,
        "example.c-banned-function.dangerous-call": 1,
        "example.cpp-banned-function.dangerous-call": 1,
    },
}
for name, rules in expected.items():
    data = json.loads((root / f"{name}.sarif").read_text(encoding="utf-8"))
    results = data["runs"][0].get("results", [])
    counts = {}
    for result in results:
        rule = result.get("ruleId")
        counts[rule] = counts.get(rule, 0) + 1
        assert result.get("partialFingerprints", {}).get("uniflow/v1"), (name, rule, "fingerprint")
        assert result.get("locations"), (name, rule, "location")
    for rule, count in rules.items():
        assert counts.get(rule) == count, (name, rule, counts)
print("valid Rust/C/C++ ABI v1/v2 checkers PASS")
PY

expect_fail() {
  local name="$1"
  local plugin="$2"
  local expected="$3"
  if run_checker "negative-$name" --checker "$plugin"; then
    echo "negative checker fixture unexpectedly succeeded: $name" >&2
    exit 1
  fi
  if ! grep -Eqi "$expected" "$RESULT_DIR/negative-$name.err"; then
    echo "negative checker fixture did not report expected diagnostic: $name / $expected" >&2
    cat "$RESULT_DIR/negative-$name.err" >&2
    exit 1
  fi
}

expect_fail missing-symbol "$MISSING_SYMBOL_PLUGIN" 'exports neither|entry_v2|entry_v1'
expect_fail null-table "$NULL_TABLE_PLUGIN" 'null ABI v2 table'
expect_fail wrong-abi "$WRONG_ABI_PLUGIN" 'v2 entry returned ABI'
expect_fail truncated "$TRUNCATED_PLUGIN" 'truncated'
expect_fail no-capability "$NO_CAPABILITY_PLUGIN" 'JSON event support'
expect_fail null-callback "$NULL_CALLBACK_PLUGIN" 'null manifest_json callback'
expect_fail invalid-manifest "$INVALID_MANIFEST_PLUGIN" 'manifest is not valid|invalid manifest'
expect_fail wrong-manifest-abi "$WRONG_MANIFEST_ABI_PLUGIN" 'manifest declares ABI'
expect_fail empty-id "$EMPTY_ID_PLUGIN" 'empty id'
expect_fail invalid-response "$INVALID_RESPONSE_PLUGIN" 'not valid CheckerResponse|invalid response|worker.*failed'
expect_fail error-response "$ERROR_RESPONSE_PLUGIN" 'fixture failure|worker.*failed'
expect_fail invalid-finding "$INVALID_FINDING_PLUGIN" 'invalid finding|empty rule id'
expect_fail hang "$HANG_PLUGIN" 'timeout|exceeded'
expect_fail crash "$CRASH_PLUGIN" 'terminated without a response|worker.*failed'

if run_checker negative-duplicate --checker "$C_PLUGIN" --checker "$DUPLICATE_ID_PLUGIN"; then
  echo "duplicate checker ID unexpectedly succeeded" >&2
  exit 1
fi
grep -Eqi 'duplicate checker id' "$RESULT_DIR/negative-duplicate.err"

"$BIN" analyze-source \
  --language c \
  --input examples/checker_demo/demo.c \
  --checker "$RUST_PLUGIN" \
  --checker "$INVALID_RESPONSE_PLUGIN" \
  --checker-timeout-ms 750 \
  --checker-isolation process \
  --checker-failure continue \
  --sarif-out "$RESULT_DIR/continue.sarif" \
  >"$RESULT_DIR/continue.out" 2>"$RESULT_DIR/continue.err"
grep -q 'checker diagnostic:' "$RESULT_DIR/continue.err"
python3 - "$RESULT_DIR/continue.sarif" <<'PY'
import json, sys
results = json.load(open(sys.argv[1], encoding="utf-8"))["runs"][0].get("results", [])
assert any(r.get("ruleId") == "example.banned-function.dangerous-call" for r in results)
print("continue-on-checker-error PASS")
PY

echo "checker SDK validation ok"
