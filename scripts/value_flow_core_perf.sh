#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

TIME_BIN="${TIME_BIN:-/usr/bin/time}"
if [[ ! -x "$TIME_BIN" ]]; then
  TIME_BIN=time
fi

run_case() {
  local label="$1"
  shift
  echo "== $label =="
  "$TIME_BIN" -f 'elapsed=%E rss_kb=%M' "$@"
}

run_case "value-flow full test suite (release)" \
  cargo test -p uniflow-value-flow --release --lib --no-fail-fast

run_case "contextual query cache smoke" \
  cargo test -p uniflow-value-flow --release --lib contextual_demand_query_cache_reuses_call_context -- --nocapture

run_case "interprocedural summary smoke" \
  cargo test -p uniflow-value-flow --release --lib interprocedural_call_summary_materializes_internal_return_edges -- --nocapture
