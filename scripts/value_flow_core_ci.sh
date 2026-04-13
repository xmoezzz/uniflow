#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

cargo test -p uniflow-value-flow --lib --no-fail-fast
cargo test -p uniflow-value-flow --lib object_graph_materializes_labels_and_shapes -- --nocapture
cargo test -p uniflow-value-flow --lib interprocedural_call_summary_materializes_internal_return_edges -- --nocapture
cargo test -p uniflow-value-flow --lib contextual_demand_query_cache_reuses_call_context -- --nocapture
