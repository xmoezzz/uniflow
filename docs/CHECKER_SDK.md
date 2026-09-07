# UniFlow native checker SDK

UniFlow loads independently compiled Rust, C, and C++ checker libraries. ABI v2 is current; ABI v1 remains compatible.

## ABI v2

A checker exports `uniflow_checker_entry_v2` and returns a static `uniflow_checker_v2` table containing:

- `abi_version = 2`;
- `struct_size = sizeof(uniflow_checker_v2)`;
- `UNIFLOW_CHECKER_CAPABILITY_JSON_EVENTS`;
- non-null manifest, create, event, destroy, and string-free callbacks.

The manifest and event protocol are UTF-8 JSON. Strings returned by a checker must be allocated by the checker and released by its `free_string` callback. The manifest ID must be nonempty and contain only ASCII alphanumeric characters, `.`, `_`, or `-`. Event subscriptions must not contain duplicates.

The optional manifest field `kind` declares the checker execution model:

- `frontend` subscribes to `analysis_start`, one `source_file` event per input, `hir_program`, and `analysis_end` for coding-style and local source/HIR checks;
- `unified_dataflow` (the backward-compatible default) may also subscribe to `ir_program`, `flow_summary`, `call`, and `taint_finding` for clang-style semantic and interprocedural checks.

The host rejects unknown event names and rejects a frontend checker that requests dataflow-only events. Both kinds return the same validated finding format and feed the same JSON/SARIF reporting pipeline.

Production checkers should declare every implemented rule in the optional `rules` array. Each rule contains a stable local `id`, a nonempty `title`, and optional `description`, `tags`, `help_uri`, custom `properties`, and `default_level` (`error`, `warning`, `note`, or `none`). Once a checker declares at least one rule, the host rejects findings for undeclared rule IDs. Manifests without `rules` remain accepted for ABI v1 and existing plugins.

```json
{
  "id": "company.security",
  "kind": "unified_dataflow",
  "rules": [{
    "id": "sql-injection",
    "title": "SQL injection",
    "default_level": "error",
    "tags": ["security", "cwe-89"],
    "help_uri": "https://example.invalid/rules/sql-injection"
  }]
}
```

Each `source_file` payload is `{ "path": string, "language": string, "source": string }`. It contains the original file text, including JSP/PHP host markup, rather than the parser's layout-preserving embedded-code view.

The host validates every finding: declared rule ID when a rule catalog is present, message, level, URI, one-based line/column, related locations, and code-flow locations. It prefixes local rule IDs with the checker ID, records checker metadata, computes a stable fingerprint when absent, and deduplicates identical findings.

## Isolation and failures

The default `process` mode starts one worker process per checker. It contains checker panic/abort, segmentation faults, and hangs. `--checker-timeout-ms` applies to worker startup and each event. `--checker-failure fail-fast` stops analysis on checker failure; `continue` disables the failed checker, records a diagnostic, and continues with healthy checkers.

`--checker-isolation in-process` avoids IPC but treats the library as fully trusted; a native crash can terminate UniFlow.

## Rust

Implement `uniflow_checker_api::Checker`, derive or implement `Default`, and invoke `uniflow_checker_api::export_checker!(YourChecker)`. The macro exports ABI v2 and v1 entry points and catches Rust panics at callbacks.

See `examples/checkers/banned_function_checker` for a unified-dataflow checker and `examples/checkers/style_checker` for a frontend source-style checker.

## C and C++

Include `include/uniflow_checker_v1.h`, implement the callbacks, define a static ABI table, and export the v2 entry point. C and C++ examples are under `examples/checkers/c_banned_function_checker` and `examples/checkers/cpp_banned_function_checker`.

## Validation

```bash
./scripts/validate-checker-sdk.sh
```

The validator builds Rust/C/C++ plugins, exercises ABI v1/v2, checks SARIF integration and deduplication, and verifies missing symbols, null/truncated tables, wrong ABI, missing capabilities/callbacks, malformed manifests/responses/findings, duplicate checker IDs, explicit checker errors, hangs, crashes, and continue-on-error behavior.
