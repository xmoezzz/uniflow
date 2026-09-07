# Legacy rule migration gate

The source of truth for the 280 registered C/C++ checkers is
`rules/migration/anzu-cpp-checkers.json`. The inventory is intentionally kept
separate from executable rule packs: an inventory entry is not treated as an
implemented checker until its original semantics have been reviewed and ported
to pure Rust.

Each entry progresses through these states:

- `pending_source`: registered name is known, but its implementation has not
  yet been inspected;
- `classified`: implementation was inspected and assigned to `frontend` or
  `unified_dataflow`;
- `implemented`: native rule IDs, execution model, and a focused testcase are
  present;
- `verified`: source provenance and Simplified Chinese, English, and
  Traditional Chinese content are also complete;
- `blocked_encrypted`: the exact source asset is known but cannot yet be
  decoded. It must never be silently counted as migrated.

The inventory validator rejects duplicate/missing registrations and rejects an
`implemented` or `verified` entry without a testcase. A `verified` entry also
requires source provenance and all three presentations.

## Asset audit

Copy the legacy package into a readable workspace directory, then run:

```bash
uniflow audit-legacy-rules \
  --input legacy-rules/darwin-arm64 \
  --json-out target/legacy-rule-audit.json
```

The audit is read-only and does not execute legacy binaries. It classifies
Clang/C++ sources, TableGen registries, structured rule files, documentation,
archives, native binaries, opaque assets, and likely encrypted content. Files
with an encryption hint require explicit resolution before their associated
rules can reach `verified`.

Rule text uses this stable order in JSON/SARIF:

1. `zh-CN` — original or reviewed Simplified Chinese;
2. `en` — English;
3. `zh-TW` — reviewed Traditional Chinese.
