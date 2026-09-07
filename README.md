# UniFlow

UniFlow is a source-only multi-language value-flow, taint, and security-baseline analyzer written entirely in Rust. It uses project-owned frontends and does not require the analyzed project to compile.

```text
source -> language frontend -> unified HIR -> analysis IR
       -> value flow -> taint/baseline/checkers -> JSON/SARIF/DOT/Markdown
```

## Product surface

UniFlow 1.0.0 includes:

- source frontends and project indexing for C, C++, C#, Java, Python, Objective-C, Objective-C++, Kotlin, Go, JavaScript/TypeScript, JSP, SQL, PHP, Ruby, Rust, Shell, and Swift;
- unified HIR and analysis IR lowering;
- assignment, call-port, field/index, object/heap, contextual-summary, callback, and modeled API value-flow behavior covered by the default test suite;
- source, sink, sanitizer, propagator, and summary rules, including built-in models for every supported frontend;
- 275 MIT-derived API models with attribution under `THIRD_PARTY_NOTICES.md`;
- 200 direct baseline rules mapped to relevant CERT, CWE, and OWASP identifiers;
- terminal JSON, SARIF, DOT, and Markdown output;
- platform-aware project caching and source-visible platform profiles;
- two checker classes: frontend source/HIR coding-style checkers and unified-dataflow checkers that consume IR, calls, flow summaries, and taint findings;
- native Rust, C, and C++ checker plugins through ABI v2, with ABI v1 compatibility;
- process-isolated checker execution with timeouts, crash containment, validation, diagnostics, and optional continue-on-error behavior.

The analyzer is intentionally source-only. It does not claim compiler-equivalent macro expansion, full C++ template instantiation, bytecode generation, linking, or ABI validation. Unsupported or damaged syntax is recovered conservatively into explicit opaque HIR nodes so analysis can continue without inventing a precise meaning.

## Build and verify

The repository pins Rust 1.97.1 as its minimum supported version.

```bash
cargo build --locked --workspace
./scripts/verify.sh
```

Windows PowerShell:

```powershell
./scripts/verify.ps1
```


## Analyze source or a project

```bash
uniflow analyze-source \
  --language c \
  --platform linux-x86_64-gnu \
  --input examples/smoke/command_flow.c \
  --use-default-models \
  --pretty-findings \
  --sarif-out findings.sarif

uniflow analyze-project \
  --language python \
  --input examples/smoke/python_project \
  --use-default-models \
  --cache-out target/python-cache.json \
  --pretty-findings
```

Supported profiles are `generic`, `linux-x86_64-gnu`, `windows-x86_64-msvc`, and `macos-aarch64`. The generic profile is open-world; named profiles remove source branches known to be impossible for that target.

Language names accepted by `--language` are `c`, `cpp`, `csharp`, `objc`, `objcpp`, `java`, `kotlin`, `swift`, `python`, `go`, `javascript`, `jsp`, `sql`, `php`, `ruby`, `rust`, and `shell`. Common aliases such as `cs`, `objective-c`, `objective-cpp`, `golang`, `js`, and `sh` are also accepted.

## Rules and baseline checks

```bash
uniflow list-rule-packs
uniflow dump-mit-rules --language python --output python-models.yml
uniflow check-rules --rules custom-rules.yml

uniflow list-baseline-packs
uniflow check-baseline --language c --input src/
uniflow check-baseline --language python --input app/ --json-out baseline.json
```

Baseline findings are candidate defects, not a certification of full CERT/CWE/OWASP conformance. Each rule has a regression obligation and the complete built-in catalog is validated as one merged pack.

## Checker plugins

Checkers may be written in Rust, C, or C++. A manifest declares either `frontend` for coding-style/local HIR checks or `unified_dataflow` for clang-like semantic checks over the common analysis pipeline. New plugins export ABI v2; existing ABI v1 plugins remain supported. Checkers run in worker processes by default.

```bash
uniflow analyze-source \
  --language c \
  --input examples/checker_demo/demo.c \
  --checker path/to/libchecker.so \
  --checker-timeout-ms 5000 \
  --checker-isolation process \
  --checker-failure continue \
  --sarif-out checker-results.sarif
```

Use `--checker` repeatedly to load several plugins. `--checker-isolation in-process` is available only for explicitly trusted plugins. See `docs/CHECKER_SDK.md`, `include/uniflow_checker_v1.h`, and `examples/checkers/`.

```bash
./scripts/validate-checker-sdk.sh
```

Windows release validation uses:

```powershell
./scripts/validate-checker-sdk.ps1
```
