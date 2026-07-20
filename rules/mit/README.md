# UniFlow MIT rule bundle

This directory contains normalized source/sink/sanitizer/summary catalogs for UniFlow's four supported source languages.

| Pack | Upstream inspiration | Scope |
|---|---|---|
| `pysa-python.yml` | Meta Pyre/Pysa | Python and web-framework taint APIs |
| `mariana-java.yml` | Meta Mariana Trench | Java, server, and Android taint APIs |
| `infer-c-cpp.yml` | Meta Infer | C/C++ libc, process, file, network, SQL, and copy APIs |
| `codeql-security.yml` | GitHub CodeQL | Cross-language security API supplement |

The files are loaded automatically by `uniflow-models`. Use:

```bash
uniflow list-rule-packs
uniflow dump-mit-rules --language python
uniflow dump-mit-rules --language java --output java-rules.yml
```

The model bundle is intentionally limited to semantics representable by the current UniFlow rule schema. Unsupported upstream concepts—such as arbitrary access paths, conditional model constraints, higher-order callables, framework-generated entry points, and query-specific control-flow predicates—are not silently approximated as exact equivalents.
