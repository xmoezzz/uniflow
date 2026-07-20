# Platform profile example

`demo.c` contains mutually exclusive Windows and Unix source branches. Analyze
it under both closed-world profiles:

```bash
cargo run --locked -p uniflow-cli --bin uniflow -- \
  analyze-source --language c --platform windows-x86_64-msvc \
  --input examples/platform_profiles/demo.c --dump-hir

cargo run --locked -p uniflow-cli --bin uniflow -- \
  analyze-source --language c --platform linux-x86_64-gnu \
  --input examples/platform_profiles/demo.c --dump-hir
```

The selected branch remains at its original offsets; the impossible branch and
preprocessor control lines are replaced with layout-preserving whitespace before
the self-developed C frontend parses the file.
