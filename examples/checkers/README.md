# Checker SDK examples

- `banned_function_checker`: Rust unified-dataflow `cdylib` checker with declared rule metadata, exported through ABI v2 and v1.
- `style_checker`: Rust frontend checker with declared rule metadata, consuming original `source_file` events.
- `c_banned_function_checker`: freestanding C checker using the public header.
- `cpp_banned_function_checker`: freestanding C++ checker using the public header.
- `fixtures`: malformed, crashing, hanging, and error-returning checker variants used by the SDK release gate.

Run `scripts/validate-checker-sdk.sh` to compile and exercise all examples and
negative fixtures through the isolated checker worker.

New checkers should populate `CheckerManifest::rules`. The host keeps an empty
catalog backward compatible, but validates emitted rule IDs once the catalog is
nonempty.
