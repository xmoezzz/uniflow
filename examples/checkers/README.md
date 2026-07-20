# Checker SDK examples

- `banned_function_checker`: Rust `cdylib` checker exported through ABI v2 and v1.
- `c_banned_function_checker`: freestanding C checker using the public header.
- `cpp_banned_function_checker`: freestanding C++ checker using the public header.
- `fixtures`: malformed, crashing, hanging, and error-returning checker variants used by the SDK release gate.

Run `scripts/validate-checker-sdk.sh` to compile and exercise all examples and
negative fixtures through the isolated checker worker.
