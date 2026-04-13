# uniflow

uniflow is a Rust workspace for source-level multi-language value-flow and taint analysis.

Current workspace components:

- language frontends for C, C++, Java, and Python
- unified HIR and lowering into a common analysis IR
- value-flow graph construction
- taint analysis on top of the value-flow graph
- YAML rule system for source, sink, sanitizer, propagator, and summary models
- built-in default models for Java, Python, C, and C++

