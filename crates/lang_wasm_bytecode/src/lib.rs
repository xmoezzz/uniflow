//! WebAssembly (`.wasm`) module ingestion: decodes a WASM binary directly
//! into `uniflow_ir::Program` (skipping the HIR source-frontend pipeline
//! entirely, the same architecture `uniflow_lang_java_bytecode` uses for
//! `.class`/`.jar` files), so a compiled WASM module — regardless of which
//! source language produced it (Rust, C/C++, AssemblyScript, TinyGo, ...) —
//! participates in the same taint analysis as any other input.
//!
//! Built on `walrus`, a structured WASM IR (blocks/loops/ifs as nested
//! constructs rather than raw jump-target byte offsets), which this crate
//! flattens into `uniflow_ir`'s flat, CFG-based `BasicBlock`/`Terminator`
//! shape. See `lower::lower_local_function` for the structured-control-flow-
//! to-CFG algorithm and its `Phi`-reconciliation strategy.

mod lower;

use anyhow::{Context, Result};
use std::path::Path;
use uniflow_hir::Language;
use uniflow_ir::{FunctionId, Program, SourceFile};

/// Decodes one in-memory WASM module. `provenance` becomes the lone
/// `SourceFile`'s path.
pub fn lower_module_bytes(bytes: &[u8], provenance: &str) -> Result<Program> {
    let module = walrus::Module::from_buffer(bytes)
        .with_context(|| format!("failed to parse wasm module {provenance}"))?;
    let functions = lower::lower_module(&module);
    let entry_points = functions.iter().map(|function| function.id).collect::<Vec<FunctionId>>();
    Ok(Program {
        // There is no dedicated `Language::Wasm` variant — WASM is a
        // genuine cross-language compilation target (Rust/C/C++/
        // AssemblyScript/TinyGo all produce it), so no single existing
        // `Language` is a faithful fit. `Unknown` is used as a deliberate,
        // documented placeholder rather than mislabeling it as one source
        // language; revisit if/when a dedicated variant is added.
        language: Language::Unknown,
        source_files: vec![SourceFile { id: 0, path: provenance.to_string() }],
        functions,
        entry_points,
        type_hierarchy: Default::default(),
    })
}

/// Decodes a standalone `.wasm` file from disk.
pub fn lower_module_file(path: &Path) -> Result<Program> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read wasm module {}", path.display()))?;
    lower_module_bytes(&bytes, &path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_ir::{validate_program, Callee, InstKind};

    fn find_function<'a>(program: &'a Program, name_suffix: &str) -> &'a uniflow_ir::Function {
        program.functions.iter().find(|f| f.name.ends_with(name_suffix)).unwrap_or_else(|| {
            panic!("no function ending in {name_suffix}; had: {:?}", program.functions.iter().map(|f| &f.name).collect::<Vec<_>>())
        })
    }

    fn call_targets(function: &uniflow_ir::Function) -> Vec<String> {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call) => match &call.callee {
                    Callee::Static(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_plain_call_chain_lowers_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/plain.wasm");
        let program = lower_module_bytes(bytes, "plain.wasm").unwrap();
        validate_program(&program).expect("valid IR");
        let run = find_function(&program, "run");
        let targets = call_targets(run);
        assert!(targets.iter().any(|t| t.contains("source")), "{targets:?}");
        assert!(targets.iter().any(|t| t.contains("sink")), "{targets:?}");
    }

    #[test]
    fn a_branchy_function_with_a_loop_lowers_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/branchy.wasm");
        let program = lower_module_bytes(bytes, "branchy.wasm").unwrap();
        validate_program(&program).expect("valid IR");
        let run = find_function(&program, "run");
        assert!(run.blocks.len() > 1, "expected a real multi-block CFG: {:#?}", run.blocks);
    }

    #[test]
    fn an_imported_host_function_call_carries_its_module_qualified_name() {
        let bytes = include_bytes!("../tests/fixtures/imported.wasm");
        let program = lower_module_bytes(bytes, "imported.wasm").unwrap();
        validate_program(&program).expect("valid IR");
        let run = find_function(&program, "run");
        let targets = call_targets(run);
        assert!(targets.iter().any(|t| t == "env.host_sink"), "{targets:?}");
    }
}
