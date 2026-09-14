//! .NET CIL ingestion: decodes managed assemblies (`.dll`/`.exe`) directly
//! into `uniflow_ir::Program` (skipping the HIR source-frontend pipeline
//! entirely, exactly like `lang_java_bytecode` does for JVM `.class`/`.jar`
//! files), so a compiled dependency's methods participate in the same
//! taint analysis as a `Language::CSharp` source project.
//!
//! # Known limitations
//! - Exception `leave`/`endfinally`/`endfilter` continuation targets are
//!   approximated (see `lower.rs`'s module doc comment) rather than
//!   precisely resolved against the original `leave` site.
//! - Generic type/method arguments are dropped from qualified names (a
//!   generic instantiation resolves to its unbound base method/type),
//!   matching the same simplification `lang_rust`/`lang_go` make.
//! - No attempt is made to recover C#-compiler-synthesized closures
//!   (display classes for lambdas/local functions) back into a real
//!   capture-aware call edge the way `lang_java_bytecode` does for
//!   `invokedynamic`-based Java lambdas — a closure's `Invoke` call target
//!   resolves to the compiler-generated method name directly instead.

mod cfg;
mod lower;
mod names;

use anyhow::{Context, Result};
use dotnetdll::prelude::*;
use dotnetdll::resolution::Resolution;
use uniflow_hir::Language;
use uniflow_ir::{FunctionId, Program, SourceFile};

/// Decodes one in-memory assembly's bytes into IR. `provenance` becomes the
/// lone `SourceFile`'s path.
pub fn lower_assembly_bytes(bytes: &[u8], provenance: &str) -> Result<(Program, Vec<String>)> {
    let res = Resolution::parse(bytes, ReadOptions::default()).with_context(|| format!("failed to parse .NET assembly {provenance}"))?;

    let mut diagnostics = Vec::new();
    let mut functions = Vec::new();
    let mut next_function_id = 0u32;
    let mut type_hierarchy = indexmap::IndexMap::new();

    for (type_idx, type_def) in res.enumerate_type_definitions() {
        let parent_type_name = type_def.nested_type_name(&res);
        let mut bases = Vec::new();
        if let Some(extends) = &type_def.extends {
            bases.push(names_show_type_source(&res, extends));
        }
        for (_, implemented) in &type_def.implements {
            bases.push(names_show_type_source(&res, implemented));
        }
        type_hierarchy.insert(parent_type_name.clone(), bases);

        for (_method_idx, method) in res.enumerate_methods(type_idx) {
            let id = FunctionId(next_function_id);
            if let Some(function) = lower::lower_method(&res, &parent_type_name, method, id, &mut diagnostics) {
                next_function_id += 1;
                functions.push(function);
            }
        }
    }

    let entry_points: Vec<FunctionId> = functions.iter().map(|function| function.id).collect();

    Ok((
        Program { language: Language::CSharp, source_files: vec![SourceFile { id: 0, path: provenance.to_string() }], functions, entry_points, type_hierarchy },
        diagnostics,
    ))
}

fn names_show_type_source(res: &Resolution, source: &dotnetdll::resolved::types::TypeSource<dotnetdll::resolved::types::MemberType>) -> String {
    names::type_source_name(source, res)
}

/// Decodes a standalone `.dll`/`.exe` file from disk.
pub fn lower_assembly_file(path: &std::path::Path) -> Result<(Program, Vec<String>)> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read assembly {}", path.display()))?;
    lower_assembly_bytes(&bytes, &path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_ir::{validate_program, Callee, InstKind};

    fn find_function<'a>(program: &'a Program, name_suffix: &str) -> &'a uniflow_ir::Function {
        program.functions.iter().find(|f| f.name.ends_with(name_suffix)).unwrap_or_else(|| panic!("no function ending with {name_suffix}, had: {:?}", program.functions.iter().map(|f| &f.name).collect::<Vec<_>>()))
    }

    fn call_names(function: &uniflow_ir::Function) -> Vec<String> {
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
    fn plain_call_chain_lowers_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/Plain.dll");
        let (program, diagnostics) = lower_assembly_bytes(bytes, "Plain.dll").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let run = find_function(&program, ".Run");
        let calls = call_names(run);
        assert!(calls.iter().any(|name| name.ends_with(".Source")), "{calls:?}");
        assert!(calls.iter().any(|name| name.ends_with(".Sink")), "{calls:?}");
    }

    #[test]
    fn branchy_method_with_a_loop_lowers_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/Branchy.dll");
        let (program, diagnostics) = lower_assembly_bytes(bytes, "Branchy.dll").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let loop_sum = find_function(&program, ".LoopSum");
        assert!(loop_sum.blocks.len() > 2, "{:?}", loop_sum.blocks.iter().map(|b| b.id).collect::<Vec<_>>());
    }

    #[test]
    fn fields_class_reads_and_writes_lower_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/Fields.dll");
        let (program, diagnostics) = lower_assembly_bytes(bytes, "Fields.dll").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let run = find_function(&program, ".Run");
        let calls = call_names(run);
        assert!(calls.iter().any(|name| name.ends_with(".SetStatic")), "{calls:?}");
        assert!(calls.iter().any(|name| name.ends_with(".Mix")), "{calls:?}");
    }

    #[test]
    fn try_catch_method_records_exception_edges() {
        let bytes = include_bytes!("../tests/fixtures/Branchy.dll");
        let (program, diagnostics) = lower_assembly_bytes(bytes, "Branchy.dll").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let try_catch = find_function(&program, ".TryCatch");
        assert!(!try_catch.exception_edges.is_empty());
    }
}
