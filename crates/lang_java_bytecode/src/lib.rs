//! Java `.class`/`.jar`/`.war` ingestion: decodes JVM bytecode directly into
//! `uniflow_ir::Program` (skipping the HIR source-frontend pipeline
//! entirely), so compiled dependencies participate in the same taint
//! analysis as `.java` sources under `Language::Java`.

mod archive;
mod cfg;
mod classfile;
mod constant_pool;
mod descriptor;
mod invokedynamic;
mod lower;
mod opcodes;
mod reader;
mod shuffle;
mod version;

pub use constant_pool::ClassfileDiagnostic;
pub use uniflow_jni_bridge::NativeMethodDecl;

use anyhow::{Context, Result};
use indexmap::IndexMap;
use rayon::prelude::*;
use std::path::Path;
use uniflow_hir::Language;
use uniflow_ir::{FunctionId, Program, SourceFile};

/// Decodes one classfile's bytes into IR. `provenance` becomes the lone
/// `SourceFile`'s path (e.g. `"lib.jar!com/example/Foo.class"` or a plain
/// filesystem path for a standalone `.class` file). The third element lists
/// every `native` method declared by the class (no body to lower — see
/// [`NativeMethodDecl`]).
pub fn lower_class_bytes(
    bytes: &[u8],
    provenance: &str,
) -> Result<(Program, Vec<ClassfileDiagnostic>, Vec<NativeMethodDecl>)> {
    let (class, mut diagnostics) =
        classfile::parse_class_file(bytes).with_context(|| format!("failed to parse {provenance}"))?;
    let mut next_function_id = 0u32;
    let mut native_methods = Vec::new();
    let functions = lower::lower_class(&class, &mut next_function_id, &mut diagnostics, &mut native_methods);
    let entry_points = functions.iter().map(|function| function.id).collect::<Vec<FunctionId>>();
    let mut type_hierarchy = IndexMap::new();
    let mut bases = Vec::new();
    bases.extend(class.super_class.clone());
    bases.extend(class.interfaces.clone());
    type_hierarchy.insert(class.this_class.clone(), bases);

    Ok((
        Program {
            language: Language::Java,
            source_files: vec![SourceFile { id: 0, path: provenance.to_string() }],
            functions,
            entry_points,
            type_hierarchy,
        },
        diagnostics,
        native_methods,
    ))
}

/// Decodes a standalone `.class` file. This covers build output trees such
/// as `target/classes` and Gradle/Maven compilation directories without
/// requiring callers to package a temporary JAR first.
pub fn lower_class_file(
    path: &Path,
) -> Result<(Program, Vec<ClassfileDiagnostic>, Vec<NativeMethodDecl>)> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat class file {}", path.display()))?;
    anyhow::ensure!(
        metadata.len() <= archive::MAX_CLASSFILE_BYTES,
        "class file {} is {} bytes, exceeding the {}-byte safety limit",
        path.display(),
        metadata.len(),
        archive::MAX_CLASSFILE_BYTES,
    );
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read class file {}", path.display()))?;
    lower_class_bytes(&bytes, &path.to_string_lossy())
}

/// Decodes every class in a `.jar`/`.war` archive (recursing into nested
/// `WEB-INF/lib/*.jar`s) into one merged `Program`.
pub fn lower_archive(
    path: &Path,
) -> Result<(Program, Vec<ClassfileDiagnostic>, Vec<NativeMethodDecl>)> {
    let entries = archive::read_archive_class_entries(path)
        .with_context(|| format!("failed to open archive {}", path.display()))?;
    // Classfiles are independent units. Decode them with Rayon so large
    // dependency archives use available cores; indexed parallel collection
    // preserves archive order, keeping function IDs and diagnostics stable.
    let decoded = entries
        .into_par_iter()
        .map(|entry| match lower_class_bytes(&entry.bytes, &entry.provenance) {
            Ok((program, diagnostics, natives)) => (Some(program), diagnostics, natives),
            Err(error) => (
                None,
                vec![ClassfileDiagnostic(format!("{}: {error}", entry.provenance))],
                Vec::new(),
            ),
        })
        .collect::<Vec<_>>();
    let mut diagnostics = Vec::new();
    let mut native_methods = Vec::new();
    let mut programs = Vec::with_capacity(decoded.len());
    for (program, mut class_diagnostics, mut natives) in decoded {
        diagnostics.append(&mut class_diagnostics);
        native_methods.append(&mut natives);
        if let Some(program) = program {
            programs.push(program);
        }
    }
    let merged = uniflow_ir::merge_programs(programs)
        .with_context(|| format!("failed to merge decoded classes from {}", path.display()))?;
    Ok((merged, diagnostics, native_methods))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_ir::validate_program;

    #[test]
    fn plain_class_lowers_to_valid_ir_with_a_call_chain() {
        let bytes = include_bytes!("../tests/fixtures/Plain.class");
        let (program, diagnostics, _natives) = lower_class_bytes(bytes, "Plain.class").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let run = program
            .functions
            .iter()
            .find(|f| f.name == "Plain.run")
            .expect("run function");
        let calls: Vec<&str> = run
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match &call.callee {
                    uniflow_ir::Callee::Static(name) => Some(name.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert!(calls.contains(&"Plain.source"));
        assert!(calls.contains(&"Plain.sink"));
    }

    #[test]
    fn branchy_class_with_loops_and_try_catch_lowers_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/Branchy.class");
        let (program, diagnostics, _natives) = lower_class_bytes(bytes, "Branchy.class").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let try_catch = program
            .functions
            .iter()
            .find(|f| f.name == "Branchy.tryCatch")
            .expect("tryCatch function");
        assert!(!try_catch.exception_edges.is_empty());
    }

    #[test]
    fn fields_class_with_static_and_instance_fields_lowers_to_valid_ir() {
        let bytes = include_bytes!("../tests/fixtures/Fields.class");
        let (program, diagnostics, _natives) = lower_class_bytes(bytes, "Fields.class").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let run = program
            .functions
            .iter()
            .find(|f| f.name == "Fields.run")
            .expect("run function");
        let calls: Vec<&str> = run
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match &call.callee {
                    uniflow_ir::Callee::Static(name) => Some(name.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert!(calls.contains(&"Fields.setStatic"));
        assert!(calls.contains(&"Fields.mix"));
        assert!(calls.contains(&"Fields.setInstance"));
    }

    #[test]
    fn native_methods_are_not_lowered_but_are_reported_as_declarations() {
        let bytes = include_bytes!("../tests/fixtures/Native.class");
        let (program, diagnostics, natives) = lower_class_bytes(bytes, "Native.class").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");

        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(!names.contains(&"Native.nativeSink"), "{names:?}");
        assert!(!names.contains(&"Native.nativeCompute"), "{names:?}");
        assert!(names.contains(&"Native.run"), "{names:?}");

        let sink = natives
            .iter()
            .find(|decl| decl.method == "nativeSink")
            .expect("nativeSink declaration");
        assert_eq!(sink.class, "Native");
        assert!(!sink.is_static);
        assert_eq!(sink.param_count, 1);
        assert_eq!(
            sink.descriptor.as_deref(),
            Some("(Ljava/lang/String;)Ljava/lang/String;")
        );
        assert_eq!(sink.qualified_name(), "Native.nativeSink");
        assert_eq!(sink.mangled_short_name(), "Java_Native_nativeSink");

        let compute = natives
            .iter()
            .find(|decl| decl.method == "nativeCompute")
            .expect("nativeCompute declaration");
        assert!(compute.is_static);
        assert_eq!(compute.param_count, 2);
    }

    #[test]
    fn lambda_class_resolves_invokedynamic_to_impl_methods_and_string_concat() {
        let bytes = include_bytes!("../tests/fixtures/Lambda.class");
        let (program, diagnostics, _natives) = lower_class_bytes(bytes, "Lambda.class").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");
        let run = program
            .functions
            .iter()
            .find(|f| f.name == "Lambda.run")
            .expect("run function");
        let calls: Vec<&str> = run
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match &call.callee {
                    uniflow_ir::Callee::Static(name) => Some(name.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        // `items.forEach(x -> sink(x))`: the LambdaMetafactory-created
        // Consumer resolves to its javac-synthesized static implementation.
        assert!(
            calls.iter().any(|name| name.contains("lambda$run$0")),
            "{calls:?}"
        );
        // `Lambda::upper` (an unbound static method reference) resolves
        // directly to the referenced method.
        assert!(calls.contains(&"Lambda.upper"), "{calls:?}");
        // `"value=" + tainted + "!"` lowers through the StringConcatFactory
        // recipe into a chain of String.concat calls.
        assert!(calls.contains(&"java.lang.String.concat"), "{calls:?}");
    }

    #[test]
    fn jar_archive_merges_multiple_classes_with_unique_function_ids() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lib.jar");
        let (program, diagnostics, _natives) = lower_archive(&path).unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");

        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"com.example.Source.read"), "{names:?}");
        assert!(names.contains(&"com.example.Sink.write"), "{names:?}");
        assert!(names.contains(&"com.example.App.run"), "{names:?}");

        let mut ids: Vec<u32> = program.functions.iter().map(|f| f.id.0).collect();
        ids.sort_unstable();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids, deduped, "function ids must be unique across merged classes");

        let paths: Vec<&str> = program.source_files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.ends_with("lib.jar!com/example/Source.class")), "{paths:?}");
        assert!(paths.iter().any(|p| p.ends_with("lib.jar!com/example/Sink.class")), "{paths:?}");

        // Cross-class call: App.run calls both Source.read and Sink.write.
        let run = program.functions.iter().find(|f| f.name == "com.example.App.run").unwrap();
        let calls: Vec<&str> = run
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match &call.callee {
                    uniflow_ir::Callee::Static(name) => Some(name.as_str()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        assert!(calls.contains(&"com.example.Source.read"));
        assert!(calls.contains(&"com.example.Sink.write"));
    }

    #[test]
    fn war_archive_recurses_into_nested_lib_jar() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/app.war");
        let (program, diagnostics, _natives) = lower_archive(&path).unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).expect("valid IR");

        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"com.webapp.Servlet.handle"), "{names:?}");
        assert!(names.contains(&"com.example.Source.read"), "{names:?}");

        let paths: Vec<&str> = program.source_files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.ends_with("WEB-INF/classes/com/webapp/Servlet.class")),
            "{paths:?}"
        );
        assert!(
            paths.iter().any(|p| p.contains("WEB-INF/lib/dep.jar!") && p.ends_with("Source.class")),
            "{paths:?}"
        );
    }
}
