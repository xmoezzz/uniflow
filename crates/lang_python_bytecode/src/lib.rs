//! CPython `.pyc` bytecode ingestion: decodes a compiled Python module
//! directly into `uniflow_ir::Program` (skipping the HIR source-frontend
//! pipeline entirely, the same way `uniflow_lang_java_bytecode` decodes
//! `.class` files), so a vendored/compiled-only Python dependency
//! participates in the same taint analysis as `.py` sources under
//! `Language::Python`.
//!
//! Only CPython 3.6-3.10's "wordcode" bytecode format is supported — see
//! `version` and `header` for the magic-number gate, and `lower`'s module
//! doc comment for what is and isn't modeled precisely.

mod cfg;
mod header;
mod lower;
mod opcodes;
mod version;

use anyhow::{bail, Context, Result};
use indexmap::IndexMap;
use std::path::Path;
use uniflow_hir::Language;
use uniflow_ir::{FunctionId, Program, SourceFile};

/// Derives this module's dotted qualified-name prefix from its file path
/// the same way every other frontend in this workspace does: strip the
/// extension, replace path separators with `.` (e.g. `pkg/mod.pyc` ->
/// `pkg.mod`).
fn module_name_for_path(path: &str) -> String {
    let without_ext = Path::new(path).with_extension("");
    without_ext
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Decodes one `.pyc` file's bytes into IR. `provenance` becomes the lone
/// `SourceFile`'s path and, with its extension stripped and separators
/// dotted, this program's module-qualified-name prefix.
pub fn lower_pyc_bytes(bytes: &[u8], provenance: &str) -> Result<(Program, Vec<String>)> {
    let header = header::parse_header(bytes).with_context(|| format!("failed to parse {provenance}"))?;
    let body = &bytes[header.body_offset..];
    let obj = py_marshal::read::marshal_loads(body).map_err(|error| anyhow::anyhow!("failed to unmarshal {provenance}: {error}"))?;
    let py_marshal::Obj::Code(root_code) = obj else {
        bail!("{provenance}: top-level marshaled object is not a code object");
    };

    let module_name = module_name_for_path(provenance);
    let mut functions = Vec::new();
    let mut next_function_id = 0u32;
    let mut diagnostics = Vec::new();
    lower::lower_code_recursive(&root_code, &module_name, header.version, &mut next_function_id, &mut functions, &mut diagnostics);

    let entry_points = functions.iter().map(|function| function.id).collect::<Vec<FunctionId>>();
    Ok((
        Program {
            language: Language::Python,
            source_files: vec![SourceFile { id: 0, path: provenance.to_string() }],
            functions,
            entry_points,
            type_hierarchy: IndexMap::new(),
        },
        diagnostics,
    ))
}

/// Decodes a standalone `.pyc` file from disk.
pub fn lower_pyc_file(path: &Path) -> Result<(Program, Vec<String>)> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    lower_pyc_bytes(&bytes, &path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use uniflow_ir::{validate_program, Callee, InstKind};

    /// Compiles `source` with the sandbox's `python3.9` (verified present
    /// and producing magic number 3425 in this environment) and returns the
    /// resulting `.pyc` bytes — the most reliable way to get a real,
    /// version-correct fixture (and to catch an opcode-table error against
    /// ground truth) rather than hand-constructing bytecode.
    fn compile_fixture(source: &str) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("uniflow-pyc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let py_path = dir.join(format!("mod_{}.py", rand_suffix()));
        let pyc_path = py_path.with_extension("pyc");
        std::fs::write(&py_path, source).unwrap();
        let status = Command::new("python3.9")
            .arg("-c")
            .arg(format!(
                "import py_compile; py_compile.compile({:?}, cfile={:?}, doraise=True)",
                py_path.to_string_lossy(),
                pyc_path.to_string_lossy()
            ))
            .status()
            .expect("python3.9 must be available to compile test fixtures");
        assert!(status.success(), "python3.9 py_compile failed");
        let bytes = std::fs::read(&pyc_path).unwrap();
        let _ = std::fs::remove_file(&py_path);
        let _ = std::fs::remove_file(&pyc_path);
        bytes
    }

    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        nanos.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_mul(0x9E3779B97F4A7C15))
    }

    fn call_names(program: &Program, function_name: &str) -> Vec<String> {
        let function = program.functions.iter().find(|f| f.name.ends_with(function_name)).unwrap_or_else(|| panic!("no function named {function_name}, had: {:?}", program.functions.iter().map(|f| &f.name).collect::<Vec<_>>()));
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
    fn plain_function_call_chain_lowers_to_valid_ir() {
        let bytes = compile_fixture(
            r#"
def source():
    return input()

def sink(value):
    print(value)

def run():
    value = source()
    sink(value)
"#,
        );
        let (program, diagnostics) = lower_pyc_bytes(&bytes, "plain.pyc").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).unwrap_or_else(|errors| panic!("{errors:?}\n{program:#?}"));
        let calls = call_names(&program, ".run");
        assert!(calls.contains(&"source".to_string()), "{calls:?}");
        assert!(calls.contains(&"sink".to_string()), "{calls:?}");
    }

    #[test]
    fn branchy_function_with_a_loop_and_conditional_lowers_to_valid_ir() {
        let bytes = compile_fixture(
            r#"
def run(items):
    total = 0
    for item in items:
        if item > 0:
            total = total + item
        else:
            total = total - 1
    return total
"#,
        );
        let (program, diagnostics) = lower_pyc_bytes(&bytes, "branchy.pyc").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).unwrap_or_else(|errors| panic!("{errors:?}\n{program:#?}"));
        let function = program.functions.iter().find(|f| f.name.ends_with(".run")).unwrap();
        assert!(function.blocks.len() > 3, "{:?}", function.blocks.len());
    }

    #[test]
    fn method_call_on_an_attribute_carries_a_qualified_callee_and_receiver() {
        let bytes = compile_fixture(
            r#"
import os

def run(cmd):
    os.system(cmd)
"#,
        );
        let (program, diagnostics) = lower_pyc_bytes(&bytes, "methodcall.pyc").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).unwrap_or_else(|errors| panic!("{errors:?}\n{program:#?}"));
        let calls = call_names(&program, ".run");
        assert!(calls.iter().any(|c| c.contains("system")), "{calls:?}");
    }

    #[test]
    fn nested_function_becomes_its_own_qualified_function() {
        let bytes = compile_fixture(
            r#"
def outer():
    def inner(x):
        return x + 1
    return inner(1)
"#,
        );
        let (program, diagnostics) = lower_pyc_bytes(&bytes, "nested.pyc").unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        validate_program(&program).unwrap_or_else(|errors| panic!("{errors:?}\n{program:#?}"));
        let names: Vec<&str> = program.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(names.iter().any(|n| n.ends_with(".outer.inner")), "{names:?}");
    }

    #[test]
    fn unrecognized_magic_number_is_rejected_with_a_clear_error() {
        let bytes = vec![0xFFu8, 0xFF, 0x0D, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let error = lower_pyc_bytes(&bytes, "bad.pyc").unwrap_err();
        let full = format!("{error:#}");
        assert!(full.contains("unrecognized"), "{full}");
    }
}
