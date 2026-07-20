use crate::FrontendOptions;
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Default)]
pub struct ClangAstOptions {
    /// Explicit clang/clang++ executable. When absent, C uses `clang` and C++ uses `clang++`.
    pub executable: Option<PathBuf>,
    /// Extra arguments appended after UniFlow's translation-unit options.
    pub extra_args: Vec<String>,
}

/// Run Clang's JSON AST dumper for callers that need compiler-grade syntax/type recovery.
///
/// This adapter is optional and deliberately separate from the built-in parser. Failure to locate
/// Clang does not change the source-only frontend; callers decide whether to fall back or surface
/// the diagnostic. The returned JSON can be consumed by checker plugins or future HIR importers.
pub fn dump_clang_ast_json(
    source: &Path,
    is_cpp: bool,
    frontend: &FrontendOptions,
    clang: &ClangAstOptions,
) -> Result<Value> {
    let executable = clang
        .executable
        .clone()
        .unwrap_or_else(|| PathBuf::from(if is_cpp { "clang++" } else { "clang" }));
    let mut command = Command::new(&executable);
    for arg in clang_translation_unit_args(frontend) {
        command.arg(arg);
    }
    command.args(&clang.extra_args);
    command
        .arg("-fsyntax-only")
        .arg("-Xclang")
        .arg("-ast-dump=json")
        .arg(source);
    let output = command
        .output()
        .with_context(|| format!("failed to execute {}", executable.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "clang AST generation failed for {}: {}",
            source.display(),
            stderr.trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("clang returned invalid AST JSON for {}", source.display()))
}

pub fn clang_translation_unit_args(frontend: &FrontendOptions) -> Vec<String> {
    let mut args = Vec::new();
    for (name, value) in &frontend.defines {
        args.push(match value {
            Some(value) => format!("-D{name}={value}"),
            None => format!("-D{name}"),
        });
    }
    for name in &frontend.undefines {
        args.push(format!("-U{name}"));
    }
    for include in &frontend.include_paths {
        args.push("-I".to_string());
        args.push(include.to_string_lossy().into_owned());
    }
    if let Some(standard) = &frontend.language_standard {
        args.push(format!("-std={standard}"));
    }
    if let Some(target) = &frontend.target_triple {
        args.push(format!("--target={target}"));
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_translation_unit_arguments_without_invoking_clang() {
        let mut frontend = FrontendOptions::default();
        frontend.defines.insert("FEATURE".into(), Some("1".into()));
        frontend.undefines.insert("OLD".into());
        frontend.include_paths.push(PathBuf::from("include"));
        frontend.language_standard = Some("c++20".into());
        frontend.target_triple = Some("x86_64-unknown-linux-gnu".into());
        let args = clang_translation_unit_args(&frontend);
        assert!(args.contains(&"-DFEATURE=1".to_string()));
        assert!(args.contains(&"-UOLD".to_string()));
        assert!(args.contains(&"-std=c++20".to_string()));
        assert!(args.contains(&"--target=x86_64-unknown-linux-gnu".to_string()));
    }
}
