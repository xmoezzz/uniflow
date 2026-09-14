//! Multi-file entry point: derives each file's module name from its path
//! (mirroring `lang_javascript::project_index`'s convention, adapted for
//! Rust's `main.rs`/`lib.rs`/`mod.rs` "this directory level" file
//! conventions), finds the project's crate root (if any) so every file
//! resolves a `crate::` path the same way, then lowers and merges every
//! file into one `Program`.

use std::path::{Component, Path};

use anyhow::Result;
use uniflow_hir::{Language, Program, ProgramMerger};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::decl::lower_file;
use crate::frontend::env::RustEnv;

/// This project's module-name convention: the file path with its extension
/// stripped and path separators replaced by `.`, e.g. `src/routes/api.rs`
/// -> `src.routes.api`. A trailing `main`/`lib`/`mod` segment is dropped —
/// each names "this directory level is the crate/binary root" or "this
/// directory level is the parent module" (Rust 2015's `foo/mod.rs`)  rather
/// than a real named submodule, so `src/lib.rs` and `src/foo/mod.rs`
/// resolve to `src` and `src.foo` respectively, matching how `src/foo.rs`
/// (the modern, file-per-module convention) already would.
pub(crate) fn module_name_for_path(path: &str) -> String {
    let without_ext = Path::new(path).with_extension("");
    let mut segments: Vec<String> = without_ext
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect();
    if matches!(segments.last().map(String::as_str), Some("main") | Some("lib") | Some("mod")) {
        segments.pop();
    }
    segments.join(".")
}

/// The crate root's own qualified prefix (e.g. `"src"` for a project whose
/// binary/library entry point is `src/main.rs`/`src/lib.rs`), used to
/// resolve a `crate::`-prefixed `use`/path uniformly across every file. Not
/// found (`None`) when no entry looks like a crate root — e.g. an arbitrary
/// scan of loose `.rs` files with no real Cargo project layout — in which
/// case each file falls back to substituting itself for `crate`
/// (`RustEnv`/`decl::translate_special_segment`'s existing, imprecise but
/// harmless default).
fn find_crate_root(entries: &[(String, String)]) -> Option<String> {
    entries
        .iter()
        .find(|(path, _)| matches!(Path::new(path).file_stem().and_then(|s| s.to_str()), Some("main") | Some("lib")))
        .map(|(path, _)| module_name_for_path(path))
}

fn parse_one(path: &str, source: &str, crate_root: Option<String>) -> Result<Program> {
    let file = syn::parse_file(source).map_err(|error| anyhow::anyhow!("rust parser encountered a fatal error on {path}: {error}"))?;
    let module_name = module_name_for_path(path);
    let mut builder = ModuleBuilder::new(Language::Rust, path, &module_name);
    let mut env = RustEnv::new(crate_root);
    lower_file(&mut builder, &mut env, source, &file, &module_name);
    Ok(builder.finish())
}

pub fn parse_file_standalone(path: &str, source: &str) -> Result<Program> {
    parse_one(path, source, None)
}

pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    parse_project_sources_with_progress(entries, &|| {})
}

pub fn parse_project_sources_with_progress(entries: &[(String, String)], on_module_parsed: &(dyn Fn() + Sync)) -> Result<Program> {
    let crate_root = find_crate_root(entries);
    let mut project = ProgramMerger::new(Language::Rust);
    for (path, source) in entries {
        project.merge(parse_one(path, source, crate_root.clone())?);
        on_module_parsed();
    }
    Ok(project.finish())
}
