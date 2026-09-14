//! Multi-file entry point. Ruby has no `crate::`-equivalent, no static
//! import system, and no file-naming convention analogous to Rust's
//! `main.rs`/`lib.rs`/`mod.rs` (see `crate::frontend::decl`'s module doc
//! comment on why there is no static binding table to resolve up front), so
//! — unlike `lang_rust`/`lang_go`/`lang_javascript`, which each need a
//! whole-project view before parsing any one file — this project index is
//! exactly an independent per-file parse merged via `ProgramMerger`, the
//! same shape `lang_rust::frontend::project_index` uses for a single file.
//! A project split across files via `require_relative` is not resolved
//! cross-file; each file's own top-level items still resolve correctly
//! on their own (see `crate::frontend::decl::register_top_level_items`).

use std::path::{Component, Path};

use anyhow::{bail, Result};
use lib_ruby_parser::{Parser, ParserOptions, ParserResult};
use uniflow_hir::{Language, Program, ProgramMerger};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::decl::lower_file;
use crate::frontend::env::RubyEnv;

/// This project's module-name convention: the file path with its extension
/// stripped and path separators replaced by `.`, e.g. `app/models/user.rb`
/// -> `app.models.user`.
fn module_name_for_path(path: &str) -> String {
    let without_ext = Path::new(path).with_extension("");
    without_ext
        .components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_one(path: &str, source: &str) -> Result<Program> {
    let options = ParserOptions { buffer_name: path.to_string(), record_tokens: false, ..Default::default() };
    let parser = Parser::new(source.as_bytes().to_vec(), options);
    let ParserResult { ast, .. } = parser.do_parse();
    let Some(ast) = ast else {
        // An empty (or comment/whitespace-only) source is valid Ruby with no
        // AST node at all — an empty module, not an error.
        let module_name = module_name_for_path(path);
        let builder = ModuleBuilder::new(Language::Ruby, path, &module_name);
        return Ok(builder.finish());
    };
    let module_name = module_name_for_path(path);
    let mut builder = ModuleBuilder::new(Language::Ruby, path, &module_name);
    let mut env = RubyEnv::new();
    lower_file(&mut builder, &mut env, source, Some(&ast), &module_name);
    Ok(builder.finish())
}

pub fn parse_file_standalone(path: &str, source: &str) -> Result<Program> {
    parse_one(path, source)
}

pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    parse_project_sources_with_progress(entries, &|| {})
}

pub fn parse_project_sources_with_progress(entries: &[(String, String)], on_file_parsed: &(dyn Fn() + Sync)) -> Result<Program> {
    if entries.is_empty() {
        bail!("no Ruby source files provided");
    }
    let mut project = ProgramMerger::new(Language::Ruby);
    for (path, source) in entries {
        project.merge(parse_one(path, source)?);
        on_file_parsed();
    }
    Ok(project.finish())
}
