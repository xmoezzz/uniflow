//! Multi-file entry point.
//!
//! Go's package model is the key structural difference from
//! `uniflow_lang_javascript`'s per-file modules: every file that declares
//! the same `package` clause shares ONE flat namespace — a function in
//! `a.go` can call a function declared in `b.go` in the same package with
//! zero import. This module builds a whole-project index (every file
//! parsed once up front) so a file's own module lowering can resolve a
//! same-package sibling file's declarations, without needing to merge
//! multiple files into one `uniflow_hir::Module` (which would give every
//! file in a package the same `FileId`/span attribution — a real
//! regression for per-file diagnostics).
//!
//! Import resolution heuristic (documented tradeoff, no `go.mod` support):
//! without a build system's real import-path -> directory mapping, this
//! resolves an import specifier's last `/`-separated segment as the
//! expected package identifier (`"net/http"` -> `http`, `"myapp/pkg/util"`
//! -> `util`) and matches it against every project file's OWN declared
//! `package` clause. A project with two distinct packages that happen to
//! share a name (rare, but legal in different directories) is a known
//! false-positive risk this heuristic accepts, mirroring the same
//! "good enough" style `uniflow_lang_javascript::frontend::project_index`
//! already documents for its own relative-import resolution.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use gosyn::ast as go;
use uniflow_hir::{Language, Program, ProgramMerger};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::decl::{bind_imports, lower_file};
use crate::frontend::env::GoEnv;

struct GoProjectIndex {
    /// package name -> (bare free-function name -> qualified name), covering
    /// every file across the whole project that declares that package.
    package_functions: HashMap<String, HashMap<String, String>>,
    /// package name -> every type name declared anywhere in that package
    /// (struct or not).
    package_types: HashMap<String, HashSet<String>>,
    /// Every package name known to exist in this project, for the
    /// last-segment import resolution heuristic described above.
    known_packages: HashSet<String>,
}

impl GoProjectIndex {
    fn build<'a>(files: impl IntoIterator<Item = &'a go::File>) -> Self {
        let mut package_functions: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut package_types: HashMap<String, HashSet<String>> = HashMap::new();
        let mut known_packages = HashSet::new();
        for file in files {
            let package_name = file.pkg_name.name.clone();
            known_packages.insert(package_name.clone());
            let functions = package_functions.entry(package_name.clone()).or_default();
            let types = package_types.entry(package_name.clone()).or_default();
            for decl in &file.decl {
                match decl {
                    go::Declaration::Function(func_decl) if func_decl.recv.is_none() => {
                        functions.insert(func_decl.name.name.clone(), format!("{package_name}.{}", func_decl.name.name));
                    }
                    go::Declaration::Type(type_decl) => {
                        for spec in &type_decl.specs {
                            types.insert(spec.name.name.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        Self { package_functions, package_types, known_packages }
    }

    /// Resolves an import's full path text to a project-internal package's
    /// own declared name, when its last `/`-separated segment matches one.
    /// `None` means "not a project package" — the caller falls back to the
    /// raw import path text itself (the standard-library/external-package
    /// convention the legacy Go rule catalog's matchers expect).
    fn resolve_import(&self, import_path: &str) -> Option<String> {
        let last_segment = import_path.rsplit('/').next().unwrap_or(import_path);
        self.known_packages.contains(last_segment).then(|| last_segment.to_string())
    }

    fn functions_for_package(&self, package_name: &str) -> HashMap<String, String> {
        self.package_functions.get(package_name).cloned().unwrap_or_default()
    }

    fn types_for_package(&self, package_name: &str) -> HashSet<String> {
        self.package_types.get(package_name).cloned().unwrap_or_default()
    }
}

fn parse_go_source(path: &str, source: &str) -> Result<go::File> {
    gosyn::parse_source(source).with_context(|| format!("failed to parse Go source in {path}"))
}

fn lower_one(
    path: &str,
    source: &str,
    file: &go::File,
    package_functions: HashMap<String, String>,
    package_types: HashSet<String>,
    resolve_import: &dyn Fn(&str) -> Option<String>,
) -> Program {
    let package_name = file.pkg_name.name.clone();
    let mut builder = ModuleBuilder::new(Language::Go, path, &package_name);
    let mut env = GoEnv::new(package_name);
    for (bare_name, qualified_name) in package_functions {
        env.register_package_function(bare_name, qualified_name);
    }
    for type_name in package_types {
        env.register_package_type(type_name);
    }
    bind_imports(&mut env, file, resolve_import);
    lower_file(&mut builder, &mut env, source, file);
    builder.finish()
}

/// Parses one file with no project-wide context — same-package sibling
/// files (in another translation unit this call never sees) obviously
/// cannot be resolved, but this file's own top-level declarations still
/// resolve each other (see `decl::lower_file`'s pass 0), and any import is
/// treated as external (its raw path text becomes the qualifier).
pub fn parse_file_standalone(path: &str, source: &str) -> Result<Program> {
    let file = parse_go_source(path, source)?;
    Ok(lower_one(path, source, &file, HashMap::new(), HashSet::new(), &|_| None))
}

pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    parse_project_sources_with_progress(entries, &|| {})
}

pub fn parse_project_sources_with_progress(entries: &[(String, String)], on_file_parsed: &(dyn Fn() + Sync)) -> Result<Program> {
    let mut parsed = Vec::with_capacity(entries.len());
    for (path, source) in entries {
        match parse_go_source(path, source) {
            Ok(file) => parsed.push((path.as_str(), source.as_str(), file)),
            Err(error) => {
                // A project may contain a construct this frontend cannot yet
                // parse (a generated file, a vendored dependency, a Go
                // version feature ahead of this parser) beside otherwise
                // valid application code. One syntactically fatal file must
                // not discard every independently parsable file or prevent a
                // SARIF report for the rest of the project — the same
                // project-recovery tradeoff `uniflow_lang_javascript`'s
                // project index already makes; standalone `analyze-source`
                // remains strict.
                eprintln!("uniflow: skipping unparsable Go source {path}: {error}");
            }
        }
    }
    if parsed.is_empty() {
        anyhow::bail!("no Go source files could be parsed successfully");
    }
    let index = GoProjectIndex::build(parsed.iter().map(|(_, _, file)| file));

    let mut project = ProgramMerger::new(Language::Go);
    for (path, source, file) in &parsed {
        let package_name = file.pkg_name.name.clone();
        let functions = index.functions_for_package(&package_name);
        let types = index.types_for_package(&package_name);
        let resolver = |import_path: &str| index.resolve_import(import_path);
        let program = lower_one(path, source, file, functions, types, &resolver);
        project.merge(program);
        on_file_parsed();
    }
    Ok(project.finish())
}
