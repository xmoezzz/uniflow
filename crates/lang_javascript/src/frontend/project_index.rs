//! Multi-file entry point: resolves each file's relative `import`/`require`
//! specifiers against every other file in the same project (so a call into
//! an imported function carries its real qualified name, matching how
//! `lang_java`/`lang_python` resolve cross-file calls), then lowers and
//! merges every file into one `Program`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use oxc_allocator::Allocator;
use oxc_parser::Parser as OxcParser;
use oxc_span::SourceType;
use uniflow_hir::{Language, Program, ProgramMerger};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::decl::{bind_imports, lower_module};
use crate::frontend::env::JsEnv;

pub(crate) fn source_type_for_path(path: &str) -> SourceType {
    SourceType::from_path(path).unwrap_or_default()
}

/// This project's module-name convention: the file path with its extension
/// stripped and path separators replaced by `.` — e.g. `routes/api.js` ->
/// `routes.api`. Applied consistently to both a module's own qualified-name
/// prefix and the paths indexed for resolving other files' relative imports.
pub(crate) fn module_name_for_path(path: &str) -> String {
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

/// Collapses `.`/`..` path components without touching the filesystem (the
/// project's files are in-memory source strings, not necessarily on disk).
fn normalize_path(path: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                parts.pop();
            }
            std::path::Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            _ => {}
        }
    }
    parts.join("/")
}

struct JsProjectIndex {
    module_name_by_normalized_path: HashMap<String, String>,
    /// A module's default export's REAL qualified name — not predictable
    /// from `{module}.default` the way a named export is, since `export
    /// default function Foo() {}` / `export default class Foo {}` /
    /// `module.exports = Foo;` all register under `Foo`'s own name (see
    /// `decl::lower_module`'s `ExportDefaultDeclaration` handling), not
    /// literally `"default"`. Populated by scanning for the exact same
    /// shapes that handling recognizes, so the two stay in agreement.
    default_export_by_module: HashMap<String, String>,
}

impl JsProjectIndex {
    fn build(entries: &[(String, String)]) -> Self {
        // Keyed by the extension-stripped, normalized path, matching what
        // `resolve` reconstructs from a relative specifier.
        let mut module_name_by_normalized_path = HashMap::new();
        for (path, _) in entries {
            let normalized = normalize_path(&Path::new(path).with_extension(""));
            module_name_by_normalized_path.insert(normalized, module_name_for_path(path));
        }
        let mut default_export_by_module = HashMap::new();
        for (path, source) in entries {
            let module_name = module_name_for_path(path);
            let allocator = Allocator::default();
            let source_type = source_type_for_path(path);
            let parsed = OxcParser::new(&allocator, source, source_type).parse();
            if let Some(target) = scan_default_export_target(&parsed.program, &module_name) {
                default_export_by_module.insert(module_name, target);
            }
        }
        Self { module_name_by_normalized_path, default_export_by_module }
    }

    /// Resolves a relative specifier (`./utils`, `../lib/db`) from
    /// `current_path`'s directory against every known project file,
    /// trying common extensions and an `index` fallback. Returns `None`
    /// for a bare package specifier (`express`) or anything unresolvable —
    /// both are left as an ordinary, non-cross-file identifier.
    fn resolve(&self, current_path: &str, specifier: &str) -> Option<String> {
        if !(specifier.starts_with("./") || specifier.starts_with("../")) {
            return None;
        }
        let current_dir = Path::new(current_path).parent().unwrap_or_else(|| Path::new(""));
        let joined = current_dir.join(specifier);
        let base = normalize_path(&joined.with_extension(""));
        let index_candidate = normalize_path(&joined.join("index"));
        [base, index_candidate].into_iter().find_map(|candidate| self.module_name_by_normalized_path.get(&candidate).cloned())
    }

    /// The qualified name a `import X from '<specifier>'` binding of `X`
    /// actually resolves to, once `<specifier>` is known to resolve to
    /// `target_module`. Falls back to `{target_module}.default` (still a
    /// reasonable, analyzable — if untraceable-to-source — qualified name)
    /// when the scan above couldn't determine the real target, e.g. `export
    /// default { a, b };` (an object literal, not a named declaration).
    fn resolve_default_export(&self, target_module: &str) -> String {
        self.default_export_by_module.get(target_module).cloned().unwrap_or_else(|| format!("{target_module}.default"))
    }
}

fn scan_default_export_target(program: &oxc_ast::ast::Program, module_name: &str) -> Option<String> {
    use oxc_ast::ast::{Expression, ExportDefaultDeclarationKind, Statement};
    for stmt in &program.body {
        match stmt {
            Statement::ExportDefaultDeclaration(export) => {
                return Some(match &export.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        format!("{module_name}.{}", function.id.as_ref().map(|id| id.name.as_str().to_string()).unwrap_or_else(|| "default".to_string()))
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                        format!("{module_name}.{}", class.id.as_ref().map(|id| id.name.as_str().to_string()).unwrap_or_else(|| "default".to_string()))
                    }
                    ExportDefaultDeclarationKind::Identifier(identifier) => format!("{module_name}.{}", identifier.name.as_str()),
                    _ => format!("{module_name}.default"),
                });
            }
            Statement::ExpressionStatement(expression_statement) => {
                if let Expression::AssignmentExpression(assignment) = &expression_statement.expression {
                    let is_module_exports = matches!(
                        &assignment.left,
                        oxc_ast::ast::AssignmentTarget::StaticMemberExpression(member)
                            if matches!(&member.object, Expression::Identifier(identifier) if identifier.name.as_str() == "module")
                                && member.property.name.as_str() == "exports"
                    );
                    if is_module_exports {
                        return Some(match &assignment.right {
                            Expression::Identifier(identifier) => format!("{module_name}.{}", identifier.name.as_str()),
                            Expression::FunctionExpression(function) => {
                                format!("{module_name}.{}", function.id.as_ref().map(|id| id.name.as_str().to_string()).unwrap_or_else(|| "default".to_string()))
                            }
                            Expression::ClassExpression(class) => {
                                format!("{module_name}.{}", class.id.as_ref().map(|id| id.name.as_str().to_string()).unwrap_or_else(|| "default".to_string()))
                            }
                            _ => format!("{module_name}.default"),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_one(path: &str, source: &str, index: Option<&Arc<JsProjectIndex>>) -> Result<Program> {
    let allocator = Allocator::default();
    let source_type = source_type_for_path(path);
    let parsed = OxcParser::new(&allocator, source, source_type).parse();
    if parsed.fatal_error {
        anyhow::bail!("javascript parser encountered a fatal error on {path}");
    }
    let module_name = module_name_for_path(path);
    let mut builder = ModuleBuilder::new(Language::JavaScript, path, &module_name);
    let mut env = JsEnv::new();
    // Even a standalone single-file parse (`analyze-source`, no project
    // index at all) must still recognize `const x = require("y")`/
    // `require("y").z(...)` bindings — `bind_require_declarators`'s own
    // fallback already resolves a bare/built-in specifier (`"util"`,
    // `"vm"`, `"child_process"`) to its own literal text when there is no
    // project file to resolve against, so passing a resolver that always
    // returns `None` here still produces the right qualified names for
    // every *built-in*-module convention; only a real cross-file
    // `import`/relative `require` needs an actual project index, and
    // correctly stays unresolved (not a crash) without one.
    match index {
        Some(index) => {
            let index_for_module = Arc::clone(index);
            let index_for_default = Arc::clone(index);
            bind_imports(
                &mut builder,
                &mut env,
                path,
                &parsed.program,
                &move |current_path, specifier| index_for_module.resolve(current_path, specifier),
                &move |target_module| index_for_default.resolve_default_export(target_module),
            );
        }
        None => {
            bind_imports(&mut builder, &mut env, path, &parsed.program, &|_current_path, _specifier| None, &|target_module| format!("{target_module}.default"));
        }
    }
    lower_module(&mut builder, &mut env, source, &parsed.program, &module_name);
    Ok(builder.finish())
}

pub fn parse_file_standalone(path: &str, source: &str) -> Result<Program> {
    parse_one(path, source, None)
}

pub fn parse_project_sources(entries: &[(String, String)]) -> Result<Program> {
    parse_project_sources_with_progress(entries, &|| {})
}

pub fn parse_project_sources_with_progress(entries: &[(String, String)], on_module_parsed: &(dyn Fn() + Sync)) -> Result<Program> {
    let index = Arc::new(JsProjectIndex::build(entries));
    let mut project = ProgramMerger::new(Language::JavaScript);
    for (path, source) in entries {
        project.merge(parse_one(path, source, Some(&index))?);
        on_module_parsed();
    }
    Ok(project.finish())
}
