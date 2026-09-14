//! Per-file top-level orchestration: dispatches `oxc_ast` top-level
//! statements to `uniflow_hir::Item::Function`/`Item::Class`, resolves
//! `import`/CommonJS `require` bindings against the project's export
//! index, and wraps ordinary top-level executable statements (extremely
//! common in Node.js — `const app = express(); app.get(...); app.listen(...)`
//! runs directly at module scope, not inside any `function`) into one
//! synthetic module-init function so every system-graph adapter — which
//! scans function bodies, not bare module statements — still sees it.

use oxc_ast::ast as js;
use uniflow_hir::{Block, Class, Field, Function, Item, ParamKind, Stmt, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::{ImportBinding, JsEnv};
use crate::frontend::expr::span;
use crate::frontend::functions::lower_function_parts;
use crate::frontend::stmt::{lower_function_body, lower_stmt, lower_variable_declaration};

/// The synthetic name given to a module's top-level executable statements
/// (never a legal JS identifier, so it can never collide with a real
/// declaration) — mirrors this codebase's existing `<init>` convention for
/// a compiler-synthesized entry a checker still needs to see as one body.
pub(crate) const MODULE_INIT_SUFFIX: &str = "<script>";

/// Recognizes a Node native-addon binding — `const alias =
/// require('./build/Release/thing.node');` or the `bindings` package's
/// indirection, `const alias = require('bindings')('thing');` — followed by
/// any `alias.method(...)` call in the same function body, mirroring
/// `lang_python`'s own deliberately simple, literal-syntax-only
/// `python_ffi_calls` scan (see `crates/system_graph/src/python_ffi.rs`):
/// this is not a JS evaluator, every alias/path/method must be literal
/// syntax in the same body, and the result is only ever a *hint* consumed by
/// `system_graph::js_ffi`'s own independently-conservative matching (exact
/// literal method name registered via an N-API call in the same scan).
fn js_native_addon_calls(body: &str) -> Vec<(String, String, String)> {
    fn strip_comment(line: &str) -> &str {
        match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        }
    }
    fn quoted_literal(text: &str) -> Option<(String, usize)> {
        let mut chars = text.char_indices();
        let (_, quote) = chars.next()?;
        if quote != '\'' && quote != '"' && quote != '`' {
            return None;
        }
        let rest = &text[quote.len_utf8()..];
        let end = rest.find(quote)?;
        Some((rest[..end].to_string(), quote.len_utf8() + end + quote.len_utf8()))
    }
    fn require_path(expr: &str) -> Option<String> {
        let rest = expr.strip_prefix("require(")?.trim_start();
        let (path, _) = quoted_literal(rest)?;
        Some(path)
    }
    fn bindings_call_name(expr: &str) -> Option<String> {
        let rest = expr.strip_prefix("require(")?.trim_start();
        let (module, consumed) = quoted_literal(rest)?;
        if module != "bindings" {
            return None;
        }
        let rest = rest[consumed..].trim_start().trim_start_matches(')').trim_start();
        let rest = rest.strip_prefix('(')?.trim_start();
        let (name, _) = quoted_literal(rest)?;
        Some(name)
    }

    let mut libraries: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for raw_line in body.lines() {
        let line = strip_comment(raw_line).trim();
        let Some((lhs, rhs)) = line.split_once('=') else { continue };
        let alias = lhs.trim().trim_start_matches("const").trim_start_matches("let").trim_start_matches("var").trim();
        if alias.is_empty() || !alias.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$') {
            continue;
        }
        let rhs = rhs.trim().trim_end_matches(';').trim();
        let library = match require_path(rhs) {
            Some(path) if path.ends_with(".node") => path,
            _ => match bindings_call_name(rhs) {
                Some(name) => name,
                None => continue,
            },
        };
        libraries.insert(alias.to_string(), library);
    }

    let mut out = Vec::new();
    for raw_line in body.lines() {
        let line = strip_comment(raw_line);
        for (alias, library) in &libraries {
            let prefix = format!("{alias}.");
            let Some(start) = line.find(prefix.as_str()) else { continue };
            let rest = &line[start + prefix.len()..];
            let symbol: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$').collect();
            if !symbol.is_empty() {
                out.push((alias.clone(), symbol, library.clone()));
            }
        }
    }
    out
}

/// Persists any native-addon bindings discovered in `function`'s own source
/// span onto its symbol as a `js.ffi.calls` attribute — the JS analogue of
/// `lang_python`'s `python.ffi.calls`, read by
/// `crates/system_graph/src/js_ffi.rs`. A no-op when `function.symbol` is
/// `None` or the scan finds nothing.
fn record_native_addon_calls(builder: &mut ModuleBuilder, source: &str, function: &Function) {
    let Some(symbol) = function.symbol else { return };
    let start = function.span.start_byte as usize;
    let end = function.span.end_byte as usize;
    let Some(body) = source.get(start.min(source.len())..end.min(source.len())) else { return };
    let calls = js_native_addon_calls(body);
    if calls.is_empty() {
        return;
    }
    let encoded = calls.iter().map(|(alias, symbol, library)| format!("{alias}\u{1e}{symbol}\u{1e}{library}")).collect::<Vec<_>>().join("\u{1f}");
    builder.set_symbol_attribute(symbol, "js.ffi.calls", encoded);
}

/// Wraps `builder.push_item(Item::Function(item))`, additionally recording
/// any native-addon bindings found in the function's own body first.
fn push_function_item(builder: &mut ModuleBuilder, source: &str, item: Function) {
    record_native_addon_calls(builder, source, &item);
    builder.push_item(Item::Function(item));
}


fn qualified(module_name: &str, name: &str) -> String {
    format!("{module_name}.{name}")
}

/// A closure's captures (`Vec<LambdaCapture>`, the shape `Expr::Lambda`
/// carries) and a declared function's captures (`Vec<Param>`, the shape
/// `uniflow_hir::Function` carries) are different types for the same
/// concept — mirrors the conversion `uniflow_lowering`'s own
/// `assigned_lambda` helper performs when it hoists an inline lambda into a
/// named function.
fn captures_to_params(captures: Vec<uniflow_hir::LambdaCapture>) -> Vec<uniflow_hir::Param> {
    captures
        .into_iter()
        .map(|capture| uniflow_hir::Param {
            name: capture.name,
            symbol: capture.symbol,
            ty: capture.ty,
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span: capture.span,
        })
        .collect()
}

/// Registers every `import`/CommonJS `require` binding this file's
/// top-level statements introduce, so later call lowering (`crate::frontend::expr::lower_call`)
/// can resolve a bare `foo()`/`ns.foo()` call to another module's qualified
/// function name. `resolve_module` turns a relative specifier into this
/// project's module-name convention; it returns `None` for a bare package
/// specifier (`express`, `fs`) or one outside the project, which is left
/// unbound on purpose — a call through it still lowers, just without a
/// cross-file target.
pub(crate) fn bind_imports(
    builder: &mut ModuleBuilder,
    env: &mut JsEnv,
    current_path: &str,
    program: &js::Program,
    resolve_module: &dyn Fn(&str, &str) -> Option<String>,
    resolve_default_export: &dyn Fn(&str) -> String,
) {
    for stmt in &program.body {
        match stmt {
            js::Statement::ImportDeclaration(import) => {
                bind_import_declaration(builder, env, current_path, import, resolve_module, resolve_default_export);
            }
            js::Statement::VariableDeclaration(decl) => bind_require_declarators(builder, env, current_path, decl, resolve_module),
            _ => {}
        }
    }
}

fn bind_import_declaration(
    builder: &mut ModuleBuilder,
    env: &mut JsEnv,
    current_path: &str,
    import: &js::ImportDeclaration,
    resolve_module: &dyn Fn(&str, &str) -> Option<String>,
    resolve_default_export: &dyn Fn(&str) -> String,
) {
    // A bare-package specifier (`import * as child from "child_process"`)
    // never resolves to a project file — same fallback as
    // `bind_require_declarators`'s CommonJS side: use the specifier text
    // itself as the qualifier, rather than leaving the binding unset
    // entirely (which would make `child.spawn(...)` fall back to an
    // ordinary, unqualified receiver-based call and never match a
    // `^child_process\.spawn$`-style bundled rule).
    let specifier_text = import.source.value.as_str();
    let resolved_module = resolve_module(current_path, specifier_text);
    let target_module = resolved_module.clone().unwrap_or_else(|| specifier_text.to_string());
    let Some(specifiers) = &import.specifiers else { return };
    for specifier in specifiers {
        match specifier {
            js::ImportDeclarationSpecifier::ImportSpecifier(named) => {
                let imported_name = match &named.imported {
                    js::ModuleExportName::IdentifierName(id) => id.name.to_string(),
                    js::ModuleExportName::IdentifierReference(id) => id.name.to_string(),
                    js::ModuleExportName::StringLiteral(lit) => lit.value.to_string(),
                };
                env.set_import_binding(named.local.name.as_str(), ImportBinding::Named(qualified(&target_module, &imported_name)));
            }
            js::ImportDeclarationSpecifier::ImportDefaultSpecifier(default) => {
                let binding = match &resolved_module {
                    // A named default export (`export default function Foo() {}`)
                    // registers under `Foo`'s own name, not literally
                    // `"default"` (see `lower_module`'s
                    // `ExportDefaultDeclaration` handling) —
                    // `resolve_default_export` is what keeps this side
                    // agreeing with that one. Only meaningful once there IS
                    // a real project file to look the real name up in.
                    Some(_) => ImportBinding::Named(resolve_default_export(&target_module)),
                    // A bare-package default import (`import bluebird from
                    // "bluebird"`) has no project file to look a "real"
                    // default export name up in — treated as directly
                    // qualified by its own module name instead (matching
                    // `const bluebird = require("bluebird")`'s
                    // `ImportBinding::Namespace` convention exactly), not a
                    // fabricated and never-declared `"bluebird.default"`.
                    None => {
                        register_namespace_import(builder, &target_module, default.local.name.as_str());
                        ImportBinding::Namespace(target_module.clone())
                    }
                };
                env.set_import_binding(default.local.name.as_str(), binding);
            }
            js::ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) => {
                register_namespace_import(builder, &target_module, namespace.local.name.as_str());
                env.set_import_binding(namespace.local.name.as_str(), ImportBinding::Namespace(target_module.clone()));
            }
        }
    }
}

pub(crate) fn require_source<'a>(call: &'a js::Expression<'a>) -> Option<&'a str> {
    let js::Expression::CallExpression(call) = call else { return None };
    let js::Expression::Identifier(callee) = &call.callee else { return None };
    if callee.name != "require" {
        return None;
    }
    let js::Argument::StringLiteral(source) = call.arguments.first()? else { return None };
    Some(source.value.as_str())
}

/// Registers `local_name` with the *shared* `uniflow_lowering` import-alias
/// mechanism too (`builder.add_import`, populating `Module.imports`,
/// consumed by `current_import_aliases` — see
/// `uniflow_lowering::lowerer::entry::lower_module`). Without this, a bare
/// reference to a namespace-bound name in a value position (most importantly,
/// as a call *receiver*, e.g. `child.spawn(cmd)`) falls through to
/// `uniflow_lowering`'s own "undefined `VarRef`" fallback (any symbol this
/// frontend never gave a real `Let`/`Param` binding — which every import
/// binding is, since an import isn't a runtime `let`), which reconstructs a
/// receiver qualifier from the RAW LOCAL BINDING NAME (`"child"`) instead of
/// the real module name (`"child_process"`) — silently corrupting the
/// already-correct qualified callee name this frontend computed elsewhere
/// (`value_flow`'s own receiver-symbol reconciliation then prepends the
/// wrong text, e.g. `"child.child_process.spawn"`).
fn register_namespace_import(builder: &mut ModuleBuilder, target_module: &str, local_name: &str) {
    builder.add_import(target_module, Some(local_name.to_string()));
}

fn bind_require_declarators(builder: &mut ModuleBuilder, env: &mut JsEnv, current_path: &str, decl: &js::VariableDeclaration, resolve_module: &dyn Fn(&str, &str) -> Option<String>) {
    for declarator in &decl.declarations {
        let Some(init) = &declarator.init else { continue };
        let Some(specifier) = require_source(init) else { continue };
        // A built-in/bare-package `require` (`require("vm")`, `require("fs")`,
        // `require("express")`) never resolves to a project file, but a large
        // body of existing bundled taint rules (`^vm\.runInNewContext$`-style
        // regexes) is written expecting the literal module name as the
        // qualifier anyway (`const vm = require("vm"); vm.runInNewContext(...)`)
        // — falling back to the specifier text itself, rather than leaving
        // the binding unset, is what keeps that convention working the same
        // way it did before this frontend replaced the descriptor engine.
        let target_module = resolve_module(current_path, specifier).unwrap_or_else(|| specifier.to_string());
        match &declarator.id {
            js::BindingPattern::BindingIdentifier(ident) => {
                register_namespace_import(builder, &target_module, ident.name.as_str());
                env.set_import_binding(ident.name.as_str(), ImportBinding::Namespace(target_module.clone()));
            }
            js::BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    let (js::PropertyKey::StaticIdentifier(key), js::BindingPattern::BindingIdentifier(local)) = (&property.key, &property.value) else { continue };
                    env.set_import_binding(local.name.as_str(), ImportBinding::Named(qualified(&target_module, key.name.as_str())));
                }
            }
            _ => {}
        }
    }
}

fn lower_top_level_function(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, function: &js::Function, module_name: &str) -> Option<Function> {
    let id = function.id.as_ref()?;
    let name = qualified(module_name, id.name.as_str());
    let symbol = builder.add_symbol(id.name.as_str(), SymbolKind::Function);
    env.declare(id.name.as_str(), symbol);
    let (params, body, captures) = lower_function_parts(builder, env, source, &function.params, |builder, env, source| {
        function.body.as_ref().map(|body| lower_function_body(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
    });
    Some(Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: captures_to_params(captures),
        return_type: None,
        body,
        is_method: false,
        receiver: None,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span(builder, source, function.span),
    })
}

fn lower_class(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, class: &js::Class, module_name: &str) -> Class {
    let simple_name = class.id.as_ref().map(|id| id.name.to_string()).unwrap_or_else(|| "<anonymous>".to_string());
    let name = qualified(module_name, &simple_name);
    let class_symbol = builder.add_symbol(&simple_name, SymbolKind::Class);
    let bases = class
        .heritage
        .as_ref()
        .and_then(|heritage| match &heritage.expression {
            js::Expression::Identifier(ident) => Some(vec![ident.name.to_string()]),
            _ => None,
        })
        .unwrap_or_default();

    let mut fields = Vec::new();
    let mut methods = Vec::new();
    for element in &class.body.body {
        match element {
            js::ClassElement::PropertyDefinition(property) => {
                let field_name = match &property.key {
                    js::PropertyKey::StaticIdentifier(ident) => ident.name.to_string(),
                    js::PropertyKey::PrivateIdentifier(ident) => format!("#{}", ident.name),
                    _ => continue,
                };
                fields.push(Field { name: field_name.clone(), symbol: Some(builder.add_symbol(&field_name, SymbolKind::Field)), ty: None, span: span(builder, source, property.span) });
            }
            js::ClassElement::MethodDefinition(method) => {
                let method_name = match method.kind {
                    js::MethodDefinitionKind::Constructor => "constructor".to_string(),
                    _ => match &method.key {
                        js::PropertyKey::StaticIdentifier(ident) => ident.name.to_string(),
                        js::PropertyKey::PrivateIdentifier(ident) => format!("#{}", ident.name),
                        _ => continue,
                    },
                };
                let method_symbol = builder.add_symbol(&method_name, SymbolKind::Method);
                let this_symbol = (!method.r#static).then(|| builder.add_symbol("this", SymbolKind::Param));
                let (params, body, captures) = lower_function_parts(builder, env, source, &method.value.params, |builder, env, source| {
                    // `this` must be declared *after* the method's own
                    // scope opens (inside this closure, which runs once
                    // `lower_function_parts` has already entered it) —
                    // declaring it beforehand would bind it in the
                    // enclosing class/module scope instead.
                    if let Some(this_symbol) = this_symbol {
                        env.declare("this", this_symbol);
                    }
                    method.value.body.as_ref().map(|body| lower_function_body(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
                });
                let receiver = this_symbol.map(|this_symbol| uniflow_hir::Param {
                    name: "this".to_string(),
                    symbol: this_symbol,
                    ty: Some(builder.ensure_type(&name)),
                    kind: ParamKind::Positional,
                    has_default: false,
                    keyword_only: false,
                    cpp: Default::default(),
                    span: span(builder, source, method.span),
                });
                methods.push(Function {
                    id: builder.alloc_function_id(),
                    name: format!("{name}.{method_name}"),
                    symbol: Some(method_symbol),
                    params,
                    captures: captures_to_params(captures),
                    return_type: None,
                    body,
                    is_method: true,
                    receiver,
                    cpp: None,
                    cpp_initializers: Vec::new(),
                    span: span(builder, source, method.span),
                });
            }
            _ => {}
        }
    }

    Class { name, symbol: Some(class_symbol), bases, fields, methods, span: span(builder, source, class.span) }
}

/// Lowers every top-level statement of one file: real `function`/`class`
/// declarations (bare or `export`-wrapped) become `Item`s; everything else
/// accumulates into the synthetic `<script>` function's body. `env` must
/// already have this file's import bindings registered (see
/// [`bind_imports`]) before this runs.
/// Registers every top-level `function`/`class` name this file declares
/// (bare or `export`/`export default`-wrapped) into `env` *before* any
/// statement is lowered — matching real JS hoisting, where such a name is
/// callable from anywhere in the file, including a call that textually
/// precedes the declaration. Without this pre-scan, a same-file call would
/// lower to an unqualified `Callee::Static` that can never match the
/// declaration's own qualified name.
fn register_top_level_names(env: &mut JsEnv, program: &js::Program, module_name: &str) {
    for stmt in &program.body {
        match stmt {
            js::Statement::FunctionDeclaration(function) => {
                if let Some(id) = &function.id {
                    env.register_top_level_function(id.name.as_str(), qualified(module_name, id.name.as_str()));
                }
            }
            js::Statement::ClassDeclaration(class) => {
                if let Some(id) = &class.id {
                    env.register_top_level_function(id.name.as_str(), qualified(module_name, id.name.as_str()));
                }
            }
            js::Statement::ExportDeclaration(export) => match &export.declaration {
                js::Declaration::FunctionDeclaration(function) => {
                    if let Some(id) = &function.id {
                        env.register_top_level_function(id.name.as_str(), qualified(module_name, id.name.as_str()));
                    }
                }
                js::Declaration::ClassDeclaration(class) => {
                    if let Some(id) = &class.id {
                        env.register_top_level_function(id.name.as_str(), qualified(module_name, id.name.as_str()));
                    }
                }
                _ => {}
            },
            js::Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                js::ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                    if let Some(id) = &function.id {
                        env.register_top_level_function(id.name.as_str(), qualified(module_name, id.name.as_str()));
                    }
                }
                js::ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                    if let Some(id) = &class.id {
                        env.register_top_level_function(id.name.as_str(), qualified(module_name, id.name.as_str()));
                    }
                }
                _ => {}
            },
            js::Statement::ExpressionStatement(expr_stmt) => {
                if let Some((name, _)) = commonjs_export_function_target(&expr_stmt.expression) {
                    env.register_top_level_function(&name, qualified(module_name, &name));
                }
            }
            _ => {}
        }
    }
}

enum CommonJsExportedFunction<'a> {
    Function(&'a js::Function<'a>),
    Arrow(&'a js::ArrowFunctionExpression<'a>),
}

fn extract_function_like<'a>(expr: &'a js::Expression<'a>) -> Option<CommonJsExportedFunction<'a>> {
    match expr {
        js::Expression::FunctionExpression(function) => Some(CommonJsExportedFunction::Function(function)),
        js::Expression::ArrowFunctionExpression(arrow) => Some(CommonJsExportedFunction::Arrow(arrow)),
        _ => None,
    }
}

fn function_like_own_name(function_like: &CommonJsExportedFunction) -> Option<String> {
    match function_like {
        CommonJsExportedFunction::Function(function) => function.id.as_ref().map(|id| id.name.to_string()),
        CommonJsExportedFunction::Arrow(_) => None,
    }
}

/// Recognizes `exports.NAME = <function/arrow>`, `module.exports.NAME =
/// <function/arrow>`, and the whole-module `module.exports = <function/arrow>`
/// — CommonJS's equivalent of `export function NAME(){}` / `export default
/// function(){}`. Without this, e.g. `exports.handler = function(event){}`
/// (the standard AWS Lambda entry-point shape) falls through to the generic
/// top-level-statement path and becomes an anonymous closure inside the
/// synthetic `<script>` function — never named `....handler`, so any rule
/// matching a *function's own name* (`(^|\.)handler$`) can never fire, and
/// its parameter is never tainted at all.
fn commonjs_export_function_target<'a>(expr: &'a js::Expression<'a>) -> Option<(String, CommonJsExportedFunction<'a>)> {
    let js::Expression::AssignmentExpression(assign) = expr else { return None };
    if !assign.operator.is_assign() {
        return None;
    }
    let js::AssignmentTarget::StaticMemberExpression(member) = &assign.left else { return None };
    let is_module_identifier = |object: &js::Expression| matches!(object, js::Expression::Identifier(id) if id.name.as_str() == "module");

    if let js::Expression::StaticMemberExpression(inner) = &member.object {
        if is_module_identifier(&inner.object) && inner.property.name.as_str() == "exports" {
            let function_like = extract_function_like(&assign.right)?;
            return Some((member.property.name.to_string(), function_like));
        }
    }
    if matches!(&member.object, js::Expression::Identifier(id) if id.name.as_str() == "exports") {
        let function_like = extract_function_like(&assign.right)?;
        return Some((member.property.name.to_string(), function_like));
    }
    if is_module_identifier(&member.object) && member.property.name.as_str() == "exports" {
        let function_like = extract_function_like(&assign.right)?;
        let name = function_like_own_name(&function_like).unwrap_or_else(|| "default".to_string());
        return Some((name, function_like));
    }
    None
}

fn lower_commonjs_exported_function(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, function_like: CommonJsExportedFunction, qualified_name: String) -> Function {
    let simple_name = qualified_name.rsplit('.').next().unwrap_or(&qualified_name).to_string();
    match function_like {
        CommonJsExportedFunction::Function(function) => {
            let symbol = builder.add_symbol(&simple_name, SymbolKind::Function);
            let (params, body, captures) = lower_function_parts(builder, env, source, &function.params, |builder, env, source| {
                function.body.as_ref().map(|body| lower_function_body(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
            });
            Function {
                id: builder.alloc_function_id(),
                name: qualified_name,
                symbol: Some(symbol),
                params,
                captures: captures_to_params(captures),
                return_type: None,
                body,
                is_method: false,
                receiver: None,
                cpp: None,
                cpp_initializers: Vec::new(),
                span: span(builder, source, function.span),
            }
        }
        CommonJsExportedFunction::Arrow(arrow) => {
            let symbol = builder.add_symbol(&simple_name, SymbolKind::Function);
            let arrow_span = span(builder, source, arrow.span);
            let (params, body, captures) = lower_function_parts(builder, env, source, &arrow.params, |builder, env, source| match &arrow.body {
                js::ArrowFunctionBody::FunctionBody(body) => lower_function_body(builder, env, source, body),
                concise => {
                    let concise_expr = concise.as_expression().expect("a non-FunctionBody arrow body is always an expression");
                    let value = crate::frontend::expr::lower_expr(builder, env, source, concise_expr);
                    let value_span = value.span();
                    Block { id: builder.alloc_block_id(), stmts: vec![Stmt::Return { id: builder.alloc_stmt_id(), value: Some(value), span: value_span }], span: value_span }
                }
            });
            Function {
                id: builder.alloc_function_id(),
                name: qualified_name,
                symbol: Some(symbol),
                params,
                captures: captures_to_params(captures),
                return_type: None,
                body,
                is_method: false,
                receiver: None,
                cpp: None,
                cpp_initializers: Vec::new(),
                span: arrow_span,
            }
        }
    }
}

pub(crate) fn lower_module(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, program: &js::Program, module_name: &str) {
    register_top_level_names(env, program, module_name);
    let mut script_stmts: Vec<Stmt> = Vec::new();
    for stmt in &program.body {
        match stmt {
            js::Statement::FunctionDeclaration(function) => {
                if let Some(item) = lower_top_level_function(builder, env, source, function, module_name) {
                    push_function_item(builder, source, item);
                }
            }
            js::Statement::ClassDeclaration(class) => {
                let item = lower_class(builder, env, source, class, module_name);
                builder.push_item(Item::Class(item));
            }
            js::Statement::ExportDeclaration(export) => match &export.declaration {
                js::Declaration::FunctionDeclaration(function) => {
                    if let Some(item) = lower_top_level_function(builder, env, source, function, module_name) {
                        push_function_item(builder, source, item);
                    }
                }
                js::Declaration::ClassDeclaration(class) => {
                    let item = lower_class(builder, env, source, class, module_name);
                    builder.push_item(Item::Class(item));
                }
                js::Declaration::VariableDeclaration(decl) => {
                    lower_variable_declaration(builder, env, source, decl, &mut script_stmts);
                }
                _ => {}
            },
            js::Statement::ExportDefaultDeclaration(export) => match &export.declaration {
                js::ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                    if function.id.is_some() {
                        if let Some(item) = lower_top_level_function(builder, env, source, function, module_name) {
                            push_function_item(builder, source, item);
                        }
                    } else {
                        let (params, body, captures) = lower_function_parts(builder, env, source, &function.params, |builder, env, source| {
                            function.body.as_ref().map(|body| lower_function_body(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
                        });
                        let symbol = builder.add_symbol("default", SymbolKind::Function);
                        let function_id = builder.alloc_function_id();
                        let function_span = span(builder, source, function.span);
                        let default_export = Function {
                            id: function_id,
                            name: qualified(module_name, "default"),
                            symbol: Some(symbol),
                            params,
                            captures: captures_to_params(captures),
                            return_type: None,
                            body,
                            is_method: false,
                            receiver: None,
                            cpp: None,
                            cpp_initializers: Vec::new(),
                            span: function_span,
                        };
                        push_function_item(builder, source, default_export);
                    }
                }
                js::ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                    let item = lower_class(builder, env, source, class, module_name);
                    builder.push_item(Item::Class(item));
                }
                _ => {}
            },
            js::Statement::ImportDeclaration(_)
            | js::Statement::ExportNamedDeclaration(_)
            | js::Statement::ExportAllDeclaration(_) => {
                // Import bindings were already resolved in `bind_imports`; a
                // bare re-export (`export { a, b };`) names an already-
                // declared local and needs no further lowering here.
            }
            js::Statement::ExpressionStatement(expr_stmt) => {
                if let Some((name, function_like)) = commonjs_export_function_target(&expr_stmt.expression) {
                    let qualified_name = qualified(module_name, &name);
                    let item = lower_commonjs_exported_function(builder, env, source, function_like, qualified_name);
                    push_function_item(builder, source, item);
                    continue;
                }
                script_stmts.extend(lower_stmt(builder, env, source, stmt));
            }
            other => script_stmts.extend(lower_stmt(builder, env, source, other)),
        }
    }

    if !script_stmts.is_empty() {
        let module_span = span(builder, source, program.span);
        let symbol = builder.add_symbol(MODULE_INIT_SUFFIX, SymbolKind::Function);
        let function_id = builder.alloc_function_id();
        let body_id = builder.alloc_block_id();
        let script_function = Function {
            id: function_id,
            name: format!("{module_name}.{MODULE_INIT_SUFFIX}"),
            symbol: Some(symbol),
            params: Vec::new(),
            captures: Vec::new(),
            return_type: None,
            body: Block { id: body_id, stmts: script_stmts, span: module_span },
            is_method: false,
            receiver: None,
            cpp: None,
            cpp_initializers: Vec::new(),
            span: module_span,
        };
        push_function_item(builder, source, script_function);
    }
}
