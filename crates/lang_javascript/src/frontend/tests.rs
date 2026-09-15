use uniflow_hir::{Expr, Item, LiteralKind, Stmt};
use uniflow_parser_core::SourceParser;

use super::JavaScriptParser;
use super::project_index::parse_project_sources;

fn parse(source: &str) -> uniflow_hir::Program {
    JavaScriptParser::default().parse_file("probe.js", source).expect("parse javascript")
}

fn only_module(program: &uniflow_hir::Program) -> &uniflow_hir::Module {
    program.modules.first().expect("one module")
}

#[test]
fn a_named_top_level_function_becomes_a_real_item() {
    let program = parse("function add(a, b) { return a + b; }");
    let module = only_module(&program);
    assert_eq!(module.items.len(), 1, "{module:#?}");
    let Item::Function(function) = &module.items[0] else { panic!("expected a function item: {module:#?}") };
    assert_eq!(function.name, "probe.add");
    assert_eq!(function.params.len(), 2);
    assert_eq!(function.params[0].name, "a");
    assert!(matches!(function.body.stmts.as_slice(), [Stmt::Return { value: Some(Expr::Binary { .. }), .. }]));
}

#[test]
fn top_level_executable_statements_are_wrapped_in_a_synthetic_script_function() {
    let program = parse(
        r#"
const express = require('express');
const app = express();
app.get('/profile', function handler(req, res) {
sink(req);
});
app.listen(3000);
"#,
    );
    let module = only_module(&program);
    let script = module.items.iter().find_map(|item| match item {
        Item::Function(function) if function.name.ends_with("<script>") => Some(function),
        _ => None,
    });
    let script = script.expect("a synthetic <script> function should exist");
    // `const app = express(); app.get(...); app.listen(...)` — three
    // top-level statements, all visible in ONE function body, exactly
    // what every system-graph adapter (which scans function bodies)
    // needs to see for a bare Express top-level script to be analyzable
    // at all.
    assert_eq!(script.body.stmts.len(), 4, "{script:#?}");
    let Stmt::Expr { expr: Expr::Call(call), .. } = &script.body.stmts[2] else { panic!("expected app.get(...) call: {script:#?}") };
    assert!(call.receiver.is_some(), "app.get(...) must carry app as an explicit receiver: {call:#?}");
    assert_eq!(call.args.len(), 2);
    assert!(matches!(&call.args[1], Expr::Lambda { .. }), "the handler argument should lower to an inline closure: {call:#?}");
}

#[test]
fn a_template_literal_preserves_ordered_literal_and_dynamic_pieces() {
    let program = parse("function build(id) { return `/profile?id=${id}&x=1`; }");
    let module = only_module(&program);
    let Item::Function(function) = &module.items[0] else { panic!() };
    let Stmt::Return { value: Some(Expr::Interp { parts, .. }), .. } = &function.body.stmts[0] else {
        panic!("expected an Interp return value: {function:#?}")
    };
    // Order matters: "/profile?id=" (literal), id (dynamic), "&x=1" (literal).
    assert_eq!(parts.len(), 3, "{parts:#?}");
    assert!(matches!(&parts[0], Expr::Literal { kind: LiteralKind::String(text), .. } if text == "/profile?id="));
    assert!(matches!(&parts[1], Expr::VarRef { .. }));
    assert!(matches!(&parts[2], Expr::Literal { kind: LiteralKind::String(text), .. } if text == "&x=1"));
}

#[test]
fn destructuring_assignment_preserves_field_level_value_flow() {
    let program = parse("function handle(req) { const { id } = req.query; sink(id); }");
    let module = only_module(&program);
    let Item::Function(function) = &module.items[0] else { panic!() };
    let Stmt::Let { init: Some(Expr::FieldRead { field, base, .. }), .. } = &function.body.stmts[0] else {
        panic!("expected `id` to be bound via a FieldRead off req.query: {function:#?}")
    };
    assert_eq!(field, "id");
    assert!(matches!(&**base, Expr::FieldRead { field, .. } if field == "query"));
}

#[test]
fn a_destructured_parameter_preserves_the_functions_real_arity() {
    // `function f({a, b})` takes ONE argument (an object); `a`/`b` are
    // fields projected from it, not two separate positional parameters —
    // getting this wrong would silently change the function's arity and
    // misattribute which argument each name actually reads from.
    let program = parse("function f({ a, b }) { return a + b; }");
    let module = only_module(&program);
    let Item::Function(function) = &module.items[0] else { panic!() };
    assert_eq!(function.params.len(), 1, "destructured params must not expand the function's arity: {function:#?}");
    let Stmt::Let { init: Some(Expr::FieldRead { base, field, .. }), .. } = &function.body.stmts[0] else {
        panic!("expected `a` to be projected via a FieldRead prologue statement: {function:#?}")
    };
    assert_eq!(field, "a");
    assert!(matches!(&**base, Expr::VarRef { .. }), "the field must be read off the single synthetic parameter: {function:#?}");
}

#[test]
fn a_destructuring_assignment_expression_assigns_the_real_targets() {
    // `({a, b} = obj);` used as a bare statement must assign the REAL `a`/
    // `b` bindings — not a throwaway discard local (the fallback this
    // frontend uses only for a destructuring assignment used as a genuine
    // sub-expression value, a much rarer case).
    let program = parse("function f(obj) { let a; let b; ({ a, b } = obj); return a + b; }");
    let module = only_module(&program);
    let Item::Function(function) = &module.items[0] else { panic!() };
    let assign_a = function.body.stmts.iter().find(|stmt| matches!(stmt, Stmt::Assign { lhs: uniflow_hir::LValue::Var(_), rhs: Expr::FieldRead { field, .. }, .. } if field == "a"));
    assert!(assign_a.is_some(), "expected a real assignment to `a` projected from `obj.a`: {function:#?}");
    let assign_b = function.body.stmts.iter().find(|stmt| matches!(stmt, Stmt::Assign { lhs: uniflow_hir::LValue::Var(_), rhs: Expr::FieldRead { field, .. }, .. } if field == "b"));
    assert!(assign_b.is_some(), "expected a real assignment to `b` projected from `obj.b`: {function:#?}");
}

#[test]
fn a_named_default_export_resolves_to_its_own_declared_name_not_literally_default() {
    // `export default function Foo() {}` registers as `utils.Foo` (see
    // `decl::lower_module`'s `ExportDefaultDeclaration` handling) — an
    // importer must resolve to that same name, not a hardcoded
    // `utils.default` that nothing ever actually declares.
    let program = parse_project_sources(&[
        ("utils.js".to_string(), "export default function Foo(value) { return value; }".to_string()),
        (
            "app.js".to_string(),
            r#"
import Foo from './utils';
function run(input) {
return Foo(input);
}
"#
            .to_string(),
        ),
    ])
    .expect("parse javascript project");

    let run_function = program
        .modules
        .iter()
        .flat_map(|module| &module.items)
        .find_map(|item| match item {
            Item::Function(function) if function.name.ends_with(".run") => Some(function),
            _ => None,
        })
        .expect("run function");
    let Stmt::Return { value: Some(Expr::Call(call)), .. } = &run_function.body.stmts[0] else { panic!("expected a return call: {run_function:#?}") };
    let uniflow_hir::CallTarget::Named(target) = &call.target else { panic!("expected a named call target: {call:#?}") };
    assert_eq!(target, "utils.Foo", "a named default export must resolve to its own declared name");
}

#[test]
fn one_fatal_javascript_file_does_not_abort_an_entire_project_scan() {
    let program = parse_project_sources(&[
        ("broken.js".to_string(), "function { this is not valid JavaScript".to_string()),
        ("server.js".to_string(), "function handle(input) { sink(input); }".to_string()),
    ])
    .expect("a valid project module must survive an unrelated fatal source");
    assert!(
        program
            .modules
            .iter()
            .flat_map(|module| &module.items)
            .any(|item| matches!(item, Item::Function(function) if function.name == "server.handle")),
        "valid source was lost: {program:#?}"
    );
}

#[test]
fn a_class_method_reads_and_writes_its_own_fields() {
    let program = parse(
        r#"
class Counter {
constructor(start) {
    this.value = start;
}
increment() {
    this.value = this.value + 1;
    return this.value;
}
}
"#,
    );
    let module = only_module(&program);
    let Item::Class(class) = &module.items[0] else { panic!("expected a class item: {module:#?}") };
    assert_eq!(class.name, "probe.Counter");
    assert_eq!(class.methods.len(), 2, "{class:#?}");
    let increment = class.methods.iter().find(|m| m.name.ends_with(".increment")).expect("increment method");
    assert!(increment.receiver.is_some(), "an instance method must carry a `this` receiver");
}

#[test]
fn a_named_import_resolves_a_call_to_the_exporting_files_qualified_name() {
    let program = parse_project_sources(&[
        ("utils.js".to_string(), "export function sanitize(value) { return value; }".to_string()),
        (
            "app.js".to_string(),
            r#"
import { sanitize } from './utils';
function run(input) {
return sanitize(input);
}
"#
            .to_string(),
        ),
    ])
    .expect("parse javascript project");

    let run_function = program
        .modules
        .iter()
        .flat_map(|module| &module.items)
        .find_map(|item| match item {
            Item::Function(function) if function.name.ends_with(".run") => Some(function),
            _ => None,
        })
        .expect("run function");
    let Stmt::Return { value: Some(Expr::Call(call)), .. } = &run_function.body.stmts[0] else { panic!("expected a return call: {run_function:#?}") };
    let uniflow_hir::CallTarget::Named(target) = &call.target else { panic!("expected a named call target: {call:#?}") };
    assert_eq!(target, "utils.sanitize", "the import must resolve to the exporting file's own qualified name");
}

#[test]
fn a_commonjs_require_destructure_resolves_the_same_way_as_an_esm_import() {
    let program = parse_project_sources(&[
        ("db.js".to_string(), "function query(sql) { return sql; }\nmodule.exports = { query };".to_string()),
        (
            "server.js".to_string(),
            r#"
const { query } = require('./db');
function load(sql) {
return query(sql);
}
"#
            .to_string(),
        ),
    ])
    .expect("parse javascript project");

    let load_function = program
        .modules
        .iter()
        .flat_map(|module| &module.items)
        .find_map(|item| match item {
            Item::Function(function) if function.name.ends_with(".load") => Some(function),
            _ => None,
        })
        .expect("load function");
    let Stmt::Return { value: Some(Expr::Call(call)), .. } = &load_function.body.stmts[0] else { panic!("expected a return call: {load_function:#?}") };
    let uniflow_hir::CallTarget::Named(target) = &call.target else { panic!("expected a named call target: {call:#?}") };
    assert_eq!(target, "db.query");
}
