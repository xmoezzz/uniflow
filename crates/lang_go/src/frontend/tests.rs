use uniflow_hir::{CallTarget, Expr, Item, Stmt};
use uniflow_parser_core::SourceParser;

use super::project_index::parse_project_sources;
use super::GoParser;

fn parse(source: &str) -> uniflow_hir::Program {
    GoParser::default().parse_file("probe.go", source).expect("parse go")
}

fn only_module(program: &uniflow_hir::Program) -> &uniflow_hir::Module {
    program.modules.first().expect("one module")
}

#[test]
fn a_free_top_level_function_becomes_a_real_item() {
    let program = parse(
        r#"
package main

func add(a int, b int) int {
	return a + b
}
"#,
    );
    let module = only_module(&program);
    let function = module.items.iter().find_map(|item| match item {
        Item::Function(function) if function.name.ends_with("add") => Some(function),
        _ => None,
    });
    let function = function.expect("an `add` function item");
    assert_eq!(function.name, "main.add");
    assert_eq!(function.params.len(), 2);
    assert!(matches!(function.body.stmts.as_slice(), [Stmt::Return { value: Some(Expr::Binary { .. }), .. }]));
}

#[test]
fn a_struct_and_pointer_receiver_method_become_a_class_with_the_method_attached() {
    let program = parse(
        r#"
package main

type Counter struct {
	Value int
}

func (c *Counter) Increment(amount int) {
	c.Value = c.Value + amount
}
"#,
    );
    let module = only_module(&program);
    let class = module.items.iter().find_map(|item| match item {
        Item::Class(class) if class.name == "main.Counter" => Some(class),
        _ => None,
    });
    let class = class.expect("a Counter class item");
    assert_eq!(class.fields.len(), 1, "{class:#?}");
    assert_eq!(class.fields[0].name, "Value");
    assert_eq!(class.methods.len(), 1, "{class:#?}");
    let method = &class.methods[0];
    assert_eq!(method.name, "main.Counter.Increment");
    assert!(method.is_method);
    assert!(method.receiver.is_some(), "{method:#?}");
    // The method body both reads (`c.Value`) and writes (`c.Value = ...`)
    // its own receiver's field.
    let Stmt::Assign { lhs: uniflow_hir::LValue::Field { field, .. }, rhs, .. } = &method.body.stmts[0] else {
        panic!("expected an assignment to a field of the receiver: {method:#?}")
    };
    assert_eq!(field, "Value");
    assert!(matches!(rhs, Expr::Binary { lhs, .. } if matches!(&**lhs, Expr::FieldRead { field, .. } if field == "Value")));
}

#[test]
fn a_short_var_declaration_preserves_symbol_identity_across_subsequent_uses() {
    let program = parse(
        r#"
package main

func run() {
	value := compute()
	sink(value)
	sink(value)
}
"#,
    );
    let module = only_module(&program);
    let Item::Function(function) = module.items.iter().find(|item| matches!(item, Item::Function(f) if f.name.ends_with("run"))).unwrap() else { unreachable!() };
    let Stmt::Let { symbol: declared_symbol, .. } = &function.body.stmts[0] else { panic!("expected a Let statement: {function:#?}") };
    for stmt in &function.body.stmts[1..] {
        let Stmt::Expr { expr: Expr::Call(call), .. } = stmt else { panic!("expected a call statement: {stmt:#?}") };
        let Some(arg) = call.args.first() else { panic!("expected sink(value) to carry an argument") };
        let Expr::VarRef { symbol, .. } = arg else { panic!("expected a VarRef argument: {arg:#?}") };
        assert_eq!(symbol, declared_symbol, "every use of `value` must resolve to the same symbol");
    }
}

#[test]
fn a_package_spread_across_two_files_resolves_a_zero_import_cross_file_call() {
    let program = parse_project_sources(&[
        ("a.go".to_string(), "package app\n\nfunc run() {\n\thelper()\n}\n".to_string()),
        ("b.go".to_string(), "package app\n\nfunc helper() {\n}\n".to_string()),
    ])
    .expect("parse go project");

    let run_function = program
        .modules
        .iter()
        .flat_map(|module| &module.items)
        .find_map(|item| match item {
            Item::Function(function) if function.name.ends_with(".run") => Some(function),
            _ => None,
        })
        .expect("a run function");
    let Stmt::Expr { expr: Expr::Call(call), .. } = &run_function.body.stmts[0] else { panic!("expected a call statement: {run_function:#?}") };
    let CallTarget::Named(target) = &call.target else { panic!("expected a named call target: {call:#?}") };
    assert_eq!(target, "app.helper", "a same-package, zero-import call must resolve to the sibling file's own qualified name");
}

#[test]
fn an_imported_stdlib_call_produces_the_qualified_dotted_name() {
    let program = parse(
        r#"
package main

import "os"

func run() string {
	return os.Getenv("X")
}
"#,
    );
    let module = only_module(&program);
    let Item::Function(function) = module.items.iter().find(|item| matches!(item, Item::Function(f) if f.name.ends_with("run"))).unwrap() else { unreachable!() };
    let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else { panic!("expected a return call: {function:#?}") };
    let CallTarget::Named(target) = &call.target else { panic!("expected a named call target: {call:#?}") };
    assert_eq!(target, "os.Getenv");
    assert!(call.receiver.is_none(), "a bare package-qualified call has no real receiver value: {call:#?}");
}

#[test]
fn a_typed_parameter_resolves_the_exact_qualified_callee_the_legacy_rule_catalog_depends_on() {
    // This is the single most important case: `legacy.go.source.0.0.web`
    // matches calls whose qualified callee name is
    // `net/http.Request.FormValue` (or `.FormFile`) — this can ONLY work if
    // a `*http.Request`-typed parameter's declared type resolves to
    // `net/http.Request` and that qualifier is then combined with the
    // called method's own name.
    let program = parse(
        r#"
package main

import "net/http"

func handle(r *http.Request) string {
	return r.FormValue("x")
}
"#,
    );
    let module = only_module(&program);
    let Item::Function(function) = module.items.iter().find(|item| matches!(item, Item::Function(f) if f.name.ends_with("handle"))).unwrap() else { unreachable!() };
    let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else { panic!("expected a return call: {function:#?}") };
    let CallTarget::Named(target) = &call.target else { panic!("expected a named call target: {call:#?}") };
    assert_eq!(target, "net/http.Request.FormValue", "typed-parameter method calls must resolve to the real stdlib qualified name");
    // The receiver (`r`) must still be preserved as a real expression, not
    // discarded just because a qualified target name was also derived (this
    // is required for `propagators`-style receiver->return rules).
    assert!(call.receiver.is_some(), "{call:#?}");
}
