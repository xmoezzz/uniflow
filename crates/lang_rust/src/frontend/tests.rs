use uniflow_hir::{Block, CallTarget, Expr, Function, Item, Program, Stmt};

use crate::frontend::project_index::parse_file_standalone;

fn parse(source: &str) -> Program {
    parse_file_standalone("test.rs", source).expect("source should parse and lower")
}

fn functions(program: &Program) -> Vec<&Function> {
    let mut out = Vec::new();
    for module in &program.modules {
        for item in &module.items {
            match item {
                Item::Function(f) => out.push(f),
                Item::Class(class) => out.extend(class.methods.iter()),
                Item::GlobalVar(_) => {}
            }
        }
    }
    out
}

fn find_function<'a>(program: &'a Program, name: &str) -> &'a Function {
    functions(program).into_iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no function named {name}, had: {:?}", functions(program).iter().map(|f| &f.name).collect::<Vec<_>>()))
}

fn collect_call_targets_expr(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Call(call) => {
            if let CallTarget::Named(name) = &call.target {
                out.push(name.clone());
            }
            if let Some(receiver) = &call.receiver {
                collect_call_targets_expr(receiver, out);
            }
            for arg in &call.args {
                collect_call_targets_expr(arg, out);
            }
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => collect_call_targets_expr(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_call_targets_expr(lhs, out);
            collect_call_targets_expr(rhs, out);
        }
        Expr::FieldRead { base, .. } => collect_call_targets_expr(base, out),
        Expr::IndexRead { base, index, .. } => {
            collect_call_targets_expr(base, out);
            collect_call_targets_expr(index, out);
        }
        Expr::Assign { rhs, .. } => collect_call_targets_expr(rhs, out),
        Expr::Interp { parts, .. } => parts.iter().for_each(|part| collect_call_targets_expr(part, out)),
        Expr::Collection { elements, .. } => elements.iter().for_each(|element| collect_call_targets_expr(element, out)),
        Expr::Conditional { cond, then_expr, else_expr, .. } => {
            collect_call_targets_expr(cond, out);
            collect_call_targets_expr(then_expr, out);
            collect_call_targets_expr(else_expr, out);
        }
        Expr::Range { low, high, .. } => {
            collect_call_targets_expr(low, out);
            collect_call_targets_expr(high, out);
        }
        Expr::Lambda { body, .. } => collect_call_targets_block(body, out),
        _ => {}
    }
}

fn collect_call_targets_stmt(stmt: &Stmt, out: &mut Vec<String>) {
    match stmt {
        Stmt::Let { init, .. } => {
            if let Some(expr) = init {
                collect_call_targets_expr(expr, out);
            }
        }
        Stmt::Assign { rhs, .. } => collect_call_targets_expr(rhs, out),
        Stmt::Expr { expr, .. } => collect_call_targets_expr(expr, out),
        Stmt::If { cond, then_block, else_block, .. } => {
            collect_call_targets_expr(cond, out);
            collect_call_targets_block(then_block, out);
            if let Some(block) = else_block {
                collect_call_targets_block(block, out);
            }
        }
        Stmt::While { cond, body, .. } => {
            collect_call_targets_expr(cond, out);
            collect_call_targets_block(body, out);
        }
        Stmt::For { init, cond, update, body, .. } => {
            collect_call_targets_block(init, out);
            if let Some(cond) = cond {
                collect_call_targets_expr(cond, out);
            }
            collect_call_targets_block(update, out);
            collect_call_targets_block(body, out);
        }
        Stmt::ForEach { iterable, body, .. } => {
            collect_call_targets_expr(iterable, out);
            collect_call_targets_block(body, out);
        }
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
            if let Some(value) = value {
                collect_call_targets_expr(value, out);
            }
        }
        Stmt::Try { try_block, catches, finally_block, .. } => {
            collect_call_targets_block(try_block, out);
            for catch in catches {
                collect_call_targets_block(&catch.body, out);
            }
            if let Some(block) = finally_block {
                collect_call_targets_block(block, out);
            }
        }
        Stmt::Switch { scrutinee, clauses, default, .. } => {
            collect_call_targets_expr(scrutinee, out);
            for clause in clauses {
                collect_call_targets_block(&clause.body, out);
            }
            if let Some(block) = default {
                collect_call_targets_block(block, out);
            }
        }
        Stmt::DoWhile { body, cond, .. } => {
            collect_call_targets_block(body, out);
            collect_call_targets_expr(cond, out);
        }
        Stmt::Break { .. } | Stmt::Continue { .. } => {}
    }
}

fn collect_call_targets_block(block: &Block, out: &mut Vec<String>) {
    for stmt in &block.stmts {
        collect_call_targets_stmt(stmt, out);
    }
}

fn call_targets(function: &Function) -> Vec<String> {
    let mut out = Vec::new();
    collect_call_targets_block(&function.body, &mut out);
    out
}

#[test]
fn a_free_function_with_a_tail_expression_returns_its_value() {
    let program = parse("fn add(a: i32, b: i32) -> i32 { a + b }");
    let function = find_function(&program, "test.add");
    assert!(matches!(function.body.stmts.as_slice(), [Stmt::Return { value: Some(_), .. }]));
}

#[test]
fn a_use_import_qualifies_a_chained_builder_call() {
    let program = parse(
        r#"
        use std::process::Command;
        fn run(cmd: &str) {
            Command::new(cmd).arg("-l").spawn().unwrap();
        }
        "#,
    );
    let function = find_function(&program, "test.run");
    let targets = call_targets(function);
    assert!(targets.iter().any(|t| t == "std.process.Command.new"), "targets: {targets:?}");
    assert!(targets.iter().any(|t| t == "std.process.Command.new.arg"), "targets: {targets:?}");
    assert!(targets.iter().any(|t| t == "std.process.Command.new.arg.spawn"), "targets: {targets:?}");
}

#[test]
fn a_bare_call_to_a_same_module_function_carries_its_qualified_name() {
    let program = parse(
        r#"
        fn helper(x: i32) -> i32 { x }
        fn run() { helper(1); }
        "#,
    );
    let function = find_function(&program, "test.run");
    let targets = call_targets(function);
    assert!(targets.iter().any(|t| t == "test.helper"), "targets: {targets:?}");
}

#[test]
fn an_impl_method_becomes_a_qualified_function_with_a_self_receiver() {
    let program = parse(
        r#"
        struct Greeter { name: String }
        impl Greeter {
            fn greet(&self) -> String { self.name.clone() }
        }
        "#,
    );
    let function = find_function(&program, "test.Greeter.greet");
    assert!(function.receiver.is_some());
    let targets = call_targets(function);
    assert!(targets.iter().any(|t| t == "clone"), "targets: {targets:?}");
}

#[test]
fn a_closure_captures_an_outer_local() {
    let program = parse(
        r#"
        fn run() {
            let secret = "s3cr3t".to_string();
            let leak = move || println!("{}", secret);
            leak();
        }
        "#,
    );
    let function = find_function(&program, "test.run");
    assert!(!call_targets(function).is_empty());
}

#[test]
fn if_let_binds_the_matched_value_into_the_then_branch() {
    let program = parse(
        r#"
        fn run(input: Option<String>) {
            if let Some(value) = input {
                println!("{}", value);
            }
        }
        "#,
    );
    let function = find_function(&program, "test.run");
    let Stmt::If { then_block, .. } = &function.body.stmts[0] else { panic!("expected an if statement") };
    assert!(matches!(then_block.stmts.first(), Some(Stmt::Let { .. })));
}

#[test]
fn format_macro_interpolates_arguments_in_source_order() {
    let program = parse(
        r#"
        fn build(name: &str) -> String {
            format!("SELECT * FROM users WHERE name = '{}'", name)
        }
        "#,
    );
    let function = find_function(&program, "test.build");
    let Stmt::Return { value: Some(Expr::Interp { parts, .. }), .. } = &function.body.stmts[0] else { panic!("expected an interpolated return value") };
    assert!(parts.len() >= 2, "parts: {parts:?}");
}

#[test]
fn tuple_destructuring_let_projects_each_element() {
    let program = parse(
        r#"
        fn run(pair: (i32, i32)) {
            let (a, b) = pair;
            let _ = a + b;
        }
        "#,
    );
    let function = find_function(&program, "test.run");
    let let_count = function.body.stmts.iter().filter(|stmt| matches!(stmt, Stmt::Let { .. })).count();
    assert!(let_count >= 2, "stmts: {:?}", function.body.stmts);
}
