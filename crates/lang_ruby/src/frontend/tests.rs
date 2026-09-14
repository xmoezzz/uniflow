use uniflow_hir::{Block, CallTarget, Expr, Function, Item, Program, Stmt};

use crate::frontend::project_index::parse_file_standalone;

fn parse(source: &str) -> Program {
    parse_file_standalone("test.rb", source).expect("source should parse and lower")
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
fn a_free_top_level_def_becomes_an_item_function() {
    let program = parse("def add(a, b)\n  a + b\nend\n");
    let function = find_function(&program, "test.add");
    assert!(matches!(function.body.stmts.as_slice(), [Stmt::Return { value: Some(_), .. }]));
}

#[test]
fn a_bare_call_to_a_same_file_function_carries_its_qualified_name() {
    let program = parse(
        r#"
        def helper(x)
          x
        end
        def run
          helper(1)
        end
        "#,
    );
    let function = find_function(&program, "test.run");
    let targets = call_targets(function);
    assert!(targets.iter().any(|t| t == "test.helper"), "targets: {targets:?}");
}

#[test]
fn a_class_with_an_instance_method_reads_and_writes_its_own_ivar() {
    let program = parse(
        r#"
        class Greeter
          def set_name(n)
            @name = n
          end
          def greet
            @name
          end
        end
        "#,
    );
    let program_items: Vec<_> = program.modules.iter().flat_map(|m| &m.items).collect();
    let class = program_items
        .iter()
        .find_map(|item| match item {
            Item::Class(c) if c.name == "test.Greeter" => Some(c),
            _ => None,
        })
        .expect("Greeter class");
    assert!(class.fields.iter().any(|f| f.name == "@name"), "fields: {:?}", class.fields);

    let set_name = find_function(&program, "test.Greeter.set_name");
    assert!(set_name.is_method);
    assert!(set_name.receiver.is_some());
    assert!(matches!(set_name.body.stmts.last(), Some(Stmt::Return { value: Some(Expr::Assign { .. }), .. })));

    let greet = find_function(&program, "test.Greeter.greet");
    assert!(matches!(greet.body.stmts.as_slice(), [Stmt::Return { value: Some(Expr::FieldRead { field, .. }), .. }] if field == "@name"));
}

#[test]
fn nested_module_and_class_produce_a_dot_qualified_name() {
    let program = parse(
        r#"
        module Outer
          class Inner
            def baz
            end
          end
        end
        "#,
    );
    let _ = find_function(&program, "test.Outer.Inner.baz");
}

#[test]
fn string_interpolation_produces_interp_with_parts_in_order() {
    let program = parse(
        r#"
        def build(a, b)
          "x#{a}y#{b}z"
        end
        "#,
    );
    let function = find_function(&program, "test.build");
    let Stmt::Return { value: Some(Expr::Interp { parts, .. }), .. } = &function.body.stmts[0] else { panic!("expected an interpolated return value, got {:?}", function.body.stmts) };
    assert_eq!(parts.len(), 5, "parts: {parts:?}");
    assert!(matches!(&parts[0], Expr::Literal { kind: uniflow_hir::LiteralKind::String(s), .. } if s == "x"));
    assert!(matches!(&parts[2], Expr::Literal { kind: uniflow_hir::LiteralKind::String(s), .. } if s == "y"));
    assert!(matches!(&parts[4], Expr::Literal { kind: uniflow_hir::LiteralKind::String(s), .. } if s == "z"));
}

/// A block passed to `each` lowers as `Expr::Lambda` and can reference an
/// outer local (closure capture). This specifically exercises a
/// DOUBLY-nested block (a block inside a block, each referencing a name
/// bound outside both), proving `RubyEnv::resolve`'s recursive
/// capture-relay fix was actually applied — not just copied without
/// verifying it does what it claims: with the naive (non-recursive, single-
/// boundary) version this bug replaces, the outer `arr.each` block would
/// never itself reference `outer_var` directly, so it would never receive
/// a capture for it, and the inner `other.each` block's capture would
/// resolve to a source symbol the outer hoisted closure was never actually
/// given — exactly the "value used without a definition" failure mode the
/// task's fix note describes.
#[test]
fn a_doubly_nested_block_captures_an_outer_local_through_the_intermediate_block() {
    let program = parse(
        r#"
        def run(arr, other)
          outer_var = 1
          arr.each { |x| other.each { |y| use(outer_var) } }
        end
        "#,
    );
    let function = find_function(&program, "test.run");
    let targets = call_targets(function);
    assert!(targets.iter().any(|t| t == "use"), "targets: {targets:?}");

    // Walk down: run's body -> Send(each) call whose last arg is the outer
    // Lambda -> that lambda's body's last arg is the inner Lambda -> the
    // inner lambda's `captures` must carry `outer_var`, AND the outer
    // lambda's `captures` must *also* carry it (the recursive-relay fix),
    // even though the outer lambda's own body never reads `outer_var`
    // directly.
    fn find_lambda(expr: &Expr) -> Option<&uniflow_hir::Expr> {
        match expr {
            Expr::Lambda { .. } => Some(expr),
            Expr::Call(call) => {
                for arg in call.args.iter().rev() {
                    if let Some(found) = find_lambda(arg) {
                        return Some(found);
                    }
                }
                None
            }
            _ => None,
        }
    }

    let outer_stmt = function.body.stmts.iter().find_map(|stmt| match stmt {
        Stmt::Expr { expr, .. } | Stmt::Return { value: Some(expr), .. } => find_lambda(expr),
        _ => None,
    });
    let Some(Expr::Lambda { captures: outer_captures, body: outer_body, .. }) = outer_stmt else { panic!("expected to find the outer each-block lambda in {:?}", function.body.stmts) };
    assert!(outer_captures.iter().any(|c| c.name == "outer_var"), "outer captures: {outer_captures:?}");

    let inner = outer_body.stmts.iter().find_map(|stmt| match stmt {
        Stmt::Expr { expr, .. } | Stmt::Return { value: Some(expr), .. } => find_lambda(expr),
        _ => None,
    });
    let Some(Expr::Lambda { captures: inner_captures, .. }) = inner else { panic!("expected to find the inner each-block lambda in {:?}", outer_body.stmts) };
    assert!(inner_captures.iter().any(|c| c.name == "outer_var"), "inner captures: {inner_captures:?}");
}
