use uniflow_hir::{BinaryOp, CallTarget, Expr, Item, LValue, LiteralKind, Stmt};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

#[test]
fn java_updates_keep_prefix_postfix_precedence_and_storage_shape() {
    use uniflow_hir::UnaryOp::*;
    for (text, expected) in [
        ("++i", PreIncrement),
        ("i++", PostIncrement),
        ("--i", PreDecrement),
        ("i--", PostDecrement),
        ("/*before*/ ++ /*middle*/ i /*after*/", PreIncrement),
        ("i /*middle*/ ++ /*after*/", PostIncrement),
    ] {
        let Expr::Unary { op, expr, .. } = expression(text) else {
            panic!("{text}")
        };
        assert_eq!(op, expected);
        assert!(matches!(*expr, Expr::VarRef { .. }));
    }
    assert!(
        matches!(expression("i++ + --n"), Expr::Binary { lhs, rhs, .. }
        if matches!(*lhs, Expr::Unary { op: PostIncrement, .. })
        && matches!(*rhs, Expr::Unary { op: PreDecrement, .. }))
    );
    assert!(matches!(expression("(int) i++"), Expr::Cast { expr, .. }
        if matches!(*expr, Expr::Unary { op: PostIncrement, .. })));
    assert!(
        matches!(expression("-i++"), Expr::Unary { op: Neg, expr, .. }
        if matches!(*expr, Expr::Unary { op: PostIncrement, .. }))
    );
    assert!(
        matches!(expression("values[i++]++"), Expr::Unary { op: PostIncrement, expr, .. }
        if matches!(expr.as_ref(), Expr::IndexRead { index, .. } if matches!(index.as_ref(), Expr::Unary { op: PostIncrement, .. })))
    );
    assert!(
        matches!(expression("object.count++"), Expr::Unary { expr, .. }
        if matches!(*expr, Expr::FieldRead { .. }))
    );
    assert!(matches!(expression("\"i++\""), Expr::Literal { .. }));
    assert!(matches!(expression("(i + n)++"), Expr::Opaque { .. }));
}

fn expression(text: &str) -> Expr {
    let source = format!("class Expressions {{ Object f(boolean flag, boolean other, String[] values, int i, int n, Object object) {{ return {text}; }} }}");
    let program = JavaParser::default()
        .parse_file("Expressions.java", &source)
        .unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else {
        panic!("class")
    };
    let Stmt::Return {
        value: Some(expr), ..
    } = &class.methods[0].body.stmts[0]
    else {
        panic!("return")
    };
    expr.clone()
}

#[test]
fn java_conditional_expressions_preserve_precedence_and_literal_boundaries() {
    let Expr::Conditional {
        cond,
        then_expr,
        else_expr,
        ..
    } = expression("flag || other ? values[i] : other ? \"? :\" : values[n]")
    else {
        panic!("conditional")
    };
    assert!(matches!(
        *cond,
        Expr::Binary {
            op: BinaryOp::Or,
            ..
        }
    ));
    assert!(matches!(*then_expr, Expr::IndexRead { .. }));
    assert!(matches!(*else_expr, Expr::Conditional { .. }));
    let Expr::Conditional {
        then_expr,
        else_expr,
        ..
    } = expression("flag ? other ? values[i] : values[n] : \"safe\"")
    else {
        panic!("nested")
    };
    assert!(matches!(*then_expr, Expr::Conditional { .. }));
    assert!(matches!(*else_expr, Expr::Literal { .. }));
    assert!(matches!(
        expression("\"a ? b : c\""),
        Expr::Literal {
            kind: LiteralKind::String(_),
            ..
        }
    ));
    assert!(matches!(
        expression("flag /* ? ignored : */ ? values[i] : \"safe\""),
        Expr::Conditional { .. }
    ));
    assert!(
        matches!(expression("flag ? i = n : 0"), Expr::Conditional { then_expr, .. } if matches!(*then_expr, Expr::Assign { .. }))
    );
}

#[test]
fn java_array_reads_writes_and_typed_receivers_are_structural() {
    assert!(
        matches!(expression("values[i]"), Expr::IndexRead { base, index, .. }
        if matches!(*base, Expr::VarRef { .. }) && matches!(*index, Expr::VarRef { .. }))
    );
    assert!(
        matches!(expression("values[lookup(\"]\")]"), Expr::IndexRead { index, .. } if matches!(*index, Expr::Call(_)))
    );
    assert!(
        matches!(expression("values[i][n]"), Expr::IndexRead { base, .. } if matches!(*base, Expr::IndexRead { .. }))
    );
    let source = "import java.sql.Statement;\nclass A { void f(Statement[] statements, String[] values, String input) { values[0] = input; statements[0].executeQuery(values[0]); } }";
    let program = JavaParser::default().parse_file("A.java", source).unwrap();
    let class = program.modules[0]
        .items
        .iter()
        .find_map(|item| {
            if let Item::Class(c) = item {
                Some(c)
            } else {
                None
            }
        })
        .unwrap();
    let statements = &class.methods[0].body.stmts;
    assert!(
        matches!(
            &statements[0],
            Stmt::Assign {
                lhs: LValue::Index { .. },
                ..
            }
        ),
        "{statements:#?}"
    );
    let Stmt::Expr {
        expr: Expr::Call(call),
        ..
    } = &statements[1]
    else {
        panic!("call: {statements:#?}")
    };
    assert!(
        matches!(&call.target, CallTarget::Named(name) if name == "java.sql.Statement.executeQuery"),
        "{call:#?}"
    );
    assert!(matches!(call.args[0], Expr::IndexRead { .. }));
}

#[test]
fn java_casts_do_not_confuse_parenthesized_arithmetic_or_receivers() {
    assert!(
        matches!(expression("(String) object"), Expr::Cast { expr, ty: Some(_), .. } if matches!(*expr, Expr::VarRef { .. }))
    );
    assert!(
        matches!(expression("((String[]) object)[i]"), Expr::IndexRead { base, .. } if matches!(*base, Expr::Cast { .. }))
    );
    assert!(
        matches!(expression("(i) + n"), Expr::Binary { op: BinaryOp::Add, lhs, .. } if matches!(*lhs, Expr::VarRef { .. }))
    );
    assert!(matches!(
        expression("(i + n)"),
        Expr::Binary {
            op: BinaryOp::Add,
            ..
        }
    ));
    assert!(
        matches!(expression("(int) -n"), Expr::Cast { expr, .. } if matches!(*expr, Expr::Unary { .. }))
    );
    assert!(
        matches!(expression("i * -n"), Expr::Binary { op: BinaryOp::Mul, rhs, .. } if matches!(*rhs, Expr::Unary { .. }))
    );
    let Expr::Call(call) = expression("((java.sql.Statement) object).executeQuery(values[i])")
    else {
        panic!("cast receiver")
    };
    assert!(
        matches!(&call.target, CallTarget::Named(name) if name == "java.sql.Statement.executeQuery"),
        "{call:#?}"
    );
    assert!(matches!(call.receiver.as_deref(), Some(Expr::Cast { .. })));
    let Expr::Call(call) = expression("(object).toString()") else {
        panic!("parenthesized receiver")
    };
    assert!(matches!(
        call.receiver.as_deref(),
        Some(Expr::VarRef { .. })
    ));
}

#[test]
fn java_conditional_lambda_precedence_preserves_executable_ownership() {
    assert!(
        matches!(expression("flag ? () -> values[i] : () -> values[n]"),
        Expr::Conditional { then_expr, else_expr, .. }
        if matches!(*then_expr, Expr::Lambda { .. }) && matches!(*else_expr, Expr::Lambda { .. }))
    );
    let Expr::Lambda { body, .. } = expression("x -> flag ? values[i] : values[n]") else {
        panic!("lambda")
    };
    assert!(matches!(
        &body.stmts[0],
        Stmt::Return {
            value: Some(Expr::Conditional { .. }),
            ..
        }
    ));
}
