use uniflow_hir::{BinaryOp, Expr, Item, Stmt, UnaryOp};
use uniflow_lang_java::{JavaParser, parse_project_sources};
use uniflow_parser_core::SourceParser;

#[test]
fn java_for_preserves_declarations_condition_updates_and_body() {
    let source = "class ForRegions { void run() { for (int i=0, j=2; i<j; i++, --j) { continue; } } }";
    let program = JavaParser::default().parse_file("ForRegions.java", source).unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else { panic!("class") };
    let Stmt::For { init, cond, update, body, .. } = &class.methods[0].body.stmts[0] else { panic!("for") };
    assert_eq!(init.stmts.len(), 2);
    assert!(init.stmts.iter().all(|s| matches!(s, Stmt::Let { init: Some(_), .. })));
    assert!(matches!(cond, Some(Expr::Binary { op: BinaryOp::Lt, .. })));
    assert_eq!(update.stmts.len(), 2);
    for (stmt, op) in update.stmts.iter().zip([UnaryOp::PostIncrement, UnaryOp::PreDecrement]) {
        assert!(matches!(stmt, Stmt::Expr { expr: Expr::Unary { op: actual, .. }, .. } if *actual == op));
    }
    assert!(matches!(body.stmts[0], Stmt::Continue { .. }));
}

#[test]
fn java_project_merge_remaps_every_for_region() {
    let entries = vec![
        ("First.java".to_string(), "class First { void run() { for (int i=0; i<2; i++) work(i); } }".to_string()),
        ("Second.java".to_string(), "class Second { void run() { for (int j=0; j<2; j++) work(j); } }".to_string()),
    ];
    let program = parse_project_sources(&entries).unwrap();
    let mut symbols = Vec::new();
    let mut regions = Vec::new();
    for module in &program.modules {
        for item in &module.items {
            let Item::Class(class) = item else { continue; };
            for method in &class.methods {
                let Stmt::For { init, cond, update, body, span, .. } = &method.body.stmts[0] else { panic!("for") };
                let Stmt::Let { symbol, .. } = init.stmts[0] else { panic!("init") };
                assert!(matches!(cond, Some(Expr::Binary { lhs, .. }) if matches!(lhs.as_ref(), Expr::VarRef { symbol: used, .. } if *used == symbol)));
                assert!(matches!(&update.stmts[0], Stmt::Expr { expr: Expr::Unary { op: UnaryOp::PostIncrement, expr, .. }, .. }
                    if matches!(expr.as_ref(), Expr::VarRef { symbol: used, .. } if *used == symbol)));
                assert_eq!(init.span.file, span.file);
                assert_eq!(update.span.file, span.file);
                symbols.push(symbol);
                regions.extend([init.id, update.id, body.id]);
            }
        }
    }
    assert_eq!(symbols.len(), 2);
    assert_ne!(symbols[0], symbols[1]);
    let unique = regions.iter().collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), 6);
}

#[test]
fn java_lambda_captures_for_inputs_but_not_loop_declarations() {
    let source = "class ForRegions { void run(int limit, String value) { Runnable job = () -> { for (int i=0; i<limit; i++) sink(value); }; } }";
    let program = JavaParser::default().parse_file("ForRegions.java", source).unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else { panic!("class") };
    let Stmt::Let { init: Some(Expr::Lambda { captures, .. }), .. } = &class.methods[0].body.stmts[0] else { panic!("lambda") };
    let names = captures.iter().map(|c| c.name.as_str()).collect::<Vec<_>>();
    assert!(names.contains(&"limit"), "{names:?}");
    assert!(names.contains(&"value"), "{names:?}");
    assert!(!names.contains(&"i"), "{names:?}");
}
