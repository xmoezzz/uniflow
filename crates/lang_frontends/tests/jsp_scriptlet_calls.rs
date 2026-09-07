use uniflow_hir::{CallTarget, Expr, Item, Language, Stmt};
use uniflow_lang_frontends::parse_file;

#[test]
fn jsp_top_level_receiver_calls_are_not_misparsed_as_functions() {
    let source = r#"<html><body><%
        java.net.URL url = new java.net.URL("https://example.invalid/");
        url.openStream();
    %></body></html>"#;
    let program = parse_file(Language::Jsp, "network.jsp", source).unwrap();
    let function = program.modules[0]
        .items
        .iter()
        .find_map(|item| match item {
            Item::Function(function) if function.name == "__top_level__" => Some(function),
            _ => None,
        })
        .expect("JSP scriptlet carrier function");
    assert!(function.body.stmts.len() >= 2, "{:#?}", function.body.stmts);
    assert!(
        function.body.stmts.iter().any(|stmt| matches!(stmt,
            Stmt::Let { init: Some(Expr::New { type_name, .. }), .. }
                if type_name == "java.net.URL")),
        "{:#?}",
        function.body.stmts
    );
    assert!(function.body.stmts.iter().any(
        |stmt| matches!(stmt, Stmt::Expr { expr: Expr::Call(call), .. }
        if matches!(&call.target, CallTarget::Named(name) if name == "openStream")
            && call.receiver.is_some())
    ));
}
