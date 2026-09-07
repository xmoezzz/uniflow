use uniflow_hir::{CallTarget, Expr, Item, Language, Stmt};
use uniflow_lang_frontends::parse_file;

#[test]
fn kotlin_type_invocations_are_constructor_hir_nodes() {
    let source = r#"
        fun check(user: String, request: javax.servlet.http.HttpServletRequest) {
            val qualified: java.net.URL = java.net.URL(user)
            val shortUrl: URL = URL(user)
            qualified.openStream()
            helper(user)
        }
    "#;
    let program = parse_file(Language::Kotlin, "Constructors.kt", source).unwrap();
    let Item::Function(function) = &program.modules[0].items[0] else {
        panic!("top-level Kotlin function");
    };
    let type_name_for = |id| {
        program
            .types
            .iter()
            .find(|ty| ty.id == id)
            .unwrap()
            .name
            .as_str()
    };
    assert_eq!(type_name_for(function.params[0].ty.unwrap()), "String");
    assert_eq!(
        type_name_for(function.params[1].ty.unwrap()),
        "javax.servlet.http.HttpServletRequest"
    );

    let Stmt::Let {
        init: Some(Expr::New { type_name, .. }),
        ..
    } = &function.body.stmts[0]
    else {
        panic!("qualified Kotlin constructor: {:#?}", function.body.stmts);
    };
    assert_eq!(type_name, "java.net.URL");

    let Stmt::Let {
        init: Some(Expr::New { type_name, .. }),
        ..
    } = &function.body.stmts[1]
    else {
        panic!("unqualified Kotlin constructor: {:#?}", function.body.stmts);
    };
    assert_eq!(type_name, "URL");

    let Stmt::Expr {
        expr: Expr::Call(method),
        ..
    } = &function.body.stmts[2]
    else {
        panic!("method call after constructor");
    };
    assert!(matches!(&method.target, CallTarget::Named(name) if name == "openStream"));
    assert!(method.receiver.is_some());

    let Stmt::Expr {
        expr: Expr::Call(helper),
        ..
    } = &function.body.stmts[3]
    else {
        panic!("ordinary Kotlin function call");
    };
    assert!(matches!(&helper.target, CallTarget::Named(name) if name == "helper"));
    assert!(helper.receiver.is_none());
}
