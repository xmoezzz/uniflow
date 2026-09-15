use uniflow_hir::{CallTarget, Expr, Item, Language, Stmt};
use uniflow_lang_frontends::parse_file;

#[test]
fn csharp_catches_keep_types_scopes_and_static_calls_are_not_declarations() {
    let source = r#"class C {
        void F(Exception outer, string path) {
            try { Work(); }
            catch(System.Exception outer) { Console.Write(outer); }
            catch(CustomException outer) { Console.Write(outer); }
            Console.Write(outer);
            File.Create(path);
            System.Text.StringBuilder builder = new System.Text.StringBuilder();
        }
    }"#;
    let program = parse_file(Language::CSharp, "Catch.cs", source).unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else {
        panic!("class");
    };
    let method = &class.methods[0];
    let Stmt::Try { catches, .. } = &method.body.stmts[0] else {
        panic!("try");
    };
    assert_eq!(catches.len(), 2);
    let type_name = |id| {
        program
            .types
            .iter()
            .find(|ty| ty.id == id)
            .unwrap()
            .name
            .as_str()
    };
    assert_eq!(type_name(catches[0].ty.unwrap()), "System.Exception");
    assert_eq!(type_name(catches[1].ty.unwrap()), "CustomException");
    assert_ne!(catches[0].symbol, catches[1].symbol);
    for catch in catches {
        assert_ne!(catch.symbol, Some(method.params[0].symbol));
        assert!(source[catch.span.start_byte as usize..].starts_with("catch"));
        let Stmt::Expr {
            expr: Expr::Call(call),
            ..
        } = &catch.body.stmts[0]
        else {
            panic!("catch call");
        };
        let Expr::VarRef { symbol, .. } = &call.args[0] else {
            panic!("exception reference");
        };
        assert_eq!(Some(*symbol), catch.symbol);
    }
    let Stmt::Expr {
        expr: Expr::Call(call),
        ..
    } = &method.body.stmts[1]
    else {
        panic!("outer call");
    };
    assert!(
        matches!(&call.args[0], Expr::VarRef { symbol, .. } if *symbol == method.params[0].symbol)
    );
    let Stmt::Expr {
        expr: Expr::Call(call),
        ..
    } = &method.body.stmts[2]
    else {
        panic!("static File.Create must remain a call");
    };
    assert!(matches!(&call.target, CallTarget::Named(name) if name == "Create"));
    assert!(call.qualifier_is_explicit);
    let Stmt::Let {
        ty: Some(ty),
        init: Some(Expr::New {
            type_name: allocated,
            ..
        }),
        ..
    } = &method.body.stmts[3]
    else {
        panic!("qualified declaration");
    };
    assert_eq!(type_name(*ty), "System.Text.StringBuilder");
    assert_eq!(allocated, "System.Text.StringBuilder");
}

/// Regression test: a class wrapped in a `namespace { ... }` block with a
/// non-empty `try` body followed by a `catch`/`finally` clause used to
/// overflow the stack. Root cause was two-fold: `namespace` was treated as
/// an `import`-style header (which only terminates at `;`/newline — never
/// true for a brace-style, non-newline-terminated language), so it silently
/// swallowed the entire namespace body up to the first real `;`, leaving a
/// stray `catch`/`finally` behind; dispatching that stray token into
/// `try_statement`'s "no `try` keyword seen" (Ruby `begin`) path then made
/// `block_for` call back into `statement()` on the same, un-advanced token
/// forever. This exercises both the namespace-as-container fix and the
/// orphaned-catch/finally guard directly on real-shaped code (mirrors what
/// was found crashing on Google's `microservices-demo` cartservice).
#[test]
fn csharp_namespace_wrapped_try_catch_and_try_finally_do_not_overflow_the_stack() {
    let source = r#"namespace N {
        public class C {
            public void M() {
                try {
                    int a = 1;
                } catch (Exception ex) {
                    int b = 2;
                }
            }
            public void M2() {
                try {
                    int a = 1;
                } finally {
                    int b = 2;
                }
            }
        }
    }"#;
    let program = parse_file(Language::CSharp, "Namespaced.cs", source).unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else {
        panic!("expected the namespace body to yield a top-level class item");
    };
    assert_eq!(class.methods.len(), 2);
    let Stmt::Try { catches, .. } = &class.methods[0].body.stmts[0] else {
        panic!("expected a try/catch as method M's first statement");
    };
    assert_eq!(catches.len(), 1);
    let Stmt::Try { finally_block, .. } = &class.methods[1].body.stmts[0] else {
        panic!("expected a try/finally as method N's first statement");
    };
    assert!(finally_block.is_some());
}
