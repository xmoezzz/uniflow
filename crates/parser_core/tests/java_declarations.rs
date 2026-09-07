use uniflow_parser_core::java_syntax::{JavaSyntax, JavaDeclarationKind as D};

#[test]
fn java_declaration_index_preserves_members_owners_and_ranges() {
    let source = r#"
@Config(values={"class Fake {}", "public"})
class Outer<T> extends Thread implements java.io.Serializable, Cloneable {
    private static final java.util.logging.Logger first = make(), second = make();
    @web.RequestMapping(path="/x", method={GET, POST})
    protected <U> U route(final U input) throws java.io.IOException { return input; }
    Outer() {}
    static { init(); }
    class Inner { int Outer; void hashCode() {} }
    void equals(Object x) {
        if (x != null) { route(x); }
        final class Local { void hashCode() {} }
        Object anonymous = new Object() { public int hashCode() { return 1; } };
    }
    abstract void pending();
}
"#;
    let syntax = JavaSyntax::parse(source);
    let declarations = &syntax.declarations;
    let outer = declarations.iter().position(|d| d.name == "Outer" && d.kind == D::Class).unwrap();
    assert_eq!(declarations[outer].interfaces, ["java.io.Serializable", "Cloneable"]);
    assert_eq!(declarations[outer].superclass, "Thread");
    let field = declarations.iter().find(|d| d.kind == D::Field && d.names.contains(&"first".into())).unwrap();
    assert_eq!(field.names, ["first", "second"]);
    assert_eq!(field.declared_type, "java.util.logging.Logger");
    assert_eq!(field.modifiers, ["private", "static", "final"]);
    assert!(source[field.range.clone()].ends_with(';'));
    let route = declarations.iter().find(|d| d.name == "route").unwrap();
    assert_eq!(route.annotations, ["web.RequestMapping"]);
    assert!(route.has_throws);
    assert_eq!(&source[route.parameters.clone().unwrap()], "final U input");
    let members = declarations.iter().filter(|d| d.owner == Some(outer) && d.is_member).collect::<Vec<_>>();
    assert_eq!(members.len(), 7, "{declarations:#?}");
    assert!(!members.iter().any(|d| d.name == "hashCode" || d.name == "Local"));
    assert_eq!(declarations.iter().filter(|d| d.kind == D::AnonymousClass).count(), 1);
    assert_eq!(declarations.iter().filter(|d| d.name == "hashCode").count(), 3);
    assert!(members.iter().any(|d| d.name == "pending" && d.kind == D::Method));
}
