use uniflow_parser_core::java_syntax::{JavaSyntax, JavaSyntaxKind as K};

#[test]
fn java_statement_boundaries_bind_else_do_and_labels() {
    let source = "if (a) if (b) x(); else y(); else z(); do work(); while (ready); label: while (ok) ; for (int i=0; i<2; i++) f(); next();";
    let slices = JavaSyntax::statement_ranges(source).into_iter().map(|r| &source[r]).collect::<Vec<_>>();
    assert_eq!(slices, ["if (a) if (b) x(); else y(); else z();", "do work(); while (ready);",
        "label: while (ok) ;", "for (int i=0; i<2; i++) f();", "next();"]);
}

#[test]
fn java_structure_distinguishes_types_methods_literals_and_initializers() {
    let source = r#"
class First {
    int[] array = {};
    String text = "while(true){}";
    First() {}
    @Check(values = {1, 2}) void empty() throws Exception {}
    Runnable lambda = () -> { while (true) {} };
    Object anonymous = new Object() { void nested() {} };
    static { if (ready) ; }
    class Inner { void inner() {} }
}
class Second { void second() {} }
"#;
    let index = JavaSyntax::parse(source);
    let methods = index.nodes.iter().filter(|n| n.kind == K::Method).map(|n| &source[n.range.clone()]).collect::<Vec<_>>();
    assert_eq!(methods.len(), 5, "{methods:#?}");
    assert!(methods.iter().any(|m| m.starts_with("@Check")));
    assert_eq!(index.nodes.iter().filter(|n| n.kind == K::While).count(), 1);
    assert_eq!(index.nodes.iter().filter(|n| n.kind == K::ConstructorBody).count(), 1);
}

#[test]
fn java_structure_handles_truncated_inputs_without_panicking() {
    for source in ["class X { void f() { if (x)", "class X { void f() { do", "{]", "class", "", "do {} while("] {
        let _ = JavaSyntax::parse(source);
        let _ = JavaSyntax::statement_ranges(source);
    }
}
