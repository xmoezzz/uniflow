use uniflow_parser_core::c_declarations::{CDeclarationIndex, DerivedDeclarator as D};

#[test]
fn c_declarator_operators_preserve_function_ownership() {
    let source = "void f(void) { return; } void *g() { return 0; } int (*pointer)(int named); int (*factory())(int) { return 0; } struct S make() { return value; }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.functions.iter().map(|f| (f.name.as_str(), f.returns_void)).collect::<Vec<_>>(), vec![("f", true), ("g", false), ("factory", false), ("make", false)]);
    let pointer = &index.declarations[0].declarators[0];
    assert_eq!(pointer.name.as_deref(), Some("pointer"));
    assert!(matches!(pointer.derived.as_slice(), [D::Pointer, D::Function { .. }]));
    assert_eq!(index.returns.len(), 4);
}

#[test]
fn c_declarations_track_aggregate_and_function_scopes_separately() {
    let source = "struct Outer { union { int a; } value; union Named *reference; void method() { extern int local; struct { int member; } x; } }; enum { A, B };";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.aggregates.iter().filter(|a| a.name.is_none() && a.body.is_some()).count(), 3);
    assert_eq!(index.aggregates.iter().filter(|a| a.kind == "union" && a.inside_struct).count(), 2);
    let local = index.declarations.iter().find(|d| d.storage.iter().any(|s| s == "extern")).unwrap();
    assert!(!local.in_aggregate);
    assert_eq!(local.enclosing_function, Some(0));
    assert!(index.declarations.iter().find(|d| d.declarators.iter().any(|d| d.name.as_deref() == Some("member"))).unwrap().in_aggregate);
}

#[test]
fn c_parameters_distinguish_abstract_declarators_and_void() {
    let source = "void f(void); int g(int, const char *name, void (*callback)(int named), int [], ...);";
    let index = CDeclarationIndex::parse(source);
    let parameters = index.parameters.iter().map(|p| (&source[p.range.clone()], p.has_name, p.plain_void)).collect::<Vec<_>>();
    assert_eq!(parameters, vec![("void", false, true), ("int", false, false), ("const char *name", true, false), ("int named", true, false), ("void (*callback)(int named)", true, false), ("int []", false, false)]);
    assert!(index.functions.is_empty());
}

#[test]
fn c_returns_exclude_lambda_and_nested_function_bodies() {
    let source = "int outer() { if (ready) return 1; int inner() { return 2; } auto lambda = []() { return 3; }; } void empty() { return /* comment */; }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.functions.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), vec!["outer", "inner", "empty"]);
    assert_eq!(index.returns.iter().map(|r| (r.function, r.has_value)).collect::<Vec<_>>(), vec![(0, true), (1, true), (2, false)]);
}

#[test]
fn c_arrays_initializers_and_malformed_input_are_bounded() {
    let source = "extern int a[], b = 1; int c[] = {1, 2}, d[2] = {3, 4};";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.declarations.len(), 2);
    assert_eq!(index.declarations[0].declarators.len(), 2);
    let c = &index.declarations[1].declarators[0];
    assert!(matches!(&c.derived[0], D::Array { size } if size.is_empty()));
    assert_eq!(&source[c.initializer.clone().unwrap()], "{1, 2}");
    for malformed in ["", "(", "int x[", "struct {", "void f(int (", "int f() { return ("] {
        let _ = CDeclarationIndex::parse(malformed);
    }
}
