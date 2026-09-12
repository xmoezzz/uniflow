use uniflow_parser_core::c_declarations::{
    CDeclarationIndex, CFunctionContext, DerivedDeclarator as D,
};

#[test]
fn c_declarator_operators_preserve_function_ownership() {
    let source = "void f(void) { return; } void *g() { return 0; } int (*pointer)(int named); int (*factory())(int) { return 0; } struct S make() { return value; }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(
        index
            .functions
            .iter()
            .map(|f| (f.name.as_str(), f.returns_void))
            .collect::<Vec<_>>(),
        vec![
            ("f", true),
            ("g", false),
            ("factory", false),
            ("make", false)
        ]
    );
    let pointer = &index.declarations[0].declarators[0];
    assert_eq!(pointer.name.as_deref(), Some("pointer"));
    assert!(matches!(
        pointer.derived.as_slice(),
        [D::Pointer, D::Function { .. }]
    ));
    assert_eq!(index.returns.len(), 4);
}

#[test]
fn c_function_definitions_preserve_return_declarator_layers() {
    let source = "int *f() { return 0; } void *g() { return 0; } int (*factory())(int) { return 0; } int value() { return 0; }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.functions.len(), 4);
    assert!(matches!(index.functions[0].return_derived.as_slice(), [D::Pointer]));
    assert!(matches!(index.functions[1].return_derived.as_slice(), [D::Pointer]));
    assert!(matches!(
        index.functions[2].return_derived.as_slice(),
        [D::Pointer, D::Function { .. }]
    ));
    assert!(index.functions[3].return_derived.is_empty());
}

#[test]
fn c_function_definitions_preserve_storage_and_exact_name_ranges() {
    let source = "static void hidden(void) { } void visible(void) { }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.functions.len(), 2);
    assert!(index.functions[0].is_static);
    assert!(!index.functions[1].is_static);
    assert_eq!(&source[index.functions[0].name_range.clone()], "hidden");
    assert_eq!(&source[index.functions[1].name_range.clone()], "visible");
}

#[test]
fn cpp_function_definitions_preserve_overloaded_operator_names() {
    let source = r#"
struct Box {
    Box& operator=(const Box& other) { return *this; }
    void* operator new(unsigned long size) { return 0; }
    void operator delete(void* ptr) { }
    int& operator[](unsigned long index) { return value; }
    int value;
};
Box& Box::operator=(const Box& other) { return *this; }
void* Box::operator new[](unsigned long size) { return 0; }
void Box::operator delete[](void* ptr) { }
"#;
    let index = CDeclarationIndex::parse(source);
    let names = index
        .functions
        .iter()
        .map(|function| {
            (
                function.name.as_str(),
                function.qualified_name.as_str(),
                &source[function.name_range.clone()],
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            ("operator=", "Box::operator=", "operator="),
            ("operator new", "Box::operator new", "operator new"),
            ("operator delete", "Box::operator delete", "operator delete"),
            ("operator[]", "Box::operator[]", "operator[]"),
            ("operator=", "Box::operator=", "operator="),
            ("operator new[]", "Box::operator new[]", "operator new[]"),
            ("operator delete[]", "Box::operator delete[]", "operator delete[]"),
        ]
    );
}

#[test]
fn cpp_function_definitions_preserve_decl_context_for_allocation_operators() {
    let source = r#"
namespace outer {
namespace domain {
void* operator new(unsigned long size) { return 0; }
}
struct Box {
    void* operator new(unsigned long size) { return 0; }
};
void Box::operator delete(void* ptr) { }
}
void* operator new[](unsigned long size) { return 0; }
"#;
    let index = CDeclarationIndex::parse(source);

    assert!(matches!(
        &index.functions[0].context,
        CFunctionContext::Namespace { name, qualified_name }
            if name == "domain" && qualified_name == "outer::domain"
    ));
    assert!(matches!(
        &index.functions[1].context,
        CFunctionContext::Record { qualified_name } if qualified_name == "outer::Box"
    ));
    assert!(matches!(
        &index.functions[2].context,
        CFunctionContext::Record { qualified_name } if qualified_name == "outer::Box"
    ));
    assert!(matches!(
        &index.functions[3].context,
        CFunctionContext::TranslationUnit
    ));
}

#[test]
fn c_declarators_split_a_lexed_double_star_into_two_pointer_layers() {
    let source = "typedef int (**CallbackHandle)(void);";
    let index = CDeclarationIndex::parse(source);
    let declarator = &index.declarations[0].declarators[0];
    assert_eq!(declarator.name.as_deref(), Some("CallbackHandle"));
    assert!(matches!(
        declarator.derived.as_slice(),
        [D::Pointer, D::Pointer, D::Function { .. }]
    ));
}

#[test]
fn c_parameters_preserve_pointer_layers_for_declaration_checkers() {
    let index = CDeclarationIndex::parse("void consume(int ***deep);");
    assert!(matches!(
        index.parameters[0].derived.as_slice(),
        [D::Pointer, D::Pointer, D::Pointer]
    ));
}

#[test]
fn cpp_parameters_preserve_undeduced_placeholder_types() {
    let source = "void direct(auto value, const auto& reference, int typed) {} void prototype(auto only_declared);";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.functions.len(), 1);
    let parameters = index
        .parameters
        .iter()
        .map(|parameter| {
            (
                &source[parameter.range.clone()],
                parameter.undeduced_type,
                parameter.name.as_deref(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        parameters,
        vec![
            ("auto value", true, Some("value")),
            ("const auto& reference", true, Some("reference")),
            ("int typed", false, Some("typed")),
            ("auto only_declared", true, Some("only_declared")),
        ]
    );
}

#[test]
fn cpp_declarators_distinguish_references_from_pointers() {
    let source = "struct C {}; void f(int *p, int &r, int &&rr, int *&rp, int C::*member);";
    let index = CDeclarationIndex::parse(source);
    let function = index
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .find(|declarator| declarator.name.as_deref() == Some("f"))
        .expect("function declaration");
    let D::Function { parameters } = &function.derived[0] else {
        panic!("expected function declarator");
    };
    let params = index
        .parameters
        .iter()
        .filter(|parameter| {
            parameters.start <= parameter.range.start && parameter.range.end <= parameters.end
        })
        .collect::<Vec<_>>();
    assert_eq!(params.len(), 5);
    assert!(matches!(params[0].derived.as_slice(), [D::Pointer]));
    assert!(matches!(params[1].derived.as_slice(), [D::Reference]));
    assert!(matches!(
        params[2].derived.as_slice(),
        [D::RvalueReference]
    ));
    assert!(matches!(
        params[3].derived.as_slice(),
        [D::Reference, D::Pointer]
    ));
    assert!(matches!(
        params[4].derived.as_slice(),
        [D::MemberPointer]
    ));
}

#[test]
fn c_parameters_preserve_member_function_pointer_declarators() {
    let index = CDeclarationIndex::parse(
        "struct Owner; void consume(void (Owner::*callback)(int));",
    );
    let parameter = index
        .parameters
        .iter()
        .find(|parameter| parameter.has_name)
        .expect("member function pointer parameter");
    assert!(matches!(
        parameter.derived.as_slice(),
        [D::MemberPointer, D::Function { .. }]
    ));
}

#[test]
fn c_declarations_track_aggregate_and_function_scopes_separately() {
    let source = "struct Outer { union { int a; } value; union Named *reference; void method() { extern int local; struct { int member; } x; } }; enum { A, B };";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(
        index
            .aggregates
            .iter()
            .filter(|a| a.name.is_none() && a.body.is_some())
            .count(),
        3
    );
    assert_eq!(
        index
            .aggregates
            .iter()
            .filter(|a| a.kind == "union" && a.inside_struct)
            .count(),
        2
    );
    let local = index
        .declarations
        .iter()
        .find(|d| d.storage.iter().any(|s| s == "extern"))
        .unwrap();
    assert!(!local.in_aggregate);
    assert_eq!(local.enclosing_function, Some(0));
    assert!(
        index
            .declarations
            .iter()
            .find(|d| d
                .declarators
                .iter()
                .any(|d| d.name.as_deref() == Some("member")))
            .unwrap()
            .in_aggregate
    );
}

#[test]
fn c_parameters_distinguish_abstract_declarators_and_void() {
    let source =
        "void f(void); int g(int, const char *name, void (*callback)(int named), int [], ...);";
    let index = CDeclarationIndex::parse(source);
    let parameters = index
        .parameters
        .iter()
        .map(|p| (&source[p.range.clone()], p.has_name, p.plain_void))
        .collect::<Vec<_>>();
    assert_eq!(
        parameters,
        vec![
            ("void", false, true),
            ("int", false, false),
            ("const char *name", true, false),
            ("int named", true, false),
            ("void (*callback)(int named)", true, false),
            ("int []", false, false)
        ]
    );
    assert!(index.functions.is_empty());
}

#[test]
fn c_returns_exclude_lambda_and_nested_function_bodies() {
    let source = "int outer() { if (ready) return 1; int inner() { return 2; } auto lambda = []() { return 3; }; } void empty() { return /* comment */; }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(
        index
            .functions
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<_>>(),
        vec!["outer", "inner", "empty"]
    );
    assert_eq!(
        index
            .returns
            .iter()
            .map(|r| (r.function, r.has_value))
            .collect::<Vec<_>>(),
        vec![(0, true), (1, true), (2, false)]
    );
    assert_eq!(
        index
            .returns
            .iter()
            .map(|r| r.value.as_ref().map(|range| &source[range.clone()]))
            .collect::<Vec<_>>(),
        vec![Some("1"), Some("2"), None]
    );
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
    for malformed in [
        "",
        "(",
        "int x[",
        "struct {",
        "void f(int (",
        "int f() { return (",
    ] {
        let _ = CDeclarationIndex::parse(malformed);
    }
}

#[test]
fn c_declarations_preserve_direct_and_block_extern_c_linkage() {
    let source = r#"
int ordinary;
extern "C" int direct;
extern "C" {
    int grouped;
    static int grouped_static;
}
void demo(void) { int local; }
"#;
    let index = CDeclarationIndex::parse(source);
    let linkage = index
        .declarations
        .iter()
        .flat_map(|declaration| {
            declaration.declarators.iter().filter_map(|declarator| {
                declarator
                    .name
                    .as_deref()
                    .map(|name| (name, declaration.extern_c))
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        linkage,
        vec![
            ("ordinary", false),
            ("direct", true),
            ("grouped", true),
            ("grouped_static", true),
            ("local", false),
        ]
    );
}

#[test]
fn c_labels_keep_function_owner_collision_names_and_direct_nesting() {
    let source = "void f(int input) { int local; input: local: work(); } void g(void) { local: work(); }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.labels.len(), 3);
    assert_eq!(index.labels[0].name, "input");
    assert_eq!(index.labels[0].function, 0);
    assert!(index.labels[0].labels_another);
    assert_eq!(index.labels[1].name, "local");
    assert!(!index.labels[1].labels_another);
    assert_eq!(index.labels[2].function, 1);
    assert_eq!(index.parameters[0].name.as_deref(), Some("input"));
}

#[test]
fn c_noreturn_functions_record_only_direct_return_children() {
    let source = "[[noreturn]] void stop(int condition) { return; if (condition) { return; } } void normal(void) { return; }";
    let index = CDeclarationIndex::parse(source);
    assert!(index.functions[0].is_noreturn);
    assert!(!index.functions[1].is_noreturn);
    assert_eq!(
        index
            .returns
            .iter()
            .map(|statement| (statement.function, statement.direct_child))
            .collect::<Vec<_>>(),
        vec![(0, true), (0, false), (1, true)]
    );
}

#[test]
fn cpp_aggregates_preserve_qualified_base_lists() {
    let source = "namespace model { class Base {}; } class Other {}; class Child final : public model::Base, private virtual Other {};";
    let index = CDeclarationIndex::parse(source);
    let child = index
        .aggregates
        .iter()
        .find(|aggregate| aggregate.name.as_deref() == Some("Child"))
        .expect("child class");
    assert_eq!(child.bases, vec!["model::Base", "Other"]);
}

#[test]
fn cpp_declarations_skip_nested_template_argument_lists() {
    let source = "void demo(void) { std::array<std::array<int, 2>, 3> values; }";
    let index = CDeclarationIndex::parse(source);
    let declaration = index
        .declarations
        .iter()
        .find(|declaration| {
            declaration
                .declarators
                .iter()
                .any(|declarator| declarator.name.as_deref() == Some("values"))
        })
        .expect("template declaration");
    assert_eq!(declaration.type_name.replace(' ', ""), "std::array<std::array<int,2>,3>");
}

#[test]
fn c_enumerators_preserve_source_ranges_and_declaration_contexts() {
    let source = "enum Global { First = 1, Second }; void demo(void) { enum Local { Third, Fourth = value() }; }";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(
        index
            .enumerators
            .iter()
            .map(|enumerator| (enumerator.name.as_str(), enumerator.enclosing_function))
            .collect::<Vec<_>>(),
        vec![("First", None), ("Second", None), ("Third", Some(0)), ("Fourth", Some(0))]
    );
    assert_eq!(
        index
            .enumerators
            .iter()
            .map(|enumerator| enumerator.initializer.as_ref().map(|range| &source[range.clone()]))
            .collect::<Vec<_>>(),
        vec![Some("1"), None, None, Some("value()")]
    );
    assert_eq!(index.enumerators[0].enum_range, index.enumerators[1].enum_range);
    assert_ne!(index.enumerators[1].enum_range, index.enumerators[2].enum_range);
}

#[test]
fn cpp_scoped_enumerators_preserve_enum_identity() {
    let source = "enum class Color { Red = 1, Blue }; enum Plain { Low, High };";
    let index = CDeclarationIndex::parse(source);
    assert_eq!(index.enumerators.len(), 4);
    assert_eq!(index.enumerators[0].enum_name.as_deref(), Some("Color"));
    assert!(index.enumerators[0].scoped);
    assert_eq!(index.enumerators[2].enum_name.as_deref(), Some("Plain"));
    assert!(!index.enumerators[2].scoped);
}

#[test]
fn c_bit_fields_preserve_width_expressions() {
    let source = "struct Flags { signed int one : 1; unsigned int two : (1 + 1); int three : WIDTH; };";
    let index = CDeclarationIndex::parse(source);
    let fields = index
        .declarations
        .iter()
        .filter(|declaration| declaration.in_aggregate)
        .flat_map(|declaration| declaration.declarators.iter())
        .map(|declarator| {
            (
                declarator.name.as_deref().expect("field name"),
                declarator
                    .bit_width
                    .as_ref()
                    .map(|range| &source[range.clone()]),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        vec![("one", Some("1")), ("two", Some("(1 + 1)")), ("three", Some("WIDTH"))]
    );
}

#[test]
fn cpp_member_functions_preserve_trailing_const_qualifiers() {
    let source = "struct Reader { void inspect() const; void mutate() noexcept; }; void Reader::inspect() const {}";
    let index = CDeclarationIndex::parse(source);
    let members = index
        .declarations
        .iter()
        .filter(|declaration| declaration.in_aggregate)
        .flat_map(|declaration| declaration.declarators.iter())
        .collect::<Vec<_>>();
    let inspect = members
        .iter()
        .find(|declarator| declarator.name.as_deref() == Some("inspect"))
        .expect("const member declaration");
    let mutate = members
        .iter()
        .find(|declarator| declarator.name.as_deref() == Some("mutate"))
        .expect("noexcept member declaration");
    assert!(inspect
        .trailing_qualifiers
        .iter()
        .any(|qualifier| qualifier == "const"));
    assert!(mutate
        .trailing_qualifiers
        .iter()
        .any(|qualifier| qualifier == "noexcept"));
    assert_eq!(index.functions.len(), 1);
    assert!(index.functions[0].is_const);
}
