use uniflow_hir::Item;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

#[test]
fn java_field_and_parameter_spans_reference_original_file_bytes() {
    let source = "// 前置说明\npackage example;\n\nclass Locations {\n    String name;\n    void run(String input, int count) {\n        return;\n    }\n}\n";
    let program = JavaParser::default()
        .parse_file("Locations.java", source)
        .unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else {
        panic!("class")
    };
    let field_span = class.fields[0].span;
    assert_eq!((field_span.start_line, field_span.start_col), (5, 5));
    assert_eq!(
        &source[field_span.start_byte as usize..field_span.end_byte as usize],
        "String name;"
    );
    let params = &class.methods[0].params;
    assert_eq!(params.len(), 2);
    for (param, declaration, column) in [
        (&params[0], "String input", 14),
        (&params[1], "int count", 28),
    ] {
        assert_eq!((param.span.start_line, param.span.start_col), (6, column));
        assert_eq!(
            &source[param.span.start_byte as usize..param.span.end_byte as usize],
            declaration
        );
    }
}

#[test]
fn java_structural_method_extraction_handles_multiline_annotations_and_ownership() {
    let source = r#"
class Locations {
    @Rule(values = {1, 2}, text = "前置说明")
    public
    String
    first(String input)
    throws Exception { return input; }
    void second() {} void third() {}
    class Nested { void inner() {} }
    Runnable callback = () -> {};
}
"#;
    let program = JavaParser::default()
        .parse_file("Locations.java", source)
        .unwrap();
    let Item::Class(class) = &program.modules[0].items[0] else {
        panic!("class")
    };
    assert_eq!(
        class
            .methods
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>(),
        ["Locations.first", "Locations.second", "Locations.third"]
    );
    let first = &class.methods[0];
    assert_eq!(first.params.len(), 1);
    assert_eq!(first.params[0].name, "input");
    assert_eq!(first.span.start_line, 3);
    assert_eq!(first.params[0].span.start_line, 6);
    let return_type = program
        .types
        .iter()
        .find(|t| Some(t.id) == first.return_type)
        .unwrap();
    assert_eq!(return_type.name, "String");
}
