use std::collections::HashMap;
use uniflow_baseline::BaselinePack;
use uniflow_hir::Language;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(language: Language, constraint: &str, statement: &str, expected: usize) {
    let mut yaml = "id: contract\ntitle: Argument contract\nrules:\n".to_string();
    for (kind, name) in [("callee", "target"), ("constructor_type", "Target")] {
        yaml.push_str(&format!("- id: contract-{kind}\n  title: Argument contract\n  severity: warning\n  confidence: high\n  matcher:\n    {kind}: '(^|\\.){name}$'\n{constraint}\n"));
    }
    let pack = BaselinePack::from_yaml_str(&yaml).unwrap();
    let param_type = if language == Language::Java {
        "Object"
    } else {
        "object"
    };
    let source = format!("class Demo {{\n void Run({param_type} value) {{\n {statement}\n }}\n}}");
    let (path, program) = if language == Language::Java {
        (
            "Demo.java",
            JavaParser::default()
                .parse_file("Demo.java", &source)
                .unwrap(),
        )
    } else {
        (
            "Demo.cs",
            uniflow_lang_frontends::parse_file(language, "Demo.cs", &source).unwrap(),
        )
    };
    let findings = pack.scan_hir(
        &program,
        &HashMap::from([(path.to_owned(), source.clone())]),
    );
    assert_eq!(
        findings.len(),
        expected,
        "{constraint}\n{source}\n{findings:#?}"
    );
}

fn positional_contract(language: Language) {
    for (constraint, positive, negative) in [
        ("    null_args: [0]", "null", "value"),
        ("    bool_arg_values: {0: false}", "false", "true"),
        ("    last_bool_arg_value: false", "false", "true"),
        ("    false_or_zero_args: [0]", "0", "1"),
        ("    false_or_zero_args: [0]", "false", "true"),
        ("    non_literal_args: [0]", "value", "\"literal\""),
        ("    non_string_literal_args: [0]", "1", "\"literal\""),
        (
            "    string_arg_not_patterns: {0: '^safe$'}",
            "\"unsafe\"",
            "\"safe\"",
        ),
        (
            "    last_string_arg_pattern: '^unsafe$'",
            "\"unsafe\"",
            "\"safe\"",
        ),
        ("    null_or_empty_string_args: [0]", "\"\"", "\"value\""),
        (
            "    int_arg_min_values: {0: 2}\n    int_arg_max_values: {0: 4}",
            "3",
            "5",
        ),
        ("    automatic_var_args: [0]", "value", "null"),
    ] {
        check(
            language.clone(),
            constraint,
            &format!("target({positive});\n new Target({positive});"),
            2,
        );
        check(
            language.clone(),
            constraint,
            &format!("target({negative});\n new Target({negative});"),
            0,
        );
        check(language.clone(), constraint, "target();\n new Target();", 0);
    }
}

#[test]
fn java_calls_and_constructors_share_positional_constraints() {
    positional_contract(Language::Java);
}

#[test]
fn csharp_calls_and_constructors_share_positional_constraints() {
    positional_contract(Language::CSharp);
}

#[test]
fn java_constructor_context_constraints_are_not_ignored() {
    check(
        Language::Java,
        "    ignored_return: true",
        "new Target();\n Target result = new Target();",
        1,
    );
    check(
        Language::Java,
        "    outside_loop: true",
        "new Target();\n while (ready) { new Target(); }",
        1,
    );
    check(
        Language::Java,
        "    inside_loop: true",
        "new Target();\n while (ready) { new Target(); }",
        1,
    );
    check(
        Language::Java,
        "    self_assignment: true",
        "value = new Target(value);\n Target result = new Target(value);",
        1,
    );
    check(
        Language::Java,
        "    requires_receiver: true",
        "new Target();",
        0,
    );
    check(
        Language::Java,
        "    named_bool_args: {enabled: false}",
        "new Target(false);",
        0,
    );
    check(
        Language::Java,
        "    string_constant_arg_patterns: {0: '^secret$'}",
        "new Target(\"secret\");",
        0,
    );
}

#[test]
fn assignment_predicates_require_an_assignment_target() {
    let yaml = r#"
id: invalid-assignment
title: Invalid assignment
rules:
- id: invalid-assignment
  title: Invalid assignment
  severity: warning
  confidence: high
  matcher:
    assignment_bool_value: false
"#;
    assert!(BaselinePack::from_yaml_str(yaml).is_err());
}

#[test]
fn call_alternatives_keep_receiver_arity_and_argument_constraints_together() {
    let yaml = r#"
id: alternatives
title: Alternatives
rules:
- id: dispatch
  title: Dispatch
  languages: [csharp]
  severity: warning
  confidence: high
  matcher:
    call_alternatives:
    - callee: '^Send$'
      receiver_path_pattern: '^left$'
      min_args: 2
      max_args: 2
      string_arg_patterns: { 0: '^bad$' }
    - callee: '^Send$'
      receiver_path_pattern: '^right$'
      min_args: 2
      max_args: 2
      string_arg_patterns: { 1: '^bad$' }
    - callee: '^Send$'
      receiver_path_pattern: '^left$'
      min_args: 2
      max_args: 2
      string_arg_patterns: { 0: '^bad$' }
"#;
    let pack = BaselinePack::from_yaml_str(yaml).unwrap();
    let source = r#"class A { void F(Receiver left, Receiver right, Receiver other) {
        left.Send("bad", "safe");
        right.Send("safe", "bad");
        right.Send("bad", "safe");
        left.Send("safe", "bad");
        other.Send("bad", "bad");
        right.Send("bad");
        new Send("bad", "bad");
    } }"#;
    let program = uniflow_lang_frontends::parse_file(Language::CSharp, "Calls.cs", source).unwrap();
    let actual = pack.scan_hir(
        &program,
        &HashMap::from([("Calls.cs".into(), source.into())]),
    );
    assert_eq!(
        actual
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(BaselinePack::from_yaml_str(&yaml.replace(
        "    call_alternatives:",
        "    min_args: 1\n    call_alternatives:"
    ))
    .is_err());
    assert!(BaselinePack::from_yaml_str(
        &yaml.replace("callee: '^Send$'", "constructor_type: '^Send$'")
    )
    .is_err());
}
