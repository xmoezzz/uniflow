use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_rules::{ApiMatcher, Port, RuleSet, SinkRule, SourceRule};
use uniflow_taint::analyze;
use uniflow_value_flow::build;

fn check(language: Language, source: &str) -> usize {
    let rules = RuleSet {
        sources: vec![SourceRule {
            id: "loop-source".into(),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                method_name: Some("input".into()),
                ..Default::default()
            },
            out: Port::Return,
            kind: "untrusted".into(),
        }],
        sinks: vec![SinkRule {
            id: "loop-sink".into(),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                method_name: Some("sink".into()),
                ..Default::default()
            },
            inputs: vec![Port::Arg(0)],
            kind: "untrusted".into(),
        }],
        ..Default::default()
    };
    let hir = parse_source(language, "loop.fixture", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules).len()
}

#[test]
fn javascript_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::JavaScript,
            r#"
function run(ready) {
    let value = "safe";
    for (; ready; value = input()) { sink(value); continue; }
}
"#
        ),
        1
    );
}

#[test]
fn csharp_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::CSharp,
            r#"
class Demo {
    void Run(bool ready) {
        string value = "safe";
        for (; ready; value = input()) { sink(value); continue; }
    }
}
"#
        ),
        1
    );
}

#[test]
fn go_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::Go,
            r#"
func run(ready bool) {
    value := "safe"
    for ; ready; value = input() { sink(value); continue }
}
"#
        ),
        1
    );
}

#[test]
fn php_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::Php,
            r#"
<?php
function run($ready) {
    $value = "safe";
    for (; $ready; $value = input()) { sink($value); continue; }
}
"#
        ),
        1
    );
}

#[test]
fn objc_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::ObjC,
            r#"
void run(int ready) {
    char *value = "safe";
    for (; ready; value = input()) { sink(value); continue; }
}

"#
        ),
        1
    );
}

#[test]
fn language_frontends_carry_taint_through_the_unified_flow_engine() {
    let cases = [
        (
            Language::C,
            "char *input(void); void sink(char *); void run(void) { char *value = input(); sink(value); }",
        ),
        (
            Language::Cpp,
            "char *input(); void sink(char *); void run() { auto value = input(); sink(value); }",
        ),
        (
            Language::Java,
            "class Demo { String input() { return \"\"; } void sink(String value) {} void run() { String value = input(); sink(value); } }",
        ),
        (
            Language::Python,
            "def run():\n  value = input()\n  sink(value)\n",
        ),
        (
            Language::Kotlin,
            "fun run() { val value = input(); sink(value) }",
        ),
        (
            Language::Swift,
            "func run() { let value = input(); sink(value) }",
        ),
        (
            Language::Ruby,
            "def run\n  value = input()\n  sink(value)\nend\n",
        ),
        (
            Language::Rust,
            "fn run() { let value = input(); sink(value); }",
        ),
        (
            Language::Shell,
            "function run() {\n  value=$(input marker)\n  sink \"$value\"\n}\n",
        ),
    ];
    for (language, source) in cases {
        assert_eq!(check(language.clone(), source), 1, "{language:?}");
    }
}

#[test]
fn objcpp_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::ObjCpp,
            r#"
void run(bool ready) {
    char *value = "safe";
    for (; ready; value = input()) { sink(value); continue; }
}
"#
        ),
        1
    );
}

#[test]
fn jsp_for_continue_runs_update_and_carries_taint() {
    assert_eq!(
        check(
            Language::Jsp,
            r#"
<html><body><%
String value = "safe";
for (; ready; value = input()) { sink(value); continue; }
%></body></html>
"#
        ),
        1
    );
}

#[test]
fn javascript_for_var_survives_loop_but_let_does_not_overwrite_outer() {
    assert_eq!(
        check(
            Language::JavaScript,
            r#"
function run(ready) {
    for (var value = input(); ready; ready = false) { break; }
    sink(value);
}
"#
        ),
        1
    );
    assert_eq!(
        check(
            Language::JavaScript,
            r#"
function run(ready) {
    let value = "safe";
    for (let value = input(); ready; ready = false) { sink(value); }
    sink(value);
}
"#
        ),
        1
    );
}

#[test]
fn php_for_assignment_survives_loop_exit() {
    assert_eq!(
        check(
            Language::Php,
            r#"
<?php
function run($ready) {
    for ($value = input(); $ready; $ready = false) { break; }
    sink($value);
}
"#
        ),
        1
    );
}

#[test]
fn go_for_short_declaration_shadows_outer_variable() {
    assert_eq!(
        check(
            Language::Go,
            r#"
func run(ready bool) {
    value := "safe"
    for value := input(); ready; ready = false { sink(value) }
    sink(value)
}
"#
        ),
        1
    );
}

#[test]
fn shared_for_break_does_not_execute_update() {
    for (language, source) in [
        (Language::JavaScript, "function run() { let value = 'safe'; for (;; value=input()) { sink(value); break; } }"),
        (Language::CSharp, "class Demo { void Run() { string value = \"safe\"; for (;; value=input()) { sink(value); break; } } }"),
        (Language::Go, "func run() { value := \"safe\"; for ;; value=input() { sink(value); break } }"),
        (Language::Php, "<?php function run() { $value = 'safe'; for (;; $value=input()) { sink($value); break; } }"),
    ] {
        assert_eq!(check(language.clone(), source), 0, "{language:?}");
    }
}
