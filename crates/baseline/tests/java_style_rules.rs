use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, count: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|r| r.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing rule {rule}");
    let findings = pack.scan_text(&Language::Java, Path::new("Style.java"), source);
    assert_eq!(findings.len(), count, "{rule}: {source}\n{findings:#?}");
    // The executable HIR route must also run frontend-only checkers, once.
    let hir = JavaParser::default().parse_file("Style.java", source).unwrap();
    let integrated = pack.scan_hir(&hir, &HashMap::from([("Style.java".into(), source.into())]));
    assert_eq!(integrated.len(), count, "integrated {rule}: {source}\n{integrated:#?}");
}

fn body(rule: &str, statement: &str, count: usize) {
    check(rule, &format!("class Style {{\n void run() {{\n  {statement}\n }}\n}}"), count);
}

#[test]
fn migrated_java_empty_block() {
    let rule = "LEGACY-JAVA-AST-empty-block";
    body(rule, "{ }", 1);
    body(rule, "{ // line comment\n }", 1);
    for negative in ["{ /* intentional */ }", "{ ; }", "int[] a = {};", "String s = \"{}\";"] {
        body(rule, negative, 0);
    }
    check(rule, "class Style {}", 0);
    check(rule, "class Style { Style() {} }", 0);
    check(rule, "class Style { void empty() {} }", 1);
}

#[test]
fn migrated_java_empty_if() {
    let rule = "LEGACY-JAVA-AST-empty-if-block";
    for positive in ["if (ready) ;", "if (ready) {}", "if (ready) { // explanation\n }"] {
        body(rule, positive, 1);
    }
    for negative in ["if (ready) work();", "if (ready) { /* intended */ }", "if (ready) { ; }", "String s = \"if (ready);\";"] {
        body(rule, negative, 0);
    }
    body(rule, "if (first) if (second) work(); else ;", 0);
}

#[test]
fn migrated_java_empty_else() {
    let rule = "LEGACY-JAVA-AST-empty-else-block";
    for positive in ["if (ready) work(); else ;", "if (ready) work(); else {}",
        "if (first) if (second) work(); else ;", "if (ready) work(); else { // line\n }"] {
        body(rule, positive, 1);
    }
    for negative in ["if (ready) work();", "if (ready) work(); else recover();", "if (ready) work(); else { /* intentional */ }"] {
        body(rule, negative, 0);
    }
}

#[test]
fn migrated_java_empty_loop() {
    let rule = "LEGACY-JAVA-AST-empty-loop-block";
    for positive in ["while (ready) ;", "while (ready) {}", "for (int i=0; i<10; i++) ;",
        "for (String item : items) {}", "do {} while (ready);", "do ; while (ready);",
        "outer: while (ready) { // intentional\n }"] {
        body(rule, positive, 1);
    }
    for negative in ["while (ready) work();", "for (;;) { work(); }", "do work(); while (ready);", "while (ready) { /* wait */ }"] {
        body(rule, negative, 0);
    }
}

#[test]
fn migrated_java_empty_method() {
    let rule = "LEGACY-JAVA-AST-empty-method-block";
    for source in ["class Style { Style() {} }", "class Style { void f() {} }",
        "class Style { void f() { // line\n } }", "class Style { @A(value={1}) void f() throws Error {} }",
        "record Style(int x) { Style {} }", "class Style { class Inner { void f() {} } }"] {
        check(rule, source, 1);
    }
    for source in ["class Style {}", "interface Style { void f(); }", "class Style { void f() { ; } }",
        "class Style { void f() { /* intentional */ } }", "class Style { Runnable f = () -> {}; }",
        "class Style { int[] f = {}; }", "class Style { static {} }"] {
        check(rule, source, 0);
    }
    check(rule, "class Style { void f() {} }\nclass Other { void g() {} }", 2);
}

#[test]
fn migrated_java_empty_synchronized() {
    let rule = "LEGACY-JAVA-AST-empty-sync-block";
    body(rule, "synchronized (lock) {}", 1);
    body(rule, "synchronized (lock) { // line\n }", 1);
    body(rule, "synchronized (lock) { work(); }", 0);
    body(rule, "synchronized (lock) { /* intended */ }", 0);
    check(rule, "class Style { synchronized void f() {} }", 0);
}

#[test]
fn migrated_java_empty_try() {
    let rule = "LEGACY-JAVA-AST-empty-try-block";
    body(rule, "try {} catch (Exception e) { work(); }", 1);
    body(rule, "try { // line\n } finally { work(); }", 1);
    body(rule, "try (Resource r = open()) {}", 1);
    body(rule, "try { work(); } catch (Exception e) {} finally {}", 0);
    body(rule, "try { /* intended */ } finally {}", 0);
}

#[test]
fn migrated_java_empty_infinite_loop() {
    let rule = "LEGACY-JAVA-AST-empty-infinity-loop";
    for positive in ["while (true) {}", "while (true) ;", "for (;;) {}", "for (;;) ;", "do {} while (true);", "do ; while (true);"] {
        body(rule, positive, 1);
    }
    for negative in ["while (ready) {}", "while (true) { work(); }", "for (start();;) {}", "for (;;advance()) {}", "do work(); while (true);"] {
        body(rule, negative, 0);
    }
}

#[test]
fn migrated_java_infinite_loop() {
    let rule = "LEGACY-JAVA-AST-empty-infinity-loop-ydt";
    for positive in ["while (true) {}", "while (true) { work(); }", "for (;;) { work(); }", "do { work(); } while (true);", "do ; while (true);"] {
        body(rule, positive, 1);
    }
    for negative in ["while (ready) {}", "for (start();;) {}", "for (;;advance()) {}", "do {} while (ready);",
        "while (true) work();", "do work(); while (true);", "for (;;) work();"] {
        body(rule, negative, 0);
    }
}

#[test]
fn migrated_java_assignment_condition() {
    let rule = "LEGACY-JAVA-AST-error-cond-stmt";
    for positive in ["if (ready = check()) work();", "if ((ready = check()) && other) work();",
        "while ((item = next()) != null) work();", "for (; ready = check(); advance()) work();",
        "do work(); while (ready = check());"] {
        body(rule, positive, 1);
    }
    for negative in ["if (a == b) work();", "while (a != b) work();", "for (int i=0; i<10; i=next()) work();", "if (ready) { x = input(); }", "if (s.equals(\"=\")) work();"] {
        body(rule, negative, 0);
    }
}

#[test]
fn migrated_java_consecutive_semicolons() {
    let rule = "LEGACY-JAVA-AST-invalid-semicolon";
    body(rule, ";\n;", 1);
    body(rule, "; /* comment */ ;", 1);
    body(rule, "work(); ;", 0);
    body(rule, "for (;;) work();", 0);
    body(rule, "String s = \";;\";", 0);
}

#[test]
fn migrated_java_detached_if_block() {
    let rule = "LEGACY-JAVA-AST-error-block";
    body(rule, "if (ready); { work(); }", 1);
    body(rule, "if (ready) /* comment */ ;\n { work(); }", 1);
    body(rule, "if (ready) { work(); }", 0);
    body(rule, "if (ready); work(); { recover(); }", 0);
    body(rule, "if (ready); else { work(); }", 0);
}

#[test]
fn migrated_java_missing_switch_default() {
    let rule = "LEGACY-JAVA-AST-switch-default";
    body(rule, "switch (value) { case 1: work(); break; }", 1);
    body(rule, "switch (value) { case 1 -> work(); }", 1);
    body(rule, "switch (value) { case 1: work(); break; default: recover(); }", 0);
    body(rule, "switch (value) { case \"default\": work(); break; }", 1);
    body(rule, "switch (value) { case 1: /* default: */ work(); }", 1);
    body(rule, "int result = switch (value) { case 1 -> 2; };", 1);
    body(rule, "return switch (value) { default -> 2; };", 0);
}

#[test]
fn java_style_checks_preserve_text_blocks_paths_and_source_coordinates() {
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|r| r.id == "LEGACY-JAVA-AST-empty-if-block");
    pack.rules[0].matcher.path_pattern = r"\.java$".into();
    let source = "// 中文前缀\nclass Style {\n void run() {\n  String text = \"\"\"\n   if (ready) {}\n  \"\"\";\n  if (ready) {}\n }\n}";
    let findings = pack.scan_text(&Language::Java, Path::new("Style.java"), source);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!((findings[0].line, findings[0].column), (7, 3));
    assert_eq!(findings[0].snippet, "if (ready) {}");
    assert!(pack.scan_text(&Language::Java, Path::new("Style.txt"), source).is_empty());
    assert!(pack.scan_text(&Language::JavaScript, Path::new("Style.java"), source).is_empty());
}

#[test]
fn java_style_check_rejects_conflicting_matcher_modes() {
    for extra in ["    callee: target", "    lexical_kind: identifier\n    lexical_pattern: target"] {
        let yaml = format!("id: invalid\ntitle: Invalid\nrules:\n- id: invalid\n  title: Invalid\n  severity: warning\n  confidence: high\n  matcher:\n    java_style: empty_if\n{extra}\n");
        assert!(BaselinePack::from_yaml_str(&yaml).is_err());
    }
}
