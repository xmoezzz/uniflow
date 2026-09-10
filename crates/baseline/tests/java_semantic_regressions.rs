use std::collections::HashMap;
use uniflow_baseline::{builtin_security_pack, BaselineFinding};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn scan(source: &str) -> Vec<BaselineFinding> {
    let program = JavaParser::default()
        .parse_file("Regression.java", source)
        .unwrap();
    builtin_security_pack().unwrap().scan_hir(
        &program,
        &HashMap::from([("Regression.java".to_owned(), source.to_owned())]),
    )
}

#[test]
fn migrated_java_null_assignment_return_requires_adjacent_same_symbol() {
    let source = r#"
class Regression {
    Object declaration() {
        Object result = null;
        /* still adjacent */ return result;
    }
    Object assignment(Object result) {
        result = null;
        return result;
    }
    Object different(Object other) {
        Object result = null;
        return other;
    }
    Object intervening(Object result) {
        result = null;
        work();
        return result;
    }
    Object nonNull(Object input) {
        Object result = input;
        return result;
    }
}
"#;
    let matches = scan(source)
        .into_iter()
        .filter(|f| f.rule_id == "LEGACY-JAVA-AST-null-password")
        .collect::<Vec<_>>();
    assert_eq!(
        matches.iter().map(|f| f.line).collect::<Vec<_>>(),
        [5, 9],
        "{matches:#?}"
    );
}

#[test]
fn migrated_java_constant_equality_results_use_hir_structure() {
    let source = r#"
class Regression {
    boolean same(int value, int other) {
        boolean a = value == value;
        boolean b = value != value;
        boolean c = (value) == value;
        boolean d = this.field == this.field;
        boolean e = call(value) != call(value);
        boolean f = value == other;
        return a;
    }
    boolean constants() {
        boolean a = 1 == 2;
        boolean b = 1 != 2;
        boolean c = "a" == "b";
        boolean d = true != false;
        boolean e = 1 == 1;
        boolean f = null == null;
        boolean g = 1.0 == 2.0;
        return a;
    }
}
"#;
    let findings = scan(source);
    let true_rule = "LEGACY-JAVA-AST-expression_always_true";
    let false_rule = "LEGACY-JAVA-AST-expression_always_false";
    let true_lines = findings
        .iter()
        .filter(|f| f.rule_id == true_rule)
        .map(|f| f.line)
        .collect::<Vec<_>>();
    let false_lines = findings
        .iter()
        .filter(|f| f.rule_id == false_rule)
        .map(|f| f.line)
        .collect::<Vec<_>>();
    assert_eq!(true_lines, [4, 6, 7, 14, 16, 17, 18], "{findings:#?}");
    assert_eq!(false_lines, [5, 8, 13, 15], "{findings:#?}");
}

#[test]
fn migrated_java_broad_catch_preserves_clause_types_and_scope() {
    let source = r#"
class Regression {
    void run() {
        try { work(); }
        catch (RuntimeException error) { recover(error); }
        catch (Exception error) { recover(error); }
        try { other(); }
        catch (Exception error) { recover(error); }
    }
}
"#;
    let matches = scan(source)
        .into_iter()
        .filter(|f| f.rule_id == "LEGACY-JAVA-AST-overly-board-catch")
        .collect::<Vec<_>>();
    assert_eq!(
        matches
            .iter()
            .map(|f| (f.line, f.column))
            .collect::<Vec<_>>(),
        [(6, 9), (8, 9)],
        "{matches:#?}"
    );
}

#[test]
fn migrated_java_optional_null_checks_returns_and_typed_operands() {
    let source = r#"
import java.util.Optional;
class Regression {
    Optional<String> field;
    Optional<String> missing() { return null; }
    boolean parameter(Optional<String> value) { return value == null; }
    boolean local() {
        Optional<String> value = Optional.empty();
        return null != value;
    }
    boolean fieldCheck() { return field == null; }
    Optional<String> safeReturn() { return Optional.empty(); }
    boolean safeCheck(Optional<String> value) { return value.isPresent(); }
    boolean ordinary(Object value) { return value == null; }
    boolean nonNull(Optional<String> value, Optional<String> other) { return value == other; }
}
"#;
    let findings = scan(source)
        .into_iter()
        .filter(|f| f.rule_id == "LEGACY-JAVA-AST-optional-null")
        .collect::<Vec<_>>();
    assert_eq!(
        findings.iter().map(|f| f.line).collect::<Vec<_>>(),
        [5, 6, 9, 11],
        "{findings:#?}"
    );
}

#[test]
fn java_findings_use_file_coordinates_and_local_types() {
    let source = "// 非 ASCII prefix\npackage sample;\nimport java.io.File;\n\nclass Regression {\n    void run() {\n        File directory = new File(\"tmp\");\n        directory.mkdir();\n        while (ready) {\n            directory.mkdir();\n        }\n        try { work(); } finally {\n            directory.mkdir();\n        }\n    }\n}\n";
    let matches = scan(source)
        .into_iter()
        .filter(|finding| finding.rule_id == "LEGACY-JAVA-AST-unchecked-return-value")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{matches:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|f| (f.line, f.column))
            .collect::<Vec<_>>(),
        [(8, 9), (10, 13), (13, 13)]
    );
    assert!(matches.iter().all(|f| f.snippet == "directory.mkdir();"));
}

#[test]
fn java_branch_local_shadows_do_not_escape_to_sibling_or_outer_scope() {
    let source = r#"
import java.util.Optional;
class Regression {
    Object value;
    boolean run(boolean first, boolean second) {
        if (first) {
            Optional<String> value = Optional.empty();
            return value == null;
        } else if (second) {
            String value = "text";
            return value == "other";
        } else {
            boolean absent = value == null;
        }
        return value == null;
    }
}
"#;
    let findings = scan(source);
    for (rule, line) in [("optional-null", 8), ("string-compare", 11)] {
        let matches = findings
            .iter()
            .filter(|f| f.rule_id == format!("LEGACY-JAVA-AST-{rule}"))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{rule}: {findings:#?}");
        assert_eq!(matches[0].line, line);
    }
}

#[test]
fn java_adjacent_loops_and_lambda_are_separate_control_regions() {
    let source = r#"
class Regression {
    void run(Object lock) {
        while (ready) { lock.wait(); }
        while (ready) {
            Runnable task = () -> { lock.wait(); };
            lock.wait();
        }
        lock.wait();
    }
}
"#;
    let matches = scan(source)
        .into_iter()
        .filter(|f| f.rule_id == "LEGACY-JAVA-AST-call-wait-await-method")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{matches:#?}");
}

#[test]
fn migrated_java_nested_equality_preserves_parentheses_and_associativity() {
    let source = r#"
class Regression {
    boolean run(boolean a, boolean b, boolean c) {
        boolean one = (a == b) == c;
        boolean two = a != (b == c);
        boolean three = a == b != c;
        boolean four = ((a != b)) != c;
        boolean separate = (a == b) && (b == c);
        boolean simple = a == b;
        String text = "a == b == c";
        return one;
    }
}
"#;
    let findings = scan(source)
        .into_iter()
        .filter(|f| f.rule_id == "LEGACY-JAVA-AST-error-compare")
        .collect::<Vec<_>>();
    assert_eq!(
        findings.iter().map(|f| f.line).collect::<Vec<_>>(),
        [4, 5, 6, 7],
        "{findings:#?}"
    );
}

#[test]
fn migrated_java_floating_loop_variables_use_declared_types_and_scope() {
    let source = r#"
class Regression {
    double counter;
    void run(float parameter) {
        for (float x = 0; x < 1; x += 0.1) work();
        double local = 0;
        while (local <= 1) { local += 0.1; }
        do { local += 0.1; } while (local != 2);
        for (int counter = 0; counter < 10; counter++) work();
        while (counter > 0) work();
        while (parameter < 1) work();
        int integer = 0;
        while (integer < 10) work();
        for (;;) break;
        double unrelated = 0;
        while (ready) work(unrelated);
    }
}
"#;
    let findings = scan(source);
    for id in [
        "LEGACY-JAVA-AST-float-loop-var",
        "LEGACY-JAVA-AST-float-loop-var-ydt",
    ] {
        let matches = findings
            .iter()
            .filter(|f| f.rule_id == id)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.iter().map(|f| f.line).collect::<Vec<_>>(),
            [5, 7, 8, 10],
            "{id}: {matches:#?}"
        );
    }
}

#[test]
fn java_wait_check_recognizes_all_three_for_clauses_and_resets_for_lambda() {
    let source = r#"
class Regression {
    void run(Object lock, boolean ready) {
        for (lock.wait(); ready; lock.wait()) {
            lock.wait();
            Runnable nested = () -> { lock.wait(); };
        }
        lock.wait();
    }
}
"#;
    let findings = scan(source)
        .into_iter()
        .filter(|f| f.rule_id == "LEGACY-JAVA-AST-call-wait-await-method")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 2, "{findings:#?}");
}
