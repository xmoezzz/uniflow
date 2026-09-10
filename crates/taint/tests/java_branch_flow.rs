use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_rules::{ApiMatcher, Port, RuleSet, SinkRule, SourceRule};
use uniflow_taint::{analyze, TaintFinding};
use uniflow_value_flow::build;

fn check(source: &str) -> Vec<TaintFinding> {
    let rules = RuleSet {
        sources: vec![SourceRule {
            id: "branch-source".into(),
            language: Some(Language::Java),
            matcher: ApiMatcher {
                method_name: Some("input".into()),
                ..Default::default()
            },
            out: Port::Return,
            kind: "untrusted".into(),
        }],
        sinks: vec![SinkRule {
            id: "branch-sink".into(),
            language: Some(Language::Java),
            matcher: ApiMatcher {
                method_name: Some("sink".into()),
                ..Default::default()
            },
            inputs: vec![Port::Arg(0)],
            kind: "untrusted".into(),
        }],
        ..Default::default()
    };
    rules.validate().unwrap();
    let hir = parse_source(Language::Java, "Branch.java", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

#[test]
fn java_branch_join_preserves_tainted_assignment() {
    let findings = check(
        r#"
class Branch {
    void run(boolean flag) {
        String value = "safe";
        if (flag) {
            value = input();
        } else {
            value = "safe";
        }
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].sink_rule_id, "branch-sink");
}

#[test]
fn java_local_shadow_taint_does_not_pollute_same_named_field() {
    let findings = check(
        r#"
class Branch {
    String value;
    void run(boolean flag) {
        if (flag) {
            String value = input();
            sink(value);
        }
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(
        findings[0].sink_location, "@Branch.java:7:13",
        "{findings:#?}"
    );
}

#[test]
fn java_unbraced_branch_assignment_reaches_join() {
    let findings = check(
        r#"
class Branch {
    void run(boolean flag) {
        String value = "safe";
        if (flag) value = input(); else value = "safe";
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].sink_location, "@Branch.java:6:9");
}

#[test]
fn java_while_condition_assignment_taints_body() {
    let findings = check(
        r#"
class Branch {
    void run() {
        String value = "safe";
        while ((value = input()) != null) sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

#[test]
fn java_do_body_executes_before_condition_and_exit() {
    let findings = check(
        r#"
class Branch {
    void run() {
        String value = "safe";
        do value = input(); while (false);
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].sink_location, "@Branch.java:6:9");
}

#[test]
fn java_enhanced_for_propagates_iterable_without_leaking_item_binding() {
    let findings = check(
        r#"
class Branch {
    String item;
    void run() {
        for (String item : input()) sink(item);
        sink(item);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert_eq!(findings[0].sink_location, "@Branch.java:5:37");
}

#[test]
fn java_loop_continue_and_break_do_not_execute_following_sink() {
    for transfer in ["continue", "break"] {
        let source = format!("class Branch {{\n void run() {{\n String value = input();\n while (ready) {{ {transfer}; sink(value); }}\n }}\n}}");
        let findings = check(&source);
        assert!(findings.is_empty(), "{transfer}: {findings:#?}");
    }
}

#[test]
fn java_uninitialized_local_assignment_does_not_taint_same_named_field() {
    let findings = check(
        r#"
class Branch {
    String value;
    void run() {
        String value;
        while ((value = input()) != null) sink(value);
        sink(this.value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert!(findings[0].sink_location.starts_with("@Branch.java:6:"));
}

#[test]
fn java_for_update_taint_reaches_next_iteration() {
    let findings = check(
        r#"
class Branch {
    void run(boolean ready) {
        String value = "safe";
        for (; ready; value = input()) sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

#[test]
fn java_for_continue_carries_assignment_into_update() {
    let findings = check(
        r#"
class Branch {
    void run(boolean ready, boolean skip) {
        String value = "safe";
        for (; ready; sink(value)) {
            if (skip) { value = input(); continue; }
            value = "safe";
        }
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

#[test]
fn java_for_break_bypasses_tainted_update() {
    let findings = check(
        r#"
class Branch {
    void run() {
        String value = "safe";
        for (;; value = input()) { break; }
        sink(value);
    }
}
"#,
    );
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn java_for_initializer_scope_and_multiple_declarators() {
    let findings = check(
        r#"
class Branch {
    String value;
    void run(boolean ready) {
        for (String value = input(), copy = value; ready; ready = false) sink(copy);
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert!(findings[0].sink_location.starts_with("@Branch.java:5:"));
}

#[test]
fn java_for_update_only_runs_after_body_not_before_first_iteration() {
    let findings = check(
        r#"
class Branch {
    void run() {
        String value = "safe";
        for (;; value = input()) { sink(value); break; }
    }
}
"#,
    );
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn java_for_continue_executes_finally_before_update() {
    let findings = check(
        r#"
class Branch {
    void run(boolean ready) {
        String value = "safe";
        for (; ready; sink(value)) {
            try { value = input(); continue; }
            finally { value = "safe"; }
        }
    }
}
"#,
    );
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn java_for_break_executes_finally_before_exit() {
    let findings = check(
        r#"
class Branch {
    void run() {
        String value = "safe";
        for (;;) {
            try { break; }
            finally { value = input(); }
        }
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
}

#[test]
fn java_normal_finally_preserves_following_statements() {
    let findings = check(
        r#"
class Branch {
    void run() {
        String value = "safe";
        try { work(); } finally { value = input(); }
        sink(value);
    }
}
"#,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
}
