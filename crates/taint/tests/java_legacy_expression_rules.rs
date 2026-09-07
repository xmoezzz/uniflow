use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.web";
const SINK: &str = "legacy.java.sink.bc4f4fcb-12de-41ab-81d6-6d9915c0e93e.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        // Select actual bundled rules, retaining their original conditions;
        // these are not simplified replacements defined by the testcase.
        let focused = RuleSet {
            sources: legacy.sources.into_iter().filter(|r| r.id == SOURCE).collect(),
            sinks: legacy.sinks.into_iter().filter(|r| r.id == SINK).collect(),
            sink_conditions: legacy.sink_conditions.into_iter().filter(|r| r.sink_rule_id == SINK).collect(),
            call_conditions: legacy.call_conditions.into_iter().filter(|r| r.rule_id == SOURCE || r.rule_id == SINK).collect(),
            ..Default::default()
        };
        assert_eq!(focused.sources.len(), 1);
        assert_eq!(focused.sinks.len(), 1);
        assert_eq!(focused.sink_conditions.len(), 1);
        focused.validate().unwrap(); focused
    })
}

fn check(body: &str, expected: usize) {
    let source = format!("class Legacy {{ void f(javax.servlet.http.HttpServletRequest request, java.sql.Statement[] statements, String[] values, boolean flag) {{ {body} }} }}");
    let hir = parse_source(Language::Java, "Legacy.java", &source).unwrap();
    let ir = lower_program(&hir);
    let findings = analyze(&build(&ir, rules()), rules());
    assert_eq!(findings.len(), expected, "{body}\n{findings:#?}");
    assert!(findings.iter().all(|finding| finding.source_rule_id == SOURCE && finding.sink_rule_id == SINK));
}

#[test]
fn bundled_java_sql_rule_checks_casts_and_conditional_result() {
    check("String query=flag ? (String) request.getQueryString() : \"SELECT 1\"; statements[0].executeQuery(query);", 1);
}

#[test]
fn bundled_java_sql_rule_checks_array_store_and_load() {
    check("values[0]=request.getQueryString(); statements[0].executeQuery(values[0]);", 1);
}

#[test]
fn bundled_java_sql_rule_keeps_safe_conditional_negative() {
    check("String query=true ? \"SELECT 1\" : request.getQueryString(); statements[0].executeQuery(query);", 0);
}
