use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.328c13ae-551e-4d3f-8880-7bdb67853da4.0.";
const SINK: &str = "legacy.java.sink.e750712b-53c0-41ba-8dbc-0485c529fd6c.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let rules = RuleSet {
            metadata: legacy.metadata.into_iter().filter(|r| r.id == SINK).collect(),
            // Keep every label emitted at the original numeric source site.
            sources: legacy.sources.into_iter().filter(|r| r.id.starts_with(SOURCE)).collect(),
            sinks: legacy.sinks.into_iter().filter(|r| r.id == SINK).collect(),
            sink_conditions: legacy.sink_conditions.into_iter().filter(|r| r.sink_rule_id == SINK).collect(),
            call_conditions: legacy.call_conditions.into_iter().filter(|r| r.rule_id.starts_with(SOURCE) || r.rule_id == SINK).collect(),
            ..Default::default()
        };
        assert_eq!(rules.sources.len(), 3);
        assert_eq!(rules.sinks.len(), 1);
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, expected: bool) {
    let source = format!("class Numeric {{ void f(javax.servlet.ServletRequest request, java.sql.PreparedStatement statement, int[] values, boolean flag) {{ {body} }} }}");
    let hir = parse_source(Language::Java, "Numeric.java", &source).unwrap();
    let ir = lower_program(&hir);
    let graph = build(&ir, rules());
    let findings = analyze(&graph, rules());
    assert_eq!(!findings.is_empty(), expected, "{source}\n{findings:#?}\n{:#?}", graph.call_meta);
    assert!(findings.iter().all(|f| f.sink_rule_id == SINK && f.source_rule_id.starts_with(SOURCE)));
    assert!(findings.iter().all(|f| f.translations.zh_cn.is_some()));
}

#[test]
fn original_java_database_access_rule_tracks_numeric_update_results_and_writeback() {
    for update in ["value++", "++value", "value--", "--value"] {
        check(&format!("int value = request.getContentLength(); statement.setInt(1, {update});"), true);
        check(&format!("int value = request.getContentLength(); {update}; statement.setInt(1, value);"), true);
        check(&format!("int value = 1; statement.setInt(1, {update});"), false);
    }
}

#[test]
fn original_java_database_access_rule_tracks_heap_updates_and_branch_merges() {
    check("values[0] = request.getContentLength(); statement.setInt(1, values[0]++);", true);
    check("values[0] = request.getContentLength(); ++values[0]; statement.setInt(1, values[0]);", true);
    check("int value = request.getContentLength(); if (flag) { value++; } else { --value; } statement.setInt(1, value);", true);
    check("int value = request.getContentLength(); value++; value = 1; statement.setInt(1, value);", false);
}

#[test]
fn original_java_database_access_rule_distinguishes_updated_array_indices() {
    check("int i = 0; values[i++] = request.getContentLength(); statement.setInt(1, values[0]);", true);
    check("int i = 0; values[i++] = request.getContentLength(); statement.setInt(1, values[i]);", false);
    check("int i = 0; values[++i] = request.getContentLength(); statement.setInt(1, values[1]);", true);
    check("int i = 0; values[++i] = request.getContentLength(); statement.setInt(1, values[0]);", false);
}
