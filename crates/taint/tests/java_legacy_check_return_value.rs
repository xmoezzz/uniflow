use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const FILE_SOURCE: &str =
    "legacy.java.source.0674ea59-fe26-4a9b-8ee1-f810fb139d41.0._check_return_value";
const STREAM_SOURCE: &str =
    "legacy.java.source.0674ea59-fe26-4a9b-8ee1-f810fb139d42.0._check_return_value";
const SINK: &str = "legacy.java.sink._check_return_value.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).expect("bundled Java rules");
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| rule.id == SINK)
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| matches!(rule.id.as_str(), FILE_SOURCE | STREAM_SOURCE))
                .collect(),
            unused_return_sinks: legacy
                .unused_return_sinks
                .into_iter()
                .filter(|rule| rule.id == SINK)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| rule.sink_rule_id == SINK)
                .collect(),
            ..Default::default()
        };
        assert_eq!(rules.sources.len(), 2);
        assert_eq!(rules.unused_return_sinks.len(), 1);
        assert_eq!(rules.sink_conditions.len(), 1);
        rules.validate().expect("focused check-return-value rules");
        rules
    })
}

fn check(body: &str, expected_sources: &[&str]) {
    let source = format!(
        "class CheckReturn {{ void consume(boolean value) {{}} void f(java.io.File file, java.io.FileInputStream stream) throws Exception {{ {body} }} }}"
    );
    let hir = parse_source(Language::Java, "CheckReturn.java", &source).expect("parse Java");
    let ir = lower_program(&hir);
    let graph = build(&ir, rules());
    let findings = analyze(&graph, rules());
    let mut actual = findings
        .iter()
        .filter(|finding| finding.sink_rule_id == SINK)
        .map(|finding| finding.source_rule_id.as_str())
        .collect::<Vec<_>>();
    actual.sort_unstable();
    let mut expected = expected_sources.to_vec();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "{body}\n{findings:#?}\n{:#?}",
        graph.call_meta
    );
}

#[test]
fn original_java_check_return_value_reports_only_discarded_results() {
    check("file.mkdir();", &[FILE_SOURCE]);
    check("stream.read();", &[STREAM_SOURCE]);
    check(
        "file.mkdir(); stream.read();",
        &[FILE_SOURCE, STREAM_SOURCE],
    );

    check("boolean created = file.mkdir(); consume(created);", &[]);
    check("int count = stream.read(); if (count > 0) { return; }", &[]);
    check("file.exists();", &[]);
}
