use std::sync::OnceLock;

use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const INTENT_NUMBER: &str = "uniflow.java.source.intent-numeric-extra";
const ACCESS_CONTROL: &str = "legacy.java.sink.45fbb6d6-acff-4e77-8a81-29c860d5b3ae.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| rule.id == ACCESS_CONTROL)
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id == INTENT_NUMBER)
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| rule.id == ACCESS_CONTROL)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| rule.sink_rule_id == ACCESS_CONTROL)
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|rule| rule.rule_id == ACCESS_CONTROL || rule.rule_id == INTENT_NUMBER)
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            (
                rules.sources.len(),
                rules.sinks.len(),
                rules.sink_conditions.len()
            ),
            (1, 1, 1)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(id: &str, expected: bool) {
    let source = format!(
        "class Provider {{ void query(android.app.Activity activity, android.content.Intent intent, android.net.Uri uri) {{ activity.managedQuery(uri, null, {id}, null, null); }} }}"
    );
    let graph = build(
        &lower_program(&parse_source(Language::Java, "Provider.java", &source).unwrap()),
        rules(),
    );
    let findings = analyze(&graph, rules());
    assert_eq!(
        findings
            .iter()
            .any(|finding| finding.sink_rule_id == ACCESS_CONTROL),
        expected,
        "{source}\n{findings:#?}\ncalls={:#?}",
        graph.call_meta
    );
}

#[test]
fn intent_numeric_ids_reach_android_provider_access_control_sinks() {
    check("intent.getIntExtra(\"id\", 0)", true);
    check("42", false);
}
