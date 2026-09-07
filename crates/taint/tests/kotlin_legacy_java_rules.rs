use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const SSRF: &str = "legacy.java.sink.56be2062-96cf-47f6-83c9-c240e1405591.0";
const URL_INIT: &str = "legacy.java.passthrough.8d04e8a5-e27f-4a9c-ad0b-19f9a80a3d19";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Kotlin).unwrap();
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| rule.id == SSRF)
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id.starts_with(SOURCE))
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| rule.id == SSRF)
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|rule| rule.id == URL_INIT)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| rule.sink_rule_id == SSRF)
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|rule| {
                    rule.rule_id.starts_with(SOURCE)
                        || rule.rule_id == SSRF
                        || rule.rule_id == URL_INIT
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            (
                rules.sources.len(),
                rules.sinks.len(),
                rules.propagators.len(),
                rules.sink_conditions.len()
            ),
            (2, 1, 1, 1)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, expected: bool) {
    let source = format!("fun check(request: javax.servlet.http.HttpServletRequest) {{ {body} }}");
    let graph = build(
        &lower_program(&parse_source(Language::Kotlin, "NetworkRules.kt", &source).unwrap()),
        rules(),
    );
    let findings = analyze(&graph, rules());
    assert_eq!(
        findings.iter().any(|finding| finding.sink_rule_id == SSRF),
        expected,
        "{body}\n{findings:#?}\ncalls={:#?}",
        graph.call_meta
    );
}

#[test]
fn retargeted_java_ssrf_rule_executes_on_kotlin_constructor_chain() {
    check(
        "val url: java.net.URL = java.net.URL(request.getQueryString()); url.openStream()",
        true,
    );
    check(
        "val url: java.net.URL = java.net.URL(\"https://example.invalid/\"); url.openStream()",
        false,
    );
    check(
        "val url: custom.URL = custom.URL(request.getQueryString()); url.openStream()",
        false,
    );
}
