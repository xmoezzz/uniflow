use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const LDAP: &str = "legacy.java.sink.7b6724bf-df47-45b8-9c28-41e3ee0d6f44.0";
const SSRF: &str = "legacy.java.sink.56be2062-96cf-47f6-83c9-c240e1405591.0";
const URL_INIT: &str = "legacy.java.passthrough.8d04e8a5-e27f-4a9c-ad0b-19f9a80a3d19";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let ids = [LDAP, SSRF];
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| ids.contains(&rule.id.as_str()))
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id.starts_with(SOURCE))
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| ids.contains(&rule.id.as_str()))
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|rule| rule.id == URL_INIT)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| ids.contains(&rule.sink_rule_id.as_str()))
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|rule| {
                    rule.rule_id.starts_with(SOURCE)
                        || ids.contains(&rule.rule_id.as_str())
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
            (2, 2, 1, 2)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!("class NetworkRules {{ void check(javax.servlet.http.HttpServletRequest request, javax.naming.directory.DirContext directory, custom.DirContext customDirectory) throws Exception {{ {body} }} }}");
    let graph = build(
        &lower_program(&parse_source(Language::Java, "NetworkRules.java", &source).unwrap()),
        rules(),
    );
    let findings = analyze(&graph, rules());
    assert_eq!(
        findings.iter().any(|finding| finding.sink_rule_id == sink),
        expected,
        "{body}\n{findings:#?}\ncalls={:#?}",
        graph.call_meta
    );
    assert!(findings
        .iter()
        .all(|finding| finding.source_rule_id.starts_with(SOURCE)));
    assert!(findings
        .iter()
        .all(|finding| finding.translations.zh_cn.is_some()));
}

#[test]
fn original_ldap_search_rule_checks_the_filter_argument() {
    check(
        "directory.search(request.getQueryString(), new Object());",
        LDAP,
        true,
    );
    check(
        "directory.search(\"(uid=alice)\", new Object());",
        LDAP,
        false,
    );
    check(
        "customDirectory.search(request.getQueryString(), new Object());",
        LDAP,
        false,
    );
}

#[test]
fn original_ssrf_rule_flows_through_url_constructor_receiver() {
    check(
        "java.net.URL url = new java.net.URL(request.getQueryString()); url.openStream();",
        SSRF,
        true,
    );
    check(
        "java.net.URL url = new java.net.URL(\"https://example.invalid/\"); url.openStream();",
        SSRF,
        false,
    );
    check(
        "custom.URL url = new custom.URL(request.getQueryString()); url.openStream();",
        SSRF,
        false,
    );
}
