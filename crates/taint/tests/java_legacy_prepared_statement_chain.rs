use std::sync::OnceLock;

use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.web";
const SINK: &str = "legacy.java.sink.e750712b-53c0-41ba-8dbc-0485c529fd6c.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let focused = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| rule.id == SINK)
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id == SOURCE)
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| rule.id == SINK)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| rule.sink_rule_id == SINK)
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|rule| rule.rule_id == SOURCE || rule.rule_id == SINK)
                .collect(),
            ..Default::default()
        };
        assert_eq!(focused.sources.len(), 1);
        assert_eq!(focused.sinks.len(), 1);
        assert_eq!(focused.sink_conditions.len(), 1);
        focused.validate().unwrap();
        focused
    })
}

fn check(value: &str, expected: usize) {
    let source = format!("class Prepared {{ void run(javax.servlet.http.HttpServletRequest request, javax.sql.DataSource data) throws Exception {{ data.getConnection().prepareStatement(\"SELECT name FROM employee WHERE id=?\").setString(1, {value}); }} }}");
    let hir = parse_source(Language::Java, "Prepared.java", &source).unwrap();
    let ir = lower_program(&hir);
    let graph = build(&ir, rules());
    let findings = analyze(&graph, rules());
    assert_eq!(
        findings.len(),
        expected,
        "{source}\n{findings:#?}\n{:#?}",
        graph.call_meta
    );
    assert!(findings
        .iter()
        .all(|finding| finding.source_rule_id == SOURCE && finding.sink_rule_id == SINK));
    assert!(findings.iter().all(|finding| finding
        .translations
        .zh_cn
        .as_ref()
        .is_some_and(|text| !text.message.is_empty())));
}

#[test]
fn bundled_java_prepared_statement_rule_executes_factory_chain() {
    check("request.getQueryString()", 1);
    check("\"safe\"", 0);
}
