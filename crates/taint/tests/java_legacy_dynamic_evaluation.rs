use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const REGEX: &str = "legacy.java.sink.27d1313b-f16a-465f-b5f9-4baac6da4cad.0";
const OGNL: &str = "legacy.java.sink.d867f4a4-afd9-4817-8710-c592ae497744.0";
const TEMPLATE: &str = "legacy.java.sink.54de28b5-3964-494d-bf0f-f20f7c87b936.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let ids = [REGEX, OGNL, TEMPLATE];
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
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| ids.contains(&rule.sink_rule_id.as_str()))
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|rule| {
                    rule.rule_id.starts_with(SOURCE) || ids.contains(&rule.rule_id.as_str())
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            (
                rules.sources.len(),
                rules.sinks.len(),
                rules.sink_conditions.len()
            ),
            (2, 3, 3)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!(
        "class DynamicEvaluation {{ void check(javax.servlet.http.HttpServletRequest request, org.apache.velocity.VelocityContext context, java.io.Writer writer) throws Exception {{ {body} }} }}"
    );
    let graph = build(
        &lower_program(&parse_source(Language::Java, "DynamicEvaluation.java", &source).unwrap()),
        rules(),
    );
    let findings = analyze(&graph, rules());
    assert_eq!(
        findings.iter().any(|finding| finding.sink_rule_id == sink),
        expected,
        "{body}\n{findings:#?}\ncalls={:#?}",
        graph.call_meta
    );
}

#[test]
fn original_regex_rule_checks_pattern_source_text() {
    check(
        "java.util.regex.Pattern.compile(request.getQueryString());",
        REGEX,
        true,
    );
    check("java.util.regex.Pattern.compile(\"[a-z]+\");", REGEX, false);
    check(
        "custom.Pattern.compile(request.getQueryString());",
        REGEX,
        false,
    );
}

#[test]
fn original_ognl_rule_checks_expression_argument() {
    check(
        "ognl.Ognl.getValue(request.getQueryString(), new Object());",
        OGNL,
        true,
    );
    check(
        "ognl.Ognl.getValue(\"safe.name\", new Object());",
        OGNL,
        false,
    );
    check(
        "custom.Ognl.getValue(request.getQueryString(), new Object());",
        OGNL,
        false,
    );
}

#[test]
fn original_velocity_rule_checks_template_argument() {
    check(
        "org.apache.velocity.app.Velocity.evaluate(context, writer, \"audit\", request.getQueryString());",
        TEMPLATE,
        true,
    );
    check(
        "org.apache.velocity.app.Velocity.evaluate(context, writer, \"audit\", \"Hello $name\");",
        TEMPLATE,
        false,
    );
    check(
        "custom.Velocity.evaluate(context, writer, \"audit\", request.getQueryString());",
        TEMPLATE,
        false,
    );
}
