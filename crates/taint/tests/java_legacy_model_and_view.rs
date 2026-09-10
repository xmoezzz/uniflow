use std::sync::OnceLock;

use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const WEB_SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const PORTLET_OBJECT: &str = "legacy.java.sink.57eac89a-d083-4846-a8fc-5c8ebed32557.0";
const SERVLET_OBJECT: &str = "legacy.java.sink.a17c7ec0-ede8-4b2c-84d8-cd2b21362cb9.0";
const SERVLET_ALL: &str = "legacy.java.sink.dc02a381-7617-4253-98cf-c9c8a99db883.0";
const MODEL_CONSTRUCTOR: &str = "legacy.java.sink.d6d784cd-746c-436a-a3b6-7f2693cf97ee.0";
const MAP_PUT: &str = "uniflow.java.propagator.map-put-value";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let sinks = [
            PORTLET_OBJECT,
            SERVLET_OBJECT,
            SERVLET_ALL,
            MODEL_CONSTRUCTOR,
        ];
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| sinks.contains(&rule.id.as_str()))
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id.starts_with(WEB_SOURCE))
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| sinks.contains(&rule.id.as_str()))
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|rule| rule.id == MAP_PUT)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|rule| sinks.contains(&rule.sink_rule_id.as_str()))
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|rule| {
                    rule.rule_id.starts_with(WEB_SOURCE)
                        || sinks.contains(&rule.rule_id.as_str())
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            (
                rules.sources.len(),
                rules.sinks.len(),
                rules.sink_conditions.len(),
                rules.propagators.len()
            ),
            (2, 4, 4, 1)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!(
        "class WebView {{ void render(javax.servlet.http.HttpServletRequest request, org.springframework.web.portlet.ModelAndView portlet, org.springframework.web.servlet.ModelAndView servlet, java.util.Map values) {{ {body} }} }}"
    );
    let graph = build(
        &lower_program(&parse_source(Language::Java, "WebView.java", &source).unwrap()),
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
fn request_data_crossing_spring_model_boundaries_is_reported() {
    check(
        "portlet.addObject(\"name\", request.getQueryString());",
        PORTLET_OBJECT,
        true,
    );
    check(
        "portlet.addObject(\"name\", \"safe\");",
        PORTLET_OBJECT,
        false,
    );
    check(
        "servlet.addObject(\"name\", request.getQueryString());",
        SERVLET_OBJECT,
        true,
    );
    check(
        "servlet.addObject(\"name\", \"safe\");",
        SERVLET_OBJECT,
        false,
    );
}

#[test]
fn spring_model_bulk_and_constructor_inputs_preserve_taint() {
    check(
        "values.put(\"name\", request.getQueryString()); servlet.addAllObjects(values);",
        SERVLET_ALL,
        true,
    );
    check(
        "values.put(\"name\", \"safe\"); servlet.addAllObjects(values);",
        SERVLET_ALL,
        false,
    );
    check(
        "servlet.addAllObjects(values); values.put(\"name\", request.getQueryString());",
        SERVLET_ALL,
        false,
    );
    check(
        "while (values != null) { servlet.addAllObjects(values); values.put(\"name\", request.getQueryString()); }",
        SERVLET_ALL,
        true,
    );
    check(
        "org.springframework.web.servlet.ModelAndView made = new org.springframework.web.servlet.ModelAndView(request.getQueryString());",
        MODEL_CONSTRUCTOR,
        true,
    );
    check(
        "org.springframework.web.servlet.ModelAndView made = new org.springframework.web.servlet.ModelAndView(\"home\");",
        MODEL_CONSTRUCTOR,
        false,
    );
}
