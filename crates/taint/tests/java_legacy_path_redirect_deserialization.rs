use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const PATH: &str = "legacy.java.sink.9745461f-0d31-4eec-9cb4-aa344d78a475.0";
const PATH_TO_FILE: &str = "legacy.java.sink.28ef8c1f-1db5-4d59-852d-f4a5023c7f1e.0";
const REDIRECT: &str = "legacy.java.sink.7508d877-8930-4793-bd4a-ca2f4ecfa86b.0";
const JSON: &str = "legacy.java.sink.d9f07628-44b6-4f47-8832-1f8e25bb6897.0";
const YAML: &str = "legacy.java.sink.5a734fb6-6c09-45ff-8509-0d73a9bcbee0.0";
const PATHS_GET: &str = "legacy.java.passthrough.f38c7f06-94a4-4e0d-b3ff-f5a766990ddb";
const SAFE_FILENAME: &str =
    "legacy.java.passthrough_transform.cc5c1ae9-f45f-43ae-b989-c03101f03596";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let ids = [PATH, PATH_TO_FILE, REDIRECT, JSON, YAML];
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
            taint_transforms: legacy
                .taint_transforms
                .into_iter()
                .filter(|rule| rule.id == SAFE_FILENAME)
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|rule| rule.id == PATHS_GET || rule.id == SAFE_FILENAME)
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
                        || rule.rule_id == PATHS_GET
                        || rule.rule_id == SAFE_FILENAME
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
            (2, 5, 5)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!(
        "class LegacySecurity {{ void check(javax.servlet.http.HttpServletRequest request, javax.servlet.ServletResponse response, com.fasterxml.jackson.databind.ObjectMapper mapper, org.yaml.snakeyaml.Yaml yaml, custom.ObjectMapper customMapper) throws Exception {{ {body} }} }}"
    );
    let graph = build(
        &lower_program(&parse_source(Language::Java, "LegacySecurity.java", &source).unwrap()),
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
fn original_path_rule_matches_jvm_file_constructor_only() {
    check(
        "java.io.FileInputStream stream = new java.io.FileInputStream(request.getQueryString());",
        PATH,
        true,
    );
    check(
        "java.io.FileInputStream stream = new java.io.FileInputStream(\"safe.txt\");",
        PATH,
        false,
    );
    check(
        "custom.FileInputStream stream = new custom.FileInputStream(request.getQueryString());",
        PATH,
        false,
    );
}

#[test]
fn original_path_transform_suppresses_only_the_filename_projection() {
    check(
        "java.nio.file.Paths.get(request.getQueryString()).toFile();",
        PATH_TO_FILE,
        true,
    );
    check(
        "java.nio.file.Paths.get(request.getQueryString()).getFileName().toFile();",
        PATH_TO_FILE,
        false,
    );
}

#[test]
fn original_redirect_rule_checks_the_destination_argument() {
    check(
        "response.sendRedirect(request.getQueryString());",
        REDIRECT,
        true,
    );
    check("response.sendRedirect(\"/home\");", REDIRECT, false);
}

#[test]
fn original_json_and_yaml_deserialization_rules_match_exact_owners() {
    check("mapper.readValue(request.getQueryString());", JSON, true);
    check("mapper.readValue(\"{}\");", JSON, false);
    check(
        "customMapper.readValue(request.getQueryString());",
        JSON,
        false,
    );
    check("yaml.load(request.getQueryString());", YAML, true);
    check("yaml.load(\"name: safe\");", YAML, false);
}
