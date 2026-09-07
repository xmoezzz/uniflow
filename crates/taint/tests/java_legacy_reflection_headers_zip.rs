use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const WEB_SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const ZIP_SOURCE: &str = "legacy.java.source.4e4fee40-7d78-4be7-9a4d-e8d33b731b4f.0.zipentryname";
const REFLECTION: &str = "legacy.java.sink.8dd1b89d-71f3-4e46-b892-fa201b5ba4f8.0";
const HEADER: &str = "legacy.java.sink.5ecb478e-f708-4016-9136-d690d7e756ce.0";
const ZIP_COPY: &str = "legacy.java.sink.d3fe1216-f703-495e-842a-ea717bfb66a4.0";
const PATHS_GET: &str = "legacy.java.passthrough.f38c7f06-94a4-4e0d-b3ff-f5a766990ddb";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let sinks = [REFLECTION, HEADER, ZIP_COPY];
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| sinks.contains(&rule.id.as_str()))
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id.starts_with(WEB_SOURCE) || rule.id == ZIP_SOURCE)
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| sinks.contains(&rule.id.as_str()))
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|rule| rule.id == PATHS_GET)
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
                        || rule.rule_id == ZIP_SOURCE
                        || rule.rule_id == PATHS_GET
                        || sinks.contains(&rule.rule_id.as_str())
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
            (3, 3, 1, 3)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!(
        "class LegacySecurity {{ void check(javax.servlet.http.HttpServletRequest request, java.lang.ClassLoader loader, custom.ClassLoader customLoader, java.net.URL url, java.net.URLConnection connection, custom.URLConnection customConnection, java.util.zip.ZipEntry entry, java.io.InputStream input) throws Exception {{ {body} }} }}"
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
}

#[test]
fn original_unsafe_reflection_rule_checks_class_loader_arguments() {
    check(
        "loader.loadClass(request.getQueryString());",
        REFLECTION,
        true,
    );
    check("loader.loadClass(\"com.example.Safe\");", REFLECTION, false);
    check(
        "customLoader.loadClass(request.getQueryString());",
        REFLECTION,
        false,
    );
}

#[test]
fn original_header_rule_checks_url_connection_value_through_factory_typing() {
    check(
        "java.net.URLConnection made = url.openConnection(); made.setRequestProperty(\"X-Test\", request.getQueryString());",
        HEADER,
        true,
    );
    check(
        "connection.setRequestProperty(\"X-Test\", \"safe\");",
        HEADER,
        false,
    );
    check(
        "customConnection.setRequestProperty(\"X-Test\", request.getQueryString());",
        HEADER,
        false,
    );
}

#[test]
fn original_zip_overwrite_rule_flows_entry_name_through_paths_get() {
    check(
        "java.nio.file.Files.copy(input, java.nio.file.Paths.get(entry.getName()));",
        ZIP_COPY,
        true,
    );
    check(
        "java.nio.file.Files.copy(input, java.nio.file.Paths.get(\"safe.txt\"));",
        ZIP_COPY,
        false,
    );
    check(
        "custom.Files.copy(input, java.nio.file.Paths.get(entry.getName()));",
        ZIP_COPY,
        false,
    );
}
