use std::sync::OnceLock;

use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const PREFIX: &str = "uniflow.java.";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| rule.id.starts_with(PREFIX))
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| rule.id.starts_with(PREFIX))
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|rule| rule.id.starts_with(PREFIX))
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|rule| rule.id.starts_with(PREFIX))
                .collect(),
            ..Default::default()
        };
        assert_eq!(
            (rules.sources.len(), rules.sinks.len(), rules.propagators.len()),
            (4, 4, 2)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!(
        "class Security {{ void check(java.util.zip.ZipEntry entry, java.util.Properties properties, javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response) throws Exception {{ {body} }} }}"
    );
    let graph = build(
        &lower_program(&parse_source(Language::Java, "Security.java", &source).unwrap()),
        rules(),
    );
    let findings = analyze(&graph, rules());
    assert_eq!(
        findings
            .iter()
            .any(|finding| finding.sink_rule_id == sink),
        expected,
        "{body}\n{findings:#?}\ncalls={:#?}",
        graph.call_meta
    );
}

#[test]
fn zip_entry_names_are_tracked_into_extraction_paths() {
    let sink = "uniflow.java.sink.zip-entry-path";
    check("java.io.File out = new java.io.File(\"root\", entry.getName());", sink, true);
    check("java.io.File out = new java.io.File(\"root\", \"safe.txt\");", sink, false);
}

#[test]
fn external_properties_are_tracked_into_pbe_salts() {
    let sink = "uniflow.java.sink.pbe-salt";
    check("javax.crypto.spec.PBEParameterSpec spec = new javax.crypto.spec.PBEParameterSpec(properties.getProperty(\"salt\").getBytes(), 10000);", sink, true);
    check("byte[] salt = new byte[16]; new java.security.SecureRandom().nextBytes(salt); javax.crypto.spec.PBEParameterSpec spec = new javax.crypto.spec.PBEParameterSpec(salt, 10000);", sink, false);
}

#[test]
fn request_data_is_tracked_into_redirects_and_unbounded_buffers() {
    check("response.sendRedirect(request.getParameter(\"password\"));", "uniflow.java.sink.password-redirect", true);
    check("response.sendRedirect(\"/home\");", "uniflow.java.sink.password-redirect", false);
    check("java.lang.StringBuilder text = new java.lang.StringBuilder(); text.append(request.getParameter(\"data\"));", "uniflow.java.sink.string-builder-dos", true);
    check("java.lang.StringBuilder text = new java.lang.StringBuilder(); text.append(\"fixed\");", "uniflow.java.sink.string-builder-dos", false);
}
