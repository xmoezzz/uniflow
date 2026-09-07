use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const WEB_SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const STREAM_SOURCE: &str = "legacy.java.source.c854699a-9933-4a2e-8ce7-ca4ee2df7531.0.";
const XML_DECODER: &str = "legacy.java.sink.b0e4cef3-b2fb-4257-a00c-246e5173d843.0";
const XSTREAM: &str = "legacy.java.sink.8632100d-b549-479a-a992-70cf4045b2bf.0";
const JNDI: &str = "legacy.java.sink.41ebde44-0880-4aab-8d83-0becd4c88625.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let ids = [XML_DECODER, XSTREAM, JNDI];
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|rule| ids.contains(&rule.id.as_str()))
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|rule| {
                    rule.id.starts_with(WEB_SOURCE) || rule.id.starts_with(STREAM_SOURCE)
                })
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
                    rule.rule_id.starts_with(WEB_SOURCE)
                        || rule.rule_id.starts_with(STREAM_SOURCE)
                        || ids.contains(&rule.rule_id.as_str())
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
            (4, 3, 3)
        );
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!(
        "class XmlAndJndi {{ void check(javax.servlet.http.HttpServletRequest request, javax.servlet.ServletRequest servletRequest, java.io.InputStream input, com.thoughtworks.xstream.XStream xstream, custom.XStream customXstream, org.springframework.ldap.core.LdapTemplate ldap, custom.LdapTemplate customLdap, org.springframework.ldap.core.ContextMapper mapper) throws Exception {{ {body} }} }}"
    );
    let graph = build(
        &lower_program(&parse_source(Language::Java, "XmlAndJndi.java", &source).unwrap()),
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
fn original_xml_decoder_rule_checks_constructor_input() {
    check(
        "new java.beans.XMLDecoder(servletRequest.getInputStream());",
        XML_DECODER,
        true,
    );
    check("new java.beans.XMLDecoder(input);", XML_DECODER, false);
    check(
        "new custom.XMLDecoder(servletRequest.getInputStream());",
        XML_DECODER,
        false,
    );
}

#[test]
fn original_xstream_rule_checks_deserialized_xml() {
    check("xstream.fromXML(request.getQueryString());", XSTREAM, true);
    check("xstream.fromXML(\"<safe/>\");", XSTREAM, false);
    check(
        "customXstream.fromXML(request.getQueryString());",
        XSTREAM,
        false,
    );
}

#[test]
fn original_spring_ldap_jndi_rule_keeps_argument_type_contract() {
    check("ldap.lookup(request.getQueryString(), mapper);", JNDI, true);
    check("ldap.lookup(\"cn=safe\", mapper);", JNDI, false);
    check(
        "customLdap.lookup(request.getQueryString(), mapper);",
        JNDI,
        false,
    );
}
