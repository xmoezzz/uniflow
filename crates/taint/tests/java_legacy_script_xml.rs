//! Execute original models, including their label predicates and metadata.
use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.";
const SCRIPT: &str = "legacy.java.sink.3ccfd229-9573-47ef-8cb3-282fa5b90050.0";
const XPATH: &str = "legacy.java.sink.bd0676d8-9535-412b-9c73-7086b7c4fc7a.0";
const XML: &str = "legacy.java.sink.bc04233f-8917-441c-9f17-1432e3f70567.0";
const XML_GENERAL_OFF: &str = "legacy.java.cleanse_transform.f2a7056e-b595-4b3e-8b79-7e31a3905085";
const XML_PARAMETER_OFF: &str =
    "legacy.java.cleanse_transform.b6a00768-e0c6-46a6-8250-b30c6ace487a";
const XML_FACTORY_NEW: &str = "legacy.java.passthrough.2368c0d2-e534-4cab-ab04-8f708fb63f35";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let ids = [SCRIPT, XPATH, XML];
        let rules = RuleSet {
            metadata: legacy
                .metadata
                .into_iter()
                .filter(|r| ids.contains(&r.id.as_str()))
                .collect(),
            sources: legacy
                .sources
                .into_iter()
                .filter(|r| r.id.starts_with(SOURCE))
                .collect(),
            sinks: legacy
                .sinks
                .into_iter()
                .filter(|r| ids.contains(&r.id.as_str()))
                .collect(),
            taint_transforms: legacy
                .taint_transforms
                .into_iter()
                .filter(|r| matches!(r.id.as_str(), XML_GENERAL_OFF | XML_PARAMETER_OFF))
                .collect(),
            propagators: legacy
                .propagators
                .into_iter()
                .filter(|r| r.id == XML_FACTORY_NEW)
                .collect(),
            sink_conditions: legacy
                .sink_conditions
                .into_iter()
                .filter(|r| ids.contains(&r.sink_rule_id.as_str()))
                .collect(),
            call_conditions: legacy
                .call_conditions
                .into_iter()
                .filter(|r| {
                    r.rule_id.starts_with(SOURCE)
                        || ids.contains(&r.rule_id.as_str())
                        || matches!(r.rule_id.as_str(), XML_GENERAL_OFF | XML_PARAMETER_OFF)
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(rules.sources.len(), 2);
        assert_eq!(rules.sinks.len(), 3);
        assert_eq!(rules.sink_conditions.len(), 3);
        assert_eq!(rules.taint_transforms.len(), 2);
        assert_eq!(rules.propagators.len(), 1);
        rules.validate().unwrap();
        rules
    })
}

fn check(body: &str, sink: &str, expected: bool) {
    let source = format!("class LegacyXml {{ void check(javax.servlet.http.HttpServletRequest request, javax.script.ScriptEngineManager engines, custom.ScriptEngineManager customEngines) throws Exception {{ {body} }} }}");
    let hir = parse_source(Language::Java, "LegacyXml.java", &source).unwrap();
    let graph = build(&lower_program(&hir), rules());
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
fn original_script_rule_executes_engine_manager_factories() {
    for factory in [
        "getEngineByName",
        "getEngineByExtension",
        "getEngineByMimeType",
    ] {
        check(
            &format!("engines.{factory}(\"js\").eval(request.getQueryString());"),
            SCRIPT,
            true,
        );
        check(
            &format!("engines.{factory}(\"js\").eval(\"1 + 1\");"),
            SCRIPT,
            false,
        );
    }
    check(
        "customEngines.getEngineByName(\"js\").eval(request.getQueryString());",
        SCRIPT,
        false,
    );
}

#[test]
fn original_xpath_rule_executes_factory_and_local_alias() {
    check(
        "javax.xml.xpath.XPathFactory.newInstance().newXPath().compile(request.getQueryString());",
        XPATH,
        true,
    );
    check(
        "javax.xml.xpath.XPathFactory.newInstance().newXPath().compile(\"/root/item\");",
        XPATH,
        false,
    );
    check("javax.xml.xpath.XPath path = javax.xml.xpath.XPathFactory.newDefaultInstance().newXPath(); path.evaluate(request.getQueryString(), new Object());", XPATH, true);
    check("javax.xml.xpath.XPath path = javax.xml.xpath.XPathFactory.newDefaultInstance().newXPath(); path.evaluate(\"/root/item\", new Object());", XPATH, false);
}

#[test]
fn original_xml_rule_executes_document_builder_factory() {
    check("javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getQueryString());", XML, true);
    check("javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(\"config.xml\");", XML, false);
    check("javax.xml.parsers.DocumentBuilder builder = javax.xml.parsers.DocumentBuilderFactory.newDefaultInstance().newDocumentBuilder(); builder.parse(request.getQueryString());", XML, true);
    check("custom.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getQueryString());", XML, false);
}

#[test]
fn original_xml_feature_transforms_follow_receiver_state_and_order() {
    check(
        "javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance(); factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false); factory.newDocumentBuilder().parse(request.getQueryString());",
        XML,
        false,
    );
    check(
        "javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance(); factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); factory.newDocumentBuilder().parse(request.getQueryString());",
        XML,
        true,
    );
    check(
        "javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance(); factory.newDocumentBuilder().parse(request.getQueryString()); factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);",
        XML,
        true,
    );
    check(
        "javax.xml.parsers.DocumentBuilderFactory hardened = javax.xml.parsers.DocumentBuilderFactory.newInstance(); hardened.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); hardened.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false); javax.xml.parsers.DocumentBuilderFactory unsafe = javax.xml.parsers.DocumentBuilderFactory.newInstance(); unsafe.newDocumentBuilder().parse(request.getQueryString());",
        XML,
        true,
    );
}
