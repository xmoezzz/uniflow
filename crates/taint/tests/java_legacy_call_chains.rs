use std::sync::OnceLock;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const SOURCE: &str = "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.web";
const COMMAND: &str = "legacy.java.sink.d4d80a8b-8a57-4fe8-a313-428d14eecc8d.0";
const XSS: &str = "legacy.java.sink.88fbda79-ef5d-42d5-8732-84a3f9b4df84.0";
const SQL: &str = "legacy.java.sink.bc4f4fcb-12de-41ab-81d6-6d9915c0e93e.0";

fn rules() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let legacy = legacy_models_for(Language::Java).unwrap();
        let ids = [COMMAND, XSS, SQL];
        let rules = RuleSet {
            sources: legacy.sources.into_iter().filter(|r| r.id.starts_with("legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.")).collect(),
            sinks: legacy.sinks.into_iter().filter(|r| ids.contains(&r.id.as_str())).collect(),
            sink_conditions: legacy.sink_conditions.into_iter().filter(|r| ids.contains(&r.sink_rule_id.as_str())).collect(),
            call_conditions: legacy.call_conditions.into_iter().filter(|r| r.rule_id == SOURCE || ids.contains(&r.rule_id.as_str())).collect(),
            ..Default::default()
        };
        assert_eq!(rules.sources.len(), 2);
        assert_eq!(rules.sinks.len(), 3);
        assert_eq!(rules.sink_conditions.len(), 3);
        rules.validate().unwrap(); rules
    })
}

fn check(body: &str, sink: &str, expected: usize) {
    let source = format!("package demo; class Chains {{ void f(javax.servlet.http.HttpServletRequest request, javax.servlet.http.HttpServletResponse response, javax.sql.DataSource data) {{ {body} }} }}");
    let hir = parse_source(Language::Java, "Chains.java", &source).unwrap();
    let ir = lower_program(&hir);
    let graph = build(&ir, rules());
    let findings = analyze(&graph, rules());
    let sites = findings.iter().filter(|f| f.sink_rule_id == sink).map(|f| &f.sink_location).collect::<std::collections::HashSet<_>>();
    assert_eq!(sites.len(), expected, "{body}\nfindings={findings:#?}\ncalls={:#?}", graph.call_meta);
    assert!(findings.iter().all(|f| f.source_rule_id == SOURCE || f.source_rule_id == SOURCE.replace(".web", ".xss")));
}

#[test]
fn bundled_java_command_rule_executes_runtime_factory_chain() {
    check("java.lang.Runtime.getRuntime().exec(request.getQueryString());", COMMAND, 1);
    check("java.lang.Runtime.getRuntime().exec(\"safe\");", COMMAND, 0);
}

#[test]
fn bundled_java_xss_rule_executes_servlet_writer_chain() {
    check("response.getWriter().println(request.getQueryString());", XSS, 1);
    check("response.getWriter().println(\"safe\");", XSS, 0);
}

#[test]
fn bundled_java_sql_rule_executes_connection_statement_chain() {
    check("data.getConnection().createStatement().executeQuery(request.getQueryString());", SQL, 1);
    check("data.getConnection().createStatement().executeQuery(\"SELECT 1\");", SQL, 0);
}
