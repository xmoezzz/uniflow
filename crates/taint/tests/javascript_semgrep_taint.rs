use std::collections::HashSet;
use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const FUNCTION_ARGUMENT_SOURCE: &str = "LEGACY-JS-SEMGREP-TAINT-SOURCE-function-argument";
const REQUIRE_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-require";
const REGEXP_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-regexp";
const MD5_SOURCE: &str = "LEGACY-JS-SEMGREP-TAINT-SOURCE-md5-password";
const MD5_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-md5-used-as-password";
const OBJECT_ASSIGN_SOURCE: &str =
    "LEGACY-JS-SEMGREP-TAINT-SOURCE-insecure-object-assign";
const OBJECT_ASSIGN_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-insecure-object-assign";
const CHILD_PROCESS_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-detect-child-process";
const TO_FAST_PROPERTIES_SINK: &str =
    "LEGACY-JS-SEMGREP-TAINT-tofastproperties-code-execution";
const MYSQL_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-node-mysql-sqli";
const MSSQL_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-node-mssql-sqli";
const POSTGRES_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-node-postgres-sqli";
const AWS_CHILD_PROCESS_SINK: &str =
    "LEGACY-JS-SEMGREP-TAINT-aws-detect-child-process";
const AWS_EVAL_SINK: &str = "LEGACY-JS-SEMGREP-TAINT-aws-tainted-eval";

fn focused_rules() -> RuleSet {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| matches!(rule.id.as_str(), REQUIRE_SINK | REGEXP_SINK))
            .collect(),
        function_sources: legacy
            .function_sources
            .into_iter()
            .filter(|rule| rule.id == FUNCTION_ARGUMENT_SOURCE)
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| matches!(rule.id.as_str(), REQUIRE_SINK | REGEXP_SINK))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.sinks.len(), 2);
    assert_eq!(rules.metadata.len(), 2);
    rules.validate().unwrap();
    rules
}

fn findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let rules = focused_rules();
    let hir = parse_source(Language::JavaScript, "semgrep-taint.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn md5_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| rule.id == MD5_SINK)
            .collect(),
        sources: legacy
            .sources
            .into_iter()
            .filter(|rule| rule.id == MD5_SOURCE)
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| rule.id == MD5_SINK)
            .collect(),
        propagators: legacy
            .propagators
            .into_iter()
            .filter(|rule| rule.id.starts_with("LEGACY-JS-SEMGREP-TAINT-PROP-md5-"))
            .collect(),
        call_conditions: legacy
            .call_conditions
            .into_iter()
            .filter(|rule| rule.rule_id == MD5_SOURCE)
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    assert_eq!(rules.propagators.len(), 2);
    assert_eq!(rules.call_conditions.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "md5-password.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn object_assign_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| rule.id == OBJECT_ASSIGN_SINK)
            .collect(),
        sources: legacy
            .sources
            .into_iter()
            .filter(|rule| rule.id == OBJECT_ASSIGN_SOURCE)
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| rule.id == OBJECT_ASSIGN_SINK)
            .collect(),
        call_conditions: legacy
            .call_conditions
            .into_iter()
            .filter(|rule| rule.rule_id == OBJECT_ASSIGN_SOURCE)
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    assert_eq!(rules.call_conditions.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "object-assign.js", source).unwrap();
    let ir = lower_program(&hir);
    let flow = build(&ir, &rules);
    assert!(flow.call_meta.values().any(|meta| {
        meta.callee_name.as_deref() == Some("JSON.parse")
            && meta.receiver_constant.is_none()
    }));
    assert!(flow
        .call_meta
        .values()
        .any(|meta| meta.callee_name.as_deref() == Some("Object.assign")));
    analyze(&flow, &rules)
}

fn module_sink_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let selected = [CHILD_PROCESS_SINK, TO_FAST_PROPERTIES_SINK];
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        function_sources: legacy
            .function_sources
            .into_iter()
            .filter(|rule| rule.id == FUNCTION_ARGUMENT_SOURCE)
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        call_conditions: legacy
            .call_conditions
            .into_iter()
            .filter(|rule| selected.contains(&rule.rule_id.as_str()))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 2);
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.sinks.len(), 2);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "module-sinks.js", source).unwrap();
    let ir = lower_program(&hir);
    let flow = build(&ir, &rules);
    let callees = flow
        .call_meta
        .values()
        .filter_map(|meta| meta.callee_name.as_deref())
        .collect::<HashSet<_>>();
    assert!(callees.iter().any(|callee| callee.starts_with("child_process.")), "{callees:?}");
    assert!(callees.contains("bluebird.toFastProperties"), "{callees:?}");
    analyze(&flow, &rules)
}

fn database_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let selected = [MYSQL_SINK, MSSQL_SINK, POSTGRES_SINK];
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        function_sources: legacy
            .function_sources
            .into_iter()
            .filter(|rule| rule.id.contains("node-mysql-function-argument")
                || rule.id.contains("node-mssql-function-argument")
                || rule.id.contains("node-postgres-function-argument"))
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        sanitizers: legacy
            .sanitizers
            .into_iter()
            .filter(|rule| rule.id == "LEGACY-JS-SEMGREP-TAINT-SANITIZER-node-mysql-parse-int")
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 3);
    assert_eq!(rules.function_sources.len(), 3);
    assert_eq!(rules.sinks.len(), 3);
    assert_eq!(rules.sanitizers.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "database-sinks.js", source).unwrap();
    let ir = lower_program(&hir);
    let flow = build(&ir, &rules);
    let callees = flow
        .call_meta
        .values()
        .filter_map(|meta| meta.callee_name.as_deref())
        .collect::<HashSet<_>>();
    for prefix in ["mysql2.", "mssql.", "pg."] {
        assert!(callees.iter().any(|callee| callee.starts_with(prefix) && callee.ends_with(".query")), "missing {prefix} query: {callees:?}");
    }
    analyze(&flow, &rules)
}

fn aws_lambda_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let selected = [
        AWS_CHILD_PROCESS_SINK,
        AWS_EVAL_SINK,
        "LEGACY-JS-SEMGREP-TAINT-aws-dynamodb-request-object",
        "LEGACY-JS-SEMGREP-TAINT-aws-knex-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-mysql-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-pg-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-sequelize-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-vm-runincontext-injection",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-response",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-string",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-sql-string",
    ];
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        function_sources: legacy
            .function_sources
            .into_iter()
            .filter(|rule| rule.id == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event")
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        call_conditions: legacy
            .call_conditions
            .into_iter()
            .filter(|rule| selected.contains(&rule.rule_id.as_str()))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 11);
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.sinks.len(), 11);
    assert_eq!(rules.call_conditions.len(), 3);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "lambda-handler.js", source).unwrap();
    let ir = lower_program(&hir);
    assert!(ir.find_function_by_name("exports.handler").is_some());
    let flow = build(&ir, &rules);
    analyze(&flow, &rules)
}

fn browser_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let selected = [
        "LEGACY-JS-SEMGREP-TAINT-js-open-redirect-from-function",
        "LEGACY-JS-SEMGREP-TAINT-js-open-redirect",
        "LEGACY-JS-SEMGREP-TAINT-detect-eval-with-expression",
        "LEGACY-JS-SEMGREP-TAINT-raw-html-concat",
    ];
    let rules = RuleSet {
        metadata: legacy
            .metadata
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        function_sources: legacy
            .function_sources
            .into_iter()
            .filter(|rule| rule.id.ends_with("SOURCE-browser-function-argument"))
            .collect(),
        field_sources: legacy
            .field_sources
            .into_iter()
            .filter(|rule| rule.id.contains("SOURCE-browser-location-"))
            .collect(),
        sinks: legacy
            .sinks
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        field_sinks: legacy
            .field_sinks
            .into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str()))
            .collect(),
        sanitizers: legacy
            .sanitizers
            .into_iter()
            .filter(|rule| rule.id.ends_with("SANITIZER-browser-html"))
            .collect(),
        call_conditions: legacy
            .call_conditions
            .into_iter()
            .filter(|rule| selected.contains(&rule.rule_id.as_str()))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 4);
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.field_sources.len(), 3);
    assert_eq!(rules.sinks.len(), 4);
    assert_eq!(rules.field_sinks.len(), 2);
    assert_eq!(rules.sanitizers.len(), 1);
    assert_eq!(rules.call_conditions.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "browser-input.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn angular_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let selected = [
        "LEGACY-JS-SEMGREP-TAINT-detect-angular-element-methods",
        "LEGACY-JS-SEMGREP-TAINT-detect-angular-element-taint",
        "LEGACY-JS-SEMGREP-TAINT-detect-angular-trust-as-method",
    ];
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str())).collect(),
        sources: legacy.sources.into_iter()
            .filter(|rule| rule.id.contains("SOURCE-angular-")).collect(),
        field_sources: legacy.field_sources.into_iter()
            .filter(|rule| rule.id.contains("SOURCE-angular-")).collect(),
        sinks: legacy.sinks.into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str())).collect(),
        sanitizers: legacy.sanitizers.into_iter()
            .filter(|rule| rule.id.contains("SANITIZER-angular-")).collect(),
        call_conditions: legacy.call_conditions.into_iter()
            .filter(|rule| rule.rule_id.contains("SOURCE-angular-")).collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 3);
    assert_eq!(rules.sources.len(), 2);
    assert_eq!(rules.field_sources.len(), 3);
    assert_eq!(rules.sinks.len(), 3);
    assert_eq!(rules.sanitizers.len(), 2);
    assert_eq!(rules.call_conditions.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "angular-controller.js", source).unwrap();
    let ir = lower_program(&hir);
    assert!(ir.functions.iter().any(|function| function.attrs
        .get("param_names").is_some_and(|names| names.contains("$scope"))),
        "lowered AngularJS scope identity is missing: {ir:#?}");
    analyze(&build(&ir, &rules), &rules)
}

fn hardcoded_jwt_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-hardcoded-jwt-secret";
    let source_id = "LEGACY-JS-SEMGREP-TAINT-SOURCE-hardcoded-jwt-secret";
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter().filter(|rule| rule.id == sink_id).collect(),
        sources: legacy.sources.into_iter().filter(|rule| rule.id == source_id).collect(),
        sinks: legacy.sinks.into_iter().filter(|rule| rule.id == sink_id).collect(),
        call_conditions: legacy.call_conditions.into_iter()
            .filter(|rule| rule.rule_id == source_id).collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    assert_eq!(rules.call_conditions.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "jwt-secret.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn web_request_eval_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-code-string-concat";
    let source_id = "LEGACY-JS-SEMGREP-TAINT-SOURCE-web-request-first-argument";
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter().filter(|rule| rule.id == sink_id).collect(),
        function_sources: legacy.function_sources.into_iter()
            .filter(|rule| rule.id == source_id).collect(),
        sinks: legacy.sinks.into_iter().filter(|rule| rule.id == sink_id).collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "web-eval.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn knex_and_path_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let selected = [
        "LEGACY-JS-SEMGREP-TAINT-node-knex-sqli",
        "LEGACY-JS-SEMGREP-TAINT-path-join-resolve-traversal",
    ];
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str())).collect(),
        function_sources: legacy.function_sources.into_iter()
            .filter(|rule| rule.id.contains("SOURCE-node-knex-")
                || rule.id.contains("SOURCE-path-function-argument"))
            .collect(),
        sinks: legacy.sinks.into_iter()
            .filter(|rule| selected.contains(&rule.id.as_str())).collect(),
        sanitizers: legacy.sanitizers.into_iter()
            .filter(|rule| rule.id.contains("SANITIZER-node-knex-")
                || rule.id.contains("SANITIZER-path-validation"))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 2);
    assert_eq!(rules.function_sources.len(), 2);
    assert_eq!(rules.sinks.len(), 2);
    assert_eq!(rules.sanitizers.len(), 2);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "knex-path.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn unsafe_format_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-unsafe-formatstring";
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter().filter(|rule| rule.id == sink_id).collect(),
        sources: legacy.sources.into_iter()
            .filter(|rule| rule.id.contains("SOURCE-unsafe-formatstring-"))
            .collect(),
        sinks: legacy.sinks.into_iter().filter(|rule| rule.id == sink_id).collect(),
        call_conditions: legacy.call_conditions.into_iter()
            .filter(|rule| rule.rule_id.contains("SOURCE-unsafe-formatstring-"))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.sources.len(), 2);
    assert_eq!(rules.sinks.len(), 1);
    assert_eq!(rules.call_conditions.len(), 2);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "unsafe-format.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn dangerous_spawn_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-dangerous-spawn-shell";
    let source_id = "LEGACY-JS-SEMGREP-TAINT-SOURCE-dangerous-spawn-shell-argument";
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter().filter(|rule| rule.id == sink_id).collect(),
        function_sources: legacy.function_sources.into_iter()
            .filter(|rule| rule.id == source_id).collect(),
        sinks: legacy.sinks.into_iter().filter(|rule| rule.id == sink_id).collect(),
        call_conditions: legacy.call_conditions.into_iter()
            .filter(|rule| rule.rule_id == sink_id).collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    assert_eq!(rules.call_conditions.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "dangerous-spawn.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn deno_run_findings(source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-deno-dangerous-run";
    let source_id = "LEGACY-JS-SEMGREP-TAINT-SOURCE-deno-dangerous-run-argument";
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter().filter(|rule| rule.id == sink_id).collect(),
        function_sources: legacy.function_sources.into_iter()
            .filter(|rule| rule.id == source_id).collect(),
        sinks: legacy.sinks.into_iter().filter(|rule| rule.id == sink_id).collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.function_sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "deno-run.js", source).unwrap();
    let ir = lower_program(&hir);
    analyze(&build(&ir, &rules), &rules)
}

fn express_io_findings(
    source: &str,
    sink_id: &str,
    source_id: &str,
    sanitizer_id: Option<&str>,
) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let mut selected_sink_ids = legacy
        .sink_reports
        .iter()
        .filter(|alias| alias.report_rule_id == sink_id)
        .map(|alias| alias.sink_rule_id.clone())
        .collect::<HashSet<_>>();
    selected_sink_ids.insert(sink_id.to_string());
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter()
            .filter(|rule| rule.id == sink_id).collect(),
        function_sources: legacy.function_sources.into_iter()
            .filter(|rule| rule.id == source_id).collect(),
        sinks: legacy.sinks.into_iter()
            .filter(|rule| selected_sink_ids.contains(rule.id.as_str())).collect(),
        sink_reports: legacy.sink_reports.into_iter()
            .filter(|alias| alias.report_rule_id == sink_id).collect(),
        sanitizers: legacy.sanitizers.into_iter()
            .filter(|rule| sanitizer_id == Some(rule.id.as_str())).collect(),
        call_conditions: legacy.call_conditions.into_iter()
            .filter(|rule| selected_sink_ids.contains(rule.rule_id.as_str())).collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.function_sources.len(), 1);
    assert!(!rules.sinks.is_empty());
    assert_eq!(rules.sanitizers.len(), usize::from(sanitizer_id.is_some()));
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "express-io.js", source).unwrap();
    let ir = lower_program(&hir);
    let flow = build(&ir, &rules);
    analyze(&flow, &rules)
}

fn configured_map_findings(
    source: &str,
    sink_id: &str,
    source_id: &str,
    sanitizer_id: Option<&str>,
) -> Vec<uniflow_taint::TaintFinding> {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter()
            .filter(|rule| rule.id == sink_id).collect(),
        sources: legacy.sources.into_iter()
            .filter(|rule| rule.id == source_id).collect(),
        sinks: legacy.sinks.into_iter()
            .filter(|rule| rule.id == sink_id).collect(),
        sanitizers: legacy.sanitizers.into_iter()
            .filter(|rule| sanitizer_id == Some(rule.id.as_str())).collect(),
        call_conditions: legacy.call_conditions.into_iter()
            .filter(|rule| rule.rule_id == source_id
                || sanitizer_id == Some(rule.rule_id.as_str()))
            .collect(),
        ..Default::default()
    };
    assert_eq!(rules.metadata.len(), 1);
    assert_eq!(rules.sources.len(), 1);
    assert_eq!(rules.sinks.len(), 1);
    assert_eq!(rules.sanitizers.len(), usize::from(sanitizer_id.is_some()));
    rules.validate().unwrap();
    let hir = parse_source(Language::JavaScript, "configured-map.js", source).unwrap();
    let ir = lower_program(&hir);
    let flow = build(&ir, &rules);
    analyze(&flow, &rules)
}

#[test]
fn function_arguments_flow_to_dynamic_require_and_regexp_sinks() {
    let actual = findings(
        r#"
function load(moduleName) {
    const selected = moduleName;
    return require(selected);
}
function compile(pattern) {
    const copied = pattern;
    const first = RegExp(copied);
    const second = new RegExp(pattern, "u");
    return [first, second];
}
function safe() {
    require("./fixed.js");
    RegExp("^[a-z]+$");
    new RegExp(/fixed/);
}
"#,
    );
    let sink_ids = actual
        .iter()
        .map(|finding| finding.sink_rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(sink_ids.iter().filter(|id| **id == REQUIRE_SINK).count(), 1, "{actual:#?}");
    assert_eq!(sink_ids.iter().filter(|id| **id == REGEXP_SINK).count(), 2, "{actual:#?}");
    let pairs = actual
        .iter()
        .map(|finding| (finding.source_rule_id.as_str(), finding.sink_rule_id.as_str()))
        .collect::<HashSet<_>>();
    assert!(pairs.contains(&(FUNCTION_ARGUMENT_SOURCE, REQUIRE_SINK)));
    assert!(pairs.contains(&(FUNCTION_ARGUMENT_SOURCE, REGEXP_SINK)));
}

#[test]
fn constants_and_non_parameter_values_do_not_trigger_parameter_taint_rules() {
    let actual = findings(
        r#"
function safe() {
    const moduleName = "./fixed.js";
    const pattern = "^[a-z]+$";
    require(moduleName);
    RegExp(pattern);
}
"#,
    );
    assert!(actual.is_empty(), "{actual:#?}");
}

#[test]
fn md5_digest_flows_through_crypto_chain_to_password_calls_only() {
    let actual = md5_findings(
        r#"
const crypto = require("crypto");
function updateUsers(first, second, input) {
    const direct = crypto.createHash("md5");
    first.setPassword(direct);
    const digest = crypto.createHash("md5").update(input).digest("hex");
    second.updatePASSWORDHash(digest);

    const safe = crypto.createHash("sha256").update(input).digest("hex");
    second.setPassword(safe);
    consume(digest);
}
"#,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
    assert!(actual.iter().all(|finding| {
        finding.source_rule_id == MD5_SOURCE && finding.sink_rule_id == MD5_SINK
    }));
}

#[test]
fn nonconstant_json_parse_flows_to_object_assign() {
    let actual = object_assign_findings(
        r#"
function update(systemData, untrustedInput) {
    const direct = Object.assign(systemData, JSON.parse(untrustedInput));
    const parsed = JSON.parse(untrustedInput);
    const copied = parsed;
    Object.assign(systemData, copied);

    Object.assign(systemData, JSON.parse('{"one": 1}'));
    const fixed = '{"two": 2}';
    Object.assign(systemData, JSON.parse(fixed));
    return direct;
}
"#,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
    assert!(actual.iter().all(|finding| {
        finding.source_rule_id == OBJECT_ASSIGN_SOURCE
            && finding.sink_rule_id == OBJECT_ASSIGN_SINK
    }));
}

#[test]
fn commonjs_module_provenance_limits_child_process_and_bluebird_sinks() {
    let actual = module_sink_findings(
        r#"
function execute(command, object) {
    const child = require("child_process");
    child.exec(command);
    child.exec("fixed-command");

    const bluebird = require("bluebird");
    bluebird.toFastProperties(object);
    bluebird.toFastProperties({safe: true});

    const unrelated = require("unrelated");
    unrelated.exec(command);
    unrelated.toFastProperties(object);
}
"#,
    );
    let sink_ids = actual
        .iter()
        .map(|finding| finding.sink_rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(sink_ids.iter().filter(|id| **id == CHILD_PROCESS_SINK).count(), 1, "{actual:#?}");
    assert_eq!(sink_ids.iter().filter(|id| **id == TO_FAST_PROPERTIES_SINK).count(), 1, "{actual:#?}");
    assert!(actual.iter().all(|finding| finding.source_rule_id == FUNCTION_ARGUMENT_SOURCE));
}

#[test]
fn es_module_aliases_preserve_package_scoped_taint_sinks() {
    let actual = module_sink_findings(
        r#"
import * as child from "child_process";
import bluebird from "bluebird";
import * as unrelated from "unrelated";
function execute(command, object) {
    child.spawn(command);
    bluebird.toFastProperties(object);
    unrelated.spawn(command);
    unrelated.toFastProperties(object);
}
"#,
    );
    let sink_ids = actual
        .iter()
        .map(|finding| finding.sink_rule_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(sink_ids.iter().filter(|id| **id == CHILD_PROCESS_SINK).count(), 1, "{actual:#?}");
    assert_eq!(sink_ids.iter().filter(|id| **id == TO_FAST_PROPERTIES_SINK).count(), 1, "{actual:#?}");
}

#[test]
fn database_client_provenance_scopes_mysql_mssql_and_postgres_taint() {
    let actual = database_findings(
        r#"
function mysqlQuery(sql) {
    const mysql = require("mysql2");
    const connection = mysql.createConnection();
    connection.query(sql);
    connection.query(parseInt(sql));
}
function mssqlQuery(sql) {
    const mssql = require("mssql");
    const pool = new mssql.ConnectionPool();
    const request = pool.request();
    request.query(sql);
}
function postgresQuery(sql) {
    const pg = require("pg");
    const client = new pg.Client();
    client.query(sql);
}
function unrelatedQuery(sql) {
    const client = require("unrelated").createClient();
    client.query(sql);
}
"#,
    );
    for (sink, source_fragment) in [
        (MYSQL_SINK, "node-mysql-function-argument"),
        (MSSQL_SINK, "node-mssql-function-argument"),
        (POSTGRES_SINK, "node-postgres-function-argument"),
    ] {
        let matching = actual
            .iter()
            .filter(|finding| finding.sink_rule_id == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "missing or duplicated {sink}: {actual:#?}");
        assert!(matching.iter().all(|finding| finding.source_rule_id.contains(source_fragment)));
    }
}

#[test]
fn aws_lambda_handler_identity_limits_event_taint() {
    let actual = aws_lambda_findings(
        r#"
exports.handler = function(event) {
    const child = require("child_process");
    child.exec(event);
    child.exec("fixed-command");
    eval(event);
    eval("fixed-expression");
};
function helper(input) {
    const child = require("child_process");
    child.exec(input);
    eval(input);
}
"#,
    );
    for sink in [AWS_CHILD_PROCESS_SINK, AWS_EVAL_SINK] {
        let matching = actual
            .iter()
            .filter(|finding| finding.sink_rule_id == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "missing or duplicated {sink}: {actual:#?}");
        assert!(matching.iter().all(|finding| {
            finding.source_rule_id
                == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event"
        }));
    }
}

#[test]
fn aws_lambda_service_rules_preserve_package_provenance() {
    let actual = aws_lambda_findings(
        r#"
exports.handler = function(event) {
    const AWS = require("aws-sdk");
    const documentClient = new AWS.DynamoDB.DocumentClient();
    documentClient.query(event);

    const knex = require("knex");
    knex.raw(event);

    const mysql = require("mysql2");
    const mysqlDb = mysql.createPool();
    mysqlDb.query(event);

    const pg = require("pg");
    const pgDb = new pg.Client();
    pgDb.query(event);

    const sequelize = require("sequelize");
    sequelize.query(event);

    const vm = require("vm");
    vm.runInThisContext(event);

    const unrelated = require("unrelated");
    unrelated.query(event);
    unrelated.raw(event);
    unrelated.runInThisContext(event);
};
"#,
    );
    for sink in [
        "LEGACY-JS-SEMGREP-TAINT-aws-dynamodb-request-object",
        "LEGACY-JS-SEMGREP-TAINT-aws-knex-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-mysql-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-pg-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-sequelize-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-vm-runincontext-injection",
    ] {
        let matching = actual
            .iter()
            .filter(|finding| finding.sink_rule_id == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "missing or duplicated {sink}: {actual:#?}");
        assert!(matching.iter().all(|finding| {
            finding.source_rule_id
                == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event"
        }));
    }
}

#[test]
fn aws_lambda_expression_rules_use_composition_semantics() {
    let actual = aws_lambda_findings(
        r#"
exports.handler = function(event) {
    const response = {
        headers: { "Content-Type": "text/html" },
        body: event
    };
    const html = "<div>" + event;
    const sql = "SELECT * FROM users WHERE id = " + event;
    const ordinary = "hello " + event;
    const json = { body: event };
    return [response, html, sql, ordinary, json];
};
"#,
    );
    for sink in [
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-response",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-string",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-sql-string",
    ] {
        let matching = actual
            .iter()
            .filter(|finding| finding.sink_rule_id == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "missing or duplicated {sink}: {actual:#?}");
        assert!(matching.iter().all(|finding| {
            finding.source_rule_id
                == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event"
        }));
    }
}

#[test]
fn browser_location_sources_drive_redirect_eval_and_html_rules() {
    let actual = browser_findings(
        r#"
function redirect(target) {
    location.href = target;
    window.location.replace(target);
}
function browserData() {
    const query = location.search;
    eval(query);
    const html = "<section>" + query;
    window.location.href = query;
    const safe = DOMPurify.sanitize(query);
    const sanitizedHtml = "<main>" + safe;
    const ordinary = "plain " + query;
    return [html, sanitizedHtml, ordinary];
}
"#,
    );
    for (sink, expected) in [
        ("LEGACY-JS-SEMGREP-TAINT-js-open-redirect-from-function", 2),
        ("LEGACY-JS-SEMGREP-TAINT-js-open-redirect", 1),
        ("LEGACY-JS-SEMGREP-TAINT-detect-eval-with-expression", 1),
        ("LEGACY-JS-SEMGREP-TAINT-raw-html-concat", 1),
    ] {
        let matching = actual
            .iter()
            .filter(|finding| finding.sink_rule_id == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), expected, "wrong count for {sink}: {actual:#?}");
    }
}

#[test]
fn angular_scope_and_browser_sources_reach_only_matching_angular_sinks() {
    let actual = angular_findings(
        r##"
function controller($scope, $sce, $sanitize, $injector) {
    const view = angular.element("#output");
    view.append($scope.html);
    view.html($sanitize($scope.safe));
    $sce.trustAsHtml($scope.html);
    const injected = $injector.get('$scope');
    view.after(injected.message);
    const unrelated = $injector.get('service');
    view.prepend(unrelated.message);
}
function browserData() {
    const view = angular.element("#browser");
    view.wrap(location.search);
    view.prepend(DOMPurify.sanitize(location.search));
}
"##,
    );
    for (sink, expected) in [
        ("LEGACY-JS-SEMGREP-TAINT-detect-angular-element-methods", 2),
        ("LEGACY-JS-SEMGREP-TAINT-detect-angular-element-taint", 1),
        ("LEGACY-JS-SEMGREP-TAINT-detect-angular-trust-as-method", 1),
    ] {
        let matching = actual.iter()
            .filter(|finding| finding.sink_rule_id == sink).collect::<Vec<_>>();
        assert_eq!(matching.len(), expected, "wrong count for {sink}: {actual:#?}");
    }
}

#[test]
fn jsonwebtoken_hardcoded_secret_requires_constant_and_package_provenance() {
    let actual = hardcoded_jwt_findings(
        r#"
function tokens(data, configured) {
    const jwt = require("jsonwebtoken");
    const fixed = "development-secret";
    jwt.sign(data, fixed);
    jwt.verify(data, "inline-secret");
    jwt.sign(data, configured);
    const unrelated = require("unrelated");
    unrelated.sign(data, "not-a-jwt-secret");
}
"#,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
    assert!(actual.iter().all(|finding| {
        finding.source_rule_id == "LEGACY-JS-SEMGREP-TAINT-SOURCE-hardcoded-jwt-secret"
            && finding.sink_rule_id == "LEGACY-JS-SEMGREP-TAINT-hardcoded-jwt-secret"
    }));
}

#[test]
fn web_request_first_argument_reaches_eval_but_response_and_constants_do_not() {
    let actual = web_request_eval_findings(
        r#"
function handler(request, response) {
    const expression = "lookup(" + request.query + ")";
    eval(expression);
    eval(response.body);
    eval("fixedExpression()");
}
"#,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
    assert_eq!(
        actual[0].source_rule_id,
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-web-request-first-argument"
    );
    assert_eq!(actual[0].sink_rule_id, "LEGACY-JS-SEMGREP-TAINT-code-string-concat");
}

#[test]
fn knex_and_path_rules_preserve_package_provenance_and_sanitizers() {
    let actual = knex_and_path_findings(
        r#"
function query(request, response) {
    const knex = require("knex");
    knex.whereRaw(request.query);
    knex.raw(parseInt(request.query));
    const unrelated = require("unrelated");
    unrelated.raw(request.query);
}
function locate(prefix, name) {
    const path = require("path");
    path.resolve(prefix, name);
    path.join("/safe", name.replace("..", ""));
    const unrelated = require("unrelated");
    unrelated.resolve(name);
}
"#,
    );
    for (sink, expected) in [
        ("LEGACY-JS-SEMGREP-TAINT-node-knex-sqli", 1),
        ("LEGACY-JS-SEMGREP-TAINT-path-join-resolve-traversal", 2),
    ] {
        let matching = actual.iter()
            .filter(|finding| finding.sink_rule_id == sink).collect::<Vec<_>>();
        assert_eq!(matching.len(), expected, "wrong count for {sink}: {actual:#?}");
    }
}

#[test]
fn unsafe_formatstring_requires_dynamic_composition_and_a_substitution_argument() {
    let actual = unsafe_format_findings(
        r#"
const util = require("util");
function render(name, value) {
    console.log("user:" + name, value);
    console.warn(`value=${value}`, name);
    util.format("prefix".concat(name), value);
    console.log("fixed", value);
    console.log("a" + "b", value);
    util.format("fixed".concat("suffix"), value);
    unrelated.format("x" + name, value);
    console.log("missing argument: " + name);
}
"#,
    );
    assert_eq!(actual.len(), 3, "{actual:#?}");
    assert!(actual.iter().all(|finding| {
        finding.sink_rule_id == "LEGACY-JS-SEMGREP-TAINT-unsafe-formatstring"
            && finding.source_rule_id.starts_with(
                "LEGACY-JS-SEMGREP-TAINT-SOURCE-unsafe-formatstring-"
            )
    }));
}

#[test]
fn dangerous_spawn_shell_requires_shell_command_and_child_process_provenance() {
    let actual = dangerous_spawn_findings(
        r#"
const {spawn, spawnSync} = require("child_process");
const cp = require("child_process");
function execute(input) {
    const shell = "bash";
    spawnSync(shell, ["-c", input]);
    cp.spawn("sh", [input]);
    spawn("ls", [input]);
    cp.spawn("zsh", ["fixed"]);
    require("unrelated").spawn("sh", [input]);
}
"#,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
    assert!(actual.iter().all(|finding| {
        finding.source_rule_id
            == "LEGACY-JS-SEMGREP-TAINT-SOURCE-dangerous-spawn-shell-argument"
            && finding.sink_rule_id == "LEGACY-JS-SEMGREP-TAINT-dangerous-spawn-shell"
    }));
}

#[test]
fn deno_run_tracks_only_the_command_payload_of_the_options_map() {
    let actual = deno_run_findings(
        r#"
function execute(input) {
    Deno.run({cmd: [input, "hello"], stdout: "piped"});
    Deno.run({cmd: ["bash", "-c", input], stderr: "piped"});
    Deno.run({cmd: ["echo", "hello"], stdout: input});
    Deno.run({cmd: ["echo", "fixed"]});
    Other.run({cmd: [input]});
}
"#,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
    assert!(actual.iter().all(|finding| {
        finding.source_rule_id
            == "LEGACY-JS-SEMGREP-TAINT-SOURCE-deno-dangerous-run-argument"
            && finding.sink_rule_id == "LEGACY-JS-SEMGREP-TAINT-deno-dangerous-run"
    }));
}

#[test]
fn express_path_rule_preserves_request_role_package_and_sanitizer() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const path = require("path");
    path.join("/base", request.params.name);
    path.resolve("/base", request.query.safe.replace("..", ""));
    path.join("/base", response.body);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-path-join-resolve-traversal",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-path-request",
        Some("LEGACY-JS-SEMGREP-TAINT-SANITIZER-express-path-validation"),
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_sendfile_rule_requires_one_argument_and_request_data() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    response.sendFile(request.params.file);
    response.sendFile(request.params.file, {root: "/safe"});
    response.sendFile("fixed.txt");
    response.sendFile(response.body);
    request.sendFile(request.params.file);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-res-sendfile",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-sendfile-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_ssrf_rule_preserves_request_package_provenance() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const client = require("request");
    client.get(request.query.url);
    client.post("https://fixed.example");
    require("unrelated").get(request.query.url);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-ssrf",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-ssrf-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_open_redirect_requires_response_receiver_role() {
    let actual = express_io_findings(
        r#"
function handler(request, reply) {
    reply.redirect(request.query.next);
    const copiedReply = reply;
    copiedReply.redirect("https://example.test/" + request.params.path);
    request.redirect(request.query.next);
    other.redirect(request.query.next);
    reply.redirect("/fixed");
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-open-redirect",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-redirect-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn express_vm_rule_preserves_node_vm_package_provenance() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const vm = require("vm");
    vm.runInNewContext(request.body.code, {});
    vm.compileFunction(request.query.code);
    vm.runInThisContext("fixed");
    require("unrelated").runInNewContext(request.body.code, {});
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-vm-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-vm-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn express_wkhtml_rule_preserves_callable_package_alias() {
    let actual = express_io_findings(
        r#"
const renderPdf = require("wkhtmltopdf");
function handler(request, response) {
    renderPdf(request.query.url);
    renderPdf("https://fixed.example");
    wkhtmltopdfOther(request.query.url);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-wkhtmltopdf-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-wkhtml-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_require_rule_tracks_only_request_role() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    require(request.query.module);
    require(response.body);
    require("fixed-module");
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-require-request",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-require-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_render_rule_requires_response_receiver_role() {
    let actual = express_io_findings(
        r#"
function handler(request, reply) {
    reply.render(request.query.template, {});
    request.render(request.query.template);
    other.render(request.query.template);
    reply.render("fixed-template", request.body);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-res-render-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-render-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_sequelize_rule_preserves_package_provenance() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const sequelize = require("sequelize");
    sequelize.query(request.body.sql);
    sequelize.query("SELECT 1");
    require("unrelated").query(request.body.sql);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-sequelize-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-sequelize-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_xml2json_rule_preserves_parser_package_provenance() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const parser = require("xml2json");
    parser.toJson(request.body.xml);
    parser.toJson("<root/>");
    require("unrelated").toJson(request.body.xml);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-xml2json-xxe",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-xml2json-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_deserialization_rule_limits_unsafe_packages() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    require("node-serialize").unserialize(request.body.payload);
    require("serialize-to-js").deserialize(request.query.payload);
    require("node-serialize").unserialize("fixed");
    require("safe-serializer").deserialize(request.body.payload);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-third-party-object-deserialization",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-deserialization-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn express_template_rule_limits_supported_template_packages() {
    let actual = express_io_findings(
        r#"
const pug = require("pug");
const handlebars = require("handlebars");
function handler(request, response) {
    pug.compile(request.body.template);
    handlebars.compile(request.query.template);
    pug.compile("fixed template");
    require("unrelated").compile(request.body.template);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-insecure-template-usage",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-template-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn direct_response_write_requires_response_role_and_honors_html_sanitizer() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    response.write(request.query.html);
    response.send(require("dompurify").sanitize(request.body.html));
    request.send(request.query.html);
    response.send("fixed");
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-direct-response-write",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-response-write-request",
        Some("LEGACY-JS-SEMGREP-TAINT-SANITIZER-express-response-html"),
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_html_composition_requires_html_literal_context() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const html = "<section>" + request.query.title;
    const template = `<main>${request.body.content}</main>`;
    const ordinary = "user:" + request.params.name;
    return [html, template, ordinary];
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-raw-html-format",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-html-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn express_sql_composition_requires_sql_keyword_context() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const select = "SELECT * FROM users WHERE id=" + request.query.id;
    const update = `UPDATE users SET name=${request.body.name}`;
    const ordinary = "user:" + request.params.name;
    return [select, update, ordinary];
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-tainted-sql-string",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-sql-string-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn express_data_exfiltration_requires_request_data_at_object_assign() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    Object.assign({}, request.body.profile);
    Object.assign({}, response.body);
    Object.assign({}, { role: "user" });
    unrelated.assign({}, request.query.profile);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-data-exfiltration",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-data-exfiltration-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_phantom_rule_tracks_page_objects_from_the_phantom_package() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const instance = require("phantom").create();
    const page = instance.createPage();
    page.open(request.query.url);
    page.setContent("<main>fixed</main>");
    require("unrelated").open(request.query.url);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-phantom-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-phantom-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_puppeteer_rule_tracks_page_objects_from_the_puppeteer_package() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const browser = require("puppeteer").launch();
    const page = browser.newPage();
    page.goto(request.query.url);
    page.evaluate("fixed", request.body.payload);
    page.setContent("<main>fixed</main>");
    require("unrelated").goto(request.query.url);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-puppeteer-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-puppeteer-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn express_expat_rule_tracks_parser_instances_from_node_expat() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const parser = require("node-expat").Parser();
    parser.parse(request.body.xml);
    parser.write("<root/>");
    require("unrelated").Parser().parse(request.body.xml);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-expat-xxe",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-expat-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_vm2_rule_tracks_constructors_and_instances_from_vm2() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const vm = require("vm2").VM(request.body.options);
    vm.run(request.query.code);
    require("vm2").VMScript(request.params.code);
    require("unrelated").VM(request.body.options);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-vm2-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-vm2-request",
        None,
    );
    assert_eq!(actual.len(), 3, "{actual:#?}");
}

#[test]
fn express_sandbox_rule_tracks_instances_from_sandbox_package() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const sandbox = require("sandbox").Sandbox(request.body.options);
    sandbox.run(request.query.code);
    sandbox.run("fixed");
    require("unrelated").Sandbox().run(request.params.code);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-sandbox-code-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-sandbox-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn unsafe_argon2_config_rejects_non_id_variant_and_accepts_argon2id() {
    let actual = configured_map_findings(
        r#"
const argon = require("argon2");
function hash(password) {
    argon.hash(password, { type: argon.argon2i });
    argon.hash(password, { type: argon.argon2id });
    argon.hash(password, { memoryCost: 65536 });
    require("unrelated").hash(password, { type: argon.argon2i });
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-unsafe-argon2-config",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-unsafe-argon2-options",
        Some("LEGACY-JS-SEMGREP-TAINT-SANITIZER-argon2id-options"),
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn passport_secret_rule_requires_constant_secret_field_and_passport_package() {
    let actual = configured_map_findings(
        r#"
const Strategy = require("passport-jwt").Strategy;
function configure(secret) {
    Strategy({ secretOrKey: "hard-coded" }, verify);
    Strategy({ secretOrKey: secret }, verify);
    Strategy({ issuer: "fixed" }, verify);
    require("unrelated").Strategy({ secretOrKey: "hard-coded" }, verify);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-hardcoded-passport-secret",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-hardcoded-passport-options",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn express_libxml_rule_requires_noent_and_libxml_package_provenance() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    require("libxmljs").parseXmlString(request.body.xml, { noent: true });
    require("libxmljs2").parseXml(request.query.xml, { noent: true });
    require("libxmljs2").parseXml(request.query.xml, { noent: false });
    require("unrelated").parseXml(request.body.xml, { noent: true });
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-libxml-noent",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-libxml-request",
        None,
    );
    assert_eq!(actual.len(), 2, "{actual:#?}");
}

#[test]
fn cors_header_rule_supports_direct_map_and_write_head_forms() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    response.set("Access-Control-Allow-Origin", request.query.origin);
    response.header({ "access-control-allow-origin": request.body.origin });
    response.writeHead(200, { "Access-Control-Allow-Origin": request.params.origin });
    response.set("Content-Type", request.query.origin);
    request.set("Access-Control-Allow-Origin", request.query.origin);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-cors-misconfiguration",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-cors-request",
        None,
    );
    assert_eq!(actual.len(), 3, "{actual:#?}");
}

#[test]
fn x_frame_header_rule_supports_direct_map_and_write_head_forms() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    response.setHeader("X-Frame-Options", request.query.frame);
    response.set({ "x-frame-options": request.body.frame });
    response.writeHead(200, { "X-Frame-Options": request.params.frame });
    response.setHeader("Content-Security-Policy", request.query.frame);
    request.setHeader("X-Frame-Options", request.query.frame);
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-x-frame-options-misconfiguration",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-x-frame-request",
        None,
    );
    assert_eq!(actual.len(), 3, "{actual:#?}");
}

#[test]
fn node_fs_rule_models_both_path_positions_without_tainting_file_contents() {
    let actual = express_io_findings(
        r#"
const fs = require("fs");
const fsp = require("fs/promises");
function handle(sourcePath, destinationPath, contents) {
    fs.readFile(sourcePath);
    fs.copyFile("fixed-source", destinationPath);
    fsp.rename(sourcePath, destinationPath);
    fs.writeFile("fixed-output", contents);
    require("unrelated").readFile(sourcePath);
    fs.readFile("fixed-input");
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-fs-filename",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-fs-function-argument",
        None,
    );
    assert_eq!(actual.len(), 4, "{actual:#?}");
}

#[test]
fn remote_property_injection_tracks_only_direct_request_controlled_store_indices() {
    let legacy = legacy_models_for(Language::JavaScript).unwrap();
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-remote-property-injection";
    let source_id = "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-property-request";
    let rules = RuleSet {
        metadata: legacy.metadata.into_iter().filter(|rule| rule.id == sink_id).collect(),
        function_sources: legacy.function_sources.into_iter()
            .filter(|rule| rule.id == source_id).collect(),
        index_sinks: legacy.index_sinks.into_iter().filter(|rule| rule.id == sink_id).collect(),
        ..Default::default()
    };
    rules.validate().unwrap();
    let hir = parse_source(
        Language::JavaScript,
        "remote-property.js",
        r#"
function handler(request, response) {
    const target = {};
    target[request.query.key] = request.body.value;
    target["fixed"] = request.body.value;
    target["prefix-" + request.query.key] = request.body.value;
    target[response.key] = request.body.value;
    const read = target[request.query.key];
    consume(read);
}
"#,
    ).unwrap();
    let ir = lower_program(&hir);
    let actual = analyze(&build(&ir, &rules), &rules);
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn xml2json_event_rule_requires_request_data_inside_a_callback() {
    let actual = express_io_findings(
        r#"
function handler(request, response) {
    const parser = require("xml2json");
    parser.toJson(request.body.outside);
    request.on("data", function(chunk) {
        parser.toJson(chunk);
        require("unrelated").toJson(request.body.inside);
    });
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-express-xml2json-xxe-event",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-express-xml2json-event-request",
        None,
    );
    assert_eq!(actual.len(), 1, "{actual:#?}");
}

#[test]
fn chrome_remote_interface_rule_selects_sensitive_map_fields_and_package_provenance() {
    let actual = express_io_findings(
        r#"
function inspect(expression, url, header, footer, html, harmless) {
    const client = require("chrome-remote-interface").connect();
    client.Runtime.compileScript({ expression: expression });
    client.Runtime.evaluate({ expression: "fixed", contextId: harmless });
    client.Page.navigate({ url: url });
    client.Page.printToPDF({ headerTemplate: header });
    client.Page.printToPDF({ footerTemplate: footer });
    client.Page.setDocumentContent({ frameId: harmless, html: html });
    require("unrelated").Runtime.compileScript({ expression: expression });
}
"#,
        "LEGACY-JS-SEMGREP-TAINT-chrome-remote-interface-compilescript-injection",
        "LEGACY-JS-SEMGREP-TAINT-SOURCE-chrome-remote-function-argument",
        None,
    );
    assert_eq!(actual.len(), 5, "{actual:#?}");
}
