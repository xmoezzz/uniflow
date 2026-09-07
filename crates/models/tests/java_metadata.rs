use std::{collections::BTreeMap, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};
use uniflow_hir::Language;
use uniflow_models::{compile_legacy_jvm_rule_tree, LegacyJvmKnowledgeCatalog};
use uniflow_rules::RuleMetadata;

fn metadata(id: &str) -> RuleMetadata {
    RuleMetadata { id: id.into(), title: "generic fallback".into(), message: "fallback".into(),
        severity: "warning".into(), cwe: vec![], standards: vec![], translations: Default::default() }
}

const KNOWLEDGE: &str = r#"
BugInfos:
  BugInfo:
  - id: '0001'
    Categories:
      Category: [{type: DetailClassChin, value: SQL注入}]
    ENDetailClassChin: [SQL Injection]
    Description: 原始描述。
    Advice: 请使用参数化查询。
    Description_En: Original description.
    Advice_En: Use parameters.
    DynamicDescription: 'DO NOT EXECUTE ${command}'
    References:
      Reference:
      - {type: CWE, value: '89:SQL Injection'}
      - {type: OWASP, value: '2021:A03'}
  - id: '0002'
    Description: 标准描述，不应替换漏洞描述。
RuleSets:
  RuleSet:
  - Name: sql_injection
    Maps:
      Map: [{type: cert, value: '0002'}, {type: bug, value: '0001'}, {type: std, value: '9999'}]
"#;

#[test]
fn jvm_metadata_preserves_original_prose_and_completes_all_locales() {
    let mut catalog = LegacyJvmKnowledgeCatalog::default();
    catalog.ingest_yaml(KNOWLEDGE).unwrap();
    let mut entries = [metadata("sink"), metadata("unmapped")];
    let names = BTreeMap::from([("sink".into(), "sql_injection".into()), ("unmapped".into(), "unknown".into())]);
    let report = catalog.enrich(&mut entries, &names);
    assert_eq!(entries[0].title, "SQL Injection");
    assert_eq!(entries[0].message, "Original description.\n\nUse parameters.");
    assert_eq!(entries[0].translations.zh_cn.as_ref().unwrap().message, "原始描述。\n\n请使用参数化查询。");
    assert_eq!(entries[0].translations.zh_tw.as_ref().unwrap().message, "原始描述。\n\n請使用引數化查詢。");
    assert_eq!(entries[0].cwe, ["CWE-89"]);
    for standard in ["LEGACY-MSG-0001", "cert:0002", "OWASP:2021:A03"] {
        assert!(entries[0].standards.iter().any(|value| value == standard));
    }
    assert_eq!(report.enriched_sinks, 2);
    assert_eq!(report.chinese_messages, 2);
    assert_eq!(report.english_messages, 2);
    assert_eq!(report.traditional_chinese_messages, 2);
    assert_eq!(report.source_enriched_sinks, 1);
    assert_eq!(report.source_chinese_messages, 1);
    assert_eq!(report.source_english_messages, 1);
    assert_eq!(report.source_traditional_chinese_messages, 0);
    assert_eq!(report.unmapped_vulnerabilities, ["unknown"]);
    assert_eq!(report.unresolved_knowledge_ids, ["9999"]);
    assert_eq!(entries[1].title, "generic fallback");
    assert_eq!(entries[1].translations.en.as_ref().unwrap().message, "fallback");
    assert_eq!(entries[1].translations.zh_tw.as_ref().unwrap().message, "fallback");
}

struct Scratch(PathBuf);
impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn jvm_tree_compilation_joins_tagged_maps_and_knowledge_files() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-jvm-metadata-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    // Metadata deliberately sorts after the executable definition.
    std::fs::write(scratch.0.join("a.yaml"), r#"
rules:
- !sinkRule
  id: Test-Id
  rule: sql_injection
  method:
    nsName: !exactPattern {exact: java.sql, caseInsensitive: false}
    className: !exactPattern {exact: Statement, caseInsensitive: false}
    methodName: !exactPattern {exact: execute, caseInsensitive: false}
  sinkPoints:
  - ins: [!valuePositionSingle {position: 0}]
    check: !checkSign {sign: web}
- !ruleMap
  name: sql_injection
  maps: [{type: custom, value: '1234'}]
"#).unwrap();
    std::fs::write(scratch.0.join("z.yaml"), KNOWLEDGE).unwrap();
    let compilation = compile_legacy_jvm_rule_tree(&scratch.0, Language::Java, "legacy.java").unwrap();
    assert_eq!(compilation.rules.sinks.len(), 1);
    assert_eq!(compilation.rules.sink_conditions.len(), 1);
    assert!(compilation.diagnostics.is_empty());
    let metadata = &compilation.rules.metadata[0];
    assert_eq!(metadata.id, "legacy.java.sink.test-id.0");
    assert_eq!(metadata.title, "SQL Injection");
    assert!(metadata.standards.contains(&"custom:1234".into()));
    assert_eq!(compilation.metadata_report.unresolved_knowledge_ids, ["1234", "9999"]);
}

#[test]
fn jvm_metadata_merge_is_idempotent_and_rejects_invalid_catalog_shapes() {
    let mut catalog = LegacyJvmKnowledgeCatalog::default();
    catalog.ingest_yaml(KNOWLEDGE).unwrap();
    catalog.ingest_yaml(KNOWLEDGE).unwrap();
    let names = BTreeMap::from([("sink".into(), "sql_injection".into())]);
    let mut entries = [metadata("sink")];
    catalog.enrich(&mut entries, &names);
    let before = serde_yaml::to_string(&entries).unwrap();
    catalog.enrich(&mut entries, &names);
    assert_eq!(before, serde_yaml::to_string(&entries).unwrap());
    assert!(catalog.ingest_yaml("BugInfos: {BugInfo: {id: invalid}}").is_err());
    assert!(catalog.ingest_yaml("RuleSets: {RuleSet: [{Name: example, Maps: {Map: [{type: bug}]}}]}").is_err());
}

#[test]
fn bundled_java_metadata_audit_matches_executable_sink_catalog() {
    let rules = uniflow_models::legacy_models_for(Language::Java).unwrap();
    let report: uniflow_models::LegacyJvmMetadataReport =
        serde_yaml::from_str(uniflow_models::bundled_java_metadata_report()).unwrap();
    assert_eq!(rules.sinks.len(), 4511);
    assert_eq!(rules.unused_return_sinks.len(), 1);
    assert_eq!(rules.metadata.len(), 4512);
    assert_eq!(report.mapped_sinks, rules.metadata.iter().filter(|meta| meta.standards.iter().any(|value| value.starts_with("LEGACY-MSG-"))).count());
    assert_eq!(report.chinese_messages, rules.metadata.iter().filter(|meta| meta.translations.zh_cn.as_ref().is_some_and(|text| !text.message.is_empty())).count());
    assert_eq!(report.english_messages, rules.metadata.iter().filter(|meta| meta.translations.en.as_ref().is_some_and(|text| !text.message.is_empty())).count());
    assert_eq!(report.traditional_chinese_messages, rules.metadata.iter().filter(|meta| meta.translations.zh_tw.as_ref().is_some_and(|text| !text.message.is_empty())).count());
    assert!(report.unmapped_vulnerabilities.is_empty());
    let sql = rules.metadata.iter().find(|meta| meta.id == "legacy.java.sink.bc4f4fcb-12de-41ab-81d6-6d9915c0e93e.0").unwrap();
    assert!(sql.cwe.contains(&"CWE-89".into()));
    assert!(sql.translations.zh_cn.as_ref().unwrap().message.contains("SQL"));
    assert!(!sql.translations.zh_cn.as_ref().unwrap().message.contains("th:if"));
    assert!(sql.translations.zh_tw.as_ref().unwrap().message.contains("SQL"));
    assert_eq!(report.enriched_sinks, 4512);
    assert_eq!(report.chinese_messages, 4512);
    assert_eq!(report.english_messages, 4512);
    assert_eq!(report.traditional_chinese_messages, 4512);
    assert_eq!(report.source_enriched_sinks, 4503);
    assert_eq!(report.source_chinese_messages, 4503);
    assert_eq!(report.source_english_messages, 631);
    assert_eq!(report.source_traditional_chinese_messages, 0);
}
