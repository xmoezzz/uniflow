use std::collections::HashMap;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use uniflow_baseline::{builtin_security_pack, bundled_java_ast_rules, bundled_java_package_rules};
use uniflow_hir::Language;
use uniflow_models::{
    audit_legacy_jvm_rule_tree, legacy_jvm_rule_map_aliases, legacy_models_for, LegacyJvmRuleKind,
    LegacyJvmRulePack,
};

fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("rules/legacy/source/dataflow/java/rules")
}

#[test]
fn every_java_rule_map_is_attached_to_executable_sink_metadata() {
    let root = source_root();
    let bundled = legacy_models_for(Language::Java).expect("bundled Java models");
    let metadata = bundled
        .metadata
        .iter()
        .map(|entry| (entry.id.as_str(), entry))
        .collect::<HashMap<_, _>>();
    let mut sinks_by_vulnerability = HashMap::<String, Vec<String>>::new();
    let baseline = builtin_security_pack().expect("bundled baseline rules");
    let baseline_rules = baseline
        .rules
        .iter()
        .map(|rule| (rule.id.as_str(), rule))
        .collect::<HashMap<_, _>>();
    let mut rule_maps = Vec::new();
    let mut missing_rule_maps = Vec::new();

    for entry in std::fs::read_dir(&root).expect("read Java source directory") {
        let path = entry.expect("Java source entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read Java source pack");
        let Ok(pack) = LegacyJvmRulePack::from_yaml_str(&source) else {
            continue;
        };
        for rule in pack.rules {
            match rule.kind {
                LegacyJvmRuleKind::Sink => {
                    let vulnerability = rule
                        .vulnerability
                        .unwrap_or_else(|| "legacy_taint".to_string());
                    for point in 0..rule.points.len() {
                        sinks_by_vulnerability
                            .entry(vulnerability.clone())
                            .or_default()
                            .push(format!(
                                "legacy.java.sink.{}.{}",
                                normalized_id(&rule.id),
                                point
                            ));
                    }
                }
                LegacyJvmRuleKind::RuleMap => {
                    rule_maps.push((rule.id, rule.mappings));
                }
                LegacyJvmRuleKind::Source
                | LegacyJvmRuleKind::Passthrough
                | LegacyJvmRuleKind::Cleanse => {}
            }
        }
    }

    assert_eq!(sinks_by_vulnerability.len(), 125);
    assert_eq!(rule_maps.len(), 635);
    assert_eq!(
        rule_maps
            .iter()
            .map(|(_, mappings)| mappings.len())
            .sum::<usize>(),
        1_009
    );
    for (vulnerability, mappings) in rule_maps {
        let expected = mappings
            .iter()
            .map(|mapping| format!("{}:{}", mapping.standard, mapping.rule_id))
            .collect::<Vec<_>>();
        let sinks = sinks_by_vulnerability.get(&vulnerability).or_else(|| {
            sinks_by_vulnerability
                .iter()
                .find(|(sink_name, _)| {
                    legacy_jvm_rule_map_aliases(sink_name)
                        .iter()
                        .any(|alias| *alias == vulnerability)
                })
                .map(|(_, sinks)| sinks)
        });
        if let Some(sinks) = sinks {
            for standard in &expected {
                assert!(
                    sinks.iter().any(|sink_id| {
                        metadata
                            .get(sink_id.as_str())
                            .is_some_and(|entry| entry.standards.contains(standard))
                    }),
                    "Java ruleMap {vulnerability} mapping {standard} is absent from taint metadata"
                );
            }
            continue;
        }

        if baseline.rules.iter().any(|rule| {
            rule.languages.contains(&Language::Java)
                && expected
                    .iter()
                    .all(|standard| rule.standards.contains(standard))
        }) {
            continue;
        }

        let mapped_ids = mappings
            .iter()
            .map(|mapping| mapping.rule_id.as_str())
            .collect::<HashSet<_>>();
        let ast_rule = bundled_java_ast_rules().iter().find(|rule| {
            rule.message_id.split(',').any(|message_id| {
                message_id
                    .trim()
                    .get(2..)
                    .is_some_and(|message_id| mapped_ids.contains(message_id))
            })
        });
        if let Some(ast_rule) = ast_rule {
            let native_id = ast_rule
                .native_rule_id
                .expect("all Java AST rules are migrated");
            let executable = baseline_rules
                .get(native_id)
                .unwrap_or_else(|| panic!("Java AST ruleMap {vulnerability} has no {native_id}"));
            for standard in &expected {
                assert!(executable.standards.contains(standard),
                    "Java AST ruleMap {vulnerability} mapping {standard} is absent from {native_id}");
            }
            continue;
        }

        let package_rule = bundled_java_package_rules().iter().find(|rule| {
            rule.message_id.split(',').any(|message_id| {
                message_id
                    .trim()
                    .get(2..)
                    .is_some_and(|message_id| mapped_ids.contains(message_id))
            })
        });
        if let Some(package_rule) = package_rule {
            let native_id = format!("LEGACY-JAVA-PKG-{}", package_rule.id);
            let executable = baseline_rules.get(native_id.as_str()).unwrap_or_else(|| {
                panic!("Java package ruleMap {vulnerability} has no {native_id}")
            });
            for standard in &expected {
                assert!(executable.standards.contains(standard),
                    "Java package ruleMap {vulnerability} mapping {standard} is absent from {native_id}");
            }
            continue;
        }

        missing_rule_maps.push(vulnerability);
    }
    missing_rule_maps.sort();
    missing_rule_maps.dedup();
    assert!(
        missing_rule_maps.is_empty(),
        "{} unique Java ruleMaps without taint, AST, or package checker: {missing_rule_maps:#?}",
        missing_rule_maps.len()
    );
}

fn normalized_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[test]
fn every_java_dataflow_source_rule_has_a_bundled_executable_model() {
    let root = source_root();
    let audit = audit_legacy_jvm_rule_tree(&root).expect("audit copied Java rule tree");
    assert_eq!(audit.total_rules, 9_009);
    assert_eq!(audit.total_executable_rules, 8_374);
    assert!(audit.duplicate_executable_ids.is_empty());
    assert_eq!(
        audit.skipped_non_executable_catalogs,
        [
            "java_j.yaml",
            "java_k.yaml",
            "java_m.yaml",
            "java_n.yaml",
            "java_p.yaml",
            "java_q.yaml",
            "java_r.yaml",
        ]
    );

    let bundled = legacy_models_for(Language::Java).expect("bundled Java models");
    let executable_ids = bundled
        .sources
        .iter()
        .map(|rule| rule.id.as_str())
        .chain(bundled.sinks.iter().map(|rule| rule.id.as_str()))
        .chain(
            bundled
                .unused_return_sinks
                .iter()
                .map(|rule| rule.id.as_str()),
        )
        .chain(bundled.sanitizers.iter().map(|rule| rule.id.as_str()))
        .chain(bundled.taint_transforms.iter().map(|rule| rule.id.as_str()))
        .chain(bundled.propagators.iter().map(|rule| rule.id.as_str()))
        .collect::<HashSet<_>>();

    for file in &audit.files {
        let source = std::fs::read_to_string(root.join(&file.path)).expect("read Java source pack");
        let pack = LegacyJvmRulePack::from_yaml_str(&source).expect("parse Java source pack");
        for rule in pack
            .rules
            .iter()
            .filter(|rule| rule.kind != LegacyJvmRuleKind::RuleMap)
        {
            let normalized = normalized_id(&rule.id);
            let prefix = match rule.kind {
                LegacyJvmRuleKind::Source => format!("legacy.java.source.{normalized}."),
                LegacyJvmRuleKind::Sink => format!("legacy.java.sink.{normalized}."),
                LegacyJvmRuleKind::Passthrough => {
                    format!("legacy.java.passthrough.{normalized}")
                }
                LegacyJvmRuleKind::Cleanse => format!("legacy.java.cleanse"),
                LegacyJvmRuleKind::RuleMap => unreachable!(),
            };
            let represented = match rule.kind {
                LegacyJvmRuleKind::Cleanse => executable_ids.iter().any(|candidate| {
                    candidate.starts_with("legacy.java.cleanse.") && candidate.contains(&normalized)
                        || candidate.starts_with("legacy.java.cleanse_transform.")
                            && candidate.ends_with(&normalized)
                }),
                _ => executable_ids
                    .iter()
                    .any(|candidate| candidate.starts_with(&prefix)),
            };
            assert!(
                represented,
                "source Java rule {} ({:?}) from {} has no bundled executable model",
                rule.id, rule.kind, file.path
            );
        }
    }
}
