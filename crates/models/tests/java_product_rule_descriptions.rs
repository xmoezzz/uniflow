use std::collections::HashSet;

use uniflow_baseline::{builtin_security_pack, bundled_legacy_raw_assets};
use uniflow_hir::Language;
use uniflow_models::legacy_models_for;

fn collect_descriptor_ids<'a>(value: &'a serde_yaml::Value, ids: &mut Vec<&'a str>) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            if let Some(id) = mapping
                .get(serde_yaml::Value::String("id".to_string()))
                .and_then(serde_yaml::Value::as_str)
            {
                ids.push(id);
            }
            for value in mapping.values() {
                collect_descriptor_ids(value, ids);
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for value in sequence {
                collect_descriptor_ids(value, ids);
            }
        }
        _ => {}
    }
}

fn canonical_rule_id(value: &str) -> Option<&str> {
    let digits = value
        .trim_end_matches(|character: char| !character.is_ascii_digit())
        .rsplit(|character: char| !character.is_ascii_digit())
        .next()?;
    (digits.len() >= 14).then(|| &digits[digits.len() - 14..])
}

#[test]
fn every_java_product_description_maps_to_a_bundled_checker_or_dataflow_policy() {
    let assets = bundled_legacy_raw_assets();
    let descriptions = assets
        .iter()
        .filter(|asset| {
            asset.path.starts_with("rules-desc/java/") && asset.path.ends_with(".xml")
        })
        .collect::<Vec<_>>();
    assert_eq!(descriptions.len(), 2_119);

    let baseline = builtin_security_pack().expect("bundled baseline rules");
    let dataflow = legacy_models_for(Language::Java).expect("bundled Java dataflow rules");
    let covered = baseline
        .rules
        .iter()
        .filter(|rule| rule.languages.contains(&Language::Java))
        .flat_map(|rule| &rule.standards)
        .chain(dataflow.metadata.iter().flat_map(|metadata| &metadata.standards))
        .filter_map(|standard| canonical_rule_id(standard))
        .collect::<HashSet<_>>();

    let mut missing = Vec::new();
    let mut product_ids = HashSet::new();
    for description in descriptions {
        let file = description.path.rsplit('/').next().unwrap();
        let product_id = file
            .strip_suffix(".xml")
            .and_then(|file| file.rsplit_once('-'))
            .map(|(_, id)| id)
            .expect("Java description filename carries its product rule id");
        assert_eq!(product_id.len(), 16, "{}", description.path);
        assert!(product_id.bytes().all(|byte| byte.is_ascii_digit()));
        product_ids.insert(product_id);
        let canonical = &product_id[2..];
        if !covered.contains(canonical) {
            missing.push((product_id, description.path));
        }
    }
    assert_eq!(product_ids.len(), 2_119);
    assert!(
        missing.is_empty(),
        "Java product descriptions without a bundled implementation: {missing:#?}"
    );

    let descriptor = assets
        .iter()
        .find(|asset| asset.path == "rules-desc/java.yaml")
        .expect("bundled Java product rule index");
    let descriptor: serde_yaml::Value =
        serde_yaml::from_slice(descriptor.bytes).expect("parse Java product rule index");
    let mut indexed = Vec::new();
    collect_descriptor_ids(&descriptor, &mut indexed);
    assert_eq!(indexed.len(), 2_124);
    assert_eq!(indexed.iter().copied().collect::<HashSet<_>>().len(), 2_117);
    assert!(indexed
        .iter()
        .filter(|id| id.bytes().all(|byte| byte.is_ascii_digit()))
        .all(|id| product_ids.contains(id)));
}

#[test]
fn general_untrusted_data_policy_is_attached_to_injection_sinks() {
    let rules = legacy_models_for(Language::Java).expect("bundled Java dataflow rules");
    let covered = rules
        .metadata
        .iter()
        .filter(|metadata| {
            metadata
                .cwe
                .iter()
                .any(|cwe| matches!(cwe.as_str(), "CWE-89" | "CWE-112" | "CWE-116" | "CWE-611"))
        })
        .collect::<Vec<_>>();
    assert!(!covered.is_empty());
    assert!(covered.iter().all(|metadata| {
        [
            "cert:02000010140200",
            "legacy-product:0202000010140200",
            "legacy-product:0302000010140200",
        ]
        .iter()
        .all(|standard| metadata.standards.iter().any(|value| value == standard))
    }));
}
