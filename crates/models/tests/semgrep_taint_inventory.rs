use std::collections::HashSet;
use uniflow_baseline::bundled_semgrep_rules;
use uniflow_hir::Language;
use uniflow_models::legacy_models_for;

#[test]
fn migrated_semgrep_taint_ids_are_executable_in_the_bundled_model_catalog() {
    let inventory = bundled_semgrep_rules();
    let rules = legacy_models_for(Language::JavaScript).unwrap();
    let executable = rules
        .sources
        .iter()
        .map(|rule| rule.id.as_str())
        .chain(rules.sinks.iter().map(|rule| rule.id.as_str()))
        .chain(rules.sanitizers.iter().map(|rule| rule.id.as_str()))
        .chain(rules.taint_transforms.iter().map(|rule| rule.id.as_str()))
        .chain(rules.propagators.iter().map(|rule| rule.id.as_str()))
        .chain(rules.field_sources.iter().map(|rule| rule.id.as_str()))
        .chain(rules.field_sinks.iter().map(|rule| rule.id.as_str()))
        .chain(rules.index_sinks.iter().map(|rule| rule.id.as_str()))
        .chain(
            rules
                .sink_reports
                .iter()
                .map(|rule| rule.report_rule_id.as_str()),
        )
        .chain(rules.function_sources.iter().map(|rule| rule.id.as_str()))
        .chain(rules.function_sinks.iter().map(|rule| rule.id.as_str()))
        .collect::<HashSet<_>>();
    let migrated = inventory
        .iter()
        .filter_map(|rule| rule.native_taint_rule_id)
        .collect::<Vec<_>>();
    assert_eq!(migrated.len(), 64);
    for id in migrated {
        assert!(
            executable.contains(id),
            "missing bundled Semgrep taint rule {id}"
        );
        assert!(
            rules.metadata_for(id).is_some(),
            "missing metadata for {id}"
        );
    }
}
