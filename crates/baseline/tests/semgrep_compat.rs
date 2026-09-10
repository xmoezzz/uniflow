use regex::Regex;
use std::path::Path;
use uniflow_baseline::{
    builtin_security_pack, bundled_legacy_raw_assets, bundled_semgrep_search_compat_rules,
    BaselinePack,
};
use uniflow_hir::Language;

fn assert_language_compatibility_models(language_name: &str, language: Language) {
    let bundled = builtin_security_pack().expect("bundled security pack");
    let annotation = Regex::new(r"ruleid:\s*([A-Za-z0-9_.-]+)").unwrap();
    let mut checked = 0;

    for spec in bundled_semgrep_search_compat_rules()
        .iter()
        .filter(|spec| spec.language == language_name)
    {
        let yaml: serde_yaml::Value = serde_yaml::from_str(spec.rule_yaml).unwrap();
        let legacy_id = yaml["id"].as_str().expect("Semgrep rule id");
        let directory = spec.source.rsplit_once('/').unwrap().0;
        let yaml_stem = Path::new(spec.source)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap();
        let fixtures = bundled_legacy_raw_assets()
            .iter()
            .filter(|asset| {
                asset.path.starts_with(directory)
                    && !asset.path.ends_with(".yaml")
                    && Path::new(asset.path)
                        .parent()
                        .is_some_and(|parent| parent == Path::new(directory))
            })
            .filter(|asset| {
                let text = String::from_utf8_lossy(asset.bytes);
                annotation
                    .captures_iter(&text)
                    .any(|capture| &capture[1] == legacy_id)
                    || Path::new(asset.path)
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .is_some_and(|stem| stem == yaml_stem)
            })
            .collect::<Vec<_>>();
        if fixtures.is_empty() && legacy_id == "check-rails-secret-yaml" {
            let rule = bundled
                .rules
                .iter()
                .find(|rule| rule.id == spec.native_rule_id)
                .unwrap()
                .clone();
            let focused = BaselinePack {
                id: "focused-rails-secret".to_string(),
                title: "Focused Rails secret rule".to_string(),
                rules: vec![rule],
            };
            let findings = focused.scan_text(
                &language,
                Path::new("config/secrets.production.yml"),
                "production:\n  secret_key_base: hardcoded-production-secret\n",
            );
            assert_eq!(findings.len(), 1, "{findings:#?}");
            checked += 1;
            continue;
        }
        assert!(
            !fixtures.is_empty(),
            "{} ({legacy_id}) has no bundled positive fixture",
            spec.source
        );

        let rule = bundled
            .rules
            .iter()
            .find(|rule| rule.id == spec.native_rule_id)
            .unwrap_or_else(|| panic!("missing bundled compatibility rule {}", spec.native_rule_id))
            .clone();
        let focused = BaselinePack {
            id: "focused-semgrep-compat".to_string(),
            title: "Focused Semgrep compatibility rule".to_string(),
            rules: vec![rule],
        };
        let deprecated = yaml["metadata"]["deprecated"].as_bool().unwrap_or(false)
            || yaml["message"]
                .as_str()
                .is_some_and(|message| message.to_ascii_lowercase().contains("deprecated"));
        if deprecated {
            for asset in &fixtures {
                let source = String::from_utf8_lossy(asset.bytes);
                assert!(
                    focused
                        .scan_text(&language, Path::new(asset.path), &source)
                        .is_empty(),
                    "deprecated rule {} must remain non-reporting",
                    spec.native_rule_id
                );
            }
            checked += 1;
            continue;
        }
        let found = fixtures.iter().any(|asset| {
            let source = String::from_utf8_lossy(asset.bytes);
            focused
                .scan_text(&language, Path::new(asset.path), &source)
                .iter()
                .any(|finding| finding.rule_id == spec.native_rule_id)
        });
        assert!(
            found,
            "{} ({legacy_id}) did not match its bundled positive fixture",
            spec.source
        );
        checked += 1;
    }

    let expected = if language_name == "javascript" {
        90
    } else {
        45
    };
    assert_eq!(checked, expected);
}

#[test]
fn every_bundled_javascript_semgrep_search_rule_has_a_native_compatibility_model() {
    assert_language_compatibility_models("javascript", Language::JavaScript);
}

#[test]
fn every_bundled_ruby_semgrep_search_rule_has_a_native_compatibility_model() {
    assert_language_compatibility_models("ruby", Language::Ruby);
}
