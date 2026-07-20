use uniflow_hir::Language;
use uniflow_models::{mit_catalog_manifest, mit_models_for};

#[test]
fn every_supported_language_has_mit_models() {
    for language in [Language::C, Language::Cpp, Language::Java, Language::Python] {
        let rules = mit_models_for(language).expect("MIT model bundle must parse");
        assert!(!rules.sources.is_empty(), "missing source models");
        assert!(!rules.sinks.is_empty(), "missing sink models");
        rules.validate().expect("MIT model bundle must validate");
    }
}

#[test]
fn manifest_is_embedded() {
    let manifest = mit_catalog_manifest();
    assert!(manifest.contains("pysa-python.yml"));
    assert!(manifest.contains("mariana-java.yml"));
    assert!(manifest.contains("infer-c-cpp.yml"));
    assert!(manifest.contains("codeql-security.yml"));
}
