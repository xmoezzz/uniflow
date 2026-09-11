const PYSA_MODELS: &str = include_str!("../../../../rules/mit/pysa-python.yml");
const MARIANA_MODELS: &str = include_str!("../../../../rules/mit/mariana-java.yml");
const INFER_MODELS: &str = include_str!("../../../../rules/mit/infer-c-cpp.yml");
const CODEQL_MODELS: &str = include_str!("../../../../rules/mit/codeql-security.yml");

pub fn mit_models_for(language: Language) -> Result<RuleSet> {
    let mut merged = RuleSet::default();
    // These files are embedded for distribution, but parsing and validating all
    // of them for every scan made a Java (or Python) one-file analysis pay for
    // unrelated language catalogs. Select the catalogs that can contain models
    // for this language before deserializing them. CodeQL is deliberately kept
    // alongside each supported language because it is the cross-language pack.
    for text in mit_assets_for(&language) {
        merged.merge(RuleSet::from_yaml_str(text)?);
    }
    // The shared CodeQL catalog contains entries for multiple languages, so
    // keep the established language boundary after parsing only that shared
    // file plus the language-specific one.
    retain_language(&mut merged, &language);
    Ok(merged)
}

fn mit_assets_for(language: &Language) -> &'static [&'static str] {
    match language {
        Language::Python => &[PYSA_MODELS, CODEQL_MODELS],
        Language::Java => &[MARIANA_MODELS, CODEQL_MODELS],
        Language::C | Language::Cpp => &[INFER_MODELS, CODEQL_MODELS],
        _ => &[],
    }
}

fn retain_language(rules: &mut RuleSet, language: &Language) {
    rules
        .sources
        .retain(|rule| language_matches(&rule.language, language));
    rules
        .sinks
        .retain(|rule| language_matches(&rule.language, language));
    rules
        .sanitizers
        .retain(|rule| language_matches(&rule.language, language));
    rules
        .propagators
        .retain(|rule| language_matches(&rule.language, language));
    rules
        .summaries
        .retain(|rule| language_matches(&rule.language, language));
}

pub fn mit_catalog_manifest() -> &'static str {
    include_str!("../../../../rules/mit/manifest.json")
}
