const PYSA_MODELS: &str = include_str!("../../../../rules/mit/pysa-python.yml");
const MARIANA_MODELS: &str = include_str!("../../../../rules/mit/mariana-java.yml");
const INFER_MODELS: &str = include_str!("../../../../rules/mit/infer-c-cpp.yml");
const CODEQL_MODELS: &str = include_str!("../../../../rules/mit/codeql-security.yml");

pub fn mit_models_for(language: Language) -> Result<RuleSet> {
    let mut merged = RuleSet::default();
    for text in [PYSA_MODELS, MARIANA_MODELS, INFER_MODELS, CODEQL_MODELS] {
        merged.merge(RuleSet::from_yaml_str(text)?);
    }
    retain_language(&mut merged, &language);
    merged.validate()?;
    Ok(merged)
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
