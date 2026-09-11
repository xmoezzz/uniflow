pub fn default_models_for(language: Language) -> RuleSet {
    match language {
        Language::Java => java_models(),
        Language::Kotlin | Language::Jsp => {
            let mut rules = retarget_models(java_models(), language.clone());
            rules.merge(portable_models(language));
            rules
        }
        Language::Python => python_models(),
        Language::C | Language::Cpp => c_like_models(language),
        Language::ObjC | Language::ObjCpp => {
            let mut rules = c_like_models(language.clone());
            rules.merge(portable_models(language));
            rules
        }
        Language::CSharp
        | Language::Swift
        | Language::Go
        | Language::JavaScript
        | Language::Sql
        | Language::Php
        | Language::Ruby
        | Language::Rust
        | Language::Shell => portable_models(language),
        Language::Unknown => RuleSet::default(),
    }
}

fn retarget_models(mut rules: RuleSet, language: Language) -> RuleSet {
    for rule in &mut rules.sources {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.sinks {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.unused_return_sinks {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.sanitizers {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.taint_transforms {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.propagators {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.summaries {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.field_sources {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.named_value_sources {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.field_sinks {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.field_sanitizers {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.function_sources {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.function_sinks {
        rule.language = Some(language.clone());
    }
    for rule in &mut rules.native_dataflow_rules {
        rule.language = Some(language.clone());
    }
    rules
}

pub fn load_with_defaults(language: Language, user_yaml: Option<&str>) -> Result<RuleSet> {
    let mut rules = default_models_for(language.clone());
    rules.merge(mit_models_for(language.clone())?);
    rules.merge(legacy_models_for(language)?);
    if let Some(text) = user_yaml {
        let user = RuleSet::from_yaml_str(text)?;
        rules.merge(user);
    }
    // Every constituent is validated when it is authored/compiled. `merge`
    // only appends and deterministically de-duplicates entries, so validating
    // the full 10k+ model catalog here merely recompiles every matcher regex on
    // every CLI invocation. User YAML is validated by `from_yaml_str` above.
    Ok(rules)
}

/// Loads the executable portion of the bundled catalogs without materializing
/// their report metadata. Callers can attach metadata for the rule IDs that
/// actually occur in a completed flow graph with
/// [`attach_legacy_metadata_for_ids`].
pub fn load_with_defaults_for_analysis(
    language: Language,
    user_yaml: Option<&str>,
) -> Result<RuleSet> {
    let mut rules = default_models_for(language.clone());
    rules.merge(mit_models_for(language.clone())?);
    rules.merge(legacy_analysis_models_for(language)?);
    if let Some(text) = user_yaml {
        rules.merge(RuleSet::from_yaml_str(text)?);
    }
    Ok(rules)
}
