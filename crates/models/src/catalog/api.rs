pub fn default_models_for(language: Language) -> RuleSet {
    match language {
        Language::Java => java_models(),
        Language::Python => python_models(),
        Language::C | Language::Cpp => c_like_models(language),
        Language::Unknown => RuleSet::default(),
    }
}

pub fn load_with_defaults(language: Language, user_yaml: Option<&str>) -> Result<RuleSet> {
    let mut rules = default_models_for(language.clone());
    rules.merge(mit_models_for(language)?);
    if let Some(text) = user_yaml {
        let user = RuleSet::from_yaml_str(text)?;
        rules.merge(user);
    }
    rules.validate()?;
    Ok(rules)
}

