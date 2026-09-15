use std::sync::OnceLock;

/// Declares one MIT-derived catalog asset: a build-time-encrypted
/// `include_bytes!` (see `encrypt_mit_assets` in `build.rs`) decrypted once,
/// on first use, into a cached `&'static str`. The `$label` here must match
/// the label `build.rs` encrypted the same asset under exactly — see
/// `uniflow_rule_crypto`'s module doc comment for what this obfuscation is
/// and is not intended to defend against.
macro_rules! encrypted_asset {
    ($name:ident, $label:literal, $enc_file:literal) => {
        fn $name() -> &'static str {
            static CIPHERTEXT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/", $enc_file));
            static CELL: OnceLock<String> = OnceLock::new();
            CELL.get_or_init(|| {
                let bytes = uniflow_rule_crypto::transform($label, CIPHERTEXT);
                String::from_utf8(bytes)
                    .unwrap_or_else(|error| panic!("decrypted asset {:?} is not valid UTF-8: {error}", $label))
            })
            .as_str()
        }
    };
}

encrypted_asset!(pysa_models, "mit/pysa-python.yml", "mit-pysa-python.yml.enc");
encrypted_asset!(mariana_models, "mit/mariana-java.yml", "mit-mariana-java.yml.enc");
encrypted_asset!(infer_models, "mit/infer-c-cpp.yml", "mit-infer-c-cpp.yml.enc");
encrypted_asset!(codeql_models, "mit/codeql-security.yml", "mit-codeql-security.yml.enc");
encrypted_asset!(mit_manifest, "mit/manifest.json", "mit-manifest.json.enc");

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

fn mit_assets_for(language: &Language) -> Vec<&'static str> {
    match language {
        Language::Python => vec![pysa_models(), codeql_models()],
        Language::Java => vec![mariana_models(), codeql_models()],
        Language::C | Language::Cpp => vec![infer_models(), codeql_models()],
        _ => vec![],
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
    mit_manifest()
}
