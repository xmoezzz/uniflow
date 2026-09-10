#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn python_models_include_django_terminals_and_session_mutators() {
        let rules = default_models_for(Language::Python);
        let ids = rules
            .summaries
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<HashSet<_>>();
        assert!(ids.contains("python-django-queryset-terminals"));
        assert!(ids.contains("python-sqlalchemy-session-mutators"));
    }

    #[test]
    fn every_supported_language_has_valid_default_models() {
        let languages = [
            Language::C,
            Language::Cpp,
            Language::CSharp,
            Language::ObjC,
            Language::ObjCpp,
            Language::Java,
            Language::Kotlin,
            Language::Swift,
            Language::Python,
            Language::Go,
            Language::JavaScript,
            Language::Jsp,
            Language::Sql,
            Language::Php,
            Language::Ruby,
            Language::Rust,
            Language::Shell,
        ];
        for language in languages {
            let rules = default_models_for(language.clone());
            rules
                .validate()
                .unwrap_or_else(|error| panic!("{language:?}: {error}"));
            assert!(
                !rules.sources.is_empty(),
                "{language:?} has no default source model"
            );
            assert!(
                !rules.sinks.is_empty(),
                "{language:?} has no default sink model"
            );
        }
    }

    #[test]
    fn sql_models_match_normalized_frontend_calls() {
        let rules = default_models_for(Language::Sql);
        assert!(rules
            .sources
            .iter()
            .any(|rule| rule.matcher.matches("sql.select")));
        assert!(rules
            .sinks
            .iter()
            .any(|rule| rule.matcher.matches("sql.update")));
    }

    #[test]
    fn rust_models_match_normalized_macro_calls() {
        let rules = default_models_for(Language::Rust);
        assert!(rules.sources.iter().any(|rule| rule.matcher.matches("var")));
        assert!(rules
            .sinks
            .iter()
            .any(|rule| rule.matcher.matches("sqlx_query!")));
    }

    #[test]
    fn php_models_match_superglobal_source_calls() {
        let rules = default_models_for(Language::Php);
        assert!(rules
            .sources
            .iter()
            .any(|rule| rule.matcher.matches("php.superglobal.GET")));
        assert!(rules
            .sources
            .iter()
            .any(|rule| rule.matcher.matches("php.superglobal.POST")));
    }

    #[test]
    fn bundled_legacy_jvm_catalogs_have_exact_migrated_counts() {
        let java = legacy_models_for(Language::Java).expect("bundled Java legacy rules");
        assert_eq!(java.sources.len(), 1_643);
        assert_eq!(java.sinks.len(), 4_515);
        assert_eq!(java.unused_return_sinks.len(), 1);
        assert_eq!(java.sanitizers.len(), 403);
        assert_eq!(java.taint_transforms.len(), 538);
        assert_eq!(java.propagators.len(), 3_240);
        assert_eq!(java.metadata.len(), 4_516);
        assert_eq!(java.sink_conditions.len(), 4_512);
        assert_eq!(java.call_conditions.len(), 278);

        let javascript =
            legacy_models_for(Language::JavaScript).expect("bundled JavaScript legacy rules");
        assert_eq!(javascript.sources.len(), 670);
        assert_eq!(javascript.sinks.len(), 698);
        assert_eq!(javascript.sink_reports.len(), 12);
        assert_eq!(javascript.field_sinks.len(), 2);
        assert_eq!(javascript.index_sinks.len(), 1);
        assert_eq!(javascript.sanitizers.len(), 12);
        assert!(javascript.taint_transforms.is_empty());
        assert_eq!(javascript.propagators.len(), 707);
        assert_eq!(javascript.metadata.len(), 691);
        assert_eq!(javascript.sink_conditions.len(), 627);
        assert_eq!(javascript.call_conditions.len(), 24);
        assert_eq!(javascript.function_sources.len(), 39);
        assert_eq!(javascript.field_sources.len(), 6);
    }

    #[test]
    fn bundled_legacy_native_catalogs_have_exact_migrated_counts() {
        let cpp = legacy_models_for(Language::Cpp).expect("bundled C/C++ legacy rules");
        assert_eq!(cpp.sources.len(), 942);
        assert_eq!(cpp.sinks.len(), 2_011);
        assert_eq!(cpp.sanitizers.len(), 2);
        assert_eq!(cpp.taint_transforms.len(), 1);
        assert_eq!(cpp.propagators.len(), 1_890);
        assert_eq!(cpp.metadata.len(), 2_011);
        assert_eq!(cpp.sink_conditions.len(), 2_011);
        assert!(cpp.call_conditions.is_empty());

        let objc = legacy_models_for(Language::ObjC).expect("bundled Objective-C legacy rules");
        assert_eq!(objc.sources.len(), 159);
        assert_eq!(objc.sinks.len(), 348);
        assert_eq!(objc.sanitizers.len(), 11);
        assert_eq!(objc.taint_transforms.len(), 15);
        assert_eq!(objc.propagators.len(), 232);
        assert_eq!(objc.metadata.len(), 348);
        assert_eq!(objc.sink_conditions.len(), 348);
        assert!(objc.call_conditions.is_empty());
    }

    #[test]
    fn bundled_legacy_python_catalog_has_exact_migrated_counts() {
        let python = legacy_models_for(Language::Python).expect("bundled Python legacy rules");
        assert_eq!(python.sources.len(), 300);
        assert_eq!(python.sinks.len(), 1058);
        assert_eq!(python.sanitizers.len(), 48);
        assert_eq!(python.propagators.len(), 245);
        assert_eq!(python.field_sources.len(), 123);
        assert_eq!(python.field_sinks.len(), 21);
        assert_eq!(python.field_sanitizers.len(), 2);
        assert_eq!(python.function_sources.len(), 4);
        assert_eq!(python.function_sinks.len(), 2);
        assert!(python.sink_conditions.is_empty());
        assert!(python.call_conditions.is_empty());
    }

    #[test]
    fn bundled_legacy_go_catalog_has_exact_migrated_counts() {
        let go = legacy_models_for(Language::Go).expect("bundled Go legacy rules");
        assert_eq!(go.sources.len(), 225);
        assert_eq!(go.sinks.len(), 754);
        assert_eq!(go.sink_conditions.len(), 754);
        assert_eq!(go.call_conditions.len(), 41);
        assert!(go.sanitizers.is_empty());
        assert!(go.propagators.is_empty());
    }

    #[test]
    fn bundled_legacy_csharp_catalog_has_exact_migrated_counts() {
        let csharp = legacy_models_for(Language::CSharp).expect("bundled C# legacy rules");
        assert_eq!(csharp.sources.len(), 240);
        assert_eq!(csharp.field_sources.len(), 1_380);
        assert_eq!(csharp.function_sources.len(), 60);
        assert_eq!(csharp.sinks.len(), 209);
        assert_eq!(csharp.field_sinks.len(), 94);
        assert_eq!(csharp.metadata.len(), 303);
        assert_eq!(csharp.sanitizers.len(), 866);
        assert_eq!(csharp.propagators.len(), 17);
        assert!(csharp.sink_conditions.is_empty());
        assert!(csharp.call_conditions.is_empty());
        assert!(csharp.metadata.iter().all(|metadata| {
            metadata.translations.en.is_some()
                && metadata.translations.zh_cn.is_some()
                && metadata.translations.zh_tw.is_some()
        }));
    }

    #[test]
    fn bundled_legacy_ruby_catalog_has_exact_migrated_counts() {
        let ruby = legacy_models_for(Language::Ruby).expect("bundled Ruby Semgrep taint rules");
        assert_eq!(ruby.metadata.len(), 36);
        assert_eq!(ruby.named_value_sources.len(), 2);
        assert_eq!(ruby.function_sources.len(), 1);
        assert_eq!(ruby.sources.len(), 8);
        assert_eq!(ruby.sinks.len(), 41);
        assert_eq!(ruby.index_sinks.len(), 2);
        assert_eq!(ruby.sink_reports.len(), 13);
        assert_eq!(ruby.sanitizers.len(), 3);
        assert_eq!(ruby.call_conditions.len(), 6);
        ruby.validate().expect("Ruby taint catalog validates");
    }

    #[test]
    fn kotlin_and_jsp_receive_retargeted_java_legacy_models() {
        for language in [Language::Kotlin, Language::Jsp] {
            let rules = legacy_models_for(language.clone()).expect("retargeted JVM rules");
            assert!(rules
                .sources
                .iter()
                .all(|rule| rule.language.as_ref() == Some(&language)));
            assert!(rules
                .taint_transforms
                .iter()
                .all(|rule| rule.language.as_ref() == Some(&language)));
        }
        for language in [Language::C, Language::ObjCpp] {
            let rules = legacy_models_for(language.clone()).expect("retargeted native rules");
            assert!(rules
                .sources
                .iter()
                .all(|rule| rule.language.as_ref() == Some(&language)));
            assert!(rules
                .taint_transforms
                .iter()
                .all(|rule| rule.language.as_ref() == Some(&language)));
        }
    }

    #[test]
    fn standard_loader_merges_bundled_legacy_rules_into_runtime_models() {
        let rules = load_with_defaults(Language::JavaScript, None)
            .expect("default JavaScript rules with legacy catalog");
        assert!(rules.sources.len() >= 661);
        assert!(rules
            .sinks
            .iter()
            .any(|rule| rule.id.starts_with("legacy.javascript.sink.")));
        assert!(rules
            .propagators
            .iter()
            .any(|rule| rule.id.starts_with("legacy.javascript.passthrough.")));
    }
}
