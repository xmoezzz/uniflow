use std::path::Path;
use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;

fn ids(language: Language, path: &str, source: &str) -> Vec<String> {
    builtin_security_pack()
        .expect("built-in pack")
        .scan_text(&language, Path::new(path), source)
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

#[test]
fn detects_representative_expanded_rules() {
    assert!(ids(
        Language::C,
        "tls.c",
        "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);\n"
    )
    .contains(&"UF-C-TLS-VERIFY-NONE".to_string()));

    assert!(ids(
        Language::Python,
        "load.py",
        "value = yaml.unsafe_load(payload)\n"
    )
    .contains(&"UF-PY-YAML-UNSAFE-LOAD".to_string()));

    assert!(
        ids(Language::Java, "Security.java", "http.csrf().disable();\n")
            .contains(&"UF-JAVA-SPRING-CSRF-DISABLE".to_string())
    );

    assert!(
        ids(Language::Cpp, "owner.cpp", "std::shared_ptr<Node>(this);\n")
            .contains(&"UF-CPP-SHARED-PTR-THIS".to_string())
    );
}

#[test]
fn detects_specific_secret_signatures_inside_literals() {
    let findings = ids(
        Language::Python,
        "settings.py",
        "TOKEN = \"glpat-0123456789abcdefghij\"\n",
    );
    assert!(findings.contains(&"UF-COMMON-GITLAB-TOKEN".to_string()));
}

#[test]
fn expanded_rules_remain_language_scoped() {
    let findings = ids(
        Language::Java,
        "Demo.java",
        "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);\n",
    );
    assert!(!findings.contains(&"UF-C-TLS-VERIFY-NONE".to_string()));
}
