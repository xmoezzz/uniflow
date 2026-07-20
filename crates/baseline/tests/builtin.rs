use std::path::Path;
use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;

#[test]
fn detects_c_gets() {
    let pack = builtin_security_pack().expect("built-in pack must load");
    let findings = pack.scan_text(&Language::C, Path::new("demo.c"), "gets(buffer);\n");
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "UF-C-STR-GETS"));
}

#[test]
fn detects_python_eval() {
    let pack = builtin_security_pack().expect("built-in pack must load");
    let findings = pack.scan_text(
        &Language::Python,
        Path::new("demo.py"),
        "eval(user_input)\n",
    );
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "UF-PY-EVAL"));
}

#[test]
fn ignores_rules_for_other_languages() {
    let pack = builtin_security_pack().expect("built-in pack must load");
    let findings = pack.scan_text(&Language::Java, Path::new("Demo.java"), "gets(buffer);\n");
    assert!(findings.is_empty());
}
