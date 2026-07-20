use std::collections::HashMap;
use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

#[test]
fn distinguishes_literal_and_nonliteral_format_arguments() {
    let source = r#"
void demo(char *user) {
    printf("%s", user);
    printf(user);
}
"#;
    let program = parse_c_like_file(Language::C, "demo.c", source).expect("parse");
    let sources = HashMap::from([("demo.c".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    let format_findings = findings
        .iter()
        .filter(|finding| finding.rule_id == "UF-C-PRINTF-NONLITERAL")
        .collect::<Vec<_>>();
    assert_eq!(format_findings.len(), 1);
}

#[test]
fn detects_only_direct_realloc_self_assignment() {
    let source = r#"
void demo(char *p, int n) {
    char *tmp = realloc(p, n);
    p = realloc(p, n);
}
"#;
    let program = parse_c_like_file(Language::C, "demo.c", source).expect("parse");
    let sources = HashMap::from([("demo.c".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    let realloc_findings = findings
        .iter()
        .filter(|finding| finding.rule_id == "UF-C-MEM-REALLOC-ASSIGN")
        .collect::<Vec<_>>();
    assert_eq!(realloc_findings.len(), 1);
}


#[test]
fn positional_boolean_matcher_checks_the_boolean_value() {
    let source = r#"
package demo;
public class Security {
    void configure() {
        setSecure(false);
        setSecure(true);
    }
    void setSecure(boolean value) {}
}
"#;
    let program = JavaParser::default()
        .parse_file("Security.java", source)
        .expect("parse");
    let sources = HashMap::from([("Security.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "UF-JAVA-COOKIE-SECURE-OFF")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1);
}
