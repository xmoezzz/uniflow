use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{BaselinePack, builtin_security_pack};
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    for language in [Language::C, Language::Cpp] {
        let actual = pack.scan_text(&language, Path::new("Flow.c"), source);
        assert_eq!(actual.len(), expected, "{rule} {language:?}: {source}\n{actual:#?}");
        let hir = parse_c_like_file(language, "Flow.c", source).unwrap();
        let integrated = pack.scan_hir(&hir, &HashMap::from([("Flow.c".into(), source.into())]));
        assert_eq!(integrated.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>(),
            actual.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>());
    }
}

#[test]
fn migrated_c_statement_rule_boundaries() {
    let rules = [
        ("LEGACY-C-AST-if-else-braces", "if(x) f(); else g();", 2),
        ("LEGACY-C-AST-loop-body-braces", "while(x) f(); for(i=0;i<3;i++) f();", 2),
        ("LEGACY-C-AST-if-else-if-must-have-else", "if(x) {} else if(y) {}", 1),
        ("LEGACY-C-AST-no-empty-switch", "switch(x) {}", 1),
        ("LEGACY-C-AST-switch-must-have-case", "switch(x) { default: break; }", 1),
        ("LEGACY-C-AST-no-empty-statement", ";", 1),
        ("LEGACY-C-AST-no-semicolon-after-for-if-while", "if(x); while(x); for(;;);", 3),
        ("LEGACY-C-AST-no-break-in-loops", "while(x) { break; }", 1),
        ("LEGACY-C-AST-no-constant-in-loop-condition", "while(7) {} do { f(); } while(2);", 2),
    ];
    for (rule, body, count) in rules {
        check(rule, &format!("void f(void) {{ {body} }}"), count);
        check(rule, &format!("void f(void) {{ /* {body} */ }}"), 0);
        check(rule, &format!("void f(void) {{ const char *text = \"{body}\"; }}"), 0);
        check(rule, &format!("#define HIDDEN {body}\nvoid f(void) {{}}"), 0);
        check(rule, &format!("#define HIDDEN \\\n {body}\nvoid f(void) {{}}"), 0);
    }
}

#[test]
fn migrated_c_brace_rules_preserve_else_if_and_do_exclusions() {
    let if_rule = "LEGACY-C-AST-if-else-braces";
    check(if_rule, "void f() { if(x) {} else if(y) {} else {} }", 0);
    check(if_rule, "void f() { if(x) if(y) g(); else h(); }", 3);
    check("LEGACY-C-AST-loop-body-braces", "void f() { while(x) {} for(;;) {} do f(); while(x); }", 0);
    check("LEGACY-C-AST-if-else-if-must-have-else", "void f() { if(x) {} else if(y) {} else {} }", 0);
    check("LEGACY-C-AST-if-else-if-must-have-else", "void f() { if(x) {} else { if(y) {} } }", 0);
    check("LEGACY-C-AST-if-else-braces", "namespace N { struct S { void f() { if(x) g(); } }; }", 1);
}

#[test]
fn migrated_c_switch_and_break_rules_use_nearest_control_owner() {
    check("LEGACY-C-AST-no-empty-switch", "void f() { switch(x) { default: f(); } }", 0);
    check("LEGACY-C-AST-no-empty-switch", "void f() { switch(x) { switch(y) { case 1: break; } } }", 1);
    check("LEGACY-C-AST-switch-must-have-case", "void f() { switch(x) { default: switch(y) { case 1: break; } } }", 1);
    check("LEGACY-C-AST-switch-must-have-case", "void f() { switch(x) { case 1: case 2: default: break; } }", 0);
    check("LEGACY-C-AST-no-break-in-loops", "void f() { while(x) { switch(y) { case 1: break; } break; } }", 1);
    check("LEGACY-C-AST-no-break-in-loops", "void f() { switch(x) { case 1: while(y) { break; } break; } }", 1);
    check("LEGACY-C-AST-no-break-in-loops", "void f() { do { break; } while(x); }", 0);
}

#[test]
fn migrated_c_empty_and_constant_loop_rules_keep_original_body_predicates() {
    check("LEGACY-C-AST-no-empty-statement", "struct S {}; void f() { for(;;) {} do {} while(x); }", 0);
    check("LEGACY-C-AST-no-semicolon-after-for-if-while", "void f() { if(x) {;} while(x) {;} for(;;) {;} }", 0);
    check("LEGACY-C-AST-no-constant-in-loop-condition", "void f() { while(1) { f(); } while(-1) {} while((1)) {} while(x) {} }", 0);
    check("LEGACY-C-AST-no-constant-in-loop-condition", "void f() { while(0x1) { /*empty*/ } do {} while(0); }", 2);
}

#[test]
fn c_statement_matchers_reject_ignored_constraints() {
    use uniflow_baseline::{BaselineMatcher, CStyleCheck};
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == "LEGACY-C-AST-no-empty-statement");
    assert_eq!(pack.rules.len(), 1);
    pack.rules[0].matcher = BaselineMatcher {
        c_style: Some(CStyleCheck::EmptyStatement), code_pattern: "ignored".into(), ..Default::default()
    };
    assert!(pack.validate().is_err());
    pack.rules[0].matcher = BaselineMatcher { c_style: Some(CStyleCheck::EmptyStatement), ..Default::default() };
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
}
