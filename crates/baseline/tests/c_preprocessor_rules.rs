use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{BaselinePack, builtin_security_pack};
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;

fn check(rule: &str, source: &str, expected: usize) -> Vec<(u32, u32)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let mut coordinates = Vec::new();
    for language in [Language::C, Language::Cpp] {
        let findings = pack.scan_text(&language, Path::new("Macros.c"), source);
        assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
        coordinates = findings.iter().map(|finding| (finding.line as u32, finding.column as u32)).collect();
        let hir = parse_c_like_file(language, "Macros.c", source).unwrap();
        let integrated = pack.scan_hir(&hir, &HashMap::from([("Macros.c".into(), source.into())]));
        assert_eq!(integrated.iter().map(|finding| (finding.line as u32, finding.column as u32)).collect::<Vec<_>>(), coordinates);
    }
    coordinates
}

#[test]
fn migrated_c_macro_rules_preserve_source_boundaries() {
    for (rule, definition) in [
        ("LEGACY-C-AST-function-like-macros-must-have-braces", "#define F(x) x+x"),
        ("LEGACY-C-AST-no-redefine-keyword", "#define while if"),
        ("LEGACY-C-AST-no-concat-in-macros", "#define F() \"#\""),
        ("LEGACY-C-AST-no-concat-twice-in-macros", "#define F(x,y) #x #y"),
        ("LEGACY-C-AST-no-macro-to-basic-type", "#define WORD unsigned int"),
        ("LEGACY-C-AST-no-semicolon-after-macro", "#define CALL() run();"),
    ] {
        check(rule, definition, 1);
        check(rule, &format!("/* {definition} */"), 0);
        check(rule, &format!("// {definition}\nvoid f() {{}}"), 0);
        check(rule, &format!("void f() {{ /* {definition} */ }}"), 0);
        let quoted = definition.replace('\\', "\\\\").replace('"', "\\\"");
        check(rule, &format!("const char *text = \"{quoted}\";"), 0);
        check(rule, &format!("// continued comment \\\n{definition}"), 0);
    }
}

#[test]
fn c_macro_matchers_validate_modes_and_apply_file_gates() {
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == "LEGACY-C-AST-no-semicolon-after-macro");
    assert_eq!(pack.rules.len(), 1);
    pack.rules[0].matcher.path_pattern = "\\.h$".into();
    pack.validate().unwrap();
    assert!(pack.scan_text(&Language::C, Path::new("M.c"), "#define M x;").is_empty());
    assert_eq!(pack.scan_text(&Language::C, Path::new("M.h"), "#define M x;").len(), 1);
    pack.rules[0].matcher.c_style = Some(uniflow_baseline::CStyleCheck::EmptyStatement);
    assert!(pack.validate().is_err());
    pack.rules[0].matcher.c_style = None;
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
}

#[test]
fn migrated_c_macro_hash_rules_retain_raw_replacement_predicates() {
    let one = "LEGACY-C-AST-no-concat-in-macros";
    check(one, "#define F() #x\n#define G(x) x##x\n#define H(x) \"#\"", 3);
    check(one, "#define F #x\n#define G (x) #x\n#define H(x) x+x", 0);
    let repeated = "LEGACY-C-AST-no-concat-twice-in-macros";
    check(repeated, "#define F(x,y) #x #y\n#define G() a##b##c", 2);
    check(repeated, "#define F(x) x##x\n#define G(x) ###\n#define H #x #y", 0);
    check(repeated, "#define F(x) \"#x#\"", 1);
}

#[test]
fn migrated_c_macro_parentheses_preserve_both_endpoint_predicate() {
    let rule = "LEGACY-C-AST-function-like-macros-must-have-braces";
    check(rule, "#define F(x) x+x\n#define G() 42", 2);
    check(rule, "#define F(x) (x+x)\n#define G(x) (x)+x\n#define H(x) x+(x)\n#define I(x) x", 0);
    check(rule, "#define F x+x\n#define G (x) x+x\n#define EMPTY()", 0);
}

#[test]
fn migrated_c_macro_object_name_and_type_gates_are_exact() {
    let keyword = "LEGACY-C-AST-no-redefine-keyword";
    check(keyword, "#define bool int\n#define for while\n#define switch while", 3);
    check(keyword, "#define boolish int\n#define for(x) x\n#define const mutable\n#undef int", 0);
    let ty = "LEGACY-C-AST-no-macro-to-basic-type";
    check(ty, "#define A unsigned int\n#define B char\n#define C unsigned long", 3);
    check(ty, "#define A(x) int\n#define B bool\n#define C int*\n#define D unsigned  int\n#define E (int)", 0);
}

#[test]
fn migrated_c_macro_continuations_keep_original_diagnostic_locations() {
    let rule = "LEGACY-C-AST-no-semicolon-after-macro";
    let source = "// 中文\n  #de\\\nfine F() first(); \\\nsecond();\n\t#define G(x) x;\n#define SAFE() (x)\n";
    assert_eq!(check(rule, source, 2), vec![(2, 3), (5, 2)]);
    check(rule, "#define F() first();\\\r\nsecond();\r\n", 1);
    check(rule, "#define A (run();)\n#define B(x) {run();}\n#define C(x) x", 0);
    check(rule, "#define F/**/() run();", 1);
}
