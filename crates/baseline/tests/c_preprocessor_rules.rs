use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;

fn check(rule: &str, source: &str, expected: usize) -> Vec<(u32, u32)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let mut coordinates = Vec::new();
    for language in [Language::C, Language::Cpp] {
        let findings = pack.scan_text(&language, Path::new("Macros.c"), source);
        assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
        coordinates = findings
            .iter()
            .map(|finding| (finding.line as u32, finding.column as u32))
            .collect();
        let hir = parse_c_like_file(language, "Macros.c", source).unwrap();
        let integrated = pack.scan_hir(&hir, &HashMap::from([("Macros.c".into(), source.into())]));
        assert_eq!(
            integrated
                .iter()
                .map(|finding| (finding.line as u32, finding.column as u32))
                .collect::<Vec<_>>(),
            coordinates
        );
    }
    coordinates
}

#[test]
fn migrated_c_macro_rules_preserve_source_boundaries() {
    for (rule, definition) in [
        (
            "LEGACY-C-AST-function-like-macros-must-have-braces",
            "#define F(x) x+x",
        ),
        ("LEGACY-C-AST-no-redefine-keyword", "#define while if"),
        ("LEGACY-C-AST-no-concat-in-macros", "#define F() \"#\""),
        (
            "LEGACY-C-AST-no-concat-twice-in-macros",
            "#define F(x,y) #x #y",
        ),
        (
            "LEGACY-C-AST-no-macro-to-basic-type",
            "#define WORD unsigned int",
        ),
        (
            "LEGACY-C-AST-no-semicolon-after-macro",
            "#define CALL() run();",
        ),
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
    pack.rules
        .retain(|rule| rule.id == "LEGACY-C-AST-no-semicolon-after-macro");
    assert_eq!(pack.rules.len(), 1);
    pack.rules[0].matcher.path_pattern = "\\.h$".into();
    pack.validate().unwrap();
    assert!(pack
        .scan_text(&Language::C, Path::new("M.c"), "#define M x;")
        .is_empty());
    assert_eq!(
        pack.scan_text(&Language::C, Path::new("M.h"), "#define M x;")
            .len(),
        1
    );
    pack.rules[0].matcher.c_style = Some(uniflow_baseline::CStyleCheck::EmptyStatement);
    assert!(pack.validate().is_err());
    pack.rules[0].matcher.c_style = None;
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
}

#[test]
fn migrated_c_macro_hash_rules_retain_raw_replacement_predicates() {
    let one = "LEGACY-C-AST-no-concat-in-macros";
    check(
        one,
        "#define F() #x\n#define G(x) x##x\n#define H(x) \"#\"",
        3,
    );
    check(one, "#define F #x\n#define G (x) #x\n#define H(x) x+x", 0);
    let repeated = "LEGACY-C-AST-no-concat-twice-in-macros";
    check(repeated, "#define F(x,y) #x #y\n#define G() a##b##c", 2);
    check(
        repeated,
        "#define F(x) x##x\n#define G(x) ###\n#define H #x #y",
        0,
    );
    check(repeated, "#define F(x) \"#x#\"", 1);
}

#[test]
fn migrated_c_macro_parentheses_preserve_both_endpoint_predicate() {
    let rule = "LEGACY-C-AST-function-like-macros-must-have-braces";
    check(rule, "#define F(x) x+x\n#define G() 42", 2);
    check(
        rule,
        "#define F(x) (x+x)\n#define G(x) (x)+x\n#define H(x) x+(x)\n#define I(x) x",
        0,
    );
    check(rule, "#define F x+x\n#define G (x) x+x\n#define EMPTY()", 0);
}

#[test]
fn migrated_c_macro_object_name_and_type_gates_are_exact() {
    let keyword = "LEGACY-C-AST-no-redefine-keyword";
    check(
        keyword,
        "#define bool int\n#define for while\n#define switch while",
        3,
    );
    check(
        keyword,
        "#define boolish int\n#define for(x) x\n#define const mutable\n#undef int",
        0,
    );
    let ty = "LEGACY-C-AST-no-macro-to-basic-type";
    check(
        ty,
        "#define A unsigned int\n#define B char\n#define C unsigned long",
        3,
    );
    check(ty, "#define A(x) int\n#define B bool\n#define C int*\n#define D unsigned  int\n#define E (int)", 0);
}

#[test]
fn migrated_c_macro_continuations_keep_original_diagnostic_locations() {
    let rule = "LEGACY-C-AST-no-semicolon-after-macro";
    let source = "// 中文\n  #de\\\nfine F() first(); \\\nsecond();\n\t#define G(x) x;\n#define SAFE() (x)\n";
    assert_eq!(check(rule, source, 2), vec![(2, 3), (5, 2)]);
    check(rule, "#define F() first();\\\r\nsecond();\r\n", 1);
    check(
        rule,
        "#define A (run();)\n#define B(x) {run();}\n#define C(x) x",
        0,
    );
    check(rule, "#define F/**/() run();", 1);
}

#[test]
fn anzu_macro_parameter_parentheses_preserve_token_exceptions_and_locations() {
    let source = r##"
#define BAD(x) x + 1
#define GOOD(x) ((x) + 1)
#define STRINGIFY(x) #x
#define PREFIX(x) prefix ## x
#define SUFFIX(x) x ## suffix
#define ZERO() 1
#define MIXED(x, y) ((x) + (y + 1))
#define CONTINUED(x) \
    x + 2
#define TEXT(x) "x" /* x */
"##;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("macro_parameters.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-PARAMETER-PARENTHESES")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(2, 16), (8, 29), (10, 5)]
    );
}

#[test]
fn anzu_macro_body_wrapper_preserves_parameter_semicolon_and_delimiter_gates() {
    let source = r#"
#define BAD(x) use(x);
#define PAREN(x) (use(x);)
#define BRACED(x) { use(x); }
#define TRAILING(x) { use(x); };
#define EXPRESSION(x) x + 1
#define EMPTY_PARAMS() use();
#define OBJECT use(value);
#define STRING(x) "not;a;statement"
#define COMMENT(x) x /* ; */
#define MULTILINE(x) \
    use(x); \
    finish(x)
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("macro_body.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-SEMICOLON-BODY-WRAPPER")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(2, 9), (11, 9)]
    );
}

#[test]
fn anzu_macro_statement_keywords_are_token_aware_and_report_first_use() {
    let source = r#"
#define OBJECT if (ready) run()
#define FUNCTION(x) while (x) step(x)
#define TWO(x) for (;;) { if (x) break; }
#define IDENTIFIERS iffy + elsewhere + format
#define TEXT "if while goto"
#define COMMENT /* switch */ value
#define MULTILINE(x) \
    goto done
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("macro_keywords.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-STATEMENT-KEYWORD")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 4, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(2, 16), (3, 21), (4, 16), (9, 5)]
    );
}

#[test]
fn anzu_macro_redefinition_tracks_define_and_undef_in_source_order() {
    let source = r##"
#define EMPTY
#define EMPTY 1
#undef EMPTY
#define EMPTY 2
#define FUNCTION(x) (x)
#define FUNCTION 3
// #define FUNCTION 4
const char *text = "#define FUNCTION 5";
#undef FUNCTION
#define FUNCTION(x) (x)
"##;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("macro_redefinition.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-REDEFINED-MACRO")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(3, 9), (7, 9)]
    );
}

#[test]
fn anzu_macro_type_alias_requires_a_nonempty_all_type_token_body() {
    let source = r#"
#define WORD unsigned long
#define POINTER (unsigned int *)
#define STORAGE static volatile char
#define VALUE unsigned long value
#define NUMBER 32
#define EMPTY
#define TEXT "unsigned long"
#define FUNCTION(x) unsigned x
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("macro_types.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-TYPE-ALIAS")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(2, 9), (3, 9), (4, 9)]
    );
}

#[test]
fn anzu_include_path_rules_preserve_filename_and_absolute_path_predicates() {
    let source = r##"
#include "safe/header.h"
#include <odd*header.h>
#include "odd'header.h"
#include "/usr/include/vendor.h"
#include <C:/sdk/vendor.h>
#include "\\server\\share\\vendor.h"
// #include "/commented.h"
const char *text = "#include <D:/text.h>";
#include HEADER_MACRO
"##;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("includes.cpp"),
        source,
    );
    let unsafe_paths = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-INCLUDE-UNSAFE-CHARACTERS")
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    let absolute_paths = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-INCLUDE-ABSOLUTE-PATH")
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(unsafe_paths, vec![(3, 10), (4, 10)], "{findings:#?}");
    assert_eq!(absolute_paths, vec![(5, 10), (6, 10)], "{findings:#?}");
}

#[test]
fn anzu_keyword_macro_rules_require_exactly_one_keyword_token() {
    let source = r#"
#define TYPE int
#define MOVE return
#define int long
#define while if
#define MANY int long
#define IDENT integer
#define NUMBER 1
#define TEXT "int"
#define EMPTY
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("keyword_macros.c"),
        source,
    );
    let aliases = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-KEYWORD-ALIAS")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    let keyword_to_keyword = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-KEYWORD-TO-KEYWORD")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(aliases, vec![2, 3, 4, 5], "{findings:#?}");
    assert_eq!(keyword_to_keyword, vec![4, 5], "{findings:#?}");
}
