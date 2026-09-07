use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{BaselinePack, builtin_security_pack};
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;

fn check(rule: &str, source: &str, expected: usize) -> Vec<(usize, usize)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let mut coordinates = Vec::new();
    for language in [Language::C, Language::Cpp] {
        let findings = pack.scan_text(&language, Path::new("Expressions.c"), source);
        assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
        coordinates = findings.iter().map(|finding| (finding.line, finding.column)).collect();
        let hir = parse_c_like_file(language, "Expressions.c", source).unwrap();
        let integrated = pack.scan_hir(&hir, &HashMap::from([("Expressions.c".into(), source.into())]));
        assert_eq!(integrated.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>(), coordinates);
    }
    coordinates
}

#[test]
fn migrated_c_expression_rules_preserve_source_boundaries() {
    for (rule, source, safe) in [
        ("LEGACY-C-AST-nullptr-zero", "int *pointer = 0;", "int *pointer = NULL;"),
        ("LEGACY-C-AST-no-assignment-outside-statement", "return value = read();", "value = read();"),
        ("LEGACY-C-AST-no-unary-in-expressions", "result = value++ + 1;", "value++;"),
        ("LEGACY-C-AST-no-side-effect-in-sizeof", "size_t n = sizeof(value++);", "size_t n = sizeof(value);"),
        ("LEGACY-C-AST-no-comma-expression", "result = (first, second);", "result = call(first, second);"),
        ("LEGACY-C-AST-no-assignment-in-if-condition", "if ((value = read())) use(value);", "if (value == read()) use(value);"),
        ("LEGACY-C-AST-no-conditional-expression", "result = flag ? yes : no;", "result = yes;"),
        ("LEGACY-C-AST-conditional-braces", "result = flag ? left + right : other;", "result = flag ? left : right;"),
        ("LEGACY-C-AST-no-dangerous-macro-in-reg-calls", "RegOpenKeyExW(key, 0, 0, KEY_ALL_ACCESS, &out);", "RegOpenKeyExW(key, 0, 0, KEY_READ, &out);"),
    ] {
        check(rule, source, 1);
        check(rule, safe, 0);
        check(rule, &format!("// {source}\n"), 0);
        check(rule, &format!("/* {source} */"), 0);
        check(rule, &format!("#define NOT_CODE {source}\n"), 0);
        let quoted = source.replace('\\', "\\\\").replace('"', "\\\"");
        check(rule, &format!("const char *text = \"{quoted}\";"), 0);
    }
}

#[test]
fn c_assignment_rules_distinguish_initializer_and_statement_ownership() {
    let outside = "LEGACY-C-AST-no-assignment-outside-statement";
    check(outside, "int value = read(); value = read(); call(value = read());", 0);
    check(outside, "int value = (other = read()); return value = read(); while ((value = read())) {}", 3);
    let in_if = "LEGACY-C-AST-no-assignment-in-if-condition";
    check(in_if, "if ((a = read()) && (b += 1)) use(a); while ((c = read())) {}", 2);
    check(in_if, "if (a == b) { a = b; }", 0);
    let null = "LEGACY-C-AST-nullptr-zero";
    check(null, "int *p = 0;", 1);
    check(null, "int **p = 0; int *a = 0, *b = 0; int (*callback)(void) = 0; int *q = (0);", 0);
}

#[test]
fn c_update_sizeof_and_comma_rules_preserve_ast_contexts() {
    let update = "LEGACY-C-AST-no-unary-in-expressions";
    check(update, "call(value++); result = left + ++right; result = (other++);", 2);
    check(update, "value++; --other;", 0);
    let size = "LEGACY-C-AST-no-side-effect-in-sizeof";
    check(size, "sizeof(read()); sizeof(value = read()); sizeof(other++); sizeof ++last;", 5);
    check(size, "read(); value = read(); other++; sizeof(value + other);", 0);
    let comma = "LEGACY-C-AST-no-comma-expression";
    check(comma, "result = (a, b); return c, d;", 2);
    check(comma, "call(a, (b, c)); for (i = 0, j = 0; i < n; ++i) {} int x = 1, y = 2; int values[] = {1, 2};", 0);
}

#[test]
fn c_conditional_and_registry_rules_keep_nested_boundaries() {
    let conditional = "LEGACY-C-AST-no-conditional-expression";
    check(conditional, "a ? b ? c : d : e;", 2);
    let binary = "LEGACY-C-AST-conditional-braces";
    check(binary, "a + b ? c : d; a ? b + c : d * e;", 3);
    check(binary, "a ? b : c; result = a + b;", 0);
    let registry = "LEGACY-C-AST-no-dangerous-macro-in-reg-calls";
    check(registry, "RegOpenKeyEx(KEY_ALL_ACCESS); RegCreateKeyExA(ALL_ACCESS); SHRegCreateUSKeyW(KEY_ALL_ACCESS);", 3);
    check(registry, "Other(KEY_ALL_ACCESS); RegOpenKeyEx(helper(KEY_ALL_ACCESS)); RegCloseKey(KEY_ALL_ACCESS);", 0);
}

#[test]
fn c_expression_matchers_validate_modes_paths_and_locations() {
    assert_eq!(check("LEGACY-C-AST-no-conditional-expression", "// 中文\nvoid f(void) {\n  value = flag ? a : b;\n}\n", 1), vec![(3, 16)]);
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == "LEGACY-C-AST-no-conditional-expression");
    pack.rules[0].matcher.path_pattern = "\\.h$".into();
    pack.validate().unwrap();
    assert!(pack.scan_text(&Language::C, Path::new("M.c"), "a ? b : c;").is_empty());
    assert_eq!(pack.scan_text(&Language::C, Path::new("M.h"), "a ? b : c;").len(), 1);
    pack.rules[0].matcher.c_style = Some(uniflow_baseline::CStyleCheck::EmptyStatement);
    assert!(pack.validate().is_err());
    pack.rules[0].matcher.c_style = None;
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
}
