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
        let findings = pack.scan_text(&language, Path::new("Declarations.c"), source);
        assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
        coordinates = findings.iter().map(|finding| (finding.line, finding.column)).collect();
        let hir = parse_c_like_file(language, "Declarations.c", source).unwrap();
        let integrated = pack.scan_hir(&hir, &HashMap::from([("Declarations.c".into(), source.into())]));
        assert_eq!(integrated.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>(), coordinates);
    }
    coordinates
}

#[test]
fn migrated_c_declaration_rules_preserve_source_boundaries() {
    for (rule, source, safe) in [
        ("LEGACY-C-AST-void-fn-must-not-return-value", "void f(void) { return 1; }", "void f(void) { return; }"),
        ("LEGACY-C-AST-non-void-fn-must-return", "int f(void) { work(); }", "int f(void) { return 1; }"),
        ("LEGACY-C-AST-non-void-fn-must-return-value", "int f(void) { return; }", "int f(void) { return 1; }"),
        ("LEGACY-C-AST-func-decl-empty", "int f() { return 1; }", "int f(void) { return 1; }"),
        ("LEGACY-C-AST-no-unnamed-argument", "void f(int);", "void f(int named);"),
        ("LEGACY-C-AST-no-unnamed-struct", "struct { int x; } object;", "struct Named { int x; } object;"),
        ("LEGACY-C-AST-no-union-declaration-in-struct", "struct S { union U *p; };", "struct S { int x; }; union U *p;"),
        ("LEGACY-C-AST-array-declaration-must-be-sized", "int a[] = {1, 2};", "int a[2] = {1, 2};"),
        ("LEGACY-C-AST-no-extern-declaration-in-function", "void f(void) { extern int x; }", "extern int x; void f(void) {}"),
        ("LEGACY-C-AST-no-init-in-extern-declaration", "extern int x = 1;", "extern int x;"),
    ] {
        check(rule, source, 1);
        check(rule, safe, 0);
        check(rule, &format!("// {source}\n"), 0);
        check(rule, &format!("/* {source} */"), 0);
        check(rule, &format!("#define NOT_CODE {source}\n"), 0);
        check(rule, &format!("const char *text = \"{source}\";"), 0);
    }
}

#[test]
fn migrated_c_return_rules_preserve_nearest_function_and_raw_predicates() {
    let void = "LEGACY-C-AST-void-fn-must-not-return-value";
    check(void, "void outer(void) { int inner(void) { return 1; } if (x) return 2; }", 1);
    check(void, "void *pointer(void) { return 0; } void f(void) { auto l = []() { return 1; }; return; }", 0);
    check(void, "void f(void) { return /* comment */; }", 1);
    let empty = "LEGACY-C-AST-non-void-fn-must-return-value";
    check(empty, "int f(void) { return /* comment */; }", 0);
    check(empty, "int f(void) { if (x) return; return 1; }", 1);
    let missing = "LEGACY-C-AST-non-void-fn-must-return";
    check(missing, "int outer(void) { int inner(void) { return 1; } }", 1);
    check(missing, "int f(void) { auto l = []() { return 1; }; }", 1);
    check(missing, "int f(void) { if (x) return 1; }", 0);
    check(missing, "struct S f(void) { work(); } void *g(void) { work(); }", 2);
    check(missing, "int prototype(void); int (*callback)(void); void f(void) {}", 0);
}

#[test]
fn migrated_c_parameter_rules_handle_function_pointer_descendants() {
    let unnamed = "LEGACY-C-AST-no-unnamed-argument";
    check(unnamed, "void f(void); void g(int named, char *text, ...);", 0);
    check(unnamed, "void f(int, const char *, int []);", 3);
    check(unnamed, "void f(void (*callback)(int));", 1);
    check(unnamed, "void f(void (*)(int named));", 0);
    check(unnamed, "void f(void (*)(int));", 2);
    let empty = "LEGACY-C-AST-func-decl-empty";
    check(empty, "int prototype(); int (*callback)();", 0);
    check(empty, "void f(/* no parameters */) {} void g(void) {}", 1);
}

#[test]
fn migrated_c_aggregate_array_and_extern_rules_keep_declaration_gates() {
    check("LEGACY-C-AST-no-unnamed-struct", "union { int x; } u; enum { A, B }; typedef struct { int x; } Alias;", 3);
    check("LEGACY-C-AST-no-unnamed-struct", "struct S; union U { int x; }; enum E { A };", 0);
    check("LEGACY-C-AST-no-union-declaration-in-struct", "struct S { union U { int x; } u; struct T { union U *p; } t; };", 2);
    let array = "LEGACY-C-AST-array-declaration-must-be-sized";
    check(array, "extern int a[]; char text[] = \"abc\"; void f(int a[]) {} struct S { int flexible[]; };", 0);
    check(array, "int a[] = {1}, b[] = {2}; int *p[] = {0};", 0);
    check(array, "void f(void) { int a[] = {1, 2}; }", 1);
    check("LEGACY-C-AST-no-extern-declaration-in-function", "struct S { void f(void) { if (x) { extern int a; } } };", 1);
    check("LEGACY-C-AST-no-init-in-extern-declaration", "extern int a = 1, b = 2; extern int c;", 1);
    check("LEGACY-C-AST-no-init-in-extern-declaration", "extern \"C\" { int x = 1; extern int y = 2; }", 1);
}

#[test]
fn c_declaration_matchers_validate_modes_paths_and_source_locations() {
    assert_eq!(check("LEGACY-C-AST-no-extern-declaration-in-function", "// 中文\nvoid f(void) {\n  extern int x;\n}\n", 1), vec![(3, 3)]);
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == "LEGACY-C-AST-no-init-in-extern-declaration");
    pack.rules[0].matcher.path_pattern = "\\.h$".into();
    pack.validate().unwrap();
    assert!(pack.scan_text(&Language::C, Path::new("M.c"), "extern int x = 1;").is_empty());
    assert_eq!(pack.scan_text(&Language::C, Path::new("M.h"), "extern int x = 1;").len(), 1);
    pack.rules[0].matcher.c_macro = Some(uniflow_baseline::CMacroCheck::TrailingSemicolon);
    assert!(pack.validate().is_err());
    pack.rules[0].matcher.c_macro = None;
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
}
