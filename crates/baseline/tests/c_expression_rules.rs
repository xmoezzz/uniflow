use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;

fn check(rule: &str, source: &str, expected: usize) -> Vec<(usize, usize)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let mut coordinates = Vec::new();
    for language in [Language::C, Language::Cpp] {
        let findings = pack.scan_text(&language, Path::new("Expressions.c"), source);
        assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
        coordinates = findings
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect();
        let hir = parse_c_like_file(language, "Expressions.c", source).unwrap();
        let integrated = pack.scan_hir(
            &hir,
            &HashMap::from([("Expressions.c".into(), source.into())]),
        );
        assert_eq!(
            integrated
                .iter()
                .map(|finding| (finding.line, finding.column))
                .collect::<Vec<_>>(),
            coordinates
        );
    }
    coordinates
}

fn check_cpp(rule: &str, source: &str, expected: usize) -> Vec<(usize, usize)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::Cpp, Path::new("Expressions.cpp"), source);
    assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    let hir = parse_c_like_file(Language::Cpp, "Expressions.cpp", source).unwrap();
    let integrated = pack.scan_hir(
        &hir,
        &HashMap::from([("Expressions.cpp".into(), source.into())]),
    );
    assert_eq!(
        integrated
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
    coordinates
}

fn check_c_only(rule: &str, source: &str, expected: usize) -> Vec<(usize, usize)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::C, Path::new("Expressions.c"), source);
    assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    let hir = parse_c_like_file(Language::C, "Expressions.c", source).unwrap();
    let integrated = pack.scan_hir(
        &hir,
        &HashMap::from([("Expressions.c".into(), source.into())]),
    );
    assert_eq!(
        integrated
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
    assert!(
        pack.scan_text(&Language::Cpp, Path::new("Expressions.cpp"), source)
            .is_empty(),
        "{rule} must remain C-only"
    );
    coordinates
}

fn check_cpp_only(rule: &str, source: &str, expected: usize) -> Vec<(usize, usize)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::Cpp, Path::new("Expressions.cpp"), source);
    assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    let hir = parse_c_like_file(Language::Cpp, "Expressions.cpp", source).unwrap();
    let integrated = pack.scan_hir(
        &hir,
        &HashMap::from([("Expressions.cpp".into(), source.into())]),
    );
    assert_eq!(
        integrated
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
    assert!(
        pack.scan_text(&Language::C, Path::new("Expressions.c"), source)
            .is_empty(),
        "{rule} must remain C++-only"
    );
    coordinates
}

#[test]
fn migrated_c_expression_rules_preserve_source_boundaries() {
    for (rule, source, safe) in [
        (
            "LEGACY-C-AST-nullptr-zero",
            "int *pointer = 0;",
            "int *pointer = NULL;",
        ),
        (
            "LEGACY-C-AST-no-assignment-outside-statement",
            "return value = read();",
            "value = read();",
        ),
        (
            "LEGACY-C-AST-no-unary-in-expressions",
            "result = value++ + 1;",
            "value++;",
        ),
        (
            "LEGACY-C-AST-no-side-effect-in-sizeof",
            "size_t n = sizeof(value++);",
            "size_t n = sizeof(value);",
        ),
        (
            "LEGACY-C-AST-no-comma-expression",
            "result = (first, second);",
            "result = call(first, second);",
        ),
        (
            "LEGACY-C-AST-no-assignment-in-if-condition",
            "if ((value = read())) use(value);",
            "if (value == read()) use(value);",
        ),
        (
            "LEGACY-C-AST-no-conditional-expression",
            "result = flag ? yes : no;",
            "result = yes;",
        ),
        (
            "LEGACY-C-AST-conditional-braces",
            "result = flag ? left + right : other;",
            "result = flag ? left : right;",
        ),
        (
            "LEGACY-C-AST-no-dangerous-macro-in-reg-calls",
            "RegOpenKeyExW(key, 0, 0, KEY_ALL_ACCESS, &out);",
            "RegOpenKeyExW(key, 0, 0, KEY_READ, &out);",
        ),
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
fn anzu_pointer_comparison_preserves_relational_type_and_macro_semantics() {
    let rule = "ANZU-POINTER-RELATIONAL-COMPARISON";
    let source = r#"
typedef int *IntPtr;
int *factory(void);
struct Node { int *next; };
int compare(int *left, int *right, int value, struct Node *node) {
    IntPtr alias = left;
    int array1[2];
    int array2[2];
    if (left < right) return 1;
    if ((left + 1) >= right) return 2;
    if (&value > right) return 3;
    if (factory() <= alias) return 4;
    if (node->next < right) return 5;
    if (left == right) return 6;
    if (array1 < array2) return 7;
    if (value < 4) return 8;
    return 0;
}
"#;
    assert_eq!(check(rule, source, 5), vec![(9, 14), (10, 20), (11, 16), (12, 19), (13, 20)]);

    check(
        rule,
        "#define WRAP(value) (value)\nint f(int *a, int *b) { return WRAP(a < b); }",
        0,
    );
    check(
        rule,
        "#define PTR_LT(a, b) ((a) < (b))\nint f(int *a, int *b) { return PTR_LT(a, b); }",
        0,
    );
}

#[test]
fn anzu_pointer_arithmetic_reports_pointer_addition_and_subtraction_only() {
    let rule = "ANZU-POINTER-ARITHMETIC";
    check(
        rule,
        r#"
int f(int *left, int *right, int value, int *__range1) {
    int *a = left + 1;
    int *b = 1 + right;
    int *c = left - 1;
    long distance = right - left;
    int ordinary = value + 1;
    int *synthetic_range = __range1 + 1;
    return *a + *b + *c + (int)distance + ordinary;
}
"#,
        4,
    );
    check(rule, "int f(int left, int right) { return left + right; }", 0);
    check(
        rule,
        "#define PTR_ADD(value) ((value) + 1)\nint f(int *value) { return PTR_ADD(value); }",
        0,
    );
}

#[test]
fn anzu_mixed_type_operation_reports_nonconstant_mismatched_operands() {
    let rule = "ANZU-MIXED-TYPE-OPERATION";
    check(
        rule,
        r#"
int f(int integer, long wider, double floating) {
    int first = integer + wider;
    double second = floating * integer;
    int constant = integer + 1;
    long another_constant = 1 + wider;
    return first + (int)second + constant + (int)another_constant;
}
"#,
        2,
    );
    check(rule, "int f(int left, int right) { return left + right; }", 0);
}

#[test]
fn c_assignment_rules_distinguish_initializer_and_statement_ownership() {
    let outside = "LEGACY-C-AST-no-assignment-outside-statement";
    check(
        outside,
        "int value = read(); value = read(); call(value = read());",
        0,
    );
    check(
        outside,
        "int value = (other = read()); return value = read(); while ((value = read())) {}",
        3,
    );
    let in_if = "LEGACY-C-AST-no-assignment-in-if-condition";
    check(
        in_if,
        "if ((a = read()) && (b += 1)) use(a); while ((c = read())) {}",
        2,
    );
    check(in_if, "if (a == b) { a = b; }", 0);
    let null = "LEGACY-C-AST-nullptr-zero";
    check(null, "int *p = 0;", 1);
    check(
        null,
        "int **p = 0; int *a = 0, *b = 0; int (*callback)(void) = 0; int *q = (0);",
        0,
    );
}

#[test]
fn anzu_assignment_in_condition_covers_all_branch_conditions_only() {
    let rule = "ANZU-ASSIGNMENT-IN-CONDITION";
    check(
        rule,
        "if (a = read()) {} while (b = read()) {} do {} while (c = read()); for (i = 0; d = read(); i = next()) {} switch (e = read()) { default: break; }",
        5,
    );
    check(
        rule,
        "a = read(); if (a == read()) { b = read(); } for (i = read(); i < n; i = next()) {}",
        0,
    );
    check(
        rule,
        "const char *text = \"if (a = read())\"; /* while (b = read()) */",
        0,
    );
}

#[test]
fn c_update_sizeof_and_comma_rules_preserve_ast_contexts() {
    let update = "LEGACY-C-AST-no-unary-in-expressions";
    check(
        update,
        "call(value++); result = left + ++right; result = (other++);",
        2,
    );
    check(update, "value++; --other;", 0);
    let size = "LEGACY-C-AST-no-side-effect-in-sizeof";
    check(
        size,
        "sizeof(read()); sizeof(value = read()); sizeof(other++); sizeof ++last;",
        5,
    );
    check(
        size,
        "read(); value = read(); other++; sizeof(value + other);",
        0,
    );
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
    check(
        registry,
        "Other(KEY_ALL_ACCESS); RegOpenKeyEx(helper(KEY_ALL_ACCESS)); RegCloseKey(KEY_ALL_ACCESS);",
        0,
    );
}

#[test]
fn c_expression_matchers_validate_modes_paths_and_locations() {
    assert_eq!(
        check(
            "LEGACY-C-AST-no-conditional-expression",
            "// 中文\nvoid f(void) {\n  value = flag ? a : b;\n}\n",
            1
        ),
        vec![(3, 16)]
    );
    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|rule| rule.id == "LEGACY-C-AST-no-conditional-expression");
    pack.rules[0].matcher.path_pattern = "\\.h$".into();
    pack.validate().unwrap();
    assert!(pack
        .scan_text(&Language::C, Path::new("M.c"), "a ? b : c;")
        .is_empty());
    assert_eq!(
        pack.scan_text(&Language::C, Path::new("M.h"), "a ? b : c;")
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
fn anzu_add_subtract_assignment_is_operator_and_function_body_aware() {
    let source = r#"
#define UPDATE(value) value += 1
const char *text = "value -= 1";
void demo(int value) {
    value += 1;
    value -= 2;
    value *= 3;
    value = value + 1;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("compound_assignment.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NO-ADD-SUBTRACT-ASSIGNMENT")
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![(5, 11), (6, 11)], "{findings:#?}");
}

#[test]
fn anzu_comma_expression_preserves_decl_for_and_call_traversal_boundaries() {
    let source = r#"
void demo(int condition) {
    int skipped = (first(), second());
    call(left, right);
    call((left, right));
    for (first(), second(); condition ? (left, right) : 0; first(), second()) {
        return left, right;
    }
}
"#;
    assert_eq!(
        check("ANZU-COMMA-OPERATOR", source, 3),
        vec![(5, 11), (6, 42), (7, 16)]
    );
}

#[test]
fn anzu_bool_switch_resolves_boolean_names_literals_and_calls() {
    let source = r#"
bool ready(void) { return true; }
void demo(bool flag, int count) {
    switch (flag) { default: break; }
    switch ((flag)) { default: break; }
    switch (ready()) { default: break; }
    switch (true) { default: break; }
    switch (count) { default: break; }
    switch (flag + 1) { default: break; }
}
"#;
    assert_eq!(
        check("ANZU-BOOLEAN-SWITCH-CONDITION", source, 4),
        vec![(4, 13), (5, 14), (6, 13), (7, 13)]
    );
}

#[test]
fn anzu_loop_control_rejects_globals_and_honors_local_shadowing() {
    let source = r#"
int global;
void demo(int parameter) {
    int local = 0;
    while (global) {}
    while (!global) {}
    do {} while (global);
    for (; global < 10; ++global) {}
    while (local) {}
    while (parameter) {}
    while (global && local) {}
}
void shadow(void) { int global = 0; while (global) {} }
"#;
    assert_eq!(
        check("ANZU-GLOBAL-LOOP-CONTROL", source, 4),
        vec![(5, 12), (6, 13), (7, 18), (8, 12)]
    );
}

#[test]
fn anzu_for_initializer_rules_resolve_float_and_storage_owners() {
    let source = r#"
double global_step;
int global_index;
void demo(float parameter) {
    int local_index;
    for (float value = 0.0f; value < 1.0f; ++value) {}
    for (global_step = 0.0; global_step < 1.0; global_step += 0.1) {}
    for (parameter = 0.0f; parameter < 1.0f; parameter += 0.1f) {}
    for (global_index = 0; global_index < 10; ++global_index) {}
    for (local_index = 0; local_index < 10; ++local_index) {}
}
"#;
    check("ANZU-FLOATING-FOR-INITIALIZER", source, 3);
    check("ANZU-NONLOCAL-FOR-INITIALIZER", source, 3);
}

#[test]
fn anzu_c_style_cast_uses_balanced_known_type_names_in_cpp_files() {
    let source = r#"
typedef unsigned Count;
struct Widget { int value; };
void demo(void *raw, int value) {
    int number = (int)value;
    Widget *widget = (Widget *)raw;
    Count count = (const Count)(value);
    int grouped = (value);
    if (value) {}
    int modern = static_cast<int>(value);
}
"#;
    let pack = builtin_security_pack().expect("pack");
    let findings = pack.scan_text(&Language::Cpp, Path::new("casts.cpp"), source);
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-NO-C-STYLE-CAST")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![5, 6, 7], "{findings:#?}");
    assert!(pack
        .scan_text(&Language::C, Path::new("casts.c"), source)
        .iter()
        .all(|finding| finding.rule_id != "ANZU-CPP-NO-C-STYLE-CAST"));
}

#[test]
fn anzu_sizeof_array_parameter_uses_original_parameter_declarator() {
    let source = r#"
void demo(int values[8], int matrix[][4], int *pointer) {
    consume(sizeof(values));
    consume(sizeof values);
    consume(sizeof((values)));
    consume(sizeof(matrix));
    consume(sizeof(values[0]));
    consume(sizeof(pointer));
    consume(sizeof(int[8]));
}
"#;
    check("ANZU-SIZEOF-ARRAY-PARAMETER", source, 4);
}

#[test]
fn anzu_in_band_error_result_requires_a_direct_add_assign_rhs_call() {
    let source = r#"
void demo(int fd, char *buffer, int total) {
    total += read(fd, buffer, 8);
    total += (snprintf(buffer, 8, "%s", "x"));
    total += strcpy(buffer, "x");
    total += strcpy_s(buffer, 8, "x");
    total += sprintf(buffer, "%s", "x");
    total = read(fd, buffer, 8);
    total += read(fd, buffer, 8) + 1;
    total += object.read(fd, buffer, 8);
    total += io::read(fd, buffer, 8);
}
"#;
    check("ANZU-NO-IN-BAND-ERROR-ADD-ASSIGN", source, 5);
}

#[test]
fn anzu_ctype_calls_resolve_plain_char_first_arguments() {
    let source = r#"
char global_character;
void demo(char character, unsigned char safe, signed char explicit_signed, int number) {
    isalpha(character);
    tolower((global_character));
    isdigit(safe);
    isspace(explicit_signed);
    isupper(number);
    isprint((unsigned char)character);
    object.isalpha(character);
    locale::tolower(character);
}
"#;
    check("ANZU-CTYPE-PLAIN-CHAR-ARGUMENT", source, 2);
    check(
        "ANZU-CTYPE-PLAIN-CHAR-ARGUMENT",
        "void demo(char value) { int (*isalpha)(int); isalpha(value); }",
        0,
    );
}

#[test]
fn anzu_abort_after_exit_registration_preserves_translation_unit_state() {
    let source = r#"
void before(void) { abort(); }
void cleanup(void) {}
void setup(void) { atexit(cleanup); }
void after(int condition) {
    assert(condition);
    abort();
    object.abort();
    process::abort();
}
"#;
    check("ANZU-ABORT-AFTER-EXIT-REGISTRATION", source, 2);
    check(
        "ANZU-ABORT-AFTER-EXIT-REGISTRATION",
        "void demo(void) { void (*abort)(void); atexit(cleanup); abort(); }",
        0,
    );
}

#[test]
fn anzu_character_relations_are_limited_to_direct_branch_operands() {
    let source = r#"
void demo(int value) {
    if (value < 'a') {}
    while (('z') >= value) {}
    for (; value > '0'; ) {}
    if (value < 10) {}
    if (value + 'a' < 10) {}
    if (value < 'a' + 1) {}
    value = value < 'x';
}
"#;
    check("ANZU-CHARACTER-LITERAL-RELATION", source, 3);
}

#[test]
fn anzu_prefer_prefix_only_matches_root_postfix_update_expressions() {
    let source = r#"
void demo(int condition, int value) {
    value++;
    --value;
    result = value++;
    consume(value++);
    if (condition) value++;
    for (; condition; value++) {}
    while (condition) { value--; }
    (value++);
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("postfix.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-PREFER-PREFIX-UPDATE")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![3, 7, 8, 9], "{findings:#?}");
}

#[test]
fn anzu_enum_comparisons_require_the_same_enum_type() {
    let source = r#"
enum Color { Red, Blue };
enum Shape { Circle };
void demo(enum Color color, enum Shape shape) {
    int same = color == Red;
    int other = color == shape;
    int integer = color != 0;
    int constants = Red < Circle;
    int ordinary = same == integer;
}
"#;
    assert_eq!(
        check("ANZU-ENUM-COMPATIBLE-COMPARISON", source, 3),
        vec![(6, 23), (7, 25), (8, 25)]
    );
}

#[test]
fn anzu_enum_values_are_not_assigned_to_non_enum_objects() {
    let source = r#"
enum Color { Red, Blue };
void demo(enum Color color) {
    int raw = color;
    raw = Red;
    color = Blue;
    enum Color copy = color;
    raw += color;
    int ordinary = raw;
}
"#;
    assert_eq!(
        check("ANZU-ENUM-VALUE-TO-NONENUM", source, 2),
        vec![(4, 13), (5, 9)]
    );
}

#[test]
fn anzu_unscoped_enum_casts_must_stay_inside_declared_range() {
    let source = r#"
enum Level { Low = -2, Normal = 0, High = 3 };
enum class Scoped { First = 1, Last = 2 };
void demo(int value, enum Level level) {
    level = (enum Level)2;
    level = (Level)9;
    level = static_cast<Level>(-2);
    level = static_cast<Level>(4);
    level = static_cast<Level>(value);
    level = (Level)level;
    Scoped scoped = static_cast<Scoped>(99);
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("enum_casts.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ENUM-CAST-RANGE")
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![(6, 13), (8, 13), (9, 13)], "{findings:#?}");
}

#[test]
fn anzu_sizeof_rejects_only_a_root_assignment_expression() {
    let source = r#"
void demo(int value) {
    int first = sizeof(value = 1);
    int second = sizeof((value += 2));
    int nested = sizeof(value + (value = 3));
    int update = sizeof(value++);
    int type = sizeof(int);
}
"#;
    assert_eq!(
        check("ANZU-ASSIGNMENT-IN-SIZEOF", source, 2),
        vec![(3, 17), (4, 18)]
    );
}

#[test]
fn anzu_allocation_calls_on_binary_rhs_require_an_immediate_cast() {
    let source = r#"
void demo(void *pointer, int size) {
    pointer = malloc(size);
    pointer = (void *)malloc(size);
    pointer = calloc(2, size);
    pointer = aligned_alloc(16, size);
    pointer = realloc(pointer, size);
    pointer = object.malloc(size);
    pointer = malloc(size) + 1;
}
"#;
    assert_eq!(
        check("ANZU-ALLOC-RESULT-EXPLICIT-CAST", source, 4),
        vec![(3, 15), (5, 15), (6, 15), (7, 15)]
    );
}

#[test]
fn anzu_bitwise_operators_reject_either_boolean_operand() {
    let source = r#"
void demo(bool flag, int number) {
    int first = flag & number;
    int second = number | flag;
    int third = flag ^ false;
    int logical = flag && flag;
    int ordinary = number & 1;
}
"#;
    assert_eq!(
        check("ANZU-BITWISE-BOOLEAN-OPERAND", source, 3),
        vec![(3, 22), (4, 25), (5, 22)]
    );
}

#[test]
fn anzu_boolean_arithmetic_preserves_the_two_legacy_operator_sets() {
    let source = r#"
void demo(bool flag) {
    int add = flag + 1;
    int subtract = 1 - flag;
    int shift = flag << 1;
    int multiply = flag * 2;
    flag++;
    int logical = flag && true;
}
"#;
    assert_eq!(
        check("ANZU-BOOL-ADD-SHIFT-UPDATE", source, 4),
        vec![(3, 20), (4, 22), (5, 22), (7, 5)]
    );
    assert_eq!(
        check("ANZU-BOOLEAN-ARITHMETIC", source, 5),
        vec![(3, 20), (4, 22), (5, 22), (6, 25), (7, 5)]
    );
}

#[test]
fn anzu_floating_equality_preserves_either_operand_and_left_operand_variants() {
    let source = r#"
void demo(float left, double right, int number) {
    int first = left == right;
    int second = number != left;
    int relation = left < right;
    int ordinary = number == 0;
}
"#;
    assert_eq!(
        check("ANZU-FLOAT-EQUALITY-EITHER-OPERAND", source, 2),
        vec![(3, 22), (4, 25)]
    );
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|rule| rule.id == "ANZU-C-FLOAT-EQUALITY-LEFT-OPERAND");
    let findings = pack.scan_text(&Language::C, Path::new("float.c"), source);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(3, 22)],
        "{findings:#?}"
    );
}

#[test]
fn anzu_unsigned_zero_and_mixed_signedness_comparisons_are_type_aware() {
    let source = r#"
void demo(unsigned int value, int signed_value, unsigned int other) {
    int first = value >= 0;
    int second = 0 <= value;
    int third = value < 0;
    int fourth = 0 > value;
    int safe = value > 0;
    int mixed = value < signed_value;
    int reverse = signed_value == other;
    int literal = value < 1;
}
"#;
    assert_eq!(
        check("ANZU-UNSIGNED-COMPARED-WITH-ZERO", source, 4),
        vec![(3, 23), (4, 20), (5, 23), (6, 20)]
    );
    assert_eq!(
        check("ANZU-MIXED-SIGNEDNESS-COMPARISON", source, 2),
        vec![(8, 23), (9, 32)]
    );
}

#[test]
fn anzu_relational_operators_reject_boolean_operands() {
    let source = r#"
void demo(bool flag, int number) {
    int first = flag < number;
    int second = number >= flag;
    int equality = flag == true;
    int ordinary = number < 2;
}
"#;
    assert_eq!(
        check("ANZU-BOOLEAN-RELATIONAL-COMPARISON", source, 2),
        vec![(3, 22), (4, 25)]
    );
}

#[test]
fn anzu_enum_switch_requires_default_only_when_cases_are_incomplete() {
    let source = r#"
enum Color { Red, Green, Blue };
void demo(enum Color color, int number) {
    switch (color) { case Red: break; case Green: break; }
    switch (color) { case Red: break; case Green: break; case Blue: break; }
    switch (color) { case Red: break; default: break; }
    switch (number) { case 1: break; }
    switch (color) {
        case Red: switch (number) { case 1: break; case 2: break; } break;
        case Green: break;
    }
}
"#;
    assert_eq!(
        check("ANZU-INCOMPLETE-ENUM-SWITCH", source, 2),
        vec![(4, 5), (8, 5)]
    );
}

#[test]
fn anzu_updates_are_reported_only_as_direct_binary_or_call_operands() {
    let source = r#"
void consume(int value, int other);
void demo(int value, int other) {
    int first = value++ + other;
    int second = other * --value;
    consume(value++, other);
    consume(other, (++value));
    value++;
    first = value++;
    value++, other++;
    consume(value++ + other, other);
}
"#;
    assert_eq!(
        check("ANZU-UPDATE-AS-OPERAND", source, 5),
        vec![(4, 22), (5, 26), (6, 18), (7, 21), (11, 18)]
    );
}

#[test]
fn anzu_void_cast_is_redundant_only_for_a_direct_void_call() {
    let source = r#"
void cleanup(void);
int compute(void);
void demo(int value) {
    (void)cleanup();
    static_cast<void>(cleanup());
    (void)compute();
    (void)value;
    cleanup();
    (void)(cleanup(), value);
}
"#;
    assert_eq!(
        check("ANZU-REDUNDANT-VOID-CALL-CAST", source, 2),
        vec![(5, 5), (6, 5)]
    );
}

#[test]
fn anzu_noop_conversion_compares_canonical_source_and_destination_types() {
    let source = r#"
void demo(int value, unsigned int other, int *pointer) {
    int first = (int)value;
    int second = static_cast<signed int>(value);
    unsigned int changed = (unsigned int)value;
    long widened = (long)1;
    int *same_pointer = (int *)pointer;
    void *changed_pointer = (void *)pointer;
    int not_same = (int)other;
}
"#;
    assert_eq!(
        check("ANZU-NOOP-EXPLICIT-CONVERSION", source, 3),
        vec![(3, 17), (4, 18), (7, 25)]
    );
}

#[test]
fn anzu_pointer_integer_casts_are_bidirectional_and_type_aware() {
    let source = r#"
void demo(int value, int *pointer) {
    void *first = (void *)value;
    int second = (int)pointer;
    int *third = reinterpret_cast<int *>(value);
    char *pointer_only = (char *)pointer;
    long integer_only = (long)value;
}
"#;
    assert_eq!(
        check("ANZU-POINTER-INTEGER-EXPLICIT-CAST", source, 3),
        vec![(3, 19), (4, 18), (5, 18)]
    );
}

#[test]
fn anzu_forced_c_style_pointer_cast_exempts_zero_and_pointer_sources() {
    let source = r#"
void demo(int value, int *pointer) {
    int *first = (int *)value;
    int *null_value = (int *)0;
    int *named = reinterpret_cast<int *>(value);
    void *pointer_source = (void *)pointer;
}
"#;
    assert_eq!(
        check("ANZU-FORCED-CSTYLE-POINTER-CAST", source, 1),
        vec![(3, 18)]
    );
}

#[test]
fn anzu_pointer_type_cast_rejects_incompatible_nonconstant_nonvoid_conversions() {
    let source = r#"
void demo(int value, int *integers, char *characters, void *generic) {
    char *different = (char *)integers;
    void *to_void = (void *)integers;
    char *from_void = (char *)generic;
    int *from_integer = (int *)value;
    int *constant = (int *)1;
    int to_integer = (int)integers;
    int *same = (int *)integers;
}
"#;
    assert_eq!(
        check("ANZU-UNSAFE-POINTER-TYPE-CAST", source, 3),
        vec![(3, 23), (6, 25), (8, 22)]
    );
}

#[test]
fn anzu_pointer_assignment_pointer_checker_preserves_bitcast_and_pointee_exemptions() {
    let source = r#"
#define WRAP(value) value
struct A { int value; };
struct B { int value; };
void demo(int *integers, char *characters, void *generic, struct A *a, struct B *b, int **integer_rows, char **character_rows) {
    characters = (char *)integers;
    characters = ((char *)integers);
    characters = (char *)characters;
    generic = (void *)integers;
    integers = (int *)generic;
    b = (struct B *)a;
    character_rows = (char **)integer_rows;
    WRAP(characters = (char *)integers);
    char *initialized = (char *)integers;
}
"#;
    assert_eq!(
        check("ANZU-POINTER-ASSIGNMENT-POINTER-MISMATCH", source, 3),
        vec![(6, 16), (7, 16), (12, 20)]
    );

    let cpp_source = r#"
void demo(int *integers, char *characters, void *generic) {
    characters = reinterpret_cast<char *>(integers);
    characters = const_cast<char *>(characters);
    generic = static_cast<void *>(integers);
    integers = static_cast<int *>(generic);
}
"#;
    assert_eq!(
        check_cpp(
            "ANZU-POINTER-ASSIGNMENT-POINTER-MISMATCH",
            cpp_source,
            1,
        ),
        vec![(3, 16)]
    );
}

#[test]
fn anzu_unpointer_and_pointer_assign_requires_explicit_integer_pointer_conversion() {
    let source = r#"
#define APPLY(value) (value)
int *returns_pointer(void);
int returns_integer(void);

void exercise(int *pointer, int integer) {
    int *bad_pointer_init = 7;
    int bad_integer_init = pointer;
    int *zero_init = 0;
    int *paren_zero_init = (0);
    int *explicit_pointer_init = (int *)integer;
    int explicit_integer_init = (int)pointer;
    int *same_pointer_init = pointer;
    int same_integer_init = integer;

    pointer = 9;
    integer = pointer;
    pointer = 0;
    pointer = (0);
    pointer = (int *)integer;
    integer = (int)pointer;
    pointer = pointer;
    integer = integer;
    pointer += 1;
    APPLY(pointer = 11);
    integer = returns_pointer();
    pointer = returns_integer();
}
"#;
    assert_eq!(
        check("ANZU-UNPOINTER-AND-POINTER-ASSIGN", source, 6),
        vec![(7, 29), (8, 28), (16, 15), (17, 15), (26, 15), (27, 15)]
    );

    let cpp = r#"
void exercise(int *pointer, long integer) {
    int *pointer_init = reinterpret_cast<int *>(integer);
    long integer_init = reinterpret_cast<long>(pointer);
    pointer = reinterpret_cast<int *>(integer);
    integer = reinterpret_cast<long>(pointer);
}
"#;
    assert!(
        check_cpp("ANZU-UNPOINTER-AND-POINTER-ASSIGN", cpp, 0).is_empty()
    );
}

#[test]
fn anzu_assignment_safety_matches_only_overloaded_assignment_address_of_pointer_arguments() {
    let source = r#"
#define APPLY(value) value
struct Box {
    Box& operator=(int **value) { return *this; }
    Box& operator+=(int **value) { return *this; }
};
void demo(Box &box, int *pointer, int integer, int **rows) {
    box = &pointer;
    box = (&pointer);
    box = &integer;
    rows = &pointer;
    box += &pointer;
    APPLY(box = &pointer);
}
"#;
    assert_eq!(
        check_cpp("ANZU-CPP-ASSIGNMENT-SAFETY", source, 2),
        vec![(8, 11), (9, 12)]
    );

    let builtin_only = r#"
void demo(int *pointer, int **rows) {
    rows = &pointer;
}
"#;
    assert!(check_cpp("ANZU-CPP-ASSIGNMENT-SAFETY", builtin_only, 0).is_empty());
}

#[test]
fn anzu_static_cast_between_distinct_record_pointers_prefers_dynamic_cast() {
    let source = r#"
class Base {};
class Derived : public Base {};
class Other {};
void demo(Base *base, Derived *derived, int *number) {
    Derived *down = static_cast<Derived *>(base);
    Base *up = static_cast<Base *>(derived);
    Base *same = static_cast<Base *>(base);
    Other *other = reinterpret_cast<Other *>(base);
    long *ordinary = static_cast<long *>(number);
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("record_casts.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-STATIC-RECORD-POINTER-CAST")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![6, 7], "{findings:#?}");
}

#[test]
fn anzu_sizeof_reports_one_finding_for_any_assignment_or_update_in_argument() {
    let source = r#"
void demo(int value) {
    int assignment = sizeof(value = 1);
    int update = sizeof(value++);
    int nested = sizeof(value + (++value));
    int multiple = sizeof((value = 2) + value++);
    int call = sizeof(work());
    int type = sizeof(int);
}
"#;
    assert_eq!(
        check("ANZU-SIDE-EFFECTING-SIZEOF", source, 4),
        vec![(3, 29), (4, 25), (5, 25), (6, 27)]
    );
}

#[test]
fn anzu_string_literals_do_not_initialize_explicit_signedness_char_storage() {
    let source = r#"
void demo(void) {
    signed char signed_array[] = "text";
    unsigned char *unsigned_pointer = "text";
    char ordinary[] = "text";
    signed char scalar = 'x';
    signed char *target;
    target = "other";
}
"#;
    assert_eq!(
        check("ANZU-EXPLICIT-CHAR-SIGNEDNESS-STRING", source, 3),
        vec![(3, 34), (4, 39), (8, 14)]
    );
}

#[test]
fn anzu_signed_odd_even_checks_do_not_assume_signed_integer_representation() {
    let source = r#"
void demo(int value, int ready) {
    if ((value & 1) == 0) work();
    while (1 != (1 & value)) work();
    for (; (value & 1) != 1; ++value) work();
    if ((value & 2) == 0) work();
    if ((1 & 3) == 1) work();
    if (((value & 1) == 0) && ready) work();
    if ((value | 1) == 0) work();
    if ((value & 1) < 1) work();
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-SIGNED-ODD-EVEN-REPRESENTATION");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::C, Path::new("odd_even.c"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(3, 9), (4, 12), (5, 12)]);
    assert!(pack
        .scan_text(&Language::Cpp, Path::new("odd_even.cpp"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::C, "odd_even.c", source).expect("C HIR");
    assert_eq!(
        pack.scan_hir(&hir, &HashMap::from([("odd_even.c".into(), source.into())]))
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_allocation_lengths_use_sizeof_instead_of_only_constants() {
    let source = r#"
void demo(unsigned count, void *old) {
    int *single = (int *)malloc(128);
    int *array = (int *)calloc(count, 32 * 4);
    int *grown = (int *)realloc(old, (64 + 64));
    int *sized = (int *)malloc(sizeof(int) * 4);
    int *dynamic = (int *)malloc(count * 4);
    int *uncast = malloc(128);
    long raw = (long)malloc(128);
    int *nested = (int *)(malloc(128));
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-ALLOCATION-LENGTH-USE-SIZEOF");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::C, Path::new("allocation.c"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(3, 33), (4, 39), (5, 38)]);
    assert!(pack
        .scan_text(&Language::Cpp, Path::new("allocation.cpp"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::C, "allocation.c", source).expect("C HIR");
    assert_eq!(
        pack.scan_hir(
            &hir,
            &HashMap::from([("allocation.c".into(), source.into())])
        )
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_constant_value_logical_not_requires_an_integer_literal_operand() {
    let source = r#"
int global = !0;
void demo(int value) {
    int zero = !0;
    int parenthesized = !(42);
    int expression = !(1 == 1);
    int unary = !+1;
    int variable = !value;
    int nested = !!0;
}
"#;
    assert_eq!(
        check("ANZU-LOGICAL-NOT-INTEGER-LITERAL", source, 3),
        vec![(4, 16), (5, 25), (9, 19)]
    );
}

#[test]
fn anzu_string_literals_require_pointers_to_const_char() {
    let source = r#"
char *global = "global";
const char *safe_global = "safe";
void demo(void) {
    char *local = ("local");
    const char *safe = "safe";
    char array[] = "array";
    char *target;
    const char *const_target;
    target = "assigned";
    const_target = "safe";
}
"#;
    assert_eq!(
        check("ANZU-STRING-LITERAL-REQUIRES-CONST-CHAR-POINTER", source, 3),
        vec![(2, 16), (5, 20), (10, 12)]
    );
}

#[test]
fn anzu_does_not_concatenate_narrow_and_wide_string_literals() {
    let source = r#"
void demo(void) {
    const void *first = "narrow" L"wide";
    const void *narrow = "one" "two";
    const void *wide = L"one" L"two";
    const void *target;
    target = L"wide" "narrow";
    consume("narrow" L"wide");
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-MIXED-STRING-LITERAL-CONCATENATION");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::C, Path::new("strings.c"), source);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(3, 25), (7, 14)]
    );
    assert!(pack
        .scan_text(&Language::Cpp, Path::new("strings.cpp"), source)
        .is_empty());
}

#[test]
fn anzu_function_addresses_are_not_used_as_values_in_binary_conditions() {
    let source = r#"
int probe(void);
int other(void);
void demo(void) {
    if (probe) work();
    if (!probe) work();
    if (probe == 0) work();
    int sum = probe + other;
    int called = probe() + other();
    consume(probe);
}
"#;
    assert_eq!(
        check("ANZU-MISUSED-FUNCTION-ADDRESS", source, 4),
        vec![(6, 10), (7, 9), (8, 15), (8, 23)]
    );
}

#[test]
fn anzu_cpp_large_step_for_loops_use_relational_termination() {
    let source = r#"
void demo(int limit) {
    for (int i = 0; i != limit; i += 2) work(i);
    for (int j = 0; limit == j; j = j - 3) work(j);
    for (int k = 0; k < limit; k += 2) work(k);
    for (int m = 0; m != limit; ++m) work(m);
    for (int n = 0; n != limit; n += 1) work(n);
    for (int p = 0; p != limit; p = 2 + p) work(p);
    for (int q = 0; q != limit; limit += 4) work(q);
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-CPP-EQUALITY-LOOP-LARGE-STEP");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::Cpp, Path::new("loops.cpp"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(3, 23), (4, 27), (9, 23)]);
    assert!(pack
        .scan_text(&Language::C, Path::new("loops.c"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::Cpp, "loops.cpp", source).expect("C++ HIR");
    assert_eq!(
        pack.scan_hir(
            &hir,
            &HashMap::from([("loops.cpp".into(), source.into())])
        )
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_function_pointer_assignment_uses_explicit_address_of() {
    let source = r#"
int work(void);
void demo(void) {
    int (*pointer)(void);
    pointer = work;
    pointer = (work);
    pointer = &work;
    pointer = work();
    pointer = work + 0;
    int (*initialized)(void) = work;
}
"#;
    assert_eq!(
        check("ANZU-FUNCTION-POINTER-EXPLICIT-ADDRESS", source, 2),
        vec![(5, 13), (6, 13)]
    );
}

#[test]
fn anzu_pointer_parameters_are_not_reassigned() {
    let source = r#"
void demo(int *pointer, int value, int array[]) {
    pointer = 0;
    value = 0;
    array = 0;
    *pointer = 1;
    pointer += 1;
    {
        int *pointer;
        pointer = 0;
    }
    pointer = 0;
}
"#;
    assert_eq!(
        check("ANZU-POINTER-PARAMETER-ASSIGNMENT", source, 3),
        vec![(3, 13), (5, 11), (12, 13)]
    );
}

#[test]
fn anzu_builtin_limit_macros_are_not_used_in_branch_comparisons() {
    let source = r#"
void demo(int value, int other) {
    if (value < INT_MAX) work();
    while (LONG_MIN >= value) work();
    for (; value <= UINT_MAX; ++value) work();
    if (value < INT_MAX && other > LONG_MAX) work();
    int limit = INT_MAX;
    consume(INT_MAX);
    if (value < INT_MAX - 1) work();
    if ((INT_MAX) > value) work();
    if (value + INT_MAX < other) work();
    if (value < PROJECT_INT_MAX) work();
}
"#;
    assert_eq!(
        check("ANZU-BUILTIN-LIMIT-MACRO-CONDITION", source, 4),
        vec![(3, 17), (4, 12), (5, 21), (6, 17)]
    );
}

#[test]
fn anzu_relational_and_equality_operators_are_nonassociative() {
    let source = r#"
int demo(int a, int b, int c) {
    int first = a < b < c;
    int second = a == (b < c);
    int third = (a < b) == c;
    int fourth = a != b == c;
    int safe_logic = a < b && b < c;
    int safe_arithmetic = a + b < c;
    int safe_group = (a + b) < c;
    return first + second + third + fourth + safe_logic + safe_arithmetic + safe_group;
}
"#;
    assert_eq!(
        check("ANZU-NONASSOCIATIVE-COMPARISON", source, 4),
        vec![(3, 23), (4, 20), (5, 25), (6, 25)]
    );
}

#[test]
fn anzu_mixed_bitwise_expressions_require_parentheses() {
    let source = r#"
int demo(int a, int b, int c) {
    int left_arithmetic = a + b & c;
    int right_arithmetic = a & b + c;
    int left_comparison = a == b & c;
    int right_comparison = a & b == c;
    int safe_left = (a + b) & c;
    int safe_right = a & (b + c);
    int safe_bitwise = a & b | c;
    int safe_logic = a && (b & c);
    return left_arithmetic + right_arithmetic + left_comparison + right_comparison
        + safe_left + safe_right + safe_bitwise + safe_logic;
}
"#;
    assert_eq!(
        check("ANZU-BITWISE-MIXED-EXPRESSION-PARENTHESES", source, 4),
        vec![(3, 33), (4, 30), (5, 34), (6, 30)]
    );
}

#[test]
fn anzu_shift_on_char_or_short_accounts_for_integer_promotion() {
    let source = r#"
int source(unsigned short value);
int demo(char byte, signed char signed_byte, unsigned short small, int value) {
    int first = byte << 1;
    int second = signed_byte << 2;
    int third = (small) >> 2;
    int fourth = ~byte << 3;
    int explicit_promotion = (int)byte << 1;
    int compound = (byte + 1) << 1;
    int call_result = source(small) << 1;
    int full_width = value << 1;
    return first + second + third + fourth + explicit_promotion + compound + call_result + full_width;
}
"#;
    assert_eq!(
        check("ANZU-SHIFT-SMALL-INTEGER", source, 4),
        vec![(4, 17), (5, 18), (6, 18), (7, 19)]
    );
}

#[test]
fn anzu_eof_comparison_tracks_character_input_values() {
    let source = r#"
int demo(void *stream) {
    int ch = getchar();
    if (ch == EOF) work();
    int copy = ch;
    if (WEOF != copy) work();
    ch = 0;
    if (ch == EOF) work();
    if (getchar() != EOF) work();
    int wide = getwc(stream);
    if (wide == WEOF) work();
    int safe = read_character();
    if (safe == EOF) work();
    if (wide < WEOF) work();
    return copy;
}
"#;
    assert_eq!(
        check("ANZU-EOF-CHARACTER-INPUT-COMPARISON", source, 4),
        vec![(4, 12), (6, 14), (9, 19), (11, 14)]
    );
}

#[test]
fn anzu_unget_tracks_each_stream_independently() {
    let source = r#"
void demo(void *stream, void *other) {
    ungetc('a', stream);
    ungetc('b', (stream));
    ungetc('c', stream);
    ungetc('x', other);
    ungetwc('y', other);
    ungetc('z', other);
    ungetc('q');
    object.ungetc('r', stream);
}
"#;
    assert_eq!(
        check("ANZU-MULTIPLE-UNGET-SAME-STREAM", source, 2),
        vec![(4, 18), (7, 18)]
    );
}

#[test]
fn anzu_cpp_classes_use_new_and_delete_instead_of_c_allocation() {
    let source = r#"
class Widget {};
struct Pod {};
void demo(Widget *widget, Pod *pod) {
    free(widget);
    free(pod);
    Widget *first = (Widget*)malloc(sizeof(Widget));
    Pod *plain = (Pod*)malloc(sizeof(Pod));
    Widget *second = reinterpret_cast<Widget*>(malloc(sizeof(Widget)));
    free((widget));
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-CPP-RAW-ALLOCATION-FOR-CLASS");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::Cpp, Path::new("allocation.cpp"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(5, 10), (7, 30), (9, 48), (10, 11)]);
    assert!(pack
        .scan_text(&Language::C, Path::new("allocation.c"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::Cpp, "allocation.cpp", source).expect("C++ HIR");
    assert_eq!(
        pack.scan_hir(
            &hir,
            &HashMap::from([("allocation.cpp".into(), source.into())])
        )
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_cpp_std_set_uses_its_find_member() {
    let source = r#"
void demo(void) {
    std::set<int> values;
    std::vector<int> sequence;
    custom::set<int> custom_values;
    auto first = std::find(values.begin(), values.end(), 7);
    auto second = std::find((values.begin()), values.end(), 8);
    auto vector_result = std::find(sequence.begin(), sequence.end(), 7);
    auto custom_result = std::find(custom_values.begin(), custom_values.end(), 7);
    auto member_result = values.find(7);
    auto short_call = std::find(values.begin(), values.end());
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-CPP-STD-FIND-ON-SET");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::Cpp, Path::new("find.cpp"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(6, 28), (7, 30)]);
    assert!(pack
        .scan_text(&Language::C, Path::new("find.c"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::Cpp, "find.cpp", source).expect("C++ HIR");
    assert_eq!(
        pack.scan_hir(&hir, &HashMap::from([("find.cpp".into(), source.into())]))
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_c_exit_handlers_return_normally_across_callees() {
    let source = r#"
void terminate_nested(void) { quick_exit(2); }
void indirect_handler(void) { terminate_nested(); }
void jump_handler(void) { longjmp(environment, 1); }
void safe_leaf(void) { work(); }
void recursive_b(void);
void recursive_a(void) { recursive_b(); }
void recursive_b(void) { recursive_a(); safe_leaf(); }
void demo(void) {
    atexit(indirect_handler);
    at_quick_exit(jump_handler);
    atexit(safe_leaf);
    atexit(recursive_a);
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-C-EXIT-HANDLER-NORMAL-RETURN");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::C, Path::new("handlers.c"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(2, 31), (4, 27)]);
    assert!(pack
        .scan_text(&Language::Cpp, Path::new("handlers.cpp"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::C, "handlers.c", source).expect("C HIR");
    assert_eq!(
        pack.scan_hir(&hir, &HashMap::from([("handlers.c".into(), source.into())]))
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_time_t_values_are_not_manipulated_directly() {
    let source = r#"
void demo(time_t start, time_t end, int delta) {
    time_t first = start + delta;
    time_t second = delta + end;
    start += delta;
    end -= 1;
    int safe_integer = delta + 1;
    time_t safe_product = start * 2;
    int safe_compare = start < end;
}
"#;
    assert_eq!(
        check("ANZU-TIME-T-DIRECT-ARITHMETIC", source, 4),
        vec![(3, 20), (4, 29), (5, 5), (6, 5)]
    );
}

#[test]
fn anzu_magic_numbers_preserve_literal_and_constant_semantics() {
    let numeric_literals = r#"
void demo(void) {
    int five = 5;
    int six = 6;
    int seven = 7;
    int eight = 8;
    double fraction = 2.5;
    double hundred = 100.0;
}
"#;
    assert_eq!(
        check("ANZU-MAGIC-NUMBER", numeric_literals, 4),
        vec![(3, 16), (4, 15), (5, 17), (7, 23)]
    );

    let constant_contexts = r#"
void demo(void) {
    const int named = 42;
    int const also_named = 43;
    enum Local { Value = 45 };
    struct Bits { unsigned width : 7; };
    int * const fixed_pointer = (int *)46;
    const int *mutable_pointer = (const int *)47;
}
"#;
    assert_eq!(
        check("ANZU-MAGIC-NUMBER", constant_contexts, 1),
        vec![(8, 47)]
    );

    check("ANZU-MAGIC-NUMBER", "int global = 47; void demo(void) {}", 0);
    check(
        "ANZU-MAGIC-NUMBER",
        "#define WRAP(value) (value)\nvoid demo(void) { int value = WRAP(47); }",
        0,
    );
    check_cpp_only(
        "ANZU-MAGIC-NUMBER",
        "void demo() { constexpr int named = 49; }",
        0,
    );
}

#[test]
fn anzu_struct_sizeof_preserves_padding_and_sizeof_sum_semantics() {
    let padded = r#"
struct Padded { char tag; int value; };
void *malloc(unsigned long);
void demo(void) {
    struct Padded *value = (struct Padded *)malloc(sizeof(char) + sizeof(int));
}
"#;
    assert_eq!(check("ANZU-STRUCT-SIZEOF", padded, 1), vec![(5, 45)]);

    let member_expressions = r#"
struct Padded { char tag; int value; };
void *malloc(unsigned long);
void demo(void) {
    struct Padded current;
    struct Padded *value = (struct Padded *)malloc(sizeof(current.tag) + sizeof(current.value));
}
"#;
    check("ANZU-STRUCT-SIZEOF", member_expressions, 1);

    let self_referential = r#"
struct Node { char tag; struct Node *next; };
void *malloc(unsigned long);
void demo(void) {
    struct Node *node = (struct Node *)malloc(sizeof(char) + sizeof(struct Node *));
}
"#;
    check("ANZU-STRUCT-SIZEOF", self_referential, 1);

    check(
        "ANZU-STRUCT-SIZEOF",
        "struct Flat { int a; int b; }; void *malloc(unsigned long); void f(void) { struct Flat *p = (struct Flat *)malloc(sizeof(int) + sizeof(int)); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "struct Padded { char tag; int value; }; void *malloc(unsigned long); void f(void) { struct Padded *p = (struct Padded *)malloc(sizeof(struct Padded)); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "struct Padded { char tag; int value; }; void *malloc(unsigned long); void f(void) { struct Padded *p = (struct Padded *)malloc(sizeof(char) * sizeof(int)); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "struct Padded { char tag; int value; }; void *malloc(unsigned long); void f(void) { struct Padded *p = (struct Padded *)malloc(sizeof(char) + sizeof(int) + sizeof(double)); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "struct Padded { char tag; int value; }; void *calloc(unsigned long, unsigned long); void f(void) { struct Padded *p = (struct Padded *)calloc(sizeof(char) + sizeof(int), 1); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "void *malloc(unsigned long); void f(void) { int *p = (int *)malloc(sizeof(char) + sizeof(int)); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "#define MAKE(sz) ((struct Padded *)malloc(sz))\nstruct Padded { char tag; int value; }; void f(void) { struct Padded *p = MAKE(sizeof(char) + sizeof(int)); }",
        0,
    );
    check(
        "ANZU-STRUCT-SIZEOF",
        "#pragma pack(push, 1)\nstruct Padded { char tag; int value; };\n#pragma pack(pop)\nvoid *malloc(unsigned long); void f(void) { struct Padded *p = (struct Padded *)malloc(sizeof(char) + sizeof(int)); }",
        0,
    );

    check_cpp(
        "ANZU-STRUCT-SIZEOF",
        "struct Padded { char tag; int value; }; void *malloc(unsigned long); void f() { Padded *p = static_cast<Padded *>(malloc(sizeof(char) + sizeof(int))); }",
        1,
    );
}

#[test]
fn anzu_printf_family_requires_arguments_for_each_conversion() {
    let source = r#"
void demo(void *stream, char *buffer, int size, int value, char *text, char *format) {
    printf("%d %s", value);
    fprintf(stream, "%d %d");
    snprintf(buffer, size, "%d %s", value);
    sprintf(buffer, "%d", value);
    printf("%% %d", value);
    printf("%d " "%s", value, text);
    printf(format, value);
    object.printf("%d %s", value);
}
"#;
    assert_eq!(
        check("ANZU-PRINTF-TOO-FEW-ARGUMENTS", source, 3),
        vec![(3, 12), (4, 21), (5, 28)]
    );
}

#[test]
fn anzu_printf_star_requires_complete_constant_width_arguments() {
    let source = r#"
void demo(int width, char *text) {
    printf("%*s");
    printf("%.*s", 3);
    printf("%*s", width, text);
    printf("%.*s", 3.0, text);
    printf("%*s", 3, text);
    printf("%% %d", width);
}
"#;
    assert_eq!(
        check("ANZU-PRINTF-STAR-MISSING-ARGUMENT", source, 2),
        vec![(3, 12), (4, 12)]
    );
    assert_eq!(
        check("ANZU-PRINTF-STAR-NONCONSTANT-ARGUMENT", source, 2),
        vec![(5, 19), (6, 20)]
    );
}

#[test]
fn anzu_scanf_percent_s_requires_an_explicit_width() {
    let source = r#"
void demo(char *buffer, char *format, void *stream) {
    scanf("%s", buffer);
    scanf("prefix " "%s", buffer);
    scanf("%10s", buffer);
    scanf("%%s", buffer);
    scanf(format, buffer);
    fscanf(stream, "%s", buffer);
    object.scanf("%s", buffer);
}
"#;
    assert_eq!(
        check("UF-C-FIO-SCANF-S", source, 2),
        vec![(3, 11), (4, 11)]
    );
}

#[test]
fn anzu_fsetpos_only_uses_positions_returned_by_fgetpos() {
    let source = r#"
void demo(void *stream, fpos_t pos, fpos_t other) {
    fsetpos(stream, &pos);
    fgetpos(stream, &pos);
    fsetpos(stream, (&pos));
    fsetpos(stream, &other);
    fgetpos(stream, &other);
    fsetpos(stream, &other);
    object.fsetpos(stream, &pos);
    fsetpos(stream);
}
"#;
    assert_eq!(
        check("ANZU-FSETPOS-REQUIRES-FGETPOS-VALUE", source, 2),
        vec![(3, 22), (6, 22)]
    );
}

#[test]
fn anzu_stream_io_switches_only_after_refresh_or_positioning() {
    let source = r#"
void demo(void *stream, void *other, char *buffer) {
    fread(buffer, 1, 8, stream);
    fwrite(buffer, 1, 8, stream);
    fwrite(buffer, 1, 8, stream);
    fflush(stream);
    fread(buffer, 1, 8, stream);
    fwrite(buffer, 1, 8, other);
    fread(buffer, 1, 8, other);
    fseek(other, 0, 0);
    fwrite(buffer, 1, 8, other);
    object.fread(buffer, 1, 8, stream);
}
"#;
    assert_eq!(
        check("ANZU-INTERLEAVED-STREAM-IO", source, 2),
        vec![(4, 26), (9, 25)]
    );
}

#[test]
fn anzu_restrict_parameters_do_not_receive_aliased_objects() {
    let source = r#"
void copy(int *restrict destination, const int *restrict source, int *ordinary);
void only_one(int *restrict destination, int *ordinary);
void demo(int *first, int *second, int *array) {
    copy(first, first, second);
    copy(first, second, first);
    copy(&array[0], &array[1], second);
    copy(first, second, second);
    only_one(first, first);
    object.copy(first, first, first);
}
"#;
    assert_eq!(
        check("ANZU-ALIASED-RESTRICT-ARGUMENTS", source, 2),
        vec![(5, 17), (7, 22)]
    );
}

#[test]
fn anzu_readlink_length_does_not_index_beyond_destination_capacity() {
    let source = r#"
void demo(char *path, int dynamic_size) {
    char small[8];
    int too_large = readlink(path, small, 16);
    small[too_large] = 0;
    char exact[8];
    int bounded = readlink(path, exact, 8);
    exact[bounded] = 0;
    char unknown[8];
    int dynamic = readlink(path, unknown, dynamic_size);
    unknown[dynamic] = 0;
    char direct[4];
    direct[readlink(path, direct, 9)] = 0;
    int ordinary = read(path, small, 8);
    small[ordinary] = 0;
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-C-READLINK-LENGTH-OUT-OF-BOUNDS");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::C, Path::new("readlink.c"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(5, 11), (11, 13), (13, 12)]);
    assert!(pack
        .scan_text(&Language::Cpp, Path::new("readlink.cpp"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::C, "readlink.c", source).expect("C HIR");
    assert_eq!(
        pack.scan_hir(&hir, &HashMap::from([("readlink.c".into(), source.into())]))
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_file_objects_are_not_copied_by_value() {
    let source = r#"
void demo(FILE original, FILE other, FILE *pointer, FILE *other_pointer) {
    FILE initialized = original;
    FILE constant = 0;
    FILE *safe_pointer = pointer;
    other = original;
    pointer = other_pointer;
    other += original;
}
"#;
    assert_eq!(
        check("ANZU-FILE-OBJECT-COPY", source, 2),
        vec![(3, 24), (6, 13)]
    );
}

#[test]
fn anzu_errno_codes_are_returned_with_errno_t() {
    let source = r#"
int first(void) { return EINVAL; }
unsigned int second(void) { return (ERANGE); }
long third(void) { return (long) EIO; }
int fourth(void) { return errno; }
errno_t correct(void) { return EINVAL; }
void *pointer(void) { return pointer_value; }
int ordinary(void) { return 7; }
int expression(void) { return EINVAL + 1; }
"#;
    assert_eq!(
        check("ANZU-ERRNO-RETURN-TYPE", source, 4),
        vec![(2, 26), (3, 37), (4, 34), (5, 27)]
    );
}

#[test]
fn anzu_errno_is_cleared_before_errno_setting_calls() {
    let source = r#"
void demo(char *text, char **end) {
    long first = strtol(text, end, 10);
    if (errno != 0) consume(first);

    errno = 0;
    long safe = strtol(text, end, 10);
    if (safe == 0 && errno != 0) consume(safe);

    errno = 1;
    double second = strtod(text, end);
    while (errno == ERANGE) consume(second);

    long unchecked = strtol(text, end, 10);
    if (unchecked == 0) consume(unchecked);

    int unrelated = puts(text);
    if (errno != 0) consume(unrelated);
}
"#;
    assert_eq!(
        check("ANZU-ERRNO-RESULT-PROTOCOL", source, 3),
        vec![(3, 18), (11, 21), (14, 22)]
    );
}

#[test]
fn anzu_string_literal_storage_is_not_modified() {
    let source = r#"
void demo(void) {
    char *literal = "immutable";
    char *alias = literal;
    char writable[] = "mutable";
    literal[0] = 'I';
    *alias = 'X';
    "direct"[1] = 'D';
    writable[0] = 'M';
    literal = writable;
}
"#;
    assert_eq!(
        check("ANZU-WRITE-STRING-LITERAL", source, 3),
        vec![(6, 5), (7, 6), (8, 5)]
    );
}

#[test]
fn anzu_const_qualified_storage_is_not_written() {
    let source = r#"
void demo(const int *input) {
    const int local = 1;
    const int values[] = {1, 2};
    int mutable = 0;
    local = 2;
    *((int *) input) = 3;
    ((int *) values)[0] = 4;
    input = &mutable;
    mutable = 5;
}
"#;
    assert_eq!(
        check("ANZU-WRITE-CONST-STORAGE", source, 3),
        vec![(6, 5), (7, 15), (8, 14)]
    );
}

#[test]
fn anzu_signed_char_is_not_promoted_without_unsigned_conversion() {
    let source = r#"
void demo(signed char value, unsigned char safe) {
    int first = value;
    long second;
    second = value;
    int explicit_conversion = (unsigned char)value;
    unsigned char same_width = value;
    int already_unsigned = safe;
}
"#;
    assert_eq!(
        check_c_only("ANZU-SIGNED-CHAR-PROMOTION", source, 2),
        vec![(3, 17), (5, 14)]
    );
}

#[test]
fn anzu_ctype_calls_receive_unsigned_char_values() {
    let source = r#"
void demo(signed char value, unsigned char safe) {
    int first = isalpha(value);
    int converted = toupper((unsigned char)value);
    int already_unsigned = isspace(safe);
    int literal = isdigit('7');
}
"#;
    assert_eq!(
        check_c_only("ANZU-CTYPE-SIGNED-CHAR-ARGUMENT", source, 1),
        vec![(3, 25)]
    );
}

#[test]
fn anzu_vla_invalid_sentinel_size_is_reported() {
    let source = r#"
void demo(int runtime_size) {
    int invalid_size = 0x7fffffff;
    int valid_size = 1024;
    int invalid[invalid_size];
    int valid[valid_size];
    int unknown[runtime_size];
    int compile_time[0x7fffffff];
}
"#;
    assert_eq!(
        check_c_only("ANZU-VLA-INVALID-SENTINEL-SIZE", source, 1),
        vec![(5, 5)]
    );
}

#[test]
fn anzu_char_traits_length_rejects_known_null_pointers() {
    let source = r#"
void demo(const char *text) {
    auto first = std::char_traits<char>::length(nullptr);
    auto second = std::char_traits<char>::length((NULL));
    auto third = std::char_traits<wchar_t>::length(0);
    auto safe = std::char_traits<char>::length(text);
    auto unrelated = custom::char_traits<char>::length(nullptr);
    std::char_traits<char>::length;
}
"#;
    assert_eq!(
        check_cpp_only("ANZU-NULL-CHAR-TRAITS-LENGTH", source, 3),
        vec![(3, 49), (4, 51), (5, 52)]
    );
}

#[test]
fn anzu_format_string_rejects_legacy_illegal_percent_followers() {
    let source = r#"
void demo(void *stream, char *buffer, int size, char *format, int value) {
    printf("%q", value);
    fprintf(stream, "%z", value);
    sprintf(buffer, "%!", value);
    snprintf(buffer, size, "%?", value);
    printf("%ld", value);
    printf("%d", value);
    printf(format, value);
    object.printf("%q", value);
}
"#;
    assert_eq!(
        check("ANZU-INVALID-PRINTF-FORMAT-SPECIFIER", source, 5),
        vec![(3, 12), (4, 21), (5, 21), (6, 28), (7, 12)]
    );
}

#[test]
fn anzu_unicode_mapping_validates_buffers_and_sizes() {
    let source = r#"
void demo(char *input, char *output) {
    MultiByteToWideChar(1, 0, input, -1, NULL, 8);
    MultiByteToWideChar(1, 0, input, -1, NULL, 0);
    WideCharToMultiByte(1, 0, input, -1, input, 8, NULL, NULL);
    WideCharToMultiByte(1, 0, input, -1, output, 8, NULL, NULL);
}
"#;
    assert_eq!(check("ANZU-UNICODE-OUTPUT-BUFFER-SIZE", source, 1), vec![(3, 5)]);
    assert_eq!(check("ANZU-UNICODE-INPUT-OUTPUT-ALIAS", source, 1), vec![(5, 5)]);
}

#[test]
fn anzu_case_sensitive_names_follow_active_lexical_scopes() {
    let source = r#"
void first(void) {
    int value = 0;
    int Value = 1;
    { int VALUE = 2; }
    if (value) { int vaLue = 3; }
    { int hidden = 0; }
    int HIDDEN = 1;
}
void second(void) { int value = 0; }
"#;
    assert_eq!(
        check("ANZU-CASE-INSENSITIVE-LOCAL-REDECLARATION", source, 3),
        vec![(4, 9), (5, 11), (6, 22)]
    );
}

#[test]
fn anzu_confusing_names_compare_only_the_same_declaration_context() {
    let source = r#"
void demo(void) {
    int file1 = 0;
    int filel = 0;
    int mode0 = 0;
    int modeO = 0;
    { int nested1 = 0; int nestedl = 0; }
    { int separate1 = 0; }
    { int separatel = 0; }
}
"#;
    assert_eq!(
        check("ANZU-CONFUSING-NAME-LOWER-L-ONE", source, 4),
        vec![(3, 9), (4, 9), (7, 11), (7, 28)]
    );
    assert_eq!(
        check("ANZU-CONFUSING-NAME-UPPER-O-ZERO", source, 2),
        vec![(5, 9), (6, 9)]
    );
}

#[test]
fn anzu_visually_confusing_names_cover_all_legacy_character_pairs() {
    let source = r#"
void demo(void) {
    int codeO = 0; int code0 = 0;
    int sell = 0; int se11 = 0;
    int sizeZ = 0; int size2 = 0;
    int passS = 0; int pass5 = 0;
    int blobB = 0; int blob8 = 0;
    int thingh = 0; int thingn = 0;
    int mode = 0; int rnode = 0;
    { int nestedO = 0; }
    { int nested0 = 0; }
    int unrelated = 0;
}
"#;
    assert_eq!(
        check("ANZU-VISUALLY-CONFUSING-VARIABLE-NAMES", source, 14),
        vec![
            (3, 9), (3, 24), (4, 9), (4, 23), (5, 9), (5, 24), (6, 9), (6, 24),
            (7, 9), (7, 24), (8, 9), (8, 25), (9, 9), (9, 23)
        ]
    );
}

#[test]
fn anzu_signed_bit_fields_require_more_than_one_value_bit() {
    let source = r#"
struct Flags {
    signed int one : 1;
    int zero : 0;
    signed short computed : (2 - 1);
    unsigned int allowed_signless : 1;
    signed int valid : 2;
    signed int unknown : WIDTH;
    double not_integer : 1;
};
"#;
    assert_eq!(
        check("ANZU-SIGNED-BIT-FIELD-WIDTH", source, 3),
        vec![(3, 16), (4, 9), (5, 18)]
    );
}

#[test]
fn anzu_bit_field_size_preserves_legacy_signed_width_threshold() {
    let source = r#"
struct Flags {
    signed int one : 1;
    int zero : 0;
    signed short computed : (3 - 2);
    unsigned int unsigned_one : 1;
    signed int valid : 2;
    signed int unknown : WIDTH;
};
"#;
    assert_eq!(
        check("ANZU-BIT-FIELD-SIZE", source, 3),
        vec![(3, 16), (4, 9), (5, 18)]
    );
}

#[test]
fn anzu_bit_size_type_preserves_legacy_cast_source_type_semantics() {
    let source = r#"
enum Width { WIDTH_ONE = 1 };
struct Bits {
    unsigned from_float : (unsigned)1.5;
    unsigned from_string : (unsigned)"x";
    unsigned from_integer : (unsigned)1;
    unsigned from_enum : (unsigned)WIDTH_ONE;
};
#define BAD_WIDTH ((unsigned)2.5)
struct MacroBits { unsigned macro_width : BAD_WIDTH; };
"#;
    assert_eq!(
        check("ANZU-BIT-SIZE-TYPE", source, 2),
        vec![(4, 37), (5, 38)]
    );

    let cpp = r#"
struct Bits {
    unsigned functional_bad : unsigned(2.5);
    unsigned functional_good : unsigned(2);
    unsigned named_bad : static_cast<unsigned>(3.5);
    unsigned named_good : static_cast<unsigned>(3);
};
"#;
    assert_eq!(
        check_cpp("ANZU-BIT-SIZE-TYPE", cpp, 2),
        vec![(3, 40), (5, 48)]
    );
}

#[test]
fn anzu_logical_expr_paren_preserves_direct_child_ast_semantics() {
    let source = r#"
int demo(int a, int b, int c, int d) {
    int chained = a && b && c;
    int precedence = a || b && c;
    int both = a && b || c && d;
    int grouped_left = (a && b) && c;
    int grouped_right = a || (b && c);
    int grouped_both = (a && b) || (c && d);
    int nested_inside_group = a && (b || c && d);
    return chained + precedence + both + grouped_left + grouped_right + grouped_both + nested_inside_group;
}
"#;
    assert_eq!(
        check("ANZU-LOGICAL-EXPR-PAREN", source, 5),
        vec![(3, 19), (4, 27), (5, 16), (5, 26), (9, 42)]
    );
}

#[test]
fn anzu_condition_expr_paren_preserves_direct_child_ast_semantics() {
    let source = r#"
#define WRAP(x) (x)
int demo(int a, int b, int c, int d, int e, int *p) {
    int condition = a + b ? c : d;
    int lhs = a ? b + c : d;
    int rhs = a ? b : c + d;
    int grouped_condition = (a + b) ? c : d;
    int grouped_branches = a ? (b + c) : (c + d);
    int nested_lhs = a ? b ? c : d : e;
    int nested_rhs = a ? b : c ? d : e;
    int assignment_lhs = a ? b = c : d;
    int comma_lhs = a ? b, c : d;
    int unary = a ? *p : d;
    int cast_unary = a ? (int)*p : d;
    int macro_argument = WRAP(a + b ? c : d);
    return condition + lhs + rhs + grouped_condition + grouped_branches + nested_lhs
        + nested_rhs + assignment_lhs + comma_lhs + unary + cast_unary + macro_argument;
}
"#;

    assert_eq!(
        check("ANZU-CONDITIONAL-OPERAND-PAREN", source, 7),
        vec![(4, 21), (5, 19), (6, 23), (9, 26), (10, 30), (11, 30), (12, 25)]
    );
}

#[test]
fn anzu_unused_static_function_resolves_real_identifier_uses() {
    let source = r#"
static void unused_simple(void) { }
static void direct_used(void) { }
static void address_used(void) { }
static void passed_used(void) { }
static void shadowed(void) { }
static void shadowed_param(void) { }
static void macro_only(void) { }
static void prose_only(void) { }
void public_unused(void) { }
static void prototype_only(void);
void takes(void (*callback)(void));

void exercise(int shadowed_param) {
    direct_used();
    void (*pointer)(void) = &address_used;
    takes(passed_used);
    int shadowed = 0;
    shadowed++;
    shadowed_param++;
    const char *text = "prose_only";
    (void)pointer;
    (void)text;
}

#define NEVER_INVOKED() macro_only()
/* prose_only(); */
"#;

    assert_eq!(
        check("ANZU-UNUSED-STATIC-FUNCTION", source, 5),
        vec![(2, 13), (6, 13), (7, 13), (8, 13), (9, 13)]
    );

    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-UNUSED-STATIC-FUNCTION");
    let findings = pack.scan_text(&Language::C, Path::new("unused.c"), source);
    assert_eq!(findings[0].message, "The static function 'unused_simple' is defined but not used.");
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "静态函数 ‘unused_simple’ 定义但未使用。"
    );
}

#[test]
fn anzu_unused_parameter_resolves_declref_binding_and_shadowing() {
    let source = r#"
int consume(int value);

int direct_use(int used, int unused) {
    return used;
}

int call_use(int value) {
    return consume(value);
}

int shadow_only(int value) {
    {
        int value = 1;
        return value;
    }
}

struct Sample { int field; };
int member_only(int field, struct Sample sample) {
    return sample.field;
}

int prose_only(int ghost) {
    const char *text = "ghost";
    /* ghost */
    return text != 0;
}

int sizeof_use(int value) {
    return sizeof(value);
}

int unnamed(int, int used) {
    return used;
}
"#;

    assert_eq!(
        check("ANZU-UNUSED-PARAMETER", source, 4),
        vec![(4, 30), (12, 21), (20, 21), (24, 20)]
    );

    let cpp = r#"
struct Holder { int value; };
int cpp_member(int value, Holder holder) {
    return holder.value;
}
int cpp_shadow(int value) {
    { int value = 3; (void)value; }
    return 0;
}
"#;
    assert_eq!(
        check_cpp("ANZU-UNUSED-PARAMETER", cpp, 2),
        vec![(3, 20), (6, 20)]
    );
}

#[test]
fn anzu_return_type_checker_preserves_legacy_assignment_semantics() {
    let source = r#"
int ok_int(void) { return 1; }
int bad_float(void) { return 1.5; }
double bad_int(void) { return 1; }
unsigned char too_big(void) { return 300; }
unsigned char zero_ok(void) { return (int)0; }
unsigned char nonconstant_ok(unsigned int value) { return value; }
char *pointer_return(void) { return 0; }
double produce(void) { return 1.0; }
int bad_call(void) { return produce(); }
int nested(int ready) { if (ready) { return 2.5; } return 0; }
"#;

    assert_eq!(
        check("ANZU-RETURN-TYPE", source, 5),
        vec![(3, 30), (4, 31), (5, 38), (10, 29), (11, 45)]
    );

    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|candidate| candidate.id == "ANZU-RETURN-TYPE");
    let findings = pack.scan_text(&Language::C, Path::new("return.c"), source);
    assert_eq!(
        findings[0].message,
        "Return type mismatch between return and definition. Expected 'double' but defined as 'int'."
    );
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "返回类型和定义不匹配。期望 ‘double’ 实际定义为 ‘int’"
    );
}

#[test]
fn anzu_num_zero_cast_pointer_preserves_implicit_null_pointer_conversions() {
    let source = r#"
#define WRAP_ZERO(x) (x)
int *global_pointer = 0;
void takes_pointer(int *pointer, int value);

int *returns_pointer(void) {
    return (0);
}

int exercise(int condition) {
    int *pointer = (0);
    pointer = 0;
    takes_pointer((0), 0);
    if (pointer == 0) { pointer = (int *)0; }
    if (0 != pointer) { pointer = WRAP_ZERO(0); }
    int *from_false = condition ? pointer : 0;
    int *from_true = condition ? (0) : pointer;
    pointer = 1;
    int *explicit_init = (int *)0;
    (void)explicit_init;
    return condition;
}
"#;

    assert_eq!(
        check("ANZU-NUM-ZERO-CAST-POINTER", source, 9),
        vec![
            (3, 23),
            (7, 13),
            (11, 21),
            (12, 15),
            (13, 20),
            (14, 20),
            (15, 9),
            (16, 45),
            (17, 35),
        ]
    );

    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-NUM-ZERO-CAST-POINTER");
    let findings = pack.scan_text(&Language::C, Path::new("zero-pointer.c"), source);
    assert_eq!(findings[0].message, "0 should not be used as an pointer");
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "0不应该被用作指针"
    );
}

#[test]
fn anzu_null_as_int_preserves_legacy_nullptr_to_bool_casts_and_macro_suppression() {
    let source = r#"
#define NULL 0
#define BOOL_NULL() nullptr

bool exercise(void *pointer) {
    bool direct_paren(nullptr);
    bool direct_brace{nullptr};
    auto functional_paren = bool(nullptr);
    auto functional_brace = bool{nullptr};
    bool *heap = new bool(nullptr);
    if ((nullptr)) { }
    while (nullptr) { break; }
    for (; nullptr; ) { break; }
    do { } while (nullptr);
    bool negated = !nullptr;
    bool conjunction = nullptr && true;
    bool disjunction = false || (nullptr);
    bool conditional = nullptr ? true : false;
    bool named_cast = static_cast<bool>(nullptr);
    bool c_style_cast = (bool)(nullptr);

    bool macro_null = NULL;
    auto macro_nullptr = BOOL_NULL();
    auto preserved_nullptr_type = nullptr;
    void *pointer_value = nullptr;
    bool comparison = pointer == nullptr;
    return direct_paren || direct_brace || functional_paren || functional_brace || *heap
        || negated || conjunction || disjunction || conditional || named_cast || c_style_cast
        || macro_null || macro_nullptr || preserved_nullptr_type == nullptr
        || pointer_value == nullptr || comparison;
}
"#;

    let findings = check_cpp("ANZU-NULL-AS-INT", source, 15);
    assert_eq!(
        findings,
        vec![
            (6, 23),
            (7, 23),
            (8, 34),
            (9, 34),
            (10, 27),
            (11, 10),
            (12, 12),
            (13, 12),
            (14, 19),
            (15, 21),
            (16, 24),
            (17, 34),
            (18, 24),
            (19, 41),
            (20, 32),
        ]
    );

    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-NULL-AS-INT");
    let findings = pack.scan_text(&Language::Cpp, Path::new("null-as-int.cpp"), source);
    assert_eq!(findings[0].message, "NULL should not be used as an integer 0");
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "NULL不能当作整数0来使用"
    );
}

#[test]
fn anzu_disable_for_body_modify_ctrl_var_preserves_legacy_binding_and_macro_semantics() {
    let source = r#"
#define WRAP(x) (x)

void exercise(int *pointer, int limit, int condition) {
    for (int i = 0; i < limit; ++i) {
        i = i + 1;
    }

    int j = 0;
    for (j = 0; j < limit; ++j) {
        j += 2;
    }

    int k = 0;
    for (; k < limit; k++) {
        ++k;
    }

    int flag = 1;
    for (; flag; ) {
        flag--;
    }

    int negated = 0;
    for (; !negated; ) {
        ++negated;
    }

    int casted = 1;
    for (; (int)casted; ) {
        casted--;
    }

    int unary_casted = 0;
    for (; !(int)unary_casted; ) {
        unary_casted++;
    }

    int *cursor = pointer;
    for (; *cursor; ) {
        cursor = pointer;
    }

    int left = 0;
    int right = 0;
    for (left = 0; left < limit && right < limit; ++left) {
        left++;
    }
    for (; left < limit && right < limit; ++right) {
        --right;
    }

    for (int outer = 0; outer < limit; ++outer) {
        { int outer = 0; outer++; }
        pointer[0] = outer;
        (outer)++;
    }

    for (int prefix = 0; prefix < limit; ++prefix) {
        ++(prefix);
    }

    for (int compound = 0; compound < limit; ++compound) {
        compound <<= 1;
    }

    for (int nested = 0; nested < limit; ++nested) {
        if (condition) nested = 3;
    }

    for (int macro_value = 0; macro_value < limit; ++macro_value) {
        WRAP(macro_value++);
    }

    for (int untouched = 0; untouched < limit; ++untouched) {
        pointer[untouched]++;
    }
}
"#;

    let findings = check(
        "ANZU-DISABLE-FOR-BODY-MODIFY-CTRL-VAR",
        source,
        14,
    );
    assert_eq!(findings.len(), 14);

    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|candidate| {
        candidate.id == "ANZU-DISABLE-FOR-BODY-MODIFY-CTRL-VAR"
    });
    let findings = pack.scan_text(&Language::C, Path::new("for-control.c"), source);
    assert_eq!(
        findings[0].message,
        "Modifying the loop control variable inside the body of a for loop is prohibited."
    );
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "禁止修改for循环体内的循环控制变量。"
    );
}

#[test]
fn anzu_plain_char_arithmetic_reports_each_direct_character_operand() {
    let source = r#"
int demo(char left, char right, signed char signed_value, unsigned char unsigned_value, int number) {
    int first = left + number;
    int second = number * (right);
    int third = left - right;
    int explicit_signed = signed_value + number;
    int explicit_unsigned = unsigned_value / number;
    int comparison = left < right;
    int compound = number += left;
    return first + second + third + explicit_signed + explicit_unsigned + comparison + compound;
}
"#;
    assert_eq!(
        check("ANZU-PLAIN-CHAR-ARITHMETIC-OPERAND", source, 4),
        vec![(3, 17), (4, 28), (5, 17), (5, 24)]
    );
}

#[test]
fn anzu_double_to_float_assignment_ignores_literals_and_explicit_casts() {
    let source = r#"
void demo(double source, float same) {
    float first = source;
    float target = 0.0F;
    target = source;
    float expression = source + same;
    float literal = 1.0;
    float parenthesized_literal = (1.0);
    float explicitly_cast = (float)source;
    target = (float)source;
    target = same;
}
"#;
    assert_eq!(
        check("ANZU-DOUBLE-TO-FLOAT-NONLITERAL-ASSIGNMENT", source, 3),
        vec![(3, 5), (5, 12), (6, 5)]
    );
}

#[test]
fn anzu_floating_to_integer_conversion_separates_initializers_and_assignments() {
    let source = r#"
void demo(float source, double wide) {
    int from_literal = 1.5;
    long from_value = source;
    int explicit_cast = (int)source;
    float floating_target = wide;
    int target = 0;
    target = source;
    target = 2.5;
    target = (int)wide;
    unsigned int unsigned_target = 0;
    unsigned_target = wide;
}
"#;
    assert_eq!(
        check("ANZU-FLOATING-TO-INTEGER-INITIALIZATION", source, 2),
        vec![(3, 5), (4, 5)]
    );
    assert_eq!(
        check("ANZU-FLOATING-TO-INTEGER-ASSIGNMENT", source, 3),
        vec![(8, 12), (9, 12), (12, 21)]
    );
}

#[test]
fn anzu_integer_to_char_and_float_rules_preserve_expression_boundaries() {
    let source = r#"
void demo(int value, int other, char plain, signed char signed_value) {
    char from_value = value;
    char from_zero = 0;
    char from_char = plain;
    char casted = (char)value;
    char from_expression = value + other;
    char target = plain;
    target = value;
    target = 0;
    target = signed_value;
    float first = value + other;
    double second = value * other;
    float direct = value;
    float shifted = value << 1;
    float converted = (float)(value + other);
    first = value - other;
    first = value << other;
}
"#;
    assert_eq!(
        check("ANZU-INTEGER-TO-PLAIN-CHAR-ASSIGNMENT", source, 4),
        vec![(3, 23), (7, 28), (9, 12), (11, 12)]
    );
    assert_eq!(
        check_c_only("ANZU-INTEGER-ARITHMETIC-TO-FLOATING-ASSIGNMENT", source, 3),
        vec![(12, 19), (13, 21), (17, 11)]
    );
}

#[test]
fn anzu_wider_integer_targets_reject_unconverted_binary_results() {
    let source = r#"
void demo(short small, short other, long wide) {
    long widened = small + other;
    int promoted = small + other;
    long direct = small;
    long same_width = wide + 1;
    long long wider_again = wide + 1;
    long target = 0;
    target = small * other;
    target = wide + 1;
    target = small;
}
"#;
    assert_eq!(
        check("ANZU-WIDER-INTEGER-TARGET-BINARY-EXPRESSION", source, 3),
        vec![(3, 20), (7, 29), (9, 12)]
    );
}

#[test]
fn anzu_nonzero_integer_pointer_cast_is_rejected_on_assignment() {
    let source = r#"
void demo(void *pointer, int value) {
    pointer = (void *)value;
    pointer = ((void *)value);
    pointer = (void *)0;
    pointer = (void *)pointer;
    void *initialized = (void *)value;
}
"#;
    assert_eq!(
        check("ANZU-NONZERO-INTEGER-POINTER-CAST-ASSIGNMENT", source, 2),
        vec![(3, 13), (4, 13)]
    );
}

#[test]
fn anzu_negated_comparison_requires_an_explicit_comparison_form() {
    let source = r#"
void demo(int left, int right, int flag) {
    if (!(left == right)) use();
    if (!((left < right))) use();
    if (!flag) use();
    if (!left == right) use();
    if (left != right) use();
}
"#;
    assert_eq!(
        check("ANZU-NEGATED-COMPARISON-IF-CONDITION", source, 2),
        vec![(3, 9), (4, 9)]
    );
}

#[test]
fn anzu_if_condition_types_follow_distinct_c_and_cpp_rules() {
    let source = r#"
enum Mode { Off, On };
void demo(int integer, float floating, int *pointer, bool flag, enum Mode mode) {
    if (integer) use();
    if (floating) use();
    if (pointer) use();
    if (flag) use();
    if (mode) use();
    if (integer < 1) use();
    if (!pointer) use();
    if ((int)floating) use();
    if ((bool)integer) use();
}
"#;
    assert_eq!(
        check_c_only("ANZU-C-IF-CONDITION-MUST-BE-INTEGER", source, 3),
        vec![(5, 9), (6, 9), (8, 9)]
    );
    assert_eq!(
        check_cpp_only("ANZU-CPP-IF-NUMERIC-CONDITION-MUST-BE-BOOL", source, 4),
        vec![(4, 9), (5, 9), (8, 9), (11, 9)]
    );
}

#[test]
fn anzu_switch_boolean_type_follows_c_and_cpp_expression_types() {
    let source = r#"
bool ready(void) { return true; }
void demo(bool flag, int count) {
    switch (flag) { default: break; }
    switch (ready()) { default: break; }
    switch (true) { default: break; }
    switch (count < 1) { default: break; }
    switch (flag && ready()) { default: break; }
    switch (count) { default: break; }
}
"#;
    assert_eq!(
        check_c_only("ANZU-C-BOOLEAN-SWITCH-CONDITION", source, 3),
        vec![(4, 13), (5, 13), (6, 13)]
    );
    assert_eq!(
        check_cpp_only("ANZU-CPP-BOOLEAN-SWITCH-CONDITION", source, 5),
        vec![(4, 13), (5, 13), (6, 13), (7, 13), (8, 13)]
    );
}

#[test]
fn anzu_inner_block_redefinition_tracks_only_active_outer_scopes() {
    let source = r#"
void demo(int parameter) {
    int value = 0;
    { int value = 1; }
    { int value = 2; }
    { int inner = 0; { int inner = 1; } }
    { int separate = 0; }
    { int separate = 1; }
    int parameter = 0;
}
"#;
    assert_eq!(
        check("ANZU-INNER-BLOCK-VARIABLE-REDEFINITION", source, 3),
        vec![(4, 7), (5, 7), (6, 24)]
    );
}

#[test]
fn anzu_recursive_calls_are_rejected_only_in_local_initializers() {
    let source = r#"
int recurse(int value) {
    int direct = recurse(value - 1);
    int nested = wrap(recurse(value - 2));
    int unrelated = other(value);
    direct = recurse(value - 3);
    return direct + nested + unrelated;
}
int other_function(void) {
    int safe = recurse(1);
    return safe;
}
"#;
    assert_eq!(
        check_cpp_only("ANZU-RECURSIVE-CALL-IN-LOCAL-INITIALIZER", source, 2),
        vec![(3, 18), (4, 23)]
    );
}

#[test]
fn anzu_mixed_shift_and_arithmetic_tracks_declaration_identity_per_expression() {
    let source = r#"
int demo(int value, int other) {
    int first = (value << 1) + value;
    int separate = value + 1;
    separate = separate << 1;
    int distinct = (value << 1) + other;
    { int value = 1; int nested = (value >> 1) - value; }
    int repeated = (value >> 1) * value;
    return first + separate + distinct + repeated;
}
"#;
    assert_eq!(
        check("ANZU-MIXED-SHIFT-AND-ARITHMETIC-VARIABLE", source, 2),
        vec![(3, 18), (7, 36)]
    );
}

#[test]
fn anzu_shift_rules_share_promoted_type_and_constant_facts() {
    let negative = r#"
void demo(unsigned int value) {
    value << -1;
    value >> (1 - 3);
    value << 1;
}
"#;
    assert_eq!(
        check("ANZU-NEGATIVE-SHIFT-COUNT", negative, 2),
        vec![(3, 14), (4, 14)]
    );

    let overflow = r#"
void demo(unsigned int value, unsigned short small, unsigned long wide) {
    value << 32;
    value << 31;
    small << 32;
    wide << 64;
    wide << 63;
}
"#;
    assert_eq!(
        check("ANZU-SHIFT-COUNT-EXCEEDS-PROMOTED-WIDTH", overflow, 3),
        vec![(3, 11), (5, 11), (6, 10)]
    );

    let signed = r#"
void demo(int value, unsigned int unsigned_value, int count) {
    value << count;
    value >> 1;
    unsigned_value << count;
    1 << count;
    (value + 1) << count;
}
"#;
    assert_eq!(
        check("ANZU-NONCONSTANT-SIGNED-SHIFT", signed, 3),
        vec![(3, 11), (4, 11), (7, 17)]
    );
}

#[test]
fn anzu_unsigned_assignment_rejects_feasibly_negative_signed_values() {
    let source = r#"
void demo(int signed_value, unsigned int unsigned_value) {
    unsigned int target = -1;
    target = signed_value;
    target = -1;
    target = 1 - 3;
    target = 3 - 1;
    target = unsigned_value;
    target = (unsigned int)signed_value;
}
"#;
    assert_eq!(
        check("ANZU-POSSIBLY-NEGATIVE-SIGNED-TO-UNSIGNED-ASSIGNMENT", source, 3),
        vec![(4, 12), (5, 12), (6, 12)]
    );
}

#[test]
fn anzu_integer_narrowing_ignores_constants_and_explicit_target_casts() {
    let source = r#"
void demo(long wide, short small) {
    short from_wide = wide;
    short from_constant = 100000;
    int int_from_wide = wide;
    short explicitly_cast = (short)wide;
    char char_from_short = small;
    short target = 0;
    target = wide;
    target = wide + 1;
    target = 42;
    target = (short)wide;
}
"#;
    assert_eq!(
        check("ANZU-NONCONSTANT-INTEGER-NARROWING-ASSIGNMENT", source, 5),
        vec![(3, 23), (5, 25), (7, 28), (9, 14), (10, 14)]
    );
}

#[test]
fn anzu_integer_narrowing_range_rules_separate_implicit_and_explicit_conversions() {
    let source = r#"
void demo(long wide) {
    short implicit_unknown = wide;
    short implicit_safe = 42;
    short implicit_bad = 100000;
    short explicit_unknown = (short)wide;
    short explicit_safe = (short)42;
    short explicit_bad = (short)100000;
    short target = 0;
    target = wide;
    target = 42;
    target = 100000;
    target = (short)wide;
}
"#;
    assert_eq!(
        check("ANZU-IMPLICIT-INTEGER-NARROWING-MAY-OVERFLOW", source, 4),
        vec![(3, 30), (5, 26), (10, 14), (12, 14)]
    );
    assert_eq!(
        check("ANZU-EXPLICIT-INTEGER-NARROWING-MAY-OVERFLOW", source, 3),
        vec![(6, 37), (8, 33), (13, 21)]
    );
}

#[test]
fn anzu_numeric_assignment_type_keeps_zero_and_explicit_cast_exceptions() {
    let source = r#"
void demo(float floating, long wide) {
    int from_float = floating;
    float from_int = 1;
    float zero = 0;
    int same_category = wide;
    unsigned char unsigned_too_large = 300;
    signed char signed_too_large = 200;
    signed char historical_negative = -200;
    int casted = (int)floating;
    int target = 0;
    target = floating;
    target = (int)floating;
}
"#;
    assert_eq!(
        check("ANZU-INCONSISTENT-NUMERIC-ASSIGNMENT-TYPE", source, 5),
        vec![(3, 22), (4, 22), (7, 40), (8, 36), (12, 12)]
    );
}

#[test]
fn anzu_argument_count_checker_preserves_resolved_function_arity_semantics() {
    let source = r#"
int pair(int left, int right);
int variadic(const char *format, ...);
void demo(void) {
    pair(1);
    pair(1, 2, 3);
    pair(1, 2);
    variadic("%d");
    unresolved(1);
    int (*callback)(int, int) = pair;
    callback(1);
}
"#;
    assert_eq!(
        check("ANZU-ARGUMENT-COUNT-MISMATCH", source, 2),
        vec![(5, 10), (6, 16)]
    );

    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-ARGUMENT-COUNT-MISMATCH");
    let findings = pack.scan_text(&Language::C, Path::new("argument-count.c"), source);
    assert_eq!(findings.len(), 2);
    assert_eq!(
        findings[0].message,
        "Argument count mismatch: Expected 2 arguments but provided 1."
    );
    assert_eq!(
        findings[1].message,
        "Argument count mismatch: Expected 2 arguments but provided 3."
    );
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "参数数量不匹配：期望提供 2 个参数，实际提供 1 个参数。"
    );

    let cpp_source = r#"
int with_default(int first, int second = 2);
struct Widget {
    Widget(int first, int second);
};
void demo_cpp(void) {
    with_default(1);
    Widget value(1);
}
"#;
    assert_eq!(
        check_cpp("ANZU-ARGUMENT-COUNT-MISMATCH", cpp_source, 1),
        vec![(7, 18)]
    );
}

#[test]
fn anzu_argument_type_checker_preserves_legacy_numeric_assignment_semantics() {
    let source = r#"
int take_int(int value);
int take_short(short value);
int take_double(double value);
int take_pointer(const int *value);
int take_variadic(int value, ...);
void demo(int i, short s, long long wide, double d, int *ptr) {
    take_int(d);
    take_double(i);
    take_short(i);
    take_short(0);
    take_int(s);
    take_int(wide);
    take_pointer(i);
    take_int(ptr);
    take_int(i);
    take_variadic(d, d);
    unresolved(d);
    int (*callback)(int) = take_int;
    callback(d);
}
"#;
    assert_eq!(
        check("ANZU-ARGUMENT-TYPE-MISMATCH", source, 6),
        vec![(8, 14), (9, 17), (10, 16), (13, 14), (15, 14), (17, 19)]
    );

    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-ARGUMENT-TYPE-MISMATCH");
    let findings = pack.scan_text(&Language::C, Path::new("argument-type.c"), source);
    assert_eq!(findings.len(), 6);
    assert_eq!(
        findings[0].message,
        "Argument type mismatch: Expected 'int' but provided 'double'."
    );
    assert_eq!(
        findings[0]
            .translations
            .zh_cn
            .as_ref()
            .expect("zh-CN translation")
            .message,
        "参数类型不匹配：期望 ‘int’类型，实际得到‘double’类型。"
    );
}

#[test]
fn anzu_value_depend_sequence_point_preserves_legacy_ast_visitor_state() {
    let source = r#"
struct Item { int value; };
void use2(int, int);
void demo(struct Item *item, int i) {
    int first = i++ + i;
    int second = i + i++;
    int third = i++ + i++;
    use2(i++, i);
    use2(i, i++);
    i++;
    use2(i, 0);
    int logical_direct = i++ && i;
    int comma_direct = (i++, i);
    int logical_nested = i++ && (i + 0);
    int comma_nested = (i++, i + 0);
    int parenthesized_update = (i)++ + i;
    int member_update = item->value++ + i;
    use2((i), i++);
    use2(i++ + 1, i);
    i = i++;
}
"#;
    assert_eq!(
        check("ANZU-VALUE-DEPEND-SEQUENCE-POINT", source, 9),
        vec![
            (5, 17),
            (6, 22),
            (7, 23),
            (8, 10),
            (9, 13),
            (14, 34),
            (15, 30),
            (19, 10),
            (20, 9),
        ]
    );

    let macro_source = r#"
#define PAIR(a, b) ((a) + (b))
void demo(int i) {
    PAIR(i++, i);
}
"#;
    check("ANZU-VALUE-DEPEND-SEQUENCE-POINT", macro_source, 0);
}
