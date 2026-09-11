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
        let findings = pack.scan_text(&language, Path::new("Declarations.c"), source);
        assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
        coordinates = findings
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect();
        let hir = parse_c_like_file(language, "Declarations.c", source).unwrap();
        let integrated = pack.scan_hir(
            &hir,
            &HashMap::from([("Declarations.c".into(), source.into())]),
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

#[test]
fn migrated_c_declaration_rules_preserve_source_boundaries() {
    for (rule, source, safe) in [
        (
            "LEGACY-C-AST-void-fn-must-not-return-value",
            "void f(void) { return 1; }",
            "void f(void) { return; }",
        ),
        (
            "LEGACY-C-AST-non-void-fn-must-return",
            "int f(void) { work(); }",
            "int f(void) { return 1; }",
        ),
        (
            "LEGACY-C-AST-non-void-fn-must-return-value",
            "int f(void) { return; }",
            "int f(void) { return 1; }",
        ),
        (
            "LEGACY-C-AST-func-decl-empty",
            "int f() { return 1; }",
            "int f(void) { return 1; }",
        ),
        (
            "LEGACY-C-AST-no-unnamed-argument",
            "void f(int);",
            "void f(int named);",
        ),
        (
            "LEGACY-C-AST-no-unnamed-struct",
            "struct { int x; } object;",
            "struct Named { int x; } object;",
        ),
        (
            "LEGACY-C-AST-no-union-declaration-in-struct",
            "struct S { union U *p; };",
            "struct S { int x; }; union U *p;",
        ),
        (
            "LEGACY-C-AST-array-declaration-must-be-sized",
            "int a[] = {1, 2};",
            "int a[2] = {1, 2};",
        ),
        (
            "LEGACY-C-AST-no-extern-declaration-in-function",
            "void f(void) { extern int x; }",
            "extern int x; void f(void) {}",
        ),
        (
            "LEGACY-C-AST-no-init-in-extern-declaration",
            "extern int x = 1;",
            "extern int x;",
        ),
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
    check(
        void,
        "void outer(void) { int inner(void) { return 1; } if (x) return 2; }",
        1,
    );
    check(
        void,
        "void *pointer(void) { return 0; } void f(void) { auto l = []() { return 1; }; return; }",
        0,
    );
    check(void, "void f(void) { return /* comment */; }", 1);
    let empty = "LEGACY-C-AST-non-void-fn-must-return-value";
    check(empty, "int f(void) { return /* comment */; }", 0);
    check(empty, "int f(void) { if (x) return; return 1; }", 1);
    let missing = "LEGACY-C-AST-non-void-fn-must-return";
    check(
        missing,
        "int outer(void) { int inner(void) { return 1; } }",
        1,
    );
    check(missing, "int f(void) { auto l = []() { return 1; }; }", 1);
    check(missing, "int f(void) { if (x) return 1; }", 0);
    check(
        missing,
        "struct S f(void) { work(); } void *g(void) { work(); }",
        2,
    );
    check(
        missing,
        "int prototype(void); int (*callback)(void); void f(void) {}",
        0,
    );
}

#[test]
fn migrated_c_parameter_rules_handle_function_pointer_descendants() {
    let unnamed = "LEGACY-C-AST-no-unnamed-argument";
    check(
        unnamed,
        "void f(void); void g(int named, char *text, ...);",
        0,
    );
    check(unnamed, "void f(int, const char *, int []);", 3);
    check(unnamed, "void f(void (*callback)(int));", 0);
    check(unnamed, "void f(void (*)(int named));", 1);
    check(unnamed, "void f(void (*)(int));", 1);
    check(unnamed, "void f(int) {}", 0);
    let empty = "LEGACY-C-AST-func-decl-empty";
    check(empty, "int prototype(); int (*callback)();", 0);
    check(empty, "void f(/* no parameters */) {} void g(void) {}", 1);
}

#[test]
fn anzu_parameter_type_checker_requires_definition_and_undeduced_type() {
    let rule = "ANZU-PARAMETER-TYPE-DECLARATION";
    let source = r#"
void prototype(auto only_declared);
void concrete(int typed, auto first, const auto& second) { }
#define MACRO_PARAMETER auto hidden
void macro_origin(MACRO_PARAMETER) { }
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");

    let findings = pack.scan_text(&Language::Cpp, Path::new("parameter_type.cpp"), source);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.line, finding.column, finding.message.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (3, 31, "Parameter must use type declaration"),
            (3, 50, "Parameter must use type declaration"),
        ],
        "{findings:#?}"
    );

    let hir = parse_c_like_file(Language::Cpp, "parameter_type.cpp", source).unwrap();
    let integrated = pack.scan_hir(
        &hir,
        &HashMap::from([("parameter_type.cpp".into(), source.into())]),
    );
    assert_eq!(
        integrated
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(3, 31), (3, 50)]
    );
}

#[test]
fn migrated_c_aggregate_array_and_extern_rules_keep_declaration_gates() {
    check(
        "LEGACY-C-AST-no-unnamed-struct",
        "union { int x; } u; enum { A, B }; typedef struct { int x; } Alias;",
        3,
    );
    check(
        "LEGACY-C-AST-no-unnamed-struct",
        "struct S; union U { int x; }; enum E { A };",
        0,
    );
    check(
        "LEGACY-C-AST-no-union-declaration-in-struct",
        "struct S { union U { int x; } u; struct T { union U *p; } t; };",
        2,
    );
    let array = "LEGACY-C-AST-array-declaration-must-be-sized";
    check(
        array,
        "extern int a[]; char text[] = \"abc\"; void f(int a[]) {} struct S { int flexible[]; };",
        0,
    );
    check(array, "int a[] = {1}, b[] = {2}; int *p[] = {0};", 0);
    check(array, "void f(void) { int a[] = {1, 2}; }", 1);
    check(
        "LEGACY-C-AST-no-extern-declaration-in-function",
        "struct S { void f(void) { if (x) { extern int a; } } };",
        1,
    );
    check(
        "LEGACY-C-AST-no-init-in-extern-declaration",
        "extern int a = 1, b = 2; extern int c;",
        2,
    );
    check(
        "LEGACY-C-AST-no-init-in-extern-declaration",
        "extern \"C\" { int x = 1; extern int y = 2; }",
        1,
    );
}

#[test]
fn anzu_local_extern_reports_each_declaration_but_not_local_function_declarations() {
    let rule = "LEGACY-C-AST-no-extern-declaration-in-function";
    check(
        rule,
        "extern int global; void f(void) { extern int first, second; extern void helper(void); if (ready) { extern int nested; } static int internal; }",
        2,
    );
}

#[test]
fn c_declaration_matchers_validate_modes_paths_and_source_locations() {
    assert_eq!(
        check(
            "LEGACY-C-AST-no-extern-declaration-in-function",
            "// 中文\nvoid f(void) {\n  extern int x;\n}\n",
            1
        ),
        vec![(3, 3)]
    );
    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|rule| rule.id == "LEGACY-C-AST-no-init-in-extern-declaration");
    pack.rules[0].matcher.path_pattern = "\\.h$".into();
    pack.validate().unwrap();
    assert!(pack
        .scan_text(&Language::C, Path::new("M.c"), "extern int x = 1;")
        .is_empty());
    assert_eq!(
        pack.scan_text(&Language::C, Path::new("M.h"), "extern int x = 1;")
            .len(),
        1
    );
    pack.rules[0].matcher.c_macro = Some(uniflow_baseline::CMacroCheck::TrailingSemicolon);
    assert!(pack.validate().is_err());
    pack.rules[0].matcher.c_macro = None;
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
}

#[test]
fn anzu_function_length_uses_source_line_distance_and_strict_limit() {
    let rule = "ANZU-FUNCTION-OVER-200-LINES";
    let boundary = format!("int boundary(void) {{\n{}return 0;\n}}", "\n".repeat(198));
    assert!(check(rule, &boundary, 0).is_empty());

    let oversized = format!(
        "int declaration_only(void);\nint oversized(void) {{\n{}return 0;\n}}",
        "\n".repeat(199)
    );
    assert_eq!(check(rule, &oversized, 1), vec![(2, 1)]);

    let cpp = format!("int oversized_cpp() {{\n{}return 0;\n}}", "\n".repeat(199));
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("function_length.cpp"),
        &cpp,
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == rule)
            .count(),
        1,
        "{findings:#?}"
    );
}

#[test]
fn anzu_typedef_keyword_rule_uses_the_complete_underlying_type() {
    let source = r#"
typedef int Integer;
typedef unsigned Unsigned;
typedef int First, Second;
typedef const int ConstantInteger;
typedef volatile char VolatileCharacter;
typedef int *Pointer;
typedef int Array[4];
typedef unsigned long Wide;
struct Record { int value; };
typedef struct Record RecordAlias;
"#;
    assert_eq!(
        check("ANZU-TYPEDEF-BUILTIN-KEYWORD", source, 3),
        vec![(2, 1), (3, 1), (4, 1)]
    );
}

#[test]
fn anzu_main_signature_checks_global_prototypes_definitions_and_pointer_aliases() {
    let valid = r#"
typedef char **Argv;
int main(void);
int main(int argc, char *argv[]);
int main(signed argc, Argv argv) { return 0; }
"#;
    assert!(check("ANZU-MAIN-SIGNATURE", valid, 0).is_empty());

    let invalid = r#"
void main(void);
int main(int argc);
int main(char argc, char **argv);
int main(int argc, char **argv, char **environment);
struct Holder { int main(char value); };
void nested(void) { int main(char value); }
"#;
    assert_eq!(
        check("ANZU-MAIN-SIGNATURE", invalid, 4),
        vec![(2, 1), (3, 1), (4, 1), (5, 1)]
    );
}

#[test]
fn anzu_label_rules_preserve_function_ownership_and_direct_adjacency() {
    let source = r#"
void first(int parameter) {
    parameter: ;
    int local;
    local: ;
    struct LocalType { int member; };
    LocalType: ;
    outer: inner: work();
    separated: { nested: work(); }
}
void second(void) {
    int only_here;
    local: ;
    only_here: ;
}
"#;
    assert_eq!(
        check("ANZU-LABEL-NAME-COLLISION", source, 4),
        vec![(3, 5), (5, 5), (7, 5), (14, 5)]
    );
    assert_eq!(check("ANZU-ADJACENT-LABELS", source, 1), vec![(8, 5)]);
}

#[test]
fn anzu_anonymous_nested_aggregate_excludes_named_typedef_and_nonmember_records() {
    let source = r#"
struct Outer {
    struct { int x; } member;
    union { int y; };
    enum { A, B } kind;
    typedef struct { int z; } Alias;
    struct Named { int value; } named;
};
void demo(void) { struct { int local; } value; }
"#;
    assert_eq!(
        check("ANZU-ANONYMOUS-NESTED-AGGREGATE", source, 3),
        vec![(3, 5), (4, 5), (5, 5)]
    );
}

#[test]
fn anzu_function_name_reuse_compares_cpp_qualified_names_and_local_identifiers() {
    let source = r#"
void global(void);
void parameters(int global, int safe) {}
void locals(void) { int global; int safe; }
namespace alpha { void task(void); int task; }
namespace beta { int task; }
struct Worker { void run(void); int run; int other; };
struct Other { int run; };
void pointer_target(void);
void (*pointer_target)(void);
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("function_names.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-FUNCTION-NAME-AS-IDENTIFIER")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![3, 4, 5, 7, 10], "{findings:#?}");
}

#[test]
fn anzu_backward_goto_resolves_labels_within_the_same_function() {
    let source = r#"
void first(int condition) {
earlier:
    work();
    if (condition) goto earlier;
    goto later;
later:
    work();
}
void second(void) {
    goto earlier;
earlier:
    work();
}
"#;
    assert_eq!(check("ANZU-BACKWARD-GOTO", source, 1), vec![(5, 20)]);
}

#[test]
fn anzu_return_use_checks_each_bare_return_and_missing_return_function() {
    let source = r#"
typedef void Void;
int missing(void) { work(); }
int bare(int condition) {
    if (condition) return;
    return /* comment */;
}
int valued(void) { return 0; }
void ordinary(void) { return; }
Void aliased(void) { return; }
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("return_use.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NONVOID-RETURN-USE")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![3, 5, 6], "{findings:#?}");
}

#[test]
fn anzu_std_namespace_checker_uses_cpp_qualified_declarations() {
    let source = r#"
namespace std {
int extension;
void helper(void) {}
}
namespace posix { int extension; }
namespace project { int extension; }
int std_value;
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("reserved.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-RESERVED-NAMESPACE-DECLARATION")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![3, 4, 6], "{findings:#?}");
    assert!(builtin_security_pack()
        .expect("pack")
        .scan_text(&Language::C, Path::new("reserved.c"), source)
        .iter()
        .all(|finding| finding.rule_id != "ANZU-RESERVED-NAMESPACE-DECLARATION"));
}

#[test]
fn anzu_unused_label_is_resolved_per_function() {
    let source = r#"
void first(void) {
used:
    work();
    goto used;
unused:
    work();
}
void second(void) {
    goto foreign;
foreign:
    work();
used:
    work();
}
"#;
    assert_eq!(check("ANZU-UNUSED-LABEL", source, 2), vec![(6, 1), (13, 1)]);
}

#[test]
fn anzu_noreturn_checker_only_reports_direct_return_children() {
    let source = r#"
[[noreturn]] void stop(int condition) {
    return;
    if (condition) { return; }
}
_Noreturn void halt(void) { return; }
void ordinary(void) { return; }
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("noreturn.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NORETURN-DIRECT-RETURN")
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![(3, 5), (6, 29)], "{findings:#?}");
}

#[test]
fn anzu_throw_checker_reports_pointer_typed_operands_only() {
    let source = r#"
void demo(int *parameter, int value) {
    int *local = parameter;
    throw parameter;
    throw local;
    throw &value;
    throw new int(1);
    throw "text";
    throw value;
    throw 1;
    throw;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("throw_pointer.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-THROW-POINTER")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![4, 5, 6, 7, 8], "{findings:#?}");
}

#[test]
fn anzu_class_member_access_rules_distinguish_fields_static_data_and_structs() {
    let source = r#"
class Sample {
    int hidden;
    static int hidden_static;
public:
    int exposed;
    static int public_static;
    void method(void);
protected:
    int inherited;
private:
    int safe;
};
struct PlainStruct { int public_by_default; };
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("members.cpp"),
        source,
    );
    let non_private = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-NONPRIVATE-DATA-MEMBER")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    let private_static = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-PRIVATE-STATIC-DATA-MEMBER")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(non_private, vec![6, 10], "{findings:#?}");
    assert_eq!(private_static, vec![4], "{findings:#?}");
}

#[test]
fn anzu_single_parameter_constructor_requires_explicit_in_classes_and_structs() {
    let source = r#"
class Value {
public:
    Value(int number);
    explicit Value(long number);
    Value();
    Value(int first, int second);
    ~Value();
};
struct Record {
    Record(double number) {}
};
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("constructors.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-SINGLE-PARAM-CONSTRUCTOR-EXPLICIT")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![4, 11], "{findings:#?}");
}

#[test]
fn anzu_postfix_operator_overloads_return_const_objects() {
    let source = r#"
class Counter {
public:
    Counter operator++(int);
    const Counter operator--(int);
    Counter &operator++();
};
Counter operator++(Counter value, int) { return value; }
Counter operator--(Counter value, int);
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("operators.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-POSTFIX-OPERATOR-CONST-RETURN")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![4, 8], "{findings:#?}");
}

#[test]
fn anzu_multiple_inheritance_compares_direct_base_member_names() {
    let source = r#"
class Left {
public:
    int value;
    void run(void);
};
class Right {
public:
    int value;
    void stop(void);
};
class Distinct {
public:
    int other;
};
class Ambiguous : public Left, private Right {};
class Safe : public Left, public Distinct {};
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("inheritance.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-AMBIGUOUS-MULTIPLE-INHERITANCE")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![16], "{findings:#?}");
}

#[test]
fn anzu_prefer_vector_only_reports_function_local_std_arrays() {
    let source = r#"
std::array<int, 4> global_values;
class Holder { std::array<int, 4> member_values; };
void demo(void) {
    std::array<int, 4> values;
    std::array<std::array<int, 2>, 3> matrix;
    std::vector<int> dynamic_values;
    project::array<int, 4> custom_values;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("arrays.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-PREFER-VECTOR-OVER-ARRAY")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![5, 6], "{findings:#?}");
}

#[test]
fn anzu_typedef_name_conflict_preserves_source_order_and_variable_kinds() {
    let source = r#"
int Before;
typedef int Before;
typedef int Alias;
void Alias(void);
void demo(void) {
    int Alias;
    void (*Before)(void);
}
struct Holder { int Alias; };
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("typedef_names.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-VARIABLE-MATCHES-TYPEDEF")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![7, 8, 10], "{findings:#?}");
}

#[test]
fn anzu_enumerator_variable_collision_is_ordered_and_context_aware() {
    let source = r#"
int Earlier;
enum FirstEnum { Earlier };
enum SecondEnum { Later, Shared };
int Later;
void first(void) {
    int Shared;
    enum LocalEnum { LocalName };
    int LocalName;
}
void second(void) { int LocalName; }
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("enum_names.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ENUMERATOR-VARIABLE-NAME-COLLISION")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![3, 5, 7, 9], "{findings:#?}");
}

#[test]
fn anzu_enum_values_are_unique_after_constant_and_implicit_evaluation() {
    let source = r#"
enum DuplicateImplicit { A = 3, B, C = 4, D = 9 };
enum DuplicateReference { E = 1, F = E + 2, G = 3 };
enum Unique { H = -2, I, J = 8 };
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        Path::new("enum_values.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ENUM-UNIQUE-VALUES")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![2, 3], "{findings:#?}");
}

#[test]
fn anzu_enum_initialization_is_all_explicit_or_first_only() {
    let source = r#"
enum AllImplicit { A, B, C };
enum FirstOnly { D = 4, E, F };
enum AllExplicit { G = 1, H = 2, I = 3 };
enum MissingMiddle { J = 1, K, L = 3 };
enum LateOnly { M, N = 2, O };
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        Path::new("enum_initialization.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ENUM-COMPLETE-INITIALIZATION")
        .map(|finding| finding.line)
        .collect::<Vec<_>>();
    assert_eq!(matches, vec![2, 5, 6], "{findings:#?}");
    assert!(
        findings
            .iter()
            .all(|finding| finding.rule_id != "LEGACY-C-AST-no-assignment-outside-statement"),
        "{findings:#?}"
    );
}

#[test]
fn anzu_cpp_function_pointer_variables_use_typedefs() {
    let source = r#"
typedef int (*Callback)(int);
int (*raw_global)(int);
Callback typed_global;
int *ordinary;
int returns_int(int value);
void demo(void) {
    int (*raw_local)(int);
    Callback typed_local;
}
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-CPP-RAW-FUNCTION-POINTER-TYPE");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::Cpp, Path::new("callbacks.cpp"), source);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        vec![(3, 1), (8, 5)]
    );
    assert!(pack
        .scan_text(&Language::C, Path::new("callbacks.c"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::Cpp, "callbacks.cpp", source).expect("C++ HIR");
    assert_eq!(
        pack.scan_hir(
            &hir,
            &HashMap::from([("callbacks.cpp".into(), source.into())])
        )
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>(),
        vec![(3, 1), (8, 5)]
    );
}

#[test]
fn anzu_fixed_char_array_initializers_leave_room_for_null_terminators() {
    let source = r#"
struct Holder {
    char name[4];
    char safe[5];
};
void demo(void) {
    char exact[3] = "abc";
    char short_buffer[2] = "abc";
    char enough[4] = "abc";
    char inferred[] = "abc";
    char matrix[2][3] = {"abc", "ok"};
    struct Holder holder = {"four", "four"};
}
"#;
    assert_eq!(
        check("ANZU-CHAR-ARRAY-NULL-TERMINATOR", source, 4),
        vec![(7, 21), (8, 28), (11, 26), (12, 29)]
    );
}

#[test]
fn anzu_pointer_variables_are_initialized() {
    let source = r#"
int *global_pointer;
int *initialized = 0;
int array[2];
void demo(int *parameter) {
    int *local_pointer;
    int (*callback)(void);
    int *ready = parameter;
}
"#;
    assert_eq!(
        check("ANZU-UNINITIALIZED-POINTER", source, 3),
        vec![(2, 1), (6, 5), (7, 5)]
    );
}

#[test]
fn anzu_parameters_do_not_shadow_variables_in_their_immediate_owner() {
    let source = r#"
int global_name;
struct Owner {
    static int member_name;
    void method(int member_name, int global_name) {}
};
void free_function(int global_name) {}
"#;
    assert_eq!(
        check("ANZU-PARAMETER-SHADOWS-GLOBAL", source, 2),
        vec![(5, 17), (7, 20)]
    );
}

#[test]
fn anzu_local_variables_do_not_shadow_global_or_owning_static_variables() {
    let source = r#"
int shared;
struct Owner {
    static int member;
    void method(void) {
        int shared;
        int member;
        static int safe_static;
    }
};
void free_function(void) {
    int shared;
}
"#;
    assert_eq!(
        check("ANZU-LOCAL-SHADOWS-GLOBAL", source, 3),
        vec![(6, 9), (7, 9), (12, 5)]
    );
}

#[test]
fn anzu_cpp_class_conversion_operators_are_reviewed() {
    let source = r#"
class Converter {
public:
    operator int() const;
    explicit operator bool() const;
    Converter &operator=(const Converter &other);
    int operator+(int value) const;
    void operator()() const;
};
struct StructConverter {
    operator int() const;
};
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-CPP-CONVERSION-OPERATOR");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::Cpp, Path::new("conversion.cpp"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(4, 5), (5, 5)]);
    assert!(pack
        .scan_text(&Language::C, Path::new("conversion.c"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::Cpp, "conversion.cpp", source).expect("C++ HIR");
    assert_eq!(
        pack.scan_hir(
            &hir,
            &HashMap::from([("conversion.cpp".into(), source.into())])
        )
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_cpp_virtual_methods_do_not_declare_default_arguments() {
    let source = r#"
struct Base {
    virtual void direct(int value = 1);
    virtual void inherited(int value);
    void ordinary(int value = 2);
};
struct Derived : Base {
    void inherited(int value = 3);
    void ordinary(int value = 4);
    static void static_method(int value = 5);
};
void free_function(int value = 6);
"#;
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|candidate| candidate.id == "ANZU-CPP-VIRTUAL-DEFAULT-ARGUMENT");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_text(&Language::Cpp, Path::new("virtual_defaults.cpp"), source);
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    assert_eq!(coordinates, vec![(3, 37), (8, 32)]);
    assert!(pack
        .scan_text(&Language::C, Path::new("virtual_defaults.c"), source)
        .is_empty());
    let hir = parse_c_like_file(Language::Cpp, "virtual_defaults.cpp", source).expect("C++ HIR");
    assert_eq!(
        pack.scan_hir(
            &hir,
            &HashMap::from([("virtual_defaults.cpp".into(), source.into())])
        )
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>(),
        coordinates
    );
}

#[test]
fn anzu_allocation_deallocation_checker_preserves_record_and_namespace_pairing() {
    fn scan(rule: &str, source: &str) -> Vec<(usize, usize, String)> {
        static PACK: OnceLock<BaselinePack> = OnceLock::new();
        let mut pack = PACK
            .get_or_init(|| builtin_security_pack().expect("pack"))
            .clone();
        pack.rules.retain(|candidate| candidate.id == rule);
        assert_eq!(pack.rules.len(), 1, "missing {rule}");
        pack.scan_text(&Language::Cpp, Path::new("allocation.cpp"), source)
            .into_iter()
            .map(|finding| (finding.line, finding.column, finding.message))
            .collect()
    }

    let scalar = "ANZU-CPP-ALLOCATION-DEALLOCATION-SCALAR-PAIR";
    let array = "ANZU-CPP-ALLOCATION-DEALLOCATION-ARRAY-PAIR";

    let source = r#"struct ScalarBad {
    void* operator new(unsigned long size);
};
struct ScalarGood {
    void* operator new(unsigned long size);
    void operator delete(void* ptr);
};
struct ArrayBad {
    void* operator new[](unsigned long size);
};
struct ArrayGood {
    void* operator new[](unsigned long size);
    void operator delete[](void* ptr);
};
namespace product {
struct Box {
    void* operator new(unsigned long size);
    void operator delete(void* ptr);
};
void* Box::operator new(unsigned long size) { return 0; }
void Box::operator delete(void* ptr) { }
}
namespace first {
void* operator new(unsigned long size) { return 0; }
Token operator+(Token lhs, Token rhs) { return lhs; }
}
namespace second {
void operator delete(void* ptr) { }
}
namespace left { namespace same {
void* operator new(unsigned long size) { return 0; }
} }
namespace right { namespace same {
void operator delete(void* ptr) { }
} }
void* operator new(unsigned long size) { return 0; }
void operator delete(void* ptr) { }
void* operator new[](unsigned long size) { return 0; }
void operator delete[](void* ptr) { }
"#;

    let scalar_findings = scan(scalar, source);
    assert_eq!(
        scalar_findings
            .iter()
            .map(|finding| (finding.0, finding.1))
            .collect::<Vec<_>>(),
        vec![(2, 5), (25, 1), (28, 1)]
    );
    assert!(scalar_findings
        .iter()
        .all(|finding| finding.2.contains("operator new and operator delete")));

    let array_findings = scan(array, source);
    assert_eq!(
        array_findings
            .iter()
            .map(|finding| (finding.0, finding.1))
            .collect::<Vec<_>>(),
        vec![(9, 5)]
    );
    assert!(array_findings[0]
        .2
        .contains("operator new[] and operator delete[]"));

    // The legacy checker keys free-function state only by the immediate
    // namespace name, so the two `same` namespaces intentionally collide.
    let mut c_pack = builtin_security_pack().expect("pack");
    c_pack.rules.retain(|candidate| candidate.id == scalar);
    assert!(c_pack
        .scan_text(&Language::C, Path::new("allocation.c"), source)
        .is_empty());
}

#[test]
fn anzu_standard_library_function_redefinition_covers_every_legacy_name() {
    for name in [
        "printf", "scanf", "malloc", "free", "exit", "getchar", "putchar", "fopen",
        "fclose", "memset", "memcpy", "strcmp", "strlen", "strcat", "atoi", "atof",
        "sin", "cos", "tan", "sqrt", "pow",
    ] {
        let source = format!("int {name}(void) {{ return 0; }}");
        assert_eq!(
            check("ANZU-STANDARD-LIBRARY-FUNCTION-REDEFINITION", &source, 1),
            vec![(1, 1)],
            "legacy name {name}"
        );
    }
    assert!(check(
        "ANZU-STANDARD-LIBRARY-FUNCTION-REDEFINITION",
        "int product_function(void) { return 0; }",
        0
    )
    .is_empty());
}
