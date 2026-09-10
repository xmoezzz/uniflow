use std::collections::HashMap;
use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;
use uniflow_lang_frontends::parse_file;
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
fn anzu_printf_family_requires_literal_format_at_each_signature_position() {
    for (rule, call, expected) in [
        ("UF-C-PRINTF-NONLITERAL", "printf(format, value);", 1),
        ("UF-C-PRINTF-NONLITERAL", "printf(\"%d\", value);", 0),
        (
            "UF-C-FPRINTF-NONLITERAL",
            "fprintf(stream, format, value);",
            1,
        ),
        (
            "UF-C-FPRINTF-NONLITERAL",
            "fprintf(stream, \"%d\", value);",
            0,
        ),
        (
            "UF-C-FPRINTF-NONLITERAL",
            "sprintf(buffer, format, value);",
            1,
        ),
        (
            "UF-C-FPRINTF-NONLITERAL",
            "sprintf(buffer, \"%d\", value);",
            0,
        ),
        (
            "UF-C-FPRINTF-NONLITERAL",
            "snprintf(buffer, size, format, value);",
            1,
        ),
        (
            "UF-C-FPRINTF-NONLITERAL",
            "snprintf(buffer, size, \"%d\", value);",
            0,
        ),
    ] {
        let source = format!(
            "void demo(void *stream, char *buffer, int size, char *format, int value) {{ {call} }}"
        );
        let program = parse_c_like_file(Language::C, "formats.c", &source).expect("parse");
        let sources = HashMap::from([("formats.c".to_string(), source)]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == rule)
                .count(),
            expected,
            "{call}: {findings:#?}"
        );
    }
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
fn detects_assignment_used_as_direct_logical_operand() {
    let source = r#"
int read_value(void);
void demo(int ready) {
    int value = 0;
    if ((value = read_value()) && ready) {}
    if ((value == read_value()) && ready) {}
    if (value = read_value() && ready) {}
}
"#;
    let program = parse_c_like_file(Language::C, "logical.c", source).expect("parse");
    let sources = HashMap::from([("logical.c".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ASSIGNMENT-IN-LOGICAL-OP")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}\nHIR: {program:#?}");
}

#[test]
fn anzu_false_static_assert_requires_a_known_false_constant_expression() {
    let source = r#"
#define HIDDEN_FAILURE _Static_assert(0, "macro")
const char *text = "_Static_assert(0, hidden)";
// _Static_assert(0, "comment")
_Static_assert(0, "zero");
_Static_assert(1 == 2, "comparison");
_Static_assert((2 + 3) * 4 < 10, "arithmetic");
_Static_assert(1 ? 0 : 1, "conditional");
_Static_assert(1, "true");
_Static_assert(unknown_constant, "not semantically known");
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("static_assert.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-FALSE-STATIC-ASSERT")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 4, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![5, 6, 7, 8]
    );
}

#[test]
fn anzu_single_declaration_only_reports_multi_var_decl_stmts_in_code_bodies() {
    let source = r#"
int global_a, global_b;
struct Pair { int left, right; };
void declared(int first, int second);
void demo(void) {
    int one;
    int first = 1, second = 2;
    for (int i = 0, j = 1; i < j; ++i) {}
    int third; int fourth;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("single_declaration.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-SINGLE-DECLARATION")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![7, 8]
    );
}

#[test]
fn anzu_pointer_typedef_excludes_function_types_function_pointers_and_arrays() {
    let source = r#"
#define HIDDEN_TYPEDEF typedef int *HiddenPointer
typedef int Value;
typedef int *IntPointer;
typedef int (*Callback)(void);
typedef int *ReturnsPointer(void);
typedef int *PointerArray[4];
typedef int (*ArrayPointer)[4];
typedef int (**CallbackHandle)(void);
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("pointer_typedef.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-POINTER-TYPEDEF")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![4, 8, 9]
    );
}

#[test]
fn migrated_rand_checker_matches_intended_direct_prng_calls() {
    for (callee, expected) in [("rand", 1), ("random", 1), ("harmless", 0)] {
        let source = format!("void demo(void) {{ {callee}(); }}");
        let program = parse_c_like_file(Language::C, "rand.c", &source).expect("parse");
        let sources = HashMap::from([("rand.c".to_string(), source)]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == "UF-C-RAND-WEAK")
            .count();
        assert_eq!(matches, expected, "callee {callee}: {findings:#?}");
    }
}

#[test]
fn migrated_goto_checker_ignores_comments_and_literals() {
    let source = r#"
void demo(int ready) {
    puts("goto hidden;");
    // goto commented;
    #define LEAVE goto cleanup
    if (ready) goto cleanup;
cleanup:
    return;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("goto.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-DISABLE-GOTO")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}");
    assert_eq!(matches[0].line, 6);
}

#[test]
fn migrated_pragma_checker_matches_only_real_directives() {
    let source = r##"
const char *text = "#pragma message(hidden)";
// #pragma once
 # pragma pack(push, 1)
"##;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("pragma.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-PRAGMA-USE")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}");
    assert_eq!(matches[0].line, 4);
}

#[test]
fn migrated_putenv_checker_requires_automatic_storage() {
    let cases = [
        (
            "void demo(void) { char value[] = \"A=B\"; putenv(value); }",
            1,
        ),
        ("void demo(char *value) { putenv(value); }", 1),
        (
            "void demo(void) { static char value[] = \"A=B\"; putenv(value); }",
            0,
        ),
        (
            "char global[] = \"A=B\"; void demo(void) { putenv(global); }",
            0,
        ),
        ("void demo(void) { putenv(\"A=B\"); }", 0),
    ];
    for (source, expected) in cases {
        let program = parse_c_like_file(Language::C, "putenv.c", source).expect("parse");
        let sources = HashMap::from([("putenv.c".to_string(), source.to_string())]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == "UF-C-ENV-PUTENV")
            .count();
        assert_eq!(matches, expected, "source: {source}\n{findings:#?}");
    }
}

#[test]
fn migrated_register_checker_matches_only_code_tokens() {
    let source = r#"
#define OLD_STORAGE register
const char *text = "register int hidden";
// register int commented;
void demo(void) { register int value = 0; }
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("register.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-REGISTER-USE")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}");
    assert_eq!(matches[0].line, 5);
}

#[test]
fn migrated_long_literal_checker_distinguishes_lowercase_suffixes() {
    let source = r#"
#define GENERATED 99l
const char *text = "77ll";
long a = 1l;
long b = 2L;
long long c = 0xFFull;
long long d = 0xFFULL;
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("literal.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-LONG-LITERAL-LOWERCASE-L")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![4, 6]
    );
}

#[test]
fn migrated_file_open_checker_validates_only_literal_mode_strings() {
    let cases = [
        ("void demo(void) { fopen(\"data\", \"r\"); }", 0),
        ("void demo(void) { fopen(\"data\", \"rw\"); }", 1),
        ("void demo(char *mode) { fopen(\"data\", mode); }", 0),
        ("void demo(void) { fopen_s(&file, \"data\", \"r+b\"); }", 0),
        ("void demo(void) { fopen_s(&file, \"data\", \"read\"); }", 1),
    ];
    for (source, expected) in cases {
        let program = parse_c_like_file(Language::C, "open.c", source).expect("parse");
        let sources = HashMap::from([("open.c".to_string(), source.to_string())]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.rule_id.as_str(),
                    "ANZU-FILE-OPEN-MODE" | "ANZU-FILE-OPEN-S-MODE"
                )
            })
            .count();
        assert_eq!(matches, expected, "source: {source}\n{findings:#?}");
    }
}

#[test]
fn migrated_int05_checker_preserves_legacy_format_constraints() {
    let cases = [
        ("void demo(void) { scanf(\"%d\", &value); }", 1),
        ("void demo(void) { scanf_s(\"%lf\", &value); }", 1),
        ("void demo(void) { scanf(\"%10d\", &value); }", 0),
        ("void demo(char *format) { scanf(format, &value); }", 0),
    ];
    for (source, expected) in cases {
        let program = parse_c_like_file(Language::C, "input.c", source).expect("parse");
        let sources = HashMap::from([("input.c".to_string(), source.to_string())]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == "ANZU-INT05-INPUT-CONVERSION")
            .count();
        assert_eq!(matches, expected, "source: {source}\n{findings:#?}");
    }
}

#[test]
fn migrated_c_style_stream_checker_preserves_cpp_extension_gate() {
    let cases = [
        (Language::Cpp, "stream.cpp", 1),
        (Language::Cpp, "stream.cc", 0),
        (Language::C, "stream.cpp", 0),
    ];
    for (language, path, expected) in cases {
        let source = "void demo(void) { printf(\"hello\"); }";
        let program = parse_c_like_file(language, path, source).expect("parse");
        let sources = HashMap::from([(path.to_string(), source.to_string())]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == "ANZU-CPP-NO-C-STYLE-STREAMS")
            .count();
        assert_eq!(matches, expected, "path: {path}\n{findings:#?}");
    }
}

#[test]
fn migrated_deprecated_stdlib_checker_requires_std_namespace() {
    for (callee, expected) in [
        ("std::random_shuffle", 1),
        ("std::bind1st", 1),
        ("random_shuffle", 0),
        ("project::random_shuffle", 0),
    ] {
        let source = format!("void demo(void) {{ {callee}(first, last); }}");
        let program = parse_c_like_file(Language::Cpp, "deprecated.cpp", &source).expect("parse");
        let sources = HashMap::from([("deprecated.cpp".to_string(), source)]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == "ANZU-CPP-DEPRECATED-STDLIB")
            .count();
        assert_eq!(matches, expected, "callee: {callee}\n{findings:#?}");
    }
}

#[test]
fn migrated_obsolescent_function_checker_requires_global_name() {
    for (callee, expected) in [
        ("printf", 1),
        ("strcpy", 1),
        ("std::printf", 0),
        ("object.printf", 0),
        ("safe_printf", 0),
    ] {
        let source = format!("void demo(void) {{ {callee}(value); }}");
        let program = parse_c_like_file(Language::Cpp, "obsolete.cpp", &source).expect("parse");
        let sources = HashMap::from([("obsolete.cpp".to_string(), source)]);
        let findings = builtin_security_pack()
            .expect("pack")
            .scan_hir(&program, &sources);
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == "ANZU-OBSOLESCENT-C-LIBRARY-FUNCTION")
            .count();
        assert_eq!(matches, expected, "callee: {callee}\n{findings:#?}");
    }
}

#[test]
fn migrated_macro_hash_checker_tokenizes_function_like_macros() {
    let source = r##"
#define OBJECT #value
#define EMPTY() #value
#define STRINGIFY(value) #value
#define PASTE(left, right) left ## right
#define TEXT(value) "#value ## ignored"
#define CONTINUED(left, right) #left \
    ## right
"##;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("macros.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-BODY-HASH")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![4, 5, 7]
    );
}

#[test]
fn migrated_multiple_macro_hash_checker_counts_hashhash_as_one_token() {
    let source = r#"
#define ONE(left, right) left ## right
#define TWO(value, suffix) #value ## suffix
#define TWO_SEPARATE(a, b) #a #b
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("macros.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-BODY-MULTIPLE-HASH")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[test]
fn migrated_macro_semicolon_checker_handles_continuations_and_literals() {
    let source = r#"
#define VALUE 42;
#define SAFE(value) do { use(value); } while (0)
#define TEXT "not a body terminator;"
#define MULTILINE(value) use(value) \
    ;
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("semicolon.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-TRAILING-SEMICOLON")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![2, 6]
    );
}

#[test]
fn migrated_multistatement_macro_checker_preserves_wrapper_exemptions() {
    let source = r#"
#define BAD(value) prepare(value); consume(value)
#define BAD_MULTILINE(value) prepare(value); \
    consume(value)
#define TRAILING_ONLY(value) consume(value);
#define WRAPPED(value) do { prepare(value); consume(value); } while (0)
#define CONDITIONAL(value) if (value) consume(value); finish(value)
#define TEXT "first; second"
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("multi.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-MACRO-UNWRAPPED-MULTISTATEMENT")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
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

#[test]
fn migrated_java_ast_lexical_rules_respect_token_boundaries() {
    let source = r#"
class LexicalRules {
    // String fake = "YYYY/MM/dd"; int $commented = 0;
    String text = "the token $inside is not an identifier";
    String slash = "\\";
    String date = "YYYY/MM/dd";
    String address = "192.168.10.20";
    int $generated = 1;
    void broad() throws Throwable {}
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Java,
        std::path::Path::new("LexicalRules.java"),
        source,
    );
    for rule_id in [
        "LEGACY-JAVA-AST-hardcode-file-delimiter",
        "LEGACY-JAVA-AST-identifier-invalid-char",
        "LEGACY-JAVA-AST-weakyear-date",
        "LEGACY-JAVA-AST-hard-code-ip",
        "LEGACY-JAVA-AST-overly-board-throws",
    ] {
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{rule_id}: {findings:#?}");
    }
}

#[test]
fn migrated_java_ast_call_rules_use_hir_callees_and_arguments() {
    let source = r#"
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.sql.DataSource;
import javax.crypto.Cipher;
import javax.net.ssl.SSLContext;
import java.security.MessageDigest;
import java.io.DataInputStream;
import java.net.URL;
import java.util.Random;
import java.util.concurrent.ScheduledThreadPoolExecutor;
class CallRules {
    void check(String value) {
        value.indexOf("x");
        DriverManager.getConnection("jdbc:test", "admin", "");
        System.out.println(value);
        System.getenv("HOME");
        SSLContext.getInstance("SSL");
        Cipher.getInstance("RSA/ECB/NoPadding");
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        MessageDigest.getInstance("MD5");
        new Boolean(true);
        new String("copy");
        new ScheduledThreadPoolExecutor(0);
        new Integer(127);
        new Integer(128);
        System.exit(1);
        value.equals("");
    }
    void jdbc(PreparedStatement statement, ResultSet results, DataSource dataSource, String value) {
        dataSource.getConnection("admin", "ignored", null);
        statement.setString(0, value);
        results.getString(0);
    }
    void io(URL url, DataInputStream input, ScheduledThreadPoolExecutor pool) {
        url.equals(new URL("https://example.test"));
        input.readInt();
        pool.setMaximumPoolSize(8);
    }
    void threads(Random random, Thread worker, ThreadGroup group) {
        random.nextInt();
        worker.run();
        worker.stop();
        group.suspend();
    }
    void contexts(Object lock, int[] first, int[] second) {
        lock.wait();
        while (ready) { lock.wait(); }
        first.hashCode();
        first.equals(second);
    }
}
"#;
    let program = JavaParser::default()
        .parse_file("CallRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("CallRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    for rule_id in [
        "LEGACY-JAVA-AST-call-indexof-param",
        "LEGACY-JAVA-AST-http-servlet-use-db",
        "LEGACY-JAVA-AST-use-system-out-println",
        "LEGACY-JAVA-AST-obsolete-functions",
        "LEGACY-JAVA-AST-weak-ssl-protocol",
        "LEGACY-JAVA-AST-check-rsa-nopadding",
        "LEGACY-JAVA-AST-not-safe-cryptographic-algorithm",
        "LEGACY-JAVA-AST-not-safe-cryptographic-algorithm-2",
        "LEGACY-JAVA-AST-use-empty-password",
        "LEGACY-JAVA-AST-create-boolean-object",
        "LEGACY-JAVA-AST-create-string-object",
        "LEGACY-JAVA-AST-error-maximum-pool-size",
        "LEGACY-JAVA-AST-use-system-exit-sjt",
        "LEGACY-JAVA-AST-use-null-password",
        "LEGACY-JAVA-AST-empty-string-compare",
        "LEGACY-JAVA-AST-invalid-index",
        "LEGACY-JAVA-AST-invalid-index-1",
        "LEGACY-JAVA-AST-compare-url",
        "LEGACY-JAVA-AST-little-endian-method",
        "LEGACY-JAVA-AST-set-maximum-pool-size",
        "LEGACY-JAVA-AST-check-use-random",
        "LEGACY-JAVA-AST-check-use-random-ydt",
        "LEGACY-JAVA-AST-call-unsafe-threadrun-method-ydt",
        "LEGACY-JAVA-AST-call-unsafe-threadstop-method",
        "LEGACY-JAVA-AST-call-unsafe-threadstop-method-ydt",
        "LEGACY-JAVA-AST-call-unsafe-threadgroup-method",
        "LEGACY-JAVA-AST-call-unsafe-threadgroup-method-ydt",
        "LEGACY-JAVA-AST-integer-ctor-use-number",
        "LEGACY-JAVA-AST-call-wait-await-method",
        "LEGACY-JAVA-AST-call-wait-await-method-ydt",
        "LEGACY-JAVA-AST-array-hashcode",
        "LEGACY-JAVA-AST-check-array-equals",
    ] {
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "{rule_id}: {findings:#?}\nHIR: {program:#?}"
        );
    }
}

#[test]
fn migrated_java_typed_argument_rules_preserve_positive_and_negative_cases() {
    let source = r#"
import java.math.BigDecimal;
import java.io.File;
class TypedRules {
    void check(byte[] bytes, File directory, Object response) {
        new BigDecimal(0.1);
        new BigDecimal("0.1");
        new String(bytes);
        new String("text");
        response.setHeader("Content-Length", "-1");
        response.setHeader("Content-Length", "12");
        directory.mkdir();
        boolean created = directory.mkdir();
    }
}
"#;
    let program = JavaParser::default()
        .parse_file("TypedRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("TypedRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    for rule_id in [
        "LEGACY-JAVA-AST-bigdecimal-ctor-use-floating-param",
        "LEGACY-JAVA-AST-byte-to-string-encode",
        "LEGACY-JAVA-AST-content-length",
        "LEGACY-JAVA-AST-unchecked-return-value",
    ] {
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "{rule_id}: {findings:#?}\nHIR: {program:#?}"
        );
    }
}

#[test]
fn migrated_java_nan_comparison_rules_use_hir_operands() {
    let source = r#"
class NanRules {
    boolean bad(double value) { return value == Double.NaN; }
    boolean alsoBad(double value) { return Double.NaN != value; }
    boolean good(double value) { return Double.isNaN(value); }
}
"#;
    let program = JavaParser::default()
        .parse_file("NanRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("NanRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    for rule_id in [
        "LEGACY-JAVA-AST-compare-nan",
        "LEGACY-JAVA-AST-compare-nan-ydt",
    ] {
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .count(),
            2,
            "{rule_id}: {findings:#?}\nHIR: {program:#?}"
        );
    }
}

#[test]
fn migrated_java_string_comparison_rule_uses_static_operand_types() {
    let source = r#"
class StringRules {
    boolean bad(String left, String right) { return left == right; }
    boolean alsoBad(String left, Object right) { return left != right; }
    boolean nullCheck(String value) { return value == null; }
    boolean contentCheck(String left, String right) { return left.equals(right); }
}
"#;
    let program = JavaParser::default()
        .parse_file("StringRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("StringRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JAVA-AST-string-compare")
            .count(),
        2,
        "{findings:#?}\nHIR: {program:#?}"
    );
}

#[test]
fn migrated_java_class_name_rule_uses_nested_hir_call_chain() {
    let source = r#"
class ClassNameRules {
    boolean bad(Object value, String name) {
        return value.getClass().getName().equals(name);
    }
    boolean good(Object value, Object expected) {
        return value.getClass().equals(expected);
    }
    boolean unrelated(String value, String name) {
        return value.trim().equals(name);
    }
}
"#;
    let program = JavaParser::default()
        .parse_file("ClassNameRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("ClassNameRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JAVA-AST-compare-class-name")
            .count(),
        1,
        "{findings:#?}\nHIR: {program:#?}"
    );
}

#[test]
fn migrated_java_null_return_rule_uses_enclosing_function_context() {
    let source = r#"
class NullReturnRules {
    String badString() { return null; }
    Object clone() { return null; }
    Object allowed() { return null; }
    String nonNull() { return "value"; }
}
"#;
    let program = JavaParser::default()
        .parse_file("NullReturnRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("NullReturnRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JAVA-AST-string-clone-null")
            .count(),
        2,
        "{findings:#?}\nHIR: {program:#?}"
    );
}

#[test]
fn migrated_java_finally_rules_use_hir_control_flow_context() {
    let source = r#"
class FinallyRules {
    int returnOutside() { return 1; }
    void throwOutside() { throw new RuntimeException(); }

    int returnInside() {
        try { work(); } finally { return 2; }
    }

    void throwInside() {
        try { work(); } finally { throw new RuntimeException(); }
    }

    void lambdaBoundary() {
        try { work(); } finally {
            java.util.function.Supplier<Integer> task = () -> { return 3; };
        }
    }
}
"#;
    let program = JavaParser::default()
        .parse_file("FinallyRules.java", source)
        .expect("parse");
    let sources = HashMap::from([("FinallyRules.java".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    for rule_id in [
        "LEGACY-JAVA-AST-finally_block_return",
        "LEGACY-JAVA-AST-finally_block_throw",
    ] {
        let matches = findings
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "{rule_id}: {findings:#?}\nHIR: {program:#?}"
        );
    }
}

#[test]
fn migrated_c_ast_token_rules_preserve_lexical_and_path_constraints() {
    let source = r#"
#pragma pack(push, 1)
#include "/opt/vendor/api.h"
#include "bad\\name.h"
register long long l = 1ul;
int O = 0;
union Payload { int value; };
void variadic(int first, ...);
void loop(void) {
    l += 1;
    for (;;) { continue; }
    if (O) goto done;
done: return;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("style.c"),
        source,
    );
    for rule_id in [
        "LEGACY-C-AST-no-goto",
        "LEGACY-C-AST-no-continue",
        "LEGACY-C-AST-no-register-storage-class",
        "LEGACY-C-AST-no-long-long",
        "LEGACY-C-AST-number-literal-suffix-must-be-upper-case",
        "LEGACY-C-AST-no-pragma",
        "LEGACY-C-AST-no-union",
        "LEGACY-C-AST-no-variadic-parameter",
        "LEGACY-C-AST-no-assignment-plus-minus",
        "LEGACY-C-AST-no-infinite-for",
        "LEGACY-C-AST-no-infinite-loop",
        "LEGACY-C-AST-no-l-O-as-identifier",
        "LEGACY-C-AST-no-absolute-include",
        "LEGACY-C-AST-no-special-chars-in-header-name",
    ] {
        assert!(
            findings.iter().any(|finding| finding.rule_id == rule_id),
            "missing {rule_id}: {findings:#?}"
        );
    }
}

#[test]
fn migrated_c_ast_call_rules_use_structured_hir_calls() {
    let source = r#"
void demo(char *buffer, void *state) {
    gets(buffer);
    setjmp(state);
    longjmp(state, 1);
    abort();
}
"#;
    let program = parse_c_like_file(Language::C, "legacy_calls.c", source).expect("parse");
    let sources = HashMap::from([("legacy_calls.c".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    for rule_id in [
        "LEGACY-C-AST-no-gets",
        "LEGACY-C-AST-no-exit-abort",
        "LEGACY-C-AST-no-setjmp-longjmp",
    ] {
        assert!(
            findings.iter().any(|finding| finding.rule_id == rule_id),
            "missing {rule_id}: {findings:#?}\nHIR: {program:#?}"
        );
    }
}

#[test]
fn migrated_cpp_operator_rules_reject_only_operator_declarations() {
    let source = r#"
struct Value {
    Value operator,(const Value &other);
    bool operator&&(const Value &other);
};
void ordinary(int a, int b) { int c = (a, b); }
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("operators.cpp"),
        source,
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-C-AST-no-overload-comma")
            .count(),
        1
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-C-AST-no-overload-logical-and-or")
            .count(),
        1
    );
}

#[test]
fn migrated_csharp_ast_rules_match_typed_calls_and_constructors() {
    let source = r#"
class Security {
    void Configure(Random random, HttpResponse response, HttpHeaders headers, RSACryptoServiceProvider rsa) {
        random.NextBytes(buffer);
        DES.Create();
        response.AddHeader("Access-Control-Allow-Origin", "*");
        headers.AddWithoutValidate("Access-Control-Allow-Origin", "*");
        options.EnableHeaderChecking = false;
        var formatter = new RSAPKCS1SignatureFormatter(key);
        var a = new ConnectionOptions("server", "user", null);
        var b = new UserNameSecurityToken("user", "");
        var padding = RSAEncryptionPadding.Pkcs1;
        var weakKey = new RSACryptoServiceProvider(1024);
        var strongKey = new RSACryptoServiceProvider(2048);
        rsa.Encrypt(buffer, false);
        rsa.Decrypt(buffer, true);
    }
}
"#;
    let program = parse_file(Language::CSharp, "Security.cs", source).expect("parse C#");
    let sources = HashMap::from([("Security.cs".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    for rule_id in [
        "LEGACY-CS-AST-SCS0005",
        "LEGACY-CS-AST-SCS0010",
        "LEGACY-CS-AST-encapsulation_overly_permissive_cors_policy_1",
        "LEGACY-CS-AST-encapsulation_overly_permissive_cors_policy_2",
        "LEGACY-CS-AST-security_features_header_checking_disabled",
        "LEGACY-CS-AST-security_features_inadequate_rsa_padding_2",
        "LEGACY-CS-AST-security_features_inadequate_rsa_padding_3",
        "LEGACY-CS-AST-security_features_null_password_1",
        "LEGACY-CS-AST-security_features_null_password_2",
        "LEGACY-CS-AST-security_features_insufficient_key_size",
        "LEGACY-CS-AST-security_features_inadequate_rsa_padding_1",
    ] {
        assert!(
            findings.iter().any(|finding| finding.rule_id == rule_id),
            "missing {rule_id}: {findings:#?}\nHIR: {program:#?}"
        );
    }
    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                finding.rule_id == "LEGACY-CS-AST-security_features_insufficient_key_size"
            })
            .count(),
        1,
        "{findings:#?}"
    );
    assert_eq!(
        findings
            .iter()
            .filter(|finding| {
                finding.rule_id == "LEGACY-CS-AST-security_features_inadequate_rsa_padding_1"
            })
            .count(),
        1,
        "{findings:#?}"
    );
}

#[test]
fn anzu_variadic_function_matches_only_top_level_c_varargs_parameters() {
    let source = r#"
#define VARIADIC_MACRO(...) (__VA_ARGS__)
const char *text = "void hidden(int, ...);";
void declared(int first, ...);
void defined(int first, ...) {}
void callback_only(void (*callback)(int, ...)) {}
void ordinary(int first, int second) {}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("variadic.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "LEGACY-C-AST-no-variadic-parameter")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![4, 5]
    );
}

#[test]
fn anzu_initialized_extern_reports_each_initializer_and_only_external_storage() {
    let source = r#"
extern int declaration_only;
extern int first = 1, second, third = 3;
static int internal = 4;
int ordinary = 5;
void demo(void) {
    extern int local_only;
    extern int local_initialized = 6;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("extern_init.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "LEGACY-C-AST-no-init-in-extern-declaration")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![3, 3, 8]
    );
}

#[test]
fn anzu_triple_pointer_checks_variables_and_parameters_but_not_fields_or_typedefs() {
    let source = r#"
typedef int ***TripleAlias;
struct Holder { int ***field; };
int **two_levels;
int ***global_first, ***global_second;
void consume(int ***parameter, int **allowed) {
    int ***local;
    int (**function_pointer)(void);
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("triple_pointer.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-TRIPLE-POINTER")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 4, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![5, 5, 6, 7]
    );
}

#[test]
fn anzu_long_long_checker_matches_only_direct_signed_var_decl_types() {
    let source = r#"
typedef signed long long Count;
typedef unsigned long long UnsignedCount;
struct Values {
    long long field;
    static long long shared;
};
long long returns_long_long(void);
long long global_first, global_second;
unsigned long long unsigned_value;
Count aliased_value;
void consume(long long parameter, long long array_parameter[2]) {
    long long local;
    long long *pointer;
    UnsignedCount still_unsigned;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("long_long.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "LEGACY-C-AST-no-long-long")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 6, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![6, 9, 9, 11, 12, 13]
    );
}

#[test]
fn anzu_incomplete_struct_distinguishes_declarations_from_existing_type_uses() {
    let source = r#"
#define HIDDEN_FORWARD struct Hidden
struct First;
struct First *first_use;
struct First;
struct Complete { int value; };
struct Complete *complete_use;
struct Introduced *introduced_here;
struct Introduced *later_use;
union IgnoredUnion;
typedef struct Tagged Tagged;
typedef struct Tagged TaggedAgain;
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("incomplete_struct.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-INCOMPLETE-STRUCT-DECLARATION")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 4, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![3, 5, 8, 11]
    );
}

#[test]
fn anzu_delete_this_accepts_only_the_bare_parenthesized_this_operand() {
    let source = r#"
#define HIDDEN_DELETE delete this
struct Owner {
    int *member;
    void release(int *other) {
        delete this;
        delete (this);
        delete[] ((this));
        delete other;
        delete this->member;
        const char *text = "delete this";
        // delete this;
    }
};
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("delete_this.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-DELETE-THIS")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![6, 7, 8]
    );
}

#[test]
fn anzu_vfork_checker_matches_only_the_direct_global_call() {
    let source = r#"
int vfork(void);
int my_vfork(void);
void demo(void) {
    vfork();
    my_vfork();
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("vfork.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NO-VFORK")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}");
    assert_eq!(matches[0].line, 5);

    let indirect = "void demo(void) { int (*vfork)(void) = acquire(); vfork(); }";
    let indirect_findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("indirect_vfork.c"),
        indirect,
    );
    assert!(
        indirect_findings
            .iter()
            .all(|finding| finding.rule_id != "ANZU-NO-VFORK"),
        "{indirect_findings:#?}"
    );
}

#[test]
fn anzu_plain_char_checker_preserves_var_decl_and_typedef_semantics() {
    let source = r#"
typedef char Character;
struct Text {
    char field;
    static char shared;
};
char returns_char(void);
char global_first, global_second;
signed char signed_value;
unsigned char unsigned_value;
Character aliased_value;
void consume(char parameter, char array_parameter[2]) {
    char local;
    char *pointer;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("plain_char.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-EXPLICIT-CHAR-SIGNEDNESS")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 6, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![5, 8, 8, 11, 12, 13]
    );
}

#[test]
fn anzu_logical_not_constant_requires_an_integer_constant_operand_in_a_body() {
    let source = r#"
#define HIDDEN_NOT !0
int global_value = !0;
void demo(int value) {
    int first = !0;
    int second = !42;
    int third = !(1 == 1);
    int fourth = !value;
    int fifth = !HIDDEN_NOT;
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("logical_not_constant.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NO-LOGICAL-NOT-ON-CONSTANT")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![5, 6, 7]
    );
}

#[test]
fn anzu_empty_function_parameters_covers_prototypes_and_definitions_not_function_pointers() {
    let source = r#"
#define HIDDEN_EMPTY() void hidden()
void declared();
void defined() {}
void explicit_void(void);
int (*callback)();
void takes_callback(void (*named_callback)());
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("empty_parameters.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-EXPLICIT-VOID-PARAMETER-LIST")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[test]
fn anzu_incomplete_array_checks_var_decls_without_inferred_or_parameter_bounds() {
    let source = r#"
typedef int IncompleteAlias[];
struct Holder { int flexible[]; };
extern int first[];
int second[], bounded[2];
int initialized[] = {1, 2};
void consume(int parameter[]) {
    int local[];
    int *pointer_array[];
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("incomplete_array.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-INCOMPLETE-ARRAY-VARIABLE")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 4, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![4, 5, 8, 9]
    );
}

#[test]
fn anzu_named_prototype_parameters_ignore_definitions_and_nested_parameters() {
    let source = r#"
void named(int value, void (*callback)(int nested));
void unnamed(int, void (*)(int nested));
void zero(void);
void definition(int value) {}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("prototype_names.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NO-PARAMETER-NAMES-IN-PROTOTYPE")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![2, 2]
    );
}

#[test]
fn anzu_typedef_redefinition_requires_a_direct_typedef_underlying_type() {
    let source = r#"
typedef int Base;
typedef Base Again;
typedef Base *PointerWrapper;
typedef Base ArrayWrapper[2];
typedef int AnotherBase;
typedef PointerWrapper PointerAgain;
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("typedef_redefinition.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NO-TYPEDEF-OF-TYPEDEF")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![3, 7]
    );
}

#[test]
fn anzu_function_parameter_limit_counts_only_outer_parameters() {
    let parameters = |count: usize| {
        (0..count)
            .map(|index| format!("int p{index}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let twenty = parameters(20);
    let twenty_one = parameters(21);
    let source = format!(
        "void allowed({twenty});\nvoid rejected({twenty_one});\nvoid rejected_definition({twenty_one}) {{}}\nvoid nested_only(void (*callback)({twenty_one}));\n"
    );
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("parameter_limit.c"),
        &source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-LIMIT-FUNCTION-PARAMETERS")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![2, 3]
    );
}

#[test]
fn anzu_function_pointer_return_handles_direct_and_typedef_forms() {
    let source = r#"
typedef int (*Callback)(int);
typedef Callback CallbackAgain;
int (*direct_factory(void))(int);
Callback alias_factory(void);
CallbackAgain alias_definition(void) { return acquire(); }
int (**pointer_to_pointer_factory(void))(int);
Callback callback_variable;
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("function_pointer_return.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-FUNCTION-POINTER-RETURN")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 3, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
}

#[test]
fn anzu_ascii_checker_decodes_narrow_literals_and_excludes_wide_or_global_literals() {
    let source = r#"
#define HIDDEN_TEXT "中文"
const char *global_text = "中文";
void demo(void) {
    const char *utf8_bytes = "中文";
    const char *hex_escape = "\xFF";
    const char *octal_escape = "\377";
    const char *unicode_escape = "\u00E9";
    const char *explicit_utf8 = u8"é";
    const char *ascii = "plain ASCII";
    const wchar_t *wide = L"中文";
    const char16_t *wide16 = u"中文";
    const char32_t *wide32 = U"中文";
    int character = 'é';
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("ascii.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NARROW-STRING-ASCII")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 5, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![5, 6, 7, 8, 9]
    );
}

#[test]
fn anzu_sized_char_array_string_initializer_preserves_type_and_bound_checks() {
    let source = r#"
#define HIDDEN_ARRAY char hidden[4] = "abc"
typedef char Character;
char fixed[4] = "abc";
Character aliased[2] = "x";
char inferred[] = "abc";
char listed[4] = {'a', 'b', 'c', '\0'};
int numbers[2] = "x";
char *pointer = "abc";
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("char_array_size.c"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-SIZED-CHAR-ARRAY-STRING-INIT")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![4, 5]
    );
}

#[test]
fn anzu_loader_absolute_path_rule_accepts_posix_drive_and_unc_paths() {
    let source = r#"
void *LoadLibrary(const char *path);
void *LoadLibraryA(const char *path);
void demo(void) {
    LoadLibraryA("plugin.dll");
    LoadLibrary("/opt/vendor/library.so");
    LoadLibrary("C:\\vendor\\library.dll");
    LoadLibrary("\\\\server\\share\\library.dll");
}
"#;
    let program = parse_c_like_file(Language::C, "absolute_path.c", source).expect("parse");
    let sources = HashMap::from([("absolute_path.c".to_string(), source.to_string())]);
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_hir(&program, &sources);
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-WINDOWS-LOAD-ABSOLUTE-PATH")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}\nHIR: {program:#?}");
}

#[test]
fn anzu_assert_checker_separates_constant_true_false_and_macro_calls() {
    let source = r#"
void assert(int condition);
void demo(int value) {
    assert(1);
    assert(2 > 1);
    assert(0);
    assert(1 == 2);
    assert(value);
    assert(1, 2);
}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("assert_function.c"),
        source,
    );
    let true_matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ASSERT-ALWAYS-TRUE")
        .count();
    let false_matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-ASSERT-ALWAYS-FALSE")
        .count();
    assert_eq!((true_matches, false_matches), (2, 2), "{findings:#?}");

    let macro_source = "#define assert(value) ((void)0)\nvoid demo(void) { assert(0); }";
    let macro_findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("assert_macro.c"),
        macro_source,
    );
    assert!(
        macro_findings.iter().all(|finding| {
            !matches!(
                finding.rule_id.as_str(),
                "ANZU-ASSERT-ALWAYS-TRUE" | "ANZU-ASSERT-ALWAYS-FALSE"
            )
        }),
        "{macro_findings:#?}"
    );
}

#[test]
fn anzu_procedure_parameter_rule_handles_direct_member_and_typedef_function_pointers() {
    let source = r#"
struct Owner;
typedef void (*Callback)(int);
void declared(
    Callback aliased,
    void (*direct)(int),
    void (Owner::*member)(int),
    void (**pointer_to_pointer)(int),
    int ordinary
);
void defined(Callback callback) {}
"#;
    let findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("procedure_parameters.cpp"),
        source,
    );
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-NO-PROCEDURE-PARAMETERS")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 4, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![5, 6, 7, 11]
    );
}

#[test]
fn anzu_ambiguous_variable_names_preserve_c_and_cpp_linkage_scopes() {
    let c_source = r#"
int l;
static int O;
void O(void);
struct S { int O; };
void demo(int l) {
    int O;
    int l;
}
"#;
    let c_findings = builtin_security_pack().expect("pack").scan_text(
        &Language::C,
        std::path::Path::new("ambiguous.c"),
        c_source,
    );
    let c_matches = c_findings
        .iter()
        .filter(|finding| finding.rule_id == "LEGACY-C-AST-no-l-O-as-identifier")
        .collect::<Vec<_>>();
    assert_eq!(c_matches.len(), 3, "{c_findings:#?}");
    assert_eq!(
        c_matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![2, 7, 8]
    );

    let cpp_source = r#"
int l;
extern "C" int O;
extern "C" { int l; }
struct S { int O; };
void demo(int l) { int O; }
"#;
    let cpp_findings = builtin_security_pack().expect("pack").scan_text(
        &Language::Cpp,
        std::path::Path::new("ambiguous.cpp"),
        cpp_source,
    );
    let cpp_matches = cpp_findings
        .iter()
        .filter(|finding| finding.rule_id == "ANZU-CPP-NO-AMBIGUOUS-L-O-VARIABLE")
        .collect::<Vec<_>>();
    assert_eq!(cpp_matches.len(), 3, "{cpp_findings:#?}");
    assert_eq!(
        cpp_matches
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![3, 4, 6]
    );
}

#[test]
fn anzu_destructor_noexcept_checks_cpp_destructors_and_deallocation_functions() {
    let source = r#"
struct Safe { ~Safe() noexcept {} };
struct Risky { ~Risky() noexcept(false) {} };
void operator delete(void *memory) noexcept { release(memory); }
void operator delete[](void *memory) { release(memory); }
void ordinary() { }
"#;
    let findings = builtin_security_pack()
        .expect("pack")
        .scan_text(&Language::Cpp, std::path::Path::new("destructors.cpp"), source);
    let matches = findings
        .iter()
        .filter(|finding| {
            finding.rule_id == "ANZU-CPP-DESTRUCTOR-DEALLOCATION-NOEXCEPT"
        })
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert_eq!(
        matches.iter().map(|finding| finding.line).collect::<Vec<_>>(),
        vec![3, 5]
    );

    let c_source = "void ordinary(void) {}";
    assert!(builtin_security_pack()
        .expect("pack")
        .scan_text(&Language::C, std::path::Path::new("ordinary.c"), c_source)
        .iter()
        .all(|finding| finding.rule_id != "ANZU-CPP-DESTRUCTOR-DEALLOCATION-NOEXCEPT"));
}

#[test]
fn anzu_disable_function_preserves_all_legacy_subrules() {
    let all = builtin_security_pack().expect("pack");
    for (rule_id, call) in [
        ("ANZU-DISABLE-FUNCTION-ATOX", "atoi(text)"),
        ("ANZU-DISABLE-FUNCTION-ATOX", "atol(text)"),
        ("ANZU-DISABLE-FUNCTION-ATOX", "atoll(text)"),
        ("ANZU-DISABLE-FUNCTION-XTOA", "itoa(size, buffer, 10)"),
        ("ANZU-DISABLE-FUNCTION-ISBADWRITEPTR", "IsBadWritePtr(pointer, size)"),
        ("ANZU-DISABLE-FUNCTION-ALLOCA", "alloca(size)"),
        ("ANZU-DISABLE-FUNCTION-ALLOCA", "_alloca(size)"),
        ("ANZU-DISABLE-FUNCTION-GETS", "gets(buffer)"),
        ("ANZU-DISABLE-FUNCTION-STD-TERM", "std::terminate()"),
        ("ANZU-DISABLE-FUNCTION-STD-TERM", "std::abort()"),
        ("ANZU-DISABLE-FUNCTION-STD-TERM", "std::_Exit(1)"),
        ("ANZU-DISABLE-FUNCTION-THREAD-KILL", "pthread_kill(1, 2)"),
        ("ANZU-DISABLE-FUNCTION-TERMINATE", "TerminateThread(pointer, 1)"),
        ("ANZU-DISABLE-FUNCTION-TERMINATE", "TerminateProcess(pointer, 1)"),
        ("ANZU-DISABLE-FUNCTION-SYSTEM", "system(text)"),
        ("ANZU-DISABLE-FUNCTION-JMP", "setjmp(env)"),
        ("ANZU-DISABLE-FUNCTION-JMP", "longjmp(env, 1)"),
        ("ANZU-DISABLE-FUNCTION-EXIT", "exit(1)"),
        ("ANZU-DISABLE-FUNCTION-EXIT", "abort()"),
        ("ANZU-DISABLE-FUNCTION-CHAR-TO-OEM", "CharToOem(text, buffer)"),
        ("ANZU-DISABLE-FUNCTION-CHAR-TO-OEM", "CharToOemA(text, buffer)"),
        ("ANZU-DISABLE-FUNCTION-CHAR-TO-OEM", "CharToOemW(text, buffer)"),
        ("ANZU-DISABLE-FUNCTION-PATH", "_splitpath(text, buffer, buffer, buffer, buffer)"),
        ("ANZU-DISABLE-FUNCTION-PATH", "_makepath(buffer, text, text, text, text)"),
        ("ANZU-DISABLE-FUNCTION-SCANF", "scanf(\"%s\", buffer)"),
        ("ANZU-DISABLE-FUNCTION-STRTOK", "strtok(buffer, \",\")"),
        ("ANZU-DISABLE-FUNCTION-CHANGE-WINDOW-MESSAGE-FILTER", "ChangeWindowMessageFilter(1, 2)"),
        ("ANZU-DISABLE-FUNCTION-EXEC", "execlp(text, text)"),
        ("ANZU-DISABLE-FUNCTION-SET-ID", "seteuid(1)"),
        ("ANZU-DISABLE-FUNCTION-SET-ID", "setegid(1)"),
        ("ANZU-DISABLE-FUNCTION-GETLOGIN", "getlogin()"),
        ("ANZU-DISABLE-FUNCTION-MEMCPY", "memcpy(buffer, text, size)"),
    ] {
        let source = format!(
            "void demo(char *text, char *buffer, void *pointer, int size, int env) {{ {call}; }}"
        );
        let program = parse_c_like_file(Language::Cpp, "disabled.cpp", &source).expect("parse");
        let sources = HashMap::from([("disabled.cpp".to_string(), source)]);
        let mut pack = all.clone();
        pack.rules.retain(|rule| rule.id == rule_id);
        assert_eq!(pack.rules.len(), 1, "missing {rule_id}");
        let findings = pack.scan_hir(&program, &sources);
        assert_eq!(
            findings.len(),
            1,
            "{rule_id} / {call}: {findings:#?}\nHIR: {program:#?}"
        );
    }
}

#[test]
fn anzu_mutex_type_uses_structured_callee_and_argument_constraints() {
    let source = r#"
void demo(void *attributes) {
    pthread_mutexattr_settype(attributes, PTHREAD_MUTEX_NORMAL);
    pthread_mutexattr_settype(attributes, PTHREAD_MUTEX_RECURSIVE);
    other(attributes, PTHREAD_MUTEX_NORMAL);
}
"#;
    let program = parse_c_like_file(Language::C, "mutex.c", source).expect("C HIR");
    let sources = HashMap::from([("mutex.c".to_string(), source.to_string())]);
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|rule| rule.id == "ANZU-PTHREAD-MUTEX-NORMAL-TYPE");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_hir(&program, &sources);
    assert_eq!(findings.len(), 1, "{findings:#?}\nHIR: {program:#?}");
    assert_eq!((findings[0].line, findings[0].column), (3, 43));
}

#[test]
fn anzu_hardcoded_crypto_key_checks_the_legacy_argument_positions() {
    let source = r#"
void demo(char *runtime_key, void *ctx) {
    DES_set_key("literal-des", ctx);
    AES_set_encrypt_key("literal-aes", 128, ctx);
    AES_set_decrypt_key(runtime_key, 128, ctx);
    EVP_BytesToKey(ctx, ctx, "literal-evp", runtime_key, 1, ctx, ctx);
    EVP_BytesToKey(ctx, ctx, runtime_key, runtime_key, 1, ctx, ctx);
    unrelated("literal-des", ctx);
}
"#;
    let program = parse_c_like_file(Language::C, "hardcoded_key.c", source).expect("C HIR");
    let sources = HashMap::from([("hardcoded_key.c".to_string(), source.to_string())]);
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|rule| rule.id == "ANZU-HARDCODED-CRYPTO-KEY");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_hir(&program, &sources);
    assert_eq!(findings.len(), 3, "{findings:#?}\nHIR: {program:#?}");
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![3, 4, 6]
    );
}

#[test]
fn anzu_weak_crypto_matches_only_the_legacy_openssl_function_set() {
    let source = r#"
void demo(void *ctx, const void *data) {
    DES_set_key(data, ctx);
    RC2_encrypt(ctx);
    RC4_set_key(ctx, 16, data);
    MD5_Init(ctx);
    SHA1_Final(ctx, data);
    SHA256_Init(ctx);
    EVP_sha1();
    user_MD5_Init(ctx);
}
"#;
    let program = parse_c_like_file(Language::Cpp, "weak_crypto.cpp", source).expect("C++ HIR");
    let sources = HashMap::from([("weak_crypto.cpp".to_string(), source.to_string())]);
    let mut pack = builtin_security_pack().expect("pack");
    pack.rules
        .retain(|rule| rule.id == "ANZU-WEAK-OPENSSL-CRYPTO");
    assert_eq!(pack.rules.len(), 1);
    let findings = pack.scan_hir(&program, &sources);
    assert_eq!(findings.len(), 5, "{findings:#?}\nHIR: {program:#?}");
    assert_eq!(
        findings
            .iter()
            .map(|finding| finding.line)
            .collect::<Vec<_>>(),
        vec![3, 4, 5, 6, 7]
    );
}
