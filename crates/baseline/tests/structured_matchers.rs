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
        assert_eq!(matches.len(), 1, "{rule_id}: {findings:#?}\nHIR: {program:#?}");
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
        assert_eq!(matches.len(), 1, "{rule_id}: {findings:#?}\nHIR: {program:#?}");
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
        assert_eq!(matches.len(), 1, "{rule_id}: {findings:#?}\nHIR: {program:#?}");
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
                finding.rule_id
                    == "LEGACY-CS-AST-security_features_inadequate_rsa_padding_1"
            })
            .count(),
        1,
        "{findings:#?}"
    );
}
