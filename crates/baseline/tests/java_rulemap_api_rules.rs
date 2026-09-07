use std::{collections::HashMap, sync::OnceLock};

use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let program = JavaParser::default()
        .parse_file("RuleMapApi.java", source)
        .unwrap();
    let findings = pack.scan_hir(
        &program,
        &HashMap::from([("RuleMapApi.java".to_string(), source.to_string())]),
    );
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

#[test]
fn system_gc_has_a_type_qualified_call_contract() {
    let rule = "LEGACY-JAVA-RULEMAP-code-correctness-call-to-system-gc";
    check(rule, "class A { void f() { System.gc(); java.lang.System.gc(); } }", 2);
    check(rule, "class A { void f(Runtime runtime) { runtime.gc(); gc(); } }", 0);
}

#[test]
fn run_finalizers_on_exit_has_an_exact_static_api_contract() {
    let rule = "LEGACY-JAVA-RULEMAP-call-system-runfinalizersonexit";
    check(rule, "class A { void f() { System.runFinalizersOnExit(true); } }", 1);
    check(rule, "class A { void f(Helper helper) { helper.runFinalizersOnExit(true); } }", 0);
}

#[test]
fn boolean_getboolean_is_distinguished_from_string_parsing() {
    let rule = "LEGACY-JAVA-RULEMAP-often-misused-boolean-getboolean";
    check(rule, "class A { boolean f(String value) { return Boolean.getBoolean(value); } }", 1);
    check(rule, "class A { boolean f(String value) { return Boolean.parseBoolean(value); } }", 0);
}

#[test]
fn string_tostring_requires_a_statically_known_string_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-often-misused-string-tostring";
    check(rule, "class A { String f(String value) { return value.toString(); } }", 1);
    check(rule, "class A { String f(Object value) { return value.toString(); } }", 0);
}

#[test]
fn finalize_requires_an_explicit_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-poor-style-explicit-call-to-finalize";
    check(rule, "class A { void f(A other) throws Throwable { other.finalize(); } }", 1);
    check(rule, "class A { void finalize() {} void f() { finalize(); } }", 0);
}

#[test]
fn sticky_broadcast_requires_an_android_context_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-android-sticky-broadcast";
    check(rule, "class A { void f(android.content.Context context, Intent intent) { context.sendStickyBroadcast(intent); } }", 1);
    check(rule, "class A { void f(Sender sender, Intent intent) { sender.sendStickyBroadcast(intent); } }", 0);
}

#[test]
fn print_stack_trace_requires_a_throwable_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-print-error-message-using-printstacktrace";
    check(rule, "class A { void f(java.io.IOException error) { error.printStackTrace(); } }", 1);
    check(rule, "class A { void f(Printer printer) { printer.printStackTrace(); } }", 0);
}

#[test]
fn delete_on_exit_requires_a_file_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-javaee-deleteonexit";
    check(rule, "class A { void f(java.io.File file) { file.deleteOnExit(); } }", 1);
    check(rule, "class A { void f(Cleanup cleanup) { cleanup.deleteOnExit(); } }", 0);
}

#[test]
fn nullcipher_is_checked_as_a_constructor() {
    let rule = "LEGACY-JAVA-RULEMAP-use-nullcipher";
    check(rule, "class A { Object f() { return new javax.crypto.NullCipher(); } }", 1);
    check(rule, "class A { Object f() { return new Cipher(); } }", 0);
}

#[test]
fn loadclass_requires_a_classloader_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-call-classloader-loadclass";
    check(rule, "class A { Class<?> f(ClassLoader loader, String name) throws Exception { return loader.loadClass(name); } }", 1);
    check(rule, "class A { Object f(Registry registry, String name) { return registry.loadClass(name); } }", 0);
}

#[test]
fn equals_null_is_not_confused_with_a_normal_equals_call() {
    let rule = "LEGACY-JAVA-RULEMAP-null-argument-to-equals";
    check(rule, "class A { boolean f(Object value) { return value.equals(null); } }", 1);
    check(rule, "class A { boolean f(Object left, Object right) { return left.equals(right); } }", 0);
}

#[test]
fn array_tostring_requires_an_array_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-tostring-on-array";
    check(rule, "class A { String f(String[] values) { return values.toString(); } }", 1);
    check(rule, "class A { String f(String value) { return value.toString(); } }", 0);
}

#[test]
fn object_allocation_is_scoped_to_loop_bodies() {
    let rule = "LEGACY-JAVA-RULEMAP-create-objects-in-loop";
    check(rule, "class A { void f(int n) { for (int i=0; i<n; i++) { Object value=new Object(); use(value); } } }", 1);
    check(rule, "class A { void f() { Object value=new Object(); use(value); } }", 0);
}

#[test]
fn android_websettings_boolean_security_switches_are_type_aware() {
    for (rule, method) in [
        ("LEGACY-JAVA-RULEMAP-webview-dom-storage", "setDomStorageEnabled"),
        ("LEGACY-JAVA-RULEMAP-webview-content-access", "setAllowContentAccess"),
        ("LEGACY-JAVA-RULEMAP-webview-file-access", "setAllowFileAccess"),
    ] {
        check(rule, &format!("class A {{ void f(android.webkit.WebSettings settings) {{ settings.{method}(true); }} }}"), 1);
        check(rule, &format!("class A {{ void f(android.webkit.WebSettings settings) {{ settings.{method}(false); }} }}"), 0);
        check(rule, &format!("class A {{ void f(Settings settings) {{ settings.{method}(true); }} }}"), 0);
    }
}

#[test]
fn file_scheme_cookie_rule_requires_the_exact_static_api_and_true() {
    let rule = "LEGACY-JAVA-RULEMAP-file-scheme-cookies";
    check(rule, "class A { void f() { android.webkit.CookieManager.setAcceptFileSchemeCookies(true); } }", 1);
    check(rule, "class A { void f() { android.webkit.CookieManager.setAcceptFileSchemeCookies(false); } }", 0);
}

#[test]
fn webview_save_password_requires_the_webview_receiver_and_signature() {
    let rule = "LEGACY-JAVA-RULEMAP-webview-save-password";
    check(rule, "class A { void f(android.webkit.WebView view) { view.savePassword(\"host\", \"user\", \"secret\"); } }", 1);
    check(rule, "class A { void f(Vault vault) { vault.savePassword(\"host\", \"user\", \"secret\"); } }", 0);
}
