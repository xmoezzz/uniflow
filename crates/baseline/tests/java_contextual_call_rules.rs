use std::{collections::HashMap, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselineFinding, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn findings(source: &str, rule: &str) -> Vec<BaselineFinding> {
    let hir = JavaParser::default().parse_file("Contextual.java", source).unwrap();
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    pack.scan_hir(&hir, &HashMap::from([("Contextual.java".into(), source.into())]))
}

fn check(rule: &str, source: &str, expected: usize) {
    let actual = findings(source, rule);
    assert_eq!(actual.len(), expected, "{rule}: {source}\n{actual:#?}");
}

#[test]
fn migrated_java_contextual_call_and_constructor_rules() {
    let ldap = "LEGACY-JAVA-AST-disable-ldap";
    check(ldap, "class A { void f(Context c) { c.addToEnvironment(Context.SECURITY_AUTHENTICATION, \"none\"); } }", 1);
    check(ldap, "class A { void f(Context c) { c.addToEnvironment(Context.SECURITY_AUTHENTICATION, \"simple\"); c.other(SECURITY_PROTOCOL, \"none\"); } }", 0);
    check(ldap, "class A { void f(Context c, String mode) { c.addToEnvironment(Context.SECURITY_AUTHENTICATION, mode); } }", 0);

    let password = "LEGACY-JAVA-AST-weak-password";
    check(password, "class A { void f(Admin a, String user, String pass) { a.createUser(user, pass, pass, true); } }", 1);
    check(password, "class A { void f(Admin a, String user, String one, String two) { a.createUser(user, one, two); } }", 0);
    check(password, "class A { void f(Admin a, String user) { a.createUser(user, token(), token()); } }", 1);
    check(password, "class A { void f(String pass) { createUser(\"u\", pass, pass); } }", 0);

    let socket = "LEGACY-JAVA-AST-http-servlet-use-socket";
    check(socket, "class A { void service(HttpServletRequest request) { Socket socket = new Socket(\"host\", 80); } }", 1);
    check(socket, "class A { void service(javax.servlet.http.HttpServletResponse response) { new java.net.Socket(); } }", 1);
    check(socket, "class A { void helper(Request request) { new Socket(); } void service(HttpServletRequest request) { helper(request); } }", 0);
    check(socket, "class A { void service(HttpServletRequest request) { new SafeSocket(); } }", 0);

    let thread = "LEGACY-JAVA-AST-http-servlet-use-thread";
    check(thread, "class A { void service(HttpServletResponse response) { Thread thread = new Thread(task); } }", 1);
    check(thread, "class A { void service(HttpServletRequest request) { if (ready) { new java.lang.Thread(); } } }", 1);
    check(thread, "class A { void helper() { new Thread(); } }", 0);
    check(thread, "class A { void service(HttpServletRequest request) { new WorkerThread(); } }", 0);
}
