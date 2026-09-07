use std::{collections::HashMap, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let hir = JavaParser::default().parse_file("Control.java", source).unwrap();
    let findings = pack.scan_hir(&hir, &HashMap::from([("Control.java".into(), source.into())]));
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

#[test]
fn migrated_java_control_context_rules() {
    let redirect = "LEGACY-JAVA-AST-redirect-exec-other-code";
    check(redirect, "class A { void f(HttpServletResponse response) { response.sendRedirect(\"/login\"); audit(); } }", 1);
    check(redirect, "class A { void f(HttpServletResponse response) { response.sendRedirect(\"/login\"); } }", 0);
    check(redirect, "class A { void f(HttpServletResponse response, boolean ready) { if (ready) { response.sendRedirect(\"/login\"); } audit(); } }", 1);
    check(redirect, "class A { void f(HttpServletResponse response, boolean ready) { if (ready) { response.sendRedirect(\"/login\"); } } }", 0);
    check(redirect, "class A { void f(Response response) { response.sendRedirect(\"/login\"); audit(); } }", 0);

    let dns = "LEGACY-JAVA-AST-sec-check-use-dns-name";
    check(dns, "class A { boolean f(InetAddress address) { if (address.getCanonicalHostName().endsWith(\".com\")) return true; return false; } }", 1);
    check(dns, "class A { boolean f(java.net.InetAddress address, String prefix) { if (address.getCanonicalHostName().equals(prefix + \".com\")) return true; return false; } }", 1);
    check(dns, "class A { boolean f(InetAddress address) { return address.getCanonicalHostName().endsWith(\".com\"); } }", 0);
    check(dns, "class A { boolean f(InetAddress address) { if (address.getHostAddress().endsWith(\".com\")) return true; return false; } }", 0);
    check(dns, "class A { boolean f(Host address) { if (address.getCanonicalHostName().endsWith(\".com\")) return true; return false; } }", 0);

    let strings = "LEGACY-JAVA-AST-stringbuild-in-loop";
    check(strings, "class A { void f(boolean ready) { String text=\"\"; while (ready) { text = text + next(); } } }", 1);
    check(strings, "class A { void f(String text, boolean ready) { for (;ready;ready=false) { text = prefix() + text + suffix(); } } }", 1);
    check(strings, "class A { String text=\"\"; void f(boolean ready) { while (ready) { text = text + next(); } } }", 1);
    check(strings, "class A { void f(boolean ready) { while (ready) { String text=\"\"; text = text + next(); } } }", 0);
    check(strings, "class A { void f(boolean ready) { String text=\"\"; while (ready) { text += next(); } } }", 0);
    check(strings, "class A { void f(boolean ready) { Object text=\"\"; while (ready) { text = text + next(); } } }", 0);
    check(strings, "class A { void f() { String text=\"\"; text = text + next(); } }", 0);
}
