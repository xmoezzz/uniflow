use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let text = pack.scan_text(&Language::Java, Path::new("Remaining.java"), source);
    let hir = JavaParser::default()
        .parse_file("Remaining.java", source)
        .unwrap();
    let integrated = pack.scan_hir(
        &hir,
        &HashMap::from([("Remaining.java".into(), source.into())]),
    );
    if pack.rules[0].matcher.java_style.is_some() {
        assert_eq!(text.len(), expected, "text {rule}: {source}\n{text:#?}");
    }
    assert_eq!(
        integrated.len(),
        expected,
        "HIR {rule}: {source}\n{integrated:#?}"
    );
}

#[test]
fn migrated_java_boxed_session_and_select_rules() {
    let boxed = "LEGACY-JAVA-AST-compare-base-object";
    check(
        boxed,
        "class A { boolean f(Integer left, Integer right) { return left == right; } }",
        1,
    );
    check(boxed, "class A { boolean f(java.lang.Boolean left, boolean primitive) { return left != primitive; } }", 1);
    check(
        boxed,
        "class A { boolean f(String left, String right) { return left == right; } }",
        0,
    );
    check(
        boxed,
        "class A { boolean f(Integer left) { return left == null; } }",
        0,
    );
    check(
        boxed,
        "class A { boolean f(Integer left) { return left.value == left.value; } }",
        0,
    );
    check(
        boxed,
        "class A { boolean f(int left, int right) { return left == right; } }",
        0,
    );

    let session = "LEGACY-JAVA-AST-session-timeout-infinite";
    check(
        session,
        "class A { void f(HttpSession session) { session.setMaxInactiveInterval(-1); } }",
        1,
    );
    check(session, "class A { void f(javax.servlet.http.HttpSession session) { session.setMaxInactiveInterval(-1); } }", 1);
    check(
        session,
        "class A { void f(HttpSession session) { session.setMaxInactiveInterval(0); } }",
        0,
    );
    check(
        session,
        "class A { void f(Session session) { session.setMaxInactiveInterval(-1); } }",
        0,
    );
    check(
        session,
        "class A { void f(HttpSession session) { setMaxInactiveInterval(-1); } }",
        0,
    );

    for rule in [
        "LEGACY-JAVA-AST-sql-query-with-ibatis",
        "LEGACY-JAVA-AST-sql-query-with-mybatis",
    ] {
        check(rule, "interface Mapper { @Select(\"select * from users where name='${name}'\") Object find(String name); }", 1);
        check(rule, "interface Mapper { @org.apache.ibatis.annotations.Select({\"select *\", \"where id=${id}\"}) Object find(int id); }", 1);
        check(rule, "interface Mapper { @Select(\"select * from users where id=#{id}\") Object find(int id); }", 0);
        check(
            rule,
            "interface Mapper { @Other(\"${name}\") Object find(String name); }",
            0,
        );
        check(
            rule,
            "interface Mapper { @Select Object find(String name); String fake=\"${name}\"; }",
            0,
        );
    }
}

#[test]
fn migrated_java_synchronization_rules() {
    let lock = "LEGACY-JAVA-AST-sync-object-is-final";
    check(
        lock,
        "class A { Object lock=new Object(); void f() { synchronized (lock) { work(); } } }",
        1,
    );
    check(
        lock,
        "class A { final Object lock=new Object(); void f() { synchronized (lock) { work(); } } }",
        0,
    );
    check(lock, "class A { Object lock=new Object(); void f() { Object lock=new Object(); synchronized (lock) { work(); } } }", 1); // Source rule resolves the class field by name.
    check(lock, "class A { Object lock=new Object(); class B { final Object lock=new Object(); void f() { synchronized (lock) {} } } }", 0);
    check(
        lock,
        "class A { Object first, lock; void f() { synchronized (lock) {} } }",
        1,
    );
    check(
        lock,
        "class A { Object lock; void f() { synchronized (this.lock) {} } }",
        0,
    );

    let string = "LEGACY-JAVA-AST-synchronized-object";
    check(
        string,
        "class A { String lock=\"x\"; void f() { synchronized(lock) { work(); } } }",
        1,
    );
    check(
        string,
        "class A { java.lang.String lock=\"x\"; void f() { synchronized(lock) {} } }",
        1,
    );
    check(
        string,
        "class A { Object lock=new Object(); void f() { synchronized(lock) {} } }",
        0,
    );
    check(string, "class A { String lock=\"x\"; class B { Object lock; void f() { synchronized(lock) {} } } }", 0);

    for notify in [
        "LEGACY-JAVA-AST-sync-object-notify-method",
        "LEGACY-JAVA-AST-sync-object-notify-method-ydt",
    ] {
        check(
            notify,
            "class A { void f(Object lock) { synchronized(lock) { lock.notify(); } } }",
            1,
        );
        check(notify, "class A { void f(Object lock) { synchronized(lock) { if (ready) { lock.notify(); } lock.notify(); } } }", 2);
        check(notify, "class A { void f(Holder holder) { synchronized(holder.lock) { holder.lock.notify(); } } }", 1);
        check(notify, "class A { void f(Object lock, Object other) { synchronized(lock) { other.notify(); lock.notifyAll(); } } }", 0);
        check(notify, "class A { void f(Object lock) { lock.notify(); synchronized(lock) { Runnable r=new Runnable() { public void run() { lock.notify(); } }; } } }", 0);
    }
}

#[test]
fn migrated_java_switch_group_rules() {
    let empty = "LEGACY-JAVA-AST-empty-case-block";
    check(
        empty,
        "class A { void f(int n) { switch(n) { case 1: } } }",
        1,
    );
    check(
        empty,
        "class A { void f(int n) { switch(n) { case 1: // comment only\n } } }",
        1,
    );
    check(
        empty,
        "class A { void f(int n) { switch(n) { case 1: case 2: work(); break; } } }",
        0,
    );
    check(
        empty,
        "class A { void f(int n) { switch(n) { case 1: ; } } }",
        0,
    );
    check(
        empty,
        "class A { void f(int n) { switch(n) { default: } } }",
        0,
    );

    let fallthrough = "LEGACY-JAVA-AST-switch-case-break";
    check(
        fallthrough,
        "class A { void f(int n) { switch(n) { case 1: work(); case 2: return; } } }",
        1,
    );
    check(
        fallthrough,
        "class A { void f(int n) { switch(n) { case 1: work(); break; case 2: throw error; } } }",
        0,
    );
    check(
        fallthrough,
        "class A { int f(int n) { switch(n) { case 1: if (ready) return 1; work(); } return 0; } }",
        0,
    );
    check(
        fallthrough,
        "class A { void f(int n) { switch(n) { case 1 -> work(); case 2 -> { work(); } } } }",
        0,
    );
    check(
        fallthrough,
        "class A { void f(int n) { switch(n) { case 1: case 2: work(); } } }",
        1,
    );
    check(
        fallthrough,
        "class A { void f(int n) { switch(n) { default: work(); } } }",
        0,
    );
}

#[test]
fn migrated_java_hash_url_declarations() {
    let rule = "LEGACY-JAVA-AST-hash-url";
    check(
        rule,
        "class A { Set<URL> urls; java.util.Map<java.net.URL, String> names; }",
        2,
    );
    check(
        rule,
        "class A { void f(Set<URL> urls, java.util.Map<java.net.URL,Integer> map) {} }",
        2,
    );
    check(rule, "class A { void f() { final Set<URL> urls=new HashSet<>(); Map<java.net.URL, String> map=null; } }", 2);
    check(
        rule,
        "class A { void f() { for (Set<URL> urls=load(); ready; advance()) { use(urls); } } }",
        1,
    );
    check(rule, "class A { Set<URI> uris; Map<String,URL> values; HashSet<URL> concrete; Set<List<URL>> nested; }", 0);
    check(rule, "class A { void f() { use(Set.class); Object x=new HashMap<URL,String>(); String fake=\"Set<URL> urls\"; } }", 0);
    check(
        rule,
        "class A { java.util.Set < java.net.URL > [] urls; }",
        1,
    );
}

#[test]
fn migrated_java_invalid_variable_initialization() {
    let rule = "LEGACY-JAVA-AST-invalid-var-init";
    check(
        rule,
        "class A { void f() { int value=first(); value=second(); } }",
        1,
    );
    check(rule, "class A { void f(int value) { value=first(); /* comments do not intervene */ value=second(); } }", 1);
    check(
        rule,
        "class A { void f() { int value=first(); value=combine(value, second()); } }",
        0,
    );
    check(
        rule,
        "class A { void f() { int value=first(); use(value); value=second(); } }",
        0,
    );
    check(
        rule,
        "class A { void f() { int first=one(), second=two(); second=three(); } }",
        1,
    );
    check(
        rule,
        "class A { void f(boolean ready) { int value=first(); if (ready) value=second(); } }",
        0,
    );
    check(
        rule,
        "class A { void f() { int value; value=second(); } }",
        0,
    );
    check(
        rule,
        "class A { void f(int value) { value=first(); value=() -> use(value); } }",
        0,
    );
}

#[test]
fn migrated_java_hibernate_query_fragments_track_latest_assignment() {
    let rule = "LEGACY-JAVA-AST-sql-query-with-hibernate";
    check(rule, "class A { void f(Session db, String user) { String query=\"name like '%\" + user + \"%'\"; db.createQuery(query); } }", 1);
    check(
        rule,
        "class A { void f(Session db, String query) { db.createQuery(query); } }",
        1,
    );
    check(rule, "class A { String query=\"name like '%admin%'\"; void f(Session db) { db.executeQuery(query); } }", 1);
    check(rule, "class A { void f(Session db, String user) { String query=\"name = ?\"; db.createQuery(query); } }", 0);
    check(rule, "class A { void f(Session db, String user) { String query=\"like '%\"+user; query=\"name = ?\"; db.createQuery(query); } }", 0);
    check(rule, "class A { void f(Session db, String user) { String query=\"name = ?\"; query=\"like '%\"+user; db.createQuery(query); } }", 1);
    check(rule, "class A { void f(Session db, String user) { String risky=\"like '%\"+user; String copied=risky; db.createQuery(copied); } }", 0);
    check(rule, "class A { void f(Session db, String user) { String query=\"like '%\"+user; db.safeQuery(query); } }", 0);
}
