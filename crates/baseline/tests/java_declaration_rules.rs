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
    pack.rules.retain(|r| r.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::Java, Path::new("Declarations.java"), source);
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
    let hir = JavaParser::default()
        .parse_file("Declarations.java", source)
        .unwrap();
    let integrated = pack.scan_hir(
        &hir,
        &HashMap::from([("Declarations.java".into(), source.into())]),
    );
    assert_eq!(
        integrated.len(),
        expected,
        "HIR {rule}: {source}\n{integrated:#?}"
    );
    assert_eq!(
        findings
            .iter()
            .map(|f| (f.line, f.column))
            .collect::<Vec<_>>(),
        integrated
            .iter()
            .map(|f| (f.line, f.column))
            .collect::<Vec<_>>()
    );
}

#[test]
fn migrated_java_final_clone_method() {
    let rule = "LEGACY-JAVA-AST-final-clone-method";
    check(
        rule,
        "class A implements Cloneable { public Object clone() { return this; } }",
        1,
    );
    check(
        rule,
        "class A implements java.lang.Cloneable { protected abstract Object clone(); }",
        1,
    );
    for source in [
        "class A implements Cloneable { public final Object clone() { return this; } }",
        "class A { public Object clone() { return this; } }",
        "class A implements Cloneable { class B { Object clone() { return this; } } }",
        "class A implements NotCloneable { Object clone() { return this; } }",
    ] {
        check(rule, source, 0);
    }
}

#[test]
fn migrated_java_private_finalize() {
    let rule = "LEGACY-JAVA-AST-private-finalize";
    check(
        rule,
        "class A { public void finalize() {} protected void finalize(int x) {} }",
        2,
    );
    check(
        rule,
        "class A { private void finalize() {} void finalize(int x) {} public void finalizer() {} }",
        0,
    );
    check(
        rule,
        "class A { @Mark(visibility=\"public\") private void finalize() {} }",
        0,
    );
}

#[test]
fn migrated_java_request_mapping_method_public() {
    let rule = "LEGACY-JAVA-AST-request-mapping-method-public";
    check(rule, "class A { @RequestMapping(\"/x\") void route() {} @web.RequestMapping(path={\"/a\",\"/b\"}) protected void other() {} }", 2);
    check(
        rule,
        "class A { @RequestMapping(\"/x\") public void route() {} @GetMapping void other() {} }",
        0,
    );
    check(
        rule,
        "@RequestMapping class A { private void ordinary() { String x=\"@RequestMapping\"; } }",
        0,
    );
    check(
        rule,
        "class A { @web.CustomRequestMapping private void route() {} }",
        1,
    );
}

#[test]
fn migrated_java_rewrite_thread_run_method() {
    let rule = "LEGACY-JAVA-AST-rewrite-thread-run-method";
    check(rule, "class A extends Thread {}", 1);
    check(
        rule,
        "class A<T> extends java.lang.Thread implements Runnable { class B { void run() {} } }",
        1,
    );
    check(
        rule,
        "class A extends Thread { Runnable x = new Runnable() { public void run() {} }; }",
        1,
    );
    check(rule, "class A extends Thread { public void run() {} }", 0);
    check(
        rule,
        "class A extends Thread { public void run(int x) {} }",
        0,
    ); // Original rule checks name, not override signature.
    check(
        rule,
        "class A extends WorkerThread {} class B implements Runnable {}",
        0,
    );
}

#[test]
fn migrated_java_default_constructor_externalizable() {
    let rule = "LEGACY-JAVA-AST-default-ctor--externalizable";
    check(rule, "class A implements Externalizable {}", 1);
    check(
        rule,
        "class A implements java.io.Externalizable { A(int n) {} class B { B() {} } }",
        1,
    );
    check(
        rule,
        "class A implements Externalizable { private A(/* empty */) {} }",
        0,
    ); // No visibility gate in source rule.
    check(rule, "class A implements Serializable {}", 0);
    check(rule, "class A implements CustomExternalizable {}", 1); // Legacy interface regex is unanchored.
}

#[test]
fn migrated_java_equals_hashcode_check() {
    let rule = "LEGACY-JAVA-AST-equals-hashcode-check";
    check(
        rule,
        "class A { boolean equals(Object x) { return true; } }",
        1,
    );
    check(rule, "class A { int hashCode() { return 1; } }", 1);
    check(
        rule,
        "class A { boolean equals(Object x) { return true; } int hashCode() { return 1; } }",
        0,
    );
    check(rule, "class A { boolean equals(Object x) { return true; } class B { int hashCode() { return 1; } } }", 2);
    check(
        rule,
        "class A { Object x = new Object() { public int hashCode() { return 1; } }; }",
        1,
    );
    check(rule, "interface A { boolean equals(Object x); }", 0);
}

#[test]
fn migrated_java_serialize_method_sign() {
    let rule = "LEGACY-JAVA-AST-serialize-method-sign";
    check(rule, "class A { void writeObject(java.io.ObjectOutputStream out) {} void readObject(ObjectInputStream in) {} void readObjectNoData() {} }", 3);
    check(rule, "class A { void writeObject(ObjectOutputStream out) throws IOException {} void readObject(ObjectInputStream in) throws Exception {} void readObjectNoData() throws Error {} }", 0);
    check(
        rule,
        "class A { void writeObject(Object out) {} void readObject(String in) {} }",
        0,
    );
    check(rule, "class A { void readObjectNoDataExtra() {} }", 1); // Original name regex is not anchored.
}

#[test]
fn migrated_java_serial_version_uid_defined() {
    let rule = "LEGACY-JAVA-AST-serial-version-uid-defined";
    check(
        rule,
        "class A implements Serializable { long serialVersionUID=1; }",
        1,
    );
    check(
        rule,
        "class A implements java.io.Serializable { static final int serialVersionUID=1; }",
        1,
    );
    check(
        rule,
        "class A implements Serializable { static final long other=0, serialVersionUID=1; }",
        0,
    );
    check(
        rule,
        "class A implements Serializable { class B { long serialVersionUID=1; } }",
        0,
    );
    check(
        rule,
        "class A { long serialVersionUID=1; } class B implements Serializable {}",
        0,
    ); // Source checks existing fields only.
    check(
        rule,
        "class A implements Serializable { void f() { long serialVersionUID=1; } }",
        0,
    );
}

#[test]
fn migrated_java_static_final_logger() {
    let rule = "LEGACY-JAVA-AST-static-final-logger";
    check(
        rule,
        "class A { Logger a=make(); static Logger b; final java.util.logging.Logger c=make(); }",
        3,
    );
    check(rule, "class A { private static final Logger a=make(), b=make(); LoggerFactory f; Logger[] array; void f() { Logger local=make(); } }", 0);
    check(rule, "class A { Logger first, second; }", 1); // One field declaration, not two declarators.
    check(
        rule,
        "class A { @Mark(text=\"static final\") Logger x; }",
        1,
    );
}

#[test]
fn migrated_java_multiple_logger() {
    let rule = "LEGACY-JAVA-AST-mult-logger";
    check(
        rule,
        "class A { Logger a; /* adjacent */ java.util.logging.Logger b; Logger c; }",
        2,
    );
    for source in [
        "class A { Logger a, b; }",
        "class A { Logger a; int n; Logger b; }",
        "class A { Logger a; void f() {} Logger b; }",
        "class A { Logger a; static {} Logger b; }",
        "class A { Logger a; class B { Logger b; } Logger c; }",
    ] {
        check(rule, source, 0);
    }
    check(
        rule,
        "class A { Logger a=new Logger() { void helper() {} }; Logger b; }",
        1,
    );
}

#[test]
fn migrated_java_field_name_and_class_name_same() {
    let rule = "LEGACY-JAVA-AST-field-name-and-class-name-same";
    check(rule, "class A { int A; }", 1);
    check(rule, "class A { int first=1, A=2; }", 1);
    check(
        rule,
        "class A { class B { int A; } void f() { int A=1; } }",
        0,
    );
    check(
        rule,
        "class A { A() {} String text=\"int A\"; } interface B { int B=1; }",
        0,
    );
}

#[test]
fn migrated_java_field_name_and_method_name_same() {
    let rule = "LEGACY-JAVA-AST-field-name-and-method-name-same";
    check(rule, "class A { int work; void work() {} }", 1);
    check(rule, "class A { void work() {} int first=0, work=1; }", 1);
    check(rule, "class A { int work; class B { void work() {} } }", 0);
    check(
        rule,
        "class A { int work; Object x=new Object() { void work() {} }; }",
        0,
    );
    check(rule, "class A { void work() { int work=0; } }", 0);
}

#[test]
fn migrated_java_final_public_static_field() {
    let rule = "LEGACY-JAVA-AST-final-public-static-field";
    check(
        rule,
        "class A { public static int count; public static volatile Object state; }",
        2,
    );
    check(
        rule,
        "class A { public static final int COUNT=1; private static int count; public int value; }",
        0,
    );
    check(
        rule,
        "interface A { int implicit=1; public static final int explicit=2; }",
        0,
    );
    check(
        rule,
        "class A { void f() { publicStatic(); } String s=\"public static\"; }",
        0,
    );
}

#[test]
fn migrated_java_static_private_final_objectstreamfield() {
    let rule = "LEGACY-JAVA-AST-static-private-final-objectstreamfield";
    check(rule, "class A { ObjectStreamField[] serialPersistentFields; public static final ObjectStreamField[] serialPersistentFields2=null; }", 1);
    check(
        rule,
        "class A { public static final ObjectStreamField[] serialPersistentFields=null; }",
        1,
    );
    check(rule, "class A { protected static final java.io.ObjectStreamField[] serialPersistentFields=null; }", 1);
    check(
        rule,
        "class A { private static final ObjectStreamField[] serialPersistentFields=null; }",
        0,
    );
    check(
        rule,
        "class A { static final java.io.ObjectStreamField[] serialPersistentFields=null; }",
        0,
    );
    check(
        rule,
        "class A { public static final Object serialPersistentFields=null; }",
        0,
    );
    check(
        rule,
        "class A { void f() { ObjectStreamField[] serialPersistentFields=null; } }",
        0,
    );
}

#[test]
fn migrated_java_static_public_final_array() {
    let rule = "LEGACY-JAVA-AST-static-public-final-array";
    check(rule, "class A { public static final int[] VALUES={1}; public static final String NAMES[]=null; }", 2);
    check(rule, "class A { private static final int[] values={1}; public static int[] values2; public static final int value=1; }", 0);
    check(rule, "class A { void f() { int[] values={1}; } }", 0);
}

#[test]
fn migrated_java_static_public_final_object() {
    let rule = "LEGACY-JAVA-AST-static-public-final-object";
    check(rule, "class A { public static final Object VALUE=new Object(); public static final int NUMBER=1; }", 2);
    check(rule, "class A { private static final Object value=new Object(); public final Object instance=new Object(); public static Object mutable=new Object(); }", 0);
    check(
        rule,
        "class A { void f() { final Object value=new Object(); } }",
        0,
    );
}

#[test]
fn migrated_java_immutable_final_field() {
    let rule = "LEGACY-JAVA-AST-immutable-final-field";
    check(
        rule,
        "@Immutable class A { int value; private Object state; }",
        2,
    );
    check(rule, "@pkg.Immutable class A { final int value=1; }", 0);
    check(
        rule,
        "@Immutable(reason=\"marker with arguments\") class A { int value; }",
        0,
    );
    check(rule, "class A { @Immutable int value; }", 0);
    check(
        rule,
        "@Immutable class A { class B { int value; } void f() { int local=0; } }",
        0,
    );
}

#[test]
fn migrated_java_immutable_public_final_field() {
    let rule = "LEGACY-JAVA-AST-immutable-public-final-field";
    check(
        rule,
        "@Immutable class A { public final int value=1; public Object state; }",
        2,
    );
    check(
        rule,
        "@Immutable class A { private final int value=1; protected Object state; }",
        0,
    );
    check(
        rule,
        "@Immutable(value=true) class A { public int value; }",
        0,
    );
    check(rule, "class A { @Immutable public int value; }", 0);
}

#[test]
fn migrated_java_transient_field_class() {
    let rule = "LEGACY-JAVA-AST-transient-field-class";
    check(
        rule,
        "class A { transient int cache; private transient Object state; }",
        2,
    );
    check(rule, "class A extends Base { transient int cache; } class B implements Tag { transient int cache; }", 0);
    check(
        rule,
        "class Outer { class Inner { transient int cache; } }",
        1,
    );
    check(
        rule,
        "class A { void f() { transientCall(); } String s=\"transient int cache\"; }",
        0,
    );
}

#[test]
fn migrated_java_stateholder_restorestate_savestate() {
    let rule = "LEGACY-JAVA-AST-stateholder-restorestate-savestate";
    check(
        rule,
        "class A extends StateHolder { void restoreState() {} }",
        1,
    );
    check(
        rule,
        "class A extends pkg.StateHolderBase { void saveState() {} }",
        1,
    );
    check(
        rule,
        "class A extends StateHolder { void restoreState() {} void saveState() {} }",
        0,
    );
    check(
        rule,
        "class A extends StateHolder { void restoreState() {} class B { void saveState() {} } }",
        1,
    );
    check(rule, "class A extends Other { void restoreState() {} }", 0);
    check(
        rule,
        "class A extends StateHolder { void restoreStateExtra() {} }",
        0,
    );
}

#[test]
fn migrated_java_static_thread_not_sec_object() {
    let rule = "LEGACY-JAVA-AST-static-thread-not-sec-object";
    check(rule, "class A { static Calendar calendar; private static javax.xml.xpath.XPath xpath; static SchemaFactory factory; }", 3);
    check(
        rule,
        "class A { Calendar calendar; static SafeCalendar safe; static XPathFactory factory; }",
        0,
    );
    check(
        rule,
        "class A { void f() { Calendar local=null; } String s=\"static Calendar\"; }",
        0,
    );
}

#[test]
fn migrated_java_inner_class_implement_serializable() {
    for rule in [
        "LEGACY-JAVA-AST-inner-class-implement-serializable",
        "LEGACY-JAVA-AST-inner-class-implement-serializable-ydt",
    ] {
        check(
            rule,
            "class Outer { class Inner implements Serializable {} }",
            1,
        );
        check(
            rule,
            "class Outer { void f() { class Local implements java.io.Serializable {} } }",
            1,
        );
        check(
            rule,
            "class Outer { static class Inner implements Serializable {} }",
            0,
        );
        check(rule, "class Top implements Serializable {}", 0);
        check(
            rule,
            "class Outer { class Inner implements NotSerializable {} }",
            0,
        );
        check(
            rule,
            "interface Outer { class Inner implements Serializable {} }",
            0,
        ); // Source requires class ancestor.
    }
}

#[test]
fn migrated_java_rewrite_clone_method() {
    let rule = "LEGACY-JAVA-AST-rewrite-clone-method";
    check(rule, "class A { Object clone() { return new A(); } }", 1);
    check(
        rule,
        "class A { Object clone(int n) { return this; } Object clone() { return super.clone(); } }",
        1,
    );
    check(
        rule,
        "class A { Object clone() { return super.clone(); } }",
        0,
    );
    check(
        rule,
        "class A { Object clone() { String fake=\"super.clone()\"; return this; } }",
        1,
    );
    check(
        rule,
        "class A { Object clone() { /* super.clone() */ return this; } }",
        1,
    );
    check(rule, "class A { Object cloning() { return this; } }", 0);
}

#[test]
fn migrated_java_next_throw_no_such_element_exception() {
    let rule = "LEGACY-JAVA-AST-next-throw-nosuchelementexception";
    check(
        rule,
        "class A { @Override public Object next() { return value; } }",
        1,
    );
    check(
        rule,
        "class A { @pkg.Override() Object next() { return value; } }",
        1,
    );
    check(
        rule,
        "class A { @Override Object next() { throw new NoSuchElementException(); } }",
        0,
    );
    check(
        rule,
        "class A { @Override Object next() { return helper(NoSuchElementException.class); } }",
        0,
    );
    check(rule, "class A { Object next() { return value; } @Override Object nextValue() { return value; } }", 0);
    check(
        rule,
        "abstract class A { @Override abstract Object next(); }",
        0,
    );
    check(rule, "class A { @Override Object next() { String fake=\"NoSuchElementException\"; return value; } }", 1);
}

#[test]
fn migrated_java_anonymous_inner_class_call_method() {
    let rule = "LEGACY-JAVA-AST-anonymous-inner-class-call-method";
    check(
        rule,
        "class A { Object x = new Base() { { initialize(); } }; }",
        1,
    );
    check(rule, "class A { void f() { Object x = new Base() { { this.initialize(); nested(call()); } }; } }", 1);
    check(
        rule,
        "class A { Object x = new Base() { int value=1; void run() { initialize(); } }; }",
        0,
    );
    check(
        rule,
        "class A { Object x = new Base(arg) { { initialize(); } }; }",
        0,
    ); // Source pattern requires new $A().
    check(rule, "class A { static { initialize(); } }", 0);
    check(
        rule,
        "class A { String s=\"new Base() {{ initialize(); }}\"; }",
        0,
    );
}

#[test]
fn migrated_java_class_initializer_use_thread() {
    let rule = "LEGACY-JAVA-AST-class-initializer-use-thread";
    check(
        rule,
        "class A { static { Thread thread = new Thread(); } }",
        1,
    );
    check(
        rule,
        "class A { static { if (ready) { Object thread = new Thread(task); } } }",
        1,
    );
    check(
        rule,
        "class A { { Thread thread = new Thread(); } void f() { new Thread(); } }",
        0,
    );
    check(
        rule,
        "class A { static { Object thread = new pkg.Thread(); String fake=\"new Thread()\"; } }",
        0,
    );
}

#[test]
fn java_rulemap_clone_requires_cloneable_interface() {
    let rule = "LEGACY-JAVA-RULEMAP-clone-without-cloneable";
    check(rule, "class A { Object clone() { return this; } }", 1);
    check(
        rule,
        "class A implements Cloneable { Object clone() { return this; } }",
        0,
    );
    check(rule, "class A { Object cloned() { return this; } }", 0);
}

#[test]
fn java_rulemap_finalize_requires_super_delegation() {
    let rule = "LEGACY-JAVA-RULEMAP-finalize-without-super";
    check(
        rule,
        "class A { protected void finalize() { clean(); } }",
        1,
    );
    check(
        rule,
        "class A { protected void finalize() { try { clean(); } finally { super.finalize(); } } }",
        0,
    );
    check(
        rule,
        "class A { protected void finalizer() { clean(); } }",
        0,
    );
}

#[test]
fn java_rulemap_method_return_wildcard_is_declaration_aware() {
    let rule = "LEGACY-JAVA-RULEMAP-return-generic-wildcard";
    check(
        rule,
        "class A { java.util.List<?> values() { return null; } }",
        1,
    );
    check(rule, "class A { java.util.List<String> values() { return null; } void consume(java.util.List<?> values) {} }", 0);
}

#[test]
fn java_rulemap_assertion_rules_are_token_and_parameter_aware() {
    check(
        "LEGACY-JAVA-RULEMAP-assert-always-false",
        "class A { void f() { assert false; } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-assert-always-false",
        "class A { void f(boolean ready) { assert ready; } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-assert-side-effect",
        "class A { void f(int count) { assert count++ > 0; } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-assert-side-effect",
        "class A { void f(int count) { assert count > 0; } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-assert-validates-parameter",
        "class A { void f(String value) { assert value != null; } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-assert-validates-parameter",
        "class A { void f(String value) { int state=1; assert state > 0; } }",
        0,
    );
}

#[test]
fn java_rulemap_method_length_uses_physical_body_lines() {
    let long_body = (0..50)
        .map(|index| format!("int value{index}={index};\n"))
        .collect::<String>();
    check(
        "LEGACY-JAVA-RULEMAP-method-over-fifty-lines",
        &format!("class A {{ void longMethod() {{\n{long_body}}} }}"),
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-method-over-fifty-lines",
        "class A { void shortMethod() { int value=1; } }",
        0,
    );
}

#[test]
fn java_rulemap_nesting_rules_report_the_first_excess_level() {
    let for_rule = "LEGACY-JAVA-RULEMAP-nested-for-over-three";
    check(
        for_rule,
        "class A { void f() { for(;;){for(;;){for(;;){for(;;){work();}}}} } }",
        1,
    );
    check(
        for_rule,
        "class A { void f() { for(;;){for(;;){for(;;){work();}}} } }",
        0,
    );

    let if_rule = "LEGACY-JAVA-RULEMAP-nested-if-over-three";
    check(
        if_rule,
        "class A { void f() { if(a){if(b){if(c){if(d){work();}}}} } }",
        1,
    );
    check(
        if_rule,
        "class A { void f() { if(a){if(b){if(c){work();}}} } }",
        0,
    );
}

#[test]
fn java_rulemap_try_inside_loop_is_structural() {
    let rule = "LEGACY-JAVA-RULEMAP-try-inside-loop";
    check(rule, "class A { void f() { while(ready) { try { work(); } catch(Exception error) { stop(); } } } }", 1);
    check(rule, "class A { void f() { try { while(ready) { work(); } } catch(Exception error) { stop(); } } }", 0);
}

#[test]
fn java_rulemap_constant_name_checks_only_static_final_fields() {
    let rule = "LEGACY-JAVA-RULEMAP-constant-name";
    check(rule, "class A { static final String badName=\"x\"; }", 1);
    check(
        rule,
        "class A { static final String GOOD_NAME=\"x\"; final String instanceName=\"x\"; }",
        0,
    );
}

#[test]
fn java_rulemap_serializable_class_rules_check_uid_and_sensitive_state() {
    let uid = "LEGACY-JAVA-RULEMAP-serializable-missing-uid";
    check(
        uid,
        "class Account implements java.io.Serializable { String name; }",
        1,
    );
    check(uid, "class Account implements java.io.Serializable { private static final long serialVersionUID=1L; }", 0);

    let sensitive = "LEGACY-JAVA-RULEMAP-serializable-sensitive-field";
    check(
        sensitive,
        "class Account implements Serializable { private String password; }",
        1,
    );
    check(sensitive, "class Account implements Serializable { private transient String password; private String name; }", 0);
}

#[test]
fn java_rulemap_applet_rules_protect_fields_inner_types_and_array_returns() {
    check(
        "LEGACY-JAVA-RULEMAP-applet-public-mutable-field",
        "class Tool extends Applet { public URL url; }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-applet-public-mutable-field",
        "class Tool extends Applet { private URL url; public final URL home=null; }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-applet-inner-class",
        "class Tool extends Applet { private class Helper {} }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-applet-inner-class",
        "class Tool { private class Helper {} }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-applet-private-array-return",
        "class Tool extends Applet { private URL[] urls; public URL[] getUrls() { return urls; } }",
        1,
    );
    check("LEGACY-JAVA-RULEMAP-applet-private-array-return", "class Tool extends Applet { private URL[] urls; public URL[] getUrls() { return urls.clone(); } }", 0);
}

#[test]
fn java_rulemap_equals_requires_a_runtime_type_check() {
    let rule = "LEGACY-JAVA-RULEMAP-equals-missing-type-check";
    check(rule, "class A { public boolean equals(Object other) { A value=(A) other; return id==value.id; } }", 1);
    check(rule, "class A { public boolean equals(Object other) { if (!(other instanceof A)) return false; A value=(A) other; return id==value.id; } }", 0);
}

#[test]
fn java_rulemap_custom_trust_manager_is_a_class_contract_check() {
    let rule = "LEGACY-JAVA-RULEMAP-custom-x509-trust-manager";
    check(rule, "class TrustAll implements javax.net.ssl.X509TrustManager { public void checkClientTrusted(X509Certificate[] chain,String auth){} public void checkServerTrusted(X509Certificate[] chain,String auth){} public X509Certificate[] getAcceptedIssuers(){return null;} }", 1);
    check(rule, "class TrustPolicy { void verify() {} }", 0);
}

#[test]
fn java_rulemap_file_upload_endpoint_requires_web_mapping_and_upload_parameter() {
    let rule = "LEGACY-JAVA-RULEMAP-file-upload-endpoint";
    check(rule, "class Upload { @PostMapping(\"/upload\") Result upload(MultipartFile file) { return save(file); } }", 1);
    check(rule, "class Upload { Result local(MultipartFile file) { return save(file); } @PostMapping(\"/text\") Result text(String value) { return save(value); } }", 0);
}

#[test]
fn java_rulemap_array_loop_uses_an_exclusive_length_bound() {
    let rule = "LEGACY-JAVA-RULEMAP-inclusive-array-length-loop";
    check(
        rule,
        "class A { void f(int[] values) { for (int i=0; i<=values.length; i++) use(values[i]); } }",
        1,
    );
    check(
        rule,
        "class A { void f(int[] values) { for (int i=0; i<values.length; i++) use(values[i]); } }",
        0,
    );
}

#[test]
fn android_activity_and_application_lifecycle_rules_check_required_methods() {
    let hijack = "LEGACY-JAVA-RULEMAP-activity-hijack-onpause";
    check(
        hijack,
        "class LoginActivity extends Activity { void onCreate() {} }",
        1,
    );
    check(
        hijack,
        "class LoginActivity extends Activity { protected void onPause() { super.onPause(); } }",
        0,
    );
    let provider = "LEGACY-JAVA-RULEMAP-provider-installer-missing";
    check(
        provider,
        "class App extends Application { public void onCreate() { super.onCreate(); } }",
        1,
    );
    check(provider, "class App extends Application { public void onCreate() { ProviderInstaller.installIfNeeded(this); } }", 0);
}

#[test]
fn spring_security_structure_rules_check_csp_matcher_order_and_binder_policy() {
    check(
        "LEGACY-JAVA-RULEMAP-spring-security-missing-csp",
        "class Security { void configure(HttpSecurity http) { http.authorizeRequests(); } }",
        1,
    );
    check("LEGACY-JAVA-RULEMAP-spring-security-missing-csp", "class Security { void configure(HttpSecurity http) { http.headers().contentSecurityPolicy(\"default-src self\"); } }", 0);
    check("LEGACY-JAVA-RULEMAP-spring-antmatcher-permit-all", "class Security { void configure(HttpSecurity http) { http.authorizeRequests().antMatchers(\"/root\").hasRole(\"ROOT\").anyRequest().permitAll(); } }", 1);
    check("LEGACY-JAVA-RULEMAP-spring-antmatcher-permit-all", "class Security { void configure(HttpSecurity http) { http.authorizeRequests().mvcMatchers(\"/root\").hasRole(\"ROOT\").anyRequest().authenticated(); } }", 0);
    check("LEGACY-JAVA-RULEMAP-spring-antmatcher-url-order", "class Security { void configure(HttpSecurity http) { http.antMatchers(\"/admin/**\").permitAll(); http.antMatchers(\"/admin/private\").denyAll(); } }", 1);
    check("LEGACY-JAVA-RULEMAP-spring-antmatcher-url-order", "class Security { void configure(HttpSecurity http) { http.antMatchers(\"/admin/private\").denyAll(); http.antMatchers(\"/admin/**\").authenticated(); } }", 0);
    check("LEGACY-JAVA-RULEMAP-insecure-web-data-binder", "class Controller { @InitBinder void bind(WebDataBinder binder) { binder.setAutoGrowNestedPaths(true); } }", 1);
    check("LEGACY-JAVA-RULEMAP-insecure-web-data-binder", "class Controller { @InitBinder void bind(WebDataBinder binder) { binder.setAllowedFields(\"name\", \"email\"); } }", 0);
}

#[test]
fn struts_aware_maps_reject_framework_parameter_names() {
    let rule = "LEGACY-JAVA-RULEMAP-struts-aware-map-exposure";
    check(rule, "class Action implements SessionAware { public void setSession(java.util.Map<String,Object> value) { this.session = value; } java.util.Map<String,Object> session; }", 1);
    check(rule, "class Action implements SessionAware, ParameterNameAware { public void setSession(java.util.Map<String,Object> value) { this.session = value; } public boolean acceptableParameterName(String name) { return !name.startsWith(\"session.\"); } java.util.Map<String,Object> session; }", 0);
}

#[test]
fn spring_session_attributes_are_reported_on_request_controllers() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-session-attributes";
    check(rule, "@Controller @SessionAttributes(\"user\") class Users { @PostMapping(\"/login\") String login(User user) { return \"ok\"; } }", 1);
    check(rule, "@Controller class Users { @PostMapping(\"/login\") String login(User user) { return \"ok\"; } }", 0);
}

#[test]
fn spring_handlers_do_not_persist_bound_entities_directly() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-persisted-entity-binding";
    check(rule, "@Entity class Order { String id; } class Orders { @PostMapping(\"/orders\") void update(Order order) { repository.save(order); } }", 1);
    check(rule, "class OrderInput { String id; } @Entity class Order { String id; } class Orders { @PostMapping(\"/orders\") void update(OrderInput input) { repository.save(copy(input)); } }", 0);
}

#[test]
fn zip_entry_paths_are_contained_before_extraction() {
    let rule = "LEGACY-JAVA-RULEMAP-unsafe-zip-entry-extraction";
    check(rule, "class Zip { void extract(ZipEntry entry, File root) { File out = new File(root, entry.getName()); write(out); } }", 1);
    check(rule, "class Zip { void extract(ZipEntry entry, File root) { File out = new File(root, entry.getName()).getCanonicalFile(); if (!out.getPath().startsWith(root.getCanonicalPath())) throw new IllegalArgumentException(); write(out); } }", 0);
}

#[test]
fn authentication_rotates_the_existing_session() {
    let rule = "LEGACY-JAVA-RULEMAP-session-fixation";
    check(rule, "class Login { void authenticate(LoginContext context, HttpSession session) { context.login(); } }", 1);
    check(rule, "class Login { void authenticate(LoginContext context, HttpSession session) { session.invalidate(); context.login(); } }", 0);
}

#[test]
fn pbe_salts_do_not_come_directly_from_external_configuration() {
    let rule = "LEGACY-JAVA-RULEMAP-user-controlled-pbe-salt";
    check(rule, "class Crypto { void init(Properties p) { PBEParameterSpec spec = new PBEParameterSpec(p.getProperty(\"salt\").getBytes(), 10000); } }", 1);
    check(rule, "class Crypto { void init(byte[] salt) { new SecureRandom().nextBytes(salt); PBEParameterSpec spec = new PBEParameterSpec(salt, 10000); } }", 0);
}

#[test]
fn cookie_values_do_not_drive_authorization() {
    let rule = "LEGACY-JAVA-RULEMAP-cookie-security-decision";
    check(rule, "class Auth { boolean allowed(HttpServletRequest request) { Cookie[] cookies = request.getCookies(); String isAdmin = cookies[0].getValue(); if (\"true\".equals(isAdmin)) return true; return false; } }", 1);
    check(rule, "class Preferences { String theme(HttpServletRequest request) { Cookie[] cookies = request.getCookies(); return cookies[0].getValue(); } }", 0);
}

#[test]
fn xml_parsers_and_axis_calls_declare_validation_contracts() {
    check("LEGACY-JAVA-RULEMAP-missing-xml-validation", "class Xml { void read(DocumentBuilderFactory factory, File input) { Document doc = factory.newDocumentBuilder().parse(input); } }", 1);
    check("LEGACY-JAVA-RULEMAP-missing-xml-validation", "class Xml { void read(DocumentBuilderFactory factory, File input) { factory.setValidating(true); Document doc = factory.newDocumentBuilder().parse(input); } }", 0);
    check("LEGACY-JAVA-RULEMAP-axis-untyped-xml-response", "class Soap { Object call(Call call) { call.addParameter(\"name\", Constants.XSD_STRING, ParameterMode.IN); return call.invoke(new Object[]{\"a\"}); } }", 1);
    check("LEGACY-JAVA-RULEMAP-axis-untyped-xml-response", "class Soap { Object call(Call call) { call.addParameter(\"name\", Constants.XSD_STRING, ParameterMode.IN); call.setReturnType(Constants.XSD_STRING); return call.invoke(new Object[]{\"a\"}); } }", 0);
}

#[test]
fn preference_activities_validate_fragment_classes() {
    let rule = "LEGACY-JAVA-RULEMAP-fragment-injection";
    check(rule, "class Settings extends PreferenceActivity { void open(String name) { Fragment.instantiate(this, name); } }", 1);
    check(rule, "class Settings extends PreferenceActivity { protected boolean isValidFragment(String name) { return name.equals(SafeFragment.class.getName()); } }", 0);
}

#[test]
fn jsonp_and_deserialization_blacklists_are_rejected() {
    check("LEGACY-JAVA-RULEMAP-jsonp-same-origin-execution", "class Advice extends AbstractJsonpResponseBodyAdvice { Advice() { super(\"callback\"); } }", 1);
    check("LEGACY-JAVA-RULEMAP-jsonp-same-origin-execution", "class Advice extends ResponseBodyAdvice { }", 0);
    check("LEGACY-JAVA-RULEMAP-deserialization-blacklist", "class Read { void f() { ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\"!com.bad.Gadget;*\"); } }", 1);
    check("LEGACY-JAVA-RULEMAP-deserialization-blacklist", "class Read { void f() { ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\"com.example.Safe;!*\"); } }", 0);
}

#[test]
fn http_message_framing_is_unambiguous() {
    let rule = "LEGACY-JAVA-RULEMAP-http-request-smuggling-headers";
    check(rule, "class Proxy { void send(Request request) { request.setHeader(\"Content-Length\", \"10\"); request.setHeader(\"Transfer-Encoding\", \"chunked\"); } }", 1);
    check(rule, "class Proxy { void send(Request request) { request.setHeader(\"Content-Length\", \"10\"); } }", 0);
}

#[test]
fn external_numeric_values_are_bounded_before_sensitive_uses() {
    let source = "class Limits { void f(BufferedReader reader, int[] values) throws Exception { int n = Integer.parseInt(reader.readLine()); int quotient = 100 / n; int value = values[n]; for (int i = 0; i < n; i++) use(i); int product = n * 1000000; } }";
    check("LEGACY-JAVA-RULEMAP-external-divisor", source, 1);
    check("LEGACY-JAVA-RULEMAP-external-array-index", source, 1);
    check("LEGACY-JAVA-RULEMAP-external-loop-bound", source, 1);
    check("LEGACY-JAVA-RULEMAP-external-integer-arithmetic", source, 1);
    let bounded = "class Limits { void f(BufferedReader reader, int[] values) throws Exception { int n = Integer.parseInt(reader.readLine()); if (n > 0 && n < 100) { int quotient = 100 / n; int value = values[n]; } } }";
    check("LEGACY-JAVA-RULEMAP-external-divisor", bounded, 0);
    check("LEGACY-JAVA-RULEMAP-external-array-index", bounded, 0);
}

#[test]
fn excessive_initial_capacities_are_reported() {
    let rule = "LEGACY-JAVA-RULEMAP-excessive-memory-allocation";
    check(rule, "class Memory { void f() { int[] data = new int[4096]; } }", 1);
    check(rule, "class Memory { void f() { int[] data = new int[32]; } }", 0);
}

#[test]
fn non_static_inner_classes_are_distinguished_from_static_nested_classes() {
    let rule = "LEGACY-JAVA-RULEMAP-non-static-inner-class-memory-leak";
    check(rule, "class Activity { class Worker {} }", 1);
    check(rule, "class Activity { static class Worker {} }", 0);
    check(
        rule,
        "class Activity { Runnable task = new Runnable() { public void run() {} }; }",
        1,
    );
}

#[test]
fn getter_and_setter_pairs_use_consistent_synchronization() {
    let rule = "LEGACY-JAVA-RULEMAP-getter-setter-synchronization";
    check(rule, "class User { synchronized String getName() { return name; } void setName(String name) { this.name=name; } }", 1);
    check(rule, "class User { String getAge() { synchronized(this) { return age; } } void setAge(int age) { this.age=age; } }", 1);
    check(rule, "class User { synchronized String getName() { return name; } synchronized void setName(String name) { this.name=name; } }", 0);
    check(rule, "class User { String getName() { return name; } void setName(String name) { this.name=name; } }", 0);
}

#[test]
fn java_bean_accessors_must_access_the_named_field() {
    let rule = "LEGACY-JAVA-RULEMAP-wrong-getter-setter-field";
    check(rule, "class User { String username; String password; String getUsername() { return this.password; } }", 1);
    check(rule, "class User { String username; String password; void setUsername(String username) { this.password=username; } }", 1);
    check(rule, "class User { String username; String getUsername() { return this.username; } void setUsername(String username) { this.username=username; } }", 0);
    check(
        rule,
        "class User { String username; String getUsername() { return normalize(username); } }",
        0,
    );
}

#[test]
fn synchronization_uses_stable_and_compatible_lock_objects() {
    let get_class = "LEGACY-JAVA-RULEMAP-synchronize-on-getclass";
    check(
        get_class,
        "class Base { void parse() { synchronized(getClass()) { work(); } } }",
        1,
    );
    check(
        get_class,
        "class Base { void parse() { synchronized(Base.class) { work(); } } }",
        0,
    );

    let concurrency = "LEGACY-JAVA-RULEMAP-synchronize-on-concurrency-object";
    check(concurrency, "class A { final java.util.concurrent.locks.Lock lock = new ReentrantLock(); void f() { synchronized(lock) { work(); } } }", 1);
    check(concurrency, "class A { void f(java.util.concurrent.locks.Condition ready) { synchronized(ready) { work(); } } }", 1);
    check(
        concurrency,
        "class A { final Object lock = new Object(); void f() { synchronized(lock) { work(); } } }",
        0,
    );
}

#[test]
fn serializable_callbacks_preserve_security_checks() {
    let rule = "LEGACY-JAVA-RULEMAP-serializable-security-check";
    check(rule, "class SafeData implements Serializable { SafeData() { SecurityManager manager=System.getSecurityManager(); manager.checkPermission(PERMISSION); } void readObject(ObjectInputStream input) { input.defaultReadObject(); } }", 1);
    check(rule, "class SafeData implements Serializable { SafeData() { verify(); } void readObject(ObjectInputStream input) { verify(); input.defaultReadObject(); } private void verify() { SecurityManager manager=System.getSecurityManager(); manager.checkPermission(PERMISSION); } }", 0);
    check(rule, "class PlainData implements Serializable { PlainData() {} void readObject(ObjectInputStream input) { input.defaultReadObject(); } }", 0);
}

#[test]
fn serializable_classes_do_not_invoke_dangerous_runtime_apis() {
    let rule = "LEGACY-JAVA-RULEMAP-serializable-dangerous-call";
    check(rule, "class Payload implements Serializable { Object readResolve() { return Class.forName(name).newInstance(); } }", 2);
    check(rule, "class Payload implements Serializable { String readResolve() { return normalize(name); } }", 0);
    check(
        rule,
        "class Ordinary { Object build() { return Class.forName(name).newInstance(); } }",
        0,
    );
}

#[test]
fn instance_locks_do_not_claim_to_protect_static_state() {
    let rule = "LEGACY-JAVA-RULEMAP-instance-lock-static-data";
    check(
        rule,
        "class Counter { static int count; synchronized void increment() { count++; } }",
        1,
    );
    check(rule, "class Counter { static int count; final Object lock=new Object(); void increment() { synchronized(lock) { count++; } } }", 1);
    check(rule, "class Counter { static int count; static final Object lock=new Object(); void increment() { synchronized(lock) { count++; } } }", 0);
    check(
        rule,
        "class Counter { static int count; static synchronized void increment() { count++; } }",
        0,
    );
}

#[test]
fn custom_types_do_not_shadow_standard_library_types() {
    let rule = "LEGACY-JAVA-RULEMAP-java-standard-library-identifier";
    check(rule, "class Vector { int value; }", 1);
    check(rule, "interface List { int size(); }", 1);
    check(rule, "class MyVector { int value; }", 0);
}

#[test]
fn javaee_debug_entry_points_are_component_scoped() {
    let rule = "LEGACY-JAVA-RULEMAP-javaee-main-debug-entry";
    check(rule, "class DebugServlet extends HttpServlet { public static void main(String[] args) { run(); } }", 1);
    check(rule, "@RestController class DebugController { public static void main(String[] args) { run(); } }", 1);
    check(
        rule,
        "class CommandLineTool { public static void main(String[] args) { run(); } }",
        0,
    );
}

#[test]
fn android_package_names_use_case_sensitive_comparison() {
    let rule = "LEGACY-JAVA-RULEMAP-case-insensitive-package-comparison";
    check(rule, "class A { boolean valid(String packageName) { return getPackageName().equalsIgnoreCase(packageName); } }", 1);
    check(rule, "class A { boolean valid(String packageName) { return getPackageName().equals(packageName); } }", 0);
    check(rule, "class A { boolean valid(String left, String right) { return left.equalsIgnoreCase(right); } }", 0);
}

#[test]
fn android_crypto_secrets_are_not_retained_in_static_fields() {
    let rule = "LEGACY-JAVA-RULEMAP-android-static-crypto-secret";
    check(rule, "class Crypto { private static javax.crypto.SecretKey key; }", 1);
    check(rule, "class Crypto { private static byte[] encryptionKey; }", 1);
    check(rule, "class Crypto { private javax.crypto.SecretKey key; private static String algorithm; }", 0);
}

#[test]
fn serializable_subclasses_require_a_constructible_nonserializable_parent() {
    let rule = "LEGACY-JAVA-RULEMAP-serializable-parent-noarg-constructor";
    check(rule, "class Human { Human(int age) {} } class User extends Human implements Serializable { User() { super(1); } }", 1);
    check(rule, "class Human { Human() {} Human(int age) {} } class User extends Human implements Serializable {}", 0);
    check(rule, "class Human implements Serializable { Human(int age) {} } class User extends Human implements Serializable {}", 0);
}

#[test]
fn servlet_response_streams_are_committed_once() {
    let rule = "LEGACY-JAVA-RULEMAP-multiple-servlet-stream-commits";
    check(rule, "class S { void get(HttpServletResponse response) { OutputStream out=response.getOutputStream(); out.flush(); response.sendRedirect(\"/done\"); } }", 1);
    check(rule, "class S { void get(HttpServletResponse response) { response.getWriter(); response.getOutputStream(); } }", 1);
    check(rule, "class S { void get(HttpServletResponse response) { PrintWriter out=response.getWriter(); out.println(\"ok\"); } }", 0);
    check(rule, "class S { void get(Response response) { response.getWriter(); response.getOutputStream(); } }", 0);
}

#[test]
fn public_buffer_accessors_do_not_expose_mutable_aliases() {
    let rule = "LEGACY-JAVA-RULEMAP-exposed-aliased-buffer";
    check(
        rule,
        "class A { private char[] data; public java.nio.CharBuffer data() { return java.nio.CharBuffer.wrap(data); } }",
        1,
    );
    check(
        rule,
        "class A { private java.nio.ByteBuffer data; public java.nio.ByteBuffer data() { return data.duplicate(); } }",
        1,
    );
    check(
        rule,
        "class A { private java.nio.ByteBuffer data; public java.nio.ByteBuffer data() { return data.duplicate().asReadOnlyBuffer(); } }",
        0,
    );
    check(
        rule,
        "class A { private java.nio.ByteBuffer data; private java.nio.ByteBuffer internal() { return data.duplicate(); } }",
        0,
    );
}

#[test]
fn inherited_static_methods_are_not_hidden() {
    let rule = "LEGACY-JAVA-RULEMAP-hidden-inherited-method";
    check(
        rule,
        "class Parent { protected static void reset(int value) {} } class Child extends Parent { public static void reset(int value) {} }",
        1,
    );
    check(
        rule,
        "class Parent { static void reset(int value) {} } class Child extends Parent { static void reset(String value) {} }",
        0,
    );
    check(
        rule,
        "class Parent { void reset(int value) {} } class Child extends Parent { @Override void reset(int value) {} }",
        0,
    );
}

#[test]
fn inherited_method_overloads_make_intent_explicit() {
    let rule = "LEGACY-JAVA-RULEMAP-misleading-method-signature";
    check(
        rule,
        "class Parent { void process(String value) {} } class Child extends Parent { void process(Object value) {} }",
        1,
    );
    check(
        rule,
        "class Parent { void process(String value) {} } class Child extends Parent { @Override void process(String value) {} }",
        0,
    );
    check(
        rule,
        "class Parent { void process(String value) {} } class Child extends Parent { void consume(Object value) {} }",
        0,
    );
}

#[test]
fn overrides_preserve_the_synchronization_contract() {
    let rule = "LEGACY-JAVA-RULEMAP-unsynchronized-override";
    check(
        rule,
        "class Parent { synchronized void update(int value) {} } class Child extends Parent { @Override void update(int value) {} }",
        1,
    );
    check(
        rule,
        "class Parent { synchronized void update(int value) {} } class Child extends Parent { @Override synchronized void update(int value) {} }",
        0,
    );
    check(
        rule,
        "class Parent { void update(int value) {} } class Child extends Parent { @Override void update(int value) {} }",
        0,
    );
}

#[test]
fn overrides_do_not_broaden_inherited_accessibility() {
    let rule = "LEGACY-JAVA-RULEMAP-increased-override-accessibility";
    check(
        rule,
        "class Parent { protected void inspect(int value) {} } class Child extends Parent { public void inspect(int value) {} }",
        1,
    );
    check(
        rule,
        "class Parent { protected void inspect(int value) {} } class Child extends Parent { protected void inspect(int value) {} }",
        0,
    );
    check(
        rule,
        "class Parent { public void inspect(int value) {} } class Child extends Parent { public void inspect(int value) {} }",
        0,
    );
}

#[test]
fn collection_views_are_not_used_as_independent_locks() {
    let rule = "LEGACY-JAVA-RULEMAP-collection-view-synchronization";
    check(
        rule,
        "class A { void f(java.util.Map<String,String> map) { java.util.Set<String> keys=map.keySet(); synchronized(keys) { keys.clear(); } } }",
        1,
    );
    check(
        rule,
        "class A { void f(java.util.List<String> values) { java.util.List<String> range=values.subList(0, 2); synchronized(range) { range.clear(); } } }",
        1,
    );
    check(
        rule,
        "class A { void f(java.util.Map<String,String> map) { java.util.Set<String> keys=map.keySet(); synchronized(map) { keys.clear(); } } }",
        0,
    );
    check(
        rule,
        "class A { void f(Object lock) { synchronized(lock) { work(); } } }",
        0,
    );
}

#[test]
fn constant_java_regular_expressions_are_validated() {
    let rule = "LEGACY-JAVA-RULEMAP-invalid-constant-regex";
    check(
        rule,
        "class A { void f() { java.util.regex.Pattern.compile(\"([a-z]+\"); } }",
        1,
    );
    check(
        rule,
        "class A { boolean f(String value) { return value.matches(\"*word\"); } }",
        1,
    );
    check(
        rule,
        "class A { void f() { java.util.regex.Pattern.compile(\"^[a-z]+$\"); } }",
        0,
    );
    check(
        rule,
        "class A { void f() { java.util.regex.Pattern.compile(\"(?<=prefix)\\\\w+\"); } }",
        0,
    );
    check(
        rule,
        "class A { void f(String dynamic) { java.util.regex.Pattern.compile(dynamic); } }",
        0,
    );
}

#[test]
fn spring_security_request_policies_have_a_deny_all_fallback() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-security-missing-fallback";
    check(
        rule,
        "class Security { protected void configure(HttpSecurity http) throws Exception { http.authorizeRequests().mvcMatchers(\"/admin/**\").hasRole(\"ADMIN\"); } }",
        1,
    );
    check(
        rule,
        "class Security { protected void configure(HttpSecurity http) throws Exception { http.authorizeRequests().mvcMatchers(\"/admin/**\").hasRole(\"ADMIN\").anyRequest().denyAll(); } }",
        0,
    );
    check(
        rule,
        "class Security { protected void configure(OtherSecurity http) { http.mvcMatchers(\"/admin/**\"); } }",
        0,
    );
}

#[test]
fn double_checked_locking_requires_volatile_publication() {
    let rule = "LEGACY-JAVA-RULEMAP-double-checked-locking";
    check(
        rule,
        "class Singleton { private static Instance instance; static Instance get() { if (instance == null) { synchronized (Singleton.class) { if (instance == null) { instance = new Instance(); } } } return instance; } }",
        1,
    );
    check(
        rule,
        "class Singleton { private static volatile Instance instance; static Instance get() { if (instance == null) { synchronized (Singleton.class) { if (instance == null) { instance = new Instance(); } } } return instance; } }",
        0,
    );
    check(
        rule,
        "class Singleton { private static Instance instance; static synchronized Instance get() { if (instance == null) { instance = new Instance(); } return instance; } }",
        0,
    );
}

#[test]
fn shared_java_components_do_not_retain_thread_unsafe_resources() {
    check(
        "LEGACY-JAVA-RULEMAP-static-unsafe-formatter",
        "class Dates { private static final java.text.SimpleDateFormat FORMAT = new SimpleDateFormat(\"yyyy-MM-dd\"); }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-static-unsafe-formatter",
        "class Dates { String format(Date value) { java.text.SimpleDateFormat format = new SimpleDateFormat(\"yyyy-MM-dd\"); return format.format(value); } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-static-database-connection",
        "class Database { private static java.sql.Connection connection; }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-static-database-connection",
        "class Database { private javax.sql.DataSource dataSource; void run() { Connection connection=dataSource.getConnection(); } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-servlet-instance-state",
        "class LoginServlet extends HttpServlet { private String username; protected void doPost(Request request) { username=request.getParameter(\"username\"); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-servlet-instance-state",
        "class LoginServlet extends HttpServlet { private static final String REALM=\"main\"; protected void doPost(Request request) { String username=request.getParameter(\"username\"); } }",
        0,
    );
}

#[test]
fn static_initialization_dependency_cycles_are_reported() {
    let rule = "LEGACY-JAVA-RULEMAP-class-initialization-cycle";
    check(
        rule,
        "class A { static final int value=B.value+1; } class B { static final int value=A.value+1; }",
        2,
    );
    check(
        rule,
        "class Cycle { final int balance; private static final Cycle INSTANCE=new Cycle(); private static final int deposit=10; Cycle() { balance=deposit-1; } }",
        1,
    );
    check(
        rule,
        "class A { static final int value=1; } class B { static final int value=A.value+1; }",
        0,
    );
}

#[test]
fn android_packages_are_not_installed_from_shared_storage() {
    let rule = "LEGACY-JAVA-RULEMAP-shared-storage-apk-install";
    check(rule, "class Installer { void install(Context context) { File apk=new File(Environment.getExternalStorageDirectory(), \"download/app.apk\"); Intent intent=new Intent(Intent.ACTION_VIEW); intent.setDataAndType(Uri.fromFile(apk), \"application/vnd.android.package-archive\"); context.startActivity(intent); } }", 1);
    check(rule, "class Installer { void install(Context context) { File apk=new File(context.getFilesDir(), \"download/app.apk\"); Intent intent=new Intent(Intent.ACTION_VIEW); intent.setDataAndType(Uri.fromFile(apk), \"application/vnd.android.package-archive\"); context.startActivity(intent); } }", 0);
}

#[test]
fn same_named_arguments_follow_the_declared_parameter_order() {
    let rule = "LEGACY-JAVA-RULEMAP-wrong-parameter-order";
    check(
        rule,
        "class Copier { void run() { Object src=openSource(); Object dest=openDestination(); copy(dest, src); } void copy(Object src, Object dest) {} }",
        1,
    );
    check(
        rule,
        "class Copier { void run() { Object src=openSource(); Object dest=openDestination(); copy(src, dest); } void copy(Object src, Object dest) {} }",
        0,
    );
    check(
        rule,
        "class Copier { void run() { Object input=openSource(); Object output=openDestination(); copy(input, output); } void copy(Object src, Object dest) {} }",
        0,
    );
}

#[test]
fn cryptographic_initialization_vectors_are_randomized() {
    let rule = "LEGACY-JAVA-RULEMAP-fixed-initialization-vector";
    check(
        rule,
        "class Crypto { void f() { byte[] iv={14,80,94,47,3,66,96,110}; IvParameterSpec spec=new IvParameterSpec(iv); } }",
        1,
    );
    check(
        rule,
        "class Crypto { void f() { IvParameterSpec spec=new IvParameterSpec(new byte[16]); } }",
        1,
    );
    check(
        rule,
        "class Crypto { void f(SecureRandom random) { byte[] iv=new byte[16]; random.nextBytes(iv); IvParameterSpec spec=new IvParameterSpec(iv); } }",
        0,
    );
    check(
        rule,
        "class Crypto { void f(byte[] iv) { IvParameterSpec spec=new IvParameterSpec(iv); } }",
        0,
    );
}

#[test]
fn privileged_operations_are_not_exposed_by_public_methods() {
    let rule = "LEGACY-JAVA-RULEMAP-public-privileged-method";
    check(rule, "class Files { public static Object open(String path) { return AccessController.doPrivileged(new OpenAction(path)); } }", 1);
    check(rule, "class Files { private static Object open(String path) { return AccessController.doPrivileged(new OpenAction(path)); } public Object validated(String path) { check(path); return open(path); } }", 0);
    check(rule, "class Files { public Object open(String path) { return ordinaryController.open(path); } }", 0);
}
