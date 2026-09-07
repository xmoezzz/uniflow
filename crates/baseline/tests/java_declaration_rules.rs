use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|r| r.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::Java, Path::new("Declarations.java"), source);
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
    let hir = JavaParser::default().parse_file("Declarations.java", source).unwrap();
    let integrated = pack.scan_hir(&hir, &HashMap::from([("Declarations.java".into(), source.into())]));
    assert_eq!(integrated.len(), expected, "HIR {rule}: {source}\n{integrated:#?}");
    assert_eq!(findings.iter().map(|f| (f.line, f.column)).collect::<Vec<_>>(),
        integrated.iter().map(|f| (f.line, f.column)).collect::<Vec<_>>());
}

#[test]
fn migrated_java_final_clone_method() {
    let rule = "LEGACY-JAVA-AST-final-clone-method";
    check(rule, "class A implements Cloneable { public Object clone() { return this; } }", 1);
    check(rule, "class A implements java.lang.Cloneable { protected abstract Object clone(); }", 1);
    for source in ["class A implements Cloneable { public final Object clone() { return this; } }",
        "class A { public Object clone() { return this; } }",
        "class A implements Cloneable { class B { Object clone() { return this; } } }",
        "class A implements NotCloneable { Object clone() { return this; } }"] { check(rule, source, 0); }
}

#[test]
fn migrated_java_private_finalize() {
    let rule = "LEGACY-JAVA-AST-private-finalize";
    check(rule, "class A { public void finalize() {} protected void finalize(int x) {} }", 2);
    check(rule, "class A { private void finalize() {} void finalize(int x) {} public void finalizer() {} }", 0);
    check(rule, "class A { @Mark(visibility=\"public\") private void finalize() {} }", 0);
}

#[test]
fn migrated_java_request_mapping_method_public() {
    let rule = "LEGACY-JAVA-AST-request-mapping-method-public";
    check(rule, "class A { @RequestMapping(\"/x\") void route() {} @web.RequestMapping(path={\"/a\",\"/b\"}) protected void other() {} }", 2);
    check(rule, "class A { @RequestMapping(\"/x\") public void route() {} @GetMapping void other() {} }", 0);
    check(rule, "@RequestMapping class A { private void ordinary() { String x=\"@RequestMapping\"; } }", 0);
    check(rule, "class A { @web.CustomRequestMapping private void route() {} }", 1);
}

#[test]
fn migrated_java_rewrite_thread_run_method() {
    let rule = "LEGACY-JAVA-AST-rewrite-thread-run-method";
    check(rule, "class A extends Thread {}", 1);
    check(rule, "class A<T> extends java.lang.Thread implements Runnable { class B { void run() {} } }", 1);
    check(rule, "class A extends Thread { Runnable x = new Runnable() { public void run() {} }; }", 1);
    check(rule, "class A extends Thread { public void run() {} }", 0);
    check(rule, "class A extends Thread { public void run(int x) {} }", 0); // Original rule checks name, not override signature.
    check(rule, "class A extends WorkerThread {} class B implements Runnable {}", 0);
}

#[test]
fn migrated_java_default_constructor_externalizable() {
    let rule = "LEGACY-JAVA-AST-default-ctor--externalizable";
    check(rule, "class A implements Externalizable {}", 1);
    check(rule, "class A implements java.io.Externalizable { A(int n) {} class B { B() {} } }", 1);
    check(rule, "class A implements Externalizable { private A(/* empty */) {} }", 0); // No visibility gate in source rule.
    check(rule, "class A implements Serializable {}", 0);
    check(rule, "class A implements CustomExternalizable {}", 1); // Legacy interface regex is unanchored.
}

#[test]
fn migrated_java_equals_hashcode_check() {
    let rule = "LEGACY-JAVA-AST-equals-hashcode-check";
    check(rule, "class A { boolean equals(Object x) { return true; } }", 1);
    check(rule, "class A { int hashCode() { return 1; } }", 1);
    check(rule, "class A { boolean equals(Object x) { return true; } int hashCode() { return 1; } }", 0);
    check(rule, "class A { boolean equals(Object x) { return true; } class B { int hashCode() { return 1; } } }", 2);
    check(rule, "class A { Object x = new Object() { public int hashCode() { return 1; } }; }", 1);
    check(rule, "interface A { boolean equals(Object x); }", 0);
}

#[test]
fn migrated_java_serialize_method_sign() {
    let rule = "LEGACY-JAVA-AST-serialize-method-sign";
    check(rule, "class A { void writeObject(java.io.ObjectOutputStream out) {} void readObject(ObjectInputStream in) {} void readObjectNoData() {} }", 3);
    check(rule, "class A { void writeObject(ObjectOutputStream out) throws IOException {} void readObject(ObjectInputStream in) throws Exception {} void readObjectNoData() throws Error {} }", 0);
    check(rule, "class A { void writeObject(Object out) {} void readObject(String in) {} }", 0);
    check(rule, "class A { void readObjectNoDataExtra() {} }", 1); // Original name regex is not anchored.
}

#[test]
fn migrated_java_serial_version_uid_defined() {
    let rule = "LEGACY-JAVA-AST-serial-version-uid-defined";
    check(rule, "class A implements Serializable { long serialVersionUID=1; }", 1);
    check(rule, "class A implements java.io.Serializable { static final int serialVersionUID=1; }", 1);
    check(rule, "class A implements Serializable { static final long other=0, serialVersionUID=1; }", 0);
    check(rule, "class A implements Serializable { class B { long serialVersionUID=1; } }", 0);
    check(rule, "class A { long serialVersionUID=1; } class B implements Serializable {}", 0); // Source checks existing fields only.
    check(rule, "class A implements Serializable { void f() { long serialVersionUID=1; } }", 0);
}

#[test]
fn migrated_java_static_final_logger() {
    let rule = "LEGACY-JAVA-AST-static-final-logger";
    check(rule, "class A { Logger a=make(); static Logger b; final java.util.logging.Logger c=make(); }", 3);
    check(rule, "class A { private static final Logger a=make(), b=make(); LoggerFactory f; Logger[] array; void f() { Logger local=make(); } }", 0);
    check(rule, "class A { Logger first, second; }", 1); // One field declaration, not two declarators.
    check(rule, "class A { @Mark(text=\"static final\") Logger x; }", 1);
}

#[test]
fn migrated_java_multiple_logger() {
    let rule = "LEGACY-JAVA-AST-mult-logger";
    check(rule, "class A { Logger a; /* adjacent */ java.util.logging.Logger b; Logger c; }", 2);
    for source in ["class A { Logger a, b; }", "class A { Logger a; int n; Logger b; }",
        "class A { Logger a; void f() {} Logger b; }", "class A { Logger a; static {} Logger b; }",
        "class A { Logger a; class B { Logger b; } Logger c; }"] { check(rule, source, 0); }
    check(rule, "class A { Logger a=new Logger() { void helper() {} }; Logger b; }", 1);
}

#[test]
fn migrated_java_field_name_and_class_name_same() {
    let rule = "LEGACY-JAVA-AST-field-name-and-class-name-same";
    check(rule, "class A { int A; }", 1);
    check(rule, "class A { int first=1, A=2; }", 1);
    check(rule, "class A { class B { int A; } void f() { int A=1; } }", 0);
    check(rule, "class A { A() {} String text=\"int A\"; } interface B { int B=1; }", 0);
}

#[test]
fn migrated_java_field_name_and_method_name_same() {
    let rule = "LEGACY-JAVA-AST-field-name-and-method-name-same";
    check(rule, "class A { int work; void work() {} }", 1);
    check(rule, "class A { void work() {} int first=0, work=1; }", 1);
    check(rule, "class A { int work; class B { void work() {} } }", 0);
    check(rule, "class A { int work; Object x=new Object() { void work() {} }; }", 0);
    check(rule, "class A { void work() { int work=0; } }", 0);
}

#[test]
fn migrated_java_final_public_static_field() {
    let rule = "LEGACY-JAVA-AST-final-public-static-field";
    check(rule, "class A { public static int count; public static volatile Object state; }", 2);
    check(rule, "class A { public static final int COUNT=1; private static int count; public int value; }", 0);
    check(rule, "interface A { int implicit=1; public static final int explicit=2; }", 0);
    check(rule, "class A { void f() { publicStatic(); } String s=\"public static\"; }", 0);
}

#[test]
fn migrated_java_static_private_final_objectstreamfield() {
    let rule = "LEGACY-JAVA-AST-static-private-final-objectstreamfield";
    check(rule, "class A { ObjectStreamField[] serialPersistentFields; public static final ObjectStreamField[] serialPersistentFields2=null; }", 1);
    check(rule, "class A { public static final ObjectStreamField[] serialPersistentFields=null; }", 1);
    check(rule, "class A { protected static final java.io.ObjectStreamField[] serialPersistentFields=null; }", 1);
    check(rule, "class A { private static final ObjectStreamField[] serialPersistentFields=null; }", 0);
    check(rule, "class A { static final java.io.ObjectStreamField[] serialPersistentFields=null; }", 0);
    check(rule, "class A { public static final Object serialPersistentFields=null; }", 0);
    check(rule, "class A { void f() { ObjectStreamField[] serialPersistentFields=null; } }", 0);
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
    check(rule, "class A { void f() { final Object value=new Object(); } }", 0);
}

#[test]
fn migrated_java_immutable_final_field() {
    let rule = "LEGACY-JAVA-AST-immutable-final-field";
    check(rule, "@Immutable class A { int value; private Object state; }", 2);
    check(rule, "@pkg.Immutable class A { final int value=1; }", 0);
    check(rule, "@Immutable(reason=\"marker with arguments\") class A { int value; }", 0);
    check(rule, "class A { @Immutable int value; }", 0);
    check(rule, "@Immutable class A { class B { int value; } void f() { int local=0; } }", 0);
}

#[test]
fn migrated_java_immutable_public_final_field() {
    let rule = "LEGACY-JAVA-AST-immutable-public-final-field";
    check(rule, "@Immutable class A { public final int value=1; public Object state; }", 2);
    check(rule, "@Immutable class A { private final int value=1; protected Object state; }", 0);
    check(rule, "@Immutable(value=true) class A { public int value; }", 0);
    check(rule, "class A { @Immutable public int value; }", 0);
}

#[test]
fn migrated_java_transient_field_class() {
    let rule = "LEGACY-JAVA-AST-transient-field-class";
    check(rule, "class A { transient int cache; private transient Object state; }", 2);
    check(rule, "class A extends Base { transient int cache; } class B implements Tag { transient int cache; }", 0);
    check(rule, "class Outer { class Inner { transient int cache; } }", 1);
    check(rule, "class A { void f() { transientCall(); } String s=\"transient int cache\"; }", 0);
}

#[test]
fn migrated_java_stateholder_restorestate_savestate() {
    let rule = "LEGACY-JAVA-AST-stateholder-restorestate-savestate";
    check(rule, "class A extends StateHolder { void restoreState() {} }", 1);
    check(rule, "class A extends pkg.StateHolderBase { void saveState() {} }", 1);
    check(rule, "class A extends StateHolder { void restoreState() {} void saveState() {} }", 0);
    check(rule, "class A extends StateHolder { void restoreState() {} class B { void saveState() {} } }", 1);
    check(rule, "class A extends Other { void restoreState() {} }", 0);
    check(rule, "class A extends StateHolder { void restoreStateExtra() {} }", 0);
}

#[test]
fn migrated_java_static_thread_not_sec_object() {
    let rule = "LEGACY-JAVA-AST-static-thread-not-sec-object";
    check(rule, "class A { static Calendar calendar; private static javax.xml.xpath.XPath xpath; static SchemaFactory factory; }", 3);
    check(rule, "class A { Calendar calendar; static SafeCalendar safe; static XPathFactory factory; }", 0);
    check(rule, "class A { void f() { Calendar local=null; } String s=\"static Calendar\"; }", 0);
}

#[test]
fn migrated_java_inner_class_implement_serializable() {
    for rule in ["LEGACY-JAVA-AST-inner-class-implement-serializable",
        "LEGACY-JAVA-AST-inner-class-implement-serializable-ydt"]
    {
        check(rule, "class Outer { class Inner implements Serializable {} }", 1);
        check(rule, "class Outer { void f() { class Local implements java.io.Serializable {} } }", 1);
        check(rule, "class Outer { static class Inner implements Serializable {} }", 0);
        check(rule, "class Top implements Serializable {}", 0);
        check(rule, "class Outer { class Inner implements NotSerializable {} }", 0);
        check(rule, "interface Outer { class Inner implements Serializable {} }", 0); // Source requires class ancestor.
    }
}

#[test]
fn migrated_java_rewrite_clone_method() {
    let rule = "LEGACY-JAVA-AST-rewrite-clone-method";
    check(rule, "class A { Object clone() { return new A(); } }", 1);
    check(rule, "class A { Object clone(int n) { return this; } Object clone() { return super.clone(); } }", 1);
    check(rule, "class A { Object clone() { return super.clone(); } }", 0);
    check(rule, "class A { Object clone() { String fake=\"super.clone()\"; return this; } }", 1);
    check(rule, "class A { Object clone() { /* super.clone() */ return this; } }", 1);
    check(rule, "class A { Object cloning() { return this; } }", 0);
}

#[test]
fn migrated_java_next_throw_no_such_element_exception() {
    let rule = "LEGACY-JAVA-AST-next-throw-nosuchelementexception";
    check(rule, "class A { @Override public Object next() { return value; } }", 1);
    check(rule, "class A { @pkg.Override() Object next() { return value; } }", 1);
    check(rule, "class A { @Override Object next() { throw new NoSuchElementException(); } }", 0);
    check(rule, "class A { @Override Object next() { return helper(NoSuchElementException.class); } }", 0);
    check(rule, "class A { Object next() { return value; } @Override Object nextValue() { return value; } }", 0);
    check(rule, "abstract class A { @Override abstract Object next(); }", 0);
    check(rule, "class A { @Override Object next() { String fake=\"NoSuchElementException\"; return value; } }", 1);
}

#[test]
fn migrated_java_anonymous_inner_class_call_method() {
    let rule = "LEGACY-JAVA-AST-anonymous-inner-class-call-method";
    check(rule, "class A { Object x = new Base() { { initialize(); } }; }", 1);
    check(rule, "class A { void f() { Object x = new Base() { { this.initialize(); nested(call()); } }; } }", 1);
    check(rule, "class A { Object x = new Base() { int value=1; void run() { initialize(); } }; }", 0);
    check(rule, "class A { Object x = new Base(arg) { { initialize(); } }; }", 0); // Source pattern requires new $A().
    check(rule, "class A { static { initialize(); } }", 0);
    check(rule, "class A { String s=\"new Base() {{ initialize(); }}\"; }", 0);
}

#[test]
fn migrated_java_class_initializer_use_thread() {
    let rule = "LEGACY-JAVA-AST-class-initializer-use-thread";
    check(rule, "class A { static { Thread thread = new Thread(); } }", 1);
    check(rule, "class A { static { if (ready) { Object thread = new Thread(task); } } }", 1);
    check(rule, "class A { { Thread thread = new Thread(); } void f() { new Thread(); } }", 0);
    check(rule, "class A { static { Object thread = new pkg.Thread(); String fake=\"new Thread()\"; } }", 0);
}
