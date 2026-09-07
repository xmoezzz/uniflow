use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let text = pack.scan_text(&Language::Java, Path::new("MemberCalls.java"), source);
    assert_eq!(text.len(), expected, "{rule}: {source}\n{text:#?}");
    let hir = JavaParser::default().parse_file("MemberCalls.java", source).unwrap();
    let integrated = pack.scan_hir(&hir, &HashMap::from([("MemberCalls.java".into(), source.into())]));
    assert_eq!(integrated.len(), expected, "HIR {rule}: {source}\n{integrated:#?}");
    assert_eq!(text.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>(),
        integrated.iter().map(|finding| (finding.line, finding.column)).collect::<Vec<_>>());
}

#[test]
fn migrated_java_member_call_rules() {
    let clone_override = "LEGACY-JAVA-AST-clone-call-override-method";
    check(clone_override, "class A { Object clone(){ hook(); this.other(); return this; } void hook(){} final void other(){} }", 1);
    check(clone_override, "class A { Object clone(){ target.hook(); super.safe(); return this; } void hook(){} void safe(){} }", 0);
    check(clone_override, "class A { String clone(){ hook(); return \"x\"; } void hook(){} }", 0);

    let ctor_override = "LEGACY-JAVA-AST-ctor-call-override-method";
    check(ctor_override, "class A { A(){ hook(); this.safe(); target.hook(); } void hook(){} final void safe(){} }", 1);
    check(ctor_override, "class A { A(){ safe(); } final void safe(){} }", 0);
    check(ctor_override, "class A { void create(){ hook(); } void hook(){} }", 0);

    let security = "LEGACY-JAVA-AST-call-securitymanager-check-method";
    check(security, "class A { public void verify(SecurityManager sm){ sm.checkPermission(null); } }", 1);
    check(security, "class A { protected void verify(){ SecurityManager sm=get(); sm.checkRead(\"x\"); } }", 1);
    check(security, "class A { public final void a(SecurityManager sm){sm.checkRead(\"x\");} private void b(SecurityManager sm){sm.checkRead(\"x\");} void c(SecurityManager sm){sm.checkRead(\"x\");} }", 0);
    check(security, "class A { public void verify(Object sm){ sm.checkPermission(null); } }", 0);

    let clone_security = "LEGACY-JAVA-AST-clone-method-use-sec-method";
    check(clone_security, "class A implements Cloneable { A(SecurityManager sm){ sm.checkPermission(null); } Object clone(){ return new A(null); } }", 1);
    check(clone_security, "class A implements Cloneable { A(SecurityManager sm){ secure(sm); } void secure(SecurityManager sm){ sm.checkPermission(null); } Object clone(){ secure(get()); return this; } }", 0);
    check(clone_security, "class A { A(SecurityManager sm){ sm.checkPermission(null); } Object clone(){ return this; } }", 0);

    let read_object = "LEGACY-JAVA-AST-readobject-call-final-method";
    check(read_object, "class A { void readObject(ObjectInputStream in){ validate(); } void validate(){} }", 1);
    check(read_object, "class A { void readObject(java.io.ObjectInputStream in){ first(); } final void first(){ second(); } void second(){} }", 1);
    check(read_object, "class A { void readObject(ObjectInputStream in){ validate(); } final void validate(){} }", 0);
    check(read_object, "final class A { void readObject(ObjectInputStream in){ validate(); } void validate(){} }", 0);
    check(read_object, "class A { void readObject(String in){ validate(); } void validate(){} }", 0);
}
