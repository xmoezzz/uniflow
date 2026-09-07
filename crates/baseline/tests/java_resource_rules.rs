use std::{collections::HashMap, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK.get_or_init(|| builtin_security_pack().unwrap()).clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let hir = JavaParser::default().parse_file("Resource.java", source).unwrap();
    let findings = pack.scan_hir(&hir, &HashMap::from([("Resource.java".into(), source.into())]));
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

#[test]
fn migrated_java_resource_release_rules() {
    for (rule, ty) in [
        ("LEGACY-JAVA-AST-unreleased-db-resource", "Connection"),
        ("LEGACY-JAVA-AST-unreleased-file", "ZipFile"),
        ("LEGACY-JAVA-AST-unreleased-socket", "Socket"),
        ("LEGACY-JAVA-AST-unreleased-stream", "BufferedReader"),
    ] {
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); use(resource); }} }}"), 1);
        check(rule, &format!("class A {{ void f() {{ {ty} resource=null; }} }}"), 0);
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); resource.close(); }} }}"), 0);
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); try {{ use(resource); }} finally {{ resource.close(); }} }} }}"), 0);
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); try {{ resource.close(); }} catch(Exception e) {{ recover(); }} }} }}"), 1);
        check(rule, &format!("class A {{ void f({ty} resource) {{ resource=open(); }} }}"), 1);
        check(rule, &format!("class A {{ void f() {{ Object resource=new Object(); }} }}"), 0);
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); Runnable r=() -> resource.close(); }} }}"), 1);
    }
    check("LEGACY-JAVA-AST-unreleased-db-resource",
        "class A { void f() { ResultSet result=open(); PreparedStatement statement=prepare(); result.close(); } }", 1);
    check("LEGACY-JAVA-AST-unreleased-stream",
        "class A { void f() { InputStreamReader input=open(); try { work(); } catch(Exception e) { input.close(); } } }", 1);
}
