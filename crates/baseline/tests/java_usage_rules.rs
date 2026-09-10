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
    let text = pack.scan_text(&Language::Java, Path::new("Usage.java"), source);
    assert_eq!(text.len(), expected, "{rule}: {source}\n{text:#?}");
    let hir = JavaParser::default()
        .parse_file("Usage.java", source)
        .unwrap();
    let integrated = pack.scan_hir(&hir, &HashMap::from([("Usage.java".into(), source.into())]));
    assert_eq!(
        integrated.len(),
        expected,
        "HIR {rule}: {source}\n{integrated:#?}"
    );
    assert_eq!(
        text.iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        integrated
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>()
    );
}

#[test]
fn migrated_java_usage_rules() {
    let field = "LEGACY-JAVA-AST-unused-field";
    check(
        field,
        "class A { private int used; private int dead; int read(){ return used; } }",
        1,
    );
    check(field, "@Generated class A { int dead; } class B { @Generated int ignored; int live; void f(){ live++; } }", 0);
    check(
        field,
        "class A { int value; void f(int value){ consume(value); } }",
        1,
    );

    let method = "LEGACY-JAVA-AST-unused-method";
    check(
        method,
        "class A { private void used(){} private void dead(){} void run(){ used(); } }",
        1,
    );
    check(
        method,
        "class A { @Override private void hook(){} private void recursive(){ recursive(); } }",
        1,
    );
    check(
        method,
        "class A { void api(){} protected void helper(){} }",
        0,
    );

    let variable = "LEGACY-JAVA-AST-unused-variable";
    check(
        variable,
        "class A { int f(int p){ int x=0; x = p; return 1; } }",
        1,
    );
    check(
        variable,
        "class A { int f(int p){ int x=0; x = p; return x; } }",
        0,
    );
    check(variable, "class A { int f(){ int x = 1; return 0; } }", 0);
    check(variable, "class A { int f(){ missing = 1; return 0; } }", 0);

    let inner = "LEGACY-JAVA-AST-inner-class-use-outer-class-field";
    check(
        inner,
        "class Outer { int state; public class View { int read(){ return state; } } }",
        1,
    );
    check(
        inner,
        "class Outer { int state; private class View { int read(){ return state; } } }",
        0,
    );
    check(
        inner,
        "class Outer { int state; public class View { int read(int state){ return state; } } }",
        0,
    );

    let immutable = "LEGACY-JAVA-AST-immutable-field";
    check(
        immutable,
        "@Immutable class A { int count; List values; void f(){ count = 1; values.add(1); } }",
        2,
    );
    check(
        immutable,
        "@Immutable class A { int count; void f(int count){ count = 1; } }",
        0,
    );
    check(
        immutable,
        "@Immutable(reason=\"documented\") class A { int count; void f(){ count = 1; } }",
        0,
    );
    check(
        immutable,
        "class A { int count; void f(){ count = 1; } }",
        0,
    );
}
