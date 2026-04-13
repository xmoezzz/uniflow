use uniflow_hir::Item;
use uniflow_lang_java::{parse_project_sources, JavaParser};
use uniflow_parser_core::SourceParser;

#[test]
fn static_import_resolves_to_fully_qualified_target() {
    let entries = vec![
        (
            "src/demo/util/SqlUtil.java".to_string(),
            r#"
                package demo.util;
                public class SqlUtil {
                    public static String escape(String sql) { return sql; }
                }
            "#
            .to_string(),
        ),
        (
            "src/demo/web/Controller.java".to_string(),
            r#"
                package demo.web;
                import static demo.util.SqlUtil.escape;
                public class Controller {
                    public String handle(String input) {
                        return escape(input);
                    }
                }
            "#
            .to_string(),
        ),
    ];

    let program = parse_project_sources(&entries).expect("project parse");
    let rendered = format!("{:?}", program.modules);
    assert!(rendered.contains("demo.util.SqlUtil.escape"));
}

#[test]
fn interface_and_record_declarations_are_indexed() {
    let entries = vec![
        (
            "src/demo/model/Repo.java".to_string(),
            r#"
                package demo.model;
                public interface Repo {}
            "#
            .to_string(),
        ),
        (
            "src/demo/model/UserRecord.java".to_string(),
            r#"
                package demo.model;
                public record UserRecord(String name) {}
            "#
            .to_string(),
        ),
        (
            "src/demo/model/JdbcRepo.java".to_string(),
            r#"
                package demo.model;
                public class JdbcRepo implements Repo {
                    public UserRecord current() { return new UserRecord("x"); }
                }
            "#
            .to_string(),
        ),
    ];

    let program = parse_project_sources(&entries).expect("project parse");
    let rendered = format!("{:?}", program.modules);
    assert!(rendered.contains("demo.model.Repo"));
    assert!(rendered.contains("demo.model.UserRecord"));
    assert!(rendered.contains("demo.model.JdbcRepo.current"));
}

#[test]
fn parser_keeps_record_name_qualified() {
    let src = r#"
        package demo.model;
        public record UserRecord(String name) {}
    "#;

    let program = JavaParser::default().parse_file("UserRecord.java", src).expect("parse file");
    let class = match &program.modules[0].items[0] {
        Item::Class(class) => class,
        _ => panic!("expected class-like item"),
    };
    assert_eq!(class.name, "demo.model.UserRecord");
}


#[test]
fn wildcard_import_conflict_does_not_pick_arbitrarily() {
    let entries = vec![
        (
            "src/demo/a/UserRepo.java".to_string(),
            "package demo.a; public class UserRepo {}".to_string(),
        ),
        (
            "src/demo/b/UserRepo.java".to_string(),
            "package demo.b; public class UserRepo {}".to_string(),
        ),
        (
            "src/demo/web/Controller.java".to_string(),
            r#"
                package demo.web;
                import demo.a.*;
                import demo.b.*;
                public class Controller {
                    UserRepo repo;
                }
            "#
            .to_string(),
        ),
    ];

    let program = parse_project_sources(&entries).expect("project parse");
    let rendered = format!("{:?}", program.modules);
    assert!(!rendered.contains("demo.a.UserRepo"));
    assert!(!rendered.contains("demo.b.UserRepo"));
}


#[test]
fn same_name_overloads_keep_project_parse_stable() {
    let entries = vec![
        (
            "src/demo/app/Repo.java".to_string(),
            r#"
                package demo.app;
                public class Repo {
                    public String current(String key) { return key; }
                    public int current(int key) { return key; }
                }
            "#
            .to_string(),
        ),
        (
            "src/demo/app/Service.java".to_string(),
            r#"
                package demo.app;
                public class Service {
                    public String run(Repo repo, String key) {
                        var value = repo.current(key);
                        return value;
                    }
                }
            "#
            .to_string(),
        ),
    ];

    let program = parse_project_sources(&entries).expect("project parse");
    let rendered = format!("{:?}", program.modules);
    assert!(rendered.contains("demo.app.Repo.current"));
    assert!(rendered.contains("demo.app.Service.run"));
}
