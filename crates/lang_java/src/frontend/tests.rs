#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn parses_java_package_receiver_and_fields() {
        let src = r#"
            package demo.app;
            import java.sql.Statement;

            public class UserService {
                private Statement stmt;

                public void run(String q) {
                    execute(q);
                }

                void execute(String q) {
                    stmt.executeQuery(q);
                }
            }
        "#;

        let program = JavaParser::default().parse_file("UserService.java", src).unwrap();
        let class = match &program.modules[0].items[0] {
            Item::Class(class) => class,
            _ => panic!("expected class"),
        };
        assert_eq!(class.name, "demo.app.UserService");
        assert_eq!(class.fields.len(), 1);
        assert!(class.methods.iter().all(|m| m.receiver.is_some()));
        assert!(class
            .methods
            .iter()
            .any(|m| m.name == "demo.app.UserService.run"));
    }

    #[test]
    fn resolves_project_imports_and_wildcards() {
        let entries = vec![
            (
                "src/demo/app/UserService.java".to_string(),
                r#"
                    package demo.app;
                    public class UserService {
                        public String read() {
                            return "x";
                        }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import demo.app.*;
                    public class Controller {
                        public void handle() {
                            UserService svc = new UserService();
                            svc.read();
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.UserService"));
        assert!(rendered.contains("demo.web.Controller.handle"));
    }

    #[test]
    fn qualifies_same_package_new_type() {
        let src = r#"
            package demo.app;
            public class Controller {
                public void handle() {
                    UserService svc = new UserService();
                    svc.run("x");
                }
            }
        "#;

        let program = JavaParser::default().parse_file("Controller.java", src).unwrap();
        let class = match &program.modules[0].items[0] {
            Item::Class(class) => class,
            _ => panic!("expected class"),
        };
        let method = class
            .methods
            .iter()
            .find(|m| m.name.ends_with(".handle"))
            .expect("handle");
        let body_text = format!("{:?}", method.body);
        assert!(body_text.contains("demo.app.UserService"));
    }

    #[test]
    fn infers_var_type_from_project_method_return() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public class Repo {
                        public void query(String sql) {}
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/app/UserService.java".to_string(),
                r#"
                    package demo.app;
                    public class UserService {
                        public Repo repo() {
                            return new Repo();
                        }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import demo.app.*;
                    public class Controller {
                        public void handle(UserService svc, String sql) {
                            var repo = svc.repo();
                            repo.query(sql);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.UserService.repo"));
        assert!(rendered.contains("demo.app.Repo.query"));
    }

    #[test]
    fn resolves_static_imported_method_calls() {
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

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.util.SqlUtil.escape"));
    }

    #[test]
    fn detects_interface_declarations_in_project_index() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public interface Repo {}
                "#
                .to_string(),
            ),
            (
                "src/demo/app/JdbcRepo.java".to_string(),
                r#"
                    package demo.app;
                    public class JdbcRepo implements Repo {
                        public void query(String sql) {}
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.Repo"));
        assert!(rendered.contains("demo.app.JdbcRepo"));
    }

    #[test]
    fn infers_field_type_through_method_chain() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public class Repo {
                        public void query(String sql) {}
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/app/UserService.java".to_string(),
                r#"
                    package demo.app;
                    public class UserService {
                        private Repo repo;
                        public Repo current() { return repo; }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/web/Controller.java".to_string(),
                r#"
                    package demo.web;
                    import demo.app.*;
                    public class Controller {
                        public void handle(UserService svc, String sql) {
                            svc.current().query(sql);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.UserService.current"));
        assert!(rendered.contains("demo.app.Repo.query"));
    }

    #[test]
    fn project_index_tracks_overload_return_types_by_arity() {
        let entries = vec![
            (
                "src/demo/app/Repo.java".to_string(),
                r#"
                    package demo.app;
                    public class Repo {
                        public String current() { return "x"; }
                        public int current(int id) { return id; }
                    }
                "#
                .to_string(),
            ),
            (
                "src/demo/app/Controller.java".to_string(),
                r#"
                    package demo.app;
                    public class Controller {
                        public void handle() {
                            var repo = new Repo();
                            var sql = repo.current();
                            repo.current(1);
                        }
                    }
                "#
                .to_string(),
            ),
        ];

        let program = parse_project_sources(&entries).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("demo.app.Repo.current"));
    }

    #[test]
    fn parses_boolean_call_arguments() {
        let src = r#"
            package demo;
            public class Security {
                public void configure() {
                    setSecure(false);
                    setEnabled(true);
                }
                void setSecure(boolean value) {}
                void setEnabled(boolean value) {}
            }
        "#;
        let program = JavaParser::default().parse_file("Security.java", src).unwrap();
        let rendered = format!("{:?}", program.modules);
        assert!(rendered.contains("Bool(false)"));
        assert!(rendered.contains("Bool(true)"));
    }

}
