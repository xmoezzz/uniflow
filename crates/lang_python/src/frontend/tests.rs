#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_hir::{CallTarget, Program, TypeId};
    use uniflow_parser_core::SourceParser;

    fn type_name(program: &Program, ty: TypeId) -> Option<&str> {
        program
            .types
            .iter()
            .find(|item| item.id == ty)
            .map(|item| item.name.as_str())
    }

    fn module_function<'a>(
        module: &'a uniflow_hir::Module,
        short_name: &str,
    ) -> Option<&'a uniflow_hir::Function> {
        module.items.iter().find_map(|item| match item {
            Item::Function(function)
                if function.name == short_name
                    || function.name.ends_with(&format!(".{short_name}")) =>
            {
                Some(function)
            }
            _ => None,
        })
    }

    #[test]
    fn unknown_factory_result_is_not_an_alias_of_the_factory() {
        let program = parse_project_sources(&[
            ("repo.py".into(), "def pick_cb(handlers):\n    return handlers[0]\n".into()),
            ("app.py".into(), "from repo import pick_cb\n\ndef handle(handlers, value):\n    cb = pick_cb(handlers)\n    return cb(value)\n".into()),
        ]).unwrap();
        let function = program.modules.iter().find_map(|module| module_function(module, "handle")).unwrap();
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = function.body.stmts.last().unwrap() else { panic!("{function:#?}") };
        assert!(matches!(call.target, CallTarget::Dynamic(_)), "{call:#?}");
        let CallTarget::Dynamic(callee) = &call.target else { unreachable!() };
        let Expr::VarRef { symbol, span, .. } = callee.as_ref() else { panic!("{callee:#?}") };
        assert_eq!(program.symbols.iter().find(|s| s.id == *symbol).unwrap().name, "cb");
        assert_eq!(span.file, function.span.file, "callee must belong to its caller file");
    }

    #[test]
    fn parses_python_class_methods_and_fields() {
        let src = r#"
from flask import request

class Controller:
    def __init__(self):
        self.name = "x"

    def handle(self):
        return request.args.get("q")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let class = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) => Some(class), _ => None })
            .expect("class present");
        assert_eq!(class.name, "Controller");
        assert!(class.fields.iter().any(|field| field.name == "name"));
        assert!(class.methods.iter().any(|method| method.name.ends_with("handle")));
    }

    #[test]
    fn propagates_self_field_types_across_methods() {
        let src = r#"
class Repo:
    def run(self, value):
        return value

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self, value):
        return self.repo.run(value)
"#;
        let program = PythonParser.parse_file("service.py", src).expect("parse ok");
        let module = &program.modules[0];
        let class = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) if class.name == "Controller" => Some(class), _ => None })
            .expect("class present");
        assert!(class.fields.iter().any(|field| field.name == "repo"));
        assert!(class.methods.iter().any(|method| method.name.ends_with("handle")));
    }

    #[test]
    fn parses_project_sources_with_cross_file_imports() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "from db import DB\n\nclass Repo:\n    def __init__(self):\n        self.db = DB()\n".to_string(),
            ),
            (
                "db.py".to_string(),
                "class DB:\n    def execute(self, sql):\n        return sql\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\nfrom flask import *\n\nclass Controller:\n    def __init__(self):\n        self.repo = Repo()\n\n    def handle(self):\n        return self.repo.db.execute(request.args.get(\"q\"))\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("project parse ok");
        assert!(program.modules.iter().any(|module| module.name == "repo"));
        assert!(program.modules.iter().any(|module| module.name == "app"));
    }

    #[test]
    fn resolves_wildcard_imports_and_nested_self_fields() {
        let src = r#"
from flask import *

class Repo:
    def __init__(self):
        self.conn = request.args

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self):
        return self.repo.conn.get("q")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Repo")));
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Controller")));
    }

    #[test]
    fn propagates_cross_file_nested_field_types() {
        let entries = vec![
            (
                "db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "repo.py".to_string(),
                "from db import DB

class Repo:
    def __init__(self):
        self.db = DB()
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class Controller:
    def __init__(self):
        self.repo = Repo()

    def handle(self, sql):
        return self.repo.db.execute(sql)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("project parse ok");
        assert!(program.modules.iter().any(|module| module.name == "app"));
    }

    #[test]
    fn infers_cross_file_method_return_types() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "from db import DB

class Repo:
    def current(self):
        return DB()
".to_string(),
            ),
            (
                "db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class App:
    def __init__(self):
        self.repo = Repo()

    def run(self, sql):
        return self.repo.current().execute(sql)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("project parse ok");
        assert!(program.modules.iter().any(|module| module.name == "app"));
    }

    #[test]
    fn parses_python_package_project_with_top_level_return() {
        let entries = vec![
            (
                "examples/python_pkg/service/__init__.py".to_string(),
                "from service.repo import make_repo
".to_string(),
            ),
            (
                "examples/python_pkg/service/repo.py".to_string(),
                "from service.db import DB

class Repo:
    def __init__(self):
        self.db = DB()

def make_repo():
    return Repo()
".to_string(),
            ),
            (
                "examples/python_pkg/service/db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "examples/python_pkg/app.py".to_string(),
                r#"from service.repo import make_repo
from flask import request

class Controller:
    def handle(self):
        repo = make_repo()
        return repo.db.execute(request.args.get("q"))
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse ok");
        assert!(!program.modules.is_empty());
    }

    #[test]
    fn resolves_package_reexports_from_init() {
        let entries = vec![
            (
                "examples/python_pkg_reexport/pkg/__init__.py".to_string(),
                "from .repo import Repo, make_repo
".to_string(),
            ),
            (
                "examples/python_pkg_reexport/pkg/repo.py".to_string(),
                "from .db import DB

class Repo:
    def __init__(self):
        self.db = DB()

def make_repo():
    return Repo()
".to_string(),
            ),
            (
                "examples/python_pkg_reexport/pkg/db.py".to_string(),
                "class DB:
    def execute(self, sql):
        return sql
".to_string(),
            ),
            (
                "examples/python_pkg_reexport/app.py".to_string(),
                "from pkg import make_repo

class App:
    def run(self, sql):
        return make_repo().db.execute(sql)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse ok");
        assert!(program.modules.iter().any(|module| module.name == "pkg"));
    }

    #[test]
    fn resolves_package_reexported_function_returns() {
        let entries = vec![
            (
                "examples/python_pkg_reexport_return/app.py".to_string(),
                "from pkg import make_repo\nvalue = make_repo()\n".to_string(),
            ),
            (
                "examples/python_pkg_reexport_return/pkg/__init__.py".to_string(),
                "from .repo import make_repo\n".to_string(),
            ),
            (
                "examples/python_pkg_reexport_return/pkg/repo.py".to_string(),
                "from .db import DB\n\ndef make_repo():\n    return DB()\n".to_string(),
            ),
            (
                "examples/python_pkg_reexport_return/pkg/db.py".to_string(),
                "class DB:\n    pass\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("pkg.make_repo", 0).as_deref(), Some("pkg.db.DB"));
    }

    #[test]
    fn resolves_package_submodule_member_from_parent_import() {
        let entries = vec![
            (
                "examples/python_pkg_submodule/app.py".to_string(),
                "from pkg import repo\n\nclass App:\n    def handle(self, request):\n        db = repo.make_db()\n        db.execute(request.args.get(\"q\"))\n".to_string(),
            ),
            (
                "examples/python_pkg_submodule/pkg/repo.py".to_string(),
                "from .db import DB\n\ndef make_db():\n    return DB()\n".to_string(),
            ),
            (
                "examples/python_pkg_submodule/pkg/db.py".to_string(),
                "class DB:\n    def execute(self, sql):\n        return sql\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("pkg.repo.make_db") || rendered.contains("pkg.repo"));
    }

    #[test]
    fn resolves_wildcard_package_submodule_member() {
        let entries = vec![
            (
                "examples/python_pkg_wildcard_submodule/app.py".to_string(),
                "from pkg import *
value = repo.make_db()
".to_string(),
            ),
            (
                "examples/python_pkg_wildcard_submodule/pkg/repo.py".to_string(),
                "from .db import DB

def make_db():
    return DB()
".to_string(),
            ),
            (
                "examples/python_pkg_wildcard_submodule/pkg/db.py".to_string(),
                r#"class DB:
    pass
"#.to_string(),
            ),
            (
                "examples/python_pkg_wildcard_submodule/pkg/__init__.py".to_string(),
                "from . import repo
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("from pkg import *
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index.clone(),
            ..Default::default()
        };
        assert_eq!(resolve_imported_name("repo", &imports, &env).as_deref(), Some("pkg.repo"));
    }

    #[test]
    fn canonicalizes_imported_module_alias_targets() {
        let entries = vec![
            (
                "examples/python_pkg_alias/pkg/__init__.py".to_string(),
                "from . import repo
".to_string(),
            ),
            (
                "examples/python_pkg_alias/pkg/repo.py".to_string(),
                "def make_db():
    return 1
".to_string(),
            ),
            (
                "examples/python_pkg_alias/app.py".to_string(),
                "import pkg.repo as repo_mod
value = repo_mod.make_db()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("import pkg.repo as repo_mod
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_imported_name("repo_mod", &imports, &env).as_deref(), Some("pkg.repo"));
    }

    #[test]
    fn import_pkg_repo_binds_pkg_root_name() {
        let imports = parse_imports_shallow_for_module("import pkg.repo\n", "app");
        assert_eq!(imports.aliases.get("pkg"), Some(&"pkg.repo".to_string()));
        assert!(!imports.aliases.contains_key("repo"));
    }

    #[test]
    fn canonicalizes_root_package_alias_prefix_chains() {
        let entries = vec![
            (
                "examples/python_pkg_root_alias/pkg/repo.py".to_string(),
                "def make_db():
    return 1
".to_string(),
            ),
            (
                "examples/python_pkg_root_alias/app.py".to_string(),
                "import pkg as root_pkg
value = root_pkg.repo.make_db()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("import pkg as root_pkg
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_prefixed_imported_name("root_pkg.repo", &imports, &env).as_deref(), Some("pkg.repo"));
    }

    #[test]
    fn resolves_unique_top_level_function_across_modules() {
        let entries = vec![
            (
                "examples/python_unique_func/pkg/repo.py".to_string(),
                "def make_db():
    return 1
".to_string(),
            ),
            (
                "examples/python_unique_func/app.py".to_string(),
                "value = make_db()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.resolve_simple_function("make_db").as_deref(), Some("pkg.repo.make_db"));
    }

    #[test]
    fn infers_module_level_value_types_and_cross_module_object_flow() {
        let entries = vec![
            (
                "examples/python_module_values/service.py".to_string(),
                r#"from db import DB

db = DB()

def get_db():
    return db
"#
                .to_string(),
            ),
            (
                "examples/python_module_values/db.py".to_string(),
                r#"class DB:
    def execute(self, sql):
        return sql
"#
                .to_string(),
            ),
            (
                "examples/python_module_values/app.py".to_string(),
                r#"from service import get_db

class App:
    def handle(self, request):
        get_db().execute(request.args.get("q"))
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type("service", "db").as_deref(), Some("db.DB"));
        assert_eq!(index.top_level_return("service.get_db", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn inherited_fields_and_method_returns_resolve_through_base_classes() {
        let entries = vec![
            (
                "examples/python_inheritance_chain/base.py".to_string(),
                r#"from db import DB

class BaseRepo:
    def __init__(self):
        self.db = DB()

    def current(self):
        return self.db
"#
                .to_string(),
            ),
            (
                "examples/python_inheritance_chain/repo.py".to_string(),
                r#"from base import BaseRepo

class Repo(BaseRepo):
    pass
"#
                .to_string(),
            ),
            (
                "examples/python_inheritance_chain/db.py".to_string(),
                r#"class DB:
    def execute(self, sql):
        return sql
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("repo.Repo", "db").as_deref(), Some("db.DB"));
        assert_eq!(index.method_return("repo.Repo", "current", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn resolves_module_value_members_through_import_aliases() {
        let entries = vec![
            (
                "examples/python_module_alias_values/service.py".to_string(),
                r#"from db import DB

db = DB()
"#
                .to_string(),
            ),
            (
                "examples/python_module_alias_values/db.py".to_string(),
                r#"class DB:
    pass
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        let imports = parse_imports_shallow_for_module("import service as svc
", "app");
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_dotted_type("svc.db", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
    }

    #[test]
    fn parses_all_exports_and_module_aliases() {
        let entries = vec![
            (
                "examples/python_pkg_all/pkg/__init__.py".to_string(),
                r#"from .repo import make_repo
__all__ = ["make_repo"]
"#
                .to_string(),
            ),
            (
                "examples/python_pkg_all/pkg/repo.py".to_string(),
                r#"class Repo:
    pass

def make_repo():
    return Repo()
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.resolve_module_member("pkg", "make_repo").as_deref(), Some("pkg.repo.make_repo"));
        assert_eq!(index.top_level_return("pkg.make_repo", 0).as_deref(), Some("pkg.repo.Repo"));
    }

    #[test]
    fn resolves_module_symbol_aliases_and_index_types() {
        let entries = vec![
            (
                "examples/python_alias_mod/db.py".to_string(),
                r#"class DB:
    pass

conn = DB()
"#
                .to_string(),
            ),
            (
                "examples/python_alias_mod/service.py".to_string(),
                r#"from db import conn
get_conn = conn
items = [conn]
vals = {"x": conn}
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_symbol_alias("service", "get_conn").as_deref(), Some("db.conn"));
        let imports = parse_imports_shallow_for_module(
            r#"from service import get_conn
from service import items
from service import vals
"#,
            "app",
        );
        let env = PyEnv {
            current_module: "app".to_string(),
            project_index: index,
            ..Default::default()
        };
        assert_eq!(resolve_dotted_type("get_conn", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("items[0]", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("vals['x']", &imports, &env, &HashSet::new()).as_deref(), Some("db.DB"));
    }

    #[test]
    fn infers_tuple_destructuring_and_tuple_indices() {
        let imports = PyImports::default();
        let mut env = PyEnv::default();
        env.current_module = "app".to_string();
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("(1, 'x')", &imports, &env, &known).as_deref(), Some("tuple<int|str>"));
        env.types.insert("pair".to_string(), "tuple<db.DB|repo.Repo>".to_string());
        assert_eq!(infer_simple_python_type("pair[0]", &imports, &env, &known).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("pair[1]", &imports, &env, &known).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn infers_module_value_types_from_destructuring() {
        let entries = vec![
            (
                "examples/python_module_destructure/db.py".to_string(),
                r#"class DB:
    pass

class Repo:
    pass

conn, repo = (DB(), Repo())
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type("db", "conn").as_deref(), Some("db.DB"));
        assert_eq!(index.module_value_type("db", "repo").as_deref(), Some("db.Repo"));
    }

    #[test]
    fn local_destructuring_keeps_index_value_types() {
        let program = parse_python_file(
            "examples/python_destructure_locals/app.py",
            r#"from db import DB

def run():
    conn, alias = (DB(), DB())
    items = [conn]
    return items[0]
"#,
            None,
        )
        .expect("parse");
        assert!(!program.modules[0].items.is_empty());
    }

    #[test]
    fn parses_general_destructuring_via_index_reads() {
        let src = r#"
def load_pair():
    return source()

def handle():
    left, right = load_pair()
    return right
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        assert!(matches!(function.body.stmts.first(), Some(Stmt::Let { .. })));
        assert!(function.body.stmts.iter().filter(|stmt| matches!(stmt, Stmt::Let { .. } | Stmt::Assign { .. })).count() >= 3);
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt,
            Stmt::Let { init: Some(Expr::IndexRead { .. }), .. } | Stmt::Assign { rhs: Expr::IndexRead { .. }, .. }
        )));
    }

    #[test]
    fn parses_for_each_destructuring_items_into_body_bindings() {
        let src = r#"
def handle(payload):
    for key, value in payload.items():
        result = value
    return result
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        let loop_stmt = function.body.stmts.iter().find_map(|stmt| match stmt {
            Stmt::ForEach { body, .. } => Some(body),
            _ => None,
        }).expect("for loop present");
        assert!(loop_stmt.stmts.iter().take(2).all(|stmt| matches!(stmt, Stmt::Let { .. } | Stmt::Assign { .. })));
    }

    #[test]
    fn infers_python_comprehension_types() {
        let imports = parse_imports_shallow_for_module("", "app");
        let mut env = PyEnv::default();
        env.current_module = "app".to_string();
        env.types.insert("items".to_string(), "list<db.DB>".to_string());
        env.types.insert("payload".to_string(), "dict<str,repo.Repo>".to_string());
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("[item for item in items]", &imports, &env, &known).as_deref(), Some("list<db.DB>"));
        assert_eq!(infer_simple_python_type("{key: value for key, value in payload.items()}", &imports, &env, &known).as_deref(), Some("dict<str,repo.Repo>"));
    }

    #[test]
    fn parses_python_control_flow_statements() {
        let src = r#"
from flask import request

def handle(items):
    cmd = request.args.get("cmd")
    if cmd:
        value = cmd
    else:
        value = "safe"
    while cmd:
        cmd = value
    for item in items:
        value = item
    try:
        result = value
    except ValueError as err:
        result = err
    finally:
        value = result
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::If { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::While { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::ForEach { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Try { .. })));
    }

    #[test]
    fn parses_python_with_statement_as_flow_setup() {
        let src = r#"
def handle(path):
    with open(path) as handle:
        return handle.read()
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("function present");
        assert!(matches!(function.body.stmts.first(), Some(Stmt::Let { .. })));
        assert!(function.body.stmts.iter().any(|stmt| matches!(stmt, Stmt::Return { .. })));
    }

    #[test]
    fn parses_async_functions_and_await_calls() {
        let src = r#"
import subprocess

async def run(cmd):
    return await subprocess.run(args=cmd, shell=True)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("function present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected return call");
        };
        assert!(matches!(call.args.first(), Some(Expr::VarRef { symbol, .. }) if *symbol == function.params[0].symbol));
        assert!(matches!(call.args.get(1), Some(Expr::Literal { kind: uniflow_hir::LiteralKind::Bool(true), .. })));
    }

    #[test]
    fn infers_async_and_keyword_argument_types() {
        let imports = parse_imports_shallow_for_module("import json\n", "app");
        let mut env = PyEnv::default();
        env.current_module = "app".to_string();
        env.types.insert("items".to_string(), "list<db.DB>".to_string());
        env.types.insert("payload".to_string(), "dict<str,repo.Repo>".to_string());
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("await items.pop()", &imports, &env, &known).as_deref(), Some("db.DB"));
        assert_eq!(infer_simple_python_type("payload.get(key='x')", &imports, &env, &known).as_deref(), Some("repo.Repo"));
        assert_eq!(infer_simple_python_type("json.dumps(obj=payload)", &imports, &env, &known).as_deref(), Some("str"));
    }

    #[test]
    fn parses_python_parameter_shapes_for_binding() {
        let specs = parse_python_param_specs("self, x, y=1, *args, z, flag=False, **kwargs");
        assert_eq!(specs.len(), 7);
        assert_eq!(specs[0].name, "self");
        assert_eq!(specs[1].name, "x");
        assert_eq!(specs[2].name, "y");
        assert!(specs[2].has_default);
        assert_eq!(specs[3].kind, PyParamKind::VarArgs);
        assert!(specs[4].keyword_only);
        assert!(specs[5].has_default);
        assert_eq!(specs[6].kind, PyParamKind::KwArgs);
    }

    #[test]
    fn call_parser_keeps_keyword_argument_names() {
        let src = r#"
def run(cmd, payload=None):
    return target(y=payload, x=cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "run" => Some(function),
                _ => None,
            })
            .expect("function present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected return call");
        };
        assert_eq!(call.arg_names, vec![Some("y".to_string()), Some("x".to_string())]);
    }

    #[test]
    fn project_index_registers_default_argument_arities() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class DB:
    pass

def load(x, y=1):
    return DB()
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("repo.load", 1).as_deref(), Some("repo.DB"));
        assert_eq!(index.top_level_return("repo.load", 2).as_deref(), Some("repo.DB"));
    }

    #[test]
    fn resolves_local_callable_aliases_to_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    runner = load
    return runner(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { .. } = &function.body.stmts[0] else {
            panic!("expected alias binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[1] else {
            panic!("expected return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn clears_local_callable_alias_after_non_callable_reassignment() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    runner = load
    runner = cmd
    return runner(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[2] else {
            panic!("expected return call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn parses_local_callback_parameters_as_dynamic_calls() {
        let src = r#"
def wrap(cb, cmd):
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "wrap" => Some(function),
                _ => None,
            })
            .expect("wrap function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected callback call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn resolves_bound_method_aliases_to_project_methods() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Service:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service

def handle(cmd):
    svc = Service()
    runner = svc.run
    return runner(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[2] else {
            panic!("expected bound method call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.Service.run"));
    }

    #[test]
    fn parses_indexed_callable_invocations_as_dynamic_calls() {
        let src = r#"
def handle(handler_list, cmd):
    return handler_list[0](cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[0] else {
            panic!("expected indexed callback call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn async_project_returns_are_indexed() {
        let entries = vec![
            (
                "db.py".to_string(),
                "class DB:\n    pass\n".to_string(),
            ),
            (
                "repo.py".to_string(),
                "from db import DB\n\nasync def current():\n    return DB()\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("repo.current", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn resolves_callable_field_values_to_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

class Service:
    def handle(self, cmd):
        self.cb = load
        return self.cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) => class.methods.iter().find(|method| method.name == "app.Service.handle" || method.name == "handle"),
                _ => None,
            })
            .expect("handle method");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[1] else {
            panic!("expected callable field return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_indexed_callable_values_to_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    handlers = [load]
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[1] else {
            panic!("expected indexed callable return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_local_object_callable_fields_inside_a_function() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, load

def handle(cmd):
    svc = Service()
    svc.cb = load
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[2] else {
            panic!("expected callable object-field return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_callable_fields_across_local_object_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, load

def handle(cmd):
    svc = Service()
    alias = svc
    alias.cb = load
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &function.body.stmts[3] else {
            panic!("expected alias-backed callable field return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn parses_lambda_capture_metadata() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let function = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(func) if func.name == "handle" => Some(func),
                _ => None,
            })
            .expect("handle function");
        let outer_cmd = function.params[0].symbol;
        let Stmt::Let { init: Some(Expr::Lambda { captures, body, .. }), .. } = &function.body.stmts[0] else {
            panic!("expected lambda assignment");
        };
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].name, "cmd");
        assert_eq!(captures[0].source_symbol, outer_cmd);
        let Stmt::Return { value: Some(Expr::VarRef { symbol, .. }), .. } = &body.stmts[0] else {
            panic!("expected rewritten lambda return");
        };
        assert_eq!(*symbol, captures[0].symbol);
    }

    #[test]
    fn parses_lambda_callback_as_hir_lambda() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let function = program
            .modules
            .first()
            .and_then(|module| module.items.iter().find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            }))
            .expect("function");
        let has_lambda = function.body.stmts.iter().any(|stmt| match stmt {
            Stmt::Let { init: Some(Expr::Lambda { .. }), .. } => true,
            _ => false,
        });
        assert!(has_lambda);
    }

    #[test]
    fn resolves_nested_function_callbacks_to_project_internal_targets() {
        let src = r#"
def handle(cmd):
    def inner(x):
        return cmd
    return inner("safe")
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[0] else {
            panic!("expected nested callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.handle.inner"));
        let inner = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle.inner" => Some(function),
                _ => None,
            })
            .expect("nested function");
        assert_eq!(inner.captures.len(), 1);
        assert_eq!(inner.captures[0].name, "cmd");
    }

    #[test]
    fn parses_nested_function_values_returned_from_functions() {
        let src = r#"
def choose(cmd):
    def inner(x):
        return cmd
    return inner
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let choose = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "choose" => Some(function),
                _ => None,
            })
            .expect("choose function");
        let Stmt::Return { value: Some(returned), .. } = &choose.body.stmts[0] else {
            panic!("expected nested function return");
        };
        let Expr::Cast { ty: Some(ty), expr, .. } = returned else {
            panic!("expected typed nested function value");
        };
        assert!(matches!(expr.as_ref(), Expr::VarRef { .. }));
        assert_eq!(type_name(&program, *ty), Some("app.choose.inner"));
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(function) if function.name == "app.choose.inner")));
    }

    #[test]
    fn project_index_recovers_nested_function_values_and_nonlocal_writebacks() {
        let entries = vec![
            (
                "app.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()

def choose(flag):
    cb = load
    def patch():
        nonlocal cb
        cb = alt
    return cb if flag else patch

def outer(cmd):
    cb = load
    def patch():
        nonlocal cb
        cb = alt
    patch()
    return cb(cmd)
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.choose", 1).as_deref(), Some("app.choose.patch"));
        assert_eq!(index.top_level_return("app.outer", 1).as_deref(), Some("app.B"));
    }

    #[test]
    fn project_index_applies_simple_decorator_wrapper_chains() {
        let entries = vec![
            (
                "app.py".to_string(),
                "class Repo:
    pass

def build(cmd):
    return Repo()

def deco(fn):
    def wrapper(cmd):
        return fn(cmd)
    return wrapper

@deco
def handle(cmd):
    return build(cmd)
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.deco", 1).as_deref(), Some("app.deco.wrapper"));
        assert_eq!(index.top_level_return("app.handle", 1).as_deref(), Some("app.Repo"));
        assert_eq!(index.module_value_type_by_path("app.handle").as_deref(), Some("app.deco.wrapper"));
    }

    #[test]
    fn resolves_callable_aliases_through_setdefault_and_get() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    mapping = {}
    mapping.setdefault("cb", load)
    cb = mapping.get("cb")
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Expr { .. } = &handle.body.stmts[1] else {
            panic!("expected setdefault expression statement");
        };
        let Stmt::Let { init: Some(Expr::Call(_)), .. } = &handle.body.stmts[2] else {
            panic!("expected get binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn resolves_callable_aliases_through_append_and_index_reads() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    handlers = []
    handlers.append(load)
    cb = handlers[0]
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Expr { .. } = &handle.body.stmts[1] else {
            panic!("expected append expression statement");
        };
        let Stmt::Let { init: Some(indexed), .. } = &handle.body.stmts[2] else {
            panic!("expected indexed callback binding");
        };
        assert!(match indexed {
            Expr::IndexRead { .. } => true,
            Expr::Cast { expr, .. } => matches!(expr.as_ref(), Expr::IndexRead { .. }),
            _ => false,
        });
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn resolves_callable_aliases_through_precise_list_literal_slots() {
        let src = r#"
def load(cmd):
    return cmd

def noop(cmd):
    return "safe"

def handle(cmd):
    handlers = [noop, load]
    alias = handlers
    cb = alias[1]
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { init: Some(Expr::IndexRead { .. }), .. } = &handle.body.stmts[2] else {
            panic!("expected precise indexed callback binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected precise callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn resolves_callable_aliases_through_precise_dict_index_updates() {
        let src = r#"
def load(cmd):
    return cmd

def noop(cmd):
    return "safe"

def handle(cmd):
    mapping = {"safe": noop}
    alias = mapping
    alias["cb"] = load
    return mapping["cb"](cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Assign { .. } = &handle.body.stmts[2] else {
            panic!("expected indexed dict assignment");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected dict callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn parses_staticmethod_classmethod_and_property_decorators() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, value):
        return value

class Factory:
    @staticmethod
    def make_repo():
        return Repo()

    @classmethod
    def current(cls):
        return cls.make_repo()

    @property
    def repo(self):
        return self.make_repo()
"#
                .to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Factory

class App:
    def handle(self, value):
        factory = Factory()
        return factory.repo.run(value)
"#
                .to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("repo.Factory", "make_repo", 0).as_deref(), Some("repo.Repo"));
        assert_eq!(index.method_return("repo.Factory", "current", 0).as_deref(), Some("repo.Repo"));
        assert_eq!(index.field_type("repo.Factory", "repo").as_deref(), Some("repo.Repo"));
        let program = parse_project_sources(&entries).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("repo.Repo.run"));
    }

    #[test]
    fn infers_callable_object_values_via_dunder_call() {
        let src = r#"
class Loader:
    def __call__(self, cmd):
        return cmd

def handle(cmd):
    loader = Loader()
    return loader(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected callable-object return call");
        };
        assert!(matches!(&call.target, CallTarget::Dynamic(_)));
    }

    #[test]
    fn lowers_setattr_getattr_receiver_calls() {
        let src = r#"
import os

class Repo:
    def run(self, cmd):
        return os.system(cmd)

class Service:
    pass

def handle(cmd):
    svc = Service()
    setattr(svc, "repo", Repo())
    return getattr(svc, "repo").run(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Assign { lhs: LValue::Field { field, .. }, .. } = &handle.body.stmts[1] else {
            panic!("expected setattr lowering to field assignment");
        };
        assert_eq!(field, "repo");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected getattr based receiver call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.Repo.run" || name.ends_with("Repo.run")));
    }

    #[test]
    fn resolves_callable_aliases_through_getattr_fields() {
        let src = r#"
def load(cmd):
    return cmd

class Holder:
    pass

def handle(cmd):
    holder = Holder()
    setattr(holder, "cb", load)
    cb = getattr(holder, "cb")
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Assign { lhs: LValue::Field { field, .. }, .. } = &handle.body.stmts[1] else {
            panic!("expected setattr lowering");
        };
        assert_eq!(field, "cb");
        let Stmt::Let { .. } = &handle.body.stmts[2] else {
            panic!("expected getattr binding");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[3] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "app.load" || name.ends_with(".load") || name == "load"));
    }

    #[test]
    fn maps_direct_builtin_constructor_calls() {
        let src = r#"
def load(cmd):
    return cmd

def handle():
    handlers = list([load])
    mapping = dict(cb=load)
    return handlers[0], mapping["cb"]
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { init: Some(Expr::Call(list_call)), .. } = &handle.body.stmts[0] else {
            panic!("expected list constructor binding");
        };
        assert!(matches!(&list_call.target, CallTarget::Named(name) if name == "builtins.list"));
        let Stmt::Let { init: Some(Expr::Call(dict_call)), .. } = &handle.body.stmts[1] else {
            panic!("expected dict constructor binding");
        };
        assert!(matches!(&dict_call.target, CallTarget::Named(name) if name == "builtins.dict"));
    }

    #[test]
    fn lowers_custom_getitem_to_method_call() {
        let src = r#"
class Box:
    def __init__(self):
        self.cb = run

    def __getitem__(self, key):
        return self.cb

def run(cmd):
    return cmd

def handle(box, cmd):
    cb = box["cb"]
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("handle") => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Let { init: Some(Expr::Call(call)), .. } = &handle.body.stmts[0] else {
            panic!("expected getitem lowering call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named __getitem__ call");
        };
        assert!(name.ends_with("Box.__getitem__"));
    }

    #[test]
    fn lowers_custom_setitem_to_method_call_stmt() {
        let src = r#"
class Box:
    def __setitem__(self, key, value):
        self.cb = value

def run(cmd):
    return cmd

def configure(box):
    box["cb"] = run
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let configure = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("configure") => Some(func), _ => None })
            .expect("configure present");
        let Stmt::Expr { expr: Expr::Call(call), .. } = &configure.body.stmts[0] else {
            panic!("expected __setitem__ expr call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named __setitem__ call");
        };
        assert!(name.ends_with("Box.__setitem__"));
    }

    #[test]
    fn resolves_callable_loop_items_from_custom_iter() {
        let src = r#"
def run(cmd):
    return cmd

class Registry:
    def __init__(self):
        self.handlers = [run]

    def __iter__(self):
        return self.handlers

def handle(registry, cmd):
    for cb in registry:
        return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("handle") => Some(func), _ => None })
            .expect("handle present");
        let Some(Stmt::ForEach { body, .. }) = handle.body.stmts.first() else {
            panic!("expected foreach");
        };
        let Some(Stmt::Return { value: Some(Expr::Call(call)), .. }) = body.stmts.first() else {
            panic!("expected return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected resolved callable loop item");
        };
        assert!(name.ends_with("run"));
    }

    #[test]
    fn resolves_super_property_receiver_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Base:
    @property
    def repo(self):
        return Repo()

class Service(Base):
    def handle(self, cmd):
        return super().repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program
            .modules
            .iter()
            .find(|module| module.name == "repo")
            .expect("repo module");
        let service = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "repo.Service" => Some(class),
                _ => None,
            })
            .expect("service class");
        let handle = service
            .methods
            .iter()
            .find(|method| method.name == "repo.Service.handle")
            .expect("handle method");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[0] else {
            panic!("expected return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named call");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn unwraps_descriptor_field_reads_to_descriptor_get_return() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"def load(cmd):
    return cmd

class LoaderDescriptor:
    def __get__(self, obj, owner):
        return load

class Service:
    handler = LoaderDescriptor()

    def handle(self, cmd):
        cb = self.handler
        return cb(cmd)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "handler").as_deref(), Some("app.LoaderDescriptor"));
        assert_eq!(descriptor_access_type(&index, "app.LoaderDescriptor").as_deref(), Some("app.load"));
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let service = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name == "app.Service" => Some(class),
                _ => None,
            })
            .expect("service class");
        let handle = service.methods.iter().find(|method| method.name == "app.Service.handle").expect("handle method");
        let Stmt::Let { init: Some(expr), .. } = &handle.body.stmts[0] else {
            panic!("expected cb binding");
        };
        let Expr::Cast { ty: Some(ty), expr, .. } = expr else {
            panic!("expected descriptor field read with inferred callable type");
        };
        assert!(matches!(expr.as_ref(), Expr::FieldRead { field, .. } if field == "handler"));
        assert_eq!(type_name(&program, *ty), Some("app.load"));
    }

    #[test]
    fn lowers_direct_delitem_to_magic_method_call() {
        let src = r#"
class Box:
    def __delitem__(self, key):
        pass

def clear(box):
    del box["cb"]
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let clear = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("clear") => Some(func), _ => None })
            .expect("clear present");
        let Stmt::Expr { expr: Expr::Call(call), .. } = &clear.body.stmts[0] else {
            panic!("expected __delitem__ expr call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named __delitem__ call");
        };
        assert!(name.ends_with("Box.__delitem__"));
    }

    #[test]
    fn tracks_property_setter_and_deleter_metadata() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"class Repo:
    pass

class Service:
    @property
    def repo(self):
        return Repo()

    @repo.setter
    def repo(self, value):
        self._repo = value

    @repo.deleter
    def repo(self):
        self._repo = None
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert!(index.class_has_property_setter("app.Service", "repo"));
        assert!(index.class_has_property_deleter("app.Service", "repo"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("app.Repo"));
    }

    #[test]
    fn parses_direct_del_field_statements() {
        let src = r#"
class Service:
    def handle(self):
        del self.repo
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let service = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) if class.name == "Service" => Some(class), _ => None })
            .expect("service class");
        let handle = service.methods.iter().find(|method| method.name == "Service.handle").expect("handle method");
        let Stmt::Expr { .. } = &handle.body.stmts[0] else {
            panic!("expected direct del lowering to expr");
        };
    }

    #[test]
    fn infers_top_level_return_through_local_alias() {
        let entries = vec![
            (
                "db.py".to_string(),
                r#"class DB:
    pass
"#.to_string(),
            ),
            (
                "service.py".to_string(),
                r#"from db import DB

def make_db():
    conn = DB()
    return conn
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("service.make_db", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn infers_method_return_through_local_alias() {
        let entries = vec![
            (
                "db.py".to_string(),
                r#"class DB:
    pass
"#.to_string(),
            ),
            (
                "service.py".to_string(),
                r#"from db import DB

class Repo:
    def __init__(self):
        self.db = DB()

    def current_db(self):
        conn = self.db
        return conn
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("service.Repo", "current_db", 0).as_deref(), Some("db.DB"));
    }

    #[test]
    fn infers_class_field_types_through_setattr_local_alias() {
        let entries = vec![
            (
                "service.py".to_string(),
                r#"class Repo:
    pass

class Service:
    def __init__(self):
        repo = Repo()
        setattr(self, "repo", repo)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("service.Service", "repo").as_deref(), Some("service.Repo"));
    }

    #[test]
    fn infers_class_body_descriptor_field_types() {
        let entries = vec![(
            "app.py".to_string(),
            r#"def load(cmd):
    return cmd

class LoaderDescriptor:
    def __get__(self, obj, owner):
        return load

class Service:
    handler = LoaderDescriptor()
"#.to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "handler").as_deref(), Some("app.LoaderDescriptor"));
    }

    #[test]
    fn infers_module_aliases_through_local_bindings_and_dynamic_imports() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def load(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from importlib import import_module

mod = import_module("repo")
cb = mod.load
exported = cb
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_symbol_alias("app", "mod").as_deref(), Some("repo"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("app", "exported").as_deref(), Some("repo.load"));
    }

    #[test]
    fn resolves_importlib_module_types_and_partial_targets() {
        let src = r#"
import importlib
from functools import partial

def load(cmd):
    return cmd

def handle(cmd):
    mod = importlib.import_module("app")
    cb = partial(mod.load)
    return cb(cmd)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name.ends_with("handle") => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected callback return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected resolved partial callback call");
        };
        assert!(name.ends_with("load"));
    }

    #[test]
    fn lowers_property_setter_and_deleter_writes_to_calls() {
        let entries = vec![(
            "app.py".to_string(),
            r#"class Repo:
    pass

class Service:
    @property
    def repo(self):
        return Repo()

    @repo.setter
    def repo(self, value):
        self._repo = value

    @repo.deleter
    def repo(self):
        self._repo = None

def configure(svc):
    svc.repo = Repo()
    del svc.repo
"#.to_string(),
        )];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let configure = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.configure" => Some(func), _ => None })
            .expect("configure present");
        let Stmt::Expr { expr: Expr::Call(first), .. } = &configure.body.stmts[0] else {
            panic!("expected property setter call");
        };
        let CallTarget::Named(first_name) = &first.target else {
            panic!("expected named property setter call");
        };
        assert!(first_name.ends_with("Service.repo"));
        let Stmt::Expr { expr: Expr::Call(second), .. } = &configure.body.stmts[1] else {
            panic!("expected property deleter call");
        };
        let CallTarget::Named(second_name) = &second.target else {
            panic!("expected named property deleter call");
        };
        assert!(second_name.ends_with("Service.repo"));
    }

    #[test]
    fn narrows_isinstance_receiver_in_if_branch() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef handle(obj, cmd):\n    if isinstance(obj, Repo):\n        return obj.run(cmd)\n    return cmd\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::If { then_block, .. } = &handle.body.stmts[0] else {
            panic!("expected if statement");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &then_block.stmts[0] else {
            panic!("expected narrowed return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named narrowed target");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn merges_branch_locals_after_if_else() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef handle(flag, cmd):\n    if flag:\n        repo = Repo()\n    else:\n        repo = Repo()\n    return repo.run(cmd)\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected merged return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named merged target");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn resolves_typing_cast_and_assert_isinstance() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from typing import cast\nfrom repo import Repo\n\ndef handle(obj, cmd):\n    repo = cast(Repo, obj)\n    assert isinstance(repo, Repo)\n    return repo.run(cmd)\n".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected cast let with explicit type");
        };
        assert!(type_name(&program, *ty).is_some_and(|name| name.ends_with("Repo")));
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected asserted return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named asserted target");
        };
        assert!(name.ends_with("Repo.run"));
    }

    #[test]
    fn tracks_module_and_class_monkey_patches_and_class_alias_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def old(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import repo

def load(cmd):
    return cmd

class Service:
    pass

repo.run = load
Service.run = load

def handle_module(cmd):
    return repo.run(cmd)

def handle_service(cmd):
    factory = Service
    svc = factory()
    return svc.run(cmd)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("repo.run").as_deref(), Some("app.load"));
        assert_eq!(index.field_type("app.Service", "run").as_deref(), Some("app.load"));

        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle_module = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle_module" => Some(func), _ => None })
            .expect("handle_module present");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle_module.body.stmts[0] else {
            panic!("expected module patch call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named module patch target");
        };
        assert_eq!(name, "app.load");

        let handle_service = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle_service" => Some(func), _ => None })
            .expect("handle_service present");
        let Stmt::Let { init: Some(Expr::New { type_name, .. }), .. } = &handle_service.body.stmts[1] else {
            panic!("expected class alias constructor new");
        };
        assert_eq!(type_name, "app.Service");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle_service.body.stmts[2] else {
            panic!("expected service patch call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named service patch target");
        };
        assert_eq!(name, "app.load");
    }

    #[test]
    fn resolves_static_globals_and_vars_namespace_accesses() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def load(cmd):
    return cmd

globals()["load_alias"] = load

class Service:
    def __init__(self):
        self.__dict__["repo"] = Repo()

    def handle(self, cmd):
        cb = globals()["load_alias"]
        return cb(vars(self)["repo"].run(cmd))
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.load_alias").as_deref(), Some("app.load"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));

        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let service = module
            .items
            .iter()
            .find_map(|item| match item { Item::Class(class) if class.name == "app.Service" => Some(class), _ => None })
            .expect("service class");
        let handle = service.methods.iter().find(|method| method.name == "app.Service.handle").expect("handle method");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected globals alias let");
        };
        assert!(type_name(&program, *ty).is_some_and(|name| name.ends_with("load")));
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected namespace return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named namespace callback target");
        };
        assert_eq!(name, "app.load");
    }

    #[test]
    fn uses_context_manager_enter_return_types_for_with_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

class RepoManager:
    def __enter__(self):
        return Repo()

    def __exit__(self, exc_type, exc, tb):
        return None

def handle(cmd):
    with RepoManager() as repo:
        return repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item { Item::Function(func) if func.name == "app.handle" => Some(func), _ => None })
            .expect("handle present");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected with alias let");
        };
        assert_eq!(type_name(&program, *ty), Some("repo.Repo"));
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected with return call");
        };
        let CallTarget::Named(name) = &call.target else {
            panic!("expected named with target");
        };
        assert_eq!(name, "repo.Repo.run");
    }

    #[test]
    fn resolves_static_namespace_get_pop_and_setdefault_helpers() {
        let entries = vec![
            (
                "examples/python_namespace_method_helpers/repo.py".to_string(),
                "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "examples/python_namespace_method_helpers/app.py".to_string(),
                "from repo import Repo, load\n\nglobals()[\"cb\"] = load\nglobals()[\"factory\"] = Repo\n\ndef handle_get(cmd):\n    cb = globals().get(\"cb\")\n    return cb(cmd)\n\ndef handle_pop(cmd):\n    cb = globals().pop(\"cb\")\n    return cb(cmd)\n\ndef handle_setdefault(cmd):\n    cb = globals().setdefault(\"cb2\", load)\n    return cb(cmd)\n\ndef handle_factory(cmd):\n    factory = globals().get(\"factory\")\n    repo = factory()\n    return repo.run(cmd)\n".to_string(),
            ),
        ];
        let project = parse_project_sources(&entries).expect("parse project");
        let app_module = project
            .modules
            .iter()
            .find(|module| module.name == "app")
            .expect("app module");
        let handle_get = module_function(app_module, "handle_get").expect("handle_get");
        let handle_pop = module_function(app_module, "handle_pop").expect("handle_pop");
        let handle_setdefault =
            module_function(app_module, "handle_setdefault").expect("handle_setdefault");
        let handle_factory =
            module_function(app_module, "handle_factory").expect("handle_factory");
        let is_repo_load_cast = |stmt: &Stmt| match stmt {
            Stmt::Let {
                init: Some(Expr::Cast { ty: Some(ty), .. }),
                ..
            } => type_name(&project, *ty) == Some("repo.load"),
            _ => false,
        };
        let saw_get_alias = handle_get.body.stmts.iter().any(is_repo_load_cast);
        let saw_pop_alias = handle_pop.body.stmts.iter().any(is_repo_load_cast);
        let saw_setdefault_alias = handle_setdefault.body.stmts.iter().any(is_repo_load_cast);
        let saw_factory_ctor = handle_factory.body.stmts.iter().any(|stmt| {
            matches!(
                stmt,
                Stmt::Let {
                    init: Some(Expr::New { type_name, .. }),
                    ..
                } if type_name == "repo.Repo"
            )
        });
        assert!(saw_get_alias);
        assert!(saw_pop_alias);
        assert!(saw_setdefault_alias);
        assert!(saw_factory_ctor);
    }

    #[test]
    fn resolves_static_eval_callable_aliases() {
        let entries = vec![
            (
                "examples/python_eval_exec_dynamic/repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "examples/python_eval_exec_dynamic/app.py".to_string(),
                r#"from repo import load

def handle(cmd):
    cb = eval("load")
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { .. } = &handle.body.stmts[0] else {
            panic!("expected eval alias let");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name.ends_with("repo.load")));
    }

    #[test]
    fn lowers_static_exec_assignments_into_real_statements() {
        let entries = vec![
            (
                "examples/python_eval_exec_dynamic/repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "examples/python_eval_exec_dynamic/app.py".to_string(),
                r#"from repo import Repo

def handle(cmd):
    exec("repo = Repo()\ncb = repo.run")
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { .. } = &handle.body.stmts[0] else {
            panic!("expected exec-defined repo let");
        };
        let Stmt::Let { .. } = &handle.body.stmts[1] else {
            panic!("expected exec-defined callback let");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[2] else {
            panic!("expected callback return call after exec");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name.ends_with("Repo.run")));
    }

    #[test]
    fn narrows_type_identity_guards() {
        let entries = vec![
            (
                "examples/python_type_identity_guard/repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "examples/python_type_identity_guard/app.py".to_string(),
                "from repo import Repo

def handle(obj, cmd):
    if type(obj) is Repo:
        return obj.run(cmd)
    return cmd
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::If { then_block, .. } = &handle.body.stmts[0] else {
            panic!("expected if statement");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &then_block.stmts[0] else {
            panic!("expected narrowed return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name.ends_with("Repo.run")));
    }

    #[test]
    fn resolves_async_with_aenter_and_async_for_anext() {
        let entries = vec![
            (
                "examples/python_async_magic/repo.py".to_string(),
                "def load(cmd):
    return cmd

class Repo:
    def run(self, cmd):
        return cmd

class AsyncManager:
    async def __aenter__(self):
        return Repo()

    async def __aexit__(self, exc_type, exc, tb):
        return None

class AsyncRegistry:
    def __aiter__(self):
        return self

    async def __anext__(self):
        return load
".to_string(),
            ),
            (
                "examples/python_async_magic/app.py".to_string(),
                "from repo import AsyncManager, AsyncRegistry

async def handle(cmd):
    async with AsyncManager() as repo:
        first = repo.run(cmd)
    async for cb in AsyncRegistry():
        return cb(first)
    return first
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Let { ty: Some(ty), .. } = &handle.body.stmts[0] else {
            panic!("expected async with alias let");
        };
        assert_eq!(type_name(&program, *ty), Some("repo.Repo"));
        let Stmt::ForEach { body, .. } = &handle.body.stmts[2] else {
            panic!("expected async for lowered as foreach");
        };
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &body.stmts[0] else {
            panic!("expected callback return inside async for");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn tracks_static_namespace_update_calls() {
        let entries = vec![
            (
                "examples/python_namespace_update_calls/repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd

def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "examples/python_namespace_update_calls/app.py".to_string(),
                r#"from repo import Repo, load

globals().update({"load_alias": load})

class Service:
    pass

vars(Service).update(repo=Repo())

def handle(cmd):
    cb = globals()["load_alias"]
    return cb(Service.repo.run(cmd))
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.load_alias").as_deref(), Some("repo.load"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn resolves_next_callable_aliases_from_iterables() {
        let entries = vec![
            (
                "examples/python_next_callable/repo.py".to_string(),
                "def load(cmd):
    return cmd

class Registry:
    def __iter__(self):
        return self

    def __next__(self):
        return load
".to_string(),
            ),
            (
                "examples/python_next_callable/app.py".to_string(),
                "from repo import Registry

def handle(cmd):
    cb = next(Registry())
    return cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn merges_try_except_finally_callback_envs() {
        let entries = vec![
            (
                "examples/python_try_except_finally_callbacks/repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "examples/python_try_except_finally_callbacks/app.py".to_string(),
                "from repo import load

def handle(cmd):
    try:
        cb = load
    except Exception as exc:
        cb = load
    finally:
        final_cb = cb
    return final_cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let call = handle.body.stmts.iter().find_map(|stmt| match stmt {
            Stmt::Return { value: Some(Expr::Call(call)), .. } => Some(call),
            _ => None,
        }).expect("expected callback return after try/finally merge");
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn resolves_generator_yield_callbacks_through_next() {
        let entries = vec![
            (
                "examples/python_generator_yield_callbacks/repo.py".to_string(),
                "def load(cmd):
    return cmd

def callbacks():
    yield load
".to_string(),
            ),
            (
                "examples/python_generator_yield_callbacks/app.py".to_string(),
                "from repo import callbacks

def handle(cmd):
    cb = next(callbacks())
    return cb(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let Stmt::Return { value: Some(Expr::Call(call)), .. } = &handle.body.stmts[1] else {
            panic!("expected generator-backed callback return call");
        };
        assert!(matches!(&call.target, CallTarget::Named(name) if name == "repo.load"));
    }

    #[test]
    fn project_index_keeps_loop_only_assignments_conservative() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

def maybe_repo(items):
    repo = None
    for item in items:
        repo = Repo()
    return repo
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.maybe_repo", 1), None);
    }

    #[test]
    fn project_index_models_map_and_sorted_iterable_helpers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

def build(x):
    return Repo()

def via_map():
    return next(map(build, [1]))

def via_sorted():
    repo = sorted([Repo()])[0]
    return repo
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.via_map", 0).as_deref(), Some("repo.Repo"));
        assert_eq!(index.top_level_return("app.via_sorted", 0).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_models_structured_if_branch_merges() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    pass\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef choose(flag):\n    if flag:\n        repo = Repo()\n    else:\n        repo = Repo()\n    return repo\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.choose", 1).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_models_structured_try_except_merges() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:\n    pass\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo\n\ndef choose():\n    try:\n        repo = Repo()\n    except Exception as exc:\n        repo = Repo()\n    return repo\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.choose", 0).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_stops_after_unconditional_return_in_summary() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):\n    return cmd\n\ndef other(cmd):\n    return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, other\n\ndef choose():\n    cb = load\n    return cb\n    cb = other\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.choose", 0).as_deref(), Some("repo.load"));
    }

    #[test]
    fn project_index_models_structured_module_level_branches() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo, load\n\nclass Service:\n    pass\n\nif flag:\n    cb = load\n    Service.repo = Repo()\nelse:\n    cb = load\n    Service.repo = Repo()\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.load"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_models_structured_module_try_imports() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):\n    return cmd\n".to_string(),
            ),
            (
                "app.py".to_string(),
                "try:\n    from repo import load as cb\nexcept ImportError:\n    from repo import load as cb\n".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.load"));
    }

    #[test]
    fn project_index_delays_nested_writebacks_until_call_time() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()
".to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import load, alt

def outer(cmd):
    cb = load

    def patch():
        nonlocal cb
        cb = alt

    return cb(cmd)
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.outer", 1).as_deref(), Some("repo.A"));
    }

    #[test]
    fn project_index_replays_module_helper_writebacks_on_call() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class A:
    pass

class B:
    pass

class Repo:
    def execute(self, value):
        return value

def load(cmd):
    return A()

def alt(cmd):
    return B()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import load, alt, Repo

cb = load

class Service:
    pass

def patch():
    global cb
    cb = alt

def install():
    Service.repo = Repo

patch()
install()
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("app.cb").as_deref(), Some("repo.alt"));
        assert_eq!(index.module_symbol_alias("app", "cb").as_deref(), Some("repo.alt"));
        assert_eq!(index.field_type("app.Service", "repo").as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn project_index_respects_cross_module_import_execution_order() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()

cb = load
".to_string(),
            ),
            (
                "patcher.py".to_string(),
                "import repo
from repo import alt

repo.cb = alt
".to_string(),
            ),
            (
                "before.py".to_string(),
                "from repo import cb
import patcher
".to_string(),
            ),
            (
                "after.py".to_string(),
                "import patcher
from repo import cb
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.module_value_type_by_path("before.cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_symbol_alias("before", "cb").as_deref(), Some("repo.load"));
        assert_eq!(index.module_value_type_by_path("after.cb").as_deref(), Some("repo.alt"));
        assert_eq!(index.module_symbol_alias("after", "cb").as_deref(), Some("repo.alt"));
    }

    #[test]
    fn project_index_replays_nested_outer_heap_writebacks_on_call() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class A:
    pass

class B:
    pass

def load(cmd):
    return A()

def alt(cmd):
    return B()

class Box:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Box, load, alt

def outer(cmd):
    holder = Box()
    holder.inner = Box()
    holder.inner.cb = load

    def patch():
        holder.inner.cb = alt

    patch()
    return holder.inner.cb(cmd)
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.outer", 1).as_deref(), Some("repo.B"));
    }

    #[test]
    fn replays_decorator_wrapper_side_effects_at_call_time() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class Service:
    pass

def deco(fn):
    def wrapper(svc, cmd):
        svc.repo = Repo()
        return fn(svc, cmd)
    return wrapper

@deco
def handle(svc, cmd):
    return cmd

def call(cmd):
    svc = Service()
    handle(svc, cmd)
    return svc.repo.run(cmd)
".to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let call = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.call" => Some(function),
                _ => None,
            })
            .expect("call function");
        let Stmt::Return { value: Some(Expr::Call(call_expr)), .. } = &call.body.stmts[2] else {
            panic!("expected decorated wrapper side-effect replayed call");
        };
        assert!(matches!(&call_expr.target, CallTarget::Named(name) if name == "repo.Repo.run"));
    }

    #[test]
    fn project_index_replays_constructor_init_side_effects_into_receiver_objects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def __init__(self):
        self.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_instance_method_side_effects_into_receivers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def install(self):
        self.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_free_function_parameter_side_effects_into_arguments() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass

def install(service):
    service.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service, install

def handle(cmd):
    svc = Service()
    install(svc)
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_dotted_receiver_method_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Runner:
    def run(self, cmd):
        return cmd

class Holder:
    def install(self):
        self.runner = Runner()

class Service:
    def __init__(self):
        self.repo = Holder()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    svc.repo.install()
    return svc.repo.runner.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Runner.run");
    }

    #[test]
    fn project_index_replays_classmethod_side_effects_into_class_receivers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

class Service:
    @classmethod
    def install(cls):
        cls.repo = Repo()

def handle(cmd):
    Service.install()
    return Service.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_applies_recursive_import_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass
"#.to_string(),
            ),
            (
                "patch_inner.py".to_string(),
                r#"from repo import Repo, Service

Service.repo = Repo()
"#.to_string(),
            ),
            (
                "patch_outer.py".to_string(),
                r#"import patch_inner
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import patch_outer
from repo import Service

def handle(cmd):
    return Service.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_decorated_method_wrapper_with_bound_self() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def deco(fn):
    def wrapper(self):
        self.repo = Repo()
        return fn(self)
    return wrapper

class Service:
    @deco
    def install(self):
        return None

def handle(cmd):
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_star_spread_argument_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass

def install(service):
    service.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service, install

def handle(cmd):
    svc = Service()
    args = (svc,)
    install(*args)
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn project_index_replays_starstar_keyword_side_effects() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    pass

def install(*, service):
    service.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service, install

def handle(cmd):
    svc = Service()
    kwargs = {"service": svc}
    install(**kwargs)
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let program = parse_project_sources(&entries).expect("parse python project");
        let module = program.modules.iter().find(|module| module.name == "app").expect("app module");
        let handle = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Function(function) if function.name == "app.handle" => Some(function),
                _ => None,
            })
            .expect("handle function");
        let resolved = handle
            .body
            .stmts
            .iter()
            .find_map(|stmt| match stmt {
                Stmt::Return { value: Some(Expr::Call(call)), .. } => match &call.target {
                    CallTarget::Named(name) => Some(name.clone()),
                    _ => None,
                },
                _ => None,
            })
            .expect("resolved return call");
        assert_eq!(resolved, "repo.Repo.run");
    }

    #[test]
    fn parses_annotated_class_body_fields() {
        let src = r#"
class Repo:
    pass

class Payload:
    repo: Repo
    items: list[Repo]
    payload: dict[str, Repo]
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let payload = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name.ends_with("Payload") => Some(class),
                _ => None,
            })
            .expect("payload class");
        let field_type = |name: &str| -> String {
            let field = payload.fields.iter().find(|field| field.name == name).expect("field present");
            let ty = field.ty.expect("typed field");
            program.types[ty.0 as usize].name.clone()
        };
        assert_eq!(field_type("repo"), "app.Repo");
        assert_eq!(field_type("items"), "list<app.Repo>");
        assert_eq!(field_type("payload"), "dict<str,app.Repo>");
    }

    #[test]
    fn project_index_recovers_annotated_framework_style_fields() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Repo

class Payload:
    repo: Repo
    items: list[Repo]
    payload: dict[str, Repo]
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Payload", "repo").as_deref(), Some("repo.Repo"));
        assert_eq!(index.field_type("app.Payload", "items").as_deref(), Some("list<repo.Repo>"));
        assert_eq!(index.field_type("app.Payload", "payload").as_deref(), Some("dict<str,repo.Repo>"));
    }

    #[test]
    fn infers_fastapi_depends_parameter_type_from_provider_return() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from fastapi import Depends
from repo import Repo

def get_repo() -> Repo:
    return Repo()

def handle(repo = Depends(get_repo)):
    return repo
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.handle", 0).as_deref(), Some("repo.Repo"));
    }

    #[test]
    fn resolves_typevar_and_newtype_annotations_in_project_index() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"from typing import NewType, TypeVar

class Repo:
    pass

RepoId = NewType("RepoId", str)
TRepo = TypeVar("TRepo", bound=Repo)

class Payload:
    repo: TRepo
    rid: RepoId
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("repo.Payload", "repo").as_deref(), Some("repo.Repo"));
        assert_eq!(index.field_type("repo.Payload", "rid").as_deref(), Some("str"));
    }

    #[test]
    fn parses_typing_extensions_and_attrs_field_factories() {
        let src = r#"
from typing_extensions import Annotated, Literal, NotRequired, Required
import attrs

class Repo:
    pass

class Payload:
    repo: Required[Annotated[Repo, "payload"]]
    rid: Literal[1]
    maybe: NotRequired[Repo]
    created = attrs.field(factory=Repo)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let payload = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name.ends_with("Payload") => Some(class),
                _ => None,
            })
            .expect("payload class");
        let field_type = |name: &str| -> String {
            let field = payload.fields.iter().find(|field| field.name == name).expect("field present");
            let ty = field.ty.expect("typed field");
            program.types[ty.0 as usize].name.clone()
        };
        assert_eq!(field_type("repo"), "app.Repo");
        assert_eq!(field_type("rid"), "int");
        assert_eq!(field_type("maybe"), "app.Repo");
        assert_eq!(field_type("created"), "app.Repo");
    }

    #[test]
    fn infers_fastapi_query_default_type() {
        let entries = vec![
            (
                "app.py".to_string(),
                "from fastapi import Query

def handle(limit = Query(10)):
    return limit
".to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.handle", 0).as_deref(), Some("int"));
    }

    #[test]
    fn parses_extended_annotation_aliases_and_field_factories() {
        let src = r#"
from dataclasses import field
from typing import Annotated, Mapping, Optional, Sequence

class Repo:
    pass

class Payload:
    repo: Optional[Repo]
    seq: Sequence[Repo]
    mapping: Mapping[str, Repo]
    annotated: Annotated[Repo, "payload"]
    created = field(default_factory=Repo)
    items = field(default_factory=list)
"#;
        let program = PythonParser.parse_file("app.py", src).expect("parse ok");
        let module = &program.modules[0];
        let payload = module
            .items
            .iter()
            .find_map(|item| match item {
                Item::Class(class) if class.name.ends_with("Payload") => Some(class),
                _ => None,
            })
            .expect("payload class");
        let field_type = |name: &str| -> String {
            let field = payload.fields.iter().find(|field| field.name == name).expect("field present");
            let ty = field.ty.expect("typed field");
            program.types[ty.0 as usize].name.clone()
        };
        assert_eq!(field_type("repo"), "app.Repo");
        assert_eq!(field_type("seq"), "list<app.Repo>");
        assert_eq!(field_type("mapping"), "dict<str,app.Repo>");
        assert_eq!(field_type("annotated"), "app.Repo");
        assert_eq!(field_type("created"), "app.Repo");
        assert_eq!(field_type("items"), "list");
    }

    #[test]
    fn project_index_substitutes_generic_base_field_types() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import Generic, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

class Repo:
    pass

class RepoBox(Box[Repo]):
    pass
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.RepoBox", "item").as_deref(), Some("app.Repo"));
    }

    #[test]
    fn project_index_substitutes_generic_base_method_returns() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import Generic, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

class Repo:
    pass

class RepoBox(Box[Repo]):
    pass
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("app.RepoBox", "current", 0).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn functional_typed_dict_declarations_are_indexed_and_key_sensitive() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import TypedDict

UserPayload = TypedDict("UserPayload", {"id": int, "name": str})

def handle(payload: UserPayload):
    return payload["id"]
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert!(index.is_typed_dict_class("app.UserPayload"));
        assert_eq!(index.field_type("app.UserPayload", "id").as_deref(), Some("int"));
        assert_eq!(index.typed_dict_key_type("app.UserPayload", "name").as_deref(), Some("str"));
    }

    #[test]
    fn functional_named_tuple_declarations_expose_fields() {
        let entries = vec![
            (
                "app.py".to_string(),
                r#"from typing import NamedTuple

Point = NamedTuple("Point", [("x", int), ("y", int)])

def handle(point: Point):
    return point.x
"#.to_string(),
            ),
        ];
        let index = PyProjectIndex::build(&entries);
        assert!(index.is_named_tuple_class("app.Point"));
        assert_eq!(index.field_type("app.Point", "x").as_deref(), Some("int"));
        assert_eq!(index.field_type("app.Point", "y").as_deref(), Some("int"));
    }

    #[test]
    fn infers_protocol_base_with_type_args() {
        let index = PyProjectIndex::build(&[(
            "repo.py".to_string(),
            r#"from typing import Protocol, TypeVar
T = TypeVar("T")
class Reader(Protocol[T]):
    def get(self) -> T:
        return None
"#
            .to_string(),
        )]);
        assert!(index.is_protocol_class("repo.Reader"));
    }

    #[test]
    fn infers_orm_relationship_field_shapes() {
        let index = PyProjectIndex::build(&[(
            "models.py".to_string(),
            r#"from sqlalchemy.orm import Mapped, relationship

class User:
    pass

class Team:
    owner: Mapped[User]
    members = relationship("User")
"#
            .to_string(),
        )]);
        assert_eq!(index.field_type("models.Team", "owner").as_deref(), Some("models.User"));
        assert_eq!(index.field_type("models.Team", "members").as_deref(), Some("models.User"));
    }

    #[test]
    fn typed_dict_get_is_key_sensitive() {
        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"from typing import TypedDict

class Payload(TypedDict):
    id: int
    name: str

def read(payload: Payload):
    return payload.get("id")
"#
            .to_string(),
        )]);
        assert_eq!(index.top_level_return("app.read", 1).as_deref(), Some("int"));
    }

    #[test]
    fn typed_dict_items_return_is_iterable_and_key_sensitive() {
        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"from typing import TypedDict

class Payload(TypedDict):
    id: int
    name: str

def read(payload: Payload):
    return payload.items()
"#
            .to_string(),
        )]);
        let ret = index.top_level_return("app.read", 1).expect("typed dict items return");
        assert!(ret.starts_with("generator<tuple<str|"));
    }

    #[test]
    fn dict_keys_and_values_returns_are_typed() {
        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"def keys(payload: dict[str, int]):
    return payload.keys()

def values(payload: dict[str, int]):
    return payload.values()
"#
            .to_string(),
        )]);
        assert_eq!(index.top_level_return("app.keys", 1).as_deref(), Some("generator<str>"));
        assert_eq!(index.top_level_return("app.values", 1).as_deref(), Some("generator<int>"));
    }

    #[test]
    fn self_return_types_are_specialized_to_concrete_class() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Self

class Repo:
    def clone(self) -> Self:
        return self
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.method_return("app.Repo", "clone", 0).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn callable_and_awaitable_annotations_are_recovered() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Awaitable, Callable

class Repo:
    pass

Handler = Callable[[str], Repo]

class Service:
    callback: Handler
    pending: Awaitable[Repo]
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "callback").as_deref(), Some("callable<app.Repo>"));
        assert_eq!(index.field_type("app.Service", "pending").as_deref(), Some("app.Repo"));
    }

    #[test]
    fn relationship_uselist_and_self_targets_are_recovered() {
        let entries = vec![(
            "models.py".to_string(),
            r#"from sqlalchemy.orm import relationship

class Node:
    children = relationship("self", uselist=True)
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("models.Node", "children").as_deref(), Some("list<models.Node>"));
    }

    #[test]
    fn normalizes_project_generic_annotations_with_type_args() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Generic, Protocol, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

class Reader(Protocol[T]):
    def get(self) -> T:
        return None

class Repo:
    pass

class Service:
    box: Box[Repo]
    reader: Reader[Repo]
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Service", "box").as_deref(), Some("app.Box<app.Repo>"));
        assert_eq!(index.field_type("app.Service", "reader").as_deref(), Some("app.Reader<app.Repo>"));
    }

    #[test]
    fn substitutes_instantiated_generic_field_and_method_types() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Generic, Protocol, TypeVar

T = TypeVar("T")

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

class Reader(Protocol[T]):
    def get(self) -> T:
        return None

class Repo:
    pass
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.field_type("app.Box<app.Repo>", "item").as_deref(), Some("app.Repo"));
        assert_eq!(index.method_return("app.Box<app.Repo>", "current", 0).as_deref(), Some("app.Repo"));
        assert_eq!(index.method_return("app.Reader<app.Repo>", "get", 0).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn infers_member_access_and_method_calls_on_instantiated_generic_types() {
        let entries = vec![(
            "app.py".to_string(),
            r#"from typing import Generic, TypeVar

T = TypeVar("T")

class Repo:
    pass

class Box(Generic[T]):
    item: T

    def current(self) -> T:
        return self.item

def read(box: Box[Repo]):
    item = box.item
    current = box.current()
    return current
"#
            .to_string(),
        )];
        let index = PyProjectIndex::build(&entries);
        assert_eq!(index.top_level_return("app.read", 1).as_deref(), Some("app.Repo"));
    }

    #[test]
    fn normalizes_pep604_union_annotations_and_typeddict_value_unions() {
        let imports = PyImports::default();
        let env = PyEnv::default();
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("dict[str, int] | None", &imports, &env, &known).as_deref(), Some("dict<str,int>"));
        assert_eq!(infer_simple_python_type("int | None", &imports, &env, &known).as_deref(), Some("int"));

        let index = PyProjectIndex::build(&[(
            "app.py".to_string(),
            r#"from typing import TypedDict

class Payload(TypedDict):
    title: str
    count: int
"#.to_string(),
        )]);
        assert_eq!(index.typed_dict_value_type("app.Payload").as_deref(), Some("int|str"));
    }

    #[test]
    fn normalizes_typeis_never_unpack_and_concatenate_annotations() {
        let imports = PyImports::default();
        let env = PyEnv::default();
        let known = HashSet::new();
        assert_eq!(infer_simple_python_type("TypeIs[int]", &imports, &env, &known).as_deref(), Some("bool"));
        assert_eq!(infer_simple_python_type("Never", &imports, &env, &known).as_deref(), Some("none"));
        assert_eq!(infer_simple_python_type("Unpack[list[int]]", &imports, &env, &known).as_deref(), Some("list<int>"));
        assert_eq!(infer_simple_python_type("Concatenate[str, int]", &imports, &env, &known).as_deref(), Some("int"));
    }

}

#[cfg(test)]
mod balanced_function_header_regressions {
    use super::*;

    #[test]
    fn parses_nested_defaults_and_return_annotation_in_function_header() {
        let parsed = parse_python_function_header(
            "def handle(repo: Repo = Depends(get_repo), limit: int = Query(10)) -> list[Item]:",
        )
        .expect("balanced function header");
        assert_eq!(parsed.0, "handle");
        assert_eq!(
            parsed.1,
            "repo: Repo = Depends(get_repo), limit: int = Query(10)"
        );
    }

    #[test]
    fn parses_quoted_parentheses_in_default_values() {
        let parsed = parse_python_function_header(
            "async def load(pattern: str = Field(default=\")\")) -> Awaitable[Result]:",
        )
        .expect("quoted closing parenthesis must not terminate parameters");
        assert_eq!(parsed.0, "load");
        assert_eq!(parsed.1, "pattern: str = Field(default=\")\")");
    }
}
