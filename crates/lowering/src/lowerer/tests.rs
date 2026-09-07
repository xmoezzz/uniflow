#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_lang_python::PythonParser;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn javascript_es_import_aliases_lower_to_package_qualified_callees() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "imports.js",
            r#"
import * as child from "child_process";
import bluebird from "bluebird";
import { exec as run } from "child_process";
function execute(command, object) {
    child.spawn(command);
    bluebird.toFastProperties(object);
    run(command);
}
"#,
        )
        .expect("parse JavaScript imports");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("execute").expect("execute function");
        let callees = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call) => match &call.callee {
                    Callee::Static(name) => Some(name.as_str()),
                    Callee::Dynamic(_) | Callee::Unknown => None,
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(callees.contains(&"child_process.spawn"), "{callees:?}");
        assert!(callees.contains(&"bluebird.toFastProperties"), "{callees:?}");
        assert!(callees.contains(&"child_process.exec"), "{callees:?}");
    }

    #[test]
    fn javascript_assigned_lambdas_keep_handler_and_variable_names() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "lambda-handlers.js",
            r#"
exports.handler = function(event) { return event; };
const localHandler = function(input) { return input; };
"#,
        )
        .expect("parse JavaScript assigned lambdas");
        let ir = lower_program(&hir);
        assert!(ir.find_function_by_name("exports.handler").is_some(), "{ir:#?}");
        assert!(ir.find_function_by_name("localHandler").is_some(), "{ir:#?}");
    }

    #[test]
    fn javascript_expression_composition_returns_a_first_class_value() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "composition.js",
            r#"
function format(name) {
    const message = "user:" + name;
    console.log(message, name);
    return message;
}
"#,
        )
        .expect("parse JavaScript composition");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("format").expect("format function");
        let composed = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(&call.callee, Callee::Static(name) if name == "__uniflow.compose.string") =>
                {
                    call.dst
                }
                _ => None,
            })
            .expect("composition call result");
        let stored = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find_map(|inst| match inst.kind {
                InstKind::Copy { dst, src } if src == composed => Some(dst),
                _ => None,
            })
            .expect("composition result stored in local");
        assert!(function.blocks.iter().flat_map(|block| &block.insts).any(|inst| {
            matches!(&inst.kind, InstKind::Call(call)
                if matches!(&call.callee, Callee::Static(name) if name.ends_with("console.log"))
                    && call.args.first() == Some(&stored))
        }), "{function:#?}");
    }

    #[test]
    fn javascript_map_descriptor_preserves_static_field_paths() {
        let hir = uniflow_lang_frontends::parse_file(
            Language::JavaScript,
            "map-descriptor.js",
            r#"
const argon = require("argon2");
function options() { return { type: argon.argon2id }; }
"#,
        )
        .expect("parse JavaScript map descriptor");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("options").expect("options function");
        let constants = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .filter_map(|inst| match &inst.kind {
                InstKind::ConstString { value, .. } => Some(value.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            constants.iter().any(|value| value.contains("type argon.argon2id")),
            "{constants:?}"
        );
    }

    #[test]
    fn lowering_expands_python_destructuring_into_index_loads() {
        let src = r#"
def load_pair():
    return source()

def handle(payload):
    left, right = load_pair()
    for key, value in payload.items():
        right = value
    return right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(&inst.kind, InstKind::LoadIndex { .. })));
    }

    #[test]
    fn lowering_preserves_resolved_python_callable_alias_targets() {
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
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_keeps_python_control_flow_inputs_live() {
        let src = r#"
from flask import request

def handle(items):
    if request.args.get("cmd"):
        pass
    for item in items:
        value = item
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(&inst.kind, InstKind::Call(_))));
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(&inst.kind, InstKind::Copy { .. })));
    }
    #[test]
    fn lowering_preserves_callable_field_value_targets() {
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
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.Service.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_indexed_callable_value_targets() {
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
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_alias_backed_callable_field_targets() {
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
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_lambda_capture_bindings() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let hir = uniflow_lang_python::PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let handle = ir.find_function_by_name("handle").expect("handle function");
        assert!(handle.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::StoreField { field, .. } => field == "__capture__cmd",
            _ => false,
        }));
        let lambda = ir.functions.iter().find(|func| func.name.contains("__lambda_")).expect("lambda function");
        assert_eq!(lambda.attrs.get("capture_names").map(|s| s.as_str()), Some("cmd"));
        assert_eq!(lambda.params.len(), 2);
    }

    #[test]
    fn lowering_preserves_lambda_callable_value_types() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.value_types.values().any(|ty| ty.contains("__lambda_")));
    }

    #[test]
    fn lowering_discovers_descriptor_lambda_functions_and_captures() {
        let hir = uniflow_lang_frontends::parse_file(
            uniflow_hir::Language::JavaScript,
            "lambda.js",
            "const prefix = source(); const cb = (x) => prefix + x; sink(cb('v'));",
        )
        .expect("parse descriptor closure");
        let ir = lower_program(&hir);
        let lambda = ir
            .functions
            .iter()
            .find(|function| function.name.contains("__lambda_"))
            .expect("descriptor lambda should lower as an invokable function");
        assert_eq!(
            lambda.attrs.get("capture_names").map(String::as_str),
            Some("prefix")
        );
        assert_eq!(lambda.params.len(), 2, "one explicit param plus one capture");
        let top = ir
            .find_function_by_name("__top_level__")
            .expect("top-level function");
        assert!(top
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .any(|inst| matches!(
                &inst.kind,
                InstKind::Call(CallInst {
                    callee: Callee::Dynamic(_),
                    ..
                })
            )));
    }

    #[test]
    fn lowering_versions_reassigned_variables() {
        let src = r#"
def handle(value):
    value = source()
    value = "safe"
    return value
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        let copies = func
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match inst.kind {
                InstKind::Copy { dst, .. } => Some(dst),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(copies.len() >= 2);
        assert_ne!(copies[copies.len() - 1], copies[copies.len() - 2]);
    }

    #[test]
    fn lowering_preserves_conditional_expression_inputs() {
        use uniflow_hir::Language;
        use uniflow_parser_core::{LangDescriptor, LexerSpec};

        let descriptor = LangDescriptor {
            lexer: LexerSpec {
                keywords: &["void", "int", "return"],
                ..LexerSpec::default()
            },
            type_before_name: true,
            ..LangDescriptor::new(Language::C)
        };
        let (hir, errors) = uniflow_parser_core::parse_program(
            &descriptor,
            "conditional.c",
            "int choose(int flag, int value) { int out = flag ? value : 0; return out; }",
        )
        .expect("generic parse");
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let ir = lower_program(&hir);
        let function = ir.find_function_by_name("choose").expect("function");
        assert!(function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .any(|inst| matches!(&inst.kind, InstKind::Phi { inputs, .. } if inputs.len() == 2)));
    }

    #[test]
    fn lowering_builds_cfg_for_if_else_and_inserts_phi() {
        let src = r#"
def handle(flag, value):
    if flag:
        value = source()
    else:
        value = "safe"
    return value
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.len() >= 4);
        assert!(func.blocks.iter().any(|block| matches!(&block.term, Terminator::Branch { .. })));
        assert!(func
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .any(|inst| matches!(&inst.kind, InstKind::Phi { .. })));
    }

    #[test]
    fn lowering_builds_loop_back_edge() {
        let src = r#"
def handle(flag, value):
    while flag:
        value = source()
    return value
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        let targets = func
            .blocks
            .iter()
            .filter_map(|block| match block.term {
                Terminator::Goto(target) => Some(target),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(targets.iter().any(|target| {
            func.blocks.iter().any(|block| block.id == *target && matches!(&block.term, Terminator::Branch { .. }))
        }));
    }

}
