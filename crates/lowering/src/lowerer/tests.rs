#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_lang_python::PythonParser;
    use uniflow_parser_core::SourceParser;

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
