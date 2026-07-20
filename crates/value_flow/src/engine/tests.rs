#[cfg(test)]
mod tests {
    use super::{
        build, canonical_heap_value, heap_projection_values_compatible, value_identity_site,
        ContextSensitivity, DemandEngine, DemandQuery, DemandSeed, EdgeKind, FlowEdge, FlowGraph,
        FlowNode, QueryBudgetProfile, SparseDirection,
    };
    use uniflow_hir::Language;
    use uniflow_lang_cpp::CppParser;
    use uniflow_lang_python::{parse_project_sources, PythonParser};
    use uniflow_lowering::lower_program;
    use uniflow_parser_core::SourceParser;
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    use uniflow_ir::{Callee, Function, FunctionId, InstKind, Program as IrProgram, ValueId};
    use uniflow_rules::{Port, RuleSet};

    struct PythonTestProject {
        ir: IrProgram,
    }

    fn build_python_project(
        entries: &[(&str, &str)],
        expected_functions: &[&str],
    ) -> PythonTestProject {
        let owned = entries
            .iter()
            .map(|(path, source)| ((*path).to_string(), (*source).to_string()))
            .collect::<Vec<_>>();
        let hir = parse_project_sources(&owned).expect("parse Python project");
        let ir = lower_program(&hir);
        for name in expected_functions {
            assert!(
                ir.find_function_by_name(name).is_some(),
                "missing expected function {name}"
            );
        }
        PythonTestProject { ir }
    }

    fn build_flow(project: &PythonTestProject) -> FlowGraph {
        build(&project.ir, &RuleSet::default())
    }

    fn find_value_by_name(function: &Function, name: &str) -> Option<ValueId> {
        function
            .attrs
            .get("value_names")?
            .split('\u{1f}')
            .find_map(|entry| {
                let (value, candidate) = entry.split_once('=')?;
                (candidate == name)
                    .then(|| value.parse::<u32>().ok().map(ValueId))
                    .flatten()
            })
    }

    #[test]
    fn resolves_dynamic_callbacks_returned_from_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def choose():
    return load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import choose

def handle(cmd):
    cb = choose()
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }
    #[test]
    fn binds_lambda_capture_values_into_internal_calls() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let lambda = ir.functions.iter().find(|func| func.name.contains("__lambda_")).expect("lambda function");
        let capture_param = fg.function_params.get(&(lambda.id, 1)).copied().expect("capture param node");
        let mut saw_capture_binding = false;
        for edge in fg.graph.edges_directed(capture_param, Direction::Incoming) {
            if !matches!(edge.weight().kind, EdgeKind::ActualToFormal) {
                continue;
            }
            if let FlowNode::FieldCell { field, .. } = &fg.graph[edge.source()] {
                if field == "__capture__cmd" {
                    saw_capture_binding = true;
                    break;
                }
            }
        }
        assert!(saw_capture_binding);
    }

    #[test]
    fn resolves_dynamic_calls_through_local_lambdas() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name.contains("__lambda_")));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_nested_functions() {
        let src = r#"
def choose(cmd):
    def inner(x):
        return cmd
    return inner

def handle(cmd):
    cb = choose(cmd)
    return cb("safe")
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "app.choose.inner"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_field_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass

def install(svc):
    svc.cb = load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, install

def handle(cmd):
    svc = Service()
    install(svc)
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_object_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass

def prepare(svc):
    svc.cb = load
    return svc
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, prepare

def handle(cmd):
    svc = Service()
    ready = prepare(svc)
    return ready.cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_index_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def install(handlers):
    handlers[0] = load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import install

def handle(cmd):
    handlers = [None]
    install(handlers)
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_field_projections() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass

def pick_cb(svc):
    return svc.cb
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, pick_cb, load

def handle(cmd):
    svc = Service()
    svc.cb = load
    cb = pick_cb(svc)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_index_projections() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def pick_cb(handlers):
    return handlers[0]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import pick_cb, load

def handle(cmd):
    handlers = [load]
    cb = pick_cb(handlers)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_nested_interprocedural_object_graphs() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass

def install(svc):
    svc.inner.cb = load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Node, Service, install

def handle(cmd):
    svc = Service()
    svc.inner = Node()
    install(svc)
    return svc.inner.cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn keeps_index_callback_slots_precise_across_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def pick_cb(handlers):
    return handlers[0]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop, pick_cb

def handle(cmd):
    handlers = [noop, load]
    cb = pick_cb(handlers)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.noop"));
        assert!(!resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn keeps_interprocedural_index_callback_slots_precise() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def install(handlers):
    handlers[1] = load

def prepare(handlers):
    handlers[0] = noop
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import install, prepare

def handle(cmd):
    handlers = [None, None]
    install(handlers)
    prepare(handlers)
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.noop"));
        assert!(!resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_nested_field_paths() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass

def pick_cb(svc):
    return svc.inner.cb
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Node, Service, pick_cb, load

def handle(cmd):
    svc = Service()
    svc.inner = Node()
    svc.inner.cb = load
    cb = pick_cb(svc)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_nested_field_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass

def install(svc):
    svc.inner.cb = load

def pick_cb(svc):
    return svc.inner.cb
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Node, Service, install, pick_cb

def handle(cmd):
    svc = Service()
    svc.inner = Node()
    install(svc)
    cb = pick_cb(svc)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_appended_list_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop

def handle(cmd):
    handlers = []
    handlers.append(noop)
    handlers.append(load)
    cb = handlers.pop()
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_dict_get_callbacks() {
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
    mapping = {}
    mapping[\"cb\"] = load
    cb = mapping.get(\"cb\")
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_dict_update_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop

def handle(cmd):
    mapping = {\"other\": noop}
    mapping.update({\"cb\": load})
    cb = mapping.get(\"cb\")
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_setdefault_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def install(mapping):
    mapping.setdefault(\"cb\", load)
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import install

def handle(cmd):
    mapping = {}
    install(mapping)
    cb = mapping.get(\"cb\")
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_precise_list_literal_slot_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def pick_cb(handlers):
    return handlers[1]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop, pick_cb

def handle(cmd):
    handlers = [noop, load]
    cb = pick_cb(handlers)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
        assert!(!resolved.iter().any(|name| name == "repo.noop"));
    }

    #[test]
    fn resolves_dynamic_calls_through_precise_dict_literal_slot_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def pick_cb(mapping):
    return mapping[\"cb\"]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop, pick_cb

def handle(cmd):
    mapping = {\"safe\": noop, \"cb\": load}
    cb = pick_cb(mapping)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
        assert!(!resolved.iter().any(|name| name == "repo.noop"));
    }

    #[test]
    fn resolves_super_property_backed_receiver_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd

class Base:
    @property
    def repo(self):
        return Repo()

class Service(Base):
    def handle(self, cmd):
        return super().repo.run(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("repo.Service.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_descriptor_backed_callable_fields() {
        let src = r#"
def load(cmd):
    return cmd

class LoaderDescriptor:
    def __get__(self, obj, owner):
        return load

class Service:
    handler = LoaderDescriptor()

    def handle(self, cmd):
        cb = self.handler
        return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("Service.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
    }

    #[test]
    fn resolves_dynamic_calls_through_callable_objects() {
        let src = r#"
class Loader:
    def __call__(self, cmd):
        return cmd

def handle(cmd):
    loader = Loader()
    return loader(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "Loader.__call__"));
    }

    #[test]
    fn resolves_property_backed_receiver_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd

class Service:
    @property
    def repo(self):
        return Repo()
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service

def handle(cmd):
    svc = Service()
    return svc.repo.run(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_getattr_receiver_calls_after_setattr() {
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
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "Repo.run" || name.ends_with("Repo.run")));
    }

    #[test]
    fn resolves_dynamic_calls_through_getattr_callable_fields() {
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
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
    }

    #[test]
    fn copies_precise_slots_through_list_constructor_calls() {
        let src = r#"
def load(cmd):
    return cmd

def noop(cmd):
    return "safe"

def handle(cmd):
    handlers = [noop, load]
    alias = list(handlers)
    cb = alias[1]
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
        assert!(!resolved.iter().any(|name| name == "noop"));
    }

    #[test]
    fn resolves_calls_through_importlib_modules() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def load(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import importlib

def handle(cmd):
    mod = importlib.import_module("repo")
    return mod.load(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_calls_through_partial_aliases() {
        let src = r#"
from functools import partial

def load(cmd):
    return cmd

def handle(cmd):
    cb = partial(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
    }

    #[test]
    fn resolves_calls_through_module_and_class_monkey_patches() {
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
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle_module = ir.find_function_by_name("app.handle_module").expect("handle_module function");
        let resolved_module = handle_module
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_module.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_module.iter().any(|name| name == "app.load"));

        let handle_service = ir.find_function_by_name("app.handle_service").expect("handle_service function");
        let resolved_service = handle_service
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_service.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_service.iter().any(|name| name == "app.load"));
    }

    #[test]
    fn resolves_calls_through_static_globals_and_vars_namespace_accesses() {
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
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.Service.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "app.load"));
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_context_manager_enter_aliases() {
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
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_static_namespace_method_helpers() {
        let project = build_python_project(
            &[
                (
                    "examples/python_namespace_method_helpers/repo.py",
                    "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n",
                ),
                (
                    "examples/python_namespace_method_helpers/app.py",
                    "from repo import Repo, load\n\nglobals()[\"cb\"] = load\nglobals()[\"factory\"] = Repo\n\ndef handle_get(cmd):\n    cb = globals().get(\"cb\")\n    return cb(cmd)\n\ndef handle_pop(cmd):\n    cb = globals().pop(\"cb\")\n    return cb(cmd)\n\ndef handle_setdefault(cmd):\n    cb = globals().setdefault(\"cb2\", load)\n    return cb(cmd)\n\ndef handle_factory(cmd):\n    factory = globals().get(\"factory\")\n    repo = factory()\n    return repo.run(cmd)\n",
                ),
            ],
            &["repo.load", "repo.Repo.run"],
        );
        let fg = build_flow(&project);
        let ir = &project.ir;
        for func_name in ["app.handle_get", "app.handle_pop", "app.handle_setdefault"] {
            let func = ir.find_function_by_name(func_name).expect("function");
            let resolved = func
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter())
                .filter_map(|inst| fg.resolved_internal_targets.get(&(func.id, inst.id)).cloned())
                .flatten()
                .collect::<Vec<_>>();
            assert!(resolved.iter().any(|name| name == "repo.load"), "missing repo.load for {func_name}: {resolved:?}");
        }
        let handle_factory = ir.find_function_by_name("app.handle_factory").expect("handle_factory");
        let resolved_factory = handle_factory
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| fg.resolved_internal_targets.get(&(handle_factory.id, inst.id)).cloned())
            .flatten()
            .collect::<Vec<_>>();
        assert!(resolved_factory.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run: {resolved_factory:?}");
    }

    #[test]
    fn resolves_calls_through_static_eval_and_exec_paths() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

def load(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo, load

def handle_eval(cmd):
    cb = eval("load")
    return cb(cmd)

def handle_exec(cmd):
    exec("repo = Repo()\ncb = repo.run")
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());

        let handle_eval = ir.find_function_by_name("app.handle_eval").expect("handle_eval function");
        let resolved_eval = handle_eval
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_eval.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_eval.iter().any(|name| name == "repo.load"));

        let handle_exec = ir.find_function_by_name("app.handle_exec").expect("handle_exec function");
        let resolved_exec = handle_exec
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_exec.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_exec.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_type_identity_guards() {
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

def handle(obj, cmd):
    if type(obj) is Repo:
        return obj.run(cmd)
    return cmd
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_generator_yields() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def load(cmd):
    return cmd

def callbacks():
    yield load
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import callbacks

def handle(cmd):
    cb = next(callbacks())
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .flat_map(|inst| {
                fg.resolved_internal_targets
                    .get(&(handle.id, inst.id))
                    .cloned()
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_calls_through_map_and_sorted_helpers() {
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

def build(x):
    return Repo()

def handle_map(cmd):
    repo = next(map(build, [1]))
    return repo.run(cmd)

def handle_sorted(cmd):
    repo = sorted([Repo()])[0]
    return repo.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());

        for function_name in ["app.handle_map", "app.handle_sorted"] {
            let function = ir.find_function_by_name(function_name).expect("function");
            let resolved = function
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter())
                .find_map(|inst| fg.resolved_internal_targets.get(&(function.id, inst.id)).cloned())
                .unwrap_or_default();
            assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run for {function_name}: {resolved:?}");
        }
    }

    #[test]
    fn resolves_calls_through_structured_module_level_bindings() {
        let project = build_python_project(
            &[
                (
                    "examples/python_structured_module_bindings/repo.py",
                    "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n",
                ),
                (
                    "examples/python_structured_module_bindings/app.py",
                    "from repo import Repo, load\n\nclass Service:\n    pass\n\nif flag:\n    cb = load\n    Service.repo = Repo()\nelse:\n    cb = load\n    Service.repo = Repo()\n\ndef handle(cmd):\n    return cb(Service.repo.run(cmd))\n",
                ),
            ],
            &["repo.load", "repo.Repo.run"],
        );
        let fg = build_flow(&project);
        let handle = project.ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .flatten()
            .collect::<Vec<_>>();
        assert!(resolved.iter().any(|name| name == "repo.load"), "missing repo.load: {resolved:?}");
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run: {resolved:?}");
    }

    #[test]
    fn resolves_calls_through_structured_module_try_imports() {
        let project = build_python_project(
            &[
                (
                    "examples/python_structured_module_try_imports/repo.py",
                    "def load(cmd):\n    return cmd\n",
                ),
                (
                    "examples/python_structured_module_try_imports/app.py",
                    "try:\n    from repo import load as cb\nexcept ImportError:\n    from repo import load as cb\n\ndef handle(cmd):\n    return cb(cmd)\n",
                ),
            ],
            &["repo.load"],
        );
        let fg = build_flow(&project);
        let handle = project.ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .flatten()
            .collect::<Vec<_>>();
        assert!(resolved.iter().any(|name| name == "repo.load"), "missing repo.load: {resolved:?}");
    }

    #[test]
    fn resolves_calls_through_constructor_init_summary_replay() {
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
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run: {resolved:?}");
    }

    #[test]
    fn resolves_calls_through_method_summary_side_effect_replay() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def install(self):
        self.repo = Repo()

    @classmethod
    def install_class(cls):
        cls.shared = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle_instance(cmd):
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)

def handle_class(cmd):
    Service.install_class()
    return Service.shared.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        for function_name in ["app.handle_instance", "app.handle_class"] {
            let function = ir.find_function_by_name(function_name).expect("function");
            let resolved = function
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter())
                .find_map(|inst| fg.resolved_internal_targets.get(&(function.id, inst.id)).cloned())
                .unwrap_or_default();
            assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run for {function_name}: {resolved:?}");
        }
    }

    #[test]
    fn tracks_constructor_identity_sites_as_distinct_roots() {
        let src = r#"
class Repo:
    def __init__(self):
        self.value = 1

def handle():
    left = Repo()
    right = Repo()
    return left, right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let constructor_dsts = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => call.dst,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(constructor_dsts.len() >= 2);
        let left_root = fg.object_identity_roots.get(&(handle.id, constructor_dsts[0])).copied();
        let right_root = fg.object_identity_roots.get(&(handle.id, constructor_dsts[1])).copied();
        assert!(left_root.is_some() && right_root.is_some());
        assert_ne!(left_root, right_root);
    }

    #[test]
    fn materializes_sparse_data_adjacency_indexes() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    cb = load
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let stats = fg.stats();
        assert!(stats.sparse_data_edges > 0);
        assert!(!fg.sparse_successors.is_empty());
        assert!(!fg.sparse_predecessors.is_empty());
    }

    #[test]
    fn sparse_reachability_walks_back_to_callable_seed() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = find_value_by_name(handle, "cb").expect("callable alias value");
        let start = fg.values.get(&(handle.id, dynamic_call)).copied().expect("start node");
        let reachable = fg.sparse_reachable_nodes(&[start], false, 8);
        assert!(reachable.iter().any(|idx| match &fg.graph[*idx] {
            FlowNode::Value { func, value } => fg.value_types.get(&(*func, *value)).is_some_and(|ty| ty == "load"),
            FlowNode::Param { func, value, .. } => fg.value_types.get(&(*func, *value)).is_some_and(|ty| ty == "load"),
            _ => false,
        }));
    }

    #[test]
    fn propagates_object_identity_across_receiver_and_return() {
        let src = r#"
class Repo:
    def __init__(self):
        self.value = 1

class Service:
    def __init__(self, repo: Repo):
        self.repo = repo

    def current(self):
        return self.repo

def handle():
    repo = Repo()
    service = Service(repo)
    current = service.current()
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let method = ir.find_function_by_name("Service.current").expect("method");
        let repo_constructor = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => call.dst,
                _ => None,
            })
            .next()
            .expect("repo dst");
        let service_constructor = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Service")) => call.dst,
                _ => None,
            })
            .next()
            .expect("service dst");
        let current_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("current")) => call.dst,
                _ => None,
            })
            .next()
            .expect("current dst");
        let repo_site = value_identity_site(&fg, handle.id, repo_constructor).map(|s| s.to_string());
        let service_site = value_identity_site(&fg, handle.id, service_constructor).map(|s| s.to_string());
        let self_param = method.params[0];
        let self_site = value_identity_site(&fg, method.id, self_param).map(|s| s.to_string());
        let current_site = value_identity_site(&fg, handle.id, current_value).map(|s| s.to_string());
        assert!(repo_site.is_some());
        assert!(service_site.is_some());
        assert_eq!(service_site, self_site);
        assert_eq!(repo_site, current_site);
    }

    #[test]
    fn demand_summary_cache_materializes_and_reuses_entries() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = find_value_by_name(handle, "cb").expect("callable alias value");
        let first = fg.demand_value_summary(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        let second = fg.demand_value_summary(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        assert_eq!(first.traversal.visited, second.traversal.visited);
        assert!(!fg.demand_summary_cache.borrow().is_empty());
    }

    #[test]
    fn demand_summary_collects_sparse_layers() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = find_value_by_name(handle, "cb").expect("callable alias value");
        let summary = fg.demand_value_summary(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        assert!(!summary.traversal.visited.is_empty());
        assert!(!summary.traversal.layers.is_empty());
        assert!(!summary.values.is_empty() || !summary.params.is_empty());
    }

    #[test]
    fn demand_reachable_values_exposes_sparse_value_hits() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = find_value_by_name(handle, "cb").expect("callable alias value");
        let reachable = fg.demand_reachable_values(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        assert!(!reachable.is_empty());
        assert!(reachable.iter().any(|(func, value)| {
            fg.value_types
                .get(&(*func, *value))
                .is_some_and(|ty| ty.contains("load"))
        }));
    }

    #[test]
    fn demand_reaches_value_detects_alias_back_edges() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    cb = load
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let load = ir.find_function_by_name("load").expect("load function");
        // Exact local callable aliases are resolved to a static target. Validate that
        // the call's actual argument still reaches the resolved formal parameter;
        // this is the interprocedural alias edge that the older dynamic-callee
        // encoding exercised indirectly.
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(&call.callee, uniflow_ir::Callee::Static(name) if name.ends_with("load")) => Some(inst.id),
                _ => None,
            })
            .expect("resolved callable alias call");
        let load_param = load.params[0];
        assert!(fg.demand_call_port_reaches_value(
            handle.id,
            call_inst,
            Port::Arg(0),
            load.id,
            load_param,
            SparseDirection::Forward,
            8,
            128,
        ));
    }

    #[test]
    fn distinct_constructor_sites_do_not_cross_bridge_projected_fields() {
        let src = r#"
class Repo:
    def __init__(self):
        self.value = 1

def handle():
    left = Repo()
    right = Repo()
    left.inner = left
    right.inner = right
    return left, right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let constructor_dsts = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => call.dst,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(constructor_dsts.len() >= 2);
        assert!(!heap_projection_values_compatible(
            &fg,
            handle.id,
            constructor_dsts[0],
            handle.id,
            constructor_dsts[1],
        ));
    }

    #[test]
    fn demand_seed_summary_cache_reuses_multi_seed_queries() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let v1 = ValueId(1);
        let v2 = ValueId(2);
        let v3 = ValueId(3);
        let n1 = fg.ensure_value(f, v1);
        let n2 = fg.ensure_value(f, v2);
        let n3 = fg.ensure_value(f, v3);
        fg.graph.add_edge(n1, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let first = fg.demand_summary_from_seeds(&[n1, n2], SparseDirection::Forward, 4, 32);
        let second = fg.demand_summary_from_seeds(&[n2, n1], SparseDirection::Forward, 4, 32);
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_seed_summary_cache.borrow().is_empty());
    }

    #[test]
    fn demand_call_summary_cache_reuses_call_queries() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    cb = load
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(&call.callee, uniflow_ir::Callee::Dynamic(_))
                        || matches!(&call.callee, uniflow_ir::Callee::Static(name) if name.ends_with("load")) => Some(inst.id),
                _ => None,
            })
            .expect("callable alias call inst");
        let first = fg
            .demand_call_summary(handle.id, inst, SparseDirection::Backward, 8, 128)
            .expect("call summary");
        let second = fg
            .demand_call_summary(handle.id, inst, SparseDirection::Backward, 8, 128)
            .expect("call summary");
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_call_summary_cache.borrow().is_empty());
    }

    #[test]
    fn loaded_field_object_preserves_identity_site() {
        let src = r#"
class Repo:
    pass

class Service:
    pass

def handle():
    repo = Repo()
    service = Service()
    service.repo = repo
    current = service.repo
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let mut repo_constructor = None;
        let mut current_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_constructor = call.dst;
                }
                uniflow_ir::InstKind::LoadField { field, dst, .. } if field == "repo" => {
                    current_value = Some(*dst);
                }
                _ => {}
            }
        }
        let repo_constructor = repo_constructor.expect("repo constructor");
        let current_value = current_value.expect("loaded field value");
        let repo_site = value_identity_site(&fg, handle.id, repo_constructor).map(|s| s.to_string());
        let current_site = value_identity_site(&fg, handle.id, current_value).map(|s| s.to_string());
        assert_eq!(repo_site, current_site);
    }

    #[test]
    fn demand_reaches_any_value_detects_one_of_multiple_targets() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let callable_alias = find_value_by_name(handle, "cb").expect("callable alias value");
        let reachable = fg.demand_reachable_values(
            handle.id,
            callable_alias,
            SparseDirection::Backward,
            8,
            128,
        );
        let real_target = reachable
            .iter()
            .copied()
            .find(|target| *target != (handle.id, callable_alias))
            .unwrap_or((handle.id, callable_alias));
        assert!(fg.demand_reaches_any_value(
            handle.id,
            callable_alias,
            &[real_target, (handle.id, ValueId(9999))],
            SparseDirection::Backward,
            8,
            128,
        ));
    }

    #[test]
    fn demand_call_port_summary_tracks_receiver_specific_queries() {
        let src = r#"
class Repo:
    pass

def use(repo):
    return repo

def handle():
    repo = Repo()
    return use(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let use_fn = ir.find_function_by_name("use").expect("use function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("use")) => Some(inst.id),
                _ => None,
            })
            .expect("use call inst");
        let summary = fg
            .demand_call_port_summary(handle.id, call_inst, Port::Arg(0), SparseDirection::Forward, 8, 128)
            .expect("call port summary");
        assert!(summary
            .params
            .iter()
            .any(|(func, index, _value)| *func == use_fn.id.0 && *index == 0));
    }

    #[test]
    fn demand_call_port_reaches_value_detects_formal_flow() {
        let src = r#"
def wrap(value):
    return value

def handle(cmd):
    return wrap(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let wrap = ir.find_function_by_name("wrap").expect("wrap function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("wrap")) => Some(inst.id),
                _ => None,
            })
            .expect("wrap call inst");
        assert!(fg.demand_call_port_reaches_value(
            handle.id,
            call_inst,
            Port::Arg(0),
            wrap.id,
            wrap.params[0],
            SparseDirection::Forward,
            8,
            128,
        ));
    }

    #[test]
    fn python_container_get_default_preserves_object_identity() {
        let src = r#"
class Repo:
    pass

def handle(cache):
    repo = Repo()
    current = cache.get("repo", repo)
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let mut repo_constructor = None;
        let mut current_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_constructor = call.dst;
                }
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.rsplit('.').next() == Some("get")) => {
                    current_value = call.dst;
                }
                _ => {}
            }
        }
        let repo_constructor = repo_constructor.expect("repo constructor");
        let current_value = current_value.expect("current value");
        let repo_site = value_identity_site(&fg, handle.id, repo_constructor).map(|s| s.to_string());
        let current_site = value_identity_site(&fg, handle.id, current_value).map(|s| s.to_string());
        assert_eq!(repo_site, current_site);
    }

    #[test]
    fn sparse_fixpoint_traversal_collapses_cycle_layers() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let n1 = fg.ensure_value(f, ValueId(1));
        let n2 = fg.ensure_value(f, ValueId(2));
        let n3 = fg.ensure_value(f, ValueId(3));
        fg.graph.add_edge(n1, n2, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n1, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let traversal = fg.sparse_fixpoint_traversal(&[n1], SparseDirection::Forward, 8, 64);
        assert_eq!(traversal.layers.len(), 2);
        assert_eq!(traversal.layers[0].len(), 2);
        assert!(traversal.layers[1].contains(&n3.index()));
    }

    #[test]
    fn demand_fixpoint_summary_cache_reuses_cycle_queries() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let n1 = fg.ensure_value(f, ValueId(1));
        let n2 = fg.ensure_value(f, ValueId(2));
        let n3 = fg.ensure_value(f, ValueId(3));
        fg.graph.add_edge(n1, n2, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n1, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let first = fg.demand_fixpoint_summary_from_seeds(&[n1], SparseDirection::Forward, 8, 64);
        let second = fg.demand_fixpoint_summary_from_seeds(&[n1], SparseDirection::Forward, 8, 64);
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_fixpoint_summary_cache.borrow().is_empty());
    }

    #[test]
    fn demand_fixpoint_call_port_summary_tracks_receiver_specific_queries() {
        let src = r#"
def sink(value):
    return value

def handle(repo, cmd):
    return repo.run(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| matches!(&inst.kind, InstKind::Call(_)).then_some(inst.id))
            .expect("call inst");
        let receiver_value = handle.params[0];
        let summary = fg
            .demand_fixpoint_call_port_summary(handle.id, call_inst, Port::Receiver, SparseDirection::Backward, 8, 128)
            .expect("fixpoint call port summary");
        assert!(summary.params.iter().any(|(func, index, value)| *func == handle.id.0 && *index == 0 && *value == receiver_value.0));
    }

    #[test]
    fn demand_fixpoint_call_port_reaches_value_detects_target_param() {
        let src = r#"
def handle(repo, cmd):
    return repo.run(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| matches!(&inst.kind, InstKind::Call(_)).then_some(inst.id))
            .expect("call inst");
        assert!(fg.demand_fixpoint_call_port_reaches_value(
            handle.id,
            call_inst,
            Port::Receiver,
            handle.id,
            handle.params[0],
            SparseDirection::Backward,
            8,
            128,
        ));
    }

    #[test]
    fn demand_query_with_heap_overlay_reaches_nested_object_values() {
        let src = r#"
class Holder:
    pass

def handle(repo):
    holder = Holder()
    holder.repo = repo
    return holder
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let holder = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call) => call.dst,
                _ => None,
            })
            .expect("holder dst");
        let plain = DemandQuery {
            seeds: vec![DemandSeed::Value {
                func: handle.id.0,
                value: holder.0,
            }],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: false,
        };
        let heap = DemandQuery {
            seeds: vec![DemandSeed::Value {
                func: handle.id.0,
                value: holder.0,
            }],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        assert!(!fg.demand_query_reaches_value(&plain, handle.id, handle.params[0], 8, 128));
        assert!(fg.demand_query_reaches_value(&heap, handle.id, handle.params[0], 8, 128));
    }

    #[test]
    fn demand_query_cache_reuses_equivalent_query_shapes() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let v1 = ValueId(1);
        let v2 = ValueId(2);
        let n1 = fg.ensure_value(f, v1);
        let n2 = fg.ensure_value(f, v2);
        fg.graph.add_edge(n1, n2, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let query = DemandQuery {
            seeds: vec![DemandSeed::Value {
                func: f.0,
                value: v1.0,
            }],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: false,
        };
        let first = fg.demand_query_summary(&query, 4, 32).expect("first query");
        let second = fg.demand_query_summary(&query, 4, 32).expect("second query");
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_query_summary_cache.borrow().is_empty());
    }

    #[test]
    fn repeated_loads_do_not_back_alias_through_cell_only_load_history() {
        let src = r#"
class Box:
    pass

def handle(repo):
    box = Box()
    box.repo = repo
    first = box.repo
    second = box.repo
    return second
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let loads = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::LoadField { field, dst, .. } if field == "repo" => Some(*dst),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(loads.len() >= 2);
        assert!(!fg.demand_reaches_value(
            handle.id,
            loads[1],
            handle.id,
            loads[0],
            SparseDirection::Backward,
            8,
            128,
        ));
    }

    #[test]
    fn strong_update_prefers_latest_unique_object_store() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle():
    box = Box()
    first = Repo()
    second = Other()
    box.item = first
    box.item = second
    current = box.item
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut first_store = None;
        let mut second_store = None;
        let mut current = None;
        let mut box_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    first_store = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    second_store = call.dst;
                }
                InstKind::LoadField { field, dst, .. } if field == "item" => {
                    current = Some(*dst);
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let first_store = first_store.expect("first store");
        let second_store = second_store.expect("second store");
        let current = current.expect("current value");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        assert!(fg.is_strong_update_cell(cell));
        assert!(fg.demand_reaches_value(
            handle.id,
            current,
            handle.id,
            second_store,
            SparseDirection::Backward,
            8,
            128,
        ));
        assert!(!fg.demand_reaches_value(
            handle.id,
            current,
            handle.id,
            first_store,
            SparseDirection::Backward,
            8,
            128,
        ));
    }

    #[test]
    fn heap_object_overlay_connects_base_cell_and_visible_value() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.item = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_value = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        let box_node = fg.values.get(&(handle.id, box_value)).copied().expect("box node");
        let repo_node = fg.values.get(&(handle.id, repo_value)).copied().expect("repo node");
        assert!(fg.heap_object_successors_of(box_node).contains(&cell));
        assert!(fg.heap_object_successors_of(cell).contains(&repo_node));
        let query = DemandQuery {
            seeds: vec![DemandSeed::Node(cell.index())],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Sparse,
            include_heap: true,
        };
        assert!(fg.demand_query_reaches_value(&query, handle.id, repo_value, 4, 64));
    }

    #[test]
    fn call_context_key_tracks_exact_callee_funcs() {
        let src = r#"
class Repo:
    pass

class Service:
    def echo(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let call = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("echo"))
            .map(|(key, _)| *key)
            .expect("call");
        let ctx = fg.call_context_key(call.0, call.1).expect("context");
        assert!(!ctx.callee_funcs.is_empty());
        let service_echo = ir.find_function_by_name("app.Service.echo").expect("callee");
        assert!(ctx.callee_funcs.iter().any(|func| *func == service_echo.id.0));
    }

    #[test]
    fn interprocedural_call_summary_tracks_exact_callee_funcs() {
        let src = r#"
class Repo:
    pass

class Service:
    def echo(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let call = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("echo"))
            .map(|(key, _)| *key)
            .expect("call");
        let summary = fg
            .interprocedural_call_summary(call.0, call.1, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("summary");
        let service_echo = ir.find_function_by_name("app.Service.echo").expect("callee");
        assert!(summary.callee_funcs.iter().any(|func| *func == service_echo.id.0));
        assert!(!summary.port_to_return.is_empty());
    }

    #[test]
    fn materialized_points_to_partitions_and_stats_are_exposed() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.item = repo
    return box.item
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_value = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        assert!(!fg.value_points_to_classes_of(handle.id, repo_value).is_empty());
        assert!(!fg.cell_points_to_classes_of(cell).is_empty());
        let stats = fg.stats();
        assert!(stats.heap_object_edges > 0);
        assert!(stats.points_to_classes > 0);
        assert!(stats.strong_update_cells > 0);
    }

    #[test]
    fn contextual_call_summary_reuses_shared_receiver_and_arg_context() {
        let src = r#"
def echo(repo):
    return repo

def handle(repo):
    first = echo(repo)
    second = echo(repo)
    return second
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_ids = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("echo")) => Some(inst.id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(call_ids.len(), 2);
        let first = fg
            .contextual_call_summary(
                handle.id,
                call_ids[0],
                ContextSensitivity::ReceiverAndArgs,
                SparseDirection::Backward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("first contextual summary");
        let second = fg
            .contextual_call_summary(
                handle.id,
                call_ids[1],
                ContextSensitivity::ReceiverAndArgs,
                SparseDirection::Backward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("second contextual summary");
        assert_eq!(fg.stats().cached_contextual_summaries, 1);
        assert_eq!(first.values, second.values);
        assert_eq!(first.params, second.params);
    }

    #[test]
    fn function_summaries_cache_param_and_return_queries() {
        let src = r#"
def echo(repo):
    return repo

def handle(repo):
    return echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let echo = ir.find_function_by_name("app.echo").expect("echo function");
        let param = fg
            .function_param_summary(
                echo.id,
                0,
                SparseDirection::Forward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("param summary");
        let ret = fg
            .function_return_summary(
                echo.id,
                SparseDirection::Backward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("return summary");
        let _ = fg.function_param_summary(
            echo.id,
            0,
            SparseDirection::Forward,
            8,
            128,
            DemandEngine::Fixpoint,
            true,
        );
        let _ = fg.function_return_summary(
            echo.id,
            SparseDirection::Backward,
            8,
            128,
            DemandEngine::Fixpoint,
            true,
        );
        assert!(fg.stats().cached_function_summaries >= 2);
        assert!(param
            .call_ports
            .iter()
            .any(|(_func, _inst, port)| port.contains("Return"))
            || param.values.iter().any(|(func, _value)| *func == echo.id.0));
        assert!(ret
            .params
            .iter()
            .any(|(func, index, _value)| *func == echo.id.0 && *index == 0)
            || ret.values.iter().any(|(func, _value)| *func == echo.id.0));
    }

    #[test]
    fn cell_write_generations_preserve_store_order() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle():
    box = Box()
    first = Repo()
    second = Other()
    box.item = first
    box.item = second
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut first_store = None;
        let mut second_store = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    first_store = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    second_store = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let first_store = first_store.expect("first store");
        let second_store = second_store.expect("second store");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        let generations = fg.cell_write_generations_of(cell);
        assert_eq!(generations.len(), 2);
        assert_eq!(generations[0], (0, handle.id, first_store));
        assert_eq!(generations[1], (1, handle.id, second_store));
        assert!(fg.stats().cell_write_generations >= 2);
    }

    #[test]
    fn load_field_only_sees_prior_visible_store() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle(flag):
    box = Box()
    first = Repo()
    box.item = first
    seen = box.item
    second = Other()
    box.item = second
    return seen
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut seen_value = None;
        let mut first_store = None;
        let mut second_store = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    first_store = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    second_store = call.dst;
                }
                InstKind::LoadField { field, dst, .. } if field == "item" => {
                    seen_value = Some(*dst);
                }
                _ => {}
            }
        }
        let seen_value = seen_value.expect("seen load dst");
        let first_store = first_store.expect("first store");
        let second_store = second_store.expect("second store");
        assert!(fg.value_may_alias(handle.id, seen_value, handle.id, first_store));
        assert!(!fg.value_may_alias(handle.id, seen_value, handle.id, second_store));
    }

    #[test]
    fn alias_queries_respect_points_to_partitions() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle():
    left = Repo()
    alias = left
    right = Other()
    box = Box()
    box.left = left
    box.right = right
    return alias
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut left = None;
        let mut alias = None;
        let mut right = None;
        let mut box_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    left = call.dst;
                }
                InstKind::Copy { dst, src } if left == Some(*src) => {
                    alias = Some(*dst);
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    right = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                _ => {}
            }
        }
        let left = left.expect("left");
        let alias = alias.expect("alias");
        let right = right.expect("right");
        let box_value = box_value.expect("box");
        assert!(fg.value_may_alias(handle.id, left, handle.id, alias));
        assert!(!fg.value_may_alias(handle.id, left, handle.id, right));
        let left_cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "left".to_string()))
            .copied()
            .expect("left cell");
        let right_cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "right".to_string()))
            .copied()
            .expect("right cell");
        assert!(!fg.cell_may_alias(left_cell, right_cell));
    }

    #[test]
    fn object_graph_materializes_labels_and_shapes() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.item = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_value = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let repo_node = *fg.values.get(&(handle.id, repo_value)).expect("repo node");
        assert!(fg.object_graph_successors_of(box_node).contains(&repo_node));
        assert_eq!(fg.object_graph_edge_label(box_node, repo_node), Some("field:item"));
        assert!(fg.object_shape_labels_of(box_node).iter().any(|label| label == "field:item"));
    }

    #[test]
    fn interprocedural_call_summary_materializes_internal_return_edges() {
        let src = r#"
def identity(repo):
    return repo

def handle(repo):
    out = identity(repo)
    return out
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| matches!(&inst.kind, InstKind::Call(_)).then_some(inst.id))
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("interprocedural summary");
        assert!(summary.port_to_return.iter().any(|port| port == "Arg(0)"));
        let mut arg_port = None;
        let mut ret_port = None;
        for ((func, inst, port), node) in &fg.call_ports {
            if *func != handle.id || *inst != call_inst {
                continue;
            }
            match port {
                Port::Arg(0) => arg_port = Some(*node),
                Port::Return => ret_port = Some(*node),
                _ => {}
            }
        }
        let arg_port = arg_port.expect("arg port");
        let ret_port = ret_port.expect("return port");
        let has_summary_edge = fg
            .graph
            .edges_directed(arg_port, Direction::Outgoing)
            .any(|edge| edge.target() == ret_port && matches!(edge.weight().kind, EdgeKind::Summary { ref rule_id } if rule_id == "internal:return"));
        assert!(has_summary_edge);
    }

    #[test]
    fn contextual_demand_query_cache_reuses_call_context() {
        let src = r#"
class Repo:
    pass

class Service:
    def run(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.run(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Dynamic(_)) || call.receiver.is_some() => Some(inst.id),
                _ => None,
            })
            .expect("call inst");
        let query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: handle.id.0, inst: call_inst.0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let first = fg
            .contextual_demand_query_summary(&query, ContextSensitivity::ReceiverAndArgs, 16, 4096)
            .expect("first summary");
        let second = fg
            .contextual_demand_query_summary(&query, ContextSensitivity::ReceiverAndArgs, 16, 4096)
            .expect("second summary");
        assert_eq!(first.values, second.values);
        assert!(!fg.contextual_demand_query_cache.borrow().is_empty());
    }

    #[test]
    fn object_shape_paths_capture_nested_fields() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Item:
    pass

def handle():
    box = Box()
    repo = Repo()
    item = Item()
    repo.item = item
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let paths = fg.object_shape_paths_of(box_node);
        assert!(paths.iter().any(|path| path == "field:repo"));
        assert!(paths.iter().any(|path| path == "field:repo.field:item"));
        assert!(fg.stats().object_shape_paths >= 2);
    }

    #[test]
    fn function_transfer_summaries_materialize_param_to_return_edges() {
        let src = r#"
def identity(repo):
    return repo
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let identity = ir.find_function_by_name("app.identity").expect("identity function");
        let param = *fg.function_params.get(&(identity.id, 0)).expect("param");
        let ret = *fg.function_returns.get(&identity.id).expect("return");
        let has_summary_edge = fg
            .graph
            .edges_directed(param, Direction::Outgoing)
            .any(|edge| edge.target() == ret && matches!(edge.weight().kind, EdgeKind::Summary { ref rule_id } if rule_id == "internal:function-return"));
        assert!(has_summary_edge);
    }

    #[test]
    fn contextual_callstring_keeps_distinct_callsites() {
        let src = r#"
class Repo:
    pass

class Service:
    def run(self, repo):
        return repo

def handle(repo):
    left = Service().run(repo)
    right = Service().run(repo)
    return right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_insts = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Dynamic(_)) || call.receiver.is_some() => Some(inst.id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(call_insts.len() >= 2);
        let left_query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: handle.id.0, inst: call_insts[0].0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let right_query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: handle.id.0, inst: call_insts[1].0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let left = fg
            .contextual_demand_query_summary(&left_query, ContextSensitivity::CallString2, 16, 4096)
            .expect("left summary");
        let right = fg
            .contextual_demand_query_summary(&right_query, ContextSensitivity::CallString2, 16, 4096)
            .expect("right summary");
        assert!(!left.traversal.seeds.is_empty());
        assert!(!right.traversal.seeds.is_empty());
        assert!(fg.contextual_demand_query_cache.borrow().len() >= 2);
    }

    #[test]
    fn recommended_context_sensitivity_prefers_receiver_args_and_callsite_for_heap_calls() {
        let query = DemandQuery {
            seeds: vec![DemandSeed::CallPort {
                func: 1,
                inst: 2,
                port: Port::Receiver,
            }, DemandSeed::CallPort {
                func: 1,
                inst: 2,
                port: Port::Arg(0),
            }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let fg = FlowGraph::default();
        assert_eq!(
            fg.recommended_context_sensitivity(&query),
            ContextSensitivity::ReceiverArgsAndCallSite
        );
    }

    #[test]
    fn solver_closure_materializes_contextual_internal_summary_edges() {
        let src = r#"
class Repo:
    pass

class Service:
    def echo(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        assert!(fg.solver_closure_iterations >= 1);
        let edge_count = fg
            .graph
            .edge_references()
            .filter(|edge| matches!(edge.weight().kind, EdgeKind::Summary { ref rule_id } if rule_id == "internal:return" || rule_id == "internal:function-return"))
            .count();
        assert!(edge_count >= 1);
    }

    #[test]
    fn call_context_key_captures_receiver_shape_paths() {
        let src = r#"
class Repo:
    def __init__(self):
        self.item = 1

class Service:
    def use(self, repo):
        return repo

def handle():
    repo = Repo()
    service = Service()
    return service.use(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let call = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("use"))
            .map(|(key, _)| *key)
            .expect("call");
        let ctx = fg.call_context_key(call.0, call.1).expect("context");
        assert!(ctx.receiver_shapes.iter().any(|shape| shape.contains("field:item")) || ctx.arg_shapes.iter().flatten().any(|shape| shape.contains("field:item")));
    }

    #[test]
    fn demand_query_summary_auto_prefers_fixpoint_for_heap_calls() {
        let query = DemandQuery {
            seeds: vec![DemandSeed::CallPort {
                func: 1,
                inst: 2,
                port: Port::Receiver,
            }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Sparse,
            include_heap: true,
        };
        let fg = FlowGraph::default();
        assert_eq!(fg.recommended_demand_engine(&query), DemandEngine::Fixpoint);
        let (max_depth, max_visits) = fg.recommended_query_limits(&query);
        assert!(max_depth >= 18);
        assert!(max_visits >= 8192);
        let plan = fg.solver_plan_for_query(&query);
        assert_eq!(plan.query.engine, DemandEngine::Fixpoint);
        assert!(matches!(plan.budget_profile, QueryBudgetProfile::Standard | QueryBudgetProfile::Deep | QueryBudgetProfile::Exhaustive));
    }

    #[test]
    fn solver_plan_auto_uses_shape_rich_context_and_exhaustive_budget() {
        let src = r#"
class Repo:
    def __init__(self):
        self.item = 1

class Service:
    def use(self, repo):
        return repo

def handle():
    repo = Repo()
    service = Service()
    return service.use(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let (func, inst) = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("use"))
            .map(|(key, _)| *key)
            .expect("call");
        let query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: func.0, inst: inst.0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Sparse,
            include_heap: true,
        };
        let plan = fg.solver_plan_for_query(&query);
        assert_eq!(plan.query.engine, DemandEngine::Fixpoint);
        assert_eq!(plan.context_sensitivity, ContextSensitivity::ReceiverArgsAndCallSite);
        assert_eq!(plan.budget_profile, QueryBudgetProfile::Exhaustive);
        assert!(plan.max_depth >= 24);
        assert!(plan.max_visits >= 16384);
    }

    #[test]
    fn points_to_fixpoint_uses_object_graph_neighbors() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            if let InstKind::Call(call) = &inst.kind {
                if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) {
                    box_value = call.dst;
                }
                if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) {
                    repo_value = call.dst;
                }
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let repo_classes = fg.value_points_to_classes_of(handle.id, repo_value);
        let box_node_classes = fg.node_points_to_classes_of(box_node);
        assert!(repo_classes.iter().any(|class| box_node_classes.contains(class)));
    }

    #[test]
    fn interprocedural_call_summary_tracks_port_to_return_values() {
        let src = r#"
class Repo:
    pass

class Service:
    def pick(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.pick(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(&call.callee, uniflow_ir::Callee::Static(name) if name.ends_with("pick"))
                        || call.receiver.is_some() => Some(inst.id),
                _ => None,
            })
            .expect("pick call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.port_to_return_values.is_empty());
        assert!(summary
            .port_to_return_values
            .iter()
            .any(|(port, _, _)| port.contains("Arg(0)") || port.contains("Receiver")));
    }

    #[test]
    fn points_to_classes_include_shape_signatures() {
        let src = r#"
class Box:
    pass

class Repo:
    def __init__(self):
        self.item = 1

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let classes = fg.value_points_to_classes_of(handle.id, box_value);
        assert!(classes.iter().any(|class| class.starts_with("shape:")));
    }

    #[test]
    fn memory_regions_materialize_for_values_and_cells() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let value_regions = fg.value_memory_regions_of(handle.id, box_value);
        assert!(!value_regions.is_empty());
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let cell_regions = fg.cell_memory_regions_of(cell);
        assert!(!cell_regions.is_empty());
        assert!(fg.stats().memory_regions > 0);
    }

    #[test]
    fn interprocedural_call_summary_tracks_heap_regions() {
        let src = r#"
class Repo:
    pass

class Service:
    def write(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.write(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.port_to_write_regions.is_empty() || !summary.port_to_return_regions.is_empty());
        let stats = fg.stats();
        assert!(stats.cached_heap_effect_summaries > 0 || stats.cached_interprocedural_summaries > 0);
    }

    #[test]
    fn cell_live_values_prefer_latest_unique_store() {
        let src = r#"
class Repo:
    pass

class Box:
    pass

def handle():
    box = Box()
    repo1 = Repo()
    repo2 = Repo()
    box.repo = repo1
    box.repo = repo2
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let mut repo_values = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => call.dst,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(repo_values.len() >= 2);
        repo_values.sort_by_key(|value| value.0);
        let latest_repo = *repo_values.last().expect("latest repo");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let live = fg.cell_live_values_of(cell);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0], (handle.id, latest_repo));
    }

    #[test]
    fn interprocedural_call_summary_tracks_return_value_regions() {
        let src = r#"
class Repo:
    pass

class Service:
    def pick(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.pick(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.return_value_regions.is_empty() || !summary.port_to_return_value_regions.is_empty());
    }

    #[test]
    fn region_graph_materializes_shared_memory_neighbors() {
        let src = r#"
class Repo:
    pass

class Box:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let succ = fg.region_graph_successors_of(box_node);
        let pred = fg.region_graph_predecessors_of(box_node);
        assert!(succ.contains(&cell) || pred.contains(&cell));
        assert!(fg.stats().region_graph_edges > 0);
    }

    #[test]
    fn live_region_state_tracks_values_from_cells() {
        let src = r#"
class Repo:
    pass

class Box:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let repo_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => call.dst,
                _ => None,
            })
            .expect("repo value");
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let region = fg
            .cell_live_regions_of(cell)
            .into_iter()
            .next()
            .or_else(|| fg.cell_memory_regions_of(cell).into_iter().next())
            .expect("region");
        let live_values = fg.region_live_values_of(&region);
        let live_cells = fg.region_live_cells_of(&region);
        assert!(live_values.contains(&(handle.id, repo_value)));
        assert!(live_cells.contains(&cell));
        assert!(fg.stats().live_region_values > 0);
        assert!(fg.stats().live_region_cells > 0);
    }

    #[test]
    fn interprocedural_call_summary_tracks_live_return_values() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.port_to_return_live_values.is_empty() || !summary.return_live_values.is_empty());
    }

    #[test]
    fn function_heap_effect_summary_tracks_relative_access_paths() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let bind = ir.find_function_by_name("app.Service.bind").expect("bind");
        let summary = fg
            .function_heap_effect_summary(bind.id, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("heap summary");
        assert!(summary.param_to_write_paths.iter().any(|(_index, path)| path == "field:repo"));
        assert!(summary.return_value_paths.iter().any(|(_func, _value, path)| path == "field:repo")
            || summary.return_paths.iter().any(|path| path == "field:repo"));
    }

    #[test]
    fn interprocedural_call_summary_tracks_relative_access_paths() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(summary.port_to_write_paths.iter().any(|(_port, path)| path == "field:repo"));
        assert!(summary.port_to_return_value_paths.iter().any(|(_port, _func, _value, path)| path == "field:repo")
            || summary.return_value_paths.iter().any(|(_func, _value, path)| path == "field:repo"));
    }

    #[test]
    fn cell_write_generations_track_transitive_interprocedural_stores() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    service.bind(repo)
    return service
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let bind = ir.find_function_by_name("app.Service.bind").expect("bind");
        let self_param = bind.params.first().copied().expect("self param");
        let cell = fg
            .field_cells
            .get(&(bind.id, self_param, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let generations = fg.cell_write_generations_of(cell);
        assert!(!generations.is_empty());
    }

    #[test]
    fn explicit_points_to_targets_materialize_and_drive_alias_queries() {
        let src = r#"
class Box:
    pass

def handle():
    left = Box()
    alias = left
    right = Box()
    left.tag = 1
    right.tag = 2
    return alias
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let left = find_value_by_name(handle, "left").expect("left");
        let alias = find_value_by_name(handle, "alias").expect("alias");
        let right = find_value_by_name(handle, "right").expect("right");
        assert!(!fg.value_points_to_targets_of(handle.id, left).is_empty());
        assert!(fg.value_must_alias(handle.id, left, handle.id, alias));
        assert!(!fg.value_may_alias(handle.id, left, handle.id, right));
    }

    #[test]
    fn function_heap_effect_summary_tracks_exact_cells() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let bind = ir.find_function_by_name("app.Service.bind").expect("bind");
        let summary = fg
            .function_heap_effect_summary(bind.id, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("heap summary");
        assert!(!summary.param_to_write_cells.is_empty());
        assert!(!summary.return_value_cells.is_empty() || !summary.return_cells.is_empty());
    }

    #[test]
    fn contextual_solver_state_tracks_return_targets() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let ctx = fg.call_context_key(handle.id, call_inst).expect("context");
        assert!(!fg.contextual_return_values_of(&ctx).is_empty());
        assert!(!fg.contextual_return_cells_of(&ctx).is_empty() || !fg.contextual_points_to_targets.get(&ctx).cloned().unwrap_or_default().is_empty());
    }

    #[test]
    fn points_to_object_ids_materialize_and_drive_alias_queries() {
        let src = r#"
class Box:
    pass

def handle():
    left = Box()
    alias = left
    right = Box()
    return alias
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let left = find_value_by_name(handle, "left").expect("left");
        let alias = find_value_by_name(handle, "alias").expect("alias");
        let right = find_value_by_name(handle, "right").expect("right");
        assert!(!fg.value_points_to_object_ids_of(handle.id, left).is_empty());
        assert!(fg.value_must_alias(handle.id, left, handle.id, alias));
        assert!(!fg.value_may_alias(handle.id, left, handle.id, right));
    }

    #[test]
    fn contextual_solver_state_materializes_per_node_object_ids() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let ctx = fg.call_context_key(handle.id, call_inst).expect("context");
        let ret_port = fg
            .call_ports
            .get(&(handle.id, call_inst, Port::Return))
            .copied()
            .expect("return port");
        assert!(!fg.contextual_node_points_to_object_ids_of(&ctx, ret_port).is_empty()
            || !fg.contextual_return_cells_of(&ctx).is_empty());
    }

    #[test]
    fn abstract_objects_materialize_for_precise_sites() {
        let src = r#"
class Box:
    pass

def handle():
    left = Box()
    return left
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let left = find_value_by_name(handle, "left").expect("left");
        let ids = fg.value_points_to_object_ids_of(handle.id, left);
        assert!(!ids.is_empty());
        assert!(ids.iter().all(|id| fg.abstract_objects.contains_key(id)));
    }

    #[test]
    fn interprocedural_call_summary_tracks_return_value_objects() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.return_value_objects.is_empty() || !summary.port_to_return_value_objects.is_empty());
    }

    #[test]
    fn contextual_function_heap_effect_summary_carries_context_metadata() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let context = fg.call_context_key(handle.id, call_inst).expect("context");
        let call_summary = fg
            .interprocedural_call_summary_with_sensitivity(handle.id, call_inst, ContextSensitivity::ReceiverArgsAndCallSite, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        let callee = call_summary.callee_funcs.first().copied().map(FunctionId).expect("callee");
        let summary = fg
            .contextual_function_heap_effect_summary(callee, &context, ContextSensitivity::ReceiverArgsAndCallSite, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("summary");
        assert!(summary.context.is_some());
        assert_eq!(summary.sensitivity, Some(ContextSensitivity::ReceiverArgsAndCallSite));
    }

    #[test]
    fn interprocedural_call_summary_with_sensitivity_records_metadata() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary_with_sensitivity(handle.id, call_inst, ContextSensitivity::CallSite, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("summary");
        assert_eq!(summary.sensitivity, Some(ContextSensitivity::CallSite));
        assert!(!summary.callee_funcs.is_empty());
    }

    #[test]
    fn contextual_function_transfer_summary_filters_to_callee_context() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(&inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let context = fg.call_context_key(handle.id, call_inst).expect("context");
        let callee = fg
            .interprocedural_call_summary_with_sensitivity(
                handle.id,
                call_inst,
                ContextSensitivity::ReceiverArgsAndCallSite,
                16,
                4096,
                DemandEngine::Fixpoint,
                true,
            )
            .and_then(|summary| summary.callee_funcs.first().copied().map(FunctionId))
            .expect("callee");
        let summary = fg
            .contextual_function_transfer_summary(
                callee,
                &context,
                ContextSensitivity::ReceiverArgsAndCallSite,
                16,
                4096,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("transfer");
        assert!(!summary.return_values.is_empty());
    }


    #[test]
    fn cpp_source_branch_reports_possible_use_after_destroy() {
        let src = r#"
struct Widget { int value; };
void consume(Widget *widget) { }
void run(int condition, Widget *widget) {
    if (condition) { delete widget; }
    consume(widget);
}
"#;
        let hir = CppParser.parse_file("branch.cpp", src).expect("parse C++");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        assert!(flow.lifetime_diagnostics.iter().any(|finding| {
            finding.rule_id == "CPP.POTENTIAL_USE_AFTER_FREE"
                && flow
                    .function_names
                    .get(&finding.function)
                    .is_some_and(|name| name.ends_with("run"))
        }));
    }

    #[test]
    fn cpp_template_calls_keep_concrete_context_identity() {
        let src = r#"
template <typename T>
T identity(T value) { return value; }
int run(int value) { return identity<int>(value); }
"#;
        let hir = CppParser.parse_file("templates.cpp", src).expect("parse C++");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        let run = ir.find_function_by_name("run").expect("run");
        let call = run.blocks.iter().flat_map(|block| block.insts.iter()).find_map(|inst| {
            match &inst.kind {
                InstKind::Call(call) if matches!(&call.callee, Callee::Static(name) if name.contains("__uniflow_tpl_int")) => Some(inst.id),
                _ => None,
            }
        }).expect("template call");
        let context = flow.call_context_key(run.id, call).expect("call context");
        assert!(context.callee_names.iter().any(|name| name.contains("__uniflow_tpl_int")));
    }


    #[test]
    fn cpp_use_after_move_is_reported_from_typed_owner_flow() {
        let src = r#"
struct Item { int value; };
void consume(Item *item) { }
void run() {
    std::unique_ptr<Item> owner = std::make_unique<Item>();
    auto moved = std::move(owner);
    consume(owner);
}
"#;
        let hir = CppParser.parse_file("move.cpp", src).expect("parse C++ move");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        assert!(flow
            .lifetime_diagnostics
            .iter()
            .any(|finding| finding.rule_id == "CPP.USE_AFTER_MOVE"));
    }

    #[test]
    fn cpp_cast_retains_target_type_in_ir() {
        let src = r#"
struct Base { int value; };
struct Derived { int value; };
Derived *run(Base *base) {
    return dynamic_cast<Derived *>(base);
}
"#;
        let hir = CppParser.parse_file("cast.cpp", src).expect("parse C++ cast");
        let ir = lower_program(&hir);
        let run = ir.find_function_by_name("run").expect("run");
        assert!(run.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| {
            matches!(
                &inst.kind,
                InstKind::Cast {
                    kind: uniflow_ir::CppCastKind::Dynamic,
                    target_type: Some(target),
                    ..
                } if target.replace(' ', "") == "Derived*"
            )
        }));
    }

    #[test]
    fn cpp_try_catch_lowers_to_typed_exception_edges() {
        let src = r#"
void run(int fail) {
    try {
        if (fail) { throw fail; }
    } catch (int error) {
        consume(error);
    }
}
"#;
        let hir = CppParser.parse_file("exceptions.cpp", src).expect("parse C++ exceptions");
        let ir = lower_program(&hir);
        let run = ir.find_function_by_name("run").expect("run");
        assert!(!run.exception_edges.is_empty());
        assert!(run
            .exception_edges
            .iter()
            .any(|edge| edge.catch_type.as_deref().is_some_and(|ty| ty.contains("int"))));
        assert!(run.blocks.iter().any(|block| matches!(&block.term, uniflow_ir::Terminator::Throw(_))));
    }

    #[test]
    fn cpp_thrown_payload_flows_into_named_catch_parameter() {
        let src = r#"
void consume(int value) { }
void run(int fail) {
    try {
        if (fail) { throw fail; }
    } catch (int error) {
        consume(error);
    }
}
"#;
        let hir = CppParser
            .parse_file("catch_payload.cpp", src)
            .expect("parse C++ catch payload");
        let ir = lower_program(&hir);
        uniflow_ir::validate_program(&ir).expect("valid IR with edge-defined catch value");
        let run = ir.find_function_by_name("run").expect("run");
        let edge = run
            .exception_edges
            .iter()
            .find(|edge| edge.thrown_value.is_some() && edge.catch_value.is_some())
            .expect("payload-binding exception edge");
        let thrown = edge.thrown_value.expect("thrown value");
        let caught = edge.catch_value.expect("catch value");

        let flow = build(&ir, &RuleSet::default());
        let src_node = flow.values[&(run.id, thrown)];
        let dst_node = flow.values[&(run.id, caught)];
        assert!(flow.graph.edges_connecting(src_node, dst_node).any(|graph_edge| {
            matches!(
                &graph_edge.weight().kind,
                EdgeKind::Summary { rule_id } if rule_id == "builtin.exception.catch"
            )
        }));
    }

    #[test]
    fn cpp_raii_scope_exit_lowers_to_destroy_event() {
        let src = r#"
struct Item { int value; };
void run() {
    std::unique_ptr<Item> owner = std::make_unique<Item>();
    consume(owner);
}
"#;
        let hir = CppParser.parse_file("raii.cpp", src).expect("parse C++ RAII");
        let ir = lower_program(&hir);
        let run = ir.find_function_by_name("run").expect("run");
        assert!(run.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| {
            matches!(
                inst.kind,
                InstKind::Lifetime {
                    event: uniflow_ir::LifetimeEvent::Destroy,
                    ..
                }
            )
        }));
    }


    #[test]
    fn cpp_pure_virtual_contract_resolves_derived_override() {
        let src = r#"
struct Base {
    virtual int read(int value) = 0;
};
struct Derived : public Base {
    int read(int value) override { return value; }
};
int run(Base *receiver, int value) {
    return receiver->read(value);
}
"#;
        let hir = CppParser.parse_file("virtual.cpp", src).expect("parse C++ virtual dispatch");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        let run = ir.find_function_by_name("run").expect("run");
        let targets = run
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| flow.resolved_internal_targets.get(&(run.id, inst.id)))
            .flatten()
            .cloned()
            .collect::<Vec<_>>();
        assert!(targets.iter().any(|target| {
            target.contains("Derived") && target.ends_with("read")
        }), "derived override was not selected: {targets:?}");
        assert!(!targets.iter().any(|target| target.contains("Base") && target.ends_with("read")),
            "pure virtual declaration must not be a concrete target: {targets:?}");
    }

    #[test]
    fn cpp_template_instance_resolves_generic_body_without_losing_context_name() {
        let src = r#"
template <typename T>
T identity(T value) { return value; }
int run(int value) { return identity<int>(value); }
"#;
        let hir = CppParser.parse_file("template_resolution.cpp", src).expect("parse C++ template");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        let run = ir.find_function_by_name("run").expect("run");
        let (inst, targets) = run
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| {
                flow.resolved_internal_targets
                    .get(&(run.id, inst.id))
                    .cloned()
                    .map(|targets| (inst.id, targets))
            })
            .expect("resolved template call");
        assert!(targets.iter().any(|target| target.ends_with("identity")),
            "generic template body was not connected: {targets:?}");
        let context = flow.call_context_key(run.id, inst).expect("template context");
        assert!(context.callee_names.iter().any(|name| name.contains("__uniflow_tpl_int")));
    }

    #[test]
    fn cpp_exception_dispatch_selects_first_compatible_catch() {
        let src = r#"
void consume(int value) { }
void run(int fail) {
    try {
        throw fail;
    } catch (float wrong) {
        consume(0);
    } catch (int error) {
        consume(error);
    } catch (...) {
        consume(-1);
    }
}
"#;
        let hir = CppParser.parse_file("catch_order.cpp", src).expect("parse catch ordering");
        let ir = lower_program(&hir);
        let run = ir.find_function_by_name("run").expect("run");
        let payload_edges = run
            .exception_edges
            .iter()
            .filter(|edge| edge.thrown_value.is_some())
            .collect::<Vec<_>>();
        assert_eq!(payload_edges.len(), 1, "known exception must select one handler");
        assert!(payload_edges[0]
            .catch_type
            .as_deref()
            .is_some_and(|ty| ty.contains("int")));
    }

    #[test]
    fn cpp_non_throwing_try_block_does_not_create_spurious_exception_edge() {
        let src = r#"
void run(int value) {
    try {
        int copy = value;
    } catch (int error) {
        value = error;
    }
}
"#;
        let hir = CppParser.parse_file("nonthrow.cpp", src).expect("parse non-throwing try");
        let ir = lower_program(&hir);
        let run = ir.find_function_by_name("run").expect("run");
        assert!(run.exception_edges.is_empty(), "plain assignments cannot throw");
    }

    #[test]
    fn cpp_borrow_from_get_is_invalidated_by_reset() {
        let src = r#"
struct Item { int value; };
void consume(Item *item) { }
void run() {
    std::unique_ptr<Item> owner = std::make_unique<Item>();
    Item *raw = owner.get();
    owner.reset(new Item());
    consume(raw);
}
"#;
        let hir = CppParser.parse_file("reset_borrow.cpp", src).expect("parse smart pointer reset");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        assert!(flow.lifetime_diagnostics.iter().any(|finding| {
            finding.rule_id == "CPP.USE_AFTER_FREE"
                && finding.message.contains("borrowed pointer")
        }));
    }

    #[test]
    fn cpp_call_exception_edge_preserves_outer_owner_and_cleans_try_local_owner() {
        let src = r#"
struct Item { int value; };
void may_throw();
void consume(Item *item) { }
void run() {
    std::unique_ptr<Item> outer = std::make_unique<Item>();
    try {
        std::unique_ptr<Item> inner = std::make_unique<Item>();
        may_throw();
    } catch (...) {
        consume(outer.get());
    }
}
"#;
        let outer_line = src
            .lines()
            .position(|line| line.contains("unique_ptr<Item> outer"))
            .map(|line| line as u32 + 1)
            .expect("outer line");
        let inner_line = src
            .lines()
            .position(|line| line.contains("unique_ptr<Item> inner"))
            .map(|line| line as u32 + 1)
            .expect("inner line");
        let hir = CppParser
            .parse_file("scoped_unwind.cpp", src)
            .expect("parse scoped unwind");
        let ir = lower_program(&hir);
        uniflow_ir::validate_program(&ir).expect("valid call-site exception IR");
        let run = ir.find_function_by_name("run").expect("run");
        let edge = run
            .exception_edges
            .iter()
            .find(|edge| {
                let Some(inst_id) = edge.source_inst else {
                    return false;
                };
                run.blocks
                    .iter()
                    .find(|block| block.id == edge.from)
                    .and_then(|block| block.insts.iter().find(|inst| inst.id == inst_id))
                    .is_some_and(|inst| {
                        matches!(
                            &inst.kind,
                            InstKind::Call(call)
                                if matches!(&call.callee, Callee::Static(name) if name.ends_with("may_throw"))
                        )
                    })
            })
            .expect("call-site exception edge");
        let cleanup_lines = edge
            .cleanup_values
            .iter()
            .filter_map(|value| run.value_spans.get(value).map(|span| span.start_line))
            .collect::<Vec<_>>();
        assert!(cleanup_lines.contains(&inner_line), "inner owner must unwind: {cleanup_lines:?}");
        assert!(!cleanup_lines.contains(&outer_line), "outer owner must survive catch: {cleanup_lines:?}");
    }

    #[test]
    fn cpp_catch_merges_outer_assignments_from_try() {
        let src = r#"
void may_throw();
void consume(int value) { }
void run(int input) {
    int result = 0;
    try {
        result = input;
        may_throw();
    } catch (...) {
        consume(result);
    }
}
"#;
        let hir = CppParser
            .parse_file("catch_environment.cpp", src)
            .expect("parse catch environment");
        let ir = lower_program(&hir);
        let run = ir.find_function_by_name("run").expect("run");
        let handler = run
            .exception_edges
            .iter()
            .find(|edge| edge.source_inst.is_some())
            .and_then(|edge| run.blocks.iter().find(|block| block.id == edge.unwind))
            .expect("catch handler");
        assert!(handler
            .insts
            .iter()
            .any(|inst| matches!(&inst.kind, InstKind::Phi { .. })),
            "catch must merge pre-try and try-updated outer variables");
    }


    #[test]
    fn cpp_weak_ptr_tracks_the_old_shared_control_block_across_reset() {
        let src = r#"
struct Item { int value; };
void consume(std::shared_ptr<Item> item) { }
void run() {
    std::shared_ptr<Item> owner = std::make_shared<Item>();
    std::shared_ptr<Item> alias = owner;
    std::weak_ptr<Item> weak = owner;
    owner.reset(new Item());
    std::shared_ptr<Item> still_old = weak.lock();
    consume(still_old);
    still_old.reset();
    alias.reset();
    std::shared_ptr<Item> expired = weak.lock();
    consume(expired);
}
"#;
        let hir = CppParser
            .parse_file("shared_generation.cpp", src)
            .expect("parse shared/weak ownership generations");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        let released = flow
            .lifetime_diagnostics
            .iter()
            .filter(|finding| finding.rule_id == "CPP.USE_AFTER_RELEASE")
            .collect::<Vec<_>>();
        assert_eq!(
            released.len(),
            1,
            "the old weak control block must remain valid while alias owns it, then expire after alias.reset(): {released:?}"
        );
    }

    #[test]
    fn cpp_unique_reset_rebinds_owner_without_reviving_old_borrows() {
        let src = r#"
struct Item { int value; };
void consume(Item *item) { }
void run() {
    std::unique_ptr<Item> owner = std::make_unique<Item>();
    Item *old = owner.get();
    owner.reset(new Item());
    Item *fresh = owner.get();
    consume(old);
    consume(fresh);
}
"#;
        let hir = CppParser
            .parse_file("unique_generation.cpp", src)
            .expect("parse unique reset generations");
        let ir = lower_program(&hir);
        let flow = build(&ir, &RuleSet::default());
        let dangling = flow
            .lifetime_diagnostics
            .iter()
            .filter(|finding| {
                finding.rule_id == "CPP.USE_AFTER_FREE"
                    && finding.message.contains("borrowed pointer")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            dangling.len(),
            1,
            "only the borrow from the replaced object should be invalid: {dangling:?}"
        );
    }


}
