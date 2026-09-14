//! Lifecycle/framework entrypoint adapter: recognizes a call to a
//! registration marker (matched by method-name convention — see
//! [`LIFECYCLE_MARKERS`]) whose argument is a callable value, and represents
//! the resolved target as a runtime-triggered [`NodeKind::Entrypoint`]
//! rather than requiring an ordinary source-level `CALL` edge from `main()`.
//!
//! No engine change is needed for this: UniFlow's taint engine already
//! analyzes every function's own body and applies rule-based sources/sinks
//! per function regardless of call-graph reachability from a `Program`'s
//! `entry_points` (`entry_points` is bookkeeping consumed only by IR
//! validation, never a scan filter — confirmed against
//! `build_for_scan_with_progress`/`static_taint_scan_function_slice`, which
//! iterate every function unconditionally). This module's job is purely to
//! make the *reason* a function is reachable (a framework lifecycle
//! trigger, not a source-level caller) visible in the system graph.

use anyhow::Result;

use uniflow_ir::{Callee, InstKind, Program};

use crate::graph::{BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, NodeKind, SystemEdge, SystemGraph, SystemNode};
use crate::ir_utils::{is_python_root_alias, resolve_callable_argument};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleKind {
    Startup,
    Shutdown,
    Scheduled,
}

impl LifecycleKind {
    fn edge_kind(self) -> EdgeKind {
        match self {
            LifecycleKind::Startup => EdgeKind::Startup,
            LifecycleKind::Shutdown => EdgeKind::Shutdown,
            LifecycleKind::Scheduled => EdgeKind::Triggers,
        }
    }

    fn node_kind(self) -> NodeKind {
        match self {
            LifecycleKind::Startup | LifecycleKind::Shutdown => NodeKind::LifecycleEvent,
            LifecycleKind::Scheduled => NodeKind::ScheduledTask,
        }
    }

    fn label(self) -> &'static str {
        match self {
            LifecycleKind::Startup => "startup",
            LifecycleKind::Shutdown => "shutdown",
            LifecycleKind::Scheduled => "scheduled",
        }
    }
}

/// Method-name conventions recognized as a lifecycle registration call —
/// matched on the callee's final `.`-segment, so `app.onStartup(fn)`,
/// `Runtime.onStartup(fn)`, and a bare `onStartup(fn)` all match alike.
/// Extending this table (or a future adapter that scans a real
/// `@PostConstruct`/`@PreDestroy`-style annotation instead) is the expected
/// way to support a specific framework's actual convention.
const LIFECYCLE_MARKERS: &[(&str, LifecycleKind)] = &[
    ("onStartup", LifecycleKind::Startup),
    ("addStartupHook", LifecycleKind::Startup),
    ("onShutdown", LifecycleKind::Shutdown),
    ("addShutdownHook", LifecycleKind::Shutdown),
    ("schedule", LifecycleKind::Scheduled),
    ("scheduleAtFixedRate", LifecycleKind::Scheduled),
];

fn method_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

/// Spring's real startup/shutdown convention: an annotation on the hook
/// method itself, not a registration call — the framework invokes it
/// directly, so there is no call site to scan for. Reuses the same
/// `java.annotations.raw` attribute `crate::http`'s Spring route recognizer
/// reads, the same "annotation IS the registration" shape as a
/// Python/Flask route decorator.
const SPRING_LIFECYCLE_ANNOTATIONS: &[(&str, LifecycleKind)] =
    &[("postconstruct", LifecycleKind::Startup), ("predestroy", LifecycleKind::Shutdown)];

fn spring_lifecycle_annotation(function: &uniflow_ir::Function) -> Option<LifecycleKind> {
    let raw = function.attrs.get("java.annotations.raw")?;
    raw.split('\u{1f}').find_map(|annotation| {
        let name = annotation.trim().trim_start_matches('@').split('(').next()?.to_ascii_lowercase();
        SPRING_LIFECYCLE_ANNOTATIONS.iter().find(|(marker, _)| *marker == name).map(|&(_, kind)| kind)
    })
}

/// FastAPI/Starlette's traditional lifecycle form is a decorator on the
/// handler itself: `@app.on_event("startup")` or `@app.on_event("shutdown")`.
/// The Python frontend already retains literal decorator spellings for route
/// discovery; consume the same durable metadata rather than treating a
/// decorator as an ordinary source-level call.
fn python_lifecycle_decorator(function: &uniflow_ir::Function) -> Option<LifecycleKind> {
    let raw = function.attrs.get("python.decorators.raw")?;
    raw.split('\u{1f}').find_map(|decorator| {
        let text = decorator.trim().trim_start_matches('@').trim();
        let (callee, args) = text.split_once('(')?;
        if callee.rsplit('.').next()? != "on_event" {
            return None;
        }
        let first = args.strip_suffix(')')?.split(',').next()?.trim();
        let quote = first.chars().next()?;
        if !matches!(quote, '\'' | '"') || !first.ends_with(quote) || first.len() < 2 {
            return None;
        }
        match &first[1..first.len() - 1] {
            "startup" => Some(LifecycleKind::Startup),
            "shutdown" => Some(LifecycleKind::Shutdown),
            _ => None,
        }
    })
}

fn add_annotation_lifecycle_entrypoint(
    graph: &mut SystemGraph,
    program: &Program,
    function: &uniflow_ir::Function,
    kind: LifecycleKind,
    evidence: String,
) -> Result<()> {
    let language_tag = program.language.as_str();
    let event_id = format!("lifecycle:{}:{language_tag}:{}", kind.label(), function.name);
    graph.upsert_node(SystemNode::new(kind.node_kind(), event_id.clone(), kind.label()));
    let handler_id = format!("code:{language_tag}:{}", function.name);
    graph.upsert_node(
        SystemNode::new(NodeKind::Entrypoint, handler_id.clone(), &function.name).with_code_ref(CodeRef {
            language: program.language.clone(),
            qualified_name: function.name.clone(),
        }),
    );
    graph.apply_boundary(
        BoundarySummary::new(kind.edge_kind(), event_id, handler_id, Confidence::Exact).with_evidence(Evidence::new(evidence)),
    )
}

fn ensure_function_node(graph: &mut SystemGraph, program: &Program, qualified_name: &str) {
    if !graph.contains(qualified_name) {
        graph.upsert_node(
            SystemNode::new(NodeKind::Function, qualified_name, qualified_name).with_code_ref(CodeRef {
                language: program.language.clone(),
                qualified_name: qualified_name.to_string(),
            }),
        );
    }
}

/// Scans every function in `program` for a lifecycle registration call and
/// records the resolved handler as a runtime-triggered entrypoint.
pub fn discover_into(graph: &mut SystemGraph, program: &Program) -> Result<()> {
    let language_tag = program.language.as_str();
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        if let Some(kind) = spring_lifecycle_annotation(function) {
            add_annotation_lifecycle_entrypoint(
                graph,
                program,
                function,
                kind,
                format!("{} is annotated as a Spring {} lifecycle hook", function.name, kind.label()),
            )?;
        }
        if let Some(kind) = python_lifecycle_decorator(function) {
            add_annotation_lifecycle_entrypoint(
                graph,
                program,
                function,
                kind,
                format!("{} declares a literal FastAPI/Starlette {} lifecycle event", function.name, kind.label()),
            )?;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                let Some(&(_, kind)) =
                    LIFECYCLE_MARKERS.iter().find(|(marker, _)| method_name(name) == *marker)
                else {
                    continue;
                };
                // The handler is whichever argument resolves to a callable
                // value; a marker's other arguments (e.g. a delay/interval)
                // are plain data, not callables, and simply won't resolve.
                let Some(handler_name) =
                    call.args.iter().find_map(|&arg| resolve_callable_argument(program, function, arg))
                else {
                    continue;
                };

                ensure_function_node(graph, program, &function.name);
                let event_id = format!("lifecycle:{}:{language_tag}:{}#{}", kind.label(), function.name, inst.id.0);
                graph.upsert_node(SystemNode::new(kind.node_kind(), event_id.clone(), kind.label()));
                let handler_id = format!("code:{language_tag}:{handler_name}");
                graph.upsert_node(
                    SystemNode::new(NodeKind::Entrypoint, handler_id.clone(), &handler_name).with_code_ref(CodeRef {
                        language: program.language.clone(),
                        qualified_name: handler_name.clone(),
                    }),
                );

                graph.add_edge(&function.name, &event_id, SystemEdge::new(EdgeKind::RegistersHandler, Confidence::Exact))?;
                graph.apply_boundary(
                    BoundarySummary::new(kind.edge_kind(), event_id, handler_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!(
                            "{} registers {} as a {} hook",
                            function.name,
                            handler_name,
                            kind.label()
                        ))),
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn lower_java(source: &str) -> Program {
        let hir = uniflow_lang_java::JavaParser::default().parse_file("Probe.java", source).expect("parse java");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_python(source: &str) -> Program {
        let hir = uniflow_lang_python::PythonParser::default().parse_file("app.py", source).expect("parse python");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn recognizes_a_startup_hook_registered_via_method_reference() {
        let program = lower_java(
            r#"
class App {
    static void main() {
        onStartup(App::initialize);
    }
    static void initialize() {}
    static void onStartup(Runnable fn) {}
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &program).expect("discover lifecycle hooks");

        let triggers: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Startup).collect();
        assert_eq!(triggers.len(), 1, "{triggers:?}");
        assert_eq!(triggers[0].1.name, "App.initialize");
        assert!(!EdgeKind::Startup.carries_data_flow());

        let registers: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::RegistersHandler).collect();
        assert_eq!(registers.len(), 1, "{registers:?}");
        assert_eq!(registers[0].0.id, "App.main");
    }

    #[test]
    fn recognizes_spring_postconstruct_and_predestroy_annotations() {
        let program = lower_java(
            r#"
class Service {
    @PostConstruct
    void init() {}

    @PreDestroy
    void cleanup() {}

    void unrelated() {}
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &program).expect("discover lifecycle hooks");

        let startups: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Startup).collect();
        assert_eq!(startups.len(), 1, "{startups:?}");
        assert_eq!(startups[0].1.name, "Service.init");

        let shutdowns: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Shutdown).collect();
        assert_eq!(shutdowns.len(), 1, "{shutdowns:?}");
        assert_eq!(shutdowns[0].1.name, "Service.cleanup");
    }

    #[test]
    fn an_unannotated_method_produces_no_lifecycle_event() {
        let program = lower_java(
            r#"
class Service {
    void ordinary() {}
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &program).expect("discover lifecycle hooks");
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Startup || edge.kind == EdgeKind::Shutdown).count(), 0);
    }

    #[test]
    fn recognizes_literal_fastapi_startup_and_shutdown_decorators() {
        let program = lower_python(
            r#"
@app.on_event("startup")
def initialize():
    pass

@app.on_event("shutdown")
def cleanup():
    pass

@app.on_event(event_name)
def dynamic_event():
    pass
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &program).expect("discover lifecycle hooks");
        let startups: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Startup).collect();
        let shutdowns: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Shutdown).collect();
        assert_eq!(startups.len(), 1, "{startups:?}");
        assert_eq!(shutdowns.len(), 1, "{shutdowns:?}");
        assert_eq!(startups[0].1.name, "initialize");
        assert_eq!(shutdowns[0].1.name, "cleanup");
    }
}
