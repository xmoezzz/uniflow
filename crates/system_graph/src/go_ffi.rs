//! Go-to-native boundary recovery for cgo, Go's own FFI mechanism.
//!
//! Two directions, both recognized purely from already-lowered IR (no
//! Go-frontend-side attribute needed for the first — `C.foo(...)` already
//! lowers to an ordinary qualified call `CallTarget::Named("C.foo")` via the
//! same import-qualifier machinery any other package selector uses, since
//! cgo's `import "C"` is, from the frontend's perspective, just an import
//! whose path text is the literal string `"C"`):
//!
//! 1. **Go calling into C** (`C.foo(...)`, after `import "C"`): mirrors
//!    `crate::python_ffi`'s exact conservatism — bridges only when exactly
//!    one global C/C++ function in the scan has that literal symbol name.
//! 2. **C calling into Go** (a `//export Foo` comment directly above a Go
//!    function definition, cgo's marker for "callable from C when this
//!    package is built as `-buildmode=c-archive`/`c-shared`"): the Go
//!    frontend (`uniflow_lang_go::frontend::decl::cgo_export_marker`) records
//!    this as the function-symbol attribute `go.cgo.export`, forwarded onto
//!    `uniflow_ir::Function::attrs` the same way `java.annotations.raw`/
//!    `python.ffi.calls` already are (see
//!    `uniflow_lowering::lowerer::entry`'s attribute-forwarding allowlist).
//!    Marked here as a real [`NodeKind::Entrypoint`] reachable from a
//!    synthetic "external C caller" node — the same shape
//!    `crate::lifecycle` uses for a Spring `@PostConstruct` hook reachable
//!    with no ordinary source-level call site.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, InstKind, Program};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};

const CGO_IMPORT_QUALIFIER: &str = "C";

fn native_functions(programs: &[(Language, Program)]) -> HashMap<String, Vec<(Language, String, usize)>> {
    let mut out: HashMap<String, Vec<(Language, String, usize)>> = HashMap::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            if function.name.contains("::") || function.is_external {
                continue;
            }
            out.entry(function.name.clone()).or_default().push((language.clone(), function.name.clone(), function.params.len()));
        }
    }
    out
}

fn external_c_caller_node_id() -> &'static str {
    "ffi:cgo:external-c-caller"
}

/// Discovers `C.foo(...)` call sites resolving to exactly one native C/C++
/// function in the scan, and `//export`-marked Go functions reachable from
/// an external C caller.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::Go {
            continue;
        }
        for function in &program.functions {
            if function.attrs.get("go.cgo.export").map(String::as_str) == Some("true") {
                let handler_id = format!("code:{}:{}", language.as_str(), function.name);
                graph.upsert_node(
                    SystemNode::new(NodeKind::Entrypoint, handler_id.clone(), &function.name).with_code_ref(CodeRef {
                        language: language.clone(),
                        qualified_name: function.name.clone(),
                    }),
                );
                graph.upsert_node(
                    SystemNode::new(NodeKind::AbstractObject, external_c_caller_node_id(), "external C caller (cgo //export)")
                        .with_attr("ffi_external_caller", "true"),
                );
                graph.apply_boundary(
                    BoundarySummary::new(EdgeKind::InteropCall, external_c_caller_node_id(), handler_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!("{} is marked //export, callable from C when built as a cgo archive/shared library", function.name))),
                )?;
            }

            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(callee) = &call.callee else { continue };
                    let Some(symbol) = callee.strip_prefix(CGO_IMPORT_QUALIFIER).and_then(|rest| rest.strip_prefix('.')) else { continue };
                    let Some(candidates) = native.get(symbol) else { continue };
                    let [candidate] = candidates.as_slice() else { continue };
                    let (native_language, native_function, native_arity) = candidate;

                    let call_id = format!("code:{}:{}#{}", language.as_str(), function.name, inst.id.0);
                    let native_id = format!("code:{}:{native_function}", native_language.as_str());
                    graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_id.clone(), callee).with_code_ref(CodeRef {
                        language: language.clone(),
                        qualified_name: function.name.clone(),
                    }));
                    graph.upsert_node(SystemNode::new(NodeKind::Function, native_id.clone(), native_function).with_code_ref(CodeRef {
                        language: native_language.clone(),
                        qualified_name: native_function.clone(),
                    }));
                    graph.apply_boundary(
                        BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), native_id.clone(), Confidence::Exact)
                            .with_evidence(Evidence::new(format!("{} invokes cgo symbol {symbol:?}, uniquely resolving to {native_function}", function.name))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!("{} invokes literal cgo symbol {symbol:?}", function.name)));
                    for index in 0..call.args.len().min(*native_arity) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!("cgo positional argument {index} maps to native parameter {index}"))),
                        );
                    }
                    graph.apply_boundary(summary)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn lower_go(source: &str) -> Program {
        let hir = uniflow_lang_go::GoParser::default().parse_file("main.go", source).expect("parse go");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_c(source: &str) -> Program {
        let hir = uniflow_lang_c::CParser::default().parse_file("native.c", source).expect("parse c");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn a_cgo_call_bridges_to_its_unique_native_c_function() {
        let go_program = lower_go(
            r#"
package main

// #include <stdlib.h>
import "C"

func run(userInput string) {
	C.native_sink(userInput)
}
"#,
        );
        let c_program = lower_c("void native_sink(char *value) {}");
        let mut graph = SystemGraph::new();
        let programs = vec![(Language::Go, go_program), (Language::C, c_program)];
        discover_into(&mut graph, &programs).expect("discover cgo boundary");

        let interop_args: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).collect();
        assert_eq!(interop_args.len(), 1, "{interop_args:?}");
        assert_eq!(interop_args[0].1.code_ref.as_ref().map(|c| c.qualified_name.as_str()), Some("native_sink"));
        assert_eq!(interop_args[0].2.value_mappings.len(), 1);
    }

    #[test]
    fn an_export_marked_function_becomes_an_entrypoint_reachable_from_an_external_c_caller() {
        let go_program = lower_go(
            r#"
package main

//export GoCallback
func GoCallback(userInput string) {
	sink(userInput)
}

func sink(value string) {}
"#,
        );
        let mut graph = SystemGraph::new();
        let programs = vec![(Language::Go, go_program)];
        discover_into(&mut graph, &programs).expect("discover cgo boundary");

        assert!(graph.contains("code:go:main.GoCallback"));
        let interop_calls: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::InteropCall).collect();
        assert_eq!(interop_calls.len(), 1, "{interop_calls:?}");
        assert_eq!(interop_calls[0].1.code_ref.as_ref().map(|c| c.qualified_name.as_str()), Some("main.GoCallback"));
        let ingress = crate::bridge::handler_source_rules(&graph, &Language::Go);
        assert_eq!(ingress.function_sources.len(), 1, "{:?}", ingress.function_sources);
        assert_eq!(ingress.function_sources[0].matcher.exact.as_deref(), Some("main.GoCallback"));
        assert_eq!(ingress.function_sources[0].out, Port::ArgsFrom(0));
    }
}
