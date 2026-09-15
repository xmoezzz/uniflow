//! Swift calls into imported C ABI functions.
//!
//! A Clang module or bridging header imports a C function into Swift as a
//! directly callable name (`native_sink(value)`). There is no runtime FFI
//! object in that shape. This adapter bridges only a bare static Swift call
//! whose symbol has exactly one project-local global C/C++ implementation;
//! qualified Swift type/member calls deliberately remain outside this model.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, InstKind, Program};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};

fn native_functions(programs: &[(Language, Program)]) -> HashMap<String, Vec<(Language, String, usize)>> {
    let mut out = HashMap::<String, Vec<(Language, String, usize)>>::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            if function.name.contains("::") || function.is_external {
                continue;
            }
            out.entry(function.name.clone())
                .or_default()
                .push((language.clone(), function.name.clone(), function.params.len()));
        }
    }
    out
}

/// Recovers direct calls to an imported C ABI symbol from Swift into one
/// proven native implementation. The source call site is preserved so bridge
/// rules never conflate two same-symbol calls in the same Swift function.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::Swift {
            continue;
        }
        for function in &program.functions {
            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(symbol) = &call.callee else { continue };
                    // A C importer exposes a global C function by a bare
                    // name. A dotted symbol is a Swift module/type/member
                    // call and must not be inferred as C ABI merely because
                    // its last component resembles a native symbol.
                    if symbol.contains('.') || symbol.contains("::") {
                        continue;
                    }
                    let Some(candidates) = native.get(symbol) else { continue };
                    let [candidate] = candidates.as_slice() else { continue };
                    let (native_language, native_function, native_arity) = candidate;
                    let call_id = format!("code:swift:{}#{}", function.name, inst.id.0);
                    let native_id = format!("code:{}:{native_function}", native_language.as_str());
                    graph.upsert_node(
                        SystemNode::new(NodeKind::CallSite, call_id.clone(), symbol).with_code_ref(CodeRef {
                            language: Language::Swift,
                            qualified_name: function.name.clone(),
                        }),
                    );
                    graph.upsert_node(
                        SystemNode::new(NodeKind::Function, native_id.clone(), native_function).with_code_ref(CodeRef {
                            language: native_language.clone(),
                            qualified_name: native_function.clone(),
                        }),
                    );
                    graph.apply_boundary(
                        BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), native_id.clone(), Confidence::Exact)
                            .with_evidence(Evidence::new(format!(
                                "{} invokes unique C ABI symbol {symbol:?} imported into Swift",
                                function.name
                            ))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!(
                            "Swift imported-C call {symbol:?} has positional ABI argument mapping"
                        )));
                    for index in 0..call.args.len().min(*native_arity) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(Language::Swift, function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!(
                                "Swift C-ABI positional argument {index} maps to native parameter {index}"
                            ))),
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
    use uniflow_rules::{CallSiteSinkRule, FunctionMatcher, FunctionSourceRule, RuleSet};

    fn lower_swift(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(Language::Swift, "Probe.swift", source).expect("parse Swift");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_c(source: &str) -> Program {
        let hir = uniflow_lang_c::CParser::default()
            .parse_file("native.c", source)
            .expect("parse C");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn a_bare_swift_imported_c_call_bridges_to_a_unique_native_function() {
        let swift = lower_swift("func run(_ input: String) { native_sink(input) }");
        let c = lower_c("void native_sink(char *value) {}");
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::Swift, swift), (Language::C, c)]).expect("discover Swift bridge");
        let mapping = &graph
            .edges()
            .find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg)
            .expect("interop argument edge")
            .2
            .value_mappings[0];
        assert_eq!(mapping.from.language, Language::Swift);
        assert_eq!(mapping.from.function, "run");
        assert_eq!(mapping.to.function, "native_sink");
    }

    #[test]
    fn a_qualified_swift_call_is_not_inferred_as_a_c_abi_boundary() {
        let swift = lower_swift("func run(_ input: String) { Wrapper.native_sink(input) }");
        let c = lower_c("void native_sink(char *value) {}");
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::Swift, swift), (Language::C, c)]).expect("discover Swift bridge");
        assert!(graph.edges().all(|(_, _, edge)| edge.kind != EdgeKind::InteropArg));
    }

    #[test]
    fn swift_function_source_reaches_an_instruction_anchored_native_call_port() {
        let swift = lower_swift("func run(_ input: String) { native_sink(input) }");
        let function = swift.functions.iter().find(|function| function.name == "run").expect("Swift run function");
        let inst_id = function
            .blocks
            .iter()
            .flat_map(|block| &block.insts)
            .find(|inst| matches!(inst.kind, InstKind::Call(_)))
            .expect("native call")
            .id
            .0;
        let rules = RuleSet {
            function_sources: vec![FunctionSourceRule {
                id: "swift-source".to_string(),
                language: Some(Language::Swift),
                matcher: FunctionMatcher { exact: Some("run".to_string()), ..Default::default() },
                out: Port::Arg(0),
                kind: "untrusted".to_string(),
            }],
            call_site_sinks: vec![CallSiteSinkRule {
                id: "native-boundary".to_string(),
                language: Some(Language::Swift),
                function: "run".to_string(),
                inst_id,
                inputs: vec![Port::Arg(0)],
                kind: "untrusted".to_string(),
            }],
            ..RuleSet::default()
        };
        let flow = uniflow_value_flow::build(&swift, &rules);
        let findings = uniflow_taint::analyze(&flow, &rules);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].source_rule_id, "swift-source");
        assert_eq!(findings[0].sink_rule_id, "native-boundary");
    }
}
