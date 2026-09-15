//! Objective-C/Objective-C++ calls into C ABI functions.
//!
//! Objective-C intentionally has no separate FFI spelling for a C function:
//! `native_sink(value)` inside a `.m`/`.mm` translation unit is already a C
//! ABI call.  The adapter therefore bridges only an IR static call whose
//! exact, unqualified symbol resolves to exactly one global C/C++ definition
//! in the same analyzed system. Objective-C message sends are represented by
//! different frontend call shapes/names and never qualify merely by sharing a
//! method-like spelling.

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
            // A namespaced C++ member is not a plain C ABI symbol. External
            // declarations are likewise not an implementation we can prove
            // belongs to this system.
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

/// Recovers direct C ABI calls from Objective-C/Objective-C++ into a unique
/// native C/C++ implementation. Each mapping is instruction-anchored, so two
/// calls to the same C symbol in one Objective-C method remain distinct.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if !matches!(language, Language::ObjC | Language::ObjCpp) {
            continue;
        }
        for function in &program.functions {
            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(symbol) = &call.callee else { continue };
                    if symbol.contains("::") {
                        continue;
                    }
                    let Some(candidates) = native.get(symbol) else { continue };
                    let [candidate] = candidates.as_slice() else { continue };
                    let (native_language, native_function, native_arity) = candidate;
                    let call_id = format!("code:{}:{}#{}", language.as_str(), function.name, inst.id.0);
                    let native_id = format!("code:{}:{native_function}", native_language.as_str());
                    graph.upsert_node(
                        SystemNode::new(NodeKind::CallSite, call_id.clone(), symbol).with_code_ref(CodeRef {
                            language: language.clone(),
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
                                "{} invokes unique global C ABI symbol {symbol:?}",
                                function.name
                            ))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!(
                            "Objective-C direct C call {symbol:?} has positional ABI argument mapping"
                        )));
                    for index in 0..call.args.len().min(*native_arity) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!(
                                "Objective-C C-ABI positional argument {index} maps to native parameter {index}"
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

    fn lower_objc(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(Language::ObjC, "Probe.m", source).expect("parse Objective-C");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_objcpp(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(Language::ObjCpp, "Probe.mm", source).expect("parse Objective-C++");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_c(source: &str) -> Program {
        let hir = uniflow_lang_c::CParser::default()
            .parse_file("native.c", source)
            .expect("parse C");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn direct_objective_c_call_bridges_to_a_unique_c_abi_function() {
        let objc = lower_objc("void run(char *input) { native_sink(input); }");
        let c = lower_c("void native_sink(char *value) {}");
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::ObjC, objc), (Language::C, c)]).expect("discover Objective-C bridge");
        let edge = graph
            .edges()
            .find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg)
            .expect("interop argument edge");
        assert_eq!(edge.2.value_mappings.len(), 1, "{:#?}", edge.2.value_mappings);
        assert_eq!(edge.2.value_mappings[0].from.language, Language::ObjC);
        assert_eq!(edge.2.value_mappings[0].from.function, "run");
        assert_eq!(edge.2.value_mappings[0].to.function, "native_sink");
        assert_eq!(edge.2.value_mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn ambiguous_native_symbol_is_not_connected() {
        let objc = lower_objc("void run(char *input) { native_sink(input); }");
        let c = lower_c("void native_sink(char *value) {}");
        let second_c = lower_c("void native_sink(char *value) {}");
        let mut graph = SystemGraph::new();
        discover_into(
            &mut graph,
            &[(Language::ObjC, objc), (Language::C, c), (Language::C, second_c)],
        )
        .expect("discover Objective-C bridge");
        assert!(graph.edges().all(|(_, _, edge)| edge.kind != EdgeKind::InteropArg));
    }

    #[test]
    fn direct_objective_cpp_call_keeps_its_own_language_boundary() {
        let objcpp = lower_objcpp("void run(char *input) { native_sink(input); }");
        let c = lower_c("void native_sink(char *value) {}");
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::ObjCpp, objcpp), (Language::C, c)]).expect("discover Objective-C++ bridge");
        let mapping = &graph
            .edges()
            .find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg)
            .expect("interop argument edge")
            .2
            .value_mappings[0];
        assert_eq!(mapping.from.language, Language::ObjCpp);
        assert_eq!(mapping.to.language, Language::C);
    }
}
