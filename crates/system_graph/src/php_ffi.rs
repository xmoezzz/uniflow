//! PHP-to-native boundary recovery for literal `FFI::cdef` declarations.
//!
//! PHP FFI exposes C functions through a runtime handle (`$ffi->symbol(...)`),
//! but a literal `FFI::cdef("... prototype ...", "library")` makes that ABI
//! relationship statically observable. The PHP frontend records only those
//! literal declarations as `php.ffi.bindings`; this adapter joins an invoked
//! symbol to exactly one global C/C++ implementation and emits the same
//! argument-to-parameter bridge used by ctypes/cffi and cgo adapters.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, InstKind, Program};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};
use crate::ir_utils::is_python_root_alias;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    alias: String,
    symbol: String,
    library: String,
}

fn bindings(function: &uniflow_ir::Function) -> Vec<Binding> {
    function
        .attrs
        .get("php.ffi.bindings")
        .into_iter()
        .flat_map(|raw| raw.split('\u{1f}'))
        .filter_map(|item| {
            let mut fields = item.split('\u{1e}');
            Some(Binding {
                alias: fields.next()?.to_string(),
                symbol: fields.next()?.to_string(),
                library: fields.next()?.to_string(),
            })
        })
        .collect()
}

fn native_functions(programs: &[(Language, Program)]) -> HashMap<String, Vec<(Language, String, usize)>> {
    let mut out = HashMap::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            if function.name.contains("::") || function.is_external {
                continue;
            }
            out.entry(function.name.clone())
                .or_insert_with(Vec::new)
                .push((language.clone(), function.name.clone(), function.params.len()));
        }
    }
    out
}

/// Discovers a PHP call only when its bare called symbol has one matching
/// literal cdef binding in the scanned PHP program and exactly one matching
/// C/C++ implementation. The generic PHP descriptor does not retain a
/// reliable receiver identity for `$ffi->symbol`, so two handles declaring
/// the same symbol are treated as ambiguous rather than choosing one.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::Php {
            continue;
        }
        let declared = program.functions.iter().flat_map(bindings).collect::<Vec<_>>();
        for function in &program.functions {
            if is_python_root_alias(program, function) {
                continue;
            }
            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(callee) = &call.callee else { continue };
                    let symbol = callee.rsplit('.').next().unwrap_or(callee);
                    let candidates = declared
                        .iter()
                        .filter(|binding| binding.symbol == symbol)
                        .collect::<Vec<_>>();
                    let [binding] = candidates.as_slice() else { continue };
                    let Some(native_candidates) = native.get(symbol) else { continue };
                    let [native] = native_candidates.as_slice() else { continue };
                    let (native_language, native_function, native_arity) = native;

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
                            .with_evidence(Evidence::new(format!(
                                "{} calls PHP FFI symbol {symbol:?} declared by literal FFI::cdef for {:?}",
                                function.name, binding.library
                            ))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!("PHP FFI symbol {symbol:?} resolves uniquely to {native_function}")));
                    for index in 0..call.args.len().min(*native_arity) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!("PHP FFI positional argument {index} maps to native parameter {index}"))),
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

    fn lower_c(source: &str) -> Program {
        let hir = uniflow_lang_c::CParser::default().parse_file("native.c", source).expect("parse C");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_php(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(Language::Php, "bridge.php", source).expect("parse PHP");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn maps_a_literal_php_cdef_call_to_its_unique_c_function() {
        let native = lower_c("void native_sink(char *value) { sink(value); }");
        let php = lower_php(
            r#"<?php
function forward($input) {
  $ffi = FFI::cdef("void native_sink(char *value);", "libnative.so");
  $ffi->native_sink($input);
}
?>"#,
        );
        let programs = vec![(Language::C, native), (Language::Php, php)];
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover PHP FFI");
        let edge = graph
            .edges()
            .find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg)
            .expect("PHP FFI argument edge");
        assert_eq!(edge.2.value_mappings.len(), 1, "{:#?}", edge.2.value_mappings);
        assert_eq!(edge.2.value_mappings[0].to.function, "native_sink");
        assert_eq!(edge.2.value_mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn refuses_a_php_symbol_declared_by_multiple_ffi_handles() {
        let native = lower_c("void native_sink(char *value) { sink(value); }");
        let php = lower_php(
            r#"<?php
function forward($input) {
  $one = FFI::cdef("void native_sink(char *value);", "one.so");
  $two = FFI::cdef("void native_sink(char *value);", "two.so");
  $one->native_sink($input);
}
?>"#,
        );
        let programs = vec![(Language::C, native), (Language::Php, php)];
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover PHP FFI");
        assert!(graph.edges().all(|(_, _, edge)| edge.kind != EdgeKind::InteropArg));
    }
}
