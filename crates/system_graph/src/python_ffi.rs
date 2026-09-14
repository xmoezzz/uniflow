//! Python-to-native boundary recovery for the explicit `ctypes` and `cffi`
//! binding forms retained by the Python frontend.
//!
//! A bridge is emitted only when all of the following are true: the Python
//! function contains a literal `CDLL`/`dlopen` binding fact, the call uses the
//! bound alias and a literal identifier-like symbol, and exactly one global
//! C/C++ function in the scanned system has that ABI symbol. This deliberately
//! rejects dynamic attributes, extension-module magic, overloaded C++ names,
//! and symbol collisions rather than inventing an unsafe FFI relation.

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

#[derive(Clone, Debug)]
struct Binding {
    alias: String,
    symbol: String,
    library: String,
}

fn bindings(function: &uniflow_ir::Function) -> Vec<Binding> {
    function
        .attrs
        .get("python.ffi.calls")
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
    let mut out: HashMap<String, Vec<(Language, String, usize)>> = HashMap::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            // Namespaced C++ methods are not C ABI symbols. An unqualified
            // definition is still checked for uniqueness below.
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

fn library_node_id(library: &str) -> String {
    format!("ffi:library:{library}")
}

/// Discovers proven `ctypes`/`cffi` argument mappings from Python call sites
/// into exactly one native function. The edge is an `INTEROP_ARG` carrying
/// precise call-site ports, so the ordinary unified taint engine can follow a
/// Python source to a real C/C++ sink without treating every native call as a
/// source or a sink.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::Python {
            continue;
        }
        for function in &program.functions {
            if is_python_root_alias(program, function) {
                continue;
            }
            let bindings = bindings(function);
            for binding in &bindings {
                // The typed Python IR canonicalizes `alias.symbol` to e.g.
                // `ctypes.CDLL.symbol` and consequently no longer retains
                // which local alias was the receiver. If several literal
                // libraries bind the same symbol in one function, that fact
                // is ambiguous and must not be bridged.
                if bindings.iter().filter(|other| other.symbol == binding.symbol).count() != 1 {
                    continue;
                }
                let Some(candidates) = native.get(&binding.symbol) else { continue };
                let [candidate] = candidates.as_slice() else { continue };
                let (native_language, native_function, native_arity) = candidate;
                for block in &function.blocks {
                    for inst in &block.insts {
                        let InstKind::Call(call) = &inst.kind else { continue };
                        let Callee::Static(callee) = &call.callee else { continue };
                        let raw_callee = format!("{}.{}", binding.alias, binding.symbol);
                        let typed_suffix = format!(".{}.{}", "CDLL", binding.symbol);
                        let typed_cffi_suffix = format!(".dlopen.{}", binding.symbol);
                        if callee != &raw_callee
                            && !callee.ends_with(&typed_suffix)
                            && !callee.ends_with(&typed_cffi_suffix)
                        {
                            continue;
                        }
                        let call_id = format!("code:{}:{}#{}", language.as_str(), function.name, inst.id.0);
                        let library_id = library_node_id(&binding.library);
                        let native_id = format!("code:{}:{native_function}", native_language.as_str());
                        graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_id.clone(), callee).with_code_ref(CodeRef {
                            language: language.clone(), qualified_name: function.name.clone(),
                        }));
                        graph.upsert_node(SystemNode::new(NodeKind::AbstractObject, library_id.clone(), &binding.library)
                            .with_attr("ffi", "ctypes-or-cffi"));
                        graph.upsert_node(SystemNode::new(NodeKind::Function, native_id.clone(), native_function).with_code_ref(CodeRef {
                            language: native_language.clone(), qualified_name: native_function.clone(),
                        }));
                        graph.apply_boundary(
                            BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), library_id.clone(), Confidence::Exact)
                                .with_evidence(Evidence::new(format!("{} binds literal native library {:?}", function.name, binding.library))),
                        )?;
                        graph.apply_boundary(
                            BoundarySummary::new(EdgeKind::InteropCall, library_id, native_id.clone(), Confidence::Exact)
                                .with_evidence(Evidence::new(format!("literal Python FFI symbol {:?} uniquely resolves to {native_function}", binding.symbol))),
                        )?;
                        let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                            .with_evidence(Evidence::new(format!("{} invokes literal FFI symbol {:?} through alias {}", function.name, binding.symbol, binding.alias)));
                        for index in 0..call.args.len().min(*native_arity) {
                            summary = summary.with_value_mapping(
                                BoundaryFlowEdge::new(
                                    ValueMappingKind::ArgumentToParameter,
                                    FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                    FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                    Confidence::Exact,
                                )
                                .with_evidence(Evidence::new(format!("FFI positional argument {index} maps to native parameter {index}"))),
                            );
                        }
                        graph.apply_boundary(summary)?;
                    }
                }
            }
        }
    }
    Ok(())
}
