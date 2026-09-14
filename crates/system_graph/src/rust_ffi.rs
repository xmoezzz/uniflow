//! Rust-to-native FFI boundary recovery, in both directions:
//!
//! - **Rust calling into C/C++** via an `extern "C" { fn foo(...); }` import
//!   block (Rust's equivalent of a JNI `native` method *declaration*, or a
//!   Python `ctypes`/`cffi` binding) — see [`discover_calls_into`].
//! - **C/C++ calling into Rust** via a `#[no_mangle]`/`#[export_name =
//!   "..."]` exported function (Rust's equivalent of a JNI `native` method's
//!   *implementation*, or a ctypes bridge's target symbol) — see
//!   [`discover_exports_into`].
//!
//! Both directions only ever bridge on a literal, statically-recoverable
//! symbol name with exactly one matching function on the other side of the
//! scan — the same deliberately conservative discipline `python_ffi.rs`
//! uses, for the same reason: an ambiguous or dynamic binding is not a proof
//! of a real FFI relation and must not become one.

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, InstKind, Program};
use uniflow_rules::Port;

use crate::graph::{BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef, NodeKind, SystemGraph, SystemNode, ValueMappingKind};

fn extern_fn_calls(function: &uniflow_ir::Function) -> Vec<&str> {
    function.attrs.get("rust.ffi.calls").into_iter().flat_map(|raw| raw.split('\u{1f}')).collect()
}

fn native_functions(programs: &[(Language, Program)]) -> std::collections::HashMap<String, Vec<(Language, String, usize)>> {
    let mut out: std::collections::HashMap<String, Vec<(Language, String, usize)>> = std::collections::HashMap::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            // Namespaced C++ methods are not C ABI symbols — an unqualified
            // definition is still checked for uniqueness below.
            if function.name.contains("::") || function.is_external {
                continue;
            }
            out.entry(function.name.clone()).or_default().push((language.clone(), function.name.clone(), function.params.len()));
        }
    }
    out
}

/// Discovers proven `extern "C"` call sites from Rust functions into exactly
/// one native C/C++ function — Rust is the caller here, so the shape mirrors
/// `python_ffi::discover_into` almost exactly, minus the alias/library
/// bookkeeping ctypes needs (a `extern "C" { fn foo(...); }` import declares
/// the real ABI symbol name directly, with no separate library handle).
pub fn discover_calls_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::Rust {
            continue;
        }
        for function in &program.functions {
            let declared_calls = extern_fn_calls(function);
            if declared_calls.is_empty() {
                continue;
            }
            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(callee) = &call.callee else { continue };
                    if !declared_calls.contains(&callee.as_str()) {
                        continue;
                    }
                    let Some(candidates) = native.get(callee) else { continue };
                    let [candidate] = candidates.as_slice() else { continue };
                    let (native_language, native_function, native_arity) = candidate;

                    let call_id = format!("code:{}:{}#{}", language.as_str(), function.name, inst.id.0);
                    let native_id = format!("code:{}:{native_function}", native_language.as_str());
                    graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_id.clone(), callee).with_code_ref(CodeRef { language: language.clone(), qualified_name: function.name.clone() }));
                    graph.upsert_node(SystemNode::new(NodeKind::Function, native_id.clone(), native_function).with_code_ref(CodeRef { language: native_language.clone(), qualified_name: native_function.clone() }));
                    graph.apply_boundary(
                        BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), native_id.clone(), Confidence::Exact)
                            .with_evidence(Evidence::new(format!("{} calls literal `extern \"C\"` symbol {callee:?}, uniquely resolving to {native_function}", function.name))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!("{} invokes extern C symbol {callee:?}", function.name)));
                    for index in 0..call.args.len().min(*native_arity) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!("extern \"C\" positional argument {index} maps to native parameter {index}"))),
                        );
                    }
                    graph.apply_boundary(summary)?;
                }
            }
        }
    }
    Ok(())
}

/// Discovers a C/C++ call site invoking a name that matches exactly one
/// `#[no_mangle]`/`#[export_name]`-exported Rust function — the reverse
/// direction, where native code is the caller and Rust is the callee (the
/// role JNI's own bridge plays for a `native` Java method's *implementation*
/// side). Bridges the C call's arguments/return into the Rust function's
/// parameters/return the same way.
pub fn discover_exports_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let mut exported: std::collections::HashMap<String, Vec<(String, usize)>> = std::collections::HashMap::new();
    for (language, program) in programs {
        if *language != Language::Rust {
            continue;
        }
        for function in &program.functions {
            let Some(symbol) = function.attrs.get("rust.ffi.export") else { continue };
            exported.entry(symbol.clone()).or_default().push((function.name.clone(), function.params.len()));
        }
    }
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(callee) = &call.callee else { continue };
                    // Only an unqualified call is a plausible C ABI symbol
                    // reference — a namespaced/method call cannot be.
                    if callee.contains("::") {
                        continue;
                    }
                    let Some(candidates) = exported.get(callee) else { continue };
                    let [(rust_function, rust_arity)] = candidates.as_slice() else { continue };

                    let call_id = format!("code:{}:{}#{}", language.as_str(), function.name, inst.id.0);
                    let rust_id = format!("code:rust:{rust_function}");
                    graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_id.clone(), callee).with_code_ref(CodeRef { language: language.clone(), qualified_name: function.name.clone() }));
                    graph.upsert_node(SystemNode::new(NodeKind::Function, rust_id.clone(), rust_function).with_code_ref(CodeRef { language: Language::Rust, qualified_name: rust_function.clone() }));
                    graph.apply_boundary(
                        BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), rust_id.clone(), Confidence::Exact)
                            .with_evidence(Evidence::new(format!("{} calls literal symbol {callee:?}, uniquely exported by Rust function {rust_function}", function.name))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, rust_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!("{} invokes Rust-exported symbol {callee:?}", function.name)));
                    for index in 0..call.args.len().min(*rust_arity) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(Language::Rust, rust_function.clone(), Port::Arg(index)),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!("positional argument {index} maps to Rust parameter {index}"))),
                        );
                    }
                    graph.apply_boundary(summary)?;
                }
            }
        }
    }
    Ok(())
}
