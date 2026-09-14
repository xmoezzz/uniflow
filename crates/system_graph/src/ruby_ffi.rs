//! Ruby-to-native boundary recovery for the `ffi` gem's `attach_function`
//! binding form.
//!
//! Unlike Python's `ctypes`/`cffi` (see `crate::python_ffi`), a real *call
//! site* into the attached method never names the native C symbol at all —
//! `attach_function :bar, :c_bar, [:int], :int` inside a class dynamically
//! defines a `bar` method, and every caller elsewhere in the program just
//! writes an ordinary `SomeClass.bar(x)`/`instance.bar(x)`. `lang_ruby`
//! already lowers this into a real, callable, qualified
//! `{qualified_class}.bar` function item (with no body of its own — see
//! `lang_ruby::frontend::decl::attach_function_item`) carrying a
//! `"ruby.ffi.attach"` symbol attribute recording the literal C symbol; this
//! module only needs to bridge that ONE declaration site into a matching
//! native definition, exactly the same "declared, no body, boundary point"
//! shape `crates/jni_bridge`/`crates/cli/src/ffi_bridge.rs` give a Java
//! `native` method. No call-site scanning is needed at all: the bridge is
//! expressed as a *function-level* `BoundaryFlowEdge` (`call_site: None` on
//! both ends), so `crate::bridge` synthesizes a `FunctionSinkRule` on
//! `{qualified_class}.bar`'s own parameters and a `FunctionSourceRule` on
//! the native function's parameters — any real call to `bar` anywhere in
//! the scanned Ruby program is matched by ordinary qualified-name rule
//! matching, the same as any other bundled taint rule.
//!
//! A bridge is emitted only when exactly one global C/C++ function in the
//! scanned system has the literal attached symbol name — the same
//! ambiguity-avoiding conservatism `python_ffi` applies.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::Program;
use uniflow_rules::Port;

use crate::graph::{BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef, NodeKind, SystemGraph, SystemNode, ValueMappingKind};

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

/// Discovers proven `attach_function` bindings — a Ruby function attached
/// to exactly one native symbol — and bridges each of its parameters into
/// the corresponding native parameter as a function-level (not call-site)
/// mapping.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::Ruby {
            continue;
        }
        for function in &program.functions {
            let Some(symbol) = function.attrs.get("ruby.ffi.attach") else { continue };
            let Some(candidates) = native.get(symbol) else { continue };
            let [candidate] = candidates.as_slice() else { continue };
            let (native_language, native_function, native_arity) = candidate;

            let ruby_id = format!("code:{}:{}", language.as_str(), function.name);
            let native_id = format!("code:{}:{native_function}", native_language.as_str());
            graph.upsert_node(SystemNode::new(NodeKind::Function, ruby_id.clone(), &function.name).with_code_ref(CodeRef { language: language.clone(), qualified_name: function.name.clone() }));
            graph.upsert_node(SystemNode::new(NodeKind::Function, native_id.clone(), native_function).with_code_ref(CodeRef { language: native_language.clone(), qualified_name: native_function.clone() }));

            let mut summary = BoundarySummary::new(EdgeKind::InteropArg, ruby_id, native_id, Confidence::Exact)
                .with_evidence(Evidence::new(format!("{} is attached via the ffi gem to literal native symbol {symbol:?}", function.name)));
            for index in 0..function.params.len().min(*native_arity) {
                summary = summary.with_value_mapping(
                    BoundaryFlowEdge::new(
                        ValueMappingKind::ArgumentToParameter,
                        FlowNodeRef::function_port(language.clone(), function.name.clone(), Port::Arg(index)),
                        FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                        Confidence::Exact,
                    )
                    .with_evidence(Evidence::new(format!("attach_function positional argument {index} maps to native parameter {index}"))),
                );
            }
            graph.apply_boundary(summary)?;
        }
    }
    Ok(())
}
