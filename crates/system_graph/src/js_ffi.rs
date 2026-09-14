//! JS/Node-to-native boundary recovery for the common Node "native addon"
//! binding forms: `const addon = require('./build/Release/thing.node');`
//! and the `bindings` package's indirection, `const addon =
//! require('bindings')('thing');`. Both are recognized textually by
//! `lang_javascript::frontend::decl::js_native_addon_calls` (the JS analogue
//! of `lang_python`'s own deliberately simple, literal-syntax-only
//! `python_ffi_calls` scan) and persisted as a `js.ffi.calls` function
//! attribute, read here exactly the way [`crate::python_ffi`] reads
//! `python.ffi.calls`.
//!
//! Unlike ctypes/JNI, there is no mangled or otherwise-literal exported C
//! symbol name visible at the JS call site — an N-API native module exposes
//! its JS-visible method names via a runtime registration call
//! (`Napi::Function::New(env, Impl, "name")`/`napi_create_function(env,
//! "name", ...)`), not via the C++ implementation function's own symbol
//! name. Recovering the true registration-call string-to-function-pointer
//! mapping would need real C++ call-argument semantics this codebase does
//! not yet track. As a conservative, real-but-simplified first cut, a
//! bridge is emitted only when a C/C++ function in the same scan is
//! **itself named** exactly the JS-visible method name — the common (and
//! often enforced-by-convention) case where an addon's implementation
//! functions are named to match what they're exposed as — and, as with
//! every other bridge in this module family, only when exactly one such
//! global C/C++ function exists.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, InstKind, Program};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};

#[derive(Clone, Debug)]
struct Binding {
    alias: String,
    symbol: String,
    library: String,
}

fn bindings(function: &uniflow_ir::Function) -> Vec<Binding> {
    function
        .attrs
        .get("js.ffi.calls")
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
    format!("ffi:node-addon:{library}")
}

/// Discovers proven native-addon call sites (`addon.method(...)`) whose
/// literal method name uniquely resolves to a same-named C/C++ function
/// elsewhere in the scan, emitting an `INTEROP_ARG` edge with precise
/// call-site ports — same shape as [`crate::python_ffi::discover_into`].
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::JavaScript {
            continue;
        }
        // A `const addon = require(...)` binding and the `addon.method(...)`
        // calls that use it are very commonly in *different* top-level
        // functions (the require typically sits in the module's own
        // synthetic `<script>` init function, while real call sites live in
        // whatever ordinary functions use the binding) — unlike Python's
        // ctypes convention, which `python_ffi` deliberately scopes to a
        // single function body, collecting every binding across the whole
        // file first (rather than per-function) is what makes this actually
        // fire for the common top-of-file-require pattern.
        let all_bindings: Vec<Binding> = program.functions.iter().flat_map(bindings).collect();
        for function in &program.functions {
            for binding in &all_bindings {
                if all_bindings.iter().filter(|other| other.symbol == binding.symbol).count() != 1 {
                    continue;
                }
                let Some(candidates) = native.get(&binding.symbol) else { continue };
                let [candidate] = candidates.as_slice() else { continue };
                let (native_language, native_function, native_arity) = candidate;
                for block in &function.blocks {
                    for inst in &block.insts {
                        let InstKind::Call(call) = &inst.kind else { continue };
                        let Callee::Static(callee) = &call.callee else { continue };
                        let raw_callee = &binding.symbol;
                        let qualified_suffix = format!(".{}", binding.symbol);
                        if callee != raw_callee && !callee.ends_with(&qualified_suffix) {
                            continue;
                        }
                        let call_id = format!("code:{}:{}#{}", language.as_str(), function.name, inst.id.0);
                        let library_id = library_node_id(&binding.library);
                        let native_id = format!("code:{}:{native_function}", native_language.as_str());
                        graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_id.clone(), callee).with_code_ref(CodeRef {
                            language: language.clone(),
                            qualified_name: function.name.clone(),
                        }));
                        graph.upsert_node(
                            SystemNode::new(NodeKind::AbstractObject, library_id.clone(), &binding.library).with_attr("ffi", "node-native-addon"),
                        );
                        graph.upsert_node(SystemNode::new(NodeKind::Function, native_id.clone(), native_function).with_code_ref(CodeRef {
                            language: native_language.clone(),
                            qualified_name: native_function.clone(),
                        }));
                        graph.apply_boundary(
                            BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), library_id.clone(), Confidence::Exact)
                                .with_evidence(Evidence::new(format!("{} binds literal native addon {:?} (via {})", function.name, binding.library, binding.alias))),
                        )?;
                        graph.apply_boundary(
                            BoundarySummary::new(EdgeKind::InteropCall, library_id, native_id.clone(), Confidence::Exact).with_evidence(Evidence::new(format!(
                                "literal JS native-addon method {:?} uniquely resolves to same-named function {native_function}",
                                binding.symbol
                            ))),
                        )?;
                        let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact).with_evidence(Evidence::new(format!(
                            "{} invokes native addon method {:?} through alias {}",
                            function.name, binding.symbol, binding.alias
                        )));
                        for index in 0..call.args.len().min(*native_arity) {
                            summary = summary.with_value_mapping(
                                BoundaryFlowEdge::new(
                                    ValueMappingKind::ArgumentToParameter,
                                    FlowNodeRef::call_site_port(language.clone(), function.name.clone(), inst.id.0, Port::Arg(index)),
                                    FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                                    Confidence::Exact,
                                )
                                .with_evidence(Evidence::new(format!("native-addon positional argument {index} maps to native parameter {index}"))),
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

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_lang_c::CParser;
    use uniflow_lang_javascript::JavaScriptParser;
    use uniflow_parser_core::SourceParser;

    fn lower_js(path: &str, source: &str) -> Program {
        let hir = JavaScriptParser::default().parse_file(path, source).expect("parse js");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_c(path: &str, source: &str) -> Program {
        let hir = CParser::default().parse_file(path, source).expect("parse c");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn a_native_addon_call_with_a_unique_same_named_c_function_bridges_taint() {
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) {
            return addon.transform(input);
        }
        "#;
        let c_source = r#"
int transform(int value) {
    return value;
}
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover node-addon boundary");
        assert!(graph.nodes().any(|node| node.kind == NodeKind::AbstractObject && node.name.contains("thing.node")), "expected a native-addon node");
        assert!(graph.nodes().any(|node| node.kind == NodeKind::Function && node.name == "transform"), "expected the native transform function to be linked");
    }

    #[test]
    fn a_bindings_package_indirection_is_also_recognized() {
        let js_source = r#"
        const addon = require('bindings')('thing');
        function run(input) {
            return addon.transform(input);
        }
        "#;
        let js_program = lower_js("index.js", js_source);
        let c_source = r#"
int transform(int value) {
    return value;
}
"#;
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover node-addon boundary");
        assert!(graph.nodes().any(|node| node.kind == NodeKind::Function && node.name == "transform"));
    }

    #[test]
    fn an_ambiguous_symbol_with_two_native_candidates_is_not_bridged() {
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) {
            return addon.transform(input);
        }
        "#;
        let js_program = lower_js("index.js", js_source);
        let c_source_a = r#"
int transform(int value) { return value; }
"#;
        let c_source_b = r#"
int transform(int value) { return value; }
"#;
        let c_program_a = lower_c("a.c", c_source_a);
        let c_program_b = lower_c("b.c", c_source_b);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program_a), (Language::C, c_program_b)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover node-addon boundary");
        assert!(!graph.nodes().any(|node| node.kind == NodeKind::AbstractObject && node.name.contains("thing.node")), "ambiguous symbol must not bridge");
    }
}
