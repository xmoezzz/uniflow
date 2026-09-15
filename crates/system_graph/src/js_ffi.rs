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
use uniflow_ir::{Callee, InstKind, Program, ValueId};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};
use crate::ir_utils::{call_defining, resolve_value_root};

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

/// Case/separator-insensitive key for the same-name fallback: strips
/// everything but ASCII alphanumerics and lowercases the rest, so `Add`
/// (a common C/C++ implementation spelling), `add` (its equally common
/// lowerCamelCase JS-visible spelling), and `do_transform`/`doTransform`
/// all collide on one canonical key. Real Node addons routinely pair a
/// PascalCase native function with a camelCase JS method name (see e.g.
/// the official `node-addon-examples` "function arguments" sample); an
/// exact-spelling-only fallback misses that entirely.
fn normalize_ffi_symbol(name: &str) -> String {
    name.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
}

/// Same population as [`native_functions`], keyed by [`normalize_ffi_symbol`]
/// instead of the literal name. Two distinctly-spelled native functions that
/// happen to normalize the same way correctly collide into one ambiguous
/// (unbridgeable) bucket, exactly like the exact-name map already does for
/// literal duplicates.
fn native_functions_by_normalized_name(programs: &[(Language, Program)]) -> HashMap<String, Vec<(Language, String, usize)>> {
    let mut out: HashMap<String, Vec<(Language, String, usize)>> = HashMap::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            if function.name.contains("::") || function.is_external {
                continue;
            }
            out.entry(normalize_ffi_symbol(&function.name))
                .or_default()
                .push((language.clone(), function.name.clone(), function.params.len()));
        }
    }
    out
}

/// Extracts a `(name, callback_symbol)` registration pair from one call
/// carrying a property/method descriptor: either the real
/// `napi_property_descriptor` layout the C frontend's
/// `__compound_napi_property_descriptor(utf8name, name, method, ...)`
/// recovers (`utf8name` at position 0, `method` at position 2 — see
/// `rewrite_plain_aggregate_initializers` in `crates/lang_c`), or an
/// unrecognized macro-wrapped element (`DECLARE_NAPI_METHOD(name, fn)`,
/// common in real Node addon sample code): the first argument that resolves
/// to a plain literal string is the name, the first *other* argument that
/// resolves to a function reference is the callback. Both paths reuse the
/// exact same `<external-symbol:...>` convention `napi_create_function`'s
/// own extraction already relies on.
fn extract_descriptor_name_and_callback(call: &uniflow_ir::CallInst, constants: &HashMap<ValueId, &str>) -> Option<(String, String)> {
    let is_known_layout = matches!(&call.callee, Callee::Static(name) if name == "__compound_napi_property_descriptor");
    if is_known_layout {
        let name = constants.get(call.args.first()?)?;
        if name.starts_with("<external-symbol:") || name.is_empty() {
            return None;
        }
        let callback = constants.get(call.args.get(2)?)?.strip_prefix("<external-symbol:")?.strip_suffix('>')?;
        return Some(((*name).to_string(), callback.to_string()));
    }
    let name = call.args.iter().find_map(|arg| {
        let text = *constants.get(arg)?;
        (!text.starts_with("<external-symbol:") && !text.is_empty()).then(|| text.to_string())
    })?;
    let callback = call.args.iter().find_map(|arg| constants.get(arg)?.strip_prefix("<external-symbol:")?.strip_suffix('>').map(str::to_string))?;
    Some((name, callback))
}

/// Recovers literal JavaScript export names and their callbacks from the two
/// N-API registration primitives real addons use: `napi_create_function(env,
/// "name", ..., callback, ...)` for a single method, and
/// `napi_define_properties(env, exports, count, properties)` for a whole
/// `napi_property_descriptor[]` table (the more common real-world shape —
/// see e.g. Node's own `node-addon-examples`). N-API keeps the public JS
/// name separate from the native implementation name, so both are stronger
/// evidence than a name convention. Dynamic export names and callback
/// expressions deliberately remain absent.
fn napi_registered_functions(programs: &[(Language, Program)]) -> HashMap<String, Vec<(Language, String, usize)>> {
    let native = native_functions(programs);
    let mut registrations = HashMap::<String, Vec<(Language, String, usize)>>::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            let constants = function
                .blocks
                .iter()
                .flat_map(|block| &block.insts)
                .filter_map(|inst| match &inst.kind {
                    InstKind::ConstString { dst, value } => Some((*dst, value.as_str())),
                    _ => None,
                })
                .collect::<HashMap<_, _>>();
            for inst in function.blocks.iter().flat_map(|block| &block.insts) {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(callee) = &call.callee else { continue };
                if callee == "napi_create_function" && call.args.len() >= 4 {
                    let Some(export_name) = constants.get(&call.args[1]) else { continue };
                    if export_name.starts_with("<external-symbol:") || export_name.is_empty() {
                        continue;
                    }
                    let Some(callback) = constants
                        .get(&call.args[3])
                        .and_then(|value| value.strip_prefix("<external-symbol:"))
                        .and_then(|value| value.strip_suffix('>'))
                    else {
                        continue;
                    };
                    let Some(candidates) = native.get(callback) else { continue };
                    let [candidate] = candidates.as_slice() else { continue };
                    registrations.entry((*export_name).to_string()).or_default().push(candidate.clone());
                    continue;
                }
                if callee == "napi_define_properties" && call.args.len() >= 4 {
                    let array_root = resolve_value_root(function, call.args[3]);
                    let Some(array_call) = call_defining(function, array_root) else { continue };
                    // Real addon code passes either a whole table (`Type
                    // arr[] = {...}`, recovered as `__compound_array_Type`)
                    // or, just as commonly (a single-method addon has no
                    // reason to build an array of one), a bare `&scalar`
                    // (`Type desc = DECLARE_NAPI_METHOD(...); ...(&desc)`,
                    // recovered as a direct `__compound_Type` call — no
                    // array wrapper at all). Treat the latter as its own
                    // one-element table.
                    let elements: Vec<ValueId> = if matches!(&array_call.callee, Callee::Static(name) if name == "__compound_array_napi_property_descriptor") {
                        array_call.args.clone()
                    } else if matches!(&array_call.callee, Callee::Static(name) if name == "__compound_napi_property_descriptor") {
                        vec![array_root]
                    } else {
                        continue;
                    };
                    for element in elements {
                        let element_root = resolve_value_root(function, element);
                        let Some(element_call) = call_defining(function, element_root) else { continue };
                        let Some((name, callback)) = extract_descriptor_name_and_callback(element_call, &constants) else { continue };
                        let Some(candidates) = native.get(callback.as_str()) else { continue };
                        let [candidate] = candidates.as_slice() else { continue };
                        registrations.entry(name).or_default().push(candidate.clone());
                    }
                }
            }
        }
    }
    for candidates in registrations.values_mut() {
        candidates.sort_by(|left, right| {
            left.0
                .as_str()
                .cmp(right.0.as_str())
                .then_with(|| left.1.cmp(&right.1))
                .then_with(|| left.2.cmp(&right.2))
        });
        candidates.dedup();
    }
    registrations
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
    let native_normalized = native_functions_by_normalized_name(programs);
    let registered = napi_registered_functions(programs);
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
                // Explicit N-API registration wins over the legacy same-name
                // convention, and an exact spelling match wins over the
                // case/separator-insensitive fallback. If several addons
                // register a name, do not infer a binary association the
                // source IR cannot prove.
                let candidates = registered
                    .get(&binding.symbol)
                    .or_else(|| native.get(&binding.symbol))
                    .or_else(|| native_normalized.get(&normalize_ffi_symbol(&binding.symbol)));
                let Some(candidates) = candidates else { continue };
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
    fn a_literal_napi_registration_maps_a_differently_named_js_export_to_its_callback() {
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) { return addon.sanitize(input); }
        "#;
        let c_source = r#"
int sanitize_impl(int value) { return value; }
void init(void) {
    napi_create_function(env, "sanitize", 8, sanitize_impl, 0, result);
}
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover N-API boundary");
        let mapping = graph
            .edges()
            .find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg)
            .expect("registered addon argument mapping");
        assert_eq!(mapping.2.value_mappings[0].from.function, "index.run");
        assert_eq!(mapping.2.value_mappings[0].to.function, "sanitize_impl");
        assert!(mapping.2.evidence[0].description.contains("sanitize"));
    }

    #[test]
    fn a_napi_define_properties_table_maps_each_descriptor_to_its_callback() {
        // Mirrors the real-world shape found in Node's own
        // `node-addon-examples`: a `napi_property_descriptor[]` table passed
        // to `napi_define_properties`, rather than one-at-a-time
        // `napi_create_function` calls.
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) { return addon.add(input); }
        "#;
        let c_source = r#"
int Add(int value) { return value; }
void init(void) {
    napi_property_descriptor properties[] = { { "add", 0, Add, 0, 0, 0, napi_default, 0 } };
    napi_define_properties(env, exports, 1, properties);
}
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover N-API boundary");
        let mapping = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).expect("registered addon argument mapping");
        assert_eq!(mapping.2.value_mappings[0].to.function, "Add");
    }

    #[test]
    fn a_napi_define_properties_table_with_a_macro_wrapped_descriptor_still_bridges() {
        // The dominant real-world idiom: `DECLARE_NAPI_METHOD(name, fn)` as
        // an array element, left unexpanded because its defining macro
        // typically lives in a header this single-file scan never sees.
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) { return addon.add(input); }
        "#;
        let c_source = r#"
int Add(int value) { return value; }
void init(void) {
    napi_property_descriptor properties[] = { DECLARE_NAPI_METHOD("add", Add) };
    napi_define_properties(env, exports, 1, properties);
}
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover N-API boundary");
        let mapping = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).expect("registered addon argument mapping");
        assert_eq!(mapping.2.value_mappings[0].to.function, "Add");
    }

    #[test]
    fn a_scalar_napi_define_properties_descriptor_bridges_with_no_array_wrapper() {
        // Mirrors the real, unmodified shape in Node's own
        // `node-addon-examples` (`1-getting-started/2_function_arguments`):
        // a single macro-defined descriptor passed by address, never
        // wrapped in an array at all — `napi_define_properties`'s own
        // signature takes a pointer to the first element either way.
        let js_source = r#"
        const addon = require('bindings')('addon.node');
        console.log(addon.add(3, 5));
        "#;
        let c_source = r#"
static int Add(int env, int info) { return env + info; }
#define DECLARE_NAPI_METHOD(name, func) { name, 0, func, 0, 0, 0, napi_default, 0 }
int Init(int env, int exports) {
    napi_property_descriptor addDescriptor = DECLARE_NAPI_METHOD("add", Add);
    int status = napi_define_properties(env, exports, 1, &addDescriptor);
    return status;
}
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("addon.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover N-API boundary");
        let mapping = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).expect("registered addon argument mapping");
        assert_eq!(mapping.2.value_mappings[0].to.function, "Add");
    }

    #[test]
    fn a_pascal_case_native_function_bridges_a_camel_case_js_method_by_normalized_name() {
        // Mirrors the real-world naming convention in Node's own
        // `node-addon-examples` "function arguments" sample: the JS-visible
        // method is lowerCamelCase while the C/C++ implementation is
        // PascalCase, with no N-API registration call in scope to disambiguate.
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) {
            return addon.add(input);
        }
        "#;
        let c_source = r#"
int Add(int value) {
    return value;
}
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover node-addon boundary");
        assert!(graph.nodes().any(|node| node.kind == NodeKind::Function && node.name == "Add"), "expected the PascalCase native function to be linked via normalized-name fallback");
    }

    #[test]
    fn two_native_functions_colliding_under_normalization_are_not_bridged() {
        let js_source = r#"
        const addon = require('./build/Release/thing.node');
        function run(input) {
            return addon.doTransform(input);
        }
        "#;
        let c_source = r#"
int do_transform(int value) { return value; }
int DoTransform(int value) { return value; }
"#;
        let js_program = lower_js("index.js", js_source);
        let c_program = lower_c("thing.c", c_source);
        let programs = vec![(Language::JavaScript, js_program), (Language::C, c_program)];

        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &programs).expect("discover node-addon boundary");
        assert!(!graph.nodes().any(|node| node.kind == NodeKind::AbstractObject && node.name.contains("thing.node")), "two normalization-colliding native candidates must not bridge");
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
