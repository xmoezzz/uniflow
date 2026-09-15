//! C#-to-native boundary recovery for P/Invoke (`[DllImport]` and modern
//! source-generated `[LibraryImport]`) binding forms.
//! It also recognizes NativeAOT's `[UnmanagedCallersOnly]` exports, where a
//! native host calls *into* managed C# without an ordinary C# call site.
//!
//! Unlike Python's `ctypes`/`cffi` (an aliased, dynamically-loaded library
//! called through a runtime handle — see [`crate::python_ffi`]), a C#
//! `[DllImport]`/`[LibraryImport]`-declared method is itself a real, statically
//! named, body-less method that ordinary C# callers already call directly
//! by its normal qualified name (the descriptor engine parses it into a
//! genuine `Function` with an empty body — confirmed empirically). So the
//! boundary to bridge is not a call-site pattern but the declaration itself:
//! whenever such a method's declared entry-point symbol uniquely matches one
//! global C/C++ function already in the scan, its own parameters/return are
//! wired 1:1 to that native function's, letting taint already flowing into
//! an ordinary call to the C# declaration continue across into the native
//! side.
//!
//! A bridge is emitted only when the P/Invoke declaration's entry-point
//! name matches *exactly one* global (non-namespaced, non-external) C/C++
//! function — the same deliberate conservatism `python_ffi` applies to a
//! `ctypes` symbol name.
//!
//! The `[DllImport(...)]` attribute itself is parsed here, straight out of
//! the raw `csharp.attributes.raw` fact `crates/lang_frontends`'
//! `add_csharp_attributes_raw` retains on every C# method (the same fact
//! `http.rs`'s `csharp_attribute_routes` reads for ASP.NET routes) — no
//! separate dedicated attribute key is needed.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::Program;
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};

#[derive(Clone, Debug)]
struct DllImportDecl {
    library: String,
    entry_point: String,
}

/// `[UnmanagedCallersOnly]` is an explicit NativeAOT/hosting ABI export. Its
/// `EntryPoint` is optional and defaults to the method name. The library is
/// deliberately not modeled: it belongs to the native host, not the managed
/// component that declares this entrypoint.
fn unmanaged_callers_only_export(function: &uniflow_ir::Function) -> Option<String> {
    let raw = function.attrs.get("csharp.attributes.raw")?;
    raw.split('\u{1f}').find_map(|attribute| {
        let attribute = attribute.trim();
        let (name, rest) = attribute.split_once('(').unwrap_or((attribute, ""));
        if !name.trim().rsplit('.').next()?.eq_ignore_ascii_case("UnmanagedCallersOnly") {
            return None;
        }
        let args = rest.strip_suffix(')').unwrap_or(rest);
        let entry_point = args
            .find("EntryPoint")
            .map(|pos| &args[pos + "EntryPoint".len()..])
            .and_then(|after| after.trim_start().strip_prefix('='))
            .and_then(extract_quoted)
            .unwrap_or_else(|| function.name.rsplit('.').next().unwrap_or(&function.name).to_string());
        Some(entry_point)
    })
}

fn extract_quoted(text: &str) -> Option<String> {
    let quote = text.chars().find(|ch| matches!(ch, '\'' | '"'))?;
    let start = text.find(quote)? + 1;
    let rest = &text[start..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// `[DllImport("lib.dll")]`/`[LibraryImport("lib.dll")]` (entry point
/// defaults to the method's own bare name — the real C# default) or an
/// explicit `EntryPoint = "RealName"` override.
fn dllimport_decl(function: &uniflow_ir::Function) -> Option<DllImportDecl> {
    let raw = function.attrs.get("csharp.attributes.raw")?;
    raw.split('\u{1f}').find_map(|attribute| {
        let attribute = attribute.trim();
        let (name, rest) = attribute.split_once('(')?;
        if !matches!(name.trim().to_ascii_lowercase().as_str(), "dllimport" | "libraryimport") {
            return None;
        }
        let args = rest.strip_suffix(')').unwrap_or(rest);
        let library = extract_quoted(args)?;
        let entry_point = args
            .find("EntryPoint")
            .map(|pos| &args[pos + "EntryPoint".len()..])
            .and_then(|after| after.trim_start().strip_prefix('='))
            .and_then(extract_quoted)
            .unwrap_or_else(|| function.name.rsplit('.').next().unwrap_or(&function.name).to_string());
        Some(DllImportDecl { library, entry_point })
    })
}

fn native_functions(programs: &[(Language, Program)]) -> HashMap<String, Vec<(Language, String, usize)>> {
    let mut out: HashMap<String, Vec<(Language, String, usize)>> = HashMap::new();
    for (language, program) in programs {
        if !matches!(language, Language::C | Language::Cpp) {
            continue;
        }
        for function in &program.functions {
            // Namespaced C++ methods are not plain C ABI symbols; an
            // unqualified definition is still checked for uniqueness below.
            if function.name.contains("::") || function.is_external {
                continue;
            }
            out.entry(function.name.clone()).or_default().push((language.clone(), function.name.clone(), function.params.len()));
        }
    }
    out
}

fn library_node_id(library: &str) -> String {
    format!("ffi:library:{library}")
}

const EXTERNAL_NATIVE_CALLER_ID: &str = "ffi:csharp:external-native-caller";

/// Discovers NativeAOT/hosting exports that can be called directly by an
/// unmanaged host. This is a lifecycle entrypoint, not an inferred C call:
/// the attribute itself is the ABI contract. Its external-input source is
/// injected centrally by `bridge::handler_source_rules`, using the marker on
/// the caller node below.
pub fn discover_exports_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    for (language, program) in programs {
        if *language != Language::CSharp {
            continue;
        }
        for function in &program.functions {
            let Some(entry_point) = unmanaged_callers_only_export(function) else { continue };
            let handler_id = format!("code:{}:{}", language.as_str(), function.name);
            graph.upsert_node(
                SystemNode::new(NodeKind::Entrypoint, handler_id.clone(), &function.name).with_code_ref(CodeRef {
                    language: language.clone(),
                    qualified_name: function.name.clone(),
                }),
            );
            graph.upsert_node(
                SystemNode::new(NodeKind::AbstractObject, EXTERNAL_NATIVE_CALLER_ID, "external unmanaged caller")
                    .with_attr("ffi_external_caller", "true"),
            );
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::InteropCall, EXTERNAL_NATIVE_CALLER_ID, handler_id, Confidence::Exact)
                    .with_evidence(Evidence::new(format!(
                        "{} is exported to unmanaged callers as literal entry point {entry_point:?}",
                        function.name
                    ))),
            )?;
        }
    }
    Ok(())
}

/// Discovers proven P/Invoke bridges from a C# declaration into
/// exactly one native function. The edge is an `INTEROP_ARG` carrying
/// precise per-parameter ports, so the ordinary unified taint engine follows
/// a C# call to the declaration straight into the matched C/C++ function
/// without treating the declaration itself as an opaque, taint-blocking
/// dead end.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let native = native_functions(programs);
    for (language, program) in programs {
        if *language != Language::CSharp {
            continue;
        }
        for function in &program.functions {
            let Some(decl) = dllimport_decl(function) else { continue };
            let Some(candidates) = native.get(&decl.entry_point) else { continue };
            let [candidate] = candidates.as_slice() else { continue };
            let (native_language, native_function, native_arity) = candidate;

            let decl_id = format!("code:{}:{}", language.as_str(), function.name);
            let library_id = library_node_id(&decl.library);
            let native_id = format!("code:{}:{native_function}", native_language.as_str());
            graph.upsert_node(
                SystemNode::new(NodeKind::Function, decl_id.clone(), &function.name)
                    .with_code_ref(CodeRef { language: language.clone(), qualified_name: function.name.clone() }),
            );
            graph.upsert_node(SystemNode::new(NodeKind::AbstractObject, library_id.clone(), &decl.library).with_attr("ffi", "pinvoke"));
            graph.upsert_node(
                SystemNode::new(NodeKind::Function, native_id.clone(), native_function)
                    .with_code_ref(CodeRef { language: native_language.clone(), qualified_name: native_function.clone() }),
            );
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::InteropCall, decl_id.clone(), library_id.clone(), Confidence::Exact)
                    .with_evidence(Evidence::new(format!("{} declares literal P/Invoke library {:?}", function.name, decl.library))),
            )?;
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::InteropCall, library_id, native_id.clone(), Confidence::Exact).with_evidence(Evidence::new(format!(
                    "literal P/Invoke entry point {:?} uniquely resolves to {native_function}",
                    decl.entry_point
                ))),
            )?;
            let mut summary = BoundarySummary::new(EdgeKind::InteropArg, decl_id, native_id, Confidence::Exact)
                .with_evidence(Evidence::new(format!("{} bridges P/Invoke entry point {:?} to its native implementation", function.name, decl.entry_point)));
            for index in 0..function.params.len().min(*native_arity) {
                summary = summary.with_value_mapping(
                    BoundaryFlowEdge::new(
                        ValueMappingKind::ArgumentToParameter,
                        FlowNodeRef::function_port(language.clone(), function.name.clone(), Port::Arg(index)),
                        FlowNodeRef::function_port(native_language.clone(), native_function.clone(), Port::Arg(index)),
                        Confidence::Exact,
                    )
                    .with_evidence(Evidence::new(format!("P/Invoke positional argument {index} maps to native parameter {index}"))),
                );
            }
            graph.apply_boundary(summary)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_lang_c::CParser;
    use uniflow_parser_core::SourceParser;

    fn lower_csharp(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(Language::CSharp, "Native.cs", source).expect("parse csharp");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_c(source: &str) -> Program {
        let hir = CParser::default().parse_file("native.c", source).expect("parse c");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn a_dllimport_declaration_bridges_to_its_unique_native_implementation() {
        let csharp_program = lower_csharp(
            r#"
class Native {
    [DllImport("nativelib.dll")]
    private static extern int DoWork(string input);

    public static void Run(string userInput) {
        DoWork(userInput);
    }
}
"#,
        );
        let c_program = lower_c(
            r#"
int DoWork(char *input) {
    return system(input);
}
"#,
        );
        let mut graph = SystemGraph::new();
        let programs = vec![(Language::CSharp, csharp_program), (Language::C, c_program)];
        discover_into(&mut graph, &programs).expect("discover FFI boundary");

        let arg_edges: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).collect();
        assert_eq!(arg_edges.len(), 1, "{arg_edges:?}");
        let mappings = &arg_edges[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].from.function, "Native.DoWork");
        assert_eq!(mappings[0].to.function, "DoWork");
        assert_eq!(mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn a_libraryimport_declaration_bridges_to_its_explicit_native_entry_point() {
        let csharp_program = lower_csharp(
            r#"
class Native {
    [LibraryImport("nativelib", EntryPoint = "native_work")]
    private static partial int DoWork(string input);
}
"#,
        );
        let c_program = lower_c(
            r#"
int native_work(char *input) {
    return system(input);
}
"#,
        );
        let mut graph = SystemGraph::new();
        let programs = vec![(Language::CSharp, csharp_program), (Language::C, c_program)];
        discover_into(&mut graph, &programs).expect("discover FFI boundary");
        let edge = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).expect("P/Invoke edge");
        assert_eq!(edge.2.value_mappings.len(), 1, "{:#?}", edge.2.value_mappings);
        assert_eq!(edge.2.value_mappings[0].from.function, "Native.DoWork");
        assert_eq!(edge.2.value_mappings[0].to.function, "native_work");
    }

    #[test]
    fn a_dllimport_with_no_matching_native_symbol_bridges_nothing() {
        let csharp_program = lower_csharp(
            r#"
class Native {
    [DllImport("nativelib.dll")]
    private static extern int Missing(string input);
}
"#,
        );
        let mut graph = SystemGraph::new();
        let programs = vec![(Language::CSharp, csharp_program)];
        discover_into(&mut graph, &programs).expect("discover FFI boundary");
        assert_eq!(graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).count(), 0);
    }

    #[test]
    fn an_unmanaged_callers_only_method_is_an_external_native_entrypoint() {
        let csharp_program = lower_csharp(
            r#"
class Callbacks {
    [UnmanagedCallersOnly(EntryPoint = "native_callback")]
    public static void Callback(string input) { sink(input); }
    static void sink(string value) {}
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_exports_into(&mut graph, &[(Language::CSharp, csharp_program)]).expect("discover export");
        let entry = graph.node("code:csharp:Callbacks.Callback").expect("exported entrypoint");
        assert_eq!(entry.kind, NodeKind::Entrypoint);
        let edge = graph
            .edges()
            .find(|(from, to, edge)| {
                from.id == EXTERNAL_NATIVE_CALLER_ID
                    && to.id == "code:csharp:Callbacks.Callback"
                    && edge.kind == EdgeKind::InteropCall
            })
            .expect("external native caller edge");
        assert!(edge.2.evidence[0].description.contains("native_callback"));
        let ingress = crate::bridge::handler_source_rules(&graph, &Language::CSharp);
        assert_eq!(ingress.function_sources.len(), 1, "{:?}", ingress.function_sources);
        assert_eq!(ingress.function_sources[0].matcher.exact.as_deref(), Some("Callbacks.Callback"));
        assert_eq!(ingress.function_sources[0].out, Port::ArgsFrom(0));
    }

    #[test]
    fn unmanaged_callers_only_defaults_its_native_entry_point_to_the_method_name() {
        let csharp_program = lower_csharp(
            r#"
class Callbacks {
    [UnmanagedCallersOnly]
    public static void Callback(string input) {}
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_exports_into(&mut graph, &[(Language::CSharp, csharp_program)]).expect("discover export");
        let edge = graph
            .edges()
            .find(|(from, _, edge)| from.id == EXTERNAL_NATIVE_CALLER_ID && edge.kind == EdgeKind::InteropCall)
            .expect("external native caller edge");
        assert!(edge.2.evidence[0].description.contains("Callback"), "{:?}", edge.2.evidence);
    }
}
