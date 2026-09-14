//! C#-to-native boundary recovery for the P/Invoke (`[DllImport]`) binding
//! form.
//!
//! Unlike Python's `ctypes`/`cffi` (an aliased, dynamically-loaded library
//! called through a runtime handle — see [`crate::python_ffi`]), a C#
//! `[DllImport]`-declared `extern` method is itself a real, statically
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
//! A bridge is emitted only when the DllImport declaration's entry-point
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

fn extract_quoted(text: &str) -> Option<String> {
    let quote = text.chars().find(|ch| matches!(ch, '\'' | '"'))?;
    let start = text.find(quote)? + 1;
    let rest = &text[start..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// `[DllImport("lib.dll")]` (entry point defaults to the method's own bare
/// name — the real C# default) or `[DllImport("lib.dll", EntryPoint =
/// "RealName")]` (an explicit override, which takes precedence).
fn dllimport_decl(function: &uniflow_ir::Function) -> Option<DllImportDecl> {
    let raw = function.attrs.get("csharp.attributes.raw")?;
    raw.split('\u{1f}').find_map(|attribute| {
        let attribute = attribute.trim();
        let (name, rest) = attribute.split_once('(')?;
        if !name.trim().eq_ignore_ascii_case("DllImport") {
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

/// Discovers proven `[DllImport]` bridges from a C# extern declaration into
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
                    .with_evidence(Evidence::new(format!("{} declares [DllImport(\"{}\")]", function.name, decl.library))),
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
}
