//! Kotlin/JVM `external fun` calls into native JNI implementations.
//!
//! The Kotlin frontend records only declarations it can prove came from a
//! literal `external fun`. This adapter then requires exactly one project
//! C/C++ function with that declaration's standard short JNI symbol. It does
//! not infer `@JvmName`, overload-qualified JNI symbols, dynamic native
//! registration, or ambiguous same-spelled methods.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, Function, InstKind, Program};
use uniflow_jni_bridge::mangle_jni_short_name;
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};

const JNI_IMPLICIT_PARAMS: usize = 2;

#[derive(Clone)]
struct Declaration {
    function: String,
    owner: Option<String>,
    symbol: String,
    native_language: Language,
    native_function: String,
    native_arity: usize,
}

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

fn jni_class(function: &Function) -> Option<String> {
    let package = function.attrs.get("kotlin.jni.package")?;
    let owner = function
        .attrs
        .get("owner_type")
        .or_else(|| function.attrs.get("kotlin.jni.facade"))?;
    Some(if package.is_empty() {
        owner.clone()
    } else {
        format!("{package}.{owner}")
    })
}

fn declarations(programs: &[(Language, Program)]) -> Vec<Declaration> {
    let native = native_functions(programs);
    let mut out = Vec::new();
    for (language, program) in programs {
        if *language != Language::Kotlin {
            continue;
        }
        for function in &program.functions {
            if function.attrs.get("kotlin.jni.external").map(String::as_str) != Some("true") {
                continue;
            }
            let Some(class) = jni_class(function) else { continue };
            let method = function.name.rsplit('.').next().unwrap_or(function.name.as_str());
            let symbol = mangle_jni_short_name(&class, method);
            let Some(candidates) = native.get(&symbol) else { continue };
            let [candidate] = candidates.as_slice() else { continue };
            out.push(Declaration {
                function: function.name.clone(),
                owner: function.attrs.get("owner_type").cloned(),
                symbol,
                native_language: candidate.0.clone(),
                native_function: candidate.1.clone(),
                native_arity: candidate.2,
            });
        }
    }
    out
}

fn matches_call(
    declaration: &Declaration,
    declarations: &[Declaration],
    enclosing: &Function,
    callee: &str,
) -> bool {
    if callee == declaration.function {
        return true;
    }
    let method = declaration.function.rsplit('.').next().unwrap_or(declaration.function.as_str());
    callee == method
        && (declaration.owner.as_deref() == enclosing.attrs.get("owner_type").map(String::as_str)
            // The descriptor parser can recover a Kotlin class declaration
            // while leaving an adjacent method's enclosing owner unavailable.
            // A globally unique external method spelling is still an exact
            // JNI target; with two declarations we keep requiring owner
            // identity and therefore never conflate them.
            || declarations
                .iter()
                .filter(|candidate| candidate.function.rsplit('.').next() == Some(callee))
                .count()
                == 1)
}

/// Recovers direct Kotlin/JVM external calls into a unique C/C++ JNI body.
/// Each Kotlin business argument starts at native parameter two, after the
/// mandatory `JNIEnv*` and `jobject`/`jclass` ABI parameters.
pub fn discover_into(graph: &mut SystemGraph, programs: &[(Language, Program)]) -> Result<()> {
    let declarations = declarations(programs);
    for (language, program) in programs {
        if *language != Language::Kotlin {
            continue;
        }
        for function in &program.functions {
            for block in &function.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else { continue };
                    let Callee::Static(callee) = &call.callee else { continue };
                    let matches = declarations
                        .iter()
                        .filter(|declaration| matches_call(declaration, &declarations, function, callee))
                        .collect::<Vec<_>>();
                    let [declaration] = matches.as_slice() else { continue };
                    if declaration.native_arity < JNI_IMPLICIT_PARAMS {
                        continue;
                    }
                    let call_id = format!("code:kotlin:{}#{}", function.name, inst.id.0);
                    let native_id = format!("code:{}:{}", declaration.native_language.as_str(), declaration.native_function);
                    graph.upsert_node(
                        SystemNode::new(NodeKind::CallSite, call_id.clone(), callee).with_code_ref(CodeRef {
                            language: Language::Kotlin,
                            qualified_name: function.name.clone(),
                        }),
                    );
                    graph.upsert_node(
                        SystemNode::new(NodeKind::Function, native_id.clone(), &declaration.native_function).with_code_ref(CodeRef {
                            language: declaration.native_language.clone(),
                            qualified_name: declaration.native_function.clone(),
                        }),
                    );
                    graph.apply_boundary(
                        BoundarySummary::new(EdgeKind::InteropCall, call_id.clone(), native_id.clone(), Confidence::Exact)
                            .with_evidence(Evidence::new(format!(
                                "{} calls Kotlin external declaration with unique JNI symbol {:?}",
                                function.name, declaration.symbol
                            ))),
                    )?;
                    let mut summary = BoundarySummary::new(EdgeKind::InteropArg, call_id, native_id, Confidence::Exact)
                        .with_evidence(Evidence::new(format!(
                            "Kotlin JNI call maps business arguments after the two implicit JNI parameters"
                        )));
                    for index in 0..call.args.len().min(declaration.native_arity - JNI_IMPLICIT_PARAMS) {
                        summary = summary.with_value_mapping(
                            BoundaryFlowEdge::new(
                                ValueMappingKind::ArgumentToParameter,
                                FlowNodeRef::call_site_port(Language::Kotlin, function.name.clone(), inst.id.0, Port::Arg(index)),
                                FlowNodeRef::function_port(
                                    declaration.native_language.clone(),
                                    declaration.native_function.clone(),
                                    Port::Arg(index + JNI_IMPLICIT_PARAMS),
                                ),
                                Confidence::Exact,
                            )
                            .with_evidence(Evidence::new(format!(
                                "Kotlin argument {index} maps to JNI native parameter {}", index + JNI_IMPLICIT_PARAMS
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

    fn lower_kotlin(source: &str) -> Program {
        let hir = uniflow_lang_frontends::parse_file(Language::Kotlin, "Native.kt", source).expect("parse Kotlin");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_c(source: &str) -> Program {
        let hir = uniflow_lang_c::CParser::default().parse_file("native.c", source).expect("parse C");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn kotlin_external_call_maps_its_first_business_argument_to_native_arg_two() {
        let kotlin = lower_kotlin(
            r#"
package com.example
class Native {
    external fun consume(input: String)
    fun invoke(input: String) { consume(input) }
}
"#,
        );
        let c = lower_c("void Java_com_example_Native_consume(void *env, void *instance, char *value) {}");
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::Kotlin, kotlin), (Language::C, c)]).expect("discover Kotlin JNI");
        let mapping = &graph
            .edges()
            .find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg)
            .expect("Kotlin JNI argument mapping")
            .2
            .value_mappings[0];
        assert_eq!(mapping.from.language, Language::Kotlin);
        assert_eq!(mapping.to.function, "Java_com_example_Native_consume");
        assert_eq!(mapping.to.port, Port::Arg(2));
    }
}
