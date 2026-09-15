//! Kotlin/JVM `external fun` calls into native JNI implementations.
//!
//! The Kotlin frontend records only declarations it can prove came from a
//! literal `external fun`. Two independent kinds of evidence bind such a
//! declaration to a real C/C++ body:
//!
//! - **Static linkage**: exactly one project C/C++ function has the
//!   declaration's standard short JNI symbol (`Java_pkg_Class_method`).
//! - **Dynamic registration**: a real `(*env)->RegisterNatives(env, clazz,
//!   methods, n)` / `env->RegisterNatives(clazz, methods, n)` call whose
//!   `clazz` traces back to a literal `FindClass(env, "pkg/Owner")` and
//!   whose `methods` traces back to a `JNINativeMethod[]` table this
//!   crate's C frontend recovers as `__compound_array_JNINativeMethod(
//!   __compound_JNINativeMethod(name, sig, fn), ...)` (see
//!   `rewrite_plain_aggregate_initializers` in `crates/lang_c`) — the
//!   modern, Android-team-recommended alternative to static linkage, and
//!   empirically the *dominant* real-world pattern (confirmed against
//!   Google's own `ndk-samples`, where the static-symbol path alone matches
//!   nothing at all). Each entry's declared JVM method name is matched, by
//!   owner class + name, to exactly one Kotlin `external fun`.
//!
//! It does not infer `@JvmName`, overload-qualified JNI symbols, or
//! ambiguous same-spelled methods either way.

use std::collections::HashMap;

use anyhow::Result;
use uniflow_hir::Language;
use uniflow_ir::{Callee, Function, InstKind, Program, ValueId};
use uniflow_jni_bridge::mangle_jni_short_name;
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};
use crate::ir_utils::{call_defining, resolve_value_root};

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

/// One `RegisterNatives` method-table entry: the JVM-internal owner class
/// (`FindClass`'s own `pkg/Owner` spelling, unconverted), the JVM method
/// name it registers, and the native function implementing it.
struct DynamicRegistration {
    class: String,
    method_name: String,
    native_language: Language,
    native_function: String,
    native_arity: usize,
}

/// `FindClass`'s slash-separated internal name (`com/example/Native`) in
/// [`jni_class`]'s own dot-separated spelling (`com.example.Native`).
fn dotted_class_name(jvm_internal_name: &str) -> String {
    jvm_internal_name.replace('/', ".")
}

/// Resolves `value` back to a literal `FindClass(env, "pkg/Owner")` call's
/// class-name argument, dot-separated to match [`jni_class`]'s convention.
fn resolve_find_class_name(function: &Function, value: uniflow_ir::ValueId, constants: &HashMap<ValueId, &str>) -> Option<String> {
    let root = resolve_value_root(function, value);
    let call = call_defining(function, root)?;
    let Callee::Static(callee) = &call.callee else { return None };
    if callee.rsplit('.').next() != Some("FindClass") {
        return None;
    }
    let literal = call.args.iter().find_map(|arg| {
        let text = *constants.get(arg)?;
        (!text.starts_with("<external-symbol:") && !text.is_empty()).then_some(text)
    })?;
    Some(dotted_class_name(literal))
}

/// Scans every C/C++ function for a real `RegisterNatives` call and recovers
/// each method-table entry it registers — see the module doc comment for
/// the exact shape required.
fn dynamic_registrations(programs: &[(Language, Program)]) -> Vec<DynamicRegistration> {
    let native = native_functions(programs);
    let mut out = Vec::new();
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
                // The JNI signature is `RegisterNatives(JNIEnv*, jclass, const
                // JNINativeMethod*, jint)`; the C idiom `(*env)->RegisterNatives(env, ...)`
                // repeats `env` as an explicit first argument (4 args total), while a
                // C++ `env->RegisterNatives(...)` receiver call does not (3 args) —
                // indexing from the END covers both without caring which.
                if callee.rsplit('.').next() != Some("RegisterNatives") || call.args.len() < 3 {
                    continue;
                }
                let n = call.args.len();
                let Some(class) = resolve_find_class_name(function, call.args[n - 3], &constants) else { continue };
                let methods_root = resolve_value_root(function, call.args[n - 2]);
                let Some(array_call) = call_defining(function, methods_root) else { continue };
                if !matches!(&array_call.callee, Callee::Static(name) if name == "__compound_array_JNINativeMethod") {
                    continue;
                }
                for &element in &array_call.args {
                    let element_root = resolve_value_root(function, element);
                    let Some(element_call) = call_defining(function, element_root) else { continue };
                    if !matches!(&element_call.callee, Callee::Static(name) if name == "__compound_JNINativeMethod") || element_call.args.len() < 3 {
                        continue;
                    }
                    let Some(method_name) = constants.get(&element_call.args[0]) else { continue };
                    if method_name.starts_with("<external-symbol:") || method_name.is_empty() {
                        continue;
                    }
                    let Some(native_symbol) = constants
                        .get(&element_call.args[2])
                        .and_then(|value| value.strip_prefix("<external-symbol:"))
                        .and_then(|value| value.strip_suffix('>'))
                    else {
                        continue;
                    };
                    let Some(candidates) = native.get(native_symbol) else { continue };
                    let [candidate] = candidates.as_slice() else { continue };
                    out.push(DynamicRegistration {
                        class: class.clone(),
                        method_name: (*method_name).to_string(),
                        native_language: candidate.0.clone(),
                        native_function: candidate.1.clone(),
                        native_arity: candidate.2,
                    });
                }
            }
        }
    }
    out
}

fn declarations(programs: &[(Language, Program)]) -> Vec<Declaration> {
    let native = native_functions(programs);
    let dynamic = dynamic_registrations(programs);
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
            let mangled = mangle_jni_short_name(&class, method);
            if let [candidate] = native.get(&mangled).map(Vec::as_slice).unwrap_or_default() {
                out.push(Declaration {
                    function: function.name.clone(),
                    owner: function.attrs.get("owner_type").cloned(),
                    symbol: format!("its unique JNI symbol {mangled:?}"),
                    native_language: candidate.0.clone(),
                    native_function: candidate.1.clone(),
                    native_arity: candidate.2,
                });
                continue;
            }
            let dynamic_matches = dynamic.iter().filter(|registration| registration.class == class && registration.method_name == method).collect::<Vec<_>>();
            if let [registration] = dynamic_matches.as_slice() {
                out.push(Declaration {
                    function: function.name.clone(),
                    owner: function.attrs.get("owner_type").cloned(),
                    symbol: format!("dynamic registration of {class}.{method}"),
                    native_language: registration.native_language.clone(),
                    native_function: registration.native_function.clone(),
                    native_arity: registration.native_arity,
                });
            }
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
                                "{} calls Kotlin external declaration bound to its native body by {}",
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

    #[test]
    fn kotlin_external_call_bridges_via_a_real_registernatives_table_with_no_static_symbol() {
        // Mirrors the dominant real-world Android pattern (confirmed against
        // Google's own `ndk-samples`): dynamic registration, not the static
        // `Java_pkg_Class_method` symbol convention `native.native_functions`
        // otherwise requires.
        let kotlin = lower_kotlin(
            r#"
package com.example
class Native {
    external fun add(a: Int, b: Int): Int
    fun invoke(x: Int, y: Int): Int { return add(x, y) }
}
"#,
        );
        let c = lower_c(
            r#"
int nativeAdd(void *env, void *instance, int a, int b) { return a + b; }
void register_methods(void *env) {
    JNINativeMethod methods[] = { {"add", "(II)I", (void*)nativeAdd} };
    jclass clazz = (*env)->FindClass(env, "com/example/Native");
    (*env)->RegisterNatives(env, clazz, methods, 1);
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::Kotlin, kotlin), (Language::C, c)]).expect("discover Kotlin JNI");
        let mapping = &graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::InteropArg).expect("Kotlin JNI argument mapping").2.value_mappings[0];
        assert_eq!(mapping.to.function, "nativeAdd");
        assert_eq!(mapping.to.port, Port::Arg(2));
    }

    #[test]
    fn a_registernatives_table_entry_for_an_unrelated_class_does_not_bridge() {
        let kotlin = lower_kotlin(
            r#"
package com.example
class Native {
    external fun add(a: Int, b: Int): Int
    fun invoke(x: Int, y: Int): Int { return add(x, y) }
}
"#,
        );
        let c = lower_c(
            r#"
int nativeAdd(void *env, void *instance, int a, int b) { return a + b; }
void register_methods(void *env) {
    JNINativeMethod methods[] = { {"add", "(II)I", (void*)nativeAdd} };
    jclass clazz = (*env)->FindClass(env, "com/example/OtherClass");
    (*env)->RegisterNatives(env, clazz, methods, 1);
}
"#,
        );
        let mut graph = SystemGraph::new();
        discover_into(&mut graph, &[(Language::Kotlin, kotlin), (Language::C, c)]).expect("discover Kotlin JNI");
        assert!(!graph.edges().any(|(_, _, edge)| edge.kind == EdgeKind::InteropArg), "a registration for a different class must not bridge");
    }
}
