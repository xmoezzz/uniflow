//! Bridges taint across a Java `native` method call to its C/C++ JNI
//! implementation, when both are present in one mixed-language project scan.
//!
//! `run_mixed_project` analyzes every language group as an independent
//! `ir::Program`/`FlowGraph` (`uniflow_ir::merge_programs` refuses to merge
//! programs of different languages, so a real cross-language `FlowGraph` is
//! not an option). Instead, a native (C/C++) function matching the standard
//! JNI naming convention is *probed* with the engine's own
//! `FunctionSourceRule`/`FunctionSinkRule` primitives — which seed/observe
//! taint at a function's own formal parameters/return, independent of any
//! call site — to compute a per-parameter taint summary. That summary is
//! then spliced into the Java group's `RuleSet` as ordinary (if synthetic)
//! `PropagatorRule`/`SourceRule`/`SinkRule` entries scoped to the Java call,
//! before the Java group is built/analyzed. Every synthetic rule id is
//! prefixed so probe-only findings never reach the emitted report.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use uniflow_hir::Language;
use uniflow_jni_bridge::NativeMethodDecl;
use uniflow_rules::{
    ApiMatcher, FlowSpec, FunctionMatcher, FunctionSinkRule, FunctionSourceRule, Port,
    PropagatorRule, RuleSet, SinkRule, SourceRule,
};
use uniflow_taint::TaintFinding;

const PROBE_SRC_PREFIX: &str = "__ffi_bridge::src::";
const PROBE_SINK_PREFIX: &str = "__ffi_bridge::sink::";

/// JNI reserves two leading native-side parameters (`JNIEnv*`, then
/// `jobject`/`jclass`) before a native method's Java-visible arguments.
const JNI_IMPLICIT_PARAMS: usize = 2;

fn probe_source_id(mangled: &str, arg_index: usize) -> String {
    format!("{PROBE_SRC_PREFIX}{mangled}::arg{arg_index}")
}

fn probe_sink_id(mangled: &str) -> String {
    format!("{PROBE_SINK_PREFIX}{mangled}::return")
}

fn parse_probe_source_id(id: &str) -> Option<(&str, usize)> {
    let rest = id.strip_prefix(PROBE_SRC_PREFIX)?;
    let (mangled, arg) = rest.rsplit_once("::arg")?;
    Some((mangled, arg.parse().ok()?))
}

fn parse_probe_sink_id(id: &str) -> Option<&str> {
    id.strip_prefix(PROBE_SINK_PREFIX)?.strip_suffix("::return")
}

fn is_probe_rule_id(id: &str) -> bool {
    id.starts_with(PROBE_SRC_PREFIX) || id.starts_with(PROBE_SINK_PREFIX)
}

/// Scans every `.java` file in `java_files` plus every `.class`/`.jar`/`.war`
/// archive in `archive_files` for `native` method declarations.
pub fn collect_native_method_decls(
    java_files: &[PathBuf],
    archive_files: &[PathBuf],
) -> Result<Vec<NativeMethodDecl>> {
    let mut decls = Vec::new();
    for path in java_files {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        decls.extend(uniflow_lang_java::java_native_method_decls(&source));
    }
    for archive in archive_files {
        let is_standalone_class = archive
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension == "class");
        let natives = if is_standalone_class {
            lower_class_file_natives(archive)?
        } else {
            lower_archive_natives(archive)?
        };
        decls.extend(natives);
    }
    Ok(decls)
}

fn lower_class_file_natives(path: &Path) -> Result<Vec<NativeMethodDecl>> {
    let (_program, _diagnostics, natives) = uniflow_lang_java_bytecode::lower_class_file(path)
        .with_context(|| format!("failed to decode Java bytecode input {}", path.display()))?;
    Ok(natives)
}

fn lower_archive_natives(path: &Path) -> Result<Vec<NativeMethodDecl>> {
    let (_program, _diagnostics, natives) = uniflow_lang_java_bytecode::lower_archive(path)
        .with_context(|| format!("failed to decode Java bytecode input {}", path.display()))?;
    Ok(natives)
}

/// Groups native declarations by their JNI short-mangled name, dropping (with
/// a diagnostic) any name shared by more than one declaration. This bridge
/// only supports the short (non-overload-qualified) JNI naming form, so
/// overloaded natives can't be disambiguated and are skipped rather than
/// bridged to the wrong implementation.
pub fn dedupe_by_mangled_name(decls: Vec<NativeMethodDecl>) -> HashMap<String, NativeMethodDecl> {
    let mut grouped: HashMap<String, Vec<NativeMethodDecl>> = HashMap::new();
    for decl in decls {
        grouped
            .entry(decl.mangled_short_name())
            .or_default()
            .push(decl);
    }
    let mut out = HashMap::new();
    for (mangled, mut group) in grouped {
        if group.len() > 1 {
            eprintln!(
                "uniflow: FFI bridge: {} native declarations mangle to the same JNI symbol \
                 {mangled}; skipping (overloaded natives are not disambiguated)",
                group.len()
            );
            continue;
        }
        out.insert(mangled, group.pop().expect("group has exactly one entry"));
    }
    out
}

/// Builds the synthetic probe rules to merge into a C/C++ group's `RuleSet`
/// before it is built/analyzed: one `FunctionSourceRule` per Java-visible
/// parameter (so taint can be seeded there) and one `FunctionSinkRule` on the
/// function's own return (so we can observe whether that taint — or any
/// pre-existing real source already defined for this language — reaches it).
///
/// Both use the reserved `"generic"` taint kind, which the engine's
/// kind-compatibility check (`kind_compatible`) always treats as a match
/// against any other kind — necessary here since a probe must connect to a
/// real source/sink of whatever kind the project's own (unknown to us) rules
/// happen to use.
pub fn build_probe_ruleset(candidates: &HashMap<String, NativeMethodDecl>) -> RuleSet {
    let mut rules = RuleSet::default();
    for (mangled, decl) in candidates {
        for arg_index in 0..decl.param_count {
            rules.function_sources.push(FunctionSourceRule {
                id: probe_source_id(mangled, arg_index),
                language: None,
                matcher: FunctionMatcher {
                    exact: Some(mangled.clone()),
                    ..Default::default()
                },
                out: Port::Arg(arg_index + JNI_IMPLICIT_PARAMS),
                kind: "generic".to_string(),
            });
        }
        rules.function_sinks.push(FunctionSinkRule {
            id: probe_sink_id(mangled),
            language: None,
            matcher: FunctionMatcher {
                exact: Some(mangled.clone()),
                ..Default::default()
            },
            inputs: vec![Port::Return],
            kind: "generic".to_string(),
        });
    }
    rules
}

/// A native function's taint behavior, as inferred by running the probe
/// rules from [`build_probe_ruleset`] through the ordinary taint engine.
#[derive(Default)]
pub struct NativeSummary {
    /// Java-visible argument indices that reach the native function's own
    /// return value.
    pub pass_through_args: Vec<usize>,
    /// Java-visible argument indices that reach a genuine (non-probe) sink
    /// already defined for the native language, plus that sink's id/kind.
    pub native_sinks: Vec<(usize, String, String)>,
    /// The native function's return is reached by a genuine (non-probe)
    /// source already defined for the native language, with no dependency
    /// on any probed argument — its id/kind.
    pub native_source: Option<(String, String)>,
}

/// Splits `findings` into (real findings, probe-only findings) — a finding
/// counts as probe-only as soon as either its source or sink rule id is one
/// of ours, so it never reaches `all_findings`/the emitted report.
pub fn partition_probe_findings(
    findings: Vec<TaintFinding>,
) -> (Vec<TaintFinding>, Vec<TaintFinding>) {
    findings.into_iter().partition(|finding| {
        !is_probe_rule_id(&finding.source_rule_id) && !is_probe_rule_id(&finding.sink_rule_id)
    })
}

/// Folds a C/C++ group's probe-only findings into the running per-mangled-name
/// summary table.
pub fn fold_native_summaries(
    probe_findings: &[TaintFinding],
    summaries: &mut HashMap<String, NativeSummary>,
) {
    for finding in probe_findings {
        let probe_src = parse_probe_source_id(&finding.source_rule_id);
        let probe_sink = parse_probe_sink_id(&finding.sink_rule_id);
        match (probe_src, probe_sink) {
            (Some((mangled, arg_index)), Some(_)) => {
                summaries
                    .entry(mangled.to_string())
                    .or_default()
                    .pass_through_args
                    .push(arg_index);
            }
            (Some((mangled, arg_index)), None) => {
                summaries
                    .entry(mangled.to_string())
                    .or_default()
                    .native_sinks
                    .push((arg_index, finding.sink_rule_id.clone(), finding.sink_kind.clone()));
            }
            (None, Some(mangled)) => {
                let entry = summaries.entry(mangled.to_string()).or_default();
                if entry.native_source.is_none() {
                    entry.native_source =
                        Some((finding.source_rule_id.clone(), finding.source_kind.clone()));
                }
            }
            (None, None) => {}
        }
    }
}

/// Builds the synthetic `PropagatorRule`/`SinkRule`/`SourceRule` entries to
/// merge into the Java group's `RuleSet`, one set per native declaration that
/// both survived mangled-name deduplication and produced a non-empty
/// [`NativeSummary`].
pub fn build_bridge_ruleset(
    candidates: &HashMap<String, NativeMethodDecl>,
    summaries: &HashMap<String, NativeSummary>,
) -> RuleSet {
    let mut rules = RuleSet::default();
    for (mangled, decl) in candidates {
        let Some(summary) = summaries.get(mangled) else {
            continue;
        };
        let fqn = decl.qualified_name();
        let matcher = ApiMatcher {
            exact: Some(fqn.clone()),
            ..Default::default()
        };

        if !summary.pass_through_args.is_empty() {
            let flows = summary
                .pass_through_args
                .iter()
                .map(|&arg_index| FlowSpec {
                    from: Port::Arg(arg_index),
                    to: Port::Return,
                })
                .collect();
            rules.propagators.push(PropagatorRule {
                id: format!("ffi-bridge::{fqn}::pass-through"),
                language: Some(Language::Java),
                matcher: matcher.clone(),
                flows,
            });
        }
        // The synthetic rule's `kind` is the *real* underlying C/C++ rule's
        // kind, verbatim (not the probe's "generic") — so it stays subject
        // to the project's own kind-compatibility semantics on the Java
        // side, exactly as if this were an ordinary same-language flow.
        for (arg_index, sink_rule_id, sink_kind) in &summary.native_sinks {
            rules.sinks.push(SinkRule {
                id: format!("ffi-bridge::{fqn}::native-sink::arg{arg_index}::{sink_rule_id}"),
                language: Some(Language::Java),
                matcher: matcher.clone(),
                inputs: vec![Port::Arg(*arg_index)],
                kind: sink_kind.clone(),
            });
        }
        if let Some((source_rule_id, source_kind)) = &summary.native_source {
            rules.sources.push(SourceRule {
                id: format!("ffi-bridge::{fqn}::native-source::{source_rule_id}"),
                language: Some(Language::Java),
                matcher: matcher.clone(),
                out: Port::Return,
                kind: source_kind.clone(),
            });
        }
    }
    rules
}
