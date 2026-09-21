use anyhow::{Context, Result};
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_checker_api::{event_kind, CheckerFinding, CheckerManifest};
use uniflow_checker_host::{CheckerDiagnostic, CheckerHostOptions, CheckerManager};
use uniflow_frontend::{collect_mixed_source_files, parse_project_files};
use uniflow_hir::{Language, Program as HirProgram};
use uniflow_ir::{merge_programs, validate_program, Program as IrProgram};
use uniflow_lowering::lower_program;
use uniflow_models::{attach_legacy_metadata_for_ids, load_with_defaults_for_analysis};
use uniflow_rules::RuleSet;
use uniflow_taint::{analyze, TaintFinding};
use uniflow_value_flow::{
    build_for_scan_with_progress, build_with_capabilities, AnalysisCapabilities, FlowGraph,
    FlowNode,
};

/// Request for the shared post-lowering pipeline: build the flow graph, run
/// taint analysis, and broadcast the relevant checker events. This is the
/// segment of logic that was duplicated between UniFlow's single-language and
/// mixed-language project scans; it is the part any caller (CLI or an
/// embedding adapter) actually needs to turn IR into findings.
pub fn build_flow_graph(
    ir: &IrProgram,
    rules: &RuleSet,
    force_full_flow_for_dump: bool,
    checker_manager: &mut CheckerManager,
    checker_findings: &mut Vec<CheckerFinding>,
) -> Result<FlowGraph> {
    let force_full_flow = flow_requires_full_materialization(
        force_full_flow_for_dump,
        false,
        checker_manager.has_subscriber(event_kind::FLOW_SUMMARY),
        checker_manager.has_subscriber(event_kind::CALL),
    );
    let flow = if force_full_flow {
        build_with_capabilities(ir, rules, AnalysisCapabilities::full(), |_| {})
    } else {
        build_for_scan_with_progress(ir, rules, |_| {})
    };

    let flow_summary_subscribed = checker_manager.has_subscriber(event_kind::FLOW_SUMMARY);
    let call_subscribed = checker_manager.has_subscriber(event_kind::CALL);
    if flow_summary_subscribed || call_subscribed {
        let call_report = flow.call_report();
        if flow_summary_subscribed {
            checker_findings.extend(checker_manager.broadcast(
                event_kind::FLOW_SUMMARY,
                json!({
                    "stats": flow.stats(),
                    "calls": &call_report,
                }),
            )?);
        }
        if call_subscribed {
            for call in &call_report {
                checker_findings.extend(checker_manager.broadcast(
                    event_kind::CALL,
                    serde_json::to_value(call).context("failed to serialize call checker event")?,
                )?);
            }
        }
    }
    Ok(flow)
}

pub fn run_taint_analysis(
    flow: &FlowGraph,
    rules: &mut RuleSet,
    hydrate_bundled_metadata: bool,
) -> Result<Vec<TaintFinding>> {
    if hydrate_bundled_metadata {
        let mut report_ids = flow
            .synthetic_sinks
            .iter()
            .filter_map(|node| match &flow.graph[*node] {
                FlowNode::SyntheticSink { rule_id, .. } => Some(rule_id.clone()),
                _ => None,
            })
            .collect::<HashSet<_>>();
        report_ids.extend(
            flow.native_dataflow_diagnostics
                .iter()
                .map(|diagnostic| diagnostic.rule_id.clone()),
        );
        report_ids.extend(
            flow.lifetime_diagnostics
                .iter()
                .map(|diagnostic| diagnostic.rule_id.clone()),
        );
        attach_legacy_metadata_for_ids(&flow.language, rules, &report_ids)?;
    }
    Ok(analyze(flow, rules))
}

pub fn broadcast_taint_findings(
    findings: &[TaintFinding],
    checker_manager: &mut CheckerManager,
    checker_findings: &mut Vec<CheckerFinding>,
) -> Result<()> {
    if checker_manager.has_subscriber(event_kind::TAINT_FINDING) {
        for finding in findings {
            checker_findings.extend(checker_manager.broadcast(
                event_kind::TAINT_FINDING,
                serde_json::to_value(finding).context("failed to serialize taint checker event")?,
            )?);
        }
    }
    Ok(())
}

pub struct FlowAndTaintOutcome {
    pub flow: FlowGraph,
    pub findings: Vec<TaintFinding>,
}

/// Convenience for the common case (no post-analysis finding
/// transformation): build the flow graph, run taint analysis, and broadcast
/// `TAINT_FINDING` for exactly what `analyze` returned. The mixed-language
/// project scan needs to partition FFI-bridge probe findings out *before*
/// broadcasting, so it calls `build_flow_graph`/`run_taint_analysis`/
/// `broadcast_taint_findings` directly instead of this wrapper.
pub fn run_flow_and_taint(
    ir: &IrProgram,
    rules: &mut RuleSet,
    hydrate_bundled_metadata: bool,
    force_full_flow_for_dump: bool,
    checker_manager: &mut CheckerManager,
    checker_findings: &mut Vec<CheckerFinding>,
) -> Result<FlowAndTaintOutcome> {
    let flow = build_flow_graph(
        ir,
        rules,
        force_full_flow_for_dump,
        checker_manager,
        checker_findings,
    )?;
    let findings = run_taint_analysis(&flow, rules, hydrate_bundled_metadata)?;
    broadcast_taint_findings(&findings, checker_manager, checker_findings)?;
    Ok(FlowAndTaintOutcome { flow, findings })
}

/// Request for a full single-language scan: parse-to-HIR has already
/// happened (the caller owns file I/O and language detection), this takes it
/// from HIR through lowering, flow construction, and taint analysis.
pub struct SingleLanguageScanRequest {
    pub hir: HirProgram,
    pub rules: RuleSet,
    pub hydrate_bundled_metadata: bool,
    pub extra_ir_programs: Vec<IrProgram>,
    pub checker_paths: Vec<String>,
    pub checker_host_options: CheckerHostOptions,
    pub dump_graph: bool,
    pub dump_call_report: bool,
}

pub struct SingleLanguageScanOutcome {
    pub ir: IrProgram,
    pub flow: FlowGraph,
    pub findings: Vec<TaintFinding>,
    pub checker_findings: Vec<CheckerFinding>,
    pub checker_manifests: Vec<CheckerManifest>,
    pub checker_diagnostics: Vec<CheckerDiagnostic>,
}

pub fn run_single_language_scan(
    request: SingleLanguageScanRequest,
) -> Result<SingleLanguageScanOutcome> {
    let SingleLanguageScanRequest {
        hir,
        mut rules,
        hydrate_bundled_metadata,
        extra_ir_programs,
        checker_paths,
        checker_host_options,
        dump_graph,
        dump_call_report,
    } = request;

    let mut checker_manager = CheckerManager::load_with_options(&checker_paths, checker_host_options)?;
    let checker_manifests = checker_manager.manifests();
    let mut checker_findings = Vec::new();

    if checker_manager.has_subscriber(event_kind::ANALYSIS_START) {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::ANALYSIS_START,
            json!({
                "language": format!("{:?}", hir.language),
                "files": hir.files.iter().map(|file| file.path.clone()).collect::<Vec<_>>(),
                "checkers": &checker_manifests,
            }),
        )?);
    }
    if checker_manager.has_subscriber(event_kind::SOURCE_FILE) {
        for file in &hir.files {
            let source = fs::read_to_string(&file.path).with_context(|| {
                format!("failed to read checker source event from {}", file.path)
            })?;
            checker_findings.extend(checker_manager.broadcast(
                event_kind::SOURCE_FILE,
                source_file_payload(&file.path, &hir.language, source),
            )?);
        }
    }
    if checker_manager.has_subscriber(event_kind::HIR_PROGRAM) {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::HIR_PROGRAM,
            serde_json::to_value(&hir).context("failed to serialize HIR checker event")?,
        )?);
    }

    let ir = validate_or_quarantine_invalid_ir_functions(lower_program(&hir))?;
    let ir = if extra_ir_programs.is_empty() {
        ir
    } else {
        let mut programs = Vec::with_capacity(extra_ir_programs.len() + 1);
        programs.push(ir);
        programs.extend(extra_ir_programs);
        merge_programs(programs).context("failed to merge decoded archive classes into project IR")?
    };
    if checker_manager.has_subscriber(event_kind::IR_PROGRAM) {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::IR_PROGRAM,
            serde_json::to_value(&ir).context("failed to serialize IR checker event")?,
        )?);
    }

    drop(hir);

    let FlowAndTaintOutcome { flow, findings } = run_flow_and_taint(
        &ir,
        &mut rules,
        hydrate_bundled_metadata,
        dump_graph || dump_call_report,
        &mut checker_manager,
        &mut checker_findings,
    )?;

    let checker_finding_count_before_end = checker_findings.len();
    if checker_manager.has_subscriber(event_kind::ANALYSIS_END) {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::ANALYSIS_END,
            json!({
                "taintFindingCount": findings.len(),
                "checkerFindingCount": checker_finding_count_before_end,
            }),
        )?);
    }

    let checker_diagnostics = checker_manager.take_diagnostics();

    Ok(SingleLanguageScanOutcome {
        ir,
        flow,
        findings,
        checker_findings,
        checker_manifests,
        checker_diagnostics,
    })
}

pub fn source_file_payload(path: &str, language: &Language, source: String) -> serde_json::Value {
    json!({
        "path": path,
        "language": language.as_str(),
        "source": source,
    })
}

/// Keep a project scan available when a source frontend cannot lower a small
/// subset of unsupported constructs into valid IR. Validation remains strict
/// for every function that reaches dataflow: invalid functions are removed as
/// an explicit per-function quarantine, never passed to the solver. A whole
/// project must not lose its SARIF because one generated test helper used a
/// construct the frontend cannot model yet.
pub fn validate_or_quarantine_invalid_ir_functions(mut ir: IrProgram) -> Result<IrProgram> {
    let Err(errors) = validate_program(&ir) else {
        return Ok(ir);
    };
    let invalid_functions = errors
        .iter()
        .filter_map(|error| (error.function != "<program>").then_some(error.function.as_str()))
        .collect::<HashSet<_>>();
    if invalid_functions.is_empty() {
        let details = errors
            .iter()
            .map(|error| format!("{}: {}", error.function, error.message))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!("lowered IR failed validation:\n{details}");
    }

    let dropped = invalid_functions.len();
    let dropped_details = errors
        .iter()
        .filter(|error| invalid_functions.contains(error.function.as_str()))
        .map(|error| format!("{}: {}", error.function, error.message))
        .collect::<Vec<_>>()
        .join("\n  ");
    ir.functions
        .retain(|function| !invalid_functions.contains(function.name.as_str()));
    let retained_ids = ir.functions.iter().map(|function| function.id).collect::<HashSet<_>>();
    ir.entry_points.retain(|entry| retained_ids.contains(entry));
    if let Err(remaining) = validate_program(&ir) {
        let details = remaining
            .into_iter()
            .map(|error| format!("{}: {}", error.function, error.message))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!("lowered IR still failed validation after quarantining {dropped} function(s):\n{details}");
    }
    eprintln!(
        "uniflow: quarantined {dropped} function(s) with invalid lowered IR; continuing with {} valid function(s):\n  {dropped_details}",
        ir.functions.len()
    );
    Ok(ir)
}

pub fn flow_requires_full_materialization(
    dump_graph: bool,
    dump_call_report: bool,
    flow_summary_subscriber: bool,
    call_subscriber: bool,
) -> bool {
    dump_graph || dump_call_report || flow_summary_subscriber || call_subscriber
}

/// SAST/taint findings across a set of source paths, grouped and analyzed
/// per-language with the bundled default rule catalog — no external rule
/// file, no external checker plugin, no cache/bytecode-decoding machinery.
/// This is `crates/cli`'s `analyze-project`/`run_mixed_project` reduced to
/// exactly what an embedding adapter (`cosmos-agent`) needs for a
/// hook-triggered or whole-repo scan: point at some paths, get findings
/// back. Multi-language projects are handled the same way `run_mixed_project`
/// does — one independent per-language group, no cross-language system-graph
/// recovery (that feature is CLI-only and not needed for guardrail scanning).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ProjectScanOutcome {
    pub taint_findings: Vec<TaintFinding>,
    pub checker_findings: Vec<CheckerFinding>,
}

pub fn scan_source_paths(paths: &[PathBuf]) -> Result<ProjectScanOutcome> {
    let mixed_files = collect_mixed_source_files(paths).context("failed to collect source files")?;

    let mut groups: Vec<(Language, Vec<PathBuf>)> = Vec::new();
    for (language, path) in mixed_files {
        match groups.iter_mut().find(|(existing, _)| *existing == language) {
            Some((_, files)) => files.push(path),
            None => groups.push((language, vec![path])),
        }
    }

    let mut outcome = ProjectScanOutcome::default();
    for (language, files) in groups {
        if files.is_empty() {
            continue;
        }
        let hir = parse_project_files(language.clone(), &files)
            .with_context(|| format!("failed to parse {} source file(s) as {}", files.len(), language.as_str()))?;
        let rules = load_with_defaults_for_analysis(language.clone(), None)
            .with_context(|| format!("failed to load default rules for {}", language.as_str()))?;
        let scan = run_single_language_scan(SingleLanguageScanRequest {
            hir,
            rules,
            hydrate_bundled_metadata: true,
            extra_ir_programs: Vec::new(),
            checker_paths: Vec::new(),
            checker_host_options: CheckerHostOptions::default(),
            dump_graph: false,
            dump_call_report: false,
        })?;
        outcome.taint_findings.extend(scan.findings);
        outcome.checker_findings.extend(scan.checker_findings);
    }
    Ok(outcome)
}

/// Same as [`scan_source_paths`], scoped to files under one directory —
/// what `cosmos-agent scan`/`scan_code` actually calls.
pub fn scan_source_directory(root: &Path) -> Result<ProjectScanOutcome> {
    scan_source_paths(&[root.to_path_buf()])
}

#[cfg(test)]
mod scan_source_tests {
    use super::*;

    #[test]
    fn flags_a_string_concatenated_sql_query_built_from_a_flask_request_param() {
        let dir = tempfile::tempdir().unwrap();
        let app_py = dir.path().join("app.py");
        std::fs::write(
            &app_py,
            r#"
import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()
"#,
        )
        .unwrap();

        let outcome = scan_source_directory(dir.path()).expect("bundled-rule scan should succeed");
        assert!(
            !outcome.taint_findings.is_empty(),
            "expected the bundled default Python rule catalog to flag string-concatenated SQL built from a request parameter"
        );
    }

    #[test]
    fn a_clean_file_with_no_taint_flow_produces_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("util.py"), "def add(a, b):\n    return a + b\n").unwrap();
        let outcome = scan_source_directory(dir.path()).expect("scan should succeed");
        assert!(outcome.taint_findings.is_empty());
    }
}
