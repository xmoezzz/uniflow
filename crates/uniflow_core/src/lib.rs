use anyhow::{Context, Result};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_baseline::BaselineFinding;
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
    /// Structural security findings from the curated misuse pack (weak
    /// hash/cipher/random, insecure cookie/TLS setup, CERT C unsafe calls —
    /// see `uniflow_baseline::misuse_security_pack`).
    pub misuse_findings: Vec<BaselineFinding>,
    /// Files or language groups the scan could not analyze, and why. A
    /// frontend crash on one file skips that file, never the project.
    pub warnings: Vec<String>,
    /// Source files left out as vendored, minified or generated code.
    pub skipped_files: usize,
}

/// Knobs for [`scan_source_paths_with`]; `Default` is what cosmos-agent uses.
#[derive(Debug, Clone, Default)]
pub struct ProjectScanOptions {
    /// Also analyze vendored / minified / generated code (third-party
    /// libraries checked into the repo, `*.min.js`, bundles). Off by
    /// default: those findings belong to the library's own maintainers (SCA
    /// reports the vulnerable version), and minified bundles were 98.6% of
    /// all findings and the cause of 12–72 GB scans on real repos.
    pub include_vendored: bool,
}

/// Directory names whose content is third-party code by convention.
const VENDORED_DIRECTORIES: &[&str] = &[
    "node_modules", "bower_components", "jspm_packages", "vendor", "vendors", "third_party", "third-party", "thirdparty",
    "external", "site-packages", "dist-packages", "Pods", "Carthage", "wwwroot/lib",
];

/// Path components that mark generated/bundled output rather than source.
const GENERATED_DIRECTORIES: &[&str] = &["dist", "build", "out", ".next", ".nuxt", "coverage", "__generated__", "generated"];

/// Heuristic, file-local: vendored by location, minified/bundled by shape,
/// generated by an explicit marker in the file head. Only the first 8 KB are
/// read — enough for a marker or a telltale minified line.
pub fn is_vendored_or_generated(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    let components: Vec<&str> = text.split('/').collect();
    let dir_components = &components[..components.len().saturating_sub(1)];
    if dir_components.iter().any(|c| VENDORED_DIRECTORIES.contains(c)) || text.contains("/wwwroot/lib/") {
        return true;
    }
    let name = components.last().copied().unwrap_or_default().to_ascii_lowercase();
    let script = [".js", ".mjs", ".cjs", ".css"].iter().any(|ext| name.ends_with(ext));
    if script && (name.contains(".min.") || name.contains(".bundle.") || name.contains("-bundle.") || name.ends_with(".chunk.js")) {
        return true;
    }
    if script && dir_components.iter().any(|c| GENERATED_DIRECTORIES.contains(c)) {
        return true;
    }
    let Ok(mut file) = fs::File::open(path) else { return false };
    let mut head = vec![0u8; 8192];
    let read = std::io::Read::read(&mut file, &mut head).unwrap_or(0);
    let head = String::from_utf8_lossy(&head[..read]);
    let lower = head.to_ascii_lowercase();
    if ["@generated", "do not edit", "auto-generated", "autogenerated", "code generated by"].iter().any(|m| lower.contains(m))
        && lower.lines().take(20).any(|l| l.contains("generated"))
    {
        return true;
    }
    // Minified: a script whose first lines are enormous (bundlers emit one
    // line per module or per file).
    script && head.lines().take(5).any(|line| line.len() > 1000)
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panic".to_string())
}

/// Parse one language group; if the whole-group parse fails or panics,
/// find the offending files one by one, drop them with a warning, and parse
/// the rest. Java and Python index across files, so a whole-group parse is
/// the normal path and the per-file probe only runs on failure.
fn parse_group_isolated(language: &Language, files: &[PathBuf], warnings: &mut Vec<String>) -> Option<HirProgram> {
    let attempt = |files: &[PathBuf]| {
        let files = files.to_vec();
        let language = language.clone();
        std::panic::catch_unwind(move || parse_project_files(language, &files))
    };
    match attempt(files) {
        Ok(Ok(hir)) => return Some(hir),
        Ok(Err(error)) => warnings.push(format!("{} group failed to parse ({error:#}); isolating the failing files", language.as_str())),
        Err(payload) => warnings.push(format!("{} parser crashed ({}); isolating the failing files", language.as_str(), panic_text(payload))),
    }
    let mut good = Vec::new();
    for file in files {
        match attempt(std::slice::from_ref(file)) {
            Ok(Ok(_)) => good.push(file.clone()),
            Ok(Err(error)) => warnings.push(format!("skipped {}: {error:#}", file.display())),
            Err(payload) => warnings.push(format!("skipped {}: parser crashed ({})", file.display(), panic_text(payload))),
        }
    }
    if good.is_empty() {
        return None;
    }
    match attempt(&good) {
        Ok(Ok(hir)) => Some(hir),
        Ok(Err(error)) => {
            warnings.push(format!("{} group still failed after isolation: {error:#}", language.as_str()));
            None
        }
        Err(payload) => {
            warnings.push(format!("{} group still crashed after isolation: {}", language.as_str(), panic_text(payload)));
            None
        }
    }
}

/// `@/path/File.java:12:5` → (`/path/File.java`, 12).
fn location_file_line(location: &str) -> (String, u32) {
    let text = location.strip_prefix('@').unwrap_or(location);
    let mut parts = text.rsplitn(3, ':');
    let col = parts.next();
    let line = parts.next();
    match (line.and_then(|l| l.parse().ok()), col.and_then(|c| c.parse::<u32>().ok()), parts.next()) {
        (Some(line), Some(_), Some(path)) => (path.to_string(), line),
        _ => (text.to_string(), 0),
    }
}

/// One taint finding per sink location and weakness: the same sink is often
/// modeled by several packs (legacy, MIT, built-in) and reached from several
/// sources, which used to yield up to 8 rows for one bug — including the
/// same SQL injection reported as `[CWE-89]` by one pack and
/// `[CWE-564, CWE-89]` by another. Findings at one location merge when their
/// CWE sets overlap, or when one of them carries no CWE at all (it can't
/// name a *different* weakness); the merged finding keeps the union of CWEs,
/// and the other rule ids are recorded in `standards` as `rule:<id>` so
/// nothing about why it fired is lost. Disjoint CWE sets at one location
/// (e.g. a path-traversal and a command-injection model on one call) stay
/// separate findings. The first finding (packs load legacy-first, and
/// `analyze` orders by source discovery) is kept as the witness.
fn dedupe_taint_findings(findings: Vec<TaintFinding>) -> Vec<TaintFinding> {
    let mut by_location: HashMap<String, Vec<usize>> = HashMap::new();
    let mut out: Vec<TaintFinding> = Vec::with_capacity(findings.len());
    for finding in findings {
        let slots = by_location.entry(finding.sink_location.clone()).or_default();
        let target = slots.iter().copied().find(|&at| {
            let existing: &TaintFinding = &out[at];
            existing.cwe.is_empty() || finding.cwe.is_empty() || existing.cwe.iter().any(|c| finding.cwe.contains(c))
        });
        match target {
            Some(at) => {
                let merged = &mut out[at];
                for cwe in &finding.cwe {
                    if !merged.cwe.contains(cwe) {
                        merged.cwe.push(cwe.clone());
                    }
                }
                merged.cwe.sort();
                let tag = format!("rule:{}", finding.sink_rule_id);
                if finding.sink_rule_id != merged.sink_rule_id && !merged.standards.contains(&tag) {
                    merged.standards.push(tag);
                }
            }
            None => {
                slots.push(out.len());
                out.push(finding);
            }
        }
    }
    out
}

/// A misuse finding already reported by taint analysis at the same line
/// with an overlapping CWE adds nothing.
fn misuse_duplicates_taint(misuse: &BaselineFinding, taint: &HashSet<(String, u32, String)>) -> bool {
    misuse.cwe.iter().any(|cwe| taint.contains(&(misuse.path.clone(), misuse.line as u32, cwe.clone())))
}

pub fn scan_source_paths(paths: &[PathBuf]) -> Result<ProjectScanOutcome> {
    scan_source_paths_with(paths, &ProjectScanOptions::default())
}

pub fn scan_source_paths_with(paths: &[PathBuf], options: &ProjectScanOptions) -> Result<ProjectScanOutcome> {
    let mixed_files = collect_mixed_source_files(paths).context("failed to collect source files")?;
    let mut outcome = ProjectScanOutcome::default();

    let mut groups: Vec<(Language, Vec<PathBuf>)> = Vec::new();
    for (language, path) in mixed_files {
        if !options.include_vendored && is_vendored_or_generated(&path) {
            outcome.skipped_files += 1;
            continue;
        }
        match groups.iter_mut().find(|(existing, _)| *existing == language) {
            Some((_, files)) => files.push(path),
            None => groups.push((language, vec![path])),
        }
    }

    let misuse_pack = uniflow_baseline::misuse_security_pack().context("failed to load the security misuse pack")?;
    for (language, files) in groups {
        if files.is_empty() {
            continue;
        }
        let Some(hir) = parse_group_isolated(&language, &files, &mut outcome.warnings) else {
            continue;
        };
        let sources: HashMap<String, String> =
            hir.files.iter().filter_map(|file| fs::read_to_string(&file.path).ok().map(|text| (file.path.clone(), text))).collect();
        let misuse = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| misuse_pack.scan_hir(&hir, &sources)));
        let misuse = match misuse {
            Ok(findings) => findings,
            Err(payload) => {
                outcome.warnings.push(format!("{} misuse checks crashed ({}); skipped", language.as_str(), panic_text(payload)));
                Vec::new()
            }
        };
        drop(sources);
        let rules = load_with_defaults_for_analysis(language.clone(), None)
            .with_context(|| format!("failed to load default rules for {}", language.as_str()))?;
        let scan = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_single_language_scan(SingleLanguageScanRequest {
                hir,
                rules,
                hydrate_bundled_metadata: true,
                extra_ir_programs: Vec::new(),
                checker_paths: Vec::new(),
                checker_host_options: CheckerHostOptions::default(),
                dump_graph: false,
                dump_call_report: false,
            })
        }));
        let scan = match scan {
            Ok(Ok(scan)) => scan,
            Ok(Err(error)) => {
                outcome.warnings.push(format!("{} analysis failed: {error:#}", language.as_str()));
                outcome.misuse_findings.extend(misuse);
                continue;
            }
            Err(payload) => {
                outcome.warnings.push(format!("{} analysis crashed ({}); structural checks only", language.as_str(), panic_text(payload)));
                outcome.misuse_findings.extend(misuse);
                continue;
            }
        };
        let taint = dedupe_taint_findings(scan.findings);
        let reported: HashSet<(String, u32, String)> = taint
            .iter()
            .flat_map(|finding| {
                let (file, line) = location_file_line(&finding.sink_location);
                finding.cwe.iter().map(move |cwe| (file.clone(), line, cwe.clone()))
            })
            .collect();
        outcome.misuse_findings.extend(misuse.into_iter().filter(|finding| !misuse_duplicates_taint(finding, &reported)));
        outcome.taint_findings.extend(taint);
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

    /// Python propagation shapes that used to lose taint: f-strings (the
    /// frontend didn't parse them at all) and values read back out of dict
    /// and list *literals* (the engine read a fresh, empty cell instead of
    /// the literal's element cell).
    #[test]
    fn python_taint_survives_fstrings_and_container_literals() {
        let cases = [
            ("fstring", r#"os.system(f"echo {p}")"#),
            ("fstring_spec_and_conversion", r#"os.system(f"echo {p!r:>10} done")"#),
            ("fstring_nested_quotes", r#"os.system(f'echo {p + '\'' + ""}')"#),
            ("dict_literal", "d = {\"k\": p}\n    os.system(d[\"k\"])"),
            ("dict_literal_two_keys", "d = {\"k\": p, \"j\": \"s\"}\n    os.system(d[\"k\"])"),
            ("list_literal_one_element", "l = [p]\n    os.system(l[0])"),
            ("list_literal", "l = [p, \"a\"]\n    os.system(l[0])"),
            ("augmented_assignment", "c = \"echo \"\n    c += p\n    os.system(c)"),
            ("augmented_assignment_fstring", "c = \"sh -c \"\n    c += f\"echo {p}\"\n    os.system(c)"),
            // Flask sources beyond `.get(...)`, and dotted-import calls.
            ("getlist_index", "v = request.form.getlist(\"x\")\n    os.system(v[0])"),
            ("request_path_split", "parts = request.path.split(\"/\")\n    os.system(parts[1])"),
            ("query_string_decode", "q = request.query_string.decode(\"utf-8\")\n    os.system(q)"),
            ("header_names", "for name in request.headers.keys():\n        os.system(name)"),
            ("dotted_import_unquote", "import urllib.parse\n    os.system(urllib.parse.unquote_plus(p))"),
        ];
        for (name, body) in cases {
            let dir = tempfile::tempdir().unwrap();
            let source = format!("import os\nfrom flask import request\n\ndef handler():\n    p = request.args.get(\"x\")\n    {body}\n");
            std::fs::write(dir.path().join("app.py"), source).unwrap();
            let outcome = scan_source_directory(dir.path()).expect("scan should succeed");
            assert!(
                outcome.taint_findings.iter().any(|f| f.cwe.iter().any(|c| c == "CWE-78")),
                "{name}: expected a CWE-78 command-injection finding"
            );
        }
    }

    #[test]
    fn one_sql_injection_is_reported_once_across_rule_packs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "import sqlite3\nfrom flask import request\n\ndef h():\n    p = request.args.get(\"id\")\n    sqlite3.connect(\"a\").cursor().execute(\"select * from t where id = \" + p)\n",
        )
        .unwrap();
        let outcome = scan_source_directory(dir.path()).expect("scan should succeed");
        let sqli: Vec<_> = outcome.taint_findings.iter().filter(|f| f.cwe.iter().any(|c| c == "CWE-89")).collect();
        assert_eq!(sqli.len(), 1, "one CWE-89 finding at the sink, got {:?}", outcome.taint_findings.iter().map(|f| (&f.sink_rule_id, &f.cwe)).collect::<Vec<_>>());
        let locations: std::collections::HashSet<_> = outcome.taint_findings.iter().map(|f| &f.sink_location).collect();
        for location in locations {
            let at: Vec<_> = outcome.taint_findings.iter().filter(|f| &f.sink_location == location).collect();
            for (i, a) in at.iter().enumerate() {
                for b in &at[i + 1..] {
                    assert!(!a.cwe.is_empty() && !b.cwe.is_empty() && !a.cwe.iter().any(|c| b.cwe.contains(c)), "overlapping findings at {location} were not merged");
                }
            }
        }
    }

    #[test]
    fn a_clean_file_with_no_taint_flow_produces_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("util.py"), "def add(a, b):\n    return a + b\n").unwrap();
        let outcome = scan_source_directory(dir.path()).expect("scan should succeed");
        assert!(outcome.taint_findings.is_empty());
    }
}
