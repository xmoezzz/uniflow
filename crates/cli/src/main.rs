mod ffi_bridge;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uniflow_baseline::{
    audit_legacy_rule_tree, builtin_pack_manifest, builtin_security_pack,
    bundled_legacy_raw_assets, decrypt_legacy_rule_tree, BaselineFinding, BaselineScanOptions,
    OracleFormsMetadata,
};
use uniflow_cache::{
    build_project_with_cache_options, load_mixed_project_cache, load_project_cache,
    save_mixed_project_cache, save_project_cache, CachePlan, MixedProjectCache,
};
use uniflow_checker_api::{event_kind, CheckerFinding};
use uniflow_checker_host::{
    CheckerFailurePolicy, CheckerHostOptions, CheckerIsolation, CheckerManager,
};
use uniflow_frontend::{
    collect_auxiliary_files, collect_dotnet_bytecode_files, collect_java_bytecode_files,
    collect_mixed_source_files, collect_python_bytecode_files, collect_source_files,
    collect_wasm_bytecode_files, parse_project_files_with_options,
    parse_project_files_with_options_and_progress, parse_project_sources_with_options,
    parse_source_with_options, FrontendOptions,
};
use uniflow_hir::{Language, Program as HirProgram};
use uniflow_ir::{merge_programs, sample_java_sql_program, Program as IrProgram};
use uniflow_lang_java_bytecode::{lower_archive, lower_class_file};
use uniflow_lowering::lower_program;
use uniflow_models::{
    audit_legacy_jvm_rule_tree, compile_legacy_csharp_pack, compile_legacy_go_pack,
    compile_legacy_jvm_rule_tree, compile_legacy_native_dataflow_pack,
    compile_legacy_pysa_rule_tree,
    load_with_defaults, load_with_defaults_for_analysis, mit_catalog_manifest, mit_models_for,
    LegacyCsharpPack, LegacyGoPack, LegacyNativeDataflowPack,
};
use uniflow_platform::PlatformProfile;
use uniflow_report::{
    export_dot, export_excel_report, export_excel_report_sections,
    export_markdown_report_with_checkers, export_sarif_with_checker_manifests, ExcelReportSection,
};
use uniflow_reasoning_oracle::{
    ConstraintKind, ConstraintQuery, Domain, LeanOracle, LlmOracle, LlmOracleConfig, Oracle,
    SemanticAnswer, SemanticQuery,
};
use uniflow_rules::{RuleSet, RuleTranslations};
use uniflow_taint::{analyze, pretty_findings, TaintFinding};
use uniflow_value_flow::{build_for_rules_with_progress, FlowGraph};

/// Recursively extracts every supported archive (zip, tar and its
/// gzip/bzip2/xz/zstd/LZMA/lzip/Unix-compress-compressed forms, 7z, .deb,
/// .rpm, .cab, LHA/LZH, ISO9660, XAR, ar, cpio, mtree, shar, and RAR — see
/// `uniflow_archive_extract` for the full format list; filesystem/firmware
/// images remain out of scope) found anywhere under `roots` into a
/// scratch directory, then
/// appends that scratch directory to `roots` so the caller's existing
/// extension-based file collectors see the unpacked content with no changes
/// of their own. Returns the scratch directory's guard, which the caller
/// must keep bound (not `_`) for as long as anything still needs to read
/// from `roots` — it deletes the directory on drop.
fn extract_archives_into(roots: &mut Vec<PathBuf>) -> Result<Option<tempfile::TempDir>> {
    let Some((guard, report)) =
        uniflow_archive_extract::extract_archives_recursively(roots, &Default::default())
            .context("failed to recursively extract archives under the scan input")?
    else {
        return Ok(None);
    };
    if report.truncated {
        eprintln!(
            "uniflow: archive extraction under the scan input stopped early after hitting a \
             safety budget ({} archive(s) extracted, {} bytes written); results from inside \
             archives may be partial",
            report.archives_found, report.bytes_written
        );
    }
    roots.push(report.extraction_root);
    Ok(Some(guard))
}

#[derive(Debug, Parser)]
#[command(name = "uniflow")]
#[command(about = "Unified source-only value-flow and taint analyzer")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LangArg {
    /// Auto-detect each file's language by extension and scan the project
    /// as a set of independently-analyzed per-language groups. Valid only
    /// for `analyze-project`; `analyze-source` always names one language.
    Mix,
    C,
    Cpp,
    #[value(name = "csharp", alias = "cs")]
    CSharp,
    #[value(name = "objc", alias = "objective-c")]
    ObjC,
    #[value(name = "objcpp", alias = "objective-cpp")]
    ObjCpp,
    Java,
    Kotlin,
    Swift,
    Python,
    #[value(name = "go", alias = "golang")]
    Go,
    #[value(name = "javascript", alias = "js")]
    JavaScript,
    Jsp,
    Sql,
    Php,
    Ruby,
    Rust,
    #[value(name = "shell", alias = "sh")]
    Shell,
}

impl From<LangArg> for Language {
    fn from(value: LangArg) -> Self {
        match value {
            // `Mix` is a CLI-only orchestration mode handled before this
            // conversion is ever reached for `analyze-project`; converting
            // it here at all only matters for `analyze-source`, where it
            // naturally bails out downstream ("language must be
            // specified") rather than silently picking a language.
            LangArg::Mix => Language::Unknown,
            LangArg::C => Language::C,
            LangArg::Cpp => Language::Cpp,
            LangArg::CSharp => Language::CSharp,
            LangArg::ObjC => Language::ObjC,
            LangArg::ObjCpp => Language::ObjCpp,
            LangArg::Java => Language::Java,
            LangArg::Kotlin => Language::Kotlin,
            LangArg::Swift => Language::Swift,
            LangArg::Python => Language::Python,
            LangArg::Go => Language::Go,
            LangArg::JavaScript => Language::JavaScript,
            LangArg::Jsp => Language::Jsp,
            LangArg::Sql => Language::Sql,
            LangArg::Php => Language::Php,
            LangArg::Ruby => Language::Ruby,
            LangArg::Rust => Language::Rust,
            LangArg::Shell => Language::Shell,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PlatformArg {
    #[value(name = "generic")]
    Generic,
    #[value(name = "linux-x86_64-gnu")]
    LinuxX86_64Gnu,
    #[value(name = "windows-x86_64-msvc")]
    WindowsX86_64Msvc,
    #[value(name = "macos-aarch64")]
    MacosAarch64,
}

impl From<PlatformArg> for PlatformProfile {
    fn from(value: PlatformArg) -> Self {
        match value {
            PlatformArg::Generic => PlatformProfile::generic(),
            PlatformArg::LinuxX86_64Gnu => PlatformProfile::linux_x86_64_gnu(),
            PlatformArg::WindowsX86_64Msvc => PlatformProfile::windows_x86_64_msvc(),
            PlatformArg::MacosAarch64 => PlatformProfile::macos_aarch64(),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CheckerFailureArg {
    FailFast,
    Continue,
}

impl From<CheckerFailureArg> for CheckerFailurePolicy {
    fn from(value: CheckerFailureArg) -> Self {
        match value {
            CheckerFailureArg::FailFast => CheckerFailurePolicy::FailFast,
            CheckerFailureArg::Continue => CheckerFailurePolicy::Continue,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CheckerIsolationArg {
    Process,
    InProcess,
}

/// The only theorem shapes UniFlow currently sends to Lean's kernel-checked
/// `omega` procedure.  These deliberately stay separate from language
/// syntax: the input is the small normalized integer-expression grammar
/// accepted by the reasoning-oracle crate.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProofKindArg {
    Satisfiability,
    Equivalence,
    Implication,
}

impl From<ProofKindArg> for ConstraintKind {
    fn from(value: ProofKindArg) -> Self {
        match value {
            ProofKindArg::Satisfiability => ConstraintKind::Satisfiability,
            ProofKindArg::Equivalence => ConstraintKind::Equivalence,
            ProofKindArg::Implication => ConstraintKind::Implication,
        }
    }
}

impl From<CheckerIsolationArg> for CheckerIsolation {
    fn from(value: CheckerIsolationArg) -> Self {
        match value {
            CheckerIsolationArg::Process => CheckerIsolation::Process,
            CheckerIsolationArg::InProcess => CheckerIsolation::InProcess,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct RuntimeCheckerOptions {
    timeout_ms: u64,
    failure_policy: CheckerFailureArg,
    isolation: CheckerIsolationArg,
}

#[derive(Debug, Clone, Default, Args)]
struct CFamilyFrontendArgs {
    /// Read per-translation-unit flags from compile_commands.json.
    #[arg(long, value_name = "FILE")]
    compile_commands: Option<PathBuf>,
    /// Define a preprocessor macro (NAME or NAME=VALUE). May be repeated.
    #[arg(long = "define", value_name = "MACRO")]
    defines: Vec<String>,
    /// Undefine a preprocessor macro. May be repeated.
    #[arg(long = "undefine", value_name = "MACRO")]
    undefines: Vec<String>,
    /// Add a C/C++ include search path. May be repeated.
    #[arg(long = "include-path", value_name = "DIR")]
    include_paths: Vec<PathBuf>,
    /// C or C++ language standard, for example c11 or c++20.
    #[arg(long = "std", value_name = "STANDARD")]
    language_standard: Option<String>,
    /// Compiler target triple used by source configuration models.
    #[arg(long, value_name = "TRIPLE")]
    target_triple: Option<String>,
}

fn make_frontend_options(platform: PlatformArg, args: CFamilyFrontendArgs) -> FrontendOptions {
    let mut defines = std::collections::BTreeMap::new();
    for define in args.defines {
        if let Some((name, value)) = define.split_once('=') {
            defines.insert(name.to_string(), Some(value.to_string()));
        } else {
            defines.insert(define, None);
        }
    }
    FrontendOptions {
        platform: platform.into(),
        defines,
        undefines: args.undefines.into_iter().collect(),
        include_paths: args.include_paths,
        language_standard: args.language_standard,
        target_triple: args.target_triple,
        compile_commands: args.compile_commands,
    }
}

#[derive(Debug, Default, Clone)]
struct ReportOutputs {
    sarif_out: Option<String>,
    dot_out: Option<String>,
    markdown_out: Option<String>,
    xlsx_out: Option<String>,
    /// Only populated by mixed-language project scans: the recovered
    /// system-wide graph (Docker Compose/Kubernetes topology, config
    /// resolution, HTTP routes, lifecycle hooks, ...) — see
    /// `uniflow_system_graph`.
    system_graph_out: Option<String>,
}

#[derive(Debug, Subcommand)]
enum Command {
    CheckRules {
        #[arg(long)]
        rules: String,
    },
    /// Ask an explicitly configured LLM for an advisory review of one source file.
    /// The answer is never promoted to a security finding without an
    /// independently verifiable UniFlow rule/flow path.
    ReviewCode {
        #[arg(long)]
        language: LangArg,
        #[arg(long)]
        input: String,
        /// OpenAI-compatible chat-completions endpoint. Source is sent only
        /// after --allow-llm-source-upload is also supplied.
        #[arg(long)]
        llm_endpoint: String,
        /// Model name accepted by --llm-endpoint.
        #[arg(long)]
        llm_model: String,
        /// Environment variable that holds the endpoint API key.
        #[arg(long, default_value = "UNIFLOW_LLM_API_KEY")]
        llm_api_key_env: String,
        /// Required acknowledgement that the input source may leave this machine.
        #[arg(long, default_value_t = false)]
        allow_llm_source_upload: bool,
        /// Limit source uploaded to the LLM, in bytes.
        #[arg(long, default_value_t = 65_536)]
        max_input_bytes: usize,
        /// Per-request network deadline for the advisory review.
        #[arg(long, default_value_t = 15_000)]
        llm_timeout_ms: u64,
        /// Optional focused review question; defaults to a security/correctness review.
        #[arg(long)]
        question: Option<String>,
        /// Write the advisory JSON document to this path instead of stdout.
        #[arg(long)]
        json_out: Option<String>,
    },
    /// Submit a normalized integer constraint to Lean's kernel-checked
    /// omega procedure. This emits a formal result or an explicit
    /// toolchain-unavailable/unknown state; it never emits a taint finding.
    ProveConstraint {
        #[arg(long, value_enum)]
        kind: ProofKindArg,
        /// Left-hand normalized integer expression (or predicate for satisfiability).
        #[arg(long)]
        lhs: String,
        /// Right-hand normalized integer expression; required for equivalence and implication.
        #[arg(long)]
        rhs: Option<String>,
        /// Optional bounded variable assumption, NAME=LOW..HIGH. May be repeated.
        #[arg(long = "bound", value_name = "NAME=LOW..HIGH")]
        bounds: Vec<String>,
        /// Lean executable to use; defaults to `lean` on PATH.
        #[arg(long, default_value = "lean")]
        lean_binary: String,
        /// Write the formal-result JSON document to this path instead of stdout.
        #[arg(long)]
        json_out: Option<String>,
    },
    ListRulePacks,
    ListBaselinePacks,
    ListBundledLegacyAssets {
        #[arg(long)]
        prefix: Option<String>,
    },
    AuditLegacyRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        json_out: Option<String>,
    },
    DecryptLegacyRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long, default_value_t = false)]
        overwrite: bool,
        #[arg(long)]
        json_out: Option<String>,
    },
    AuditLegacyJvmRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        json_out: Option<String>,
    },
    CompileLegacyJvmRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        language: LangArg,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        diagnostics_out: Option<String>,
        /// Separate metadata audit; missing translations are not hidden in model counts.
        #[arg(long)]
        metadata_report_out: Option<String>,
    },
    /// Attach original knowledge-base text to native rules by their LEGACY-MSG ids.
    EnrichLegacyJvmBaseline {
        #[arg(long)]
        input: String,
        #[arg(long)]
        knowledge: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        metadata_report_out: Option<String>,
    },
    CompileLegacyNativeRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        language: LangArg,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        diagnostics_out: Option<String>,
    },
    CompileLegacyPysaRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        diagnostics_out: Option<String>,
    },
    CompileLegacyGoRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        diagnostics_out: Option<String>,
    },
    CompileLegacyCsharpRules {
        #[arg(long)]
        input: String,
        #[arg(long)]
        messages: String,
        #[arg(long)]
        vulnerabilities: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        output: String,
        #[arg(long)]
        diagnostics_out: Option<String>,
    },
    DumpMitRules {
        #[arg(long)]
        language: LangArg,
        #[arg(long)]
        output: Option<String>,
    },
    CheckBaseline {
        /// Defaults to `mix`: route every source file to its own frontend
        /// before running bundled coding-style/baseline checkers.
        #[arg(long, value_enum, default_value = "mix")]
        language: LangArg,
        #[arg(long = "input", required = true)]
        inputs: Vec<String>,
        #[arg(long)]
        json_out: Option<String>,
        /// Oracle Forms metadata JSON used by metadata-aware PL/SQL rules.
        #[arg(long)]
        forms_metadata: Option<String>,
        /// XPath 1.0 expression for the bundled configurable SQL AST rule.
        #[arg(long)]
        sql_xpath_query: Option<String>,
        /// Finding message used with --sql-xpath-query.
        #[arg(long)]
        sql_xpath_message: Option<String>,
    },
    Demo {
        #[arg(long)]
        rules: Option<String>,
        #[arg(long, default_value_t = false)]
        use_default_models: bool,
        #[arg(long, default_value_t = false)]
        dump_graph: bool,
        #[arg(long, default_value_t = false)]
        dump_call_report: bool,
        #[arg(long, default_value_t = false)]
        dump_stats: bool,
        #[arg(long, default_value_t = false)]
        pretty_findings: bool,
        #[arg(long)]
        sarif_out: Option<String>,
        #[arg(long)]
        dot_out: Option<String>,
        #[arg(long)]
        markdown_out: Option<String>,
        /// Write a formatted Excel workbook with findings, paths, calls, and summaries.
        #[arg(long)]
        xlsx_out: Option<String>,
    },
    AnalyzeSource {
        #[arg(long)]
        language: LangArg,
        #[arg(long, value_enum, default_value = "generic")]
        platform: PlatformArg,
        #[command(flatten)]
        c_family: CFamilyFrontendArgs,
        #[arg(long)]
        input: String,
        #[arg(long)]
        rules: Option<String>,
        #[arg(long, default_value_t = false)]
        use_default_models: bool,
        /// Restrict reportable rules by id while retaining their dataflow dependencies.
        #[arg(long = "rule-id", value_name = "ID")]
        rule_ids: Vec<String>,
        #[arg(long, default_value_t = false)]
        dump_hir: bool,
        #[arg(long, default_value_t = false)]
        dump_ir: bool,
        #[arg(long, default_value_t = false)]
        dump_graph: bool,
        #[arg(long, default_value_t = false)]
        dump_call_report: bool,
        #[arg(long, default_value_t = false)]
        dump_stats: bool,
        #[arg(long, default_value_t = false)]
        pretty_findings: bool,
        #[arg(long)]
        sarif_out: Option<String>,
        #[arg(long)]
        dot_out: Option<String>,
        #[arg(long)]
        markdown_out: Option<String>,
        /// Write a formatted Excel workbook with findings, paths, calls, and summaries.
        #[arg(long)]
        xlsx_out: Option<String>,
        /// Load an external checker dynamic library. May be repeated.
        #[arg(long = "checker", value_name = "LIBRARY")]
        checkers: Vec<String>,
        /// Maximum time allowed for checker startup and each event.
        #[arg(long, default_value_t = 5000)]
        checker_timeout_ms: u64,
        /// Stop analysis on checker failure, or disable the checker and continue.
        #[arg(long, value_enum, default_value = "fail-fast")]
        checker_failure: CheckerFailureArg,
        /// Run checkers in an isolated worker process by default.
        #[arg(long, value_enum, default_value = "process")]
        checker_isolation: CheckerIsolationArg,
    },
    AnalyzeProject {
        /// Defaults to `mix`: auto-detect each file's language by extension
        /// and analyze the project as independent per-language groups.
        #[arg(long, value_enum, default_value = "mix")]
        language: LangArg,
        #[arg(long, value_enum, default_value = "generic")]
        platform: PlatformArg,
        #[command(flatten)]
        c_family: CFamilyFrontendArgs,
        #[arg(long = "input", required = true)]
        inputs: Vec<String>,
        #[arg(long)]
        rules: Option<String>,
        #[arg(long, default_value_t = false)]
        use_default_models: bool,
        /// Restrict reportable rules by id while retaining their dataflow dependencies.
        #[arg(long = "rule-id", value_name = "ID")]
        rule_ids: Vec<String>,
        #[arg(long, default_value_t = false)]
        list_files: bool,
        #[arg(long, default_value_t = false)]
        dump_hir: bool,
        #[arg(long, default_value_t = false)]
        dump_ir: bool,
        #[arg(long, default_value_t = false)]
        dump_graph: bool,
        #[arg(long, default_value_t = false)]
        dump_call_report: bool,
        #[arg(long, default_value_t = false)]
        dump_stats: bool,
        #[arg(long, default_value_t = false)]
        pretty_findings: bool,
        #[arg(long, default_value_t = false)]
        dump_cache_plan: bool,
        #[arg(long)]
        cache_in: Option<String>,
        #[arg(long)]
        cache_out: Option<String>,
        #[arg(long)]
        sarif_out: Option<String>,
        #[arg(long)]
        dot_out: Option<String>,
        #[arg(long)]
        markdown_out: Option<String>,
        /// Write one consolidated Excel workbook, including mixed-language scans.
        #[arg(long)]
        xlsx_out: Option<String>,
        /// Mixed-language scans only: writes the recovered system-wide
        /// graph (Docker Compose/Kubernetes topology, config resolution,
        /// HTTP routes, lifecycle hooks, ...) as JSON.
        #[arg(long)]
        system_graph_out: Option<String>,
        /// Load an external checker dynamic library. May be repeated.
        #[arg(long = "checker", value_name = "LIBRARY")]
        checkers: Vec<String>,
        /// Maximum time allowed for checker startup and each event.
        #[arg(long, default_value_t = 5000)]
        checker_timeout_ms: u64,
        /// Stop analysis on checker failure, or disable the checker and continue.
        #[arg(long, value_enum, default_value = "fail-fast")]
        checker_failure: CheckerFailureArg,
        /// Run checkers in an isolated worker process by default.
        #[arg(long, value_enum, default_value = "process")]
        checker_isolation: CheckerIsolationArg,
    },
}

struct ProgressTracker {
    multi: MultiProgress,
    overall: ProgressBar,
    total_steps: u64,
    completed_steps: u64,
}

impl ProgressTracker {
    fn new(total_steps: u64) -> Self {
        let multi = MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(10));
        let overall = multi.add(ProgressBar::new(total_steps));
        overall.set_style(progress_style());
        overall.set_message("starting");
        Self {
            multi,
            overall,
            total_steps,
            completed_steps: 0,
        }
    }

    fn advance(&mut self, phase: &str, elapsed: Duration) {
        self.completed_steps += 1;
        self.overall
            .set_position(self.completed_steps.min(self.total_steps));
        self.overall.set_message(format!(
            "{}/{} done, last: {} ({})",
            self.completed_steps,
            self.total_steps,
            phase,
            format_duration(elapsed)
        ));
    }

    fn phase<T, F>(&mut self, name: &str, detail: impl Into<String>, f: F) -> Result<T>
    where
        F: FnOnce(&MultiProgress) -> Result<T>,
    {
        self.phase_with_spinner(name, detail, |multi, _spinner| f(multi))
    }

    fn phase_with_spinner<T, F>(&mut self, name: &str, detail: impl Into<String>, f: F) -> Result<T>
    where
        F: FnOnce(&MultiProgress, &ProgressBar) -> Result<T>,
    {
        let spinner = self.multi.add(ProgressBar::new_spinner());
        spinner.set_style(spinner_style());
        spinner.set_message(format!("{}: {}", name, detail.into()));
        spinner.tick();
        let start = Instant::now();
        let result = f(&self.multi, &spinner);
        let elapsed = start.elapsed();
        match &result {
            Ok(_) => spinner.finish_with_message(format!(
                "{} done in {}",
                name,
                format_duration(elapsed)
            )),
            Err(_) => spinner.abandon_with_message(format!(
                "{} failed after {}",
                name,
                format_duration(elapsed)
            )),
        }
        self.advance(name, elapsed);
        result
    }

    fn finish(&self) {
        self.overall.finish_with_message("analysis complete");
    }
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.cyan} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} {msg}",
    )
    .unwrap()
    .progress_chars("█▉▊▋▌▍▎▏  ")
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {msg}").unwrap()
}

fn file_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{spinner:.yellow} [{elapsed_precise}] [{wide_bar:.yellow/blue}] {pos}/{len} {msg}",
    )
    .unwrap()
    .progress_chars("█▉▊▋▌▍▎▏  ")
}

fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{}. {:03}s", secs, millis).replace(" ", "")
    } else {
        format!("{}ms", millis)
    }
}

/// Deeply nested or generated source (huge `else if` chains, long argument
/// lists, deeply nested expressions) can drive the recursive-descent parser
/// and HIR walkers past the default OS thread stack. Run the real work on a
/// worker thread with a much larger stack instead of relying on the main
/// thread's (often 8MB) stack.
const WORKER_STACK_SIZE: usize = 1 << 30;

fn default_semantic_review_question() -> String {
    "Review this one code unit for security and correctness defects. Identify concrete unsafe source/sink, authorization or validation gaps, injection/deserialization, filesystem/network/crypto, lifetime/concurrency, and framework-boundary hazards. State the exact symbols and preconditions for every claim. This is an advisory hypothesis: do not claim proof of a vulnerability when required context is absent.".to_string()
}

/// LLM output is deliberately isolated from ordinary SARIF findings. A model
/// can suggest a useful hypothesis, but it has not established a source,
/// sink, propagation path, or deployment precondition in UniFlow's IR.
fn semantic_review_document(input: &str, language: Language, answer: SemanticAnswer) -> serde_json::Value {
    json!({
        "classification": "advisory",
        "oracle": "llm",
        "input": input,
        "language": language.as_str(),
        "answer": answer.answer,
        "confidence": answer.confidence,
        "rationale": answer.rationale,
        "verification_required": [
            "Resolve every cited symbol and source span in the parsed frontend.",
            "Establish a deterministic source-to-sink or checker-rule path before promotion to a finding.",
            "Record configuration, framework, FFI, or deployment assumptions as boundary evidence."
        ]
    })
}

fn parse_proof_bounds(raw_bounds: Vec<String>) -> Result<Vec<(String, String)>> {
    raw_bounds
        .into_iter()
        .map(|raw| {
            let (name, range) = raw
                .split_once('=')
                .context("--bound must have the form NAME=LOW..HIGH")?;
            if name.is_empty()
                || !name.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
                || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
            {
                anyhow::bail!("invalid --bound variable name {name:?}");
            }
            let (low, high) = range
                .split_once("..")
                .context("--bound range must have the form LOW..HIGH")?;
            let _: i64 = low.trim().parse().context("--bound lower bound must be an integer")?;
            let _: i64 = high.trim().parse().context("--bound upper bound must be an integer")?;
            Ok((name.to_string(), range.to_string()))
        })
        .collect()
}

fn formal_proof_document(
    query: &ConstraintQuery,
    lean_binary: &str,
    decision: Option<uniflow_reasoning_oracle::Decision>,
) -> serde_json::Value {
    json!({
        "classification": "formal-proof-result",
        "verifier": "lean-omega",
        "lean_binary": lean_binary,
        "query": query,
        "status": if decision.is_some() { "kernel-checked" } else { "toolchain-unavailable" },
        "decision": decision,
        "finding_promotion": "A formal arithmetic decision constrains path feasibility only. A UniFlow source-to-sink path and all boundary evidence remain required for a security finding."
    })
}

fn main() -> Result<()> {
    std::thread::Builder::new()
        .stack_size(WORKER_STACK_SIZE)
        .spawn(run)
        .expect("failed to spawn analysis worker thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

fn run() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("__checker-worker") {
        let path = std::env::args_os()
            .nth(2)
            .context("checker worker requires a library path")?;
        return uniflow_checker_host::run_worker(Path::new(&path));
    }

    let cli = Cli::parse();
    match cli.command {
        Command::CheckRules { rules } => {
            let text = fs::read_to_string(&rules)
                .with_context(|| format!("failed to read rules from {rules}"))?;
            let _ = RuleSet::from_yaml_str(&text)?;
            println!("rules ok");
        }
        Command::ReviewCode {
            language,
            input,
            llm_endpoint,
            llm_model,
            llm_api_key_env,
            allow_llm_source_upload,
            max_input_bytes,
            llm_timeout_ms,
            question,
            json_out,
        } => {
            if matches!(language, LangArg::Mix) {
                anyhow::bail!("review-code requires one concrete --language; use analyze-project --language mix for a system scan");
            }
            if !allow_llm_source_upload {
                anyhow::bail!(
                    "refusing to upload source: pass --allow-llm-source-upload after reviewing the endpoint and data-handling policy"
                );
            }
            if max_input_bytes == 0 {
                anyhow::bail!("--max-input-bytes must be greater than zero");
            }
            let source = fs::read_to_string(&input)
                .with_context(|| format!("failed to read source from {input}"))?;
            if source.len() > max_input_bytes {
                anyhow::bail!(
                    "refusing to upload {} bytes from {input}; --max-input-bytes is {max_input_bytes}",
                    source.len()
                );
            }
            let api_key = std::env::var(&llm_api_key_env).with_context(|| {
                format!("LLM API key environment variable {llm_api_key_env:?} is not set")
            })?;
            let mut config = LlmOracleConfig::new(llm_endpoint, api_key, llm_model);
            config.timeout = Duration::from_millis(llm_timeout_ms.clamp(1, 120_000));
            let answer = LlmOracle::new(config).interpret_semantics(&SemanticQuery {
                language: Language::from(language).as_str().to_string(),
                code_snippet: source,
                question: question.unwrap_or_else(default_semantic_review_question),
            })?;
            let document = semantic_review_document(&input, Language::from(language), answer);
            let rendered = serde_json::to_string_pretty(&document)
                .context("failed to serialize LLM advisory review")?;
            if let Some(path) = json_out {
                write_text_file(&path, &rendered)?;
            } else {
                println!("{rendered}");
            }
        }
        Command::ProveConstraint { kind, lhs, rhs, bounds, lean_binary, json_out } => {
            if matches!(kind, ProofKindArg::Equivalence | ProofKindArg::Implication) && rhs.is_none() {
                anyhow::bail!("--rhs is required for --kind {kind:?}");
            }
            if matches!(kind, ProofKindArg::Satisfiability) && rhs.is_some() {
                anyhow::bail!("--rhs is not accepted for --kind satisfiability");
            }
            let query = ConstraintQuery {
                kind: kind.into(),
                domain: Domain::IntegerArithmetic,
                language: "uniflow-normalized".to_string(),
                lhs,
                rhs,
                context: parse_proof_bounds(bounds)?,
            };
            let decision = LeanOracle::detect_named(&lean_binary)
                .map(|oracle| oracle.decide_constraint(&query))
                .transpose()?;
            let document = formal_proof_document(&query, &lean_binary, decision);
            let rendered = serde_json::to_string_pretty(&document)
                .context("failed to serialize Lean proof result")?;
            if let Some(path) = json_out {
                write_text_file(&path, &rendered)?;
            } else {
                println!("{rendered}");
            }
        }
        Command::ListRulePacks => {
            println!("{}", mit_catalog_manifest());
        }
        Command::ListBaselinePacks => {
            println!("{}", builtin_pack_manifest());
        }
        Command::ListBundledLegacyAssets { prefix } => {
            let assets = bundled_legacy_raw_assets()
                .iter()
                .filter(|asset| {
                    prefix
                        .as_deref()
                        .is_none_or(|prefix| asset.path.starts_with(prefix))
                })
                .map(|asset| json!({ "path": asset.path, "bytes": asset.bytes.len() }))
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&assets)
                    .context("failed to serialize bundled legacy asset list")?
            );
        }
        Command::AuditLegacyRules { input, json_out } => {
            let audit = audit_legacy_rule_tree(Path::new(&input))?;
            let json = serde_json::to_string_pretty(&audit)
                .context("failed to serialize legacy rule audit")?;
            if let Some(path) = json_out {
                write_text_file(&path, &json)?;
            } else {
                println!("{json}");
            }
        }
        Command::DecryptLegacyRules {
            input,
            output,
            overwrite,
            json_out,
        } => {
            let report =
                decrypt_legacy_rule_tree(Path::new(&input), Path::new(&output), overwrite)?;
            let json = serde_json::to_string_pretty(&report)
                .context("failed to serialize legacy rule decryption report")?;
            if let Some(path) = json_out {
                write_text_file(&path, &json)?;
            } else {
                println!("{json}");
            }
        }
        Command::AuditLegacyJvmRules { input, json_out } => {
            let report = audit_legacy_jvm_rule_tree(Path::new(&input))?;
            let json = serde_json::to_string_pretty(&report)
                .context("failed to serialize legacy JVM rule report")?;
            if let Some(path) = json_out {
                write_text_file(&path, &json)?;
            } else {
                println!("{json}");
            }
        }
        Command::CompileLegacyJvmRules {
            input,
            language,
            namespace,
            output,
            diagnostics_out,
            metadata_report_out,
        } => {
            let compilation = compile_legacy_jvm_rule_tree(
                Path::new(&input),
                Language::from(language),
                &namespace,
            )?;
            let yaml = serde_yaml::to_string(&compilation.rules)
                .context("failed to serialize compiled legacy JVM rules")?;
            write_text_file(&output, &yaml)?;
            if let Some(path) = diagnostics_out {
                let json = serde_json::to_string_pretty(&compilation.diagnostics)
                    .context("failed to serialize legacy JVM compile diagnostics")?;
                write_text_file(&path, &json)?;
            }
            if let Some(path) = metadata_report_out {
                write_text_file(
                    &path,
                    &serde_json::to_string_pretty(&compilation.metadata_report)?,
                )?;
            }
            println!(
                "compiled {} sources, {} sinks, {} sanitizers, {} propagators; {} deferred features",
                compilation.rules.sources.len(),
                compilation.rules.sinks.len(),
                compilation.rules.sanitizers.len(),
                compilation.rules.propagators.len(),
                compilation.diagnostics.len()
            );
        }
        Command::EnrichLegacyJvmBaseline {
            input,
            knowledge,
            output,
            metadata_report_out,
        } => {
            let text = fs::read_to_string(&input)?;
            let mut document: serde_yaml::Value = serde_yaml::from_str(&text)?;
            let mut pack = uniflow_baseline::BaselinePack::from_yaml_str(&text)?;
            let mut catalog =
                uniflow_models::LegacyJvmKnowledgeCatalog::from_tree(Path::new(&knowledge))?;
            let mut names = std::collections::BTreeMap::new();
            let mut metadata = Vec::new();
            for rule in &pack.rules {
                names.insert(rule.id.clone(), rule.id.clone());
                for standard in &rule.standards {
                    if let Some(id) = standard.strip_prefix("LEGACY-MSG-") {
                        for id in id.split(',') {
                            catalog.add_rule_mapping(&rule.id, "ast", id.trim())?;
                        }
                    }
                }
                metadata.push(serde_yaml::from_value::<uniflow_rules::RuleMetadata>(
                    serde_yaml::to_value(rule)?,
                )?);
            }
            let report = catalog.enrich(&mut metadata, &names);
            for (rule, metadata) in pack.rules.iter_mut().zip(metadata) {
                rule.translations =
                    serde_yaml::from_value(serde_yaml::to_value(metadata.translations)?)?;
                rule.standards = metadata.standards;
                rule.cwe = metadata.cwe;
            }
            pack.validate()?;
            for (value, rule) in document
                .get_mut("rules")
                .and_then(serde_yaml::Value::as_sequence_mut)
                .context("baseline document has no rules sequence")?
                .iter_mut()
                .zip(&pack.rules)
            {
                value["translations"] = serde_yaml::to_value(&rule.translations)?;
                value["standards"] = serde_yaml::to_value(&rule.standards)?;
                value["cwe"] = serde_yaml::to_value(&rule.cwe)?;
            }
            write_text_file(&output, &serde_yaml::to_string(&document)?)?;
            if let Some(path) = metadata_report_out {
                write_text_file(&path, &serde_json::to_string_pretty(&report)?)?;
            }
            println!(
                "completed {} of {} baseline rule presentations; {} contain original source prose",
                report.enriched_sinks,
                pack.rules.len(),
                report.source_enriched_sinks
            );
        }
        Command::CompileLegacyNativeRules {
            input,
            language,
            namespace,
            output,
            diagnostics_out,
        } => {
            let text = fs::read_to_string(&input)
                .with_context(|| format!("failed to read legacy native rules from {input}"))?;
            let pack = LegacyNativeDataflowPack::from_yaml_str(&text)?;
            let compilation =
                compile_legacy_native_dataflow_pack(&pack, Language::from(language), &namespace)?;
            let yaml = serde_yaml::to_string(&compilation.rules)
                .context("failed to serialize compiled legacy native rules")?;
            write_text_file(&output, &yaml)?;
            if let Some(path) = diagnostics_out {
                let json = serde_json::to_string_pretty(&compilation.diagnostics)
                    .context("failed to serialize legacy native compile diagnostics")?;
                write_text_file(&path, &json)?;
            }
            println!(
                "compiled {} sources, {} sinks, {} sanitizers, {} transforms, {} propagators; {} deferred features",
                compilation.rules.sources.len(),
                compilation.rules.sinks.len(),
                compilation.rules.sanitizers.len(),
                compilation.rules.taint_transforms.len(),
                compilation.rules.propagators.len(),
                compilation.diagnostics.len()
            );
        }
        Command::CompileLegacyPysaRules {
            input,
            namespace,
            output,
            diagnostics_out,
        } => {
            let compilation = compile_legacy_pysa_rule_tree(Path::new(&input), &namespace)?;
            let yaml = serde_yaml::to_string(&compilation.rules)
                .context("failed to serialize compiled legacy Pysa rules")?;
            write_text_file(&output, &yaml)?;
            if let Some(path) = diagnostics_out {
                let json = serde_json::to_string_pretty(&compilation.diagnostics)
                    .context("failed to serialize legacy Pysa compile diagnostics")?;
                write_text_file(&path, &json)?;
            }
            println!(
                "compiled {} Pysa models from {} files: {} call sources, {} call sinks, {} field sources, {} field sinks, {} function sources, {} function sinks, {} sanitizers, {} propagators; {} deferred features",
                compilation.models,
                compilation.files,
                compilation.rules.sources.len(),
                compilation.rules.sinks.len(),
                compilation.rules.field_sources.len(),
                compilation.rules.field_sinks.len(),
                compilation.rules.function_sources.len(),
                compilation.rules.function_sinks.len(),
                compilation.rules.sanitizers.len() + compilation.rules.field_sanitizers.len(),
                compilation.rules.propagators.len(),
                compilation.diagnostics.len()
            );
        }
        Command::CompileLegacyGoRules {
            input,
            namespace,
            output,
            diagnostics_out,
        } => {
            let text = fs::read_to_string(&input)
                .with_context(|| format!("failed to read legacy Go rules from {input}"))?;
            let pack = LegacyGoPack::from_yaml_str(&text)?;
            let compilation = compile_legacy_go_pack(&pack, &namespace)?;
            let yaml = serde_yaml::to_string(&compilation.rules)
                .context("failed to serialize compiled legacy Go rules")?;
            write_text_file(&output, &yaml)?;
            if let Some(path) = diagnostics_out {
                let json = serde_json::to_string_pretty(&compilation.diagnostics)
                    .context("failed to serialize legacy Go compile diagnostics")?;
                write_text_file(&path, &json)?;
            }
            println!(
                "compiled {} sources and {} sinks with {} sink conditions and {} call conditions; {} deferred features",
                compilation.rules.sources.len(),
                compilation.rules.sinks.len(),
                compilation.rules.sink_conditions.len(),
                compilation.rules.call_conditions.len(),
                compilation.diagnostics.len()
            );
        }
        Command::CompileLegacyCsharpRules {
            input,
            messages,
            vulnerabilities,
            namespace,
            output,
            diagnostics_out,
        } => {
            let config = fs::read_to_string(&input)
                .with_context(|| format!("failed to read legacy C# rules from {input}"))?;
            let messages = fs::read_to_string(&messages)
                .with_context(|| format!("failed to read legacy C# messages from {messages}"))?;
            let vulnerabilities = fs::read_to_string(&vulnerabilities).with_context(|| {
                format!("failed to read legacy C# vulnerabilities from {vulnerabilities}")
            })?;
            let pack = LegacyCsharpPack::from_yaml_str(&config)?;
            let compilation =
                compile_legacy_csharp_pack(&pack, &messages, &vulnerabilities, &namespace)?;
            let yaml = serde_yaml::to_string(&compilation.rules)
                .context("failed to serialize compiled legacy C# rules")?;
            write_text_file(&output, &yaml)?;
            if let Some(path) = diagnostics_out {
                let json = serde_json::to_string_pretty(&compilation.diagnostics)
                    .context("failed to serialize legacy C# compile diagnostics")?;
                write_text_file(&path, &json)?;
            }
            println!(
                "compiled {} call sources, {} field sources, {} entry sources, {} call sinks, {} field sinks, {} sanitizers and {} propagators; {} deferred features",
                compilation.rules.sources.len(),
                compilation.rules.field_sources.len(),
                compilation.rules.function_sources.len(),
                compilation.rules.sinks.len(),
                compilation.rules.field_sinks.len(),
                compilation.rules.sanitizers.len(),
                compilation.rules.propagators.len(),
                compilation.diagnostics.len()
            );
        }
        Command::DumpMitRules { language, output } => {
            let rules = mit_models_for(Language::from(language))?;
            let yaml = serde_yaml::to_string(&rules).context("failed to serialize MIT rules")?;
            if let Some(path) = output {
                write_text_file(&path, &yaml)?;
            } else {
                print!("{yaml}");
            }
        }
        Command::CheckBaseline {
            language,
            inputs,
            json_out,
            forms_metadata,
            sql_xpath_query,
            sql_xpath_message,
        } => {
            if matches!(language, LangArg::Mix) {
                run_mixed_baseline(
                    inputs,
                    json_out,
                    forms_metadata,
                    sql_xpath_query,
                    sql_xpath_message,
                )?;
                return Ok(());
            }
            let language = Language::from(language);
            let mut roots = inputs.iter().map(PathBuf::from).collect::<Vec<_>>();
            let _extract_guard = extract_archives_into(&mut roots)?;
            let files = collect_source_files(language.clone(), &roots)?;
            let mut pack = builtin_security_pack()?;
            if let Some(query) = sql_xpath_query {
                let template = pack
                    .rules
                    .iter_mut()
                    .find(|rule| rule.id == "LEGACY-SQL-XPath")
                    .context("bundled SQL XPath template is missing")?;
                template.matcher.sql_xpath_query = query;
                if let Some(message) = sql_xpath_message {
                    template.matcher.sql_xpath_message = message;
                }
                pack.validate()?;
            } else {
                anyhow::ensure!(
                    sql_xpath_message.is_none(),
                    "--sql-xpath-message requires --sql-xpath-query"
                );
            }
            let mut entries = Vec::with_capacity(files.len());
            let mut source_by_path = HashMap::new();
            for file in &files {
                let path = file.to_string_lossy().to_string();
                let source = fs::read_to_string(file)
                    .with_context(|| format!("failed to read source from {}", file.display()))?;
                source_by_path.insert(path.clone(), source.clone());
                entries.push((path, source));
            }
            let program = parse_project_sources_with_options(
                language.clone(),
                &entries,
                &FrontendOptions::default(),
            )?;
            for file in collect_auxiliary_files(language.clone(), &roots)? {
                let path = file.to_string_lossy().to_string();
                let source = fs::read_to_string(&file).with_context(|| {
                    format!("failed to read auxiliary project file {}", file.display())
                })?;
                source_by_path.insert(path, source);
            }
            let options = BaselineScanOptions {
                oracle_forms_metadata: forms_metadata
                    .as_deref()
                    .map(|path| {
                        let text = fs::read_to_string(path).with_context(|| {
                            format!("failed to read Oracle Forms metadata from {path}")
                        })?;
                        serde_json::from_str::<OracleFormsMetadata>(&text).with_context(|| {
                            format!("failed to parse Oracle Forms metadata from {path}")
                        })
                    })
                    .transpose()?,
            };
            let findings = pack.scan_hir_with_options(&program, &source_by_path, &options);
            let json = serde_json::to_string_pretty(&findings)
                .context("failed to serialize baseline findings")?;
            if let Some(path) = json_out {
                write_text_file(&path, &json)?;
            } else {
                println!("{json}");
            }
        }
        Command::Demo {
            rules,
            use_default_models,
            dump_graph,
            dump_call_report,
            dump_stats,
            pretty_findings: pretty,
            sarif_out,
            dot_out,
            markdown_out,
            xlsx_out,
        } => {
            let language = Language::Java;
            let rules = load_rules(language.clone(), rules.as_deref(), use_default_models)?;
            let program = sample_java_sql_program();
            let flow = build_for_rules_with_progress(&program, &rules, |_| {});
            emit_flow_views(&flow, dump_graph, dump_call_report, dump_stats)?;
            let findings = analyze(&flow, &rules);
            maybe_write_reports(
                &flow,
                &findings,
                &ReportOutputs {
                    sarif_out,
                    dot_out,
                    markdown_out,
                    xlsx_out,
                    ..Default::default()
                },
                &[],
                &[],
            )?;
            print_findings(&findings, pretty)?;
        }
        Command::AnalyzeSource {
            language,
            platform,
            c_family,
            input,
            rules,
            use_default_models,
            rule_ids,
            dump_hir,
            dump_ir,
            dump_graph,
            dump_call_report,
            dump_stats,
            pretty_findings: pretty,
            sarif_out,
            dot_out,
            markdown_out,
            xlsx_out,
            checkers,
            checker_timeout_ms,
            checker_failure,
            checker_isolation,
        } => {
            let language: Language = language.into();
            let hydrate_bundled_metadata = use_default_models || rules.is_none();
            let frontend_options = make_frontend_options(platform, c_family);
            let mut tracker = ProgressTracker::new(11);
            let source = tracker.phase("read-source", input.clone(), |_| {
                fs::read_to_string(&input)
                    .with_context(|| format!("failed to read source from {input}"))
            })?;
            let mut rules = tracker.phase(
                "load-rules",
                rules.clone().unwrap_or_else(|| "defaults".to_string()),
                |_| load_analysis_rules(language.clone(), rules.as_deref(), use_default_models),
            )?;
            rules.retain_reportable_ids(&rule_ids)?;
            let hir = tracker.phase("parse-source", input.clone(), |_| {
                parse_source_with_options(language, &input, &source, &frontend_options)
            })?;
            run_and_print_with_progress(
                &mut tracker,
                hir,
                rules,
                hydrate_bundled_metadata,
                dump_hir,
                dump_ir,
                dump_graph,
                dump_call_report,
                dump_stats,
                pretty,
                &ReportOutputs {
                    sarif_out,
                    dot_out,
                    markdown_out,
                    xlsx_out,
                    ..Default::default()
                },
                &checkers,
                RuntimeCheckerOptions {
                    timeout_ms: checker_timeout_ms,
                    failure_policy: checker_failure,
                    isolation: checker_isolation,
                },
            )?;
        }
        Command::AnalyzeProject {
            language,
            platform,
            c_family,
            inputs,
            rules,
            use_default_models,
            rule_ids,
            list_files,
            dump_hir,
            dump_ir,
            dump_graph,
            dump_call_report,
            dump_stats,
            pretty_findings: pretty,
            dump_cache_plan,
            cache_in,
            cache_out,
            sarif_out,
            dot_out,
            markdown_out,
            xlsx_out,
            system_graph_out,
            checkers,
            checker_timeout_ms,
            checker_failure,
            checker_isolation,
        } => {
            if matches!(language, LangArg::Mix) {
                run_mixed_project(
                    platform,
                    c_family,
                    inputs,
                    rules,
                    use_default_models,
                    &rule_ids,
                    list_files,
                    dump_hir,
                    dump_ir,
                    dump_graph,
                    dump_call_report,
                    dump_stats,
                    pretty,
                    dump_cache_plan,
                    cache_in,
                    cache_out,
                    &ReportOutputs {
                        sarif_out,
                        dot_out,
                        markdown_out,
                        xlsx_out,
                        system_graph_out,
                    },
                    &checkers,
                    RuntimeCheckerOptions {
                        timeout_ms: checker_timeout_ms,
                        failure_policy: checker_failure,
                        isolation: checker_isolation,
                    },
                )?;
                return Ok(());
            }
            let language: Language = language.into();
            let hydrate_bundled_metadata = use_default_models || rules.is_none();
            let frontend_options = make_frontend_options(platform, c_family);
            let mut paths = inputs.into_iter().map(PathBuf::from).collect::<Vec<_>>();
            let _extract_guard = extract_archives_into(&mut paths)?;
            let use_cache = cache_in.is_some() || cache_out.is_some() || dump_cache_plan;
            let total_steps = 11;
            let mut tracker = ProgressTracker::new(total_steps);
            let mut rules = tracker.phase(
                "load-rules",
                rules.clone().unwrap_or_else(|| "defaults".to_string()),
                |_| load_analysis_rules(language.clone(), rules.as_deref(), use_default_models),
            )?;
            rules.retain_reportable_ids(&rule_ids)?;
            let files = tracker.phase(
                "collect-files",
                format!("{} input roots", paths.len()),
                |_| collect_source_files(language.clone(), &paths),
            )?;
            if list_files {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                    )
                    .context("failed to serialize file list")?
                );
            }

            // JAR/WAR, .NET, CPython, and WASM bytecode dependencies are
            // each decoded straight to IR (bypassing every HIR source
            // frontend entirely — there isn't one for compiled-only input)
            // and merged in below, so a compiled dependency participates in
            // the same flow graph as the project's own sources. Collected
            // up front so a project made up *entirely* of bytecode (no
            // source files at all) can skip HIR parsing rather than failing
            // on an empty source-file list.
            let extra_ir_programs = collect_bytecode_ir_programs(&language, &paths)?;

            let hir = if files.is_empty() {
                anyhow::ensure!(
                    !extra_ir_programs.is_empty(),
                    "no supported source files or archives found"
                );
                uniflow_hir::Program::empty(language.clone())
            } else if use_cache {
                tracker.phase(
                    "build-project-cache",
                    format!("{} files", files.len()),
                    |_| {
                        let existing_cache = cache_in
                            .as_deref()
                            .map(Path::new)
                            .map(load_project_cache)
                            .transpose()?;
                        let build_result = build_project_with_cache_options(
                            language.clone(),
                            &files,
                            existing_cache.as_ref(),
                            &frontend_options,
                        )?;
                        if dump_cache_plan {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&build_result.plan)
                                    .context("failed to serialize cache plan")?
                            );
                        }
                        if let Some(path) = cache_out.as_deref() {
                            save_project_cache(Path::new(path), &build_result.cache)?;
                        }
                        Ok(build_result.program)
                    },
                )?
            } else {
                tracker.phase(
                    "parse-project",
                    format!("{} source files", files.len()),
                    |multi| {
                        // Keep project parsing file-backed. The previous CLI path
                        // first loaded every source into `Vec<(String, String)>`
                        // and then handed that complete snapshot to the frontend,
                        // causing large scans to retain all source text until HIR
                        // construction finished. The frontend already owns the
                        // project-file loading path, including header expansion
                        // and compile-database handling, so let it read files as
                        // needed instead of duplicating the source buffer.
                        let _file_bar = multi.add(ProgressBar::new(files.len() as u64));
                        _file_bar.set_style(file_style());
                        _file_bar.set_message(if language == Language::Python {
                            "indexing Python project before parallel parsing"
                        } else {
                            "parsing source files"
                        });
                        let completed_file_bar = _file_bar.clone();
                        parse_project_files_with_options_and_progress(
                            language.clone(),
                            &files,
                            &frontend_options,
                            &|| {
                                completed_file_bar.set_message("parsing source files");
                                completed_file_bar.inc(1);
                            },
                        )
                    },
                )?
            };

            run_and_print_with_progress_and_extra_ir(
                &mut tracker,
                hir,
                rules,
                hydrate_bundled_metadata,
                dump_hir,
                dump_ir,
                dump_graph,
                dump_call_report,
                dump_stats,
                pretty,
                &ReportOutputs {
                    sarif_out,
                    dot_out,
                    markdown_out,
                    xlsx_out,
                    // System-wide semantic boundary recovery only runs for
                    // mixed-language project scans (see `run_mixed_project`);
                    // `--system-graph-out` has no effect on a single-language
                    // `analyze-project` run.
                    system_graph_out: None,
                },
                &checkers,
                RuntimeCheckerOptions {
                    timeout_ms: checker_timeout_ms,
                    failure_policy: checker_failure,
                    isolation: checker_isolation,
                },
                extra_ir_programs,
            )?;
        }
    }
    Ok(())
}

/// Runs the frontend coding-style/baseline checker over every language group
/// in a polyglot project.  HIR is language-specific, so each group is parsed
/// independently and findings are merged only at the report boundary.
fn run_mixed_baseline(
    inputs: Vec<String>,
    json_out: Option<String>,
    forms_metadata: Option<String>,
    sql_xpath_query: Option<String>,
    sql_xpath_message: Option<String>,
) -> Result<()> {
    if sql_xpath_query.is_none() {
        anyhow::ensure!(
            sql_xpath_message.is_none(),
            "--sql-xpath-message requires --sql-xpath-query"
        );
    }
    let mut roots = inputs.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let _extract_guard = extract_archives_into(&mut roots)?;
    let options = BaselineScanOptions {
        oracle_forms_metadata: forms_metadata
            .as_deref()
            .map(|path| {
                let text = fs::read_to_string(path)
                    .with_context(|| format!("failed to read Oracle Forms metadata from {path}"))?;
                serde_json::from_str::<OracleFormsMetadata>(&text)
                    .with_context(|| format!("failed to parse Oracle Forms metadata from {path}"))
            })
            .transpose()?,
    };
    let mut groups: Vec<(Language, Vec<PathBuf>)> = Vec::new();
    for (language, path) in collect_mixed_source_files(&roots)? {
        match groups.iter_mut().find(|(existing, _)| *existing == language) {
            Some((_, files)) => files.push(path),
            None => groups.push((language, vec![path])),
        }
    }
    // Java configuration checkers (Android manifest, Spring properties,
    // Dockerfile, etc.) are source-independent.  In a configuration-only
    // project mixed discovery has no `.java` path from which to create a
    // group, so explicitly retain an empty Java group to run those bundled
    // structured rules against the auxiliary inputs.
    let java_auxiliary_files = collect_auxiliary_files(Language::Java, &roots)?;
    if !java_auxiliary_files.is_empty()
        && !groups
            .iter()
            .any(|(language, _)| *language == Language::Java)
    {
        groups.push((Language::Java, Vec::new()));
    }
    groups.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));
    anyhow::ensure!(
        !groups.is_empty(),
        "no supported source files or Java auxiliary configuration files found"
    );

    let mut findings: Vec<BaselineFinding> = Vec::new();
    for (language, files) in groups {
        let mut sources = HashMap::with_capacity(files.len());
        let entries = files
            .iter()
            .map(|file| {
                let path = file.to_string_lossy().to_string();
                let source = fs::read_to_string(file)
                    .with_context(|| format!("failed to read source from {}", file.display()))?;
                sources.insert(path.clone(), source.clone());
                Ok((path, source))
            })
            .collect::<Result<Vec<_>>>()?;
        let program = if entries.is_empty() {
            // Only Java's structured auxiliary rule family can create an
            // empty source group. `scan_hir_with_options` still evaluates
            // source-independent project/config checks against `sources`.
            HirProgram::empty(language.clone())
        } else {
            parse_project_sources_with_options(
                language.clone(),
                &entries,
                &FrontendOptions::default(),
            )?
        };
        if language == Language::Java {
            for file in &java_auxiliary_files {
                let path = file.to_string_lossy().to_string();
                let source = fs::read_to_string(file).with_context(|| {
                    format!("failed to read auxiliary project file {}", file.display())
                })?;
                sources.insert(path, source);
            }
        }
        let mut pack = builtin_security_pack()?;
        if let Some(query) = sql_xpath_query.as_ref() {
            let template = pack
                .rules
                .iter_mut()
                .find(|rule| rule.id == "LEGACY-SQL-XPath")
                .context("bundled SQL XPath template is missing")?;
            template.matcher.sql_xpath_query = query.clone();
            if let Some(message) = sql_xpath_message.as_ref() {
                template.matcher.sql_xpath_message = message.clone();
            }
            pack.validate()?;
        }
        findings.extend(pack.scan_hir_with_options(&program, &sources, &options));
    }
    let json = serde_json::to_string_pretty(&findings)
        .context("failed to serialize mixed baseline findings")?;
    if let Some(path) = json_out {
        write_text_file(&path, &json)?;
    } else {
        println!("{json}");
    }
    Ok(())
}

fn load_rules(
    language: Language,
    rules_path: Option<&str>,
    use_default_models: bool,
) -> Result<RuleSet> {
    let yaml = if let Some(path) = rules_path {
        Some(
            fs::read_to_string(path)
                .with_context(|| format!("failed to read rules from {path}"))?,
        )
    } else {
        None
    };

    if use_default_models || yaml.is_none() {
        load_with_defaults(language, yaml.as_deref())
    } else {
        RuleSet::from_yaml_str(yaml.as_deref().unwrap())
    }
}

fn load_analysis_rules(
    language: Language,
    rules_path: Option<&str>,
    use_default_models: bool,
) -> Result<RuleSet> {
    let yaml = if let Some(path) = rules_path {
        Some(
            fs::read_to_string(path)
                .with_context(|| format!("failed to read rules from {path}"))?,
        )
    } else {
        None
    };

    if use_default_models || yaml.is_none() {
        load_with_defaults_for_analysis(language, yaml.as_deref())
    } else {
        RuleSet::from_yaml_str(yaml.as_deref().unwrap())
    }
}

fn run_and_print_with_progress(
    tracker: &mut ProgressTracker,
    hir: uniflow_hir::Program,
    rules: RuleSet,
    hydrate_bundled_metadata: bool,
    dump_hir: bool,
    dump_ir: bool,
    dump_graph: bool,
    dump_call_report: bool,
    dump_stats: bool,
    pretty_findings_flag: bool,
    report_outputs: &ReportOutputs,
    checker_paths: &[String],
    checker_options: RuntimeCheckerOptions,
) -> Result<()> {
    run_and_print_with_progress_and_extra_ir(
        tracker,
        hir,
        rules,
        hydrate_bundled_metadata,
        dump_hir,
        dump_ir,
        dump_graph,
        dump_call_report,
        dump_stats,
        pretty_findings_flag,
        report_outputs,
        checker_paths,
        checker_options,
        Vec::new(),
    )
}

/// Same as `run_and_print_with_progress`, but also merges `extra_ir_programs`
/// (for example, Java classes decoded from `.jar`/`.war` archives via
/// `uniflow_lang_java_bytecode`) into the source-derived IR before dataflow
/// analysis, so a project's compiled dependencies participate in the same
/// flow graph as its own sources.
#[allow(clippy::too_many_arguments)]
fn run_and_print_with_progress_and_extra_ir(
    tracker: &mut ProgressTracker,
    hir: uniflow_hir::Program,
    rules: RuleSet,
    hydrate_bundled_metadata: bool,
    dump_hir: bool,
    dump_ir: bool,
    dump_graph: bool,
    dump_call_report: bool,
    dump_stats: bool,
    pretty_findings_flag: bool,
    report_outputs: &ReportOutputs,
    checker_paths: &[String],
    checker_options: RuntimeCheckerOptions,
    extra_ir_programs: Vec<IrProgram>,
) -> Result<()> {
    // Lowering, checker events, flow construction, and taint analysis are the
    // part of this pipeline that is identical (up to FFI-bridge partitioning,
    // which only `run_mixed_project` needs) to the per-language-group
    // pipeline below, so both live in `uniflow_core` as the shared scan
    // primitive rather than being duplicated here.
    if dump_hir {
        println!(
            "{}",
            serde_json::to_string_pretty(&hir).context("failed to serialize hir")?
        );
    }
    let file_count = hir.files.len();
    let outcome = tracker.phase("scan", format!("{file_count} files"), |_| {
        uniflow_core::run_single_language_scan(uniflow_core::SingleLanguageScanRequest {
            hir,
            rules,
            hydrate_bundled_metadata,
            extra_ir_programs,
            checker_paths: checker_paths.to_vec(),
            checker_host_options: CheckerHostOptions {
                isolation: checker_options.isolation.into(),
                timeout: Duration::from_millis(checker_options.timeout_ms.max(1)),
                failure_policy: checker_options.failure_policy.into(),
            },
            dump_graph,
            dump_call_report,
        })
    })?;

    if dump_ir {
        println!(
            "{}",
            serde_json::to_string_pretty(&outcome.ir).context("failed to serialize ir")?
        );
    }
    tracker.phase("emit-flow-views", "graph / call report / stats", |_| {
        emit_flow_views(&outcome.flow, dump_graph, dump_call_report, dump_stats)
    })?;
    for diagnostic in &outcome.checker_diagnostics {
        eprintln!(
            "checker diagnostic: {}",
            serde_json::to_string(diagnostic).context("failed to serialize checker diagnostic")?
        );
    }
    tracker.phase("reports", "sarif / dot / markdown / xlsx / findings", |_| {
        maybe_write_reports(
            &outcome.flow,
            &outcome.findings,
            report_outputs,
            &outcome.checker_findings,
            &outcome.checker_manifests,
        )?;
        print_all_findings(&outcome.findings, &outcome.checker_findings, pretty_findings_flag)
    })?;
    tracker.finish();
    Ok(())
}

/// Scans a project auto-detecting each file's language by extension
/// (`uniflow_frontend::collect_mixed_source_files`) plus any `.jar`/`.war`
/// archives, and runs each language group through its own
/// parse/lower/flow/taint pipeline independently — a mixed project is never
/// fed to one frontend, since `ir::Program`/`FlowGraph` are single-language.
/// Findings are aggregated for SARIF/console output; DOT and Markdown
/// exports stay per-language-group (both are relative to one `FlowGraph`),
/// gaining a `.<language>` suffix whenever more than one group produced
/// output.
#[allow(clippy::too_many_arguments)]
fn run_mixed_project(
    platform: PlatformArg,
    c_family: CFamilyFrontendArgs,
    inputs: Vec<String>,
    rules_path: Option<String>,
    use_default_models: bool,
    rule_ids: &[String],
    list_files: bool,
    dump_hir: bool,
    dump_ir: bool,
    dump_graph: bool,
    dump_call_report: bool,
    dump_stats: bool,
    pretty_findings_flag: bool,
    dump_cache_plan: bool,
    cache_in: Option<String>,
    cache_out: Option<String>,
    report_outputs: &ReportOutputs,
    checker_paths: &[String],
    checker_options: RuntimeCheckerOptions,
) -> Result<()> {
    let hydrate_bundled_metadata = use_default_models || rules_path.is_none();
    let frontend_options = make_frontend_options(platform, c_family);
    let mut paths = inputs.into_iter().map(PathBuf::from).collect::<Vec<_>>();
    let _extract_guard = extract_archives_into(&mut paths)?;

    let mixed_files = collect_mixed_source_files(&paths)
        .context("failed to collect mixed-language project files")?;
    let archive_files = collect_java_bytecode_files(&paths)
        .context("failed to collect Java bytecode inputs")?;
    let dotnet_bytecode_files = collect_dotnet_bytecode_files(&paths)
        .context("failed to collect .NET bytecode inputs")?;
    let python_bytecode_files = collect_python_bytecode_files(&paths)
        .context("failed to collect CPython bytecode inputs")?;
    let wasm_bytecode_files = collect_wasm_bytecode_files(&paths)
        .context("failed to collect WASM bytecode inputs")?;

    if list_files {
        let mut listed = mixed_files
            .iter()
            .map(|(language, path)| {
                json!({ "language": language.as_str(), "path": path.display().to_string() })
            })
            .collect::<Vec<_>>();
        listed.extend(archive_files.iter().map(|path| {
            json!({ "language": "java", "path": path.display().to_string() })
        }));
        listed.extend(dotnet_bytecode_files.iter().map(|path| {
            json!({ "language": "csharp", "path": path.display().to_string() })
        }));
        listed.extend(python_bytecode_files.iter().map(|path| {
            json!({ "language": "python", "path": path.display().to_string() })
        }));
        // WASM has no owning source `Language` (see `collect_bytecode_ir_programs`),
        // so it is listed under its own literal tag rather than an existing one.
        listed.extend(wasm_bytecode_files.iter().map(|path| {
            json!({ "language": "wasm", "path": path.display().to_string() })
        }));
        println!(
            "{}",
            serde_json::to_string_pretty(&listed).context("failed to serialize file list")?
        );
    }

    anyhow::ensure!(
        !mixed_files.is_empty()
            || !archive_files.is_empty()
            || !dotnet_bytecode_files.is_empty()
            || !python_bytecode_files.is_empty()
            || !wasm_bytecode_files.is_empty(),
        "no supported source files or archives found"
    );

    let mut groups: Vec<(Language, Vec<PathBuf>)> = Vec::new();
    for (language, path) in mixed_files {
        match groups.iter_mut().find(|(existing, _)| *existing == language) {
            Some((_, files)) => files.push(path),
            None => groups.push((language, vec![path])),
        }
    }
    if !archive_files.is_empty() && !groups.iter().any(|(language, _)| *language == Language::Java) {
        groups.push((Language::Java, Vec::new()));
    }
    if !dotnet_bytecode_files.is_empty() && !groups.iter().any(|(language, _)| *language == Language::CSharp) {
        groups.push((Language::CSharp, Vec::new()));
    }
    if !python_bytecode_files.is_empty() && !groups.iter().any(|(language, _)| *language == Language::Python) {
        groups.push((Language::Python, Vec::new()));
    }
    // WASM has no owning source `Language` (it is a genuine cross-language
    // compilation target — Rust/C/C++/AssemblyScript/TinyGo all produce
    // it); `Language::Unknown` is used as its dedicated pseudo-group tag
    // the same way `Language::Java` doubles as the archive-only group tag
    // above, rather than guessing an owning language.
    if !wasm_bytecode_files.is_empty() && !groups.iter().any(|(language, _)| *language == Language::Unknown) {
        groups.push((Language::Unknown, Vec::new()));
    }
    // Alphabetical order also happens to put every C-family group ("c",
    // "cpp") ahead of "java", which the FFI bridge below depends on: by the
    // time the Java group is analyzed, every C/C++ group has already
    // contributed to `native_summaries`.
    groups.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

    // FFI/JNI bridge: when the project has both a Java group and a C/C++
    // group, probe each native declaration's same-named C/C++ implementation
    // for its own taint behavior, then splice that behavior into the Java
    // group's rules as synthetic source/sink/propagator rules. See
    // `ffi_bridge` for the full design rationale.
    let java_source_files: Vec<PathBuf> = groups
        .iter()
        .find(|(language, _)| *language == Language::Java)
        .map(|(_, files)| files.clone())
        .unwrap_or_default();
    let has_c_family_group = groups
        .iter()
        .any(|(language, _)| matches!(language, Language::C | Language::Cpp));
    let ffi_bridge_candidates = if has_c_family_group {
        let native_decls =
            ffi_bridge::collect_native_method_decls(&java_source_files, &archive_files)
                .context("failed to scan for native (JNI) method declarations")?;
        ffi_bridge::dedupe_by_mangled_name(native_decls)
    } else {
        HashMap::new()
    };
    let mut native_summaries: HashMap<String, ffi_bridge::NativeSummary> = HashMap::new();

    // System-wide semantic boundary recovery: Docker Compose/Kubernetes
    // topology, `getenv`-style config reads, HTTP route registrations,
    // message consumers/producers, and
    // lifecycle hooks are recovered into one `SystemGraph`, then folded into
    // synthetic per-language rules the main loop below merges in just like
    // the FFI bridge's own rules above. This requires parsing+lowering every
    // group before a group's own rules are finalized, because an outbound
    // HTTP call in one group can only be matched against a route recovered
    // from *any* group. The resulting IR is retained and reused by normal
    // scans below, avoiding a second source pass. See
    // `uniflow_system_graph` for the full design.
    let mut system_graph = uniflow_system_graph::SystemGraph::new();
    uniflow_system_graph::docker_compose::discover_into(
        &mut system_graph,
        &uniflow_system_graph::docker_compose::find_compose_files(&paths),
    )
    .context("failed to discover Docker Compose topology")?;
    uniflow_system_graph::kubernetes::discover_into(
        &mut system_graph,
        &uniflow_system_graph::kubernetes::find_manifest_files(&paths),
    )
    .context("failed to discover Kubernetes topology")?;
    let proto_services = uniflow_system_graph::grpc::load_proto_services(&uniflow_system_graph::grpc::find_proto_files(&paths))
        .context("failed to parse .proto service declarations")?;

    let use_cache = cache_in.is_some() || cache_out.is_some() || dump_cache_plan;
    let existing_mixed_cache = cache_in
        .as_deref()
        .map(Path::new)
        .map(load_mixed_project_cache)
        .transpose()?;
    let mut rebuilt_cache_groups = BTreeMap::new();
    let mut cache_plans = BTreeMap::<String, CachePlan>::new();
    let mut system_graph_programs: Vec<(Language, IrProgram)> = Vec::new();
    let mut database_operations = Vec::new();
    for (language, files) in &groups {
        if files.is_empty() {
            continue;
        }
        let parsed = if use_cache {
            build_project_with_cache_options(
                language.clone(),
                files,
                existing_mixed_cache
                    .as_ref()
                    .and_then(|cache| cache.compatible_group(language)),
                &frontend_options,
            )
            .map(|result| {
                cache_plans.insert(language.as_str().to_string(), result.plan);
                rebuilt_cache_groups.insert(language.as_str().to_string(), result.cache);
                result.program
            })
        } else {
            parse_project_files_with_options(language.clone(), files, &frontend_options)
        };
        let Ok(hir) = parsed else {
            // Not this pass's job to report a parse error — the main loop
            // below parses the same files again and will surface it there.
            continue;
        };
        system_graph_programs.push((language.clone(), lower_program(&hir)));
    }
    if dump_cache_plan {
        println!(
            "{}",
            serde_json::to_string_pretty(&cache_plans)
                .context("failed to serialize mixed-project cache plan")?
        );
    }
    if let Some(path) = cache_out.as_deref() {
        save_mixed_project_cache(Path::new(path), &MixedProjectCache::new(rebuilt_cache_groups))?;
    }
    let mut grpc_servers = Vec::new();
    for (language, ir) in &system_graph_programs {
        uniflow_system_graph::config::discover_into(&mut system_graph, ir)
            .with_context(|| format!("failed to discover configuration reads in {}", language.as_str()))?;
        database_operations.extend(
            uniflow_system_graph::database::discover_into(&mut system_graph, ir)
                .with_context(|| format!("failed to discover database resource use in {}", language.as_str()))?,
        );
        uniflow_system_graph::lifecycle::discover_into(&mut system_graph, ir)
            .with_context(|| format!("failed to discover lifecycle hooks in {}", language.as_str()))?;
        uniflow_system_graph::http::discover_routes_into(&mut system_graph, ir)
            .with_context(|| format!("failed to discover HTTP routes in {}", language.as_str()))?;
        grpc_servers.extend(
            uniflow_system_graph::grpc::discover_server_methods_into(&mut system_graph, &proto_services, ir)
                .with_context(|| format!("failed to discover gRPC server implementations in {}", language.as_str()))?,
        );
    }
    uniflow_system_graph::python_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Python ctypes/cffi native boundaries")?;
    uniflow_system_graph::php_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover PHP FFI native boundaries")?;
    uniflow_system_graph::csharp_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover C# P/Invoke native boundaries")?;
    uniflow_system_graph::csharp_ffi::discover_exports_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover C# unmanaged-callable exports")?;
    uniflow_system_graph::rust_ffi::discover_calls_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Rust extern \"C\" native call boundaries")?;
    uniflow_system_graph::rust_ffi::discover_exports_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover native calls into #[no_mangle]-exported Rust functions")?;
    uniflow_system_graph::js_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Node native-addon boundaries")?;
    uniflow_system_graph::ruby_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Ruby `ffi` gem native boundaries")?;
    uniflow_system_graph::go_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Go cgo native boundaries")?;
    uniflow_system_graph::objc_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Objective-C C ABI boundaries")?;
    uniflow_system_graph::swift_ffi::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Swift imported-C ABI boundaries")?;
    uniflow_system_graph::kotlin_jni::discover_into(&mut system_graph, &system_graph_programs)
        .context("failed to discover Kotlin/JVM JNI boundaries")?;
    // Cross-referencing a route's handler (which may live in a *different*
    // group's `Program`) by its own parameter names — not merging
    // Programs, not regex/string-matching call sites — is what lets the
    // outbound-call pass below recover a precise, field-level
    // `BoundaryFlowEdge` instead of "some value reaches somewhere". See
    // `uniflow_system_graph::ir_utils::FunctionIndex`.
    let function_index = uniflow_system_graph::FunctionIndex::build(&system_graph_programs);
    let mut message_consumers = Vec::new();
    for (language, ir) in &system_graph_programs {
        message_consumers.extend(
            uniflow_system_graph::message::discover_consumers_into(&mut system_graph, ir)
                .with_context(|| format!("failed to discover message consumers in {}", language.as_str()))?,
        );
    }
    for (language, ir) in &system_graph_programs {
        uniflow_system_graph::http::discover_outbound_calls_into(&mut system_graph, ir, &function_index)
            .with_context(|| format!("failed to discover outbound HTTP calls in {}", language.as_str()))?;
        uniflow_system_graph::message::discover_publications_into(
            &mut system_graph,
            ir,
            &message_consumers,
            &function_index,
        )
        .with_context(|| format!("failed to discover message publications in {}", language.as_str()))?;
        uniflow_system_graph::grpc::discover_client_calls_into(&mut system_graph, &proto_services, ir, &grpc_servers, &function_index)
            .with_context(|| format!("failed to discover gRPC client calls in {}", language.as_str()))?;
    }
    uniflow_system_graph::database::connect_operations_into(&mut system_graph, &database_operations)
        .context("failed to connect statically identified database persistence flows")?;

    let mut tracker = ProgressTracker::new((groups.len() as u64 * 3).max(1) + 2);
    let mut checker_manager = tracker.phase(
        "load-checkers",
        if checker_paths.is_empty() {
            "none".to_string()
        } else {
            format!("{} dynamic libraries", checker_paths.len())
        },
        |_| {
            CheckerManager::load_with_options(
                checker_paths,
                CheckerHostOptions {
                    isolation: checker_options.isolation.into(),
                    timeout: Duration::from_millis(checker_options.timeout_ms.max(1)),
                    failure_policy: checker_options.failure_policy.into(),
                },
            )
        },
    )?;
    let checker_manifests = checker_manager.manifests();
    let mut checker_findings = Vec::new();
    if checker_manager.has_subscriber(event_kind::ANALYSIS_START) {
        let mut all_files = groups
            .iter()
            .flat_map(|(_, files)| files.iter().map(|path| path.display().to_string()))
            .collect::<Vec<_>>();
        all_files.extend(archive_files.iter().map(|path| path.display().to_string()));
        all_files.extend(dotnet_bytecode_files.iter().map(|path| path.display().to_string()));
        all_files.extend(python_bytecode_files.iter().map(|path| path.display().to_string()));
        all_files.extend(wasm_bytecode_files.iter().map(|path| path.display().to_string()));
        checker_findings.extend(checker_manager.broadcast(
            event_kind::ANALYSIS_START,
            json!({
                "language": "mix",
                "files": all_files,
                "checkers": &checker_manifests,
            }),
        )?);
    }

    // The system-boundary pass above has already parsed and lowered every
    // source group.  A normal scan consumes only IR, so retain those programs
    // instead of parsing and lowering the complete project a second time.
    // HIR dumps and HIR/source-file checker callbacks intentionally keep the
    // old path: their public payloads require the original frontend program.
    let mut prepared_source_irs = system_graph_programs;

    let mut all_findings: Vec<TaintFinding> = Vec::new();
    let mut per_language_flows: Vec<(Language, FlowGraph, Vec<TaintFinding>)> = Vec::new();

    for (language, files) in groups {
        let group_label = language.as_str().to_string();
        let mut rules = tracker.phase(
            &format!("load-rules[{group_label}]"),
            rules_path.clone().unwrap_or_else(|| "defaults".to_string()),
            |_| load_analysis_rules(language.clone(), rules_path.as_deref(), use_default_models),
        )?;
        rules.retain_reportable_ids(rule_ids)?;

        if !ffi_bridge_candidates.is_empty() {
            if matches!(language, Language::C | Language::Cpp) {
                rules.merge(ffi_bridge::build_probe_ruleset(&ffi_bridge_candidates));
            } else if language == Language::Java {
                rules.merge(ffi_bridge::build_bridge_ruleset(
                    &ffi_bridge_candidates,
                    &native_summaries,
                ));
            }
        }

        // System-wide boundary bridging: a field-precise `BoundaryFlowEdge`
        // (recovered above) becomes exactly two rules — a sink on the
        // producer's own mapped parameter, a source on the consumer's own
        // mapped parameter — so the *value itself* (not "some parameter")
        // crosses the boundary. The blanket external-ingress fallback only
        // applies to a route nothing in the analyzed code ever calls. See
        // `uniflow_system_graph::bridge`.
        rules.merge(uniflow_system_graph::bridge::boundary_output_sink_rules(&system_graph, &language));
        rules.merge(uniflow_system_graph::bridge::boundary_input_source_rules(&system_graph, &language));
        rules.merge(uniflow_system_graph::bridge::handler_source_rules(&system_graph, &language));

        let requires_hir = dump_hir
            || checker_manager.has_subscriber(event_kind::SOURCE_FILE)
            || checker_manager.has_subscriber(event_kind::HIR_PROGRAM);
        let (hir, mut source_ir) = if files.is_empty() {
            (None, None)
        } else if !requires_hir {
            // A failed boundary pre-pass must never hide a parse failure from
            // the actual analysis.  Fall back to the normal parse/lower path
            // when it did not yield a reusable program for this group.
            let prepared_index = prepared_source_irs
                .iter()
                .position(|(prepared_language, _)| *prepared_language == language);
            match prepared_index.map(|index| prepared_source_irs.swap_remove(index).1) {
                Some(ir) => (None, Some(ir)),
                None => {
                    let hir = tracker.phase(
                        &format!("parse-project[{group_label}]"),
                        format!("{} source files", files.len()),
                        |_| {
                            parse_project_files_with_options(
                                language.clone(),
                                &files,
                                &frontend_options,
                            )
                        },
                    )?;
                    (Some(hir), None)
                }
            }
        } else {
            // The retained IR is not useful when a public HIR payload is
            // requested. Drop it before parsing so a large group is never
            // kept twice in memory (once as pre-pass IR and once as HIR).
            if let Some(index) = prepared_source_irs
                .iter()
                .position(|(prepared_language, _)| *prepared_language == language)
            {
                prepared_source_irs.swap_remove(index);
            }
            let hir = tracker.phase(
                &format!("parse-project[{group_label}]"),
                format!("{} source files", files.len()),
                |_| parse_project_files_with_options(language.clone(), &files, &frontend_options),
            )?;
            (Some(hir), None)
        };

        if dump_hir {
            if let Some(hir) = &hir {
                println!(
                    "{}",
                    serde_json::to_string_pretty(hir).context("failed to serialize hir")?
                );
            }
        }
        if let Some(hir) = &hir {
            if checker_manager.has_subscriber(event_kind::SOURCE_FILE) {
                for file in &hir.files {
                    let source = fs::read_to_string(&file.path).with_context(|| {
                        format!("failed to read checker source event from {}", file.path)
                    })?;
                    checker_findings.extend(checker_manager.broadcast(
                        event_kind::SOURCE_FILE,
                        uniflow_core::source_file_payload(&file.path, &hir.language, source),
                    )?);
                }
            }
            if checker_manager.has_subscriber(event_kind::HIR_PROGRAM) {
                checker_findings.extend(checker_manager.broadcast(
                    event_kind::HIR_PROGRAM,
                    serde_json::to_value(hir).context("failed to serialize HIR checker event")?,
                )?);
            }
        }

        if source_ir.is_none() {
            source_ir = hir
                .as_ref()
                .map(|hir| uniflow_core::validate_or_quarantine_invalid_ir_functions(lower_program(hir)))
                .transpose()?;
        }

        let has_bytecode_for_group = (language == Language::Java && !archive_files.is_empty())
            || (language == Language::CSharp && !dotnet_bytecode_files.is_empty())
            || (language == Language::Python && !python_bytecode_files.is_empty())
            || (language == Language::Unknown && !wasm_bytecode_files.is_empty());
        let ir = if has_bytecode_for_group {
            let mut programs = Vec::new();
            if let Some(source_ir) = source_ir {
                programs.push(source_ir);
            }
            if language == Language::Java {
                for archive in &archive_files {
                    let (program, diagnostics, _natives) = lower_java_bytecode_input(archive).with_context(|| {
                        format!("failed to decode Java bytecode input {}", archive.display())
                    })?;
                    for diagnostic in diagnostics {
                        eprintln!("uniflow: {}: {}", archive.display(), diagnostic.0);
                    }
                    programs.push(program);
                }
            }
            if language == Language::CSharp {
                for dotnet_file in &dotnet_bytecode_files {
                    let (program, diagnostics) = lower_dotnet_bytecode_input(dotnet_file).with_context(|| {
                        format!("failed to decode .NET bytecode input {}", dotnet_file.display())
                    })?;
                    for diagnostic in diagnostics {
                        eprintln!("uniflow: {}: {diagnostic}", dotnet_file.display());
                    }
                    programs.push(program);
                }
            }
            if language == Language::Python {
                for pyc_file in &python_bytecode_files {
                    let (program, diagnostics) = lower_python_bytecode_input(pyc_file).with_context(|| {
                        format!("failed to decode CPython bytecode input {}", pyc_file.display())
                    })?;
                    for diagnostic in diagnostics {
                        eprintln!("uniflow: {}: {diagnostic}", pyc_file.display());
                    }
                    programs.push(program);
                }
            }
            if language == Language::Unknown {
                for wasm_file in &wasm_bytecode_files {
                    let program = lower_wasm_bytecode_input(wasm_file).with_context(|| {
                        format!("failed to decode WASM bytecode input {}", wasm_file.display())
                    })?;
                    programs.push(program);
                }
            }
            merge_programs(programs).context("failed to merge decoded bytecode inputs")?
        } else {
            source_ir.with_context(|| format!("no lowered IR for language {group_label}"))?
        };

        if checker_manager.has_subscriber(event_kind::IR_PROGRAM) {
            checker_findings.extend(checker_manager.broadcast(
                event_kind::IR_PROGRAM,
                serde_json::to_value(&ir).context("failed to serialize IR checker event")?,
            )?);
        }
        if dump_ir {
            println!(
                "{}",
                serde_json::to_string_pretty(&ir).context("failed to serialize ir")?
            );
        }

        // Flow construction and (non-FFI-partitioned) taint analysis are
        // exactly what `run_and_print_with_progress_and_extra_ir` also needs,
        // so both live in `uniflow_core`; only the FFI-bridge partitioning
        // step below is specific to a mixed-language project scan.
        let flow = tracker.phase(&format!("build-flow[{group_label}]"), format!("{} IR functions", ir.functions.len()), |_| {
            uniflow_core::build_flow_graph(
                &ir,
                &rules,
                dump_graph || dump_call_report,
                &mut checker_manager,
                &mut checker_findings,
            )
        })?;
        if dump_graph || dump_call_report || dump_stats {
            println!("== {group_label} ==");
            emit_flow_views(&flow, dump_graph, dump_call_report, dump_stats)?;
        }

        let findings = tracker.phase(
            &format!("taint-analysis[{group_label}]"),
            format!("{} flow nodes", flow.graph.node_count()),
            |_| uniflow_core::run_taint_analysis(&flow, &mut rules, hydrate_bundled_metadata),
        )?;
        let (findings, ffi_probe_findings) = ffi_bridge::partition_probe_findings(findings);
        ffi_bridge::fold_native_summaries(&ffi_probe_findings, &mut native_summaries);
        uniflow_core::broadcast_taint_findings(&findings, &mut checker_manager, &mut checker_findings)?;

        all_findings.extend(findings.iter().cloned());
        per_language_flows.push((language, flow, findings));
    }

    // Every finding whose source/sink rule id is a boundary-output/-input
    // marker (injected above) is intermediate plumbing, not an
    // independently reportable violation — pull matching producer/consumer
    // pairs out into one continuous cross-component `SystemFinding` and
    // drop the raw pair from the ordinary findings list. See
    // `uniflow_system_graph::compose`.
    let cross_component_findings =
        uniflow_system_graph::compose::compose_cross_boundary_findings(&mut all_findings, &system_graph);

    let checker_finding_count_before_end = checker_findings.len();
    if checker_manager.has_subscriber(event_kind::ANALYSIS_END) {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::ANALYSIS_END,
            json!({
                "taintFindingCount": all_findings.len(),
                "checkerFindingCount": checker_finding_count_before_end,
            }),
        )?);
    }
    for diagnostic in checker_manager.take_diagnostics() {
        eprintln!(
            "checker diagnostic: {}",
            serde_json::to_string(&diagnostic).context("failed to serialize checker diagnostic")?
        );
    }

    if let Some(path) = report_outputs.system_graph_out.as_deref() {
        let mut document = system_graph.to_json();
        document["cross_component_findings"] = serde_json::to_value(&cross_component_findings)
            .context("failed to encode cross-component findings")?;
        write_text_file(
            path,
            &serde_json::to_string_pretty(&document).context("failed to encode system graph")?,
        )?;
    }
    if let Some(path) = report_outputs.sarif_out.as_deref() {
        let value = export_sarif_with_checker_manifests(
            "uniflow",
            &all_findings,
            &checker_findings,
            &checker_manifests,
        );
        write_text_file(
            path,
            &serde_json::to_string_pretty(&value).context("failed to encode SARIF")?,
        )?;
    }
    if let Some(path) = report_outputs.xlsx_out.as_deref() {
        let sections = per_language_flows
            .iter()
            .map(|(language, flow, findings)| ExcelReportSection {
                name: language.as_str(),
                flow,
                findings,
            })
            .collect::<Vec<_>>();
        export_excel_report_sections(path, &sections, &checker_findings)
            .map_err(|err| anyhow::anyhow!("failed to write Excel report to {path}: {err}"))?;
    }
    if per_language_flows.len() == 1 {
        let (_, flow, findings) = &per_language_flows[0];
        if let Some(path) = report_outputs.dot_out.as_deref() {
            write_text_file(path, &export_dot(flow, findings))?;
        }
        if let Some(path) = report_outputs.markdown_out.as_deref() {
            write_text_file(
                path,
                &export_markdown_report_with_checkers(flow, findings, &checker_findings),
            )?;
        }
    } else {
        for (language, flow, findings) in &per_language_flows {
            if let Some(path) = report_outputs.dot_out.as_deref() {
                write_text_file(&suffix_path_for_language(path, language), &export_dot(flow, findings))?;
            }
            if let Some(path) = report_outputs.markdown_out.as_deref() {
                write_text_file(
                    &suffix_path_for_language(path, language),
                    &export_markdown_report_with_checkers(flow, findings, &checker_findings),
                )?;
            }
        }
    }

    print_all_findings(&all_findings, &checker_findings, pretty_findings_flag)?;
    tracker.finish();
    Ok(())
}

fn lower_java_bytecode_input(
    path: &Path,
) -> Result<(
    IrProgram,
    Vec<uniflow_lang_java_bytecode::ClassfileDiagnostic>,
    Vec<uniflow_jni_bridge::NativeMethodDecl>,
)> {
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "class")
    {
        lower_class_file(path)
    } else {
        lower_archive(path)
    }
}

/// Decodes one `.dll`/`.exe` (.NET CIL) input into IR, mirroring
/// `lower_java_bytecode_input`'s shape for the JVM.
fn lower_dotnet_bytecode_input(path: &Path) -> Result<(IrProgram, Vec<String>)> {
    uniflow_lang_dotnet_bytecode::lower_assembly_file(path)
}

/// Decodes one `.pyc` (CPython bytecode) input into IR, mirroring
/// `lower_java_bytecode_input`'s shape for the JVM.
fn lower_python_bytecode_input(path: &Path) -> Result<(IrProgram, Vec<String>)> {
    uniflow_lang_python_bytecode::lower_pyc_file(path)
}

/// Decodes one `.wasm` input into IR. Unlike the other three bytecode
/// formats, a WASM module carries no per-file diagnostics list — its
/// frontend never produces partial/best-effort output, only success or a
/// hard parse error.
fn lower_wasm_bytecode_input(path: &Path) -> Result<IrProgram> {
    uniflow_lang_wasm_bytecode::lower_module_file(path)
}

/// Decodes every bytecode dependency reachable from `paths` straight to IR
/// (bypassing each format's HIR source frontend entirely — there isn't one
/// for compiled-only input), for a *single-language* scan. Java bytecode
/// (`.class`/`.jar`/`.war`) is collected only when `language` is `Java`,
/// .NET CIL (`.dll`/`.exe`) only when `CSharp`, and CPython bytecode
/// (`.pyc`) only when `Python` — mirroring how the project's own source
/// files are gated. WASM (`.wasm`) has no owning source `Language` (it is a
/// genuine cross-language compilation target), so it is always collected
/// regardless of which language this scan is otherwise restricted to.
fn collect_bytecode_ir_programs(language: &Language, paths: &[PathBuf]) -> Result<Vec<IrProgram>> {
    let mut programs = Vec::new();
    if *language == Language::Java {
        let bytecode_files =
            collect_java_bytecode_files(paths).context("failed to collect Java bytecode inputs")?;
        for bytecode_file in &bytecode_files {
            let (program, diagnostics, _natives) = lower_java_bytecode_input(bytecode_file)
                .with_context(|| format!("failed to decode Java bytecode input {}", bytecode_file.display()))?;
            for diagnostic in diagnostics {
                eprintln!("uniflow: {}: {}", bytecode_file.display(), diagnostic.0);
            }
            programs.push(program);
        }
    }
    if *language == Language::CSharp {
        let dotnet_files =
            collect_dotnet_bytecode_files(paths).context("failed to collect .NET bytecode inputs")?;
        for dotnet_file in &dotnet_files {
            let (program, diagnostics) = lower_dotnet_bytecode_input(dotnet_file)
                .with_context(|| format!("failed to decode .NET bytecode input {}", dotnet_file.display()))?;
            for diagnostic in diagnostics {
                eprintln!("uniflow: {}: {diagnostic}", dotnet_file.display());
            }
            programs.push(program);
        }
    }
    if *language == Language::Python {
        let pyc_files =
            collect_python_bytecode_files(paths).context("failed to collect CPython bytecode inputs")?;
        for pyc_file in &pyc_files {
            let (program, diagnostics) = lower_python_bytecode_input(pyc_file)
                .with_context(|| format!("failed to decode CPython bytecode input {}", pyc_file.display()))?;
            for diagnostic in diagnostics {
                eprintln!("uniflow: {}: {diagnostic}", pyc_file.display());
            }
            programs.push(program);
        }
    }
    let wasm_files = collect_wasm_bytecode_files(paths).context("failed to collect WASM bytecode inputs")?;
    for wasm_file in &wasm_files {
        let program = lower_wasm_bytecode_input(wasm_file)
            .with_context(|| format!("failed to decode WASM bytecode input {}", wasm_file.display()))?;
        programs.push(program);
    }
    Ok(programs)
}

/// Inserts `.<language>` before a report path's extension (or appends it if
/// the path has none), used when a mixed run produces more than one
/// per-language-group DOT/Markdown report and they can't share one filename.
fn suffix_path_for_language(path: &str, language: &Language) -> String {
    let path_buf = Path::new(path);
    let suffix = language.as_str();
    match path_buf.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => {
            let stem = path_buf
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("output");
            let file_name = format!("{stem}.{suffix}.{ext}");
            match path_buf.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                Some(parent) => parent.join(file_name).display().to_string(),
                None => file_name,
            }
        }
        None => format!("{path}.{suffix}"),
    }
}

fn emit_flow_views(
    flow: &FlowGraph,
    dump_graph: bool,
    dump_call_report: bool,
    dump_stats: bool,
) -> Result<()> {
    if dump_graph {
        println!(
            "{}",
            serde_json::to_string_pretty(&flow.node_label_map())
                .context("failed to serialize graph label map")?
        );
    }
    if dump_call_report {
        println!(
            "{}",
            serde_json::to_string_pretty(&flow.call_report())
                .context("failed to serialize call report")?
        );
    }
    if dump_stats {
        println!(
            "{}",
            serde_json::to_string_pretty(&flow.stats())
                .context("failed to serialize flow stats")?
        );
    }
    Ok(())
}

fn maybe_write_reports(
    flow: &FlowGraph,
    findings: &[TaintFinding],
    outputs: &ReportOutputs,
    checker_findings: &[CheckerFinding],
    checker_manifests: &[uniflow_checker_api::CheckerManifest],
) -> Result<()> {
    if let Some(path) = outputs.sarif_out.as_deref() {
        let value = export_sarif_with_checker_manifests(
            "uniflow",
            findings,
            checker_findings,
            checker_manifests,
        );
        write_text_file(
            path,
            &serde_json::to_string_pretty(&value).context("failed to encode SARIF")?,
        )?;
    }
    if let Some(path) = outputs.dot_out.as_deref() {
        let dot = export_dot(flow, findings);
        write_text_file(path, &dot)?;
    }
    if let Some(path) = outputs.markdown_out.as_deref() {
        let markdown = export_markdown_report_with_checkers(flow, findings, checker_findings);
        write_text_file(path, &markdown)?;
    }
    if let Some(path) = outputs.xlsx_out.as_deref() {
        export_excel_report(path, flow, findings, checker_findings)
            .map_err(|err| anyhow::anyhow!("failed to write Excel report to {path}: {err}"))?;
    }
    Ok(())
}

fn write_text_file(path: &str, text: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create report directory {}", parent.display())
            })?;
        }
    }
    fs::write(path, text).with_context(|| format!("failed to write report to {path}"))
}

/// The console is a transport for scan results, not a rule-catalog export.
/// In particular, legacy translations can contain whole knowledge-base
/// articles and examples. Repeating those documents on every finding made a
/// tiny project consume gigabytes while `serde_json::to_string_pretty` built
/// the output in memory. Keep the complete metadata for explicit reports, but
/// emit a compact, streaming finding representation to the terminal.
#[derive(Serialize)]
struct ConsoleTaintFinding<'a> {
    source_rule_id: &'a str,
    sink_rule_id: &'a str,
    source_kind: &'a str,
    sink_kind: &'a str,
    sink_node: usize,
    path: &'a [usize],
    source_label: &'a str,
    sink_label: &'a str,
    source_location: &'a str,
    sink_location: &'a str,
    path_labels: &'a [String],
    steps: &'a [uniflow_taint::TaintStep],
    finding_kind: &'a str,
    severity: &'a str,
    message: &'a str,
    rule_title: &'a str,
    cwe: &'a [String],
    standards: &'a [String],
    translations: &'a RuleTranslations,
    analysis_complete: bool,
    completeness: &'a uniflow_value_flow::QueryCompleteness,
}

impl<'a> From<&'a TaintFinding> for ConsoleTaintFinding<'a> {
    fn from(finding: &'a TaintFinding) -> Self {
        Self {
            source_rule_id: &finding.source_rule_id,
            sink_rule_id: &finding.sink_rule_id,
            source_kind: &finding.source_kind,
            sink_kind: &finding.sink_kind,
            sink_node: finding.sink_node,
            path: &finding.path,
            source_label: &finding.source_label,
            sink_label: &finding.sink_label,
            source_location: &finding.source_location,
            sink_location: &finding.sink_location,
            path_labels: &finding.path_labels,
            steps: &finding.steps,
            finding_kind: &finding.finding_kind,
            severity: &finding.severity,
            message: &finding.message,
            rule_title: &finding.rule_title,
            cwe: &finding.cwe,
            standards: &finding.standards,
            // Taint findings compact every localized string before reaching
            // the CLI, so this preserves actionable bundled rule text without
            // reintroducing the historical whole-knowledge-base allocation.
            translations: &finding.translations,
            analysis_complete: finding.analysis_complete,
            completeness: &finding.completeness,
        }
    }
}

fn print_all_findings(
    findings: &[TaintFinding],
    checker_findings: &[CheckerFinding],
    pretty: bool,
) -> Result<()> {
    if checker_findings.is_empty() {
        return print_findings(findings, pretty);
    }
    if pretty {
        print!("{}", pretty_findings(findings));
        println!("External checker findings:");
        for finding in checker_findings {
            println!(
                "- [{}] {} at {}:{}:{}: {}",
                finding.level,
                finding.rule_id,
                finding.location.uri,
                finding.location.line,
                finding.location.column,
                finding.message
            );
        }
        Ok(())
    } else {
        #[derive(Serialize)]
        struct ConsoleFindings<'a> {
            #[serde(rename = "taintFindings")]
            taint_findings: Vec<ConsoleTaintFinding<'a>>,
            #[serde(rename = "checkerFindings")]
            checker_findings: &'a [CheckerFinding],
        }
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(
            &mut out,
            &ConsoleFindings {
                taint_findings: findings.iter().map(ConsoleTaintFinding::from).collect(),
                checker_findings,
            },
        )
        .context("failed to serialize findings")?;
        writeln!(out).context("failed to finish findings output")?;
        Ok(())
    }
}

fn print_findings(findings: &[TaintFinding], pretty: bool) -> Result<()> {
    if pretty {
        print!("{}", pretty_findings(findings));
        Ok(())
    } else {
        let mut out = io::stdout().lock();
        let compact = findings
            .iter()
            .map(ConsoleTaintFinding::from)
            .collect::<Vec<_>>();
        serde_json::to_writer_pretty(&mut out, &compact)
            .context("failed to serialize taint findings")?;
        writeln!(out).context("failed to finish findings output")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_ir::validate_program;

    #[test]
    fn llm_review_document_is_explicitly_advisory_and_requires_verification() {
        let document = semantic_review_document(
            "service.py",
            Language::Python,
            SemanticAnswer {
                answer: "possible command injection".to_string(),
                confidence: 0.7,
                rationale: "request data reaches shell construction".to_string(),
            },
        );
        assert_eq!(document["classification"], "advisory");
        assert_eq!(document["oracle"], "llm");
        assert_eq!(document["language"], "python");
        assert_eq!(document["verification_required"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn review_code_cli_requires_an_explicit_source_upload_acknowledgement_flag() {
        let cli = Cli::try_parse_from([
            "uniflow",
            "review-code",
            "--language",
            "python",
            "--input",
            "service.py",
            "--llm-endpoint",
            "https://llm.example/v1/chat/completions",
            "--llm-model",
            "model",
        ])
        .expect("parse review-code arguments");
        let Command::ReviewCode { allow_llm_source_upload, max_input_bytes, .. } = cli.command else {
            panic!("review-code command");
        };
        assert!(!allow_llm_source_upload);
        assert_eq!(max_input_bytes, 65_536);
    }

    #[test]
    fn prove_constraint_cli_keeps_formal_results_separate_from_findings() {
        let cli = Cli::try_parse_from([
            "uniflow",
            "prove-constraint",
            "--kind",
            "implication",
            "--lhs",
            "x >= 0",
            "--rhs",
            "x + 1 > 0",
            "--bound",
            "x=0..256",
        ])
        .expect("parse prove-constraint arguments");
        let Command::ProveConstraint { kind, lhs, rhs, bounds, .. } = cli.command else {
            panic!("prove-constraint command");
        };
        let query = ConstraintQuery {
            kind: kind.into(),
            domain: Domain::IntegerArithmetic,
            language: "uniflow-normalized".to_string(),
            lhs,
            rhs,
            context: parse_proof_bounds(bounds).expect("valid bound"),
        };
        let document = formal_proof_document(&query, "lean", None);
        assert_eq!(document["classification"], "formal-proof-result");
        assert_eq!(document["status"], "toolchain-unavailable");
        assert!(document["finding_promotion"].as_str().is_some_and(|text| text.contains("source-to-sink")));
    }

    #[test]
    fn proof_bounds_reject_non_integer_or_ambiguous_input() {
        assert!(parse_proof_bounds(vec!["x=zero..1".to_string()]).is_err());
        assert!(parse_proof_bounds(vec!["x=0..1..2".to_string()]).is_err());
        assert!(parse_proof_bounds(vec!["not-a-name=0..1".to_string()]).is_err());
    }

    #[test]
    fn invalid_lowered_functions_are_quarantined_without_disabling_the_project() {
        let mut ir = sample_java_sql_program();
        let duplicate = ir.functions[0].blocks[0].clone();
        ir.functions[0].blocks.push(duplicate);
        let valid = uniflow_core::validate_or_quarantine_invalid_ir_functions(ir)
            .expect("the remaining project IR should validate");
        assert!(valid.functions.is_empty());
        assert!(valid.entry_points.is_empty());
        validate_program(&valid).expect("quarantined IR must be safe for dataflow");
    }

    #[test]
    fn cli_exposes_every_supported_language() {
        let actual = LangArg::value_variants()
            .iter()
            .copied()
            .map(Language::from)
            .collect::<Vec<_>>();
        assert_eq!(
            actual,
            vec![
                // `Mix` is a CLI-only orchestration mode, not a real
                // frontend language; it deliberately has no dedicated
                // `Language` variant.
                Language::Unknown,
                Language::C,
                Language::Cpp,
                Language::CSharp,
                Language::ObjC,
                Language::ObjCpp,
                Language::Java,
                Language::Kotlin,
                Language::Swift,
                Language::Python,
                Language::Go,
                Language::JavaScript,
                Language::Jsp,
                Language::Sql,
                Language::Php,
                Language::Ruby,
                Language::Rust,
                Language::Shell,
            ]
        );
    }

    #[test]
    fn dump_stats_does_not_force_global_flow_materialization() {
        assert!(!uniflow_core::flow_requires_full_materialization(false, false, false, false));
        assert!(uniflow_core::flow_requires_full_materialization(true, false, false, false));
        assert!(uniflow_core::flow_requires_full_materialization(false, true, false, false));
        assert!(uniflow_core::flow_requires_full_materialization(false, false, true, false));
        assert!(uniflow_core::flow_requires_full_materialization(false, false, false, true));
    }

    #[test]
    fn cli_accepts_objective_cpp_alias() {
        let cli = Cli::try_parse_from([
            "uniflow",
            "analyze-source",
            "--language",
            "objective-cpp",
            "--input",
            "sample.mm",
        ])
        .expect("Objective-C++ alias should parse");
        let Command::AnalyzeSource { language, .. } = cli.command else {
            panic!("expected analyze-source");
        };
        assert!(matches!(Language::from(language), Language::ObjCpp));
    }

    #[test]
    fn source_file_checker_payload_preserves_host_markup() {
        let source = "<main><% value(); %></main>".to_string();
        let payload = uniflow_core::source_file_payload("view.jsp", &Language::Jsp, source.clone());
        assert_eq!(payload["path"], "view.jsp");
        assert_eq!(payload["language"], "jsp");
        assert_eq!(payload["source"], source);
    }
}
