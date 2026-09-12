use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde::Serialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uniflow_baseline::{
    audit_legacy_rule_tree, builtin_pack_manifest, builtin_security_pack,
    bundled_legacy_raw_assets, decrypt_legacy_rule_tree, BaselineScanOptions, OracleFormsMetadata,
};
use uniflow_cache::{build_project_with_cache_options, load_project_cache, save_project_cache};
use uniflow_checker_api::{event_kind, CheckerFinding};
use uniflow_checker_host::{
    CheckerFailurePolicy, CheckerHostOptions, CheckerIsolation, CheckerManager,
};
use uniflow_frontend::{
    collect_auxiliary_files, collect_source_files, parse_project_files_with_options_and_progress,
    parse_project_sources_with_options, parse_source_with_options, FrontendOptions,
};
use uniflow_hir::Language;
use uniflow_ir::{sample_java_sql_program, validate_program, Program as IrProgram};
use uniflow_lowering::lower_program;
use uniflow_models::{
    audit_legacy_jvm_rule_tree, compile_legacy_csharp_pack, compile_legacy_go_pack,
    compile_legacy_jvm_rule_tree, compile_legacy_native_dataflow_pack,
    attach_legacy_metadata_for_ids, compile_legacy_pysa_rule_tree,
    load_with_defaults, load_with_defaults_for_analysis, mit_catalog_manifest, mit_models_for,
    LegacyCsharpPack, LegacyGoPack, LegacyNativeDataflowPack,
};
use uniflow_platform::PlatformProfile;
use uniflow_report::{
    export_dot, export_markdown_report_with_checkers, export_sarif_with_checker_manifests,
};
use uniflow_rules::{RuleSet, RuleTranslations};
use uniflow_taint::{analyze, pretty_findings, TaintFinding};
use uniflow_value_flow::{
    build_for_rules_with_progress, build_for_scan_with_progress, build_with_capabilities,
    AnalysisCapabilities, FlowGraph, FlowNode,
};

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
}

#[derive(Debug, Subcommand)]
enum Command {
    CheckRules {
        #[arg(long)]
        rules: String,
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
        #[arg(long)]
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
        #[arg(long)]
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
            let language = Language::from(language);
            let roots = inputs.iter().map(PathBuf::from).collect::<Vec<_>>();
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
            checkers,
            checker_timeout_ms,
            checker_failure,
            checker_isolation,
        } => {
            let language: Language = language.into();
            let hydrate_bundled_metadata = use_default_models || rules.is_none();
            let frontend_options = make_frontend_options(platform, c_family);
            let paths = inputs.into_iter().map(PathBuf::from).collect::<Vec<_>>();
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

            let hir = if use_cache {
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
                },
                &checkers,
                RuntimeCheckerOptions {
                    timeout_ms: checker_timeout_ms,
                    failure_policy: checker_failure,
                    isolation: checker_isolation,
                },
            )?;
        }
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
    mut rules: RuleSet,
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

    tracker.phase(
        "emit-hir",
        if dump_hir {
            "serializing HIR"
        } else {
            "skipped"
        },
        |_| {
            if dump_hir {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&hir).context("failed to serialize hir")?
                );
            }
            Ok(())
        },
    )?;

    let ir = tracker.phase("lower", format!("{} files", hir.files.len()), |_| {
        validate_or_quarantine_invalid_ir_functions(lower_program(&hir))
    })?;
    if checker_manager.has_subscriber(event_kind::IR_PROGRAM) {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::IR_PROGRAM,
            serde_json::to_value(&ir).context("failed to serialize IR checker event")?,
        )?);
    }
    tracker.phase(
        "emit-ir",
        if dump_ir { "serializing IR" } else { "skipped" },
        |_| {
            if dump_ir {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&ir).context("failed to serialize ir")?
                );
            }
            Ok(())
        },
    )?;

    // Lowering owns all information required by flow/taint analysis.  Keeping
    // the parsed HIR alive until report emission duplicates a large project in
    // memory while the flow graph is being built; on PyTorch that alone was
    // several gigabytes before the first graph node existed.
    drop(hir);

    // Statistics describe whichever analysis plan was selected and do not
    // require the legacy global closure.  Keep `--dump-stats` on the normal
    // rule-driven path so it remains safe to use when investigating a large
    // project; graph/call dumps still explicitly request full materialization.
    let force_full_flow = flow_requires_full_materialization(
        dump_graph,
        dump_call_report,
        checker_manager.has_subscriber(event_kind::FLOW_SUMMARY),
        checker_manager.has_subscriber(event_kind::CALL),
    );
    let capabilities = if force_full_flow {
        AnalysisCapabilities::full()
    } else {
        AnalysisCapabilities::for_rules(&ir, &rules)
    };
    let flow = tracker.phase_with_spinner(
        "build-flow",
        format!("{} IR functions", ir.functions.len()),
        |_, spinner| {
            spinner.set_message(format!(
                "build-flow/init: {} IR functions",
                ir.functions.len()
            ));
            let build = |progress: uniflow_value_flow::BuildProgress| {
                spinner.set_message(format!(
                    "build-flow/{}: {}",
                    progress.stage, progress.detail
                ));
            };
            if force_full_flow {
                Ok(build_with_capabilities(&ir, &rules, capabilities, build))
            } else {
                Ok(build_for_scan_with_progress(&ir, &rules, build))
            }
        },
    )?;
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
    tracker.phase("emit-flow-views", "graph / call report / stats", |_| {
        emit_flow_views(&flow, dump_graph, dump_call_report, dump_stats)
    })?;
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
        attach_legacy_metadata_for_ids(&flow.language, &mut rules, &report_ids)?;
    }
    let findings = tracker.phase(
        "taint-analysis",
        format!("{} flow nodes", flow.graph.node_count()),
        |_| Ok(analyze(&flow, &rules)),
    )?;
    if checker_manager.has_subscriber(event_kind::TAINT_FINDING) {
        for finding in &findings {
            checker_findings.extend(checker_manager.broadcast(
                event_kind::TAINT_FINDING,
                serde_json::to_value(finding).context("failed to serialize taint checker event")?,
            )?);
        }
    }
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
    for diagnostic in checker_manager.take_diagnostics() {
        eprintln!(
            "checker diagnostic: {}",
            serde_json::to_string(&diagnostic).context("failed to serialize checker diagnostic")?
        );
    }
    tracker.phase("reports", "sarif / dot / markdown / findings", |_| {
        maybe_write_reports(
            &flow,
            &findings,
            report_outputs,
            &checker_findings,
            &checker_manifests,
        )?;
        print_all_findings(&findings, &checker_findings, pretty_findings_flag)
    })?;
    tracker.finish();
    Ok(())
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

fn source_file_payload(path: &str, language: &Language, source: String) -> serde_json::Value {
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
fn validate_or_quarantine_invalid_ir_functions(mut ir: IrProgram) -> Result<IrProgram> {
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
        "uniflow: quarantined {dropped} function(s) with invalid lowered IR; continuing with {} valid function(s)",
        ir.functions.len()
    );
    Ok(ir)
}

fn flow_requires_full_materialization(
    dump_graph: bool,
    dump_call_report: bool,
    flow_summary_subscriber: bool,
    call_subscriber: bool,
) -> bool {
    dump_graph || dump_call_report || flow_summary_subscriber || call_subscriber
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_lowered_functions_are_quarantined_without_disabling_the_project() {
        let mut ir = sample_java_sql_program();
        let duplicate = ir.functions[0].blocks[0].clone();
        ir.functions[0].blocks.push(duplicate);
        let valid = validate_or_quarantine_invalid_ir_functions(ir)
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
        assert!(!flow_requires_full_materialization(false, false, false, false));
        assert!(flow_requires_full_materialization(true, false, false, false));
        assert!(flow_requires_full_materialization(false, true, false, false));
        assert!(flow_requires_full_materialization(false, false, true, false));
        assert!(flow_requires_full_materialization(false, false, false, true));
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
        let payload = source_file_payload("view.jsp", &Language::Jsp, source.clone());
        assert_eq!(payload["path"], "view.jsp");
        assert_eq!(payload["language"], "jsp");
        assert_eq!(payload["source"], source);
    }
}
