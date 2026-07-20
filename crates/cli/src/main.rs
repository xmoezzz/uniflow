use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uniflow_baseline::{builtin_pack_manifest, builtin_security_pack};
use uniflow_cache::{build_project_with_cache_options, load_project_cache, save_project_cache};
use uniflow_checker_api::{event_kind, CheckerFinding};
use uniflow_checker_host::{
    CheckerFailurePolicy, CheckerHostOptions, CheckerIsolation, CheckerManager,
};
use uniflow_frontend::{
    collect_source_files, parse_project_sources_with_options, parse_source_with_options,
    FrontendOptions,
};
use uniflow_hir::Language;
use uniflow_ir::{sample_java_sql_program, validate_program};
use uniflow_lowering::lower_program;
use uniflow_models::{load_with_defaults, mit_catalog_manifest, mit_models_for};
use uniflow_platform::PlatformProfile;
use uniflow_report::{
    export_dot, export_markdown_report_with_checkers, export_sarif_with_checkers,
};
use uniflow_rules::RuleSet;
use uniflow_taint::{analyze, pretty_findings, TaintFinding};
use uniflow_value_flow::{build, build_with_progress, FlowGraph};

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
    Java,
    Python,
}

impl From<LangArg> for Language {
    fn from(value: LangArg) -> Self {
        match value {
            LangArg::C => Language::C,
            LangArg::Cpp => Language::Cpp,
            LangArg::Java => Language::Java,
            LangArg::Python => Language::Python,
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
        spinner.enable_steady_tick(Duration::from_millis(100));
        spinner.set_message(format!("{}: {}", name, detail.into()));
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

fn main() -> Result<()> {
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
        } => {
            let language = Language::from(language);
            let roots = inputs.iter().map(PathBuf::from).collect::<Vec<_>>();
            let files = collect_source_files(language.clone(), &roots)?;
            let pack = builtin_security_pack()?;
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
            let findings = pack.scan_hir(&program, &source_by_path);
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
            let flow = build(&program, &rules);
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
            let frontend_options = make_frontend_options(platform, c_family);
            let mut tracker = ProgressTracker::new(11);
            let source = tracker.phase("read-source", input.clone(), |_| {
                fs::read_to_string(&input)
                    .with_context(|| format!("failed to read source from {input}"))
            })?;
            let rules = tracker.phase(
                "load-rules",
                rules.clone().unwrap_or_else(|| "defaults".to_string()),
                |_| load_rules(language.clone(), rules.as_deref(), use_default_models),
            )?;
            let hir = tracker.phase("parse-source", input.clone(), |_| {
                parse_source_with_options(language, &input, &source, &frontend_options)
            })?;
            run_and_print_with_progress(
                &mut tracker,
                hir,
                &rules,
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
            let frontend_options = make_frontend_options(platform, c_family);
            let paths = inputs.into_iter().map(PathBuf::from).collect::<Vec<_>>();
            let use_cache = cache_in.is_some() || cache_out.is_some() || dump_cache_plan;
            let total_steps = 11;
            let mut tracker = ProgressTracker::new(total_steps);
            let rules = tracker.phase(
                "load-rules",
                rules.clone().unwrap_or_else(|| "defaults".to_string()),
                |_| load_rules(language.clone(), rules.as_deref(), use_default_models),
            )?;
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
                        let file_bar = multi.add(ProgressBar::new(files.len() as u64));
                        file_bar.set_style(file_style());
                        file_bar.set_message("reading source files");
                        let mut entries = Vec::with_capacity(files.len());
                        for file in &files {
                            let label = file.display().to_string();
                            file_bar.set_message(shorten_path(&label));
                            let source = fs::read_to_string(file).with_context(|| {
                                format!("failed to read source from {}", file.display())
                            })?;
                            entries.push((label, source));
                            file_bar.inc(1);
                        }
                        file_bar.finish_with_message(format!("read {} files", files.len()));
                        parse_project_sources_with_options(
                            language.clone(),
                            &entries,
                            &frontend_options,
                        )
                    },
                )?
            };

            run_and_print_with_progress(
                &mut tracker,
                hir,
                &rules,
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

fn run_and_print_with_progress(
    tracker: &mut ProgressTracker,
    hir: uniflow_hir::Program,
    rules: &RuleSet,
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
    let mut checker_findings = Vec::new();
    checker_findings.extend(checker_manager.broadcast(
        event_kind::ANALYSIS_START,
        json!({
            "language": format!("{:?}", hir.language),
            "files": hir.files.iter().map(|file| file.path.clone()).collect::<Vec<_>>(),
            "checkers": checker_manager.manifests(),
        }),
    )?);
    checker_findings.extend(checker_manager.broadcast(
        event_kind::HIR_PROGRAM,
        serde_json::to_value(&hir).context("failed to serialize HIR checker event")?,
    )?);

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
        let ir = lower_program(&hir);
        if let Err(errors) = validate_program(&ir) {
            let details = errors
                .into_iter()
                .map(|error| format!("{}: {}", error.function, error.message))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!("lowered IR failed validation:\n{details}");
        }
        Ok(ir)
    })?;
    checker_findings.extend(checker_manager.broadcast(
        event_kind::IR_PROGRAM,
        serde_json::to_value(&ir).context("failed to serialize IR checker event")?,
    )?);
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

    let flow = tracker.phase_with_spinner(
        "build-flow",
        format!("{} IR functions", ir.functions.len()),
        |_, spinner| {
            spinner.set_message(format!(
                "build-flow/init: {} IR functions",
                ir.functions.len()
            ));
            Ok(build_with_progress(&ir, rules, |progress| {
                spinner.set_message(format!(
                    "build-flow/{}: {}",
                    progress.stage, progress.detail
                ));
            }))
        },
    )?;
    let call_report = flow.call_report();
    checker_findings.extend(checker_manager.broadcast(
        event_kind::FLOW_SUMMARY,
        json!({
            "stats": flow.stats(),
            "calls": &call_report,
        }),
    )?);
    for call in &call_report {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::CALL,
            serde_json::to_value(call).context("failed to serialize call checker event")?,
        )?);
    }
    tracker.phase("emit-flow-views", "graph / call report / stats", |_| {
        emit_flow_views(&flow, dump_graph, dump_call_report, dump_stats)
    })?;
    let findings = tracker.phase(
        "taint-analysis",
        format!("{} flow nodes", flow.graph.node_count()),
        |_| Ok(analyze(&flow, rules)),
    )?;
    for finding in &findings {
        checker_findings.extend(checker_manager.broadcast(
            event_kind::TAINT_FINDING,
            serde_json::to_value(finding).context("failed to serialize taint checker event")?,
        )?);
    }
    let checker_finding_count_before_end = checker_findings.len();
    checker_findings.extend(checker_manager.broadcast(
        event_kind::ANALYSIS_END,
        json!({
            "taintFindingCount": findings.len(),
            "checkerFindingCount": checker_finding_count_before_end,
        }),
    )?);
    for diagnostic in checker_manager.take_diagnostics() {
        eprintln!(
            "checker diagnostic: {}",
            serde_json::to_string(&diagnostic)
                .context("failed to serialize checker diagnostic")?
        );
    }
    tracker.phase("reports", "sarif / dot / markdown / findings", |_| {
        maybe_write_reports(&flow, &findings, report_outputs, &checker_findings)?;
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
) -> Result<()> {
    if let Some(path) = outputs.sarif_out.as_deref() {
        let value = export_sarif_with_checkers("uniflow", findings, checker_findings);
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
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "taintFindings": findings,
                "checkerFindings": checker_findings,
            }))
            .context("failed to serialize findings")?
        );
        Ok(())
    }
}

fn print_findings(findings: &[TaintFinding], pretty: bool) -> Result<()> {
    if pretty {
        print!("{}", pretty_findings(findings));
        Ok(())
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(findings).context("failed to serialize taint findings")?
        );
        Ok(())
    }
}

fn shorten_path(path: &str) -> String {
    const MAX_LEN: usize = 80;
    if path.chars().count() <= MAX_LEN {
        return path.to_string();
    }
    let tail: String = path
        .chars()
        .rev()
        .take(MAX_LEN - 3)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("...{}", tail)
}
