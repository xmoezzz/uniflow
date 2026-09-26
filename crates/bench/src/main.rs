//! `uniflow-bench`: reproducible quality numbers for uniflow's SAST and SCA
//! (cosmos ADR-0019). Every suite has published ground truth and is scored
//! with that suite's own rules, so results are comparable with what other
//! tools report on the same corpora.
//!
//! ```text
//! uniflow-bench sast --suite all --out bench-out            # default (sampled where huge)
//! uniflow-bench sast --suite juliet-c-cpp-1.3 --full --out bench-out
//! uniflow-bench sca  --corpus DIR --snapshot vulndb.jsonl --others DIR --out bench-out
//! uniflow-bench report --in bench-out --markdown report.md
//! ```
mod corpus;
mod metrics;
mod report;
mod sast;
mod sca;
mod suites;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

pub const SAST_SUITES: &[&str] = &["owasp-benchmark-java", "owasp-benchmark-python", "juliet-c-cpp-1.3", "realvuln-python", "realvuln-js", "gosec-samples"];

#[derive(Parser)]
#[command(name = "uniflow-bench", version, about = "SAST/SCA quality benchmark for uniflow")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Score SAST against labeled suites. Each suite runs in its own child
    /// process, so its peak memory is measured on its own.
    Sast {
        /// A suite id, or `all`.
        #[arg(long, default_value = "all")]
        suite: String,
        /// Whole corpora instead of the deterministic default subsets
        /// (Juliet: 25 cases per CWE; RealVuln: community repos only).
        #[arg(long)]
        full: bool,
        /// Record new/changed corpus pins in corpora.lock.json instead of
        /// refusing to run — only when a corpus is added or bumped on purpose.
        #[arg(long)]
        update_lock: bool,
        #[arg(long, default_value = "bench-out")]
        out: PathBuf,
        /// Internal: run exactly one suite in this process.
        #[arg(long, hide = true)]
        child: bool,
    },
    /// Score SCA against other scanners' results on the same inputs.
    Sca {
        /// Directory of projects (one per subdirectory) and/or `docker save`
        /// image tarballs (`*.tar`).
        #[arg(long)]
        corpus: PathBuf,
        /// Vuln snapshot (JSON Lines of `uniflow_vuln_db::VulnRecord`).
        #[arg(long)]
        snapshot: PathBuf,
        /// `<tool>/<input-name>.json` results of trivy / grype / osv-scanner.
        #[arg(long)]
        others: PathBuf,
        #[arg(long, default_value = "bench-out")]
        out: PathBuf,
    },
    /// Internal: one bounded scan for `sast::scan_bounded`.
    #[command(hide = true)]
    ScanPaths {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(last = true)]
        paths: Vec<PathBuf>,
    },
    /// Fetch (and pin) the SCA project corpus into `out/<name>`.
    ScaCorpus {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        update_lock: bool,
    },
    /// Merge `bench-out/*.json` into one Markdown report.
    Report {
        #[arg(long = "in", default_value = "bench-out")]
        input: PathBuf,
        #[arg(long)]
        markdown: PathBuf,
    },
}

/// Peak resident set size of this process, in MB.
fn peak_rss_mb() -> Option<f64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return None;
    }
    // Linux reports KiB, macOS bytes.
    let bytes = if cfg!(target_os = "macos") { usage.ru_maxrss as f64 } else { usage.ru_maxrss as f64 * 1024.0 };
    Some(bytes / (1024.0 * 1024.0))
}

fn run_one(suite: &str, full: bool, update_lock: bool) -> Result<suites::SuiteResult> {
    // Names the optional raw-findings dump (see `sast::scan`).
    std::env::set_var("UNIFLOW_BENCH_SUITE", suite);
    let mut lock = corpus::Lock::load()?;
    let result = match suite {
        "owasp-benchmark-java" => suites::owasp::run(&suites::owasp::JAVA, &mut lock, update_lock, None),
        "owasp-benchmark-python" => suites::owasp::run(&suites::owasp::PYTHON, &mut lock, update_lock, None),
        "juliet-c-cpp-1.3" => suites::juliet::run(&mut lock, update_lock, (!full).then_some(25)),
        "realvuln-python" => suites::realvuln::run("python", &mut lock, update_lock, full),
        "realvuln-js" => suites::realvuln::run("js", &mut lock, update_lock, full),
        "gosec-samples" => suites::gosec::run(&mut lock, update_lock),
        other => bail!("unknown suite {other} (known: {})", SAST_SUITES.join(", ")),
    };
    if update_lock {
        lock.save()?;
    }
    result
}

fn write_json(out: &Path, name: &str, value: &impl serde::Serialize) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let path = out.join(format!("{name}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(value)?).with_context(|| format!("writing {}", path.display()))
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Sast { suite, full, update_lock, out, child } => {
            if child || suite != "all" {
                let mut result = run_one(&suite, full, update_lock)?;
                // Suites that scan in bounded children report the largest
                // child's peak; the rest scanned in this process.
                result.peak_rss_mb = result.peak_rss_mb.or_else(peak_rss_mb);
                write_json(&out, &format!("sast-{}", result.suite), &result)?;
                eprintln!("{}: recall {:?} precision {:?} ({} cases, {:.0}s)", result.suite, result.overall.recall, result.overall.precision, result.cases, result.scan_seconds);
                return Ok(());
            }
            let exe = std::env::current_exe()?;
            let mut failed = Vec::new();
            for suite in SAST_SUITES {
                eprintln!("== {suite}");
                let mut cmd = std::process::Command::new(&exe);
                cmd.args(["sast", "--child", "--suite", suite, "--out"]).arg(&out);
                if full {
                    cmd.arg("--full");
                }
                if update_lock {
                    cmd.arg("--update-lock");
                }
                if !cmd.status()?.success() {
                    failed.push(*suite);
                }
            }
            if !failed.is_empty() {
                bail!("suites failed: {}", failed.join(", "));
            }
            Ok(())
        }
        Command::Sca { corpus, snapshot, others, out } => {
            let result = sca::run(&corpus, &snapshot, &others)?;
            write_json(&out, "sca-comparison", &result)
        }
        Command::ScanPaths { root, out, paths } => {
            let mut run = sast::scan(&root, &paths)?;
            run.peak_rss_mb = peak_rss_mb();
            std::fs::write(&out, serde_json::to_vec(&run)?)?;
            Ok(())
        }
        Command::ScaCorpus { out, update_lock } => {
            let mut lock = corpus::Lock::load()?;
            sca::materialize(&out, &mut lock, update_lock)?;
            if update_lock {
                lock.save()?;
            }
            Ok(())
        }
        Command::Report { input, markdown } => report::write(&input, &markdown),
    }
}
