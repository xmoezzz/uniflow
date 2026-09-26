//! The SAST side of the harness: runs the exact entry point `cosmos-agent`
//! uses (`uniflow_core::scan_source_paths`) and flattens its two finding
//! kinds (taint flows, checker findings) into one shape the suites can
//! match against ground truth.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Path relative to the scanned corpus root, `/`-separated.
    pub file: String,
    pub line: Option<u32>,
    /// Normalized `CWE-<n>` ids, possibly empty (a rule with no CWE can
    /// never match a CWE-labeled ground truth entry — reported as such).
    pub cwes: BTreeSet<String>,
    pub rule_id: String,
    pub kind: String,
}

pub fn normalize_cwe(raw: &str) -> Option<String> {
    let digits: String = raw.trim().trim_start_matches("CWE").trim_start_matches(['-', ':', ' ']).chars().take_while(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then(|| format!("CWE-{}", digits.trim_start_matches('0')))
}

/// `@/abs/path/File.java:12:5` → (`/abs/path/File.java`, 12).
fn parse_location(location: &str) -> (String, Option<u32>) {
    let stripped = location.strip_prefix('@').unwrap_or(location);
    match stripped.rsplit_once(':').and_then(|(rest, col)| col.chars().all(|c| c.is_ascii_digit()).then_some(rest)).and_then(|rest| rest.rsplit_once(':')) {
        Some((path, line)) if line.chars().all(|c| c.is_ascii_digit()) && !line.is_empty() => (path.to_string(), line.parse().ok()),
        _ => (stripped.to_string(), None),
    }
}

fn relative(root: &Path, file: &str) -> String {
    let path = Path::new(file);
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.to_string_lossy().replace('\\', "/").trim_start_matches("./").to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanRun {
    pub findings: Vec<Finding>,
    pub seconds: f64,
    pub files_scanned: usize,
    /// Peak RSS of the scanning child process (bounded scans only).
    #[serde(default)]
    pub peak_rss_mb: Option<f64>,
}

/// Scans `paths` (all under `root`) in one call, so rule models load once
/// per batch instead of once per test case.
pub fn scan(root: &Path, paths: &[PathBuf]) -> Result<ScanRun> {
    let started = Instant::now();
    let outcome = uniflow_core::scan_source_paths(paths)?;
    let seconds = started.elapsed().as_secs_f64();
    let mut findings = Vec::new();
    for taint in &outcome.taint_findings {
        let (file, line) = parse_location(&taint.sink_location);
        findings.push(Finding {
            file: relative(root, &file),
            line,
            cwes: taint.cwe.iter().filter_map(|c| normalize_cwe(c)).collect(),
            rule_id: taint.sink_rule_id.clone(),
            kind: "taint".into(),
        });
    }
    for checker in &outcome.checker_findings {
        let mut cwes: BTreeSet<String> = BTreeSet::new();
        for key in ["cwe", "cwes", "CWE"] {
            match checker.properties.get(key) {
                Some(serde_json::Value::String(s)) => cwes.extend(s.split([',', ' ']).filter_map(normalize_cwe)),
                Some(serde_json::Value::Array(items)) => cwes.extend(items.iter().filter_map(|v| v.as_str()).filter_map(normalize_cwe)),
                _ => {}
            }
        }
        findings.push(Finding {
            file: relative(root, &checker.location.uri.trim_start_matches("file://").to_string()),
            line: Some(checker.location.line),
            cwes,
            rule_id: checker.rule_id.clone(),
            kind: "checker".into(),
        });
    }
    for misuse in &outcome.misuse_findings {
        findings.push(Finding {
            file: relative(root, &misuse.path),
            line: Some(misuse.line as u32),
            cwes: misuse.cwe.iter().filter_map(|c| normalize_cwe(c)).collect(),
            rule_id: misuse.rule_id.clone(),
            kind: "misuse".into(),
        });
    }
    // Raw findings for manual triage of a surprising score: every finding
    // as the harness saw it, appended as JSON Lines.
    if let Ok(dir) = std::env::var("UNIFLOW_BENCH_DUMP") {
        use std::io::Write as _;
        std::fs::create_dir_all(&dir)?;
        let mut out = std::fs::OpenOptions::new().create(true).append(true).open(Path::new(&dir).join(format!("{}.jsonl", std::env::var("UNIFLOW_BENCH_SUITE").unwrap_or_else(|_| "findings".into()))))?;
        for finding in &findings {
            writeln!(out, "{}", serde_json::to_string(finding)?)?;
        }
    }
    // What the engine actually parsed, not how many roots it was handed.
    let files_scanned = uniflow_frontend::collect_mixed_source_files(paths).map(|f| f.len()).unwrap_or(0);
    Ok(ScanRun { findings, seconds, files_scanned, peak_rss_mb: None })
}

/// Per-scan time budget for [`scan_bounded`]: `UNIFLOW_BENCH_TIMEOUT`
/// seconds, default 900.
pub fn budget() -> std::time::Duration {
    std::time::Duration::from_secs(std::env::var("UNIFLOW_BENCH_TIMEOUT").ok().and_then(|v| v.parse().ok()).unwrap_or(900))
}

/// Per-scan memory budget: `UNIFLOW_BENCH_MAX_RSS_MB`, default 12 GB — above
/// what a developer laptop or CI runner can give one scan.
pub fn memory_budget_mb() -> f64 {
    std::env::var("UNIFLOW_BENCH_MAX_RSS_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(12_000.0)
}

pub enum Bounded {
    Finished(ScanRun),
    TimedOut,
    /// Killed at this resident size.
    OverMemory(f64),
    /// The engine crashed (a panic, typically); the first panic line.
    Crashed(String),
}

/// Resident size of `pid` in MB via `ps` (portable across macOS/Linux).
fn rss_mb(pid: u32) -> Option<f64> {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output().ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().ok().map(|kb| kb / 1024.0)
}

/// [`scan`] in a child process of this binary, killed when it exceeds the
/// time or memory budget: one pathological input (a repo full of vendored
/// minified JS, say) must cost the run a bounded amount of time and
/// memory and be *reported*, not hang it or take the machine down. A
/// finished child also reports its own peak RSS — the memory this one scan
/// needed.
pub fn scan_bounded(root: &Path, paths: &[PathBuf], budget: std::time::Duration) -> Result<Bounded> {
    let out = std::env::temp_dir().join(format!("uniflow-bench-scan-{}-{}.json", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)));
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .arg("scan-paths")
        .arg("--root")
        .arg(root)
        .arg("--out")
        .arg(&out)
        .arg("--")
        .args(paths)
        .stderr(std::fs::File::create(out.with_extension("stderr"))?)
        .spawn()?;
    let started = Instant::now();
    let max_mb = memory_budget_mb();
    let mut last_rss_check = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                let stderr = std::fs::read_to_string(out.with_extension("stderr")).unwrap_or_default();
                let _ = std::fs::remove_file(out.with_extension("stderr"));
                let panic = stderr.lines().find(|l| l.contains("panicked at")).map(|l| {
                    let next = stderr.lines().skip_while(|x| *x != l).nth(1).unwrap_or("");
                    format!("{} — {}", l.trim(), next.trim())
                });
                return Ok(Bounded::Crashed(panic.unwrap_or_else(|| format!("exit {status}"))));
            }
            let _ = std::fs::remove_file(out.with_extension("stderr"));
            let run: ScanRun = serde_json::from_slice(&std::fs::read(&out)?)?;
            let _ = std::fs::remove_file(&out);
            return Ok(Bounded::Finished(run));
        }
        let over_time = started.elapsed() > budget;
        let over_memory = if last_rss_check.elapsed() >= std::time::Duration::from_secs(1) {
            last_rss_check = Instant::now();
            rss_mb(child.id()).filter(|mb| *mb > max_mb)
        } else {
            None
        };
        if over_time || over_memory.is_some() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&out);
            let _ = std::fs::remove_file(out.with_extension("stderr"));
            return Ok(match over_memory {
                Some(mb) => Bounded::OverMemory(mb),
                None => Bounded::TimedOut,
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// CWE equivalence used when a suite labels one CWE and a rule reports a
/// parent/child of it (a path-traversal rule tagging CWE-23 on an OWASP
/// `pathtraver` case labeled CWE-22). Kept deliberately small and listed in
/// ADR-0019 — a generous table would inflate recall by accepting unrelated
/// rules.
pub fn cwe_family(cwe: &str) -> &'static [&'static str] {
    match cwe {
        "CWE-22" | "CWE-23" | "CWE-36" | "CWE-73" => &["CWE-22", "CWE-23", "CWE-36", "CWE-73"],
        "CWE-78" | "CWE-77" | "CWE-88" => &["CWE-78", "CWE-77", "CWE-88"],
        "CWE-79" | "CWE-80" | "CWE-83" | "CWE-87" => &["CWE-79", "CWE-80", "CWE-83", "CWE-87"],
        "CWE-89" | "CWE-564" | "CWE-943" => &["CWE-89", "CWE-564", "CWE-943"],
        "CWE-94" | "CWE-95" | "CWE-1336" => &["CWE-94", "CWE-95", "CWE-1336"],
        "CWE-327" | "CWE-326" => &["CWE-327", "CWE-326"],
        "CWE-328" | "CWE-916" => &["CWE-328", "CWE-916", "CWE-327"],
        "CWE-330" | "CWE-338" => &["CWE-330", "CWE-338"],
        "CWE-614" | "CWE-1004" => &["CWE-614", "CWE-1004"],
        "CWE-601" => &["CWE-601"],
        "CWE-611" | "CWE-776" => &["CWE-611", "CWE-776"],
        "CWE-918" => &["CWE-918"],
        "CWE-502" => &["CWE-502"],
        _ => &[],
    }
}

pub fn cwe_matches(labeled: &str, finding_cwes: &BTreeSet<String>) -> bool {
    finding_cwes.contains(labeled) || cwe_family(labeled).iter().any(|c| finding_cwes.contains(*c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sink_locations_and_cwes() {
        assert_eq!(parse_location("@/a/b/X.java:12:5"), ("/a/b/X.java".to_string(), Some(12)));
        assert_eq!(parse_location("@analysis"), ("analysis".to_string(), None));
        assert_eq!(normalize_cwe("CWE-089").as_deref(), Some("CWE-89"));
        assert_eq!(normalize_cwe("CWE ID 22").as_deref(), None, "free text is not a CWE id");
        assert_eq!(normalize_cwe("79").as_deref(), Some("CWE-79"));
    }

    #[test]
    fn cwe_families_accept_children_but_not_strangers() {
        let found: BTreeSet<String> = ["CWE-23".to_string()].into();
        assert!(cwe_matches("CWE-22", &found));
        assert!(!cwe_matches("CWE-89", &found));
    }
}
