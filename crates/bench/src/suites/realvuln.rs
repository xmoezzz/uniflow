//! RealVuln 3.x: real, intentionally vulnerable Python and JS/TS web apps
//! (DVNA, NodeGoat, PyGoat, Juice Shop, …) with manually reviewed ground
//! truth, including false-positive *traps* (`is_vulnerable: false`) and
//! `non_scoring` entries. Matching replicates the upstream scorer
//! (`scorer/matcher.py`) exactly: a finding matches a scored entry when the
//! file is equal, its CWE is in `acceptable_cwes`, and its line lies in
//! `[start−10, end+10]` (primary or `acceptable_locations`); each entry is
//! matched at most once, vulnerable entries preferred; a match on a trap
//! is an FP; an unmatched finding that lands on a non-scoring entry's
//! lines is withheld, otherwise it is an FP; unmatched vulnerable entries
//! are FNs and unmatched traps TNs.
//!
//! Upstream scores each finding under one CWE; ours may carry several, so
//! a finding matches when *any* of its CWEs is acceptable.
use super::{Outcome, SuiteResult, Tally};
use crate::corpus::{self, Lock};
use crate::metrics::{Counts, Row};
use crate::sast::{self, Finding};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

const REPO: &str = "kolega-ai/Real-Vuln-Benchmark";
const COMMIT: &str = "7a710251f55c17d32d3adcb13d37468e2e3b9e4a";
const LINE_TOLERANCE: u32 = 10;

#[derive(Deserialize)]
struct GroundTruth {
    repo_id: String,
    repo_url: String,
    commit_sha: String,
    language: String,
    #[serde(default)]
    authorship: String,
    findings: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    is_vulnerable: bool,
    #[serde(default)]
    primary_cwe: String,
    #[serde(default)]
    acceptable_cwes: Vec<String>,
    file: String,
    location: Location,
    #[serde(default)]
    acceptable_locations: Vec<AltLocation>,
    #[serde(default)]
    scoring: Option<String>,
}

#[derive(Deserialize)]
struct Location {
    start_line: Option<u32>,
    end_line: Option<u32>,
}

#[derive(Deserialize)]
struct AltLocation {
    file: String,
    start_line: Option<u32>,
    end_line: Option<u32>,
}

fn within(line: Option<u32>, start: Option<u32>, end: Option<u32>) -> bool {
    match (line, start) {
        (Some(l), Some(s)) => {
            let e = end.unwrap_or(s);
            l + LINE_TOLERANCE >= s && l <= e + LINE_TOLERANCE
        }
        // Upstream: an entry or finding without a line matches on file alone.
        _ => true,
    }
}

fn located(finding: &Finding, entry: &Entry) -> bool {
    (finding.file == entry.file && within(finding.line, entry.location.start_line, entry.location.end_line))
        || entry.acceptable_locations.iter().any(|a| finding.file == a.file && within(finding.line, a.start_line, a.end_line))
}

fn cwe_ok(finding: &Finding, entry: &Entry) -> bool {
    entry.acceptable_cwes.iter().filter_map(|c| sast::normalize_cwe(c)).any(|c| finding.cwes.contains(&c))
}

/// The upstream matching, parameterized by whether the CWE must agree
/// (`false` is the CWE-agnostic diagnostic). Returns the repo's counts
/// and, when recording, feeds `tally`.
fn match_repo(gt: &GroundTruth, findings: &[Finding], require_cwe: bool, mut tally: Option<&mut Tally>, withheld: &mut usize) -> Counts {
    let scored: Vec<&Entry> = gt.findings.iter().filter(|e| e.scoring.as_deref() != Some("non_scoring")).collect();
    let non_scoring: Vec<&Entry> = gt.findings.iter().filter(|e| e.scoring.as_deref() == Some("non_scoring")).collect();
    let mut matched: HashSet<&str> = HashSet::new();
    let mut counts = Counts::default();
    for finding in findings {
        let mut candidates: Vec<&&Entry> =
            scored.iter().filter(|e| !matched.contains(e.id.as_str()) && (!require_cwe || cwe_ok(finding, e)) && located(finding, e)).collect();
        candidates.sort_by_key(|e| !e.is_vulnerable);
        if let Some(best) = candidates.first() {
            matched.insert(best.id.as_str());
            let outcome = if best.is_vulnerable { Outcome::Tp } else { Outcome::Fp };
            if let Some(t) = tally.as_deref_mut() {
                t.record(&best.primary_cwe, outcome, &best.id);
            }
            if best.is_vulnerable { counts.tp += 1 } else { counts.fp += 1 }
        } else if finding.line.is_some() && non_scoring.iter().any(|e| located(finding, e)) {
            *withheld += 1;
        } else {
            if let Some(t) = tally.as_deref_mut() {
                let category = finding.cwes.iter().next().cloned().unwrap_or_else(|| "(no CWE)".into());
                t.record(&category, Outcome::Fp, &format!("{}:{}:{} {}", gt.repo_id, finding.file, finding.line.unwrap_or(0), finding.rule_id));
            }
            counts.fp += 1;
        }
    }
    for entry in &scored {
        if !matched.contains(entry.id.as_str()) {
            let outcome = if entry.is_vulnerable { Outcome::Fn } else { Outcome::Tn };
            if let Some(t) = tally.as_deref_mut() {
                t.record(&entry.primary_cwe, outcome, &entry.id);
            }
            if entry.is_vulnerable { counts.fn_ += 1 } else { counts.tn += 1 }
        }
    }
    counts
}

/// `python` or `js` (JavaScript + TypeScript).
pub fn run(lang: &str, lock: &mut Lock, update_lock: bool, full: bool) -> Result<SuiteResult> {
    let gt_root = corpus::ensure(lock, "realvuln", &corpus::github_tarball(REPO, COMMIT), "tar.gz", "RealVuln ground truth (Apache-2.0)", update_lock)?;
    let mut truths: Vec<GroundTruth> = Vec::new();
    for entry in std::fs::read_dir(gt_root.join("ground-truth"))?.flatten() {
        let path = entry.path().join("ground-truth.json");
        if !path.exists() {
            continue;
        }
        let gt: GroundTruth = serde_json::from_str(&std::fs::read_to_string(&path)?).with_context(|| format!("parsing {}", path.display()))?;
        let lang_ok = match lang {
            "python" => gt.language == "python",
            _ => gt.language == "javascript" || gt.language == "typescript",
        };
        if lang_ok && (full || gt.authorship != "llm_generated") {
            truths.push(gt);
        }
    }
    truths.sort_by(|a, b| a.repo_id.cmp(&b.repo_id));

    let mut tally = Tally::default();
    let mut agnostic = Counts::default();
    let mut per_repo: Vec<Row> = Vec::new();
    let (mut seconds, mut files_scanned, mut findings_total, mut withheld) = (0.0, 0usize, 0usize, 0usize);
    let mut timeouts: Vec<String> = Vec::new();
    let mut peak_rss: f64 = 0.0;
    for gt in &truths {
        let repo = gt.repo_url.trim_start_matches("https://github.com/").trim_end_matches(".git").trim_end_matches('/');
        let root = corpus::ensure(lock, &format!("realvuln-target/{}", gt.repo_id), &corpus::github_tarball(repo, &gt.commit_sha), "tar.gz", "", update_lock)?;
        eprintln!("  realvuln {}", gt.repo_id);
        let run = match sast::scan_bounded(&root, &[PathBuf::from(&root)], sast::budget())? {
            sast::Bounded::Finished(run) => Some(run),
            sast::Bounded::TimedOut => {
                timeouts.push(format!("{} (time)", gt.repo_id));
                None
            }
            sast::Bounded::OverMemory(mb) => {
                timeouts.push(format!("{} (memory, killed at {mb:.0} MB)", gt.repo_id));
                None
            }
            sast::Bounded::Crashed(why) => {
                timeouts.push(format!("{} (engine crash: {why})", gt.repo_id));
                None
            }
        };
        let Some(run) = run else {
            // Counted, not skipped: every vulnerable entry of a repo the
            // engine could not finish is a miss.
            let empty: Vec<Finding> = Vec::new();
            let mut ignored = 0;
            let counts = match_repo(gt, &empty, true, Some(&mut tally), &mut ignored);
            agnostic.add(counts);
            per_repo.push(Row::new(format!("{} (timeout)", gt.repo_id), counts));
            continue;
        };
        peak_rss = peak_rss.max(run.peak_rss_mb.unwrap_or(0.0));
        seconds += run.seconds;
        files_scanned += run.files_scanned;
        findings_total += run.findings.len();

        let repo_counts = match_repo(gt, &run.findings, true, Some(&mut tally), &mut withheld);
        let mut ignored = 0;
        agnostic.add(match_repo(gt, &run.findings, false, None, &mut ignored));
        per_repo.push(Row::new(gt.repo_id.clone(), repo_counts));
    }
    let overall = tally.overall();
    let f3 = overall.f_beta(3.0);
    let mut notes = vec![
        format!("{withheld} findings landed on non-scoring entries and were withheld (upstream rule)"),
        format!(
            "scan budget {}s / {:.0} MB per repo; over budget or crashed (scored as all-miss): {}",
            sast::budget().as_secs(),
            sast::memory_budget_mb(),
            if timeouts.is_empty() { "none".to_string() } else { timeouts.join(", ") }
        ),
        format!("largest single-repo scan peak RSS: {peak_rss:.0} MB"),
        format!("RealVuln's headline metric, F3×100 (recall-weighted 9:1): {}", f3.map(|v| format!("{:.1}", v * 100.0)).unwrap_or_else(|| "n/a".into())),
        "unmatched findings count as FP (upstream rule), so FP here includes true issues the ground truth does not list".into(),
    ];
    notes.push(format!("per repo: {}", per_repo.iter().map(|r| format!("{} tp={} fp={} fn={}", r.key, r.counts.tp, r.counts.fp, r.counts.fn_)).collect::<Vec<_>>().join("; ")));
    let mut examples = tally.examples.clone();
    examples.retain(|_, e| !e.false_negatives.is_empty() || !e.false_positives.is_empty());
    let by_category: BTreeMap<String, Counts> = tally.by_category.clone();
    Ok(SuiteResult {
        suite: format!("realvuln-{lang}"),
        language: if lang == "python" { "python".into() } else { "javascript/typescript".into() },
        mode: if full { "full".into() } else { "sample:community (human-authored and non-LLM) repos only".into() },
        matching: "upstream RealVuln scorer: same file + acceptable CWE + line within ±10 of the entry range; one finding per entry".into(),
        cases: truths.iter().map(|t| t.findings.len() as u64).sum(),
        overall: Row::new("all", overall),
        by_category: by_category.into_iter().map(|(k, c)| Row::new(k, c)).collect(),
        benchmark_score: None,
        cwe_agnostic: Some(Row::new("same matching without the CWE requirement", agnostic)),
        scan_seconds: seconds,
        files_scanned,
        findings_total,
        peak_rss_mb: Some(peak_rss),
        examples,
        notes,
    })
}
