//! OWASP Benchmark (Java 1.2, Python 0.1): one synthetic test case per
//! file, each labeled "real vulnerability true/false" for one category and
//! CWE in `expectedresults-*.csv`. Scoring follows the official scorecard:
//! a test case counts as *flagged* when the tool reports a finding of the
//! case's CWE (family, see `sast::cwe_family`) anywhere in that test's
//! file; per category, score = TPR − FPR; the Benchmark score is the mean
//! over categories.
use super::{Outcome, SuiteResult, Tally};
use crate::corpus::{self, Lock};
use crate::metrics::Row;
use crate::sast;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct Flavor {
    pub id: &'static str,
    pub language: &'static str,
    pub repo: &'static str,
    pub commit: &'static str,
    pub expected: &'static str,
    /// Directories (relative to the corpus root) handed to the scanner:
    /// the test cases plus the helper classes their data flows through.
    pub scan_dirs: &'static [&'static str],
    pub test_dir: &'static str,
    pub extension: &'static str,
}

pub const JAVA: Flavor = Flavor {
    id: "owasp-benchmark-java",
    language: "java",
    repo: "OWASP-Benchmark/BenchmarkJava",
    commit: "20cbf3d11123347e47ed89541e6942836def53f7",
    expected: "expectedresults-1.2.csv",
    scan_dirs: &["src/main/java"],
    test_dir: "src/main/java/org/owasp/benchmark/testcode",
    extension: "java",
};

pub const PYTHON: Flavor = Flavor {
    id: "owasp-benchmark-python",
    language: "python",
    repo: "OWASP-Benchmark/BenchmarkPython",
    commit: "f1291485808b66e20ddb6b01b10dc71b3df8c8ba",
    expected: "expectedresults-0.1.csv",
    scan_dirs: &["testcode", "helpers", "app.py"],
    test_dir: "testcode",
    extension: "py",
};

struct Case {
    name: String,
    category: String,
    vulnerable: bool,
    cwe: String,
}

fn load_expected(path: &Path) -> Result<Vec<Case>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut cases = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(str::trim).collect();
        if cols.len() < 4 {
            continue;
        }
        cases.push(Case {
            name: cols[0].to_string(),
            category: cols[1].to_string(),
            vulnerable: cols[2].eq_ignore_ascii_case("true"),
            cwe: sast::normalize_cwe(cols[3]).unwrap_or_else(|| cols[3].to_string()),
        });
    }
    Ok(cases)
}

pub fn run(flavor: &Flavor, lock: &mut Lock, update_lock: bool, sample_every: Option<usize>) -> Result<SuiteResult> {
    let url = corpus::github_tarball(flavor.repo, flavor.commit);
    let root = corpus::ensure(lock, flavor.id, &url, "tar.gz", "OWASP Benchmark; GPL — scanned, never redistributed", update_lock)?;
    let mut cases = load_expected(&root.join(flavor.expected))?;
    cases.sort_by(|a, b| a.name.cmp(&b.name));
    let mode = match sample_every {
        Some(n) if n > 1 => {
            cases = cases.into_iter().enumerate().filter(|(i, _)| i % n == 0).map(|(_, c)| c).collect();
            format!("sample:every {n}th test case by name")
        }
        _ => "full".to_string(),
    };

    let paths: Vec<PathBuf> = flavor.scan_dirs.iter().map(|d| root.join(d)).filter(|p| p.exists()).collect();
    let run = sast::scan(&root, &paths)?;

    // test name -> CWEs reported anywhere in its file.
    let mut reported: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for finding in &run.findings {
        if let Some(name) = Path::new(&finding.file).file_stem().and_then(|s| s.to_str()) {
            if finding.file.starts_with(flavor.test_dir) && finding.file.ends_with(flavor.extension) {
                reported.entry(name.to_string()).or_default().extend(finding.cwes.iter().cloned());
            }
        }
    }

    let mut files_with_findings: BTreeSet<String> = BTreeSet::new();
    for finding in &run.findings {
        if let Some(name) = Path::new(&finding.file).file_stem().and_then(|s| s.to_str()) {
            files_with_findings.insert(name.to_string());
        }
    }
    let mut tally = Tally::default();
    let mut agnostic = Tally::default();
    for case in &cases {
        let any = files_with_findings.contains(&case.name);
        agnostic.record("all", outcome_for(case.vulnerable, any), &case.name);
        let flagged = reported.get(&case.name).is_some_and(|cwes| sast::cwe_matches(&case.cwe, cwes));
        let outcome = match (case.vulnerable, flagged) {
            (true, true) => Outcome::Tp,
            (true, false) => Outcome::Fn,
            (false, true) => Outcome::Fp,
            (false, false) => Outcome::Tn,
        };
        tally.record(&format!("{} ({})", case.category, case.cwe), outcome, &case.name);
    }
    let by_category = tally.rows();
    let scores: Vec<f64> = by_category.iter().filter_map(|r| r.youden).collect();
    let benchmark_score = (!scores.is_empty()).then(|| scores.iter().sum::<f64>() / scores.len() as f64);
    let findings_without_cwe = run.findings.iter().filter(|f| f.cwes.is_empty()).count();

    Ok(SuiteResult {
        suite: flavor.id.to_string(),
        language: flavor.language.to_string(),
        mode,
        matching: "test case flagged = any finding of the case's CWE family in the test's file (official scorecard rule)".into(),
        cases: cases.len() as u64,
        overall: Row::new("all", tally.overall()),
        by_category,
        benchmark_score,
        cwe_agnostic: Some(Row::new("any finding in the test's file", agnostic.overall())),
        scan_seconds: run.seconds,
        files_scanned: run.files_scanned,
        findings_total: run.findings.len(),
        peak_rss_mb: None,
        examples: tally.examples,
        notes: vec![format!("{findings_without_cwe} of {} findings carry no CWE and cannot match any case", run.findings.len())],
    })
}

pub(crate) fn outcome_for(vulnerable: bool, flagged: bool) -> Outcome {
    match (vulnerable, flagged) {
        (true, true) => Outcome::Tp,
        (true, false) => Outcome::Fn,
        (false, true) => Outcome::Fp,
        (false, false) => Outcome::Tn,
    }
}
