//! NIST SARD Juliet C/C++ 1.3. `C/manifest.xml` lists every test case's
//! files and exact flaw lines. Each test case contributes one positive and
//! one negative, the usual SAMATE-style accounting:
//! - positive: TP when some finding of the case's CWE (family, below) lies
//!   within ±`LINE_TOLERANCE` lines of a manifest flaw line, else FN;
//! - negative: FP when some finding of the case's CWE lies inside a
//!   `good*` function of the case's files, else TN.
//! Findings of *other* CWEs are ignored — Juliet is a per-CWE suite, and a
//! stray memory warning in an injection case is neither a hit nor a
//! false alarm for that case.
use super::{Outcome, SuiteResult, Tally};
use crate::corpus::{self, Lock};
use crate::metrics::Row;
use crate::sast::{self, Finding};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

pub const ID: &str = "juliet-c-cpp-1.3";
const URL: &str = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip";
const LINE_TOLERANCE: u32 = 5;

struct TestCase {
    /// Juliet case id: the first file's stem without a split suffix.
    id: String,
    cwe: String,
    files: Vec<String>,
    flaws: Vec<(String, u32)>,
}

fn parse_manifest(text: &str) -> Vec<TestCase> {
    let attr = |line: &str, name: &str| -> Option<String> {
        let key = format!("{name}=\"");
        let start = line.find(&key)? + key.len();
        Some(line[start..].split('"').next()?.to_string())
    };
    let mut cases = Vec::new();
    let mut current: Option<TestCase> = None;
    let mut file: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("<testcase") {
            current = Some(TestCase { id: String::new(), cwe: String::new(), files: Vec::new(), flaws: Vec::new() });
        } else if line.starts_with("</testcase") {
            if let Some(case) = current.take() {
                if !case.files.is_empty() && !case.cwe.is_empty() {
                    cases.push(case);
                }
            }
        } else if line.starts_with("<file") {
            if let (Some(case), Some(path)) = (current.as_mut(), attr(line, "path")) {
                if case.id.is_empty() {
                    let stem = Path::new(&path).file_stem().and_then(|s| s.to_str()).unwrap_or(&path).to_string();
                    // Multi-file cases are `..._51a.c`, `..._51b.c`: the id drops the letter.
                    case.id = stem.trim_end_matches(|c: char| c.is_ascii_lowercase() && c != '_').to_string();
                    if case.id.ends_with('_') || case.id.is_empty() {
                        case.id = stem;
                    }
                }
                case.files.push(path.clone());
                file = Some(path);
            }
        } else if line.starts_with("<flaw") {
            if let (Some(case), Some(path), Some(line_no), Some(name)) =
                (current.as_mut(), file.as_ref(), attr(line, "line").and_then(|l| l.parse().ok()), attr(line, "name"))
            {
                if case.cwe.is_empty() {
                    case.cwe = sast::normalize_cwe(&name).unwrap_or_default();
                }
                case.flaws.push((path.clone(), line_no));
            }
        }
    }
    cases
}

/// Juliet's flaw CWEs are specific children; rules usually report the
/// class (a CWE-121 stack overflow as CWE-787/CWE-119). One family per
/// Juliet weakness group, listed in ADR-0019.
fn family(cwe: &str) -> &'static [&'static str] {
    match cwe {
        "CWE-121" | "CWE-122" | "CWE-124" | "CWE-126" | "CWE-127" | "CWE-119" | "CWE-120" | "CWE-787" | "CWE-125" | "CWE-805" | "CWE-806" => {
            &["CWE-121", "CWE-122", "CWE-124", "CWE-126", "CWE-127", "CWE-119", "CWE-120", "CWE-787", "CWE-125", "CWE-805", "CWE-806"]
        }
        "CWE-190" | "CWE-191" | "CWE-680" => &["CWE-190", "CWE-191", "CWE-680"],
        "CWE-401" | "CWE-772" => &["CWE-401", "CWE-772"],
        "CWE-476" | "CWE-690" => &["CWE-476", "CWE-690"],
        "CWE-416" | "CWE-825" => &["CWE-416", "CWE-825"],
        "CWE-415" => &["CWE-415"],
        "CWE-134" => &["CWE-134"],
        _ => &[],
    }
}

fn matches_cwe(cwe: &str, found: &BTreeSet<String>) -> bool {
    sast::cwe_matches(cwe, found) || family(cwe).iter().any(|c| found.contains(*c))
}

/// Line spans of functions whose name contains `good` — a brace-matching
/// scan over Juliet's regular formatting (function header on one line,
/// `{` on the same or next line), skipping string/char literals and
/// comments so braces inside them don't unbalance the count.
fn good_function_spans(source: &str) -> Vec<(u32, u32)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let header = !line.trim_end().ends_with(';') && line.contains('(') && !line.trim_start().starts_with("//") && !line.trim_start().starts_with('*');
        let name = header.then(|| line.split('(').next().unwrap_or("").split_whitespace().last().unwrap_or("").trim_start_matches(['*', '&'])).unwrap_or("");
        let opens_here = line.contains('{') || lines.get(i + 1).is_some_and(|l| l.trim_start().starts_with('{'));
        // C++ cases implement good paths as `goodG2B::action()` methods, so
        // the whole qualified name counts, not just its last segment.
        if name.to_ascii_lowercase().contains("good") && opens_here {
            let start = i as u32 + 1;
            let mut depth = 0i32;
            let mut seen_open = false;
            let mut j = i;
            'scan: while j < lines.len() {
                let mut chars = lines[j].chars().peekable();
                let mut in_str: Option<char> = None;
                while let Some(c) = chars.next() {
                    match (in_str, c) {
                        (Some(q), '\\') if q != '/' => {
                            chars.next();
                        }
                        (Some(q), c) if c == q => in_str = None,
                        (Some(_), _) => {}
                        (None, '"') | (None, '\'') => in_str = Some(c),
                        (None, '/') if chars.peek() == Some(&'/') => break,
                        (None, '{') => {
                            depth += 1;
                            seen_open = true;
                        }
                        (None, '}') => {
                            depth -= 1;
                            if seen_open && depth == 0 {
                                spans.push((start, j as u32 + 1));
                                break 'scan;
                            }
                        }
                        _ => {}
                    }
                }
                j += 1;
            }
            i = j.max(i) + 1;
            continue;
        }
        i += 1;
    }
    spans
}

pub fn run(lock: &mut Lock, update_lock: bool, per_cwe: Option<usize>) -> Result<SuiteResult> {
    let root = corpus::ensure(lock, ID, URL, "zip", "NIST SARD Juliet C/C++ 1.3 (public domain, US Government work)", update_lock)?.join("C");
    let manifest = std::fs::read_to_string(root.join("manifest.xml")).context("reading C/manifest.xml")?;
    let mut cases = parse_manifest(&manifest);
    cases.sort_by(|a, b| a.id.cmp(&b.id));

    // File name -> on-disk path (names are unique across the suite).
    let mut locations: HashMap<String, PathBuf> = HashMap::new();
    let mut stack = vec![root.join("testcases")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                locations.insert(name.to_string(), path);
            }
        }
    }

    let mode = match per_cwe {
        Some(k) => {
            let mut per: BTreeMap<String, usize> = BTreeMap::new();
            cases.retain(|case| {
                let n = per.entry(case.cwe.clone()).or_default();
                *n += 1;
                *n <= k
            });
            format!("sample:first {k} test cases per CWE by id")
        }
        None => "full".to_string(),
    };

    // One scan per CWE batch: rules load once per batch, and a batch stays
    // small enough to keep memory flat.
    let mut by_cwe: BTreeMap<String, Vec<&TestCase>> = BTreeMap::new();
    for case in &cases {
        by_cwe.entry(case.cwe.clone()).or_default().push(case);
    }
    let support = root.join("testcasesupport");
    let mut tally = Tally::default();
    let mut agnostic = Tally::default();
    let (mut seconds, mut files_scanned, mut findings_total) = (0.0, 0usize, 0usize);
    let mut skipped_missing = 0usize;
    let mut timeouts: Vec<String> = Vec::new();
    let mut peak_rss: f64 = 0.0;
    for (cwe, batch) in &by_cwe {
        let mut paths: Vec<PathBuf> = batch.iter().flat_map(|c| c.files.iter()).filter_map(|f| locations.get(f).cloned()).collect();
        if paths.is_empty() {
            skipped_missing += batch.len();
            continue;
        }
        // The per-case support code only — `main.cpp`/`testcases.h` there
        // reference all ~64k test cases and would turn every batch into a
        // scan of the whole suite's call surface.
        for file in ["io.c", "std_thread.c", "std_testcase.h", "std_testcase_io.h", "std_thread.h"] {
            paths.push(support.join(file));
        }
        eprintln!("  juliet {cwe}: {} cases, {} files", batch.len(), paths.len() - 1);
        let run = match sast::scan_bounded(&root, &paths, sast::budget())? {
            sast::Bounded::Finished(run) => run,
            other => {
                timeouts.push(match other {
                    sast::Bounded::OverMemory(mb) => format!("{cwe} (memory, killed at {mb:.0} MB)"),
                    sast::Bounded::Crashed(why) => format!("{cwe} (engine crash: {why})"),
                    _ => format!("{cwe} (time)"),
                });
                sast::ScanRun { findings: Vec::new(), seconds: sast::budget().as_secs_f64(), files_scanned: 0, peak_rss_mb: None }
            }
        };
        peak_rss = peak_rss.max(run.peak_rss_mb.unwrap_or(0.0));
        seconds += run.seconds;
        files_scanned += run.files_scanned;
        findings_total += run.findings.len();
        let mut by_file: HashMap<String, Vec<&Finding>> = HashMap::new();
        for finding in &run.findings {
            let name = Path::new(&finding.file).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            by_file.entry(name).or_default().push(finding);
        }
        for case in batch {
            // `any_cwe`: the CWE-agnostic diagnostic (see SuiteResult).
            let judge = |any_cwe: bool| {
                let relevant = |file: &str| {
                    by_file.get(file).into_iter().flatten().filter(|f| any_cwe || matches_cwe(&case.cwe, &f.cwes)).copied().collect::<Vec<_>>()
                };
                let hit_bad = case.flaws.iter().any(|(file, flaw_line)| {
                    relevant(file).iter().any(|f| f.line.is_some_and(|l| l.abs_diff(*flaw_line) <= LINE_TOLERANCE))
                });
                let hit_good = case.files.iter().any(|file| {
                    let Some(path) = locations.get(file) else { return false };
                    let spans = std::fs::read_to_string(path).map(|s| good_function_spans(&s)).unwrap_or_default();
                    relevant(file).iter().any(|f| f.line.is_some_and(|l| spans.iter().any(|(s, e)| (*s..=*e).contains(&l))))
                });
                (hit_bad, hit_good)
            };
            let (hit_bad, hit_good) = judge(false);
            tally.record(cwe, if hit_bad { Outcome::Tp } else { Outcome::Fn }, &case.id);
            tally.record(cwe, if hit_good { Outcome::Fp } else { Outcome::Tn }, &case.id);
            let (any_bad, any_good) = judge(true);
            agnostic.record("all", if any_bad { Outcome::Tp } else { Outcome::Fn }, &case.id);
            agnostic.record("all", if any_good { Outcome::Fp } else { Outcome::Tn }, &case.id);
        }
    }
    let mut notes = vec!["each test case counts once as a positive (bad flow) and once as a negative (good functions)".to_string()];
    notes.push(format!(
        "scan budget {}s / {:.0} MB per CWE batch; over budget (scored with no findings): {}",
        sast::budget().as_secs(),
        sast::memory_budget_mb(),
        if timeouts.is_empty() { "none".to_string() } else { timeouts.join(", ") }
    ));
    if skipped_missing > 0 {
        notes.push(format!("{skipped_missing} manifest cases had no files on disk and were skipped"));
    }
    Ok(SuiteResult {
        suite: ID.into(),
        language: "c/c++".into(),
        mode,
        matching: format!("bad: finding of the case CWE family within ±{LINE_TOLERANCE} lines of a manifest flaw line; good: such a finding inside a good* function"),
        cases: cases.len() as u64,
        overall: Row::new("all", tally.overall()),
        by_category: tally.rows(),
        benchmark_score: None,
        cwe_agnostic: Some(Row::new("any finding at the flaw / in good functions", agnostic.overall())),
        scan_seconds: seconds,
        files_scanned,
        findings_total,
        peak_rss_mb: Some(peak_rss),
        examples: tally.examples,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_cases_group_split_files_and_keep_flaw_lines() {
        let xml = r#"<container>
  <testcase>
    <file path="CWE78_OS_Command_Injection__char_console_execl_51a.c"/>
    <file path="CWE78_OS_Command_Injection__char_console_execl_51b.c">
      <flaw line="57" name="CWE-78: OS Command Injection"/>
    </file>
  </testcase>
</container>"#;
        let cases = parse_manifest(xml);
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].id, "CWE78_OS_Command_Injection__char_console_execl_51");
        assert_eq!(cases[0].cwe, "CWE-78");
        assert_eq!(cases[0].flaws, vec![("CWE78_OS_Command_Injection__char_console_execl_51b.c".to_string(), 57)]);
    }

    #[test]
    fn good_spans_cover_good_functions_only() {
        let src = "void CWE78_bad()\n{\n  system(x);\n}\n\nstatic void goodG2B()\n{\n  char *s = \"}\";\n  system(\"ls\");\n}\n\nvoid CWE78_good()\n{\n    goodG2B();\n}\n";
        assert_eq!(good_function_spans(src), vec![(6, 10), (12, 15)]);
    }
}
