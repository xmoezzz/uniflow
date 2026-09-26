//! Go has no OWASP-Benchmark-style suite, so this uses gosec's own labeled
//! rule samples (`testutils/g*_samples.go`, Apache-2.0): each sample is a
//! small Go program plus the number of issues gosec's rule must report in
//! it — `> 0` is a vulnerable case, `0` a safe look-alike. That makes them a
//! per-rule positive/negative suite. A sample is *flagged* when uniflow
//! reports any finding of the rule's CWE in the sample's files.
//!
//! Limits (ADR-0019): the samples were written to exercise gosec's rules,
//! so they are biased toward the syntactic shapes gosec detects, and most
//! are single-function `main` programs — they measure rule coverage, not
//! inter-procedural depth.
use super::{Outcome, SuiteResult, Tally};
use crate::corpus::{self, Lock};
use crate::metrics::Row;
use crate::sast;
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

const REPO: &str = "securego/gosec";
const COMMIT: &str = "8c77519419e934a3e158dbf1a3fbbc0871b8c691";

/// Security rules with a clear weakness class, and the CWE we label them
/// with. gosec's own table maps G107 (HTTP request to a variable URL) to
/// CWE-88; the weakness it detects is SSRF, CWE-918, which is what a
/// taint engine reports — the one deliberate relabel.
const RULES: &[(&str, &str)] = &[
    ("g101", "CWE-798"),
    ("g107", "CWE-918"),
    ("g201", "CWE-89"),
    ("g202", "CWE-89"),
    ("g203", "CWE-79"),
    ("g204", "CWE-78"),
    ("g304", "CWE-22"),
    ("g305", "CWE-22"),
    ("g401", "CWE-328"),
    ("g402", "CWE-295"),
    ("g404", "CWE-338"),
    ("g405", "CWE-327"),
    ("g501", "CWE-327"),
    ("g502", "CWE-327"),
    ("g505", "CWE-327"),
    ("g701", "CWE-89"),
    ("g702", "CWE-78"),
    ("g703", "CWE-22"),
    ("g704", "CWE-918"),
    ("g705", "CWE-79"),
    ("g706", "CWE-117"),
    ("g707", "CWE-93"),
    ("g708", "CWE-94"),
    ("g709", "CWE-502"),
    ("g710", "CWE-601"),
];

/// Extracts `(sources, expected_issue_count)` from a gosec samples file.
/// Two entry shapes exist upstream: positional
/// `{[]string{`src1`, `src2`}, N, gosec.NewConfig()}` and named
/// `{Code: []string{`src`}, Errors: N, Config: …}`.
fn parse_samples(text: &str) -> Vec<(Vec<String>, u32)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("[]string{") {
        rest = &rest[at + "[]string{".len()..];
        let mut sources = Vec::new();
        // Raw string literals (a Go raw string cannot contain a backtick),
        // separated by commas/whitespace, until the list's closing brace.
        loop {
            rest = rest.trim_start_matches([',', ' ', '\t', '\n', '\r']);
            if let Some(body) = rest.strip_prefix('`') {
                let Some(close) = body.find('`') else { return out };
                sources.push(body[..close].to_string());
                rest = &body[close + 1..];
            } else {
                break;
            }
        }
        let Some(after) = rest.strip_prefix('}') else { continue };
        rest = after;
        let after_list = rest.trim_start_matches([',', ' ', '\t', '\n', '\r']);
        let after_list = after_list.strip_prefix("Errors:").map(|r| r.trim_start()).unwrap_or(after_list);
        let count: String = after_list.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let (false, Ok(n)) = (sources.is_empty(), count.parse::<u32>()) {
            out.push((sources, n));
        }
    }
    out
}

pub fn run(lock: &mut Lock, update_lock: bool) -> Result<SuiteResult> {
    let root = corpus::ensure(lock, "gosec-samples", &corpus::github_tarball(REPO, COMMIT), "tar.gz", "gosec rule samples (Apache-2.0)", update_lock)?;
    let work = corpus::cache_dir()?.join("work").join("gosec");
    if work.exists() {
        std::fs::remove_dir_all(&work)?;
    }
    let mut tally = Tally::default();
    let mut agnostic = Tally::default();
    let (mut seconds, mut files_scanned, mut findings_total, mut cases) = (0.0, 0usize, 0usize, 0u64);
    for (rule, cwe) in RULES {
        let path = root.join("testutils").join(format!("{rule}_samples.go"));
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let samples = parse_samples(&text);
        let rule_dir = work.join(rule);
        for (i, (sources, _)) in samples.iter().enumerate() {
            let dir = rule_dir.join(format!("{i:03}"));
            std::fs::create_dir_all(&dir)?;
            for (k, src) in sources.iter().enumerate() {
                std::fs::write(dir.join(format!("sample_{k}.go")), src)?;
            }
        }
        eprintln!("  gosec {rule}: {} samples", samples.len());
        let run = sast::scan(&work, &[rule_dir.clone()])?;
        seconds += run.seconds;
        files_scanned += run.files_scanned;
        findings_total += run.findings.len();
        let mut reported: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for finding in &run.findings {
            // `<rule>/<NNN>/sample_k.go`
            if let Some(sample) = finding.file.split('/').nth(1) {
                reported.entry(sample.to_string()).or_default().extend(finding.cwes.iter().cloned());
            }
        }
        for (i, (_, expected)) in samples.iter().enumerate() {
            let id = format!("{i:03}");
            agnostic.record("all", super::owasp::outcome_for(*expected > 0, reported.contains_key(&id)), &id);
            let flagged = reported.get(&id).is_some_and(|cwes| sast::cwe_matches(cwe, cwes));
            let outcome = match (*expected > 0, flagged) {
                (true, true) => Outcome::Tp,
                (true, false) => Outcome::Fn,
                (false, true) => Outcome::Fp,
                (false, false) => Outcome::Tn,
            };
            tally.record(&format!("{} ({cwe})", rule.to_uppercase()), outcome, &format!("{}#{id}", rule.to_uppercase()));
            cases += 1;
        }
    }
    Ok(SuiteResult {
        suite: "gosec-samples".into(),
        language: "go".into(),
        mode: "full".into(),
        matching: "sample flagged = any finding of the rule's CWE family in the sample's files; gosec's expected issue count > 0 = vulnerable".into(),
        cases,
        overall: Row::new("all", tally.overall()),
        by_category: tally.rows(),
        benchmark_score: None,
        cwe_agnostic: Some(Row::new("any finding in the sample", agnostic.overall())),
        scan_seconds: seconds,
        files_scanned,
        findings_total,
        peak_rss_mb: None,
        examples: tally.examples,
        notes: vec!["samples were written for gosec's rules: they measure rule coverage, not inter-procedural depth".into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gosec_sample_entries() {
        let text = "var S = []CodeSample{\n\t{[]string{`\npackage main\nfunc main(){}\n`}, 1, gosec.NewConfig()},\n\t{[]string{`a`, `b`}, 0, gosec.NewConfig()},\n}";
        let samples = parse_samples(text);
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].1, 1);
        assert!(samples[0].0[0].contains("package main"));
        assert_eq!(samples[1].0, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(samples[1].1, 0);
        let named = "var S = []CodeSample{\n\t{\n\t\tCode: []string{`\npackage main\n`},\n\t\tErrors: 2,\n\t\tConfig: gosec.NewConfig(),\n\t},\n}";
        assert_eq!(parse_samples(named), vec![(vec!["\npackage main\n".to_string()], 2)]);
    }
}
