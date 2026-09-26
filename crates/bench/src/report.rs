//! Renders every `bench-out/*.json` into one Markdown report: a headline
//! table, per-suite category tables sorted worst-first, example ids for the
//! weakest categories, and the SCA comparison.
use crate::metrics::Row;
use crate::sca::ScaResult;
use crate::suites::SuiteResult;
use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::path::Path;

fn pct(v: Option<f64>) -> String {
    v.map(|x| format!("{:.1}%", x * 100.0)).unwrap_or_else(|| "–".into())
}

fn num(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.3}")).unwrap_or_else(|| "–".into())
}

fn row_line(r: &Row) -> String {
    format!(
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
        r.key, r.counts.tp, r.counts.fp, r.counts.fn_, r.counts.tn, pct(r.precision), pct(r.recall), pct(r.fpr), num(r.youden)
    )
}

pub fn write(input: &Path, markdown: &Path) -> Result<()> {
    let mut sast: Vec<SuiteResult> = Vec::new();
    let mut sca: Option<ScaResult> = None;
    let mut entries: Vec<_> = std::fs::read_dir(input).with_context(|| format!("reading {}", input.display()))?.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let bytes = std::fs::read(&path)?;
        if name.starts_with("sast-") && name.ends_with(".json") {
            sast.push(serde_json::from_slice(&bytes).with_context(|| format!("parsing {name}"))?);
        } else if name == "sca-comparison.json" {
            sca = Some(serde_json::from_slice(&bytes)?);
        }
    }

    let mut md = String::new();
    writeln!(md, "## SAST — headline\n")?;
    writeln!(md, "| Suite | Language | Mode | Cases | Precision | Recall | FPR | F1 | Score | Recall / FPR ignoring CWE | Scan time | Peak RSS |")?;
    writeln!(md, "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")?;
    for s in &sast {
        // RealVuln's negatives are only its FP traps while its FP count also
        // includes every finding the ground truth doesn't list, so an FPR /
        // Youden's J is meaningless there; its own headline metric is F3.
        let realvuln = s.suite.starts_with("realvuln");
        let score = if realvuln {
            s.overall.counts.f_beta(3.0).map(|v| format!("{:.1} (F3)", v * 100.0)).unwrap_or_else(|| "–".into())
        } else {
            s.benchmark_score.map(|v| format!("{:.1} (Benchmark)", v * 100.0)).unwrap_or_else(|| num(s.overall.youden))
        };
        let fpr = if realvuln { "–".to_string() } else { pct(s.overall.fpr) };
        let agnostic = s.cwe_agnostic.as_ref().map(|r| if realvuln { format!("{} / –", pct(r.recall)) } else { format!("{} / {}", pct(r.recall), pct(r.fpr)) });
        writeln!(
            md,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.0}s | {} |",
            s.suite,
            s.language,
            s.mode,
            s.cases,
            pct(s.overall.precision),
            pct(s.overall.recall),
            fpr,
            num(s.overall.f1),
            score,
            agnostic.unwrap_or_else(|| "–".into()),
            s.scan_seconds,
            s.peak_rss_mb.map(|m| format!("{m:.0} MB")).unwrap_or_else(|| "–".into())
        )?;
    }
    writeln!(md, "\n\"Ignoring CWE\" is a diagnostic, not a score: the same matching with the CWE requirement dropped. A large gap to Recall means the engine found the flow but labeled it with a missing or wrong CWE.")?;
    writeln!(md, "\nScore column: OWASP Benchmark score (mean per-category TPR−FPR ×100) where defined, RealVuln: F3×100 (its upstream headline metric); else overall TPR−FPR (Youden's J).\n")?;

    for s in &sast {
        writeln!(md, "### {} ({})\n", s.suite, s.language)?;
        writeln!(md, "Matching: {}.\n", s.matching)?;
        writeln!(md, "| Category | TP | FP | FN | TN | Precision | Recall | FPR | TPR−FPR |")?;
        writeln!(md, "|---|---:|---:|---:|---:|---:|---:|---:|---:|")?;
        let mut rows = s.by_category.clone();
        // Worst first: most missed positives, then most false alarms.
        rows.sort_by(|a, b| (b.counts.fn_, b.counts.fp).cmp(&(a.counts.fn_, a.counts.fp)));
        for r in &rows {
            writeln!(md, "{}", row_line(r))?;
        }
        writeln!(md, "{}", row_line(&s.overall).replacen("| all |", "| **all** |", 1))?;
        let worst: Vec<&Row> = rows.iter().filter(|r| r.counts.fn_ + r.counts.fp > 0).take(6).collect();
        if !worst.is_empty() {
            writeln!(md, "\nExample cases (weakest categories):\n")?;
            for r in worst {
                if let Some(e) = s.examples.get(&r.key) {
                    if !e.false_negatives.is_empty() {
                        writeln!(md, "- {} missed: {}", r.key, e.false_negatives.join(", "))?;
                    }
                    if !e.false_positives.is_empty() {
                        writeln!(md, "- {} false alarms: {}", r.key, e.false_positives.join(", "))?;
                    }
                }
            }
        }
        for note in &s.notes {
            writeln!(md, "\n> {note}")?;
        }
        writeln!(md, "\nFiles scanned: {} · findings: {}\n", s.files_scanned, s.findings_total)?;
    }

    if let Some(sca) = &sca {
        writeln!(md, "## SCA — comparison with other scanners\n")?;
        writeln!(md, "Cosmos snapshot: {} advisory rows. Unit: one (package, vulnerability) pair, alias-aware.\n", sca.snapshot_records)?;
        writeln!(md, "| Tool | Both | Cosmos only | Other only | Cosmos covers other's findings | other-only: data absent | other-only: data present, unmatched |")?;
        writeln!(md, "|---|---:|---:|---:|---:|---:|---:|")?;
        for (tool, c) in &sca.totals {
            writeln!(
                md,
                "| {tool} | {} | {} | {} | {} | {} | {} |",
                c.both,
                c.cosmos_only,
                c.other_only,
                pct(c.agreement_with_other),
                c.triage.get("data-absent").copied().unwrap_or(0),
                c.triage.get("data-present-unmatched").copied().unwrap_or(0)
            )?;
        }
        writeln!(md, "\n| Input | Cosmos findings | Distro | trivy (both/C-only/T-only) | grype (both/C-only/G-only) | osv-scanner (both/C-only/O-only) |")?;
        writeln!(md, "|---|---:|---|---|---|---|")?;
        for i in &sca.inputs {
            let cell = |tool: &str| match i.tools.get(tool).and_then(|c| c.as_ref()) {
                Some(c) => format!("{}/{}/{}", c.both, c.cosmos_only, c.other_only),
                None => "–".into(),
            };
            writeln!(md, "| {} | {} | {} | {} | {} | {} |", i.input, i.cosmos_findings, i.distro.clone().unwrap_or_default(), cell("trivy"), cell("grype"), cell("osv-scanner"))?;
        }
        for note in &sca.notes {
            writeln!(md, "\n> {note}")?;
        }
    }
    std::fs::write(markdown, md).with_context(|| format!("writing {}", markdown.display()))?;
    Ok(())
}
