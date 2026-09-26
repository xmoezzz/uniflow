//! One module per labeled SAST suite. Each turns (corpus, scan findings)
//! into a [`SuiteResult`] using that suite's *own* published scoring rules,
//! so our numbers are comparable with what other tools report on it.
pub mod gosec;
pub mod juliet;
pub mod owasp;
pub mod realvuln;

use crate::metrics::{Counts, Row};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteResult {
    pub suite: String,
    pub language: String,
    /// `full`, or `sample:<description>` for a deterministic subset.
    pub mode: String,
    /// How a finding is matched to ground truth, in one line.
    pub matching: String,
    pub cases: u64,
    pub overall: Row,
    pub by_category: Vec<Row>,
    /// OWASP Benchmark only: the official score (mean over categories of
    /// TPR − FPR).
    pub benchmark_score: Option<f64>,
    /// Diagnostic, not a score: the same matching with the CWE requirement
    /// dropped (a finding of *any* rule at the right place counts). The gap
    /// between this and `overall` is detection the engine did but labeled
    /// with a missing or wrong CWE.
    #[serde(default)]
    pub cwe_agnostic: Option<Row>,
    pub scan_seconds: f64,
    pub files_scanned: usize,
    pub findings_total: usize,
    pub peak_rss_mb: Option<f64>,
    /// Up to a few case ids per bucket, per category — the evidence the
    /// weakness analysis cites.
    pub examples: BTreeMap<String, Examples>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Examples {
    pub false_negatives: Vec<String>,
    pub false_positives: Vec<String>,
}

pub const EXAMPLES_PER_BUCKET: usize = 5;

/// Per-category counts plus example ids, accumulated case by case.
#[derive(Default)]
pub struct Tally {
    pub by_category: BTreeMap<String, Counts>,
    pub examples: BTreeMap<String, Examples>,
}

impl Tally {
    pub fn record(&mut self, category: &str, outcome: Outcome, case_id: &str) {
        let counts = self.by_category.entry(category.to_string()).or_default();
        let examples = self.examples.entry(category.to_string()).or_default();
        match outcome {
            Outcome::Tp => counts.tp += 1,
            Outcome::Tn => counts.tn += 1,
            Outcome::Fp => {
                counts.fp += 1;
                if examples.false_positives.len() < EXAMPLES_PER_BUCKET {
                    examples.false_positives.push(case_id.to_string());
                }
            }
            Outcome::Fn => {
                counts.fn_ += 1;
                if examples.false_negatives.len() < EXAMPLES_PER_BUCKET {
                    examples.false_negatives.push(case_id.to_string());
                }
            }
        }
    }

    pub fn overall(&self) -> Counts {
        let mut total = Counts::default();
        for counts in self.by_category.values() {
            total.add(*counts);
        }
        total
    }

    pub fn rows(&self) -> Vec<Row> {
        self.by_category.iter().map(|(k, c)| Row::new(k.clone(), *c)).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    Tp,
    Fp,
    Fn,
    Tn,
}
