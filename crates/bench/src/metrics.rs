//! Confusion-matrix arithmetic shared by every suite.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Counts {
    pub tp: u64,
    pub fp: u64,
    #[serde(rename = "fn")]
    pub fn_: u64,
    pub tn: u64,
}

impl Counts {
    pub fn add(&mut self, other: Counts) {
        self.tp += other.tp;
        self.fp += other.fp;
        self.fn_ += other.fn_;
        self.tn += other.tn;
    }

    fn ratio(num: u64, den: u64) -> Option<f64> {
        (den > 0).then(|| num as f64 / den as f64)
    }

    pub fn precision(&self) -> Option<f64> {
        Self::ratio(self.tp, self.tp + self.fp)
    }

    /// Recall = true-positive rate.
    pub fn recall(&self) -> Option<f64> {
        Self::ratio(self.tp, self.tp + self.fn_)
    }

    /// False-positive rate over *negative cases* (needs TN; suites that only
    /// label positives report `None`).
    pub fn fpr(&self) -> Option<f64> {
        Self::ratio(self.fp, self.fp + self.tn)
    }

    pub fn f_beta(&self, beta: f64) -> Option<f64> {
        let (p, r) = (self.precision()?, self.recall()?);
        let b2 = beta * beta;
        let den = b2 * p + r;
        Some(if den == 0.0 { 0.0 } else { (1.0 + b2) * p * r / den })
    }

    /// OWASP Benchmark's score: TPR − FPR (Youden's J), in [-1, 1]; 0 is
    /// what random guessing earns.
    pub fn youden(&self) -> Option<f64> {
        Some(self.recall()? - self.fpr()?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    /// e.g. a CWE id, an OWASP category, a language.
    pub key: String,
    pub counts: Counts,
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    pub fpr: Option<f64>,
    pub f1: Option<f64>,
    pub youden: Option<f64>,
}

impl Row {
    pub fn new(key: impl Into<String>, counts: Counts) -> Self {
        Self {
            key: key.into(),
            counts,
            precision: counts.precision(),
            recall: counts.recall(),
            fpr: counts.fpr(),
            f1: counts.f_beta(1.0),
            youden: counts.youden(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_on_a_known_matrix() {
        let c = Counts { tp: 8, fp: 2, fn_: 2, tn: 8 };
        assert_eq!(c.precision(), Some(0.8));
        assert_eq!(c.recall(), Some(0.8));
        assert!((c.youden().unwrap() - 0.6).abs() < 1e-9);
        assert!((c.f_beta(1.0).unwrap() - 0.8).abs() < 1e-9);
        assert_eq!(Counts::default().recall(), None);
    }
}
