use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub manifest_path: String,
    pub direct: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DependencyFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub vulnerable_range: String,
    pub recommended_version: Option<String>,
    pub manifest_path: String,
    pub cve_ids: Vec<String>,
    pub cwe: Vec<String>,
    pub message: String,
    /// Whether any manifest in the scanned tree declares this package
    /// itself (as opposed to it only arriving as some other package's
    /// dependency). Lockfiles alone can't say — see
    /// `uniflow_sca_orchestrator`'s dependency-graph pass, which sets this.
    #[serde(default)]
    pub direct: bool,
    /// How this package got into the build: root → … → this package
    /// (`name@version` entries), shortest path first, when a lockfile
    /// records the dependency graph. Empty when no graph is available.
    #[serde(default)]
    pub dependency_path: Vec<String>,
    /// Fully-qualified vulnerable functions/symbols from the advisory
    /// (Go `imports[].symbols`, RustSec `affects.functions`, curated
    /// data), in the advisory's own notation — what reachability analysis
    /// looks for in first-party code. Empty = the advisory doesn't say.
    #[serde(default)]
    pub affected_symbols: Vec<String>,
    #[serde(default)]
    pub fixed_versions: Vec<String>,
    /// FIRST EPSS probability (0..1) of exploitation in the next 30 days.
    #[serde(default)]
    pub epss: Option<f32>,
    /// Listed in CISA's Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub kev: bool,
    /// Filled in by `uniflow_sca_reachability` when a source tree is
    /// available; `None` means reachability was never evaluated (e.g. a
    /// container-image OS package), which is different from
    /// [`ReachabilityLevel::Unknown`] ("evaluated, but couldn't tell").
    #[serde(default)]
    pub reachability: Option<Reachability>,
    #[serde(default)]
    pub risk: Option<RiskScore>,
    /// Present only for OS-package findings (dpkg/rpm/apk matched against
    /// a distribution's own advisories) — see [`OsFindingInfo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<OsFindingInfo>,
}

/// One installed OS package as the package manager recorded it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsPackage {
    /// Binary package name (`libssl3`, `openssl-libs`).
    pub name: String,
    /// The installed version in the package manager's own syntax (dpkg
    /// `[epoch:]upstream-revision`, rpm `[epoch:]version-release`, apk
    /// `version-rN`).
    pub version: String,
    /// Source package it was built from (dpkg `Source:`, rpm
    /// `SOURCERPM`, apk origin). Debian, Ubuntu, Alpine, openEuler and
    /// Anolis advisories are keyed by source package.
    #[serde(default)]
    pub source_name: Option<String>,
    /// dpkg records a separate source version when it differs (binNMUs,
    /// `+b1`); advisories keyed by source compare against this.
    #[serde(default)]
    pub source_version: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    /// RHEL/CentOS module stream (`nodejs:18:...`), when the package came
    /// from one — advisories for module packages carry the stream.
    #[serde(default)]
    pub module: Option<String>,
}

/// Where a distro stands on fixing one vulnerability for one package.
/// Mirrors what distro trackers publish (Debian tracker, Ubuntu CVE
/// tracker, Red Hat VEX/OVAL): "not affected" never becomes a finding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixState {
    /// A fixed package exists in the distro's repositories.
    Fixed,
    /// Affected, fix not (yet) released — tracked as open by the distro.
    Unfixed,
    /// The distro decided not to fix it on this release (Red Hat "Will not
    /// fix", Debian `no-dsa`/`ignored`, Ubuntu `deferred`/`ignored`).
    WontFix,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OsFindingInfo {
    /// `debian:12` — the scanned system.
    pub distro: String,
    /// "Debian 12" — for badges.
    pub distro_label: String,
    /// The advisory dataset that produced the match; differs from
    /// `distro` only for binary-compatible rebuilds (CentOS → `rhel:7`).
    pub data_source: String,
    /// Source package, when the distro keys advisories by it.
    #[serde(default)]
    pub source_package: Option<String>,
    /// Installed binary packages this finding covers (all binaries of an
    /// affected source package, or the one binary for binary-keyed data).
    pub binaries: Vec<String>,
    pub installed_version: String,
    pub fix_state: FixState,
    /// DSA/DLA/USN/RHSA/ALSA/RLSA/OESA/ANSA/OCSA/ELSA ids for this finding.
    #[serde(default)]
    pub advisory_ids: Vec<String>,
    /// The distro's own rating (`important`, `medium`, `unimportant`, …)
    /// — often different from NVD's CVSS, and the one ops teams act on.
    #[serde(default)]
    pub distro_severity: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// Reachability verdict for one dependency finding, strongest first.
/// Deliberately a small closed set — the UI filters and the backend's
/// `finding.reachability` column are keyed on exactly these names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReachabilityLevel {
    /// First-party code calls/references a known-vulnerable symbol.
    Reachable,
    /// First-party code imports the package, but either the advisory names
    /// no vulnerable symbols or none of them is referenced.
    Imported,
    /// No first-party source of the package's language imports it.
    Unreachable,
    /// The package's ecosystem/language isn't analyzable here, or there's
    /// no first-party source for it (a binary, an image layer, ...).
    Unknown,
}

impl ReachabilityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Imported => "imported",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A call (or reference) to a vulnerable symbol.
    Call,
    /// An import/require/use of the package's module.
    Import,
    /// A qualified reference to the package's module that isn't a known
    /// vulnerable symbol (e.g. `requests.Session` when only `requests.get`
    /// is affected, or a Rust `crate::path` used without a `use`).
    Reference,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReachabilityEvidence {
    pub kind: EvidenceKind,
    /// Path relative to the scanned root.
    pub path: String,
    pub line: u32,
    /// The fully-qualified name as resolved in first-party code.
    pub symbol: String,
    /// The advisory symbol this evidence matched, when `kind == Call`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Entry point → … → the function containing this call, when the
    /// project's call graph connects them. Empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub call_path: Vec<String>,
    /// Evidence found only under a test directory — still real, but code
    /// that doesn't ship.
    #[serde(default)]
    pub in_test: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reachability {
    pub level: ReachabilityLevel,
    pub confidence: Confidence,
    /// One-sentence human explanation of the verdict (English).
    pub reason: String,
    /// Machine-readable form of `reason` for localized UIs:
    /// `calls_symbol`, `imported_no_symbols`, `imported_symbols_not_called`,
    /// `test_only`, `not_imported`, `unsupported_ecosystem`, `no_source`,
    /// `no_module_mapping` — with its parameters in `reason_params`.
    #[serde(default)]
    pub reason_code: String,
    #[serde(default)]
    pub reason_params: std::collections::BTreeMap<String, String>,
    /// Which analyzer produced this (`python`, `javascript`, …) — `None`
    /// for `Unknown`.
    #[serde(default)]
    pub analyzer: Option<String>,
    #[serde(default)]
    pub evidence: Vec<ReachabilityEvidence>,
}

/// One weighted input to [`RiskScore`], kept so the UI can show *why* a
/// finding scored what it did instead of an opaque number.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub value: String,
    /// Multiplier this factor contributed (0..=1).
    pub weight: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskScore {
    /// 0..=100, higher = fix first.
    pub score: u8,
    pub factors: Vec<RiskFactor>,
}

/// Composite fix-first priority for one dependency finding:
/// `100 × severity × reachability × exploitability × fixability`, every
/// factor in 0..=1. Multiplicative rather than additive on purpose: a
/// critical CVE in a package nothing imports should land well below a
/// high one that's actually called with a public exploit — additive
/// schemes (severity points + bonus points) let severity alone dominate,
/// which is exactly the alert-fatigue problem reachability exists to fix.
/// See ADR-0008 for the weight rationale.
pub fn risk_score(finding: &DependencyFinding) -> RiskScore {
    let mut factors = Vec::new();
    let severity = match finding.severity {
        Severity::Critical => 1.0,
        Severity::High => 0.75,
        Severity::Medium => 0.45,
        Severity::Low => 0.2,
    };
    factors.push(RiskFactor { factor: "severity".into(), value: format!("{:?}", finding.severity).to_lowercase(), weight: severity });

    let (reach_value, reach) = match &finding.reachability {
        Some(r) => match r.level {
            ReachabilityLevel::Reachable => ("reachable", if r.confidence == Confidence::Low { 0.85 } else { 1.0 }),
            // Imported with symbols known-but-not-called is real evidence of
            // "probably not exploitable through this code"; imported with no
            // symbol data at all is merely "can't tell at function level".
            ReachabilityLevel::Imported if finding.affected_symbols.is_empty() => ("imported", 0.7),
            ReachabilityLevel::Imported => ("imported_symbols_not_called", 0.5),
            ReachabilityLevel::Unreachable if finding.direct => ("not_imported", 0.2),
            ReachabilityLevel::Unreachable => ("not_imported_transitive", 0.3),
            ReachabilityLevel::Unknown => ("unknown", 0.6),
        },
        None => ("not_analyzed", 0.6),
    };
    factors.push(RiskFactor { factor: "reachability".into(), value: reach_value.into(), weight: reach });

    let (exploit_value, exploit) = if finding.kev {
        ("kev".to_string(), 1.0)
    } else if let Some(epss) = finding.epss {
        // sqrt spreads the long tail: most EPSS scores sit well below 0.1,
        // where a linear mapping would make them all indistinguishable.
        (format!("epss:{epss:.3}"), 0.55 + 0.45 * epss.clamp(0.0, 1.0).sqrt())
    } else {
        ("no_exploit_data".to_string(), 0.6)
    };
    factors.push(RiskFactor { factor: "exploitability".into(), value: exploit_value, weight: exploit });

    // Fixability nudges rather than dominates: an unfixable finding is no
    // less dangerous, it's just less actionable today.
    let (fix_value, fix) = if finding.recommended_version.is_some() { ("fix_available", 1.0) } else { ("no_fix", 0.9) };
    factors.push(RiskFactor { factor: "fixability".into(), value: fix_value.into(), weight: fix });

    let score = (100.0 * severity * reach * exploit * fix).round().clamp(0.0, 100.0) as u8;
    RiskScore { score, factors }
}

/// Something the scan couldn't fully do, surfaced instead of silently
/// dropped (a manifest that failed to parse, a dependency whose version
/// can't be matched, an ecosystem with no advisory data, …).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanWarning {
    /// `manifest_parse_error`, `unresolved_version`, `no_advisory_data`,
    /// `vulndb_lines_skipped`, `reachability_error`.
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    /// English text; `kind` + `params` let a UI render it localized.
    pub message: String,
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

impl ScanWarning {
    pub fn new(kind: &str, path: Option<String>, message: String, params: &[(&str, String)]) -> Self {
        Self { kind: kind.to_string(), path, message, params: params.iter().map(|(k, v)| (k.to_string(), v.clone())).collect() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MalwareFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub path: String,
    pub line: usize,
    pub snippet: String,
    pub message: String,
}

pub trait ManifestParser {
    fn ecosystem(&self) -> &'static str;
    /// Exact filenames this parser handles (the common case: `package.json`,
    /// `go.mod`, ...). Ecosystems whose manifest is named after the package
    /// itself rather than a fixed convention (OCaml opam's `<name>.opam`)
    /// instead override [`Self::matches_file_name`].
    fn manifest_file_names(&self) -> &'static [&'static str];
    /// Whether this parser should run against a file named `file_name`.
    /// Defaults to an exact match against [`Self::manifest_file_names`].
    fn matches_file_name(&self, file_name: &str) -> bool {
        self.manifest_file_names().contains(&file_name)
    }
    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>>;
}
