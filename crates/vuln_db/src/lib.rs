mod os;
mod range;
pub mod version;

pub use os::OsLookup;
pub use range::{Ver, VersionRange};
pub use version::Scheme;

use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::Path;
use uniflow_sca_core::{Dependency, DependencyFinding, Severity};

/// One line of a vuln-db bundle — the exact JSONL schema `cosmos-backend`
/// exports from its `vuln_advisory`/`vuln_advisory_override` tables (see
/// `GET /api/v1/organizations/{org_id}/vulndb/effective`) and that
/// `cosmos-agent vulndb sync` writes to a local snapshot file. Loading a
/// bundle is therefore just deserializing this struct line by line — no
/// translation layer between "what the backend computed as this org's
/// effective advisory set" and "what the matcher reads".
#[derive(Debug, Clone, Deserialize)]
pub struct VulnRecord {
    /// Stable identity for display/audit — e.g. `osv:GHSA-jf85-cpcp-j695` or
    /// `manual:<uuid>`. Never an Antiy-internal ID.
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub ecosystem: String,
    pub package: String,
    pub severity: Severity,
    pub summary: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    /// Raw range expression(s), e.g. `"<4.17.21"` or `">=1.0.0,<1.2.0 ||
    /// >=2.0.0,<2.0.5"` — parsed on load via [`range::parse_ranges`].
    pub vulnerable_range: String,
    /// Fully-qualified vulnerable functions/symbols (Go
    /// `github.com/x/y.Func`, RustSec `crate::path::fn`, Python
    /// `yaml.load`) — the input to `uniflow_sca_reachability`. Every field
    /// below is `default` so snapshots written before it existed still load.
    #[serde(default)]
    pub affected_symbols: Vec<String>,
    #[serde(default)]
    pub fixed_versions: Vec<String>,
    #[serde(default)]
    pub epss: Option<f32>,
    #[serde(default)]
    pub kev: bool,
    /// OS advisories only: `fixed` / `unfixed` / `wont_fix` /
    /// `not_affected`, as the distro's tracker states it. Absent = derive
    /// from the range (an upper bound means a fix exists).
    #[serde(default)]
    pub fix_state: Option<String>,
    /// The distro's own severity word (`important`, `unimportant`, …).
    #[serde(default)]
    pub distro_severity: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
}

/// A handful of well-known CVEs kept as a built-in fallback so a fresh
/// `cosmos-agent` install (or any embedder of this crate) has *some*
/// coverage before its first `vulndb sync` — not a substitute for the real
/// OSV/NVD-sourced dataset a deployment imports via `cosmos-backend`.
fn builtin_seed() -> Vec<VulnRecord> {
    vec![
        VulnRecord {
            id: "seed:CVE-2021-23337".to_string(),
            aliases: vec!["CVE-2021-23337".to_string()],
            ecosystem: "npm".to_string(),
            package: "lodash".to_string(),
            severity: Severity::High,
            summary: "Command injection via the template function".to_string(),
            cwe: vec!["CWE-94".to_string()],
            vulnerable_range: "<4.17.21".to_string(),
            affected_symbols: vec!["lodash.template".to_string()],
            fixed_versions: vec!["4.17.21".to_string()],
            epss: None,
            kev: false,
            fix_state: None,
            distro_severity: None,
            references: Vec::new(),
        },
        VulnRecord {
            id: "seed:CVE-2021-44906".to_string(),
            aliases: vec!["CVE-2021-44906".to_string()],
            ecosystem: "npm".to_string(),
            package: "minimist".to_string(),
            severity: Severity::Critical,
            summary: "Prototype pollution via constructor/proto keys".to_string(),
            cwe: vec!["CWE-1321".to_string()],
            vulnerable_range: "<1.2.6".to_string(),
            affected_symbols: Vec::new(),
            fixed_versions: vec!["1.2.6".to_string()],
            epss: None,
            kev: false,
            fix_state: None,
            distro_severity: None,
            references: Vec::new(),
        },
        VulnRecord {
            id: "seed:RUSTSEC-2020-0071".to_string(),
            aliases: vec!["RUSTSEC-2020-0071".to_string()],
            ecosystem: "cargo".to_string(),
            package: "time".to_string(),
            severity: Severity::Medium,
            summary: "Segfault in localtime_r under concurrent access".to_string(),
            cwe: vec!["CWE-125".to_string()],
            vulnerable_range: "<0.2.23".to_string(),
            affected_symbols: vec!["time::at".to_string(), "time::now".to_string(), "time::strptime".to_string()],
            fixed_versions: vec!["0.2.23".to_string()],
            epss: None,
            kev: false,
            fix_state: None,
            distro_severity: None,
            references: Vec::new(),
        },
    ]
}

/// A record with its range expression parsed once at load time — parsing
/// used to happen per (dependency × record) lookup, which on a full OSV
/// snapshot (hundreds of thousands of rows) dominated scan time.
struct IndexedRecord {
    record: VulnRecord,
    ranges: Vec<VersionRange>,
}

pub struct VulnDb {
    records: Vec<IndexedRecord>,
    /// (normalized ecosystem, normalized package) → indices into `records`.
    /// Lookup used to be a linear scan of every record for every
    /// dependency (O(deps × records)); this makes it O(matches).
    index: HashMap<(String, String), Vec<usize>>,
    skipped_lines: usize,
}

impl Default for VulnDb {
    fn default() -> Self {
        Self::load_embedded()
    }
}

/// The result of matching one dependency, including the case the old
/// `lookup` silently swallowed: advisories exist for this package, but the
/// dependency's version couldn't be parsed/pinned (an unpinned
/// `requirements.txt` line, a `package.json` `"latest"`/git URL, ...), so
/// whether it's affected is genuinely unknown.
#[derive(Debug, Default)]
pub struct LookupOutcome {
    pub findings: Vec<DependencyFinding>,
    /// `Some(n)` = `n` advisories for this package could not be evaluated
    /// because the version is unresolved.
    pub unresolved_advisories: Option<usize>,
}

/// Canonical ecosystem tag — accepts both our internal tags and OSV's
/// display names so a hand-built or older snapshot using `PyPI`/
/// `crates.io` still matches.
pub fn normalize_ecosystem(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        "crates.io" | "crates" | "rust" => "cargo".to_string(),
        "golang" => "go".to_string(),
        "pip" | "python" => "pypi".to_string(),
        "composer" => "packagist".to_string(),
        "gem" | "ruby" => "rubygems".to_string(),
        "gradle" => "maven".to_string(),
        _ => lower,
    }
}

/// Canonical package name for matching within `ecosystem`, following each
/// registry's own identity rules — exact string comparison used to miss
/// e.g. `PyYAML` (requirements.txt) vs `pyyaml` (OSV), or a crate spelled
/// with `_` vs `-`.
pub fn normalize_package_name(ecosystem: &str, name: &str) -> String {
    let name = name.trim();
    match normalize_ecosystem(ecosystem).as_str() {
        // PEP 503: lowercase, and any run of `-`, `_`, `.` is equivalent.
        "pypi" => {
            let mut out = String::with_capacity(name.len());
            let mut last_sep = false;
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !last_sep {
                        out.push('-');
                    }
                    last_sep = true;
                } else {
                    out.extend(c.to_lowercase());
                    last_sep = false;
                }
            }
            out
        }
        // crates.io treats `-` and `_` as the same name and is
        // case-insensitive for uniqueness.
        "cargo" => name.to_ascii_lowercase().replace('_', "-"),
        // Maven coordinates are `groupId:artifactId`; tolerate stray
        // whitespace around the colon and a trailing `:version`/`:type`
        // some exporters append.
        "maven" => {
            let mut parts = name.split(':').map(str::trim);
            match (parts.next(), parts.next()) {
                (Some(group), Some(artifact)) => format!("{group}:{artifact}").to_ascii_lowercase(),
                _ => name.to_ascii_lowercase(),
            }
        }
        // Go module paths are case-sensitive (the module proxy
        // case-encodes them), so they're compared exactly.
        "go" => name.to_string(),
        // npm, packagist, nuget, rubygems, pub, ...: case-insensitive in
        // practice (npm forbids uppercase in new names; NuGet/Packagist
        // are case-insensitive).
        _ => name.to_lowercase(),
    }
}

impl VulnDb {
    /// The built-in fallback dataset — see [`builtin_seed`].
    pub fn load_embedded() -> Self {
        Self::from_records(builtin_seed())
    }

    pub fn from_records(records: Vec<VulnRecord>) -> Self {
        let mut db = Self { records: Vec::with_capacity(records.len()), index: HashMap::new(), skipped_lines: 0 };
        for record in records {
            db.push(record);
        }
        db
    }

    fn push(&mut self, record: VulnRecord) {
        let key = (normalize_ecosystem(&record.ecosystem), normalize_package_name(&record.ecosystem, &record.package));
        let ranges = range::parse_ranges_with(Scheme::for_ecosystem(&key.0), &record.vulnerable_range);
        self.index.entry(key).or_default().push(self.records.len());
        self.records.push(IndexedRecord { record, ranges });
    }

    /// Loads a bundle (one JSON `VulnRecord` per line) exported by
    /// `cosmos-backend` or fetched via `cosmos-agent vulndb sync`. A line
    /// that fails to parse is skipped rather than aborting the whole load —
    /// a single malformed advisory should never take down scanning — but
    /// it is counted ([`Self::skipped_lines`]) so the scan can say so.
    pub fn load_from_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut db = Self { records: Vec::new(), index: HashMap::new(), skipped_lines: 0 };
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<VulnRecord>(trimmed) {
                Ok(record) => db.push(record),
                Err(_) => db.skipped_lines += 1,
            }
        }
        Ok(db)
    }

    pub fn load_from_path(path: &Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        Self::load_from_reader(io::BufReader::new(file))
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Records indexed under (normalized ecosystem, normalized package).
    pub(crate) fn candidates(&self, ecosystem: &str, package: &str) -> impl Iterator<Item = (&VulnRecord, &[VersionRange])> {
        let key = (normalize_ecosystem(ecosystem), normalize_package_name(ecosystem, package));
        self.index.get(&key).into_iter().flatten().map(|&i| (&self.records[i].record, self.records[i].ranges.as_slice()))
    }

    /// Snapshot lines that failed to parse at load time.
    pub fn skipped_lines(&self) -> usize {
        self.skipped_lines
    }

    /// Whether this dataset has any advisory at all for `ecosystem` — lets
    /// a scan report "N chef dependencies were never checked" instead of
    /// implying they're clean.
    pub fn covers_ecosystem(&self, ecosystem: &str) -> bool {
        let ecosystem = normalize_ecosystem(ecosystem);
        self.index.keys().any(|(eco, _)| *eco == ecosystem)
    }

    /// Checks `dependency`'s version against every matching record's
    /// vulnerable-range window (via [`range::VersionRange::contains`]) and,
    /// for each hit, recommends a fix by merging that record's windows with
    /// the swept-line algorithm (see [`range::recommend_fix`]) rather than
    /// trusting a single hand-authored "upgrade to X" string.
    pub fn lookup(&self, dependency: &Dependency) -> Vec<DependencyFinding> {
        self.lookup_detailed(dependency).findings
    }

    pub fn lookup_detailed(&self, dependency: &Dependency) -> LookupOutcome {
        let key = (normalize_ecosystem(&dependency.ecosystem), normalize_package_name(&dependency.ecosystem, &dependency.name));
        let Some(candidates) = self.index.get(&key) else { return LookupOutcome::default() };
        // Same ordering the record's ranges were parsed with (see `insert`):
        // PEP 440 for PyPI, ComparableVersion for Maven, lenient otherwise.
        let Some(version) = Ver::parse(Scheme::for_ecosystem(&key.0), &normalize_version(&dependency.version)) else {
            return LookupOutcome { findings: Vec::new(), unresolved_advisories: Some(candidates.len()) };
        };

        let findings = candidates
            .iter()
            .map(|&i| &self.records[i])
            .filter_map(|IndexedRecord { record, ranges }| {
                if !ranges.iter().any(|r| r.contains(&version)) {
                    return None;
                }
                let recommended_version = range::recommend_fix(ranges, &version);
                Some(DependencyFinding {
                    rule_id: record.id.clone(),
                    title: record.summary.clone(),
                    severity: record.severity,
                    ecosystem: dependency.ecosystem.clone(),
                    package: dependency.name.clone(),
                    version: dependency.version.clone(),
                    vulnerable_range: record.vulnerable_range.clone(),
                    recommended_version: recommended_version.clone(),
                    manifest_path: dependency.manifest_path.clone(),
                    cve_ids: record.aliases.clone(),
                    cwe: record.cwe.clone(),
                    message: finding_message(&dependency.name, &dependency.version, &record.summary, recommended_version.as_deref()),
                    direct: dependency.direct,
                    dependency_path: Vec::new(),
                    affected_symbols: record.affected_symbols.clone(),
                    fixed_versions: record.fixed_versions.clone(),
                    epss: record.epss,
                    kev: record.kev,
                    reachability: None,
                    risk: None,
                    os: None,
                })
            })
            .collect();
        LookupOutcome { findings: merge_alias_duplicates(findings), unresolved_advisories: None }
    }
}

pub(crate) fn finding_message(package: &str, version: &str, summary: &str, fix: Option<&str>) -> String {
    match fix {
        Some(fix) => format!("{package} {version} is vulnerable ({summary}); upgrade to {fix}"),
        None => format!("{package} {version} is vulnerable ({summary}); no known fixed version in this data"),
    }
}

/// The bare advisory id, without the `<source>:` prefix the backend's
/// snapshot adds (`osv:GHSA-…` → `GHSA-…`), so it compares against aliases.
pub(crate) fn bare_id(id: &str) -> &str {
    id.split_once(':').map_or(id, |(_, rest)| rest)
}

/// Which record of an alias cluster fronts the merged finding: a reviewed
/// GHSA carries CVSS-based severity and CWE, while database-native ids like
/// PYSEC often carry neither (so they default to `medium`), then CVE, then
/// anything else — ties broken by id for determinism.
fn primary_rank(id: &str) -> u8 {
    let bare = bare_id(id);
    if bare.starts_with("GHSA-") {
        0
    } else if bare.starts_with("CVE-") {
        1
    } else {
        2
    }
}

/// OSV publishes the same vulnerability once per database that tracks it
/// (`GHSA-6757-jp84-gxfx` and `PYSEC-2020-96` are both CVE-2020-1747 in
/// PyYAML), each listing the others as aliases. Reported separately they
/// double-count the dependency's risk and can even disagree on severity,
/// so records whose ids/aliases overlap are merged into one finding:
/// highest severity, the union of CWEs/aliases/symbols/fixed versions, the
/// strongest exploit signal, and the highest recommended version (the one
/// that clears every advisory in the cluster).
pub(crate) fn merge_alias_duplicates(findings: Vec<DependencyFinding>) -> Vec<DependencyFinding> {
    if findings.len() < 2 {
        return findings;
    }
    // Union-find over findings, joined whenever two share any identifier.
    let mut parent: Vec<usize> = (0..findings.len()).collect();
    fn find(parent: &mut [usize], i: usize) -> usize {
        let mut root = i;
        while parent[root] != root {
            root = parent[root];
        }
        let mut node = i;
        while parent[node] != root {
            let next = parent[node];
            parent[node] = root;
            node = next;
        }
        root
    }
    let mut owner: HashMap<String, usize> = HashMap::new();
    for (i, finding) in findings.iter().enumerate() {
        let ids = std::iter::once(bare_id(&finding.rule_id)).chain(finding.cve_ids.iter().map(String::as_str));
        for id in ids {
            match owner.get(id) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        parent[a] = b;
                    }
                }
                None => {
                    owner.insert(id.to_string(), i);
                }
            }
        }
    }

    let mut clusters: Vec<Vec<DependencyFinding>> = Vec::new();
    let mut slot: HashMap<usize, usize> = HashMap::new();
    for (i, finding) in findings.into_iter().enumerate() {
        let root = find(&mut parent, i);
        let index = *slot.entry(root).or_insert_with(|| {
            clusters.push(Vec::new());
            clusters.len() - 1
        });
        clusters[index].push(finding);
    }

    clusters
        .into_iter()
        .map(|mut cluster| {
            cluster.sort_by(|a, b| primary_rank(&a.rule_id).cmp(&primary_rank(&b.rule_id)).then_with(|| a.rule_id.cmp(&b.rule_id)));
            let mut rest = cluster.split_off(1);
            let mut merged = cluster.pop().expect("clusters are never empty");
            let primary_bare = bare_id(&merged.rule_id).to_string();
            for other in rest.drain(..) {
                merged.severity = merged.severity.max(other.severity);
                merged.cve_ids.push(bare_id(&other.rule_id).to_string());
                merged.cve_ids.extend(other.cve_ids);
                merged.cwe.extend(other.cwe);
                merged.affected_symbols.extend(other.affected_symbols);
                merged.fixed_versions.extend(other.fixed_versions);
                merged.kev |= other.kev;
                merged.epss = match (merged.epss, other.epss) {
                    (Some(a), Some(b)) => Some(a.max(b)),
                    (a, b) => a.or(b),
                };
                let scheme = Scheme::for_ecosystem(&normalize_ecosystem(&merged.ecosystem));
                merged.recommended_version = match (merged.recommended_version.take(), other.recommended_version) {
                    (Some(a), Some(b)) => match (Ver::parse(scheme, &a), Ver::parse(scheme, &b)) {
                        (Some(va), Some(vb)) if vb > va => Some(b),
                        _ => Some(a),
                    },
                    (a, b) => a.or(b),
                };
            }
            for list in [&mut merged.cve_ids, &mut merged.cwe, &mut merged.affected_symbols, &mut merged.fixed_versions] {
                list.sort();
                list.dedup();
            }
            merged.cve_ids.retain(|id| *id != primary_bare);
            merged.message = finding_message(&merged.package, &merged.version, &merged.title, merged.recommended_version.as_deref());
            merged
        })
        .collect()
}

/// Strips range operators a manifest (not a lockfile) records, plus Go's
/// `v` prefix, down to a bare version. An empty result (an unpinned
/// requirement) or an unparseable one (`latest`, a git URL, `*`) makes
/// `Versioning::new` fail, which `lookup_detailed` reports as unresolved.
fn normalize_version(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches(['^', '~', '=', '>', '<', ' ']);
    let trimmed = trimmed.strip_prefix('v').filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit())).unwrap_or(trimmed);
    // `versions::Versioning` accepts almost anything as a "Mess" version
    // (`latest` included), so require a leading digit — every real
    // ecosystem version (semver, PEP 440, Maven, Debian epochs) has one.
    if !trimmed.starts_with(|c: char| c.is_ascii_digit()) || trimmed.contains("://") || trimmed.contains(' ') {
        return String::new();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn flags_a_vulnerable_dependency_with_a_recommended_fix() {
        let db = VulnDb::load_embedded();
        let dependency = Dependency {
            ecosystem: "npm".to_string(),
            name: "lodash".to_string(),
            version: "4.17.15".to_string(),
            manifest_path: "package.json".to_string(),
            direct: true,
        };
        let findings = db.lookup(&dependency);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].recommended_version.as_deref(), Some("4.17.21"));
        assert_eq!(findings[0].cve_ids, vec!["CVE-2021-23337".to_string()]);
    }

    #[test]
    fn does_not_flag_an_already_fixed_version() {
        let db = VulnDb::load_embedded();
        let dependency = Dependency {
            ecosystem: "npm".to_string(),
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            manifest_path: "package.json".to_string(),
            direct: true,
        };
        assert!(db.lookup(&dependency).is_empty());
    }

    #[test]
    fn ignores_an_unrelated_package_or_ecosystem() {
        let db = VulnDb::load_embedded();
        let dependency = Dependency {
            ecosystem: "pypi".to_string(),
            name: "lodash".to_string(),
            version: "1.0.0".to_string(),
            manifest_path: "requirements.txt".to_string(),
            direct: true,
        };
        assert!(db.lookup(&dependency).is_empty());
    }

    #[test]
    fn loads_a_bundle_from_a_jsonl_file_and_matches_against_it() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"{{"id":"osv:GHSA-test","aliases":["CVE-2099-0001"],"ecosystem":"pypi","package":"widget","severity":"critical","summary":"test advisory","cwe":["CWE-1"],"vulnerable_range":"<2.0.0"}}"#
        )
        .unwrap();
        writeln!(file).unwrap(); // a blank line must not break parsing
        writeln!(file, "not valid json").unwrap(); // a malformed line must be skipped, not fatal

        let db = VulnDb::load_from_path(file.path()).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db.skipped_lines(), 1, "the malformed line must be counted, not silently dropped");

        let dependency = Dependency {
            ecosystem: "pypi".to_string(),
            name: "widget".to_string(),
            version: "1.0.0".to_string(),
            manifest_path: "requirements.txt".to_string(),
            direct: true,
        };
        let findings = db.lookup(&dependency);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cve_ids, vec!["CVE-2099-0001".to_string()]);
    }

    fn dep(ecosystem: &str, name: &str, version: &str) -> Dependency {
        Dependency {
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            manifest_path: "m".to_string(),
            direct: true,
        }
    }

    fn record(ecosystem: &str, package: &str, range: &str) -> VulnRecord {
        VulnRecord {
            id: format!("test:{package}"),
            aliases: Vec::new(),
            ecosystem: ecosystem.to_string(),
            package: package.to_string(),
            severity: Severity::High,
            summary: "s".to_string(),
            cwe: Vec::new(),
            vulnerable_range: range.to_string(),
            affected_symbols: vec!["yaml.load".to_string()],
            fixed_versions: Vec::new(),
            epss: Some(0.4),
            kev: true,
            fix_state: None,
            distro_severity: None,
            references: Vec::new(),
        }
    }

    #[test]
    fn pypi_names_match_under_pep_503_normalization() {
        // Regression: `PyYAML` in requirements.txt never matched OSV's `pyyaml`.
        let db = VulnDb::from_records(vec![record("pypi", "pyyaml", "<5.4")]);
        for (name, expected) in [("PyYAML", 1), ("pyyaml", 1), ("PyYaml", 1), ("py_yaml", 0), ("py-yaml", 0)] {
            assert_eq!(db.lookup(&dep("pypi", name, "5.3")).len(), expected, "{name}");
        }
        let db = VulnDb::from_records(vec![record("PyPI", "zope.interface", "<9")]);
        assert_eq!(db.lookup(&dep("pypi", "Zope-Interface", "1.0")).len(), 1);
    }

    #[test]
    fn cargo_and_maven_names_normalize() {
        let db = VulnDb::from_records(vec![record("crates.io", "tokio-util", "<1"), record("maven", "org.yaml:snakeyaml", "<2.0")]);
        assert_eq!(db.lookup(&dep("cargo", "tokio_util", "0.7.0")).len(), 1);
        assert_eq!(db.lookup(&dep("maven", "org.yaml : snakeyaml", "1.33")).len(), 1);
        assert_eq!(db.lookup(&dep("maven", "org.yaml:snakeyaml:jar", "1.33")).len(), 1);
    }

    #[test]
    fn go_versions_with_a_v_prefix_match() {
        let db = VulnDb::from_records(vec![record("go", "github.com/dgrijalva/jwt-go", "<4.0.0")]);
        assert_eq!(db.lookup(&dep("go", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible")).len(), 1);
        assert!(db.lookup(&dep("go", "github.com/Dgrijalva/jwt-go", "v3.2.0")).is_empty(), "Go module paths are case-sensitive");
    }

    #[test]
    fn an_unpinned_version_is_reported_as_unresolved_not_silently_clean() {
        // Regression: an unparseable version used to return "no findings",
        // indistinguishable from "not vulnerable".
        let db = VulnDb::from_records(vec![record("pypi", "pyyaml", "<5.4")]);
        for version in ["", "latest", "*", "git+https://github.com/yaml/pyyaml"] {
            let outcome = db.lookup_detailed(&dep("pypi", "pyyaml", version));
            assert!(outcome.findings.is_empty());
            assert_eq!(outcome.unresolved_advisories, Some(1), "{version:?}");
        }
        assert_eq!(db.lookup_detailed(&dep("pypi", "requests", "")).unresolved_advisories, None, "no advisories = nothing unresolved");
    }

    #[test]
    fn findings_carry_symbols_epss_kev_and_direct() {
        let db = VulnDb::from_records(vec![record("pypi", "pyyaml", "<5.4")]);
        let finding = &db.lookup(&dep("pypi", "PyYAML", "5.3"))[0];
        assert_eq!(finding.affected_symbols, vec!["yaml.load".to_string()]);
        assert_eq!(finding.epss, Some(0.4));
        assert!(finding.kev);
        assert!(finding.direct);
    }

    #[test]
    fn old_snapshot_lines_without_the_new_fields_still_load() {
        let line = r#"{"id":"osv:X","ecosystem":"npm","package":"a","severity":"low","summary":"s","vulnerable_range":"<1"}"#;
        let db = VulnDb::load_from_reader(std::io::BufReader::new(line.as_bytes())).unwrap();
        assert_eq!(db.len(), 1);
        assert!(db.covers_ecosystem("npm"));
        assert!(!db.covers_ecosystem("chef"));
    }

    #[test]
    fn alias_duplicates_merge_into_one_finding() {
        // OSV's real PyYAML shape: the same CVE published as a GHSA (with
        // CVSS severity) and as a PYSEC (no severity → default medium).
        let mut ghsa = record("PyPI", "pyyaml", "<5.4");
        ghsa.id = "osv:GHSA-8q59-q68h-6hv4".to_string();
        ghsa.aliases = vec!["CVE-2020-14343".to_string(), "PYSEC-2021-142".to_string()];
        ghsa.severity = Severity::Critical;
        ghsa.cwe = vec!["CWE-20".to_string()];
        let mut pysec = record("PyPI", "pyyaml", "<5.4");
        pysec.id = "osv:PYSEC-2021-142".to_string();
        pysec.aliases = vec!["CVE-2020-14343".to_string(), "GHSA-8q59-q68h-6hv4".to_string()];
        pysec.severity = Severity::Medium;
        pysec.affected_symbols = vec!["yaml.full_load".to_string()];
        pysec.kev = true;
        let mut unrelated = record("PyPI", "pyyaml", "<5.4");
        unrelated.id = "osv:GHSA-rprw-h62v-c2w7".to_string();
        unrelated.aliases = vec!["CVE-2020-1747".to_string()];
        let db = VulnDb::from_records(vec![pysec, ghsa, unrelated]);
        let dependency = Dependency {
            ecosystem: "pypi".to_string(),
            name: "PyYAML".to_string(),
            version: "5.3".to_string(),
            manifest_path: "requirements.txt".to_string(),
            direct: true,
        };
        let mut findings = db.lookup(&dependency);
        findings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        assert_eq!(findings.len(), 2, "the GHSA/PYSEC pair collapses, the unrelated advisory stays");
        let merged = findings.iter().find(|f| f.rule_id == "osv:GHSA-8q59-q68h-6hv4").expect("GHSA fronts the cluster");
        assert_eq!(merged.severity, Severity::Critical);
        assert_eq!(merged.cve_ids, vec!["CVE-2020-14343".to_string(), "PYSEC-2021-142".to_string()]);
        assert!(merged.affected_symbols.contains(&"yaml.full_load".to_string()), "symbols from every record in the cluster are kept");
        assert!(merged.kev);
    }
}
