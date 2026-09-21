mod range;

pub use range::VersionRange;

use serde::Deserialize;
use std::io::{self, BufRead};
use std::path::Path;
use uniflow_sca_core::{Dependency, DependencyFinding, Severity};
use versions::Versioning;

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
        },
    ]
}

pub struct VulnDb {
    records: Vec<VulnRecord>,
}

impl Default for VulnDb {
    fn default() -> Self {
        Self::load_embedded()
    }
}

impl VulnDb {
    /// The built-in fallback dataset — see [`builtin_seed`].
    pub fn load_embedded() -> Self {
        Self { records: builtin_seed() }
    }

    pub fn from_records(records: Vec<VulnRecord>) -> Self {
        Self { records }
    }

    /// Loads a bundle (one JSON `VulnRecord` per line) exported by
    /// `cosmos-backend` or fetched via `cosmos-agent vulndb sync`. A line
    /// that fails to parse is skipped rather than aborting the whole load —
    /// a single malformed advisory should never take down scanning.
    pub fn load_from_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut records = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<VulnRecord>(trimmed) {
                records.push(record);
            }
        }
        Ok(Self { records })
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

    /// Checks `dependency`'s version against every matching record's
    /// vulnerable-range window (via [`range::VersionRange::contains`]) and,
    /// for each hit, recommends a fix by merging that record's windows with
    /// the swept-line algorithm (see [`range::recommend_fix`]) rather than
    /// trusting a single hand-authored "upgrade to X" string.
    pub fn lookup(&self, dependency: &Dependency) -> Vec<DependencyFinding> {
        let Some(version) = Versioning::new(normalize_version(&dependency.version)) else {
            return Vec::new();
        };

        self.records
            .iter()
            .filter(|record| record.ecosystem == dependency.ecosystem && record.package == dependency.name)
            .filter_map(|record| {
                let ranges = range::parse_ranges(&record.vulnerable_range);
                if !ranges.iter().any(|r| r.contains(&version)) {
                    return None;
                }
                let recommended_version = range::recommend_fix(&ranges, &version);
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
                    message: match &recommended_version {
                        Some(fix) => format!(
                            "{} {} is vulnerable ({}); upgrade to {fix}",
                            dependency.name, dependency.version, record.summary
                        ),
                        None => format!(
                            "{} {} is vulnerable ({}); no known fixed version in this data",
                            dependency.name, dependency.version, record.summary
                        ),
                    },
                })
            })
            .collect()
    }
}

fn normalize_version(raw: &str) -> String {
    raw.trim_start_matches(['^', '~', '=', '>', '<', ' ']).to_string()
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
}
