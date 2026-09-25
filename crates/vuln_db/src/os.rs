//! Matching installed OS packages against distribution advisories.
//!
//! Differs from application-dependency matching in three ways that each
//! decide correctness:
//! 1. **Which name.** Debian, Ubuntu, Alpine, openEuler and Anolis key
//!    advisories by *source* package (`openssl`), Red Hat-family data by
//!    *binary* package (`openssl-libs`). Every installed package is looked
//!    up under both; binaries built from one source are reported together.
//! 2. **Which version.** dpkg keeps a separate source version for binNMUs
//!    (`2.36-9+deb12u4` vs binary `…+b1`); source-keyed data compares the
//!    source version, binary-keyed data the binary one.
//! 3. **What a finding is.** Distro advisories come per CVE
//!    (`DEBIAN-CVE-…`, `UBUNTU-CVE-…`, Red Hat unpatched OVAL) *and* per
//!    fix announcement bundling many CVEs (`DSA`, `USN`, `RHSA`, `OESA`…).
//!    Findings are one per (package, CVE), like Trivy and Grype report
//!    them, with every announcement that covers the CVE attached — never
//!    one USN swallowing ten unrelated CVEs.
use crate::range::{self, Ver};
use crate::version::Scheme;
use crate::{bare_id, finding_message, normalize_ecosystem, VulnDb, VulnRecord};
use std::collections::{BTreeMap, BTreeSet};
use uniflow_sca_core::{DependencyFinding, FixState, OsFindingInfo, OsPackage, Severity};

#[derive(Debug, Default)]
pub struct OsLookup {
    pub findings: Vec<DependencyFinding>,
    /// The dataset that was actually used (first of `data_keys` with any
    /// advisories), or `None` — no data for this distro release at all.
    pub data_source: Option<String>,
    pub packages_checked: usize,
}

/// Whether an advisory id names one CVE (a per-CVE tracker record) rather
/// than a fix announcement covering several.
fn is_per_cve(id: &str) -> bool {
    let bare = bare_id(id);
    bare.starts_with("CVE-") || bare.contains("-CVE-")
}

fn cve_of(id: &str) -> Option<String> {
    let bare = bare_id(id);
    bare.find("CVE-").map(|at| bare[at..].to_string())
}

fn parse_fix_state(record: &VulnRecord, has_upper_bound: bool) -> Option<FixState> {
    match record.fix_state.as_deref() {
        Some("not_affected") => None,
        Some("wont_fix") => Some(FixState::WontFix),
        Some("unfixed") => Some(FixState::Unfixed),
        Some("fixed") => Some(FixState::Fixed),
        _ if has_upper_bound => Some(FixState::Fixed),
        _ => Some(FixState::Unfixed),
    }
}

/// Fixed beats a decision beats "still open": if any source has a fix,
/// the user can upgrade; a won't-fix decision is more informative than
/// the generic "no fix yet".
fn state_rank(state: FixState) -> u8 {
    match state {
        FixState::Fixed => 0,
        FixState::WontFix => 1,
        FixState::Unfixed => 2,
    }
}

/// Oracle (and some RHEL) errata ship parallel rpm streams of one
/// package — Ksplice live-patch builds (`…ksplice1.el8`) and FIPS builds
/// (`…_fips`, often with a bumped epoch) — whose fix versions are
/// meaningless for a system on the regular stream: `2:2.28-251.0.4.ksplice1`
/// sorts above every epoch-0 glibc. A record only applies to installs of
/// the same flavor.
fn rpm_flavor(version: &str) -> u8 {
    if version.contains("ksplice") {
        1
    } else if version.contains("_fips") || version.contains(".fips") {
        2
    } else {
        0
    }
}

struct Query {
    name: String,
    version: String,
    by_source: bool,
    binaries: BTreeSet<String>,
}

#[derive(Default)]
struct Acc {
    title: Option<String>,
    specific_severity: Option<Severity>,
    bundle_severity: Option<Severity>,
    cwe: BTreeSet<String>,
    advisories: BTreeSet<String>,
    references: BTreeSet<String>,
    fixed: Option<String>,
    fixed_versions: BTreeSet<String>,
    state: Option<FixState>,
    distro_severity: Option<String>,
    epss: Option<f32>,
    kev: bool,
    range: String,
}

impl VulnDb {
    /// Matches `packages` (one system's inventory) against the first of
    /// `data_keys` that this database has advisories for.
    pub fn lookup_os(&self, data_keys: &[String], distro_key: &str, distro_label: &str, db_path: &str, packages: &[OsPackage]) -> OsLookup {
        let Some(data_key) = data_keys.iter().find(|k| self.covers_ecosystem(k)).cloned() else {
            return OsLookup { findings: Vec::new(), data_source: None, packages_checked: packages.len() };
        };
        let scheme = Scheme::for_ecosystem(&normalize_ecosystem(&data_key));

        // One query per distinct (name, version); binaries sharing a source
        // package collapse into one query carrying all their names.
        let mut queries: BTreeMap<(String, String), Query> = BTreeMap::new();
        for pkg in packages {
            let binary_key = (pkg.name.clone(), pkg.version.clone());
            queries
                .entry(binary_key)
                .or_insert_with(|| Query { name: pkg.name.clone(), version: pkg.version.clone(), by_source: false, binaries: BTreeSet::new() })
                .binaries
                .insert(pkg.name.clone());
            if let Some(source) = pkg.source_name.as_ref().filter(|s| **s != pkg.name) {
                let version = pkg.source_version.clone().unwrap_or_else(|| pkg.version.clone());
                queries
                    .entry((source.clone(), version.clone()))
                    .or_insert_with(|| Query { name: source.clone(), version, by_source: true, binaries: BTreeSet::new() })
                    .binaries
                    .insert(pkg.name.clone());
            }
        }

        let mut findings = Vec::new();
        for query in queries.values() {
            let Some(installed) = Ver::parse(scheme, &query.version) else { continue };
            let mut by_cve: BTreeMap<String, Acc> = BTreeMap::new();
            for (record, ranges) in self.candidates(&data_key, &query.name) {
                if scheme == Scheme::Rpm && record.fixed_versions.iter().chain(std::iter::once(&record.vulnerable_range)).any(|v| rpm_flavor(v) != rpm_flavor(&query.version)) {
                    continue;
                }
                if !ranges.iter().any(|r| r.contains(&installed)) {
                    continue;
                }
                let fix = range::recommend_fix(ranges, &installed);
                let Some(state) = parse_fix_state(record, fix.is_some()) else { continue };
                let per_cve = is_per_cve(&record.id);
                let keys: Vec<String> = if per_cve {
                    vec![cve_of(&record.id).unwrap_or_else(|| bare_id(&record.id).to_string())]
                } else {
                    let cves: Vec<String> = record.aliases.iter().filter(|a| a.starts_with("CVE-")).cloned().collect();
                    if cves.is_empty() { vec![bare_id(&record.id).to_string()] } else { cves }
                };
                for key in keys {
                    let acc = by_cve.entry(key).or_default();
                    if per_cve || acc.title.is_none() {
                        acc.title = Some(record.summary.clone());
                    }
                    let slot = if per_cve { &mut acc.specific_severity } else { &mut acc.bundle_severity };
                    *slot = Some(slot.map_or(record.severity, |s| s.max(record.severity)));
                    acc.cwe.extend(record.cwe.iter().cloned());
                    if !per_cve {
                        acc.advisories.insert(bare_id(&record.id).to_string());
                    }
                    acc.references.extend(record.references.iter().take(4).cloned());
                    acc.fixed_versions.extend(record.fixed_versions.iter().cloned());
                    if let Some(fix) = &fix {
                        acc.fixed = match acc.fixed.take() {
                            Some(prev) if Ver::parse(scheme, &prev) >= Ver::parse(scheme, fix) => Some(prev),
                            _ => Some(fix.clone()),
                        };
                    }
                    acc.state = Some(match acc.state {
                        Some(prev) if state_rank(prev) <= state_rank(state) => prev,
                        _ => state,
                    });
                    if acc.distro_severity.is_none() || per_cve {
                        if let Some(word) = &record.distro_severity {
                            acc.distro_severity = Some(word.clone());
                        }
                    }
                    acc.epss = match (acc.epss, record.epss) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    acc.kev |= record.kev;
                    if acc.range.is_empty() || per_cve {
                        acc.range = record.vulnerable_range.clone();
                    }
                }
            }
            for (cve, acc) in by_cve {
                let severity = acc.specific_severity.or(acc.bundle_severity).unwrap_or(Severity::Medium);
                let title = acc.title.unwrap_or_else(|| cve.clone());
                let fix_state = acc.state.unwrap_or(FixState::Unfixed);
                let recommended = if fix_state == FixState::Fixed { acc.fixed } else { None };
                findings.push(DependencyFinding {
                    rule_id: cve.clone(),
                    message: finding_message(&query.name, &query.version, &title, recommended.as_deref()),
                    title,
                    severity,
                    ecosystem: data_key.clone(),
                    package: query.name.clone(),
                    version: query.version.clone(),
                    vulnerable_range: acc.range,
                    recommended_version: recommended,
                    manifest_path: db_path.to_string(),
                    cve_ids: if cve.starts_with("CVE-") { vec![cve.clone()] } else { Vec::new() },
                    cwe: acc.cwe.into_iter().collect(),
                    // OS packages are installed system-wide; the direct/
                    // transitive distinction is an app-dependency concept.
                    direct: true,
                    dependency_path: Vec::new(),
                    affected_symbols: Vec::new(),
                    fixed_versions: acc.fixed_versions.into_iter().collect(),
                    epss: acc.epss,
                    kev: acc.kev,
                    reachability: None,
                    risk: None,
                    os: Some(OsFindingInfo {
                        distro: distro_key.to_string(),
                        distro_label: distro_label.to_string(),
                        data_source: data_key.clone(),
                        source_package: query.by_source.then(|| query.name.clone()),
                        binaries: query.binaries.iter().cloned().collect(),
                        installed_version: query.version.clone(),
                        fix_state,
                        advisory_ids: acc.advisories.into_iter().collect(),
                        distro_severity: acc.distro_severity,
                        references: acc.references.into_iter().take(6).collect(),
                    }),
                });
            }
        }

        // A package whose binary name equals its source name (bash,
        // openssl on rpm distros) is queried once; but data keyed by both
        // conventions (openEuler rows for the source, Red Hat rows for
        // binaries) can still produce the same CVE for a source and one of
        // its binaries — keep the source-level one, which lists every
        // binary.
        let source_level: BTreeSet<(String, String)> = findings
            .iter()
            .filter_map(|f| f.os.as_ref().filter(|o| o.source_package.is_some()).map(|o| (f.rule_id.clone(), o.binaries.join(","))))
            .collect();
        findings.retain(|f| {
            let Some(os) = &f.os else { return true };
            os.source_package.is_some()
                || !source_level.iter().any(|(cve, bins)| *cve == f.rule_id && bins.split(',').any(|b| os.binaries.contains(&b.to_string())))
        });
        findings.sort_by(|a, b| a.package.cmp(&b.package).then_with(|| a.rule_id.cmp(&b.rule_id)));
        OsLookup { findings, data_source: Some(data_key), packages_checked: packages.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, eco: &str, pkg: &str, range: &str, aliases: &[&str], severity: Severity) -> VulnRecord {
        VulnRecord {
            id: id.to_string(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            ecosystem: eco.to_string(),
            package: pkg.to_string(),
            severity,
            summary: format!("{id} summary"),
            cwe: Vec::new(),
            vulnerable_range: range.to_string(),
            affected_symbols: Vec::new(),
            fixed_versions: Vec::new(),
            epss: None,
            kev: false,
            fix_state: None,
            distro_severity: None,
            references: Vec::new(),
        }
    }

    fn deb(name: &str, version: &str, source: &str, source_version: Option<&str>) -> OsPackage {
        OsPackage {
            name: name.to_string(),
            version: version.to_string(),
            source_name: Some(source.to_string()),
            source_version: source_version.map(str::to_string),
            arch: Some("amd64".to_string()),
            module: None,
        }
    }

    fn lookup(db: &VulnDb, keys: &[&str], pkgs: &[OsPackage]) -> OsLookup {
        let keys: Vec<String> = keys.iter().map(|s| s.to_string()).collect();
        db.lookup_os(&keys, &keys[0], "Test", "/var/lib/dpkg/status", pkgs)
    }

    #[test]
    fn debian_matches_by_source_package_and_source_version_with_dpkg_ordering() {
        let db = VulnDb::from_records(vec![
            // Fixed in a +deb12uN security update — generic ordering would miss it.
            rec("osv:DEBIAN-CVE-2024-0001", "debian:12", "openssl", "<3.0.14-1~deb12u1", &[], Severity::High),
            // Still unfixed on bookworm.
            rec("osv:DEBIAN-CVE-2024-0002", "debian:12", "openssl", ">=0", &[], Severity::Medium),
            // Not this release.
            rec("osv:DEBIAN-CVE-2024-0003", "debian:11", "openssl", ">=0", &[], Severity::Critical),
            rec("osv:DEBIAN-CVE-2024-0004", "debian:12", "glibc", "<2.36-9+deb12u4", &[], Severity::High),
        ]);
        let out = lookup(
            &db,
            &["debian:12"],
            &[
                deb("libssl3", "3.0.11-1~deb12u2", "openssl", None),
                deb("openssl", "3.0.11-1~deb12u2", "openssl", None),
                // binNMU: binary is +b1 but the source version is already fixed.
                deb("libc6", "2.36-9+deb12u4+b1", "glibc", Some("2.36-9+deb12u4")),
            ],
        );
        let ids: Vec<(&str, &str)> = out.findings.iter().map(|f| (f.package.as_str(), f.rule_id.as_str())).collect();
        assert_eq!(ids, vec![("openssl", "CVE-2024-0001"), ("openssl", "CVE-2024-0002")]);
        let fixed = &out.findings[0];
        assert_eq!(fixed.recommended_version.as_deref(), Some("3.0.14-1~deb12u1"));
        let os = fixed.os.as_ref().unwrap();
        assert_eq!(os.fix_state, FixState::Fixed);
        assert_eq!(os.binaries, vec!["libssl3", "openssl"]);
        assert_eq!(out.findings[1].os.as_ref().unwrap().fix_state, FixState::Unfixed);
    }

    #[test]
    fn a_multi_cve_announcement_yields_one_finding_per_cve_carrying_its_id() {
        let db = VulnDb::from_records(vec![
            rec("osv:USN-7001-1", "ubuntu:22.04", "curl", "<7.81.0-1ubuntu1.18", &["CVE-2024-1111", "CVE-2024-2222"], Severity::High),
            rec("osv:UBUNTU-CVE-2024-1111", "ubuntu:22.04", "curl", "<7.81.0-1ubuntu1.18", &[], Severity::Low),
        ]);
        let out = lookup(&db, &["ubuntu:22.04"], &[deb("libcurl4", "7.81.0-1ubuntu1.15", "curl", None)]);
        assert_eq!(out.findings.len(), 2);
        let first = &out.findings[0];
        assert_eq!(first.rule_id, "CVE-2024-1111");
        // Per-CVE record's own severity wins over the bundle's.
        assert_eq!(first.severity, Severity::Low);
        assert_eq!(first.os.as_ref().unwrap().advisory_ids, vec!["USN-7001-1"]);
        assert_eq!(out.findings[1].severity, Severity::High);
    }

    #[test]
    fn centos_uses_rhel_data_by_binary_name_with_rpm_ordering() {
        let db = VulnDb::from_records(vec![rec("osv:RHSA-2024:0001", "rhel:7", "openssl-libs", "<1:1.0.2k-26.el7_9", &["CVE-2023-0286"], Severity::High)]);
        let pkg = OsPackage {
            name: "openssl-libs".to_string(),
            version: "1:1.0.2k-25.el7_9".to_string(),
            source_name: Some("openssl".to_string()),
            source_version: None,
            arch: Some("x86_64".to_string()),
            module: None,
        };
        let out = lookup(&db, &["centos:7", "rhel:7"], &[pkg]);
        assert_eq!(out.data_source.as_deref(), Some("rhel:7"));
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].os.as_ref().unwrap().data_source, "rhel:7");
        assert_eq!(out.findings[0].os.as_ref().unwrap().source_package, None);
    }

    #[test]
    fn oracle_ksplice_and_fips_streams_do_not_match_regular_installs() {
        let db = VulnDb::from_records(vec![
            rec("distro:ELSA-2026-50174", "ol:8", "glibc", "<2:2.28-251.0.4.ksplice1.el8_10.31", &["CVE-2025-15281"], Severity::High),
            rec("distro:ELSA-2022-9564", "ol:8", "libgcrypt", "<10:1.8.5-7.el8_6_fips", &["CVE-2021-40528"], Severity::Medium),
            rec("distro:ELSA-2026-1", "ol:8", "glibc", "<2.28-251.0.6.el8_10.41", &["CVE-2026-1"], Severity::High),
        ]);
        let pkg = |name: &str, v: &str| OsPackage { name: name.into(), version: v.into(), source_name: None, source_version: None, arch: None, module: None };
        let out = lookup(&db, &["ol:8"], &[pkg("glibc", "2.28-251.0.5.el8_10.40"), pkg("libgcrypt", "1.8.5-8.el8_10")]);
        let ids: Vec<&str> = out.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(ids, vec!["CVE-2026-1"]);
    }

    #[test]
    fn wont_fix_and_not_affected_come_from_the_tracker() {
        let mut wont = rec("redhat:CVE-2005-2541", "rhel:9", "tar", ">=0", &[], Severity::Medium);
        wont.fix_state = Some("wont_fix".to_string());
        let mut not_affected = rec("redhat:CVE-2024-9", "rhel:9", "tar", ">=0", &[], Severity::High);
        not_affected.fix_state = Some("not_affected".to_string());
        let db = VulnDb::from_records(vec![wont, not_affected]);
        let pkg = OsPackage { name: "tar".into(), version: "2:1.34-6.el9".into(), source_name: Some("tar".into()), source_version: None, arch: None, module: None };
        let out = lookup(&db, &["rhel:9"], &[pkg]);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].os.as_ref().unwrap().fix_state, FixState::WontFix);
    }

    #[test]
    fn no_data_for_the_release_is_reported_not_guessed() {
        let db = VulnDb::from_records(vec![rec("osv:DEBIAN-CVE-1", "debian:12", "bash", ">=0", &[], Severity::Low)]);
        let out = lookup(&db, &["ubuntu:24.04"], &[deb("bash", "5.2", "bash", None)]);
        assert!(out.data_source.is_none());
        assert!(out.findings.is_empty());
    }
}
