//! The SCA side: there is no labeled ground truth for "every vulnerable
//! dependency in a real project", so SCA is scored *comparatively* — the
//! same inputs through uniflow and through Trivy, Grype and osv-scanner,
//! then agreement and each side's exclusive findings, keyed by
//! (package, vulnerability) with alias-aware vulnerability identity.
//!
//! Every exclusive finding gets an automatic triage bucket from what the
//! Cosmos dataset itself says about it:
//! - `data-absent` — no Cosmos advisory for that package carries any of the
//!   other tool's ids/aliases: a data difference, not a matcher bug;
//! - `data-present-unmatched` — Cosmos has the advisory but did not match
//!   the installed version: version semantics or a range bug; the ones
//!   worth a human look;
//! - `cosmos-only` — the other tool has nothing: its data gap, a Cosmos
//!   false positive, or a granularity difference; a sample is triaged by
//!   hand in the report.
//! Fairness caveat (ADR-0019): each tool uses its own vulnerability data as
//! of the run date; nothing here forces a shared database.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;
use uniflow_vuln_db::{VulnDb, VulnRecord};

pub const TOOLS: &[&str] = &["trivy", "grype", "osv-scanner"];

/// Real projects at old releases (so they contain known-vulnerable
/// dependencies), covering every ecosystem the comparison is about:
/// (input name, GitHub repo, commit). Pinned in `corpora.lock.json` like
/// the SAST suites.
pub const PROJECTS: &[(&str, &str, &str)] = &[
    ("mastodon-3.0.0", "mastodon/mastodon", "83d3e7733da892f5ad94ed2b8757db11250fbe6a"),
    ("discourse-2.4.0", "discourse/discourse", "76b9be3f19f393a216973b791245228f2d3e92f8"),
    ("nodegoat", "OWASP/NodeGoat", "c5cb68a7084e4ae7dcc60e6a98768720a81841e8"),
    ("webgoat-8.0.0", "WebGoat/WebGoat", "985148ede3de39073c3bfa5b784ed52eb8496dfc"),
    ("spring-petclinic", "spring-projects/spring-petclinic", "818c4136ea971c21674525f9053de0d9c7ad8cfe"),
    ("gin-1.6.0", "gin-gonic/gin", "c4fd2489ced13e86c6e9328e7d66cd3bb2957f00"),
    ("hugo-0.60.0", "gohugoio/hugo", "f2dea9b036364d3aa380787dd0f495c73792ad95"),
    ("pygoat", "adeyosemanputra/pygoat", "19d17cc8874861142b330636d068bbde54e86b85"),
    ("superset-0.36.0", "apache/superset", "2cd8ca94c8923c4320e305f92d74d282390646a5"),
    ("alacritty-0.4.0", "alacritty/alacritty", "b115b9038566d6ce0ed56f4a50c428c98e04b51a"),
    ("matomo-3.14.0", "matomo-org/matomo", "6b6dc723c73dc4d59b2ae849d241270dc53e5a39"),
    ("eshoponweb", "dotnet-architecture/eShopOnWeb", "4da8212117e87d808d4bbc7da6286fd2147ce606"),
];

/// Materializes the pinned project corpus as `out/<name>` symlinks into the
/// verified cache, ready to hand to every scanner.
pub fn materialize(out: &Path, lock: &mut crate::corpus::Lock, update_lock: bool) -> Result<()> {
    std::fs::create_dir_all(out)?;
    for (name, repo, commit) in PROJECTS {
        let root = crate::corpus::ensure(lock, &format!("sca/{name}"), &crate::corpus::github_tarball(repo, commit), "tar.gz", "", update_lock)?;
        let link = out.join(name);
        if link.symlink_metadata().is_ok() {
            std::fs::remove_file(&link).or_else(|_| std::fs::remove_dir_all(&link))?;
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&root, &link)?;
    }
    Ok(())
}

/// One (package, vulnerability) observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Obs {
    pub package: String,
    pub version: String,
    /// Every id this tool knows the vulnerability by (primary + aliases).
    pub ids: BTreeSet<String>,
}

pub fn normalize_package(name: &str) -> String {
    // Maven: Grype names packages by artifactId, Cosmos/Trivy/osv-scanner by
    // `groupId:artifactId` — compare on the artifactId everywhere.
    let name = name.rsplit_once(':').map_or(name, |(_, artifact)| artifact);
    let lower = name.trim().to_ascii_lowercase();
    // PEP 503-style: `Foo_Bar.baz` and `foo-bar-baz` are one package; the
    // same collapse is harmless for every other ecosystem's names.
    let mut out = String::with_capacity(lower.len());
    let mut last_sep = false;
    for c in lower.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !last_sep {
                out.push('-');
            }
            last_sep = true;
        } else {
            out.push(c);
            last_sep = false;
        }
    }
    out
}

fn bare(id: &str) -> String {
    id.split_once(':').map_or(id, |(_, rest)| rest).trim().to_ascii_uppercase()
}

/// OSV's distro records are named `DEBIAN-CVE-2024-1234`,
/// `UBUNTU-CVE-…`, `ALPINE-CVE-…`: the CVE inside is the identity every
/// other tool uses, so both forms are kept.
fn with_embedded_cve(ids: &mut BTreeSet<String>) {
    let extra: Vec<String> = ids.iter().filter_map(|id| id.find("-CVE-").map(|at| id[at + 1..].to_string())).collect();
    ids.extend(extra);
}

// ---- uniflow side ------------------------------------------------------

fn from_findings(findings: &[uniflow_sca_core::DependencyFinding], out: &mut Vec<Obs>) {
    for f in findings {
        let mut ids: BTreeSet<String> = f.cve_ids.iter().map(|i| bare(i)).collect();
        ids.insert(bare(&f.rule_id));
        with_embedded_cve(&mut ids);
        if let Some(os) = &f.os {
            ids.extend(os.advisory_ids.iter().map(|i| bare(i)));
            // Other tools report OS vulnerabilities per *binary* package;
            // uniflow per source package with its binaries listed.
            let names: Vec<&String> = if os.binaries.is_empty() { vec![&f.package] } else { os.binaries.iter().collect() };
            for name in names {
                out.push(Obs { package: normalize_package(name), version: os.installed_version.clone(), ids: ids.clone() });
            }
        } else {
            out.push(Obs { package: normalize_package(&f.package), version: f.version.clone(), ids });
        }
    }
}

fn scan_uniflow(input: &Path, db: &VulnDb) -> Result<(Vec<Obs>, Option<String>)> {
    let mut obs = Vec::new();
    if input.is_dir() {
        let result = uniflow_sca_orchestrator::scan_directory_with_vuln_db(input, db)?;
        from_findings(&result.dependency_findings, &mut obs);
        return Ok((obs, None));
    }
    let image = uniflow_container_image::squash_image(input, &Default::default())?;
    let root = image.root.path();
    let app = uniflow_sca_orchestrator::scan_root_filesystem_with_vuln_db(root, db)?;
    from_findings(&app.dependency_findings, &mut obs);
    let inventory = uniflow_os_package_db::inventory(root);
    let mut distro_key = None;
    if let Some(distro) = &inventory.distro {
        let lookup = db.lookup_os(&distro.data_keys(), &distro.key(), &distro.label(), "", &inventory.packages);
        from_findings(&lookup.findings, &mut obs);
        distro_key = Some(format!("{} ({} packages, data {})", distro.key(), inventory.packages.len(), lookup.data_source.unwrap_or_else(|| "none".into())));
    }
    Ok((obs, distro_key))
}

// ---- other tools -------------------------------------------------------

fn parse_trivy(value: &serde_json::Value, out: &mut Vec<Obs>) {
    for result in value["Results"].as_array().into_iter().flatten() {
        for v in result["Vulnerabilities"].as_array().into_iter().flatten() {
            let (Some(name), Some(id)) = (v["PkgName"].as_str(), v["VulnerabilityID"].as_str()) else { continue };
            let mut ids: BTreeSet<String> = [bare(id)].into();
            ids.extend(v["VendorIDs"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).map(bare));
            with_embedded_cve(&mut ids);
            out.push(Obs { package: normalize_package(name), version: v["InstalledVersion"].as_str().unwrap_or("").into(), ids });
        }
    }
}

fn parse_grype(value: &serde_json::Value, out: &mut Vec<Obs>) {
    for m in value["matches"].as_array().into_iter().flatten() {
        let (Some(name), Some(id)) = (m["artifact"]["name"].as_str(), m["vulnerability"]["id"].as_str()) else { continue };
        let mut ids: BTreeSet<String> = [bare(id)].into();
        ids.extend(m["relatedVulnerabilities"].as_array().into_iter().flatten().filter_map(|r| r["id"].as_str()).map(bare));
        with_embedded_cve(&mut ids);
        out.push(Obs { package: normalize_package(name), version: m["artifact"]["version"].as_str().unwrap_or("").into(), ids });
    }
}

fn parse_osv_scanner(value: &serde_json::Value, out: &mut Vec<Obs>) {
    for result in value["results"].as_array().into_iter().flatten() {
        for pkg in result["packages"].as_array().into_iter().flatten() {
            let Some(name) = pkg["package"]["name"].as_str() else { continue };
            let version = pkg["package"]["version"].as_str().unwrap_or("").to_string();
            for v in pkg["vulnerabilities"].as_array().into_iter().flatten() {
                let Some(id) = v["id"].as_str() else { continue };
                let mut ids: BTreeSet<String> = [bare(id)].into();
                ids.extend(v["aliases"].as_array().into_iter().flatten().filter_map(|a| a.as_str()).map(bare));
                with_embedded_cve(&mut ids);
                out.push(Obs { package: normalize_package(name), version: version.clone(), ids });
            }
        }
    }
}

fn load_other(tool: &str, path: &Path) -> Result<Vec<Obs>> {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?).with_context(|| format!("parsing {}", path.display()))?;
    let mut out = Vec::new();
    match tool {
        "trivy" => parse_trivy(&value, &mut out),
        "grype" => parse_grype(&value, &mut out),
        _ => parse_osv_scanner(&value, &mut out),
    }
    Ok(out)
}

// ---- comparison --------------------------------------------------------

/// Collapses a tool's observations to one entry per (package, vuln
/// cluster): tools list the same CVE once per matched advisory, installed
/// copy or layer, and raw counts would compare noise.
fn dedupe(obs: Vec<Obs>) -> Vec<Obs> {
    let mut by_pkg: BTreeMap<String, Vec<Obs>> = BTreeMap::new();
    for o in obs {
        let list = by_pkg.entry(o.package.clone()).or_default();
        if let Some(existing) = list.iter_mut().find(|e| !e.ids.is_disjoint(&o.ids)) {
            existing.ids.extend(o.ids);
        } else {
            list.push(o);
        }
    }
    by_pkg.into_values().flatten().collect()
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub both: usize,
    pub cosmos_only: usize,
    pub other_only: usize,
    /// Share of the other tool's findings Cosmos also reports.
    pub agreement_with_other: Option<f64>,
    pub triage: BTreeMap<String, usize>,
    /// A few `(package, ids)` per triage bucket, for manual review.
    pub samples: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct InputResult {
    pub input: String,
    pub cosmos_findings: usize,
    pub cosmos_seconds: f64,
    pub distro: Option<String>,
    pub tools: BTreeMap<String, Option<Comparison>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScaResult {
    pub snapshot_records: usize,
    pub inputs: Vec<InputResult>,
    pub totals: BTreeMap<String, Comparison>,
    pub notes: Vec<String>,
}

const SAMPLES_PER_BUCKET: usize = 8;

fn compare(cosmos: &[Obs], other: &[Obs], known_ids: &HashMap<String, BTreeSet<String>>) -> Comparison {
    let mut result = Comparison::default();
    let sample = |bucket: &str, o: &Obs, result: &mut Comparison| {
        *result.triage.entry(bucket.to_string()).or_default() += 1;
        let list = result.samples.entry(bucket.to_string()).or_default();
        if list.len() < SAMPLES_PER_BUCKET {
            list.push(format!("{}@{} {}", o.package, o.version, o.ids.iter().take(3).cloned().collect::<Vec<_>>().join("/")));
        }
    };
    for o in other {
        if cosmos.iter().any(|c| c.package == o.package && !c.ids.is_disjoint(&o.ids)) {
            result.both += 1;
        } else {
            result.other_only += 1;
            let in_data = known_ids.get(&o.package).is_some_and(|ids| !ids.is_disjoint(&o.ids));
            sample(if in_data { "data-present-unmatched" } else { "data-absent" }, o, &mut result);
        }
    }
    for c in cosmos {
        if !other.iter().any(|o| o.package == c.package && !o.ids.is_disjoint(&c.ids)) {
            result.cosmos_only += 1;
            sample("cosmos-only", c, &mut result);
        }
    }
    let other_total = result.both + result.other_only;
    result.agreement_with_other = (other_total > 0).then(|| result.both as f64 / other_total as f64);
    result
}

fn add(total: &mut Comparison, c: &Comparison) {
    total.both += c.both;
    total.cosmos_only += c.cosmos_only;
    total.other_only += c.other_only;
    for (k, v) in &c.triage {
        *total.triage.entry(k.clone()).or_default() += v;
    }
    for (k, v) in &c.samples {
        let list = total.samples.entry(k.clone()).or_default();
        for s in v {
            if list.len() < SAMPLES_PER_BUCKET * 3 {
                list.push(s.clone());
            }
        }
    }
    let other_total = total.both + total.other_only;
    total.agreement_with_other = (other_total > 0).then(|| total.both as f64 / other_total as f64);
}

pub fn run(corpus: &Path, snapshot: &Path, others: &Path) -> Result<ScaResult> {
    eprintln!("loading {}", snapshot.display());
    let text = std::fs::read_to_string(snapshot).with_context(|| format!("reading {}", snapshot.display()))?;
    let mut records: Vec<VulnRecord> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if let Ok(record) = serde_json::from_str::<VulnRecord>(line) {
            records.push(record);
        }
    }
    drop(text);
    // package -> every id/alias Cosmos has for it: the triage oracle.
    let mut known_ids: HashMap<String, BTreeSet<String>> = HashMap::new();
    for r in &records {
        let ids = known_ids.entry(normalize_package(&r.package)).or_default();
        ids.insert(bare(&r.id));
        ids.extend(r.aliases.iter().map(|a| bare(a)));
    }
    let snapshot_records = records.len();
    let db = VulnDb::from_records(records);

    let mut inputs: Vec<std::path::PathBuf> = std::fs::read_dir(corpus)?.flatten().map(|e| e.path()).filter(|p| p.is_dir() || p.extension().is_some_and(|e| e == "tar")).collect();
    inputs.sort();
    let mut result = ScaResult { snapshot_records, ..Default::default() };
    for input in inputs {
        // Directories by full name (`alacritty-0.4.0` has no extension to
        // strip); image tarballs without `.tar`.
        let name = if input.is_dir() { input.file_name() } else { input.file_stem() }.and_then(|s| s.to_str()).unwrap_or("?").to_string();
        eprintln!("  sca {name}");
        let started = Instant::now();
        let (cosmos, distro) = match scan_uniflow(&input, &db) {
            Ok(pair) => pair,
            Err(error) => {
                result.notes.push(format!("{name}: uniflow scan failed: {error:#}"));
                continue;
            }
        };
        let cosmos = dedupe(cosmos);
        let mut row = InputResult { input: name.clone(), cosmos_findings: cosmos.len(), cosmos_seconds: started.elapsed().as_secs_f64(), distro, tools: BTreeMap::new() };
        for tool in TOOLS {
            let path = others.join(tool).join(format!("{name}.json"));
            let comparison = match load_other(tool, &path) {
                Ok(obs) => Some(compare(&cosmos, &dedupe(obs), &known_ids)),
                Err(error) => {
                    result.notes.push(format!("{name}/{tool}: no usable result ({error:#})"));
                    None
                }
            };
            if let Some(c) = &comparison {
                add(result.totals.entry(tool.to_string()).or_default(), c);
            }
            row.tools.insert(tool.to_string(), comparison);
        }
        result.inputs.push(row);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(p: &str, ids: &[&str]) -> Obs {
        Obs { package: normalize_package(p), version: "1".into(), ids: ids.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn alias_aware_comparison_and_triage() {
        let cosmos = vec![obs("PyYAML", &["GHSA-8Q59-Q68H-6HV4", "CVE-2020-14343"]), obs("lodash", &["CVE-2021-23337"])];
        let other = vec![obs("pyyaml", &["CVE-2020-14343"]), obs("requests", &["CVE-2023-32681"]), obs("urllib3", &["CVE-2099-0001"])];
        let mut known = HashMap::new();
        known.insert("requests".to_string(), BTreeSet::from(["CVE-2023-32681".to_string()]));
        let c = compare(&cosmos, &other, &known);
        assert_eq!((c.both, c.other_only, c.cosmos_only), (1, 2, 1));
        assert_eq!(c.triage["data-present-unmatched"], 1);
        assert_eq!(c.triage["data-absent"], 1);
        assert_eq!(normalize_package("Foo_Bar.baz"), "foo-bar-baz");
        assert_eq!(normalize_package("com.thoughtworks.xstream:xstream"), normalize_package("xstream"));
    }

    #[test]
    fn dedupe_merges_repeated_reports_of_one_vulnerability() {
        let merged = dedupe(vec![obs("openssl", &["CVE-1"]), obs("openssl", &["CVE-1", "DSA-9"]), obs("openssl", &["CVE-2"])]);
        assert_eq!(merged.len(), 2);
    }
}
