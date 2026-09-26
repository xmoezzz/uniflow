pub mod graph;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use uniflow_archive_extract::{extract_archives_recursively, ExtractOptions};
mod installed;
use uniflow_deps_cargo::CargoParser;
use uniflow_deps_chef::BerkshelfParser;
use uniflow_deps_cocoapods::CocoaPodsParser;
use uniflow_deps_conan::ConanParser;
use uniflow_deps_cran::RenvParser;
use uniflow_deps_dart::PubParser;
use uniflow_deps_dotnet::NuGetParser;
use uniflow_deps_elm::ElmParser;
use uniflow_deps_fortran::FpmParser;
use uniflow_deps_go::GoParser;
use uniflow_deps_gradle::GradleLockParser;
use uniflow_deps_haxelib::HaxelibParser;
use uniflow_deps_maven::MavenParser;
use uniflow_deps_npm::NpmParser;
use uniflow_deps_opam::OpamParser;
use uniflow_deps_php::ComposerParser;
use uniflow_deps_python::PythonParser;
use uniflow_deps_ruby::BundlerParser;
use uniflow_deps_swift::SwiftPmParser;
use uniflow_filetype::{detect, FileKind};
use uniflow_license_scan::{is_license_file_name, scan_text, LicenseFinding};
use uniflow_malware_heuristics::scan_source;
use uniflow_sca_core::{Dependency, DependencyFinding, ManifestParser, MalwareFinding, ScanWarning};
use uniflow_vuln_db::{normalize_ecosystem, normalize_package_name, VulnDb};

const IGNORED_DIRS: &[&str] = &[
    "node_modules", "target", ".git", "vendor", "dist", "build",
    // Python virtualenvs/tool caches hold *installed* third-party code;
    // scanning them double-counts dependencies and runs the malware
    // heuristics over every library's own source.
    ".venv", "venv", ".tox", "__pycache__", "site-packages",
];

/// Lockfiles (resolved versions) per ecosystem. When one of these sits
/// next to a manifest of the same ecosystem, the lockfile's versions win —
/// the manifest's `^4.17.15`-style ranges only name a *minimum*, and
/// reporting both used to produce a duplicate (and often wrong-version)
/// finding for every package.
const LOCKFILES: &[(&str, &[&str])] = &[
    ("npm", &["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]),
    ("cargo", &["Cargo.lock"]),
    ("pypi", &["poetry.lock", "Pipfile.lock", "uv.lock"]),
    ("go", &["go.mod"]),
    // Resolved versions win over the `*.csproj` PackageReferences next to it.
    ("nuget", &["packages.lock.json"]),
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScaScanResult {
    pub dependencies: Vec<Dependency>,
    pub dependency_findings: Vec<DependencyFinding>,
    pub malware_findings: Vec<MalwareFinding>,
    pub license_findings: Vec<LicenseFinding>,
    /// How many archives (zip/tar/7z/deb/rpm/cab/...) were found and
    /// unpacked under `root` before scanning — 0 if none were found, or if
    /// extraction stopped early against its safety budget (see
    /// `uniflow_archive_extract::ExtractionReport::truncated`).
    pub archives_extracted: usize,
    /// What the scan couldn't fully do — surfaced rather than swallowed.
    #[serde(default)]
    pub warnings: Vec<ScanWarning>,
}

fn manifest_parsers() -> Vec<Box<dyn ManifestParser>> {
    vec![
        Box::new(NpmParser),
        Box::new(CargoParser),
        Box::new(PythonParser),
        Box::new(GoParser),
        Box::new(ComposerParser),
        Box::new(NuGetParser),
        Box::new(BundlerParser),
        Box::new(MavenParser),
        Box::new(GradleLockParser),
        Box::new(PubParser),
        Box::new(CocoaPodsParser),
        Box::new(ConanParser),
        Box::new(RenvParser),
        Box::new(BerkshelfParser),
        Box::new(ElmParser),
        Box::new(FpmParser),
        Box::new(HaxelibParser),
        Box::new(OpamParser),
        Box::new(SwiftPmParser),
    ]
}

/// Walks `root`, plus — if any zip/tar/7z/deb/rpm/cab/... archive is found
/// anywhere under it — the recursively-extracted content of those archives
/// too (see `uniflow_archive_extract`; this is the same "scan inside
/// archives" capability `sca-main` had, now pure-Rust with no external
/// `7z`/`unshield`/`unpack200` process). The extraction scratch directory is
/// deleted once this function returns.
pub fn scan_directory(root: &Path) -> anyhow::Result<ScaScanResult> {
    scan_directory_with_vuln_db(root, &VulnDb::load_embedded())
}

/// Same as [`scan_directory`], but against a caller-supplied vuln database —
/// used by `cosmos-agent`, which loads whatever `vulndb sync` last cached
/// locally (the org's real OSV/NVD-sourced, shield/revise-customized set)
/// instead of this crate's tiny built-in fallback seed.
pub fn scan_directory_with_vuln_db(root: &Path, vuln_db: &VulnDb) -> anyhow::Result<ScaScanResult> {
    let parsers = manifest_parsers();

    let mut collected = Collected::default();
    scan_one_root(root, &parsers, &mut collected);

    let mut archives_extracted = 0;
    if let Some((guard, report)) =
        extract_archives_recursively(&[root.to_path_buf()], &ExtractOptions::default())
            .map_err(|error| anyhow::anyhow!("archive extraction failed: {error:#}"))?
    {
        archives_extracted = report.archives_found;
        scan_one_root(&report.extraction_root, &parsers, &mut collected);
        drop(guard);
    }

    let Collected { dependencies, malware_findings, license_findings, mut warnings, graphs, declared } = collected;
    let dependencies = reconcile_dependencies(dependencies, &declared, &graphs);
    let dependency_findings = match_dependencies(&dependencies, vuln_db, &graphs, &mut warnings);

    Ok(ScaScanResult {
        dependencies,
        dependency_findings,
        malware_findings,
        license_findings,
        archives_extracted,
        warnings,
    })
}

/// [`scan_directory_with_vuln_db`] for a *root filesystem* (a squashed
/// container image, or a host): manifests and lockfiles found anywhere in
/// it, plus language packages that are installed rather than declared —
/// `site-packages`, `node_modules`, jars, Go/Rust binaries (see
/// `installed`). An installed package already reported from a lockfile at
/// the same version is not reported twice.
pub fn scan_root_filesystem_with_vuln_db(root: &Path, vuln_db: &VulnDb) -> anyhow::Result<ScaScanResult> {
    let mut result = scan_directory_with_vuln_db(root, vuln_db)?;
    let (found, mut warnings) = installed::inventory(root);
    let known: HashSet<(String, String, String)> = result
        .dependencies
        .iter()
        .map(|d| (normalize_ecosystem(&d.ecosystem), normalize_package_name(&d.ecosystem, &d.name), d.version.clone()))
        .collect();
    let mut added: HashSet<(String, String, String)> = HashSet::new();
    let new: Vec<Dependency> = found
        .into_iter()
        .filter(|d| {
            let key = (normalize_ecosystem(&d.ecosystem), normalize_package_name(&d.ecosystem, &d.name), d.version.clone());
            !known.contains(&key) && added.insert(key)
        })
        .collect();
    let findings = match_dependencies(&new, vuln_db, &BTreeMap::new(), &mut warnings);
    result.dependencies.extend(new);
    result.dependency_findings.extend(findings);
    result.warnings.extend(warnings);
    Ok(result)
}

#[derive(Default)]
struct Collected {
    dependencies: Vec<Dependency>,
    malware_findings: Vec<MalwareFinding>,
    license_findings: Vec<LicenseFinding>,
    warnings: Vec<ScanWarning>,
    /// Lockfile graphs keyed by (ecosystem, directory).
    graphs: BTreeMap<(String, PathBuf), graph::LockGraph>,
    /// Manifest-declared direct names keyed by (ecosystem, directory).
    declared: BTreeMap<(String, PathBuf), BTreeSet<String>>,
}

fn manifest_dir(manifest_path: &str) -> PathBuf {
    Path::new(manifest_path).parent().map(Path::to_path_buf).unwrap_or_default()
}

fn manifest_file_name(manifest_path: &str) -> &str {
    Path::new(manifest_path).file_name().and_then(|n| n.to_str()).unwrap_or_default()
}

fn is_lockfile(ecosystem: &str, file_name: &str) -> bool {
    LOCKFILES.iter().any(|(eco, files)| *eco == ecosystem && files.contains(&file_name))
}

/// Turns the raw per-manifest dependency lists into one list per
/// directory: lockfile versions preferred over manifest ranges, `go.sum`
/// dropped when `go.mod` is present (go.sum lists every version *ever*
/// consulted during module resolution, not the ones selected — it was a
/// steady source of findings against versions the build doesn't use),
/// `direct` set from manifests + lockfile roots, exact duplicates removed.
fn reconcile_dependencies(
    dependencies: Vec<Dependency>,
    declared: &BTreeMap<(String, PathBuf), BTreeSet<String>>,
    graphs: &BTreeMap<(String, PathBuf), graph::LockGraph>,
) -> Vec<Dependency> {
    let mut has_lock: HashSet<(String, PathBuf)> = HashSet::new();
    let mut locked_names: HashSet<(String, PathBuf, String)> = HashSet::new();
    let mut has_go_mod: HashSet<PathBuf> = HashSet::new();
    for dep in &dependencies {
        let eco = normalize_ecosystem(&dep.ecosystem);
        let dir = manifest_dir(&dep.manifest_path);
        let file = manifest_file_name(&dep.manifest_path);
        if file == "go.mod" {
            has_go_mod.insert(dir.clone());
        }
        if is_lockfile(&eco, file) {
            locked_names.insert((eco.clone(), dir.clone(), normalize_package_name(&eco, &dep.name)));
            has_lock.insert((eco, dir));
        }
    }

    let mut seen: HashSet<(String, String, String, String)> = HashSet::new();
    let mut out = Vec::with_capacity(dependencies.len());
    for mut dep in dependencies {
        let eco = normalize_ecosystem(&dep.ecosystem);
        let dir = manifest_dir(&dep.manifest_path);
        let file = manifest_file_name(&dep.manifest_path);
        let name_key = normalize_package_name(&eco, &dep.name);
        if file == "go.sum" && has_go_mod.contains(&dir) {
            continue;
        }
        let from_lock = is_lockfile(&eco, file);
        if !from_lock
            && has_lock.contains(&(eco.clone(), dir.clone()))
            && locked_names.contains(&(eco.clone(), dir.clone(), name_key.clone()))
        {
            // The lockfile entry for this name carries the real version;
            // this manifest line only contributes "it's direct" (below).
            continue;
        }
        let dir_key = (eco.clone(), dir.clone());
        if declared.get(&dir_key).is_some_and(|names| names.contains(&name_key))
            || graphs.get(&dir_key).is_some_and(|g| g.direct.contains(&name_key))
        {
            dep.direct = true;
        }
        // Identity includes the manifest path: the same package@version in
        // two services' lockfiles is two things to fix, not one.
        if seen.insert((eco, name_key, dep.version.clone(), dep.manifest_path.clone())) {
            out.push(dep);
        }
    }
    out
}

fn match_dependencies(
    dependencies: &[Dependency],
    vuln_db: &VulnDb,
    graphs: &BTreeMap<(String, PathBuf), graph::LockGraph>,
    warnings: &mut Vec<ScanWarning>,
) -> Vec<DependencyFinding> {
    if vuln_db.skipped_lines() > 0 {
        warnings.push(ScanWarning::new(
            "vulndb_lines_skipped",
            None,
            format!("{} vulnerability-database lines could not be parsed and were ignored", vuln_db.skipped_lines()),
            &[("count", vuln_db.skipped_lines().to_string())],
        ));
    }

    let mut findings = Vec::new();
    let mut seen: HashSet<(String, String, String, String, String)> = HashSet::new();
    let mut uncovered: BTreeMap<String, usize> = BTreeMap::new();
    for dependency in dependencies {
        let eco = normalize_ecosystem(&dependency.ecosystem);
        if !vuln_db.covers_ecosystem(&eco) {
            *uncovered.entry(eco).or_default() += 1;
            continue;
        }
        let outcome = vuln_db.lookup_detailed(dependency);
        if let Some(count) = outcome.unresolved_advisories {
            warnings.push(ScanWarning::new(
                "unresolved_version",
                Some(dependency.manifest_path.clone()),
                format!(
                    "{} has {count} known advisor{} but its version {:?} is not pinned/parseable, so it could not be checked — pin it or commit a lockfile",
                    dependency.name,
                    if count == 1 { "y" } else { "ies" },
                    dependency.version
                ),
                &[("package", dependency.name.clone()), ("version", dependency.version.clone()), ("count", count.to_string())],
            ));
        }
        let graph = graphs.get(&(eco.clone(), manifest_dir(&dependency.manifest_path)));
        for mut finding in outcome.findings {
            if let Some(path) = graph.and_then(|g| g.path_to(&dependency.name)) {
                // A two-element path (root → package) means the lockfile
                // itself records it as a root dependency.
                finding.direct |= path.len() == 2;
                finding.dependency_path = path;
            }
            // The package is part of the identity: one advisory routinely
            // covers several packages at the same version (GHSA-968p-4wvh-cqc8
            // for @babel/runtime *and* -corejs2/-corejs3; lodash and
            // lodash-es), and each is its own thing to upgrade.
            if seen.insert((finding.rule_id.clone(), eco.clone(), normalize_package_name(&eco, &finding.package), finding.version.clone(), finding.manifest_path.clone())) {
                findings.push(finding);
            }
        }
    }
    for (eco, count) in uncovered {
        warnings.push(ScanWarning::new(
            "no_advisory_data",
            None,
            format!("{count} {eco} dependencies were not checked: the vulnerability database has no {eco} advisories (sync it, or this ecosystem has no feed)"),
            &[("count", count.to_string()), ("ecosystem", eco.clone())],
        ));
    }
    findings
}

fn scan_one_root(root: &Path, parsers: &[Box<dyn ManifestParser>], collected: &mut Collected) {
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| !is_ignored_dir(entry.path()))
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();

        for parser in parsers {
            if parser.matches_file_name(file_name) {
                match parser.parse(path) {
                    Ok(deps) => collected.dependencies.extend(deps),
                    Err(error) => collected.warnings.push(ScanWarning::new(
                        "manifest_parse_error",
                        Some(path.display().to_string()),
                        format!("could not parse {file_name}: {error:#}"),
                        &[("file", file_name.to_string()), ("error", format!("{error:#}"))],
                    )),
                }
            }
        }
        let dir = path.parent().map(Path::to_path_buf).unwrap_or_default();
        if let Some(lock_graph) = graph::read_lock_graph(path) {
            collected.graphs.insert((lock_graph.ecosystem.clone(), dir.clone()), lock_graph);
        }
        if let Some((eco, names)) = graph::declared_direct_names(path) {
            collected
                .declared
                .entry((eco.to_string(), dir))
                .or_default()
                .extend(names.iter().map(|name| normalize_package_name(eco, name)));
        }

        if is_license_file_name(file_name) {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Some(finding) = scan_text(&path.display().to_string(), &text) {
                    collected.license_findings.push(finding);
                }
            }
            continue;
        }

        if matches!(detect(path), Ok(FileKind::Text)) {
            if let Ok(source) = std::fs::read_to_string(path) {
                collected.malware_findings.extend(scan_source(&path.display().to_string(), &source));
            }
        }
    }
}

fn is_ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| IGNORED_DIRS.contains(&name))
        .unwrap_or(false)
}
