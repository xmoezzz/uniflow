use serde::{Deserialize, Serialize};
use std::path::Path;
use uniflow_archive_extract::{extract_archives_recursively, ExtractOptions};
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
use uniflow_sca_core::{Dependency, DependencyFinding, ManifestParser, MalwareFinding};
use uniflow_vuln_db::VulnDb;

const IGNORED_DIRS: &[&str] = &["node_modules", "target", ".git", "vendor", "dist", "build"];

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

    let mut dependencies = Vec::new();
    let mut malware_findings = Vec::new();
    let mut license_findings = Vec::new();
    scan_one_root(root, &parsers, &mut dependencies, &mut malware_findings, &mut license_findings);

    let mut archives_extracted = 0;
    if let Some((guard, report)) =
        extract_archives_recursively(&[root.to_path_buf()], &ExtractOptions::default())
            .map_err(|error| anyhow::anyhow!("archive extraction failed: {error:#}"))?
    {
        archives_extracted = report.archives_found;
        scan_one_root(
            &report.extraction_root,
            &parsers,
            &mut dependencies,
            &mut malware_findings,
            &mut license_findings,
        );
        drop(guard);
    }

    let dependency_findings = dependencies
        .iter()
        .flat_map(|dependency| vuln_db.lookup(dependency))
        .collect();

    Ok(ScaScanResult {
        dependencies,
        dependency_findings,
        malware_findings,
        license_findings,
        archives_extracted,
    })
}

fn scan_one_root(
    root: &Path,
    parsers: &[Box<dyn ManifestParser>],
    dependencies: &mut Vec<Dependency>,
    malware_findings: &mut Vec<MalwareFinding>,
    license_findings: &mut Vec<LicenseFinding>,
) {
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
                if let Ok(deps) = parser.parse(path) {
                    dependencies.extend(deps);
                }
            }
        }

        if is_license_file_name(file_name) {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Some(finding) = scan_text(&path.display().to_string(), &text) {
                    license_findings.push(finding);
                }
            }
            continue;
        }

        if matches!(detect(path), Ok(FileKind::Text)) {
            if let Ok(source) = std::fs::read_to_string(path) {
                malware_findings.extend(scan_source(&path.display().to_string(), &source));
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
