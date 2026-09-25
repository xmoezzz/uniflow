//! Regression tests for the dependency reconciliation pass: lockfile
//! versions over manifest ranges, `direct` + introduction paths, dedup
//! identity, and warnings for what a scan could not check.
use uniflow_sca_core::Severity;
use uniflow_sca_orchestrator::scan_directory_with_vuln_db;
use uniflow_vuln_db::{VulnDb, VulnRecord};

fn record(ecosystem: &str, package: &str, range: &str) -> VulnRecord {
    VulnRecord {
        id: format!("osv:TEST-{package}"),
        aliases: vec![],
        ecosystem: ecosystem.into(),
        package: package.into(),
        severity: Severity::High,
        summary: "test".into(),
        cwe: vec![],
        vulnerable_range: range.into(),
        affected_symbols: vec![],
        fixed_versions: vec![],
        epss: None,
        kev: false,
        fix_state: None,
        distro_severity: None,
        references: Vec::new(),
    }
}

fn write(dir: &std::path::Path, rel: &str, body: &str) {
    let path = dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

const LOCK: &str = r#"{"name":"shop","lockfileVersion":3,"packages":{
  "":{"dependencies":{"express":"^4.0.0"}},
  "node_modules/express":{"version":"4.17.1","dependencies":{"qs":"6.7.0"}},
  "node_modules/qs":{"version":"6.7.0"}}}"#;

#[test]
fn lockfile_version_wins_over_manifest_range_without_duplicate_findings() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "package.json", r#"{"dependencies":{"express":"^4.0.0"}}"#);
    write(dir.path(), "package-lock.json", LOCK);
    let db = VulnDb::from_records(vec![record("npm", "express", "<4.18.0"), record("npm", "qs", "<6.10.3")]);
    let result = scan_directory_with_vuln_db(dir.path(), &db).unwrap();

    // Regression: package.json `^4.0.0` and package-lock `4.17.1` used to
    // produce two express findings (one against version "4.0.0").
    let express: Vec<_> = result.dependency_findings.iter().filter(|f| f.package == "express").collect();
    assert_eq!(express.len(), 1, "{express:#?}");
    assert_eq!(express[0].version, "4.17.1");
    assert!(express[0].direct);

    let qs = result.dependency_findings.iter().find(|f| f.package == "qs").unwrap();
    assert!(!qs.direct, "qs only arrives through express");
    assert_eq!(qs.dependency_path, vec!["shop", "express@4.17.1", "qs@6.7.0"]);
}

#[test]
fn the_same_package_in_two_services_is_two_findings() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "svc-a/package-lock.json", LOCK);
    write(dir.path(), "svc-b/package-lock.json", LOCK);
    let db = VulnDb::from_records(vec![record("npm", "qs", "<6.10.3")]);
    let result = scan_directory_with_vuln_db(dir.path(), &db).unwrap();
    assert_eq!(result.dependency_findings.len(), 2);
}

#[test]
fn go_sum_is_ignored_when_go_mod_is_present() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "go.mod", "module x\n\nrequire golang.org/x/net v0.23.0\n");
    // go.sum also lists an old version consulted during resolution.
    write(dir.path(), "go.sum", "golang.org/x/net v0.7.0 h1:x=\ngolang.org/x/net v0.23.0 h1:y=\n");
    let db = VulnDb::from_records(vec![record("go", "golang.org/x/net", "<0.17.0")]);
    let result = scan_directory_with_vuln_db(dir.path(), &db).unwrap();
    assert!(result.dependency_findings.is_empty(), "{:#?}", result.dependency_findings);
}

#[test]
fn unparseable_manifests_unpinned_versions_and_uncovered_ecosystems_are_reported() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "requirements.txt", "PyYAML\n");
    write(dir.path(), "Cargo.lock", "this is [[ not toml");
    write(dir.path(), "Berksfile.lock", "DEPENDENCIES\n  nginx\n\nGRAPH\n  nginx (2.7.6)\n");
    let db = VulnDb::from_records(vec![record("pypi", "pyyaml", "<5.4")]);
    let result = scan_directory_with_vuln_db(dir.path(), &db).unwrap();
    let kinds: Vec<&str> = result.warnings.iter().map(|w| w.kind.as_str()).collect();
    assert!(kinds.contains(&"manifest_parse_error"), "{:#?}", result.warnings);
    assert!(kinds.contains(&"unresolved_version"), "{:#?}", result.warnings);
    assert!(kinds.contains(&"no_advisory_data"), "{:#?}", result.warnings);
}
