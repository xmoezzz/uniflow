//! Per-language fixture repos: each checks the three core verdicts plus
//! evidence shape. Built in temp dirs so the fixtures live next to their
//! assertions.
use std::path::Path;
use uniflow_sca_core::{Confidence, DependencyFinding, EvidenceKind, ReachabilityLevel, Severity};
use uniflow_sca_reachability::{analyze, Options};

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

fn finding(ecosystem: &str, package: &str, symbols: &[&str], direct: bool) -> DependencyFinding {
    DependencyFinding {
        rule_id: format!("osv:TEST-{package}"),
        title: "t".into(),
        severity: Severity::High,
        ecosystem: ecosystem.into(),
        package: package.into(),
        version: "1.0.0".into(),
        vulnerable_range: "<2".into(),
        recommended_version: Some("2.0.0".into()),
        manifest_path: "m".into(),
        cve_ids: vec![],
        cwe: vec![],
        message: "m".into(),
        direct,
        dependency_path: vec![],
        affected_symbols: symbols.iter().map(|s| s.to_string()).collect(),
        fixed_versions: vec![],
        epss: None,
        kev: false,
        reachability: None,
        risk: None,
        os: None,
    }
}

fn run(root: &Path, findings: &mut [DependencyFinding]) {
    analyze(root, findings, &Options::default());
}

fn level(f: &DependencyFinding) -> ReachabilityLevel {
    f.reachability.as_ref().unwrap().level
}

#[test]
fn python() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "app/main.py", "from app.util import parse\n\ndef main():\n    parse(input())\n\nif __name__ == '__main__':\n    main()\n");
    write(root, "app/util.py", "import yaml\nfrom requests import Session\n\ndef parse(s):\n    return yaml.load(s)\n\ndef fetch():\n    return Session()\n");
    write(root, "tests/test_x.py", "import pytest_mock\n");
    // Installed library code must never count as first-party usage.
    write(root, ".venv/lib/python3.12/site-packages/jinja2/__init__.py", "import markupsafe\nmarkupsafe.escape(x)\n");
    let mut findings = vec![
        finding("pypi", "PyYAML", &["yaml.load"], true),
        finding("pypi", "requests", &["requests.get"], true),
        finding("pypi", "markupsafe", &["markupsafe.escape"], false),
        finding("pypi", "pytest-mock", &[], true),
        finding("pypi", "urllib3", &[], false),
    ];
    run(root, &mut findings);

    let yaml = findings[0].reachability.as_ref().unwrap();
    assert_eq!(yaml.level, ReachabilityLevel::Reachable, "{yaml:#?}");
    assert_eq!(yaml.confidence, Confidence::High, "HIR confirms the resolved call");
    let call = yaml.evidence.iter().find(|e| e.kind == EvidenceKind::Call).unwrap();
    assert_eq!((call.path.as_str(), call.line), ("app/util.py", 5));
    assert_eq!(call.matched_symbol.as_deref(), Some("yaml.load"));
    assert_eq!(call.snippet.as_deref(), Some("return yaml.load(s)"));
    assert!(call.call_path.len() >= 2, "call path from an entry point: {:?}", call.call_path);
    assert!(call.call_path.last().unwrap().contains("yaml.load"));

    assert_eq!(level(&findings[1]), ReachabilityLevel::Imported, "Session is used, requests.get is not");
    assert_eq!(level(&findings[2]), ReachabilityLevel::Unreachable, "only .venv code uses markupsafe");
    assert_eq!(level(&findings[3]), ReachabilityLevel::Unreachable, "test-only usage");
    assert!(findings[3].reachability.as_ref().unwrap().reason.contains("test"));
    assert_eq!(level(&findings[4]), ReachabilityLevel::Unreachable);
    assert!(findings[4].reachability.as_ref().unwrap().reason.contains("transitive"));
    assert!(findings.iter().all(|f| f.risk.is_some()));
    assert!(findings[0].risk.as_ref().unwrap().score > findings[4].risk.as_ref().unwrap().score);
}

#[test]
fn javascript_and_typescript() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "src/index.ts", "import { template } from 'lodash';\nimport merge from 'lodash/merge';\nimport * as qs from 'qs';\nexport function render(x: string) {\n  return template(x)();\n}\nexport const m = merge({}, qs.stringify({}));\n");
    write(root, "node_modules/minimist/index.js", "module.exports = function () {};\n");
    write(root, "src/cli.js", "const { format } = require('date-fns');\nformat(new Date());\n");
    let mut findings = vec![
        finding("npm", "lodash", &["lodash.template"], true),
        finding("npm", "qs", &["qs.parse"], true),
        finding("npm", "minimist", &[], false),
        finding("npm", "date-fns", &["format"], true),
    ];
    run(root, &mut findings);
    assert_eq!(level(&findings[0]), ReachabilityLevel::Reachable, "{:#?}", findings[0].reachability);
    assert_eq!(level(&findings[1]), ReachabilityLevel::Imported);
    assert_eq!(level(&findings[2]), ReachabilityLevel::Unreachable);
    assert_eq!(level(&findings[3]), ReachabilityLevel::Reachable, "a bare advisory symbol is qualified with the package");
}

#[test]
fn java() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "src/main/java/com/acme/Api.java",
        "package com.acme;\nimport org.apache.commons.text.StringSubstitutor;\nimport com.fasterxml.jackson.databind.ObjectMapper;\npublic class Api {\n  public String run(String s) throws Exception {\n    new ObjectMapper().readValue(s, Object.class);\n    return StringSubstitutor.replaceSystemProperties(s);\n  }\n}\n",
    );
    write(root, "src/test/java/com/acme/ApiTest.java", "package com.acme;\nimport org.yaml.snakeyaml.Yaml;\nclass ApiTest { void t() { new Yaml().load(\"x\"); } }\n");
    let mut findings = vec![
        finding("maven", "org.apache.commons:commons-text", &["org.apache.commons.text.StringSubstitutor"], true),
        finding("maven", "com.fasterxml.jackson.core:jackson-databind", &["com.fasterxml.jackson.databind.ObjectMapper.readValue"], true),
        finding("maven", "org.yaml:snakeyaml", &["org.yaml.snakeyaml.Yaml.load"], true),
        finding("maven", "org.apache.logging.log4j:log4j-core", &[], false),
    ];
    run(root, &mut findings);
    assert_eq!(level(&findings[0]), ReachabilityLevel::Reachable);
    let jackson = findings[1].reachability.as_ref().unwrap();
    assert_eq!(jackson.level, ReachabilityLevel::Reachable, "constructor-chained call via method-name fallback: {jackson:#?}");
    assert_eq!(level(&findings[2]), ReachabilityLevel::Unreachable, "snakeyaml only in src/test");
    assert_eq!(level(&findings[3]), ReachabilityLevel::Unreachable);
    assert_eq!(findings[3].reachability.as_ref().unwrap().confidence, Confidence::High, "log4j-core mapping is curated");
}

#[test]
fn go() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "go.mod", "module example.com/app\n");
    write(root, "cmd/server/main.go", "package main\n\nimport (\n\t\"fmt\"\n\tjwt \"github.com/dgrijalva/jwt-go\"\n\t\"golang.org/x/net/html\"\n)\n\nfunc handle(t string) {\n\tjwt.Parse(t, nil)\n\tfmt.Println(html.EscapeString(t))\n}\n\nfunc main() { handle(\"x\") }\n");
    write(root, "vendor/golang.org/x/text/x.go", "package text\n");
    let mut findings = vec![
        finding("go", "github.com/dgrijalva/jwt-go", &["github.com/dgrijalva/jwt-go.Parse"], true),
        finding("go", "golang.org/x/net", &["golang.org/x/net/html.Parse"], true),
        finding("go", "golang.org/x/text", &["golang.org/x/text/language.Parse"], false),
    ];
    run(root, &mut findings);
    let jwt = findings[0].reachability.as_ref().unwrap();
    assert_eq!(jwt.level, ReachabilityLevel::Reachable, "{jwt:#?}");
    assert_eq!(jwt.evidence.iter().find(|e| e.kind == EvidenceKind::Call).unwrap().line, 10);
    assert_eq!(level(&findings[1]), ReachabilityLevel::Imported, "html imported but html.Parse not called");
    assert_eq!(level(&findings[2]), ReachabilityLevel::Unreachable, "vendored copy doesn't count");
}

#[test]
fn rust() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "src/main.rs", "use hyper::Server;\nuse tokio_util::codec::Framed;\n\nfn serve() {\n    let _ = time::now();\n    Server::bind(&addr);\n}\n\nfn main() { serve() }\n");
    let mut findings = vec![
        finding("cargo", "time", &["time::now", "time::at"], false),
        finding("cargo", "hyper", &["hyper::body::to_bytes"], true),
        finding("cargo", "tokio-util", &[], true),
        finding("cargo", "smallvec", &["smallvec::SmallVec::insert_many"], false),
    ];
    run(root, &mut findings);
    assert_eq!(level(&findings[0]), ReachabilityLevel::Reachable, "path call without `use`: {:#?}", findings[0].reachability);
    assert_eq!(level(&findings[1]), ReachabilityLevel::Imported);
    assert_eq!(level(&findings[2]), ReachabilityLevel::Imported, "crate name `-` → `_`");
    assert_eq!(level(&findings[3]), ReachabilityLevel::Unreachable);
}

#[test]
fn unanalyzable_cases_are_unknown_not_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "app.py", "print(1)\n");
    let mut findings = vec![finding("nuget", "Newtonsoft.Json", &[], true), finding("npm", "lodash", &[], true)];
    run(dir.path(), &mut findings);
    assert_eq!(level(&findings[0]), ReachabilityLevel::Unknown);
    assert_eq!(level(&findings[1]), ReachabilityLevel::Unknown, "no JS source at all → can't say");
}

#[test]
fn results_are_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..30 {
        write(dir.path(), &format!("pkg/m{i}.py"), "import yaml\nyaml.load(x)\n");
    }
    let render = || {
        let mut findings = vec![finding("pypi", "pyyaml", &["yaml.load"], true)];
        run(dir.path(), &mut findings);
        serde_json::to_string(&findings[0].reachability).unwrap()
    };
    assert_eq!(render(), render());
}
