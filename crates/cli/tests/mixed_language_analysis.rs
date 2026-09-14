//! `analyze-project` defaults `--language` to `mix`: each file is routed to
//! its own frontend by extension and analyzed as an independent
//! per-language group (a mixed project is never fed to one parser). This
//! proves a single scan over a Python file, a Java file, and a `.jar`
//! archive produces taint findings attributable to every group, merged
//! into one SARIF report.

use std::{
    collections::HashSet,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const LIB_JAR: &[u8] = include_bytes!("../../lang_java_bytecode/tests/fixtures/lib.jar");

const RULES_YAML: &str = r#"
sources:
  - id: py-source
    language: python
    matcher:
      contains: taint_source_py
    out: return
    kind: untrusted
  - id: java-source
    language: java
    matcher:
      exact: App.source
    out: return
    kind: untrusted
  - id: jar-source
    language: java
    matcher:
      exact: com.example.Source.read
    out: return
    kind: untrusted

sinks:
  - id: py-sink
    language: python
    matcher:
      contains: taint_sink_py
    inputs: [arg0]
    kind: untrusted
  - id: java-sink
    language: java
    matcher:
      exact: App.sink
    inputs: [arg0]
    kind: untrusted
  - id: jar-sink
    language: java
    matcher:
      exact: com.example.Sink.write
    inputs: [arg0]
    kind: untrusted
"#;

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uniflow-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).expect("create temporary project");
    dir
}

#[test]
fn mix_is_the_default_language_and_scans_every_frontend_independently() {
    let project = Scratch(scratch("mixed-analysis"));
    std::fs::write(
        project.0.join("app.py"),
        "def taint_source_py():\n    return input()\n\n\ndef taint_sink_py(x):\n    print(x)\n\n\ndef run():\n    taint_sink_py(taint_source_py())\n",
    )
    .expect("write python fixture");
    std::fs::write(
        project.0.join("App.java"),
        "class App {\n    static String source() { return System.getenv(\"X\"); }\n    static void sink(String s) { System.out.println(s); }\n    static void run() { sink(source()); }\n}\n",
    )
    .expect("write java fixture");
    std::fs::write(project.0.join("lib.jar"), LIB_JAR).expect("write jar fixture");

    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");
    let sarif_path = project.0.join("out.sarif.json");

    // No `--language` at all: `analyze-project` must default to `mix`.
    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--sarif-out")
        .arg(&sarif_path)
        .output()
        .expect("run analyze-project");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    let sink_ids: Vec<&str> = findings
        .iter()
        .filter_map(|finding| finding["sink_rule_id"].as_str())
        .collect();
    assert!(sink_ids.contains(&"py-sink"), "{findings:#?}");
    assert!(sink_ids.contains(&"java-sink"), "{findings:#?}");
    assert!(sink_ids.contains(&"jar-sink"), "{findings:#?}");

    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&sarif_path).expect("read sarif output"),
    )
    .expect("sarif is valid JSON");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("sarif has a results array");
    assert!(results.len() >= 3, "{sarif:#?}");
}

#[test]
fn explicit_mix_language_flag_is_accepted() {
    let project = Scratch(scratch("mixed-explicit"));
    std::fs::write(
        project.0.join("app.py"),
        "def taint_source_py():\n    return input()\n\n\ndef taint_sink_py(x):\n    print(x)\n\n\ndef run():\n    taint_sink_py(taint_source_py())\n",
    )
    .expect("write python fixture");

    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--pretty-findings")
        .output()
        .expect("run analyze-project");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("py-sink"), "{stdout}");
}

#[test]
fn mix_hir_dump_keeps_the_frontend_payload_path() {
    let project = Scratch(scratch("mixed-hir-dump"));
    std::fs::write(
        project.0.join("app.py"),
        "def taint_source_py():\n    return input()\n\n\ndef taint_sink_py(x):\n    print(x)\n\n\ndef run():\n    taint_sink_py(taint_source_py())\n",
    )
    .expect("write python fixture");
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");
    let sarif_path = project.0.join("out.sarif.json");

    // The normal mixed scan reuses the system-boundary pre-pass IR.  HIR
    // output is intentionally different: it must retain the frontend
    // program so callers receive the complete source-level payload.
    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--dump-hir")
        .arg("--sarif-out")
        .arg(&sarif_path)
        .output()
        .expect("run mixed HIR dump analysis");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"language\": \"python\""), "{stdout}");
    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&sarif_path).expect("read SARIF output"),
    )
    .expect("SARIF is valid JSON");
    assert!(
        sarif["runs"][0]["results"]
            .as_array()
            .is_some_and(|results| !results.is_empty()),
        "{sarif:#?}"
    );
}

#[test]
fn default_mix_scans_a_pure_jar_project_without_java_source_files() {
    let project = Scratch(scratch("mixed-jar-only"));
    std::fs::write(project.0.join("dependency.jar"), LIB_JAR).expect("write jar fixture");

    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");

    // No `--language` and no `.java` source: archive discovery itself must
    // create the Java group in mixed mode.
    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run mixed jar scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "jar-source"
            && finding["sink_rule_id"] == "jar-sink"),
        "{findings:#?}"
    );
}

#[test]
fn mixed_project_cache_reuses_each_language_group() {
    let project = Scratch(scratch("mixed-cache"));
    std::fs::write(
        project.0.join("app.py"),
        "def taint_source_py():\n    return input()\n\ndef taint_sink_py(value):\n    print(value)\n\ndef run():\n    taint_sink_py(taint_source_py())\n",
    )
    .expect("write Python fixture");
    std::fs::write(
        project.0.join("App.java"),
        "class App { static String source() { return System.getenv(\"X\"); } static void sink(String value) {} static void run() { sink(source()); } }\n",
    )
    .expect("write Java fixture");
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");
    let cache_path = project.0.join("mixed-cache.json");

    let first = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--cache-out")
        .arg(&cache_path)
        .output()
        .expect("create mixed cache");
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    let cache: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&cache_path).expect("read mixed cache"),
    )
    .expect("mixed cache is JSON");
    assert!(cache["groups"]["python"].is_object(), "{cache:#?}");
    assert!(cache["groups"]["java"].is_object(), "{cache:#?}");

    let sarif_path = project.0.join("cached.sarif.json");
    let second = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--cache-in")
        .arg(&cache_path)
        .arg("--dump-cache-plan")
        .arg("--sarif-out")
        .arg(&sarif_path)
        .output()
        .expect("reuse mixed cache");
    assert!(second.status.success(), "{}", String::from_utf8_lossy(&second.stderr));
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(stdout.contains("\"python\""), "{stdout}");
    assert!(stdout.contains("\"java\""), "{stdout}");
    assert!(stdout.contains("\"reused\""), "{stdout}");
    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&sarif_path).expect("read cached SARIF"),
    )
    .expect("cached scan writes SARIF");
    assert!(
        sarif["runs"][0]["results"]
            .as_array()
            .is_some_and(|results| results.len() >= 2),
        "{sarif:#?}"
    );
}

#[test]
fn mix_routes_every_product_language_into_the_unified_taint_engine() {
    let project = Scratch(scratch("mixed-all-languages"));
    let cases = [
        ("c", "flow.c", "char *taint_source(void); void sink(char *); void run(void) { char *value = taint_source(); sink(value); }"),
        ("cpp", "flow.cpp", "char *taint_source(); void sink(char *); void run() { auto value = taint_source(); sink(value); }"),
        ("csharp", "Flow.cs", "class Flow { void Run() { var value = taint_source(); sink(value); } }"),
        ("objc", "flow.m", "char *taint_source(void); void sink(char *); void run(void) { char *value = taint_source(); sink(value); }"),
        ("objcpp", "flow.mm", "char *taint_source(); void sink(char *); void run() { auto value = taint_source(); sink(value); }"),
        ("java", "Flow.java", "class Flow { static String taint_source() { return \"\"; } static void sink(String value) {} static void run() { sink(taint_source()); } }"),
        ("python", "flow.py", "def run():\n    value = taint_source()\n    sink(value)\n"),
        ("kotlin", "flow.kt", "fun run() { val value = taint_source(); sink(value) }"),
        // Go now goes through the real `gosyn`-backed `uniflow_lang_go`
        // frontend (see `crates/frontend/src/parse.rs`), which requires a
        // real `package` clause up front — the old generic descriptor
        // engine this used to route through was tolerant of a bare
        // C-family-shaped snippet, but real Go source never is.
        ("go", "flow.go", "package main\n\nfunc run() {\n\tvalue := taint_source()\n\tsink(value)\n}\n"),
        ("javascript", "flow.js", "function run() { const value = taint_source(); sink(value); }"),
        ("jsp", "flow.jsp", "<% void run() { String value = taint_source(); sink(value); } %>"),
        ("sql", "flow.sql", "SELECT secret;\nUPDATE secret SET value = secret;"),
        ("php", "flow.php", "<?php function run() { $value = taint_source(); sink($value); } ?>"),
        ("ruby", "flow.rb", "def run\n  value = taint_source()\n  sink(value)\nend\n"),
        ("rust", "flow.rs", "fn run() { let value = taint_source(); sink(value); }"),
        ("shell", "flow.sh", "function run() { local value=taint_source marker\n  sink $value\n}"),
        ("swift", "flow.swift", "func run() { let value = taint_source(); sink(value) }"),
    ];
    let mut rules = String::from("sources:\n");
    for (language, _, _) in cases {
        let method_name = if language == "sql" { "select" } else { "taint_source" };
        rules.push_str(&format!(
            "  - id: matrix-source-{language}\n    language: {language}\n    matcher:\n      method_name: {method_name}\n    out: return\n    kind: untrusted\n"
        ));
    }
    rules.push_str("sinks:\n");
    for (language, _, _) in cases {
        let method_name = if language == "sql" { "update" } else { "sink" };
        rules.push_str(&format!(
            "  - id: matrix-sink-{language}\n    language: {language}\n    matcher:\n      method_name: {method_name}\n    inputs: [arg0]\n    kind: untrusted\n"
        ));
    }
    for (_, path, source) in cases {
        std::fs::write(project.0.join(path), source).expect("write mixed language fixture");
    }
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, rules).expect("write matrix rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run all-language mixed analysis");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    let sink_ids = findings
        .iter()
        .filter_map(|finding| finding["sink_rule_id"].as_str())
        .collect::<HashSet<_>>();
    for (language, _, _) in cases {
        assert!(
            sink_ids.contains(format!("matrix-sink-{language}").as_str()),
            "{language} did not reach the mixed CLI taint pipeline: {findings:#?}"
        );
    }
}
