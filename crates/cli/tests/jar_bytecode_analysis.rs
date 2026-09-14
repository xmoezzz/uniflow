//! End-to-end coverage for JAR ingestion: a taint rule pack written against
//! ordinary fully-qualified Java call names must trace a finding entirely
//! through classes decoded from a `.jar` archive, with no `.java` source
//! anywhere in the project. This proves `uniflow_lang_java_bytecode`'s
//! `Callee::Static` naming convention lines up with the existing Java rule
//! matcher (`exact: com.example.Sink.write`) unchanged.

use std::{
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
const APP_WAR: &[u8] = include_bytes!("../../lang_java_bytecode/tests/fixtures/app.war");
const PLAIN_CLASS: &[u8] = include_bytes!("../../lang_java_bytecode/tests/fixtures/Plain.class");

const RULES_YAML: &str = r#"
sources:
  - id: jar-source
    language: java
    matcher:
      exact: com.example.Source.read
    out: return
    kind: untrusted

sinks:
  - id: jar-sink
    language: java
    matcher:
      exact: com.example.Sink.write
    inputs: [arg0]
    kind: untrusted
"#;

const PLAIN_CLASS_RULES_YAML: &str = r#"
sources:
  - id: class-source
    language: java
    matcher:
      exact: Plain.source
    out: return
    kind: untrusted

sinks:
  - id: class-sink
    language: java
    matcher:
      exact: Plain.sink
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
fn jar_archive_taint_finding_traces_entirely_through_decoded_bytecode() {
    let project = Scratch(scratch("jar-analysis"));
    std::fs::write(project.0.join("lib.jar"), LIB_JAR).expect("write jar fixture");

    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");
    let sarif_path = project.0.join("out.sarif.json");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "java", "--input"])
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

    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&sarif_path).expect("read sarif output"),
    )
    .expect("sarif is valid JSON");
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("sarif has a results array");
    assert!(!results.is_empty(), "{sarif:#?}");

    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "jar-source"
            && finding["sink_rule_id"] == "jar-sink"),
        "{findings:#?}"
    );
    // Provenance survives into the reported location: it must point back
    // into the jar entry that calls the sink (`App.run`), not a bare class
    // name or filesystem path with no archive context.
    assert!(
        findings.iter().any(|finding| finding["sink_location"]
            .as_str()
            .is_some_and(|location| location.contains("lib.jar!com/example/App.class"))),
        "{findings:#?}"
    );
}

#[test]
fn war_archive_with_nested_lib_is_scanned_end_to_end() {
    let project = Scratch(scratch("war-analysis"));
    std::fs::write(project.0.join("app.war"), APP_WAR).expect("write war fixture");

    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "java", "--input"])
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
    assert!(stdout.contains("jar-source"), "{stdout}");
    assert!(stdout.contains("jar-sink"), "{stdout}");
}

#[test]
fn standalone_classfile_is_scanned_without_packaging_a_jar() {
    let project = Scratch(scratch("class-analysis"));
    std::fs::create_dir_all(project.0.join("build/classes")).expect("create class output tree");
    std::fs::write(project.0.join("build/classes/Plain.class"), PLAIN_CLASS)
        .expect("write class fixture");
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, PLAIN_CLASS_RULES_YAML).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "java", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run analyze-project");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "class-source"
            && finding["sink_rule_id"] == "class-sink"
            && finding["sink_location"]
                .as_str()
                .is_some_and(|location| location.ends_with("build/classes/Plain.class"))),
        "{findings:#?}"
    );
}
