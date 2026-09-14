//! Coding-style/baseline checking must follow the same polyglot project
//! routing as taint analysis: no source file may be parsed by another
//! language's frontend, and findings from all groups must be returned in one
//! JSON report.

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

#[test]
fn mixed_baseline_scan_reports_c_and_ruby_bundled_rules() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let project = Scratch(std::env::temp_dir().join(format!(
        "uniflow-mixed-baseline-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir(&project.0).expect("create temporary project");
    std::fs::write(
        project.0.join("legacy.c"),
        include_str!("fixtures/CDeclarationRules.c"),
    )
    .expect("write C fixture");
    std::fs::write(
        project.0.join("legacy.rb"),
        include_str!("fixtures/RubyLegacySearchRules.rb"),
    )
    .expect("write Ruby fixture");

    // No `--language`: coding-style checking defaults to the same polyglot
    // routing mode as dataflow analysis.
    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["check-baseline", "--input"])
        .arg(&project.0)
        .output()
        .expect("run mixed baseline scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    let ids = findings
        .iter()
        .filter_map(|finding| finding["rule_id"].as_str())
        .collect::<HashSet<_>>();
    assert!(
        ids.contains("LEGACY-C-AST-void-fn-must-not-return-value"),
        "missing C result: {ids:#?}"
    );
    assert!(
        ids.iter().any(|id| id.starts_with("LEGACY-RUBY-")),
        "missing Ruby result: {ids:#?}"
    );
}

#[test]
fn mixed_baseline_scans_java_auxiliary_rules_without_java_source_files() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let project = Scratch(std::env::temp_dir().join(format!(
        "uniflow-mixed-java-config-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir_all(&project.0).expect("create temporary project");
    std::fs::write(
        project.0.join("AndroidManifest.xml"),
        r#"<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:debuggable="true" android:allowBackup="false"/>
</manifest>"#,
    )
    .expect("write Android manifest fixture");

    // No `--language java` and no Java source file: configuration-only
    // projects must still execute Java's bundled structured baseline rules.
    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["check-baseline", "--input"])
        .arg(&project.0)
        .output()
        .expect("run mixed baseline configuration scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| {
            finding["rule_id"] == "LEGACY-JAVA-RULEMAP-android-debuggable-manifest"
                && finding["path"]
                    .as_str()
                    .is_some_and(|path| path.ends_with("AndroidManifest.xml"))
        }),
        "{findings:#?}"
    );
}
