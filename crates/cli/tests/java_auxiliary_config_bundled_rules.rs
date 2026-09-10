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

#[test]
fn java_baseline_discovers_bundled_android_manifest_rules() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-java-config-{}-{unique}",
        std::process::id()
    )));
    let source_dir = scratch.0.join("app/src/main/java/example");
    let manifest_dir = scratch.0.join("app/src/main");
    std::fs::create_dir_all(&source_dir).unwrap();
    std::fs::write(
        source_dir.join("Application.java"),
        "package example; class Application {}",
    )
    .unwrap();
    std::fs::write(
        manifest_dir.join("AndroidManifest.xml"),
        r#"<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example">
  <application android:debuggable="true" android:allowBackup="false"/>
</manifest>"#,
    )
    .unwrap();

    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "java", "--input"])
        .arg(&scratch.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    let debug = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "LEGACY-JAVA-RULEMAP-android-debuggable-manifest")
        .collect::<Vec<_>>();
    assert_eq!(debug.len(), 1, "{findings:#?}");
    assert!(debug[0]["path"]
        .as_str()
        .is_some_and(|path| path.ends_with("AndroidManifest.xml")));
    assert!(!findings
        .iter()
        .any(|finding| { finding["rule_id"] == "LEGACY-JAVA-RULEMAP-android-backup-enabled" }));
}
