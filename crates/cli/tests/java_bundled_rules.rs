use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn java_structural_rules_execute_from_bundle_without_rule_directory() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-java-bundle-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("JavaStructuralRules.java");
    std::fs::write(&fixture, include_str!("fixtures/JavaStructuralRules.java")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["check-baseline", "--language", "java", "--input"])
        .arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings.iter().filter_map(|f| f["rule_id"].as_str()).collect::<HashSet<_>>();
    for suffix in ["empty-block", "empty-if-block", "empty-else-block", "empty-loop-block",
        "empty-method-block", "empty-sync-block", "empty-try-block", "empty-infinity-loop",
        "empty-infinity-loop-ydt", "error-cond-stmt", "invalid-semicolon", "error-block",
        "switch-default", "error-compare", "float-loop-var", "float-loop-var-ydt"]
    {
        assert!(ids.contains(format!("LEGACY-JAVA-AST-{suffix}").as_str()), "missing {suffix}: {ids:#?}");
    }
    assert!(findings.iter().all(|f| f["line"].as_u64().is_some_and(|line| line > 0)));
}
