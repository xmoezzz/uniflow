use std::{collections::HashSet, path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn csharp_legacy_rules_execute_from_bundle_without_rule_directory() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-csharp-bundle-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("CSharpLegacyRules.cs");
    std::fs::write(&fixture, include_str!("fixtures/CSharpLegacyRules.cs")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["check-baseline", "--language", "csharp", "--input"])
        .arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings.iter().filter_map(|finding| finding["rule_id"].as_str()).collect::<HashSet<_>>();
    let inventory = uniflow_baseline::bundled_csharp_ast_rules();
    assert_eq!(inventory.len(), 33);
    for rule in inventory {
        let native = rule.native_rule_id.expect("C# migration is executable");
        assert!(ids.contains(native), "missing {native}: {ids:#?}");
    }
    assert!(findings.iter().all(|finding| finding["line"].as_u64().is_some_and(|line| line > 0)));
}
