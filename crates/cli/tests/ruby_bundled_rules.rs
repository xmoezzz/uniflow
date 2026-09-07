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
fn ruby_search_rules_execute_from_bundle_without_rule_directory() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-ruby-bundle-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("RubyLegacySearchRules.rb");
    std::fs::write(&fixture, include_str!("fixtures/RubyLegacySearchRules.rb")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "ruby", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings
        .iter()
        .filter_map(|finding| finding["rule_id"].as_str())
        .collect::<HashSet<_>>();
    let migrated = uniflow_baseline::bundled_semgrep_rules()
        .iter()
        .filter(|rule| rule.language == "ruby")
        .filter_map(|rule| rule.native_rule_id)
        .collect::<HashSet<_>>();
    assert_eq!(migrated.len(), 30);
    for rule_id in migrated {
        assert!(ids.contains(rule_id), "missing {rule_id}: {ids:#?}");
    }
}
