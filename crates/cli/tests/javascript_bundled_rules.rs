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
fn javascript_structural_search_rules_execute_from_bundle_without_rule_directory() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-javascript-bundle-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("JavaScriptLegacySearchRules.js");
    std::fs::write(
        &fixture,
        include_str!("fixtures/JavaScriptLegacySearchRules.js"),
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("JavaScriptLegacySearchRules.mustache"),
        include_str!("fixtures/JavaScriptLegacySearchRules.mustache"),
    )
    .unwrap();
    std::fs::write(
        scratch.0.join("JavaScriptLegacySearchRules.pug"),
        include_str!("fixtures/JavaScriptLegacySearchRules.pug"),
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
        .args(["check-baseline", "--language", "javascript", "--input"])
        .arg(&scratch.0)
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
    for rule_id in [
        "LEGACY-JS-SEMGREP-detect-angular-sce-disabled",
        "LEGACY-JS-SEMGREP-wildcard-postmessage-configuration",
        "LEGACY-JS-SEMGREP-detect-pseudoRandomBytes",
        "LEGACY-JS-SEMGREP-javascript_buf_rule-buffer-noassert",
        "LEGACY-JS-SEMGREP-eval-detected",
        "LEGACY-JS-SEMGREP-prohibit-jquery-html",
        "LEGACY-JS-SEMGREP-no-replaceall",
        "LEGACY-JS-SEMGREP-javascript_require_rule-non-literal-require",
        "LEGACY-JS-SEMGREP-javascript-alert",
        "LEGACY-JS-SEMGREP-javascript-confirm",
        "LEGACY-JS-SEMGREP-javascript-prompt",
        "LEGACY-JS-SEMGREP-javascript-debugger",
        "LEGACY-JS-SEMGREP-insecure-createnodesfrommarkup",
        "LEGACY-JS-SEMGREP-detect-buffer-noassert",
        "LEGACY-JS-SEMGREP-javascript_random_rule-pseudo-random-bytes",
        "LEGACY-JS-SEMGREP-mustache-explicit-unescape",
        "LEGACY-JS-SEMGREP-pug-explicit-unescape",
        "LEGACY-JS-SEMGREP-pug-var-in-script-tag",
        "LEGACY-JS-SEMGREP-detect-angular-open-redirect",
        "LEGACY-JS-SEMGREP-insecure-innerhtml",
        "LEGACY-JS-SEMGREP-detect-disable-mustache-escape",
        "LEGACY-JS-SEMGREP-assigned-undefined",
        "LEGACY-JS-SEMGREP-detect-replaceall-sanitization",
        "LEGACY-JS-SEMGREP-incomplete-sanitization",
    ] {
        assert!(ids.contains(rule_id), "missing {rule_id}: {ids:#?}");
    }
}
