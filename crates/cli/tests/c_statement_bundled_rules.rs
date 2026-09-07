use std::{collections::HashSet, path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn c_statement_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-c-statements-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("CStatementRules.c");
    std::fs::write(&fixture, include_str!("fixtures/CStatementRules.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"]).arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings.iter().filter_map(|finding| finding["rule_id"].as_str()).collect::<HashSet<_>>();
    for suffix in ["if-else-braces", "loop-body-braces", "if-else-if-must-have-else", "no-empty-switch",
        "switch-must-have-case", "no-empty-statement", "no-semicolon-after-for-if-while",
        "no-break-in-loops", "no-constant-in-loop-condition"] {
        assert!(ids.contains(format!("LEGACY-C-AST-{suffix}").as_str()), "missing {suffix}: {ids:#?}");
    }
}
