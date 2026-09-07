use std::{collections::HashSet, path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn c_preprocessor_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-c-macros-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("CMacroRules.c");
    std::fs::write(&fixture, include_str!("fixtures/CMacroRules.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"]).arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings.iter().filter_map(|finding| finding["rule_id"].as_str()).collect::<HashSet<_>>();
    for suffix in ["function-like-macros-must-have-braces", "no-redefine-keyword", "no-concat-in-macros",
        "no-concat-twice-in-macros", "no-macro-to-basic-type", "no-semicolon-after-macro"] {
        let native = format!("LEGACY-C-AST-{suffix}");
        assert!(ids.contains(native.as_str()), "missing {suffix}: {ids:#?}");
        let finding = findings.iter().find(|finding| finding["rule_id"] == native).unwrap();
        for locale in ["zh-CN", "en", "zh-TW"] {
            assert!(finding["translations"][locale]["message"].as_str().is_some_and(|message| !message.is_empty()));
        }
    }
}
