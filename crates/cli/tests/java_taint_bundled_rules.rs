use std::{path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn java_legacy_sql_taint_executes_from_isolated_binary() {
    let rule = "legacy.java.sink.bc4f4fcb-12de-41ab-81d6-6d9915c0e93e.0";
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-java-taint-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let source = include_str!("fixtures/JavaLegacyExpressionRules.java");
    let fixture = scratch.0.join("JavaLegacyExpressionRules.java");
    std::fs::write(&fixture, source).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["analyze-source", "--language", "java", "--use-default-models", "--rule-id", rule, "--input"])
        .arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    let sql = findings.iter().filter(|finding| finding["sink_rule_id"] == rule).collect::<Vec<_>>();
    assert!(!sql.is_empty(), "missing bundled SQL rule: {findings:#?}");
    let tainted_line = source.lines().position(|line| line.contains("// tainted-sink")).unwrap() + 1;
    assert!(sql.iter().all(|finding| finding["sink_location"].as_str()
        .is_some_and(|location| location.contains(&format!(".java:{tainted_line}:")))), "{sql:#?}");
    assert!(sql.iter().any(|finding| finding["source_rule_id"] == "legacy.java.source.ef3204b8-093b-4fa9-9b52-dc06e3e75533.0.web"));
    assert!(sql.iter().all(|finding| ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
        finding["translations"][locale]["title"].as_str().is_some_and(|title| !title.is_empty())
            && finding["translations"][locale]["message"].as_str().is_some_and(|message| !message.is_empty())
    })));
}

#[test]
fn java_check_return_value_executes_from_isolated_binary() {
    let rule = "legacy.java.sink._check_return_value.0";
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-java-unused-return-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("CheckReturn.java");
    std::fs::write(
        &fixture,
        "class CheckReturn { void f(java.io.File file) { file.mkdir(); } }",
    )
    .unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args([
            "analyze-source",
            "--language",
            "java",
            "--use-default-models",
            "--rule-id",
            rule,
            "--input",
        ])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == rule)
            .count(),
        1,
        "{findings:#?}"
    );
    assert_eq!(
        findings[0]["source_rule_id"],
        "legacy.java.source.0674ea59-fe26-4a9b-8ee1-f810fb139d41.0._check_return_value"
    );
}
