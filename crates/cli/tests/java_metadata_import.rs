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
fn java_baseline_metadata_import_preserves_matchers_and_source_message_ids() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(
        std::env::temp_dir().join(format!("uniflow-java-text-{}-{nonce}", std::process::id())),
    );
    std::fs::create_dir(&scratch.0).unwrap();
    let knowledge = scratch.0.join("knowledge");
    std::fs::create_dir(&knowledge).unwrap();
    std::fs::write(
        knowledge.join("knowledge.yml"),
        r#"
BugInfos:
  BugInfo:
  - id: '00001'
    Categories:
      Category: [{type: DetailClassChin, value: 检查调用}]
    Description: 原始说明。
    Advice: 原始建议。
    References:
      Reference: [{type: CWE, value: '89:SQL Injection'}]
"#,
    )
    .unwrap();
    let input = scratch.0.join("native.yml");
    let original = r#"
id: test-java
title: Java source metadata import
rules:
- id: JAVA-TEST
  title: Existing title
  languages: [java]
  severity: error
  confidence: high
  matcher: {callee: dangerous, min_args: 1, non_literal_args: [0]}
  standards: [LEGACY-MSG-00001]
  message: Existing reviewed message.
"#;
    std::fs::write(&input, original).unwrap();
    let output = scratch.0.join("enriched.yml");
    let audit = scratch.0.join("audit.json");
    let result = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["enrich-legacy-jvm-baseline", "--input"])
        .arg(&input)
        .arg("--knowledge")
        .arg(&knowledge)
        .arg("--output")
        .arg(&output)
        .arg("--metadata-report-out")
        .arg(&audit)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let enriched: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(output).unwrap()).unwrap();
    let original: serde_yaml::Value = serde_yaml::from_str(original).unwrap();
    for field in [
        "id",
        "title",
        "languages",
        "severity",
        "confidence",
        "matcher",
        "message",
    ] {
        assert_eq!(enriched["rules"][0][field], original["rules"][0][field]);
    }
    assert_eq!(
        enriched["rules"][0]["translations"]["zh-CN"]["message"].as_str(),
        Some("原始说明。\n\n原始建议。")
    );
    assert_eq!(
        enriched["rules"][0]["translations"]["zh-TW"]["message"].as_str(),
        Some("原始說明。\n\n原始建議。")
    );
    assert_eq!(
        enriched["rules"][0]["translations"]["en"]["message"].as_str(),
        Some("Existing reviewed message.")
    );
    assert_eq!(enriched["rules"][0]["cwe"][0].as_str(), Some("CWE-89"));
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(audit).unwrap()).unwrap();
    assert_eq!(report["enriched_sinks"], 1);
    assert_eq!(report["traditional_chinese_messages"], 1);
    assert_eq!(report["source_traditional_chinese_messages"], 0);
}

#[test]
fn java_ast_original_knowledge_text_executes_from_isolated_bundle() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-java-knowledge-bundle-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("Lock.java");
    std::fs::write(
        &fixture,
        "class A { Object lock = new Object(); void f() { synchronized(lock) { work(); } } }",
    )
    .unwrap();
    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "java", "--input"])
        .arg(fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "LEGACY-JAVA-AST-sync-object-is-final")
        .unwrap();
    assert_eq!(
        finding["translations"]["zh-CN"]["title"],
        "【强制】不要基于非final对象进行同步"
    );
    assert!(finding["translations"]["zh-CN"]["message"]
        .as_str()
        .is_some_and(|message| !message.is_empty()));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(finding["translations"][locale]["title"]
            .as_str()
            .is_some_and(|title| !title.is_empty()));
        assert!(finding["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
    assert_ne!(
        finding["translations"]["zh-CN"]["message"],
        finding["translations"]["zh-TW"]["message"]
    );
    assert!(!scratch.0.join("rules").exists());
}
