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
fn sql_xpath_template_executes_from_bundle_and_rejects_invalid_queries() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-sql-xpath-bundle-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("xpath.sql");
    std::fs::write(
        &fixture,
        "SELECT one FROM dual;\nUPDATE sample SET value = 1;\n",
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
        .args(["check-baseline", "--language", "sql", "--input"])
        .arg(&fixture)
        .args([
            "--sql-xpath-query",
            "//STATEMENT",
            "--sql-xpath-message",
            "Avoid statements",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matches = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "LEGACY-SQL-XPath")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert!(matches
        .iter()
        .all(|finding| finding["message"] == "Avoid statements"));

    let invalid = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "sql", "--input"])
        .arg(&fixture)
        .args(["--sql-xpath-query", "+++"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid SQL XPath query"));
}
