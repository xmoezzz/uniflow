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
fn sql_forms_reference_rule_executes_from_bundle_with_metadata() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-sql-forms-bundle-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("form.sql");
    std::fs::write(
        &fixture,
        "BEGIN find_alert('missing'); find_alert('known'); go_item('MAIN.missing'); go_item('MAIN.known'); END;\n",
    )
    .unwrap();
    let metadata = scratch.0.join("forms-metadata.json");
    std::fs::write(
        &metadata,
        r#"{"alerts":["known"],"blocks":[{"name":"MAIN","items":["known"]}],"lovs":[]}"#,
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
        .arg("--forms-metadata")
        .arg(&metadata)
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
        .filter(|finding| finding["rule_id"] == "LEGACY-SQL-InvalidReferenceToObject")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 2, "{findings:#?}");
    assert!(
        matches.iter().any(|finding| finding["message"]
            .as_str()
            .is_some_and(|message| message.contains("missing") && message.contains("FIND_ALERT"))),
        "{matches:#?}"
    );
    assert!(
        matches.iter().any(|finding| {
            finding["message"].as_str().is_some_and(|message| {
                message.contains("MAIN.missing") && message.contains("GO_ITEM")
            })
        }),
        "{matches:#?}"
    );
}
