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
fn tainted_loop_variable_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-tainted-loop-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).expect("create scratch directory");
    let fixture = scratch.0.join("TaintedLoopVariable.c");
    std::fs::write(&fixture, include_str!("fixtures/TaintedLoopVariable.c"))
        .expect("write fixture");
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).expect("copy binary");
    let sarif = scratch.0.join("findings.sarif");

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["analyze-project", "--language", "c", "--input"])
        .arg(&fixture)
        .arg("--sarif-out")
        .arg(&sarif)
        .output()
        .expect("run isolated binary");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&sarif).expect("read SARIF"),
    )
    .expect("valid SARIF");
    let findings = document["runs"][0]["results"]
        .as_array()
        .expect("SARIF results");
    let finding = findings
        .iter()
        .find(|finding| finding["ruleId"] == "ANZU-TAINTED-LOOP-VARIABLE")
        .expect("bundled tainted loop rule finding");
    let standards = finding["properties"]["standards"]
        .as_array()
        .expect("standards");
    assert!(standards.iter().any(|item| item == "0201000010120027"));
}
