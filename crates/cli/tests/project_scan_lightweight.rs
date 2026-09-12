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
fn project_scan_avoids_heap_closure_without_a_modeled_taint_sink() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-project-scan-lightweight-{}-{nonce}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).expect("create temporary project");
    std::fs::write(
        scratch.0.join("first.js"),
        "function make(value) { return { value }; }",
    )
    .expect("write first source");
    std::fs::write(
        scratch.0.join("second.js"),
        "function consume(item) { return item.value; }",
    )
    .expect("write second source");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "javascript", "--input"])
        .arg(&scratch.0)
        .arg("--dump-stats")
        .output()
        .expect("run project scan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("CLI output is UTF-8");
    assert!(stdout.contains("\"files\": 2"), "{stdout}");
    assert!(stdout.contains("\"synthetic_sinks\": 0"), "{stdout}");
    assert!(stdout.contains("\"object_shape_paths\": 0"), "{stdout}");
    assert!(stdout.contains("\"memory_regions\": 0"), "{stdout}");
}
