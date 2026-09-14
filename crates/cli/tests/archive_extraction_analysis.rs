//! `analyze-project` has no archive-extraction flag: recursive extraction of
//! zip/tar (+ gzip/bzip2/xz/zstd) archives found under the scan input is on
//! by default. This proves the wiring end-to-end (not just
//! `uniflow-archive-extract` in isolation): a project directory containing
//! only a `.tar.gz` archive (no source file at all outside it) still
//! produces a taint finding from the source hidden inside that archive.

use std::{
    io::Write,
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

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uniflow-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).expect("create temporary project");
    dir
}

const JAVA_SRC: &str =
    "class App {\n    static String source() { return System.getenv(\"X\"); }\n    static void sink(String s) { System.out.println(s); }\n    static void run() { sink(source()); }\n}\n";

const RULES_YAML: &str = r#"
sources:
  - id: java-source
    language: java
    matcher:
      exact: App.source
    out: return
    kind: untrusted

sinks:
  - id: java-sink
    language: java
    matcher:
      exact: App.sink
    inputs: [arg0]
    kind: untrusted
"#;

fn write_tar_gz(dest: &PathBuf, entries: &[(&str, &[u8])]) {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, *name, *contents).expect("append tar entry");
    }
    let tar_bytes = builder.into_inner().expect("finish tar");

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar_bytes).expect("gzip write");
    let gz_bytes = encoder.finish().expect("gzip finish");
    std::fs::write(dest, gz_bytes).expect("write tar.gz fixture");
}

#[test]
fn a_java_source_file_hidden_inside_a_tar_gz_is_extracted_and_analyzed() {
    let project = Scratch(scratch("archive-extraction"));
    write_tar_gz(&project.0.join("bundle.tar.gz"), &[("App.java", JAVA_SRC.as_bytes())]);

    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, RULES_YAML).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run analyze-project");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "java-source"
            && finding["sink_rule_id"] == "java-sink"),
        "expected a finding from the Java source hidden inside bundle.tar.gz: {findings:#?}"
    );
}
