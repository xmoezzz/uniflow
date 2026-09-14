//! End-to-end coverage proving the three new bytecode formats (.NET CIL,
//! CPython `.pyc`, WASM) are actually collected and analyzed by the CLI,
//! not just parseable in isolation by their own crates — mirrors
//! `jar_bytecode_analysis.rs`'s pattern for Java.

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

const PLAIN_DLL: &[u8] = include_bytes!("../../lang_dotnet_bytecode/tests/fixtures/Plain.dll");
const PLAIN_WASM: &[u8] = include_bytes!("../../lang_wasm_bytecode/tests/fixtures/plain.wasm");

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uniflow-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).expect("create temporary project");
    dir
}

#[test]
fn dotnet_dll_taint_finding_traces_entirely_through_decoded_bytecode() {
    let project = Scratch(scratch("dotnet-bytecode-analysis"));
    std::fs::write(project.0.join("Plain.dll"), PLAIN_DLL).expect("write dll fixture");

    let rules_yaml = r#"
sources:
  - id: dotnet-source
    language: csharp
    matcher:
      regex: '\.Source$'
    out: return
    kind: untrusted

sinks:
  - id: dotnet-sink
    language: csharp
    matcher:
      regex: '\.Sink$'
    inputs: [arg0]
    kind: untrusted
"#;
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, rules_yaml).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "csharp", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run analyze-project");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "dotnet-source" && finding["sink_rule_id"] == "dotnet-sink"),
        "{findings:#?}"
    );
}

#[test]
fn wasm_module_taint_finding_traces_entirely_through_decoded_bytecode() {
    let project = Scratch(scratch("wasm-bytecode-analysis"));
    std::fs::write(project.0.join("plain.wasm"), PLAIN_WASM).expect("write wasm fixture");

    // WASM has no owning source `Language` — its decoded IR is tagged
    // `Language::Unknown`, and `--language mix` is what makes the CLI pick
    // up bytecode formats without an owning language at all (see
    // `run_mixed_project`'s dedicated `Language::Unknown` pseudo-group).
    let rules_yaml = r#"
sources:
  - id: wasm-source
    language: unknown
    matcher:
      regex: '(?i)source$'
    out: return
    kind: untrusted

sinks:
  - id: wasm-sink
    language: unknown
    matcher:
      regex: '(?i)sink$'
    inputs: [arg0]
    kind: untrusted
"#;
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, rules_yaml).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run analyze-project");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("{error}: {stdout}"));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "wasm-source" && finding["sink_rule_id"] == "wasm-sink"),
        "{findings:#?}"
    );
}

#[test]
fn python_pyc_taint_finding_traces_entirely_through_decoded_bytecode() {
    let python = which_python39();
    let Some(python) = python else {
        eprintln!("skipping: no python3.9 interpreter available in this environment to compile a .pyc fixture");
        return;
    };

    let project = Scratch(scratch("pyc-bytecode-analysis"));
    let source_path = project.0.join("mod.py");
    std::fs::write(
        &source_path,
        r#"
def source():
    return input()

def sink(value):
    eval(value)

def run():
    sink(source())
"#,
    )
    .expect("write python source");
    let pyc_path = project.0.join("mod.pyc");
    let status = Command::new(&python)
        .arg("-c")
        .arg(format!(
            "import py_compile; py_compile.compile({:?}, cfile={:?}, doraise=True)",
            source_path.to_string_lossy(),
            pyc_path.to_string_lossy()
        ))
        .status()
        .expect("run python3.9 to compile fixture");
    assert!(status.success(), "py_compile failed");
    std::fs::remove_file(&source_path).expect("remove source, keep only bytecode");

    let rules_yaml = r#"
sources:
  - id: pyc-source
    language: python
    matcher:
      exact: input
    out: return
    kind: untrusted

sinks:
  - id: pyc-sink
    language: python
    matcher:
      exact: eval
    inputs: [arg0]
    kind: untrusted
"#;
    let rules_path = project.0.join("rules.yaml");
    std::fs::write(&rules_path, rules_yaml).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "python", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .output()
        .expect("run analyze-project");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "pyc-source" && finding["sink_rule_id"] == "pyc-sink"),
        "{findings:#?}"
    );
}

/// Only `python3.9` is used deliberately — `uniflow-lang-python-bytecode`
/// only supports CPython 3.6-3.10's wordcode format, and a bare `python3`
/// on the running machine could resolve to 3.11+ (adaptive/specialized
/// opcodes, explicitly unsupported) with no way to tell from here.
fn which_python39() -> Option<String> {
    Command::new("python3.9")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
        .then(|| "python3.9".to_string())
}
