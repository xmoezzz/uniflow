//! A Java `native` method has no body, so a Java-only or C/C++-only scan
//! sees only half of an FFI/JNI hop: the Java side has an unresolved call, and
//! the C/C++ side has an implementation nothing in-language ever calls. This
//! proves a `--language mix` scan over a project containing both a `native`
//! declaration and its same-named (per the standard JNI naming convention)
//! C implementation bridges taint across that hop in every direction the
//! bridge supports: Java-tainted argument reaching a genuine native sink,
//! Java-tainted argument passed straight through the native call and back
//! into a genuine Java sink, and native-origin taint (no argument
//! dependency) reaching a genuine Java sink — while never leaking the
//! bridge's internal probe rule ids into the emitted findings.

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

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("uniflow-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).expect("create temporary project");
    dir
}

const JAVA_SRC: &str = r#"
class App {
    static native String nativeSink(String tainted);
    static native String nativePassthrough(String value);
    static native String nativeGetSecret();

    static String source() { return System.getenv("X"); }
    static void sink(String s) { System.out.println(s); }

    static void runSinkBridge() {
        nativeSink(source());
    }

    static void runPassthroughBridge() {
        sink(nativePassthrough(source()));
    }

    static void runNativeSourceBridge() {
        sink(nativeGetSecret());
    }
}
"#;

const NATIVE_C_SRC: &str = r#"
char* Java_App_nativeSink(void* env, void* thiz, char* tainted) {
    system(tainted);
    return tainted;
}

char* Java_App_nativePassthrough(void* env, void* thiz, char* value) {
    return value;
}

char* Java_App_nativeGetSecret(void* env, void* thiz) {
    return getenv("SECRET");
}
"#;

const RULES_YAML: &str = r#"
sources:
  - id: java-source
    language: java
    matcher:
      exact: App.source
    out: return
    kind: untrusted
  - id: c-getenv-source
    language: c
    matcher:
      exact: getenv
    out: return
    kind: untrusted

sinks:
  - id: java-sink
    language: java
    matcher:
      exact: App.sink
    inputs: [arg0]
    kind: untrusted
  - id: c-system-sink
    language: c
    matcher:
      exact: system
    inputs: [arg0]
    kind: untrusted
"#;

#[test]
fn native_method_bridges_taint_across_the_jni_boundary_in_every_direction() {
    let project = Scratch(scratch("ffi-bridge"));
    std::fs::write(project.0.join("App.java"), JAVA_SRC).expect("write java fixture");
    std::fs::write(project.0.join("native.c"), NATIVE_C_SRC).expect("write native fixture");

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

    // No internal probe rule id may ever reach the emitted findings.
    for finding in &findings {
        for key in ["source_rule_id", "sink_rule_id"] {
            let value = finding[key].as_str().unwrap_or_default();
            assert!(
                !value.starts_with("__ffi_bridge::"),
                "internal probe rule id leaked into findings: {finding:#?}"
            );
        }
    }

    // Java source -> nativeSink's tainted argument -> genuine native sink.
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "java-source"
            && finding["sink_rule_id"]
                .as_str()
                .is_some_and(|id| id.contains("nativeSink") && id.contains("c-system-sink"))
            && finding["sink_kind"] == "untrusted"),
        "expected Java source reaching the native system() sink through nativeSink: {findings:#?}"
    );

    // Java source -> nativePassthrough (pass-through propagator) -> Java sink.
    assert!(
        findings
            .iter()
            .any(|finding| finding["source_rule_id"] == "java-source"
                && finding["sink_rule_id"] == "java-sink"),
        "expected Java source reaching the Java sink through the nativePassthrough bridge: {findings:#?}"
    );

    // nativeGetSecret (native-origin source, no argument dependency) -> Java sink.
    assert!(
        findings.iter().any(|finding| finding["source_rule_id"]
            .as_str()
            .is_some_and(|id| id.contains("nativeGetSecret") && id.contains("c-getenv-source"))
            && finding["source_kind"] == "untrusted"
            && finding["sink_rule_id"] == "java-sink"),
        "expected the native-origin getenv() source reaching the Java sink through nativeGetSecret: {findings:#?}"
    );
}
