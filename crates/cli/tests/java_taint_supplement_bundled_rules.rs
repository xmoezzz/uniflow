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
fn java_taint_supplement_executes_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-java-taint-supplement-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("Supplement.java");
    std::fs::write(
        &fixture,
        r#"class Supplement {
  void check(java.util.zip.ZipEntry entry, java.util.Properties properties,
             javax.servlet.http.HttpServletRequest request,
             javax.servlet.http.HttpServletResponse response) throws Exception {
    java.io.File out = new java.io.File("root", entry.getName());
    javax.crypto.spec.PBEParameterSpec spec = new javax.crypto.spec.PBEParameterSpec(properties.getProperty("salt").getBytes(), 10000);
    response.sendRedirect(request.getParameter("password"));
    java.lang.StringBuilder text = new java.lang.StringBuilder();
    text.append(request.getParameter("data"));
  }
}"#,
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
        .args([
            "analyze-source",
            "--language",
            "java",
            "--use-default-models",
            "--input",
        ])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));

    for rule in [
        "uniflow.java.sink.zip-entry-path",
        "uniflow.java.sink.pbe-salt",
        "uniflow.java.sink.password-redirect",
        "uniflow.java.sink.string-builder-dos",
    ] {
        assert!(
            findings
                .iter()
                .any(|finding| finding["sink_rule_id"] == rule),
            "missing bundled {rule}: {findings:#?}"
        );
    }
}
