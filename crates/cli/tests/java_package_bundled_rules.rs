use regex_syntax::hir::{Class, Hir, HirKind};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use uniflow_baseline::bundled_java_package_rules;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn regex_witness(pattern: &str) -> String {
    fn emit(hir: &Hir, output: &mut Vec<u8>) {
        match hir.kind() {
            HirKind::Empty | HirKind::Look(_) => {}
            HirKind::Literal(literal) => output.extend_from_slice(&literal.0),
            HirKind::Class(Class::Unicode(class)) => {
                let character = class.iter().next().expect("non-empty Unicode class").start();
                let mut bytes = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
            }
            HirKind::Class(Class::Bytes(class)) => {
                output.push(class.iter().next().expect("non-empty byte class").start());
            }
            HirKind::Repetition(repetition) => {
                for _ in 0..repetition.min {
                    emit(&repetition.sub, output);
                }
            }
            HirKind::Capture(capture) => emit(&capture.sub, output),
            HirKind::Concat(parts) => {
                for part in parts {
                    emit(part, output);
                }
            }
            HirKind::Alternation(parts) => emit(&parts[0], output),
        }
    }

    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .unwrap_or_else(|error| panic!("invalid package regex {pattern}: {error}"));
    let mut bytes = Vec::new();
    emit(&hir, &mut bytes);
    String::from_utf8(bytes).expect("package regex witness must be UTF-8")
}

#[test]
fn all_java_package_rules_execute_from_bundle_without_rule_directory() {
    let inventory = bundled_java_package_rules();
    assert_eq!(inventory.len(), 544);

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-java-package-bundle-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let mut source = String::new();
    for (index, rule) in inventory.iter().enumerate() {
        source.push_str("import ");
        source.push_str(&regex_witness(rule.import_regex));
        source.push_str(&format!("UniflowWitness{index};\n"));
    }
    source.push_str("class JavaPackageBundleWitness {}\n");
    let fixture = scratch.0.join("JavaPackageBundleWitness.java");
    std::fs::write(&fixture, source).unwrap();
    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "java", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings
        .iter()
        .filter_map(|finding| finding["rule_id"].as_str())
        .collect::<HashSet<_>>();
    for rule in inventory {
        let native_id = format!("LEGACY-JAVA-PKG-{}", rule.id);
        assert!(ids.contains(native_id.as_str()), "missing {native_id}");
    }
}
