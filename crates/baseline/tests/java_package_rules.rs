use regex::Regex;
use regex_syntax::hir::{Class, Hir, HirKind};
use std::path::Path;
use uniflow_baseline::{bundled_java_package_pack, bundled_java_package_rules, BaselinePack};
use uniflow_hir::Language;

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
    let witness = String::from_utf8(bytes)
        .unwrap_or_else(|error| panic!("non-UTF-8 package witness for {pattern}: {error}"));
    assert!(
        Regex::new(pattern).unwrap().is_match(&witness),
        "generated package witness {witness:?} does not match {pattern}"
    );
    witness
}

#[test]
fn every_bundled_java_package_rule_has_positive_and_non_code_witnesses() {
    let inventory = bundled_java_package_rules();
    let pack = bundled_java_package_pack().expect("compiled Java package rules");
    assert_eq!(inventory.len(), 544);
    assert_eq!(pack.rules.len(), inventory.len());

    for legacy in inventory {
        let native_id = format!("LEGACY-JAVA-PKG-{}", legacy.id);
        let rule = pack
            .rules
            .iter()
            .find(|candidate| candidate.id == native_id)
            .unwrap_or_else(|| panic!("missing executable package rule {native_id}"))
            .clone();
        let witness = regex_witness(legacy.import_regex);
        let imported_type = format!("{witness}UniflowWitness");
        let source = format!(
            "// import {imported_type};\nclass Text {{ String value = \"import {imported_type};\"; }}\nimport\n    {imported_type};\n"
        );
        let focused = BaselinePack {
            id: format!("focused-{native_id}"),
            title: native_id.clone(),
            rules: vec![rule],
        };
        let findings = focused.scan_text(
            &Language::Java,
            Path::new("PackageWitness.java"),
            &source,
        );
        assert_eq!(
            findings.len(),
            1,
            "{native_id} must match its import once and ignore comment/string copies: {findings:#?}"
        );
        assert_eq!(findings[0].rule_id, native_id);
        assert_eq!(findings[0].line, 3);
        assert_eq!(findings[0].message, legacy.purl);
    }
}
