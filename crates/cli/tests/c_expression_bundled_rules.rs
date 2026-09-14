use std::{
    collections::HashSet,
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
fn c_expression_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-c-expressions-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("CExpressionRules.c");
    std::fs::write(&fixture, include_str!("fixtures/CExpressionRules.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"])
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
    for suffix in [
        "nullptr-zero",
        "no-assignment-outside-statement",
        "no-unary-in-expressions",
        "no-side-effect-in-sizeof",
        "no-comma-expression",
        "no-assignment-in-if-condition",
        "no-conditional-expression",
        "conditional-braces",
        "no-dangerous-macro-in-reg-calls",
    ] {
        let native = format!("LEGACY-C-AST-{suffix}");
        assert!(ids.contains(native.as_str()), "missing {suffix}: {ids:#?}");
        let finding = findings
            .iter()
            .find(|finding| finding["rule_id"] == native)
            .unwrap();
        for locale in ["zh-CN", "en", "zh-TW"] {
            assert!(finding["translations"][locale]["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()));
        }
    }
}

#[test]
fn delete_array_wrong_type_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-delete-array-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("DeleteArrayWrongType.cpp");
    std::fs::write(&fixture, include_str!("fixtures/DeleteArrayWrongType.cpp")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "ANZU-DELETE-ARRAY-WRONG-TYPE")
        .unwrap_or_else(|| panic!("missing bundled rule: {findings:#?}"));
    assert_eq!(finding["standards"], serde_json::json!(["0101000010110355"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(finding["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn reinterpret_cast_multiple_inheritance_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-reinterpret-inheritance-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("ReinterpretCastMultipleInheritance.cpp");
    std::fs::write(
        &fixture,
        include_str!("fixtures/ReinterpretCastMultipleInheritance.cpp"),
    )
    .unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "ANZU-REINTERPRET-CAST-MULTIPLE-INHERITANCE")
        .unwrap_or_else(|| panic!("missing bundled rule: {findings:#?}"));
    assert_eq!(finding["standards"], serde_json::json!(["0101000010110352"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(finding["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn strong_typedef_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-strong-typedef-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("StrongTypedefMismatch.c");
    std::fs::write(&fixture, include_str!("fixtures/StrongTypedefMismatch.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (rule_id, standard) in [
        ("ANZU-STRONG-TYPEDEF-ARGUMENT-MISMATCH", "2401000010120093"),
        ("ANZU-STRONG-TYPEDEF-RETURN-MISMATCH", "2401000010120094"),
        ("ANZU-STRONG-TYPEDEF-MISMATCH", "2401000010120095"),
    ] {
        let finding = findings
            .iter()
            .find(|finding| finding["rule_id"] == rule_id)
            .unwrap_or_else(|| panic!("missing {rule_id}: {findings:#?}"));
        assert_eq!(finding["standards"], serde_json::json!([standard]));
        for locale in ["zh-CN", "en", "zh-TW"] {
            assert!(finding["translations"][locale]["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()));
        }
    }
}

#[test]
fn no_private_data_return_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-private-data-return-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("NoPrivateDataReturn.cpp");
    std::fs::write(&fixture, include_str!("fixtures/NoPrivateDataReturn.cpp")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "ANZU-NO-PRIVATE-DATA-RETURN")
        .unwrap_or_else(|| panic!("missing bundled rule: {findings:#?}"));
    assert_eq!(finding["standards"], serde_json::json!(["0101000010110398"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(finding["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn virtual_call_from_constructor_or_destructor_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-virtual-ctor-call-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("VirtualCallFromConstructor.cpp");
    std::fs::write(
        &fixture,
        include_str!("fixtures/VirtualCallFromConstructor.cpp"),
    )
    .unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();

    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding["rule_id"] == "ANZU-VIRTUAL-CALL-FROM-CONSTRUCTOR-OR-DESTRUCTOR")
        .unwrap_or_else(|| panic!("missing bundled rule: {findings:#?}"));
    assert_eq!(finding["standards"], serde_json::json!(["0101000010110401"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(finding["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn constructor_destructor_try_catch_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-function-try-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("ConstructorDestructorTryCatch.cpp");
    std::fs::write(
        &fixture,
        include_str!("fixtures/ConstructorDestructorTryCatch.cpp"),
    )
    .unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matched = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "ANZU-CONSTRUCTOR-DESTRUCTOR-TRY-CATCH-MEMBER-ACCESS")
        .collect::<Vec<_>>();
    assert_eq!(matched.len(), 2, "{findings:#?}");
    assert_eq!(matched[0]["standards"], serde_json::json!(["0101000010110343"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(matched[0]["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn virtual_destructor_delete_mismatch_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-virtual-dtor-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("VirtualDestructorDelete.cpp");
    std::fs::write(&fixture, include_str!("fixtures/VirtualDestructorDelete.cpp")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matched = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "ANZU-VIRTUAL-DESTRUCTOR-DELETE-MISMATCH")
        .collect::<Vec<_>>();
    assert_eq!(matched.len(), 1, "{findings:#?}");
    assert_eq!(
        matched[0]["standards"],
        serde_json::json!(["0101000010110403", "0101000010110444"])
    );
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(matched[0]["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn incompatible_pointer_store_type_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-pointer-store-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("IncompatiblePointerStore.c");
    std::fs::write(&fixture, include_str!("fixtures/IncompatiblePointerStore.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matched = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "ANZU-INCOMPATIBLE-POINTER-STORE-TYPE")
        .collect::<Vec<_>>();
    assert_eq!(matched.len(), 1, "{findings:#?}");
    assert_eq!(matched[0]["standards"], serde_json::json!(["0101000010110208"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(matched[0]["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn pointer_arithmetic_out_of_bounds_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-pointer-arithmetic-ex-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("PointerArithmeticOutOfBounds.c");
    std::fs::write(&fixture, include_str!("fixtures/PointerArithmeticOutOfBounds.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matched = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "ANZU-POINTER-ARITHMETIC-OUT-OF-BOUNDS")
        .collect::<Vec<_>>();
    assert_eq!(matched.len(), 1, "{findings:#?}");
    assert_eq!(
        matched[0]["standards"],
        serde_json::json!(["0101000010110149", "0101000010110190", "0901000010110190"])
    );
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(matched[0]["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn pointer_align_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-pointer-align-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("PointerAlignment.c");
    std::fs::write(&fixture, include_str!("fixtures/PointerAlignment.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (id, standards) in [
        (
            "ANZU-POINTER-CAST-STRICTER-ALIGNMENT",
            serde_json::json!(["0101000010110206", "0901000010110206", "2401000010120206", "0101000010110443", "0901000010110443", "2401000010120443", "2801000010180010"]),
        ),
        (
            "ANZU-POINTER-OFFSET-MISALIGNMENT",
            serde_json::json!(["0201000010120024", "2401000010120024"]),
        ),
    ] {
        let matched = findings
            .iter()
            .filter(|finding| finding["rule_id"] == id)
            .collect::<Vec<_>>();
        assert_eq!(matched.len(), 1, "{id}: {findings:#?}");
        assert_eq!(matched[0]["standards"], standards);
        for locale in ["zh-CN", "en", "zh-TW"] {
            assert!(matched[0]["translations"][locale]["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()));
        }
    }
}

#[test]
fn member_initializer_list_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-member-init-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("MemberInitializerList.cpp");
    std::fs::write(&fixture, include_str!("fixtures/MemberInitializerList.cpp")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "cpp", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matched = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "ANZU-MEMBER-INITIALIZER-UNINITIALIZED-USE")
        .collect::<Vec<_>>();
    assert_eq!(matched.len(), 1, "{findings:#?}");
    assert_eq!(
        matched[0]["standards"],
        serde_json::json!(["2401000010120103", "0101000010110404", "2801000010180047"])
    );
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(matched[0]["translations"][locale]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
    }
}

#[test]
fn legacy_integer_overflow_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-legacy-overflow-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("LegacyIntegerOverflow.c");
    std::fs::write(&fixture, include_str!("fixtures/LegacyIntegerOverflow.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary)
        .current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"])
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    for (id, standards) in [
        (
            "ANZU-SIGNED-INTEGER-OVERFLOW",
            serde_json::json!(["0101000010120011", "0201000010120011", "0301000010120011", "0501000010120011", "0901000010120011", "2401000010120011"]),
        ),
        (
            "ANZU-UNSIGNED-INTEGER-OVERFLOW",
            serde_json::json!(["0201000010120019", "0301000010120019", "0501000010120019", "2401000010120019", "0101000010110415", "0901000010110415"]),
        ),
    ] {
        let matched = findings
            .iter()
            .filter(|finding| finding["rule_id"] == id)
            .collect::<Vec<_>>();
        assert_eq!(matched.len(), 1, "{id}: {findings:#?}");
        assert_eq!(matched[0]["standards"], standards);
        for locale in ["zh-CN", "en", "zh-TW"] {
            assert!(matched[0]["translations"][locale]["message"]
                .as_str()
                .is_some_and(|message| !message.is_empty()));
        }
    }
}

#[test]
fn bstr_usage_rule_executes_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-bstr-{unique}")));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("BstrUsage.c");
    std::fs::write(&fixture, include_str!("fixtures/BstrUsage.c")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["check-baseline", "--language", "c", "--input"]).arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let matched = findings.iter().filter(|f| f["rule_id"] == "ANZU-BSTR-USAGE").collect::<Vec<_>>();
    assert_eq!(matched.len(), 4, "{findings:#?}");
    assert_eq!(matched[0]["standards"], serde_json::json!(["2401000010120074"]));
    for locale in ["zh-CN", "en", "zh-TW"] {
        assert!(matched[0]["translations"][locale]["message"].as_str().is_some_and(|text| !text.is_empty()));
    }
}
