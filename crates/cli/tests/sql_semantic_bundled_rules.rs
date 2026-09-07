use std::{collections::HashSet, path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);
impl Drop for Scratch { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn sql_semantic_rules_execute_from_isolated_binary() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-sql-semantic-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("SqlSemanticRules.sql");
    std::fs::write(&fixture, include_str!("fixtures/SqlSemanticRules.sql")).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["check-baseline", "--language", "sql", "--input"]).arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap();
    let ids = findings.iter().filter_map(|finding| finding["rule_id"].as_str()).collect::<HashSet<_>>();
    for suffix in [
        "CommitRollback", "ColumnsShouldHaveTableName", "CursorBodyInPackageSpec", "DeadCode",
        "DisabledTest", "NotASelectedExpression", "NotFound", "ParsingError",
        "QueryWithoutExceptionHandling", "RaiseStandardException", "RedundantExpectation",
        "TooManyRowsHandler", "UnhandledUserDefinedException", "UnnecessaryAliasInQuery",
        "UnusedCursor", "UnusedParameter", "UnusedVariable", "VariableHiding", "VariableInCount",
        "VariableName",
    ] {
        let native = format!("LEGACY-SQL-{suffix}");
        assert!(ids.contains(native.as_str()), "missing {suffix}: {ids:#?}");
        let finding = findings.iter().find(|finding| finding["rule_id"] == native).unwrap();
        for locale in ["zh-CN", "en", "zh-TW"] {
            assert!(finding["translations"][locale]["message"].as_str().is_some_and(|message| !message.is_empty()));
        }
    }
}
