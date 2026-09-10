use std::{collections::HashMap, path::Path, sync::OnceLock};

use uniflow_baseline::{
    builtin_security_pack, BaselinePack, BaselineScanOptions, OracleFormsBlock, OracleFormsMetadata,
};
use uniflow_hir::Language;
use uniflow_lang_frontends::parse_file;

fn check(rule: &str, source: &str, expected: usize) -> Vec<(usize, usize)> {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::Sql, Path::new("Rules.sql"), source);
    assert_eq!(findings.len(), expected, "{rule} {source}\n{findings:#?}");
    let coordinates = findings
        .iter()
        .map(|finding| (finding.line, finding.column))
        .collect::<Vec<_>>();
    let hir = parse_file(Language::Sql, "Rules.sql", source).unwrap();
    let integrated = pack.scan_hir(&hir, &HashMap::from([("Rules.sql".into(), source.into())]));
    assert_eq!(
        integrated
            .iter()
            .map(|finding| (finding.line, finding.column))
            .collect::<Vec<_>>(),
        coordinates
    );
    coordinates
}

#[test]
fn sql_structural_rules_have_positive_safe_and_non_code_cases() {
    for (suffix, source, safe) in [
        (
            "AddParenthesesInNestedExpression",
            "IF a AND b OR c THEN x; END IF;",
            "IF (a AND b) OR c THEN x; END IF;",
        ),
        (
            "CollapsibleIfStatements",
            "IF a THEN IF b THEN x; END IF; END IF;",
            "IF a AND b THEN x; END IF;",
        ),
        (
            "ConcatenationWithNull",
            "value := '' || id;",
            "value := TO_CHAR(id);",
        ),
        (
            "DeclareSectionWithoutDeclarations",
            "DECLARE BEGIN work; END;",
            "DECLARE value NUMBER; BEGIN work; END;",
        ),
        (
            "DuplicateConditionIfElsif",
            "IF a THEN x; ELSIF b THEN y; ELSIF a THEN z; END IF;",
            "IF a THEN x; ELSIF b THEN y; END IF;",
        ),
        (
            "DuplicatedValueInIn",
            "IF value IN (a, fn(b, c), a) THEN x; END IF;",
            "IF value IN (a, fn(b, c)) THEN x; END IF;",
        ),
        ("EmptyBlock", "BEGIN NULL; END;", "BEGIN work; END;"),
        (
            "ExplicitInParameter",
            "PROCEDURE p(value NUMBER) IS BEGIN work; END;",
            "PROCEDURE p(value IN NUMBER) IS BEGIN work; END;",
        ),
        (
            "FunctionWithOutParameter",
            "FUNCTION f(value OUT NUMBER) RETURN NUMBER IS BEGIN RETURN 1; END;",
            "FUNCTION f(value IN NUMBER) RETURN NUMBER IS BEGIN RETURN value; END;",
        ),
        (
            "IdenticalExpression",
            "IF account.id = account.id THEN x; END IF;",
            "IF account.id = other.id THEN x; END IF;",
        ),
        (
            "IfWithExit",
            "IF done THEN EXIT; END IF;",
            "EXIT WHEN done;",
        ),
        (
            "ReturnOfBooleanExpression",
            "IF valid THEN RETURN TRUE; ELSE RETURN FALSE; END IF;",
            "RETURN valid;",
        ),
        (
            "SameBranch",
            "IF a THEN work; ELSIF b THEN work; END IF;",
            "IF a THEN work; ELSIF b THEN other; END IF;",
        ),
        (
            "SameCondition",
            "IF (x = 1) AND (x = 1) THEN work; END IF;",
            "IF (x = 1) AND (y = 1) THEN work; END IF;",
        ),
        (
            "SelectWithRownumAndOrderBy",
            "SELECT name FROM users WHERE ROWNUM <= 5 ORDER BY created DESC;",
            "SELECT name FROM (SELECT name FROM users ORDER BY created DESC) WHERE ROWNUM <= 5;",
        ),
        (
            "UnnecessaryElse",
            "IF valid THEN RETURN value; ELSE value := NULL; END IF;",
            "IF valid THEN value := 1; ELSE value := NULL; END IF;",
        ),
        (
            "UnnecessaryNullStatement",
            "BEGIN work; NULL; END;",
            "BEGIN NULL; END;",
        ),
        (
            "UselessParenthesis",
            "IF ((a = b)) THEN work; END IF;",
            "IF (a = b) THEN work; END IF;",
        ),
        (
            "VariableInitializationWithFunctionCall",
            "DECLARE name VARCHAR2(10) := lookup(5); BEGIN work; END;",
            "DECLARE name VARCHAR2(10); BEGIN name := lookup(5); END;",
        ),
        (
            "VariableInitializationWithNull",
            "DECLARE name VARCHAR2(10) := NULL; BEGIN work; END;",
            "DECLARE name VARCHAR2(10); BEGIN work; END;",
        ),
    ] {
        let rule = format!("LEGACY-SQL-{suffix}");
        check(&rule, source, 1);
        check(&rule, safe, 0);
        check(&rule, &format!("-- {source}\nSELECT 1;"), 0);
        check(&rule, &format!("SELECT '{source}';"), 0);
    }
}

#[test]
fn sql_structural_rules_preserve_nested_scope_and_locations() {
    assert_eq!(
        check(
            "LEGACY-SQL-DuplicateConditionIfElsif",
            "-- 中文\nIF a THEN x;\nELSIF a THEN y;\nEND IF;",
            1
        ),
        vec![(3, 1)]
    );
    check(
        "LEGACY-SQL-DuplicatedValueInIn",
        "value IN (a, (a, b), fn(a, b));",
        0,
    );
    check(
        "LEGACY-SQL-SelectWithRownumAndOrderBy",
        "SELECT * FROM (SELECT * FROM t WHERE ROWNUM < 5 ORDER BY id);",
        1,
    );
    check(
        "LEGACY-SQL-UnnecessaryNullStatement",
        "BEGIN work; BEGIN NULL; END; END;",
        0,
    );
    check(
        "LEGACY-SQL-EmptyBlock",
        "BEGIN work; BEGIN NULL; END; END;",
        1,
    );
}

#[test]
fn sql_structural_matchers_validate_exclusive_language_and_path_modes() {
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == "LEGACY-SQL-IfWithExit");
    pack.rules[0].matcher.path_pattern = "\\.pkb$".into();
    pack.validate().unwrap();
    assert!(pack
        .scan_text(
            &Language::Sql,
            Path::new("body.sql"),
            "IF x THEN EXIT; END IF;"
        )
        .is_empty());
    assert_eq!(
        pack.scan_text(
            &Language::Sql,
            Path::new("body.pkb"),
            "IF x THEN EXIT; END IF;"
        )
        .len(),
        1
    );
    pack.rules[0].languages = vec![Language::Java];
    assert!(pack.validate().is_err());
    pack.rules[0].languages = vec![Language::Sql];
    pack.rules[0].matcher.code_pattern = "exit".into();
    assert!(pack.validate().is_err());
}

#[test]
fn sql_control_flow_symbol_and_query_rules_have_focused_cases() {
    for (suffix, source, safe) in [
        ("CommitRollback", "PROCEDURE p IS BEGIN COMMIT; END;", "PROCEDURE p IS PRAGMA AUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;"),
        ("ColumnsShouldHaveTableName", "SELECT name FROM employee;", "SELECT employee.name FROM employee;"),
        ("CursorBodyInPackageSpec", "CREATE PACKAGE pkg IS CURSOR cur IS SELECT dummy FROM dual; END;", "CREATE PACKAGE BODY pkg IS CURSOR cur IS SELECT dummy FROM dual; END;"),
        ("DeadCode", "BEGIN RAISE my_error; log('never'); END;", "BEGIN log('before'); RAISE my_error; END;"),
        ("DisabledTest", "-- %test(sample)\n-- %disabled\nPROCEDURE test;", "-- %test(sample)\n-- %disabled infrastructure issue\nPROCEDURE test;"),
        ("NotASelectedExpression", "SELECT DISTINCT item.name FROM item ORDER BY item.group_id;", "SELECT DISTINCT item.name AS full_name FROM item ORDER BY full_name;"),
        ("NotFound", "IF NOT cur%FOUND THEN work; END IF;", "IF cur%NOTFOUND THEN work; END IF;"),
        ("ParsingError", "BEGIN work(1; END;", "BEGIN work(1); END;"),
        ("QueryWithoutExceptionHandling", "BEGIN SELECT name INTO value FROM employee; END;", "BEGIN SELECT name INTO value FROM employee; EXCEPTION WHEN NO_DATA_FOUND THEN value := NULL; END;"),
        ("RaiseStandardException", "BEGIN RAISE TOO_MANY_ROWS; END;", "BEGIN RAISE application_error; END;"),
        ("RedundantExpectation", "BEGIN ut.expect(actual).to_equal(actual); END;", "BEGIN ut.expect(actual).to_equal(expected); END;"),
        ("TooManyRowsHandler", "BEGIN work; EXCEPTION WHEN TOO_MANY_ROWS THEN NULL; END;", "BEGIN work; EXCEPTION WHEN TOO_MANY_ROWS THEN value := NULL; END;"),
        ("UnhandledUserDefinedException", "DECLARE my_error EXCEPTION; BEGIN RAISE my_error; END;", "DECLARE my_error EXCEPTION; BEGIN RAISE my_error; EXCEPTION WHEN my_error THEN NULL; END;"),
        ("UnnecessaryAliasInQuery", "SELECT a.id FROM employee a;", "SELECT employee.id FROM employee;"),
        ("UnusedCursor", "DECLARE CURSOR cur IS SELECT id FROM employee; BEGIN work; END;", "DECLARE CURSOR cur IS SELECT id FROM employee; BEGIN OPEN cur; END;"),
        ("UnusedParameter", "PROCEDURE p(a IN NUMBER, b IN NUMBER) IS BEGIN compute(a); END;", "PROCEDURE p(a IN NUMBER) IS BEGIN compute(a); END;"),
        ("UnusedVariable", "DECLARE unused_value NUMBER; BEGIN work; END;", "DECLARE used_value NUMBER; BEGIN compute(used_value); END;"),
        ("VariableHiding", "DECLARE value NUMBER; BEGIN DECLARE value VARCHAR2(5); BEGIN work; END; END;", "DECLARE value NUMBER; BEGIN DECLARE inner_value VARCHAR2(5); BEGIN work; END; END;"),
        ("VariableInCount", "DECLARE local_id NUMBER; BEGIN SELECT COUNT(local_id) INTO total FROM employee; END;", "DECLARE local_id NUMBER; BEGIN SELECT COUNT(employee.id) INTO total FROM employee; END;"),
        ("VariableName", "DECLARE dept_name_ VARCHAR2(20); BEGIN work; END;", "DECLARE dept_name VARCHAR2(20); BEGIN work; END;"),
    ] {
        let rule = format!("LEGACY-SQL-{suffix}");
        check(&rule, source, 1);
        check(&rule, safe, 0);
    }
}

#[test]
fn sql_symbol_rules_ignore_comments_strings_and_preserve_nested_query_scope() {
    check(
        "LEGACY-SQL-NotASelectedExpression",
        "SELECT DISTINCT item.name, item.group_id FROM item ORDER BY item.group_id DESC;",
        0,
    );
    check(
        "LEGACY-SQL-UnnecessaryAliasInQuery",
        "SELECT a.id, parent.id FROM employee a, employee parent WHERE a.parent_id = parent.id;",
        0,
    );
    check("LEGACY-SQL-CommitRollback", "COMMIT;", 0);
    check(
        "LEGACY-SQL-DeadCode",
        "BEGIN IF done THEN RETURN; END IF; log('reachable'); END;",
        0,
    );
    check(
        "LEGACY-SQL-DisabledTest",
        "SELECT '-- %disabled'; -- %disabled has a reason\n",
        0,
    );
    check(
        "LEGACY-SQL-ParsingError",
        "SELECT '(not syntax)' FROM dual; -- ( ignored\n",
        0,
    );
}

#[test]
fn invalid_reference_to_object_uses_forms_metadata_and_exact_call_contract() {
    const RULE: &str = "LEGACY-SQL-InvalidReferenceToObject";
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == RULE);
    assert_eq!(pack.rules.len(), 1);
    let options = BaselineScanOptions {
        oracle_forms_metadata: Some(OracleFormsMetadata {
            alerts: vec!["foo".into()],
            blocks: vec![OracleFormsBlock {
                name: "foo".into(),
                items: vec!["item1".into()],
            }],
            lovs: vec!["foo".into()],
        }),
    };
    let calls = [
        ("find_alert('invalid')", "find_alert('foo')"),
        (
            "set_alert_button_property('invalid', b, p, v)",
            "set_alert_button_property('foo', b, p, v)",
        ),
        (
            "set_alert_property('invalid', p, v)",
            "set_alert_property('foo', p, v)",
        ),
        ("show_alert('invalid')", "show_alert('foo')"),
        ("find_lov('invalid')", "find_lov('foo')"),
        (
            "get_lov_property('invalid', p)",
            "get_lov_property('foo', p)",
        ),
        (
            "set_lov_column_property('invalid', 1, p, v)",
            "set_lov_column_property('foo', 1, p, v)",
        ),
        (
            "set_lov_property('invalid', p, v)",
            "set_lov_property('foo', p, v)",
        ),
        (
            "set_lov_property('invalid', p, x, y)",
            "set_lov_property('foo', p, x, y)",
        ),
        ("show_lov('invalid')", "show_lov('foo')"),
        ("find_block('invalid')", "find_block('foo')"),
        (
            "get_block_property('invalid', p)",
            "get_block_property('foo', p)",
        ),
        ("go_block('invalid')", "go_block('foo')"),
        (
            "set_block_property('invalid', p, v)",
            "set_block_property('foo', p, v)",
        ),
        (
            "set_block_property('invalid', p, x, y)",
            "set_block_property('foo', p, x, y)",
        ),
        (
            "checkbox_checked('foo.invalid')",
            "checkbox_checked('foo.item1')",
        ),
        (
            "convert_other_value('foo.invalid')",
            "convert_other_value('foo.item1')",
        ),
        (
            "display_item('foo.invalid', v)",
            "display_item('foo.item1', v)",
        ),
        ("find_item('foo.invalid')", "find_item('foo.item1')"),
        (
            "get_item_instance_property('foo.invalid', r, p)",
            "get_item_instance_property('foo.item1', r, p)",
        ),
        (
            "get_item_property('foo.invalid', p)",
            "get_item_property('foo.item1', p)",
        ),
        (
            "get_radio_button_property('foo.invalid', b, p)",
            "get_radio_button_property('foo.item1', b, p)",
        ),
        ("go_item('foo.invalid')", "go_item('foo.item1')"),
        (
            "image_scroll('foo.invalid', x, y)",
            "image_scroll('foo.item1', x, y)",
        ),
        ("image_zoom('foo.invalid', p)", "image_zoom('foo.item1', p)"),
        (
            "image_zoom('foo.invalid', p, v)",
            "image_zoom('foo.item1', p, v)",
        ),
        ("play_sound('foo.invalid')", "play_sound('foo.item1')"),
        (
            "read_image_file(f, t, 'foo.invalid')",
            "read_image_file(f, t, 'foo.item1')",
        ),
        (
            "read_sound_file(f, t, 'foo.invalid')",
            "read_sound_file(f, t, 'foo.item1')",
        ),
        ("recalculate('foo.invalid')", "recalculate('foo.item1')"),
        (
            "set_item_instance_property('foo.invalid', r, p, v)",
            "set_item_instance_property('foo.item1', r, p, v)",
        ),
        (
            "set_item_property('foo.invalid', p, v)",
            "set_item_property('foo.item1', p, v)",
        ),
        (
            "set_item_property('foo.invalid', p, x, y)",
            "set_item_property('foo.item1', p, x, y)",
        ),
        (
            "set_radio_button_property('foo.invalid', b, p, v)",
            "set_radio_button_property('foo.item1', b, p, v)",
        ),
        (
            "set_radio_button_property('foo.invalid', b, p, x, y)",
            "set_radio_button_property('foo.item1', b, p, x, y)",
        ),
        (
            "write_image_file(f, t, 'foo.invalid', c, d)",
            "write_image_file(f, t, 'foo.item1', c, d)",
        ),
        (
            "write_sound_file(f, t, 'foo.invalid', q, s)",
            "write_sound_file(f, t, 'foo.item1', q, s)",
        ),
    ];
    let invalid = calls
        .iter()
        .map(|(invalid, _)| format!("{invalid};"))
        .collect::<Vec<_>>()
        .join("\n");
    let safe = calls
        .iter()
        .map(|(_, safe)| format!("{safe};"))
        .collect::<Vec<_>>()
        .join("\n");
    let findings =
        pack.scan_text_with_options(&Language::Sql, Path::new("form.sql"), &invalid, &options);
    assert_eq!(findings.len(), calls.len(), "{findings:#?}");
    assert!(findings.iter().all(|finding| {
        finding.rule_id == RULE
            && finding
                .message
                .starts_with("Invalid reference to the object")
            && finding.message.ends_with("call.")
    }));
    assert!(pack
        .scan_text_with_options(&Language::Sql, Path::new("form.sql"), &safe, &options)
        .is_empty());
    assert!(pack
        .scan_text(&Language::Sql, Path::new("form.sql"), &invalid)
        .is_empty());
    assert!(pack
        .scan_text_with_options(
            &Language::Sql,
            Path::new("form.sql"),
            "find_alert(name); find_alert('invalid', extra);",
            &options,
        )
        .is_empty());
}

#[test]
fn xpath_template_supports_nodes_booleans_and_ignores_scalar_results() {
    const RULE: &str = "LEGACY-SQL-XPath";
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|rule| rule.id == RULE);
    assert_eq!(pack.rules.len(), 1);
    let source = "SELECT one FROM dual;\nUPDATE sample SET value = 1;\n";

    pack.rules[0].matcher.sql_xpath_query = "//STATEMENT".into();
    pack.rules[0].matcher.sql_xpath_message = "Avoid statements".into();
    pack.validate().unwrap();
    let findings = pack.scan_text(&Language::Sql, Path::new("xpath.sql"), source);
    assert_eq!(findings.len(), 2, "{findings:#?}");
    assert_eq!(findings[0].line, 1);
    assert_eq!(findings[1].line, 2);
    assert!(findings
        .iter()
        .all(|finding| finding.message == "Avoid statements"));

    pack.rules[0].matcher.sql_xpath_query = "count(//STATEMENT) > 0".into();
    pack.validate().unwrap();
    let findings = pack.scan_text(&Language::Sql, Path::new("xpath.sql"), source);
    assert_eq!(findings.len(), 1);
    assert_eq!((findings[0].line, findings[0].column), (1, 1));

    for scalar in [
        "count(//STATEMENT) < 0",
        "count(//STATEMENT)",
        "string(//TOKEN[1])",
    ] {
        pack.rules[0].matcher.sql_xpath_query = scalar.into();
        pack.validate().unwrap();
        assert!(pack
            .scan_text(&Language::Sql, Path::new("xpath.sql"), source)
            .is_empty());
    }
    pack.rules[0].matcher.sql_xpath_query = "+++".into();
    assert!(pack.validate().is_err());
}
