use std::collections::HashMap;
use std::sync::OnceLock;

use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, files: &[(&str, &str)], expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let java = files
        .iter()
        .find(|(path, _)| path.ends_with(".java"))
        .copied()
        .unwrap_or(("Dummy.java", "class Dummy {}"));
    let program = JavaParser::default().parse_file(java.0, java.1).unwrap();
    let mut sources = files
        .iter()
        .map(|(path, source)| ((*path).to_string(), (*source).to_string()))
        .collect::<HashMap<_, _>>();
    sources
        .entry(java.0.to_string())
        .or_insert_with(|| java.1.to_string());
    let findings = pack.scan_hir(&program, &sources);
    assert_eq!(findings.len(), expected, "{rule}: {files:#?}\n{findings:#?}");
}

#[test]
fn struts2_action_fields_and_validator_fields_are_cross_checked() {
    let java = "class UserAction extends ActionSupport { String name; String email; }";
    let validation = "<validators><field name=\"name\"><field-validator type=\"required\"/></field></validators>";
    check(
        "LEGACY-JAVA-RULEMAP-struts2-action-field-without-validator",
        &[("UserAction.java", java), ("UserAction-validation.xml", validation)],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts2-validator-without-field",
        &[("UserAction.java", java), ("UserAction-validation.xml", "<validators><field name=\"missing\"><field-validator type=\"required\"/></field></validators>")],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts2-validator-without-field",
        &[("UserAction.java", java), ("UserAction-validation.xml", validation)],
        0,
    );
}

#[test]
fn struts2_validation_files_are_paired_uniquely_with_actions() {
    let java = "class UserAction extends ActionSupport { String name; }";
    let validation = "<validators><field name=\"name\"><field-validator type=\"required\"/></field></validators>";
    check(
        "LEGACY-JAVA-RULEMAP-struts2-duplicate-validation-files",
        &[("UserAction.java", java), ("UserAction-validation.xml", validation), ("UserAction-save-validation.xml", validation)],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts2-unvalidated-action",
        &[("UserAction.java", java)],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts2-unvalidated-action",
        &[("UserAction.java", java), ("UserAction-validation.xml", validation)],
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts2-validation-without-action",
        &[("Dummy.java", "class Dummy {}"), ("GhostAction-validation.xml", validation)],
        1,
    );
}

#[test]
fn struts2_validator_types_are_declared() {
    check(
        "LEGACY-JAVA-RULEMAP-struts2-undeclared-validator",
        &[("UserAction.java", "class UserAction extends ActionSupport { String name; }"), ("UserAction-validation.xml", "<validators><field name=\"name\"><field-validator type=\"companyOnly\"/></field></validators>")],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts2-undeclared-validator",
        &[("UserAction.java", "class UserAction extends ActionSupport { String name; }"), ("UserAction-validation.xml", "<validators><field name=\"name\"><field-validator type=\"required\"/></field></validators>")],
        0,
    );
}

#[test]
fn struts1_validation_forms_are_unique_and_used() {
    let config = "<struts-config><form-beans><form-bean name=\"loginForm\" type=\"LoginForm\"/></form-beans><action-mappings><action path=\"/login\" name=\"loginForm\" type=\"LoginAction\"/></action-mappings></struts-config>";
    let java = "class LoginForm extends ValidatorForm { String username; } class LoginAction {}";
    check(
        "LEGACY-JAVA-RULEMAP-struts-duplicate-validation-forms",
        &[("LoginForm.java", java), ("struts-config.xml", config), ("validation.xml", "<form-validation><formset><form name=\"loginForm\"/><form name=\"loginForm\"/></formset></form-validation>")],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts-unused-validation-form",
        &[("LoginForm.java", java), ("struts-config.xml", config), ("validation.xml", "<form-validation><formset><form name=\"orphanForm\"/></formset></form-validation>")],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts-unused-validation-form",
        &[("LoginForm.java", java), ("struts-config.xml", config), ("validation.xml", "<form-validation><formset><form name=\"loginForm\"/></formset></form-validation>")],
        0,
    );
}

#[test]
fn struts1_form_classes_and_validate_methods_follow_the_contract() {
    check(
        "LEGACY-JAVA-RULEMAP-struts-erroneous-validate-method",
        &[("LoginForm.java", "class LoginForm extends ActionForm { void validate(ActionMapping mapping) {} }")],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts-erroneous-validate-method",
        &[("LoginForm.java", "class LoginForm extends ActionForm { ActionErrors validate(ActionMapping mapping, HttpServletRequest request) { return new ActionErrors(); } }")],
        0,
    );
    let config = "<struts-config><form-bean name=\"loginForm\" type=\"LoginForm\"/><action path=\"/login\" name=\"loginForm\" type=\"LoginAction\"/></struts-config>";
    let validation = "<form-validation><formset><form name=\"loginForm\"><field property=\"username\"/></form></formset></form-validation>";
    check(
        "LEGACY-JAVA-RULEMAP-struts-form-base-class",
        &[("LoginForm.java", "class LoginForm extends ActionForm { String username; }"), ("struts-config.xml", config), ("validation.xml", validation)],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts-form-base-class",
        &[("LoginForm.java", "class LoginForm extends ValidatorForm { String username; }"), ("struts-config.xml", config), ("validation.xml", validation)],
        0,
    );
}

#[test]
fn struts1_form_fields_and_validators_are_cross_checked() {
    let config = "<struts-config><form-bean name=\"loginForm\" type=\"LoginForm\"/><action path=\"/login\" name=\"loginForm\" type=\"LoginAction\"/></struts-config>";
    let java = "class LoginForm extends ValidatorForm { String username; String password; }";
    let validation = "<form-validation><formset><form name=\"loginForm\"><field property=\"username\"/></form></formset></form-validation>";
    check(
        "LEGACY-JAVA-RULEMAP-struts-form-field-without-validator",
        &[("LoginForm.java", java), ("struts-config.xml", config), ("validation.xml", validation)],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts-validator-without-form-field",
        &[("LoginForm.java", "class LoginForm extends ValidatorForm { String username; }"), ("struts-config.xml", config), ("validation.xml", "<form-validation><formset><form name=\"loginForm\"><field property=\"missing\"/></form></formset></form-validation>")],
        1,
    );
}

#[test]
fn struts1_actions_do_not_use_unvalidated_forms() {
    let config = "<struts-config><form-bean name=\"loginForm\" type=\"LoginForm\"/><action path=\"/login\" name=\"loginForm\" type=\"LoginAction\" validate=\"true\"/></struts-config>";
    check(
        "LEGACY-JAVA-RULEMAP-struts-unvalidated-action-form",
        &[("LoginForm.java", "class LoginForm extends ActionForm { String username; }"), ("struts-config.xml", config)],
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-struts-unvalidated-action-form",
        &[("LoginForm.java", "class LoginForm extends ValidatorForm { String username; }"), ("struts-config.xml", config)],
        0,
    );
}
