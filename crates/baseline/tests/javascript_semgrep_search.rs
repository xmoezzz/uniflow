use std::collections::HashMap;
use std::path::Path;

use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;

#[test]
fn migrated_javascript_structural_search_rules_preserve_variadic_and_receiver_semantics() {
    let source = r#"
function audit(provider, popup, data, buf, other, dynamicValue) {
    provider.enabled(false);
    provider.enabled(true);
    enabled(false);

    popup.postMessage(data, '*');
    popup.postMessage(JSON.stringify(data), 'https://example.test');
    postMessage(data, '*');

    crypto.pseudoRandomBytes;
    crypto.randomBytes;
    other.pseudoRandomBytes;
    // crypto.pseudoRandomBytes
    const ignored = "crypto.pseudoRandomBytes";

    buf.readUInt8(0, true);
    buf.writeDoubleBE(0, 1, true);
    buf.readUInt8(0, false);
    buf.readBigUInt64LE(0, true);

    eval(dynamicValue);
    eval(1);
    eval("fixed");
    other.eval(dynamicValue);

    other.html(dynamicValue);
    other.html(1);
    other.html("fixed");
    other.replaceAll("old", dynamicValue);
    other.replaceAll(dynamicValue, "new");

    require(dynamicValue);
    require(1);
    require("fixed");
    other.require(dynamicValue);

    alert();
    alert(dynamicValue);
    alert(dynamicValue, dynamicValue);
    other.alert();
    confirm(dynamicValue, dynamicValue);
    other.confirm(dynamicValue);
    prompt();
    prompt(dynamicValue, "default");
    prompt(dynamicValue, "default", dynamicValue);
    other.prompt();

    debugger;
    other.debugger;
    // debugger;
    const debuggerText = "debugger;";

    createNodesFromMarkup();
    createNodesFromMarkup(dynamicValue);
    createNodesFromMarkup("fixed");
    other.createNodesFromMarkup(dynamicValue);

    other.location.href = dynamicValue;
    other.location.href = 1;
    other.location.href = "fixed";
    other.href = dynamicValue;

    other.innerHTML = dynamicValue;
    other.innerHTML = 1;
    other.innerHTML = "fixed";
    innerHTML = dynamicValue;

    other.escapeMarkup = false;
    other.escapeMarkup = true;
    escapeMarkup = false;

    undefined = dynamicValue;
    var undefined = dynamicValue;
    let undefined = dynamicValue;
    const undefined = dynamicValue;

    other.replace("<", "&lt;");
    other.replaceAll("&", "&amp;");
    other.replace(">", "wrong");
    other.replace("safe", "value");
}
"#;
    let path = "security.js";
    let program = uniflow_lang_frontends::parse_file(Language::JavaScript, path, source)
        .expect("JavaScript fixture must parse");
    let findings = builtin_security_pack().expect("built-in pack").scan_hir(
        &program,
        &HashMap::from([(path.to_owned(), source.to_owned())]),
    );

    for (rule_id, expected) in [
        ("LEGACY-JS-SEMGREP-detect-angular-sce-disabled", 1),
        ("LEGACY-JS-SEMGREP-wildcard-postmessage-configuration", 1),
        ("LEGACY-JS-SEMGREP-detect-pseudoRandomBytes", 1),
        ("LEGACY-JS-SEMGREP-javascript_buf_rule-buffer-noassert", 2),
        ("LEGACY-JS-SEMGREP-eval-detected", 2),
        ("LEGACY-JS-SEMGREP-prohibit-jquery-html", 2),
        ("LEGACY-JS-SEMGREP-no-replaceall", 2),
        (
            "LEGACY-JS-SEMGREP-javascript_require_rule-non-literal-require",
            2,
        ),
        ("LEGACY-JS-SEMGREP-javascript-alert", 2),
        ("LEGACY-JS-SEMGREP-javascript-confirm", 1),
        ("LEGACY-JS-SEMGREP-javascript-prompt", 2),
        ("LEGACY-JS-SEMGREP-javascript-debugger", 1),
        ("LEGACY-JS-SEMGREP-insecure-createnodesfrommarkup", 3),
        ("LEGACY-JS-SEMGREP-detect-buffer-noassert", 2),
        (
            "LEGACY-JS-SEMGREP-javascript_random_rule-pseudo-random-bytes",
            1,
        ),
        ("LEGACY-JS-SEMGREP-detect-angular-open-redirect", 2),
        ("LEGACY-JS-SEMGREP-insecure-innerhtml", 2),
        ("LEGACY-JS-SEMGREP-detect-disable-mustache-escape", 1),
        ("LEGACY-JS-SEMGREP-assigned-undefined", 4),
        ("LEGACY-JS-SEMGREP-detect-replaceall-sanitization", 2),
        ("LEGACY-JS-SEMGREP-incomplete-sanitization", 2),
    ] {
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .count(),
            expected,
            "unexpected findings for {rule_id}: {findings:#?}"
        );
    }

    let lexical = builtin_security_pack().expect("built-in pack").scan_text(
        &Language::JavaScript,
        Path::new(path),
        source,
    );
    assert_eq!(
        lexical
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JS-SEMGREP-detect-pseudoRandomBytes")
            .count(),
        1
    );

    let mustache = "{{{include 'partial'}}}\n{{{user.name}}}\n{{&account}}\n{{safe}}\n";
    let mustache_findings = builtin_security_pack().expect("built-in pack").scan_text(
        &Language::JavaScript,
        Path::new("view.mustache"),
        mustache,
    );
    assert_eq!(
        mustache_findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JS-SEMGREP-mustache-explicit-unescape")
            .count(),
        2,
        "{mustache_findings:#?}"
    );

    let pug = r#"
a(href!=url) Documentation
if value !== true
h1 !{title_text}
script(type="text/javascript")=src
script(type="text/javascript")="a += " + a
script="var a = 1;"
"#;
    let pug_findings = builtin_security_pack().expect("built-in pack").scan_text(
        &Language::JavaScript,
        Path::new("view.pug"),
        pug,
    );
    assert_eq!(
        pug_findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JS-SEMGREP-pug-explicit-unescape")
            .count(),
        2,
        "{pug_findings:#?}"
    );
    assert_eq!(
        pug_findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-JS-SEMGREP-pug-var-in-script-tag")
            .count(),
        2,
        "{pug_findings:#?}"
    );
}
