use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bundled_findings(source: &str, rule_ids: &[&str]) -> Vec<serde_json::Value> {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-javascript-taint-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("semgrep-taint.js");
    std::fs::write(&fixture, source).unwrap();
    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());

    let mut command = Command::new(&binary);
    command.current_dir(&scratch.0).args([
        "analyze-source",
        "--language",
        "javascript",
        "--use-default-models",
    ]);
    for rule_id in rule_ids {
        command.args(["--rule-id", rule_id]);
    }
    let output = command.args(["--input"]).arg(&fixture).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
}

#[test]
fn dynamic_require_and_regexp_rules_execute_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
function load(name) { const moduleName = name; return require(moduleName); }
function compile(pattern) { return new RegExp(pattern); }
function safe() { require("./fixed.js"); RegExp("fixed"); }
"#,
        &[
            "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-require",
            "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-regexp",
        ],
    );
    for sink in [
        "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-require",
        "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-regexp",
    ] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicated {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-function-argument"
                && finding["analysis_complete"] == true
        }));
    }
}

#[test]
fn md5_password_rule_executes_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
function passwords(user, input) {
    const digest = crypto.createHash("md5").update(input).digest("hex");
    user.setPassword(digest);
    user.setPassword(crypto.createHash("sha256").update(input).digest("hex"));
}
"#,
        &["LEGACY-JS-SEMGREP-TAINT-md5-used-as-password"],
    );
    let md5 = findings
        .iter()
        .filter(|finding| finding["sink_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-md5-used-as-password")
        .collect::<Vec<_>>();
    assert_eq!(
        md5.len(),
        1,
        "missing or duplicated MD5 finding: {findings:#?}"
    );
    assert!(md5.iter().all(|finding| {
        finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-md5-password"
            && finding["analysis_complete"] == true
    }));
}

#[test]
fn insecure_object_assign_rule_executes_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
function assign(target, input) {
    Object.assign(target, JSON.parse(input));
    Object.assign(target, JSON.parse('{"fixed": true}'));
}
"#,
        &["LEGACY-JS-SEMGREP-TAINT-insecure-object-assign"],
    );
    let object_assign = findings
        .iter()
        .filter(|finding| {
            finding["sink_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-insecure-object-assign"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        object_assign.len(),
        1,
        "missing or duplicated Object.assign finding: {findings:#?}"
    );
    assert!(object_assign.iter().all(|finding| {
        finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-insecure-object-assign"
            && finding["analysis_complete"] == true
    }));
}

#[test]
fn commonjs_package_scoped_rules_execute_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
function execute(command, object) {
    const child = require("child_process");
    child.exec(command);
    child.exec("fixed-command");
    const bluebird = require("bluebird");
    bluebird.toFastProperties(object);
    const unrelated = require("unrelated");
    unrelated.exec(command);
    unrelated.toFastProperties(object);
}
"#,
        &[
            "LEGACY-JS-SEMGREP-TAINT-detect-child-process",
            "LEGACY-JS-SEMGREP-TAINT-tofastproperties-code-execution",
        ],
    );
    for sink in [
        "LEGACY-JS-SEMGREP-TAINT-detect-child-process",
        "LEGACY-JS-SEMGREP-TAINT-tofastproperties-code-execution",
    ] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicated {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-function-argument"
                && finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn database_rules_execute_with_package_provenance_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
function mysqlQuery(sql) {
    const mysql = require("mysql2");
    const connection = mysql.createConnection();
    connection.query(sql);
    connection.query(parseInt(sql));
}
function mssqlQuery(sql) {
    const mssql = require("mssql");
    const pool = new mssql.ConnectionPool();
    const request = pool.request();
    request.query(sql);
}
function postgresQuery(sql) {
    const pg = require("pg");
    const client = new pg.Client();
    client.query(sql);
}
function unrelatedQuery(sql) {
    const unrelated = require("unrelated");
    const client = unrelated.createClient();
    client.query(sql);
}
"#,
        &[
            "LEGACY-JS-SEMGREP-TAINT-node-mysql-sqli",
            "LEGACY-JS-SEMGREP-TAINT-node-mssql-sqli",
            "LEGACY-JS-SEMGREP-TAINT-node-postgres-sqli",
        ],
    );
    for sink in [
        "LEGACY-JS-SEMGREP-TAINT-node-mysql-sqli",
        "LEGACY-JS-SEMGREP-TAINT-node-mssql-sqli",
        "LEGACY-JS-SEMGREP-TAINT-node-postgres-sqli",
    ] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicated {sink}: {findings:#?}"
        );
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn aws_lambda_rules_execute_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
exports.handler = function(event) {
    const child = require("child_process");
    child.exec(event);
    child.exec("fixed-command");
    eval(event);
    eval("fixed-expression");
};
function helper(input) {
    const child = require("child_process");
    child.exec(input);
    eval(input);
}
"#,
        &[
            "LEGACY-JS-SEMGREP-TAINT-aws-detect-child-process",
            "LEGACY-JS-SEMGREP-TAINT-aws-tainted-eval",
        ],
    );
    for sink in [
        "LEGACY-JS-SEMGREP-TAINT-aws-detect-child-process",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-eval",
    ] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicated {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event"
                && finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn aws_lambda_service_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-aws-dynamodb-request-object",
        "LEGACY-JS-SEMGREP-TAINT-aws-knex-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-mysql-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-pg-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-sequelize-sqli",
        "LEGACY-JS-SEMGREP-TAINT-aws-vm-runincontext-injection",
    ];
    let findings = bundled_findings(
        r#"
exports.handler = function(event) {
    const AWS = require("aws-sdk");
    new AWS.DynamoDB.DocumentClient().query(event);
    require("knex").raw(event);
    require("mysql2").createPool().query(event);
    const pg = require("pg");
    const pgDb = new pg.Client();
    pgDb.query(event);
    require("sequelize").query(event);
    require("vm").runInThisContext(event);

    const unrelated = require("unrelated");
    unrelated.query(event);
    unrelated.raw(event);
    unrelated.runInThisContext(event);
};
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicated {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event"
                && finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn aws_lambda_expression_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-response",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-string",
        "LEGACY-JS-SEMGREP-TAINT-aws-tainted-sql-string",
    ];
    let findings = bundled_findings(
        r#"
exports.handler = function(event) {
    const response = {
        headers: { "Content-Type": "text/html" },
        body: event
    };
    const html = "<main>" + event;
    const sql = "SELECT * FROM records WHERE id = " + event;
    const ordinary = "plain text " + event;
    const json = { body: event };
    return [response, html, sql, ordinary, json];
};
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "missing or duplicated {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-aws-lambda-event"
                && finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn browser_taint_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-js-open-redirect-from-function",
        "LEGACY-JS-SEMGREP-TAINT-js-open-redirect",
        "LEGACY-JS-SEMGREP-TAINT-detect-eval-with-expression",
        "LEGACY-JS-SEMGREP-TAINT-raw-html-concat",
    ];
    let findings = bundled_findings(
        r#"
function redirect(target) {
    location.href = target;
    window.location.replace(target);
}
function browserData() {
    const query = location.search;
    eval(query);
    const html = "<article>" + query;
    window.location.href = query;
    const safe = DOMPurify.sanitize(query);
    const sanitizedHtml = "<aside>" + safe;
    const ordinary = "plain " + query;
    return [html, sanitizedHtml, ordinary];
}
"#,
        &sink_ids,
    );
    for (sink, expected) in [
        (sink_ids[0], 2),
        (sink_ids[1], 1),
        (sink_ids[2], 1),
        (sink_ids[3], 1),
    ] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            expected,
            "wrong count for {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn angular_taint_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-detect-angular-element-methods",
        "LEGACY-JS-SEMGREP-TAINT-detect-angular-element-taint",
        "LEGACY-JS-SEMGREP-TAINT-detect-angular-trust-as-method",
    ];
    let findings = bundled_findings(
        r##"
function controller($scope, $sce, $sanitize, $injector) {
    const view = angular.element("#output");
    view.append($scope.html);
    view.html($sanitize($scope.safe));
    $sce.trustAsHtml($scope.html);
    const injected = $injector.get('$scope');
    view.after(injected.message);
    const unrelated = $injector.get('service');
    view.prepend(unrelated.message);
}
function browserData() {
    const view = angular.element("#browser");
    view.wrap(location.search);
    view.prepend(DOMPurify.sanitize(location.search));
}
"##,
        &sink_ids,
    );
    for (sink, expected) in [(sink_ids[0], 2), (sink_ids[1], 1), (sink_ids[2], 1)] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            expected,
            "wrong count for {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn hardcoded_jwt_rule_executes_from_isolated_binary() {
    let sink = "LEGACY-JS-SEMGREP-TAINT-hardcoded-jwt-secret";
    let findings = bundled_findings(
        r#"
function tokens(data, configured) {
    const jwt = require("jsonwebtoken");
    const fixed = "development-secret";
    jwt.sign(data, fixed);
    jwt.verify(data, "inline-secret");
    jwt.sign(data, configured);
    const unrelated = require("unrelated");
    unrelated.sign(data, "not-a-jwt-secret");
}
"#,
        &[sink],
    );
    let matching = findings
        .iter()
        .filter(|finding| finding["sink_rule_id"] == sink)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 2, "{findings:#?}");
    assert!(matching.iter().all(|finding| {
        finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-hardcoded-jwt-secret"
            && finding["analysis_complete"] == true
            && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                finding["translations"][locale]["message"]
                    .as_str()
                    .is_some_and(|message| !message.is_empty())
            })
    }));
}

#[test]
fn web_request_eval_rule_executes_from_isolated_binary() {
    let sink = "LEGACY-JS-SEMGREP-TAINT-code-string-concat";
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    const expression = "lookup(" + request.query + ")";
    eval(expression);
    eval(response.body);
    eval("fixedExpression()");
}
"#,
        &[sink],
    );
    let matching = findings
        .iter()
        .filter(|finding| finding["sink_rule_id"] == sink)
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "{findings:#?}");
    assert!(matching.iter().all(|finding| {
        finding["source_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-SOURCE-web-request-first-argument"
            && finding["analysis_complete"] == true
            && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                finding["translations"][locale]["message"]
                    .as_str()
                    .is_some_and(|message| !message.is_empty())
            })
    }));
}

#[test]
fn knex_and_path_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-node-knex-sqli",
        "LEGACY-JS-SEMGREP-TAINT-path-join-resolve-traversal",
    ];
    let findings = bundled_findings(
        r#"
function query(request, response) {
    const knex = require("knex");
    knex.whereRaw(request.query);
    knex.raw(parseInt(request.query));
    require("unrelated").raw(request.query);
}
function locate(prefix, name) {
    const path = require("path");
    path.resolve(prefix, name);
    path.join("/safe", name.replace("..", ""));
    require("unrelated").resolve(name);
}
"#,
        &sink_ids,
    );
    for (sink, expected) in [(sink_ids[0], 1), (sink_ids[1], 2)] {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            expected,
            "wrong count for {sink}: {findings:#?}"
        );
        assert!(matching.iter().all(|finding| {
            finding["analysis_complete"] == true
                && ["zh-CN", "en", "zh-TW"].iter().all(|locale| {
                    finding["translations"][locale]["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty())
                })
        }));
    }
}

#[test]
fn unsafe_formatstring_rule_executes_from_isolated_binary() {
    let findings = bundled_findings(
        r#"
const util = require("util");
function render(name, value) {
    console.log("user:" + name, value);
    util.format("prefix".concat(name), value);
    console.log("fixed", value);
    console.log("a" + "b", value);
}
"#,
        &["LEGACY-JS-SEMGREP-TAINT-unsafe-formatstring"],
    );
    let matching = findings
        .iter()
        .filter(|finding| finding["sink_rule_id"] == "LEGACY-JS-SEMGREP-TAINT-unsafe-formatstring")
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 2, "{findings:#?}");
    assert!(matching.iter().all(|finding| {
        finding["source_rule_id"].as_str().is_some_and(|source| {
            source.starts_with("LEGACY-JS-SEMGREP-TAINT-SOURCE-unsafe-formatstring-")
        }) && finding["analysis_complete"] == true
    }));
}

#[test]
fn shell_spawn_and_deno_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-dangerous-spawn-shell",
        "LEGACY-JS-SEMGREP-TAINT-deno-dangerous-run",
    ];
    let findings = bundled_findings(
        r#"
const {spawnSync} = require("child_process");
function execute(input) {
    spawnSync("bash", ["-c", input]);
    spawnSync("ls", [input]);
    Deno.run({cmd: [input], stdout: "piped"});
    Deno.run({cmd: ["echo"], stdout: input});
}

#[test]
fn express_io_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-express-path-join-resolve-traversal",
        "LEGACY-JS-SEMGREP-TAINT-express-res-sendfile",
        "LEGACY-JS-SEMGREP-TAINT-express-ssrf",
        "LEGACY-JS-SEMGREP-TAINT-express-open-redirect",
    ];
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    require("path").join("/base", request.params.name);
    response.sendFile(request.params.file);
    require("request").get(request.query.url);
    response.redirect(request.query.next);
}
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "wrong count for {sink}: {findings:#?}");
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn express_execution_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-express-vm-injection",
        "LEGACY-JS-SEMGREP-TAINT-express-wkhtmltopdf-injection",
    ];
    let findings = bundled_findings(
        r#"
const renderPdf = require("wkhtmltopdf");
function handler(request, response) {
    require("vm").runInNewContext(request.body.code, {});
    renderPdf(request.query.url);
}
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "wrong count for {sink}: {findings:#?}");
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn express_loading_and_sequelize_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-require-request",
        "LEGACY-JS-SEMGREP-TAINT-res-render-injection",
        "LEGACY-JS-SEMGREP-TAINT-express-sequelize-injection",
    ];
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    require(request.query.module);
    response.render(request.query.template);
    require("sequelize").query(request.body.sql);
}
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "wrong count for {sink}: {findings:#?}");
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn express_parser_and_template_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-express-xml2json-xxe",
        "LEGACY-JS-SEMGREP-TAINT-express-third-party-object-deserialization",
        "LEGACY-JS-SEMGREP-TAINT-express-insecure-template-usage",
    ];
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    require("xml2json").toJson(request.body.xml);
    require("node-serialize").unserialize(request.body.payload);
    require("pug").compile(request.body.template);
}
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "wrong count for {sink}: {findings:#?}");
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn express_response_and_composition_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-direct-response-write",
        "LEGACY-JS-SEMGREP-TAINT-express-raw-html-format",
        "LEGACY-JS-SEMGREP-TAINT-express-tainted-sql-string",
    ];
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    response.write(request.query.html);
    const html = "<main>" + request.body.content;
    const sql = "SELECT * FROM users WHERE id=" + request.query.id;
    return [html, sql];
}
"#,
        &sink_ids,
    );
    for sink in sink_ids {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == sink)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1, "wrong count for {sink}: {findings:#?}");
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

fn assert_rule_counts(findings: &[serde_json::Value], expected: &[(&str, usize)]) {
    for (sink, count) in expected {
        let matching = findings
            .iter()
            .filter(|finding| finding["sink_rule_id"] == *sink)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            *count,
            "wrong count for {sink}: {findings:#?}"
        );
        assert!(matching
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn express_object_and_runtime_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-express-data-exfiltration",
        "LEGACY-JS-SEMGREP-TAINT-express-phantom-injection",
        "LEGACY-JS-SEMGREP-TAINT-express-puppeteer-injection",
        "LEGACY-JS-SEMGREP-TAINT-express-expat-xxe",
        "LEGACY-JS-SEMGREP-TAINT-express-vm2-injection",
        "LEGACY-JS-SEMGREP-TAINT-express-sandbox-code-injection",
    ];
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    Object.assign({}, request.body.profile);
    require("phantom").create().createPage().open(request.query.url);
    require("puppeteer").launch().newPage().goto(request.query.url);
    require("node-expat").Parser().parse(request.body.xml);
    require("vm2").VM().run(request.body.code);
    require("sandbox").Sandbox().run(request.body.code);
}
"#,
        &sink_ids,
    );
    let expected = sink_ids.map(|sink| (sink, 1));
    assert_rule_counts(&findings, &expected);
}

#[test]
fn javascript_configured_security_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-unsafe-argon2-config",
        "LEGACY-JS-SEMGREP-TAINT-hardcoded-passport-secret",
        "LEGACY-JS-SEMGREP-TAINT-express-libxml-noent",
    ];
    let findings = bundled_findings(
        r#"
const argon = require("argon2");
const Strategy = require("passport-jwt").Strategy;
function configure(request, password) {
    argon.hash(password, { type: argon.argon2i });
    Strategy({ secretOrKey: "hard-coded" }, verify);
    require("libxmljs").parseXml(request.body.xml, { noent: true });
}
"#,
        &sink_ids,
    );
    let expected = sink_ids.map(|sink| (sink, 1));
    assert_rule_counts(&findings, &expected);
}

#[test]
fn javascript_libxml_rule_executes_from_isolated_binary() {
    let sink_id = "LEGACY-JS-SEMGREP-TAINT-express-libxml-noent";
    let findings = bundled_findings(
        r#"
function handler(request, response) {
    require("libxmljs").parseXml(request.body.xml, { noent: true });
}
"#,
        &[sink_id],
    );
    assert_rule_counts(&findings, &[(sink_id, 1)]);
}

#[test]
fn javascript_header_fs_and_property_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-cors-misconfiguration",
        "LEGACY-JS-SEMGREP-TAINT-x-frame-options-misconfiguration",
        "LEGACY-JS-SEMGREP-TAINT-detect-non-literal-fs-filename",
        "LEGACY-JS-SEMGREP-TAINT-remote-property-injection",
    ];
    let findings = bundled_findings(
        r#"
const fs = require("fs");
function handler(request, response) {
    response.set("Access-Control-Allow-Origin", request.query.origin);
    response.setHeader("X-Frame-Options", request.query.frame);
    fs.copyFile(request.query.source, request.query.destination);
    const target = {};
    target[request.query.key] = request.body.value;
}
"#,
        &sink_ids,
    );
    assert_rule_counts(
        &findings,
        &[
            (sink_ids[0], 1),
            (sink_ids[1], 1),
            (sink_ids[2], 2),
            (sink_ids[3], 1),
        ],
    );
}

#[test]
fn javascript_event_and_chrome_rules_execute_from_isolated_binary() {
    let sink_ids = [
        "LEGACY-JS-SEMGREP-TAINT-express-xml2json-xxe-event",
        "LEGACY-JS-SEMGREP-TAINT-chrome-remote-interface-compilescript-injection",
    ];
    let findings = bundled_findings(
        r#"
function inspect(expression, request) {
    require("chrome-remote-interface").connect().Runtime.compileScript({ expression: expression });
    const parser = require("xml2json");
    request.on("data", function(chunk) { parser.toJson(chunk); });
}
"#,
        &sink_ids,
    );
    let expected = sink_ids.map(|sink| (sink, 1));
    assert_rule_counts(&findings, &expected);
}
