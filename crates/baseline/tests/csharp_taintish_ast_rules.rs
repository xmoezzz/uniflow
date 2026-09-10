use std::{collections::HashMap, path::Path, sync::OnceLock};
use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;
use uniflow_lang_frontends::parse_file;

fn findings(source: &str) -> Vec<String> {
    let program = parse_file(Language::CSharp, "Input.cs", source).expect("parse C#");
    builtin_security_pack()
        .expect("pack")
        .scan_hir(
            &program,
            &HashMap::from([("Input.cs".to_string(), source.to_string())]),
        )
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

fn check_rule(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<uniflow_baseline::BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let program = parse_file(Language::CSharp, "Input.cs", source).unwrap();
    let actual = pack.scan_hir(
        &program,
        &HashMap::from([("Input.cs".into(), source.into())]),
    );
    assert_eq!(actual.len(), expected, "{rule}: {source}\n{actual:#?}");
}

#[test]
fn migrated_csharp_sql_adapter_requires_declared_source_provenance() {
    for rule in [
        "LEGACY-CS-AST-SCS0002",
        "LEGACY-CS-AST-security_risky_sql_query",
    ] {
        check_rule(
            rule,
            "class A { void F(string p) { var x = new SqlDataAdapter(\"select \" + p, conn); } }",
            1,
        );
        check_rule(rule, "class A { void F() { string q = Request.QueryString[\"q\"]; var x = new SqlDataAdapter(q, conn); } }", 1);
        check_rule(rule, "class A { void F() { string q = Request[\"q\"]; var x = new SqlDataAdapter(q, conn); } }", 1);
        check_rule(rule, "class A { string q = Request.QueryString[\"q\"]; void F() { var x = new SqlDataAdapter(q, conn); } }", 1);
        check_rule(rule, "class A { string q = Request.QueryString[\"q\"]; void F(int q) { var x = new SqlDataAdapter(q, conn); } }", 0);
        check_rule(rule, "class A { void F() { string q = \"select 1\"; var x = new SqlDataAdapter(q, conn); } }", 0);
        check_rule(rule, "class A { void F() { string q = \"Request.QueryString\"; var x = new SqlDataAdapter(q, conn); } }", 0);
        check_rule(
            rule,
            "class A { void F() { string q = helper(); var x = new SqlDataAdapter(q, conn); } }",
            0,
        );
        check_rule(
            rule,
            "class A { void F(int p) { var x = new SqlDataAdapter(p.ToString(), conn); } }",
            0,
        );
        check_rule(
            rule,
            "class A { void F(string p) { var x = new SqlDataAdapter(\"fixed\", conn); } }",
            0,
        );
    }
}

#[test]
fn migrated_csharp_typed_query_rules_match_nested_declaration_references() {
    for (rule, ty, call) in [
        ("LEGACY-CS-AST-SCS0003", "XPathNavigator", "Select"),
        (
            "LEGACY-CS-AST-input_validation_and_representation_linq",
            "DataContext",
            "ExecuteCommand",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_nhibernate",
            "ISession",
            "CreateQuery",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_xquery_injection",
            "XQueryCompiler",
            "Compile",
        ),
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F({ty} api, string p) {{ api.{call}(\"prefix\" + p); }} }}"),
            1,
        );
        check_rule(
            rule,
            &format!(
                "class A {{ void F({ty} api) {{ string p = \"constant\"; api.{call}(p); }} }}"
            ),
            1,
        );
        check_rule(
            rule,
            &format!("class A {{ void F({ty} api) {{ api.{call}(\"constant\"); }} }}"),
            0,
        );
        check_rule(
            rule,
            &format!("class A {{ void F({ty} api, int p) {{ api.{call}(p.ToString()); }} }}"),
            0,
        );
        check_rule(
            rule,
            &format!("class A {{ void F(Unrelated api, string p) {{ api.{call}(p); }} }}"),
            0,
        );
    }
}

#[test]
fn migrated_csharp_log_forging_distinguishes_parameters_and_initializers() {
    let rule = "LEGACY-CS-AST-input_validation_and_representation_log_forging";
    check_rule(
        rule,
        "class A { void F(string p, Logger log) { log.Warn(\"prefix\" + p); } }",
        1,
    );
    check_rule(
        rule,
        "class A { void F(Logger log) { string p = Request.Form[\"p\"]; log.Warn(p); } }",
        1,
    );
    check_rule(
        rule,
        "class A { void F(Logger log) { string p = \"fixed\"; log.Warn(p); } }",
        0,
    );
    // Original log rule accepts member access, not direct Request[...] access.
    check_rule(
        rule,
        "class A { void F(Logger log) { string p = Request[\"p\"]; log.Warn(p); } }",
        0,
    );
}

#[test]
fn migrated_csharp_file_paths_use_each_apis_argument_position() {
    let rule = "LEGACY-CS-AST-SCS0018";
    for statement in [
        "File.Create(p);",
        "Request.WriteFile(p);",
        "Request.MapPath(p);",
        "Request.TransmitFile(p);",
        "provider.GetFileInfo(p);",
        "client.DownloadFile(\"url\", p);",
        "client.DownloadFileAsync(\"url\", p);",
        "client.DownloadFileTaskAsync(\"url\", p);",
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F(string p) {{ {statement} }} }}"),
            1,
        );
    }
    for statement in [
        "Unrelated.Create(p);",
        "Response.MapPath(p);",
        "client.DownloadFile(p, \"fixed\");",
        "client.DownloadFileAsync(p, \"fixed\");",
        "client.DownloadFile(p);",
        "GetFileInfo(p);",
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F(string p) {{ {statement} }} }}"),
            0,
        );
    }
    check_rule(
        rule,
        "class A { void F() { string p = Response.Value; File.Create(p); } }",
        1,
    );
    check_rule(
        rule,
        "class A { void F() { string p = Request.Value; File.Create(p); } }",
        0,
    );
    check_rule(
        rule,
        "class A { void F() { string p = \"fixed\"; File.Create(p); } }",
        0,
    );
}

#[test]
fn migrated_csharp_exception_disclosure_requires_catch_receiver_and_exception() {
    for (rule, receiver) in [
        ("LEGACY-CS-AST-encapsulation_external", "Reponse"),
        ("LEGACY-CS-AST-encapsulation_internal", "Console"),
        (
            "LEGACY-CS-AST-encapsulation_system_information_leak",
            "Console",
        ),
    ] {
        check_rule(rule, &format!("class A {{ void F() {{ try {{ Work(); }} catch(Exception ex) {{ {receiver}.Write(\"error\", ex.Message); }} }} }}"), 1);
        check_rule(
            rule,
            &format!("class A {{ void F(Exception ex) {{ {receiver}.Write(ex); }} }}"),
            0,
        );
        check_rule(rule, &format!("class A {{ void F() {{ try {{ Work(); }} catch(Exception ex) {{ {receiver}.Write(\"fixed\"); }} }} }}"), 0);
        check_rule(
            rule,
            "class A { void F() { try { Work(); } catch(Exception ex) { Other.Write(ex); } } }",
            0,
        );
        check_rule(rule, &format!("class A {{ void F() {{ try {{ Work(); }} catch(CustomException ex) {{ {receiver}.Write(ex); }} }} }}"), 0);
        check_rule(rule, &format!("class A {{ void F() {{ try {{ Work(); }} catch(Exception ex) {{ Action later = () => {receiver}.Write(ex); }} }} }}"), 0);
    }
}

#[test]
fn migrated_csharp_websocket_options_preserve_same_symbol_exclusion() {
    let rule = "LEGACY-CS-AST-security_websocket_hacking";
    check_rule(rule, "class A { void F(AspNetWebSocketOptions options) { context.AcceptWebSocketRequest(handler, options); } }", 1);
    check_rule(rule, "class A { void F(AspNetWebSocketOptions options) { options.RequireSameOrigin = true; context.AcceptWebSocketRequest(handler, options); } }", 0);
    // Legacy is an enclosing-block existence check, even when set after the call.
    check_rule(rule, "class A { void F(AspNetWebSocketOptions options) { context.AcceptWebSocketRequest(handler, options); options.RequireSameOrigin = true; } }", 0);
    check_rule(rule, "class A { void F(AspNetWebSocketOptions options, AspNetWebSocketOptions other) { other.RequireSameOrigin = true; context.AcceptWebSocketRequest(handler, options); } }", 1);
    check_rule(rule, "class A { void F(AspNetWebSocketOptions options) { options.RequireSameOrigin = false; context.AcceptWebSocketRequest(handler, options); } }", 1);
    check_rule(
        rule,
        "class A { void F(object options) { context.AcceptWebSocketRequest(handler, options); } }",
        0,
    );
    check_rule(rule, "class A { void F(AspNetWebSocketOptions options) { context.AcceptWebSocketRequest(options); } }", 0);
}

#[test]
fn migrated_csharp_redirect_and_cookie_preserve_legacy_if_exclusions() {
    for (rule, statement) in [
        ("LEGACY-CS-AST-SCS0027", "Response.Redirect(p);"),
        (
            "LEGACY-CS-AST-input_validation_and_representation_cookies",
            "var c = new Cookie(\"n\", p);",
        ),
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F(string p) {{ {statement} }} }}"),
            1,
        );
        check_rule(
            rule,
            &format!("class A {{ void F(string p) {{ if(IsLocal(p)) {{ {statement} }} }} }}"),
            0,
        );
        check_rule(
            rule,
            &format!(
                "class A {{ void F(string p) {{ if(IsLocal(p)) {{ Work(); }} {statement} }} }}"
            ),
            0,
        );
        check_rule(
            rule,
            &format!(
                "class A {{ void F(string p) {{ {statement} if(IsLocal(p)) {{ Work(); }} }} }}"
            ),
            1,
        );
        check_rule(rule, &format!("class A {{ void F(string p, string other) {{ if(IsLocal(other)) {{ Work(); }} {statement} }} }}"), 1);
        check_rule(rule, &format!("class A {{ void Guard(string p) {{ if(IsLocal(p)) {{ Work(); }} }} void F(string p) {{ {statement} }} }}"), 1);
    }
    check_rule(
        "LEGACY-CS-AST-SCS0027",
        "class A { void F(string p) { Other.Redirect(p); } }",
        0,
    );
}

#[test]
fn migrated_csharp_xss_header_uses_structural_receiver_and_argument_tokens() {
    let rule = "LEGACY-CS-AST-xss_protection";
    for statement in [
        "Response.AddHeader(\"X-XSS-Protection\", 0);",
        "response.AppendHeader(\"X-XSS-Protection\", disabled);",
        "Response.Headers.Remove(\"X-XSS-Protection\");",
        "response.Headers.Remove(\"X-XSS-Protection\");",
        // Legacy flag regex matches the quotes in a string argument, including "1".
        "response.AddHeader(\"X-XSS-Protection\", \"1\");",
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F(HttpResponse response) {{ {statement} }} }}"),
            1,
        );
    }
    for statement in [
        "Other.AddHeader(\"X-XSS-Protection\", 0);",
        "Other.Headers.Remove(\"X-XSS-Protection\");",
        "response.AddHeader(\"Other\", 0);",
        "response.AddHeader(\"X-XSS-Protection\", 1);",
        "response.AddHeader(\"X-XSS-Protection\", /* comment */ 1);",
        "response.Remove(\"X-XSS-Protection\");",
        "/* Response.Headers.Remove(\"X-XSS-Protection\"); */",
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F(HttpResponse response) {{ {statement} }} }}"),
            0,
        );
    }
}

#[test]
fn migrated_csharp_upload_encoding_and_template_rules_have_negative_cases() {
    for (rule, parameters, positive, negative) in [
        (
            "LEGACY-CS-AST-input_validation_and_representation_file_upload_1",
            "HtmlInputFile input, object other",
            "var f = input.PostedFile;",
            "var f = other.PostedFile;",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_file_upload_2",
            "FileUpload input, object other",
            "input.SaveAs(path);",
            "other.SaveAs(path);",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_poor_validation",
            "string p",
            "HttpUtility.HtmlEncode(p);",
            "Unrelated.HtmlEncode(p);",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_razor",
            "string p",
            "Razor.Parse(\"prefix\" + p, model);",
            "Other.Parse(p, model);",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_castle_activerecord",
            "string p",
            "var q = new SimpleQuery<Model>(\"prefix\" + p);",
            "var q = new SimpleQuery<Model>(\"fixed\");",
        ),
        (
            "LEGACY-CS-AST-input_validation_and_representation_subsonic",
            "string p",
            "var q = new InlineQuery(\"prefix\" + p);",
            "var q = new InlineQuery(\"fixed\");",
        ),
    ] {
        check_rule(
            rule,
            &format!("class A {{ void F({parameters}) {{ {positive} }} }}"),
            1,
        );
        check_rule(
            rule,
            &format!("class A {{ void F({parameters}) {{ {negative} }} }}"),
            0,
        );
        check_rule(
            rule,
            &format!("class A {{ void F({parameters}) {{ /* {positive} */ }} }}"),
            0,
        );
    }
}

#[test]
fn migrated_csharp_antiforgery_attributes_are_owned_by_the_method() {
    static PACK: OnceLock<uniflow_baseline::BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|rule| rule.id == "LEGACY-CS-AST-SCS0016");
    assert_eq!(pack.rules.len(), 1);
    for (source, expected) in [
        ("class A { [HttpPost] void Bad() {} }", 1),
        (
            "class A { [ValidateAntiForgeryToken] [HttpPost] void Safe() {} }",
            0,
        ),
        (
            "class A { [HttpPost] [ValidateAntiForgeryToken] void Safe() {} }",
            0,
        ),
        (
            "class A { [HttpPost, ValidateAntiForgeryToken] void Safe() {} }",
            0,
        ),
        (
            "class A { [HttpPost] void Bad() {} [ValidateAntiForgeryToken] void Other() {} }",
            1,
        ),
        ("[HttpPost] class A { void Ordinary() {} }", 0),
        ("class A { [Note(\"[HttpPost]\")] void Ordinary() {} }", 0),
        ("class A { /* [HttpPost] */ void Ordinary() {} }", 0),
        // Source rule anchors the entire attribute, excluding arguments/qualification.
        (
            "class A { [HttpPost()] void Ordinary() {} [Mvc.HttpPost] void Other() {} }",
            0,
        ),
        (
            "class A { [HttpPost] [ValidateAntiForgeryToken()] void Bad() {} }",
            1,
        ),
        (
            "class A { [Note(values = new[] {1, 2})] [HttpPost] public async Task Bad() {} }",
            1,
        ),
        (
            "class A { class B { [HttpPost] void Bad() {} } [HttpGet] void Good() {} }",
            1,
        ),
    ] {
        let actual = pack.scan_text(&Language::CSharp, Path::new("Attributes.cs"), source);
        assert_eq!(actual.len(), expected, "{source}\n{actual:#?}");
        let program = parse_file(Language::CSharp, "Attributes.cs", source).unwrap();
        let integrated = pack.scan_hir(
            &program,
            &HashMap::from([("Attributes.cs".into(), source.into())]),
        );
        assert_eq!(integrated.len(), expected, "HIR {source}\n{integrated:#?}");
    }
}

#[test]
fn migrated_csharp_taintish_ast_rules_preserve_typed_sinks_and_attributes() {
    let source = r#"
class InputController {
    [HttpPost]
    void Save(string query, string xpath, string path, string url,
              XPathNavigator navigator, HtmlInputFile input, FileUpload upload) {
        var adapter = new SqlDataAdapter(query, connection);
        navigator.Select(xpath);
        File.Create(path);
        Response.Redirect(url);
        var active = new SimpleQuery<Model>(query);
        var cookie = new Cookie("name", path);
        var posted = input.PostedFile;
        upload.SaveAs(path);
        HttpUtility.HtmlEncode(query);
        Razor.Parse(query, model);
        var inline = new InlineQuery(query);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    void Protected(string literal) {
        var adapter = new SqlDataAdapter("select 1", connection);
        Response.Redirect("/home");
    }
}
"#;
    let actual = findings(source);
    for rule in [
        "LEGACY-CS-AST-SCS0002",
        "LEGACY-CS-AST-SCS0003",
        "LEGACY-CS-AST-SCS0016",
        "LEGACY-CS-AST-SCS0018",
        "LEGACY-CS-AST-SCS0027",
        "LEGACY-CS-AST-input_validation_and_representation_castle_activerecord",
        "LEGACY-CS-AST-input_validation_and_representation_cookies",
        "LEGACY-CS-AST-input_validation_and_representation_file_upload_1",
        "LEGACY-CS-AST-input_validation_and_representation_file_upload_2",
        "LEGACY-CS-AST-input_validation_and_representation_poor_validation",
        "LEGACY-CS-AST-input_validation_and_representation_razor",
        "LEGACY-CS-AST-input_validation_and_representation_subsonic",
    ] {
        assert!(
            actual.iter().any(|candidate| candidate == rule),
            "missing {rule}: {actual:#?}"
        );
    }
    assert_eq!(
        actual
            .iter()
            .filter(|id| id.as_str() == "LEGACY-CS-AST-SCS0016")
            .count(),
        1,
        "{actual:#?}"
    );
    assert_eq!(
        actual
            .iter()
            .filter(|id| id.as_str() == "LEGACY-CS-AST-SCS0002")
            .count(),
        1,
        "{actual:#?}"
    );
    assert_eq!(
        actual
            .iter()
            .filter(|id| id.as_str() == "LEGACY-CS-AST-SCS0027")
            .count(),
        1,
        "{actual:#?}"
    );
}
