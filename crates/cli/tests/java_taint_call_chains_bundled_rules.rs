use std::{path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

fn scan(body: &str) -> Vec<serde_json::Value> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-java-call-chains-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let source = format!("package demo; class JavaLegacyCallChains {{ void check(javax.servlet.http.HttpServletRequest request, javax.servlet.ServletRequest servletRequest, javax.servlet.http.HttpServletResponse response, javax.servlet.ServletResponse servletResponse, javax.sql.DataSource data, javax.script.ScriptEngineManager engines, com.fasterxml.jackson.databind.ObjectMapper mapper, org.yaml.snakeyaml.Yaml yaml, java.lang.ClassLoader loader, java.net.URL url, java.util.zip.ZipEntry entry, java.io.InputStream input, org.apache.velocity.VelocityContext velocityContext, java.io.Writer writer, com.thoughtworks.xstream.XStream xstream, org.springframework.ldap.core.LdapTemplate ldap, org.springframework.ldap.core.ContextMapper contextMapper) throws Exception {{ {body} }} }}");
    let fixture = scratch.0.join("JavaLegacyCallChains.java");
    std::fs::write(&fixture, &source).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());
    let output = Command::new(&binary).current_dir(&scratch.0)
        .args(["analyze-source", "--language", "java", "--use-default-models", "--input"])
        .arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
}

fn check(body: &str, rule: &str) {
    let findings = scan(body);
    assert!(findings.iter().any(|finding| finding["sink_rule_id"] == rule), "missing {rule}: {findings:#?}");
    let finding = findings.iter().find(|finding| finding["sink_rule_id"] == rule).unwrap();
    assert!(finding["translations"]["zh-CN"]["message"].as_str().is_some_and(|message| !message.is_empty()),
        "bundled sink lost its original Chinese knowledge text: {rule}");
    assert!(finding["standards"].as_array().unwrap().iter().any(|value|
        value.as_str().is_some_and(|value| value.starts_with("LEGACY-MSG-"))), "missing original mapping for {rule}");
}

fn check_absent(body: &str, rule: &str) {
    let findings = scan(body);
    assert!(
        findings.iter().all(|finding| finding["sink_rule_id"] != rule),
        "unexpected {rule}: {findings:#?}"
    );
}

#[test]
fn java_command_chain_executes_from_isolated_binary() {
    check("java.lang.Runtime.getRuntime().exec(request.getQueryString());",
        "legacy.java.sink.d4d80a8b-8a57-4fe8-a313-428d14eecc8d.0");
}

#[test]
fn java_xss_chain_executes_from_isolated_binary() {
    check("response.getWriter().println(request.getQueryString());",
        "legacy.java.sink.88fbda79-ef5d-42d5-8732-84a3f9b4df84.0");
}

#[test]
fn java_sql_chain_executes_from_isolated_binary() {
    check("data.getConnection().createStatement().executeQuery(request.getQueryString());",
        "legacy.java.sink.bc4f4fcb-12de-41ab-81d6-6d9915c0e93e.0");
}

#[test]
fn java_prepared_statement_chain_executes_from_isolated_binary() {
    check("data.getConnection().prepareStatement(\"SELECT name FROM employee WHERE id=?\").setString(1, request.getQueryString());",
        "legacy.java.sink.e750712b-53c0-41ba-8dbc-0485c529fd6c.0");
}

#[test]
fn java_numeric_update_rule_executes_from_isolated_binary() {
    check("int value = request.getContentLength(); data.getConnection().prepareStatement(\"SELECT name FROM employee WHERE id=?\").setInt(1, ++value);",
        "legacy.java.sink.e750712b-53c0-41ba-8dbc-0485c529fd6c.0");
}

#[test]
fn java_script_engine_chain_executes_from_isolated_binary() {
    check("engines.getEngineByName(\"js\").eval(request.getQueryString());",
        "legacy.java.sink.3ccfd229-9573-47ef-8cb3-282fa5b90050.0");
}

#[test]
fn java_xpath_chain_executes_from_isolated_binary() {
    check("javax.xml.xpath.XPathFactory.newInstance().newXPath().compile(request.getQueryString());",
        "legacy.java.sink.bd0676d8-9535-412b-9c73-7086b7c4fc7a.0");
}

#[test]
fn java_document_builder_chain_executes_from_isolated_binary() {
    check("javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(request.getQueryString());",
        "legacy.java.sink.bc04233f-8917-441c-9f17-1432e3f70567.0");
}

#[test]
fn java_hardened_document_builder_is_suppressed_from_isolated_binary() {
    check_absent(
        "javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance(); factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false); factory.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false); factory.newDocumentBuilder().parse(request.getQueryString());",
        "legacy.java.sink.bc04233f-8917-441c-9f17-1432e3f70567.0",
    );
}

#[test]
fn java_ldap_search_executes_from_isolated_binary() {
    check("javax.naming.directory.DirContext directory = null; directory.search(request.getQueryString(), new Object());",
        "legacy.java.sink.7b6724bf-df47-45b8-9c28-41e3ee0d6f44.0");
}

#[test]
fn java_url_ssrf_executes_from_isolated_binary() {
    check("java.net.URL url = new java.net.URL(request.getQueryString()); url.openStream();",
        "legacy.java.sink.56be2062-96cf-47f6-83c9-c240e1405591.0");
}

#[test]
fn java_path_constructor_executes_from_isolated_binary() {
    check("new java.io.FileInputStream(request.getQueryString());",
        "legacy.java.sink.9745461f-0d31-4eec-9cb4-aa344d78a475.0");
}

#[test]
fn java_redirect_executes_from_isolated_binary() {
    check("servletResponse.sendRedirect(request.getQueryString());",
        "legacy.java.sink.7508d877-8930-4793-bd4a-ca2f4ecfa86b.0");
}

#[test]
fn java_json_deserialization_executes_from_isolated_binary() {
    check("mapper.readValue(request.getQueryString());",
        "legacy.java.sink.d9f07628-44b6-4f47-8832-1f8e25bb6897.0");
}

#[test]
fn java_yaml_deserialization_executes_from_isolated_binary() {
    check("yaml.load(request.getQueryString());",
        "legacy.java.sink.5a734fb6-6c09-45ff-8509-0d73a9bcbee0.0");
}

#[test]
fn java_unsafe_reflection_executes_from_isolated_binary() {
    check("loader.loadClass(request.getQueryString());",
        "legacy.java.sink.8dd1b89d-71f3-4e46-b892-fa201b5ba4f8.0");
}

#[test]
fn java_header_manipulation_executes_from_isolated_binary() {
    check("url.openConnection().setRequestProperty(\"X-Test\", request.getQueryString());",
        "legacy.java.sink.5ecb478e-f708-4016-9136-d690d7e756ce.0");
}

#[test]
fn java_zip_entry_overwrite_executes_from_isolated_binary() {
    check("java.nio.file.Files.copy(input, java.nio.file.Paths.get(entry.getName()));",
        "legacy.java.sink.d3fe1216-f703-495e-842a-ea717bfb66a4.0");
}

#[test]
fn java_regex_injection_executes_from_isolated_binary() {
    check("java.util.regex.Pattern.compile(request.getQueryString());",
        "legacy.java.sink.27d1313b-f16a-465f-b5f9-4baac6da4cad.0");
}

#[test]
fn java_ognl_injection_executes_from_isolated_binary() {
    check("ognl.Ognl.getValue(request.getQueryString(), new Object());",
        "legacy.java.sink.d867f4a4-afd9-4817-8710-c592ae497744.0");
}

#[test]
fn java_velocity_template_injection_executes_from_isolated_binary() {
    check("org.apache.velocity.app.Velocity.evaluate(velocityContext, writer, \"audit\", request.getQueryString());",
        "legacy.java.sink.54de28b5-3964-494d-bf0f-f20f7c87b936.0");
}

#[test]
fn java_xml_decoder_injection_executes_from_isolated_binary() {
    check("new java.beans.XMLDecoder(servletRequest.getInputStream());",
        "legacy.java.sink.b0e4cef3-b2fb-4257-a00c-246e5173d843.0");
}

#[test]
fn java_xstream_deserialization_executes_from_isolated_binary() {
    check("xstream.fromXML(request.getQueryString());",
        "legacy.java.sink.8632100d-b549-479a-a992-70cf4045b2bf.0");
}

#[test]
fn java_jndi_reference_injection_executes_from_isolated_binary() {
    check("ldap.lookup(request.getQueryString(), contextMapper);",
        "legacy.java.sink.41ebde44-0880-4aab-8d83-0becd4c88625.0");
}
