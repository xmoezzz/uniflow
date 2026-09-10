use std::{collections::HashMap, sync::OnceLock};

use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let program = JavaParser::default()
        .parse_file("RuleMapApi.java", source)
        .unwrap();
    let findings = pack.scan_hir(
        &program,
        &HashMap::from([("RuleMapApi.java".to_string(), source.to_string())]),
    );
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

#[test]
fn request_key_parameters_are_not_treated_as_authoritative_values() {
    let rule = "LEGACY-JAVA-RULEMAP-key-parameter-tampering";
    check(rule, "class A { void f(javax.servlet.http.HttpServletRequest request) { String price = request.getParameter(\"price\"); } }", 1);
    check(rule, "class A { void f(javax.servlet.http.HttpServletRequest request) { String product = request.getParameter(\"productId\"); } }", 0);
}

#[test]
fn http_sessions_store_only_serializable_project_types() {
    let rule = "LEGACY-JAVA-RULEMAP-nonserializable-session-value";
    check(rule, "class A { void f(javax.servlet.http.HttpSession session, Cart cart) { session.setAttribute(\"cart\", cart); } } class Cart { int count; }", 1);
    check(rule, "class A { void f(javax.servlet.http.HttpSession session, Cart cart) { session.setAttribute(\"cart\", cart); } } class Cart implements java.io.Serializable { int count; }", 0);
}

#[test]
fn redirect_locations_do_not_contain_password_values() {
    let rule = "LEGACY-JAVA-RULEMAP-password-in-redirect";
    check(rule, "class A { void f(javax.servlet.http.HttpServletResponse response, String password) throws Exception { response.sendRedirect(\"/next?password=\" + password); } }", 1);
    check(rule, "class A { void f(javax.servlet.http.HttpServletResponse response) throws Exception { response.sendRedirect(\"/home\"); } }", 0);
}

#[test]
fn unbounded_input_is_not_appended_to_string_builders() {
    let rule = "LEGACY-JAVA-RULEMAP-unbounded-string-builder-input";
    check(rule, "class A { void f(javax.servlet.http.HttpServletRequest request, StringBuilder out) { out.append(request.getParameter(\"data\")); } }", 1);
    check(rule, "class A { void f(StringBuilder out) { out.append(\"fixed\"); } }", 0);
}

#[test]
fn spring_view_names_and_file_paths_are_not_request_controlled() {
    check("LEGACY-JAVA-RULEMAP-file-disclosure-model-view", "class A { Object f(javax.servlet.http.HttpServletRequest request) { return new ModelAndView(request.getParameter(\"path\")); } }", 1);
    check("LEGACY-JAVA-RULEMAP-file-disclosure-model-view", "class A { Object f() { return new ModelAndView(\"home\"); } }", 0);
    check("LEGACY-JAVA-RULEMAP-path-access-control", "class A { Object f(javax.servlet.http.HttpServletRequest request) { return new java.io.File(request.getParameter(\"id\")); } }", 1);
    check("LEGACY-JAVA-RULEMAP-path-access-control", "class A { Object f() { return new java.io.File(\"/srv/app/public.png\"); } }", 0);
}

#[test]
fn android_object_queries_include_an_authorization_scope() {
    let rule = "LEGACY-JAVA-RULEMAP-android-query-access-control";
    check(rule, "class A { Object f(android.content.ContentResolver resolver, String id) { return resolver.query(uri, columns, \"id = ?\", new String[]{id}, null); } }", 1);
    check(rule, "class A { Object f(android.content.ContentResolver resolver, String id, String user) { return resolver.query(uri, columns, \"id = ? AND user = ?\", new String[]{id, user}, null); } }", 0);
}

#[test]
fn reflected_file_download_configuration_is_hardened() {
    let rule = "LEGACY-JAVA-RULEMAP-reflected-file-download";
    check(rule, "class A { void f(ContentNegotiationManagerFactoryBean bean) { bean.setUseJaf(true); } }", 1);
    check(rule, "class A { void f(ContentNegotiationManagerFactoryBean bean) { bean.setUseJaf(false); bean.setIgnoreAcceptHeader(true); } }", 0);
}

#[test]
fn process_execution_uses_an_absolute_search_path() {
    let rule = "LEGACY-JAVA-RULEMAP-untrusted-search-path";
    check(rule, "class A { void f(java.lang.Runtime runtime) throws Exception { runtime.exec(\"tool --check\"); } }", 1);
    check(rule, "class A { void f(java.lang.Runtime runtime) throws Exception { runtime.exec(\"/usr/bin/tool --check\"); } }", 0);
}

#[test]
fn explicit_errors_are_not_used_for_recoverable_failures() {
    let rule = "LEGACY-JAVA-RULEMAP-unhandled-error";
    check(rule, "class A { void f() { throw new AssertionError(\"bad state\"); } }", 1);
    check(rule, "class A { void f() { throw new IllegalStateException(\"bad state\"); } }", 0);
}

#[test]
fn dom_xss_sinks_are_detected_without_matching_comments() {
    let rule = "LEGACY-JAVA-RULEMAP-dom-xss";
    check(rule, "class A { void f(Element element, String input) { element.innerHTML = input; } }", 1);
    check(rule, "class A { void f(String input) { // element.innerHTML = input\n log(input); } }", 0);
}

#[test]
fn system_gc_has_a_type_qualified_call_contract() {
    let rule = "LEGACY-JAVA-RULEMAP-code-correctness-call-to-system-gc";
    check(
        rule,
        "class A { void f() { System.gc(); java.lang.System.gc(); } }",
        2,
    );
    check(
        rule,
        "class A { void f(Runtime runtime) { runtime.gc(); gc(); } }",
        0,
    );
}

#[test]
fn run_finalizers_on_exit_has_an_exact_static_api_contract() {
    let rule = "LEGACY-JAVA-RULEMAP-call-system-runfinalizersonexit";
    check(
        rule,
        "class A { void f() { System.runFinalizersOnExit(true); } }",
        1,
    );
    check(
        rule,
        "class A { void f(Helper helper) { helper.runFinalizersOnExit(true); } }",
        0,
    );
}

#[test]
fn boolean_getboolean_is_distinguished_from_string_parsing() {
    let rule = "LEGACY-JAVA-RULEMAP-often-misused-boolean-getboolean";
    check(
        rule,
        "class A { boolean f(String value) { return Boolean.getBoolean(value); } }",
        1,
    );
    check(
        rule,
        "class A { boolean f(String value) { return Boolean.parseBoolean(value); } }",
        0,
    );
}

#[test]
fn string_tostring_requires_a_statically_known_string_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-often-misused-string-tostring";
    check(
        rule,
        "class A { String f(String value) { return value.toString(); } }",
        1,
    );
    check(
        rule,
        "class A { String f(Object value) { return value.toString(); } }",
        0,
    );
}

#[test]
fn finalize_requires_an_explicit_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-poor-style-explicit-call-to-finalize";
    check(
        rule,
        "class A { void f(A other) throws Throwable { other.finalize(); } }",
        1,
    );
    check(
        rule,
        "class A { void finalize() {} void f() { finalize(); } }",
        0,
    );
}

#[test]
fn sticky_broadcast_requires_an_android_context_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-android-sticky-broadcast";
    check(rule, "class A { void f(android.content.Context context, Intent intent) { context.sendStickyBroadcast(intent); } }", 1);
    check(
        rule,
        "class A { void f(Sender sender, Intent intent) { sender.sendStickyBroadcast(intent); } }",
        0,
    );
}

#[test]
fn print_stack_trace_requires_a_throwable_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-print-error-message-using-printstacktrace";
    check(
        rule,
        "class A { void f(java.io.IOException error) { error.printStackTrace(); } }",
        1,
    );
    check(
        rule,
        "class A { void f(Printer printer) { printer.printStackTrace(); } }",
        0,
    );
}

#[test]
fn delete_on_exit_requires_a_file_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-javaee-deleteonexit";
    check(
        rule,
        "class A { void f(java.io.File file) { file.deleteOnExit(); } }",
        1,
    );
    check(
        rule,
        "class A { void f(Cleanup cleanup) { cleanup.deleteOnExit(); } }",
        0,
    );
}

#[test]
fn nullcipher_is_checked_as_a_constructor() {
    let rule = "LEGACY-JAVA-RULEMAP-use-nullcipher";
    check(
        rule,
        "class A { Object f() { return new javax.crypto.NullCipher(); } }",
        1,
    );
    check(rule, "class A { Object f() { return new Cipher(); } }", 0);
}

#[test]
fn loadclass_requires_a_classloader_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-call-classloader-loadclass";
    check(rule, "class A { Class<?> f(ClassLoader loader, String name) throws Exception { return loader.loadClass(name); } }", 1);
    check(
        rule,
        "class A { Object f(Registry registry, String name) { return registry.loadClass(name); } }",
        0,
    );
}

#[test]
fn equals_null_is_not_confused_with_a_normal_equals_call() {
    let rule = "LEGACY-JAVA-RULEMAP-null-argument-to-equals";
    check(
        rule,
        "class A { boolean f(Object value) { return value.equals(null); } }",
        1,
    );
    check(
        rule,
        "class A { boolean f(Object left, Object right) { return left.equals(right); } }",
        0,
    );
}

#[test]
fn array_tostring_requires_an_array_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-tostring-on-array";
    check(
        rule,
        "class A { String f(String[] values) { return values.toString(); } }",
        1,
    );
    check(
        rule,
        "class A { String f(String value) { return value.toString(); } }",
        0,
    );
}

#[test]
fn object_allocation_is_scoped_to_loop_bodies() {
    let rule = "LEGACY-JAVA-RULEMAP-create-objects-in-loop";
    check(rule, "class A { void f(int n) { for (int i=0; i<n; i++) { Object value=new Object(); use(value); } } }", 1);
    check(
        rule,
        "class A { void f() { Object value=new Object(); use(value); } }",
        0,
    );
}

#[test]
fn anonymous_ldap_bind_requires_the_authentication_environment_key() {
    let rule = "LEGACY-JAVA-RULEMAP-anonymous-ldap-bind";
    check(rule, "class A { void f(java.util.Hashtable env) { env.put(javax.naming.Context.SECURITY_AUTHENTICATION, \"none\"); } }", 1);
    check(rule, "class A { void f(java.util.Hashtable env, String password) { env.put(javax.naming.Context.SECURITY_AUTHENTICATION, password); } }", 0);
}

#[test]
fn webview_javascript_bridge_requires_a_webview_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-webview-javascript-interface";
    check(rule, "class A { void f(android.webkit.WebView view, Object bridge) { view.addJavascriptInterface(bridge, \"bridge\"); } }", 1);
    check(rule, "class A { void f(BridgeRegistry registry, Object bridge) { registry.addJavascriptInterface(bridge, \"bridge\"); } }", 0);
}

#[test]
fn webview_message_rule_finds_only_wildcard_target_origins() {
    let rule = "LEGACY-JAVA-RULEMAP-webview-wildcard-message-origin";
    check(rule, "class A { void f(android.webkit.WebView view, WebMessage message) { view.postWebMessage(message, Uri.parse(\"*\")); } }", 1);
    check(rule, "class A { void f(android.webkit.WebView view, WebMessage message) { view.postWebMessage(message, Uri.parse(\"https://app.example\")); } }", 0);
}

#[test]
fn implicit_intent_rule_covers_constructor_and_set_action_forms() {
    let constructor = "LEGACY-JAVA-RULEMAP-implicit-intent-constructor";
    check(constructor, "class A { void f() { android.content.Intent intent = new android.content.Intent(\"example.OPEN\"); } }", 1);
    check(constructor, "class A { void f(Context context) { android.content.Intent intent = new android.content.Intent(context, TargetActivity.class); } }", 0);

    let set_action = "LEGACY-JAVA-RULEMAP-implicit-intent-set-action";
    check(
        set_action,
        "class A { void f(android.content.Intent intent) { intent.setAction(\"example.OPEN\"); } }",
        1,
    );
    check(set_action, "class A { void f(android.content.Intent intent, Context context) { intent.setClass(context, TargetActivity.class); } }", 0);
}

#[test]
fn clipboard_rule_requires_the_android_clipboard_manager() {
    let rule = "LEGACY-JAVA-RULEMAP-sensitive-clipboard-data";
    check(rule, "class A { void f(android.content.ClipboardManager clipboard, ClipData secret) { clipboard.setPrimaryClip(secret); } }", 1);
    check(rule, "class A { void f(LocalClipboard clipboard, Object value) { clipboard.setPrimaryClip(value); } }", 0);
}

#[test]
fn database_client_rules_require_credentialless_constructors() {
    let mongo = "LEGACY-JAVA-RULEMAP-unauthenticated-mongodb";
    check(
        mongo,
        "class A { Object f() { return new com.mongodb.MongoClient(); } }",
        1,
    );
    check(mongo, "class A { Object f(MongoCredential credential) { return new com.mongodb.MongoClient(credential); } }", 0);

    let redis = "LEGACY-JAVA-RULEMAP-unauthenticated-redis";
    check(redis, "class A { Object f() { return new org.springframework.data.redis.connection.jedis.JedisConnectionFactory(); } }", 1);
    check(redis, "class A { Object f(RedisStandaloneConfiguration config) { return new org.springframework.data.redis.connection.jedis.JedisConnectionFactory(config); } }", 0);
}

#[test]
fn spring_security_disable_rules_require_the_expected_builder_chain() {
    for (rule, call) in [
        (
            "LEGACY-JAVA-RULEMAP-spring-security-headers-disabled",
            "http.headers().disable()",
        ),
        (
            "LEGACY-JAVA-RULEMAP-spring-mime-sniffing-disabled",
            "http.headers().contentTypeOptions().disable()",
        ),
        (
            "LEGACY-JAVA-RULEMAP-spring-xss-header-disabled",
            "http.headers().xssProtection().disable()",
        ),
        (
            "LEGACY-JAVA-RULEMAP-spring-hsts-disabled",
            "http.headers().httpStrictTransportSecurity().disable()",
        ),
        (
            "LEGACY-JAVA-RULEMAP-spring-frame-options-disabled",
            "http.headers().frameOptions().disable()",
        ),
    ] {
        check(
            rule,
            &format!("class A {{ void f(HttpSecurity http) {{ {call}; }} }}"),
            1,
        );
        check(
            rule,
            "class A { void f(Feature feature) { feature.disable(); } }",
            0,
        );
    }
}

#[test]
fn spring_hsts_options_check_subdomains_and_one_year_duration() {
    let subdomains = "LEGACY-JAVA-RULEMAP-spring-hsts-subdomains-disabled";
    check(
        subdomains,
        "class A { void f(HstsConfigurer hsts) { hsts.includeSubDomains(false); } }",
        1,
    );
    check(
        subdomains,
        "class A { void f(HstsConfigurer hsts) { hsts.includeSubDomains(true); } }",
        0,
    );

    let duration = "LEGACY-JAVA-RULEMAP-spring-hsts-short-max-age";
    check(
        duration,
        "class A { void f(HstsConfigurer hsts) { hsts.maxAgeInSeconds(500); } }",
        1,
    );
    check(
        duration,
        "class A { void f(HstsConfigurer hsts) { hsts.maxAgeInSeconds(31536000); } }",
        0,
    );
}

#[test]
fn spring_csp_rules_distinguish_report_only_and_unsafe_directives() {
    let report_only = "LEGACY-JAVA-RULEMAP-spring-csp-report-only";
    check(report_only, "class A { void f(HeadersConfigurer headers) { headers.contentSecurityPolicy(\"default-src https:\").reportOnly(); } }", 1);
    check(report_only, "class A { void f(HeadersConfigurer headers) { headers.contentSecurityPolicy(\"default-src https:\"); } }", 0);

    let permissive = "LEGACY-JAVA-RULEMAP-spring-csp-permissive";
    check(permissive, "class A { void f(HeadersConfigurer headers) { headers.contentSecurityPolicy(\"default-src *; script-src unsafe-eval\"); } }", 1);
    check(permissive, "class A { void f(HeadersConfigurer headers) { headers.contentSecurityPolicy(\"default-src https://cdn.example\"); } }", 0);
}

#[test]
fn gwt_hidden_field_rule_requires_the_hidden_widget_constructor() {
    let rule = "LEGACY-JAVA-RULEMAP-gwt-hidden-field";
    check(rule, "class A { Object f(String secret) { return new com.google.gwt.user.client.ui.Hidden(\"token\", secret); } }", 1);
    check(
        rule,
        "class A { Object f(String value) { return new TextBox(value); } }",
        0,
    );
}

#[test]
fn cipher_mode_rule_rejects_ecb_and_implicit_symmetric_defaults() {
    let rule = "LEGACY-JAVA-RULEMAP-cipher-insecure-mode";
    check(rule, "class A { Object f() throws Exception { return javax.crypto.Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); } }", 1);
    check(rule, "class A { Object f() throws Exception { return javax.crypto.Cipher.getInstance(\"AES/GCM/NoPadding\"); } }", 0);
}

#[test]
fn keygenerator_rules_distinguish_small_user_controlled_and_fixed_sizes() {
    let small = "LEGACY-JAVA-RULEMAP-keygenerator-small-key";
    check(
        small,
        "class A { void f(javax.crypto.KeyGenerator generator) { generator.init(64); } }",
        1,
    );
    check(
        small,
        "class A { void f(javax.crypto.KeyGenerator generator) { generator.init(256); } }",
        0,
    );

    let controlled = "LEGACY-JAVA-RULEMAP-keygenerator-user-size";
    check(controlled, "class A { void f(javax.crypto.KeyGenerator generator, int requested) { generator.init(requested); } }", 1);
    check(
        controlled,
        "class A { void f(javax.crypto.KeyGenerator generator) { generator.init(256); } }",
        0,
    );
}

#[test]
fn pbe_rules_check_iteration_count_and_literal_salt_structure() {
    let iterations = "LEGACY-JAVA-RULEMAP-pbe-low-iteration-count";
    check(iterations, "class A { Object f(byte[] salt) { return new javax.crypto.spec.PBEParameterSpec(salt, 1000); } }", 1);
    check(iterations, "class A { Object f(byte[] salt) { return new javax.crypto.spec.PBEParameterSpec(salt, 10000); } }", 0);

    let salt = "LEGACY-JAVA-RULEMAP-pbe-hardcoded-salt";
    check(salt, "class A { Object f() { return new javax.crypto.spec.PBEParameterSpec(new byte[]{1,2,3,4}, 10000); } }", 1);
    check(salt, "class A { Object f(byte[] randomSalt) { return new javax.crypto.spec.PBEParameterSpec(randomSalt, 10000); } }", 0);
}

#[test]
fn tls_hostname_and_android_socket_rules_match_insecure_apis() {
    let verifier = "LEGACY-JAVA-RULEMAP-allow-all-hostname-verifier";
    check(verifier, "class A { void f(SSLSocketFactory factory) { factory.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER); } }", 1);
    check(verifier, "class A { void f(SSLSocketFactory factory, HostnameVerifier verifier) { factory.setHostnameVerifier(verifier); } }", 0);
    check(
        "LEGACY-JAVA-RULEMAP-allow-all-hostname-verifier-constructor",
        "class A { Object f() { return new AllowAllHostnameVerifier(); } }",
        1,
    );

    let socket = "LEGACY-JAVA-RULEMAP-android-insecure-ssl-socket";
    check(socket, "class A { Object f(android.net.SSLCertificateSocketFactory factory, InetAddress address) { return factory.createSocket(address, 443); } }", 1);
    check(socket, "class A { Object f(javax.net.ssl.SSLSocketFactory factory, String host) { return factory.createSocket(host, 443); } }", 0);
}

#[test]
fn certificate_ldap_and_referer_rules_bind_exact_security_apis() {
    let certificates = "LEGACY-JAVA-RULEMAP-direct-server-certificates";
    check(certificates, "class A { Object f(javax.net.ssl.HttpsURLConnection connection) { return connection.getServerCertificates(); } }", 1);
    check(certificates, "class A { Object f(Connection connection) { return connection.getServerCertificates(); } }", 0);

    let ldap = "LEGACY-JAVA-RULEMAP-ldap-url-deserialization-enabled";
    check(ldap, "class A { void f() { System.setProperty(\"com.sun.jndi.ldap.object.trustURLCodebase\", \"true\"); } }", 1);
    check(ldap, "class A { void f() { System.setProperty(\"com.sun.jndi.ldap.object.trustURLCodebase\", \"false\"); } }", 0);

    let referer = "LEGACY-JAVA-RULEMAP-referer-authentication";
    check(referer, "class A { String f(HttpServletRequest request) { return request.getHeader(\"Referer\"); } }", 1);
    check(referer, "class A { String f(HttpServletRequest request) { return request.getHeader(\"Authorization\"); } }", 0);
}

#[test]
fn android_os_and_smtp_rules_match_privileged_or_cleartext_construction() {
    check(
        "LEGACY-JAVA-RULEMAP-android-os-privilege-change",
        "class A { void f() { android.system.Os.setgid(2); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-android-os-privilege-change",
        "class A { void f() { Process.setGroup(2); } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-android-os-umask",
        "class A { void f() { android.system.Os.umask(0700); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-android-os-umask",
        "class A { void f() { android.system.Os.chmod(\"file\", 0600); } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-smtp-without-tls",
        "class A { Object f() { return new AuthenticatingSMTPClient(); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-smtp-without-tls",
        "class A { Object f() { return new AuthenticatingSMTPClient(\"TLS\", true); } }",
        0,
    );
}

#[test]
fn numeric_expression_rules_use_hir_operators_and_literal_values() {
    let zero = "LEGACY-JAVA-RULEMAP-literal-division-by-zero";
    check(
        zero,
        "class A { int f(int value) { return value / 0; } }",
        1,
    );
    check(
        zero,
        "class A { int f(int value, int divisor) { return value / divisor; } }",
        0,
    );
    let index = "LEGACY-JAVA-RULEMAP-negative-array-index";
    check(
        index,
        "class A { int f(int[] values) { return values[-1]; } }",
        1,
    );
    check(
        index,
        "class A { int f(int[] values, int index) { return values[index]; } }",
        0,
    );
}

#[test]
fn hardcoded_personal_identifiers_match_only_complete_string_literals() {
    check(
        "LEGACY-JAVA-RULEMAP-hardcoded-bank-card",
        "class A { String card=\"4111111111111111\"; }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-hardcoded-bank-card",
        "class A { long count=4111111111111111L; String label=\"card\"; }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-hardcoded-national-id",
        "class A { String id=\"11010519900101123X\"; }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-hardcoded-national-id",
        "class A { String id=\"example-user\"; }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-hardcoded-phone-number",
        "class A { String phone=\"13800138000\"; }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-hardcoded-phone-number",
        "class A { String phone=getPhone(); }",
        0,
    );
}

#[test]
fn optional_get_rule_tracks_the_is_present_then_branch() {
    let rule = "LEGACY-JAVA-RULEMAP-optional-get-without-ispresent";
    check(
        rule,
        "class A { String f(java.util.Optional value) { return value.get(); } }",
        1,
    );
    check(rule, "class A { String f(java.util.Optional value) { if (value.isPresent()) { return value.get(); } return \"none\"; } }", 0);
}

#[test]
fn unnecessary_thread_safe_class_rule_uses_constructor_types() {
    let rule = "LEGACY-JAVA-RULEMAP-unnecessary-thread-safe-class";
    check(
        rule,
        "class A { Object f() { return new java.util.Vector(); } }",
        1,
    );
    check(
        rule,
        "class A { Object f() { return new java.util.ArrayList(); } }",
        0,
    );
}

#[test]
fn dex_class_loader_rejects_parameter_controlled_input_and_output_paths() {
    let input = "LEGACY-JAVA-RULEMAP-dex-class-loader-input-path";
    check(input, "class A { Object f(String dexPath, String output, ClassLoader parent) { return new dalvik.system.DexClassLoader(dexPath, \"/data/private\", null, parent); } }", 1);
    check(input, "class A { Object f(ClassLoader parent) { return new dalvik.system.DexClassLoader(\"/data/app/base.dex\", \"/data/private\", null, parent); } }", 0);
    let output = "LEGACY-JAVA-RULEMAP-dex-class-loader-output-path";
    check(output, "class A { Object f(String output, ClassLoader parent) { return new dalvik.system.DexClassLoader(\"/data/app/base.dex\", output, null, parent); } }", 1);
    check(output, "class A { Object f(ClassLoader parent) { return new dalvik.system.DexClassLoader(\"/data/app/base.dex\", \"/data/private\", null, parent); } }", 0);
}

#[test]
fn shoulder_surfing_rules_match_visible_android_password_configuration() {
    let visible = "LEGACY-JAVA-RULEMAP-visible-password-input";
    check(visible, "class A { void f(EditText password) { password.setInputType(InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD); } }", 1);
    check(visible, "class A { void f(EditText password) { password.setInputType(InputType.TYPE_TEXT_VARIATION_PASSWORD); } }", 0);
    let transform = "LEGACY-JAVA-RULEMAP-password-transformation-disabled";
    check(
        transform,
        "class A { void f(EditText password) { password.setTransformationMethod(null); } }",
        1,
    );
    check(transform, "class A { void f(EditText password) { password.setTransformationMethod(PasswordTransformationMethod.getInstance()); } }", 0);
}

#[test]
fn referrer_policy_rule_matches_only_unsafe_url() {
    let rule = "LEGACY-JAVA-RULEMAP-unsafe-referrer-policy";
    check(rule, "class A { void f(Headers headers) { headers.referrerPolicy(ReferrerPolicy.UNSAFE_URL); } }", 1);
    check(rule, "class A { void f(Headers headers) { headers.referrerPolicy(ReferrerPolicy.SAME_ORIGIN); } }", 0);
}

#[test]
fn android_websettings_boolean_security_switches_are_type_aware() {
    for (rule, method) in [
        (
            "LEGACY-JAVA-RULEMAP-webview-dom-storage",
            "setDomStorageEnabled",
        ),
        (
            "LEGACY-JAVA-RULEMAP-webview-content-access",
            "setAllowContentAccess",
        ),
        (
            "LEGACY-JAVA-RULEMAP-webview-file-access",
            "setAllowFileAccess",
        ),
    ] {
        check(rule, &format!("class A {{ void f(android.webkit.WebSettings settings) {{ settings.{method}(true); }} }}"), 1);
        check(rule, &format!("class A {{ void f(android.webkit.WebSettings settings) {{ settings.{method}(false); }} }}"), 0);
        check(
            rule,
            &format!("class A {{ void f(Settings settings) {{ settings.{method}(true); }} }}"),
            0,
        );
    }
}

#[test]
fn file_scheme_cookie_rule_requires_the_exact_static_api_and_true() {
    let rule = "LEGACY-JAVA-RULEMAP-file-scheme-cookies";
    check(
        rule,
        "class A { void f() { android.webkit.CookieManager.setAcceptFileSchemeCookies(true); } }",
        1,
    );
    check(
        rule,
        "class A { void f() { android.webkit.CookieManager.setAcceptFileSchemeCookies(false); } }",
        0,
    );
}

#[test]
fn webview_save_password_requires_the_webview_receiver_and_signature() {
    let rule = "LEGACY-JAVA-RULEMAP-webview-save-password";
    check(rule, "class A { void f(android.webkit.WebView view) { view.savePassword(\"host\", \"user\", \"secret\"); } }", 1);
    check(
        rule,
        "class A { void f(Vault vault) { vault.savePassword(\"host\", \"user\", \"secret\"); } }",
        0,
    );
}

#[test]
fn null_pointer_catch_is_type_specific() {
    let rule = "LEGACY-JAVA-RULEMAP-catch-nullpointerexception";
    check(rule, "class A { void f() { try { work(); } catch (NullPointerException error) { recover(error); } } }", 1);
    check(rule, "class A { void f() { try { work(); } catch (IllegalArgumentException error) { recover(error); } } }", 0);
}

#[test]
fn commons_email_requires_tls_server_identity_verification() {
    let rule = "LEGACY-JAVA-RULEMAP-email-server-identity-disabled";
    check(rule, "class A { void f(org.apache.commons.mail.SimpleEmail email) { email.setSSLCheckServerIdentity(false); } }", 1);
    check(rule, "class A { void f(org.apache.commons.mail.SimpleEmail email) { email.setSSLCheckServerIdentity(true); } }", 0);
    check(
        rule,
        "class A { void f(CustomEmail email) { email.setSSLCheckServerIdentity(false); } }",
        0,
    );
}

#[test]
fn fatal_and_ssl_exceptions_are_not_silently_swallowed() {
    let death = "LEGACY-JAVA-RULEMAP-swallowed-thread-death";
    check(
        death,
        "class A { void f() { try { work(); } catch (ThreadDeath death) { cleanup(); } } }",
        1,
    );
    check(death, "class A { void f() { try { work(); } catch (ThreadDeath death) { cleanup(); throw death; } } }", 0);
    check(
        death,
        "class A { void f() { try { work(); } catch (Error error) { cleanup(); } } }",
        0,
    );

    let ssl = "LEGACY-JAVA-RULEMAP-unhandled-ssl-exception";
    check(ssl, "class A { void f() { try { connect(); } catch (SSLHandshakeException error) { /* ignored */ } } }", 1);
    check(ssl, "class A { void f() { try { connect(); } catch (SSLHandshakeException error) { logger.error(\"TLS failed\", error); } } }", 0);
    check(
        ssl,
        "class A { void f() { try { connect(); } catch (IOException error) { recover(); } } }",
        0,
    );
}

#[test]
fn guomi_cryptographic_engines_are_review_markers() {
    let rule = "LEGACY-JAVA-RULEMAP-guomi-algorithm-review";
    check(
        rule,
        "class A { Object f() { return new org.bouncycastle.crypto.engines.SM2Engine(); } }",
        1,
    );
    check(
        rule,
        "class A { Object f() { return new org.bouncycastle.crypto.digests.SM3Digest(); } }",
        1,
    );
    check(
        rule,
        "class A { Object f() { return new SHA256Digest(); } }",
        0,
    );
}

#[test]
fn webview_debugging_requires_the_exact_android_api_and_true() {
    let rule = "LEGACY-JAVA-RULEMAP-android-webview-debugging";
    check(rule, "class A { void f(android.webkit.WebView view) { view.setWebContentsDebuggingEnabled(true); } }", 1);
    check(rule, "class A { void f(android.webkit.WebView view) { view.setWebContentsDebuggingEnabled(false); } }", 0);
    check(
        rule,
        "class A { void f(CustomView view) { view.setWebContentsDebuggingEnabled(true); } }",
        0,
    );
}

#[test]
fn esapi_prohibited_api_profile_is_type_aware() {
    let rule = "LEGACY-JAVA-RULEMAP-esapi-prohibited-api";
    check(rule, "class A { void f(java.lang.Runtime runtime) { runtime.exec(command); } }", 1);
    check(rule, "class A { void f(java.sql.Statement statement) { statement.execute(sql); } }", 1);
    check(rule, "class A { void f(SafeRunner runtime) { runtime.exec(command); } }", 0);
}

#[test]
fn object_output_stream_requires_a_serializable_project_type() {
    let rule = "LEGACY-JAVA-RULEMAP-serialize-non-serializable";
    check(rule, "class A { void f(java.io.ObjectOutputStream out, User user) { out.writeObject(user); } } class User {}", 1);
    check(rule, "class A { void f(java.io.ObjectOutputStream out, User user) { out.writeObject(user); } } class User implements java.io.Serializable {}", 0);
    check(rule, "class A { void f(java.io.ObjectOutputStream out, String value) { out.writeObject(value); } }", 0);
    check(rule, "class A { void f(CustomOutput out, User user) { out.writeObject(user); } } class User {}", 0);
}

#[test]
fn equals_calls_require_a_project_value_type_override() {
    let rule = "LEGACY-JAVA-RULEMAP-class-missing-equals";
    check(rule, "class A { boolean same(Person left, Person right) { return left.equals(right); } } class Person { int id; }", 1);
    check(rule, "class A { boolean same(Person left, Person right) { return left.equals(right); } } class Person { public boolean equals(Object other) { return true; } }", 0);
    check(rule, "class A { boolean same(String left, String right) { return left.equals(right); } }", 0);
}

#[test]
fn empty_catch_uses_the_parsed_catch_body() {
    let rule = "LEGACY-JAVA-RULEMAP-empty-catch-block";
    check(
        rule,
        "class A { void f() { try { work(); } catch (Exception error) { /* ignored */ } } }",
        1,
    );
    check(
        rule,
        "class A { void f() { try { work(); } catch (Exception error) { recover(error); } } }",
        0,
    );
}

#[test]
fn send_broadcast_requires_permission_overload() {
    let rule = "LEGACY-JAVA-RULEMAP-unprotected-send-broadcast";
    check(rule, "class A { void f(android.content.Context context, Intent intent) { context.sendBroadcast(intent); } }", 1);
    check(rule, "class A { void f(android.content.Context context, Intent intent) { context.sendBroadcast(intent, \"app.permission.INTERNAL\"); } }", 0);
}

#[test]
fn dynamic_receiver_requires_permission_overload() {
    let rule = "LEGACY-JAVA-RULEMAP-unprotected-register-receiver";
    check(rule, "class A { void f(android.content.Context context, BroadcastReceiver receiver, IntentFilter filter) { context.registerReceiver(receiver, filter); } }", 1);
    check(rule, "class A { void f(android.content.Context context, BroadcastReceiver receiver, IntentFilter filter) { context.registerReceiver(receiver, filter, \"app.permission.INTERNAL\", null); } }", 0);
}

#[test]
fn spring_default_permit_requires_the_any_request_chain() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-default-permit";
    check(rule, "class A { void f(HttpSecurity http) { http.authorizeRequests().anyRequest().permitAll(); } }", 1);
    check(rule, "class A { void f(HttpSecurity http) { http.authorizeRequests().mvcMatchers(\"/public\").permitAll(); } }", 0);
}

#[test]
fn spring_firewall_rule_is_typed_and_requires_relaxation() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-permissive-firewall";
    check(rule, "class A { void f(org.springframework.security.web.firewall.StrictHttpFirewall firewall) { firewall.setAllowSemicolon(true); firewall.setAllowUrlEncodedSlash(true); } }", 2);
    check(rule, "class A { void f(org.springframework.security.web.firewall.StrictHttpFirewall firewall) { firewall.setAllowSemicolon(false); } }", 0);
    check(
        rule,
        "class A { void f(Firewall firewall) { firewall.setAllowSemicolon(true); } }",
        0,
    );
}

#[test]
fn spring_csrf_rule_requires_the_csrf_disable_chain() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-csrf-disabled";
    check(
        rule,
        "class A { void f(HttpSecurity http) { http.csrf().disable(); } }",
        1,
    );
    check(
        rule,
        "class A { void f(Feature feature) { feature.disable(); } }",
        0,
    );
}

#[test]
fn jfinal_development_mode_rule_is_typed_and_boolean_aware() {
    let rule = "LEGACY-JAVA-RULEMAP-jfinal-dev-mode";
    check(
        rule,
        "class A { void f(com.jfinal.config.Constants constants) { constants.setDevMode(true); } }",
        1,
    );
    check(rule, "class A { void f(com.jfinal.config.Constants constants) { constants.setDevMode(false); } }", 0);
}

#[test]
fn hostname_rule_requires_an_inetaddress_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-use-gethostname";
    check(
        rule,
        "class A { String f(java.net.InetAddress address) { return address.getHostName(); } }",
        1,
    );
    check(
        rule,
        "class A { String f(Service service) { return service.getHostName(); } }",
        0,
    );
}

#[test]
fn unsafe_jni_rule_selects_native_method_declarations_only() {
    let rule = "LEGACY-JAVA-RULEMAP-unsafe-jni";
    check(
        rule,
        "class A { public native void execute(byte[] input); }",
        1,
    );
    check(
        rule,
        "class A { public void execute(byte[] input) { use(input); } String nativeText; }",
        0,
    );
}

#[test]
fn string_getbytes_requires_a_string_receiver_and_default_charset_overload() {
    let rule = "LEGACY-JAVA-RULEMAP-string-getbytes-default-charset";
    check(
        rule,
        "class A { byte[] f(String text) { return text.getBytes(); } }",
        1,
    );
    check(
        rule,
        "class A { byte[] f(String text) throws Exception { return text.getBytes(\"UTF-8\"); } }",
        0,
    );
    check(
        rule,
        "class A { byte[] f(Buffer buffer) { return buffer.getBytes(); } }",
        0,
    );
}

#[test]
fn contract_methods_require_explicit_null_parameter_checks() {
    let rule = "LEGACY-JAVA-RULEMAP-missing-contract-null-parameter-check";
    check(
        rule,
        "class A { boolean equals(Object other) { return name.equals(other.toString()); } }",
        1,
    );
    check(rule, "class A { boolean equals(Object other) { if (other == null) return false; return name.equals(other.toString()); } }", 0);
    check(rule, "class A { int compare(Object left, Object right) { if (left == null) return -1; return left.toString().compareTo(right.toString()); } }", 1);
    check(rule, "class A { int compare(Object left, Object right) { if (null == left) return -1; if (right != null) return 1; return 0; } }", 0);
    check(
        rule,
        "class A { boolean unrelated(Object value) { return value != null; } }",
        0,
    );
}

#[test]
fn locale_sensitive_case_conversion_requires_an_explicit_locale() {
    let rule = "LEGACY-JAVA-RULEMAP-locale-dependent-case-conversion";
    check(
        rule,
        "class A { String f(String text) { return text.toUpperCase(); } }",
        1,
    );
    check(
        rule,
        "class A { String f(String text) { return text.toUpperCase(java.util.Locale.ROOT); } }",
        0,
    );
}

#[test]
fn stream_read_preserves_eof_in_an_int_target() {
    let rule = "LEGACY-JAVA-RULEMAP-stream-read-result-narrowed";
    check(rule, "class A { void f(java.io.InputStream input) throws Exception { byte value=input.read(); use(value); } }", 1);
    check(rule, "class A { void f(java.io.InputStream input) throws Exception { int value=input.read(); use(value); } }", 0);
    check(
        rule,
        "class A { int f(java.io.InputStream input) throws Exception { return input.read(); } }",
        0,
    );
}

#[test]
fn bulk_stream_read_warns_that_one_call_may_be_short() {
    let rule = "LEGACY-JAVA-RULEMAP-single-read-assumed-to-fill-array";
    check(rule, "class A { int f(java.io.InputStream input, byte[] bytes) throws Exception { return input.read(bytes); } }", 1);
    check(rule, "class A { int f(java.io.InputStream input, char[] chars) throws Exception { return input.read(chars); } }", 0);
}

#[test]
fn outputstream_write_rejects_only_out_of_byte_range_constants() {
    let rule = "LEGACY-JAVA-RULEMAP-outputstream-write-out-of-range";
    check(rule, "class A { void f(java.io.OutputStream output) throws Exception { output.write(-1); output.write(256); } }", 2);
    check(rule, "class A { void f(java.io.OutputStream output) throws Exception { output.write(0); output.write(255); } }", 0);
    check(
        rule,
        "class A { void f(Writer output) throws Exception { output.write(256); } }",
        0,
    );
}

#[test]
fn cookie_secure_and_httponly_rules_require_explicit_false() {
    let secure = "LEGACY-JAVA-RULEMAP-cookie-secure-disabled";
    check(
        secure,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setSecure(false); } }",
        1,
    );
    check(
        secure,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setSecure(true); } }",
        0,
    );
    let http_only = "LEGACY-JAVA-RULEMAP-cookie-httponly-disabled";
    check(
        http_only,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setHttpOnly(false); } }",
        1,
    );
    check(
        http_only,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setHttpOnly(true); } }",
        0,
    );
}

#[test]
fn cookie_domain_rule_requires_a_cookie_receiver() {
    let rule = "LEGACY-JAVA-RULEMAP-cookie-overly-broad-domain";
    check(rule, "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setDomain(\".example.com\"); } }", 1);
    check(
        rule,
        "class A { void f(Settings settings) { settings.setDomain(\".example.com\"); } }",
        0,
    );
}

#[test]
fn cookie_root_path_is_distinguished_from_a_scoped_path() {
    let rule = "LEGACY-JAVA-RULEMAP-cookie-overly-broad-path";
    check(
        rule,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setPath(\"/\"); } }",
        1,
    );
    check(
        rule,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setPath(\"/account\"); } }",
        0,
    );
}

#[test]
fn cookie_positive_max_age_is_persistent() {
    let rule = "LEGACY-JAVA-RULEMAP-persistent-session-cookie";
    check(
        rule,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setMaxAge(86400); } }",
        1,
    );
    check(
        rule,
        "class A { void f(javax.servlet.http.Cookie cookie) { cookie.setMaxAge(-1); } }",
        0,
    );
}

#[test]
fn reflection_accessibility_rule_is_typed_and_boolean_aware() {
    let rule = "LEGACY-JAVA-RULEMAP-reflection-increase-accessibility";
    check(
        rule,
        "class A { void f(java.lang.reflect.Field field) { field.setAccessible(true); } }",
        1,
    );
    check(
        rule,
        "class A { void f(java.lang.reflect.Field field) { field.setAccessible(false); } }",
        0,
    );
    check(
        rule,
        "class A { void f(Settings settings) { settings.setAccessible(true); } }",
        0,
    );
}

#[test]
fn dangerous_intent_permission_rule_inspects_flag_tokens() {
    let rule = "LEGACY-JAVA-RULEMAP-dangerous-intent-uri-permission";
    check(rule, "class A { void f(android.content.Intent intent) { intent.addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION); } }", 1);
    check(rule, "class A { void f(android.content.Intent intent) { intent.setFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK); } }", 0);
    check(rule, "class A { void f(Flags flags) { flags.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); } }", 0);
}

#[test]
fn open_android_service_rule_matches_listening_socket_construction() {
    let rule = "LEGACY-JAVA-RULEMAP-open-android-app-service";
    check(
        rule,
        "class A { Object f() throws Exception { return new java.net.ServerSocket(8080); } }",
        1,
    );
    check(
        rule,
        "class A { Object f() { return new java.net.Socket(); } }",
        0,
    );
}

#[test]
fn insecure_rfcomm_rule_distinguishes_authenticated_api() {
    let rule = "LEGACY-JAVA-RULEMAP-insecure-rfcomm-socket";
    check(rule, "class A { Object f(android.bluetooth.BluetoothDevice device, java.util.UUID id) throws Exception { return device.createInsecureRfcommSocketToServiceRecord(id); } }", 1);
    check(rule, "class A { Object f(android.bluetooth.BluetoothDevice device, java.util.UUID id) throws Exception { return device.createRfcommSocketToServiceRecord(id); } }", 0);
}

#[test]
fn android_world_file_mode_checks_the_mode_argument() {
    let rule = "LEGACY-JAVA-RULEMAP-android-world-accessible-file-mode";
    check(rule, "class A { Object f(android.content.Context context) throws Exception { return context.openFileOutput(\"data\", android.content.Context.MODE_WORLD_WRITEABLE); } }", 1);
    check(rule, "class A { Object f(android.content.Context context) throws Exception { return context.openFileOutput(\"data\", android.content.Context.MODE_PRIVATE); } }", 0);
}

#[test]
fn android_permission_rule_rejects_calling_or_self_variants() {
    let rule = "LEGACY-JAVA-RULEMAP-android-calling-or-self-permission-check";
    check(rule, "class A { int f(android.content.Context context, String permission) { return context.checkCallingOrSelfPermission(permission); } }", 1);
    check(rule, "class A { int f(android.content.Context context, String permission) { return context.checkCallingPermission(permission); } }", 0);
}

#[test]
fn android_hidden_api_rule_requires_a_constant_internal_class_name() {
    let rule = "LEGACY-JAVA-RULEMAP-android-hidden-api-reflection";
    check(rule, "class A { Class<?> f() throws Exception { return Class.forName(\"android.test.TestCaseUtil\"); } }", 1);
    check(rule, "class A { Class<?> f() throws Exception { return Class.forName(\"android.content.Intent\"); } }", 0);
    check(
        rule,
        "class A { Class<?> f(String name) throws Exception { return Class.forName(name); } }",
        0,
    );
}

#[test]
fn android_external_storage_rule_is_typed_and_excludes_internal_storage() {
    let rule = "LEGACY-JAVA-RULEMAP-android-external-storage-location";
    check(rule, "class A { Object f(android.content.Context context) { return context.getExternalFilesDir(null); } }", 1);
    check(
        rule,
        "class A { Object f(android.content.Context context) { return context.getFilesDir(); } }",
        0,
    );
    check(
        rule,
        "class A { Object f(Storage storage) { return storage.getExternalFilesDir(null); } }",
        0,
    );
}
