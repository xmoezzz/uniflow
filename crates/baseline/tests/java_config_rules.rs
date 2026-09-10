use std::{path::Path, sync::OnceLock};

use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_hir::Language;

fn manifest(rule: &str, body: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let source = format!(
        r#"<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="example">{body}</manifest>"#
    );
    let findings = pack.scan_text(
        &Language::Java,
        Path::new("app/src/main/AndroidManifest.xml"),
        &source,
    );
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

fn config(rule: &str, path: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let findings = pack.scan_text(&Language::Java, Path::new(path), source);
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

#[test]
fn android_debuggable_manifest_rule_is_namespace_aware() {
    let rule = "LEGACY-JAVA-RULEMAP-android-debuggable-manifest";
    manifest(rule, r#"<application android:debuggable="true"/>"#, 1);
    manifest(rule, r#"<application android:debuggable="false"/>"#, 0);
}

#[test]
fn android_backup_rule_honors_the_secure_explicit_value_and_default() {
    let rule = "LEGACY-JAVA-RULEMAP-android-backup-enabled";
    manifest(rule, r#"<application/>"#, 1);
    manifest(rule, r#"<application android:allowBackup="true"/>"#, 1);
    manifest(rule, r#"<application android:allowBackup="false"/>"#, 0);
}

#[test]
fn android_task_reparenting_rule_checks_application_and_activity() {
    let rule = "LEGACY-JAVA-RULEMAP-android-task-reparenting";
    manifest(
        rule,
        r#"<application android:allowTaskReparenting="true"><activity android:name=".A" android:allowTaskReparenting="true"/></application>"#,
        2,
    );
    manifest(
        rule,
        r#"<application android:allowTaskReparenting="false"/>"#,
        0,
    );
}

#[test]
fn android_single_task_rule_checks_only_activity_launch_mode() {
    let rule = "LEGACY-JAVA-RULEMAP-android-single-task";
    manifest(
        rule,
        r#"<application><activity android:name=".A" android:launchMode="singleTask"/></application>"#,
        1,
    );
    manifest(
        rule,
        r#"<application><activity android:name=".A" android:launchMode="standard"/></application>"#,
        0,
    );
}

#[test]
fn android_normal_permission_rule_includes_the_platform_default() {
    let rule = "LEGACY-JAVA-RULEMAP-android-normal-permission";
    manifest(
        rule,
        r#"<permission android:name="example.NORMAL"/><permission android:name="example.EXPLICIT" android:protectionLevel="normal"/>"#,
        2,
    );
    manifest(
        rule,
        r#"<permission android:name="example.INTERNAL" android:protectionLevel="signature"/>"#,
        0,
    );
}

#[test]
fn android_deprecated_permission_rule_handles_both_legacy_levels() {
    let rule = "LEGACY-JAVA-RULEMAP-android-deprecated-permission-level";
    manifest(
        rule,
        r#"<permission android:name="example.A" android:protectionLevel="system"/><permission android:name="example.B" android:protectionLevel="signatureOrSystem"/>"#,
        2,
    );
    manifest(
        rule,
        r#"<permission android:name="example.C" android:protectionLevel="signature"/>"#,
        0,
    );
}

#[test]
fn exported_component_rule_accepts_component_specific_permissions() {
    let rule = "LEGACY-JAVA-RULEMAP-android-exported-without-permission";
    manifest(
        rule,
        r#"<application><activity android:name=".A" android:exported="true"/><provider android:name=".P" android:exported="true"/></application>"#,
        2,
    );
    manifest(
        rule,
        r#"<application><activity android:name=".A" android:exported="false"/><provider android:name=".P" android:exported="true" android:readPermission="example.READ"/></application>"#,
        0,
    );
}

#[test]
fn android_config_rules_reject_wrong_paths_and_malformed_xml() {
    let mut pack = builtin_security_pack().unwrap();
    pack.rules
        .retain(|rule| rule.id == "LEGACY-JAVA-RULEMAP-android-debuggable-manifest");
    let source = r#"<manifest><application android:debuggable="true"></manifest>"#;
    assert!(pack
        .scan_text(&Language::Java, Path::new("not-manifest.xml"), source)
        .is_empty());
    assert!(pack
        .scan_text(&Language::Java, Path::new("AndroidManifest.xml"), source)
        .is_empty());
}

#[test]
fn spring_actuator_properties_and_yaml_preserve_nested_keys() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-actuator-security-disabled";
    config(
        rule,
        "src/main/resources/application.properties",
        "management.security.enabled=false\nendpoints.health.sensitive=false\n",
        2,
    );
    config(
        rule,
        "src/main/resources/application.properties",
        "# management.security.enabled=false\nmanagement.security.enabled=true\n",
        0,
    );
    config(rule, "src/main/resources/application-prod.yml", "management:\n  security:\n    enabled: false\nendpoints:\n  health:\n    sensitive: false # unsafe\n", 2);
    config(
        rule,
        "src/main/resources/application.yml",
        "management:\n  security:\n    enabled: true\n",
        0,
    );
}

#[test]
fn spring_admin_and_shutdown_properties_have_secure_negatives() {
    let admin = "LEGACY-JAVA-RULEMAP-spring-admin-mbean-enabled";
    config(
        admin,
        "application.properties",
        "spring.application.admin.enabled=true\n",
        1,
    );
    config(
        admin,
        "application.properties",
        "spring.application.admin.enabled=false\n",
        0,
    );
    config(
        admin,
        "application.yml",
        "spring:\n  application:\n    admin:\n      enabled: true\n",
        1,
    );

    let shutdown = "LEGACY-JAVA-RULEMAP-spring-shutdown-endpoint-enabled";
    config(
        shutdown,
        "application.properties",
        "endpoints.shutdown.enabled=true\nmanagement.endpoint.shutdown.enabled=true\n",
        2,
    );
    config(
        shutdown,
        "application.yml",
        "management:\n  endpoint:\n    shutdown:\n      enabled: false\n",
        0,
    );
}

#[test]
fn spring_devtools_rule_understands_maven_and_gradle_dependencies() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-devtools-enabled";
    config(rule, "pom.xml", "<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-devtools</artifactId></dependency></dependencies></project>", 1);
    config(rule, "pom.xml", "<project><!-- <artifactId>spring-boot-devtools</artifactId> --><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>", 0);
    config(rule, "build.gradle", "developmentOnly 'org.springframework.boot:spring-boot-devtools'\n// implementation 'org.springframework.boot:spring-boot-devtools'\n", 1);
}

#[test]
fn antisamy_policies_reject_offsite_links() {
    let rule = "LEGACY-JAVA-RULEMAP-antisamy-external-links";
    config(rule, "antisamy-policy.xml", "<policy><attribute name=\"href\"><regexp-list><regexp name=\"onsiteURL\"/><regexp name=\"offsiteURL\"/></regexp-list></attribute></policy>", 1);
    config(rule, "antisamy-policy.xml", "<policy><attribute name=\"href\"><regexp-list><regexp name=\"onsiteURL\"/></regexp-list></attribute></policy>", 0);
}

#[test]
fn spring_webflow_form_actions_have_validators() {
    let rule = "LEGACY-JAVA-RULEMAP-spring-webflow-form-validator";
    config(rule, "webflow-context.xml", "<beans><bean id=\"userAction\" class=\"org.springframework.webflow.action.FormAction\"><property name=\"formObjectClass\" value=\"User\"/></bean></beans>", 1);
    config(rule, "webflow-context.xml", "<beans><bean id=\"userAction\" class=\"org.springframework.webflow.action.FormAction\"><property name=\"validator\"><bean class=\"UserValidator\"/></property></bean></beans>", 0);
}

#[test]
fn j2ee_session_timeout_uses_the_legacy_thirty_minute_boundary() {
    let rule = "LEGACY-JAVA-RULEMAP-j2ee-excessive-session-timeout";
    config(rule, "WEB-INF/web.xml", "<web-app><session-config><session-timeout>-1</session-timeout></session-config><session-config><session-timeout>60</session-timeout></session-config></web-app>", 2);
    config(
        rule,
        "WEB-INF/web.xml",
        "<web-app><session-config><session-timeout>30</session-timeout></session-config></web-app>",
        0,
    );
}

#[test]
fn j2ee_session_id_length_requires_sixteen_bytes() {
    let rule = "LEGACY-JAVA-RULEMAP-j2ee-insufficient-session-id-length";
    config(rule, "META-INF/weblogic-application.xml", "<weblogic-application><session-descriptor><id-length>10</id-length></session-descriptor></weblogic-application>", 1);
    config(rule, "WEB-INF/weblogic.xml", "<weblogic-web-app><session-descriptor><id-length>16</id-length></session-descriptor></weblogic-web-app>", 0);
}

#[test]
fn j2ee_cookie_transport_detects_url_tracking_and_weblogic_disablement() {
    let rule = "LEGACY-JAVA-RULEMAP-j2ee-cookies-disabled";
    config(
        rule,
        "WEB-INF/web.xml",
        "<web-app><session-config><tracking-mode>URL</tracking-mode></session-config></web-app>",
        1,
    );
    config(
        rule,
        "WEB-INF/web.xml",
        "<web-app><session-config><tracking-mode>COOKIE</tracking-mode></session-config></web-app>",
        0,
    );
    config(rule, "WEB-INF/weblogic.xml", "<weblogic-web-app><session-descriptor><cookies-enabled>false</cookies-enabled></session-descriptor></weblogic-web-app>", 1);
}

#[test]
fn j2ee_authentication_method_is_required_only_for_authorization_constraints() {
    let rule = "LEGACY-JAVA-RULEMAP-j2ee-missing-authentication-method";
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint></security-constraint></web-app>", 1);
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint></security-constraint><login-config><auth-method>FORM</auth-method></login-config></web-app>", 0);
    config(rule, "WEB-INF/web.xml", "<web-app><servlet/></web-app>", 0);
}

#[test]
fn j2ee_each_protected_resource_requires_confidential_transport() {
    let rule = "LEGACY-JAVA-RULEMAP-j2ee-missing-transport-constraint";
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint></security-constraint></web-app>", 1);
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint><user-data-constraint><transport-guarantee>NONE</transport-guarantee></user-data-constraint></security-constraint></web-app>", 1);
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint><user-data-constraint><transport-guarantee>CONFIDENTIAL</transport-guarantee></user-data-constraint></security-constraint></web-app>", 0);
}

#[test]
fn javaee_debug_and_tomcat_transport_rules_use_numeric_and_boolean_semantics() {
    let debug = "LEGACY-JAVA-RULEMAP-j2ee-debug-information";
    config(
        debug,
        "conf/server.xml",
        "<Server><Realm className=\"org.apache.catalina.realm.JAASRealm\" debug=\"3\"/></Server>",
        1,
    );
    config(
        debug,
        "conf/server.xml",
        "<Server><Realm debug=\"2\"/></Server>",
        0,
    );
    let transport = "LEGACY-JAVA-RULEMAP-tomcat-insecure-connector";
    config(
        transport,
        "conf/server.xml",
        "<Server><Connector port=\"8009\" protocol=\"HTTP/1.1\" redirectPort=\"8443\"/></Server>",
        1,
    );
    config(
        transport,
        "conf/server.xml",
        "<Server><Connector port=\"8443\" protocol=\"HTTP/1.1\" secure=\"true\"/></Server>",
        0,
    );
}

#[test]
fn javaee_duplicate_role_and_mapping_rules_report_only_later_entries() {
    let roles = "LEGACY-JAVA-RULEMAP-j2ee-duplicate-security-role";
    config(roles, "WEB-INF/web.xml", "<web-app><security-role><role-name>admin</role-name></security-role><security-role><role-name>admin</role-name></security-role></web-app>", 1);
    config(roles, "WEB-INF/web.xml", "<web-app><security-role><role-name>admin</role-name></security-role><security-role><role-name>user</role-name></security-role></web-app>", 0);
    let mappings = "LEGACY-JAVA-RULEMAP-j2ee-duplicate-servlet-mapping";
    config(mappings, "WEB-INF/web.xml", "<web-app><servlet-mapping><servlet-name>A</servlet-name><url-pattern>/same/*</url-pattern></servlet-mapping><servlet-mapping><servlet-name>B</servlet-name><url-pattern>/same/*</url-pattern></servlet-mapping></web-app>", 1);
    config(mappings, "WEB-INF/web.xml", "<web-app><servlet-mapping><servlet-name>A</servlet-name><url-pattern>/a/*</url-pattern></servlet-mapping><servlet-mapping><servlet-name>B</servlet-name><url-pattern>/b/*</url-pattern></servlet-mapping></web-app>", 0);
}

#[test]
fn javaee_excessive_mapping_and_invalid_servlet_rules_are_scoped_per_element() {
    let excessive = "LEGACY-JAVA-RULEMAP-j2ee-excessive-servlet-mappings";
    config(excessive, "WEB-INF/web.xml", "<web-app><servlet-mapping><servlet-name>A</servlet-name><url-pattern>/a</url-pattern><url-pattern>/b</url-pattern></servlet-mapping></web-app>", 1);
    config(excessive, "WEB-INF/web.xml", "<web-app><servlet-mapping><servlet-name>A</servlet-name><url-pattern>/a</url-pattern></servlet-mapping></web-app>", 0);
    let invalid = "LEGACY-JAVA-RULEMAP-j2ee-invalid-servlet-name";
    config(invalid, "WEB-INF/web.xml", "<web-app><servlet><servlet-class>A</servlet-class></servlet><servlet><servlet-name/><servlet-class>B</servlet-class></servlet><servlet><servlet-name>C</servlet-name><servlet-name>D</servlet-name></servlet></web-app>", 3);
    config(invalid, "WEB-INF/web.xml", "<web-app><servlet><servlet-name>A</servlet-name><servlet-class>A</servlet-class></servlet></web-app>", 0);
}

#[test]
fn javaee_error_page_rules_distinguish_absent_and_incomplete_handling() {
    let absent = "LEGACY-JAVA-RULEMAP-j2ee-missing-error-handling";
    config(
        absent,
        "WEB-INF/web.xml",
        "<web-app><servlet/></web-app>",
        1,
    );
    config(absent, "WEB-INF/web.xml", "<web-app><error-page><error-code>500</error-code><location>/error.jsp</location></error-page></web-app>", 0);
    let throwable = "LEGACY-JAVA-RULEMAP-j2ee-incomplete-throwable-error-handling";
    config(throwable, "WEB-INF/web.xml", "<web-app><error-page><error-code>500</error-code><location>/error.jsp</location></error-page></web-app>", 1);
    config(throwable, "WEB-INF/web.xml", "<web-app><error-page><exception-type>java.lang.Throwable</exception-type><location>/error.jsp</location></error-page></web-app>", 0);
}

#[test]
fn javaee_reference_rules_join_definitions_to_mappings_and_roles() {
    let filter = "LEGACY-JAVA-RULEMAP-j2ee-missing-filter-definition";
    config(filter, "WEB-INF/web.xml", "<web-app><filter><filter-name>One</filter-name><filter-class>F</filter-class></filter><filter-mapping><filter-name>Two</filter-name><url-pattern>/*</url-pattern></filter-mapping></web-app>", 1);
    config(filter, "WEB-INF/web.xml", "<web-app><filter><filter-name>One</filter-name><filter-class>F</filter-class></filter><filter-mapping><filter-name>One</filter-name><url-pattern>/*</url-pattern></filter-mapping></web-app>", 0);
    let role = "LEGACY-JAVA-RULEMAP-j2ee-missing-security-role";
    config(role, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint></security-constraint></web-app>", 1);
    config(role, "WEB-INF/web.xml", "<web-app><security-constraint><auth-constraint><role-name>user</role-name></auth-constraint></security-constraint><security-role><role-name>user</role-name></security-role></web-app>", 0);
    let servlet = "LEGACY-JAVA-RULEMAP-j2ee-missing-servlet-mapping";
    config(servlet, "WEB-INF/web.xml", "<web-app><servlet><servlet-name>A</servlet-name><servlet-class>A</servlet-class></servlet></web-app>", 1);
    config(servlet, "WEB-INF/web.xml", "<web-app><servlet><servlet-name>A</servlet-name><servlet-class>A</servlet-class></servlet><servlet-mapping><servlet-name>A</servlet-name><url-pattern>/a</url-pattern></servlet-mapping></web-app>", 0);
}

#[test]
fn javaee_ejb_rules_detect_remote_entities_and_anyone_permissions() {
    let remote = "LEGACY-JAVA-RULEMAP-j2ee-unsafe-bean-declaration";
    config(remote, "META-INF/ejb-jar.xml", "<ejb-jar><enterprise-beans><entity><ejb-name>E</ejb-name><remote>Remote</remote></entity></enterprise-beans></ejb-jar>", 1);
    config(remote, "META-INF/ejb-jar.xml", "<ejb-jar><enterprise-beans><entity><ejb-name>E</ejb-name><local>Local</local></entity></enterprise-beans></ejb-jar>", 0);
    let anyone = "LEGACY-JAVA-RULEMAP-j2ee-weak-access-permissions";
    config(anyone, "META-INF/ejb-jar.xml", "<ejb-jar><assembly-descriptor><method-permission><role-name>ANYONE</role-name><method><ejb-name>E</ejb-name></method></method-permission></assembly-descriptor></ejb-jar>", 1);
    config(anyone, "META-INF/ejb-jar.xml", "<ejb-jar><assembly-descriptor><method-permission><role-name>admin</role-name></method-permission></assembly-descriptor></ejb-jar>", 0);
}

#[test]
fn websphere_servlet_by_class_name_supports_xml_and_xmi_forms() {
    let rule = "LEGACY-JAVA-RULEMAP-websphere-servlet-by-class-name";
    config(rule, "WEB-INF/ibm-web-ext.xml", "<web-ext><enable-serving-servlets-by-class-name>true</enable-serving-servlets-by-class-name></web-ext>", 1);
    config(rule, "WEB-INF/ibm-web-ext.xml", "<web-ext><enable-serving-servlets-by-class-name>false</enable-serving-servlets-by-class-name></web-ext>", 0);
    config(rule, "WEB-INF/ibm-web-ext.xmi", "<webappext xmi:version=\"2.0\" xmlns:xmi=\"http://www.omg.org/XMI\" serveServletsByClassnameEnabled=\"true\"/>", 1);
}

#[test]
fn ivy_dynamic_revision_rule_rejects_ranges_and_latest_versions() {
    let rule = "LEGACY-JAVA-RULEMAP-build-dynamic-dependency-version";
    config(rule, "ivy.xml", "<ivy-module><dependencies><dependency org=\"clover\" name=\"clover\" rev=\"latest.release\"/><dependency org=\"a\" name=\"b\" rev=\"[1.0,2.0)\"/></dependencies></ivy-module>", 2);
    config(rule, "ivy.xml", "<ivy-module><dependencies><dependency org=\"clover\" name=\"clover\" rev=\"1.3.9\"/></dependencies></ivy-module>", 0);
}

#[test]
fn build_repository_rules_distinguish_external_hosts_from_private_mirrors() {
    let ant = "LEGACY-JAVA-RULEMAP-build-external-ant-repository";
    config(
        ant,
        "build.xml",
        "<project><get src=\"https://repo.example.org/a.jar\" dest=\"a.jar\"/></project>",
        1,
    );
    config(
        ant,
        "build.xml",
        "<project><get src=\"http://172.16.1.13/a.jar\" dest=\"a.jar\"/></project>",
        0,
    );
    let ivy = "LEGACY-JAVA-RULEMAP-build-external-ivy-repository";
    config(ivy, "ivysettings.xml", "<ivysettings><resolvers><url><artifact pattern=\"https://repo.example.org/[artifact]-[revision].[ext]\"/></url></resolvers></ivysettings>", 1);
    config(ivy, "ivyconf.xml", "<ivyconf><resolvers><url><ivy pattern=\"http://10.0.0.8/[module]/ivy.xml\"/></url></resolvers></ivyconf>", 0);
    let maven = "LEGACY-JAVA-RULEMAP-build-external-maven-repository";
    config(maven, "pom.xml", "<project><repositories><repository><id>public</id><url>https://repo.example.org/maven</url></repository></repositories></project>", 1);
    config(maven, "settings.xml", "<settings><profiles><profile><repositories><repository><url>http://192.168.1.8/maven</url></repository></repositories></profile></profiles></settings>", 0);
}

#[test]
fn docker_default_user_rule_uses_the_final_user_instruction() {
    let rule = "LEGACY-JAVA-RULEMAP-docker-default-user-privilege";
    config(
        rule,
        "Dockerfile",
        "FROM eclipse-temurin:21\nCOPY app.jar /app.jar\n",
        1,
    );
    config(
        rule,
        "Dockerfile",
        "FROM eclipse-temurin:21\nUSER app\nUSER root\n",
        1,
    );
    config(
        rule,
        "Dockerfile",
        "FROM eclipse-temurin:21\nUSER 10001:10001\n",
        0,
    );
}

#[test]
fn docker_privileged_container_and_port_rules_ignore_safe_forms() {
    let privileged = "LEGACY-JAVA-RULEMAP-docker-privileged-container";
    config(
        privileged,
        "Dockerfile",
        "FROM docker:cli\nRUN docker run --privileged worker\n",
        1,
    );
    config(
        privileged,
        "Dockerfile",
        "FROM docker:cli\n# RUN docker run --privileged worker\nRUN docker run worker\n",
        0,
    );
    let port = "LEGACY-JAVA-RULEMAP-docker-privileged-port";
    config(port, "Dockerfile", "FROM app\nEXPOSE 80 8443/tcp\n", 1);
    config(port, "Dockerfile", "FROM app\nEXPOSE 8080/tcp\n", 0);
}

#[test]
fn docker_sensitive_volume_and_ssh_rules_cover_shell_and_json_volume_forms() {
    let volume = "LEGACY-JAVA-RULEMAP-docker-sensitive-host-directory";
    config(
        volume,
        "Dockerfile",
        "FROM app\nVOLUME [\"/etc/ssl\", \"/data\"]\n",
        1,
    );
    config(
        volume,
        "Dockerfile",
        "FROM app\nVOLUME /var/lib/example\n",
        0,
    );
    let ssh = "LEGACY-JAVA-RULEMAP-docker-ssh-service";
    config(
        ssh,
        "Dockerfile",
        "FROM app\nRUN apt-get install openssh-server\nEXPOSE 22\n",
        2,
    );
    config(
        ssh,
        "Dockerfile",
        "FROM app\nRUN java -jar app.jar\nEXPOSE 8080\n",
        0,
    );
}

#[test]
fn android_provider_permission_rules_distinguish_write_only_combined_and_split() {
    let write_only = "LEGACY-JAVA-RULEMAP-android-provider-write-only-permission";
    manifest(write_only, "<application><provider android:name=\".P\" android:writePermission=\"app.WRITE\"/></application>", 1);
    manifest(write_only, "<application><provider android:name=\".P\" android:readPermission=\"app.READ\" android:writePermission=\"app.WRITE\"/></application>", 0);
    let combined = "LEGACY-JAVA-RULEMAP-android-provider-combined-permission";
    manifest(combined, "<application><provider android:name=\".P\" android:permission=\"app.READ_WRITE\"/></application>", 1);
    manifest(combined, "<application><provider android:name=\".P\" android:readPermission=\"app.READ\" android:writePermission=\"app.WRITE\"/></application>", 0);
}

#[test]
fn android_provider_export_and_network_configuration_require_explicit_policy() {
    let provider = "LEGACY-JAVA-RULEMAP-android-provider-missing-export-or-permission";
    manifest(
        provider,
        "<application><provider android:name=\".P\"/></application>",
        1,
    );
    manifest(
        provider,
        "<application><provider android:name=\".P\" android:exported=\"false\"/></application>",
        0,
    );
    let network = "LEGACY-JAVA-RULEMAP-android-missing-network-security-config";
    manifest(network, "<application/>", 1);
    manifest(
        network,
        "<application android:networkSecurityConfig=\"@xml/network_security_config\"/>",
        0,
    );
}

#[test]
fn android_receiver_mixing_and_legacy_sdk_are_structurally_checked() {
    let receiver = "LEGACY-JAVA-RULEMAP-android-mixed-receiver-functionality";
    manifest(receiver, "<application><receiver android:name=\".R\"><intent-filter><action android:name=\"android.intent.action.BOOT_COMPLETED\"/><action android:name=\"com.example.REFRESH\"/></intent-filter></receiver></application>", 1);
    manifest(receiver, "<application><receiver android:name=\".R\"><intent-filter><action android:name=\"com.example.REFRESH\"/></intent-filter></receiver></application>", 0);
    let sdk = "LEGACY-JAVA-RULEMAP-android-tap-jacking-sdk";
    manifest(
        sdk,
        "<uses-sdk android:minSdkVersion=\"5\"/><application/>",
        1,
    );
    manifest(
        sdk,
        "<uses-sdk android:minSdkVersion=\"9\"/><application/>",
        0,
    );
    manifest(sdk, "<application/>", 1);
}

#[test]
fn axis_soap_monitor_rule_detects_servlet_and_module_forms() {
    let rule = "LEGACY-JAVA-RULEMAP-axis-soap-monitor-enabled";
    config(rule, "WEB-INF/web.xml", "<web-app><servlet><servlet-name>SOAPMonitorService</servlet-name><servlet-class>org.apache.axis.monitor.SOAPMonitorService</servlet-class></servlet></web-app>", 2);
    config(
        rule,
        "conf/axis2.xml",
        "<axisconfig><module ref=\"soapmonitor\"/></axisconfig>",
        1,
    );
    config(rule, "WEB-INF/web.xml", "<web-app><servlet><servlet-name>Application</servlet-name><servlet-class>example.Application</servlet-class></servlet></web-app>", 0);
}

#[test]
fn axis_ws_security_rules_require_inflow_outflow_and_rampart() {
    let insecure = "<axisconfig name=\"AxisJava2.0\"><parameter name=\"disableREST\" locked=\"true\">false</parameter></axisconfig>";
    config(
        "LEGACY-JAVA-RULEMAP-axis-missing-inflow-security",
        "conf/axis2.xml",
        insecure,
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-rest-enabled",
        "conf/axis2.xml",
        insecure,
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-missing-outflow-security",
        "conf/axis2.xml",
        insecure,
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-missing-rampart",
        "conf/axis2.xml",
        insecure,
        1,
    );
    let secure = "<axisconfig name=\"AxisJava2.0\"><parameter name=\"disableREST\">true</parameter><parameter name=\"InflowSecurity\"/><parameter name=\"OutflowSecurity\"/><module ref=\"rampart\"/></axisconfig>";
    config(
        "LEGACY-JAVA-RULEMAP-axis-missing-inflow-security",
        "conf/axis2.xml",
        secure,
        0,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-rest-enabled",
        "conf/axis2.xml",
        secure,
        0,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-missing-outflow-security",
        "conf/axis2.xml",
        secure,
        0,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-missing-rampart",
        "conf/axis2.xml",
        secure,
        0,
    );
}

#[test]
fn adf_task_flow_requires_explicit_url_invocation_policy() {
    let rule = "LEGACY-JAVA-RULEMAP-adf-url-invoke-default";
    config(rule, "WEB-INF/account-task-flow-definition.xml", "<adfc-config><task-flow-definition id=\"account\"><input-parameter-definition/></task-flow-definition></adfc-config>", 1);
    config(rule, "WEB-INF/account-task-flow-definition.xml", "<adfc-config><task-flow-definition id=\"account\"><visibility><url-invoke-disallowed/></visibility></task-flow-definition></adfc-config>", 0);
}

#[test]
fn struts_definition_rules_validate_form_bean_identity_and_types() {
    let duplicate = "LEGACY-JAVA-RULEMAP-struts-duplicate-form-bean";
    config(duplicate, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"LoginForm\"/><form-bean name=\"login\" type=\"OtherForm\"/></form-beans></struts-config>", 1);
    config(duplicate, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"LoginForm\"/></form-beans></struts-config>", 0);

    let name = "LEGACY-JAVA-RULEMAP-struts-missing-form-bean-name";
    config(
        name,
        "WEB-INF/struts-config.xml",
        "<struts-config><form-beans><form-bean type=\"LoginForm\"/></form-beans></struts-config>",
        1,
    );
    config(name, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"LoginForm\"/></form-beans></struts-config>", 0);

    let ty = "LEGACY-JAVA-RULEMAP-struts-missing-form-bean-type";
    config(
        ty,
        "WEB-INF/struts-config.xml",
        "<struts-config><form-beans><form-bean name=\"login\"/></form-beans></struts-config>",
        1,
    );
    config(ty, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"LoginForm\"/></form-beans></struts-config>", 0);

    let property = "LEGACY-JAVA-RULEMAP-struts-missing-form-property-type";
    config(property, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"org.apache.struts.action.DynaActionForm\"><form-property name=\"user\"/></form-bean></form-beans></struts-config>", 1);
    config(property, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"org.apache.struts.action.DynaActionForm\"><form-property name=\"user\" type=\"java.lang.String\"/></form-bean></form-beans></struts-config>", 0);
}

#[test]
fn struts_action_rules_validate_references_paths_inputs_and_validation() {
    let path = "LEGACY-JAVA-RULEMAP-struts-invalid-action-path";
    config(path, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"login\"/></action-mappings></struts-config>", 1);
    config(path, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"/login\"/></action-mappings></struts-config>", 0);

    let input = "LEGACY-JAVA-RULEMAP-struts-missing-action-input";
    config(input, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"/login\" name=\"login\" validate=\"true\"/></action-mappings></struts-config>", 1);
    config(input, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"/login\" name=\"login\" input=\"/login.jsp\"/></action-mappings></struts-config>", 0);

    let missing = "LEGACY-JAVA-RULEMAP-struts-missing-form-bean";
    config(missing, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"/login\" name=\"missing\"/></action-mappings></struts-config>", 1);
    config(missing, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"LoginForm\"/></form-beans><action-mappings><action path=\"/login\" name=\"login\"/></action-mappings></struts-config>", 0);

    let disabled = "LEGACY-JAVA-RULEMAP-struts-validator-disabled";
    config(disabled, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"/login\" validate=\"false\"/></action-mappings></struts-config>", 1);
    config(disabled, "WEB-INF/struts-config.xml", "<struts-config><action-mappings><action path=\"/login\" validate=\"true\"/></action-mappings></struts-config>", 0);
}

#[test]
fn struts_mapping_and_framework_rules_validate_required_attributes_and_usage() {
    let exception = "LEGACY-JAVA-RULEMAP-struts-missing-exception-type";
    config(exception, "WEB-INF/struts-config.xml", "<struts-config><global-exceptions><exception key=\"failure\"/></global-exceptions></struts-config>", 1);
    config(exception, "WEB-INF/struts-config.xml", "<struts-config><global-exceptions><exception key=\"failure\" type=\"java.lang.Exception\"/></global-exceptions></struts-config>", 0);

    let forward_name = "LEGACY-JAVA-RULEMAP-struts-missing-forward-name";
    config(forward_name, "WEB-INF/struts-config.xml", "<struts-config><global-forwards><forward path=\"/home.jsp\"/></global-forwards></struts-config>", 1);
    config(forward_name, "WEB-INF/struts-config.xml", "<struts-config><global-forwards><forward name=\"home\" path=\"/home.jsp\"/></global-forwards></struts-config>", 0);

    let forward_path = "LEGACY-JAVA-RULEMAP-struts-missing-forward-path";
    config(forward_path, "WEB-INF/struts-config.xml", "<struts-config><global-forwards><forward name=\"home\"/></global-forwards></struts-config>", 1);
    config(forward_path, "WEB-INF/struts-config.xml", "<struts-config><global-forwards><forward name=\"home\" path=\"/home.jsp\"/></global-forwards></struts-config>", 0);

    let plugin = "LEGACY-JAVA-RULEMAP-struts-validator-plugin-missing";
    config(
        plugin,
        "WEB-INF/struts-config.xml",
        "<struts-config><form-beans/></struts-config>",
        1,
    );
    config(plugin, "WEB-INF/struts-config.xml", "<struts-config><plug-in className=\"org.apache.struts.validator.ValidatorPlugIn\"/></struts-config>", 0);

    let unused = "LEGACY-JAVA-RULEMAP-struts-unused-action-form";
    config(unused, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"unused\" type=\"LoginForm\"/></form-beans></struts-config>", 1);
    config(unused, "WEB-INF/struts-config.xml", "<struts-config><form-beans><form-bean name=\"login\" type=\"LoginForm\"/></form-beans><action-mappings><action path=\"/login\" name=\"login\"/></action-mappings></struts-config>", 0);
}

#[test]
fn spring_html_escape_and_cors_rules_parse_xml_properties_and_yaml() {
    let escaping = "LEGACY-JAVA-RULEMAP-spring-html-escaping-disabled";
    config(escaping, "WEB-INF/spring.xml", "<taglib xmlns:spring=\"urn:spring\"><spring:htmlEscape defaultHtmlEscape=\"false\"/></taglib>", 1);
    config(escaping, "WEB-INF/spring.xml", "<taglib xmlns:spring=\"urn:spring\"><spring:htmlEscape defaultHtmlEscape=\"true\"/></taglib>", 0);

    let cors = "LEGACY-JAVA-RULEMAP-cors-wildcard-origin";
    config(
        cors,
        "application.properties",
        "endpoints.cors.allowed-origins=*\n",
        1,
    );
    config(cors, "application.yml", "management:\n  endpoints:\n    web:\n      cors:\n        allowed-origins: https://app.example\n", 0);
}

#[test]
fn cross_domain_rules_reject_domain_and_header_wildcards() {
    let domain = "LEGACY-JAVA-RULEMAP-cross-domain-wildcard";
    config(domain, "clientaccesspolicy.xml", "<access-policy><cross-domain-access><policy><allow-from><domain uri=\"*\"/></allow-from></policy></cross-domain-access></access-policy>", 1);
    config(domain, "clientaccesspolicy.xml", "<access-policy><cross-domain-access><policy><allow-from><domain uri=\"https://app.example\"/></allow-from></policy></cross-domain-access></access-policy>", 0);

    let headers = "LEGACY-JAVA-RULEMAP-cross-domain-wildcard-headers";
    config(headers, "crossdomain.xml", "<cross-domain-policy><allow-http-request-headers-from domain=\"example.com\" headers=\"*\"/></cross-domain-policy>", 1);
    config(headers, "crossdomain.xml", "<cross-domain-policy><allow-http-request-headers-from domain=\"example.com\" headers=\"X-Token\"/></cross-domain-policy>", 0);
}

#[test]
fn monitoring_dependencies_are_detected_structurally_in_maven_projects() {
    let druid = "LEGACY-JAVA-RULEMAP-druid-dependency";
    config(druid, "pom.xml", "<project><dependencies><dependency><groupId>com.alibaba</groupId><artifactId>druid</artifactId></dependency></dependencies></project>", 1);
    config(druid, "pom.xml", "<project><dependencies><dependency><groupId>org.postgresql</groupId><artifactId>postgresql</artifactId></dependency></dependencies></project>", 0);

    let swagger = "LEGACY-JAVA-RULEMAP-springfox-dependency";
    config(swagger, "pom.xml", "<project><dependencies><dependency><groupId>io.springfox</groupId><artifactId>springfox-swagger-ui</artifactId></dependency></dependencies></project>", 1);
    config(swagger, "pom.xml", "<project><dependencies><dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId></dependency></dependencies></project>", 0);
}

#[test]
fn logging_rules_parse_real_property_values_without_matching_comments() {
    let sql = "LEGACY-JAVA-RULEMAP-broad-sql-logging";
    config(
        sql,
        "log4j.properties",
        "log4j.logger.org.hibernate=INFO\n",
        1,
    );
    config(
        sql,
        "log4j.properties",
        "# log4j.logger.org.hibernate=DEBUG\nlog4j.logger.org.hibernate=WARN\n",
        0,
    );

    let debug = "LEGACY-JAVA-RULEMAP-broad-debug-logging";
    config(
        debug,
        "log4j.properties",
        "log4j.rootLogger = DEBUG, LOG1\n",
        1,
    );
    config(
        debug,
        "application.properties",
        "logging.level.root=INFO\n",
        0,
    );
}

#[test]
fn android_sensitive_permission_rules_match_their_own_permission_families() {
    for (rule, permission) in [
        (
            "LEGACY-JAVA-RULEMAP-android-permission-activity-recognition",
            "ACTIVITY_RECOGNITION",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-calendar",
            "READ_CALENDAR",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-call-log",
            "WRITE_CALL_LOG",
        ),
        ("LEGACY-JAVA-RULEMAP-android-permission-camera", "CAMERA"),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-contacts",
            "READ_CONTACTS",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-external-storage",
            "WRITE_EXTERNAL_STORAGE",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-device-admin",
            "BIND_DEVICE_ADMIN",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-location",
            "ACCESS_FINE_LOCATION",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-messaging",
            "SEND_SMS",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-microphone",
            "RECORD_AUDIO",
        ),
        ("LEGACY-JAVA-RULEMAP-android-permission-network", "INTERNET"),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-sensors",
            "BODY_SENSORS",
        ),
        (
            "LEGACY-JAVA-RULEMAP-android-permission-telephony",
            "CALL_PHONE",
        ),
    ] {
        manifest(
            rule,
            &format!(
                "<uses-permission android:name=\"android.permission.{permission}\"/><application/>"
            ),
            1,
        );
        manifest(
            rule,
            "<uses-permission android:name=\"android.permission.VIBRATE\"/><application/>",
            0,
        );
    }
}

#[test]
fn struts2_runtime_features_require_secure_deployment_configuration() {
    let dynamic = "LEGACY-JAVA-RULEMAP-struts2-dynamic-method-invocation";
    config(
        dynamic,
        "WEB-INF/classes/struts.xml",
        "<struts><package name=\"app\"/></struts>",
        1,
    );
    config(dynamic, "WEB-INF/classes/struts.xml", "<struts><constant name=\"struts.enable.DynamicMethodInvocation\" value=\"false\"/></struts>", 0);

    let browser = "LEGACY-JAVA-RULEMAP-struts2-config-browser";
    config(browser, "WEB-INF/classes/struts.xml", "<struts><package name=\"app\" extends=\"struts-default, config-browser-default\"/></struts>", 1);
    config(
        browser,
        "WEB-INF/classes/struts.xml",
        "<struts><package name=\"app\" extends=\"struts-default\"/></struts>",
        0,
    );
}

#[test]
fn struts2_validator_files_reject_duplicate_names_and_field_types() {
    let field = "LEGACY-JAVA-RULEMAP-struts2-duplicate-field-validator";
    config(field, "LoginAction-validation.xml", "<validators><field name=\"username\"><field-validator type=\"requiredstring\"/><field-validator type=\"requiredstring\"/></field></validators>", 1);
    config(field, "LoginAction-validation.xml", "<validators><field name=\"username\"><field-validator type=\"requiredstring\"/><field-validator type=\"length\"/></field></validators>", 0);

    let global = "LEGACY-JAVA-RULEMAP-struts2-duplicate-validator";
    config(global, "validators.xml", "<validators><validator name=\"safe\" class=\"A\"/><validator name=\"safe\" class=\"B\"/></validators>", 1);
    config(global, "validators.xml", "<validators><validator name=\"safe\" class=\"A\"/><validator name=\"length\" class=\"B\"/></validators>", 0);
}

#[test]
fn axis_transport_and_spring_exporter_rules_are_element_aware() {
    config(
        "LEGACY-JAVA-RULEMAP-axis-http-transport-sender",
        "axis2.xml",
        "<axisconfig><transportSender name=\"http\" class=\"Sender\"/></axisconfig>",
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-http-transport-sender",
        "axis2.xml",
        "<axisconfig><transportSender name=\"https\" class=\"Sender\"/></axisconfig>",
        0,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-http-transport-receiver",
        "axis2.xml",
        "<axisconfig><transportReceiver name=\"http\" class=\"Receiver\"/></axisconfig>",
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-axis-http-transport-receiver",
        "axis2.xml",
        "<axisconfig><transportReceiver name=\"https\" class=\"Receiver\"/></axisconfig>",
        0,
    );
    config("LEGACY-JAVA-RULEMAP-spring-web-service-exporter", "spring.xml", "<beans><bean class=\"org.springframework.remoting.jaxws.SimpleJaxWsServiceExporter\"/></beans>", 1);
    config(
        "LEGACY-JAVA-RULEMAP-spring-web-service-exporter",
        "spring.xml",
        "<beans><bean class=\"example.LocalService\"/></beans>",
        0,
    );
    config("LEGACY-JAVA-RULEMAP-spring-remote-service-exporter", "spring.xml", "<beans><bean class=\"org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter\"/></beans>", 1);
    config(
        "LEGACY-JAVA-RULEMAP-spring-remote-service-exporter",
        "spring.xml",
        "<beans><bean class=\"example.LocalService\"/></beans>",
        0,
    );
}

#[test]
fn android_exact_permission_path_rule_ignores_prefix_permissions() {
    let rule = "LEGACY-JAVA-RULEMAP-android-exact-permission-path";
    manifest(rule, "<application><provider android:name=\".Files\"><path-permission android:path=\"/documents\" android:readPermission=\"app.READ\"/></provider></application>", 1);
    manifest(rule, "<application><provider android:name=\".Files\"><path-permission android:pathPrefix=\"/documents/\" android:readPermission=\"app.READ\"/></provider></application>", 0);
}

#[test]
fn password_configuration_rules_distinguish_empty_literal_and_secret_reference() {
    let empty = "LEGACY-JAVA-RULEMAP-empty-password-property";
    config(empty, "application.properties", "database.password=\n", 1);
    config(
        empty,
        "application.properties",
        "database.password=${DB_PASSWORD}\n",
        0,
    );

    let hardcoded = "LEGACY-JAVA-RULEMAP-hardcoded-password-property";
    config(
        hardcoded,
        "application.yml",
        "database:\n  password: change-me\n",
        1,
    );
    config(
        hardcoded,
        "application.yml",
        "database:\n  password: ${DB_PASSWORD}\n",
        0,
    );
    config(
        hardcoded,
        "spring.xml",
        "<beans><property name=\"password\" value=\"change-me\"/></beans>",
        1,
    );
    config(
        hardcoded,
        "spring.xml",
        "<beans><property name=\"password\" value=\"${DB_PASSWORD}\"/></beans>",
        0,
    );
}

#[test]
fn xml_schema_rules_are_namespace_aware_and_attribute_scoped() {
    let prefix = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">";
    config(
        "LEGACY-JAVA-RULEMAP-xsd-lax-processing",
        "schema/service.xsd",
        &format!("{prefix}<xs:any processContents=\"lax\"/></xs:schema>"),
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-xsd-lax-processing",
        "schema/service.xsd",
        &format!("{prefix}<xs:any processContents=\"strict\"/></xs:schema>"),
        0,
    );
    config(
        "LEGACY-JAVA-RULEMAP-xsd-any-type",
        "schema/service.xsd",
        &format!("{prefix}<xs:element name=\"payload\" type=\"xs:anyType\"/></xs:schema>"),
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-xsd-any-type",
        "schema/service.xsd",
        &format!("{prefix}<xs:element name=\"payload\" type=\"xs:string\"/></xs:schema>"),
        0,
    );
    config(
        "LEGACY-JAVA-RULEMAP-xsd-unbounded-occurrence",
        "schema/service.xsd",
        &format!("{prefix}<xs:element name=\"item\" maxOccurs=\"unbounded\"/></xs:schema>"),
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-xsd-unbounded-occurrence",
        "schema/service.xsd",
        &format!("{prefix}<xs:element name=\"item\" maxOccurs=\"100\"/></xs:schema>"),
        0,
    );
}

#[test]
fn javaee_direct_jsp_mapping_is_detected_in_web_xml() {
    let rule = "LEGACY-JAVA-RULEMAP-direct-jsp-access";
    config(rule, "WEB-INF/web.xml", "<web-app><servlet-mapping><servlet-name>View</servlet-name><url-pattern>*.jsp</url-pattern></servlet-mapping></web-app>", 1);
    config(rule, "WEB-INF/web.xml", "<web-app><servlet-mapping><servlet-name>Controller</servlet-name><url-pattern>/app/*</url-pattern></servlet-mapping></web-app>", 0);
}

#[test]
fn jsp_html_comment_rule_ignores_server_side_jsp_comments() {
    config(
        "LEGACY-JAVA-RULEMAP-jsp-html-comment",
        "view/account.jsp",
        "<html><!-- internal endpoint /admin --></html>",
        1,
    );
    config(
        "LEGACY-JAVA-RULEMAP-jsp-html-comment",
        "view/account.jsp",
        "<html><%-- server-side note --%></html>",
        0,
    );
}

#[test]
fn actuator_dependency_is_identified_as_a_deserialization_surface() {
    let rule = "LEGACY-JAVA-RULEMAP-unsafe-deserialization-component";
    config(rule, "pom.xml", "<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-actuator</artifactId></dependency></dependencies></project>", 1);
    config(rule, "pom.xml", "<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>", 0);
    config(rule, "settings.xml", "<dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-actuator</artifactId></dependency>", 0);
}

#[test]
fn javaee_security_constraints_require_exact_urls() {
    let rule = "LEGACY-JAVA-RULEMAP-j2ee-weak-security-constraint";
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><web-resource-collection><url-pattern>/admin/*</url-pattern></web-resource-collection><auth-constraint><role-name>ADMIN</role-name></auth-constraint></security-constraint></web-app>", 1);
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><web-resource-collection><url-pattern>/admin/create</url-pattern></web-resource-collection><auth-constraint><role-name>ADMIN</role-name></auth-constraint></security-constraint></web-app>", 0);
    config(rule, "WEB-INF/web.xml", "<web-app><servlet-mapping><url-pattern>*.jsp</url-pattern></servlet-mapping></web-app>", 0);
}

#[test]
fn javaee_security_constraints_cover_every_http_method() {
    let rule = "LEGACY-JAVA-RULEMAP-http-verb-tampering";
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><web-resource-collection><url-pattern>/admin/create</url-pattern><http-method>GET</http-method></web-resource-collection><auth-constraint><role-name>ADMIN</role-name></auth-constraint></security-constraint></web-app>", 1);
    config(rule, "WEB-INF/web.xml", "<web-app><security-constraint><web-resource-collection><url-pattern>/admin/create</url-pattern></web-resource-collection><auth-constraint><role-name>ADMIN</role-name></auth-constraint></security-constraint></web-app>", 0);
    config(rule, "WEB-INF/web.xml", "<web-app><servlet><init-param><param-name>http-method</param-name><param-value>GET</param-value></init-param></servlet></web-app>", 0);
}

#[test]
fn database_connections_require_transport_encryption() {
    let rule = "LEGACY-JAVA-RULEMAP-insecure-database-transport";
    config(rule, "app.config.xml", "<configuration><connectionStrings><add name=\"Main\" connectionString=\"Data Source=db.example.test,1433;Initial Catalog=main;User ID=app;Password=secret\" providerName=\"System.Data.SqlClient\"/></connectionStrings></configuration>", 1);
    config(rule, "app.config.xml", "<configuration><connectionStrings><add name=\"Main\" connectionString=\"Data Source=db.example.test,1433;Initial Catalog=main;Encrypt=yes\" providerName=\"System.Data.SqlClient\"/></connectionStrings></configuration>", 0);
    config(rule, "application.properties", "spring.datasource.url=jdbc:mysql://db.example.test/main?useSSL=false\n", 1);
    config(rule, "application.properties", "spring.datasource.url=jdbc:mysql://db.example.test/main?useSSL=true\n", 0);
    config(rule, "application.yml", "spring:\n  datasource:\n    url: jdbc:postgresql://db.example.test/main?sslmode=verify-full\n", 0);
}

#[test]
fn android_permissions_are_exposed_for_least_privilege_review() {
    let rule = "LEGACY-JAVA-RULEMAP-android-permission-review";
    manifest(rule, "<uses-permission android:name=\"android.permission.CAMERA\"/><application/>", 1);
    manifest(rule, "<application android:label=\"Example\"/>", 0);
}
