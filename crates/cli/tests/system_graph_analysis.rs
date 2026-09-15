//! End-to-end tests for system-wide semantic boundary recovery
//! (`uniflow_system_graph`): Docker Compose/Kubernetes topology, config
//! resolution, HTTP route/call stitching with **field-precise** value
//! mappings, and framework/lifecycle entrypoints, wired into
//! `analyze-project --language mix` via `crates/cli/src/main.rs`'s
//! pre-pass, per-group rule injection, and post-loop composition.
//!
//! Both "services" in these fixtures happen to be written in Java (the most
//! thoroughly IR-verified frontend in this codebase) — nothing in
//! `uniflow_system_graph`'s adapters is Java-specific; they all operate on
//! the generic `uniflow_ir::Program`/`InstKind::Call` shape every frontend
//! produces.
//!
//! The critical property under test throughout this file is *value
//! identity*: a cross-service finding must only appear when a real source
//! reaches the *specific* query field a *specific* handler parameter reads
//! — never because "some value" reached "some parameter" of the same
//! route, and never merely because two components are deployed together.

use std::{
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

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after epoch").as_nanos();
    let dir = std::env::temp_dir().join(format!("uniflow-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).expect("create temporary project");
    dir
}

fn run_mix(project: &PathBuf, rules_yaml: &str, system_graph_path: &PathBuf) -> Vec<serde_json::Value> {
    let rules_path = project.join("rules.yaml");
    std::fs::write(&rules_path, rules_yaml).expect("write rules");

    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(project)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--system-graph-out")
        .arg(system_graph_path)
        .output()
        .expect("run analyze-project");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
}

fn read_system_graph(path: &PathBuf) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("read system graph output");
    serde_json::from_str(&text).expect("system graph output is valid JSON")
}

fn edges_of_kind<'a>(graph: &'a serde_json::Value, kind: &str) -> Vec<&'a serde_json::Value> {
    graph["edges"].as_array().unwrap().iter().filter(|edge| edge["kind"] == kind).collect()
}

fn cross_component_findings(graph: &serde_json::Value) -> Vec<serde_json::Value> {
    graph["cross_component_findings"].as_array().cloned().unwrap_or_default()
}

/// A rule set that marks `ServiceA.run`'s own parameter 0 as an untrusted
/// source directly (a `function_sources` rule, exactly the same primitive
/// this crate's own "external ingress" fallback injects) — isolating these
/// tests to the boundary-crossing mechanism itself, independent of how
/// `ServiceA.run` came to receive untrusted data in a real deployment.
fn rules_with_caller_source_and_sink(sink_matcher: &str) -> String {
    format!(
        r#"
function_sources:
  - id: caller-source
    language: java
    matcher:
      exact: ServiceA.run
    out: arg0
    kind: untrusted

sinks:
  - id: real-sink
    language: java
    matcher:
      exact: {sink_matcher}
    inputs: [arg0]
    kind: untrusted
"#
    )
}

const COMPOSE_YAML: &str = r#"
services:
  api:
    image: api:latest
    depends_on:
      - user
    environment:
      - USER_SERVICE_URL=http://user:8080
  user:
    image: user:latest
"#;

/// Test 1: Docker Compose + environment + HTTP, with a *field-precise*
/// value mapping. UniFlow reconstructs the service target through the
/// Compose-defined environment variable and produces **one continuous**
/// cross-service finding — not two independently-evidenced ones — and the
/// value identity (`userInput` -> query field `id` -> handler parameter
/// `id`) is preserved throughout.
#[test]
fn compose_environment_and_http_stitching_produces_one_continuous_cross_service_path() {
    let project = Scratch(scratch("sysgraph-compose-http"));
    std::fs::write(project.0.join("docker-compose.yml"), COMPOSE_YAML).expect("write compose");
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void run(String userInput) {
        String base = System.getenv("USER_SERVICE_URL");
        String url = base + "/profile?id=" + userInput;
        Http.get(url);
    }
}
"#,
    )
    .expect("write service a");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() {
        route("/profile", ServiceB::handler);
    }
    static void handler(String id) {
        sink(id);
    }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service b");
    let system_graph_path = project.0.join("system-graph.json");

    let findings = run_mix(&project.0, &rules_with_caller_source_and_sink("ServiceB.sink"), &system_graph_path);

    // The internal plumbing (boundary-output/-input tagged findings) must
    // never leak into the ordinary findings list.
    assert!(
        findings.iter().all(|finding| {
            let source = finding["source_rule_id"].as_str().unwrap_or_default();
            let sink = finding["sink_rule_id"].as_str().unwrap_or_default();
            !source.starts_with("boundary-input::") && !sink.starts_with("boundary-output::")
        }),
        "boundary-tagged findings leaked into the plain findings list: {findings:#?}"
    );

    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    assert_eq!(composed[0]["confidence"], "inferred"); // base URL resolved through Compose config, not a hardcoded literal
    assert_eq!(composed[0]["producer"]["source_rule_id"], "caller-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "real-sink");
    assert_eq!(composed[0]["producer_component"], "java");
    assert_eq!(composed[0]["consumer_component"], "java");

    let depends_on = edges_of_kind(&graph, "STARTUP_DEPENDS_ON");
    assert_eq!(depends_on.len(), 1, "{depends_on:#?}");

    let http_calls = edges_of_kind(&graph, "HTTP_CALL");
    assert_eq!(http_calls.len(), 1, "{http_calls:#?}");
    let mappings = http_calls[0]["value_mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 1, "{mappings:#?}");
    assert_eq!(mappings[0]["from"]["function"], "ServiceA.run");
    assert_eq!(mappings[0]["from"]["port"], "arg0");
    assert_eq!(mappings[0]["to"]["function"], "ServiceB.handler");
    assert_eq!(mappings[0]["to"]["port"], "arg0");
}

/// A request boundary is bidirectional: an explicit source returned by a
/// remote handler must reach the result value of the precise HTTP call in
/// the client, then a real local sink. This guards against a system graph
/// that merely records a response edge without turning it into executable
/// per-program source/sink bridge rules.
#[test]
fn http_handler_response_reaches_the_client_call_result_and_local_sink() {
    let project = Scratch(scratch("sysgraph-http-response"));
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void run() {
        String profile = Http.get("http://user:8080/profile");
        sink(profile);
    }
    static void sink(String value) {}
}
"#,
    )
    .expect("write client service");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static String handler() { return secret(); }
    static String secret() { return "secret"; }
}
"#,
    )
    .expect("write remote service");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: remote-response
    language: java
    matcher:
      exact: ServiceB.handler
    out: return
    kind: untrusted
function_sinks:
  - id: client-sink
    language: java
    matcher:
      exact: ServiceA.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must be composed: {findings:#?}");

    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "remote-response");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "client-sink");
    let http_calls = edges_of_kind(&graph, "HTTP_CALL");
    assert_eq!(http_calls.len(), 1, "{http_calls:#?}");
    let response = http_calls[0]["value_mappings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mapping| mapping["kind"] == "return_to_result")
        .expect("response mapping");
    assert_eq!(response["from"]["function"], "ServiceB.handler");
    assert_eq!(response["to"]["function"], "ServiceA.run");
    assert_eq!(response["to"]["port"], "return");
    assert!(response["to"]["call_site"].is_number());
}

/// NativeAOT's explicit unmanaged export is a real lifecycle entrypoint:
/// native code can supply its arguments without a managed call site. The
/// system graph must therefore inject the same external-ingress source that
/// an HTTP/RPC boundary receives, but only for an explicitly annotated ABI
/// export rather than for arbitrary C# static methods.
#[test]
fn csharp_unmanaged_callers_only_export_reaches_a_local_sink_from_external_native_input() {
    let project = Scratch(scratch("sysgraph-csharp-unmanaged-export"));
    std::fs::write(
        project.0.join("Callbacks.cs"),
        r#"
class Callbacks {
    [UnmanagedCallersOnly(EntryPoint = "native_callback")]
    public static void Callback(string input) {
        Sink(input);
    }
    static void Sink(string value) {}
}
"#,
    )
    .expect("write C# callback");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sinks:
  - id: csharp-callback-sink
    language: csharp
    matcher:
      exact: Callbacks.Sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert!(
        findings[0]["source_rule_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("system-boundary::ffi-external-ingress::Callbacks.Callback")),
        "{findings:#?}"
    );
    assert_eq!(findings[0]["sink_rule_id"], "csharp-callback-sink");
    let graph = read_system_graph(&system_graph_path);
    let edge = edges_of_kind(&graph, "INTEROP_CALL")
        .into_iter()
        .find(|edge| edge["from"] == "ffi:csharp:external-native-caller")
        .expect("external native caller edge");
    assert_eq!(edge["to"], "code:csharp:Callbacks.Callback");
}

/// Rust cdylib/staticlib exports are also externally callable lifecycle
/// entrypoints. This verifies the strict Rust frontend's `#[no_mangle]`
/// attribute reaches the mixed-project system pass and becomes an executable
/// native-input taint source, not merely a graph annotation.
#[test]
fn rust_no_mangle_export_reaches_a_local_sink_from_external_native_input() {
    let project = Scratch(scratch("sysgraph-rust-native-export"));
    std::fs::write(
        project.0.join("lib.rs"),
        r#"
#[no_mangle]
pub extern "C" fn native_callback(input: *const u8) {
    sink(input);
}

fn sink(value: *const u8) {}
"#,
    )
    .expect("write Rust export");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sinks:
  - id: rust-callback-sink
    language: rust
    matcher:
      exact: sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert!(
        findings[0]["source_rule_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("system-boundary::ffi-external-ingress::native_callback")),
        "{findings:#?}"
    );
    assert_eq!(findings[0]["sink_rule_id"], "rust-callback-sink");
    let graph = read_system_graph(&system_graph_path);
    let edge = edges_of_kind(&graph, "INTEROP_CALL")
        .into_iter()
        .find(|edge| edge["from"] == "ffi:rust:external-native-caller")
        .expect("external native caller edge");
    assert_eq!(edge["to"], "code:rust:native_callback");
}

/// Objective-C calls C ABI functions directly rather than through a separate
/// FFI runtime. A unique project-local C definition is enough evidence to
/// carry this exact argument across the language boundary.
#[test]
fn objective_c_direct_c_abi_call_produces_one_cross_component_finding() {
    let project = Scratch(scratch("sysgraph-objc-c-abi"));
    std::fs::write(
        project.0.join("Caller.m"),
        r#"
void run(char *user_input) {
    native_sink(user_input);
}
"#,
    )
    .expect("write Objective-C caller");
    std::fs::write(
        project.0.join("native.c"),
        r#"
void native_sink(char *value) {}
"#,
    )
    .expect("write C native sink");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: objc-source
    language: objc
    matcher:
      exact: run
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-native-sink
    language: c
    matcher:
      exact: native_sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must be composed: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "objc-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-native-sink");
}

/// A Swift bridging header/Clang module exposes C functions as bare Swift
/// calls. A unique local C implementation therefore creates one executable
/// interop boundary rather than two disconnected per-language results.
#[test]
fn swift_imported_c_call_produces_one_cross_component_finding() {
    let project = Scratch(scratch("sysgraph-swift-c-abi"));
    std::fs::write(
        project.0.join("Caller.swift"),
        r#"
func run(_ userInput: String) {
    native_sink(userInput)
}
"#,
    )
    .expect("write Swift caller");
    std::fs::write(project.0.join("native.c"), "void native_sink(char *value) {}")
        .expect("write C native sink");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: swift-source
    language: swift
    matcher:
      exact: run
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-native-sink
    language: c
    matcher:
      exact: native_sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must be composed: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "swift-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-native-sink");
}

/// Test A (negative): the query field is a hardcoded literal. A literal can
/// never be a taint source, so no value ever crosses the boundary and no
/// finding — composed or plain — may appear.
#[test]
fn a_constant_query_field_produces_no_cross_service_finding() {
    let project = Scratch(scratch("sysgraph-negative-a"));
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void run() {
        Http.get("http://user:8080/profile?id=constant");
    }
}
"#,
    )
    .expect("write service a");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) { sink(id); }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service b");
    let system_graph_path = project.0.join("system-graph.json");

    let findings = run_mix(
        &project.0,
        r#"
sinks:
  - id: real-sink
    language: java
    matcher:
      exact: ServiceB.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "{findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    assert!(cross_component_findings(&graph).is_empty());
    // Nothing calls `handler` with a mapped "id" — but the route *is*
    // called (with no dynamic field), so the external-ingress fallback
    // must not fire for `id` either.
    let http_calls = edges_of_kind(&graph, "HTTP_CALL");
    assert_eq!(http_calls[0]["value_mappings"].as_array().unwrap().len(), 0);
}

/// Test B (negative + positive): two query fields, `id` constant and
/// `lang` dynamic. A sink reading `id` must see no finding; the *same*
/// project with the sink reading `lang` instead must produce one.
#[test]
fn only_the_field_the_sink_actually_reads_participates_in_the_flow() {
    let service_a = r#"
class ServiceA {
    static void run(String langValue) {
        Http.get("http://user:8080/profile?id=constant&lang=" + langValue);
    }
}
"#;
    let source_rule = r#"
function_sources:
  - id: caller-source
    language: java
    matcher:
      exact: ServiceA.run
    out: arg0
    kind: untrusted
"#;

    // (B1) sink reads `id` -> no finding.
    {
        let project = Scratch(scratch("sysgraph-negative-b1"));
        std::fs::write(project.0.join("ServiceA.java"), service_a).expect("write service a");
        std::fs::write(
            project.0.join("ServiceB.java"),
            r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id, String lang) { sink(id); }
    static void sink(String s) {}
}
"#,
        )
        .expect("write service b");
        let system_graph_path = project.0.join("system-graph.json");
        let findings = run_mix(
            &project.0,
            &format!("{source_rule}\nsinks:\n  - id: real-sink\n    language: java\n    matcher:\n      exact: ServiceB.sink\n    inputs: [arg0]\n    kind: untrusted\n"),
            &system_graph_path,
        );
        assert!(findings.is_empty(), "{findings:#?}");
        let graph = read_system_graph(&system_graph_path);
        assert!(cross_component_findings(&graph).is_empty(), "no finding must flow through the untouched `id` field");
    }

    // (B2) sink reads `lang` -> a finding, correctly attributed to `lang`.
    {
        let project = Scratch(scratch("sysgraph-negative-b2"));
        std::fs::write(project.0.join("ServiceA.java"), service_a).expect("write service a");
        std::fs::write(
            project.0.join("ServiceB.java"),
            r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id, String lang) { sink(lang); }
    static void sink(String s) {}
}
"#,
        )
        .expect("write service b");
        let system_graph_path = project.0.join("system-graph.json");
        let findings = run_mix(
            &project.0,
            &format!("{source_rule}\nsinks:\n  - id: real-sink\n    language: java\n    matcher:\n      exact: ServiceB.sink\n    inputs: [arg0]\n    kind: untrusted\n"),
            &system_graph_path,
        );
        assert!(findings.is_empty());
        let graph = read_system_graph(&system_graph_path);
        let composed = cross_component_findings(&graph);
        assert_eq!(composed.len(), 1, "{composed:#?}");
        let http_calls = edges_of_kind(&graph, "HTTP_CALL");
        let mappings = http_calls[0]["value_mappings"].as_array().unwrap();
        assert_eq!(mappings.len(), 1, "{mappings:#?}");
        assert_eq!(mappings[0]["to"]["port"], "arg1"); // "lang" is handler's 2nd parameter
    }
}

/// Test C (negative): `lang` is the hardcoded constant this time (`id` is
/// dynamic); a sink reading `lang` must still see nothing.
#[test]
fn a_constant_field_never_lights_up_even_when_a_sibling_field_is_dynamic() {
    let project = Scratch(scratch("sysgraph-negative-c"));
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void run(String userInput) {
        Http.get("http://user:8080/profile?id=" + userInput + "&lang=ja");
    }
}
"#,
    )
    .expect("write service a");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id, String lang) { sink(lang); }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service b");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        &rules_with_caller_source_and_sink("ServiceB.sink"),
        &system_graph_path,
    );
    assert!(findings.is_empty(), "{findings:#?}");
    let graph = read_system_graph(&project.0.join("system-graph.json"));
    assert!(cross_component_findings(&graph).is_empty(), "the constant `lang` field must never be treated as reachable");
}

/// Test D: two independently, externally reachable services that share a
/// route path/parameter name must never be joined into a cross-service
/// finding just because their names match — only a recovered `HTTP_CALL`
/// justifies composition, which requires an actual caller.
#[test]
fn same_route_and_parameter_names_alone_never_join_two_unrelated_services() {
    let project = Scratch(scratch("sysgraph-negative-d"));
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) { sink(id); }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service b");
    std::fs::write(
        project.0.join("ServiceC.java"),
        r#"
class ServiceC {
    static void registerRoutes() { route("/profile", ServiceC::handler); }
    static void handler(String id) { sink(id); }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service c");
    let system_graph_path = project.0.join("system-graph.json");
    // Neither service is called by anything: both fall back to the
    // external-ingress default (their own `id` parameter is a source), so
    // EACH gets its OWN local finding — but never a cross-component one.
    let findings = run_mix(
        &project.0,
        r#"
sinks:
  - id: real-sink-b
    language: java
    matcher:
      exact: ServiceB.sink
    inputs: [arg0]
    kind: untrusted
  - id: real-sink-c
    language: java
    matcher:
      exact: ServiceC.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert_eq!(findings.len(), 2, "{findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    assert!(cross_component_findings(&graph).is_empty(), "no HTTP_CALL exists, so nothing may be composed");
}

/// Test E: an ambiguous route target (two handlers claim the same path) —
/// every defensible candidate is represented, marked `conservative`,
/// rather than one being picked arbitrarily.
#[test]
fn an_ambiguous_route_shared_by_two_handlers_marks_every_candidate_conservative() {
    let project = Scratch(scratch("sysgraph-ambiguous"));
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) {}
}
"#,
    )
    .expect("write service b");
    std::fs::write(
        project.0.join("ServiceC.java"),
        r#"
class ServiceC {
    static void registerRoutes() { route("/profile", ServiceC::handler); }
    static void handler(String id) {}
}
"#,
    )
    .expect("write service c");
    let system_graph_path = project.0.join("system-graph.json");

    run_mix(&project.0, "sources: []\nsinks: []\n", &system_graph_path);

    let graph = read_system_graph(&system_graph_path);
    let handles = edges_of_kind(&graph, "HANDLES");
    assert_eq!(handles.len(), 2, "expected both candidate handlers to be listed, not one arbitrarily chosen: {handles:#?}");
    let mut targets: Vec<&str> = handles.iter().map(|edge| edge["to"].as_str().unwrap()).collect();
    targets.sort_unstable();
    assert_eq!(targets, vec!["code:java:ServiceB.handler", "code:java:ServiceC.handler"]);
}

const K8S_MANIFESTS_YAML: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  SERVICE_URL: http://worker:9000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
  namespace: default
  labels:
    app: worker
spec:
  template:
    metadata:
      labels:
        app: worker
    spec:
      containers:
        - name: worker
          env:
            - name: SERVICE_URL
              valueFrom:
                configMapKeyRef:
                  name: app-config
                  key: SERVICE_URL
---
apiVersion: v1
kind: Service
metadata:
  name: worker
  namespace: default
spec:
  selector:
    app: worker
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: main
  namespace: default
spec:
  rules:
    - http:
        paths:
          - path: /worker
            backend:
              service:
                name: worker
"#;

/// Test 2: Kubernetes routing/config. UniFlow recovers
/// `Ingress -> Service -> Deployment` plus the application's environment
/// value coming through a `ConfigMap`, without incorrectly creating a
/// `DATA_FLOW`/`HTTP_CALL` edge for any of that pure deployment/routing
/// topology.
#[test]
fn kubernetes_ingress_service_deployment_and_configmap_topology_is_recovered() {
    let project = Scratch(scratch("sysgraph-k8s"));
    std::fs::write(project.0.join("manifests.yaml"), K8S_MANIFESTS_YAML).expect("write manifests");
    std::fs::write(project.0.join("Placeholder.java"), "class Placeholder {}\n").expect("write placeholder");
    let system_graph_path = project.0.join("system-graph.json");

    let findings = run_mix(&project.0, "sources: []\nsinks: []\n", &system_graph_path);
    assert!(findings.is_empty(), "{findings:#?}");

    let graph = read_system_graph(&project.0.join("system-graph.json"));
    let routes_to = edges_of_kind(&graph, "ROUTES_TO");
    assert_eq!(routes_to.len(), 1, "{routes_to:#?}");
    assert_eq!(routes_to[0]["from"], "k8s:Ingress:default/main");
    assert_eq!(routes_to[0]["to"], "k8s:Service:default/worker");

    let selects = edges_of_kind(&graph, "SELECTS");
    assert_eq!(selects.len(), 1, "{selects:#?}");
    assert_eq!(selects[0]["from"], "k8s:Service:default/worker");
    assert_eq!(selects[0]["to"], "k8s:Deployment:default/worker");

    let reads_config = edges_of_kind(&graph, "READS_CONFIG");
    assert_eq!(reads_config.len(), 1, "{reads_config:#?}");
    assert_eq!(reads_config[0]["to"], "k8s:ConfigMap:default/app-config");

    assert!(edges_of_kind(&graph, "DATA_FLOW").is_empty());
    assert!(edges_of_kind(&graph, "HTTP_CALL").is_empty());
    assert!(cross_component_findings(&graph).is_empty());
}

/// Test 3 (negative case): two services exist in the same Compose
/// deployment (with `depends_on`) but neither registers nor calls any HTTP
/// route — UniFlow must not invent a cross-service data-flow edge merely
/// because they are deployed together.
#[test]
fn co_deployed_services_with_no_communication_evidence_get_no_cross_service_edge() {
    let project = Scratch(scratch("sysgraph-negative-deploy"));
    std::fs::write(project.0.join("docker-compose.yml"), COMPOSE_YAML).expect("write compose");
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void run() {
        String base = System.getenv("USER_SERVICE_URL");
        System.out.println(base);
    }
}
"#,
    )
    .expect("write service a");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void handler(String id) {}
}
"#,
    )
    .expect("write service b");
    let system_graph_path = project.0.join("system-graph.json");

    let findings = run_mix(&project.0, "sources: []\nsinks: []\n", &system_graph_path);
    assert!(findings.is_empty(), "{findings:#?}");

    let graph = read_system_graph(&system_graph_path);
    assert!(edges_of_kind(&graph, "HTTP_CALL").is_empty());
    assert!(edges_of_kind(&graph, "DATA_FLOW").is_empty());
    assert!(edges_of_kind(&graph, "HANDLES").is_empty());
    assert!(cross_component_findings(&graph).is_empty());
    let depends_on = edges_of_kind(&graph, "STARTUP_DEPENDS_ON");
    assert_eq!(depends_on.len(), 1, "{depends_on:#?}");
}

/// Test 5 (lifecycle/framework implicit edge): a handler is registered as a
/// startup hook but has no ordinary source-level caller. UniFlow must
/// still analyze it (not leave it unreachable) and must represent the
/// runtime trigger in the system graph.
#[test]
fn a_startup_hook_with_no_ordinary_caller_is_still_analyzed_and_represented() {
    let project = Scratch(scratch("sysgraph-lifecycle"));
    std::fs::write(
        project.0.join("App.java"),
        r#"
class App {
    static void main() {
        onStartup(App::initialize);
    }
    static void initialize() {
        String secret = readSecret();
        sink(secret);
    }
    static String readSecret() { return "boot-time-secret"; }
    static void sink(String s) {}
}
"#,
    )
    .expect("write app");
    let system_graph_path = project.0.join("system-graph.json");

    let findings = run_mix(
        &project.0,
        r#"
sources:
  - id: secret-source
    language: java
    matcher:
      exact: App.readSecret
    out: return
    kind: untrusted
sinks:
  - id: startup-sink
    language: java
    matcher:
      exact: App.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );

    assert!(
        findings.iter().any(|finding| finding["source_rule_id"] == "secret-source" && finding["sink_rule_id"] == "startup-sink"),
        "expected App.initialize (reachable only via the startup hook) to still be analyzed: {findings:#?}"
    );

    let graph = read_system_graph(&system_graph_path);
    let startup_edges = edges_of_kind(&graph, "STARTUP");
    assert_eq!(startup_edges.len(), 1, "{startup_edges:#?}");
    assert_eq!(startup_edges[0]["to"], "code:java:App.initialize");
    let registers = edges_of_kind(&graph, "REGISTERS_HANDLER");
    assert_eq!(registers.len(), 1, "{registers:#?}");
    assert_eq!(registers[0]["from"], "App.main");
}

/// Deliverable #10: one concrete end-to-end path where a *real* source in
/// Service A (marked tainted only because nothing in the analyzed project
/// calls it — the external-ingress fallback, i.e. "assume this is reached
/// from the internet") reaches a *real* sink in Service B, through the
/// recovered HTTP boundary, without ServiceB ever being blanket-tainted:
/// `ServiceB.handler`'s *only* parameter is `id`, and it only becomes a
/// source because ServiceA's own recovered mapping names it precisely.
#[test]
fn external_ingress_in_service_a_reaches_a_real_sink_in_service_b_through_the_boundary() {
    let project = Scratch(scratch("sysgraph-end-to-end"));
    std::fs::write(project.0.join("docker-compose.yml"), COMPOSE_YAML).expect("write compose");
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void registerRoutes() {
        route("/forward", ServiceA::run);
    }
    static void run(String userInput) {
        String base = System.getenv("USER_SERVICE_URL");
        Http.get(base + "/profile?id=" + userInput);
    }
}
"#,
    )
    .expect("write service a");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    static void registerRoutes() { route("/profile", ServiceB::handler); }
    static void handler(String id) {
        sink(id);
    }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service b");
    let system_graph_path = project.0.join("system-graph.json");

    // No user-supplied source/sink for ServiceA.run at all: its only taint
    // origin is this crate's own external-ingress fallback (nothing calls
    // `/forward` from anywhere in the analyzed code).
    let findings = run_mix(
        &project.0,
        r#"
sinks:
  - id: real-sink
    language: java
    matcher:
      exact: ServiceB.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "{findings:#?}");

    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "findings={findings:#?}\ncomposed={composed:#?}");
    assert!(
        composed[0]["producer"]["source_rule_id"].as_str().unwrap().starts_with("system-boundary::http-external-ingress::"),
        "{composed:#?}"
    );
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "real-sink");
}

/// Persistence is a real system boundary, not a deployment-only relation:
/// user input stored by one component can become an issue only when another
/// component loads it later.  The write SQL contains a dynamic value but a
/// literal table identifier; the read proves the same table.  The unrelated
/// `audit_log` query is intentionally absent from the path.
#[test]
fn static_sql_table_identity_stitches_a_persisted_value_to_a_later_read() {
    let project = Scratch(scratch("sysgraph-database-persistence"));
    std::fs::write(
        project.0.join("Writer.java"),
        r#"
class Writer {
    static void store(String input) {
        Db.execute("INSERT INTO profiles(value) VALUES ('" + input + "')");
    }
}

"#,
    )
    .expect("write producer");
    std::fs::write(
        project.0.join("reader.py"),
        r#"
def load():
    stored = Db.query("SELECT value FROM profiles")
    sink(stored)

def unrelated():
    Db.query("SELECT event FROM audit_log")

def sink(value):
    pass
"#,
    )
    .expect("write consumer");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: stored-user-input
    language: java
    matcher:
      exact: Writer.store
    out: arg0
    kind: untrusted
sinks:
  - id: rendered-stored-value
    language: python
    matcher:
      exact: reader.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "DATA_FLOW");
    assert_eq!(composed[0]["producer_component"], "java");
    assert_eq!(composed[0]["consumer_component"], "python");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "stored-user-input");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "rendered-stored-value");

    let flows = edges_of_kind(&graph, "DATA_FLOW");
    assert_eq!(flows.len(), 1, "only the shared profiles table may connect calls: {flows:#?}");
    assert_eq!(flows[0]["value_mappings"][0]["from"]["function"], "Writer.store");
    assert_eq!(flows[0]["value_mappings"][0]["to"]["function"], "reader.load");
}

/// Python's common web-service shape is a decorator-defined FastAPI/Flask
/// handler on one side and a `requests`-family call on the other. This must
/// be recovered from the actual framework surface, not only an artificial
/// `router.get` registration in another language.
/// The JavaScript frontend's whole reason for being built first (of the
/// four new source-level languages) — an Express-style route registered as
/// a bare top-level statement (not inside any `function`) must still be
/// visible to `http.rs`'s route scanner via the synthetic `<script>`
/// function this frontend wraps top-level code in, and the field-precise
/// value mapping must survive `uniflow_lowering`'s JS-specific
/// `__uniflow.compose.string` wrapping of `+`-concatenation.
///
/// `app.get('/api/profile', function (id) { return profileImpl(id); })`
/// passes an inline, anonymous wrapper — `uniflow_lowering`'s generic
/// lambda-hoisting gives it an auto-generated internal name, then
/// `resolve_callable_argument`'s single-forwarding-call unwrap (the same
/// mechanism a Java method reference relies on) resolves it straight
/// through to `profileImpl`'s own real, stable, same-parameter-shape
/// qualified name — so this test never needs to reference the wrapper's
/// own auto-generated name, only `profileImpl`'s.
#[test]
fn javascript_express_route_and_outbound_call_produce_one_continuous_path() {
    let project = Scratch(scratch("sysgraph-javascript-express"));
    std::fs::write(
        project.0.join("client.js"),
        r#"
function fetchData(untrustedId) {
    const url = "http://profiles/api/profile?id=" + untrustedId;
    http.get(url);
}
"#,
    )
    .expect("write javascript client");
    std::fs::write(
        project.0.join("service.js"),
        r#"
function profileImpl(id) {
    sink(id);
}
function sink(value) {}
const app = express();
app.get('/api/profile', function (id) { return profileImpl(id); });
"#,
    )
    .expect("write javascript express service");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: javascript-client-input
    language: javascript
    matcher:
      exact: client.fetchData
    out: arg0
    kind: untrusted
sinks:
  - id: express-real-sink
    language: javascript
    matcher:
      exact: service.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "javascript-client-input");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "express-real-sink");
    let calls = edges_of_kind(&graph, "HTTP_CALL");
    let mappings = calls.iter().flat_map(|call| call["value_mappings"].as_array().unwrap()).collect::<Vec<_>>();
    assert_eq!(mappings.len(), 1, "{mappings:#?}");
    assert_eq!(mappings[0]["from"]["function"], "client.fetchData");
    assert_eq!(mappings[0]["to"]["function"], "service.profileImpl");
}

#[test]
fn python_requests_to_fastapi_decorator_stitches_the_named_query_field() {
    let project = Scratch(scratch("sysgraph-python-requests-fastapi"));
    std::fs::write(
        project.0.join("client.py"),
        r#"
import requests

def fetch(untrusted_id):
    url = "http://profiles/api/profile?id=" + untrusted_id
    requests.get(url)
"#,
    )
    .expect("write Python client");
    std::fs::write(
        project.0.join("service.py"),
        r#"
from fastapi import FastAPI
app = FastAPI()

@app.get("/api/profile")
def profile(id):
    sink(id)

def sink(value):
    pass
"#,
    )
    .expect("write FastAPI service");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: python-request-input
    language: python
    matcher:
      exact: client.fetch
    out: arg0
    kind: untrusted
sinks:
  - id: fastapi-real-sink
    language: python
    matcher:
      exact: service.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "python-request-input");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "fastapi-real-sink");
    let calls = edges_of_kind(&graph, "HTTP_CALL");
    assert_eq!(calls.len(), 1, "{calls:#?}");
    assert_eq!(calls[0]["value_mappings"][0]["from"]["function"], "client.fetch");
    assert_eq!(calls[0]["value_mappings"][0]["to"]["function"], "service.profile");
}

#[test]
fn python_requests_post_to_fastapi_api_route_preserves_the_verb_and_field_mapping() {
    let project = Scratch(scratch("sysgraph-python-requests-fastapi-api-route"));
    std::fs::write(
        project.0.join("client.py"),
        r#"
import requests

def submit(untrusted_id):
    requests.post("http://profiles/api/profile?id=" + untrusted_id)
"#,
    )
    .expect("write Python client");
    std::fs::write(
        project.0.join("service.py"),
        r#"
from fastapi import FastAPI
app = FastAPI()

@app.api_route("/api/profile", methods=["POST"])
def profile(id):
    sink(id)

def sink(value):
    pass
"#,
    )
    .expect("write FastAPI service");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: python-post-input
    language: python
    matcher:
      exact: client.submit
    out: arg0
    kind: untrusted
sinks:
  - id: fastapi-post-sink
    language: python
    matcher:
      exact: service.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    let calls = edges_of_kind(&graph, "HTTP_CALL");
    assert_eq!(calls.len(), 1, "{calls:#?}");
    assert_eq!(calls[0]["to"], "http:route:POST:/api/profile");
    assert_eq!(calls[0]["value_mappings"][0]["to"]["function"], "service.profile");
}

/// `ctypes` is a real Python system boundary: the caller has no ordinary
/// source-level edge to the C implementation. A literal library binding and
/// uniquely defined C ABI symbol must produce one exact call-site-to-native
/// parameter mapping; the generic boundary compositor consumes this fact.
#[test]
fn python_ctypes_literal_symbol_reaches_a_unique_c_function_sink() {
    let project = Scratch(scratch("sysgraph-python-ctypes"));
    std::fs::write(
        project.0.join("client.py"),
        r#"
import ctypes

def invoke(untrusted):
    native = ctypes.CDLL("libnative.so")
    native.consume(untrusted)
"#,
    )
    .expect("write ctypes caller");
    std::fs::write(
        project.0.join("native.c"),
        r#"
void consume(char *value) {
}
"#,
    )
    .expect("write native implementation");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: python-ffi-source
    language: python
    matcher:
      exact: client.invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-ffi-sink
    language: c
    matcher:
      exact: consume
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let edges = edges_of_kind(&graph, "INTEROP_ARG");
    assert_eq!(edges.len(), 1, "{edges:#?}");
    assert_eq!(edges[0]["value_mappings"][0]["from"]["function"], "client.invoke");
    assert_eq!(edges[0]["value_mappings"][0]["to"]["function"], "consume");
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "python-ffi-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-ffi-sink");
}

/// Rust's `extern "C" { fn foo(...); }` import is a real system boundary,
/// symmetric to the Python `ctypes` case above but without an alias/library
/// handle to track — the imported symbol name IS the ABI symbol.
#[test]
fn rust_extern_c_literal_symbol_reaches_a_unique_c_function_sink() {
    let project = Scratch(scratch("sysgraph-rust-extern-c"));
    std::fs::write(
        project.0.join("client.rs"),
        r#"
extern "C" {
    fn consume(value: *const u8);
}

fn invoke(untrusted: *const u8) {
    unsafe { consume(untrusted) };
}
"#,
    )
    .expect("write extern \"C\" caller");
    std::fs::write(
        project.0.join("native.c"),
        r#"
void consume(char *value) {
}
"#,
    )
    .expect("write native implementation");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: rust-ffi-source
    language: rust
    matcher:
      exact: client.invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-ffi-sink
    language: c
    matcher:
      exact: consume
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let edges = edges_of_kind(&graph, "INTEROP_ARG");
    assert_eq!(edges.len(), 1, "{edges:#?}");
    assert_eq!(edges[0]["value_mappings"][0]["from"]["function"], "client.invoke");
    assert_eq!(edges[0]["value_mappings"][0]["to"]["function"], "consume");
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "rust-ffi-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-ffi-sink");
}

/// A `#[no_mangle]` Rust function is the reverse boundary: native code (C
/// here) is the caller, Rust is the callee — the role JNI's own bridge
/// plays for a `native` Java method's *implementation* side.
#[test]
fn c_caller_reaches_a_unique_no_mangle_rust_export() {
    let project = Scratch(scratch("sysgraph-rust-export"));
    std::fs::write(
        project.0.join("native.rs"),
        r#"
#[no_mangle]
pub extern "C" fn consume(value: *const u8) {
    let _ = value;
}
"#,
    )
    .expect("write no_mangle export");
    std::fs::write(
        project.0.join("client.c"),
        r#"
void consume(char *value);

void invoke(char *untrusted) {
    consume(untrusted);
}
"#,
    )
    .expect("write native caller");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: c-source
    language: c
    matcher:
      exact: invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: rust-export-sink
    language: rust
    matcher:
      exact: native.consume
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let edges = edges_of_kind(&graph, "INTEROP_ARG");
    assert_eq!(edges.len(), 1, "{edges:#?}");
    assert_eq!(edges[0]["value_mappings"][0]["from"]["function"], "invoke");
    // The Rust side of the bridge is named by its own module-qualified
    // function name (`native.consume`), not the bare exported ABI symbol —
    // unlike the C side of the *other* direction's test above, where a
    // top-level C function's name is already unqualified.
    assert_eq!(edges[0]["value_mappings"][0]["to"]["function"], "native.consume");
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "c-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "rust-export-sink");
}

/// cgo's explicit `C.symbol(...)` syntax must cross into the corresponding
/// C definition through the same generic boundary compositor used by every
/// other FFI adapter.
#[test]
fn go_cgo_call_reaches_a_unique_c_function_sink() {
    let project = Scratch(scratch("sysgraph-go-cgo"));
    std::fs::write(
        project.0.join("main.go"),
        r#"
package main

/*
void consume(char *value);
*/
import "C"

func invoke(untrusted string) {
	C.consume(untrusted)
}
"#,
    )
    .expect("write cgo caller");
    std::fs::write(project.0.join("native.c"), "void consume(char *value) {}\n")
        .expect("write native implementation");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: go-cgo-source
    language: go
    matcher:
      exact: main.invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-cgo-sink
    language: c
    matcher:
      exact: consume
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "go-cgo-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-cgo-sink");
}

/// A literal Node native-addon import has no source-level body for the
/// native method. Its JavaScript call-site argument must nevertheless reach
/// the uniquely matched C implementation through an exact FFI mapping.
#[test]
fn javascript_native_addon_call_reaches_a_unique_c_function_sink() {
    let project = Scratch(scratch("sysgraph-js-addon"));
    std::fs::write(
        project.0.join("index.js"),
        r#"
const addon = require('./build/Release/native.node');
function invoke(untrusted) {
  addon.consume(untrusted);
}
"#,
    )
    .expect("write addon caller");
    std::fs::write(project.0.join("native.c"), "void consume(char *value) {}\n")
        .expect("write native implementation");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: js-addon-source
    language: javascript
    matcher:
      exact: index.invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-addon-sink
    language: c
    matcher:
      exact: consume
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "js-addon-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-addon-sink");
}

/// N-API commonly exposes a public JS method name that differs from its C
/// callback's implementation name. The literal registration call, rather
/// than a naming convention, must carry the cross-language value flow.
#[test]
fn javascript_napi_registration_reaches_the_registered_differently_named_c_callback() {
    let project = Scratch(scratch("sysgraph-js-napi-registration"));
    std::fs::write(
        project.0.join("index.js"),
        r#"
const addon = require('./build/Release/native.node');
function invoke(untrusted) {
  addon.consume(untrusted);
}
"#,
    )
    .expect("write addon caller");
    std::fs::write(
        project.0.join("native.c"),
        r#"
void consume_impl(char *value) {}
void init(void) {
  napi_create_function(env, "consume", 7, consume_impl, 0, result);
}
"#,
    )
    .expect("write N-API registration");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: js-napi-source
    language: javascript
    matcher:
      exact: index.invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-napi-sink
    language: c
    matcher:
      exact: consume_impl
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "js-napi-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-napi-sink");
}

/// P/Invoke is declaration-level FFI: ordinary code first reaches the C#
/// extern declaration, then the declaration's parameter maps to the native
/// ABI parameter. The whole chain must be reported as one system finding.
#[test]
fn csharp_pinvoke_call_reaches_a_unique_c_function_sink() {
    let project = Scratch(scratch("sysgraph-csharp-pinvoke"));
    std::fs::write(
        project.0.join("Native.cs"),
        r#"
class Native {
    [DllImport("native.dll")]
    private static extern void Consume(string value);

    public static void Invoke(string untrusted) {
        Consume(untrusted);
    }
}
"#,
    )
    .expect("write pinvoke caller");
    std::fs::write(project.0.join("native.c"), "void Consume(char *value) {}\n")
        .expect("write native implementation");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: pinvoke-source
    language: csharp
    matcher:
      exact: Native.Invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: pinvoke-native-sink
    language: c
    matcher:
      exact: Consume
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "pinvoke-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "pinvoke-native-sink");
}

/// actix-web/Rocket's shared `#[get("/path")]` attribute-macro convention
/// registers its own function as an HTTP route handler, the same
/// self-registering shape Spring's `@GetMapping`/Flask's `@app.get`
/// decorators already produce.
#[test]
fn rust_actix_attribute_macro_registers_an_http_route_handler() {
    let project = Scratch(scratch("sysgraph-rust-actix-route"));
    std::fs::write(
        project.0.join("service.rs"),
        r#"
#[get("/profile")]
async fn handler(id: String) {
    sink(id);
}
fn sink(s: String) {}
"#,
    )
    .expect("write actix handler");
    let system_graph_path = project.0.join("system-graph.json");
    run_mix(&project.0, "sources: []\nsinks: []\n", &system_graph_path);
    let graph = read_system_graph(&system_graph_path);
    let handles = edges_of_kind(&graph, "HANDLES");
    assert_eq!(handles.len(), 1, "{handles:#?}");
    assert_eq!(handles[0]["from"], "http:route:GET:/profile");
    assert_eq!(handles[0]["to"], "code:rust:service.handler");
}

/// Ruby's `ffi` gem `attach_function` is a *declaration-site* boundary, not
/// a call-site one: a real caller elsewhere in the program just calls
/// `Native.consume(x)` (never naming the C symbol at all), so the bridge is
/// a function-level mapping from `Native.consume`'s own parameters straight
/// to the native function's, matching how a Java `native` method's own
/// declaration (not each of its call sites) is the JNI boundary point.
#[test]
fn ruby_attach_function_bridges_a_declared_native_symbol() {
    let project = Scratch(scratch("sysgraph-ruby-attach-function"));
    std::fs::write(
        project.0.join("native.rb"),
        r#"
class Native
  extend FFI::Library
  ffi_lib 'libnative'
  attach_function :consume, :consume_impl, [:string], :void
end

def invoke(untrusted)
  Native.consume(untrusted)
end
"#,
    )
    .expect("write ffi gem caller");
    std::fs::write(
        project.0.join("native.c"),
        r#"
void consume_impl(char *value) {
}
"#,
    )
    .expect("write native implementation");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: ruby-ffi-source
    language: ruby
    matcher:
      exact: native.invoke
    out: arg0
    kind: untrusted
function_sinks:
  - id: c-ffi-sink
    language: c
    matcher:
      exact: consume_impl
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    let graph = read_system_graph(&system_graph_path);
    let edges = edges_of_kind(&graph, "INTEROP_ARG");
    assert_eq!(edges.len(), 1, "{edges:#?}");
    assert_eq!(edges[0]["value_mappings"][0]["from"]["function"], "native.Native.consume");
    assert_eq!(edges[0]["value_mappings"][0]["to"]["function"], "consume_impl");
    let composed = cross_component_findings(&graph);
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "INTEROP_ARG");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "ruby-ffi-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "c-ffi-sink");
}

/// Spring MVC's own annotation convention (`@PostMapping`) and its own
/// `RestTemplate` outbound client (`postForObject`) — not the generic
/// verb-shaped fallback used elsewhere in this file — recover the same
/// one continuous cross-service path end to end.
#[test]
fn spring_mvc_annotation_route_and_resttemplate_call_produce_one_continuous_path() {
    let project = Scratch(scratch("sysgraph-spring-resttemplate"));
    std::fs::write(
        project.0.join("ServiceA.java"),
        r#"
class ServiceA {
    static void run(String userInput, RestTemplate rt, Object body, Class responseType) {
        rt.postForObject("http://user:8080/profile?id=" + userInput, body, responseType);
    }
}
"#,
    )
    .expect("write service a");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    @PostMapping("/profile")
    static void handler(String id) {
        sink(id);
    }
    static void sink(String s) {}
}
"#,
    )
    .expect("write service b");
    let system_graph_path = project.0.join("system-graph.json");

    let findings = run_mix(&project.0, &rules_with_caller_source_and_sink("ServiceB.sink"), &system_graph_path);
    assert!(
        findings.iter().all(|finding| {
            let source = finding["source_rule_id"].as_str().unwrap_or_default();
            let sink = finding["sink_rule_id"].as_str().unwrap_or_default();
            !source.starts_with("boundary-input::") && !sink.starts_with("boundary-output::")
        }),
        "boundary-tagged findings leaked into the plain findings list: {findings:#?}"
    );

    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    assert_eq!(composed[0]["confidence"], "exact"); // a literal host, not env-resolved
    assert_eq!(composed[0]["producer_component"], "java");
    assert_eq!(composed[0]["consumer_component"], "java");

    let http_calls = edges_of_kind(&graph, "HTTP_CALL");
    assert_eq!(http_calls.len(), 1, "{http_calls:#?}");
    let mappings = http_calls[0]["value_mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 1, "{mappings:#?}");
    assert_eq!(mappings[0]["from"]["function"], "ServiceA.run");
    assert_eq!(mappings[0]["to"]["function"], "ServiceB.handler");
    assert_eq!(mappings[0]["to"]["port"], "arg0");
}

/// A JSON-style literal JavaScript object supplied directly as a POST body
/// has a recoverable key/value contract. Only its dynamic `id` field, not a
/// sibling constant field, may cross into the Java handler's `id` parameter.
#[test]
fn javascript_post_body_field_reaches_the_matching_java_handler_sink() {
    let project = Scratch(scratch("sysgraph-js-post-body"));
    std::fs::write(
        project.0.join("client.js"),
        r#"
function run(userInput) {
  Http.post("http://user/profile", { id: userInput, fixed: "constant" });
}
"#,
    )
    .expect("write javascript client");
    std::fs::write(
        project.0.join("ServiceB.java"),
        r#"
class ServiceB {
    @PostMapping("/profile")
    static void handler(String id) { sink(id); }
    static void sink(String value) {}
}
"#,
    )
    .expect("write java handler");
    let system_graph_path = project.0.join("system-graph.json");
    let findings = run_mix(
        &project.0,
        r#"
function_sources:
  - id: js-body-source
    language: javascript
    matcher:
      exact: client.run
    out: arg0
    kind: untrusted
sinks:
  - id: java-body-sink
    language: java
    matcher:
      exact: ServiceB.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert!(findings.is_empty(), "boundary plumbing must compose rather than leak: {findings:#?}");
    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "HTTP_CALL");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "js-body-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "java-body-sink");
}

/// A value stored through a parameterized JDBC `PreparedStatement` (already
/// safe from SQL injection at that call site) still becomes a real
/// cross-function finding when a later, unrelated read of the same table
/// and column hands it to an unsafe sink — the "harmless in one file,
/// dangerous across the program's lifetime" case.
#[test]
fn a_parameterized_jdbc_write_still_stitches_to_a_later_unsafe_read() {
    let project = Scratch(scratch("sysgraph-jdbc-prepared"));
    std::fs::write(
        project.0.join("Store.java"),
        r#"
class Store {
    static void store(Connection conn, String untrusted) {
        PreparedStatement stmt = conn.prepareStatement("INSERT INTO profiles(value) VALUES (?)");
        stmt.setString(1, untrusted);
        stmt.executeUpdate();
    }
}
"#,
    )
    .expect("write store");
    std::fs::write(
        project.0.join("Loader.java"),
        r#"
class Loader {
    static void load() {
        String value = Db.query("SELECT value FROM profiles");
        sink(value);
    }
    static void sink(String s) {}
}
"#,
    )
    .expect("write loader");
    let system_graph_path = project.0.join("system-graph.json");

    let rules = r#"
function_sources:
  - id: stored-source
    language: java
    matcher:
      exact: Store.store
    out: arg1
    kind: untrusted

sinks:
  - id: real-sink
    language: java
    matcher:
      exact: Loader.sink
    inputs: [arg0]
    kind: untrusted
"#;
    let findings = run_mix(&project.0, rules, &system_graph_path);
    assert!(
        findings.iter().all(|finding| {
            let source = finding["source_rule_id"].as_str().unwrap_or_default();
            let sink = finding["sink_rule_id"].as_str().unwrap_or_default();
            !source.starts_with("boundary-input::") && !sink.starts_with("boundary-output::")
        }),
        "boundary-tagged findings leaked into the plain findings list: {findings:#?}"
    );

    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "DATA_FLOW");
    assert_eq!(composed[0]["producer"]["source_rule_id"], "stored-source");
    assert_eq!(composed[0]["consumer"]["sink_rule_id"], "real-sink");

    let flows = edges_of_kind(&graph, "DATA_FLOW");
    assert_eq!(flows.len(), 1, "{flows:#?}");
    let mappings = flows[0]["value_mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 1, "{mappings:#?}");
    assert_eq!(mappings[0]["from"]["function"], "Store.store");
    assert_eq!(mappings[0]["from"]["port"], "arg1");
    assert_eq!(mappings[0]["to"]["function"], "Loader.load");
    assert_eq!(mappings[0]["to"]["port"], "return");
}

/// A `.proto` service contract, a Go gRPC client, and a Java gRPC server
/// implementation, scanned together: the Go call site's request argument
/// must reach the Java handler's request parameter through the discovered
/// `RPC_CALL` boundary — the same end-to-end, real-CLI-scan proof the other
/// framework/protocol boundaries in this file already have, extended to
/// gRPC's cross-language, contract-first service shape.
#[test]
fn grpc_go_client_call_reaches_the_java_server_implementation_across_a_proto_contract() {
    let project = Scratch(scratch("sysgraph-grpc"));
    std::fs::write(
        project.0.join("order.proto"),
        r#"
syntax = "proto3";
package demo;

service OrderService {
  rpc PlaceOrder (PlaceOrderRequest) returns (PlaceOrderResponse);
}

message PlaceOrderRequest { string item = 1; }
message PlaceOrderResponse { string id = 1; }
"#,
    )
    .expect("write proto");
    std::fs::write(
        project.0.join("client.go"),
        r#"
package client

func run(ctx Context, stub OrderServiceClient, req PlaceOrderRequest) {
	stub.PlaceOrder(ctx, req)
}
"#,
    )
    .expect("write go client");
    std::fs::write(
        project.0.join("OrderServiceImpl.java"),
        r#"
class OrderServiceImpl {
    void placeOrder(PlaceOrderRequest req) {
        sink(req);
    }
    static void sink(Object o) {}
}
"#,
    )
    .expect("write java server");
    let system_graph_path = project.0.join("system-graph.json");

    let rules = r#"
function_sources:
  - id: grpc-client-source
    language: go
    matcher:
      exact: client.run
    out: arg2
    kind: untrusted

sinks:
  - id: grpc-server-sink
    language: java
    matcher:
      exact: OrderServiceImpl.sink
    inputs: [arg0]
    kind: untrusted
"#;
    let findings = run_mix(&project.0, rules, &system_graph_path);
    assert!(
        findings.iter().all(|finding| {
            let source = finding["source_rule_id"].as_str().unwrap_or_default();
            let sink = finding["sink_rule_id"].as_str().unwrap_or_default();
            !source.starts_with("boundary-input::") && !sink.starts_with("boundary-output::")
        }),
        "boundary-tagged findings leaked into the plain findings list: {findings:#?}"
    );

    let graph = read_system_graph(&system_graph_path);
    let composed = cross_component_findings(&graph);
    assert_eq!(composed.len(), 1, "{composed:#?}");
    assert_eq!(composed[0]["boundary_kind"], "RPC_CALL");
    assert_eq!(composed[0]["producer_component"], "go");
    assert_eq!(composed[0]["consumer_component"], "java");

    let calls = edges_of_kind(&graph, "RPC_CALL");
    assert_eq!(calls.len(), 1, "{calls:#?}");
    let mappings = calls[0]["value_mappings"].as_array().unwrap();
    assert_eq!(mappings.len(), 1, "{mappings:#?}");
    assert_eq!(mappings[0]["from"]["function"], "client.run");
    assert_eq!(mappings[0]["from"]["port"], "arg1");
    assert_eq!(mappings[0]["to"]["function"], "OrderServiceImpl.placeOrder");
    assert_eq!(mappings[0]["to"]["port"], "arg0");
}

/// A Go `http.Handler` (a bare `ServeHTTP` method, Go's *structural*
/// convention — no decorator/annotation the way Spring/Flask have one)
/// gets no analyzed caller in this project at all, so it must still be
/// treated as reachable from the internet by the same external-ingress
/// fallback the annotation-based routes already prove elsewhere in this
/// file — proving `is_go_servehttp_handler`'s recognition actually
/// participates in taint-source injection, not just node bookkeeping.
#[test]
fn a_go_servehttp_handler_with_no_caller_still_gets_the_external_ingress_fallback() {
    let project = Scratch(scratch("sysgraph-go-servehttp"));
    std::fs::write(
        project.0.join("handler.go"),
        r#"
package main

type Handler struct{}

func (h *Handler) ServeHTTP(w ResponseWriter, r *Request) {
	sink(r)
}

func sink(v *Request) {}
"#,
    )
    .expect("write go handler");
    let system_graph_path = project.0.join("system-graph.json");

    // Unlike the two-service HTTP round trips elsewhere in this file, there
    // is only one hop here: the external-ingress fallback source and the
    // user-defined sink both fire within the same, single scan, so this is
    // an ordinary top-level finding — not a `cross_component_findings`
    // composition (that mechanism is for stitching a *producer* finding in
    // one function to a *consumer* finding in another via a shared
    // boundary id; here the fallback source reaches the sink directly).
    let findings = run_mix(
        &project.0,
        r#"
sinks:
  - id: servehttp-sink
    language: go
    matcher:
      exact: main.sink
    inputs: [arg0]
    kind: untrusted
"#,
        &system_graph_path,
    );
    assert_eq!(findings.len(), 1, "{findings:#?}");
    assert!(
        findings[0]["source_rule_id"].as_str().unwrap().starts_with("system-boundary::http-external-ingress::"),
        "{findings:#?}"
    );
    assert_eq!(findings[0]["sink_rule_id"], "servehttp-sink");
}
