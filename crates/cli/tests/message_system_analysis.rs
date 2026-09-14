//! End-to-end checks for the message-boundary adapter.  The first fixture is
//! intentionally cross-language: a Java Kafka producer hands an untrusted
//! payload to a Python listener decorated with a literal topic.  The second
//! asserts that a hard-coded payload never becomes a synthetic source merely
//! because a producer and consumer use the same topic.

use std::{path::PathBuf, process::Command, time::{SystemTime, UNIX_EPOCH}};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock after epoch").as_nanos();
    let path = std::env::temp_dir().join(format!("uniflow-{name}-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&path).expect("create project");
    Scratch(path)
}

fn analyze(project: &Scratch, rules: &str) -> serde_json::Value {
    let rules_path = project.0.join("rules.yaml");
    let graph_path = project.0.join("system.json");
    std::fs::write(&rules_path, rules).expect("write rules");
    let output = Command::new(env!("CARGO_BIN_EXE_uniflow"))
        .args(["analyze-project", "--language", "mix", "--input"])
        .arg(&project.0)
        .arg("--rules")
        .arg(&rules_path)
        .arg("--system-graph-out")
        .arg(&graph_path)
        .output()
        .expect("run analyzer");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_str(&std::fs::read_to_string(graph_path).expect("read system graph")).expect("valid graph JSON")
}

const CROSS_LANGUAGE_RULES: &str = r#"
function_sources:
  - id: producer-input
    language: java
    matcher:
      exact: Producer.send
    out: arg0
    kind: untrusted
sinks:
  - id: python-real-sink
    language: python
    matcher:
      exact: consumer.sink
    inputs: [arg0]
    kind: untrusted
"#;

const COMPOSE: &str = r#"
services:
  producer:
    environment:
      ORDER_TOPIC: orders
"#;

#[test]
fn java_kafka_producer_reaches_python_decorated_listener_sink() {
    let project = scratch("system-message-cross-language");
    let source_dir = project.0.join("src");
    std::fs::create_dir(&source_dir).expect("create source directory");
    std::fs::write(project.0.join("docker-compose.yml"), COMPOSE).expect("write deployment config");
    std::fs::write(
        source_dir.join("Producer.java"),
        r#"class Producer { static void send(String input) { String topic = System.getenv("ORDER_TOPIC"); KafkaTemplate.send(topic, input); } }"#,
    )
    .expect("write producer");
    std::fs::write(
        source_dir.join("consumer.py"),
        r#"
@kafka_listener("orders")
def consume(payload):
    sink(payload)

def sink(value):
    pass
"#,
    )
    .expect("write consumer");

    let graph = analyze(&project, CROSS_LANGUAGE_RULES);
    let findings = graph["cross_component_findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "{graph:#?}");
    assert_eq!(findings[0]["boundary_kind"], "PUBLISHES");
    assert_eq!(findings[0]["confidence"], "inferred");
    assert_eq!(findings[0]["producer_component"], "java");
    assert_eq!(findings[0]["consumer_component"], "python");
    assert_eq!(findings[0]["producer"]["source_rule_id"], "producer-input");
    assert_eq!(findings[0]["consumer"]["sink_rule_id"], "python-real-sink");

    let publication = graph["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .find(|edge| edge["kind"] == "PUBLISHES")
        .expect("publication edge");
    assert_eq!(publication["to"], "message:topic:orders");
    assert_eq!(publication["value_mappings"][0]["from"]["function"], "Producer.send");
    assert_eq!(publication["value_mappings"][0]["to"]["function"], "consumer.consume");
}

#[test]
fn constant_message_payload_does_not_create_a_cross_component_finding() {
    let project = scratch("system-message-constant");
    let source_dir = project.0.join("src");
    std::fs::create_dir(&source_dir).expect("create source directory");
    std::fs::write(
        source_dir.join("Producer.java"),
        r#"class Producer { static void send() { KafkaTemplate.send("orders", "constant"); } }"#,
    )
    .expect("write producer");
    std::fs::write(
        source_dir.join("consumer.py"),
        r#"
@kafka_listener("orders")
def consume(payload):
    sink(payload)

def sink(value):
    pass
"#,
    )
    .expect("write consumer");

    let graph = analyze(&project, CROSS_LANGUAGE_RULES);
    assert!(graph["cross_component_findings"].as_array().expect("findings array").is_empty(), "{graph:#?}");
    let publication = graph["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .find(|edge| edge["kind"] == "PUBLISHES")
        .expect("publication edge");
    assert!(publication["value_mappings"].as_array().expect("mappings").is_empty(), "{publication:#?}");
}
