//! Message-boundary adapter for Kafka/RabbitMQ/AMQP, Redis Streams, and
//! NATS-shaped APIs.
//!
//! This adapter intentionally accepts only evidence it can prove from IR:
//! a literal topic (or literal exchange/routing-key pair), a known message
//! client call, and a payload that is one formal parameter of the producer.
//! On the consumer side it accepts either an explicit registration with a
//! callable handler (`consumer.subscribe("orders", Handler::handle)`) or a
//! Python listener decorator carrying a literal topic.  Dynamic topics,
//! decoded payload fields, `poll` loops, and wildcard subscriptions remain
//! unconnected rather than being guessed.

use anyhow::Result;
use uniflow_ir::{Callee, Function, InstKind, Program, ValueId};
use uniflow_rules::Port;

use crate::graph::{
    BoundaryFlowEdge, BoundarySummary, CodeRef, Confidence, EdgeKind, Evidence, FlowNodeRef,
    NodeKind, SystemGraph, SystemNode, ValueMappingKind,
};
use crate::config::{getenv_name_for_result, resolve_env_literal};
use crate::ir_utils::{is_python_root_alias, parameter_index, resolve_callable_argument, resolve_string_sequence, FunctionIndex, StringPiece};

const PUBLISH_METHODS: &[&str] = &[
    "send",
    "publish",
    "produce",
    "convertandsend",
    "basicpublish",
    // Redis Streams: XADD <stream> <field/value map>.  This is deliberately
    // separate from a generic `add`, which is too ambiguous to treat as a
    // broker publication.
    "xadd",
];
const SUBSCRIBE_METHODS: &[&str] = &["subscribe", "registerconsumer", "registerhandler", "onmessage", "listen"];
const PYTHON_LISTENER_DECORATORS: &[&str] = &[
    "kafka_listener", "kafkalistener", "rabbit_listener", "rabbitlistener", "message_listener", "messagelistener",
];
const PYTHON_CELERY_TASK_DECORATORS: &[&str] = &["task", "shared_task"];

#[derive(Clone, Debug)]
pub struct MessageConsumer {
    topic: String,
    function: String,
    confidence: Confidence,
    evidence: Evidence,
}

fn method_name(callee: &str) -> String {
    callee.rsplit('.').next().unwrap_or(callee).to_ascii_lowercase()
}

fn looks_like_message_client(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    [
        "kafka", "rabbit", "amqp", "redis", "nats", "jetstream", "message", "producer",
        "consumer", "topic", "queue",
    ]
        .iter()
        .any(|marker| lower.contains(marker))
}

fn direct_literal(function: &Function, value: ValueId) -> Option<String> {
    match resolve_string_sequence(function, value).as_slice() {
        [StringPiece::Literal(text)] if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn topic_node_id(topic: &str) -> String {
    format!("message:topic:{topic}")
}

fn function_node_id(language: &uniflow_hir::Language, function: &str) -> String {
    format!("code:{}:{function}", language.as_str())
}

fn ensure_topic(graph: &mut SystemGraph, topic: &str) -> String {
    let id = topic_node_id(topic);
    graph.upsert_node(SystemNode::new(NodeKind::MessageTopic, id.clone(), topic));
    id
}

fn ensure_handler(graph: &mut SystemGraph, language: &uniflow_hir::Language, function: &str) -> String {
    let id = function_node_id(language, function);
    graph.upsert_node(
        SystemNode::new(NodeKind::MessageHandler, id.clone(), function).with_code_ref(CodeRef {
            language: language.clone(),
            qualified_name: function.to_string(),
        }),
    );
    id
}

fn consumer_from_registration(
    graph: &mut SystemGraph,
    program: &Program,
    enclosing: &Function,
    name: &str,
    args: &[ValueId],
) -> Result<Option<MessageConsumer>> {
    if !SUBSCRIBE_METHODS.contains(&method_name(name).as_str()) || !looks_like_message_client(name) {
        return Ok(None);
    }
    let Some(&topic_arg) = args.first() else { return Ok(None) };
    let Some(topic) = direct_literal(enclosing, topic_arg) else { return Ok(None) };
    let Some(handler) = args.iter().skip(1).find_map(|&arg| resolve_callable_argument(program, enclosing, arg)) else {
        return Ok(None);
    };
    let topic_id = ensure_topic(graph, &topic);
    let handler_id = ensure_handler(graph, &program.language, &handler);
    graph.apply_boundary(
        BoundarySummary::new(EdgeKind::Subscribes, handler_id.clone(), topic_id.clone(), Confidence::Exact).with_evidence(Evidence::new(format!(
            "{} registers {handler} as a consumer of message topic {topic:?}", enclosing.name
        ))),
    )?;
    graph.apply_boundary(
        BoundarySummary::new(EdgeKind::DeliversTo, topic_id, handler_id, Confidence::Exact).with_evidence(Evidence::new(format!(
            "message topic {topic:?} dispatches payloads to {handler}"
        ))),
    )?;
    Ok(Some(MessageConsumer {
        topic,
        function: handler,
        confidence: Confidence::Exact,
        evidence: Evidence::new("literal topic and explicit callable consumer registration"),
    }))
}

fn quoted_first_argument(decorator: &str) -> Option<String> {
    let text = decorator.trim().trim_start_matches('@').trim();
    let (_, args) = text.split_once('(')?;
    let arg = args.strip_suffix(')')?.trim();
    let first = arg.split(',').next()?.trim();
    let quote = first.chars().next()?;
    if !matches!(quote, '\'' | '"') || !first.ends_with(quote) || first.len() < 2 {
        return None;
    }
    Some(first[1..first.len() - 1].to_string())
}

fn python_decorator_topic(function: &Function) -> Option<String> {
    function.attrs.get("python.decorators.raw")?.split('\u{1f}').find_map(|decorator| {
        let name = decorator
            .trim()
            .trim_start_matches('@')
            .split_once('(')
            .map(|(name, _)| name)
            .unwrap_or(decorator)
            .rsplit('.')
            .next()?
            .to_ascii_lowercase();
        PYTHON_LISTENER_DECORATORS.contains(&name.as_str()).then(|| quoted_first_argument(decorator)).flatten()
    })
}

/// A Celery task name is a durable, cross-process routing key only when it
/// is spelled explicitly. Celery's default task-name derivation depends on
/// module import/runtime configuration, so an undecorated or unnamed task is
/// intentionally not guessed.
fn python_celery_task_topic(function: &Function) -> Option<String> {
    function.attrs.get("python.decorators.raw")?.split('\u{1f}').find_map(|decorator| {
        let trimmed = decorator.trim().trim_start_matches('@');
        let (raw_name, args) = trimmed.split_once('(')?;
        let name = raw_name.rsplit('.').next()?.to_ascii_lowercase();
        if !PYTHON_CELERY_TASK_DECORATORS.contains(&name.as_str()) {
            return None;
        }
        let args = args.strip_suffix(')')?;
        args.split(',').find_map(|argument| {
            let (key, value) = argument.split_once('=')?;
            if key.trim() != "name" {
                return None;
            }
            let value = value.trim();
            let quote = value.chars().next()?;
            (matches!(quote, '\'' | '"') && value.ends_with(quote) && value.len() >= 2)
                .then(|| value[1..value.len() - 1].to_string())
        })
    })
}

/// Discovers consumer endpoints before publications.  The caller aggregates
/// results from every language group, then invokes
/// [`discover_publications_into`] so a producer in one language may target a
/// consumer in another without merging their IR programs.
pub fn discover_consumers_into(graph: &mut SystemGraph, program: &Program) -> Result<Vec<MessageConsumer>> {
    let mut consumers = Vec::new();
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        if let Some(topic) = python_decorator_topic(function) {
            let topic_id = ensure_topic(graph, &topic);
            let handler_id = ensure_handler(graph, &program.language, &function.name);
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::Subscribes, handler_id.clone(), topic_id.clone(), Confidence::Exact).with_evidence(Evidence::new(format!(
                    "{} is decorated as a consumer of literal topic {topic:?}", function.name
                ))),
            )?;
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::DeliversTo, topic_id, handler_id, Confidence::Exact).with_evidence(Evidence::new(format!(
                    "literal Python listener decorator dispatches topic {topic:?} to {}", function.name
                ))),
            )?;
            consumers.push(MessageConsumer {
                topic,
                function: function.name.clone(),
                confidence: Confidence::Exact,
                evidence: Evidence::new("literal Python message-listener decorator"),
            });
        }
        if let Some(topic) = python_celery_task_topic(function) {
            let topic_id = ensure_topic(graph, &topic);
            let handler_id = ensure_handler(graph, &program.language, &function.name);
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::Subscribes, handler_id.clone(), topic_id.clone(), Confidence::Exact).with_evidence(Evidence::new(format!(
                    "{} is a Celery task with literal name {topic:?}", function.name
                ))),
            )?;
            graph.apply_boundary(
                BoundarySummary::new(EdgeKind::DeliversTo, topic_id, handler_id, Confidence::Exact).with_evidence(Evidence::new(format!(
                    "literal Celery task name dispatches messages to {}", function.name
                ))),
            )?;
            consumers.push(MessageConsumer {
                topic,
                function: function.name.clone(),
                confidence: Confidence::Exact,
                evidence: Evidence::new("literal Celery task decorator name"),
            });
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                if let Some(consumer) = consumer_from_registration(graph, program, function, name, &call.args)? {
                    consumers.push(consumer);
                }
            }
        }
    }
    Ok(consumers)
}

fn configured_topic(graph: &SystemGraph, function: &Function, value: ValueId) -> Option<(String, Confidence)> {
    if let Some(topic) = direct_literal(function, value) {
        return Some((topic, Confidence::Exact));
    }
    let env_name = getenv_name_for_result(function, value)?;
    resolve_env_literal(graph, &env_name).map(|topic| (topic, Confidence::Inferred))
}

fn publication_topic_and_payload(
    graph: &SystemGraph,
    function: &Function,
    name: &str,
    args: &[ValueId],
) -> Option<(String, ValueId, Confidence)> {
    let method = method_name(name);
    if method == "send_task" {
        let (topic, confidence) = configured_topic(graph, function, *args.first()?)?;
        // Celery's `send_task(name, args=[...])` uses the list/tuple as its
        // payload.  The lowerer represents a one-element container as a
        // single-input Phi/composition; `single_container_parameter` below
        // unwraps only that exact shape.
        let payload = *args.get(1)?;
        return Some((topic, payload, confidence));
    }
    if !PUBLISH_METHODS.contains(&method.as_str()) || !looks_like_message_client(name) {
        return None;
    }
    let payload = *args.last()?;
    if matches!(method.as_str(), "convertandsend" | "basicpublish") {
        let exchange = direct_literal(function, *args.first()?)?;
        let routing_key = direct_literal(function, *args.get(1)?)?;
        return Some((format!("{exchange}/{routing_key}"), payload, Confidence::Exact));
    }
    let (topic, confidence) = configured_topic(graph, function, *args.first()?)?;
    Some((topic, payload, confidence))
}

/// Celery's bound task object APIs (`tasks.charge.delay(payload)` and
/// `tasks.charge.apply_async(...)`) do not carry the durable task name at
/// the call site.  They are still recoverable when the consumer was declared
/// with an *explicit* `@task(name="...")`: match only the lexical task
/// object's final segment against the declared Python function's final
/// segment, and only if all matching declarations agree on one topic.  This
/// deliberately does not infer Celery's default module-qualified name or
/// follow aliases/imports — both require runtime configuration/import
/// semantics that this IR cannot prove.
fn bound_celery_publication(
    program: &Program,
    callee: &str,
    args: &[ValueId],
    consumers: &[MessageConsumer],
) -> Option<(String, ValueId, Confidence)> {
    if program.language != uniflow_hir::Language::Python {
        return None;
    }
    let (owner, method) = callee.rsplit_once('.')?;
    if !matches!(method_name(method).as_str(), "delay" | "apply_async") {
        return None;
    }
    let task_function = owner.rsplit('.').next()?;
    if task_function.is_empty() {
        return None;
    }
    let mut topics = consumers
        .iter()
        .filter(|consumer| consumer.function.rsplit('.').next() == Some(task_function))
        .map(|consumer| consumer.topic.clone())
        .collect::<Vec<_>>();
    topics.sort();
    topics.dedup();
    let [topic] = topics.as_slice() else { return None };
    // `delay` passes positional task arguments directly. For `apply_async`,
    // accept only its first positional `args` argument, which subsequently
    // goes through `single_container_parameter` and therefore cannot collapse
    // multiple task arguments into one taint path.
    let payload = *args.first()?;
    let confidence = consumers
        .iter()
        .filter(|consumer| consumer.topic == *topic && consumer.function.rsplit('.').next() == Some(task_function))
        .map(|consumer| consumer.confidence)
        .min()
        .unwrap_or(Confidence::Inferred);
    Some((topic.clone(), payload, confidence))
}

/// Returns a formal parameter only when `value` is exactly that parameter,
/// possibly wrapped in copies, one-input Phis, or the lowerer's transparent
/// composition call. This recognizes Celery's `[input]`/`(input,)` payload
/// form but refuses multi-element containers, maps, or control-flow joins.
fn single_container_parameter(function: &Function, value: ValueId) -> Option<usize> {
    let mut defs = std::collections::HashMap::new();
    for block in &function.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::Copy { dst, .. } | InstKind::Phi { dst, .. } => {
                    defs.insert(*dst, &inst.kind);
                }
                InstKind::Call(call) if call.dst.is_some() => {
                    defs.insert(call.dst.expect("checked"), &inst.kind);
                }
                _ => {}
            }
        }
    }
    fn resolve(
        function: &Function,
        defs: &std::collections::HashMap<ValueId, &InstKind>,
        value: ValueId,
        visited: &mut std::collections::HashSet<ValueId>,
    ) -> Option<usize> {
        if !visited.insert(value) {
            return None;
        }
        if let Some(index) = parameter_index(function, value) {
            return Some(index);
        }
        match defs.get(&value) {
            Some(InstKind::Copy { src, .. }) => resolve(function, defs, *src, visited),
            Some(InstKind::Phi { inputs, .. }) if inputs.len() == 1 => resolve(function, defs, inputs[0], visited),
            Some(InstKind::Call(call))
                if matches!(
                    &call.callee,
                    Callee::Static(name)
                        if matches!(name.as_str(), "__uniflow.compose.string" | "builtins.list" | "builtins.tuple")
                            && call.args.len() == 1
                ) => resolve(function, defs, call.args[0], visited),
            _ => None,
        }
    }
    resolve(function, &defs, value, &mut std::collections::HashSet::new())
}

/// Emits one precise producer-payload -> consumer-payload mapping for every
/// consumer of the same literal topic.  Ambiguity is represented explicitly:
/// multiple handlers receive a mapping each at `Conservative` confidence;
/// no arbitrary winner is selected.
pub fn discover_publications_into(
    graph: &mut SystemGraph,
    program: &Program,
    consumers: &[MessageConsumer],
    function_index: &FunctionIndex<'_>,
) -> Result<()> {
    for function in &program.functions {
        if is_python_root_alias(program, function) {
            continue;
        }
        for block in &function.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else { continue };
                let Callee::Static(name) = &call.callee else { continue };
                let Some((topic, payload, topic_confidence)) = publication_topic_and_payload(graph, function, name, &call.args)
                    .or_else(|| bound_celery_publication(program, name, &call.args, consumers))
                else {
                    continue;
                };
                let topic_id = ensure_topic(graph, &topic);
                let call_site_id = format!("code:{}:{}#{}", program.language.as_str(), function.name, inst.id.0);
                graph.upsert_node(SystemNode::new(NodeKind::CallSite, call_site_id.clone(), name).with_code_ref(CodeRef {
                    language: program.language.clone(),
                    qualified_name: function.name.clone(),
                }));

                let matches: Vec<_> = consumers.iter().filter(|consumer| consumer.topic == topic).collect();
                let ambiguous = matches.len() > 1;
                let mut summary = BoundarySummary::new(
                    EdgeKind::Publishes,
                    call_site_id,
                    topic_id,
                    if matches.is_empty() { Confidence::Conservative } else { topic_confidence },
                )
                .with_evidence(Evidence::new(format!(
                    "{} publishes to {} message topic {topic:?} via {name}",
                    function.name,
                    if topic_confidence == Confidence::Exact { "literal" } else { "environment-resolved" },
                )));

                let Some(producer_parameter) = parameter_index(function, payload).or_else(|| single_container_parameter(function, payload)) else {
                    graph.apply_boundary(summary)?;
                    continue;
                };
                for consumer in matches {
                    let Some((consumer_language, consumer_function)) = function_index.get(&consumer.function) else { continue };
                    if consumer_function.params.is_empty() {
                        continue;
                    }
                    let confidence = if ambiguous { Confidence::Conservative } else { topic_confidence.min(consumer.confidence) };
                    summary = summary.with_value_mapping(
                        BoundaryFlowEdge::new(
                            ValueMappingKind::ArgumentToParameter,
                            FlowNodeRef::function_port(program.language.clone(), function.name.clone(), Port::Arg(producer_parameter)),
                            FlowNodeRef::function_port(consumer_language.clone(), consumer.function.clone(), Port::Arg(0)),
                            confidence,
                        )
                        .with_evidence(Evidence::new(format!(
                            "literal topic {topic:?} maps producer payload to consumer {} payload parameter", consumer.function
                        )))
                        .with_evidence(consumer.evidence.clone()),
                    );
                }
                graph.apply_boundary(summary)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    fn lower_java(source: &str) -> Program {
        let hir = uniflow_lang_java::JavaParser::default().parse_file("Probe.java", source).expect("parse java");
        uniflow_lowering::lower_program(&hir)
    }

    fn lower_python(source: &str) -> Program {
        let hir = uniflow_lang_python::PythonParser::default().parse_file("tasks.py", source).expect("parse python");
        uniflow_lowering::lower_program(&hir)
    }

    #[test]
    fn maps_a_literal_kafka_payload_to_an_explicit_consumer_precisely() {
        let consumer_program = lower_java(
            r#"
class Consumer { static void register() { KafkaConsumer.subscribe("orders", Consumer::handle); } static void handle(String payload) {} }
"#,
        );
        let producer_program = lower_java(
            r#"
class Producer { static void send(String input) { KafkaTemplate.send("orders", input); } }
"#,
        );
        let programs = vec![
            (uniflow_hir::Language::Java, consumer_program),
            (uniflow_hir::Language::Java, producer_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &programs[0].1).expect("discover consumer");
        discover_publications_into(&mut graph, &producer_program, &consumers, &index).expect("discover publication");

        let published: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Publishes).collect();
        assert_eq!(published.len(), 1, "{published:?}");
        let mappings = &published[0].2.value_mappings;
        assert_eq!(mappings.len(), 1, "{mappings:?}");
        assert_eq!(mappings[0].from.function, "Producer.send");
        assert_eq!(mappings[0].from.port, Port::Arg(0));
        assert_eq!(mappings[0].to.function, "Consumer.handle");
        assert_eq!(mappings[0].to.port, Port::Arg(0));
    }

    #[test]
    fn maps_a_literal_rabbit_exchange_and_routing_key() {
        let consumer_program = lower_java(
            r#"
class Consumer { static void register() { RabbitConsumer.subscribe("events/created", Consumer::handle); } static void handle(String payload) {} }
"#,
        );
        let producer_program = lower_java(
            r#"
class Producer { static void send(String input) { RabbitTemplate.convertAndSend("events", "created", input); } }
"#,
        );
        let programs = vec![
            (uniflow_hir::Language::Java, consumer_program),
            (uniflow_hir::Language::Java, producer_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &programs[0].1).expect("discover consumer");
        discover_publications_into(&mut graph, &producer_program, &consumers, &index).expect("discover publication");

        let published: Vec<_> = graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Publishes).collect();
        assert_eq!(published.len(), 1, "{published:?}");
        assert_eq!(published[0].1.id, "message:topic:events/created");
        assert_eq!(published[0].2.value_mappings.len(), 1, "{:?}", published[0].2.value_mappings);
    }

    #[test]
    fn resolves_a_kafka_topic_through_deployment_configuration() {
        let consumer_program = lower_java(
            r#"class Consumer { static void register() { KafkaConsumer.subscribe("orders", Consumer::handle); } static void handle(String payload) {} }"#,
        );
        let producer_program = lower_java(
            r#"class Producer { static void send(String input) { String topic = System.getenv("ORDER_TOPIC"); KafkaTemplate.send(topic, input); } }"#,
        );
        let programs = vec![
            (uniflow_hir::Language::Java, consumer_program),
            (uniflow_hir::Language::Java, producer_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        graph.upsert_node(
            SystemNode::new(NodeKind::EnvironmentVariable, "compose:env:producer:ORDER_TOPIC", "ORDER_TOPIC")
                .with_attr("value", "orders"),
        );
        let consumers = discover_consumers_into(&mut graph, &programs[0].1).expect("discover consumer");
        discover_publications_into(&mut graph, &producer_program, &consumers, &index).expect("discover publication");
        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert_eq!(published.2.confidence, Confidence::Inferred);
        assert_eq!(published.2.value_mappings[0].confidence, Confidence::Inferred);
    }

    #[test]
    fn maps_a_redis_stream_payload_to_an_explicit_consumer() {
        let consumer_program = lower_java(
            r#"class Worker { static void register() { RedisConsumer.subscribe("orders", Worker::handle); } static void handle(String payload) {} }"#,
        );
        let producer_program = lower_java(
            r#"class Producer { static void submit(String input) { RedisTemplate.xadd("orders", input); } }"#,
        );
        let programs = vec![
            (uniflow_hir::Language::Java, consumer_program),
            (uniflow_hir::Language::Java, producer_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &programs[0].1).expect("discover consumer");
        discover_publications_into(&mut graph, &producer_program, &consumers, &index).expect("discover publication");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert_eq!(published.1.id, "message:topic:orders");
        assert_eq!(published.2.value_mappings.len(), 1, "{:?}", published.2.value_mappings);
        assert_eq!(published.2.value_mappings[0].from.function, "Producer.submit");
        assert_eq!(published.2.value_mappings[0].to.function, "Worker.handle");
    }

    #[test]
    fn resolves_a_message_topic_through_kubernetes_env_from() {
        let consumer_program = lower_java(
            r#"class Worker { static void register() { KafkaConsumer.subscribe("orders", Worker::handle); } static void handle(String payload) {} }"#,
        );
        let producer_program = lower_java(
            r#"class Producer { static void submit(String input) { String topic = System.getenv("APP_TOPIC"); KafkaTemplate.send(topic, input); } }"#,
        );
        let programs = vec![
            (uniflow_hir::Language::Java, consumer_program),
            (uniflow_hir::Language::Java, producer_program.clone()),
        ];
        let index = FunctionIndex::build(&programs);
        let temporary = tempfile::tempdir().expect("create manifest directory");
        let manifest = temporary.path().join("producer.yaml");
        std::fs::write(
            &manifest,
            r#"
apiVersion: v1
kind: ConfigMap
metadata:
  name: messaging
data:
  TOPIC: orders
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: producer
spec:
  template:
    spec:
      containers:
        - name: app
          envFrom:
            - prefix: APP_
              configMapRef:
                name: messaging
"#,
        )
        .expect("write manifest");

        let mut graph = SystemGraph::new();
        crate::kubernetes::discover_into(&mut graph, &[manifest]).expect("discover deployment configuration");
        let consumers = discover_consumers_into(&mut graph, &programs[0].1).expect("discover consumer");
        discover_publications_into(&mut graph, &producer_program, &consumers, &index).expect("discover publication");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert_eq!(published.1.id, "message:topic:orders");
        assert_eq!(published.2.confidence, Confidence::Inferred, "deployment-resolved topic must retain its non-literal confidence");
        assert_eq!(published.2.value_mappings.len(), 1, "{:?}", published.2.value_mappings);
    }

    #[test]
    fn maps_a_literal_celery_task_and_one_argument_payload() {
        let program = lower_python(
            r#"
@shared_task(name="orders.process")
def process(payload):
    return payload

def submit(input):
    app.send_task("orders.process", [input])
"#,
        );
        let programs = vec![(uniflow_hir::Language::Python, program.clone())];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &program).expect("discover Celery task");
        discover_publications_into(&mut graph, &program, &consumers, &index).expect("discover send_task");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert_eq!(published.1.id, "message:topic:orders.process");
        assert_eq!(published.2.value_mappings.len(), 1, "{:?}", published.2.value_mappings);
        assert_eq!(published.2.value_mappings[0].from.function, "submit");
        assert_eq!(published.2.value_mappings[0].to.function, "process");
    }

    #[test]
    fn maps_a_bound_explicitly_named_celery_task_delay_call() {
        let program = lower_python(
            r#"
@shared_task(name="orders.process")
def process(payload):
    return payload

def submit(input):
    process.delay(input)
"#,
        );
        let programs = vec![(uniflow_hir::Language::Python, program.clone())];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &program).expect("discover Celery task");
        discover_publications_into(&mut graph, &program, &consumers, &index).expect("discover delay");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert_eq!(published.1.id, "message:topic:orders.process");
        assert_eq!(published.2.value_mappings.len(), 1, "{:?}", published.2.value_mappings);
        assert_eq!(published.2.value_mappings[0].from.function, "submit");
        assert_eq!(published.2.value_mappings[0].to.function, "process");
    }

    #[test]
    fn maps_a_one_argument_bound_celery_apply_async_payload_without_unwrapping_multiple_arguments() {
        let program = lower_python(
            r#"
@shared_task(name="orders.process")
def process(payload):
    return payload

def submit(input):
    process.apply_async([input])
"#,
        );
        let programs = vec![(uniflow_hir::Language::Python, program.clone())];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &program).expect("discover Celery task");
        discover_publications_into(&mut graph, &program, &consumers, &index).expect("discover apply_async");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert_eq!(published.2.value_mappings.len(), 1, "{:?}", published.2.value_mappings);
        assert_eq!(published.2.value_mappings[0].from.function, "submit");
        assert_eq!(published.2.value_mappings[0].to.function, "process");
    }

    #[test]
    fn does_not_collapse_a_multi_argument_bound_celery_apply_async_payload() {
        let program = lower_python(
            r#"
@shared_task(name="orders.process")
def process(payload):
    return payload

def submit(first, second):
    process.apply_async([first, second])
"#,
        );
        let programs = vec![(uniflow_hir::Language::Python, program.clone())];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &program).expect("discover Celery task");
        discover_publications_into(&mut graph, &program, &consumers, &index).expect("discover apply_async");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication");
        assert!(published.2.value_mappings.is_empty(), "{:?}", published.2.value_mappings);
    }

    #[test]
    fn does_not_collapse_a_multi_argument_celery_payload_to_one_handler_parameter() {
        let program = lower_python(
            r#"
@shared_task(name="orders.process")
def process(payload):
    return payload

def submit(first, second):
    app.send_task("orders.process", [first, second])
"#,
        );
        let programs = vec![(uniflow_hir::Language::Python, program.clone())];
        let index = FunctionIndex::build(&programs);
        let mut graph = SystemGraph::new();
        let consumers = discover_consumers_into(&mut graph, &program).expect("discover Celery task");
        discover_publications_into(&mut graph, &program, &consumers, &index).expect("discover send_task");

        let published = graph.edges().find(|(_, _, edge)| edge.kind == EdgeKind::Publishes).expect("publication resource fact");
        assert!(published.2.value_mappings.is_empty(), "multi-argument Celery payload has no one-to-one handler mapping");
    }
}
