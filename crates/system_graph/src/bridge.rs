//! Turns [`crate::graph::BoundaryFlowEdge`]s into synthetic per-language
//! `uniflow_rules::RuleSet` additions that make the *actual value flow*
//! cross a recovered semantic boundary, instead of merely producing two
//! independently-evidenced findings.
//!
//! ## Why the earlier synthetic-source/synthetic-sink pair was insufficient
//!
//! The first version of this bridge tagged *every* parameter of a route's
//! handler as tainted (`FunctionSourceRule` with `out: Port::ArgsFrom(0)`)
//! and treated the whole outbound call's URL argument as one sink
//! (`SinkRule` on `Arg(0)`, scoped only by a `containing_function_regex`
//! string match). That produced two findings whose *only* connection was
//! shared evidence text — not a preserved value correspondence. It would
//! (and, before this change, did) fail every negative test in
//! `crates/cli/tests/system_graph_analysis.rs`: a handler with two
//! parameters where only one is ever supplied by a real caller had *both*
//! marked tainted, and a caller with two query fields where only one was
//! dynamic had its *entire* call treated as a sink regardless of which
//! field actually carried the tainted value.
//!
//! ## The fix
//!
//! [`crate::http`] now recovers field-precise [`BoundaryFlowEdge`]s (which
//! specific caller parameter feeds which specific handler parameter, by
//! *name*, not "some value reaches somewhere"). This module turns each one
//! into exactly two rules, tagged with a shared, deterministic id derived
//! from the mapping's own [`FlowNodeRef`]s (not from any regex/string
//! match): a [`FunctionSinkRule`] on the caller's *exact* parameter, and a
//! [`FunctionSourceRule`] on the callee's *exact* parameter — nothing else
//! is touched. The one exception (see [`handler_source_rules`]) is a route
//! genuinely never called from anywhere in the analyzed code, where
//! blanket parameter tainting remains a defensible "assume this is a
//! public internet-facing endpoint" default.
//!
//! `crate::compose` then correlates a caller-side finding and a callee-side
//! finding that share the same boundary id into one continuous
//! [`crate::compose::SystemFinding`] — but that correlation is only
//! *presentation*: the reason the callee-side finding can fire in the first
//! place, sourced from *exactly* the parameter the caller maps to it and no
//! other, is this module's rule injection, not the composition step.

use std::collections::HashSet;

use uniflow_hir::Language;
use uniflow_rules::{
    CallSiteSinkRule, CallSiteSourceRule, FunctionMatcher, FunctionSinkRule, FunctionSourceRule,
    Port, RuleSet,
};

use crate::graph::{BoundaryFlowEdge, EdgeKind, NodeKind, SystemGraph};

const BOUNDARY_KIND: &str = "untrusted";

fn port_tag(port: &Port) -> String {
    match port {
        Port::Arg(index) => format!("arg{index}"),
        Port::Return => "return".to_string(),
        Port::Receiver => "receiver".to_string(),
        Port::NamedArg(name) => format!("named:{name}"),
        Port::NamedArgOrAll(name) => format!("named_or_all:{name}"),
        Port::Member(name) => format!("member:{name}"),
        Port::ArgsFrom(start) => format!("args_from{start}"),
        Port::ArgsRange { start, end } => format!("args{start}..={end}"),
    }
}

/// A deterministic id shared by exactly the two synthetic rules
/// [`boundary_output_sink_rules`] and [`boundary_input_source_rules`]
/// derive from the *same* [`BoundaryFlowEdge`] — and the same id
/// `crate::compose` looks for on both sides of a pair of real findings to
/// correlate them. Derived entirely from the mapping's own stable
/// `FlowNodeRef`s (function name + port), never from a regex/string match
/// against unrelated call sites.
pub fn boundary_id(mapping: &BoundaryFlowEdge) -> String {
    let endpoint = |node: &crate::graph::FlowNodeRef| match node.call_site {
        Some(inst) => format!("{}#{inst}:{}", node.function, port_tag(&node.port)),
        None => format!("{}:{}", node.function, port_tag(&node.port)),
    };
    format!(
        "{}->{}",
        endpoint(&mapping.from),
        endpoint(&mapping.to),
    )
}

pub const BOUNDARY_OUTPUT_PREFIX: &str = "boundary-output::";
pub const BOUNDARY_INPUT_PREFIX: &str = "boundary-input::";

/// Every concrete, value-carrying system boundary.  HTTP was the first
/// adapter, but the bridge deliberately does not know whether a mapping
/// came from HTTP, a queue, RPC, or a future FFI adapter: the mapping itself
/// is the proof that a particular value crosses a particular boundary.
fn boundary_mappings(graph: &SystemGraph) -> impl Iterator<Item = &BoundaryFlowEdge> {
    graph
        .edges()
        .filter(|(_, _, edge)| edge.kind.carries_data_flow())
        .flat_map(|(_, _, edge)| edge.value_mappings.iter())
}

/// One [`FunctionSinkRule`] per recovered [`BoundaryFlowEdge`] whose
/// *producer* side (`from`) lives in `language`, scoped to that exact
/// caller parameter — so only taint that actually reaches the value
/// mapped across the boundary is reported, not every argument of every
/// call to the same outbound-call helper.
pub fn boundary_output_sink_rules(graph: &SystemGraph, language: &Language) -> RuleSet {
    let mut rules = RuleSet::default();
    for mapping in boundary_mappings(graph) {
        if &mapping.from.language != language {
            continue;
        }
        let id = format!("{BOUNDARY_OUTPUT_PREFIX}{}", boundary_id(mapping));
        if let Some(inst_id) = mapping.from.call_site {
            rules.call_site_sinks.push(CallSiteSinkRule {
                id,
                language: Some(language.clone()),
                function: mapping.from.function.clone(),
                inst_id,
                inputs: vec![mapping.from.port.clone()],
                kind: BOUNDARY_KIND.to_string(),
            });
        } else {
            rules.function_sinks.push(FunctionSinkRule {
                id,
                language: Some(language.clone()),
                matcher: FunctionMatcher { exact: Some(mapping.from.function.clone()), ..Default::default() },
                inputs: vec![mapping.from.port.clone()],
                kind: BOUNDARY_KIND.to_string(),
            });
        }
    }
    rules
}

/// One [`FunctionSourceRule`] per recovered [`BoundaryFlowEdge`] whose
/// *consumer* side (`to`) lives in `language`, scoped to that exact handler
/// parameter — the field-precise replacement for tainting every parameter.
pub fn boundary_input_source_rules(graph: &SystemGraph, language: &Language) -> RuleSet {
    let mut rules = RuleSet::default();
    for mapping in boundary_mappings(graph) {
        if &mapping.to.language != language {
            continue;
        }
        let id = format!("{BOUNDARY_INPUT_PREFIX}{}", boundary_id(mapping));
        if let Some(inst_id) = mapping.to.call_site {
            rules.call_site_sources.push(CallSiteSourceRule {
                id,
                language: Some(language.clone()),
                function: mapping.to.function.clone(),
                inst_id,
                out: mapping.to.port.clone(),
                kind: BOUNDARY_KIND.to_string(),
            });
        } else {
            rules.function_sources.push(FunctionSourceRule {
                id,
                language: Some(language.clone()),
                matcher: FunctionMatcher { exact: Some(mapping.to.function.clone()), ..Default::default() },
                out: mapping.to.port.clone(),
                kind: BOUNDARY_KIND.to_string(),
            });
        }
    }
    rules
}

/// External-ingress fallback: an HTTP route handler that is *never* the
/// target of a recovered `HTTP_CALL` (i.e. it is presumably reached directly
/// from the internet), a gRPC method never reached by a recovered `RPC_CALL`,
/// or a message handler whose topic has no recovered internal `PUBLISHES`
/// edge (i.e. it may receive data from an unknown producer), or an explicitly
/// exported FFI entrypoint called by an external native host, still needs a
/// taint source to be analyzable at all.
///
/// A handler that *is* reached by at least one recovered internal caller
/// never gets this treatment, even for parameters no [`BoundaryFlowEdge`]
/// covers (an unresolved field is left with no source at all, rather than
/// blanket-tainted) — per this crate's design brief: internal
/// service-to-service propagation must only carry the values actually
/// mapped across the boundary. Message deliveries use only `Arg(0)`: the
/// message adapter itself models its payload as the handler's first argument,
/// while later framework metadata/acknowledgement arguments are not payload.
pub fn handler_source_rules(graph: &SystemGraph, language: &Language) -> RuleSet {
    let mut rules = RuleSet::default();
    let internally_called_routes: HashSet<&str> =
        graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).map(|(_, to, _)| to.id.as_str()).collect();
    let internally_called_rpc_methods: HashSet<&str> =
        graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::RpcCall).map(|(_, to, _)| to.id.as_str()).collect();
    let internally_published_topics: HashSet<&str> =
        graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::Publishes).map(|(_, to, _)| to.id.as_str()).collect();

    // A function can intentionally be exposed through more than one
    // transport (for example an internal HTTP compatibility endpoint and an
    // external gRPC method). Deduplicate repeated registrations *within* a
    // mechanism, but never let one mechanism suppress another mechanism's
    // distinct payload port.
    let mut seen_http = HashSet::new();
    for (route, handler, edge) in graph.edges() {
        if edge.kind != EdgeKind::Handles || route.kind != NodeKind::HttpRoute {
            continue;
        }
        if internally_called_routes.contains(route.id.as_str()) {
            continue;
        }
        let Some(code_ref) = &handler.code_ref else { continue };
        if &code_ref.language != language || !seen_http.insert(handler.id.clone()) {
            continue;
        }
        rules.function_sources.push(FunctionSourceRule {
            id: format!("system-boundary::http-external-ingress::{}", code_ref.qualified_name),
            language: Some(language.clone()),
            matcher: FunctionMatcher { exact: Some(code_ref.qualified_name.clone()), ..Default::default() },
            out: Port::ArgsFrom(0),
            kind: BOUNDARY_KIND.to_string(),
        });
    }

    let mut seen_grpc = HashSet::new();
    for (method, handler, edge) in graph.edges() {
        if edge.kind != EdgeKind::Handles
            || method.kind != NodeKind::RpcMethod
            || internally_called_rpc_methods.contains(method.id.as_str())
        {
            continue;
        }
        let Some(code_ref) = &handler.code_ref else { continue };
        if &code_ref.language != language || !seen_grpc.insert(handler.id.clone()) {
            continue;
        }
        // Go's generated unary server interface is
        // `Method(context.Context, Request)`, while the Java/C# shapes this
        // adapter recognizes place Request first. Never taint transport
        // context/metadata merely because the RPC is externally reachable.
        let request_port = if code_ref.language == Language::Go {
            Port::Arg(1)
        } else {
            Port::Arg(0)
        };
        rules.function_sources.push(FunctionSourceRule {
            id: format!("system-boundary::grpc-external-ingress::{}", code_ref.qualified_name),
            language: Some(language.clone()),
            matcher: FunctionMatcher { exact: Some(code_ref.qualified_name.clone()), ..Default::default() },
            out: request_port,
            kind: BOUNDARY_KIND.to_string(),
        });
    }

    let mut seen_messages = HashSet::new();
    for (topic, handler, edge) in graph.edges() {
        if edge.kind != EdgeKind::DeliversTo
            || internally_published_topics.contains(topic.id.as_str())
            || handler.kind != NodeKind::MessageHandler
        {
            continue;
        }
        let Some(code_ref) = &handler.code_ref else { continue };
        if &code_ref.language != language || !seen_messages.insert(handler.id.clone()) {
            continue;
        }
        rules.function_sources.push(FunctionSourceRule {
            id: format!("system-boundary::message-external-ingress::{}", code_ref.qualified_name),
            language: Some(language.clone()),
            matcher: FunctionMatcher { exact: Some(code_ref.qualified_name.clone()), ..Default::default() },
            out: Port::Arg(0),
            kind: BOUNDARY_KIND.to_string(),
        });
    }

    let mut seen_external_ffi = HashSet::new();
    for (caller, handler, edge) in graph.edges() {
        // Reverse FFI adapters mark their synthetic native-host node rather
        // than assuming every INTEROP_CALL is external: a P/Invoke call or
        // a resolved C->Rust call has a real caller-side value mapping and
        // must not become a blanket source.
        if edge.kind != EdgeKind::InteropCall
            || caller.attrs.get("ffi_external_caller").map(String::as_str) != Some("true")
        {
            continue;
        }
        let Some(code_ref) = &handler.code_ref else { continue };
        if &code_ref.language != language || !seen_external_ffi.insert(handler.id.clone()) {
            continue;
        }
        rules.function_sources.push(FunctionSourceRule {
            id: format!("system-boundary::ffi-external-ingress::{}", code_ref.qualified_name),
            language: Some(language.clone()),
            matcher: FunctionMatcher { exact: Some(code_ref.qualified_name.clone()), ..Default::default() },
            out: Port::ArgsFrom(0),
            kind: BOUNDARY_KIND.to_string(),
        });
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{Confidence, FlowNodeRef, ValueMappingKind};

    fn sample_mapping() -> BoundaryFlowEdge {
        BoundaryFlowEdge::new(
            ValueMappingKind::ArgumentToParameter,
            FlowNodeRef::function_port(Language::Java, "ServiceA.run", Port::Arg(0)),
            FlowNodeRef::function_port(Language::Java, "ServiceB.handler", Port::Arg(0)),
            Confidence::Exact,
        )
    }

    #[test]
    fn boundary_id_is_shared_by_output_and_input_rules_for_the_same_mapping() {
        let mapping = sample_mapping();
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "call", "call"));
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::HttpRoute, "route", "route"));
        graph
            .add_edge(
                "call",
                "route",
                crate::graph::SystemEdge::new(EdgeKind::HttpCall, Confidence::Exact).with_value_mapping(mapping.clone()),
            )
            .unwrap();

        let sinks = boundary_output_sink_rules(&graph, &Language::Java);
        let sources = boundary_input_source_rules(&graph, &Language::Java);
        assert_eq!(sinks.function_sinks.len(), 1);
        assert_eq!(sources.function_sources.len(), 1);
        let sink_id = sinks.function_sinks[0].id.strip_prefix(BOUNDARY_OUTPUT_PREFIX).unwrap();
        let source_id = sources.function_sources[0].id.strip_prefix(BOUNDARY_INPUT_PREFIX).unwrap();
        assert_eq!(sink_id, source_id, "both sides must derive the identical boundary id from the same mapping");

        assert_eq!(sinks.function_sinks[0].matcher.exact.as_deref(), Some("ServiceA.run"));
        assert_eq!(sinks.function_sinks[0].inputs, vec![Port::Arg(0)]);
        assert_eq!(sources.function_sources[0].matcher.exact.as_deref(), Some("ServiceB.handler"));
        assert_eq!(sources.function_sources[0].out, Port::Arg(0));
    }

    #[test]
    fn a_handler_reached_by_a_recovered_caller_gets_no_blanket_fallback_source() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::HttpRoute, "http:route:GET:/profile", "GET /profile"));
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::Function, "code:java:ServiceB.handler", "ServiceB.handler")
                .with_code_ref(crate::graph::CodeRef { language: Language::Java, qualified_name: "ServiceB.handler".to_string() }),
        );
        graph
            .add_edge(
                "http:route:GET:/profile",
                "code:java:ServiceB.handler",
                crate::graph::SystemEdge::new(EdgeKind::Handles, Confidence::Exact),
            )
            .unwrap();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "call", "call"));
        graph
            .add_edge("call", "http:route:GET:/profile", crate::graph::SystemEdge::new(EdgeKind::HttpCall, Confidence::Exact))
            .unwrap();

        let fallback = handler_source_rules(&graph, &Language::Java);
        assert!(fallback.function_sources.is_empty(), "{:?}", fallback.function_sources);
    }

    #[test]
    fn call_site_anchored_mapping_becomes_call_site_rules() {
        let mapping = BoundaryFlowEdge::new(
            ValueMappingKind::ValueToValue,
            FlowNodeRef::call_site_port(Language::Java, "Writer.store", 11, Port::Arg(0)),
            FlowNodeRef::call_site_port(Language::Python, "reader.load", 29, Port::Return),
            Confidence::Exact,
        );
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "writer", "writer"));
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "reader", "reader"));
        graph
            .add_edge("writer", "reader", crate::graph::SystemEdge::new(EdgeKind::WritesResource, Confidence::Exact).with_value_mapping(mapping))
            .unwrap();
        let output = boundary_output_sink_rules(&graph, &Language::Java);
        let input = boundary_input_source_rules(&graph, &Language::Python);
        assert!(output.function_sinks.is_empty());
        assert!(input.function_sources.is_empty());
        assert_eq!(output.call_site_sinks[0].function, "Writer.store");
        assert_eq!(output.call_site_sinks[0].inst_id, 11);
        assert_eq!(input.call_site_sources[0].function, "reader.load");
        assert_eq!(input.call_site_sources[0].inst_id, 29);
    }

    #[test]
    fn return_mapping_bridges_a_handler_return_to_one_client_result() {
        let mapping = BoundaryFlowEdge::new(
            ValueMappingKind::ReturnToResult,
            FlowNodeRef::function_port(Language::Java, "ProfileController.handler", Port::Return),
            FlowNodeRef::call_site_port(Language::Java, "Gateway.fetch", 41, Port::Return),
            Confidence::Exact,
        );
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::HttpRoute, "route", "GET /profile"));
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "call", "Http.get"));
        graph
            .add_edge(
                "call",
                "route",
                crate::graph::SystemEdge::new(EdgeKind::HttpCall, Confidence::Exact).with_value_mapping(mapping),
            )
            .unwrap();

        let output = boundary_output_sink_rules(&graph, &Language::Java);
        let input = boundary_input_source_rules(&graph, &Language::Java);
        assert_eq!(output.function_sinks.len(), 1);
        assert_eq!(output.function_sinks[0].matcher.exact.as_deref(), Some("ProfileController.handler"));
        assert_eq!(output.function_sinks[0].inputs, vec![Port::Return]);
        assert_eq!(input.call_site_sources.len(), 1);
        assert_eq!(input.call_site_sources[0].function, "Gateway.fetch");
        assert_eq!(input.call_site_sources[0].inst_id, 41);
        assert_eq!(input.call_site_sources[0].out, Port::Return);
    }

    #[test]
    fn distinct_call_sites_never_share_a_boundary_id() {
        let first = BoundaryFlowEdge::new(
            ValueMappingKind::ValueToValue,
            FlowNodeRef::call_site_port(Language::Java, "Writer.store", 11, Port::Arg(0)),
            FlowNodeRef::call_site_port(Language::Java, "Reader.load", 21, Port::Return),
            Confidence::Exact,
        );
        let second = BoundaryFlowEdge::new(
            ValueMappingKind::ValueToValue,
            FlowNodeRef::call_site_port(Language::Java, "Writer.store", 12, Port::Arg(0)),
            FlowNodeRef::call_site_port(Language::Java, "Reader.load", 22, Port::Return),
            Confidence::Exact,
        );
        assert_ne!(boundary_id(&first), boundary_id(&second));
    }

    #[test]
    fn a_handler_with_no_recovered_caller_falls_back_to_the_blanket_external_ingress_source() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::HttpRoute, "http:route:GET:/public", "GET /public"));
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::Function, "code:java:App.publicHandler", "App.publicHandler")
                .with_code_ref(crate::graph::CodeRef { language: Language::Java, qualified_name: "App.publicHandler".to_string() }),
        );
        graph
            .add_edge(
                "http:route:GET:/public",
                "code:java:App.publicHandler",
                crate::graph::SystemEdge::new(EdgeKind::Handles, Confidence::Exact),
            )
            .unwrap();

        let fallback = handler_source_rules(&graph, &Language::Java);
        assert_eq!(fallback.function_sources.len(), 1);
        assert_eq!(fallback.function_sources[0].matcher.exact.as_deref(), Some("App.publicHandler"));
        assert_eq!(fallback.function_sources[0].out, Port::ArgsFrom(0));
    }

    #[test]
    fn a_message_handler_without_an_internal_producer_gets_only_its_payload_as_external_input() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::MessageTopic, "message:topic:orders", "orders"));
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::MessageHandler, "code:java:Worker.consume", "Worker.consume")
                .with_code_ref(crate::graph::CodeRef { language: Language::Java, qualified_name: "Worker.consume".to_string() }),
        );
        graph
            .add_edge(
                "message:topic:orders",
                "code:java:Worker.consume",
                crate::graph::SystemEdge::new(EdgeKind::DeliversTo, Confidence::Exact),
            )
            .unwrap();
        let fallback = handler_source_rules(&graph, &Language::Java);
        assert_eq!(fallback.function_sources.len(), 1, "{:?}", fallback.function_sources);
        assert_eq!(fallback.function_sources[0].matcher.exact.as_deref(), Some("Worker.consume"));
        assert_eq!(fallback.function_sources[0].out, Port::Arg(0));
    }

    #[test]
    fn an_internally_published_message_topic_does_not_get_a_blanket_consumer_source() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::MessageTopic, "message:topic:orders", "orders"));
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "code:java:Producer.send#1", "send"));
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::MessageHandler, "code:java:Worker.consume", "Worker.consume")
                .with_code_ref(crate::graph::CodeRef { language: Language::Java, qualified_name: "Worker.consume".to_string() }),
        );
        graph
            .add_edge(
                "code:java:Producer.send#1",
                "message:topic:orders",
                crate::graph::SystemEdge::new(EdgeKind::Publishes, Confidence::Exact),
            )
            .unwrap();
        graph
            .add_edge(
                "message:topic:orders",
                "code:java:Worker.consume",
                crate::graph::SystemEdge::new(EdgeKind::DeliversTo, Confidence::Exact),
            )
            .unwrap();
        assert!(handler_source_rules(&graph, &Language::Java).function_sources.is_empty());
    }

    #[test]
    fn external_grpc_methods_taint_only_the_language_specific_request_parameter() {
        let mut graph = SystemGraph::new();
        for method in ["GetJava", "GetGo", "Internal"] {
            graph.upsert_node(crate::graph::SystemNode::new(
                crate::graph::NodeKind::RpcMethod,
                format!("grpc:method:Orders.{method}"),
                method,
            ));
        }
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::Entrypoint, "code:java:OrdersImpl.getJava", "OrdersImpl.getJava")
                .with_code_ref(crate::graph::CodeRef { language: Language::Java, qualified_name: "OrdersImpl.getJava".to_string() }),
        );
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::Entrypoint, "code:go:orders.Server.GetGo", "orders.Server.GetGo")
                .with_code_ref(crate::graph::CodeRef { language: Language::Go, qualified_name: "orders.Server.GetGo".to_string() }),
        );
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::Entrypoint, "code:java:OrdersImpl.internal", "OrdersImpl.internal")
                .with_code_ref(crate::graph::CodeRef { language: Language::Java, qualified_name: "OrdersImpl.internal".to_string() }),
        );
        for (method, handler) in [
            ("grpc:method:Orders.GetJava", "code:java:OrdersImpl.getJava"),
            ("grpc:method:Orders.GetGo", "code:go:orders.Server.GetGo"),
            ("grpc:method:Orders.Internal", "code:java:OrdersImpl.internal"),
        ] {
            graph
                .add_edge(method, handler, crate::graph::SystemEdge::new(EdgeKind::Handles, Confidence::Inferred))
                .unwrap();
        }
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::CallSite, "client", "client"));
        graph
            .add_edge("client", "grpc:method:Orders.Internal", crate::graph::SystemEdge::new(EdgeKind::RpcCall, Confidence::Inferred))
            .unwrap();

        let java = handler_source_rules(&graph, &Language::Java);
        assert_eq!(java.function_sources.len(), 1, "{:?}", java.function_sources);
        assert_eq!(java.function_sources[0].matcher.exact.as_deref(), Some("OrdersImpl.getJava"));
        assert_eq!(java.function_sources[0].out, Port::Arg(0));
        let go = handler_source_rules(&graph, &Language::Go);
        assert_eq!(go.function_sources.len(), 1, "{:?}", go.function_sources);
        assert_eq!(go.function_sources[0].matcher.exact.as_deref(), Some("orders.Server.GetGo"));
        assert_eq!(go.function_sources[0].out, Port::Arg(1));
    }

    #[test]
    fn distinct_external_transports_for_one_handler_keep_their_own_payload_ports() {
        let mut graph = SystemGraph::new();
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::HttpRoute, "http:route:POST:/compat", "POST /compat"));
        graph.upsert_node(crate::graph::SystemNode::new(crate::graph::NodeKind::RpcMethod, "grpc:method:Compat.Send", "Compat.Send"));
        graph.upsert_node(
            crate::graph::SystemNode::new(crate::graph::NodeKind::Entrypoint, "code:go:compat.Server.Send", "compat.Server.Send")
                .with_code_ref(crate::graph::CodeRef { language: Language::Go, qualified_name: "compat.Server.Send".to_string() }),
        );
        graph
            .add_edge("http:route:POST:/compat", "code:go:compat.Server.Send", crate::graph::SystemEdge::new(EdgeKind::Handles, Confidence::Exact))
            .unwrap();
        graph
            .add_edge("grpc:method:Compat.Send", "code:go:compat.Server.Send", crate::graph::SystemEdge::new(EdgeKind::Handles, Confidence::Inferred))
            .unwrap();

        let rules = handler_source_rules(&graph, &Language::Go);
        let mut ports = rules.function_sources.iter().map(|rule| rule.out.clone()).collect::<Vec<_>>();
        ports.sort_by_key(|port| format!("{port:?}"));
        assert_eq!(ports, vec![Port::Arg(1), Port::ArgsFrom(0)]);
    }
}
