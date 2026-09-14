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

use crate::graph::{BoundaryFlowEdge, EdgeKind, SystemGraph};

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

/// External-ingress fallback: a route handler that is *never* the target
/// of any recovered `HTTP_CALL` (i.e. nothing in the analyzed code calls
/// it — it is presumably reached directly from the internet) still needs
/// *some* taint source to be analyzable at all, so every one of its
/// parameters is tainted, exactly as before.
///
/// A handler that *is* reached by at least one recovered internal caller
/// never gets this treatment, even for parameters no [`BoundaryFlowEdge`]
/// covers (an unresolved field is left with no source at all, rather than
/// blanket-tainted) — per this crate's design brief: internal
/// service-to-service propagation must only carry the values actually
/// mapped across the boundary.
pub fn handler_source_rules(graph: &SystemGraph, language: &Language) -> RuleSet {
    let mut rules = RuleSet::default();
    let internally_called_routes: HashSet<&str> =
        graph.edges().filter(|(_, _, edge)| edge.kind == EdgeKind::HttpCall).map(|(_, to, _)| to.id.as_str()).collect();

    let mut seen = HashSet::new();
    for (route, handler, edge) in graph.edges() {
        if edge.kind != EdgeKind::Handles {
            continue;
        }
        if internally_called_routes.contains(route.id.as_str()) {
            continue;
        }
        let Some(code_ref) = &handler.code_ref else { continue };
        if &code_ref.language != language || !seen.insert(handler.id.clone()) {
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
}
