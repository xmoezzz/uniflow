//! Composes a producer-side finding and a consumer-side finding that share
//! the same boundary id (see [`crate::bridge::boundary_id`]) into **one**
//! continuous [`SystemFinding`] — the actual deliverable of cross-boundary
//! value-flow analysis. This is presentation only: the reason the two
//! findings are safe to compose (they really do describe the same
//! parameter-to-parameter correspondence, not "two unrelated findings that
//! happen to share a route name") is that [`crate::bridge`] derived both
//! sides' synthetic rule ids from the identical [`crate::graph::BoundaryFlowEdge`]
//! in the first place — composition never has to *guess* that two findings
//! belong together.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uniflow_taint::TaintFinding;

use crate::bridge::{boundary_id, BOUNDARY_INPUT_PREFIX, BOUNDARY_OUTPUT_PREFIX};
use crate::graph::{Confidence, EdgeKind, Evidence, SystemGraph};

/// One continuous cross-component path: a producer's own local finding
/// (real source -> the exact value that crosses the boundary), the
/// boundary transition itself (kind/evidence/confidence/components), and a
/// consumer's own local finding (the exact same value, now a parameter ->
/// real sink).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemFinding {
    pub boundary_kind: EdgeKind,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub producer_component: uniflow_hir::Language,
    pub consumer_component: uniflow_hir::Language,
    /// The producer/caller side's own finding: local source -> the value
    /// that becomes the boundary output.
    pub producer: TaintFinding,
    /// The consumer/callee side's own finding: the boundary-input parameter
    /// -> local sink.
    pub consumer: TaintFinding,
}

struct BoundaryMeta {
    kind: EdgeKind,
    confidence: Confidence,
    evidence: Vec<Evidence>,
    producer_component: uniflow_hir::Language,
    consumer_component: uniflow_hir::Language,
}

fn boundary_metadata(graph: &SystemGraph) -> HashMap<String, BoundaryMeta> {
    let mut out = HashMap::new();
    for (_, _, edge) in graph.edges().filter(|(_, _, edge)| edge.kind.carries_data_flow()) {
        for mapping in &edge.value_mappings {
            out.insert(
                boundary_id(mapping),
                BoundaryMeta {
                    kind: edge.kind,
                    confidence: mapping.confidence,
                    evidence: mapping.evidence.clone(),
                    producer_component: mapping.from.language.clone(),
                    consumer_component: mapping.to.language.clone(),
                },
            );
        }
    }
    out
}

/// Removes every finding tagged with a `boundary-output::`/`boundary-input::`
/// synthetic rule id from `findings` — they are intermediate facts ("local
/// taint reaches the boundary" / "the boundary reaches a local sink"), not
/// independently meaningful vulnerabilities — and returns the
/// [`SystemFinding`]s formed by pairing up a producer finding and a
/// consumer finding that share the same boundary id. A one-sided result
/// (only one side actually fired) is still removed from `findings` but
/// produces no [`SystemFinding`]: nothing measurable crossed the boundary.
pub fn compose_cross_boundary_findings(findings: &mut Vec<TaintFinding>, graph: &SystemGraph) -> Vec<SystemFinding> {
    let metadata = boundary_metadata(graph);
    let mut producers: HashMap<String, Vec<TaintFinding>> = HashMap::new();
    let mut consumers: HashMap<String, Vec<TaintFinding>> = HashMap::new();

    findings.retain(|finding| {
        if let Some(id) = finding.sink_rule_id.strip_prefix(BOUNDARY_OUTPUT_PREFIX) {
            producers.entry(id.to_string()).or_default().push(finding.clone());
            return false;
        }
        if let Some(id) = finding.source_rule_id.strip_prefix(BOUNDARY_INPUT_PREFIX) {
            consumers.entry(id.to_string()).or_default().push(finding.clone());
            return false;
        }
        true
    });

    let mut out = Vec::new();
    for (id, producer_findings) in &producers {
        let Some(consumer_findings) = consumers.get(id) else { continue };
        let meta = metadata.get(id);
        for producer in producer_findings {
            for consumer in consumer_findings {
                out.push(SystemFinding {
                    // A missing entry can only occur for malformed
                    // externally-created synthetic findings.  Keep the
                    // historic HTTP fallback for that defensive case; real
                    // findings always have metadata from a value mapping.
                    boundary_kind: meta.map(|m| m.kind).unwrap_or(EdgeKind::HttpCall),
                    confidence: meta.map(|m| m.confidence).unwrap_or(Confidence::Conservative),
                    evidence: meta.map(|m| m.evidence.clone()).unwrap_or_default(),
                    producer_component: meta.map(|m| m.producer_component.clone()).unwrap_or(uniflow_hir::Language::Unknown),
                    consumer_component: meta.map(|m| m.consumer_component.clone()).unwrap_or(uniflow_hir::Language::Unknown),
                    producer: producer.clone(),
                    consumer: consumer.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{BoundaryFlowEdge, FlowNodeRef, NodeKind, SystemEdge, SystemNode, ValueMappingKind};
    use uniflow_rules::Port;

    fn finding(source_rule_id: &str, sink_rule_id: &str) -> TaintFinding {
        TaintFinding {
            source_rule_id: source_rule_id.to_string(),
            sink_rule_id: sink_rule_id.to_string(),
            source_kind: "untrusted".to_string(),
            sink_kind: "untrusted".to_string(),
            sink_node: 0,
            path: vec![],
            source_label: String::new(),
            sink_label: String::new(),
            source_location: String::new(),
            sink_location: String::new(),
            path_labels: vec![],
            steps: vec![],
            finding_kind: "taint".to_string(),
            severity: "warning".to_string(),
            message: String::new(),
            rule_title: String::new(),
            cwe: vec![],
            standards: vec![],
            translations: Default::default(),
            analysis_complete: true,
            completeness: Default::default(),
        }
    }

    fn graph_with_one_mapping() -> (SystemGraph, String) {
        let mapping = BoundaryFlowEdge::new(
            ValueMappingKind::ArgumentToParameter,
            FlowNodeRef::function_port(uniflow_hir::Language::Java, "ServiceA.run", Port::Arg(0)),
            FlowNodeRef::function_port(uniflow_hir::Language::Java, "ServiceB.handler", Port::Arg(0)),
            Confidence::Exact,
        );
        let id = boundary_id(&mapping);
        let mut graph = SystemGraph::new();
        graph.upsert_node(SystemNode::new(NodeKind::CallSite, "call", "call"));
        graph.upsert_node(SystemNode::new(NodeKind::HttpRoute, "route", "route"));
        graph
            .add_edge("call", "route", SystemEdge::new(EdgeKind::HttpCall, Confidence::Exact).with_value_mapping(mapping))
            .unwrap();
        (graph, id)
    }

    #[test]
    fn a_matching_producer_and_consumer_compose_into_one_system_finding() {
        let (graph, id) = graph_with_one_mapping();
        let mut findings = vec![
            finding("real-source", &format!("{BOUNDARY_OUTPUT_PREFIX}{id}")),
            finding(&format!("{BOUNDARY_INPUT_PREFIX}{id}"), "real-sink"),
        ];
        let composed = compose_cross_boundary_findings(&mut findings, &graph);
        assert!(findings.is_empty(), "boundary-tagged findings must not leak into the plain findings list: {findings:#?}");
        assert_eq!(composed.len(), 1, "{composed:#?}");
        assert_eq!(composed[0].producer.source_rule_id, "real-source");
        assert_eq!(composed[0].consumer.sink_rule_id, "real-sink");
    }

    #[test]
    fn a_one_sided_finding_composes_nothing_but_is_still_removed() {
        let (graph, id) = graph_with_one_mapping();
        let mut findings = vec![finding("real-source", &format!("{BOUNDARY_OUTPUT_PREFIX}{id}"))];
        let composed = compose_cross_boundary_findings(&mut findings, &graph);
        assert!(composed.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn unrelated_findings_are_left_untouched() {
        let (graph, _id) = graph_with_one_mapping();
        let mut findings = vec![finding("plain-source", "plain-sink")];
        let composed = compose_cross_boundary_findings(&mut findings, &graph);
        assert!(composed.is_empty());
        assert_eq!(findings.len(), 1);
    }
}
