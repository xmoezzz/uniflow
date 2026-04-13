use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use uniflow_rules::{language_matches, RuleSet};
use uniflow_value_flow::{FlowGraph, FlowNode};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaintStep {
    pub from_node: usize,
    pub to_node: usize,
    pub edge_kind: String,
    pub from_label: String,
    pub to_label: String,
    pub from_location: String,
    pub to_location: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaintFinding {
    pub source_rule_id: String,
    pub sink_rule_id: String,
    pub source_kind: String,
    pub sink_kind: String,
    pub sink_node: usize,
    pub path: Vec<usize>,
    pub source_label: String,
    pub sink_label: String,
    pub source_location: String,
    pub sink_location: String,
    pub path_labels: Vec<String>,
    pub steps: Vec<TaintStep>,
}

#[derive(Clone, Debug)]
struct SourceSeed {
    node: NodeIndex,
    rule_id: String,
    kind: String,
}

#[derive(Clone, Debug)]
struct SanitizerEdge {
    from: usize,
    to: usize,
    kind: String,
}

pub fn analyze(flow: &FlowGraph, rules: &RuleSet) -> Vec<TaintFinding> {
    let sanitizer_edges = build_sanitizer_map(flow, rules);
    let source_seeds = collect_source_seeds(flow);
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for source in source_seeds {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<NodeIndex, (NodeIndex, String)> = HashMap::new();

        queue.push_back(source.node);
        visited.insert(source.node);

        while let Some(node) = queue.pop_front() {
            for edge in flow.graph.edges(node) {
                let next = edge.target();
                if is_sanitized_transfer(&sanitizer_edges, &source.kind, edge.source(), next) {
                    continue;
                }
                if visited.insert(next) {
                    parent.insert(next, (node, format!("{:?}", edge.weight().kind)));
                    queue.push_back(next);
                }
                if let FlowNode::SyntheticSink { rule_id, kind, .. } = &flow.graph[next] {
                    if !kind_compatible(&source.kind, kind) {
                        continue;
                    }
                    let path = reconstruct_path(source.node, next, &parent);
                    let key = (
                        source.rule_id.clone(),
                        rule_id.clone(),
                        source.kind.clone(),
                        kind.clone(),
                        path.clone(),
                    );
                    if seen.insert(key) {
                        findings.push(build_finding(
                            flow,
                            &source.rule_id,
                            rule_id,
                            &source.kind,
                            kind,
                            next,
                            &path,
                        ));
                    }
                }
            }
        }
    }

    findings
}

pub fn pretty_findings(findings: &[TaintFinding]) -> String {
    let mut out = String::new();
    for (idx, finding) in findings.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "finding {}\n  source_rule: {}\n  sink_rule: {}\n  source_kind: {}\n  sink_kind: {}\n  source: {}\n  sink: {}\n  source_location: {}\n  sink_location: {}\n",
            idx + 1,
            finding.source_rule_id,
            finding.sink_rule_id,
            finding.source_kind,
            finding.sink_kind,
            finding.source_label,
            finding.sink_label,
            finding.source_location,
            finding.sink_location,
        ));
        for step in &finding.steps {
            out.push_str(&format!(
                "    - {} [{}] --{}--> {} [{}]\n",
                step.from_label,
                step.from_location,
                step.edge_kind,
                step.to_label,
                step.to_location,
            ));
        }
    }
    if findings.is_empty() {
        out.push_str("no findings\n");
    }
    out
}

fn collect_source_seeds(flow: &FlowGraph) -> Vec<SourceSeed> {
    flow.synthetic_sources
        .iter()
        .filter_map(|idx| match &flow.graph[*idx] {
            FlowNode::SyntheticSource { rule_id, kind, .. } => Some(SourceSeed {
                node: *idx,
                rule_id: rule_id.clone(),
                kind: kind.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn build_finding(
    flow: &FlowGraph,
    source_rule_id: &str,
    sink_rule_id: &str,
    source_kind: &str,
    sink_kind: &str,
    sink: NodeIndex,
    path: &[usize],
) -> TaintFinding {
    let path_labels = path
        .iter()
        .map(|idx| flow.describe_node(NodeIndex::new(*idx)))
        .collect::<Vec<_>>();

    let mut steps = Vec::new();
    for window in path.windows(2) {
        let from = NodeIndex::new(window[0]);
        let to = NodeIndex::new(window[1]);
        steps.push(TaintStep {
            from_node: from.index(),
            to_node: to.index(),
            edge_kind: flow.describe_edge(from, to),
            from_label: flow.describe_node(from),
            to_label: flow.describe_node(to),
            from_location: node_location(flow, from),
            to_location: node_location(flow, to),
        });
    }

    let source_node = path.first().copied().map(NodeIndex::new);
    let sink_node = Some(sink);

    TaintFinding {
        source_rule_id: source_rule_id.to_string(),
        sink_rule_id: sink_rule_id.to_string(),
        source_kind: source_kind.to_string(),
        sink_kind: sink_kind.to_string(),
        sink_node: sink.index(),
        path: path.to_vec(),
        source_label: path_labels
            .first()
            .cloned()
            .unwrap_or_else(|| "<empty-path>".to_string()),
        sink_label: path_labels
            .last()
            .cloned()
            .unwrap_or_else(|| "<empty-path>".to_string()),
        source_location: source_node
            .map(|idx| node_location(flow, idx))
            .unwrap_or_else(|| "@unknown".to_string()),
        sink_location: sink_node
            .map(|idx| node_location(flow, idx))
            .unwrap_or_else(|| "@unknown".to_string()),
        path_labels,
        steps,
    }
}

fn reconstruct_path(
    start: NodeIndex,
    end: NodeIndex,
    parent: &HashMap<NodeIndex, (NodeIndex, String)>,
) -> Vec<usize> {
    let mut path = vec![end];
    let mut cur = end;
    while cur != start {
        let Some((prev, _)) = parent.get(&cur) else {
            break;
        };
        path.push(*prev);
        cur = *prev;
    }
    path.reverse();
    path.into_iter().map(|n| n.index()).collect()
}

fn build_sanitizer_map(flow: &FlowGraph, rules: &RuleSet) -> Vec<SanitizerEdge> {
    let mut blocked = Vec::new();
    for ((func, inst), meta) in &flow.call_meta {
        let Some(call_info) = meta.as_call_info() else {
            continue;
        };
        for rule in &rules.sanitizers {
            if !language_matches(&rule.language, &flow.language) || !rule.matcher.matches_call(&call_info) {
                continue;
            }
            for input in &rule.inputs {
                for output in &rule.outputs {
                    let from = flow.call_ports.get(&(*func, *inst, input.clone())).copied();
                    let to = flow.call_ports.get(&(*func, *inst, output.clone())).copied();
                    if let (Some(from), Some(to)) = (from, to) {
                        blocked.push(SanitizerEdge {
                            from: from.index(),
                            to: to.index(),
                            kind: rule.kind.clone(),
                        });
                    }
                }
            }
        }
    }
    blocked
}

fn is_sanitized_transfer(
    blocked: &[SanitizerEdge],
    taint_kind: &str,
    from: NodeIndex,
    to: NodeIndex,
) -> bool {
    blocked.iter().any(|edge| {
        edge.from == from.index() && edge.to == to.index() && kind_compatible(taint_kind, &edge.kind)
    })
}

fn kind_compatible(source_kind: &str, other_kind: &str) -> bool {
    let source_kind = normalize_kind(source_kind);
    let other_kind = normalize_kind(other_kind);
    source_kind == "generic" || other_kind == "generic" || source_kind == other_kind
}

fn normalize_kind(kind: &str) -> &str {
    let trimmed = kind.trim();
    if trimmed.is_empty() {
        "generic"
    } else {
        trimmed
    }
}

fn node_location(flow: &FlowGraph, idx: NodeIndex) -> String {
    match &flow.graph[idx] {
        FlowNode::CallPort { func, inst, .. }
        | FlowNode::SyntheticSource { func, inst, .. }
        | FlowNode::SyntheticSink { func, inst, .. } => flow.location_text(*func, *inst),
        FlowNode::FieldCell { func, inst, .. } | FlowNode::IndexCell { func, inst, .. } => {
            flow.location_text(*func, *inst)
        }
        FlowNode::Param { func, value, .. } | FlowNode::Value { func, value } => {
            if let Some(span) = flow.value_spans.get(&(*func, *value)) {
                flow.span_text(span)
            } else if let Some(span) = flow.function_spans.get(func) {
                flow.span_text(span)
            } else {
                "@unknown".to_string()
            }
        }
        FlowNode::Return { func } => flow
            .function_spans
            .get(func)
            .map(|span| flow.span_text(span))
            .unwrap_or_else(|| "@unknown".to_string()),
    }
}
