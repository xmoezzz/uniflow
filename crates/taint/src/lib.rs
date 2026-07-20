use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use uniflow_rules::{language_matches, RuleSet};
use uniflow_value_flow::{
    DemandEngine, DemandQuery, DemandSeed, EdgeKind, FlowGraph, FlowNode, QueryCompleteness,
    SparseDirection,
};

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
    #[serde(default)]
    pub finding_kind: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub message: String,
    #[serde(default = "default_true")]
    pub analysis_complete: bool,
    #[serde(default)]
    pub completeness: QueryCompleteness,
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TraversalState {
    node: NodeIndex,
    call_stack: Vec<(u32, u32)>,
    context_truncated: bool,
}


fn default_true() -> bool { true }

pub fn analyze(flow: &FlowGraph, rules: &RuleSet) -> Vec<TaintFinding> {
    let sanitizer_edges = build_sanitizer_map(flow, rules);
    let source_seeds = collect_source_seeds(flow);
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for source in source_seeds {
        let forward_query = DemandQuery {
            seeds: vec![DemandSeed::Node(source.node.index())],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let forward_plan = flow.solver_plan_for_query(&forward_query);
        let Some(forward_summary) = flow.execute_solver_plan(&forward_plan) else {
            continue;
        };
        let forward_nodes = forward_summary
            .traversal
            .visited
            .iter()
            .copied()
            .collect::<HashSet<_>>();

        for sink in collect_compatible_sinks(flow, &source.kind, &forward_nodes) {
            // A forward demand summary tells us which nodes may be influenced by the source.  A
            // sink-specific backward summary removes nodes that cannot contribute to this sink.
            // The witness search is therefore constrained to the bidirectional demand slice,
            // rather than falling back to an unrestricted whole-graph taint traversal.
            let backward_query = DemandQuery {
                seeds: vec![DemandSeed::Node(sink.node.index())],
                direction: SparseDirection::Backward,
                engine: DemandEngine::Fixpoint,
                include_heap: true,
            };
            let backward_plan = flow.solver_plan_for_query(&backward_query);
            let Some(backward_summary) = flow.execute_solver_plan(&backward_plan) else {
                continue;
            };
            let backward_nodes = backward_summary
                .traversal
                .visited
                .iter()
                .copied()
                .collect::<HashSet<_>>();
            let mut allowed_nodes = forward_nodes
                .intersection(&backward_nodes)
                .copied()
                .collect::<HashSet<_>>();
            allowed_nodes.insert(source.node.index());
            allowed_nodes.insert(sink.node.index());

            let context_limit = forward_plan
                .max_depth
                .max(backward_plan.max_depth)
                .clamp(8, 32);
            let Some((path, context_truncated)) = find_contextual_path_to_sink(
                flow,
                &sanitizer_edges,
                &source,
                &sink,
                &allowed_nodes,
                context_limit,
            ) else {
                continue;
            };

            let mut completeness = merge_completeness(
                forward_summary.traversal.completeness,
                backward_summary.traversal.completeness,
            );
            if context_truncated {
                completeness = merge_completeness(
                    completeness,
                    QueryCompleteness::ContextLimitReached,
                );
            }
            let finding = build_finding(
                flow,
                &source.rule_id,
                &sink.rule_id,
                &source.kind,
                &sink.kind,
                sink.node,
                &path,
                completeness,
            );
            let key = (
                finding.source_rule_id.clone(),
                finding.sink_rule_id.clone(),
                finding.source_kind.clone(),
                finding.sink_kind.clone(),
                finding.source_location.clone(),
                finding.sink_location.clone(),
                finding.path_labels.clone(),
            );
            if seen.insert(key) {
                findings.push(finding);
            }
        }
    }

    findings.extend(lifetime_findings(flow));
    findings
}

#[derive(Clone, Debug)]
struct SinkSeed {
    node: NodeIndex,
    rule_id: String,
    kind: String,
}

fn collect_compatible_sinks(
    flow: &FlowGraph,
    source_kind: &str,
    forward_nodes: &HashSet<usize>,
) -> Vec<SinkSeed> {
    flow.synthetic_sinks
        .iter()
        .filter(|node| forward_nodes.contains(&node.index()))
        .filter_map(|node| match &flow.graph[*node] {
            FlowNode::SyntheticSink { rule_id, kind, .. }
                if kind_compatible(source_kind, kind) =>
            {
                Some(SinkSeed {
                    node: *node,
                    rule_id: rule_id.clone(),
                    kind: kind.clone(),
                })
            }
            _ => None,
        })
        .collect()
}

fn find_contextual_path_to_sink(
    flow: &FlowGraph,
    sanitizer_edges: &[SanitizerEdge],
    source: &SourceSeed,
    sink: &SinkSeed,
    allowed_nodes: &HashSet<usize>,
    context_limit: usize,
) -> Option<(Vec<usize>, bool)> {
    let start = TraversalState {
        node: source.node,
        call_stack: Vec::new(),
        context_truncated: false,
    };
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = HashSet::from([start.clone()]);
    let mut parent = HashMap::<TraversalState, TraversalState>::new();

    while let Some(state) = queue.pop_front() {
        if state.node == sink.node {
            let path = reconstruct_contextual_path(&start, &state, &parent);
            return Some((path, state.context_truncated));
        }
        for edge in flow.graph.edges(state.node) {
            let next_node = edge.target();
            if !allowed_nodes.contains(&next_node.index()) {
                continue;
            }
            if is_sanitized_transfer(
                sanitizer_edges,
                &source.kind,
                edge.source(),
                next_node,
            ) {
                continue;
            }
            let Some(next_state) = transition_state(
                flow,
                &state,
                next_node,
                &edge.weight().kind,
                context_limit,
            ) else {
                continue;
            };
            if visited.insert(next_state.clone()) {
                parent.insert(next_state.clone(), state.clone());
                queue.push_back(next_state);
            }
        }
    }
    None
}

fn merge_completeness(left: QueryCompleteness, right: QueryCompleteness) -> QueryCompleteness {
    fn rank(value: QueryCompleteness) -> u8 {
        match value {
            QueryCompleteness::Complete => 0,
            QueryCompleteness::HeapWidened => 1,
            QueryCompleteness::ContextLimitReached => 2,
            QueryCompleteness::DepthLimitReached => 3,
            QueryCompleteness::VisitLimitReached => 4,
        }
    }
    if rank(right) > rank(left) { right } else { left }
}

fn transition_state(
    flow: &FlowGraph,
    state: &TraversalState,
    next_node: NodeIndex,
    edge_kind: &EdgeKind,
    context_limit: usize,
) -> Option<TraversalState> {
    let mut call_stack = state.call_stack.clone();
    match edge_kind {
        EdgeKind::ActualToFormal => {
            let site = call_site_of(&flow.graph[state.node])?;
            call_stack.push(site);
            let mut context_truncated = state.context_truncated;
            if call_stack.len() > context_limit {
                let excess = call_stack.len() - context_limit;
                call_stack.drain(0..excess);
                context_truncated = true;
            }
            return Some(TraversalState {
                node: next_node,
                call_stack,
                context_truncated,
            });
        }
        EdgeKind::FormalToActual => {
            let site = call_site_of(&flow.graph[next_node])?;
            if let Some(active) = call_stack.last().copied() {
                if active != site {
                    return None;
                }
                call_stack.pop();
            }
        }
        _ => {}
    }
    Some(TraversalState {
        node: next_node,
        call_stack,
        context_truncated: state.context_truncated,
    })
}

fn call_site_of(node: &FlowNode) -> Option<(u32, u32)> {
    match node {
        FlowNode::CallPort { func, inst, .. }
        | FlowNode::SyntheticSource { func, inst, .. }
        | FlowNode::SyntheticSink { func, inst, .. } => Some((func.0, inst.0)),
        _ => None,
    }
}

fn reconstruct_contextual_path(
    start: &TraversalState,
    end: &TraversalState,
    parent: &HashMap<TraversalState, TraversalState>,
) -> Vec<usize> {
    let mut path = vec![end.node.index()];
    let mut cur = end.clone();
    while &cur != start {
        let Some(prev) = parent.get(&cur) else {
            break;
        };
        path.push(prev.node.index());
        cur = prev.clone();
    }
    path.reverse();
    path
}

pub fn pretty_findings(findings: &[TaintFinding]) -> String {
    let mut out = String::new();
    for (idx, finding) in findings.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "finding {}\n  kind: {}\n  rule: {}\n  severity: {}\n  message: {}\n  source_kind: {}\n  sink_kind: {}\n  source: {}\n  sink: {}\n  source_location: {}\n  sink_location: {}\n  complete: {} ({:?})\n",
            idx + 1,
            finding.finding_kind,
            finding.sink_rule_id,
            finding.severity,
            finding.message,
            finding.source_kind,
            finding.sink_kind,
            finding.source_label,
            finding.sink_label,
            finding.source_location,
            finding.sink_location,
            finding.analysis_complete,
            finding.completeness,
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
    completeness: QueryCompleteness,
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
        finding_kind: "taint".to_string(),
        severity: if sink_kind == "command" { "error" } else { "warning" }.to_string(),
        message: format!(
            "Taint of kind '{}' reaches sink '{}' from source '{}'",
            source_kind, sink_rule_id, source_rule_id
        ),
        analysis_complete: completeness == QueryCompleteness::Complete,
        completeness,
    }
}

fn lifetime_findings(flow: &FlowGraph) -> Vec<TaintFinding> {
    flow.lifetime_diagnostics
        .iter()
        .map(|diagnostic| {
            let node = flow
                .values
                .get(&(diagnostic.function, diagnostic.value))
                .copied();
            let path = node.map(|node| vec![node.index()]).unwrap_or_default();
            let label = diagnostic.message.clone();
            let location = flow.span_text(&diagnostic.span);
            TaintFinding {
                source_rule_id: diagnostic.rule_id.clone(),
                sink_rule_id: diagnostic.rule_id.clone(),
                source_kind: "lifetime".to_string(),
                sink_kind: "lifetime".to_string(),
                sink_node: node.map(NodeIndex::index).unwrap_or(0),
                path: path.clone(),
                source_label: label.clone(),
                sink_label: label.clone(),
                source_location: location.clone(),
                sink_location: location,
                path_labels: vec![label],
                steps: Vec::new(),
                finding_kind: "lifetime".to_string(),
                severity: diagnostic.severity.clone(),
                message: diagnostic.message.clone(),
                analysis_complete: true,
                completeness: QueryCompleteness::Complete,
            }
        })
        .collect()
}

fn build_sanitizer_map(flow: &FlowGraph, rules: &RuleSet) -> Vec<SanitizerEdge> {
    let mut blocked = Vec::new();
    for ((func, inst), meta) in &flow.call_meta {
        let Some(call_info) = meta.as_call_info() else {
            continue;
        };
        for rule in &rules.sanitizers {
            if !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
            {
                continue;
            }
            for input in &rule.inputs {
                for output in &rule.outputs {
                    let from = flow.call_ports.get(&(*func, *inst, input.clone())).copied();
                    let to = flow
                        .call_ports
                        .get(&(*func, *inst, output.clone()))
                        .copied();
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
        edge.from == from.index()
            && edge.to == to.index()
            && kind_compatible(taint_kind, &edge.kind)
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

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_frontend::parse_source;
    use uniflow_hir::Language;
    use uniflow_lowering::lower_program;
    use uniflow_models::default_models_for;
    use uniflow_value_flow::build;

    fn analyze_source(language: Language, path: &str, source: &str) -> Vec<TaintFinding> {
        let rules = default_models_for(language.clone());
        let hir = parse_source(language, path, source).expect("source should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        analyze(&flow, &rules)
    }

    #[test]
    fn detects_c_getenv_to_system_end_to_end() {
        let findings = analyze_source(
            Language::C,
            "smoke.c",
            r#"
char *getenv(const char *name);
int system(const char *command);
int main(void) {
    char *cmd = getenv("CMD");
    return system(cmd);
}
"#,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_rule_id, "c-getenv");
        assert_eq!(findings[0].sink_rule_id, "c-system");
        assert!(findings[0].path_labels.len() >= 5);
    }

    #[test]
    fn detects_cpp_getenv_to_system_end_to_end() {
        let findings = analyze_source(
            Language::Cpp,
            "smoke.cpp",
            r#"
char *getenv(const char *name);
int system(const char *command);
int main() {
    char *cmd = getenv("CMD");
    return system(cmd);
}
"#,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_rule_id, "c-getenv");
        assert_eq!(findings[0].sink_rule_id, "c-system");
        assert!(findings[0].path_labels.len() >= 5);
    }

    #[test]
    fn detects_java_request_parameter_to_sql_end_to_end() {
        let findings = analyze_source(
            Language::Java,
            "Controller.java",
            r#"
import javax.servlet.http.HttpServletRequest;
import java.sql.Statement;

class Controller {
    void handle(HttpServletRequest req, Statement stmt) {
        String sql = req.getParameter("q");
        stmt.executeQuery(sql);
    }
}
"#,
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source_rule_id, "java-http-request-param");
        assert_eq!(findings[0].sink_rule_id, "java-sql-statement-executequery");
        assert!(findings[0].path_labels.len() >= 5);
    }

    #[test]
    fn detects_python_getenv_to_system_once_end_to_end() {
        let findings = analyze_source(
            Language::Python,
            "smoke.py",
            r#"
import os

def handle():
    cmd = os.getenv("CMD")
    os.system(cmd)
"#,
        );

        assert_eq!(
            findings.len(),
            1,
            "equivalent model matches must be deduplicated"
        );
        assert_eq!(findings[0].source_rule_id, "python-os-getenv");
        assert_eq!(findings[0].sink_rule_id, "python-os-system");
        assert!(findings[0].path_labels.len() >= 5);
    }

    #[test]
    fn taint_witness_is_constrained_by_bidirectional_demand_slices() {
        let language = Language::C;
        let rules = default_models_for(language.clone());
        let hir = parse_source(
            language,
            "bidirectional.c",
            r#"
char *getenv(const char *name);
int system(const char *command);
int main(void) {
    char *cmd = getenv("CMD");
    return system(cmd);
}
"#,
        )
        .expect("source should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        let findings = analyze(&flow, &rules);
        let finding = findings
            .iter()
            .find(|finding| finding.finding_kind == "taint")
            .expect("taint finding");
        let source = *finding.path.first().expect("source node");
        let sink = *finding.path.last().expect("sink node");
        let forward = flow
            .execute_solver_plan(&flow.solver_plan_for_query(&DemandQuery {
                seeds: vec![DemandSeed::Node(source)],
                direction: SparseDirection::Forward,
                engine: DemandEngine::Fixpoint,
                include_heap: true,
            }))
            .expect("forward demand summary");
        let backward = flow
            .execute_solver_plan(&flow.solver_plan_for_query(&DemandQuery {
                seeds: vec![DemandSeed::Node(sink)],
                direction: SparseDirection::Backward,
                engine: DemandEngine::Fixpoint,
                include_heap: true,
            }))
            .expect("backward demand summary");
        let forward = forward.traversal.visited.into_iter().collect::<HashSet<_>>();
        let backward = backward.traversal.visited.into_iter().collect::<HashSet<_>>();
        assert!(finding
            .path
            .iter()
            .all(|node| forward.contains(node) && backward.contains(node)));
    }

}
