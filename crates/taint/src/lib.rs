use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use uniflow_rules::{
    expand_port, language_matches, Port, RuleMetadata, RuleSet, RuleTranslations, TaintCondition,
};
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
    #[serde(default)]
    pub rule_title: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default, skip_serializing_if = "RuleTranslations::is_empty")]
    pub translations: RuleTranslations,
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
    labels: Vec<String>,
}

#[derive(Clone, Debug)]
struct LabelTransformEdge {
    from: Option<usize>,
    to: usize,
    add_kinds: Vec<String>,
    remove_kinds: Vec<String>,
    remove_compatible: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TraversalState {
    node: NodeIndex,
    labels: Vec<String>,
    call_stack: Vec<(u32, u32)>,
    context_truncated: bool,
}

fn default_true() -> bool {
    true
}

pub fn analyze(flow: &FlowGraph, rules: &RuleSet) -> Vec<TaintFinding> {
    let label_transforms = build_label_transform_map(flow, rules);
    let receiver_side_labels = build_receiver_side_labels(flow, rules);
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

        for sink in collect_candidate_sinks(flow, &forward_nodes) {
            if !kind_can_transform_to(rules, &source.kind, &sink.kind) {
                continue;
            }
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
            let Some((path, context_truncated, _sink_labels)) = find_contextual_path_to_sink(
                flow,
                rules,
                &label_transforms,
                &receiver_side_labels,
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
                completeness =
                    merge_completeness(completeness, QueryCompleteness::ContextLimitReached);
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
                rules.metadata_for(&sink.rule_id),
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

fn collect_candidate_sinks(flow: &FlowGraph, forward_nodes: &HashSet<usize>) -> Vec<SinkSeed> {
    flow.synthetic_sinks
        .iter()
        .filter(|node| forward_nodes.contains(&node.index()))
        .filter_map(|node| match &flow.graph[*node] {
            FlowNode::SyntheticSink { rule_id, kind, .. } => Some(SinkSeed {
                node: *node,
                rule_id: rule_id.clone(),
                kind: kind.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn sink_condition_matches(
    flow: &FlowGraph,
    sink_node: NodeIndex,
    condition: &TaintCondition,
    labels: &[String],
) -> bool {
    let FlowNode::SyntheticSink { func, inst, .. } = flow.graph[sink_node] else {
        return false;
    };
    let Some(meta) = flow.call_meta.get(&(func, inst)) else {
        return false;
    };
    meta.as_call_info()
        .is_some_and(|call| condition.matches_call(&call, labels))
}

fn find_contextual_path_to_sink(
    flow: &FlowGraph,
    rules: &RuleSet,
    label_transforms: &[LabelTransformEdge],
    receiver_side_labels: &HashMap<(u32, u32), Vec<String>>,
    source: &SourceSeed,
    sink: &SinkSeed,
    allowed_nodes: &HashSet<usize>,
    context_limit: usize,
) -> Option<(Vec<usize>, bool, Vec<String>)> {
    let start = TraversalState {
        node: source.node,
        labels: source.labels.clone(),
        call_stack: Vec::new(),
        context_truncated: false,
    };
    let mut queue = VecDeque::from([start.clone()]);
    let mut visited = HashSet::from([start.clone()]);
    let mut parent = HashMap::<TraversalState, TraversalState>::new();

    while let Some(state) = queue.pop_front() {
        let mut sink_labels = state.labels.clone();
        if state.node == sink.node {
            if let FlowNode::SyntheticSink { func, inst, .. } = flow.graph[sink.node] {
                sink_labels.extend(
                    receiver_side_labels
                        .get(&(func.0, inst.0))
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
                sink_labels.sort();
                sink_labels.dedup();
            }
        }
        if state.node == sink.node
            && sink_labels
                .iter()
                .any(|label| kind_compatible(label, &sink.kind))
            && rules
                .sink_conditions
                .iter()
                .find(|condition| condition.sink_rule_id == sink.rule_id)
                .is_none_or(|condition| {
                    sink_condition_matches(flow, sink.node, &condition.condition, &sink_labels)
                })
        {
            let path = reconstruct_contextual_path(&start, &state, &parent);
            return Some((path, state.context_truncated, sink_labels));
        }
        for edge in flow.graph.edges(state.node) {
            let next_node = edge.target();
            if !allowed_nodes.contains(&next_node.index()) {
                continue;
            }
            let Some(mut next_state) =
                transition_state(flow, &state, next_node, &edge.weight().kind, context_limit)
            else {
                continue;
            };
            next_state.labels =
                transformed_labels(label_transforms, &state.labels, edge.source(), next_node);
            if next_state.labels.is_empty() {
                continue;
            }
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
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
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
                labels: state.labels.clone(),
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
        labels: state.labels.clone(),
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
    let mut colocated = HashMap::<(u32, u32, Port), Vec<String>>::new();
    for idx in &flow.synthetic_sources {
        if let FlowNode::SyntheticSource { func, inst, kind, out, .. } = &flow.graph[*idx] {
            colocated.entry((func.0, inst.0, out.clone())).or_default()
                .push(normalize_kind(kind).to_string());
        }
    }
    for labels in colocated.values_mut() { labels.sort(); labels.dedup(); }
    flow.synthetic_sources
        .iter()
        .filter_map(|idx| match &flow.graph[*idx] {
            FlowNode::SyntheticSource { func, inst, rule_id, kind, out } => Some(SourceSeed {
                node: *idx,
                rule_id: rule_id.clone(),
                kind: kind.clone(),
                labels: colocated.get(&(func.0, inst.0, out.clone())).cloned()
                    .unwrap_or_else(|| vec![normalize_kind(kind).to_string()]),
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
    metadata: Option<&RuleMetadata>,
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

    let fallback_severity = if sink_kind == "command" {
        "error"
    } else {
        "warning"
    };
    let fallback_message = format!(
        "Taint of kind '{}' reaches sink '{}' from source '{}'",
        source_kind, sink_rule_id, source_rule_id
    );
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
        severity: metadata
            .map(|item| item.severity.clone())
            .unwrap_or_else(|| fallback_severity.to_string()),
        message: metadata
            .map(|item| item.message.clone())
            .filter(|message| !message.trim().is_empty())
            .unwrap_or(fallback_message),
        rule_title: metadata.map(|item| item.title.clone()).unwrap_or_default(),
        cwe: metadata.map(|item| item.cwe.clone()).unwrap_or_default(),
        standards: metadata
            .map(|item| item.standards.clone())
            .unwrap_or_default(),
        translations: metadata
            .map(|item| item.translations.clone())
            .unwrap_or_default(),
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
                rule_title: diagnostic.message.clone(),
                cwe: Vec::new(),
                standards: Vec::new(),
                translations: RuleTranslations::default(),
                analysis_complete: true,
                completeness: QueryCompleteness::Complete,
            }
        })
        .collect()
}

fn build_label_transform_map(flow: &FlowGraph, rules: &RuleSet) -> Vec<LabelTransformEdge> {
    let mut transforms = Vec::new();
    for ((func, inst), meta) in &flow.call_meta {
        let Some(call_info) = meta.as_call_info() else {
            continue;
        };
        for rule in &rules.sanitizers {
            if !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
                || !rules.call_condition_matches(&rule.id, &call_info)
            {
                continue;
            }
            let arg_count = call_info.arg_count.unwrap_or(0);
            let outputs = rule
                .outputs
                .iter()
                .flat_map(|output| expand_port(output, arg_count))
                .collect::<Vec<_>>();
            if rule.inputs.is_empty() {
                for output in outputs {
                    if let Some(to) = flow.call_ports.get(&(*func, *inst, output)).copied() {
                        transforms.push(LabelTransformEdge {
                            from: None,
                            to: to.index(),
                            add_kinds: Vec::new(),
                            remove_kinds: vec![rule.kind.clone()],
                            remove_compatible: true,
                        });
                    }
                }
                continue;
            }
            for input in rule
                .inputs
                .iter()
                .flat_map(|input| expand_port(input, arg_count))
            {
                for output in &outputs {
                    let from = flow.call_ports.get(&(*func, *inst, input.clone())).copied();
                    let to = flow
                        .call_ports
                        .get(&(*func, *inst, output.clone()))
                        .copied();
                    if let (Some(from), Some(to)) = (from, to) {
                        transforms.push(LabelTransformEdge {
                            from: Some(from.index()),
                            to: to.index(),
                            add_kinds: Vec::new(),
                            remove_kinds: vec![rule.kind.clone()],
                            remove_compatible: true,
                        });
                    }
                }
            }
        }
        for rule in &rules.taint_transforms {
            if !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
                || !rules.call_condition_matches(&rule.id, &call_info)
            {
                continue;
            }
            let arg_count = call_info.arg_count.unwrap_or(0);
            let outputs = rule
                .outputs
                .iter()
                .flat_map(|output| expand_port(output, arg_count))
                .collect::<Vec<_>>();
            if rule.inputs.is_empty() {
                for output in outputs {
                    if let Some(to) = flow.call_ports.get(&(*func, *inst, output)).copied() {
                        transforms.push(LabelTransformEdge {
                            from: None,
                            to: to.index(),
                            add_kinds: rule.add_kinds.clone(),
                            remove_kinds: rule.remove_kinds.clone(),
                            remove_compatible: false,
                        });
                    }
                }
                continue;
            }
            for input in rule
                .inputs
                .iter()
                .flat_map(|input| expand_port(input, arg_count))
            {
                for output in &outputs {
                    let from = flow.call_ports.get(&(*func, *inst, input.clone())).copied();
                    let to = flow
                        .call_ports
                        .get(&(*func, *inst, output.clone()))
                        .copied();
                    if let (Some(from), Some(to)) = (from, to) {
                        transforms.push(LabelTransformEdge {
                            from: Some(from.index()),
                            to: to.index(),
                            add_kinds: rule.add_kinds.clone(),
                            remove_kinds: rule.remove_kinds.clone(),
                            remove_compatible: false,
                        });
                    }
                }
            }
        }
    }
    for node in flow.graph.node_indices() {
        let FlowNode::FieldCell {
            func, base, field, ..
        } = &flow.graph[node]
        else {
            continue;
        };
        let Some(owner) = flow.value_types.get(&(*func, *base)) else {
            continue;
        };
        let owners = field_owner_candidates(flow, owner);
        for rule in &rules.field_sanitizers {
            if !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches(&owners, field)
            {
                continue;
            }
            for edge in flow.graph.edges(node) {
                if !matches!(edge.weight().kind, EdgeKind::LoadField { .. }) {
                    continue;
                }
                transforms.push(LabelTransformEdge {
                    from: Some(node.index()),
                    to: edge.target().index(),
                    add_kinds: Vec::new(),
                    remove_kinds: vec![rule.kind.clone()],
                    remove_compatible: true,
                });
            }
        }
    }
    transforms
}

/// Compute labels established on mutable receiver objects independently of a
/// tainted value path. This is needed for stateful APIs such as XML factories:
/// `setFeature(..., false)` changes the factory, and `newDocumentBuilder()`
/// transfers that hardened state to the returned parser. Calls are processed
/// in lowered instruction order so a later configuration cannot sanitize an
/// earlier sink.
fn build_receiver_side_labels(
    flow: &FlowGraph,
    rules: &RuleSet,
) -> HashMap<(u32, u32), Vec<String>> {
    let mut calls = flow.call_meta.iter().collect::<Vec<_>>();
    calls.sort_by_key(|((func, inst), _)| (func.0, inst.0));
    let mut object_labels = HashMap::<String, BTreeSet<String>>::new();
    let mut labels_at_call = HashMap::<(u32, u32), Vec<String>>::new();

    for ((func, inst), meta) in calls {
        let Some(call_info) = meta.as_call_info() else {
            continue;
        };
        let receiver_keys = flow
            .call_ports
            .get(&(*func, *inst, Port::Receiver))
            .map(|node| side_state_keys(flow, *node))
            .unwrap_or_default();
        let mut receiver_labels = labels_for_keys(&object_labels, &receiver_keys);
        labels_at_call.insert((func.0, inst.0), receiver_labels.iter().cloned().collect());

        for rule in &rules.taint_transforms {
            if !rule.inputs.is_empty()
                || !rule.outputs.iter().any(|output| output == &Port::Receiver)
                || !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
                || !rules.call_condition_matches(&rule.id, &call_info)
            {
                continue;
            }
            for key in &receiver_keys {
                let labels = object_labels.entry(key.clone()).or_default();
                labels.retain(|label| {
                    !rule
                        .remove_kinds
                        .iter()
                        .any(|removed| normalize_kind(label) == normalize_kind(removed))
                });
                labels.extend(
                    rule.add_kinds
                        .iter()
                        .map(|kind| normalize_kind(kind).to_string()),
                );
            }
        }

        receiver_labels = labels_for_keys(&object_labels, &receiver_keys);
        if receiver_labels.is_empty() {
            continue;
        }
        let transfers_receiver_to_return = rules.propagators.iter().any(|rule| {
            language_matches(&rule.language, &flow.language)
                && rule.matcher.matches_call(&call_info)
                && rules.call_condition_matches(&rule.id, &call_info)
                && rule.flows.iter().any(|spec| {
                    spec.from == Port::Receiver && spec.to == Port::Return
                })
        });
        if !transfers_receiver_to_return {
            continue;
        }
        let return_keys = flow
            .call_ports
            .get(&(*func, *inst, Port::Return))
            .map(|node| side_state_keys(flow, *node))
            .unwrap_or_default();
        for key in return_keys {
            object_labels
                .entry(key)
                .or_default()
                .extend(receiver_labels.iter().cloned());
        }
    }
    labels_at_call
}

fn labels_for_keys(
    object_labels: &HashMap<String, BTreeSet<String>>,
    keys: &[String],
) -> BTreeSet<String> {
    keys.iter()
        .filter_map(|key| object_labels.get(key))
        .flat_map(|labels| labels.iter().cloned())
        .collect()
}

fn side_state_keys(flow: &FlowGraph, node: NodeIndex) -> Vec<String> {
    fn collect_value_key(flow: &FlowGraph, node: NodeIndex, keys: &mut BTreeSet<String>) {
        if let FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } = flow.graph[node]
        {
            let root = flow
                .object_identity_roots
                .get(&(func, value))
                .or_else(|| flow.heap_alias_roots.get(&(func, value)))
                .or_else(|| flow.value_alias_roots.get(&(func, value)))
                .copied()
                .unwrap_or(value);
            keys.insert(format!("value:{}:{}", func.0, root.0));
        }
    }

    let mut keys = BTreeSet::new();
    collect_value_key(flow, node, &mut keys);
    for edge in flow.graph.edges_directed(node, petgraph::Direction::Incoming) {
        if matches!(edge.weight().kind, EdgeKind::ValueToCallPort | EdgeKind::CallPortToValue) {
            collect_value_key(flow, edge.source(), &mut keys);
        }
    }
    for edge in flow.graph.edges(node) {
        if matches!(edge.weight().kind, EdgeKind::ValueToCallPort | EdgeKind::CallPortToValue) {
            collect_value_key(flow, edge.target(), &mut keys);
        }
    }
    // A broad points-to overlay may contain every object in a connected
    // region. Never write a security state onto that whole set. Use a single
    // abstract object only when no concrete SSA identity is available.
    if keys.is_empty() {
        match flow.node_points_to_object_ids.get(&node.index()).map(Vec::as_slice) {
            Some([id]) => {
                keys.insert(format!("object:{id}"));
            }
            _ => {
                keys.insert(format!("node:{}", node.index()));
            }
        }
    }
    keys.into_iter().collect()
}

fn field_owner_candidates(flow: &FlowGraph, owner: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let mut pending = vec![owner.to_string()];
    while let Some(candidate) = pending.pop() {
        if candidates.contains(&candidate) {
            continue;
        }
        if let Some(parents) = flow.type_hierarchy.get(&candidate) {
            pending.extend(parents.iter().cloned());
        }
        candidates.push(candidate);
    }
    candidates
}

fn transformed_labels(
    transforms: &[LabelTransformEdge],
    labels: &[String],
    from: NodeIndex,
    to: NodeIndex,
) -> Vec<String> {
    let applicable = transforms
        .iter()
        .filter(|edge| {
            edge.from
                .is_none_or(|transform_from| transform_from == from.index())
                && edge.to == to.index()
        })
        .collect::<Vec<_>>();
    if applicable.is_empty() {
        return labels.to_vec();
    }
    let mut result = labels.iter().cloned().collect::<BTreeSet<_>>();
    for edge in applicable {
        result.retain(|label| {
            !edge
                .remove_kinds
                .iter()
                .any(|removed| {
                    if edge.remove_compatible {
                        kind_compatible(label, removed)
                    } else {
                        normalize_kind(label) == normalize_kind(removed)
                    }
                })
        });
        result.extend(
            edge.add_kinds
                .iter()
                .map(|kind| normalize_kind(kind).to_string()),
        );
    }
    result.into_iter().collect()
}

fn kind_compatible(source_kind: &str, other_kind: &str) -> bool {
    let source_kind = normalize_kind(source_kind);
    let other_kind = normalize_kind(other_kind);
    source_kind == "generic" || other_kind == "generic" || source_kind == other_kind
}

fn kind_can_transform_to(rules: &RuleSet, source_kind: &str, sink_kind: &str) -> bool {
    if kind_compatible(source_kind, sink_kind) {
        return true;
    }
    let mut reachable = HashSet::from([normalize_kind(source_kind).to_string()]);
    let mut changed = true;
    while changed {
        changed = false;
        for transform in &rules.taint_transforms {
            let applies = transform.remove_kinds.is_empty()
                || transform.remove_kinds.iter().any(|removed| {
                    reachable.iter().any(|kind| kind_compatible(kind, removed))
                });
            if applies {
                for added in &transform.add_kinds {
                    changed |= reachable.insert(normalize_kind(added).to_string());
                }
            }
        }
    }
    reachable
        .iter()
        .any(|kind| kind_compatible(kind, sink_kind))
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
    use uniflow_rules::{
        ApiMatcher, CallConditionRule, FlowSpec, FunctionMatcher, FunctionSinkRule,
        FunctionSourceRule, LocalizedRuleText, Port, PropagatorRule, RuleMetadata,
        RuleTranslations, SanitizerRule, SinkConditionRule, SinkRule, SourceRule, TaintCondition,
        TaintTransformRule,
    };
    use uniflow_value_flow::build;

    fn analyze_source(language: Language, path: &str, source: &str) -> Vec<TaintFinding> {
        let rules = default_models_for(language.clone());
        let hir = parse_source(language, path, source).expect("source should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        analyze(&flow, &rules)
    }

    fn analyze_with_test_rules(language: Language, path: &str, source: &str) -> Vec<TaintFinding> {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "test-source".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..ApiMatcher::default()
                },
                out: Port::Return,
                kind: "test-data".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "test-sink".to_string(),
                language: Some(language.clone()),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..ApiMatcher::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "test-data".to_string(),
            }],
            ..RuleSet::default()
        };
        let hir = parse_source(language, path, source).expect("source should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        analyze(&flow, &rules)
    }

    #[test]
    fn csharp_named_sink_port_selects_the_labeled_argument_end_to_end() {
        let source = r#"
void Run() {
    var tainted = taint_source();
    var safe = "safe";
    Execute(commandText: safe, value: tainted);
}
"#;
        let analyze_port = |name: &str| {
            let rules = RuleSet {
                sources: vec![SourceRule {
                    id: "csharp-named-source".to_string(),
                    language: Some(Language::CSharp),
                    matcher: ApiMatcher {
                        exact: Some("taint_source".to_string()),
                        ..Default::default()
                    },
                    out: Port::Return,
                    kind: "command".to_string(),
                }],
                sinks: vec![SinkRule {
                    id: "csharp-named-sink".to_string(),
                    language: Some(Language::CSharp),
                    matcher: ApiMatcher {
                        exact: Some("Execute".to_string()),
                        ..Default::default()
                    },
                    inputs: vec![Port::NamedArg(name.to_string())],
                    kind: "command".to_string(),
                }],
                ..Default::default()
            };
            let hir = parse_source(Language::CSharp, "named.cs", source).expect("parse C#");
            let ir = lower_program(&hir);
            let flow = build(&ir, &rules);
            analyze(&flow, &rules)
        };
        assert!(analyze_port("value")
            .iter()
            .any(|finding| finding.sink_rule_id == "csharp-named-sink"));
        assert!(analyze_port("commandText").is_empty());
    }

    #[test]
    fn decorated_function_entry_source_reaches_function_return_sink() {
        let source = r#"
def route(path):
    def decorate(function):
        return function
    return decorate

@route("/hello")
def hello(name):
    return name
"#;
        let matcher = FunctionMatcher {
            decorator_regex: Some(r"(?:^|\.)route$".to_string()),
            ..FunctionMatcher::default()
        };
        let rules = RuleSet {
            function_sources: vec![FunctionSourceRule {
                id: "route-source".to_string(),
                language: Some(Language::Python),
                matcher: matcher.clone(),
                out: Port::ArgsFrom(0),
                kind: "UserControlled".to_string(),
            }],
            function_sinks: vec![FunctionSinkRule {
                id: "route-return".to_string(),
                language: Some(Language::Python),
                matcher,
                inputs: vec![Port::Return],
                kind: "UserControlled".to_string(),
            }],
            ..RuleSet::default()
        };
        let hir = parse_source(Language::Python, "app.py", source).expect("source should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        let findings = analyze(&flow, &rules);
        assert!(findings.iter().any(|finding| {
            finding.source_rule_id == "route-source" && finding.sink_rule_id == "route-return"
        }));
    }

    #[test]
    fn taint_finding_uses_localized_sink_rule_metadata() {
        let rules = RuleSet {
            metadata: vec![RuleMetadata {
                id: "localized-sink".to_string(),
                title: "Command injection".to_string(),
                message: "Untrusted data reaches command execution.".to_string(),
                severity: "error".to_string(),
                cwe: vec!["CWE-78".to_string()],
                standards: vec!["GJB-8114".to_string()],
                translations: RuleTranslations {
                    zh_cn: Some(LocalizedRuleText {
                        title: "命令注入".to_string(),
                        message: "不可信数据到达命令执行接口。".to_string(),
                    }),
                    en: Some(LocalizedRuleText {
                        title: "Command injection".to_string(),
                        message: "Untrusted data reaches command execution.".to_string(),
                    }),
                    zh_tw: Some(LocalizedRuleText {
                        title: "命令注入".to_string(),
                        message: "不可信資料到達命令執行介面。".to_string(),
                    }),
                },
            }],
            sources: vec![SourceRule {
                id: "localized-source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..ApiMatcher::default()
                },
                out: Port::Return,
                kind: "command".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "localized-sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..ApiMatcher::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "command".to_string(),
            }],
            ..RuleSet::default()
        };
        rules.validate().expect("localized rules");
        let hir = parse_source(
            Language::JavaScript,
            "localized.js",
            "const value = taint_source(); sink(value);",
        )
        .expect("source");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        let findings = analyze(&flow, &rules);
        let finding = findings.first().expect("localized taint finding");
        assert_eq!(finding.rule_title, "Command injection");
        assert_eq!(finding.severity, "error");
        assert_eq!(finding.cwe, vec!["CWE-78"]);
        assert_eq!(finding.standards, vec!["GJB-8114"]);
        assert_eq!(
            finding
                .translations
                .zh_tw
                .as_ref()
                .expect("traditional text")
                .message,
            "不可信資料到達命令執行介面。"
        );
    }

    #[test]
    fn output_only_sanitizer_blocks_taint_entering_the_clean_output() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "xss".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "xss".to_string(),
            }],
            sanitizers: vec![SanitizerRule {
                id: "cleanse".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("cleanse".to_string()),
                    ..Default::default()
                },
                inputs: Vec::new(),
                outputs: vec![Port::Return],
                kind: "xss".to_string(),
            }],
            ..Default::default()
        };
        rules.validate().expect("output-only sanitizer rules");
        let hir = parse_source(
            Language::JavaScript,
            "cleanse.js",
            "const clean = cleanse(taint_source()); sink(clean);",
        )
        .expect("source");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        assert!(analyze(&flow, &rules).is_empty());
    }

    #[test]
    fn variadic_propagator_expands_only_over_actual_call_arguments() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            propagators: vec![PropagatorRule {
                id: "join".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("join".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::ArgsFrom(0),
                    to: Port::Return,
                }],
            }],
            ..Default::default()
        };
        rules.validate().expect("variadic propagation rules");
        let hir = parse_source(
            Language::JavaScript,
            "variadic.js",
            "const value = join('prefix', taint_source()); sink(value);",
        )
        .expect("source");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        assert_eq!(analyze(&flow, &rules).len(), 1);
    }

    #[test]
    fn sink_sign_condition_filters_safe_taint_kinds() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "safe-source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("safe_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "safeSql".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "sql-sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            sink_conditions: vec![SinkConditionRule {
                sink_rule_id: "sql-sink".to_string(),
                condition: TaintCondition::Not(Box::new(TaintCondition::HasKind(
                    "safeSql".to_string(),
                ))),
            }],
            ..Default::default()
        };
        rules.validate().expect("conditional sink rules");
        let hir = parse_source(
            Language::JavaScript,
            "sink-condition.js",
            "sink(safe_source());",
        )
        .expect("source");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        assert!(analyze(&flow, &rules).is_empty());
    }

    #[test]
    fn colocated_source_rules_supply_all_labels_to_sink_conditions() {
        let source_rule = |id: &str, kind: &str| SourceRule {
            id: id.to_string(), language: Some(Language::JavaScript),
            matcher: ApiMatcher { exact: Some("input".to_string()), ..Default::default() },
            out: Port::Return, kind: kind.to_string(),
        };
        let rules = RuleSet {
            sources: vec![source_rule("source-alpha", "alpha"), source_rule("source-beta", "beta")],
            sinks: vec![SinkRule { id: "combined-sink".to_string(), language: Some(Language::JavaScript),
                matcher: ApiMatcher { exact: Some("sink".to_string()), ..Default::default() },
                inputs: vec![Port::Arg(0)], kind: "generic".to_string() }],
            sink_conditions: vec![SinkConditionRule { sink_rule_id: "combined-sink".to_string(),
                condition: TaintCondition::All(vec![TaintCondition::HasKind("alpha".to_string()), TaintCondition::HasKind("beta".to_string())]) }],
            ..Default::default()
        };
        rules.validate().unwrap();
        let hir = parse_source(Language::JavaScript, "labels.js", "sink(input());").unwrap();
        let graph = build(&lower_program(&hir), &rules);
        let findings = analyze(&graph, &rules);
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert!(findings.iter().all(|finding| finding.sink_rule_id == "combined-sink"));

        let mut split = rules.clone();
        split.sources[1].matcher.exact = Some("other_input".to_string());
        let graph = build(&lower_program(&hir), &split);
        assert!(analyze(&graph, &split).is_empty());

        let mut alpha_only = rules.clone();
        alpha_only.sinks[0].kind = "alpha".to_string();
        alpha_only.sink_conditions.clear();
        let graph = build(&lower_program(&hir), &alpha_only);
        let findings = analyze(&graph, &alpha_only);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].source_rule_id, "source-alpha");
    }

    #[test]
    fn call_transform_replaces_taint_labels_before_sink_conditions() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "xss-source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "xss".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "html-sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            propagators: vec![PropagatorRule {
                id: "html-encoder-flow".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("encode".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            }],
            taint_transforms: vec![TaintTransformRule {
                id: "html-encoder-labels".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("encode".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                add_kinds: vec!["safeXss".to_string()],
                remove_kinds: vec!["xss".to_string()],
            }],
            sink_conditions: vec![SinkConditionRule {
                sink_rule_id: "html-sink".to_string(),
                condition: TaintCondition::Not(Box::new(TaintCondition::HasKind(
                    "safeXss".to_string(),
                ))),
            }],
            ..Default::default()
        };
        rules.validate().expect("label transform rules");
        assert!(kind_can_transform_to(&rules, "xss", "safeXss"));
        assert!(!kind_can_transform_to(&rules, "xss", "sql"));

        for (expression, expected) in [("taint_source()", 1), ("encode(taint_source())", 0)] {
            let source = format!("sink({expression});");
            let hir =
                parse_source(Language::JavaScript, "label-transform.js", &source).expect("source");
            let ir = lower_program(&hir);
            let flow = build(&ir, &rules);
            assert_eq!(analyze(&flow, &rules).len(), expected, "{expression}");
        }
    }

    #[test]
    fn member_ports_preserve_receiver_field_state_across_calls() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "source".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    method_name: Some("taint_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "sink".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    method_name: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            propagators: vec![
                PropagatorRule {
                    id: "set-job-name".to_string(),
                    language: Some(Language::Java),
                    matcher: ApiMatcher {
                        method_name: Some("setJobName".to_string()),
                        ..Default::default()
                    },
                    flows: vec![FlowSpec {
                        from: Port::Arg(0),
                        to: Port::Member("jobName".to_string()),
                    }],
                },
                PropagatorRule {
                    id: "get-job-name".to_string(),
                    language: Some(Language::Java),
                    matcher: ApiMatcher {
                        method_name: Some("getJobName".to_string()),
                        ..Default::default()
                    },
                    flows: vec![FlowSpec {
                        from: Port::Member("jobName".to_string()),
                        to: Port::Return,
                    }],
                },
            ],
            ..Default::default()
        };
        rules.validate().expect("member port rules");
        let hir = parse_source(
            Language::Java,
            "member-port.java",
            "void run(JobConf conf) { conf.setJobName(taint_source()); sink(conf.getJobName()); }",
        )
        .expect("Java member flow source");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        assert_eq!(analyze(&flow, &rules).len(), 1);
    }

    #[test]
    fn sink_value_conditions_use_call_argument_constants() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "conditional-sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            sink_conditions: vec![SinkConditionRule {
                sink_rule_id: "conditional-sink".to_string(),
                condition: TaintCondition::All(vec![
                    TaintCondition::IsConstant(Port::Arg(1)),
                    TaintCondition::ValueMatches {
                        port: Port::Arg(1),
                        exact: None,
                        regex: Some("^allow$".to_string()),
                    },
                ]),
            }],
            ..Default::default()
        };
        rules.validate().expect("value-conditional sink rules");
        for (literal, expected) in [("allow", 1), ("deny", 0)] {
            let source = format!("sink(taint_source(), '{literal}');");
            let hir =
                parse_source(Language::JavaScript, "value-condition.js", &source).expect("source");
            let ir = lower_program(&hir);
            let flow = build(&ir, &rules);
            assert_eq!(analyze(&flow, &rules).len(), expected, "literal {literal}");
        }
    }

    #[test]
    fn source_call_condition_filters_rule_by_constant_argument() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "tenant-source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("tenant_input".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            call_conditions: vec![CallConditionRule {
                rule_id: "tenant-source".to_string(),
                condition: TaintCondition::ValueMatches {
                    port: Port::Arg(0),
                    exact: Some("tenant-a".to_string()),
                    regex: None,
                },
            }],
            ..Default::default()
        };
        rules.validate().expect("conditional source rule");
        for (tenant, expected) in [("tenant-a", 1), ("tenant-b", 0)] {
            let source = format!("sink(tenant_input('{tenant}'));");
            let hir =
                parse_source(Language::JavaScript, "source-condition.js", &source).expect("source");
            let ir = lower_program(&hir);
            let flow = build(&ir, &rules);
            assert_eq!(analyze(&flow, &rules).len(), expected, "{tenant}");
        }
    }

    #[test]
    fn null_literal_call_condition_controls_sanitizer_activation() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "source".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("taint_source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "xss".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "xss".to_string(),
            }],
            propagators: vec![PropagatorRule {
                id: "sanitize-flow".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sanitize".to_string()),
                    ..Default::default()
                },
                flows: vec![FlowSpec {
                    from: Port::Arg(0),
                    to: Port::Return,
                }],
            }],
            sanitizers: vec![SanitizerRule {
                id: "conditional-sanitizer".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sanitize".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                outputs: vec![Port::Return],
                kind: "xss".to_string(),
            }],
            call_conditions: vec![CallConditionRule {
                rule_id: "conditional-sanitizer".to_string(),
                condition: TaintCondition::ValueMatches {
                    port: Port::Arg(1),
                    exact: Some("<null>".to_string()),
                    regex: None,
                },
            }],
            ..Default::default()
        };
        rules.validate().expect("null-conditional sanitizer");
        for (value, expected) in [("null", 0), ("'enabled'", 1)] {
            let source = format!("sink(sanitize(taint_source(), {value}));");
            let hir =
                parse_source(Language::JavaScript, "null-condition.js", &source).expect("source");
            let ir = lower_program(&hir);
            let flow = build(&ir, &rules);
            assert_eq!(analyze(&flow, &rules).len(), expected, "{value}");
        }
    }

    #[test]
    fn descriptor_languages_reach_unified_taint_engine() {
        let cases = [
            (
                Language::CSharp,
                "void run() { var x = taint_source(); sink(x); }",
                "a.cs",
            ),
            (
                Language::ObjC,
                "void run() { char *x = taint_source(); sink(x); }",
                "a.m",
            ),
            (
                Language::ObjCpp,
                "void run() { char *x = taint_source(); sink(x); }",
                "a.mm",
            ),
            (
                Language::Kotlin,
                "fun run() { val x = taint_source()\n sink(x)\n }",
                "a.kt",
            ),
            (
                Language::Swift,
                "func run() { let x = taint_source()\n sink(x)\n }",
                "a.swift",
            ),
            (
                Language::Go,
                "func run() { x := taint_source()\n sink(x)\n }",
                "a.go",
            ),
            (
                Language::JavaScript,
                "function run() { const x = taint_source(); sink(x); }",
                "a.js",
            ),
            (
                Language::Jsp,
                "<% void run() { int x = taint_source(); sink(x); } %>",
                "a.jsp",
            ),
            (
                Language::Php,
                "<?php function run() { $x = taint_source(); sink($x); } ?>",
                "a.php",
            ),
            (
                Language::Ruby,
                "def run\n x = taint_source()\n sink(x)\nend\n",
                "a.rb",
            ),
            (
                Language::Rust,
                "fn run() { let x = taint_source(); sink(x); }",
                "a.rs",
            ),
            (
                Language::Shell,
                "function run() { local x=taint_source marker\n sink $x\n }",
                "a.sh",
            ),
        ];
        for (language, source, path) in cases {
            let findings = analyze_with_test_rules(language, path, source);
            assert!(
                findings.iter().any(|finding| {
                    finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
                }),
                "missing taint path for {path}: {findings:#?}"
            );
        }
    }

    #[test]
    fn descriptor_lambda_capture_reaches_sink_through_dynamic_call() {
        let findings = analyze_with_test_rules(
            Language::JavaScript,
            "lambda.js",
            "const prefix = taint_source(); const cb = (x) => prefix + x; sink(cb('safe'));",
        );
        assert!(
            findings.iter().any(|finding| {
                finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
            }),
            "captured taint should cross closure construction and invocation: {findings:#?}"
        );
    }

    #[test]
    fn shell_command_substitution_reaches_unified_taint_engine() {
        for substitution in ["$(taint_source dummy)", "`taint_source dummy`"] {
            let source = format!("function run() {{ local x\n x={substitution}\n sink $x\n }}");
            let findings = analyze_with_test_rules(Language::Shell, "command.sh", &source);
            assert!(
                findings.iter().any(|finding| {
                    finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
                }),
                "Shell command substitution dropped taint for {substitution}: {findings:#?}"
            );
        }
    }

    #[test]
    fn php_superglobal_index_reaches_default_system_sink() {
        let findings = analyze_source(
            Language::Php,
            "request.php",
            "<?php function run() { system($_GET[\"cmd\"]); } ?>",
        );
        assert!(
            findings.iter().any(|finding| {
                finding.source_rule_id == "php-portable-untrusted-input"
                    && finding.sink_rule_id == "php-portable-dangerous-operation"
            }),
            "PHP superglobal input should reach system(): {findings:#?}"
        );
    }

    #[test]
    fn java_lambda_capture_reaches_sink_through_functional_interface_call() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "java-lambda-source".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    regex: Some(r"(?:^|\.)taint_source$".to_string()),
                    ..ApiMatcher::default()
                },
                out: Port::Return,
                kind: "test-data".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "java-lambda-sink".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    regex: Some(r"(?:^|\.)sink$".to_string()),
                    ..ApiMatcher::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "test-data".to_string(),
            }],
            ..RuleSet::default()
        };
        let hir = parse_source(
            Language::Java,
            "Worker.java",
            r#"
public class Worker {
    public void run() {
        String prefix = taint_source();
        java.util.function.Function<String, String> cb = x -> prefix + x;
        sink(cb.apply("safe"));
    }
}
"#,
        )
        .expect("Java lambda should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        let calls = flow.call_report();
        let findings = analyze(&flow, &rules);
        assert!(
            findings.iter().any(|finding| {
                finding.source_rule_id == "java-lambda-source"
                    && finding.sink_rule_id == "java-lambda-sink"
            }),
            "Java captured taint should cross the functional call; calls: {calls:#?}; findings: {findings:#?}"
        );
    }

    #[test]
    fn java_bound_method_reference_preserves_captured_receiver_taint() {
        let rules = RuleSet {
            sources: vec![SourceRule {
                id: "method-reference-source".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    regex: Some(r"(?:^|\.)taint_source$".to_string()),
                    ..ApiMatcher::default()
                },
                out: Port::Return,
                kind: "test-data".to_string(),
            }],
            sinks: vec![SinkRule {
                id: "method-reference-sink".to_string(),
                language: Some(Language::Java),
                matcher: ApiMatcher {
                    regex: Some(r"(?:^|\.)sink$".to_string()),
                    ..ApiMatcher::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "test-data".to_string(),
            }],
            ..RuleSet::default()
        };
        let hir = parse_source(
            Language::Java,
            "MethodReference.java",
            r#"
public class MethodReference {
    public void run() {
        String prefix = taint_source();
        java.util.function.Function<String, String> append = prefix::concat;
        sink(append.apply("safe"));
    }
}
"#,
        )
        .expect("Java method reference should parse");
        let ir = lower_program(&hir);
        let flow = build(&ir, &rules);
        let calls = flow.call_report();
        let findings = analyze(&flow, &rules);
        assert!(
            findings.iter().any(|finding| {
                finding.source_rule_id == "method-reference-source"
                    && finding.sink_rule_id == "method-reference-sink"
            }),
            "bound method-reference receiver taint should cross invocation; calls: {calls:#?}; IR: {ir:#?}; findings: {findings:#?}"
        );
    }

    #[test]
    fn cpp_lambda_capture_reaches_sink_through_bound_callable() {
        let findings = analyze_with_test_rules(
            Language::Cpp,
            "lambda.cpp",
            r#"
char *taint_source();
void sink(char *value);
void run() {
    char *prefix = taint_source();
    auto cb = [prefix](char *suffix) { return prefix; };
    sink(cb("safe"));
}
"#,
        );
        assert!(
            findings.iter().any(|finding| {
                finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
            }),
            "C++ bound lambda must preserve captured taint: {findings:#?}"
        );
    }

    #[test]
    fn objective_c_block_capture_reaches_sink() {
        let findings = analyze_with_test_rules(
            Language::ObjC,
            "block.m",
            r#"
id run() {
    id prefix = taint_source();
    id callback = ^(id value) { return prefix; };
    sink(callback(@"safe"));
}
"#,
        );
        assert!(
            findings.iter().any(|finding| {
                finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
            }),
            "Objective-C block must preserve captured taint: {findings:#?}"
        );
    }

    #[test]
    fn interpolated_strings_preserve_taint_in_csharp_and_javascript() {
        let cases = [
            (
                Language::CSharp,
                "var input = taint_source(); sink($\"run {input}\");",
                "interp.cs",
            ),
            (
                Language::JavaScript,
                "const input = taint_source(); sink(`run ${input}`);",
                "interp.js",
            ),
        ];
        for (language, source, path) in cases {
            let findings = analyze_with_test_rules(language.clone(), path, source);
            assert!(
                findings.iter().any(|finding| {
                    finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
                }),
                "{language:?} interpolation dropped taint: {findings:#?}"
            );
        }
    }

    #[test]
    fn multiline_interpolation_preserves_taint_in_kotlin_and_swift() {
        let cases = [
            (
                Language::Kotlin,
                "fun run() {\n val input = taint_source()\n sink(\"\"\"select\n$input\n\"\"\")\n}",
                "multiline.kt",
            ),
            (
                Language::Swift,
                "func run() {\n let input = taint_source()\n sink(\"\"\"select\n\\(input)\n\"\"\")\n}",
                "multiline.swift",
            ),
        ];
        for (language, source, path) in cases {
            let findings = analyze_with_test_rules(language.clone(), path, source);
            assert!(
                findings.iter().any(|finding| {
                    finding.source_rule_id == "test-source" && finding.sink_rule_id == "test-sink"
                }),
                "{language:?} multiline interpolation dropped taint: {findings:#?}"
            );
        }
    }

    #[test]
    fn sql_identifier_flow_reaches_unified_taint_engine() {
        let findings = analyze_source(
            Language::Sql,
            "flow.sql",
            "SELECT secret;\nUPDATE secret SET value = secret;",
        );
        assert!(findings.iter().any(|finding| {
            finding.source_rule_id == "sql-portable-untrusted-input"
                && finding.sink_rule_id == "sql-portable-dangerous-operation"
        }));
    }

    #[test]
    fn objective_c_message_flow_uses_default_models() {
        let findings = analyze_source(
            Language::ObjC,
            "request.m",
            r#"
@implementation Handler
- (void)run:(id)request database:(id)database {
    id value = [request objectForKey:@"key"];
    [database executeQuery:value];
}
@end
"#,
        );
        assert!(findings.iter().any(|finding| {
            finding.source_rule_id == "objc-portable-untrusted-input"
                && finding.sink_rule_id == "objc-portable-dangerous-operation"
        }));
    }

    #[test]
    fn portable_default_models_reach_unified_taint_engine() {
        let cases = [
            (
                Language::CSharp,
                "void run() { var x = ReadLine(); Start(x); }",
                "a.cs",
            ),
            (
                Language::Kotlin,
                "fun run() { val x = readLine()\n exec(x)\n }",
                "a.kt",
            ),
            (
                Language::Swift,
                "func run() { let x = readLine()\n system(x)\n }",
                "a.swift",
            ),
            (
                Language::Go,
                "func run() { x := Getenv(\"X\")\n Command(x)\n }",
                "a.go",
            ),
            (
                Language::JavaScript,
                "function run() { const x = prompt(); eval(x); }",
                "a.js",
            ),
            (
                Language::Jsp,
                "<% void run() { Object x = getParameter(\"x\"); executeQuery(x); } %>",
                "a.jsp",
            ),
            (
                Language::Php,
                "<?php function run() { $x = getenv(\"X\"); system($x); } ?>",
                "a.php",
            ),
            (
                Language::Ruby,
                "def run\n x = gets()\n system(x)\nend\n",
                "a.rb",
            ),
            (
                Language::Rust,
                "fn run(dummy) { let x = var(\"X\"); sqlx_query!(x); }",
                "a.rs",
            ),
            (
                Language::Shell,
                "function run() { local x\n read x\n eval $x\n }",
                "a.sh",
            ),
        ];
        for (language, source, path) in cases {
            let rules = default_models_for(language.clone());
            let hir = parse_source(language.clone(), path, source).expect("source should parse");
            let ir = lower_program(&hir);
            let flow = build(&ir, &rules);
            let calls = flow.call_report();
            let findings = analyze(&flow, &rules);
            assert!(
                !findings.is_empty(),
                "default models produced no taint path for {language:?}; calls: {calls:#?}"
            );
        }
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
    fn detects_c_out_parameter_source_to_sink() {
        let findings = analyze_source(
            Language::C,
            "buffer.c",
            r#"
char *fgets(char *buffer, int size, void *stream);
int system(const char *command);
int main(void) {
    char buffer[128];
    fgets(buffer, 128, 0);
    return system(buffer);
}
"#,
        );
        assert!(findings.iter().any(|finding| {
            finding.source_rule_id == "c-fgets-buffer" && finding.sink_rule_id == "c-system"
        }));
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
        let forward = forward
            .traversal
            .visited
            .into_iter()
            .collect::<HashSet<_>>();
        let backward = backward
            .traversal
            .visited
            .into_iter()
            .collect::<HashSet<_>>();
        assert!(finding
            .path
            .iter()
            .all(|node| forward.contains(node) && backward.contains(node)));
    }
}
