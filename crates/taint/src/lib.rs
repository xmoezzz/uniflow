use petgraph::{Direction, graph::NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use uniflow_rules::{
    expand_port, language_matches, ApiMatcherIndex, Port, RuleMetadata, RuleSet,
    RuleTranslations, TaintCondition,
};
use uniflow_value_flow::{
    DemandEngine, DemandQuery, DemandReachability, EdgeKind, FlowGraph, FlowNode,
    QueryCompleteness, SparseDirection,
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

type LabelTransformMap = HashMap<usize, Vec<LabelTransformEdge>>;

/// Source groups whose demand slices are computed in parallel before their
/// witnesses are searched sequentially.
const PARALLEL_SLICE_CHUNK: usize = 256;

// A project can have hundreds of broad source and sink models. Materializing a
// witness (labels, locations, and every edge) for their Cartesian product is
// not useful to a reviewer and used to exhaust memory before the CLI could
// print a result. So a witness is materialized once per (sink node, sink
// rule) — the unit a reviewer triages; every further source reaching an
// already-reported sink is skipped before any path search — and this cap
// only bounds the number of *distinct* sinks. It used to be 512 findings
// counted across the source×sink product, which silently truncated any
// real project (a 2,700-file Java app hit it) long before memory was a
// concern. The limit is explicit in the returned findings below.
const MAX_MATERIALIZED_TAINT_FINDINGS: usize = 20_000;

/// States one witness search may visit before giving up (see
/// `find_contextual_path_to_sink`).
const MAX_WITNESS_SEARCH_STATES: usize = 4_000;

/// Failure budget per sink before it stops being retried. Sinks reachable
/// in the coarse demand slice but not under label/context rules would
/// otherwise be re-searched once per source in the project. A search that
/// ran out of states costs `EXHAUSTED_WITNESS_FAILURE_COST`; one that proved
/// the negative quickly costs 1, so a function whose many parameters reach
/// one call (only some of them feeding the sink port) is still fully tried.
const MAX_FAILED_WITNESS_ATTEMPTS_PER_SINK: u8 = 8;
const EXHAUSTED_WITNESS_FAILURE_COST: u8 = 4;

/// Rule-family indexes are built once per taint run. They preserve the final
/// matcher check while avoiding an O(calls × all-models) regex walk.
struct TaintMatcherIndex<'a> {
    sanitizers: ApiMatcherIndex<'a>,
    transforms: ApiMatcherIndex<'a>,
    propagators: ApiMatcherIndex<'a>,
}

impl<'a> TaintMatcherIndex<'a> {
    fn new(rules: &'a RuleSet) -> Self {
        Self {
            sanitizers: ApiMatcherIndex::new(rules.sanitizers.iter().map(|rule| &rule.matcher)),
            transforms: ApiMatcherIndex::new(
                rules.taint_transforms.iter().map(|rule| &rule.matcher),
            ),
            propagators: ApiMatcherIndex::new(
                rules.propagators.iter().map(|rule| &rule.matcher),
            ),
        }
    }
}

fn default_true() -> bool {
    true
}

pub fn analyze(flow: &FlowGraph, rules: &RuleSet) -> Vec<TaintFinding> {
    let source_seeds = collect_source_seeds(flow);
    let sink_seeds = collect_sink_seeds(flow);
    if source_seeds.is_empty() || sink_seeds.is_empty() {
        let mut findings = lifetime_findings(flow, rules);
        findings.extend(native_dataflow_findings(flow, rules));
        return findings;
    }
    let matcher_index = TaintMatcherIndex::new(rules);
    let label_transforms = build_label_transform_map(flow, rules, &matcher_index);
    let receiver_side_labels = build_receiver_side_labels(flow, rules, &matcher_index);
    // Normalized taint kinds as small integers: the (source kind, sink kind)
    // compatibility check runs for every source × sink pair in a slice, and
    // keying its cache on two freshly allocated Strings dominated the loop.
    let mut kinds = KindIds::default();
    let mut kind_transform_cache = FxHashMap::<(u32, u32), bool>::default();
    let sink_kind_ids: Vec<u32> = sink_seeds.iter().map(|sink| kinds.id(&sink.kind)).collect();
    let mut sinks_by_node = FxHashMap::<u32, Vec<usize>>::default();
    for (index, sink) in sink_seeds.iter().enumerate() {
        sinks_by_node.entry(sink.node.index() as u32).or_default().push(index);
    }
    let mut findings = Vec::new();
    let mut seen = HashSet::new();
    // Source rules that already have a witness at each (sink node, sink rule);
    // borrowed sink rule ids live as long as `sink_seeds`. Keying on the
    // source *rule* keeps one finding per distinct source model (colocated
    // models carry different labels) while every further call site of the
    // same model reaching an already-reported sink is skipped.
    let mut reported_sinks: FxHashMap<(usize, &str), Vec<String>> = FxHashMap::default();
    let already_reported = |reported: &FxHashMap<(usize, &str), Vec<String>>,
                            key: &(usize, &str),
                            source_rule: &str| {
        reported
            .get(key)
            .is_some_and(|rules| rules.iter().any(|rule| rule == source_rule))
    };
    let mut failed_attempts: FxHashMap<(usize, &str), u8> = FxHashMap::default();
    let mut result_limit_reached = false;

    // Several bundled models can mark the same output port as different taint
    // kinds. Their witness labels remain distinct, but the forward graph slice
    // is identical. Compute that slice once per output port and process each
    // source model against it while the bit-vector is still live.
    let mut source_groups: HashMap<usize, (usize, Vec<SourceSeed>)> = HashMap::new();
    for (position, source) in source_seeds.into_iter().enumerate() {
        let key = flow
            .graph
            .edges(source.node)
            .next()
            .map(|edge| edge.target().index())
            .unwrap_or_else(|| source.node.index());
        let group = source_groups.entry(key).or_insert_with(|| (position, Vec::new()));
        group.1.push(source);
    }
    let mut source_groups = source_groups.into_values().collect::<Vec<_>>();
    source_groups.sort_unstable_by_key(|(first_position, _)| *first_position);

    // Forward and backward demand slices are pure reads of the flow graph, so
    // they are computed in parallel one chunk of source groups at a time. The
    // witness search below stays sequential in source order: which source
    // reports a sink first (and therefore the emitted witness) must not depend
    // on thread scheduling.
    let forward_query = DemandQuery {
        seeds: Vec::new(),
        direction: SparseDirection::Forward,
        engine: DemandEngine::Fixpoint,
        include_heap: true,
    };
    let forward_plan = flow.solver_plan_for_query(&forward_query);
    let backward_query = DemandQuery {
        seeds: Vec::new(),
        direction: SparseDirection::Backward,
        engine: DemandEngine::Fixpoint,
        include_heap: true,
    };
    let backward_plan = flow.solver_plan_for_query(&backward_query);
    let forward_slice = |node: NodeIndex| {
        flow.one_shot_node_reachability(
            node,
            forward_plan.query.direction,
            forward_plan.query.engine,
            forward_plan.max_depth,
            forward_plan.max_visits,
            forward_plan.query.include_heap,
        )
    };
    // The backward slice from a sink is taken inside the source's forward
    // slice: any witness lies in both, and a global backward slice per sink
    // is both larger and not reusable across sources without a cache that
    // grows with `sinks × budget`.
    let backward_slice = |node: NodeIndex, forward_nodes: &DemandReachability| {
        flow.one_shot_node_reachability_within(
            node,
            backward_plan.query.direction,
            backward_plan.query.engine,
            backward_plan.max_depth,
            backward_plan.max_visits,
            backward_plan.query.include_heap,
            Some(forward_nodes),
        )
    };

    let mut allowed_scratch = AllowedNodes::default();
    let mut remaining_groups = source_groups.into_iter().map(|(_, sources)| sources);
    'sources: loop {
        let chunk = remaining_groups
            .by_ref()
            .take(PARALLEL_SLICE_CHUNK)
            .collect::<Vec<_>>();
        if chunk.is_empty() {
            break;
        }
        let forward_slices = chunk
            .par_iter()
            .map(|sources| {
                let representative = sources
                    .first()
                    .expect("a source group is created from at least one source");
                forward_slice(representative.node)
            })
            .collect::<Vec<_>>();
        for (sources, forward_nodes) in chunk.into_iter().zip(forward_slices) {
            // Prefetch, in parallel, the backward slices the sequential loop
            // below will request for this group (same kind, event-order and
            // already-reported filters). Holding one group's slices at a time
            // bounds memory by that group's sink fan-out.
            // Sinks inside this group's forward slice, in `sink_seeds` order —
            // the same for every source of the group, so filtered once.
            // Walk whichever side is smaller: a project has far more sinks
            // than one source's slice usually holds, and testing every sink
            // against every group's slice was quadratic in project size.
            let sinks_in_slice: Vec<usize> = if forward_nodes.len() < sink_seeds.len() {
                let mut hits: Vec<usize> =
                    forward_nodes.node_ids().iter().filter_map(|id| sinks_by_node.get(id)).flatten().copied().collect();
                hits.sort_unstable();
                hits
            } else {
                (0..sink_seeds.len()).filter(|&i| forward_nodes.contains(sink_seeds[i].node.index())).collect()
            };
            let mut wanted = Vec::new();
            for source in &sources {
                let source_kind = kinds.id(&source.kind);
                for &sink_index in &sinks_in_slice {
                    let sink = &sink_seeds[sink_index];
                    let sink_key = (sink.node.index(), sink.rule_id.as_str());
                    if already_reported(&reported_sinks, &sink_key, &source.rule_id)
                        || failed_attempts
                            .get(&sink_key)
                            .is_some_and(|n| *n >= MAX_FAILED_WITNESS_ATTEMPTS_PER_SINK)
                    {
                        continue;
                    }
                    let kind_key = (source_kind, sink_kind_ids[sink_index]);
                    let kind_reachable = *kind_transform_cache.entry(kind_key).or_insert_with(|| {
                        kind_can_transform_to(rules, kinds.name(kind_key.0), kinds.name(kind_key.1))
                    });
                    if kind_reachable && source_event_can_reach_sink(flow, source.node, sink.node) {
                        wanted.push(sink.node);
                    }
                }
            }
            wanted.sort_unstable();
            wanted.dedup();
            // Each backward slice is kept with its intersection with this
            // group's forward slice: the witness search only ever asks
            // "is this node in both?", so it probes one precomputed set.
            let with_intersection = |backward: DemandReachability| {
                let both = forward_nodes.intersection_ids(&backward);
                (backward, both)
            };
            let mut backward_slices = wanted
                .par_iter()
                .map(|sink| (sink.index(), with_intersection(backward_slice(*sink, &forward_nodes))))
                .collect::<HashMap<_, _>>();

            for source in sources {
                let source_kind = kinds.id(&source.kind);
                for &sink_index in &sinks_in_slice {
                    let sink = &sink_seeds[sink_index];
                    let sink_key = (sink.node.index(), sink.rule_id.as_str());
                    if already_reported(&reported_sinks, &sink_key, &source.rule_id)
                        || failed_attempts.get(&sink_key).is_some_and(|n| *n >= MAX_FAILED_WITNESS_ATTEMPTS_PER_SINK)
                    {
                        continue;
                    }
                    if findings.len() >= MAX_MATERIALIZED_TAINT_FINDINGS {
                        result_limit_reached = true;
                        break 'sources;
                    }
                    let kind_key = (source_kind, sink_kind_ids[sink_index]);
                    let kind_reachable = *kind_transform_cache.entry(kind_key).or_insert_with(|| {
                        kind_can_transform_to(rules, kinds.name(kind_key.0), kinds.name(kind_key.1))
                    });
                    if !kind_reachable {
                        continue;
                    }
                    if !source_event_can_reach_sink(flow, source.node, sink.node) {
                        continue;
                    }
                    // A forward demand summary tells us which nodes may be influenced by the source.
                    // A sink-specific backward summary removes nodes that cannot contribute to this
                    // sink. The witness search is therefore constrained to the bidirectional demand
                    // slice, rather than falling back to an unrestricted whole-graph taint traversal.
                    let (backward_nodes, allowed_ids) = &*backward_slices
                        .entry(sink.node.index())
                        .or_insert_with(|| with_intersection(backward_slice(sink.node, &forward_nodes)));

                    let context_limit = forward_plan
                        .max_depth
                        .max(backward_plan.max_depth)
                        .clamp(8, 32);
                    let mut budget_exhausted = false;
                    let Some((path, context_truncated, _sink_labels)) = find_contextual_path_to_sink(
                        flow,
                        rules,
                        &label_transforms,
                        &receiver_side_labels,
                        &source,
                        &sink,
                        allowed_ids,
                        &mut allowed_scratch,
                        context_limit,
                        &mut budget_exhausted,
                    ) else {
                        let cost = if budget_exhausted {
                            EXHAUSTED_WITNESS_FAILURE_COST
                        } else {
                            1
                        };
                        let spent = failed_attempts.entry(sink_key).or_default();
                        *spent = spent.saturating_add(cost);
                        continue;
                    };

                    let mut completeness = merge_completeness(
                        forward_nodes.completeness,
                        backward_nodes.completeness,
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
                        reported_sinks
                            .entry((sink.node.index(), sink.rule_id.as_str()))
                            .or_default()
                            .push(source.rule_id.clone());
                        findings.push(finding);
                    }
                }
            }
        }
    }

    if result_limit_reached {
        findings.push(taint_result_limit_finding());
    }

    findings.extend(lifetime_findings(flow, rules));
    findings.extend(native_dataflow_findings(flow, rules));
    findings
}

fn taint_result_limit_finding() -> TaintFinding {
    TaintFinding {
        source_rule_id: "UNIFLOW-TAINT-RESULT-LIMIT".to_string(),
        sink_rule_id: "UNIFLOW-TAINT-RESULT-LIMIT".to_string(),
        source_kind: "analysis-limit".to_string(),
        sink_kind: "analysis-limit".to_string(),
        sink_node: 0,
        path: Vec::new(),
        source_label: "taint finding budget".to_string(),
        sink_label: "taint finding budget".to_string(),
        source_location: "@analysis".to_string(),
        sink_location: "@analysis".to_string(),
        path_labels: Vec::new(),
        steps: Vec::new(),
        finding_kind: "analysis-limit".to_string(),
        severity: "warning".to_string(),
        message: format!(
            "Taint result budget of {MAX_MATERIALIZED_TAINT_FINDINGS} findings reached; refine rule IDs or split the scan to inspect additional results."
        ),
        rule_title: "Taint result limit reached".to_string(),
        cwe: Vec::new(),
        standards: Vec::new(),
        translations: RuleTranslations::default(),
        analysis_complete: false,
        completeness: QueryCompleteness::VisitLimitReached,
    }
}

#[derive(Clone, Debug)]
struct SinkSeed {
    node: NodeIndex,
    rule_id: String,
    kind: String,
}

fn collect_sink_seeds(flow: &FlowGraph) -> Vec<SinkSeed> {
    flow.synthetic_sinks
        .iter()
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

fn source_event_can_reach_sink(
    flow: &FlowGraph,
    source_node: NodeIndex,
    sink_node: NodeIndex,
) -> bool {
    let FlowNode::SyntheticSource {
        func: source_func,
        inst: source_inst,
        ..
    } = flow.graph[source_node]
    else {
        return true;
    };
    let FlowNode::SyntheticSink {
        func: sink_func,
        inst: sink_inst,
        ..
    } = flow.graph[sink_node]
    else {
        return true;
    };
    if source_func != sink_func {
        return true;
    }
    let Some(&(source_block, source_position)) = flow
        .inst_control_positions
        .get(&(source_func, source_inst))
    else {
        return true;
    };
    let Some(&(sink_block, sink_position)) =
        flow.inst_control_positions.get(&(sink_func, sink_inst))
    else {
        return true;
    };
    if source_block == sink_block && source_position <= sink_position {
        return true;
    }

    // Start at successors rather than at source_block. For a later source and
    // earlier sink in the same block, only a real CFG cycle makes the sink
    // reachable in a subsequent iteration.
    let mut pending = flow
        .block_successors
        .get(&(source_func, source_block))
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect::<VecDeque<_>>();
    let mut visited = HashSet::new();
    while let Some(block) = pending.pop_front() {
        if block == sink_block {
            return true;
        }
        if !visited.insert(block) {
            continue;
        }
        pending.extend(
            flow.block_successors
                .get(&(source_func, block))
                .into_iter()
                .flatten()
                .copied(),
        );
    }
    false
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

/// Normalized taint kind strings interned to small integers.
#[derive(Default)]
struct KindIds {
    ids: FxHashMap<String, u32>,
    names: Vec<String>,
}

impl KindIds {
    fn id(&mut self, kind: &str) -> u32 {
        let kind = normalize_kind(kind);
        if let Some(&id) = self.ids.get(kind) {
            return id;
        }
        let id = self.names.len() as u32;
        self.names.push(kind.to_string());
        self.ids.insert(kind.to_string(), id);
        id
    }

    fn name(&self, id: u32) -> &str {
        &self.names[id as usize]
    }
}

/// Interned label sets: a witness state carries a `u32` instead of a
/// `Vec<String>` that every expansion used to clone and SipHash twice.
/// Identity is exact vector equality — the same notion of "same state" the
/// search had before — so the explored state space is unchanged.
#[derive(Default)]
struct LabelSets {
    sets: Vec<Vec<String>>,
    index: FxHashMap<Vec<String>, u32>,
    transformed: FxHashMap<(u32, u32, u32), u32>,
}

impl LabelSets {
    fn intern(&mut self, labels: Vec<String>) -> u32 {
        if let Some(&id) = self.index.get(&labels) {
            return id;
        }
        let id = self.sets.len() as u32;
        self.sets.push(labels.clone());
        self.index.insert(labels, id);
        id
    }

    fn get(&self, id: u32) -> &[String] {
        &self.sets[id as usize]
    }

    /// `transformed_labels`, memoized: it depends only on the label set and
    /// the edge, and most edges have no transform at all.
    fn transform(&mut self, transforms: &LabelTransformMap, id: u32, from: NodeIndex, to: NodeIndex) -> u32 {
        if !transforms.contains_key(&to.index()) {
            return id;
        }
        let key = (id, from.index() as u32, to.index() as u32);
        if let Some(&out) = self.transformed.get(&key) {
            return out;
        }
        let out = transformed_labels(transforms, self.get(id), from, to);
        let out = self.intern(out);
        self.transformed.insert(key, out);
        out
    }
}

/// Call stacks as a persistent linked list in an arena: id 0 is the empty
/// stack, every other id is one frame (parent id + call site). Each
/// distinct site sequence gets exactly one id, so comparing ids compares
/// stacks.
struct CallStacks {
    frames: Vec<(u32, (u32, u32), u32)>, // (parent, site, depth)
    index: FxHashMap<(u32, (u32, u32)), u32>,
}

impl CallStacks {
    fn new() -> Self {
        Self { frames: vec![(0, (0, 0), 0)], index: FxHashMap::default() }
    }

    fn push(&mut self, parent: u32, site: (u32, u32)) -> u32 {
        if let Some(&id) = self.index.get(&(parent, site)) {
            return id;
        }
        let id = self.frames.len() as u32;
        let depth = self.frames[parent as usize].2 + 1;
        self.frames.push((parent, site, depth));
        self.index.insert((parent, site), id);
        id
    }

    fn top(&self, id: u32) -> Option<(u32, u32)> {
        (id != 0).then(|| self.frames[id as usize].1)
    }

    fn parent(&self, id: u32) -> u32 {
        self.frames[id as usize].0
    }

    fn depth(&self, id: u32) -> usize {
        self.frames[id as usize].2 as usize
    }

    /// Drops the oldest frames so at most `limit` remain (the context bound).
    fn keep_newest(&mut self, id: u32, limit: usize) -> u32 {
        let mut sites = Vec::with_capacity(self.depth(id));
        let mut cur = id;
        while cur != 0 {
            sites.push(self.frames[cur as usize].1);
            cur = self.parent(cur);
        }
        sites.reverse();
        let excess = sites.len().saturating_sub(limit);
        sites[excess..].iter().fold(0, |stack, site| self.push(stack, *site))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct WitnessState {
    node: u32,
    labels: u32,
    stack: u32,
    truncated: bool,
}

/// Bitmap over flow-graph nodes marking forward ∩ backward for the sink
/// being searched; reused across searches and cleared through the id list.
#[derive(Default)]
pub(crate) struct AllowedNodes {
    words: Vec<u64>,
}

impl AllowedNodes {
    fn mark(&mut self, ids: &[u32], node_count: usize) {
        let needed = node_count.div_ceil(64);
        if self.words.len() < needed {
            self.words.resize(needed, 0);
        }
        for &id in ids {
            self.words[(id / 64) as usize] |= 1 << (id % 64);
        }
    }

    fn clear(&mut self, ids: &[u32]) {
        for &id in ids {
            self.words[(id / 64) as usize] &= !(1 << (id % 64));
        }
    }

    fn contains(&self, id: usize) -> bool {
        self.words.get(id / 64).is_some_and(|word| word & (1 << (id % 64)) != 0)
    }
}

#[allow(clippy::too_many_arguments)]
fn find_contextual_path_to_sink(
    flow: &FlowGraph,
    rules: &RuleSet,
    label_transforms: &LabelTransformMap,
    receiver_side_labels: &HashMap<(u32, u32), Vec<String>>,
    source: &SourceSeed,
    sink: &SinkSeed,
    allowed_ids: &[u32],
    allowed: &mut AllowedNodes,
    context_limit: usize,
    budget_exhausted: &mut bool,
) -> Option<(Vec<usize>, bool, Vec<String>)> {
    allowed.mark(allowed_ids, flow.graph.node_count());
    let result = search_witness(flow, rules, label_transforms, receiver_side_labels, source, sink, allowed, context_limit, budget_exhausted);
    allowed.clear(allowed_ids);
    result
}

#[allow(clippy::too_many_arguments)]
fn search_witness(
    flow: &FlowGraph,
    rules: &RuleSet,
    label_transforms: &LabelTransformMap,
    receiver_side_labels: &HashMap<(u32, u32), Vec<String>>,
    source: &SourceSeed,
    sink: &SinkSeed,
    allowed: &AllowedNodes,
    context_limit: usize,
    budget_exhausted: &mut bool,
) -> Option<(Vec<usize>, bool, Vec<String>)> {
    let mut labels = LabelSets::default();
    let mut stacks = CallStacks::new();
    let start = WitnessState { node: source.node.index() as u32, labels: labels.intern(source.labels.clone()), stack: 0, truncated: false };
    let mut queue = VecDeque::from([start]);
    let mut visited = FxHashSet::default();
    visited.insert(start);
    let mut parent = FxHashMap::<WitnessState, WitnessState>::default();
    let sink_condition = rules.sink_conditions.iter().find(|condition| condition.sink_rule_id == sink.rule_id);

    while let Some(state) = queue.pop_front() {
        // The (node, labels, call stack) state space is exponential in the
        // worst case; a witness that exists is found within a few thousand
        // states on real code, so an unbounded search only ever burns time
        // proving a negative (it turned a 17 s benchmark into >10 min).
        if visited.len() > MAX_WITNESS_SEARCH_STATES {
            *budget_exhausted = true;
            return None;
        }
        let node = NodeIndex::new(state.node as usize);
        if node == sink.node {
            let mut sink_labels = labels.get(state.labels).to_vec();
            if let FlowNode::SyntheticSink { func, inst, .. } = flow.graph[sink.node] {
                sink_labels.extend(receiver_side_labels.get(&(func.0, inst.0)).into_iter().flatten().cloned());
                sink_labels.sort();
                sink_labels.dedup();
            }
            if live_for_sink(&sink_labels, &sink.kind)
                && sink_condition.is_none_or(|condition| sink_condition_matches(flow, sink.node, &condition.condition, &sink_labels))
            {
                let mut path = vec![state.node as usize];
                let mut cur = state;
                while cur != start {
                    let Some(prev) = parent.get(&cur) else { break };
                    path.push(prev.node as usize);
                    cur = *prev;
                }
                path.reverse();
                return Some((path, state.truncated, sink_labels));
            }
        }
        for edge in flow.graph.edges(node) {
            let next_node = edge.target();
            if next_node != source.node && next_node != sink.node && !allowed.contains(next_node.index()) {
                continue;
            }
            let Some((stack, truncated)) = transition_stack(flow, &mut stacks, state, node, next_node, &edge.weight().kind, context_limit) else {
                continue;
            };
            let next_labels = labels.transform(label_transforms, state.labels, edge.source(), next_node);
            if labels.get(next_labels).is_empty() {
                continue;
            }
            let next_state = WitnessState { node: next_node.index() as u32, labels: next_labels, stack, truncated };
            if visited.insert(next_state) {
                parent.insert(next_state, state);
                queue.push_back(next_state);
            }
        }
    }
    None
}

/// Context-sensitive call matching: entering a callee pushes the call
/// site (bounded by `context_limit`, oldest frames dropped), returning must
/// pop the matching site; an empty stack may return anywhere.
fn transition_stack(
    flow: &FlowGraph,
    stacks: &mut CallStacks,
    state: WitnessState,
    node: NodeIndex,
    next_node: NodeIndex,
    edge_kind: &EdgeKind,
    context_limit: usize,
) -> Option<(u32, bool)> {
    match edge_kind {
        EdgeKind::ActualToFormal => {
            let site = call_site_of(&flow.graph[node])?;
            let pushed = stacks.push(state.stack, site);
            if stacks.depth(pushed) > context_limit {
                return Some((stacks.keep_newest(pushed, context_limit), true));
            }
            Some((pushed, state.truncated))
        }
        EdgeKind::FormalToActual => {
            let site = call_site_of(&flow.graph[next_node])?;
            match stacks.top(state.stack) {
                Some(active) if active != site => None,
                Some(_) => Some((stacks.parent(state.stack), state.truncated)),
                None => Some((state.stack, state.truncated)),
            }
        }
        _ => Some((state.stack, state.truncated)),
    }
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

fn call_site_of(node: &FlowNode) -> Option<(u32, u32)> {
    match node {
        FlowNode::CallPort { func, inst, .. }
        | FlowNode::SyntheticSource { func, inst, .. }
        | FlowNode::SyntheticSink { func, inst, .. } => Some((func.0, inst.0)),
        _ => None,
    }
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
        if let FlowNode::SyntheticSource {
            func,
            inst,
            kind,
            out,
            ..
        } = &flow.graph[*idx]
        {
            colocated
                .entry((func.0, inst.0, out.clone()))
                .or_default()
                .push(normalize_kind(kind).to_string());
        }
    }
    for labels in colocated.values_mut() {
        labels.sort();
        labels.dedup();
    }
    flow.synthetic_sources
        .iter()
        .filter_map(|idx| match &flow.graph[*idx] {
            FlowNode::SyntheticSource {
                func,
                inst,
                rule_id,
                kind,
                out,
            } => Some(SourceSeed {
                node: *idx,
                rule_id: rule_id.clone(),
                kind: kind.clone(),
                labels: colocated
                    .get(&(func.0, inst.0, out.clone()))
                    .cloned()
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
            .map(|item| truncate_finding_translation(&item.message))
            .filter(|message| !message.trim().is_empty())
            .unwrap_or(fallback_message),
        rule_title: metadata.map(|item| item.title.clone()).unwrap_or_default(),
        cwe: finding_cwes(metadata, sink_kind, sink_rule_id),
        standards: metadata
            .map(|item| item.standards.clone())
            .unwrap_or_default(),
        translations: metadata
            .map(|item| compact_finding_translations(item.translations.clone()))
            .unwrap_or_default(),
        analysis_complete: completeness == QueryCompleteness::Complete,
        completeness,
    }
}

/// The finding's CWE(s): the rule's own when it has any; otherwise the
/// weakness its sink kind names (`sql`, `command`, … — the MIT and built-in
/// models' only classification), then whatever class its title/message
/// names. Without this last resort a finding with a real flow but a
/// metadata-less rule could never be grouped, scored or put in a standards
/// book (see `uniflow_rules::vuln_class`). The very last signal is the sink
/// kind and rule id *text* (`semgrep.….aws-lambda-event` /
/// `…-tainted-shell-call`, `…-log-forging`), which for converted third-party
/// packs is often the only place the weakness is named.
fn finding_cwes(metadata: Option<&RuleMetadata>, sink_kind: &str, sink_rule_id: &str) -> Vec<String> {
    if let Some(cwe) = metadata.map(|item| &item.cwe).filter(|cwe| !cwe.is_empty()) {
        return cwe.clone();
    }
    uniflow_rules::vuln_class::for_sink_kind(sink_kind)
        .or_else(|| metadata.and_then(|item| uniflow_rules::vuln_class::classify_category(&format!("{} {}", item.title, item.message))))
        .or_else(|| uniflow_rules::vuln_class::classify_category(&format!("{sink_kind} {sink_rule_id}")))
        .map(|class| vec![class.cwe_id()])
        .unwrap_or_default()
}

fn lifetime_findings(flow: &FlowGraph, rules: &RuleSet) -> Vec<TaintFinding> {
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
            let metadata = rules.metadata_for(&diagnostic.rule_id);
            let message = metadata
                .map(|item| item.message.clone())
                .filter(|message| !message.trim().is_empty())
                .unwrap_or_else(|| diagnostic.message.clone());
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
                message: truncate_finding_translation(&message),
                rule_title: metadata
                    .map(|item| item.title.clone())
                    .filter(|title| !title.trim().is_empty())
                    .unwrap_or_else(|| diagnostic.message.clone()),
                cwe: metadata.map(|item| item.cwe.clone()).unwrap_or_default(),
                standards: metadata
                    .map(|item| item.standards.clone())
                    .unwrap_or_default(),
                translations: metadata
                    .map(|item| compact_finding_translations(item.translations.clone()))
                    .unwrap_or_default(),
                analysis_complete: true,
                completeness: QueryCompleteness::Complete,
            }
        })
        .collect()
}

fn native_dataflow_findings(flow: &FlowGraph, rules: &RuleSet) -> Vec<TaintFinding> {
    flow.native_dataflow_diagnostics
        .iter()
        .filter(|diagnostic| {
            rules.native_dataflow_rules.iter().any(|rule| {
                rule.id == diagnostic.rule_id && language_matches(&rule.language, &flow.language)
            })
        })
        .map(|diagnostic| {
            let node = flow
                .values
                .get(&(diagnostic.function, diagnostic.value))
                .copied();
            let path = node.map(|node| vec![node.index()]).unwrap_or_default();
            let location = flow.span_text(&diagnostic.span);
            let metadata = rules.metadata_for(&diagnostic.rule_id);
            let message = metadata
                .map(|metadata| format_message_template(&metadata.message, &diagnostic.message_args))
                .filter(|message| !message.trim().is_empty())
                .unwrap_or_else(|| diagnostic.message.clone());
            let translations = metadata
                .map(|metadata| {
                    let mut translations = metadata.translations.clone();
                    if let Some(text) = translations.zh_cn.as_mut() {
                        text.message =
                            format_message_template(&text.message, &diagnostic.message_args);
                    }
                    if let Some(text) = translations.en.as_mut() {
                        text.message =
                            format_message_template(&text.message, &diagnostic.message_args);
                    }
                    if let Some(text) = translations.zh_tw.as_mut() {
                        text.message =
                            format_message_template(&text.message, &diagnostic.message_args);
                    }
                    translations
                })
                .unwrap_or_default();
            TaintFinding {
                source_rule_id: diagnostic.rule_id.clone(),
                sink_rule_id: diagnostic.rule_id.clone(),
                source_kind: diagnostic.finding_kind.clone(),
                sink_kind: diagnostic.finding_kind.clone(),
                sink_node: node.map(NodeIndex::index).unwrap_or(0),
                path: path.clone(),
                source_label: message.clone(),
                sink_label: message.clone(),
                source_location: location.clone(),
                sink_location: location,
                path_labels: vec![message.clone()],
                steps: Vec::new(),
                finding_kind: diagnostic.finding_kind.clone(),
                severity: metadata
                    .map(|metadata| metadata.severity.clone())
                    .filter(|severity| !severity.trim().is_empty())
                    .unwrap_or_else(|| diagnostic.severity.clone()),
                message: truncate_finding_translation(&message),
                rule_title: metadata
                    .map(|metadata| metadata.title.clone())
                    .unwrap_or_else(|| diagnostic.rule_id.clone()),
                cwe: metadata.map(|metadata| metadata.cwe.clone()).unwrap_or_default(),
                standards: metadata
                    .map(|metadata| metadata.standards.clone())
                    .unwrap_or_default(),
                translations: compact_finding_translations(translations),
                analysis_complete: true,
                completeness: QueryCompleteness::Complete,
            }
        })
        .collect()
}

// Legacy rule packs may embed full knowledge-base articles (including long
// code samples) in each localized message. A finding is intentionally a
// compact scan result, while the RuleSet remains the canonical full catalog.
// Capping the per-finding copy prevents an N-findings × N-locales allocation
// explosion without losing the title or actionable opening of the message.
const MAX_FINDING_TRANSLATION_BYTES: usize = 4_096;

fn compact_finding_translations(mut translations: RuleTranslations) -> RuleTranslations {
    for text in [
        &mut translations.zh_cn,
        &mut translations.en,
        &mut translations.zh_tw,
    ]
    .into_iter()
    .flatten()
    {
        text.title = truncate_finding_translation(&text.title);
        text.message = truncate_finding_translation(&text.message);
    }
    translations
}

fn truncate_finding_translation(text: &str) -> String {
    if text.len() <= MAX_FINDING_TRANSLATION_BYTES {
        return text.to_string();
    }
    let mut end = MAX_FINDING_TRANSLATION_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated; see bundled rule catalog for full text]", &text[..end])
}

fn format_message_template(template: &str, args: &[String]) -> String {
    let mut formatted = template.to_string();
    for arg in args {
        formatted = formatted.replacen("{}", arg, 1);
    }
    formatted
}

fn build_label_transform_map(
    flow: &FlowGraph,
    rules: &RuleSet,
    matcher_index: &TaintMatcherIndex<'_>,
) -> LabelTransformMap {
    let mut transforms = LabelTransformMap::new();
    for ((func, inst), meta) in &flow.call_meta {
        let Some(call_info) = meta.as_call_info() else {
            continue;
        };
        matcher_index.sanitizers.for_each_candidate(&call_info, |position| {
            let rule = &rules.sanitizers[position];
            if !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
                || !rules.call_condition_matches(&rule.id, &call_info)
            {
                return;
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
                        transforms.entry(to.index()).or_default().push(LabelTransformEdge {
                            from: None,
                            to: to.index(),
                            add_kinds: Vec::new(),
                            remove_kinds: vec![rule.kind.clone()],
                            remove_compatible: true,
                        });
                    }
                }
                return;
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
                        transforms.entry(to.index()).or_default().push(LabelTransformEdge {
                            from: Some(from.index()),
                            to: to.index(),
                            add_kinds: Vec::new(),
                            remove_kinds: vec![rule.kind.clone()],
                            remove_compatible: true,
                        });
                    }
                }
            }
        });
        matcher_index.transforms.for_each_candidate(&call_info, |position| {
            let rule = &rules.taint_transforms[position];
            if !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
                || !rules.call_condition_matches(&rule.id, &call_info)
            {
                return;
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
                        transforms.entry(to.index()).or_default().push(LabelTransformEdge {
                            from: None,
                            to: to.index(),
                            add_kinds: rule.add_kinds.clone(),
                            remove_kinds: rule.remove_kinds.clone(),
                            remove_compatible: false,
                        });
                    }
                }
                return;
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
                        transforms.entry(to.index()).or_default().push(LabelTransformEdge {
                            from: Some(from.index()),
                            to: to.index(),
                            add_kinds: rule.add_kinds.clone(),
                            remove_kinds: rule.remove_kinds.clone(),
                            remove_compatible: false,
                        });
                    }
                }
            }
        });
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
                let target = edge.target().index();
                transforms.entry(target).or_default().push(LabelTransformEdge {
                    from: Some(node.index()),
                    to: target,
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
    matcher_index: &TaintMatcherIndex<'_>,
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

        matcher_index.transforms.for_each_candidate(&call_info, |position| {
            let rule = &rules.taint_transforms[position];
            if !rule.inputs.is_empty()
                || !rule.outputs.iter().any(|output| output == &Port::Receiver)
                || !language_matches(&rule.language, &flow.language)
                || !rule.matcher.matches_call(&call_info)
                || !rules.call_condition_matches(&rule.id, &call_info)
            {
                return;
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
        });

        receiver_labels = labels_for_keys(&object_labels, &receiver_keys);
        if receiver_labels.is_empty() {
            continue;
        }
        let mut transfers_receiver_to_return = false;
        matcher_index
            .propagators
            .for_each_candidate(&call_info, |position| {
                let rule = &rules.propagators[position];
                transfers_receiver_to_return |= language_matches(&rule.language, &flow.language)
                    && rule.matcher.matches_call(&call_info)
                    && rules.call_condition_matches(&rule.id, &call_info)
                    && rule
                        .flows
                        .iter()
                        .any(|spec| spec.from == Port::Receiver && spec.to == Port::Return);
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
        if let FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } =
            flow.graph[node]
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
    for edge in flow
        .graph
        .edges_directed(node, petgraph::Direction::Incoming)
    {
        if matches!(
            edge.weight().kind,
            EdgeKind::ValueToCallPort | EdgeKind::CallPortToValue
        ) {
            collect_value_key(flow, edge.source(), &mut keys);
        }
    }
    for edge in flow.graph.edges(node) {
        if matches!(
            edge.weight().kind,
            EdgeKind::ValueToCallPort | EdgeKind::CallPortToValue
        ) {
            collect_value_key(flow, edge.target(), &mut keys);
        }
    }
    // A broad points-to overlay may contain every object in a connected
    // region. Never write a security state onto that whole set. Use a single
    // abstract object only when no concrete SSA identity is available.
    if keys.is_empty() {
        match flow
            .node_points_to_object_ids
            .get(&node.index())
            .map(Vec::as_slice)
        {
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
    transforms: &LabelTransformMap,
    labels: &[String],
    from: NodeIndex,
    to: NodeIndex,
) -> Vec<String> {
    let Some(applicable) = transforms.get(&to.index()) else {
        return labels.to_vec();
    };
    let mut result = labels.iter().cloned().collect::<BTreeSet<_>>();
    let mut changed = false;
    for edge in applicable.iter().filter(|edge| {
        debug_assert_eq!(edge.to, to.index());
        edge.from
            .is_none_or(|transform_from| transform_from == from.index())
    }) {
        changed = true;
        let had_generic = result.iter().any(|label| normalize_kind(label) == "generic");
        result.retain(|label| {
            !edge.remove_kinds.iter().any(|removed| {
                let (label, removed) = (normalize_kind(label), normalize_kind(removed));
                // A specific-kind removal never deletes a `generic` label: an
                // HTML encoder makes data safe for an XSS sink, not for SQL,
                // and a legacy "passthrough_remove safeX" (a decoder undoing
                // encoding) removes a safety sign, not the taint. Deleting
                // the generic label used to lose every flow through
                // `URLDecoder.decode` for sources modeled as `generic`.
                label == removed || (edge.remove_compatible && removed == "generic")
            })
        });
        if had_generic && edge.remove_compatible {
            // Remember what the generic taint was neutralized for, so a sink
            // of exactly that kind is not reported (see `live_for_sink`).
            result.extend(
                edge.remove_kinds
                    .iter()
                    .map(|removed| normalize_kind(removed))
                    .filter(|removed| *removed != "generic" && !is_safety_sign(removed))
                    .map(|removed| format!("{NEUTRALIZED_PREFIX}{removed}")),
            );
        }
        result.extend(
            edge.add_kinds
                .iter()
                .map(|kind| normalize_kind(kind).to_string()),
        );
    }
    if !changed {
        return labels.to_vec();
    }
    result.into_iter().collect()
}

const NEUTRALIZED_PREFIX: &str = "neutralized:";

/// Whether `labels` still carry taint that `sink_kind` must report: some
/// real (non-marker) label compatible with the sink, where a `generic` label
/// does not count if it was neutralized for exactly this sink kind.
fn live_for_sink(labels: &[String], sink_kind: &str) -> bool {
    let sink_kind = normalize_kind(sink_kind);
    let neutralized_here = sink_kind != "generic" && labels.iter().any(|label| label.strip_prefix(NEUTRALIZED_PREFIX) == Some(sink_kind));
    labels.iter().any(|label| {
        !label.starts_with(NEUTRALIZED_PREFIX)
            && kind_compatible(label, sink_kind)
            && !(neutralized_here && normalize_kind(label) == "generic")
    })
}

/// Legacy packs record sanitization as *signs* on a value
/// (`safeSqlInjection`, `safeCrossSiteScriptingReflected`, …) that sinks
/// test with `not has_kind safeX`. Removing such a sign — `URLDecoder.decode`
/// undoes HTML/URL encoding — must remove only that sign. Letting the
/// `generic` wildcard of [`kind_compatible`] apply here stripped the taint
/// label itself, so every flow through a decoder vanished.
fn is_safety_sign(kind: &str) -> bool {
    normalize_kind(kind).to_ascii_lowercase().starts_with("safe")
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
                || transform
                    .remove_kinds
                    .iter()
                    .any(|removed| reachable.iter().any(|kind| kind_compatible(kind, removed)));
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
        FlowNode::CallPort { func, inst, .. } => flow.location_text(*func, *inst),
        // Function-boundary rules deliberately use a synthetic instruction ID:
        // the parameter/return they attach to is the real source location. Do
        // not leak that implementation detail into SARIF as `@unknown`.
        FlowNode::SyntheticSource { func, inst, .. } => {
            let location = flow.location_text(*func, *inst);
            if location != "@unknown" {
                location
            } else {
                adjacent_node_location(flow, idx, Direction::Outgoing)
            }
        }
        FlowNode::SyntheticSink { func, inst, .. } => {
            let location = flow.location_text(*func, *inst);
            if location != "@unknown" {
                location
            } else {
                adjacent_node_location(flow, idx, Direction::Incoming)
            }
        }
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

fn adjacent_node_location(flow: &FlowGraph, idx: NodeIndex, direction: Direction) -> String {
    flow.graph
        .neighbors_directed(idx, direction)
        .map(|neighbor| match &flow.graph[neighbor] {
            // A synthetic boundary can be directly paired with another boundary
            // rule. Its own missing instruction span is not useful evidence.
            FlowNode::SyntheticSource { .. } | FlowNode::SyntheticSink { .. } => {
                "@unknown".to_string()
            }
            _ => node_location(flow, neighbor),
        })
        .find(|location| location != "@unknown")
        .unwrap_or_else(|| "@unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_frontend::parse_source;
    use uniflow_hir::Language;
    use uniflow_lowering::lower_program;
    use uniflow_ir::validate_program;
    use uniflow_models::default_models_for;
    use uniflow_rules::{
        ApiMatcher, CallConditionRule, FlowSpec, FunctionMatcher, FunctionSinkRule,
        FunctionSourceRule, LocalizedRuleText, Port, PropagatorRule, RuleMetadata,
        RuleTranslations, SanitizerRule, SinkConditionRule, SinkRule, SourceRule, TaintCondition,
        TaintTransformRule,
    };
    use uniflow_value_flow::build;

    #[test]
    fn rust_frontend_lowers_taint_crate_without_undefined_values() {
        let hir = parse_source(Language::Rust, "taint.rs", include_str!("lib.rs"))
            .expect("taint crate Rust source should parse");
        let ir = lower_program(&hir);
        if let Err(errors) = validate_program(&ir) {
            let rendered = errors
                .iter()
                .map(|error| format!("{}: {}", error.function, error.message))
                .collect::<Vec<_>>()
                .join("\n");
            panic!("lowered Rust fixture is invalid:\n{rendered}\nIR: {ir:#?}");
        }
    }

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
    fn c_tainted_loop_control_is_reported_only_for_a_nonconstant_comparison_peer() {
        let findings = analyze_source(
            Language::C,
            "loop.c",
            "char *getenv(const char *);\nvoid f(int limit) { char *value = getenv(\"X\"); while (value < limit) { break; } while (value < 10) { break; } }\n",
        );
        let loop_findings = findings
            .iter()
            .filter(|finding| finding.sink_rule_id == "ANZU-TAINTED-LOOP-VARIABLE")
            .collect::<Vec<_>>();
        assert_eq!(loop_findings.len(), 1, "{findings:#?}");
        assert_eq!(loop_findings[0].source_rule_id, "c-getenv");
    }

    #[test]
    fn colocated_source_models_keep_individual_findings() {
        let language = Language::Rust;
        let mut rules = RuleSet {
            sources: vec![SourceRule {
                id: "source-a".to_string(),
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
        rules.sources.push(SourceRule {
            id: "source-b".to_string(),
            language: Some(language.clone()),
            matcher: ApiMatcher {
                exact: Some("taint_source".to_string()),
                ..ApiMatcher::default()
            },
            out: Port::Return,
            kind: "test-data".to_string(),
        });
        let hir = parse_source(
            language,
            "colocated.rs",
            "fn run() { let value = taint_source(); sink(value); }",
        )
        .expect("source should parse");
        let flow = build(&lower_program(&hir), &rules);
        let findings = analyze(&flow, &rules);
        let source_ids = findings
            .iter()
            .map(|finding| finding.source_rule_id.as_str())
            .collect::<HashSet<_>>();
        assert!(source_ids.contains("source-a"));
        assert!(source_ids.contains("source-b"));
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
        let finding = findings.iter().find(|finding| {
            finding.source_rule_id == "route-source" && finding.sink_rule_id == "route-return"
        }).expect("route taint finding");
        assert_ne!(finding.source_location, "@unknown");
        assert_ne!(finding.sink_location, "@unknown");
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
                categories: Default::default(),
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
            id: id.to_string(),
            language: Some(Language::JavaScript),
            matcher: ApiMatcher {
                exact: Some("input".to_string()),
                ..Default::default()
            },
            out: Port::Return,
            kind: kind.to_string(),
        };
        let rules = RuleSet {
            sources: vec![
                source_rule("source-alpha", "alpha"),
                source_rule("source-beta", "beta"),
            ],
            sinks: vec![SinkRule {
                id: "combined-sink".to_string(),
                language: Some(Language::JavaScript),
                matcher: ApiMatcher {
                    exact: Some("sink".to_string()),
                    ..Default::default()
                },
                inputs: vec![Port::Arg(0)],
                kind: "generic".to_string(),
            }],
            sink_conditions: vec![SinkConditionRule {
                sink_rule_id: "combined-sink".to_string(),
                condition: TaintCondition::All(vec![
                    TaintCondition::HasKind("alpha".to_string()),
                    TaintCondition::HasKind("beta".to_string()),
                ]),
            }],
            ..Default::default()
        };
        rules.validate().unwrap();
        let hir = parse_source(Language::JavaScript, "labels.js", "sink(input());").unwrap();
        let graph = build(&lower_program(&hir), &rules);
        let findings = analyze(&graph, &rules);
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert!(findings
            .iter()
            .all(|finding| finding.sink_rule_id == "combined-sink"));

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
                "package main\n\nfunc run() { x := taint_source()\n sink(x)\n }",
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
                "package main\n\nfunc run() { x := Getenv(\"X\")\n Command(x)\n }",
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
                "fn run(dummy: i32) { let x = var(\"X\"); sqlx_query!(x); }",
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
    fn reports_malloc_free_lifetime_rule_with_bundled_metadata() {
        let findings = analyze_source(
            Language::C,
            "malloc_free.c",
            "void run(int *borrowed) { free(borrowed); }",
        );
        let finding = findings
            .iter()
            .find(|finding| finding.sink_rule_id == "ANZU-MALLOC-FREE")
            .expect("invalid free finding");
        assert_eq!(finding.finding_kind, "lifetime");
        assert_eq!(finding.standards, ["0701000010130053"]);
        assert_eq!(finding.message, "Pointer must be allocated by malloc or calloc");
        assert_eq!(
            finding.translations.zh_cn.as_ref().map(|text| text.message.as_str()),
            Some("指针必须由malloc或calloc分配")
        );
        assert_eq!(
            finding.translations.zh_tw.as_ref().map(|text| text.message.as_str()),
            Some("指標必須由malloc或calloc配置")
        );
    }

    #[test]
    fn reports_dynamic_allocation_use_with_the_default_c_models() {
        let findings = analyze_source(
            Language::C,
            "dynamic_alloc.c",
            "int run(void) { int *value = malloc(sizeof(int)); return *value; }",
        );
        let finding = findings
            .iter()
            .find(|finding| finding.sink_rule_id == "ANZU-DYNAMIC-ALLOC-POINTER-USE")
            .expect("unchecked allocation use must be reported by the bundled C models");
        assert_eq!(finding.finding_kind, "lifetime");
        assert_eq!(
            finding.message,
            "Dynamically allocated pointer must be checked for NULL before use."
        );
        assert_eq!(finding.standards, ["0701000010130027", "0101000010110338"]);
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
    fn reports_cpp_argument_validation_native_dataflow_with_legacy_metadata() {
        let findings = analyze_source(
            Language::Cpp,
            "argument_validation.cpp",
            "void consume(int *value) {} void run() { int *p = nullptr; consume(p); }",
        );
        let finding = findings
            .iter()
            .find(|finding| finding.sink_rule_id == "ANZU-ARGUMENT-VALIDATION")
            .expect("native argument-validation finding");
        assert_eq!(finding.finding_kind, "native-dataflow");
        assert_eq!(finding.severity, "warning");
        assert_eq!(finding.standards, ["0101000010110430"]);
        assert_eq!(
            finding.message,
            "Pointer argument 'value' might be null and should be validated."
        );
        assert_eq!(
            finding.translations.zh_cn.as_ref().map(|text| text.message.as_str()),
            Some("指针参数 ‘value’需要确认是否为空指针。")
        );
        assert!(finding.translations.zh_tw.is_none());
    }

    #[test]
    fn reports_c_array_index_native_dataflow_with_legacy_metadata() {
        let findings = analyze_source(
            Language::C,
            "array_index.c",
            "int run(int *a, int i) { return a[i]; }",
        );
        let finding = findings
            .iter()
            .find(|finding| finding.sink_rule_id == "ANZU-ARRAY-INDEX")
            .expect("native array-index finding");
        assert_eq!(finding.finding_kind, "native-dataflow");
        assert_eq!(finding.severity, "warning");
        assert_eq!(finding.standards, ["0701000010130047"]);
        assert_eq!(finding.message, "Array index is less than zero");
        assert_eq!(
            finding.translations.zh_cn.as_ref().map(|text| text.message.as_str()),
            Some("数组索引小于0。")
        );
        assert!(finding.translations.zh_tw.is_none());
    }

    #[test]
    fn reports_c_array_bound_native_dataflow_with_legacy_metadata() {
        let findings = analyze_source(
            Language::C,
            "array_bound.c",
            "int run(void) { int a[2]; return a[2]; }",
        );
        let finding = findings
            .iter()
            .find(|finding| finding.sink_rule_id == "ANZU-ARRAY-BOUND")
            .expect("native array-bound finding");
        assert_eq!(finding.finding_kind, "native-dataflow");
        assert_eq!(finding.severity, "warning");
        assert_eq!(
            finding.standards,
            [
                "0201000010120009",
                "0301000010120009",
                "0501000010120009",
                "1301000010120009",
                "2401000010120009",
                "0701000010130046",
                "0601000010140037",
            ]
        );
        assert_eq!(finding.message, "Array bound read/write exceeds size");
        assert_eq!(
            finding.translations.zh_cn.as_ref().map(|text| text.message.as_str()),
            Some("数组读写越界。")
        );
        assert!(finding.translations.zh_tw.is_none());
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
                seeds: vec![uniflow_value_flow::DemandSeed::Node(source)],
                direction: SparseDirection::Forward,
                engine: DemandEngine::Fixpoint,
                include_heap: true,
            }))
            .expect("forward demand summary");
        let backward = flow
            .execute_solver_plan(&flow.solver_plan_for_query(&DemandQuery {
                seeds: vec![uniflow_value_flow::DemandSeed::Node(sink)],
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
