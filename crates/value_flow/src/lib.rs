use petgraph::algo::kosaraju_scc;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use uniflow_hir::{Language, Span};
use uniflow_ir::{
    BlockId, Callee, CallInst, Function, FunctionId, InstId, InstKind, Program, Terminator, ValueId,
};
use uniflow_rules::{language_matches, CallInfo, FlowSpec, Port, RuleSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowGraph {
    pub language: Language,
    pub graph: DiGraph<FlowNode, FlowEdge>,
    pub function_params: HashMap<(FunctionId, usize), NodeIndex>,
    pub function_returns: HashMap<FunctionId, NodeIndex>,
    pub values: HashMap<(FunctionId, ValueId), NodeIndex>,
    pub call_ports: HashMap<(FunctionId, InstId, Port), NodeIndex>,
    pub function_names: HashMap<FunctionId, String>,
    pub function_spans: HashMap<FunctionId, Span>,
    pub file_paths: HashMap<u32, String>,
    pub inst_spans: HashMap<(FunctionId, InstId), Span>,
    pub value_spans: HashMap<(FunctionId, ValueId), Span>,
    pub value_types: HashMap<(FunctionId, ValueId), String>,
    pub value_alias_roots: HashMap<(FunctionId, ValueId), ValueId>,
    pub heap_alias_roots: HashMap<(FunctionId, ValueId), ValueId>,
    pub object_identity_roots: HashMap<(FunctionId, ValueId), ValueId>,
    pub object_identity_sites: HashMap<(FunctionId, ValueId), String>,
    pub field_cells: HashMap<(FunctionId, ValueId, String), NodeIndex>,
    pub index_cells: HashMap<(FunctionId, ValueId, String), NodeIndex>,
    pub sparse_successors: HashMap<usize, Vec<usize>>,
    pub sparse_predecessors: HashMap<usize, Vec<usize>>,
    pub heap_value_successors: HashMap<usize, Vec<usize>>,
    pub heap_value_predecessors: HashMap<usize, Vec<usize>>,
    pub heap_object_successors: HashMap<usize, Vec<usize>>,
    pub heap_object_predecessors: HashMap<usize, Vec<usize>>,
    pub object_graph_successors: HashMap<usize, Vec<usize>>,
    pub object_graph_predecessors: HashMap<usize, Vec<usize>>,
    pub object_graph_labels: HashMap<(usize, usize), String>,
    pub object_shape_labels: HashMap<usize, Vec<String>>,
    pub object_shape_paths: HashMap<usize, Vec<String>>,
    pub node_memory_regions: HashMap<usize, Vec<String>>,
    pub value_memory_regions: HashMap<(FunctionId, ValueId), Vec<String>>,
    pub cell_memory_regions: HashMap<usize, Vec<String>>,
    pub region_graph_successors: HashMap<usize, Vec<usize>>,
    pub region_graph_predecessors: HashMap<usize, Vec<usize>>,
    pub cell_live_values: HashMap<usize, Vec<(u32, u32)>>,
    pub cell_live_regions: HashMap<usize, Vec<String>>,
    pub region_live_values: HashMap<String, Vec<(u32, u32)>>,
    pub region_live_cells: HashMap<String, Vec<usize>>,
    pub node_points_to_classes: HashMap<usize, Vec<String>>,
    pub value_points_to_classes: HashMap<(FunctionId, ValueId), Vec<String>>,
    pub cell_points_to_classes: HashMap<usize, Vec<String>>,
    pub node_points_to_targets: HashMap<usize, Vec<String>>,
    pub value_points_to_targets: HashMap<(FunctionId, ValueId), Vec<String>>,
    pub cell_points_to_targets: HashMap<usize, Vec<String>>,
    pub points_to_object_ids: HashMap<String, u32>,
    pub object_seed_ids: HashMap<AbstractObjectSeed, u32>,
    pub abstract_objects: HashMap<u32, AbstractObjectInfo>,
    pub abstract_object_seed_nodes: HashMap<usize, Vec<u32>>,
    pub node_points_to_object_ids: HashMap<usize, Vec<u32>>,
    pub value_points_to_object_ids: HashMap<(FunctionId, ValueId), Vec<u32>>,
    pub cell_points_to_object_ids: HashMap<usize, Vec<u32>>,
    pub contextual_node_points_to_targets: HashMap<(CallContextKey, usize), Vec<String>>,
    pub contextual_value_points_to_targets: HashMap<(CallContextKey, u32, u32), Vec<String>>,
    pub contextual_cell_points_to_targets: HashMap<(CallContextKey, usize), Vec<String>>,
    pub contextual_node_points_to_object_ids: HashMap<(CallContextKey, usize), Vec<u32>>,
    pub contextual_value_points_to_object_ids: HashMap<(CallContextKey, u32, u32), Vec<u32>>,
    pub contextual_cell_points_to_object_ids: HashMap<(CallContextKey, usize), Vec<u32>>,
    pub strong_update_cells: HashSet<usize>,
    pub cell_write_generations: HashMap<usize, Vec<(u64, u32, u32)>>,
    pub contextual_return_values: HashMap<CallContextKey, Vec<(u32, u32)>>,
    pub contextual_return_cells: HashMap<CallContextKey, Vec<usize>>,
    pub contextual_points_to_targets: HashMap<CallContextKey, Vec<String>>,
    pub contextual_points_to_object_ids: HashMap<CallContextKey, Vec<u32>>,
    pub solver_closure_iterations: usize,
    pub global_solver_iterations: usize,
    #[serde(skip)]
    pub demand_summary_cache: RefCell<HashMap<(usize, SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_seed_summary_cache: RefCell<HashMap<(Vec<usize>, SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_call_summary_cache: RefCell<HashMap<((u32, u32), SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_fixpoint_summary_cache: RefCell<HashMap<(Vec<usize>, SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_query_summary_cache: RefCell<HashMap<(DemandQuery, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub contextual_call_summary_cache: RefCell<HashMap<(CallContextKey, SparseDirection, usize, usize, DemandEngine, bool), SparseValueSummary>>,
    #[serde(skip)]
    pub function_summary_cache: RefCell<HashMap<(u32, String, SparseDirection, usize, usize, DemandEngine, bool), SparseValueSummary>>,
    #[serde(skip)]
    pub contextual_demand_query_cache: RefCell<HashMap<(DemandQuery, ContextSensitivity, Vec<CallContextKey>, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub interprocedural_call_summary_cache: RefCell<HashMap<(CallContextKey, ContextSensitivity, usize, usize, DemandEngine, bool), InterproceduralCallSummary>>,
    #[serde(skip)]
    pub function_transfer_summary_cache: RefCell<HashMap<(u32, usize, usize, DemandEngine, bool), FunctionTransferSummary>>,
    #[serde(skip)]
    pub contextual_function_transfer_summary_cache: RefCell<HashMap<(u32, CallContextKey, ContextSensitivity, usize, usize, DemandEngine, bool), FunctionTransferSummary>>,
    #[serde(skip)]
    pub function_heap_effect_summary_cache: RefCell<HashMap<(u32, usize, usize, DemandEngine, bool), FunctionHeapEffectSummary>>,
    #[serde(skip)]
    pub contextual_function_heap_effect_summary_cache: RefCell<HashMap<(u32, CallContextKey, ContextSensitivity, usize, usize, DemandEngine, bool), FunctionHeapEffectSummary>>,
    pub type_hierarchy: HashMap<String, Vec<String>>,
    pub call_meta: HashMap<(FunctionId, InstId), CallMeta>,
    pub resolved_internal_targets: HashMap<(FunctionId, InstId), Vec<String>>,
    pub synthetic_sources: Vec<NodeIndex>,
    pub synthetic_sinks: Vec<NodeIndex>,
}
impl Default for FlowGraph {
    fn default() -> Self {
        Self {
            language: Language::Unknown,
            graph: DiGraph::new(),
            function_params: HashMap::new(),
            function_returns: HashMap::new(),
            values: HashMap::new(),
            call_ports: HashMap::new(),
            function_names: HashMap::new(),
            function_spans: HashMap::new(),
            file_paths: HashMap::new(),
            inst_spans: HashMap::new(),
            value_spans: HashMap::new(),
            value_types: HashMap::new(),
            value_alias_roots: HashMap::new(),
            heap_alias_roots: HashMap::new(),
            object_identity_roots: HashMap::new(),
            object_identity_sites: HashMap::new(),
            field_cells: HashMap::new(),
            index_cells: HashMap::new(),
            sparse_successors: HashMap::new(),
            sparse_predecessors: HashMap::new(),
            heap_value_successors: HashMap::new(),
            heap_value_predecessors: HashMap::new(),
            heap_object_successors: HashMap::new(),
            heap_object_predecessors: HashMap::new(),
            object_graph_successors: HashMap::new(),
            object_graph_predecessors: HashMap::new(),
            object_graph_labels: HashMap::new(),
            object_shape_labels: HashMap::new(),
            object_shape_paths: HashMap::new(),
            node_memory_regions: HashMap::new(),
            value_memory_regions: HashMap::new(),
            cell_memory_regions: HashMap::new(),
            region_graph_successors: HashMap::new(),
            region_graph_predecessors: HashMap::new(),
            cell_live_values: HashMap::new(),
            cell_live_regions: HashMap::new(),
            region_live_values: HashMap::new(),
            region_live_cells: HashMap::new(),
            node_points_to_classes: HashMap::new(),
            value_points_to_classes: HashMap::new(),
            cell_points_to_classes: HashMap::new(),
            node_points_to_targets: HashMap::new(),
            value_points_to_targets: HashMap::new(),
            cell_points_to_targets: HashMap::new(),
            points_to_object_ids: HashMap::new(),
            object_seed_ids: HashMap::new(),
            abstract_objects: HashMap::new(),
            abstract_object_seed_nodes: HashMap::new(),
            node_points_to_object_ids: HashMap::new(),
            value_points_to_object_ids: HashMap::new(),
            cell_points_to_object_ids: HashMap::new(),
            contextual_node_points_to_targets: HashMap::new(),
            contextual_value_points_to_targets: HashMap::new(),
            contextual_cell_points_to_targets: HashMap::new(),
            contextual_node_points_to_object_ids: HashMap::new(),
            contextual_value_points_to_object_ids: HashMap::new(),
            contextual_cell_points_to_object_ids: HashMap::new(),
            strong_update_cells: HashSet::new(),
            cell_write_generations: HashMap::new(),
            contextual_return_values: HashMap::new(),
            contextual_return_cells: HashMap::new(),
            contextual_points_to_targets: HashMap::new(),
            contextual_points_to_object_ids: HashMap::new(),
            solver_closure_iterations: 0,
            global_solver_iterations: 0,
            demand_summary_cache: RefCell::new(HashMap::new()),
            demand_seed_summary_cache: RefCell::new(HashMap::new()),
            demand_call_summary_cache: RefCell::new(HashMap::new()),
            demand_fixpoint_summary_cache: RefCell::new(HashMap::new()),
            demand_query_summary_cache: RefCell::new(HashMap::new()),
            contextual_call_summary_cache: RefCell::new(HashMap::new()),
            function_summary_cache: RefCell::new(HashMap::new()),
            contextual_demand_query_cache: RefCell::new(HashMap::new()),
            interprocedural_call_summary_cache: RefCell::new(HashMap::new()),
            function_transfer_summary_cache: RefCell::new(HashMap::new()),
            contextual_function_transfer_summary_cache: RefCell::new(HashMap::new()),
            function_heap_effect_summary_cache: RefCell::new(HashMap::new()),
            contextual_function_heap_effect_summary_cache: RefCell::new(HashMap::new()),
            type_hierarchy: HashMap::new(),
            call_meta: HashMap::new(),
            resolved_internal_targets: HashMap::new(),
            synthetic_sources: Vec::new(),
            synthetic_sinks: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallMeta {
    pub func: FunctionId,
    pub inst: InstId,
    pub function_name: String,
    pub callee_name: Option<String>,
    pub receiver_type: Option<String>,
    pub receiver_type_candidates: Vec<String>,
    pub method_name: Option<String>,
    pub arg_count: usize,
    pub arg_types: Vec<Option<String>>,
    pub arg_type_candidates: Vec<Vec<String>>,
    pub span: Span,
}

impl CallMeta {
    pub fn as_call_info(&self) -> Option<CallInfo> {
        Some(CallInfo::new(
            self.callee_name.clone()?,
            self.receiver_type.clone(),
            self.receiver_type_candidates.clone(),
            self.method_name.clone(),
            Some(self.arg_count),
            self.arg_types.clone(),
            self.arg_type_candidates.clone(),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FlowNode {
    Param {
        func: FunctionId,
        index: usize,
        value: ValueId,
    },
    Return {
        func: FunctionId,
    },
    Value {
        func: FunctionId,
        value: ValueId,
    },
    CallPort {
        func: FunctionId,
        inst: InstId,
        port: Port,
        callee_name: Option<String>,
    },
    FieldCell {
        func: FunctionId,
        block: BlockId,
        inst: InstId,
        base: ValueId,
        field: String,
    },
    IndexCell {
        func: FunctionId,
        block: BlockId,
        inst: InstId,
        base: ValueId,
        index: ValueId,
        abstract_key: String,
    },
    SyntheticSource {
        func: FunctionId,
        inst: InstId,
        rule_id: String,
        kind: String,
        out: Port,
    },
    SyntheticSink {
        func: FunctionId,
        inst: InstId,
        rule_id: String,
        kind: String,
        input: Port,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowEdge {
    pub kind: EdgeKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallReport {
    pub function_name: String,
    pub location: String,
    pub callee_name: Option<String>,
    pub receiver_type: Option<String>,
    pub receiver_type_candidates: Vec<String>,
    pub method_name: Option<String>,
    pub arg_count: usize,
    pub arg_types: Vec<Option<String>>,
    pub arg_type_candidates: Vec<Vec<String>>,
    pub is_dynamic: bool,
    pub resolved_internal_targets: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AbstractObjectInfo {
    pub id: u32,
    pub canonical_target: String,
    pub kind: String,
    pub identity_site: Option<String>,
    pub root_regions: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbstractObjectSeed {
    ValueSite(String),
    ValueRootRegion(String),
    ValueRegion(String),
    ReturnRegion(String),
    CallPort(String),
    CellIdentity(String),
    MemoryUnit(String),
    CellRegion(String),
    SyntheticSource(String),
    SyntheticSink(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowStats {
    pub files: usize,
    pub functions: usize,
    pub value_nodes: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub sparse_data_edges: usize,
    pub heap_value_edges: usize,
    pub heap_object_edges: usize,
    pub object_graph_edges: usize,
    pub region_graph_edges: usize,
    pub object_shape_nodes: usize,
    pub object_shape_paths: usize,
    pub object_identity_values: usize,
    pub points_to_classes: usize,
    pub points_to_targets: usize,
    pub points_to_objects: usize,
    pub strong_update_cells: usize,
    pub cell_write_generations: usize,
    pub contextual_states: usize,
    pub contextual_points_to_objects: usize,
    pub solver_closure_iterations: usize,
    pub global_solver_iterations: usize,
    pub memory_regions: usize,
    pub live_cell_values: usize,
    pub live_cell_regions: usize,
    pub live_region_values: usize,
    pub live_region_cells: usize,
    pub cached_sparse_summaries: usize,
    pub cached_demand_queries: usize,
    pub cached_contextual_queries: usize,
    pub cached_contextual_summaries: usize,
    pub cached_function_summaries: usize,
    pub cached_interprocedural_summaries: usize,
    pub cached_transfer_summaries: usize,
    pub cached_heap_effect_summaries: usize,
    pub static_calls: usize,
    pub dynamic_calls: usize,
    pub resolved_internal_calls: usize,
    pub unresolved_static_calls: usize,
    pub synthetic_sources: usize,
    pub synthetic_sinks: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SparseDirection {
    Forward,
    Backward,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SparseTraversal {
    pub seeds: Vec<usize>,
    pub visited: Vec<usize>,
    pub layers: Vec<Vec<usize>>,
    pub frontier_cutoff: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SparseValueSummary {
    pub traversal: SparseTraversal,
    pub values: Vec<(u32, u32)>,
    pub params: Vec<(u32, usize, u32)>,
    pub call_ports: Vec<(u32, u32, String)>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DemandEngine {
    Sparse,
    Fixpoint,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DemandSeed {
    Node(usize),
    Value { func: u32, value: u32 },
    Call { func: u32, inst: u32 },
    CallPort { func: u32, inst: u32, port: Port },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DemandQuery {
    pub seeds: Vec<DemandSeed>,
    pub direction: SparseDirection,
    pub engine: DemandEngine,
    pub include_heap: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum QueryBudgetProfile {
    Light,
    Standard,
    Deep,
    Exhaustive,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SolverPlan {
    pub query: DemandQuery,
    pub context_sensitivity: ContextSensitivity,
    pub budget_profile: QueryBudgetProfile,
    pub max_depth: usize,
    pub max_visits: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CallContextKey {
    pub callee_names: Vec<String>,
    pub callee_funcs: Vec<u32>,
    pub receiver_classes: Vec<String>,
    pub receiver_shapes: Vec<String>,
    pub arg_classes: Vec<Vec<String>>,
    pub arg_shapes: Vec<Vec<String>>,
    pub call_sites: Vec<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ContextSensitivity {
    None,
    CallSite,
    Receiver,
    ReceiverAndArgs,
    ReceiverArgsAndCallSite,
    CallString2,
}

fn all_context_sensitivities() -> &'static [ContextSensitivity] {
    &[
        ContextSensitivity::CallSite,
        ContextSensitivity::Receiver,
        ContextSensitivity::ReceiverAndArgs,
        ContextSensitivity::ReceiverArgsAndCallSite,
        ContextSensitivity::CallString2,
    ]
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FunctionTransferSummary {
    pub func: u32,
    pub return_reachable_params: Vec<usize>,
    pub param_to_param: Vec<(usize, usize)>,
    pub param_to_return_values: Vec<(usize, u32, u32)>,
    pub return_values: Vec<(u32, u32)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct FunctionHeapEffectSummary {
    pub func: u32,
    pub context: Option<CallContextKey>,
    pub sensitivity: Option<ContextSensitivity>,
    pub param_to_read_regions: Vec<(usize, String)>,
    pub param_to_read_paths: Vec<(usize, String)>,
    pub param_to_read_cells: Vec<(usize, u32)>,
    pub param_to_read_objects: Vec<(usize, u32)>,
    pub param_to_write_regions: Vec<(usize, String)>,
    pub param_to_write_paths: Vec<(usize, String)>,
    pub param_to_write_cells: Vec<(usize, u32)>,
    pub param_to_write_objects: Vec<(usize, u32)>,
    pub param_to_return_regions: Vec<(usize, String)>,
    pub param_to_return_paths: Vec<(usize, String)>,
    pub param_to_return_cells: Vec<(usize, u32)>,
    pub param_to_return_objects: Vec<(usize, u32)>,
    pub param_to_return_live_values: Vec<(usize, u32, u32)>,
    pub return_regions: Vec<String>,
    pub return_paths: Vec<String>,
    pub return_cells: Vec<u32>,
    pub return_objects: Vec<u32>,
    pub return_value_regions: Vec<(u32, u32, String)>,
    pub return_value_paths: Vec<(u32, u32, String)>,
    pub return_value_cells: Vec<(u32, u32, u32)>,
    pub return_value_objects: Vec<(u32, u32, u32)>,
    pub return_live_values: Vec<(u32, u32)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InterproceduralCallSummary {
    pub caller_func: u32,
    pub inst: u32,
    pub sensitivity: Option<ContextSensitivity>,
    pub callee_names: Vec<String>,
    pub callee_funcs: Vec<u32>,
    pub context: CallContextKey,
    pub port_to_return: Vec<String>,
    pub port_to_param: Vec<(String, usize)>,
    pub port_to_port: Vec<(String, String)>,
    pub port_to_return_values: Vec<(String, u32, u32)>,
    pub port_to_return_live_values: Vec<(String, u32, u32)>,
    pub port_to_return_value_regions: Vec<(String, u32, u32, String)>,
    pub port_to_return_value_paths: Vec<(String, u32, u32, String)>,
    pub port_to_return_value_objects: Vec<(String, u32, u32, u32)>,
    pub port_to_read_regions: Vec<(String, String)>,
    pub port_to_read_paths: Vec<(String, String)>,
    pub port_to_read_cells: Vec<(String, u32)>,
    pub port_to_read_objects: Vec<(String, u32)>,
    pub port_to_write_regions: Vec<(String, String)>,
    pub port_to_write_paths: Vec<(String, String)>,
    pub port_to_write_cells: Vec<(String, u32)>,
    pub port_to_write_objects: Vec<(String, u32)>,
    pub port_to_return_regions: Vec<(String, String)>,
    pub port_to_return_paths: Vec<(String, String)>,
    pub port_to_return_cells: Vec<(String, u32)>,
    pub port_to_return_objects: Vec<(String, u32)>,
    pub return_values: Vec<(u32, u32)>,
    pub return_live_values: Vec<(u32, u32)>,
    pub return_value_regions: Vec<(u32, u32, String)>,
    pub return_value_paths: Vec<(u32, u32, String)>,
    pub return_value_cells: Vec<(u32, u32, u32)>,
    pub return_value_objects: Vec<(u32, u32, u32)>,
    pub return_paths: Vec<String>,
    pub return_cells: Vec<u32>,
    pub return_objects: Vec<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EdgeKind {
    Assign,
    Phi,
    LoadField { field: String },
    StoreField { field: String },
    LoadIndex,
    StoreIndex,
    ValueToCallPort,
    CallPortToValue,
    ActualToFormal,
    FormalToActual,
    Summary { rule_id: String },
    Source { rule_id: String },
    Sink { rule_id: String },
}

fn ensure_alias_parent(parent: &mut HashMap<ValueId, ValueId>, value: ValueId) {
    parent.entry(value).or_insert(value);
}

fn find_alias_parent(parent: &mut HashMap<ValueId, ValueId>, value: ValueId) -> ValueId {
    let parent_value = *parent.entry(value).or_insert(value);
    if parent_value == value {
        value
    } else {
        let root = find_alias_parent(parent, parent_value);
        parent.insert(value, root);
        root
    }
}

fn union_alias_parent(parent: &mut HashMap<ValueId, ValueId>, left: ValueId, right: ValueId) {
    let left_root = find_alias_parent(parent, left);
    let right_root = find_alias_parent(parent, right);
    if left_root == right_root {
        return;
    }
    let keep = if left_root.0 <= right_root.0 { left_root } else { right_root };
    let merge = if keep == left_root { right_root } else { left_root };
    parent.insert(merge, keep);
}

fn finalize_alias_parent(parent: &mut HashMap<ValueId, ValueId>) -> HashMap<ValueId, ValueId> {
    let keys = parent.keys().copied().collect::<Vec<_>>();
    let mut out = HashMap::new();
    for value in keys {
        let root = find_alias_parent(parent, value);
        out.insert(value, root);
    }
    out
}

fn compute_value_alias_representatives(func: &Function) -> HashMap<ValueId, ValueId> {
    let mut parent = HashMap::new();
    for value in func.params.iter().chain(func.locals.iter()) {
        ensure_alias_parent(&mut parent, *value);
    }
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::Copy { dst, src } => {
                    ensure_alias_parent(&mut parent, *dst);
                    ensure_alias_parent(&mut parent, *src);
                    union_alias_parent(&mut parent, *dst, *src);
                }
                InstKind::Phi { dst, inputs } => {
                    ensure_alias_parent(&mut parent, *dst);
                    for input in inputs {
                        ensure_alias_parent(&mut parent, *input);
                        union_alias_parent(&mut parent, *dst, *input);
                    }
                }
                _ => {}
            }
        }
    }
    finalize_alias_parent(&mut parent)
}

fn compute_heap_alias_representatives(func: &Function) -> HashMap<ValueId, ValueId> {
    let mut parent = HashMap::new();
    for value in func.params.iter().chain(func.locals.iter()) {
        ensure_alias_parent(&mut parent, *value);
    }
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::Copy { dst, src } => {
                    ensure_alias_parent(&mut parent, *dst);
                    ensure_alias_parent(&mut parent, *src);
                    union_alias_parent(&mut parent, *dst, *src);
                }
                InstKind::Phi { dst, inputs } => {
                    ensure_alias_parent(&mut parent, *dst);
                    let mut roots = Vec::new();
                    for input in inputs {
                        ensure_alias_parent(&mut parent, *input);
                        roots.push(find_alias_parent(&mut parent, *input));
                    }
                    roots.sort_unstable();
                    roots.dedup();
                    if roots.len() == 1 {
                        union_alias_parent(&mut parent, *dst, roots[0]);
                    }
                }
                _ => {}
            }
        }
    }
    finalize_alias_parent(&mut parent)
}

fn canonical_value(alias_roots: &HashMap<ValueId, ValueId>, value: ValueId) -> ValueId {
    alias_roots.get(&value).copied().unwrap_or(value)
}

fn is_object_like_type(ty: &str) -> bool {
    let trimmed = ty.trim();
    if trimmed.is_empty() {
        return false;
    }
    if matches!(trimmed, "unknown" | "int" | "float" | "bool" | "str" | "bytes" | "None" | "none") {
        return false;
    }
    trimmed.contains('.')
        || trimmed.starts_with("list<")
        || trimmed.starts_with("dict<")
        || trimmed.starts_with("set<")
        || trimmed.starts_with("tuple<")
        || trimmed.starts_with("generator<")
        || trimmed.starts_with("typing.")
        || trimmed.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
}

fn looks_like_constructor_name(name: &str) -> bool {
    name.split('.').next_back().is_some_and(|tail| tail.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()))
}

fn compute_object_identity_representatives(func: &Function) -> (HashMap<ValueId, ValueId>, HashMap<ValueId, String>) {
    let mut roots = HashMap::new();
    let mut sites = HashMap::new();

    for (index, param) in func.params.iter().copied().enumerate() {
        if func
            .value_types
            .get(&param)
            .is_some_and(|ty| is_object_like_type(ty))
        {
            roots.insert(param, param);
            sites.insert(param, format!("f{}:param#{index}", func.id.0));
        }
    }

    for block in &func.blocks {
        for inst in &block.insts {
            let seeded = match &inst.kind {
                InstKind::Call(call) => call.dst.filter(|dst| {
                    func.value_types
                        .get(dst)
                        .is_some_and(|ty| is_object_like_type(ty))
                        || static_callee_name(call)
                            .as_deref()
                            .is_some_and(looks_like_constructor_name)
                }),
                InstKind::LoadField { dst, .. } | InstKind::LoadIndex { dst, .. } => Some(*dst).filter(|dst| {
                    func.value_types
                        .get(dst)
                        .is_some_and(|ty| is_object_like_type(ty))
                }),
                _ => None,
            };
            if let Some(dst) = seeded {
                roots.entry(dst).or_insert(dst);
                sites.entry(dst).or_insert_with(|| format!("f{}:inst@{}", func.id.0, inst.id.0));
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            for inst in &block.insts {
                match &inst.kind {
                    InstKind::Copy { dst, src } => {
                        if let Some(root) = roots.get(src).copied() {
                            if roots.get(dst) != Some(&root) {
                                roots.insert(*dst, root);
                                changed = true;
                            }
                        }
                    }
                    InstKind::Phi { dst, inputs } => {
                        let mut candidates = inputs
                            .iter()
                            .filter_map(|input| roots.get(input).copied())
                            .collect::<Vec<_>>();
                        candidates.sort_unstable();
                        candidates.dedup();
                        if candidates.len() == 1 && roots.get(dst) != candidates.first() {
                            roots.insert(*dst, candidates[0]);
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    (roots, sites)
}

fn canonical_heap_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> ValueId {
    fg.object_identity_roots
        .get(&(func, value))
        .copied()
        .or_else(|| fg.heap_alias_roots.get(&(func, value)).copied())
        .unwrap_or(value)
}

fn value_identity_site<'a>(fg: &'a FlowGraph, func: FunctionId, value: ValueId) -> Option<&'a str> {
    let root = fg.object_identity_roots.get(&(func, value)).copied().unwrap_or(value);
    fg.object_identity_sites.get(&(func, root)).map(|s| s.as_str())
}

fn identity_sites_definitely_distinct(left: Option<&str>, right: Option<&str>) -> bool {
    match (left.map(str::trim), right.map(str::trim)) {
        (Some(left), Some(right)) if left != right => left.contains(":inst@") && right.contains(":inst@"),
        _ => false,
    }
}

fn propagate_object_identity_site(
    fg: &mut FlowGraph,
    src_func: FunctionId,
    src_value: ValueId,
    dst_func: FunctionId,
    dst_value: ValueId,
) {
    let Some(site) = value_identity_site(fg, src_func, src_value).map(|s| s.to_string()) else {
        return;
    };
    fg.object_identity_roots.insert((dst_func, dst_value), dst_value);
    fg.object_identity_sites.insert((dst_func, dst_value), site);
}

fn returned_direct_identity_sites(fg: &FlowGraph, func: &Function) -> Vec<String> {
    let mut out = Vec::new();
    for block in &func.blocks {
        let Terminator::Return(Some(value)) = &block.term else {
            continue;
        };
        if let Some(site) = value_identity_site(fg, func.id, *value) {
            if !out.iter().any(|existing| existing == site) {
                out.push(site.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn object_types_compatible(left: Option<&str>, right: Option<&str>) -> bool {
    match (left.map(str::trim), right.map(str::trim)) {
        (Some(left), Some(right)) => {
            left == right
                || left.split('.').next_back() == right.split('.').next_back()
                || (left.starts_with("list<") && right.starts_with("list<"))
                || (left.starts_with("dict<") && right.starts_with("dict<"))
                || (left.starts_with("set<") && right.starts_with("set<"))
                || (left.starts_with("tuple<") && right.starts_with("tuple<"))
        }
        _ => true,
    }
}

fn normalized_type_point_class(ty: &str) -> String {
    let trimmed = ty.trim();
    let simple = trimmed.split('.').next_back().unwrap_or(trimmed);
    if let Some(base) = simple.split('<').next() {
        format!("type:{}", base)
    } else {
        format!("type:{}", simple)
    }
}

fn normalized_shape_point_class(shape: &str) -> String {
    let trimmed = shape.trim();
    let compact = trimmed
        .replace("field:", "f:")
        .replace("index:", "i:");
    format!("shape:{}", compact)
}

fn inferred_shape_point_classes_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    let mut classes = BTreeSet::new();
    let mut shapes = fg.object_shape_paths_of(node);
    if shapes.is_empty() {
        shapes = fg.object_shape_labels_of(node);
    }
    shapes.sort();
    shapes.dedup();
    for shape in shapes.into_iter() {
        if !shape.trim().is_empty() {
            classes.insert(normalized_shape_point_class(&shape));
        }
    }
    classes.into_iter().collect()
}

fn normalized_memory_region(path: &str) -> String {
    let trimmed = path.trim();
    let compact = trimmed
        .replace("field:", ".")
        .replace("index:", "[")
        .replace('.', ".")
        .replace("[", "[")
        .replace("]", "]");
    format!("mem:{}", compact)
}

fn memory_region_seed_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let mut regions = BTreeSet::new();
    if let Some(site) = value_identity_site(fg, func, value) {
        regions.insert(format!("mem:site:{}", site.trim()));
    }
    if let Some(ty) = fg.value_types.get(&(func, value)) {
        let trimmed = ty.trim();
        if !trimmed.is_empty() {
            regions.insert(format!("mem:{}", normalized_type_point_class(trimmed).replace("type:", "type:")));
        }
    }
    if let Some(&node) = fg.values.get(&(func, value)) {
        for shape in fg.object_shape_paths_of(node) {
            if !shape.trim().is_empty() {
                regions.insert(normalized_memory_region(&shape));
            }
        }
        for shape in fg.object_shape_labels_of(node) {
            if !shape.trim().is_empty() {
                regions.insert(normalized_memory_region(&shape));
            }
        }
    }
    if regions.is_empty() {
        regions.insert(format!("mem:value:{}:{}", func.0, value.0));
    }
    regions.into_iter().collect()
}

fn memory_regions_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.iter().any(|other| other == value))
}

fn memory_region_has_boundary_prefix(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    child
        .strip_prefix(parent)
        .map(|suffix| suffix.starts_with('.') || suffix.starts_with('['))
        .unwrap_or(false)
}

fn memory_region_related(left: &str, right: &str) -> bool {
    memory_region_has_boundary_prefix(left, right) || memory_region_has_boundary_prefix(right, left)
}

fn memory_region_ancestor_chain(region: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = region.trim().to_string();
    while !current.is_empty() {
        if !out.iter().any(|existing| existing == &current) {
            out.push(current.clone());
        }
        if let Some(idx) = current.rfind('[') {
            current.truncate(idx);
            continue;
        }
        if let Some(idx) = current.rfind('.') {
            current.truncate(idx);
            continue;
        }
        break;
    }
    out
}

fn stable_hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn stable_hash_map_contents<K, V>(map: &HashMap<K, V>) -> u64
where
    K: Ord + Clone + Hash,
    V: Clone + Hash,
{
    let mut entries = map
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    stable_hash_value(&entries)
}

fn analysis_state_signature(fg: &FlowGraph) -> Vec<u64> {
    vec![
        fg.graph.edge_count() as u64,
        fg.object_shape_paths.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.node_memory_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.value_memory_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.cell_memory_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.region_graph_successors.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.node_points_to_classes.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.node_points_to_targets.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.cell_live_values.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.cell_live_regions.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.region_live_values.values().map(|values| values.len()).sum::<usize>() as u64,
        fg.region_live_cells.values().map(|values| values.len()).sum::<usize>() as u64,
        (fg.contextual_points_to_targets.values().map(|values| values.len()).sum::<usize>()
            + fg.contextual_points_to_object_ids.values().map(|values| values.len()).sum::<usize>()
            + fg.abstract_objects.len()
            + fg.object_seed_ids.len()) as u64,
        stable_hash_map_contents(&fg.object_shape_paths),
        stable_hash_map_contents(&fg.node_memory_regions),
        stable_hash_map_contents(&fg.value_memory_regions),
        stable_hash_map_contents(&fg.cell_memory_regions),
        stable_hash_map_contents(&fg.node_points_to_classes),
        stable_hash_map_contents(&fg.node_points_to_targets),
        stable_hash_map_contents(&fg.node_points_to_object_ids),
        stable_hash_map_contents(&fg.contextual_points_to_targets),
        stable_hash_map_contents(&fg.contextual_points_to_object_ids),
        stable_hash_map_contents(&fg.abstract_objects) ^ stable_hash_map_contents(&fg.object_seed_ids),
    ]
}

fn inferred_points_to_classes_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let mut classes = BTreeSet::new();
    if let Some(site) = value_identity_site(fg, func, value) {
        classes.insert(format!("site:{}", site.trim()));
    }
    if let Some(ty) = fg.value_types.get(&(func, value)) {
        let trimmed = ty.trim();
        if !trimmed.is_empty() {
            classes.insert(normalized_type_point_class(trimmed));
        }
    }
    if let Some(&node) = fg.values.get(&(func, value)) {
        for class in inferred_shape_point_classes_for_node(fg, node) {
            classes.insert(class);
        }
    }
    for region in memory_region_seed_for_value(fg, func, value) {
        classes.insert(region.replace("mem:", "region:"));
    }
    classes.into_iter().collect()
}

fn points_to_classes_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.iter().any(|other| other == value))
}

fn points_to_targets_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().any(|value| right.iter().any(|other| other == value))
}

fn is_precise_points_to_target(target: &str) -> bool {
    target.starts_with("obj:site:") || target.starts_with("cell:field:") || target.starts_with("cell:index:")
}

fn points_to_object_ids_overlap(left: &[u32], right: &[u32]) -> bool {
    left.iter().any(|value| right.iter().any(|other| other == value))
}

fn object_id_sets_definitely_disjoint(left: &[u32], right: &[u32]) -> bool {
    !left.is_empty() && !right.is_empty() && !points_to_object_ids_overlap(left, right)
}

fn stable_points_to_object_id_for_seed(seed: &AbstractObjectSeed) -> u32 {
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    let raw = hasher.finish();
    ((raw ^ (raw >> 32)) as u32).max(1)
}

fn abstract_object_seed_to_target(seed: &AbstractObjectSeed) -> String {
    match seed {
        AbstractObjectSeed::ValueSite(site) => format!("obj:site:{}", site),
        AbstractObjectSeed::ValueRootRegion(region) => format!("obj:root:{}", region),
        AbstractObjectSeed::ValueRegion(region) => format!("obj:region:{}", region),
        AbstractObjectSeed::ReturnRegion(region) => format!("obj:return:{}", region),
        AbstractObjectSeed::CallPort(port) => format!("obj:port:{}", port),
        AbstractObjectSeed::CellIdentity(key) => format!("cell:{}", key),
        AbstractObjectSeed::MemoryUnit(unit) => format!("memunit:{}", unit),
        AbstractObjectSeed::CellRegion(region) => format!("cell:region:{}", region),
        AbstractObjectSeed::SyntheticSource(name) => format!("obj:synthetic-source:{}", name),
        AbstractObjectSeed::SyntheticSink(name) => format!("obj:synthetic-sink:{}", name),
    }
}

fn insert_abstract_object_seed(fg: &mut FlowGraph, seed: &AbstractObjectSeed) -> u32 {
    if let Some(id) = fg.object_seed_ids.get(seed).copied() {
        return id;
    }
    let target = abstract_object_seed_to_target(seed);
    let mut id = stable_points_to_object_id_for_seed(seed);
    while let Some(existing) = fg.abstract_objects.get(&id) {
        if existing.canonical_target == target {
            fg.object_seed_ids.insert(seed.clone(), id);
            fg.points_to_object_ids.insert(target, id);
            return id;
        }
        id = id.wrapping_add(1).max(1);
    }
    fg.object_seed_ids.insert(seed.clone(), id);
    fg.points_to_object_ids.insert(target.clone(), id);
    fg.abstract_objects.insert(id, abstract_object_info_for_target(id, &target));
    id
}

fn abstract_object_seeds_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<AbstractObjectSeed> {
    let mut out = BTreeSet::new();
    if let Some(site) = value_identity_site(fg, func, value) {
        out.insert(AbstractObjectSeed::ValueSite(site.trim().to_string()));
    }
    for region in value_root_memory_regions(fg, func, value) {
        out.insert(AbstractObjectSeed::ValueRootRegion(region));
    }
    for region in fg.value_memory_regions_of(func, value) {
        out.insert(AbstractObjectSeed::ValueRegion(region));
    }
    out.into_iter().collect()
}

fn abstract_object_seeds_for_cell(fg: &FlowGraph, cell: NodeIndex) -> Vec<AbstractObjectSeed> {
    let mut out = BTreeSet::new();
    if let Some(key) = cell_abstract_identity_key(fg, cell) {
        out.insert(AbstractObjectSeed::CellIdentity(key));
    }
    if let Some(unit) = precise_memory_unit_key_for_cell(fg, cell) {
        out.insert(AbstractObjectSeed::MemoryUnit(unit));
    }
    for region in fg.cell_memory_regions_of(cell) {
        out.insert(AbstractObjectSeed::CellRegion(region));
    }
    out.into_iter().collect()
}

fn abstract_object_seeds_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<AbstractObjectSeed> {
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            abstract_object_seeds_for_value(fg, *func, *value)
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            abstract_object_seeds_for_cell(fg, node)
        }
        _ => Vec::new(),
    }
}

fn seeded_abstract_object_seeds(fg: &FlowGraph) -> BTreeSet<AbstractObjectSeed> {
    let mut seeds = BTreeSet::new();
    for (&(func, value), _) in &fg.values {
        for seed in abstract_object_seeds_for_value(fg, func, value) {
            seeds.insert(seed);
        }
    }
    for cell in all_cell_nodes(fg) {
        for seed in abstract_object_seeds_for_cell(fg, cell) {
            seeds.insert(seed);
        }
    }
    seeds
}

fn canonical_abstract_object_keys_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    abstract_object_seeds_for_value(fg, func, value)
        .into_iter()
        .map(|seed| abstract_object_seed_to_target(&seed))
        .collect()
}

fn canonical_abstract_object_keys_for_cell(fg: &FlowGraph, cell: NodeIndex) -> Vec<String> {
    abstract_object_seeds_for_cell(fg, cell)
        .into_iter()
        .map(|seed| abstract_object_seed_to_target(&seed))
        .collect()
}

fn canonical_abstract_object_keys_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    abstract_object_seeds_for_node(fg, node)
        .into_iter()
        .map(|seed| abstract_object_seed_to_target(&seed))
        .collect()
}

fn direct_seed_object_targets_for_node(fg: &FlowGraph, node: NodeIndex) -> Vec<String> {
    canonical_abstract_object_keys_for_node(fg, node)
}

fn materialize_abstract_object_catalog(fg: &mut FlowGraph) {
    fg.points_to_object_ids.clear();
    fg.object_seed_ids.clear();
    fg.abstract_objects.clear();
    fg.abstract_object_seed_nodes.clear();
    for seed in seeded_abstract_object_seeds(fg) {
        insert_abstract_object_seed(fg, &seed);
    }
    for node in fg.graph.node_indices() {
        let mut seeded_ids = BTreeSet::new();
        for seed in abstract_object_seeds_for_node(fg, node) {
            let id = insert_abstract_object_seed(fg, &seed);
            seeded_ids.insert(id);
        }
        if !seeded_ids.is_empty() {
            fg.abstract_object_seed_nodes
                .insert(node.index(), seeded_ids.into_iter().collect());
        }
    }
}

fn abstract_object_kind_for_target(target: &str) -> String {
    if target.starts_with("memunit:") {
        "memory-unit".to_string()
    } else if target.starts_with("cell:") {
        "cell".to_string()
    } else if target.starts_with("obj:site:") {
        "site".to_string()
    } else if target.starts_with("obj:root:") {
        "root-region".to_string()
    } else if target.starts_with("obj:return:") || target.starts_with("obj:return-func:") {
        "return".to_string()
    } else if target.starts_with("obj:region:") {
        "region".to_string()
    } else if target.starts_with("obj:port:") {
        "call-port".to_string()
    } else if target.starts_with("obj:synthetic-source:") {
        "synthetic-source".to_string()
    } else if target.starts_with("obj:synthetic-sink:") {
        "synthetic-sink".to_string()
    } else {
        "value".to_string()
    }
}

fn abstract_object_info_for_target(id: u32, target: &str) -> AbstractObjectInfo {
    let identity_site = target
        .strip_prefix("obj:site:")
        .or_else(|| target.strip_prefix("cell:field:"))
        .or_else(|| target.strip_prefix("cell:index:"))
        .or_else(|| target.strip_prefix("memunit:field:"))
        .or_else(|| target.strip_prefix("memunit:index:"))
        .map(|value| value.split(':').next().unwrap_or(value).trim().to_string());
    let root_regions = if let Some(region) = target.strip_prefix("obj:root:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("cell:region:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("obj:return:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("obj:port:") {
        vec![region.to_string()]
    } else if let Some(region) = target.strip_prefix("obj:region:") {
        vec![region.to_string()]
    } else {
        Vec::new()
    };
    AbstractObjectInfo {
        id,
        canonical_target: target.to_string(),
        kind: abstract_object_kind_for_target(target),
        identity_site,
        root_regions,
    }
}

fn precise_value_object_id(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Option<u32> {
    let site = value_identity_site(fg, func, value)?.trim().to_string();
    fg.points_to_object_ids.get(&format!("obj:site:{}", site)).copied()
}

fn precise_cell_object_id(fg: &FlowGraph, cell: NodeIndex) -> Option<u32> {
    if let Some(unit) = precise_memory_unit_key_for_cell(fg, cell) {
        if let Some(id) = fg.points_to_object_ids.get(&format!("memunit:{}", unit)).copied() {
            return Some(id);
        }
    }
    let key = cell_abstract_identity_key(fg, cell)?;
    fg.points_to_object_ids.get(&format!("cell:{}", key)).copied()
}

fn precise_memory_unit_key_for_cell(fg: &FlowGraph, cell: NodeIndex) -> Option<String> {
    match &fg.graph[cell] {
        FlowNode::FieldCell { func, base, field, .. } => {
            let base_object = precise_value_object_id(fg, *func, *base)?;
            Some(format!("mu:{base_object}:field:{field}"))
        }
        FlowNode::IndexCell { func, base, abstract_key, .. } if abstract_key != "*" => {
            let base_object = precise_value_object_id(fg, *func, *base)?;
            Some(format!("mu:{base_object}:index:{abstract_key}"))
        }
        _ => None,
    }
}

fn precise_memory_unit_cells(fg: &FlowGraph, unit_key: &str) -> Vec<NodeIndex> {
    let mut out = all_cell_nodes(fg)
        .into_iter()
        .filter(|candidate| precise_memory_unit_key_for_cell(fg, *candidate).as_deref() == Some(unit_key))
        .collect::<Vec<_>>();
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn target_sets_definitely_disjoint(left: &[String], right: &[String]) -> bool {
    !left.is_empty()
        && !right.is_empty()
        && !points_to_targets_overlap(left, right)
        && left.iter().all(|target| is_precise_points_to_target(target))
        && right.iter().all(|target| is_precise_points_to_target(target))
}

fn heap_projection_values_compatible(
    fg: &FlowGraph,
    left_func: FunctionId,
    left_value: ValueId,
    right_func: FunctionId,
    right_value: ValueId,
) -> bool {
    let left_site = value_identity_site(fg, left_func, left_value);
    let right_site = value_identity_site(fg, right_func, right_value);
    if left_site.is_some() && right_site.is_some() && left_site == right_site {
        return true;
    }
    if identity_sites_definitely_distinct(left_site, right_site) {
        return false;
    }
    let left_classes = inferred_points_to_classes_for_value(fg, left_func, left_value);
    let right_classes = inferred_points_to_classes_for_value(fg, right_func, right_value);
    if !left_classes.is_empty() && !right_classes.is_empty() && !points_to_classes_overlap(&left_classes, &right_classes) {
        let left_has_site = left_classes.iter().any(|value| value.starts_with("site:"));
        let right_has_site = right_classes.iter().any(|value| value.starts_with("site:"));
        if left_has_site || right_has_site {
            return false;
        }
    }
    let left_ty = fg.value_types.get(&(left_func, left_value)).map(|s| s.as_str());
    let right_ty = fg.value_types.get(&(right_func, right_value)).map(|s| s.as_str());
    object_types_compatible(left_ty, right_ty)
}

fn compute_literal_index_keys(func: &Function) -> HashMap<ValueId, String> {
    let mut literals = HashMap::new();
    let mut changed = true;
    while changed {
        changed = false;
        for block in &func.blocks {
            for inst in &block.insts {
                match &inst.kind {
                    InstKind::ConstInt { dst, value } => {
                        let key = value.to_string();
                        if literals.get(dst) != Some(&key) {
                            literals.insert(*dst, key);
                            changed = true;
                        }
                    }
                    InstKind::ConstString { dst, value } => {
                        if literals.get(dst) != Some(value) {
                            literals.insert(*dst, value.clone());
                            changed = true;
                        }
                    }
                    InstKind::Copy { dst, src } => {
                        if let Some(key) = literals.get(src).cloned() {
                            if literals.get(dst) != Some(&key) {
                                literals.insert(*dst, key);
                                changed = true;
                            }
                        }
                    }
                    InstKind::Phi { dst, inputs } => {
                        let mut iter = inputs.iter().filter_map(|input| literals.get(input));
                        if let Some(first) = iter.next().cloned() {
                            if iter.all(|key| key == &first) && literals.get(dst) != Some(&first) {
                                literals.insert(*dst, first);
                                changed = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    literals
}

fn abstract_index_key(literal_keys: &HashMap<ValueId, String>, index: ValueId) -> String {
    literal_keys.get(&index).cloned().unwrap_or_else(|| "*".to_string())
}

#[derive(Clone, Debug)]
pub struct BuildProgress {
    pub stage: &'static str,
    pub detail: String,
}

pub fn build(program: &Program, rules: &RuleSet) -> FlowGraph {
    build_with_progress(program, rules, |_| {})
}

pub fn build_with_progress<F>(program: &Program, rules: &RuleSet, mut on_progress: F) -> FlowGraph
where
    F: FnMut(BuildProgress),
{
    on_progress(BuildProgress {
        stage: "init",
        detail: format!("{} source files, {} functions", program.source_files.len(), program.functions.len()),
    });
    let mut fg = FlowGraph::default();
    fg.language = program.language.clone();
    for file in &program.source_files {
        fg.file_paths.insert(file.id, file.path.clone());
    }
    for (ty, parents) in &program.type_hierarchy {
        fg.type_hierarchy.insert(ty.clone(), parents.clone());
    }

    on_progress(BuildProgress {
        stage: "create-function-nodes",
        detail: format!("{} functions", program.functions.len()),
    });
    for func in &program.functions {
        fg.function_names.insert(func.id, func.name.clone());
        fg.function_spans.insert(func.id, func.span);
        for (value, span) in &func.value_spans {
            fg.value_spans.insert((func.id, *value), *span);
        }
        for (value, ty) in &func.value_types {
            fg.value_types.insert((func.id, *value), ty.clone());
        }
        create_function_nodes(&mut fg, func);
    }

    on_progress(BuildProgress {
        stage: "index-functions",
        detail: format!("{} candidate callees", program.functions.len()),
    });
    let func_index = FunctionIndex::new(program);

    on_progress(BuildProgress {
        stage: "scan-function-bodies",
        detail: format!("{} functions", program.functions.len()),
    });
    for func in &program.functions {
        let ret_node = *fg
            .function_returns
            .get(&func.id)
            .expect("return node must exist");
        let alias_roots = compute_value_alias_representatives(func);
        let heap_alias_roots = compute_heap_alias_representatives(func);
        let (object_identity_roots, object_identity_sites) = compute_object_identity_representatives(func);
        let literal_index_keys = compute_literal_index_keys(func);
        for (value, root) in &alias_roots {
            fg.value_alias_roots.insert((func.id, *value), *root);
        }
        for (value, root) in &heap_alias_roots {
            fg.heap_alias_roots.insert((func.id, *value), *root);
        }
        for (value, root) in &object_identity_roots {
            fg.object_identity_roots.insert((func.id, *value), *root);
        }
        for (value, site) in &object_identity_sites {
            fg.object_identity_sites.insert((func.id, *value), site.clone());
        }
        let mut abstract_field_cells: HashMap<(ValueId, String), NodeIndex> = HashMap::new();
        let mut abstract_index_cells: HashMap<(ValueId, String), NodeIndex> = HashMap::new();

        for block in &func.blocks {
            for inst in &block.insts {
                fg.inst_spans.insert((func.id, inst.id), inst.span);
                match &inst.kind {
                    InstKind::ConstInt { .. } | InstKind::ConstString { .. } => {}
                    InstKind::Copy { dst, src } => {
                        edge_value_to_value(&mut fg, func.id, *src, *dst, EdgeKind::Assign);
                    }
                    InstKind::Phi { dst, inputs } => {
                        for input in inputs {
                            edge_value_to_value(&mut fg, func.id, *input, *dst, EdgeKind::Phi);
                        }
                    }
                    InstKind::LoadField { dst, base, field } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let field_key = (canonical_base, field.clone());
                        let field_cell = *abstract_field_cells.entry(field_key.clone()).or_insert_with(|| {
                            let node = fg.graph.add_node(FlowNode::FieldCell {
                                func: func.id,
                                block: block.id,
                                inst: inst.id,
                                base: canonical_base,
                                field: field.clone(),
                            });
                            fg.field_cells.insert((func.id, canonical_base, field.clone()), node);
                            node
                        });
                        let base_node = value_node(&fg, func.id, *base);
                        let dst_node = value_node(&fg, func.id, *dst);
                        fg.graph.add_edge(
                            base_node,
                            field_cell,
                            FlowEdge {
                                kind: EdgeKind::LoadField {
                                    field: field.clone(),
                                },
                            },
                        );
                        connect_cell_projected_values_to_dst(
                            &mut fg,
                            field_cell,
                            func.id,
                            *dst,
                            EdgeKind::LoadField {
                                field: field.clone(),
                            },
                        );
                    }
                    InstKind::StoreField { base, field, src } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let field_key = (canonical_base, field.clone());
                        let field_cell = *abstract_field_cells.entry(field_key.clone()).or_insert_with(|| {
                            let node = fg.graph.add_node(FlowNode::FieldCell {
                                func: func.id,
                                block: block.id,
                                inst: inst.id,
                                base: canonical_base,
                                field: field.clone(),
                            });
                            fg.field_cells.insert((func.id, canonical_base, field.clone()), node);
                            node
                        });
                        let src_node = value_node(&fg, func.id, *src);
                        fg.graph.add_edge(
                            src_node,
                            field_cell,
                            FlowEdge {
                                kind: EdgeKind::StoreField {
                                    field: field.clone(),
                                },
                            },
                        );
                    }
                    InstKind::LoadIndex { dst, base, index } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let key = abstract_index_key(&literal_index_keys, *index);
                        let cell = *abstract_index_cells.entry((canonical_base, key.clone())).or_insert_with(|| {
                            let node = fg.graph.add_node(FlowNode::IndexCell {
                                func: func.id,
                                block: block.id,
                                inst: inst.id,
                                base: canonical_base,
                                index: *index,
                                abstract_key: key.clone(),
                            });
                            fg.index_cells.insert((func.id, canonical_base, key.clone()), node);
                            node
                        });
                        let base_node = value_node(&fg, func.id, *base);
                        let dst_node = value_node(&fg, func.id, *dst);
                        fg.graph.add_edge(base_node, cell, FlowEdge { kind: EdgeKind::LoadIndex });
                        connect_cell_projected_values_to_dst(&mut fg, cell, func.id, *dst, EdgeKind::LoadIndex);
                    }
                    InstKind::StoreIndex { base, index, src } => {
                        let canonical_base = canonical_heap_value(&fg, func.id, *base);
                        let key = abstract_index_key(&literal_index_keys, *index);
                        let cell = *abstract_index_cells.entry((canonical_base, key.clone())).or_insert_with(|| {
                            let node = fg.graph.add_node(FlowNode::IndexCell {
                                func: func.id,
                                block: block.id,
                                inst: inst.id,
                                base: canonical_base,
                                index: *index,
                                abstract_key: key.clone(),
                            });
                            fg.index_cells.insert((func.id, canonical_base, key.clone()), node);
                            node
                        });
                        let src_node = value_node(&fg, func.id, *src);
                        fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
                    }
                    InstKind::Call(call) => {
                        let meta = build_call_meta(&fg, func, inst.id, call, inst.span);
                        fg.call_meta.insert((func.id, inst.id), meta.clone());
                        connect_call_value_ports(&mut fg, func.id, inst.id, call);

                        connect_builtin_python_container_semantics(&mut fg, func.id, call, &meta, &literal_index_keys);
                        connect_python_container_semantics(&mut fg, func.id, call, &meta, &literal_index_keys);
                        let mut resolved_targets = Vec::new();
                        for callee_func in func_index.resolve_call(&meta) {
                            if !resolved_targets.iter().any(|existing| existing == &callee_func.name) {
                                resolved_targets.push(callee_func.name.clone());
                            }
                            connect_internal_call(&mut fg, func.id, inst.id, call, callee_func, ret_node);
                        }
                        if !resolved_targets.is_empty() {
                            fg.resolved_internal_targets.insert((func.id, inst.id), resolved_targets);
                        }
                        connect_rule_summaries(&mut fg, rules, func.id, inst.id, &meta);
                        attach_rule_sources_and_sinks(&mut fg, rules, func.id, inst.id, &meta);
                    }
                }
            }

            if let Terminator::Return(value) = &block.term {
                if let Some(v) = value {
                    let src_node = value_node(&fg, func.id, *v);
                    fg.graph.add_edge(src_node, ret_node, FlowEdge { kind: EdgeKind::Assign });
                }
            }
        }
    }

    on_progress(BuildProgress {
        stage: "sparse-adjacency-1",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });
    materialize_sparse_data_adjacency(&mut fg);
    on_progress(BuildProgress {
        stage: "global-closure-1",
        detail: format!("{} functions", program.functions.len()),
    });
    materialize_global_solver_closure(&mut fg, program);
    on_progress(BuildProgress {
        stage: "aggregate-partitions-1",
        detail: format!("{} contextual states", fg.contextual_points_to_targets.len()),
    });
    aggregate_partitioned_points_to_state(&mut fg);
    on_progress(BuildProgress {
        stage: "sparse-adjacency-2",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });
    materialize_sparse_data_adjacency(&mut fg);
    on_progress(BuildProgress {
        stage: "bridge-internal-heap-cells",
        detail: format!("{} functions", program.functions.len()),
    });
    bridge_internal_heap_cells(&mut fg, program);
    on_progress(BuildProgress {
        stage: "global-closure-2",
        detail: format!("{} functions", program.functions.len()),
    });
    materialize_global_solver_closure(&mut fg, program);
    on_progress(BuildProgress {
        stage: "aggregate-partitions-2",
        detail: format!("{} contextual states", fg.contextual_points_to_targets.len()),
    });
    aggregate_partitioned_points_to_state(&mut fg);
    on_progress(BuildProgress {
        stage: "sparse-adjacency-3",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });
    materialize_sparse_data_adjacency(&mut fg);
    on_progress(BuildProgress {
        stage: "done",
        detail: format!("{} graph nodes", fg.graph.node_count()),
    });

    fg
}

#[derive(Default)]
struct FunctionIndex<'a> {
    exact: HashMap<&'a str, Vec<&'a Function>>,
    exact_arity: HashMap<(String, usize), Vec<&'a Function>>,
    simple: HashMap<String, Vec<&'a Function>>,
    simple_arity: HashMap<(String, usize), Vec<&'a Function>>,
    owner_method: HashMap<(String, String), Vec<&'a Function>>,
    owner_method_arity: HashMap<(String, String, usize), Vec<&'a Function>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ParamBindingKind {
    Positional,
    VarArgs,
    KwArgs,
    Capture,
}

#[derive(Clone, Debug)]
struct ParamBindingSpec {
    name: String,
    kind: ParamBindingKind,
    has_default: bool,
    keyword_only: bool,
    ir_index: usize,
}

impl<'a> FunctionIndex<'a> {
    fn new(program: &'a Program) -> Self {
        let mut index = Self::default();
        for func in &program.functions {
            let supported_arities = function_supported_arities(func);
            index.exact.entry(func.name.as_str()).or_default().push(func);
            for arity in &supported_arities {
                index
                    .exact_arity
                    .entry((func.name.clone(), *arity))
                    .or_default()
                    .push(func);
            }
            for key in candidate_names(&func.name) {
                index.simple.entry(key.clone()).or_default().push(func);
                for arity in &supported_arities {
                    index.simple_arity.entry((key.clone(), *arity)).or_default().push(func);
                }
            }
            if let Some(method) = func.name.rsplit('.').next() {
                if let Some(owner) = func.attrs.get("owner_type") {
                    index
                        .owner_method
                        .entry((owner.clone(), method.to_string()))
                        .or_default()
                        .push(func);
                    for arity in &supported_arities {
                        index
                            .owner_method_arity
                            .entry((owner.clone(), method.to_string(), *arity))
                            .or_default()
                            .push(func);
                    }
                }
            }
        }
        index
    }

    fn resolve_named_callable(
        &self,
        name: &str,
        arg_count: usize,
        arg_types: &[Option<String>],
        arg_type_candidates: &[Vec<String>],
    ) -> Vec<&'a Function> {
        let meta = CallMeta {
            func: FunctionId(0),
            inst: InstId(0),
            function_name: String::new(),
            callee_name: Some(name.to_string()),
            receiver_type: None,
            receiver_type_candidates: Vec::new(),
            method_name: None,
            arg_count,
            arg_types: arg_types.to_vec(),
            arg_type_candidates: arg_type_candidates.to_vec(),
            span: Span::default(),
        };
        self.resolve_call(&meta)
    }

    fn resolve_call(&self, meta: &CallMeta) -> Vec<&'a Function> {
        let mut out: Vec<&'a Function> = Vec::new();
        if let Some(method_name) = meta.method_name.as_deref() {
            if let Some(arg_count) = Some(meta.arg_count) {
                for owner in meta
                    .receiver_type_candidates
                    .iter()
                    .chain(meta.receiver_type.iter())
                {
                    if let Some(found) = self
                        .owner_method_arity
                        .get(&(owner.clone(), method_name.to_string(), arg_count))
                    {
                        for func in found {
                            if !out.iter().any(|existing| existing.id == func.id) {
                                out.push(*func);
                            }
                        }
                    }
                }
            }
            if out.is_empty() {
                for owner in meta
                    .receiver_type_candidates
                    .iter()
                    .chain(meta.receiver_type.iter())
                {
                    if let Some(found) = self.owner_method.get(&(owner.clone(), method_name.to_string())) {
                        for func in found {
                            if !out.iter().any(|existing| existing.id == func.id) {
                                out.push(*func);
                            }
                        }
                    }
                }
            }
            let refined = refine_by_argument_types(out.clone(), meta);
            if !refined.is_empty() {
                return refined;
            }
            if !out.is_empty() {
                return out;
            }
        }
        let Some(name) = meta.callee_name.as_deref() else {
            return out;
        };
        if let Some(found) = self.exact_arity.get(&(name.to_string(), meta.arg_count)) {
            let refined = refine_by_argument_types(found.clone(), meta);
            if !refined.is_empty() {
                return refined;
            }
            return found.clone();
        }
        if let Some(found) = self.exact.get(name) {
            if found.len() == 1 {
                return found.clone();
            }
        }
        for key in candidate_names(name) {
            if let Some(found) = self.simple_arity.get(&(key.clone(), meta.arg_count)) {
                for func in found {
                    if !out.iter().any(|existing| existing.id == func.id) {
                        out.push(*func);
                    }
                }
            }
        }
        let refined = refine_by_argument_types(out.clone(), meta);
        if !refined.is_empty() {
            return refined;
        }
        if !out.is_empty() {
            return out;
        }
        for key in candidate_names(name) {
            if let Some(found) = self.simple.get(&key) {
                for func in found {
                    if !out.iter().any(|existing| existing.id == func.id) {
                        out.push(*func);
                    }
                }
            }
        }
        let refined = refine_by_argument_types(out.clone(), meta);
        if !refined.is_empty() {
            return refined;
        }
        out
    }
}

fn refine_by_argument_types<'a>(funcs: Vec<&'a Function>, meta: &CallMeta) -> Vec<&'a Function> {
    if funcs.len() <= 1 {
        return funcs;
    }
    let mut best_score: Option<usize> = None;
    let mut out = Vec::new();
    for func in funcs {
        let Some(score) = score_function_signature(func, meta) else {
            continue;
        };
        match best_score {
            None => {
                best_score = Some(score);
                out.push(func);
            }
            Some(existing) if score > existing => {
                best_score = Some(score);
                out.clear();
                out.push(func);
            }
            Some(existing) if score == existing => {
                out.push(func);
            }
            _ => {}
        }
    }
    out
}

fn score_function_signature(func: &Function, meta: &CallMeta) -> Option<usize> {
    let expected = function_param_type_names(func);
    if expected.len() != meta.arg_count {
        return None;
    }
    let mut score = 0usize;
    let mut seen_known = false;
    for (idx, expected_ty) in expected.iter().enumerate() {
        let Some(expected_ty) = expected_ty.as_deref() else {
            continue;
        };
        let actual_ty = meta.arg_types.get(idx).and_then(|ty| ty.clone());
        let actual_candidates = meta.arg_type_candidates.get(idx).cloned().unwrap_or_default();
        let Some(actual_ty) = actual_ty else {
            continue;
        };
        seen_known = true;
        if actual_ty == expected_ty {
            score += 2;
            continue;
        }
        if actual_candidates.iter().any(|candidate| candidate == expected_ty) {
            score += 1;
            continue;
        }
        return None;
    }
    Some(if seen_known { score } else { 0 })
}

fn function_param_type_names(func: &Function) -> Vec<Option<String>> {
    function_param_specs(func)
        .into_iter()
        .map(|spec| func.params.get(spec.ir_index).and_then(|value| func.value_types.get(value).cloned()))
        .collect()
}

fn function_receiver_offset(func: &Function) -> usize {
    func.attrs
        .get("has_receiver")
        .map(|value| value == "1")
        .unwrap_or_else(|| func.attrs.contains_key("owner_type"))
        as usize
}

fn function_param_specs(func: &Function) -> Vec<ParamBindingSpec> {
    let offset = function_receiver_offset(func);
    let names = func
        .attrs
        .get("param_names")
        .map(|value| {
            value
                .split('\u{1f}')
                .filter(|part| !part.is_empty())
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let count = func
        .attrs
        .get("arity")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(names.len());
    if count == 0 {
        return Vec::new();
    }
    let kinds = func
        .attrs
        .get("param_kinds")
        .map(|value| value.split('\u{1f}').map(|part| part.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    let defaults = func
        .attrs
        .get("param_defaults")
        .map(|value| value.split('\u{1f}').map(|part| part.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    let keyword_only = func
        .attrs
        .get("param_keyword_only")
        .map(|value| value.split('\u{1f}').map(|part| part.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    (0..count)
        .map(|idx| ParamBindingSpec {
            name: names.get(idx).cloned().unwrap_or_else(|| format!("arg{idx}")),
            kind: match kinds.get(idx).map(|value| value.as_str()) {
                Some("var") => ParamBindingKind::VarArgs,
                Some("kw") => ParamBindingKind::KwArgs,
                Some("cap") => ParamBindingKind::Capture,
                _ => ParamBindingKind::Positional,
            },
            has_default: defaults.get(idx).is_some_and(|value| value == "1"),
            keyword_only: keyword_only.get(idx).is_some_and(|value| value == "1"),
            ir_index: idx + offset,
        })
        .collect()
}

fn function_supported_arities(func: &Function) -> Vec<usize> {
    let specs = function_param_specs(func);
    if specs.is_empty() {
        let visible = func
            .attrs
            .get("arity")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        return vec![visible];
    }

    let mut min = 0usize;
    let mut max = 0usize;
    for spec in specs {
        if spec.kind == ParamBindingKind::Positional {
            max += 1;
            if !spec.has_default {
                min += 1;
            }
        }
    }
    let mut out = (min..=max).collect::<Vec<_>>();
    if out.is_empty() {
        out.push(0);
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn function_capture_names(func: &Function) -> Vec<String> {
    func.attrs
        .get("capture_names")
        .map(|value| {
            value
                .split('\u{1f}')
                .filter(|part| !part.is_empty())
                .map(|part| part.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn capture_param_ir_indices(func: &Function) -> Vec<(usize, String)> {
    let offset = function_receiver_offset(func);
    let visible = function_param_specs(func).len();
    function_capture_names(func)
        .into_iter()
        .enumerate()
        .map(|(idx, name)| (offset + visible + idx, name))
        .collect()
}

fn candidate_names(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    out.push(name.to_string());
    if let Some(last) = name.rsplit('.').next() {
        out.push(last.to_string());
    }
    if let Some(last) = name.rsplit("::").next() {
        out.push(last.to_string());
    }
    if let Some((_, tail)) = name.rsplit_once('.') {
        out.push(tail.to_string());
    }
    out.sort();
    out.dedup();
    out
}

impl FlowGraph {
    pub fn ensure_value(&mut self, func: FunctionId, value: ValueId) -> NodeIndex {
        if let Some(node) = self.values.get(&(func, value)).copied() {
            return node;
        }
        let node = self.graph.add_node(FlowNode::Value { func, value });
        self.values.insert((func, value), node);
        node
    }

    pub fn materialize_sparse_data_adjacency(&mut self) {
        materialize_sparse_data_adjacency(self);
    }

    pub fn successors(&self, node: NodeIndex) -> impl Iterator<Item = NodeIndex> + '_ {
        self.graph.neighbors_directed(node, petgraph::Direction::Outgoing)
    }

    pub fn sparse_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        if let Some(values) = self.sparse_successors.get(&node.index()) {
            return values.iter().copied().map(NodeIndex::new).collect();
        }
        self.graph
            .edges_directed(node, petgraph::Direction::Outgoing)
            .filter(|edge| is_sparse_data_edge(&edge.weight().kind))
            .map(|edge| edge.target())
            .collect()
    }

    pub fn sparse_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        if let Some(values) = self.sparse_predecessors.get(&node.index()) {
            return values.iter().copied().map(NodeIndex::new).collect();
        }
        self.graph
            .edges_directed(node, petgraph::Direction::Incoming)
            .filter(|edge| is_sparse_data_edge(&edge.weight().kind))
            .map(|edge| edge.source())
            .collect()
    }

    pub fn sparse_reachable_nodes(&self, seeds: &[NodeIndex], forward: bool, max_depth: usize) -> Vec<NodeIndex> {
        let direction = if forward {
            SparseDirection::Forward
        } else {
            SparseDirection::Backward
        };
        self.sparse_traversal(seeds, direction, max_depth, usize::MAX)
            .visited
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn sparse_neighbors_of(&self, node: NodeIndex, direction: SparseDirection) -> Vec<NodeIndex> {
        match direction {
            SparseDirection::Forward => self.sparse_successors_of(node),
            SparseDirection::Backward => self.sparse_predecessors_of(node),
        }
    }

    pub fn heap_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_value_successors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn heap_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_value_predecessors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }


    pub fn heap_object_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_object_successors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn heap_object_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.heap_object_predecessors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn object_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        let mut out = self.heap_object_successors_of(node);
        out.extend(self.object_graph_successors_of(node));
        out.sort_unstable_by_key(|idx| idx.index());
        out.dedup_by_key(|idx| idx.index());
        out
    }

    pub fn object_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        let mut out = self.heap_object_predecessors_of(node);
        out.extend(self.object_graph_predecessors_of(node));
        out.sort_unstable_by_key(|idx| idx.index());
        out.dedup_by_key(|idx| idx.index());
        out
    }

    pub fn object_graph_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.object_graph_successors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn object_graph_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.object_graph_predecessors
            .get(&node.index())
            .map(|values| values.iter().copied().map(NodeIndex::new).collect())
            .unwrap_or_default()
    }

    pub fn object_graph_edge_label(&self, src: NodeIndex, dst: NodeIndex) -> Option<&str> {
        self.object_graph_labels
            .get(&(src.index(), dst.index()))
            .map(|value| value.as_str())
    }

    pub fn object_shape_labels_of(&self, node: NodeIndex) -> Vec<String> {
        self.object_shape_labels.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn object_shape_paths_of(&self, node: NodeIndex) -> Vec<String> {
        self.object_shape_paths.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn node_memory_regions_of(&self, node: NodeIndex) -> Vec<String> {
        self.node_memory_regions.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_memory_regions_of(&self, func: FunctionId, value: ValueId) -> Vec<String> {
        self.value_memory_regions.get(&(func, value)).cloned().unwrap_or_default()
    }

    pub fn cell_memory_regions_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_memory_regions.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn region_graph_successors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.region_graph_successors
            .get(&node.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn region_graph_predecessors_of(&self, node: NodeIndex) -> Vec<NodeIndex> {
        self.region_graph_predecessors
            .get(&node.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn cell_live_values_of(&self, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
        self
            .cell_live_values
            .get(&cell.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn cell_live_regions_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_live_regions.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn region_live_values_of(&self, region: &str) -> Vec<(FunctionId, ValueId)> {
        self.region_live_values
            .get(region)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn region_live_cells_of(&self, region: &str) -> Vec<NodeIndex> {
        self.region_live_cells
            .get(region)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn node_points_to_classes_of(&self, node: NodeIndex) -> Vec<String> {
        self.node_points_to_classes.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_points_to_classes_of(&self, func: FunctionId, value: ValueId) -> Vec<String> {
        self.value_points_to_classes
            .get(&(func, value))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cell_points_to_classes_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_points_to_classes.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn node_points_to_targets_of(&self, node: NodeIndex) -> Vec<String> {
        self.node_points_to_targets.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_points_to_targets_of(&self, func: FunctionId, value: ValueId) -> Vec<String> {
        self.value_points_to_targets
            .get(&(func, value))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cell_points_to_targets_of(&self, cell: NodeIndex) -> Vec<String> {
        self.cell_points_to_targets.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn node_points_to_object_ids_of(&self, node: NodeIndex) -> Vec<u32> {
        self.node_points_to_object_ids.get(&node.index()).cloned().unwrap_or_default()
    }

    pub fn value_points_to_object_ids_of(&self, func: FunctionId, value: ValueId) -> Vec<u32> {
        self.value_points_to_object_ids
            .get(&(func, value))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cell_points_to_object_ids_of(&self, cell: NodeIndex) -> Vec<u32> {
        self.cell_points_to_object_ids.get(&cell.index()).cloned().unwrap_or_default()
    }

    pub fn contextual_node_points_to_targets_of(&self, context: &CallContextKey, node: NodeIndex) -> Vec<String> {
        self.contextual_node_points_to_targets
            .get(&(context.clone(), node.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_value_points_to_targets_of(&self, context: &CallContextKey, func: FunctionId, value: ValueId) -> Vec<String> {
        self.contextual_value_points_to_targets
            .get(&(context.clone(), func.0, value.0))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_cell_points_to_targets_of(&self, context: &CallContextKey, cell: NodeIndex) -> Vec<String> {
        self.contextual_cell_points_to_targets
            .get(&(context.clone(), cell.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_node_points_to_object_ids_of(&self, context: &CallContextKey, node: NodeIndex) -> Vec<u32> {
        self.contextual_node_points_to_object_ids
            .get(&(context.clone(), node.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_value_points_to_object_ids_of(&self, context: &CallContextKey, func: FunctionId, value: ValueId) -> Vec<u32> {
        self.contextual_value_points_to_object_ids
            .get(&(context.clone(), func.0, value.0))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_cell_points_to_object_ids_of(&self, context: &CallContextKey, cell: NodeIndex) -> Vec<u32> {
        self.contextual_cell_points_to_object_ids
            .get(&(context.clone(), cell.index()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn contextual_return_values_of(&self, context: &CallContextKey) -> Vec<(FunctionId, ValueId)> {
        self.contextual_return_values
            .get(context)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn contextual_return_cells_of(&self, context: &CallContextKey) -> Vec<NodeIndex> {
        self.contextual_return_cells
            .get(context)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(NodeIndex::new)
            .collect()
    }

    pub fn contextual_points_to_object_ids_of(&self, context: &CallContextKey) -> Vec<u32> {
        self.contextual_points_to_object_ids
            .get(context)
            .cloned()
            .unwrap_or_default()
    }

    pub fn is_strong_update_cell(&self, cell: NodeIndex) -> bool {
        self.strong_update_cells.contains(&cell.index())
    }

    pub fn value_must_alias(
        &self,
        left_func: FunctionId,
        left_value: ValueId,
        right_func: FunctionId,
        right_value: ValueId,
    ) -> bool {
        if left_func == right_func && left_value == right_value {
            return true;
        }
        let left_precise = precise_value_object_id(self, left_func, left_value);
        let right_precise = precise_value_object_id(self, right_func, right_value);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_site = value_identity_site(self, left_func, left_value);
        let right_site = value_identity_site(self, right_func, right_value);
        if left_site.is_some() && right_site.is_some() {
            return left_site == right_site;
        }
        let left_object_ids = self.value_points_to_object_ids_of(left_func, left_value);
        let right_object_ids = self.value_points_to_object_ids_of(right_func, right_value);
        if !left_object_ids.is_empty()
            && left_object_ids == right_object_ids
            && left_object_ids.len() == 1
        {
            return true;
        }
        let left_targets = self.value_points_to_targets_of(left_func, left_value);
        let right_targets = self.value_points_to_targets_of(right_func, right_value);
        !left_targets.is_empty()
            && left_targets == right_targets
            && left_targets.len() == 1
            && left_targets.iter().all(|target| is_precise_points_to_target(target))
    }

    pub fn value_may_alias(
        &self,
        left_func: FunctionId,
        left_value: ValueId,
        right_func: FunctionId,
        right_value: ValueId,
    ) -> bool {
        let left_precise = precise_value_object_id(self, left_func, left_value);
        let right_precise = precise_value_object_id(self, right_func, right_value);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_site = value_identity_site(self, left_func, left_value);
        let right_site = value_identity_site(self, right_func, right_value);
        if left_site.is_some() && right_site.is_some() {
            return left_site == right_site;
        }
        if identity_sites_definitely_distinct(left_site, right_site) {
            return false;
        }
        let left_object_ids = self.value_points_to_object_ids_of(left_func, left_value);
        let right_object_ids = self.value_points_to_object_ids_of(right_func, right_value);
        if !left_object_ids.is_empty() && !right_object_ids.is_empty() {
            if points_to_object_ids_overlap(&left_object_ids, &right_object_ids) {
                return true;
            }
            if object_id_sets_definitely_disjoint(&left_object_ids, &right_object_ids) {
                return false;
            }
        }
        let left_targets = self.value_points_to_targets_of(left_func, left_value);
        let right_targets = self.value_points_to_targets_of(right_func, right_value);
        if !left_targets.is_empty() && !right_targets.is_empty() {
            if points_to_targets_overlap(&left_targets, &right_targets) {
                return true;
            }
            if target_sets_definitely_disjoint(&left_targets, &right_targets) {
                return false;
            }
        }
        let left_regions = self.value_memory_regions_of(left_func, left_value);
        let right_regions = self.value_memory_regions_of(right_func, right_value);
        if !left_regions.is_empty() && !right_regions.is_empty() && memory_regions_overlap(&left_regions, &right_regions) {
            return true;
        }
        let left_classes = self.value_points_to_classes_of(left_func, left_value);
        let right_classes = self.value_points_to_classes_of(right_func, right_value);
        if !left_classes.is_empty() && !right_classes.is_empty() {
            return points_to_classes_overlap(&left_classes, &right_classes);
        }
        let left_ty = self.value_types.get(&(left_func, left_value)).map(|s| s.as_str());
        let right_ty = self.value_types.get(&(right_func, right_value)).map(|s| s.as_str());
        object_types_compatible(left_ty, right_ty)
    }

    pub fn cell_must_alias(&self, left: NodeIndex, right: NodeIndex) -> bool {
        if left == right {
            return true;
        }
        let left_unit = precise_memory_unit_key_for_cell(self, left);
        let right_unit = precise_memory_unit_key_for_cell(self, right);
        if left_unit.is_some() && right_unit.is_some() {
            return left_unit == right_unit;
        }
        let left_precise = precise_cell_object_id(self, left);
        let right_precise = precise_cell_object_id(self, right);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_object_ids = self.cell_points_to_object_ids_of(left);
        let right_object_ids = self.cell_points_to_object_ids_of(right);
        if !left_object_ids.is_empty()
            && left_object_ids == right_object_ids
            && left_object_ids.len() == 1
        {
            return true;
        }
        let left_targets = self.cell_points_to_targets_of(left);
        let right_targets = self.cell_points_to_targets_of(right);
        !left_targets.is_empty()
            && left_targets == right_targets
            && left_targets.len() == 1
            && left_targets.iter().all(|target| is_precise_points_to_target(target))
    }

    pub fn cell_may_alias(&self, left: NodeIndex, right: NodeIndex) -> bool {
        if left == right {
            return true;
        }
        let left_unit = precise_memory_unit_key_for_cell(self, left);
        let right_unit = precise_memory_unit_key_for_cell(self, right);
        if left_unit.is_some() && right_unit.is_some() {
            return left_unit == right_unit;
        }
        let left_precise = precise_cell_object_id(self, left);
        let right_precise = precise_cell_object_id(self, right);
        if left_precise.is_some() && right_precise.is_some() {
            return left_precise == right_precise;
        }
        let left_object_ids = self.cell_points_to_object_ids_of(left);
        let right_object_ids = self.cell_points_to_object_ids_of(right);
        if !left_object_ids.is_empty() && !right_object_ids.is_empty() {
            if points_to_object_ids_overlap(&left_object_ids, &right_object_ids) {
                return true;
            }
            if object_id_sets_definitely_disjoint(&left_object_ids, &right_object_ids) {
                return false;
            }
        }
        let left_targets = self.cell_points_to_targets_of(left);
        let right_targets = self.cell_points_to_targets_of(right);
        if !left_targets.is_empty() && !right_targets.is_empty() {
            if points_to_targets_overlap(&left_targets, &right_targets) {
                return true;
            }
            if target_sets_definitely_disjoint(&left_targets, &right_targets) {
                return false;
            }
        }
        let left_regions = self.cell_memory_regions_of(left);
        let right_regions = self.cell_memory_regions_of(right);
        if !left_regions.is_empty() && !right_regions.is_empty() && memory_regions_overlap(&left_regions, &right_regions) {
            return true;
        }
        let left_classes = self.cell_points_to_classes_of(left);
        let right_classes = self.cell_points_to_classes_of(right);
        if !left_classes.is_empty() && !right_classes.is_empty() {
            return points_to_classes_overlap(&left_classes, &right_classes);
        }
        match (&self.graph[left], &self.graph[right]) {
            (
                FlowNode::FieldCell { func: lf, base: lb, field: lfield, .. },
                FlowNode::FieldCell { func: rf, base: rb, field: rfield, .. },
            ) if lfield == rfield => self.value_may_alias(*lf, *lb, *rf, *rb),
            (
                FlowNode::IndexCell { func: lf, base: lb, abstract_key: lkey, .. },
                FlowNode::IndexCell { func: rf, base: rb, abstract_key: rkey, .. },
            ) if lkey == rkey || lkey == "*" || rkey == "*" => self.value_may_alias(*lf, *lb, *rf, *rb),
            _ => false,
        }
    }

    fn demand_query_neighbors_of(
        &self,
        node: NodeIndex,
        direction: SparseDirection,
        include_heap: bool,
    ) -> Vec<NodeIndex> {
        let mut out = self.sparse_neighbors_of(node, direction);
        if include_heap {
            let heap = match direction {
                SparseDirection::Forward => self.heap_successors_of(node),
                SparseDirection::Backward => self.heap_predecessors_of(node),
            };
            for neighbor in heap {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
            let object = match direction {
                SparseDirection::Forward => self.heap_object_successors_of(node),
                SparseDirection::Backward => self.heap_object_predecessors_of(node),
            };
            for neighbor in object {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
            let object_graph = match direction {
                SparseDirection::Forward => self.object_graph_successors_of(node),
                SparseDirection::Backward => self.object_graph_predecessors_of(node),
            };
            for neighbor in object_graph {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
            let region_graph = match direction {
                SparseDirection::Forward => self.region_graph_successors_of(node),
                SparseDirection::Backward => self.region_graph_predecessors_of(node),
            };
            for neighbor in region_graph {
                if !out.contains(&neighbor) {
                    out.push(neighbor);
                }
            }
        }
        out.sort_unstable_by_key(|node| node.index());
        out.dedup_by_key(|node| node.index());
        out
    }

    fn demand_query_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let mut seen = HashSet::new();
        let mut frontier = seeds.to_vec();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for node in frontier {
                if out.visited.len() >= max_visits {
                    out.frontier_cutoff = true;
                    return out;
                }
                if !seen.insert(node) {
                    continue;
                }
                out.visited.push(node.index());
                layer.push(node.index());
                for neighbor in self.demand_query_neighbors_of(node, direction, include_heap) {
                    if !seen.contains(&neighbor) {
                        next.push(neighbor);
                    }
                }
            }
            if !layer.is_empty() {
                out.layers.push(layer);
            }
            frontier = next;
            depth += 1;
        }
        out
    }

    fn contextual_demand_query_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
        context: &CallContextKey,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let mut seen = HashSet::new();
        let mut frontier = seeds
            .iter()
            .copied()
            .filter(|node| self.node_matches_call_context(*node, context))
            .collect::<Vec<_>>();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for node in frontier {
                if out.visited.len() >= max_visits {
                    out.frontier_cutoff = true;
                    return out;
                }
                if !self.node_matches_call_context(node, context) || !seen.insert(node) {
                    continue;
                }
                out.visited.push(node.index());
                layer.push(node.index());
                for neighbor in self.demand_query_neighbors_of(node, direction, include_heap) {
                    if self.node_matches_call_context(neighbor, context) && !seen.contains(&neighbor) {
                        next.push(neighbor);
                    }
                }
            }
            if !layer.is_empty() {
                layer.sort_unstable();
                layer.dedup();
                out.layers.push(layer);
            }
            next.sort_unstable_by_key(|node| node.index());
            next.dedup_by_key(|node| node.index());
            frontier = next;
            depth += 1;
        }
        out
    }

    fn contextual_demand_query_fixpoint_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
        context: &CallContextKey,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let (components, node_to_component, succ, pred) = self.demand_query_scc_index(include_heap);
        let component_allowed = components
            .iter()
            .enumerate()
            .map(|(component, members)| {
                (
                    component,
                    members
                        .iter()
                        .any(|member| self.node_matches_call_context(NodeIndex::new(*member), context)),
                )
            })
            .collect::<HashMap<_, _>>();
        let mut frontier = seeds
            .iter()
            .filter(|seed| self.node_matches_call_context(**seed, context))
            .filter_map(|seed| node_to_component.get(seed.index()).copied())
            .filter(|component| *component != usize::MAX && component_allowed.get(component).copied().unwrap_or(false))
            .collect::<Vec<_>>();
        frontier.sort_unstable();
        frontier.dedup();
        let mut seen_components = HashSet::new();
        let mut seen_nodes = HashSet::new();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for component in frontier {
                if !seen_components.insert(component) {
                    continue;
                }
                let members = components.get(component).cloned().unwrap_or_default();
                for member in members {
                    let node = NodeIndex::new(member);
                    if !self.node_matches_call_context(node, context) {
                        continue;
                    }
                    if out.visited.len() >= max_visits {
                        out.frontier_cutoff = true;
                        return out;
                    }
                    if seen_nodes.insert(member) {
                        out.visited.push(member);
                        layer.push(member);
                    }
                }
                let neighbors = match direction {
                    SparseDirection::Forward => succ.get(&component),
                    SparseDirection::Backward => pred.get(&component),
                };
                if let Some(neighbors) = neighbors {
                    for neighbor in neighbors {
                        if !seen_components.contains(neighbor)
                            && component_allowed.get(neighbor).copied().unwrap_or(false)
                        {
                            next.push(*neighbor);
                        }
                    }
                }
            }
            if !layer.is_empty() {
                layer.sort_unstable();
                layer.dedup();
                out.layers.push(layer);
            }
            next.sort_unstable();
            next.dedup();
            frontier = next;
            depth += 1;
        }
        out
    }

    pub fn sparse_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let mut seen = HashSet::new();
        let mut frontier = seeds.to_vec();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for node in frontier {
                if out.visited.len() >= max_visits {
                    out.frontier_cutoff = true;
                    return out;
                }
                if !seen.insert(node) {
                    continue;
                }
                out.visited.push(node.index());
                layer.push(node.index());
                for neighbor in self.sparse_neighbors_of(node, direction) {
                    if !seen.contains(&neighbor) {
                        next.push(neighbor);
                    }
                }
            }
            if !layer.is_empty() {
                out.layers.push(layer);
            }
            frontier = next;
            depth += 1;
        }
        out
    }

    pub fn clear_sparse_caches(&self) {
        self.demand_summary_cache.borrow_mut().clear();
        self.demand_seed_summary_cache.borrow_mut().clear();
        self.demand_call_summary_cache.borrow_mut().clear();
        self.demand_fixpoint_summary_cache.borrow_mut().clear();
        self.demand_query_summary_cache.borrow_mut().clear();
        self.contextual_call_summary_cache.borrow_mut().clear();
        self.function_summary_cache.borrow_mut().clear();
        self.contextual_demand_query_cache.borrow_mut().clear();
        self.interprocedural_call_summary_cache.borrow_mut().clear();
        self.function_transfer_summary_cache.borrow_mut().clear();
        self.contextual_function_transfer_summary_cache.borrow_mut().clear();
        self.function_heap_effect_summary_cache.borrow_mut().clear();
        self.contextual_function_heap_effect_summary_cache.borrow_mut().clear();
    }

    fn summarize_sparse_traversal(&self, traversal: SparseTraversal) -> SparseValueSummary {
        let mut summary = SparseValueSummary {
            traversal,
            ..SparseValueSummary::default()
        };
        for idx in &summary.traversal.visited {
            let node = NodeIndex::new(*idx);
            match &self.graph[node] {
                FlowNode::Value { func, value } => summary.values.push((func.0, value.0)),
                FlowNode::Param { func, index, value } => summary.params.push((func.0, *index, value.0)),
                FlowNode::CallPort { func, inst, port, .. } => {
                    summary.call_ports.push((func.0, inst.0, format!("{:?}", port)));
                }
                _ => {}
            }
        }
        summary.values.sort_unstable();
        summary.values.dedup();
        summary.params.sort_unstable();
        summary.params.dedup();
        summary.call_ports.sort_unstable();
        summary.call_ports.dedup();
        summary
    }

    fn sparse_scc_index(
        &self,
    ) -> (Vec<Vec<usize>>, Vec<usize>, HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
        let mut sparse = DiGraph::<(), ()>::new();
        for _ in 0..self.graph.node_count() {
            sparse.add_node(());
        }
        for (src, dsts) in &self.sparse_successors {
            for dst in dsts {
                sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
            }
        }
        let components = kosaraju_scc(&sparse)
            .into_iter()
            .map(|component| component.into_iter().map(|node| node.index()).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut node_to_component = vec![usize::MAX; self.graph.node_count()];
        for (component_idx, members) in components.iter().enumerate() {
            for member in members {
                if *member < node_to_component.len() {
                    node_to_component[*member] = component_idx;
                }
            }
        }
        let mut succ = HashMap::<usize, Vec<usize>>::new();
        let mut pred = HashMap::<usize, Vec<usize>>::new();
        for (src, dsts) in &self.sparse_successors {
            let Some(&src_component) = node_to_component.get(*src) else {
                continue;
            };
            if src_component == usize::MAX {
                continue;
            }
            for dst in dsts {
                let Some(&dst_component) = node_to_component.get(*dst) else {
                    continue;
                };
                if dst_component == usize::MAX || src_component == dst_component {
                    continue;
                }
                succ.entry(src_component).or_default().push(dst_component);
                pred.entry(dst_component).or_default().push(src_component);
            }
        }
        for values in succ.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        for values in pred.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        (components, node_to_component, succ, pred)
    }

    fn demand_query_scc_index(
        &self,
        include_heap: bool,
    ) -> (Vec<Vec<usize>>, Vec<usize>, HashMap<usize, Vec<usize>>, HashMap<usize, Vec<usize>>) {
        let mut sparse = DiGraph::<(), ()>::new();
        for _ in 0..self.graph.node_count() {
            sparse.add_node(());
        }
        for (src, dsts) in &self.sparse_successors {
            for dst in dsts {
                sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
            }
        }
        if include_heap {
            for (src, dsts) in &self.heap_value_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
            for (src, dsts) in &self.heap_object_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
            for (src, dsts) in &self.object_graph_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
            for (src, dsts) in &self.region_graph_successors {
                for dst in dsts {
                    sparse.add_edge(NodeIndex::new(*src), NodeIndex::new(*dst), ());
                }
            }
        }
        let components = kosaraju_scc(&sparse)
            .into_iter()
            .map(|component| component.into_iter().map(|node| node.index()).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let mut node_to_component = vec![usize::MAX; self.graph.node_count()];
        for (component_idx, members) in components.iter().enumerate() {
            for member in members {
                if *member < node_to_component.len() {
                    node_to_component[*member] = component_idx;
                }
            }
        }
        let mut succ = HashMap::<usize, Vec<usize>>::new();
        let mut pred = HashMap::<usize, Vec<usize>>::new();
        let mut push_component_edges = |edges: &HashMap<usize, Vec<usize>>| {
            for (src, dsts) in edges {
                let Some(&src_component) = node_to_component.get(*src) else {
                    continue;
                };
                if src_component == usize::MAX {
                    continue;
                }
                for dst in dsts {
                    let Some(&dst_component) = node_to_component.get(*dst) else {
                        continue;
                    };
                    if dst_component == usize::MAX || src_component == dst_component {
                        continue;
                    }
                    succ.entry(src_component).or_default().push(dst_component);
                    pred.entry(dst_component).or_default().push(src_component);
                }
            }
        };
        push_component_edges(&self.sparse_successors);
        if include_heap {
            push_component_edges(&self.heap_value_successors);
            push_component_edges(&self.heap_object_successors);
            push_component_edges(&self.object_graph_successors);
            push_component_edges(&self.region_graph_successors);
        }
        for values in succ.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        for values in pred.values_mut() {
            values.sort_unstable();
            values.dedup();
        }
        (components, node_to_component, succ, pred)
    }

    fn demand_query_fixpoint_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        include_heap: bool,
    ) -> SparseTraversal {
        let mut out = SparseTraversal {
            seeds: seeds.iter().map(|node| node.index()).collect(),
            ..SparseTraversal::default()
        };
        let (components, node_to_component, succ, pred) = self.demand_query_scc_index(include_heap);
        let mut frontier = seeds
            .iter()
            .filter_map(|seed| node_to_component.get(seed.index()).copied())
            .filter(|component| *component != usize::MAX)
            .collect::<Vec<_>>();
        frontier.sort_unstable();
        frontier.dedup();
        let mut seen_components = HashSet::new();
        let mut seen_nodes = HashSet::new();
        let mut depth = 0usize;
        while !frontier.is_empty() && depth <= max_depth {
            let mut layer = Vec::new();
            let mut next = Vec::new();
            for component in frontier {
                if !seen_components.insert(component) {
                    continue;
                }
                let members = components.get(component).cloned().unwrap_or_default();
                for member in members {
                    if out.visited.len() >= max_visits {
                        out.frontier_cutoff = true;
                        return out;
                    }
                    if seen_nodes.insert(member) {
                        out.visited.push(member);
                        layer.push(member);
                    }
                }
                let neighbors = match direction {
                    SparseDirection::Forward => succ.get(&component),
                    SparseDirection::Backward => pred.get(&component),
                };
                if let Some(neighbors) = neighbors {
                    for neighbor in neighbors {
                        if !seen_components.contains(neighbor) {
                            next.push(*neighbor);
                        }
                    }
                }
            }
            if !layer.is_empty() {
                layer.sort_unstable();
                layer.dedup();
                out.layers.push(layer);
            }
            next.sort_unstable();
            next.dedup();
            frontier = next;
            depth += 1;
        }
        out
    }

    pub fn sparse_fixpoint_traversal(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseTraversal {
        self.demand_query_fixpoint_traversal(seeds, direction, max_depth, max_visits, false)
    }

    pub fn demand_fixpoint_summary_from_seeds(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let mut key_seeds = seeds.iter().map(|seed| seed.index()).collect::<Vec<_>>();
        key_seeds.sort_unstable();
        key_seeds.dedup();
        let key = (key_seeds, direction, max_depth, max_visits);
        if let Some(cached) = self.demand_fixpoint_summary_cache.borrow().get(&key).cloned() {
            return cached;
        }
        let traversal = self.sparse_fixpoint_traversal(seeds, direction, max_depth, max_visits);
        let summary = self.summarize_sparse_traversal(traversal);
        self.demand_fixpoint_summary_cache.borrow_mut().insert(key, summary.clone());
        summary
    }

    pub fn demand_fixpoint_value_summary(
        &self,
        func: FunctionId,
        value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let seed = value_node(self, func, value);
        self.demand_fixpoint_summary_from_seeds(&[seed], direction, max_depth, max_visits)
    }

    pub fn demand_fixpoint_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let mut seeds = self
            .call_ports
            .iter()
            .filter_map(|((call_func, call_inst, _port), node)| {
                (*call_func == func && *call_inst == inst).then_some(*node)
            })
            .collect::<Vec<_>>();
        seeds.sort_unstable_by_key(|node| node.index());
        seeds.dedup();
        if seeds.is_empty() {
            return None;
        }
        Some(self.demand_fixpoint_summary_from_seeds(&seeds, direction, max_depth, max_visits))
    }

    pub fn demand_fixpoint_reaches_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_fixpoint_value_summary(src_func, src_value, direction, max_depth, max_visits);
        summary
            .values
            .iter()
            .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn demand_fixpoint_reaches_any_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        targets: &[(FunctionId, ValueId)],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_fixpoint_value_summary(src_func, src_value, direction, max_depth, max_visits);
        targets.iter().any(|(dst_func, dst_value)| {
            summary
                .values
                .iter()
                .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
                || summary
                    .params
                    .iter()
                    .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
        })
    }

    pub fn demand_fixpoint_call_port_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let seed = self.call_ports.get(&(func, inst, port))?.to_owned();
        Some(self.demand_fixpoint_summary_from_seeds(&[seed], direction, max_depth, max_visits))
    }

    pub fn demand_fixpoint_call_port_reaches_value(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_fixpoint_call_port_summary(func, inst, port, direction, max_depth, max_visits) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(summary_func, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(summary_func, _index, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
    }

    pub fn resolve_demand_seed_nodes(&self, seeds: &[DemandSeed]) -> Vec<NodeIndex> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for seed in seeds {
            match seed {
                DemandSeed::Node(index) => {
                    if *index < self.graph.node_count() {
                        let node = NodeIndex::new(*index);
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
                DemandSeed::Value { func, value } => {
                    if let Some(node) = self.values.get(&(FunctionId(*func), ValueId(*value))).copied() {
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
                DemandSeed::Call { func, inst } => {
                    let mut call_nodes = self
                        .call_ports
                        .iter()
                        .filter_map(|((call_func, call_inst, _), node)| {
                            (*call_func == FunctionId(*func) && *call_inst == InstId(*inst)).then_some(*node)
                        })
                        .collect::<Vec<_>>();
                    call_nodes.sort_unstable_by_key(|node| node.index());
                    call_nodes.dedup();
                    for node in call_nodes {
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
                DemandSeed::CallPort { func, inst, port } => {
                    if let Some(node) = self.call_ports.get(&(FunctionId(*func), InstId(*inst), port.clone())).copied() {
                        if seen.insert(node.index()) {
                            out.push(node);
                        }
                    }
                }
            }
        }
        out.sort_unstable_by_key(|node| node.index());
        out.dedup_by_key(|node| node.index());
        out
    }

    pub fn demand_query_summary(
        &self,
        query: &DemandQuery,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let key = (query.clone(), max_depth, max_visits);
        if let Some(cached) = self.demand_query_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let seeds = self.resolve_demand_seed_nodes(&query.seeds);
        if seeds.is_empty() {
            return None;
        }
        let traversal = match query.engine {
            DemandEngine::Sparse => self.demand_query_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap),
            DemandEngine::Fixpoint => self.demand_query_fixpoint_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap),
        };
        let summary = self.summarize_sparse_traversal(traversal);
        self.demand_query_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn demand_query_reachable_values(
        &self,
        query: &DemandQuery,
        max_depth: usize,
        max_visits: usize,
    ) -> Vec<(FunctionId, ValueId)> {
        self.demand_query_summary(query, max_depth, max_visits)
            .map(|summary| {
                summary
                    .values
                    .into_iter()
                    .map(|(func, value)| (FunctionId(func), ValueId(value)))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn demand_query_reaches_value(
        &self,
        query: &DemandQuery,
        dst_func: FunctionId,
        dst_value: ValueId,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_query_summary(query, max_depth, max_visits) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn demand_query_reaches_any_value(
        &self,
        query: &DemandQuery,
        targets: &[(FunctionId, ValueId)],
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_query_summary(query, max_depth, max_visits) else {
            return false;
        };
        targets.iter().any(|(dst_func, dst_value)| {
            summary
                .values
                .iter()
                .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
                || summary
                    .params
                    .iter()
                    .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
        })
    }

    fn call_port_source_values(&self, port_node: NodeIndex) -> Vec<(FunctionId, ValueId)> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for edge in self.graph.edges_directed(port_node, petgraph::Direction::Incoming) {
            if !matches!(edge.weight().kind, EdgeKind::ValueToCallPort) {
                continue;
            }
            if let FlowNode::Value { func, value } = self.graph[edge.source()] {
                if seen.insert((func, value)) {
                    out.push((func, value));
                }
            }
        }
        out.sort_unstable();
        out
    }

    fn function_param_arity(&self, func: FunctionId) -> usize {
        self.function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .max()
            .map(|max_index| max_index + 1)
            .unwrap_or(0)
    }

    fn candidate_function_matches_call_signature(&self, candidate_func: FunctionId, meta: &CallMeta) -> bool {
        let arity = self.function_param_arity(candidate_func);
        if arity != 0 && !(arity == meta.arg_count || arity == meta.arg_count + 1 || arity + 1 == meta.arg_count) {
            return false;
        }
        if let Some(callee_name) = meta.callee_name.as_ref() {
            if let Some(candidate_name) = self.function_names.get(&candidate_func) {
                if candidate_name != callee_name && !candidate_name.ends_with(&format!(".{callee_name}")) {
                    return false;
                }
            }
        }
        true
    }

    fn exact_callee_ids_for_call(&self, func: FunctionId, inst: InstId) -> Vec<FunctionId> {
        let mut out = BTreeSet::new();
        for ((call_func, call_inst, _port), node) in &self.call_ports {
            if *call_func != func || *call_inst != inst {
                continue;
            }
            for edge in self.graph.edges_directed(*node, petgraph::Direction::Outgoing) {
                if !matches!(edge.weight().kind, EdgeKind::ActualToFormal) {
                    continue;
                }
                if let FlowNode::Param { func: callee_func, .. } = self.graph[edge.target()] {
                    out.insert(callee_func);
                }
            }
        }
        out.into_iter().collect()
    }

    fn refine_call_context_for_sensitivity(
        &self,
        mut context: CallContextKey,
        sensitivity: ContextSensitivity,
    ) -> CallContextKey {
        match sensitivity {
            ContextSensitivity::None => CallContextKey::default(),
            ContextSensitivity::CallSite => {
                context.receiver_classes.clear();
                context.receiver_shapes.clear();
                context.arg_classes.clear();
                context.arg_shapes.clear();
                context
            }
            ContextSensitivity::Receiver => {
                context.arg_classes.clear();
                context.arg_shapes.clear();
                context.call_sites.clear();
                context
            }
            ContextSensitivity::ReceiverAndArgs => {
                context.call_sites.clear();
                context
            }
            ContextSensitivity::CallString2 => context,
            ContextSensitivity::ReceiverArgsAndCallSite => context,
        }
    }

    fn node_matches_structural_call_context(&self, node: NodeIndex, context: &CallContextKey) -> bool {
        let allowed_funcs = context
            .callee_funcs
            .iter()
            .copied()
            .map(FunctionId)
            .chain(context.call_sites.iter().map(|(func, _)| FunctionId(*func)))
            .collect::<BTreeSet<_>>();
        let allowed_sites = context.call_sites.iter().copied().collect::<BTreeSet<_>>();
        match &self.graph[node] {
            FlowNode::Value { func, .. }
            | FlowNode::Param { func, .. }
            | FlowNode::Return { func }
            | FlowNode::FieldCell { func, .. }
            | FlowNode::IndexCell { func, .. } => {
                allowed_funcs.is_empty() || allowed_funcs.contains(func)
            }
            FlowNode::CallPort { func, inst, .. }
            | FlowNode::SyntheticSource { func, inst, .. }
            | FlowNode::SyntheticSink { func, inst, .. } => {
                allowed_sites.is_empty() || allowed_sites.contains(&(func.0, inst.0))
            }
        }
    }

    fn node_matches_call_context(&self, node: NodeIndex, context: &CallContextKey) -> bool {
        if !self.node_matches_structural_call_context(node, context) {
            return false;
        }
        let contextual_node_targets = self.contextual_node_points_to_targets_of(context, node);
        if !contextual_node_targets.is_empty() {
            let node_targets = self.node_points_to_targets_of(node);
            if !node_targets.is_empty() && !points_to_targets_overlap(&contextual_node_targets, &node_targets) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        } else if let Some(context_targets) = self.contextual_points_to_targets.get(context) {
            let node_targets = self.node_points_to_targets_of(node);
            if !context_targets.is_empty() && !node_targets.is_empty() && !points_to_targets_overlap(context_targets, &node_targets) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        }
        let contextual_node_object_ids = self.contextual_node_points_to_object_ids_of(context, node);
        if !contextual_node_object_ids.is_empty() {
            let node_object_ids = self.node_points_to_object_ids_of(node);
            if !node_object_ids.is_empty() && !points_to_object_ids_overlap(&contextual_node_object_ids, &node_object_ids) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        } else if let Some(context_object_ids) = self.contextual_points_to_object_ids.get(context) {
            let node_object_ids = self.node_points_to_object_ids_of(node);
            if !context_object_ids.is_empty() && !node_object_ids.is_empty() && !points_to_object_ids_overlap(context_object_ids, &node_object_ids) {
                match &self.graph[node] {
                    FlowNode::CallPort { .. } | FlowNode::Return { .. } => {}
                    _ => return false,
                }
            }
        }
        true
    }

    fn filter_sparse_summary_to_context(
        &self,
        mut summary: SparseValueSummary,
        context: &CallContextKey,
    ) -> SparseValueSummary {
        let callee_funcs = context
            .callee_funcs
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let call_sites = context.call_sites.iter().copied().collect::<BTreeSet<_>>();
        if !callee_funcs.is_empty() {
            summary
                .params
                .retain(|(func, _, _)| callee_funcs.contains(func));
        }
        if !call_sites.is_empty() {
            summary
                .call_ports
                .retain(|(func, inst, _)| call_sites.contains(&(*func, *inst)));
        }
        if !call_sites.is_empty() {
            summary.traversal.visited.retain(|idx| self.node_matches_call_context(NodeIndex::new(*idx), context));
            for layer in &mut summary.traversal.layers {
                layer.retain(|idx| self.node_matches_call_context(NodeIndex::new(*idx), context));
            }
            summary.traversal.layers.retain(|layer| !layer.is_empty());
            if !callee_funcs.is_empty() {
                let caller_funcs = call_sites.iter().map(|(func, _)| *func).collect::<BTreeSet<_>>();
                summary.values.retain(|(func, _)| caller_funcs.contains(func) || callee_funcs.contains(func));
            }
        }
        summary
    }

    pub fn call_context_key(&self, func: FunctionId, inst: InstId) -> Option<CallContextKey> {
        let callee_funcs = self.exact_callee_ids_for_call(func, inst);
        let mut callee_names = callee_funcs
            .iter()
            .filter_map(|callee_func| self.function_names.get(callee_func).cloned())
            .collect::<Vec<_>>();
        callee_names.sort();
        callee_names.dedup();

        let mut receiver_classes = BTreeSet::new();
        let mut receiver_shapes = BTreeSet::new();
        let mut arg_classes = BTreeMap::<usize, BTreeSet<String>>::new();
        let mut arg_shapes = BTreeMap::<usize, BTreeSet<String>>::new();
        for ((call_func, call_inst, port), node) in &self.call_ports {
            if *call_func != func || *call_inst != inst {
                continue;
            }
            let mut port_classes = self.node_points_to_classes_of(*node);
            let mut port_shapes = self.object_shape_paths_of(*node);
            port_shapes.extend(self.node_memory_regions_of(*node));
            let sources = self.call_port_source_values(*node);
            for (src_func, src_value) in sources {
                if port_classes.is_empty() {
                    port_classes.extend(self.value_points_to_classes_of(src_func, src_value));
                }
                let src_node = value_node(self, src_func, src_value);
                port_shapes.extend(self.object_shape_paths_of(src_node));
                port_shapes.extend(self.value_memory_regions_of(src_func, src_value));
            }
            port_classes.sort();
            port_classes.dedup();
            port_shapes.sort();
            port_shapes.dedup();
            match port {
                Port::Receiver => {
                    for class in port_classes {
                        receiver_classes.insert(class);
                    }
                    for shape in port_shapes {
                        receiver_shapes.insert(shape);
                    }
                }
                Port::Arg(index) => {
                    let class_entry = arg_classes.entry(*index).or_default();
                    for class in port_classes {
                        class_entry.insert(class);
                    }
                    let shape_entry = arg_shapes.entry(*index).or_default();
                    for shape in port_shapes {
                        shape_entry.insert(shape);
                    }
                }
                _ => {}
            }
        }

        if callee_names.is_empty() && callee_funcs.is_empty() && receiver_classes.is_empty() && receiver_shapes.is_empty() && arg_classes.is_empty() && arg_shapes.is_empty() {
            return None;
        }

        let max_arg = arg_classes
            .keys()
            .chain(arg_shapes.keys())
            .copied()
            .max();
        let (arg_classes, arg_shapes) = if let Some(max_arg) = max_arg {
            (
                (0..=max_arg)
                    .map(|index| arg_classes.remove(&index).map(|values| values.into_iter().collect()).unwrap_or_default())
                    .collect::<Vec<Vec<String>>>(),
                (0..=max_arg)
                    .map(|index| arg_shapes.remove(&index).map(|values| values.into_iter().collect()).unwrap_or_default())
                    .collect::<Vec<Vec<String>>>(),
            )
        } else {
            (Vec::new(), Vec::new())
        };

        Some(CallContextKey {
            callee_names,
            callee_funcs: callee_funcs.iter().map(|func| func.0).collect(),
            receiver_classes: receiver_classes.into_iter().collect(),
            receiver_shapes: receiver_shapes.into_iter().collect(),
            arg_classes,
            arg_shapes,
            call_sites: vec![(func.0, inst.0)],
        })
    }

    pub fn contextual_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        sensitivity: ContextSensitivity,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        if matches!(sensitivity, ContextSensitivity::None) {
            return self.demand_call_summary(func, inst, direction, max_depth, max_visits);
        }
        let context = self.refine_call_context_for_sensitivity(self.call_context_key(func, inst)?, sensitivity);
        let key = (context.clone(), direction, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.contextual_call_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let seeds = self.resolve_demand_seed_nodes(&[DemandSeed::Call { func: func.0, inst: inst.0 }]);
        if seeds.is_empty() {
            return None;
        }
        let traversal = match engine {
            DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, direction, max_depth, max_visits, include_heap, &context),
            DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, direction, max_depth, max_visits, include_heap, &context),
        };
        let summary = self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &context);
        self.contextual_call_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn contextual_call_reaches_value(
        &self,
        func: FunctionId,
        inst: InstId,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> bool {
        let Some(summary) = self.contextual_call_summary(
            func,
            inst,
            ContextSensitivity::ReceiverArgsAndCallSite,
            direction,
            max_depth,
            max_visits,
            engine,
            include_heap,
        ) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(func_id, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func_id, _index, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
    }

    pub fn function_param_summary(
        &self,
        func: FunctionId,
        index: usize,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let key = (
            func.0,
            format!("param:{index}"),
            direction,
            max_depth,
            max_visits,
            engine,
            include_heap,
        );
        if let Some(cached) = self.function_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let node = self.function_params.get(&(func, index)).copied()?;
        let query = DemandQuery {
            seeds: vec![DemandSeed::Node(node.index())],
            direction,
            engine,
            include_heap,
        };
        let summary = self.demand_query_summary(&query, max_depth, max_visits)?;
        self.function_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn function_return_summary(
        &self,
        func: FunctionId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let key = (
            func.0,
            "return".to_string(),
            direction,
            max_depth,
            max_visits,
            engine,
            include_heap,
        );
        if let Some(cached) = self.function_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let node = self.function_returns.get(&func).copied()?;
        let query = DemandQuery {
            seeds: vec![DemandSeed::Node(node.index())],
            direction,
            engine,
            include_heap,
        };
        let summary = self.demand_query_summary(&query, max_depth, max_visits)?;
        self.function_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    fn call_seed_contexts(&self, seeds: &[DemandSeed], sensitivity: ContextSensitivity) -> Vec<CallContextKey> {
        if matches!(sensitivity, ContextSensitivity::None) {
            return Vec::new();
        }
        let mut contexts = seeds
            .iter()
            .filter_map(|seed| match seed {
                DemandSeed::Call { func, inst } | DemandSeed::CallPort { func, inst, .. } => {
                    self.call_context_key(FunctionId(*func), InstId(*inst))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        contexts.sort();
        contexts.dedup();
        for context in &mut contexts {
            *context = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        }
        if matches!(sensitivity, ContextSensitivity::CallString2) {
            let mut all_sites = contexts.iter().flat_map(|ctx| ctx.call_sites.clone()).collect::<Vec<_>>();
            all_sites.sort();
            all_sites.dedup();
            if all_sites.len() > 2 {
                all_sites = all_sites[all_sites.len().saturating_sub(2)..].to_vec();
            }
            for context in &mut contexts {
                context.call_sites = all_sites.clone();
            }
        }
        contexts.sort();
        contexts.dedup();
        contexts
    }

    fn intersect_sparse_summaries(
        &self,
        mut base: SparseValueSummary,
        filter: &SparseValueSummary,
    ) -> SparseValueSummary {
        let visited = filter.traversal.visited.iter().copied().collect::<HashSet<_>>();
        if !visited.is_empty() {
            base.traversal.visited.retain(|idx| visited.contains(idx));
            for layer in &mut base.traversal.layers {
                layer.retain(|idx| visited.contains(idx));
            }
            base.traversal.layers.retain(|layer| !layer.is_empty());
        }
        let values = filter.values.iter().copied().collect::<HashSet<_>>();
        if !values.is_empty() {
            base.values.retain(|value| values.contains(value));
        }
        let params = filter.params.iter().copied().collect::<HashSet<_>>();
        if !params.is_empty() {
            base.params.retain(|value| params.contains(value));
        }
        let call_ports = filter.call_ports.iter().cloned().collect::<HashSet<_>>();
        if !call_ports.is_empty() {
            base.call_ports.retain(|value| call_ports.contains(value));
        }
        base
    }


    fn union_sparse_summaries(
        &self,
        summaries: impl IntoIterator<Item = SparseValueSummary>,
    ) -> Option<SparseValueSummary> {
        let mut iter = summaries.into_iter();
        let mut base = iter.next()?;
        let mut visited = base.traversal.visited.iter().copied().collect::<BTreeSet<_>>();
        let mut values = base.values.iter().copied().collect::<BTreeSet<_>>();
        let mut params = base.params.iter().copied().collect::<BTreeSet<_>>();
        let mut call_ports = base.call_ports.iter().cloned().collect::<BTreeSet<_>>();
        let mut layer_nodes = base
            .traversal
            .layers
            .iter()
            .flat_map(|layer| layer.iter().copied())
            .collect::<BTreeSet<_>>();
        for summary in iter {
            visited.extend(summary.traversal.visited.iter().copied());
            values.extend(summary.values.iter().copied());
            params.extend(summary.params.iter().copied());
            call_ports.extend(summary.call_ports.iter().cloned());
            layer_nodes.extend(summary.traversal.layers.iter().flat_map(|layer| layer.iter().copied()));
            base.traversal.frontier_cutoff |= summary.traversal.frontier_cutoff;
        }
        base.traversal.visited = visited.into_iter().collect();
        base.traversal.layers = if layer_nodes.is_empty() {
            Vec::new()
        } else {
            vec![layer_nodes.into_iter().collect()]
        };
        base.values = values.into_iter().collect();
        base.params = params.into_iter().collect();
        base.call_ports = call_ports.into_iter().collect();
        Some(base)
    }

    pub fn recommended_context_sensitivity(&self, query: &DemandQuery) -> ContextSensitivity {
        let mut has_callsite = false;
        let mut has_receiver = false;
        let mut arg_count = 0usize;
        let mut has_shape_rich_context = false;
        for seed in &query.seeds {
            match seed {
                DemandSeed::Call { func, inst } => {
                    has_callsite = true;
                    if let Some(ctx) = self.call_context_key(FunctionId(*func), InstId(*inst)) {
                        has_shape_rich_context |= !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty());
                    }
                }
                DemandSeed::CallPort { func, inst, port } => {
                    has_callsite = true;
                    if let Some(ctx) = self.call_context_key(FunctionId(*func), InstId(*inst)) {
                        has_shape_rich_context |= !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty());
                    }
                    match port {
                        Port::Receiver => has_receiver = true,
                        Port::Arg(_) => arg_count += 1,
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if has_callsite && has_shape_rich_context {
            ContextSensitivity::ReceiverArgsAndCallSite
        } else if query.include_heap && has_receiver && arg_count > 0 {
            ContextSensitivity::ReceiverArgsAndCallSite
        } else if has_callsite && has_receiver {
            ContextSensitivity::ReceiverArgsAndCallSite
        } else if has_callsite && arg_count > 1 {
            ContextSensitivity::CallString2
        } else if has_callsite {
            ContextSensitivity::CallSite
        } else if query.include_heap {
            ContextSensitivity::ReceiverAndArgs
        } else {
            ContextSensitivity::None
        }
    }

    pub fn recommended_demand_engine(&self, query: &DemandQuery) -> DemandEngine {
        let has_call_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Call { .. } | DemandSeed::CallPort { .. }));
        let has_node_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Node(_)));
        if query.include_heap || has_call_seed {
            DemandEngine::Fixpoint
        } else if query.direction == SparseDirection::Backward && (query.seeds.len() > 1 || has_node_seed) {
            DemandEngine::Fixpoint
        } else {
            DemandEngine::Sparse
        }
    }

    pub fn recommended_budget_profile(&self, query: &DemandQuery) -> QueryBudgetProfile {
        let has_call_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Call { .. } | DemandSeed::CallPort { .. }));
        let has_node_seed = query.seeds.iter().any(|seed| matches!(seed, DemandSeed::Node(_)));
        let has_shape_rich_context = query.seeds.iter().any(|seed| match seed {
            DemandSeed::Call { func, inst } => self
                .call_context_key(FunctionId(*func), InstId(*inst))
                .map(|ctx| !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty()))
                .unwrap_or(false),
            DemandSeed::CallPort { func, inst, .. } => self
                .call_context_key(FunctionId(*func), InstId(*inst))
                .map(|ctx| !ctx.receiver_shapes.is_empty() || ctx.arg_shapes.iter().any(|paths| !paths.is_empty()))
                .unwrap_or(false),
            _ => false,
        });
        if query.include_heap && has_call_seed && has_shape_rich_context {
            QueryBudgetProfile::Exhaustive
        } else if query.include_heap && has_call_seed {
            QueryBudgetProfile::Deep
        } else if query.include_heap || has_call_seed || has_node_seed {
            QueryBudgetProfile::Standard
        } else {
            QueryBudgetProfile::Light
        }
    }

    pub fn recommended_query_limits(&self, query: &DemandQuery) -> (usize, usize) {
        match self.recommended_budget_profile(query) {
            QueryBudgetProfile::Light => {
                if query.direction == SparseDirection::Backward {
                    (14, 4096)
                } else {
                    (10, 2048)
                }
            }
            QueryBudgetProfile::Standard => (18, 8192),
            QueryBudgetProfile::Deep => (24, 16384),
            QueryBudgetProfile::Exhaustive => (28, 24576),
        }
    }

    pub fn solver_plan_for_query(&self, query: &DemandQuery) -> SolverPlan {
        let mut planned = query.clone();
        planned.engine = self.recommended_demand_engine(query);
        let context_sensitivity = self.recommended_context_sensitivity(&planned);
        let budget_profile = self.recommended_budget_profile(&planned);
        let (max_depth, max_visits) = self.recommended_query_limits(&planned);
        SolverPlan {
            query: planned,
            context_sensitivity,
            budget_profile,
            max_depth,
            max_visits,
        }
    }

    pub fn execute_solver_plan(&self, plan: &SolverPlan) -> Option<SparseValueSummary> {
        if matches!(plan.context_sensitivity, ContextSensitivity::None) {
            self.demand_query_summary(&plan.query, plan.max_depth, plan.max_visits)
        } else {
            self.contextual_demand_query_summary(
                &plan.query,
                plan.context_sensitivity,
                plan.max_depth,
                plan.max_visits,
            )
        }
    }

    pub fn solver_reaches_value(&self, plan: &SolverPlan, dst_func: FunctionId, dst_value: ValueId) -> bool {
        let Some(summary) = self.execute_solver_plan(plan) else {
            return false;
        };
        summary.values.iter().any(|(func_id, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
            || summary.params.iter().any(|(func_id, _index, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
    }

    pub fn solver_reaches_any_value(&self, plan: &SolverPlan, targets: &[(FunctionId, ValueId)]) -> bool {
        let Some(summary) = self.execute_solver_plan(plan) else {
            return false;
        };
        let targets = targets.iter().map(|(func, value)| (func.0, value.0)).collect::<HashSet<_>>();
        summary.values.iter().any(|pair| targets.contains(pair))
            || summary.params.iter().any(|(func, _index, value)| targets.contains(&(*func, *value)))
    }

    pub fn demand_query_summary_auto(&self, query: &DemandQuery) -> Option<SparseValueSummary> {
        let plan = self.solver_plan_for_query(query);
        self.execute_solver_plan(&plan)
    }

    pub fn demand_query_reaches_value_auto(
        &self,
        query: &DemandQuery,
        dst_func: FunctionId,
        dst_value: ValueId,
    ) -> bool {
        let Some(summary) = self.demand_query_summary_auto(query) else {
            return false;
        };
        summary.values.iter().any(|(func_id, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
            || summary.params.iter().any(|(func_id, _index, value_id)| *func_id == dst_func.0 && *value_id == dst_value.0)
    }

    pub fn demand_query_reaches_any_value_auto(
        &self,
        query: &DemandQuery,
        targets: &[(FunctionId, ValueId)],
    ) -> bool {
        let Some(summary) = self.demand_query_summary_auto(query) else {
            return false;
        };
        let targets = targets.iter().map(|(func, value)| (func.0, value.0)).collect::<HashSet<_>>();
        summary.values.iter().any(|pair| targets.contains(pair))
            || summary.params.iter().any(|(func, _index, value)| targets.contains(&(*func, *value)))
    }

    pub fn contextual_demand_query_summary_auto(
        &self,
        query: &DemandQuery,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let mut plan = self.solver_plan_for_query(query);
        plan.max_depth = plan.max_depth.max(max_depth);
        plan.max_visits = plan.max_visits.max(max_visits);
        self.execute_solver_plan(&plan)
    }

    pub fn contextual_demand_query_reaches_value_auto(
        &self,
        query: &DemandQuery,
        dst_func: FunctionId,
        dst_value: ValueId,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let sensitivity = self.recommended_context_sensitivity(query);
        self.contextual_demand_query_reaches_value(query, sensitivity, dst_func, dst_value, max_depth, max_visits)
    }

    pub fn contextual_demand_query_summary(
        &self,
        query: &DemandQuery,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        if matches!(sensitivity, ContextSensitivity::None) {
            return self.demand_query_summary(query, max_depth, max_visits);
        }
        let contexts = self.call_seed_contexts(&query.seeds, sensitivity);
        let key = (query.clone(), sensitivity, contexts.clone(), max_depth, max_visits);
        if let Some(cached) = self.contextual_demand_query_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let seeds = self.resolve_demand_seed_nodes(&query.seeds);
        if seeds.is_empty() {
            return None;
        }
        let summary = if contexts.is_empty() {
            self.demand_query_summary(query, max_depth, max_visits)?
        } else {
            let mut contextual_summaries = Vec::new();
            for context in contexts {
                let traversal = match query.engine {
                    DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap, &context),
                    DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, query.direction, max_depth, max_visits, query.include_heap, &context),
                };
                contextual_summaries.push(self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &context));
            }
            self.union_sparse_summaries(contextual_summaries)?
        };
        self.contextual_demand_query_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn contextual_demand_query_reaches_value(
        &self,
        query: &DemandQuery,
        sensitivity: ContextSensitivity,
        dst_func: FunctionId,
        dst_value: ValueId,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.contextual_demand_query_summary(query, sensitivity, max_depth, max_visits) else {
            return false;
        };
        summary.values.iter().any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn function_transfer_summary(
        &self,
        func: FunctionId,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionTransferSummary> {
        let key = (func.0, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.function_transfer_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let backward_return = self.function_return_summary(
            func,
            SparseDirection::Backward,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )?;
        let mut return_reachable_params = backward_return
            .params
            .iter()
            .filter_map(|(summary_func, index, _value)| (*summary_func == func.0).then_some(*index))
            .collect::<Vec<_>>();
        return_reachable_params.sort_unstable();
        return_reachable_params.dedup();

        let mut param_indices = self
            .function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .collect::<Vec<_>>();
        param_indices.sort_unstable();
        param_indices.dedup();

        let mut param_to_param = BTreeSet::new();
        let mut param_forward_summaries = BTreeMap::new();
        for index in &param_indices {
            if let Some(summary) = self.function_param_summary(
                func,
                *index,
                SparseDirection::Forward,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) {
                for (summary_func, target_index, _value) in &summary.params {
                    if *summary_func == func.0 && *target_index != *index {
                        param_to_param.insert((*index, *target_index));
                    }
                }
                param_forward_summaries.insert(*index, summary);
            }
        }

        let mut return_values = backward_return
            .values
            .iter()
            .copied()
            .filter(|(summary_func, _value)| *summary_func == func.0)
            .collect::<Vec<_>>();
        return_values.sort_unstable();
        return_values.dedup();

        let return_value_set = return_values.iter().copied().collect::<BTreeSet<_>>();
        let mut param_to_return_values = BTreeSet::new();
        for (index, summary) in &param_forward_summaries {
            for (summary_func, summary_value) in &summary.values {
                if return_value_set.contains(&(*summary_func, *summary_value)) {
                    param_to_return_values.insert((*index, *summary_func, *summary_value));
                }
            }
        }

        let summary = FunctionTransferSummary {
            func: func.0,
            return_reachable_params,
            param_to_param: param_to_param.into_iter().collect(),
            param_to_return_values: param_to_return_values.into_iter().collect(),
            return_values,
        };
        self.function_transfer_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    fn contextual_function_param_summary(
        &self,
        func: FunctionId,
        index: usize,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let node = self.function_params.get(&(func, index)).copied()?;
        let seeds = vec![node];
        let traversal = match engine {
            DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
            DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
        };
        Some(self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &refined))
    }

    fn contextual_function_return_summary(
        &self,
        func: FunctionId,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<SparseValueSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let node = self.function_returns.get(&func).copied()?;
        let seeds = vec![node];
        let traversal = match engine {
            DemandEngine::Sparse => self.contextual_demand_query_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
            DemandEngine::Fixpoint => self.contextual_demand_query_fixpoint_traversal(&seeds, direction, max_depth, max_visits, include_heap, &refined),
        };
        Some(self.filter_sparse_summary_to_context(self.summarize_sparse_traversal(traversal), &refined))
    }

    pub fn contextual_function_transfer_summary(
        &self,
        func: FunctionId,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionTransferSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let key = (func.0, refined.clone(), sensitivity, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self
            .contextual_function_transfer_summary_cache
            .borrow()
            .get(&key)
            .cloned()
        {
            return Some(cached);
        }

        let backward_return = self.contextual_function_return_summary(
            func,
            &refined,
            sensitivity,
            SparseDirection::Backward,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )?;
        let mut return_reachable_params = backward_return
            .params
            .iter()
            .filter_map(|(summary_func, index, _value)| (*summary_func == func.0).then_some(*index))
            .collect::<Vec<_>>();
        return_reachable_params.sort_unstable();
        return_reachable_params.dedup();

        let mut param_indices = self
            .function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .collect::<Vec<_>>();
        param_indices.sort_unstable();
        param_indices.dedup();

        let mut param_to_param = BTreeSet::new();
        let mut param_forward_summaries = BTreeMap::new();
        for index in &param_indices {
            if let Some(summary) = self.contextual_function_param_summary(
                func,
                *index,
                &refined,
                sensitivity,
                SparseDirection::Forward,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) {
                for (summary_func, target_index, _value) in &summary.params {
                    if *summary_func == func.0 && *target_index != *index {
                        param_to_param.insert((*index, *target_index));
                    }
                }
                param_forward_summaries.insert(*index, summary);
            }
        }

        let mut return_values = backward_return
            .values
            .iter()
            .copied()
            .filter(|(summary_func, _value)| *summary_func == func.0)
            .collect::<Vec<_>>();
        return_values.sort_unstable();
        return_values.dedup();

        let return_value_set = return_values.iter().copied().collect::<BTreeSet<_>>();
        let mut param_to_return_values = BTreeSet::new();
        for (index, summary) in &param_forward_summaries {
            for (summary_func, summary_value) in &summary.values {
                if return_value_set.contains(&(*summary_func, *summary_value)) {
                    param_to_return_values.insert((*index, *summary_func, *summary_value));
                }
            }
        }

        let summary = FunctionTransferSummary {
            func: func.0,
            return_reachable_params,
            param_to_param: param_to_param.into_iter().collect(),
            param_to_return_values: param_to_return_values.into_iter().collect(),
            return_values,
        };
        self.contextual_function_transfer_summary_cache
            .borrow_mut()
            .insert(key, summary.clone());
        Some(summary)
    }

    pub fn function_heap_effect_summary(
        &self,
        func: FunctionId,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionHeapEffectSummary> {
        let key = (func.0, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.function_heap_effect_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let transfer = self.function_transfer_summary(func, max_depth, max_visits, engine, include_heap)?;
        let mut param_indices = self
            .function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .collect::<Vec<_>>();
        param_indices.sort_unstable();
        param_indices.dedup();

        let mut param_to_read_regions = BTreeSet::new();
        let mut param_to_read_paths = BTreeSet::new();
        let mut param_to_read_cells = BTreeSet::new();
        let mut param_to_read_objects = BTreeSet::new();
        let mut param_to_write_regions = BTreeSet::new();
        let mut param_to_write_paths = BTreeSet::new();
        let mut param_to_write_cells = BTreeSet::new();
        let mut param_to_write_objects = BTreeSet::new();
        let mut param_to_return_regions = BTreeSet::new();
        let mut param_to_return_paths = BTreeSet::new();
        let mut param_to_return_cells = BTreeSet::new();
        let mut param_to_return_objects = BTreeSet::new();
        let mut param_to_return_live_values = BTreeSet::new();
        let mut return_regions = BTreeSet::new();
        let mut return_paths = BTreeSet::new();
        let mut return_cells = BTreeSet::new();
        let mut return_objects = BTreeSet::new();
        let mut return_value_regions = BTreeSet::new();
        let mut return_value_paths = BTreeSet::new();
        let mut return_value_cells = BTreeSet::new();
        let mut return_value_objects = BTreeSet::new();
        let mut return_live_values = BTreeSet::new();

        for (summary_func, summary_value) in &transfer.return_values {
            if *summary_func != func.0 {
                continue;
            }
            let value_func = FunctionId(*summary_func);
            let value_id = ValueId(*summary_value);
            let root_regions = value_root_memory_regions(self, value_func, value_id);
            for region in self.value_memory_regions_of(value_func, value_id) {
                return_regions.insert(region.clone());
                return_value_regions.insert((*summary_func, *summary_value, region.clone()));
                for path in region_relative_access_paths(&root_regions, &region) {
                    return_paths.insert(path.clone());
                    return_value_paths.insert((*summary_func, *summary_value, path));
                }
            }
            for object_id in self.value_points_to_object_ids_of(value_func, value_id) {
                return_objects.insert(object_id);
                return_value_objects.insert((*summary_func, *summary_value, object_id));
            }
            for cell in cell_candidates_for_value_targets(self, value_func, value_id) {
                return_cells.insert(cell.index() as u32);
                return_value_cells.insert((*summary_func, *summary_value, cell.index() as u32));
            }
        }

        for index in &param_indices {
            let Some(summary) = self.function_param_summary(
                func,
                *index,
                SparseDirection::Forward,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) else {
                continue;
            };
            let reachable_values = summary.values.iter().copied().collect::<BTreeSet<_>>();
            let reachable_params = summary
                .params
                .iter()
                .map(|(f, _i, v)| (*f, *v))
                .collect::<BTreeSet<_>>();
            let Some(&param_node) = self.function_params.get(&(func, *index)) else {
                continue;
            };
            let param_value = match &self.graph[param_node] {
                FlowNode::Param { value, .. } => *value,
                _ => continue,
            };
            let param_root_regions = value_root_memory_regions(self, func, param_value);
            for visited in &summary.traversal.visited {
                let node = NodeIndex::new(*visited);
                match &self.graph[node] {
                    FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                        for region in self.cell_memory_regions_of(node) {
                            param_to_read_regions.insert((*index, region.clone()));
                            for path in region_relative_access_paths(&param_root_regions, &region) {
                                param_to_read_paths.insert((*index, path));
                            }
                        }
                        param_to_read_cells.insert((*index, node.index() as u32));
                        for object_id in self.cell_points_to_object_ids_of(node) {
                            param_to_read_objects.insert((*index, object_id));
                        }
                        let writes = self
                            .cell_live_values_of(node)
                            .into_iter()
                            .chain(cell_store_values(self, node).into_iter())
                            .map(|(f, v)| (f.0, v.0))
                            .collect::<BTreeSet<_>>();
                        if !writes.is_empty()
                            && (writes.iter().any(|pair| reachable_values.contains(pair))
                                || writes.iter().any(|pair| reachable_params.contains(pair)))
                        {
                            for region in self.cell_memory_regions_of(node) {
                                param_to_write_regions.insert((*index, region.clone()));
                                for path in region_relative_access_paths(&param_root_regions, &region) {
                                    param_to_write_paths.insert((*index, path));
                                }
                            }
                            param_to_write_cells.insert((*index, node.index() as u32));
                            for object_id in self.cell_points_to_object_ids_of(node) {
                                param_to_write_objects.insert((*index, object_id));
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                if *from_index != *index {
                    continue;
                }
                let value_func = FunctionId(*summary_func);
                let value_id = ValueId(*summary_value);
                for region in self.value_memory_regions_of(value_func, value_id) {
                    param_to_return_regions.insert((*index, region.clone()));
                    for path in region_relative_access_paths(&param_root_regions, &region) {
                        param_to_return_paths.insert((*index, path));
                    }
                }
                for object_id in self.value_points_to_object_ids_of(value_func, value_id) {
                    param_to_return_objects.insert((*index, object_id));
                }
                for cell in cell_candidates_for_value_targets(self, value_func, value_id) {
                    param_to_return_cells.insert((*index, cell.index() as u32));
                }
            }
        }

        for (index, region) in &param_to_return_regions {
            for (live_func, live_value) in self.region_live_values_of(region) {
                param_to_return_live_values.insert((*index, live_func.0, live_value.0));
            }
        }
        for region in &return_regions {
            for (live_func, live_value) in self.region_live_values_of(region) {
                return_live_values.insert((live_func.0, live_value.0));
            }
        }

        let summary = FunctionHeapEffectSummary {
            func: func.0,
            context: None,
            sensitivity: None,
            param_to_read_regions: param_to_read_regions.into_iter().collect(),
            param_to_read_paths: param_to_read_paths.into_iter().collect(),
            param_to_read_cells: param_to_read_cells.into_iter().collect(),
            param_to_read_objects: param_to_read_objects.into_iter().collect(),
            param_to_write_regions: param_to_write_regions.into_iter().collect(),
            param_to_write_paths: param_to_write_paths.into_iter().collect(),
            param_to_write_cells: param_to_write_cells.into_iter().collect(),
            param_to_write_objects: param_to_write_objects.into_iter().collect(),
            param_to_return_regions: param_to_return_regions.into_iter().collect(),
            param_to_return_paths: param_to_return_paths.into_iter().collect(),
            param_to_return_cells: param_to_return_cells.into_iter().collect(),
            param_to_return_objects: param_to_return_objects.into_iter().collect(),
            param_to_return_live_values: param_to_return_live_values.into_iter().collect(),
            return_regions: return_regions.into_iter().collect(),
            return_paths: return_paths.into_iter().collect(),
            return_cells: return_cells.into_iter().collect(),
            return_objects: return_objects.into_iter().collect(),
            return_value_regions: return_value_regions.into_iter().collect(),
            return_value_paths: return_value_paths.into_iter().collect(),
            return_value_cells: return_value_cells.into_iter().collect(),
            return_value_objects: return_value_objects.into_iter().collect(),
            return_live_values: return_live_values.into_iter().collect(),
        };
        self.function_heap_effect_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn contextual_function_heap_effect_summary(
        &self,
        func: FunctionId,
        context: &CallContextKey,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<FunctionHeapEffectSummary> {
        let refined = self.refine_call_context_for_sensitivity(context.clone(), sensitivity);
        let key = (func.0, refined.clone(), sensitivity, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self
            .contextual_function_heap_effect_summary_cache
            .borrow()
            .get(&key)
            .cloned()
        {
            return Some(cached);
        }
        let transfer = self.contextual_function_transfer_summary(
            func,
            &refined,
            sensitivity,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )?;
        let mut param_indices = self
            .function_params
            .keys()
            .filter_map(|(summary_func, index)| (*summary_func == func).then_some(*index))
            .collect::<Vec<_>>();
        param_indices.sort_unstable();
        param_indices.dedup();

        let mut param_to_read_regions = BTreeSet::new();
        let mut param_to_read_paths = BTreeSet::new();
        let mut param_to_read_cells = BTreeSet::new();
        let mut param_to_read_objects = BTreeSet::new();
        let mut param_to_write_regions = BTreeSet::new();
        let mut param_to_write_paths = BTreeSet::new();
        let mut param_to_write_cells = BTreeSet::new();
        let mut param_to_write_objects = BTreeSet::new();
        let mut param_to_return_regions = BTreeSet::new();
        let mut param_to_return_paths = BTreeSet::new();
        let mut param_to_return_cells = BTreeSet::new();
        let mut param_to_return_objects = BTreeSet::new();
        let mut param_to_return_live_values = BTreeSet::new();
        let mut return_regions = BTreeSet::new();
        let mut return_paths = BTreeSet::new();
        let mut return_cells = BTreeSet::new();
        let mut return_objects = BTreeSet::new();
        let mut return_value_regions = BTreeSet::new();
        let mut return_value_paths = BTreeSet::new();
        let mut return_value_cells = BTreeSet::new();
        let mut return_value_objects = BTreeSet::new();
        let mut return_live_values = BTreeSet::new();

        for (summary_func, summary_value) in &transfer.return_values {
            let value_func = FunctionId(*summary_func);
            let value_id = ValueId(*summary_value);
            let root_regions = value_root_memory_regions(self, value_func, value_id);
            for region in self.value_memory_regions_of(value_func, value_id) {
                return_regions.insert(region.clone());
                return_value_regions.insert((*summary_func, *summary_value, region.clone()));
                for path in region_relative_access_paths(&root_regions, &region) {
                    return_paths.insert(path.clone());
                    return_value_paths.insert((*summary_func, *summary_value, path));
                }
            }
            let value_object_ids = self.value_points_to_object_ids_of(value_func, value_id);
            for object_id in &value_object_ids {
                return_objects.insert(*object_id);
                return_value_objects.insert((*summary_func, *summary_value, *object_id));
            }
            let mut cells = cell_candidates_for_object_ids(self, &value_object_ids);
            cells.extend(cell_candidates_for_value_targets(self, value_func, value_id));
            cells.sort_unstable_by_key(|node| node.index());
            cells.dedup_by_key(|node| node.index());
            for cell in cells {
                return_cells.insert(cell.index() as u32);
                return_value_cells.insert((*summary_func, *summary_value, cell.index() as u32));
            }
        }

        for index in &param_indices {
            let Some(summary) = self.contextual_function_param_summary(
                func,
                *index,
                &refined,
                sensitivity,
                SparseDirection::Forward,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) else {
                continue;
            };
            let reachable_values = summary.values.iter().copied().collect::<BTreeSet<_>>();
            let reachable_params = summary
                .params
                .iter()
                .map(|(f, _i, v)| (*f, *v))
                .collect::<BTreeSet<_>>();
            let Some(&param_node) = self.function_params.get(&(func, *index)) else {
                continue;
            };
            let param_value = match &self.graph[param_node] {
                FlowNode::Param { value, .. } => *value,
                _ => continue,
            };
            let param_root_regions = value_root_memory_regions(self, func, param_value);
            for visited in &summary.traversal.visited {
                let node = NodeIndex::new(*visited);
                match &self.graph[node] {
                    FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                        for region in self.cell_memory_regions_of(node) {
                            param_to_read_regions.insert((*index, region.clone()));
                            for path in region_relative_access_paths(&param_root_regions, &region) {
                                param_to_read_paths.insert((*index, path));
                            }
                        }
                        param_to_read_cells.insert((*index, node.index() as u32));
                        for object_id in self.cell_points_to_object_ids_of(node) {
                            param_to_read_objects.insert((*index, object_id));
                        }
                        let writes = self
                            .cell_live_values_of(node)
                            .into_iter()
                            .chain(cell_store_values(self, node).into_iter())
                            .map(|(f, v)| (f.0, v.0))
                            .collect::<BTreeSet<_>>();
                        if !writes.is_empty()
                            && (writes.iter().any(|pair| reachable_values.contains(pair))
                                || writes.iter().any(|pair| reachable_params.contains(pair)))
                        {
                            for region in self.cell_memory_regions_of(node) {
                                param_to_write_regions.insert((*index, region.clone()));
                                for path in region_relative_access_paths(&param_root_regions, &region) {
                                    param_to_write_paths.insert((*index, path));
                                }
                            }
                            param_to_write_cells.insert((*index, node.index() as u32));
                            for object_id in self.cell_points_to_object_ids_of(node) {
                                param_to_write_objects.insert((*index, object_id));
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                if *from_index != *index {
                    continue;
                }
                let value_func = FunctionId(*summary_func);
                let value_id = ValueId(*summary_value);
                for region in self.value_memory_regions_of(value_func, value_id) {
                    param_to_return_regions.insert((*index, region.clone()));
                    for path in region_relative_access_paths(&param_root_regions, &region) {
                        param_to_return_paths.insert((*index, path));
                    }
                }
                let value_object_ids = self.value_points_to_object_ids_of(value_func, value_id);
                for object_id in &value_object_ids {
                    param_to_return_objects.insert((*index, *object_id));
                }
                let mut cells = cell_candidates_for_object_ids(self, &value_object_ids);
                cells.extend(cell_candidates_for_value_targets(self, value_func, value_id));
                cells.sort_unstable_by_key(|node| node.index());
                cells.dedup_by_key(|node| node.index());
                for cell in cells {
                    param_to_return_cells.insert((*index, cell.index() as u32));
                }
            }
        }

        for (index, region) in &param_to_return_regions {
            for (live_func, live_value) in self.region_live_values_of(region) {
                param_to_return_live_values.insert((*index, live_func.0, live_value.0));
            }
        }
        for region in &return_regions {
            for (live_func, live_value) in self.region_live_values_of(region) {
                return_live_values.insert((live_func.0, live_value.0));
            }
        }

        let summary = FunctionHeapEffectSummary {
            func: func.0,
            context: Some(refined.clone()),
            sensitivity: Some(sensitivity),
            param_to_read_regions: param_to_read_regions.into_iter().collect(),
            param_to_read_paths: param_to_read_paths.into_iter().collect(),
            param_to_read_cells: param_to_read_cells.into_iter().collect(),
            param_to_read_objects: param_to_read_objects.into_iter().collect(),
            param_to_write_regions: param_to_write_regions.into_iter().collect(),
            param_to_write_paths: param_to_write_paths.into_iter().collect(),
            param_to_write_cells: param_to_write_cells.into_iter().collect(),
            param_to_write_objects: param_to_write_objects.into_iter().collect(),
            param_to_return_regions: param_to_return_regions.into_iter().collect(),
            param_to_return_paths: param_to_return_paths.into_iter().collect(),
            param_to_return_cells: param_to_return_cells.into_iter().collect(),
            param_to_return_objects: param_to_return_objects.into_iter().collect(),
            param_to_return_live_values: param_to_return_live_values.into_iter().collect(),
            return_regions: return_regions.into_iter().collect(),
            return_paths: return_paths.into_iter().collect(),
            return_cells: return_cells.into_iter().collect(),
            return_objects: return_objects.into_iter().collect(),
            return_value_regions: return_value_regions.into_iter().collect(),
            return_value_paths: return_value_paths.into_iter().collect(),
            return_value_cells: return_value_cells.into_iter().collect(),
            return_value_objects: return_value_objects.into_iter().collect(),
            return_live_values: return_live_values.into_iter().collect(),
        };
        self.contextual_function_heap_effect_summary_cache
            .borrow_mut()
            .insert(key, summary.clone());
        Some(summary)
    }

    pub fn interprocedural_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<InterproceduralCallSummary> {
        self.interprocedural_call_summary_with_sensitivity(
            func,
            inst,
            ContextSensitivity::ReceiverArgsAndCallSite,
            max_depth,
            max_visits,
            engine,
            include_heap,
        )
    }

    pub fn interprocedural_call_summary_with_sensitivity(
        &self,
        func: FunctionId,
        inst: InstId,
        sensitivity: ContextSensitivity,
        max_depth: usize,
        max_visits: usize,
        engine: DemandEngine,
        include_heap: bool,
    ) -> Option<InterproceduralCallSummary> {
        let context = self
            .call_context_key(func, inst)
            .map(|context| self.refine_call_context_for_sensitivity(context, sensitivity))?;
        let key = (context.clone(), sensitivity, max_depth, max_visits, engine, include_heap);
        if let Some(cached) = self.interprocedural_call_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }

        let mut callee_ids = context
            .callee_funcs
            .iter()
            .copied()
            .map(FunctionId)
            .collect::<Vec<_>>();
        if callee_ids.is_empty() {
            callee_ids = self
                .exact_callee_ids_for_call(func, inst)
                .into_iter()
                .collect::<Vec<_>>();
        }
        callee_ids.sort();
        callee_ids.dedup();
        if callee_ids.is_empty() {
            return None;
        }

        let mut port_to_params = BTreeMap::<String, BTreeSet<usize>>::new();
        let mut param_to_ports = BTreeMap::<usize, BTreeSet<String>>::new();
        for ((call_func, call_inst, port), node) in &self.call_ports {
            if *call_func != func || *call_inst != inst {
                continue;
            }
            let port_name = format!("{:?}", port);
            for edge in self.graph.edges_directed(*node, petgraph::Direction::Outgoing) {
                if !matches!(edge.weight().kind, EdgeKind::ActualToFormal) {
                    continue;
                }
                if let FlowNode::Param { func: param_func, index, .. } = self.graph[edge.target()] {
                    if callee_ids.iter().any(|candidate| *candidate == param_func) {
                        port_to_params.entry(port_name.clone()).or_default().insert(index);
                        param_to_ports.entry(index).or_default().insert(port_name.clone());
                    }
                }
            }
        }

        let mut port_to_return = BTreeSet::new();
        let mut port_to_param = BTreeSet::new();
        let mut port_to_port = BTreeSet::new();
        let mut port_to_return_values = BTreeSet::new();
        let mut port_to_return_live_values = BTreeSet::new();
        let mut port_to_return_value_regions = BTreeSet::new();
        let mut port_to_return_value_paths = BTreeSet::new();
        let mut port_to_return_value_objects = BTreeSet::new();
        let mut port_to_read_regions = BTreeSet::new();
        let mut port_to_read_paths = BTreeSet::new();
        let mut port_to_read_cells = BTreeSet::new();
        let mut port_to_read_objects = BTreeSet::new();
        let mut port_to_write_regions = BTreeSet::new();
        let mut port_to_write_paths = BTreeSet::new();
        let mut port_to_write_cells = BTreeSet::new();
        let mut port_to_write_objects = BTreeSet::new();
        let mut port_to_return_regions = BTreeSet::new();
        let mut port_to_return_paths = BTreeSet::new();
        let mut port_to_return_cells = BTreeSet::new();
        let mut port_to_return_objects = BTreeSet::new();
        let mut return_values = BTreeSet::new();
        let mut return_live_values = BTreeSet::new();
        let mut return_value_regions = BTreeSet::new();
        let mut return_value_paths = BTreeSet::new();
        let mut return_value_cells = BTreeSet::new();
        let mut return_value_objects = BTreeSet::new();
        let mut return_paths = BTreeSet::new();
        let mut return_cells = BTreeSet::new();
        let mut return_objects = BTreeSet::new();
        for callee_func in &callee_ids {
            let Some(transfer) = self.contextual_function_transfer_summary(
                *callee_func,
                &context,
                sensitivity,
                max_depth,
                max_visits,
                engine,
                include_heap,
            ) else {
                continue;
            };
            let heap_effects = self.contextual_function_heap_effect_summary(
                *callee_func,
                &context,
                sensitivity,
                max_depth,
                max_visits,
                engine,
                include_heap,
            );
            for value in &transfer.return_values {
                return_values.insert(*value);
            }
            if let Some(effects) = &heap_effects {
                for (summary_func, summary_value, region) in &effects.return_value_regions {
                    return_value_regions.insert((*summary_func, *summary_value, region.clone()));
                }
                for (summary_func, summary_value, path) in &effects.return_value_paths {
                    return_value_paths.insert((*summary_func, *summary_value, path.clone()));
                }
                for (summary_func, summary_value, cell) in &effects.return_value_cells {
                    return_value_cells.insert((*summary_func, *summary_value, *cell));
                }
                for (summary_func, summary_value, object_id) in &effects.return_value_objects {
                    return_value_objects.insert((*summary_func, *summary_value, *object_id));
                    return_objects.insert(*object_id);
                }
                for object_id in &effects.return_objects {
                    return_objects.insert(*object_id);
                }
                for path in &effects.return_paths {
                    return_paths.insert(path.clone());
                }
                for cell in &effects.return_cells {
                    return_cells.insert(*cell);
                }
                for (summary_func, summary_value) in &effects.return_live_values {
                    return_live_values.insert((*summary_func, *summary_value));
                }
            }
            for (port_name, params) in &port_to_params {
                if params.iter().any(|index| transfer.return_reachable_params.iter().any(|target| target == index)) {
                    port_to_return.insert(port_name.clone());
                }
                for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                    if params.contains(from_index) {
                        port_to_return_values.insert((port_name.clone(), *summary_func, *summary_value));
                    }
                }
                for (from_index, to_index) in &transfer.param_to_param {
                    if !params.contains(from_index) {
                        continue;
                    }
                    port_to_param.insert((port_name.clone(), *to_index));
                    if let Some(target_ports) = param_to_ports.get(to_index) {
                        for target_port in target_ports {
                            port_to_port.insert((port_name.clone(), target_port.clone()));
                        }
                    }
                }
                if let Some(effects) = &heap_effects {
                    for (from_index, region) in &effects.param_to_read_regions {
                        if params.contains(from_index) {
                            port_to_read_regions.insert((port_name.clone(), region.clone()));
                        }
                    }
                    for (from_index, path) in &effects.param_to_read_paths {
                        if params.contains(from_index) {
                            port_to_read_paths.insert((port_name.clone(), path.clone()));
                        }
                    }
                    for (from_index, cell) in &effects.param_to_read_cells {
                        if params.contains(from_index) {
                            port_to_read_cells.insert((port_name.clone(), *cell));
                        }
                    }
                    for (from_index, object_id) in &effects.param_to_read_objects {
                        if params.contains(from_index) {
                            port_to_read_objects.insert((port_name.clone(), *object_id));
                        }
                    }
                    for (from_index, region) in &effects.param_to_write_regions {
                        if params.contains(from_index) {
                            port_to_write_regions.insert((port_name.clone(), region.clone()));
                        }
                    }
                    for (from_index, path) in &effects.param_to_write_paths {
                        if params.contains(from_index) {
                            port_to_write_paths.insert((port_name.clone(), path.clone()));
                        }
                    }
                    for (from_index, cell) in &effects.param_to_write_cells {
                        if params.contains(from_index) {
                            port_to_write_cells.insert((port_name.clone(), *cell));
                        }
                    }
                    for (from_index, object_id) in &effects.param_to_write_objects {
                        if params.contains(from_index) {
                            port_to_write_objects.insert((port_name.clone(), *object_id));
                        }
                    }
                    for (from_index, region) in &effects.param_to_return_regions {
                        if params.contains(from_index) {
                            port_to_return_regions.insert((port_name.clone(), region.clone()));
                        }
                    }
                    for (from_index, path) in &effects.param_to_return_paths {
                        if params.contains(from_index) {
                            port_to_return_paths.insert((port_name.clone(), path.clone()));
                        }
                    }
                    for (from_index, cell) in &effects.param_to_return_cells {
                        if params.contains(from_index) {
                            port_to_return_cells.insert((port_name.clone(), *cell));
                        }
                    }
                    for (from_index, object_id) in &effects.param_to_return_objects {
                        if params.contains(from_index) {
                            port_to_return_objects.insert((port_name.clone(), *object_id));
                        }
                    }
                    for (from_index, summary_func, summary_value) in &effects.param_to_return_live_values {
                        if params.contains(from_index) {
                            port_to_return_live_values.insert((port_name.clone(), *summary_func, *summary_value));
                        }
                    }
                    for (from_index, summary_func, summary_value) in &transfer.param_to_return_values {
                        if !params.contains(from_index) {
                            continue;
                        }
                        for region in self.value_memory_regions_of(FunctionId(*summary_func), ValueId(*summary_value)) {
                            port_to_return_value_regions.insert((port_name.clone(), *summary_func, *summary_value, region));
                        }
                        for (_ret_func, _ret_value, path) in effects
                            .return_value_paths
                            .iter()
                            .filter(|(ret_func, ret_value, _)| *ret_func == *summary_func && *ret_value == *summary_value)
                        {
                            port_to_return_value_paths.insert((port_name.clone(), *summary_func, *summary_value, path.clone()));
                        }
                        for (_ret_func, _ret_value, object_id) in effects
                            .return_value_objects
                            .iter()
                            .filter(|(ret_func, ret_value, _)| *ret_func == *summary_func && *ret_value == *summary_value)
                        {
                            port_to_return_value_objects.insert((port_name.clone(), *summary_func, *summary_value, *object_id));
                        }
                    }
                }
            }
        }

        let summary = InterproceduralCallSummary {
            caller_func: func.0,
            inst: inst.0,
            sensitivity: Some(sensitivity),
            callee_names: context.callee_names.clone(),
            callee_funcs: callee_ids.iter().map(|func| func.0).collect(),
            context,
            port_to_return: port_to_return.into_iter().collect(),
            port_to_param: port_to_param.into_iter().collect(),
            port_to_port: port_to_port.into_iter().collect(),
            port_to_return_values: port_to_return_values.into_iter().collect(),
            port_to_return_live_values: port_to_return_live_values.into_iter().collect(),
            port_to_return_value_regions: port_to_return_value_regions.into_iter().collect(),
            port_to_return_value_paths: port_to_return_value_paths.into_iter().collect(),
            port_to_return_value_objects: port_to_return_value_objects.into_iter().collect(),
            port_to_read_regions: port_to_read_regions.into_iter().collect(),
            port_to_read_paths: port_to_read_paths.into_iter().collect(),
            port_to_read_cells: port_to_read_cells.into_iter().collect(),
            port_to_read_objects: port_to_read_objects.into_iter().collect(),
            port_to_write_regions: port_to_write_regions.into_iter().collect(),
            port_to_write_paths: port_to_write_paths.into_iter().collect(),
            port_to_write_cells: port_to_write_cells.into_iter().collect(),
            port_to_write_objects: port_to_write_objects.into_iter().collect(),
            port_to_return_regions: port_to_return_regions.into_iter().collect(),
            port_to_return_paths: port_to_return_paths.into_iter().collect(),
            port_to_return_cells: port_to_return_cells.into_iter().collect(),
            port_to_return_objects: port_to_return_objects.into_iter().collect(),
            return_values: return_values.into_iter().collect(),
            return_live_values: return_live_values.into_iter().collect(),
            return_value_regions: return_value_regions.into_iter().collect(),
            return_value_paths: return_value_paths.into_iter().collect(),
            return_value_cells: return_value_cells.into_iter().collect(),
            return_value_objects: return_value_objects.into_iter().collect(),
            return_paths: return_paths.into_iter().collect(),
            return_cells: return_cells.into_iter().collect(),
            return_objects: return_objects.into_iter().collect(),
        };
        self.interprocedural_call_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn cell_write_generations_of(&self, cell: NodeIndex) -> Vec<(u64, FunctionId, ValueId)> {
        self.cell_write_generations
            .get(&cell.index())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(generation, func, value)| (generation, FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn demand_summary_from_seeds(
        &self,
        seeds: &[NodeIndex],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let mut key_seeds = seeds.iter().map(|seed| seed.index()).collect::<Vec<_>>();
        key_seeds.sort_unstable();
        key_seeds.dedup();
        let key = (key_seeds, direction, max_depth, max_visits);
        if let Some(cached) = self.demand_seed_summary_cache.borrow().get(&key).cloned() {
            return cached;
        }
        let traversal = self.sparse_traversal(seeds, direction, max_depth, max_visits);
        let summary = self.summarize_sparse_traversal(traversal);
        self.demand_seed_summary_cache.borrow_mut().insert(key, summary.clone());
        summary
    }

    pub fn demand_summary_from_node(
        &self,
        seed: NodeIndex,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let key = (seed.index(), direction, max_depth, max_visits);
        if let Some(cached) = self.demand_summary_cache.borrow().get(&key).cloned() {
            return cached;
        }
        let summary = self.summarize_sparse_traversal(self.sparse_traversal(&[seed], direction, max_depth, max_visits));
        self.demand_summary_cache.borrow_mut().insert(key, summary.clone());
        summary
    }

    pub fn demand_multi_value_summary(
        &self,
        seeds: &[(FunctionId, ValueId)],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let nodes = seeds
            .iter()
            .filter_map(|(func, value)| self.values.get(&(*func, *value)).copied())
            .collect::<Vec<_>>();
        self.demand_summary_from_seeds(&nodes, direction, max_depth, max_visits)
    }

    pub fn demand_reachable_values(
        &self,
        func: FunctionId,
        value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Vec<(FunctionId, ValueId)> {
        let summary = self.demand_value_summary(func, value, direction, max_depth, max_visits);
        summary
            .values
            .into_iter()
            .map(|(func, value)| (FunctionId(func), ValueId(value)))
            .collect()
    }

    pub fn demand_reaches_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_value_summary(src_func, src_value, direction, max_depth, max_visits);
        summary
            .values
            .iter()
            .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
    }

    pub fn demand_reaches_any_value(
        &self,
        src_func: FunctionId,
        src_value: ValueId,
        targets: &[(FunctionId, ValueId)],
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let summary = self.demand_value_summary(src_func, src_value, direction, max_depth, max_visits);
        targets.iter().any(|(dst_func, dst_value)| {
            summary
                .values
                .iter()
                .any(|(func, value)| *func == dst_func.0 && *value == dst_value.0)
                || summary
                    .params
                    .iter()
                    .any(|(func, _index, value)| *func == dst_func.0 && *value == dst_value.0)
        })
    }

    pub fn demand_call_port_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let seed = self.call_ports.get(&(func, inst, port))?.to_owned();
        Some(self.demand_summary_from_node(seed, direction, max_depth, max_visits))
    }

    pub fn demand_call_port_reaches_value(
        &self,
        func: FunctionId,
        inst: InstId,
        port: Port,
        dst_func: FunctionId,
        dst_value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> bool {
        let Some(summary) = self.demand_call_port_summary(func, inst, port, direction, max_depth, max_visits) else {
            return false;
        };
        summary
            .values
            .iter()
            .any(|(summary_func, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
            || summary
                .params
                .iter()
                .any(|(summary_func, _index, summary_value)| *summary_func == dst_func.0 && *summary_value == dst_value.0)
    }

    pub fn demand_call_summary(
        &self,
        func: FunctionId,
        inst: InstId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> Option<SparseValueSummary> {
        let key = ((func.0, inst.0), direction, max_depth, max_visits);
        if let Some(cached) = self.demand_call_summary_cache.borrow().get(&key).cloned() {
            return Some(cached);
        }
        let mut seeds = self
            .call_ports
            .iter()
            .filter_map(|((call_func, call_inst, _port), node)| {
                (*call_func == func && *call_inst == inst).then_some(*node)
            })
            .collect::<Vec<_>>();
        seeds.sort_unstable_by_key(|node| node.index());
        seeds.dedup();
        if seeds.is_empty() {
            return None;
        }
        let summary = self.demand_summary_from_seeds(&seeds, direction, max_depth, max_visits);
        self.demand_call_summary_cache.borrow_mut().insert(key, summary.clone());
        Some(summary)
    }

    pub fn demand_value_summary(
        &self,
        func: FunctionId,
        value: ValueId,
        direction: SparseDirection,
        max_depth: usize,
        max_visits: usize,
    ) -> SparseValueSummary {
        let seed = value_node(self, func, value);
        self.demand_summary_from_node(seed, direction, max_depth, max_visits)
    }

    pub fn call_info(&self, func: FunctionId, inst: InstId) -> Option<CallInfo> {
        self.call_meta.get(&(func, inst)).and_then(|meta| meta.as_call_info())
    }

    pub fn node_label_map(&self) -> BTreeMap<usize, String> {
        let mut out = BTreeMap::new();
        for idx in self.graph.node_indices() {
            out.insert(idx.index(), self.describe_node(idx));
        }
        out
    }
    pub fn stats(&self) -> FlowStats {
        let static_calls = self
            .call_meta
            .values()
            .filter(|meta| meta.callee_name.is_some())
            .count();
        let dynamic_calls = self.call_meta.len().saturating_sub(static_calls);
        let resolved_internal_calls = self.resolved_internal_targets.len();
        let unresolved_static_calls = self
            .call_meta
            .iter()
            .filter(|(key, meta)| meta.callee_name.is_some() && !self.resolved_internal_targets.contains_key(key))
            .count();
        let value_nodes = self
            .graph
            .node_indices()
            .filter(|idx| matches!(self.graph[*idx], FlowNode::Value { .. } | FlowNode::Param { .. } | FlowNode::Return { .. }))
            .count();
        let sparse_data_edges = self
            .sparse_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let heap_value_edges = self
            .heap_value_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let heap_object_edges = self
            .heap_object_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let object_graph_edges = self
            .object_graph_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let region_graph_edges = self
            .region_graph_successors
            .values()
            .map(|nodes| nodes.len())
            .sum();
        let object_shape_nodes = self.object_shape_labels.len();
        let object_shape_paths = self.object_shape_paths.values().map(|values| values.len()).sum();
        let memory_regions = self.value_memory_regions.len() + self.cell_memory_regions.len() + self.node_memory_regions.len();
        let live_cell_values = self.cell_live_values.values().map(|values| values.len()).sum();
        let live_cell_regions = self.cell_live_regions.values().map(|values| values.len()).sum();
        let live_region_values = self.region_live_values.values().map(|values| values.len()).sum();
        let live_region_cells = self.region_live_cells.values().map(|values| values.len()).sum();
        let points_to_classes = self.value_points_to_classes.len() + self.cell_points_to_classes.len() + self.node_points_to_classes.len();
        let points_to_targets = self.value_points_to_targets.len() + self.cell_points_to_targets.len() + self.node_points_to_targets.len();
        let points_to_objects = self.abstract_objects.len() + self.value_points_to_object_ids.len() + self.cell_points_to_object_ids.len() + self.node_points_to_object_ids.len();
        let cell_write_generations = self.cell_write_generations.values().map(|values| values.len()).sum();
        let contextual_states = self.contextual_points_to_targets.len()
            + self.contextual_points_to_object_ids.len()
            + self.contextual_return_values.len()
            + self.contextual_return_cells.len()
            + self.contextual_node_points_to_targets.len()
            + self.contextual_value_points_to_targets.len()
            + self.contextual_cell_points_to_targets.len();
        let contextual_points_to_objects = self.contextual_points_to_object_ids.len()
            + self.contextual_node_points_to_object_ids.len()
            + self.contextual_value_points_to_object_ids.len()
            + self.contextual_cell_points_to_object_ids.len();
        let cached_sparse_summaries = self.demand_summary_cache.borrow().len()
            + self.demand_seed_summary_cache.borrow().len()
            + self.demand_call_summary_cache.borrow().len()
            + self.demand_fixpoint_summary_cache.borrow().len();
        let cached_demand_queries = self.demand_query_summary_cache.borrow().len();
        let cached_contextual_queries = self.contextual_demand_query_cache.borrow().len();
        let cached_contextual_summaries = self.contextual_call_summary_cache.borrow().len();
        let cached_function_summaries = self.function_summary_cache.borrow().len();
        let cached_interprocedural_summaries = self.interprocedural_call_summary_cache.borrow().len();
        let cached_transfer_summaries = self.function_transfer_summary_cache.borrow().len()
            + self.contextual_function_transfer_summary_cache.borrow().len();
        let cached_heap_effect_summaries = self.function_heap_effect_summary_cache.borrow().len()
            + self.contextual_function_heap_effect_summary_cache.borrow().len();
        let solver_closure_iterations = self.solver_closure_iterations;
        let global_solver_iterations = self.global_solver_iterations;
        FlowStats {
            files: self.file_paths.len(),
            functions: self.function_names.len(),
            value_nodes,
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
            sparse_data_edges,
            heap_value_edges,
            heap_object_edges,
            object_graph_edges,
            region_graph_edges,
            object_shape_nodes,
            object_shape_paths,
            object_identity_values: self.object_identity_roots.len(),
            points_to_classes,
            points_to_targets,
            points_to_objects,
            strong_update_cells: self.strong_update_cells.len(),
            cell_write_generations,
            contextual_states,
            contextual_points_to_objects,
            solver_closure_iterations,
            global_solver_iterations,
            memory_regions,
            live_cell_values,
            live_cell_regions,
            live_region_values,
            live_region_cells,
            cached_sparse_summaries,
            cached_demand_queries,
            cached_contextual_queries,
            cached_contextual_summaries,
            cached_function_summaries,
            cached_interprocedural_summaries,
            cached_transfer_summaries,
            cached_heap_effect_summaries,
            static_calls,
            dynamic_calls,
            resolved_internal_calls,
            unresolved_static_calls,
            synthetic_sources: self.synthetic_sources.len(),
            synthetic_sinks: self.synthetic_sinks.len(),
        }
    }

    pub fn call_report(&self) -> Vec<CallReport> {
        let mut out = self
            .call_meta
            .iter()
            .map(|(key, meta)| CallReport {
                function_name: self.function_name(meta.func).to_string(),
                location: self.location_text(meta.func, meta.inst),
                callee_name: meta.callee_name.clone(),
                receiver_type: meta.receiver_type.clone(),
                receiver_type_candidates: meta.receiver_type_candidates.clone(),
                method_name: meta.method_name.clone(),
                arg_count: meta.arg_count,
                arg_types: meta.arg_types.clone(),
                arg_type_candidates: meta.arg_type_candidates.clone(),
                is_dynamic: meta.callee_name.is_none(),
                resolved_internal_targets: self
                    .resolved_internal_targets
                    .get(key)
                    .cloned()
                    .unwrap_or_default(),
            })
            .collect::<Vec<_>>();
        out.sort_by(|a, b| a.location.cmp(&b.location).then_with(|| a.function_name.cmp(&b.function_name)));
        out
    }


    pub fn describe_node(&self, idx: NodeIndex) -> String {
        match &self.graph[idx] {
            FlowNode::Param { func, index, value } => {
                let identity = value_identity_site(self, *func, *value)
                    .map(|site| format!(" [oid={site}]"))
                    .unwrap_or_default();
                format!(
                    "param {}#{} v{}{}",
                    self.function_name(*func),
                    index,
                    value.0,
                    identity,
                )
            },
            FlowNode::Return { func } => format!("return {}", self.function_name(*func)),
            FlowNode::Value { func, value } => {
                let ty_suffix = self
                    .value_types
                    .get(&(*func, *value))
                    .map(|ty| format!(":{ty}"))
                    .unwrap_or_default();
                let identity = value_identity_site(self, *func, *value)
                    .map(|site| format!(" [oid={site}]"))
                    .unwrap_or_default();
                format!("value {}::v{}{}{}", self.function_name(*func), value.0, ty_suffix, identity)
            },
            FlowNode::CallPort { func, inst, port, callee_name } => {
                let location = self.location_text(*func, *inst);
                let callee = callee_name.clone().unwrap_or_else(|| "<dynamic>".to_string());
                format!(
                    "call-port {} {:?} {} {}",
                    self.function_name(*func),
                    port.clone(),
                    callee,
                    location
                )
            }
            FlowNode::FieldCell { func, base, field, .. } => {
                format!("field-cell {} base=v{} .{}", self.function_name(*func), base.0, field)
            }
            FlowNode::IndexCell { func, base, index, abstract_key, .. } => {
                format!("index-cell {} base=v{} idx=v{} key={}", self.function_name(*func), base.0, index.0, abstract_key)
            }
            FlowNode::SyntheticSource { func, inst, rule_id, kind, out } => {
                format!(
                    "source {} [{}] {:?} {} {}",
                    rule_id,
                    kind,
                    out,
                    self.function_name(*func),
                    self.location_text(*func, *inst)
                )
            }
            FlowNode::SyntheticSink { func, inst, rule_id, kind, input } => {
                format!(
                    "sink {} [{}] {:?} {} {}",
                    rule_id,
                    kind,
                    input,
                    self.function_name(*func),
                    self.location_text(*func, *inst)
                )
            }
        }
    }

    pub fn describe_edge(&self, from: NodeIndex, to: NodeIndex) -> String {
        if let Some(edge) = self.graph.edges_connecting(from, to).next() {
            format!("{:?}", edge.weight().kind)
        } else {
            "<no-edge>".to_string()
        }
    }

    pub fn function_name(&self, func: FunctionId) -> &str {
        self.function_names
            .get(&func)
            .map(|s| s.as_str())
            .unwrap_or("<unknown-func>")
    }

    pub fn location_text(&self, func: FunctionId, inst: InstId) -> String {
        let Some(span) = self.inst_spans.get(&(func, inst)) else {
            return "@unknown".to_string();
        };
        self.span_text(span)
    }

    pub fn span_text(&self, span: &Span) -> String {
        let path = self
            .file_paths
            .get(&span.file)
            .cloned()
            .unwrap_or_else(|| format!("file#{}", span.file));
        if span.start_line == 0 && span.end_line == 0 && span.start_col == 0 && span.end_col == 0 {
            return if self.file_paths.contains_key(&span.file) {
                format!("@{}", path)
            } else {
                "@unknown".to_string()
            };
        }
        format!("@{}:{}:{}", path, span.start_line, span.start_col)
    }
}

fn create_function_nodes(fg: &mut FlowGraph, func: &Function) {
    for (idx, param) in func.params.iter().copied().enumerate() {
        let param_node = fg.graph.add_node(FlowNode::Param {
            func: func.id,
            index: idx,
            value: param,
        });
        fg.function_params.insert((func.id, idx), param_node);
        let value_node = fg.graph.add_node(FlowNode::Value {
            func: func.id,
            value: param,
        });
        fg.values.insert((func.id, param), value_node);
        fg.graph.add_edge(param_node, value_node, FlowEdge { kind: EdgeKind::Assign });
    }

    for local in func.locals.iter().copied() {
        fg.values.entry((func.id, local)).or_insert_with(|| {
            fg.graph.add_node(FlowNode::Value {
                func: func.id,
                value: local,
            })
        });
    }

    let return_node = fg.graph.add_node(FlowNode::Return { func: func.id });
    fg.function_returns.insert(func.id, return_node);
}

fn value_node(fg: &FlowGraph, func: FunctionId, value: ValueId) -> NodeIndex {
    *fg.values
        .get(&(func, value))
        .expect("value node must be pre-created")
}

fn edge_value_to_value(fg: &mut FlowGraph, func: FunctionId, src: ValueId, dst: ValueId, kind: EdgeKind) {
    let src_node = value_node(fg, func, src);
    let dst_node = value_node(fg, func, dst);
    fg.graph.add_edge(src_node, dst_node, FlowEdge { kind });
}

fn connect_call_value_ports(fg: &mut FlowGraph, func: FunctionId, inst: InstId, call: &CallInst) {
    let callee_name = static_callee_name(call);

    if let Some(receiver) = call.receiver {
        let port = Port::Receiver;
        let port_node = get_or_create_call_port(fg, func, inst, port.clone(), callee_name.clone());
        let src = value_node(fg, func, receiver);
        fg.graph.add_edge(src, port_node, FlowEdge { kind: EdgeKind::ValueToCallPort });
    }

    for (idx, arg) in call.args.iter().copied().enumerate() {
        let port = Port::Arg(idx);
        let port_node = get_or_create_call_port(fg, func, inst, port.clone(), callee_name.clone());
        let src = value_node(fg, func, arg);
        fg.graph.add_edge(src, port_node, FlowEdge { kind: EdgeKind::ValueToCallPort });
    }

    if let Some(dst) = call.dst {
        let port = Port::Return;
        let port_node = get_or_create_call_port(fg, func, inst, port, callee_name);
        let dst_node = value_node(fg, func, dst);
        fg.graph.add_edge(port_node, dst_node, FlowEdge { kind: EdgeKind::CallPortToValue });
    }
}

fn connect_lambda_capture_bindings(
    fg: &mut FlowGraph,
    caller_func: FunctionId,
    callee_value: ValueId,
    callee_func: &Function,
) {
    let canonical_callee = canonical_heap_value(fg, caller_func, callee_value);
    for (ir_index, capture_name) in capture_param_ir_indices(callee_func) {
        let field_name = format!("__capture__{capture_name}");
        let Some(field_cell) = fg.field_cells.get(&(caller_func, canonical_callee, field_name)).copied() else {
            continue;
        };
        let Some(param_node) = fg.function_params.get(&(callee_func.id, ir_index)).copied() else {
            continue;
        };
        fg.graph.add_edge(field_cell, param_node, FlowEdge { kind: EdgeKind::ActualToFormal });
    }
}

fn compute_actual_formal_bindings(call: &CallInst, callee_func: &Function) -> Vec<(Port, ValueId, usize)> {
    let mut bindings = Vec::new();
    let receiver_offset = function_receiver_offset(callee_func);
    if receiver_offset == 1 {
        if let Some(receiver) = call.receiver {
            if !callee_func.params.is_empty() {
                bindings.push((Port::Receiver, receiver, 0));
            }
        }
    }

    let specs = function_param_specs(callee_func);
    if specs.is_empty() {
        let param_offset = receiver_offset;
        for (idx, arg) in call.args.iter().copied().enumerate() {
            let ir_index = idx + param_offset;
            if ir_index < callee_func.params.len() {
                bindings.push((Port::Arg(idx), arg, ir_index));
            }
        }
        return bindings;
    }

    let mut consumed = Vec::<usize>::new();
    let positional_targets = specs
        .iter()
        .filter(|spec| spec.kind == ParamBindingKind::Positional && !spec.keyword_only)
        .map(|spec| spec.ir_index)
        .collect::<Vec<_>>();
    let vararg_target = specs
        .iter()
        .find(|spec| spec.kind == ParamBindingKind::VarArgs)
        .map(|spec| spec.ir_index);
    let kwarg_target = specs
        .iter()
        .find(|spec| spec.kind == ParamBindingKind::KwArgs)
        .map(|spec| spec.ir_index);
    let mut next_positional = 0usize;

    for (idx, arg) in call.args.iter().copied().enumerate() {
        let target_index = if let Some(name) = call.arg_names.get(idx).and_then(|name| name.as_deref()) {
            if let Some(spec) = specs.iter().find(|spec| spec.name == name && spec.kind == ParamBindingKind::Positional) {
                if consumed.iter().any(|existing| *existing == spec.ir_index) {
                    kwarg_target.or(vararg_target)
                } else {
                    consumed.push(spec.ir_index);
                    Some(spec.ir_index)
                }
            } else {
                kwarg_target.or(vararg_target)
            }
        } else {
            while next_positional < positional_targets.len()
                && consumed.iter().any(|existing| *existing == positional_targets[next_positional])
            {
                next_positional += 1;
            }
            if let Some(ir_index) = positional_targets.get(next_positional).copied() {
                consumed.push(ir_index);
                next_positional += 1;
                Some(ir_index)
            } else {
                vararg_target.or(kwarg_target)
            }
        };

        if let Some(ir_index) = target_index {
            if ir_index < callee_func.params.len() {
                bindings.push((Port::Arg(idx), arg, ir_index));
            }
        }
    }

    bindings
}


fn connect_cell_projected_values_to_dst(
    fg: &mut FlowGraph,
    cell: NodeIndex,
    dst_func: FunctionId,
    dst: ValueId,
    edge_kind: EdgeKind,
) {
    let dst_node = value_node(fg, dst_func, dst);
    let cutoff_edge = fg.graph.add_edge(cell, dst_node, FlowEdge { kind: edge_kind.clone() });
    let cutoff_edge_idx = Some(cutoff_edge.index());
    for (proj_func, proj_value) in cell_values_for_flow_before_edge(fg, cell, cutoff_edge_idx) {
        connect_bidirectional_value_pair(fg, proj_func, proj_value, dst_func, dst);
        propagate_object_identity_site(fg, proj_func, proj_value, dst_func, dst);
        let mut visited = HashSet::new();
        bridge_nested_heap_values(fg, proj_func, proj_value, dst_func, dst, &mut visited);
    }
}

fn connect_python_container_semantics(
    fg: &mut FlowGraph,
    func: FunctionId,
    call: &CallInst,
    meta: &CallMeta,
    literal_index_keys: &HashMap<ValueId, String>,
) {
    let Some(receiver) = call.receiver else {
        return;
    };
    let Some(method) = meta.method_name.as_deref() else {
        return;
    };

    match method {
        "append" => {
            let Some(src) = call.args.get(0).copied() else {
                return;
            };
            let precise_key = next_precise_numeric_index_key(fg, func, receiver);
            for key in [precise_key.as_str(), "*"] {
                let cell = ensure_index_cell(fg, func, receiver, key);
                let src_node = value_node(fg, func, src);
                fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
            }
        }
        "insert" => {
            let Some(src) = call.args.get(1).copied() else {
                return;
            };
            let key = call
                .args
                .get(0)
                .map(|index| abstract_index_key(literal_index_keys, *index))
                .unwrap_or_else(|| "*".to_string());
            for slot in [key.as_str(), "*"] {
                let cell = ensure_index_cell(fg, func, receiver, slot);
                let src_node = value_node(fg, func, src);
                fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
            }
        }
        "extend" | "update" => {
            let Some(other) = call.args.get(0).copied() else {
                return;
            };
            let mut visited = HashSet::new();
            bridge_nested_heap_values(fg, func, receiver, func, other, &mut visited);
        }
        "get" => {
            let Some(dst) = call.dst else {
                return;
            };
            let key = call
                .args
                .get(0)
                .map(|index| abstract_index_key(literal_index_keys, *index))
                .unwrap_or_else(|| "*".to_string());
            let mut cells = index_cells_for_key(fg, func, receiver, &key);
            if cells.is_empty() {
                cells.push(ensure_index_cell(fg, func, receiver, &key));
            }
            for cell in cells {
                connect_cell_projected_values_to_dst(fg, cell, func, dst, EdgeKind::LoadIndex);
            }
            if let Some(default) = call.args.get(1).copied() {
                edge_value_to_value(fg, func, default, dst, EdgeKind::LoadIndex);
                propagate_object_identity_site(fg, func, default, func, dst);
                let mut visited = HashSet::new();
                bridge_nested_heap_values(fg, func, default, func, dst, &mut visited);
            }
        }
        "pop" => {
            let Some(dst) = call.dst else {
                return;
            };
            let key = if let Some(index) = call.args.get(0) {
                abstract_index_key(literal_index_keys, *index)
            } else if let Some(last_key) = last_precise_numeric_index_key(fg, func, receiver) {
                last_key
            } else {
                "*".to_string()
            };
            let mut cells = index_cells_for_key(fg, func, receiver, &key);
            if cells.is_empty() {
                cells.push(ensure_index_cell(fg, func, receiver, &key));
            }
            for cell in cells {
                connect_cell_projected_values_to_dst(fg, cell, func, dst, EdgeKind::LoadIndex);
            }
            if let Some(default) = call.args.get(1).copied() {
                edge_value_to_value(fg, func, default, dst, EdgeKind::LoadIndex);
                propagate_object_identity_site(fg, func, default, func, dst);
                let mut visited = HashSet::new();
                bridge_nested_heap_values(fg, func, default, func, dst, &mut visited);
            }
        }
        "setdefault" => {
            let key = call
                .args
                .get(0)
                .map(|index| abstract_index_key(literal_index_keys, *index))
                .unwrap_or_else(|| "*".to_string());
            let cell = ensure_index_cell(fg, func, receiver, &key);
            if let Some(default) = call.args.get(1).copied() {
                let src_node = value_node(fg, func, default);
                fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
                let wildcard = ensure_index_cell(fg, func, receiver, "*");
                fg.graph.add_edge(src_node, wildcard, FlowEdge { kind: EdgeKind::StoreIndex });
            }
            if let Some(dst) = call.dst {
                connect_cell_projected_values_to_dst(fg, cell, func, dst, EdgeKind::LoadIndex);
            }
        }
        "copy" | "__copy__" => {
            let Some(dst) = call.dst else {
                return;
            };
            let mut visited = HashSet::new();
            bridge_nested_heap_values(fg, func, receiver, func, dst, &mut visited);
        }
        _ => {}
    }
}


fn connect_internal_call(
    fg: &mut FlowGraph,
    caller_func: FunctionId,
    inst: InstId,
    call: &CallInst,
    callee_func: &Function,
    _caller_ret: NodeIndex,
) {
    if let Callee::Dynamic(callee_value) = &call.callee {
        connect_lambda_capture_bindings(fg, caller_func, *callee_value, callee_func);
    }

    let bindings = compute_actual_formal_bindings(call, callee_func);
    for (port, actual_value, ir_index) in &bindings {
        let Some(param_node) = fg.function_params.get(&(callee_func.id, *ir_index)).copied() else {
            continue;
        };
        let arg_port = get_or_create_call_port(
            fg,
            caller_func,
            inst,
            port.clone(),
            Some(callee_func.name.clone()),
        );
        fg.graph.add_edge(arg_port, param_node, FlowEdge { kind: EdgeKind::ActualToFormal });
        propagate_object_identity_site(fg, caller_func, *actual_value, callee_func.id, callee_func.params[*ir_index]);
    }

    if let Some(dst) = call.dst {
        let ret_port = get_or_create_call_port(
            fg,
            caller_func,
            inst,
            Port::Return,
            Some(callee_func.name.clone()),
        );
        let callee_ret = *fg
            .function_returns
            .get(&callee_func.id)
            .expect("callee return node must exist");
        fg.graph.add_edge(callee_ret, ret_port, FlowEdge { kind: EdgeKind::FormalToActual });
        let direct_sites = returned_direct_identity_sites(fg, callee_func);
        if direct_sites.len() == 1 {
            fg.object_identity_roots.insert((caller_func, dst), dst);
            fg.object_identity_sites.insert((caller_func, dst), direct_sites[0].clone());
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ProjectionStep {
    Field(String),
    Index(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum ReturnedProjection {
    Param { ir_index: usize },
    Path { ir_index: usize, steps: Vec<ProjectionStep> },
}

fn returned_projections(fg: &FlowGraph, func: &Function) -> Vec<ReturnedProjection> {
    let literal_index_keys = compute_literal_index_keys(func);
    let mut defs = HashMap::new();
    for block in &func.blocks {
        for inst in &block.insts {
            match &inst.kind {
                InstKind::ConstInt { dst, .. }
                | InstKind::ConstString { dst, .. }
                | InstKind::Copy { dst, .. }
                | InstKind::Phi { dst, .. }
                | InstKind::LoadField { dst, .. }
                | InstKind::LoadIndex { dst, .. } => {
                    defs.insert(*dst, &inst.kind);
                }
                InstKind::StoreField { .. } | InstKind::StoreIndex { .. } | InstKind::Call(_) => {}
            }
        }
    }
    let param_roots = func
        .params
        .iter()
        .copied()
        .enumerate()
        .map(|(idx, param)| {
            (
                idx,
                fg.value_alias_roots
                    .get(&(func.id, param))
                    .copied()
                    .unwrap_or(param),
            )
        })
        .collect::<Vec<_>>();

    fn append_step(proj: ReturnedProjection, step: ProjectionStep) -> ReturnedProjection {
        match proj {
            ReturnedProjection::Param { ir_index } => ReturnedProjection::Path {
                ir_index,
                steps: vec![step],
            },
            ReturnedProjection::Path { ir_index, mut steps } => {
                steps.push(step);
                ReturnedProjection::Path { ir_index, steps }
            }
        }
    }

    fn walk_projection(
        fg: &FlowGraph,
        func: &Function,
        value: ValueId,
        defs: &HashMap<ValueId, &InstKind>,
        param_roots: &[(usize, ValueId)],
        literal_index_keys: &HashMap<ValueId, String>,
        visiting: &mut HashSet<ValueId>,
    ) -> Vec<ReturnedProjection> {
        if !visiting.insert(value) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let root = fg
            .value_alias_roots
            .get(&(func.id, value))
            .copied()
            .unwrap_or(value);
        for (idx, param_root) in param_roots {
            if *param_root == root {
                out.push(ReturnedProjection::Param { ir_index: *idx });
            }
        }
        if let Some(kind) = defs.get(&value) {
            match *kind {
                InstKind::Copy { src, .. } => {
                    out.extend(walk_projection(
                        fg,
                        func,
                        *src,
                        defs,
                        param_roots,
                        literal_index_keys,
                        visiting,
                    ));
                }
                InstKind::Phi { inputs, .. } => {
                    for input in inputs {
                        out.extend(walk_projection(
                            fg,
                            func,
                            *input,
                            defs,
                            param_roots,
                            literal_index_keys,
                            visiting,
                        ));
                    }
                }
                InstKind::LoadField { base, field, .. } => {
                    for projection in walk_projection(
                        fg,
                        func,
                        *base,
                        defs,
                        param_roots,
                        literal_index_keys,
                        visiting,
                    ) {
                        out.push(append_step(projection, ProjectionStep::Field(field.clone())));
                    }
                }
                InstKind::LoadIndex { base, index, .. } => {
                    let key = abstract_index_key(literal_index_keys, *index);
                    for projection in walk_projection(
                        fg,
                        func,
                        *base,
                        defs,
                        param_roots,
                        literal_index_keys,
                        visiting,
                    ) {
                        out.push(append_step(projection, ProjectionStep::Index(key.clone())));
                    }
                }
                InstKind::ConstInt { .. }
                | InstKind::ConstString { .. }
                | InstKind::StoreField { .. }
                | InstKind::StoreIndex { .. }
                | InstKind::Call(_) => {}
            }
        }
        visiting.remove(&value);
        out.sort();
        out.dedup();
        out
    }

    let mut out = Vec::new();
    for block in &func.blocks {
        let Terminator::Return(Some(value)) = &block.term else {
            continue;
        };
        let mut visiting = HashSet::new();
        out.extend(walk_projection(
            fg,
            func,
            *value,
            &defs,
            &param_roots,
            &literal_index_keys,
            &mut visiting,
        ));
    }
    out.sort();
    out.dedup();
    out
}

fn ensure_field_cell(
    fg: &mut FlowGraph,
    func: FunctionId,
    value: ValueId,
    field: &str,
) -> NodeIndex {
    let root = canonical_heap_value(fg, func, value);
    if let Some(existing) = fg.field_cells.get(&(func, root, field.to_string())).copied() {
        return existing;
    }
    let node = fg.graph.add_node(FlowNode::FieldCell {
        func,
        block: BlockId(0),
        inst: InstId(0),
        base: root,
        field: field.to_string(),
    });
    fg.field_cells.insert((func, root, field.to_string()), node);
    let base_node = value_node(fg, func, value);
    fg.graph.add_edge(
        base_node,
        node,
        FlowEdge {
            kind: EdgeKind::LoadField {
                field: field.to_string(),
            },
        },
    );
    node
}

fn ensure_index_cell(
    fg: &mut FlowGraph,
    func: FunctionId,
    value: ValueId,
    key: &str,
) -> NodeIndex {
    let root = canonical_heap_value(fg, func, value);
    if let Some(existing) = fg.index_cells.get(&(func, root, key.to_string())).copied() {
        return existing;
    }
    let node = fg.graph.add_node(FlowNode::IndexCell {
        func,
        block: BlockId(0),
        inst: InstId(0),
        base: root,
        index: ValueId(u32::MAX),
        abstract_key: key.to_string(),
    });
    fg.index_cells.insert((func, root, key.to_string()), node);
    let base_node = value_node(fg, func, value);
    fg.graph.add_edge(base_node, node, FlowEdge { kind: EdgeKind::LoadIndex });
    node
}

fn index_cells_for_key(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
    key: &str,
) -> Vec<NodeIndex> {
    let root = canonical_heap_value(fg, func, value);
    let mut out = Vec::new();
    if key == "*" {
        for ((cell_func, cell_root, _), node) in &fg.index_cells {
            if *cell_func == func && *cell_root == root && !out.contains(node) {
                out.push(*node);
            }
        }
        return out;
    }
    if let Some(node) = fg.index_cells.get(&(func, root, key.to_string())).copied() {
        out.push(node);
        return out;
    }
    if let Some(node) = fg.index_cells.get(&(func, root, "*".to_string())).copied() {
        out.push(node);
    }
    out
}

fn index_keys_for_value(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let root = canonical_heap_value(fg, func, value);
    let mut out = Vec::new();
    for (cell_func, cell_root, key) in fg.index_cells.keys() {
        if *cell_func == func && *cell_root == root && !out.contains(key) {
            out.push(key.clone());
        }
    }
    out
}

fn next_precise_numeric_index_key(fg: &FlowGraph, func: FunctionId, value: ValueId) -> String {
    let mut next = 0usize;
    for key in index_keys_for_value(fg, func, value) {
        if let Ok(parsed) = key.parse::<usize>() {
            next = next.max(parsed.saturating_add(1));
        }
    }
    next.to_string()
}

fn last_precise_numeric_index_key(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Option<String> {
    let mut best: Option<usize> = None;
    for key in index_keys_for_value(fg, func, value) {
        if let Ok(parsed) = key.parse::<usize>() {
            best = Some(best.map(|current| current.max(parsed)).unwrap_or(parsed));
        }
    }
    best.map(|value| value.to_string())
}

fn connect_container_value_copy(
    fg: &mut FlowGraph,
    func: FunctionId,
    src: ValueId,
    dst: ValueId,
) {
    let keys = index_keys_for_value(fg, func, src);
    if keys.is_empty() {
        let src_node = value_node(fg, func, src);
        let wildcard = ensure_index_cell(fg, func, dst, "*");
        fg.graph.add_edge(src_node, wildcard, FlowEdge { kind: EdgeKind::StoreIndex });
        return;
    }
    for key in keys {
        let dst_cell = ensure_index_cell(fg, func, dst, &key);
        for src_cell in index_cells_for_key(fg, func, src, &key) {
            fg.graph.add_edge(src_cell, dst_cell, FlowEdge { kind: EdgeKind::StoreIndex });
        }
    }
}

fn connect_builtin_python_container_semantics(
    fg: &mut FlowGraph,
    func: FunctionId,
    call: &CallInst,
    meta: &CallMeta,
    literal_index_keys: &HashMap<ValueId, String>,
) {
    let Some(dst) = call.dst else {
        return;
    };
    let Some(callee_name) = meta.callee_name.as_deref() else {
        return;
    };

    match callee_name {
        "builtins.list" | "builtins.tuple" => {
            if call.args.len() == 1 {
                connect_container_value_copy(fg, func, call.args[0], dst);
                return;
            }
            for (idx, arg) in call.args.iter().copied().enumerate() {
                let key = idx.to_string();
                let cell = ensure_index_cell(fg, func, dst, &key);
                let src_node = value_node(fg, func, arg);
                fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
                let wildcard = ensure_index_cell(fg, func, dst, "*");
                fg.graph.add_edge(src_node, wildcard, FlowEdge { kind: EdgeKind::StoreIndex });
            }
        }
        "builtins.dict" => {
            if call.args.len() == 1 {
                connect_container_value_copy(fg, func, call.args[0], dst);
                return;
            }
            for pair in call.args.chunks(2) {
                let Some(key_value) = pair.get(0).copied() else {
                    continue;
                };
                let Some(src) = pair.get(1).copied() else {
                    continue;
                };
                let key = abstract_index_key(literal_index_keys, key_value);
                let cell = ensure_index_cell(fg, func, dst, &key);
                let src_node = value_node(fg, func, src);
                fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
                let wildcard = ensure_index_cell(fg, func, dst, "*");
                fg.graph.add_edge(src_node, wildcard, FlowEdge { kind: EdgeKind::StoreIndex });
            }
        }
        "builtins.set" => {
            if call.args.len() == 1 {
                connect_container_value_copy(fg, func, call.args[0], dst);
                return;
            }
            for (idx, arg) in call.args.iter().copied().enumerate() {
                let src_node = value_node(fg, func, arg);
                let wildcard = ensure_index_cell(fg, func, dst, "*");
                fg.graph.add_edge(src_node, wildcard, FlowEdge { kind: EdgeKind::StoreIndex });
                let key = idx.to_string();
                let cell = ensure_index_cell(fg, func, dst, &key);
                fg.graph.add_edge(src_node, cell, FlowEdge { kind: EdgeKind::StoreIndex });
            }
        }
        _ => {}
    }
}

fn connect_bidirectional_value_pair(
    fg: &mut FlowGraph,
    left_func: FunctionId,
    left_value: ValueId,
    right_func: FunctionId,
    right_value: ValueId,
) {
    let left = value_node(fg, left_func, left_value);
    let right = value_node(fg, right_func, right_value);
    fg.graph.add_edge(left, right, FlowEdge { kind: EdgeKind::ActualToFormal });
    fg.graph.add_edge(right, left, FlowEdge { kind: EdgeKind::FormalToActual });
}

fn direct_cell_projected_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Outgoing) {
        match (&edge.weight().kind, &fg.graph[edge.target()]) {
            (EdgeKind::LoadField { .. } | EdgeKind::LoadIndex, FlowNode::Value { func, value }) => {
                if seen.insert((*func, *value)) {
                    out.push((*func, *value));
                }
            }
            _ => {}
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        match (&edge.weight().kind, &fg.graph[edge.source()]) {
            (EdgeKind::StoreField { .. } | EdgeKind::StoreIndex, FlowNode::Value { func, value }) => {
                if seen.insert((*func, *value)) {
                    out.push((*func, *value));
                }
            }
            _ => {}
        }
    }
    out
}

fn collect_transitive_cell_projected_values(
    fg: &FlowGraph,
    cell: NodeIndex,
    visited_cells: &mut HashSet<NodeIndex>,
    seen_values: &mut HashSet<(FunctionId, ValueId)>,
    out: &mut Vec<(FunctionId, ValueId)>,
) {
    if !visited_cells.insert(cell) {
        return;
    }
    for projected in direct_cell_projected_values(fg, cell) {
        if seen_values.insert(projected) {
            out.push(projected);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Outgoing) {
        if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) {
            continue;
        }
        if matches!(fg.graph[edge.target()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
            collect_transitive_cell_projected_values(fg, edge.target(), visited_cells, seen_values, out);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) {
            continue;
        }
        if matches!(fg.graph[edge.source()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
            collect_transitive_cell_projected_values(fg, edge.source(), visited_cells, seen_values, out);
        }
    }
}

fn all_cell_nodes(fg: &FlowGraph) -> Vec<NodeIndex> {
    let mut cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    cells.extend(fg.index_cells.values().copied());
    cells.sort_unstable_by_key(|node| node.index());
    cells.dedup_by_key(|node| node.index());
    cells
}

fn alias_equivalent_cells(fg: &FlowGraph, cell: NodeIndex) -> Vec<NodeIndex> {
    let mut out = Vec::new();
    let cell_regions = fg.cell_memory_regions_of(cell);
    for candidate in all_cell_nodes(fg) {
        let candidate_regions = fg.cell_memory_regions_of(candidate);
        if candidate == cell
            || fg.cell_may_alias(cell, candidate)
            || (!cell_regions.is_empty() && !candidate_regions.is_empty() && memory_regions_overlap(&cell_regions, &candidate_regions))
        {
            out.push(candidate);
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn cell_projected_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut visited_cells = HashSet::new();
    let mut seen_values = HashSet::new();
    collect_transitive_cell_projected_values(fg, cell, &mut visited_cells, &mut seen_values, &mut out);
    out
}

fn cell_abstract_identity_key(fg: &FlowGraph, cell: NodeIndex) -> Option<String> {
    match &fg.graph[cell] {
        FlowNode::FieldCell { func, base, field, .. } => {
            let site = value_identity_site(fg, *func, *base)?.trim().to_string();
            Some(format!("field:{}:{}", site, field))
        }
        FlowNode::IndexCell { func, base, abstract_key, .. } if abstract_key != "*" => {
            let site = value_identity_site(fg, *func, *base)?.trim().to_string();
            Some(format!("index:{}:{}", site, abstract_key))
        }
        _ => None,
    }
}

fn cell_allows_strong_update(fg: &FlowGraph, cell: NodeIndex) -> bool {
    let Some(memory_unit) = precise_memory_unit_key_for_cell(fg, cell) else {
        return false;
    };
    let alias_cells = alias_equivalent_cells(fg, cell);
    let must_alias_cells = alias_cells
        .iter()
        .copied()
        .filter(|candidate| fg.cell_must_alias(cell, *candidate))
        .collect::<Vec<_>>();
    if must_alias_cells.len() != 1 || must_alias_cells[0] != cell {
        return false;
    }
    if alias_cells
        .iter()
        .copied()
        .any(|candidate| candidate != cell && fg.cell_may_alias(cell, candidate))
    {
        return false;
    }
    let Some(memory_unit_object_id) = fg.points_to_object_ids.get(&format!("memunit:{}", memory_unit)).copied() else {
        return false;
    };
    let cell_object_ids = fg.cell_points_to_object_ids_of(cell);
    cell_object_ids.is_empty() || cell_object_ids.iter().any(|id| *id == memory_unit_object_id)
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct DetailedStoreRecord {
    edge_idx: usize,
    origin_cell: usize,
    func: FunctionId,
    value: ValueId,
}

fn direct_cell_store_records(fg: &FlowGraph, cell: NodeIndex) -> Vec<DetailedStoreRecord> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        match (&edge.weight().kind, &fg.graph[edge.source()]) {
            (EdgeKind::StoreField { .. } | EdgeKind::StoreIndex, FlowNode::Value { func, value }) => {
                let key = DetailedStoreRecord { edge_idx: edge.id().index(), origin_cell: cell.index(), func: *func, value: *value };
                if seen.insert(key) {
                    out.push(key);
                }
            }
            (EdgeKind::Summary { rule_id }, FlowNode::Value { func, value })
                if rule_id.contains("heap-write")
                    || rule_id.contains("return-value-region")
                    || rule_id.contains("return-region-value") =>
            {
                let key = DetailedStoreRecord { edge_idx: edge.id().index(), origin_cell: cell.index(), func: *func, value: *value };
                if seen.insert(key) {
                    out.push(key);
                }
            }
            _ => {}
        }
    }
    out.sort_unstable_by_key(|record| record.edge_idx);
    out
}

fn collect_transitive_cell_store_records(
    fg: &FlowGraph,
    cell: NodeIndex,
    visited_cells: &mut HashSet<NodeIndex>,
    seen_records: &mut HashSet<DetailedStoreRecord>,
    out: &mut Vec<DetailedStoreRecord>,
) {
    if !visited_cells.insert(cell) {
        return;
    }
    for record in direct_cell_store_records(fg, cell) {
        if seen_records.insert(record) {
            out.push(record);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Outgoing) {
        if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) {
            continue;
        }
        if matches!(fg.graph[edge.target()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
            collect_transitive_cell_store_records(fg, edge.target(), visited_cells, seen_records, out);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) {
            continue;
        }
        if matches!(fg.graph[edge.source()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
            collect_transitive_cell_store_records(fg, edge.source(), visited_cells, seen_records, out);
        }
    }
}

fn transitive_cell_store_records(fg: &FlowGraph, cell: NodeIndex) -> Vec<DetailedStoreRecord> {
    let mut out = Vec::new();
    let mut visited_cells = HashSet::new();
    let mut seen_records = HashSet::new();
    collect_transitive_cell_store_records(fg, cell, &mut visited_cells, &mut seen_records, &mut out);
    out.sort_unstable_by_key(|record| record.edge_idx);
    out.dedup();
    out
}

fn store_record_partition_keys(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
) -> Vec<String> {
    let mut keys = fg.value_memory_regions_of(func, value);
    keys.extend(fg.value_points_to_classes_of(func, value));
    keys.extend(fg.value_points_to_targets_of(func, value));
    keys.extend(fg.value_points_to_object_ids_of(func, value).into_iter().map(|id| format!("object:{id}")));
    if keys.is_empty() {
        if let Some(site) = value_identity_site(fg, func, value) {
            keys.push(format!("site:{}", site.trim()));
        }
    }
    if keys.is_empty() {
        if let Some(ty) = fg.value_types.get(&(func, value)) {
            let trimmed = ty.trim();
            if !trimmed.is_empty() {
                keys.push(normalized_type_point_class(trimmed));
            }
        }
    }
    if keys.is_empty() {
        keys.push(format!("value:{}:{}", func.0, value.0));
    }
    keys.sort();
    keys.dedup();
    keys
}

fn store_record_target_partition_keys(
    fg: &FlowGraph,
    record: &DetailedStoreRecord,
) -> Vec<String> {
    let origin_cell = NodeIndex::new(record.origin_cell);
    let mut keys = fg.cell_memory_regions_of(origin_cell);
    keys.extend(fg.cell_points_to_targets_of(origin_cell));
    keys.extend(
        fg.cell_points_to_object_ids_of(origin_cell)
            .into_iter()
            .map(|id| format!("cell-object:{id}")),
    );
    if let Some(id) = precise_cell_object_id(fg, origin_cell) {
        keys.push(format!("precise-cell-object:{id}"));
    }
    if let Some(unit) = precise_memory_unit_key_for_cell(fg, origin_cell) {
        keys.push(format!("memory-unit:{unit}"));
    }
    if keys.is_empty() {
        keys.push(format!("origin-cell:{}", record.origin_cell));
    }
    keys.sort();
    keys.dedup();
    keys
}

fn visible_direct_cell_store_records_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(usize, FunctionId, ValueId)> {
    let mut records = alias_equivalent_cells(fg, cell)
        .into_iter()
        .flat_map(|candidate| transitive_cell_store_records(fg, candidate))
        .collect::<Vec<_>>();
    if let Some(cutoff) = cutoff_edge_idx {
        records.retain(|record| record.edge_idx < cutoff);
    }
    if records.is_empty() {
        return Vec::new();
    }
    records.sort_unstable_by_key(|record| record.edge_idx);
    records.dedup();

    let mut visible = Vec::<DetailedStoreRecord>::new();
    for record in records {
        let origin_cell = NodeIndex::new(record.origin_cell);
        if cell_allows_strong_update(fg, origin_cell) {
            visible.retain(|existing| {
                let existing_cell = NodeIndex::new(existing.origin_cell);
                !fg.cell_must_alias(origin_cell, existing_cell)
            });
        }
        visible.push(record);
    }

    if cell_allows_strong_update(fg, cell) {
        let mut latest: Option<DetailedStoreRecord> = None;
        for record in visible {
            let origin_cell = NodeIndex::new(record.origin_cell);
            if fg.cell_must_alias(cell, origin_cell) {
                let replace = latest
                    .as_ref()
                    .map(|existing| record.edge_idx >= existing.edge_idx)
                    .unwrap_or(true);
                if replace {
                    latest = Some(record);
                }
            }
        }
        return latest
            .into_iter()
            .map(|record| (record.edge_idx, record.func, record.value))
            .collect();
    }

    let mut latest_by_partition = HashMap::<String, DetailedStoreRecord>::new();
    for record in visible {
        let mut partition_keys = store_record_partition_keys(fg, record.func, record.value);
        partition_keys.extend(store_record_target_partition_keys(fg, &record));
        partition_keys.sort();
        partition_keys.dedup();
        for key in partition_keys {
            let replace = latest_by_partition
                .get(&key)
                .map(|existing| record.edge_idx >= existing.edge_idx)
                .unwrap_or(true);
            if replace {
                latest_by_partition.insert(key, record);
            }
        }
    }
    let mut out = latest_by_partition
        .into_values()
        .map(|record| (record.edge_idx, record.func, record.value))
        .collect::<Vec<_>>();
    out.sort_unstable_by_key(|(edge_idx, _, _)| *edge_idx);
    out.dedup();
    out
}

fn direct_cell_store_values_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (_edge_idx, func, value) in visible_direct_cell_store_records_before_edge(fg, cell, cutoff_edge_idx) {
        if seen.insert((func, value)) {
            out.push((func, value));
        }
    }
    out
}

fn direct_cell_store_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let live = fg.cell_live_values_of(cell);
    if !live.is_empty() {
        return live;
    }
    direct_cell_store_values_before_edge(fg, cell, None)
}

fn region_candidate_cells(fg: &FlowGraph, region: &str) -> Vec<NodeIndex> {
    let mut out = fg.region_live_cells_of(region);
    if out.is_empty() {
        for (candidate_region, cells) in &fg.region_live_cells {
            if !memory_region_related(candidate_region, region) {
                continue;
            }
            out.extend(cells.iter().copied().map(NodeIndex::new));
        }
    }
    if out.is_empty() {
        for cell in all_cell_nodes(fg) {
            if fg
                .cell_memory_regions_of(cell)
                .iter()
                .any(|candidate| memory_region_related(candidate, region))
            {
                out.push(cell);
            }
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}


fn suffix_to_access_path(suffix: &str) -> Option<String> {
    let trimmed = suffix.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut idx = 0usize;
    let mut labels = Vec::new();
    while idx < bytes.len() {
        match bytes[idx] {
            b'.' => {
                idx += 1;
                let start = idx;
                while idx < bytes.len() && bytes[idx] != b'.' && bytes[idx] != b'[' {
                    idx += 1;
                }
                let field = trimmed[start..idx].trim();
                if !field.is_empty() {
                    labels.push(format!("field:{}", field));
                }
            }
            b'[' => {
                idx += 1;
                let start = idx;
                while idx < bytes.len() && bytes[idx] != b']' {
                    idx += 1;
                }
                let key = trimmed[start..idx].trim();
                if !key.is_empty() {
                    labels.push(format!("index:{}", key));
                }
                if idx < bytes.len() && bytes[idx] == b']' {
                    idx += 1;
                }
            }
            _ => idx += 1,
        }
    }
    (!labels.is_empty()).then_some(labels.join("."))
}

fn region_relative_access_paths(base_regions: &[String], region: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for base in base_regions {
        if !memory_region_has_boundary_prefix(region, base) {
            continue;
        }
        let suffix = &region[base.len()..];
        if let Some(path) = suffix_to_access_path(suffix) {
            out.insert(path);
        }
    }
    out.into_iter().collect()
}

fn value_root_memory_regions(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<String> {
    let mut roots = memory_region_seed_for_value(fg, func, value);
    roots.sort();
    roots.dedup();
    roots
}

fn parse_access_path(path: &str) -> Vec<(String, String)> {
    path.split('.')
        .filter_map(|segment| {
            let trimmed = segment.trim();
            if let Some(field) = trimmed.strip_prefix("field:") {
                return Some(("field".to_string(), field.trim().to_string()));
            }
            if let Some(index) = trimmed.strip_prefix("index:") {
                return Some(("index".to_string(), index.trim().to_string()));
            }
            None
        })
        .filter(|(_, label)| !label.is_empty())
        .collect()
}

fn candidate_cells_for_relative_path_from_value(
    fg: &mut FlowGraph,
    func: FunctionId,
    value: ValueId,
    path: &str,
) -> Vec<NodeIndex> {
    let segments = parse_access_path(path);
    if segments.is_empty() {
        return Vec::new();
    }
    let mut bases = vec![(func, value)];
    let mut current_cells = Vec::new();
    for (kind, label) in segments {
        current_cells.clear();
        let mut next_bases = Vec::new();
        for (base_func, base_value) in &bases {
            let cell = if kind == "field" {
                ensure_field_cell(fg, *base_func, *base_value, &label)
            } else {
                ensure_index_cell(fg, *base_func, *base_value, &label)
            };
            current_cells.push(cell);
            next_bases.extend(cell_projected_values(fg, cell));
        }
        current_cells.sort_unstable_by_key(|node| node.index());
        current_cells.dedup_by_key(|node| node.index());
        next_bases.sort_unstable();
        next_bases.dedup();
        if next_bases.is_empty() {
            break;
        }
        bases = next_bases;
    }
    current_cells.sort_unstable_by_key(|node| node.index());
    current_cells.dedup_by_key(|node| node.index());
    current_cells
}

fn relative_path_candidate_cells_for_port(
    fg: &mut FlowGraph,
    port_node: NodeIndex,
    path: &str,
) -> Vec<NodeIndex> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let sources = fg.call_port_source_values(port_node);
    for (func, value) in sources {
        for cell in candidate_cells_for_relative_path_from_value(fg, func, value, path) {
            if seen.insert(cell) {
                out.push(cell);
            }
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn collect_transitive_cell_store_values(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
    visited_cells: &mut HashSet<NodeIndex>,
    seen_values: &mut HashSet<(FunctionId, ValueId)>,
    out: &mut Vec<(FunctionId, ValueId)>,
) {
    if !visited_cells.insert(cell) {
        return;
    }
    for projected in direct_cell_store_values_before_edge(fg, cell, cutoff_edge_idx) {
        if seen_values.insert(projected) {
            out.push(projected);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Outgoing) {
        if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) {
            continue;
        }
        if matches!(fg.graph[edge.target()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
            collect_transitive_cell_store_values(fg, edge.target(), cutoff_edge_idx, visited_cells, seen_values, out);
        }
    }
    for edge in fg.graph.edges_directed(cell, petgraph::Direction::Incoming) {
        if !matches!(edge.weight().kind, EdgeKind::ActualToFormal | EdgeKind::FormalToActual) {
            continue;
        }
        if matches!(fg.graph[edge.source()], FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. }) {
            collect_transitive_cell_store_values(fg, edge.source(), cutoff_edge_idx, visited_cells, seen_values, out);
        }
    }
}

fn cell_store_values_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(FunctionId, ValueId)> {
    let mut out = Vec::new();
    let mut visited_cells = HashSet::new();
    let mut seen_values = HashSet::new();
    collect_transitive_cell_store_values(fg, cell, cutoff_edge_idx, &mut visited_cells, &mut seen_values, &mut out);
    out
}

fn cell_store_values(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    cell_store_values_before_edge(fg, cell, None)
}

fn cell_values_for_flow_before_edge(
    fg: &FlowGraph,
    cell: NodeIndex,
    cutoff_edge_idx: Option<usize>,
) -> Vec<(FunctionId, ValueId)> {
    let stored = cell_store_values_before_edge(fg, cell, cutoff_edge_idx);
    if stored.is_empty() {
        cell_projected_values(fg, cell)
    } else {
        stored
    }
}

fn cell_values_for_flow(fg: &FlowGraph, cell: NodeIndex) -> Vec<(FunctionId, ValueId)> {
    let live = fg.cell_live_values_of(cell);
    if !live.is_empty() {
        return live;
    }
    cell_values_for_flow_before_edge(fg, cell, None)
}

fn bridge_nested_heap_values(
    fg: &mut FlowGraph,
    left_func: FunctionId,
    left_value: ValueId,
    right_func: FunctionId,
    right_value: ValueId,
    visited: &mut HashSet<(u32, u32, u32, u32)>,
) {
    let key = (left_func.0, left_value.0, right_func.0, right_value.0);
    if !visited.insert(key) {
        return;
    }

    let left_root = canonical_heap_value(fg, left_func, left_value);
    let right_root = canonical_heap_value(fg, right_func, right_value);

    let mut field_names = HashSet::new();
    for (func, base, field) in fg.field_cells.keys() {
        if (*func == left_func && *base == left_root) || (*func == right_func && *base == right_root) {
            field_names.insert(field.clone());
        }
    }

    for field in field_names {
        let left_cell = ensure_field_cell(fg, left_func, left_value, &field);
        let right_cell = ensure_field_cell(fg, right_func, right_value, &field);
        fg.graph.add_edge(left_cell, right_cell, FlowEdge { kind: EdgeKind::ActualToFormal });
        fg.graph.add_edge(right_cell, left_cell, FlowEdge { kind: EdgeKind::FormalToActual });
        let left_projected = cell_values_for_flow(fg, left_cell);
        let right_projected = cell_values_for_flow(fg, right_cell);
        for (lf, lv) in &left_projected {
            for (rf, rv) in &right_projected {
                if !heap_projection_values_compatible(fg, *lf, *lv, *rf, *rv) {
                    continue;
                }
                connect_bidirectional_value_pair(fg, *lf, *lv, *rf, *rv);
                bridge_nested_heap_values(fg, *lf, *lv, *rf, *rv, visited);
            }
        }
    }

    let mut index_keys = index_keys_for_value(fg, left_func, left_value);
    for key in index_keys_for_value(fg, right_func, right_value) {
        if !index_keys.contains(&key) {
            index_keys.push(key);
        }
    }
    if !index_keys.iter().any(|key| key == "*") {
        index_keys.push("*".to_string());
    }

    for key in index_keys {
        let mut left_cells = index_cells_for_key(fg, left_func, left_value, &key);
        if left_cells.is_empty() {
            left_cells.push(ensure_index_cell(fg, left_func, left_value, &key));
        }
        let mut right_cells = index_cells_for_key(fg, right_func, right_value, &key);
        if right_cells.is_empty() {
            right_cells.push(ensure_index_cell(fg, right_func, right_value, &key));
        }
        for left_cell in &left_cells {
            for right_cell in &right_cells {
                fg.graph.add_edge(*left_cell, *right_cell, FlowEdge { kind: EdgeKind::ActualToFormal });
                fg.graph.add_edge(*right_cell, *left_cell, FlowEdge { kind: EdgeKind::FormalToActual });
                let left_projected = cell_values_for_flow(fg, *left_cell);
                let right_projected = cell_values_for_flow(fg, *right_cell);
                for (lf, lv) in &left_projected {
                    for (rf, rv) in &right_projected {
                        if !heap_projection_values_compatible(fg, *lf, *lv, *rf, *rv) {
                            continue;
                        }
                        connect_bidirectional_value_pair(fg, *lf, *lv, *rf, *rv);
                        bridge_nested_heap_values(fg, *lf, *lv, *rf, *rv, visited);
                    }
                }
            }
        }
    }
}

fn connect_returned_path_projection(
    fg: &mut FlowGraph,
    caller_func: FunctionId,
    actual_value: ValueId,
    steps: &[ProjectionStep],
    dst: ValueId,
) {
    if steps.is_empty() {
        let actual_node = value_node(fg, caller_func, actual_value);
        let dst_node = value_node(fg, caller_func, dst);
        fg.graph.add_edge(actual_node, dst_node, FlowEdge { kind: EdgeKind::Assign });
        propagate_object_identity_site(fg, caller_func, actual_value, caller_func, dst);
        let mut visited = HashSet::new();
        bridge_nested_heap_values(fg, caller_func, actual_value, caller_func, dst, &mut visited);
        return;
    }

    let mut frontier = vec![(caller_func, actual_value)];
    for (step_idx, step) in steps.iter().enumerate() {
        let is_last = step_idx + 1 == steps.len();
        let mut next_frontier = Vec::new();
        let mut seen_values = HashSet::new();
        let mut seen_cells = HashSet::new();
        for (func, value) in &frontier {
            match step {
                ProjectionStep::Field(field) => {
                    let cell = ensure_field_cell(fg, *func, *value, field);
                    if !seen_cells.insert(cell) {
                        continue;
                    }
                    if is_last {
                        let dst_node = value_node(fg, caller_func, dst);
                        fg.graph.add_edge(
                            cell,
                            dst_node,
                            FlowEdge {
                                kind: EdgeKind::LoadField {
                                    field: field.clone(),
                                },
                            },
                        );
                    }
                    for projected in cell_values_for_flow(fg, cell) {
                        if seen_values.insert(projected) {
                            if is_last {
                                let mut visited = HashSet::new();
                                connect_bidirectional_value_pair(fg, projected.0, projected.1, caller_func, dst);
                                propagate_object_identity_site(fg, projected.0, projected.1, caller_func, dst);
                                bridge_nested_heap_values(fg, projected.0, projected.1, caller_func, dst, &mut visited);
                            } else {
                                next_frontier.push(projected);
                            }
                        }
                    }
                }
                ProjectionStep::Index(key) => {
                    let mut cells = index_cells_for_key(fg, *func, *value, key);
                    if cells.is_empty() {
                        cells.push(ensure_index_cell(fg, *func, *value, key));
                    }
                    for cell in cells {
                        if !seen_cells.insert(cell) {
                            continue;
                        }
                        if is_last {
                            let dst_node = value_node(fg, caller_func, dst);
                            fg.graph.add_edge(cell, dst_node, FlowEdge { kind: EdgeKind::LoadIndex });
                        }
                        for projected in cell_values_for_flow(fg, cell) {
                            if seen_values.insert(projected) {
                                if is_last {
                                    let mut visited = HashSet::new();
                                    connect_bidirectional_value_pair(fg, projected.0, projected.1, caller_func, dst);
                                    bridge_nested_heap_values(fg, projected.0, projected.1, caller_func, dst, &mut visited);
                                } else {
                                    next_frontier.push(projected);
                                }
                            }
                        }
                    }
                }
            }
        }
        if is_last {
            break;
        }
        frontier = next_frontier;
        if frontier.is_empty() {
            break;
        }
    }
}

fn bridge_internal_heap_cells(fg: &mut FlowGraph, program: &Program) {
    for caller_func in &program.functions {
        for block in &caller_func.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else {
                    continue;
                };
                let Some(targets) = fg.resolved_internal_targets.get(&(caller_func.id, inst.id)).cloned() else {
                    continue;
                };
                for target_name in targets {
                    let Some(callee_func) = program.find_function_by_name(&target_name) else {
                        continue;
                    };
                    let bindings = compute_actual_formal_bindings(call, callee_func);
                    let mut visited = HashSet::new();
                    for (_, actual_value, ir_index) in &bindings {
                        let Some(formal_value) = callee_func.params.get(*ir_index).copied() else {
                            continue;
                        };
                        bridge_nested_heap_values(fg, caller_func.id, *actual_value, callee_func.id, formal_value, &mut visited);
                    }
                    if let Some(dst) = call.dst {
                        for projection in returned_projections(fg, callee_func) {
                            match projection {
                                ReturnedProjection::Param { ir_index } => {
                                    let Some((_, actual_value, _)) = bindings.iter().find(|(_, _, idx)| *idx == ir_index) else {
                                        continue;
                                    };
                                    connect_returned_path_projection(fg, caller_func.id, *actual_value, &[], dst);
                                }
                                ReturnedProjection::Path { ir_index, steps } => {
                                    let Some((_, actual_value, _)) = bindings.iter().find(|(_, _, idx)| *idx == ir_index) else {
                                        continue;
                                    };
                                    connect_returned_path_projection(fg, caller_func.id, *actual_value, &steps, dst);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_sparse_data_edge(kind: &EdgeKind) -> bool {
    matches!(
        kind,
        EdgeKind::Assign
            | EdgeKind::Phi
            | EdgeKind::LoadField { .. }
            | EdgeKind::StoreField { .. }
            | EdgeKind::LoadIndex
            | EdgeKind::StoreIndex
            | EdgeKind::ValueToCallPort
            | EdgeKind::CallPortToValue
            | EdgeKind::ActualToFormal
            | EdgeKind::FormalToActual
            | EdgeKind::Summary { .. }
            | EdgeKind::Source { .. }
    )
}

fn push_unique_index(map: &mut HashMap<usize, Vec<usize>>, src: usize, dst: usize) {
    let values = map.entry(src).or_default();
    if !values.contains(&dst) {
        values.push(dst);
    }
}

fn push_unique_labeled_index(
    map: &mut HashMap<usize, Vec<usize>>,
    labels: &mut HashMap<(usize, usize), String>,
    src: usize,
    dst: usize,
    label: String,
) {
    push_unique_index(map, src, dst);
    labels.entry((src, dst)).or_insert(label);
}

fn materialize_heap_value_adjacency(fg: &mut FlowGraph) {
    fg.heap_value_successors.clear();
    fg.heap_value_predecessors.clear();
    for (&(func, base, _), &cell) in &fg.field_cells {
        let Some(&base_node) = fg.values.get(&(func, base)) else {
            continue;
        };
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(&mut fg.heap_value_successors, base_node.index(), proj_node.index());
            push_unique_index(&mut fg.heap_value_predecessors, proj_node.index(), base_node.index());
        }
    }
    for (&(func, base, _), &cell) in &fg.index_cells {
        let Some(&base_node) = fg.values.get(&(func, base)) else {
            continue;
        };
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(&mut fg.heap_value_successors, base_node.index(), proj_node.index());
            push_unique_index(&mut fg.heap_value_predecessors, proj_node.index(), base_node.index());
        }
    }
    for values in fg.heap_value_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.heap_value_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn materialize_heap_object_adjacency(fg: &mut FlowGraph) {
    fg.heap_object_successors.clear();
    fg.heap_object_predecessors.clear();
    let mut all_cells = fg
        .field_cells
        .iter()
        .map(|(&(func, base, _), &cell)| (func, base, cell))
        .collect::<Vec<_>>();
    all_cells.extend(
        fg.index_cells
            .iter()
            .map(|(&(func, base, _), &cell)| (func, base, cell)),
    );
    for (func, base, cell) in all_cells {
        let Some(&base_node) = fg.values.get(&(func, base)) else {
            continue;
        };
        push_unique_index(&mut fg.heap_object_successors, base_node.index(), cell.index());
        push_unique_index(&mut fg.heap_object_predecessors, cell.index(), base_node.index());
        let projected = cell_values_for_flow(fg, cell);
        for (proj_func, proj_value) in projected {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_index(&mut fg.heap_object_successors, cell.index(), proj_node.index());
            push_unique_index(&mut fg.heap_object_predecessors, proj_node.index(), cell.index());
        }
    }
    for values in fg.heap_object_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.heap_object_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn materialize_object_graph_adjacency(fg: &mut FlowGraph) {
    fg.object_graph_successors.clear();
    fg.object_graph_predecessors.clear();
    fg.object_graph_labels.clear();
    fg.object_shape_labels.clear();

    for ((func, base, field), &cell) in &fg.field_cells {
        let Some(&base_node) = fg.values.get(&(*func, *base)) else {
            continue;
        };
        let label = format!("field:{}", field);
        fg.object_shape_labels.entry(base_node.index()).or_default().push(label.clone());
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_labeled_index(
                &mut fg.object_graph_successors,
                &mut fg.object_graph_labels,
                base_node.index(),
                proj_node.index(),
                label.clone(),
            );
            push_unique_labeled_index(
                &mut fg.object_graph_predecessors,
                &mut fg.object_graph_labels,
                proj_node.index(),
                base_node.index(),
                label.clone(),
            );
        }
    }

    for ((func, base, key), &cell) in &fg.index_cells {
        let Some(&base_node) = fg.values.get(&(*func, *base)) else {
            continue;
        };
        let label = format!("index:{}", key);
        fg.object_shape_labels.entry(base_node.index()).or_default().push(label.clone());
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            let Some(&proj_node) = fg.values.get(&(proj_func, proj_value)) else {
                continue;
            };
            push_unique_labeled_index(
                &mut fg.object_graph_successors,
                &mut fg.object_graph_labels,
                base_node.index(),
                proj_node.index(),
                label.clone(),
            );
            push_unique_labeled_index(
                &mut fg.object_graph_predecessors,
                &mut fg.object_graph_labels,
                proj_node.index(),
                base_node.index(),
                label.clone(),
            );
        }
    }

    for values in fg.object_graph_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.object_graph_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.object_shape_labels.values_mut() {
        values.sort();
        values.dedup();
    }
}

fn collect_object_shape_paths(
    fg: &FlowGraph,
    node: NodeIndex,
    prefix: String,
    depth: usize,
    seen_edges: &mut HashSet<(usize, usize)>,
    out: &mut BTreeSet<String>,
) {
    if depth == 0 {
        return;
    }
    for succ in fg.object_graph_successors_of(node) {
        let Some(label) = fg.object_graph_edge_label(node, succ) else {
            continue;
        };
        if !seen_edges.insert((node.index(), succ.index())) {
            continue;
        }
        let next = if prefix.is_empty() {
            label.to_string()
        } else {
            format!("{}.{}", prefix, label)
        };
        out.insert(next.clone());
        collect_object_shape_paths(fg, succ, next, depth.saturating_sub(1), seen_edges, out);
        seen_edges.remove(&(node.index(), succ.index()));
    }
}

fn materialize_object_shape_paths(fg: &mut FlowGraph) {
    fg.object_shape_paths.clear();
    let value_nodes = fg.values.values().copied().collect::<Vec<_>>();
    for node in value_nodes {
        let mut out = BTreeSet::new();
        let mut seen_edges = HashSet::new();
        collect_object_shape_paths(fg, node, String::new(), 4, &mut seen_edges, &mut out);
        if !out.is_empty() {
            fg.object_shape_paths.insert(node.index(), out.into_iter().collect());
        }
    }
}

fn shape_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    let mut out = fg.object_graph_successors_of(node);
    out.extend(fg.object_graph_predecessors_of(node));
    out.extend(fg.heap_object_successors_of(node));
    out.extend(fg.heap_object_predecessors_of(node));
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Forward));
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Backward));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_object_shape_fixpoint(fg: &mut FlowGraph) {
    let mut propagated = HashMap::<usize, BTreeSet<String>>::new();
    for (&node_idx, labels) in &fg.object_shape_paths {
        propagated
            .entry(node_idx)
            .or_default()
            .extend(labels.iter().cloned());
    }
    let mut changed = true;
    let mut iterations = 0usize;
    while changed {
        changed = false;
        iterations += 1;
        let nodes = fg.graph.node_indices().collect::<Vec<_>>();
        for node in nodes {
            let mut merged = propagated.get(&node.index()).cloned().unwrap_or_default();
            for neighbor in shape_propagation_neighbors(fg, node) {
                if let Some(values) = propagated.get(&neighbor.index()) {
                    let before = merged.len();
                    merged.extend(values.iter().cloned());
                    if merged.len() > before {
                        changed = true;
                    }
                }
            }
            if !merged.is_empty() {
                let replace = propagated
                    .get(&node.index())
                    .map(|prev| prev != &merged)
                    .unwrap_or(true);
                if replace {
                    propagated.insert(node.index(), merged);
                    changed = true;
                }
            }
        }
    }
    fg.object_shape_paths = propagated
        .into_iter()
        .map(|(node_idx, values)| (node_idx, values.into_iter().collect()))
        .collect();
}

fn initial_memory_regions_for_node(fg: &FlowGraph, node: NodeIndex) -> BTreeSet<String> {
    let mut regions = BTreeSet::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            for region in memory_region_seed_for_value(fg, *func, *value) {
                regions.insert(region);
            }
        }
        FlowNode::FieldCell { func, base, field, .. } => {
            let mut bases = fg.value_memory_regions_of(*func, *base);
            if bases.is_empty() {
                bases = memory_region_seed_for_value(fg, *func, *base);
            }
            for base_region in bases {
                regions.insert(format!("{}.{}", base_region, field));
            }
        }
        FlowNode::IndexCell { func, base, abstract_key, .. } => {
            let mut bases = fg.value_memory_regions_of(*func, *base);
            if bases.is_empty() {
                bases = memory_region_seed_for_value(fg, *func, *base);
            }
            for base_region in bases {
                regions.insert(format!("{}[{}]", base_region, abstract_key));
            }
        }
        FlowNode::CallPort { port, .. } => {
            regions.insert(format!("mem:port:{:?}", port));
        }
        _ => {}
    }
    for shape in fg.object_shape_paths_of(node) {
        if !shape.trim().is_empty() {
            regions.insert(normalized_memory_region(&shape));
        }
    }
    regions
}

fn memory_region_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    let mut out = points_to_propagation_neighbors(fg, node);
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Forward));
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Backward));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_memory_regions(fg: &mut FlowGraph) {
    fg.node_memory_regions.clear();
    fg.value_memory_regions.clear();
    fg.cell_memory_regions.clear();
    let mut regions = HashMap::<usize, BTreeSet<String>>::new();
    for node in fg.graph.node_indices() {
        let seeded = initial_memory_regions_for_node(fg, node);
        if !seeded.is_empty() {
            regions.insert(node.index(), seeded);
        }
    }
    let mut changed = true;
    let mut iterations = 0usize;
    while changed {
        changed = false;
        iterations += 1;
        let nodes = fg.graph.node_indices().collect::<Vec<_>>();
        for node in nodes {
            let mut merged = regions.get(&node.index()).cloned().unwrap_or_default();
            for neighbor in memory_region_propagation_neighbors(fg, node) {
                if let Some(values) = regions.get(&neighbor.index()) {
                    let before = merged.len();
                    merged.extend(values.iter().cloned());
                    if merged.len() > before {
                        changed = true;
                    }
                }
            }
            if !merged.is_empty() {
                let replace = regions.get(&node.index()).map(|prev| prev != &merged).unwrap_or(true);
                if replace {
                    regions.insert(node.index(), merged);
                    changed = true;
                }
            }
        }
    }
    for (node_idx, values) in &regions {
        fg.node_memory_regions.insert(*node_idx, values.iter().cloned().collect());
    }
    for (&(func, value), &node) in &fg.values {
        if let Some(node_regions) = fg.node_memory_regions.get(&node.index()).cloned() {
            let mut merged = fg.value_memory_regions.remove(&(func, value)).unwrap_or_default();
            merged.extend(node_regions);
            merged.sort();
            merged.dedup();
            fg.value_memory_regions.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_regions) = fg.node_memory_regions.get(&cell.index()).cloned() {
            let mut merged = fg.cell_memory_regions.remove(&cell.index()).unwrap_or_default();
            merged.extend(node_regions);
            merged.sort();
            merged.dedup();
            fg.cell_memory_regions.insert(cell.index(), merged);
        }
    }
}

fn add_region_graph_edge(fg: &mut FlowGraph, src: usize, dst: usize) {
    if src == dst {
        return;
    }
    let succs = fg.region_graph_successors.entry(src).or_default();
    if !succs.iter().any(|existing| *existing == dst) {
        succs.push(dst);
    }
    let preds = fg.region_graph_predecessors.entry(dst).or_default();
    if !preds.iter().any(|existing| *existing == src) {
        preds.push(src);
    }
}

fn materialize_region_graph_adjacency(fg: &mut FlowGraph) {
    fg.region_graph_successors.clear();
    fg.region_graph_predecessors.clear();

    let mut region_to_nodes = BTreeMap::<String, BTreeSet<usize>>::new();
    for node in fg.graph.node_indices() {
        for region in fg.node_memory_regions_of(node) {
            region_to_nodes.entry(region).or_default().insert(node.index());
        }
    }

    let regions = region_to_nodes.keys().cloned().collect::<Vec<_>>();
    for (left_idx, left_region) in regions.iter().enumerate() {
        for right_region in regions.iter().skip(left_idx) {
            if !memory_region_related(left_region, right_region) {
                continue;
            }
            let Some(left_nodes) = region_to_nodes.get(left_region) else {
                continue;
            };
            let Some(right_nodes) = region_to_nodes.get(right_region) else {
                continue;
            };
            for left_node in left_nodes {
                for right_node in right_nodes {
                    if left_node == right_node {
                        continue;
                    }
                    add_region_graph_edge(fg, *left_node, *right_node);
                    add_region_graph_edge(fg, *right_node, *left_node);
                }
            }
        }
    }

    for values in fg.region_graph_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.region_graph_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
}

fn materialize_cell_live_state(fg: &mut FlowGraph) {
    fg.cell_live_values.clear();
    fg.cell_live_regions.clear();
    for cell in all_cell_nodes(fg) {
        let live = visible_direct_cell_store_records_before_edge(fg, cell, None);
        if !live.is_empty() {
            let mut values = live
                .iter()
                .map(|(_edge_idx, func, value)| (func.0, value.0))
                .collect::<Vec<_>>();
            values.sort_unstable();
            values.dedup();
            fg.cell_live_values.insert(cell.index(), values);
        }
        let mut regions = BTreeSet::new();
        for (_edge_idx, func, value) in &live {
            for region in fg.value_memory_regions_of(*func, *value) {
                regions.insert(region);
            }
        }
        if regions.is_empty() {
            for region in fg.cell_memory_regions_of(cell) {
                regions.insert(region);
            }
        }
        if !regions.is_empty() {
            fg.cell_live_regions.insert(cell.index(), regions.into_iter().collect());
        }
    }
}

fn materialize_region_live_state(fg: &mut FlowGraph) {
    fg.region_live_values.clear();
    fg.region_live_cells.clear();

    let mut live_values = BTreeMap::<String, BTreeSet<(u32, u32)>>::new();
    let mut live_cells = BTreeMap::<String, BTreeSet<usize>>::new();
    for cell in all_cell_nodes(fg) {
        let mut cell_regions = fg.cell_live_regions_of(cell);
        if cell_regions.is_empty() {
            cell_regions = fg.cell_memory_regions_of(cell);
        }
        let mut cell_values = fg.cell_live_values_of(cell);
        if cell_values.is_empty() {
            cell_values = direct_cell_store_values(fg, cell);
        }
        for region in cell_regions {
            for ancestor in memory_region_ancestor_chain(&region) {
                live_cells.entry(ancestor.clone()).or_default().insert(cell.index());
                for (func, value) in &cell_values {
                    live_values.entry(ancestor.clone()).or_default().insert((func.0, value.0));
                }
            }
        }
    }

    fg.region_live_values = live_values
        .into_iter()
        .map(|(region, values)| (region, values.into_iter().collect()))
        .collect();
    fg.region_live_cells = live_cells
        .into_iter()
        .map(|(region, cells)| (region, cells.into_iter().collect()))
        .collect();
}

fn materialize_cell_write_generations(fg: &mut FlowGraph) {
    fg.cell_write_generations.clear();
    let mut all_cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    all_cells.extend(fg.index_cells.values().copied());
    all_cells.sort_unstable_by_key(|node| node.index());
    all_cells.dedup_by_key(|node| node.index());
    for cell in all_cells {
        let records = visible_direct_cell_store_records_before_edge(fg, cell, None);
        if records.is_empty() {
            continue;
        }
        let generations = records
            .into_iter()
            .enumerate()
            .map(|(generation, (_edge_idx, func, value))| (generation as u64, func.0, value.0))
            .collect::<Vec<_>>();
        fg.cell_write_generations.insert(cell.index(), generations);
    }
}

fn materialize_points_to_partitions(fg: &mut FlowGraph) {
    fg.value_points_to_classes.clear();
    fg.cell_points_to_classes.clear();
    fg.strong_update_cells.clear();
    let values = fg.values.keys().copied().collect::<Vec<_>>();
    for (func, value) in values {
        let classes = inferred_points_to_classes_for_value(fg, func, value);
        if !classes.is_empty() {
            fg.value_points_to_classes.insert((func, value), classes);
        }
    }
    let mut all_cells = fg.field_cells.values().copied().collect::<Vec<_>>();
    all_cells.extend(fg.index_cells.values().copied());
    all_cells.sort_unstable_by_key(|node| node.index());
    all_cells.dedup_by_key(|node| node.index());
    for cell in all_cells {
        if cell_allows_strong_update(fg, cell) {
            fg.strong_update_cells.insert(cell.index());
        }
        let mut classes = BTreeSet::new();
        match &fg.graph[cell] {
            FlowNode::FieldCell { func, base, field, .. } => {
                if let Some(site) = value_identity_site(fg, *func, *base) {
                    classes.insert(format!("cell-site:{}:{}", site.trim(), field));
                }
                if let Some(ty) = fg.value_types.get(&(*func, *base)) {
                    classes.insert(format!("cell-field:{}:{}", normalized_type_point_class(ty), field));
                }
            }
            FlowNode::IndexCell { func, base, abstract_key, .. } => {
                if let Some(site) = value_identity_site(fg, *func, *base) {
                    classes.insert(format!("cell-site:{}:[{}]", site.trim(), abstract_key));
                }
                if let Some(ty) = fg.value_types.get(&(*func, *base)) {
                    classes.insert(format!("cell-index:{}:[{}]", normalized_type_point_class(ty), abstract_key));
                }
            }
            _ => {}
        }
        for (proj_func, proj_value) in cell_values_for_flow(fg, cell) {
            for class in inferred_points_to_classes_for_value(fg, proj_func, proj_value) {
                classes.insert(class);
            }
        }
        for class in inferred_shape_point_classes_for_node(fg, cell) {
            classes.insert(class);
        }
        if !classes.is_empty() {
            fg.cell_points_to_classes.insert(cell.index(), classes.into_iter().collect());
        }
    }
}

fn initial_node_points_to_classes(fg: &FlowGraph, node: NodeIndex) -> BTreeSet<String> {
    let mut classes = BTreeSet::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            for class in inferred_points_to_classes_for_value(fg, *func, *value) {
                classes.insert(class);
            }
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            for class in fg.cell_points_to_classes_of(node) {
                classes.insert(class);
            }
        }
        _ => {}
    }
    classes
}

fn points_to_propagation_neighbors(fg: &FlowGraph, node: NodeIndex) -> Vec<NodeIndex> {
    let mut out = fg.sparse_neighbors_of(node, SparseDirection::Forward);
    out.extend(fg.sparse_neighbors_of(node, SparseDirection::Backward));
    out.extend(fg.heap_object_successors_of(node));
    out.extend(fg.heap_object_predecessors_of(node));
    out.extend(fg.object_graph_successors_of(node));
    out.extend(fg.object_graph_predecessors_of(node));
    out.extend(fg.region_graph_successors_of(node));
    out.extend(fg.region_graph_predecessors_of(node));
    out.sort_unstable_by_key(|n| n.index());
    out.dedup_by_key(|n| n.index());
    out
}

fn materialize_points_to_fixpoint(fg: &mut FlowGraph) {
    fg.node_points_to_classes.clear();
    let mut classes = HashMap::<usize, BTreeSet<String>>::new();
    for node in fg.graph.node_indices() {
        let seeded = initial_node_points_to_classes(fg, node);
        if !seeded.is_empty() {
            classes.insert(node.index(), seeded);
        }
    }
    let mut changed = true;
    let mut iterations = 0usize;
    while changed {
        changed = false;
        iterations += 1;
        let nodes = fg.graph.node_indices().collect::<Vec<_>>();
        for node in nodes {
            let mut merged = classes.get(&node.index()).cloned().unwrap_or_default();
            for neighbor in points_to_propagation_neighbors(fg, node) {
                if let Some(values) = classes.get(&neighbor.index()) {
                    let before = merged.len();
                    merged.extend(values.iter().cloned());
                    if merged.len() != before {
                        changed = true;
                    }
                }
            }
            if !merged.is_empty() {
                let replace = classes
                    .get(&node.index())
                    .map(|prev| prev != &merged)
                    .unwrap_or(true);
                if replace {
                    classes.insert(node.index(), merged);
                    changed = true;
                }
            }
        }
    }
    for (node_idx, values) in &classes {
        fg.node_points_to_classes
            .insert(*node_idx, values.iter().cloned().collect());
    }
    for (&(func, value), &node) in &fg.values {
        if let Some(node_classes) = fg.node_points_to_classes.get(&node.index()).cloned() {
            let mut merged = fg.value_points_to_classes.remove(&(func, value)).unwrap_or_default();
            merged.extend(node_classes);
            merged.sort();
            merged.dedup();
            fg.value_points_to_classes.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_classes) = fg.node_points_to_classes.get(&cell.index()).cloned() {
            let mut merged = fg.cell_points_to_classes.remove(&cell.index()).unwrap_or_default();
            merged.extend(node_classes);
            merged.sort();
            merged.dedup();
            fg.cell_points_to_classes.insert(cell.index(), merged);
        }
    }
}

fn initial_node_points_to_targets(fg: &FlowGraph, node: NodeIndex) -> BTreeSet<String> {
    let mut targets = BTreeSet::new();
    match &fg.graph[node] {
        FlowNode::Value { func, value } | FlowNode::Param { func, value, .. } => {
            if let Some(site) = value_identity_site(fg, *func, *value) {
                targets.insert(format!("obj:site:{}", site.trim()));
            }
            for region in value_root_memory_regions(fg, *func, *value) {
                targets.insert(format!("obj:root:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("obj:value:{}:{}", func.0, value.0));
            }
        }
        FlowNode::Return { func } => {
            for region in fg.node_memory_regions_of(node) {
                targets.insert(format!("obj:return:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("obj:return-func:{}", func.0));
            }
        }
        FlowNode::CallPort { port, .. } => {
            for (src_func, src_value) in fg.call_port_source_values(node) {
                for target in fg.value_points_to_targets_of(src_func, src_value) {
                    targets.insert(target);
                }
                if let Some(site) = value_identity_site(fg, src_func, src_value) {
                    targets.insert(format!("obj:site:{}", site.trim()));
                }
            }
            for region in fg.node_memory_regions_of(node) {
                targets.insert(format!("obj:port:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("obj:port:{:?}", port));
            }
        }
        FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
            if let Some(key) = cell_abstract_identity_key(fg, node) {
                targets.insert(format!("cell:{}", key));
            }
            for region in fg.cell_memory_regions_of(node) {
                targets.insert(format!("cell:region:{}", normalized_memory_region(&region)));
            }
            if targets.is_empty() {
                targets.insert(format!("cell:node:{}", node.index()));
            }
        }
        FlowNode::SyntheticSource { rule_id, .. } => {
            targets.insert(format!("obj:synthetic-source:{}", rule_id));
        }
        FlowNode::SyntheticSink { rule_id, .. } => {
            targets.insert(format!("obj:synthetic-sink:{}", rule_id));
        }
    }
    targets
}

fn compute_points_to_targets_fixpoint_for_allowed_nodes(
    fg: &FlowGraph,
    allowed_nodes: Option<&HashSet<usize>>,
) -> HashMap<usize, Vec<String>> {
    let nodes = fg
        .graph
        .node_indices()
        .filter(|node| allowed_nodes.map(|allowed| allowed.contains(&node.index())).unwrap_or(true))
        .collect::<Vec<_>>();
    let allowed_lookup = nodes.iter().map(|node| node.index()).collect::<HashSet<_>>();
    let mut targets = HashMap::<usize, BTreeSet<String>>::new();
    let mut reverse = HashMap::<usize, BTreeSet<usize>>::new();
    for node in &nodes {
        let seeded = initial_node_points_to_targets(fg, *node);
        if !seeded.is_empty() {
            targets.insert(node.index(), seeded);
        }
    }
    for node in &nodes {
        for neighbor in points_to_propagation_neighbors(fg, *node) {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            reverse.entry(neighbor.index()).or_default().insert(node.index());
        }
    }
    let mut queue = nodes.iter().map(|node| node.index()).collect::<VecDeque<_>>();
    let mut queued = queue.iter().copied().collect::<HashSet<_>>();
    while let Some(node_idx) = queue.pop_front() {
        queued.remove(&node_idx);
        let node = NodeIndex::new(node_idx);
        let mut merged = targets.get(&node_idx).cloned().unwrap_or_default();
        let before = merged.len();
        for neighbor in points_to_propagation_neighbors(fg, node) {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            if let Some(values) = targets.get(&neighbor.index()) {
                merged.extend(values.iter().cloned());
            }
        }
        if merged.len() != before || !targets.contains_key(&node_idx) {
            targets.insert(node_idx, merged);
            if let Some(preds) = reverse.get(&node_idx) {
                for pred in preds {
                    if queued.insert(*pred) {
                        queue.push_back(*pred);
                    }
                }
            }
        }
    }
    targets
        .into_iter()
        .map(|(node_idx, values)| (node_idx, values.into_iter().collect::<Vec<_>>()))
        .collect()
}

fn materialize_points_to_targets_fixpoint(fg: &mut FlowGraph) {
    fg.node_points_to_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, None);
    fg.value_points_to_targets.clear();
    fg.cell_points_to_targets.clear();
    for (&(func, value), &node) in &fg.values {
        if let Some(node_targets) = fg.node_points_to_targets.get(&node.index()).cloned() {
            let mut merged = fg.value_points_to_targets.remove(&(func, value)).unwrap_or_default();
            merged.extend(node_targets);
            merged.sort();
            merged.dedup();
            fg.value_points_to_targets.insert((func, value), merged);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(node_targets) = fg.node_points_to_targets.get(&cell.index()).cloned() {
            let mut merged = fg.cell_points_to_targets.remove(&cell.index()).unwrap_or_default();
            merged.extend(node_targets);
            merged.sort();
            merged.dedup();
            fg.cell_points_to_targets.insert(cell.index(), merged);
        }
    }
}

fn compute_points_to_object_ids_fixpoint_for_allowed_nodes(
    fg: &mut FlowGraph,
    allowed_nodes: Option<&HashSet<usize>>,
) -> HashMap<usize, Vec<u32>> {
    let nodes = fg
        .graph
        .node_indices()
        .filter(|node| allowed_nodes.map(|allowed| allowed.contains(&node.index())).unwrap_or(true))
        .collect::<Vec<_>>();
    let allowed_lookup = nodes.iter().map(|node| node.index()).collect::<HashSet<_>>();
    let mut object_ids = HashMap::<usize, BTreeSet<u32>>::new();
    let mut reverse = HashMap::<usize, BTreeSet<usize>>::new();
    for node in &nodes {
        if let Some(ids) = fg.abstract_object_seed_nodes.get(&node.index()) {
            let seeded = ids.iter().copied().collect::<BTreeSet<_>>();
            if !seeded.is_empty() {
                object_ids.insert(node.index(), seeded);
            }
        }
    }
    for node in &nodes {
        let mut neighbors = points_to_propagation_neighbors(fg, *node);
        neighbors.extend(fg.object_successors_of(*node));
        neighbors.extend(fg.object_predecessors_of(*node));
        neighbors.sort_unstable_by_key(|idx| idx.index());
        neighbors.dedup_by_key(|idx| idx.index());
        for neighbor in neighbors {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            reverse.entry(neighbor.index()).or_default().insert(node.index());
        }
    }
    let mut queue = nodes.iter().map(|node| node.index()).collect::<VecDeque<_>>();
    let mut queued = queue.iter().copied().collect::<HashSet<_>>();
    while let Some(node_idx) = queue.pop_front() {
        queued.remove(&node_idx);
        let node = NodeIndex::new(node_idx);
        let mut merged = object_ids.get(&node_idx).cloned().unwrap_or_default();
        let before = merged.len();
        let mut neighbors = points_to_propagation_neighbors(fg, node);
        neighbors.extend(fg.object_successors_of(node));
        neighbors.extend(fg.object_predecessors_of(node));
        neighbors.sort_unstable_by_key(|idx| idx.index());
        neighbors.dedup_by_key(|idx| idx.index());
        for neighbor in neighbors {
            if !allowed_lookup.contains(&neighbor.index()) {
                continue;
            }
            if let Some(values) = object_ids.get(&neighbor.index()) {
                merged.extend(values.iter().copied());
            }
        }
        if merged.len() != before || !object_ids.contains_key(&node_idx) {
            object_ids.insert(node_idx, merged);
            if let Some(preds) = reverse.get(&node_idx) {
                for pred in preds {
                    if queued.insert(*pred) {
                        queue.push_back(*pred);
                    }
                }
            }
        }
    }
    object_ids
        .into_iter()
        .map(|(node_idx, values)| (node_idx, values.into_iter().collect::<Vec<_>>()))
        .collect()
}


fn materialize_points_to_object_ids(fg: &mut FlowGraph) {
    materialize_abstract_object_catalog(fg);
    fg.node_points_to_object_ids.clear();
    fg.value_points_to_object_ids.clear();
    fg.cell_points_to_object_ids.clear();

    fg.node_points_to_object_ids = compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, None);
    for (&(func, value), &node) in &fg.values {
        if let Some(ids) = fg.node_points_to_object_ids.get(&node.index()).cloned() {
            fg.value_points_to_object_ids.insert((func, value), ids);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(ids) = fg.node_points_to_object_ids.get(&cell.index()).cloned() {
            fg.cell_points_to_object_ids.insert(cell.index(), ids);
        }
    }
}

fn cell_candidates_for_object_ids(fg: &FlowGraph, object_ids: &[u32]) -> Vec<NodeIndex> {
    if object_ids.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for cell in all_cell_nodes(fg) {
        let candidate_ids = fg.cell_points_to_object_ids_of(cell);
        if !candidate_ids.is_empty() && points_to_object_ids_overlap(object_ids, &candidate_ids) {
            out.push(cell);
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn cell_candidates_for_value_targets(fg: &FlowGraph, func: FunctionId, value: ValueId) -> Vec<NodeIndex> {
    let targets = fg.value_points_to_targets_of(func, value);
    if targets.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for cell in all_cell_nodes(fg) {
        let cell_targets = fg.cell_points_to_targets_of(cell);
        if !cell_targets.is_empty() && points_to_targets_overlap(&targets, &cell_targets) {
            out.push(cell);
        }
    }
    out.sort_unstable_by_key(|node| node.index());
    out.dedup_by_key(|node| node.index());
    out
}

fn materialize_contextual_solver_state(fg: &mut FlowGraph, program: &Program) {
    materialize_abstract_object_catalog(fg);
    fg.contextual_return_values.clear();
    fg.contextual_return_cells.clear();
    fg.contextual_points_to_targets.clear();
    fg.contextual_points_to_object_ids.clear();
    fg.contextual_node_points_to_targets.clear();
    fg.contextual_value_points_to_targets.clear();
    fg.contextual_cell_points_to_targets.clear();
    fg.contextual_node_points_to_object_ids.clear();
    fg.contextual_value_points_to_object_ids.clear();
    fg.contextual_cell_points_to_object_ids.clear();
    for func in &program.functions {
        for block in &func.blocks {
            for inst in &block.insts {
                let InstKind::Call(_call) = &inst.kind else {
                    continue;
                };
                let Some(base_context) = fg.call_context_key(func.id, inst.id) else {
                    continue;
                };
                for sensitivity in all_context_sensitivities() {
                    let context = fg.refine_call_context_for_sensitivity(base_context.clone(), *sensitivity);
                    let Some(summary) = fg.contextual_call_summary(
                        func.id,
                        inst.id,
                        *sensitivity,
                        SparseDirection::Forward,
                        16,
                        4096,
                        DemandEngine::Fixpoint,
                        true,
                    ) else {
                        continue;
                    };
                    let Some(call_summary) = fg.interprocedural_call_summary_with_sensitivity(
                        func.id,
                        inst.id,
                        *sensitivity,
                        16,
                        4096,
                        DemandEngine::Fixpoint,
                        true,
                    ) else {
                        continue;
                    };
                    let mut allowed_nodes = summary
                        .traversal
                        .visited
                        .iter()
                        .copied()
                        .filter(|node_idx| fg.node_matches_structural_call_context(NodeIndex::new(*node_idx), &context))
                        .collect::<HashSet<_>>();
                    for (ret_func, ret_value) in &call_summary.return_values {
                        if let Some(&node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                            allowed_nodes.insert(node.index());
                        }
                    }
                    for (ret_func, ret_value) in &call_summary.return_live_values {
                        if let Some(&node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                            allowed_nodes.insert(node.index());
                        }
                    }
                    for cell in &call_summary.return_cells {
                        allowed_nodes.insert(*cell as usize);
                    }
                    for (_ret_func, _ret_value, cell) in &call_summary.return_value_cells {
                        allowed_nodes.insert(*cell as usize);
                    }
                    let contextual_node_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, Some(&allowed_nodes));
                    let contextual_node_object_ids = compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, Some(&allowed_nodes));
                    let mut targets = fg
                        .contextual_points_to_targets
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    let mut object_ids = fg
                        .contextual_points_to_object_ids
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    let mut return_values = fg
                        .contextual_return_values
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    let mut return_cells = fg
                        .contextual_return_cells
                        .remove(&context)
                        .unwrap_or_default()
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    for (node_idx, node_targets) in contextual_node_targets {
                        let node = NodeIndex::new(node_idx);
                        let mut merged_targets = fg
                            .contextual_node_points_to_targets
                            .remove(&(context.clone(), node_idx))
                            .unwrap_or_default()
                            .into_iter()
                            .collect::<BTreeSet<_>>();
                        merged_targets.extend(node_targets.iter().cloned());
                        let merged_targets_vec = merged_targets.iter().cloned().collect::<Vec<_>>();
                        fg.contextual_node_points_to_targets.insert((context.clone(), node_idx), merged_targets_vec.clone());
                        let mut node_object_ids = fg
                            .contextual_node_points_to_object_ids
                            .remove(&(context.clone(), node_idx))
                            .unwrap_or_default()
                            .into_iter()
                            .collect::<BTreeSet<_>>();
                        if let Some(ids) = contextual_node_object_ids.get(&node_idx) {
                            node_object_ids.extend(ids.iter().copied());
                        }
                        if !node_object_ids.is_empty() {
                            let ids = node_object_ids.iter().copied().collect::<Vec<_>>();
                            fg.contextual_node_points_to_object_ids.insert((context.clone(), node_idx), ids.clone());
                            object_ids.extend(ids.iter().copied());
                        }
                        targets.extend(merged_targets_vec.iter().cloned());
                        match &fg.graph[node] {
                            FlowNode::Value { func: value_func, value } | FlowNode::Param { func: value_func, value, .. } => {
                                fg.contextual_value_points_to_targets.insert((context.clone(), value_func.0, value.0), merged_targets_vec.clone());
                                if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                                    fg.contextual_value_points_to_object_ids.insert((context.clone(), value_func.0, value.0), ids);
                                }
                            }
                            FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                                fg.contextual_cell_points_to_targets.insert((context.clone(), node_idx), merged_targets_vec.clone());
                                if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                                    fg.contextual_cell_points_to_object_ids.insert((context.clone(), node_idx), ids);
                                }
                            }
                            _ => {}
                        }
                    }
                    for (ret_func, ret_value) in &call_summary.return_values {
                        return_values.insert((*ret_func, *ret_value));
                    }
                    for (ret_func, ret_value) in &call_summary.return_live_values {
                        return_values.insert((*ret_func, *ret_value));
                    }
                    for cell in &call_summary.return_cells {
                        return_cells.insert(*cell as usize);
                    }
                    for (_ret_func, _ret_value, cell) in &call_summary.return_value_cells {
                        return_cells.insert(*cell as usize);
                    }
                    fg.contextual_return_values.insert(context.clone(), return_values.into_iter().collect());
                    fg.contextual_return_cells.insert(context.clone(), return_cells.into_iter().collect());
                    fg.contextual_points_to_targets.insert(context.clone(), targets.into_iter().collect());
                    fg.contextual_points_to_object_ids.insert(context.clone(), object_ids.into_iter().collect());
                }
            }
        }
    }

    let covered_nodes = fg
        .contextual_node_points_to_targets
        .keys()
        .map(|(_, node_idx)| *node_idx)
        .chain(
            fg.contextual_node_points_to_object_ids
                .keys()
                .map(|(_, node_idx)| *node_idx),
        )
        .collect::<HashSet<_>>();
    let fallback_nodes = if covered_nodes.is_empty() {
        fg.graph.node_indices().map(|node| node.index()).collect::<HashSet<_>>()
    } else {
        fg.graph
            .node_indices()
            .map(|node| node.index())
            .filter(|node_idx| !covered_nodes.contains(node_idx))
            .collect::<HashSet<_>>()
    };
    if !fallback_nodes.is_empty() {
        let context = CallContextKey::default();
        let contextual_node_targets = compute_points_to_targets_fixpoint_for_allowed_nodes(fg, Some(&fallback_nodes));
        let contextual_node_object_ids = compute_points_to_object_ids_fixpoint_for_allowed_nodes(fg, Some(&fallback_nodes));
        let mut targets = BTreeSet::<String>::new();
        let mut object_ids = BTreeSet::<u32>::new();
        for (node_idx, node_targets) in contextual_node_targets {
            let node = NodeIndex::new(node_idx);
            let mut merged_targets = fg
                .contextual_node_points_to_targets
                .remove(&(context.clone(), node_idx))
                .unwrap_or_default()
                .into_iter()
                .collect::<BTreeSet<_>>();
            merged_targets.extend(node_targets.iter().cloned());
            let merged_targets_vec = merged_targets.iter().cloned().collect::<Vec<_>>();
            fg.contextual_node_points_to_targets
                .insert((context.clone(), node_idx), merged_targets_vec.clone());
            targets.extend(merged_targets_vec.iter().cloned());
            let mut merged_object_ids = fg
                .contextual_node_points_to_object_ids
                .remove(&(context.clone(), node_idx))
                .unwrap_or_default()
                .into_iter()
                .collect::<BTreeSet<_>>();
            if let Some(ids) = contextual_node_object_ids.get(&node_idx) {
                merged_object_ids.extend(ids.iter().copied());
            }
            if !merged_object_ids.is_empty() {
                let ids = merged_object_ids.iter().copied().collect::<Vec<_>>();
                fg.contextual_node_points_to_object_ids
                    .insert((context.clone(), node_idx), ids.clone());
                object_ids.extend(ids.iter().copied());
            }
            match &fg.graph[node] {
                FlowNode::Value { func: value_func, value } | FlowNode::Param { func: value_func, value, .. } => {
                    fg.contextual_value_points_to_targets
                        .insert((context.clone(), value_func.0, value.0), merged_targets_vec.clone());
                    if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                        fg.contextual_value_points_to_object_ids
                            .insert((context.clone(), value_func.0, value.0), ids);
                    }
                }
                FlowNode::FieldCell { .. } | FlowNode::IndexCell { .. } => {
                    fg.contextual_cell_points_to_targets
                        .insert((context.clone(), node_idx), merged_targets_vec.clone());
                    if let Some(ids) = fg.contextual_node_points_to_object_ids.get(&(context.clone(), node_idx)).cloned() {
                        fg.contextual_cell_points_to_object_ids.insert((context.clone(), node_idx), ids);
                    }
                }
                _ => {}
            }
        }
        fg.contextual_points_to_targets.insert(context.clone(), targets.into_iter().collect());
        fg.contextual_points_to_object_ids.insert(context, object_ids.into_iter().collect());
    }
}


fn materialize_partitioned_points_to_state(fg: &mut FlowGraph, program: &Program) {
    materialize_contextual_solver_state(fg, program);
    aggregate_partitioned_points_to_state(fg);
}

fn aggregate_partitioned_points_to_state(fg: &mut FlowGraph) {
    fg.node_points_to_targets.clear();
    fg.value_points_to_targets.clear();
    fg.cell_points_to_targets.clear();
    fg.node_points_to_object_ids.clear();
    fg.value_points_to_object_ids.clear();
    fg.cell_points_to_object_ids.clear();

    let contextual_target_entries = fg
        .contextual_node_points_to_targets
        .iter()
        .map(|((_, node_idx), targets)| (*node_idx, targets.clone()))
        .collect::<Vec<_>>();
    let contextual_object_entries = fg
        .contextual_node_points_to_object_ids
        .iter()
        .map(|((_, node_idx), ids)| (*node_idx, ids.clone()))
        .collect::<Vec<_>>();

    let mut covered_nodes = HashSet::<usize>::new();
    for (node_idx, targets) in contextual_target_entries {
        covered_nodes.insert(node_idx);
        let mut merged = fg.node_points_to_targets.remove(&node_idx).unwrap_or_default();
        merged.extend(targets);
        merged.sort();
        merged.dedup();
        fg.node_points_to_targets.insert(node_idx, merged);
    }
    for (node_idx, ids) in contextual_object_entries {
        covered_nodes.insert(node_idx);
        let mut merged = fg.node_points_to_object_ids.remove(&node_idx).unwrap_or_default();
        merged.extend(ids);
        merged.sort_unstable();
        merged.dedup();
        fg.node_points_to_object_ids.insert(node_idx, merged);
    }

    let value_entries = fg.values.iter().map(|(&(func, value), &node)| (func, value, node.index())).collect::<Vec<_>>();
    for (func, value, node_idx) in value_entries {
        if let Some(targets) = fg.node_points_to_targets.get(&node_idx).cloned() {
            fg.value_points_to_targets.insert((func, value), targets);
        }
        if let Some(ids) = fg.node_points_to_object_ids.get(&node_idx).cloned() {
            fg.value_points_to_object_ids.insert((func, value), ids);
        }
    }
    for cell in all_cell_nodes(fg) {
        if let Some(targets) = fg.node_points_to_targets.get(&cell.index()).cloned() {
            fg.cell_points_to_targets.insert(cell.index(), targets);
        }
        if let Some(ids) = fg.node_points_to_object_ids.get(&cell.index()).cloned() {
            fg.cell_points_to_object_ids.insert(cell.index(), ids);
        }
    }
}

fn materialize_sparse_data_adjacency(fg: &mut FlowGraph) {
    fg.sparse_successors.clear();
    fg.sparse_predecessors.clear();
    fg.clear_sparse_caches();
    for edge in fg.graph.edge_references() {
        if !is_sparse_data_edge(&edge.weight().kind) {
            continue;
        }
        let src = edge.source().index();
        let dst = edge.target().index();
        fg.sparse_successors.entry(src).or_default().push(dst);
        fg.sparse_predecessors.entry(dst).or_default().push(src);
    }
    for values in fg.sparse_successors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    for values in fg.sparse_predecessors.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    materialize_heap_value_adjacency(fg);
    materialize_heap_object_adjacency(fg);
    materialize_object_graph_adjacency(fg);
    materialize_object_shape_paths(fg);
    materialize_object_shape_fixpoint(fg);
    materialize_cell_write_generations(fg);
    materialize_memory_regions(fg);
    materialize_region_graph_adjacency(fg);
    materialize_memory_regions(fg);
    materialize_region_graph_adjacency(fg);
    materialize_cell_live_state(fg);
    materialize_region_live_state(fg);
    materialize_object_graph_adjacency(fg);
    materialize_object_shape_paths(fg);
    materialize_object_shape_fixpoint(fg);
    materialize_memory_regions(fg);
    materialize_region_graph_adjacency(fg);
    materialize_region_live_state(fg);
}

fn add_unique_summary_edge(fg: &mut FlowGraph, src: NodeIndex, dst: NodeIndex, rule_id: &str) -> bool {
    for edge in fg.graph.edges_connecting(src, dst) {
        if let EdgeKind::Summary { rule_id: existing } = &edge.weight().kind {
            if existing == rule_id {
                return false;
            }
        }
    }
    fg.graph.add_edge(
        src,
        dst,
        FlowEdge {
            kind: EdgeKind::Summary {
                rule_id: rule_id.to_string(),
            },
        },
    );
    true
}

fn connect_materialized_function_transfer_summaries(fg: &mut FlowGraph, program: &Program) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        let Some(summary) = fg.function_transfer_summary(func.id, 16, 4096, DemandEngine::Fixpoint, true) else {
            continue;
        };
        let Some(&ret_node) = fg.function_returns.get(&func.id) else {
            continue;
        };
        for index in &summary.return_reachable_params {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                pending_edges.push((param_node, ret_node, "internal:function-return".to_string()));
            }
        }
        for (from_index, to_index) in &summary.param_to_param {
            if let (Some(&src), Some(&dst)) = (
                fg.function_params.get(&(func.id, *from_index)),
                fg.function_params.get(&(func.id, *to_index)),
            ) {
                pending_edges.push((src, dst, "internal:function-param".to_string()));
            }
        }
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn connect_materialized_function_heap_effect_summaries(fg: &mut FlowGraph, program: &Program) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        let Some(summary) = fg.function_heap_effect_summary(func.id, 16, 4096, DemandEngine::Fixpoint, true) else {
            continue;
        };
        let Some(&ret_node) = fg.function_returns.get(&func.id) else {
            continue;
        };
        for (index, cell) in &summary.param_to_read_cells {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                    pending_edges.push((param_node, cell, "internal:function-heap-read".to_string()));
                }
            }
        }
        for (index, region) in &summary.param_to_read_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let mut candidates = summary
                    .param_to_read_cells
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .param_to_read_objects
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_index, path) in &summary.param_to_read_paths {
                    if path_index != index {
                        continue;
                    }
                    if let FlowNode::Param { value, .. } = &fg.graph[param_node] {
                        candidates.extend(candidate_cells_for_relative_path_from_value(fg, func.id, *value, path));
                    }
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((param_node, cell, "internal:function-heap-read".to_string()));
                }
            }
        }
        for (index, cell) in &summary.param_to_write_cells {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                    pending_edges.push((param_node, cell, "internal:function-heap-write".to_string()));
                }
            }
        }
        for (index, region) in &summary.param_to_write_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let mut candidates = summary
                    .param_to_write_cells
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .param_to_write_objects
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_index, path) in &summary.param_to_write_paths {
                    if path_index != index {
                        continue;
                    }
                    if let FlowNode::Param { value, .. } = &fg.graph[param_node] {
                        candidates.extend(candidate_cells_for_relative_path_from_value(fg, func.id, *value, path));
                    }
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((param_node, cell, "internal:function-heap-write".to_string()));
                }
            }
        }
        for (index, cell) in &summary.param_to_return_cells {
            if let Some(_param_node) = fg.function_params.get(&(func.id, *index)) {
                let cell = NodeIndex::new(*cell as usize);
                if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                    pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
                }
            }
        }
        for (index, region) in &summary.param_to_return_regions {
            if let Some(&param_node) = fg.function_params.get(&(func.id, *index)) {
                let mut candidates = summary
                    .param_to_return_cells
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .param_to_return_objects
                    .iter()
                    .filter(|(path_index, _)| path_index == index)
                    .map(|(_, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_index, path) in &summary.param_to_return_paths {
                    if path_index != index {
                        continue;
                    }
                    if let FlowNode::Param { value, .. } = &fg.graph[param_node] {
                        candidates.extend(candidate_cells_for_relative_path_from_value(fg, func.id, *value, path));
                    }
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
                }
            }
        }
        for (_index, live_func, live_value) in &summary.param_to_return_live_values {
            if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                pending_edges.push((live_value_node, ret_node, "internal:function-live-return-value".to_string()));
            }
        }
        for (ret_func, ret_value, region) in &summary.return_value_regions {
            if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                let mut candidates = summary
                    .return_value_cells
                    .iter()
                    .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                    .map(|(_, _, cell)| NodeIndex::new(*cell as usize))
                    .collect::<Vec<_>>();
                let object_ids = summary
                    .return_value_objects
                    .iter()
                    .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                    .map(|(_, _, object_id)| *object_id)
                    .collect::<Vec<_>>();
                candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                candidates.extend(region_candidate_cells(fg, region));
                for (path_func, path_value, path) in &summary.return_value_paths {
                    if path_func != ret_func || path_value != ret_value {
                        continue;
                    }
                    candidates.extend(candidate_cells_for_relative_path_from_value(
                        fg,
                        FunctionId(*ret_func),
                        ValueId(*ret_value),
                        path,
                    ));
                }
                candidates.sort_unstable_by_key(|node| node.index());
                candidates.dedup_by_key(|node| node.index());
                for cell in candidates {
                    if !matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                        continue;
                    }
                    pending_edges.push((ret_value_node, cell, "internal:function-return-value-region".to_string()));
                }
            }
        }
        for cell in &summary.return_cells {
            let cell = NodeIndex::new(*cell as usize);
            if matches!(fg.graph[cell], FlowNode::FieldCell { func: cell_func, .. } | FlowNode::IndexCell { func: cell_func, .. } if cell_func == func.id) {
                pending_edges.push((cell, ret_node, "internal:function-heap-return".to_string()));
            }
        }
        for (live_func, live_value) in &summary.return_live_values {
            if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                pending_edges.push((live_value_node, ret_node, "internal:function-live-return-value".to_string()));
            }
        }
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn connect_materialized_interprocedural_summaries(fg: &mut FlowGraph, program: &Program) -> usize {
    let mut pending_edges = Vec::<(NodeIndex, NodeIndex, String)>::new();
    for func in &program.functions {
        for block in &func.blocks {
            for inst in &block.insts {
                let InstKind::Call(_call) = &inst.kind else {
                    continue;
                };
                let Some(summary) = fg.interprocedural_call_summary(
                    func.id,
                    inst.id,
                    16,
                    4096,
                    DemandEngine::Fixpoint,
                    true,
                ) else {
                    continue;
                };
                let callee_name = fg
                    .call_meta
                    .get(&(func.id, inst.id))
                    .and_then(|meta| meta.callee_name.clone());
                let ret_port = get_or_create_call_port(
                    fg,
                    func.id,
                    inst.id,
                    Port::Return,
                    callee_name,
                );
                let mut port_nodes = BTreeMap::<String, NodeIndex>::new();
                for ((call_func, call_inst, port), node) in &fg.call_ports {
                    if *call_func == func.id && *call_inst == inst.id {
                        port_nodes.insert(format!("{:?}", port), *node);
                    }
                }
                for port_name in &summary.port_to_return {
                    if let Some(src) = port_nodes.get(port_name) {
                        pending_edges.push((*src, ret_port, "internal:return".to_string()));
                    }
                }
                for (src_name, dst_name) in &summary.port_to_port {
                    if let (Some(src), Some(dst)) = (port_nodes.get(src_name), port_nodes.get(dst_name)) {
                        pending_edges.push((*src, *dst, "internal:param".to_string()));
                    }
                }
                for (src_name, ret_func, ret_value) in &summary.port_to_return_values {
                    if let Some(src) = port_nodes.get(src_name) {
                        if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                            pending_edges.push((*src, ret_value_node, "internal:return-value-source".to_string()));
                            pending_edges.push((ret_value_node, ret_port, "internal:return-value".to_string()));
                        }
                    }
                }
                for (src_name, live_func, live_value) in &summary.port_to_return_live_values {
                    if let Some(src) = port_nodes.get(src_name) {
                        if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                            pending_edges.push((*src, live_value_node, "internal:heap-live-return-source".to_string()));
                            pending_edges.push((live_value_node, ret_port, "internal:heap-live-return".to_string()));
                        }
                    }
                }
                for (ret_func, ret_value) in &summary.return_values {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        pending_edges.push((ret_value_node, ret_port, "internal:return-value".to_string()));
                    }
                }
                for (live_func, live_value) in &summary.return_live_values {
                    if let Some(&live_value_node) = fg.values.get(&(FunctionId(*live_func), ValueId(*live_value))) {
                        pending_edges.push((live_value_node, ret_port, "internal:heap-live-return".to_string()));
                    }
                }
                for cell in &summary.return_cells {
                    let cell_node = NodeIndex::new(*cell as usize);
                    pending_edges.push((cell_node, ret_port, "internal:heap-return".to_string()));
                }
                for (ret_func, ret_value, cell) in &summary.return_value_cells {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        pending_edges.push((ret_value_node, NodeIndex::new(*cell as usize), "internal:return-value-region".to_string()));
                    }
                }
                for (src_name, ret_func, ret_value, region) in &summary.port_to_return_value_regions {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        let mut candidates = summary
                            .return_value_cells
                            .iter()
                            .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                            .map(|(_, _, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_return_value_objects
                            .iter()
                            .filter(|(path_src, path_func, path_value, _)| path_src == src_name && path_func == ret_func && path_value == ret_value)
                            .map(|(_, _, _, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        if let Some(src) = port_nodes.get(src_name) {
                            for (path_src, path_func, path_value, path) in &summary.port_to_return_value_paths {
                                if path_src == src_name && path_func == ret_func && path_value == ret_value {
                                    candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                                }
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((ret_value_node, cell, "internal:return-value-region".to_string()));
                        }
                    }
                }
                for (ret_func, ret_value, region) in &summary.return_value_regions {
                    if let Some(&ret_value_node) = fg.values.get(&(FunctionId(*ret_func), ValueId(*ret_value))) {
                        let object_ids = summary
                            .return_value_objects
                            .iter()
                            .filter(|(path_func, path_value, _)| path_func == ret_func && path_value == ret_value)
                            .map(|(_, _, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        let mut candidates = cell_candidates_for_object_ids(fg, &object_ids);
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_func, path_value, path) in &summary.return_value_paths {
                            if path_func == ret_func && path_value == ret_value {
                                candidates.extend(candidate_cells_for_relative_path_from_value(
                                    fg,
                                    FunctionId(*ret_func),
                                    ValueId(*ret_value),
                                    path,
                                ));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((ret_value_node, cell, "internal:return-region-value".to_string()));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_read_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        pending_edges.push((*src, NodeIndex::new(*cell as usize), "internal:heap-read".to_string()));
                    }
                }
                for (src_name, region) in &summary.port_to_read_regions {
                    if let Some(src) = port_nodes.get(src_name) {
                        let mut candidates = summary
                            .port_to_read_cells
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_read_objects
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_src, path) in &summary.port_to_read_paths {
                            if path_src == src_name {
                                candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((*src, cell, "internal:heap-read".to_string()));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_write_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        pending_edges.push((*src, NodeIndex::new(*cell as usize), "internal:heap-write".to_string()));
                    }
                }
                for (src_name, region) in &summary.port_to_write_regions {
                    if let Some(src) = port_nodes.get(src_name) {
                        let mut candidates = summary
                            .port_to_write_cells
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_write_objects
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_src, path) in &summary.port_to_write_paths {
                            if path_src == src_name {
                                candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((*src, cell, "internal:heap-write".to_string()));
                        }
                    }
                }
                for (src_name, cell) in &summary.port_to_return_cells {
                    if let Some(src) = port_nodes.get(src_name) {
                        let cell = NodeIndex::new(*cell as usize);
                        pending_edges.push((*src, cell, "internal:heap-return-source".to_string()));
                        pending_edges.push((cell, ret_port, "internal:heap-return".to_string()));
                    }
                }
                for (src_name, region) in &summary.port_to_return_regions {
                    if let Some(src) = port_nodes.get(src_name) {
                        let mut candidates = summary
                            .port_to_return_cells
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, cell)| NodeIndex::new(*cell as usize))
                            .collect::<Vec<_>>();
                        let object_ids = summary
                            .port_to_return_objects
                            .iter()
                            .filter(|(path_src, _)| path_src == src_name)
                            .map(|(_, object_id)| *object_id)
                            .collect::<Vec<_>>();
                        candidates.extend(cell_candidates_for_object_ids(fg, &object_ids));
                        candidates.extend(region_candidate_cells(fg, region));
                        for (path_src, path) in &summary.port_to_return_paths {
                            if path_src == src_name {
                                candidates.extend(relative_path_candidate_cells_for_port(fg, *src, path));
                            }
                        }
                        candidates.sort_unstable_by_key(|node| node.index());
                        candidates.dedup_by_key(|node| node.index());
                        for cell in candidates {
                            pending_edges.push((*src, cell, "internal:heap-return-source".to_string()));
                            pending_edges.push((cell, ret_port, "internal:heap-return".to_string()));
                        }
                    }
                }
            }
        }
    }
    let mut added = 0usize;
    for (src, dst, rule_id) in pending_edges {
        if add_unique_summary_edge(fg, src, dst, &rule_id) {
            added += 1;
        }
    }
    added
}

fn solver_iteration_cap(fg: &FlowGraph) -> usize {
    let graph_nodes = fg.graph.node_count().max(1);
    let graph_edges = fg.graph.edge_count().max(1);
    graph_nodes.saturating_add(graph_edges).saturating_mul(4).max(64)
}

fn materialize_unified_analysis_state(fg: &mut FlowGraph) {
    let mut previous_signature = None;
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        materialize_sparse_data_adjacency(fg);
        materialize_object_shape_paths(fg);
        materialize_object_shape_fixpoint(fg);
        materialize_cell_write_generations(fg);
        materialize_memory_regions(fg);
        materialize_region_graph_adjacency(fg);
        materialize_cell_live_state(fg);
        materialize_region_live_state(fg);
        materialize_object_graph_adjacency(fg);
        let signature = analysis_state_signature(fg);
        if previous_signature.as_ref() == Some(&signature) {
            break;
        }
        assert!(iterations <= solver_iteration_cap(fg), "unified analysis failed to converge");
        previous_signature = Some(signature);
    }
}

fn materialize_interprocedural_solver_closure(fg: &mut FlowGraph, program: &Program) {
    let mut previous_signature = None;
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        let added_function_edges = connect_materialized_function_transfer_summaries(fg, program);
        let added_heap_edges = connect_materialized_function_heap_effect_summaries(fg, program);
        let added_call_edges = connect_materialized_interprocedural_summaries(fg, program);
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        let signature = analysis_state_signature(fg);
        if added_function_edges == 0 && added_heap_edges == 0 && added_call_edges == 0 && previous_signature.as_ref() == Some(&signature) {
            break;
        }
        assert!(iterations <= solver_iteration_cap(fg), "interprocedural solver failed to converge");
        previous_signature = Some(signature);
    }
    fg.solver_closure_iterations = iterations;
}

fn materialize_global_solver_closure(fg: &mut FlowGraph, program: &Program) {
    let mut previous_signature = None;
    let mut iterations = 0usize;
    loop {
        iterations += 1;
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        materialize_interprocedural_solver_closure(fg, program);
        materialize_unified_analysis_state(fg);
        materialize_partitioned_points_to_state(fg, program);
        let signature = analysis_state_signature(fg);
        if previous_signature.as_ref() == Some(&signature) {
            break;
        }
        assert!(iterations <= solver_iteration_cap(fg), "global solver failed to converge");
        previous_signature = Some(signature);
    }
    fg.global_solver_iterations = iterations;
}

fn resolve_dynamic_internal_calls(
    fg: &mut FlowGraph,
    program: &Program,
    func_index: &FunctionIndex<'_>,
    rules: &RuleSet,
) {
    for func in &program.functions {
        let ret_node = *fg
            .function_returns
            .get(&func.id)
            .expect("return node must exist");
        for block in &func.blocks {
            for inst in &block.insts {
                let InstKind::Call(call) = &inst.kind else {
                    continue;
                };
                let Callee::Dynamic(_callee_value) = &call.callee else {
                    continue;
                };
                let Some(existing_meta) = fg.call_meta.get(&(func.id, inst.id)).cloned() else {
                    continue;
                };
                let mut resolved_targets = Vec::new();
                for callee_func in func_index.resolve_call(&existing_meta) {
                    if !resolved_targets.iter().any(|existing| existing == &callee_func.name) {
                        resolved_targets.push(callee_func.name.clone());
                    }
                    connect_internal_call(fg, func.id, inst.id, call, callee_func, ret_node);
                }
                if resolved_targets.is_empty() {
                    continue;
                }
                fg.resolved_internal_targets
                    .insert((func.id, inst.id), resolved_targets.clone());
                if resolved_targets.len() == 1 {
                    let mut updated = existing_meta;
                    updated.callee_name = resolved_targets.first().cloned();
                    if let Some(name) = updated.callee_name.as_deref() {
                        let info = CallInfo::from_callee_name(name);
                        if updated.receiver_type.is_none() {
                            updated.receiver_type = info.receiver_type;
                        }
                        updated.method_name = info.method_name;
                    }
                    fg.call_meta.insert((func.id, inst.id), updated.clone());
                    connect_rule_summaries(fg, rules, func.id, inst.id, &updated);
                    attach_rule_sources_and_sinks(fg, rules, func.id, inst.id, &updated);
                }
            }
        }
    }
}


fn infer_dynamic_callee_names(
    fg: &FlowGraph,
    func: FunctionId,
    value: ValueId,
    max_depth: usize,
) -> Vec<String> {
    let query = DemandQuery {
        seeds: vec![DemandSeed::Value {
            func: func.0,
            value: value.0,
        }],
        direction: SparseDirection::Backward,
        engine: DemandEngine::Fixpoint,
        include_heap: true,
    };
    let summary = fg
        .contextual_demand_query_summary_auto(&query, max_depth, usize::MAX)
        .or_else(|| fg.demand_query_summary_auto(&query))
        .or_else(|| fg.demand_query_summary(&query, max_depth, usize::MAX))
        .unwrap_or_default();
    let mut out = Vec::new();
    for (func_id, value_id) in &summary.values {
        let func_id = FunctionId(*func_id);
        let value_id = ValueId(*value_id);
        let precise = precise_value_object_id(fg, func_id, value_id).is_some()
            || fg.value_points_to_object_ids_of(func_id, value_id).len() == 1;
        if !precise {
            continue;
        }
        if let Some(ty) = fg.value_types.get(&(func_id, value_id)) {
            if looks_like_project_callable_type(ty) {
                out.push(ty.clone());
            }
        }
    }
    for (func_id, _index, value_id) in &summary.params {
        let func_id = FunctionId(*func_id);
        let value_id = ValueId(*value_id);
        let precise = precise_value_object_id(fg, func_id, value_id).is_some()
            || fg.value_points_to_object_ids_of(func_id, value_id).len() == 1;
        if !precise {
            continue;
        }
        if let Some(ty) = fg.value_types.get(&(func_id, value_id)) {
            if looks_like_project_callable_type(ty) {
                out.push(ty.clone());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn looks_like_project_callable_type(name: &str) -> bool {
    !name.is_empty()
        && name.contains('.')
        && !name.contains('<')
        && !name.ends_with("#ret")
        && name
            .split('.')
            .next_back()
            .is_some_and(|tail| tail.chars().next().is_some_and(|ch| ch.is_ascii_lowercase() || ch == '_'))
}

fn connect_rule_summaries(fg: &mut FlowGraph, rules: &RuleSet, func: FunctionId, inst: InstId, meta: &CallMeta) {
    let Some(call_info) = meta.as_call_info() else {
        return;
    };

    for rule in &rules.propagators {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            connect_flow_specs(
                fg,
                func,
                inst,
                &call_info.callee_name,
                &rule.id,
                &rule.flows,
            );
        }
    }
    for rule in &rules.summaries {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            connect_flow_specs(
                fg,
                func,
                inst,
                &call_info.callee_name,
                &rule.id,
                &rule.flows,
            );
        }
    }
}

fn connect_flow_specs(
    fg: &mut FlowGraph,
    func: FunctionId,
    inst: InstId,
    callee_name: &str,
    rule_id: &str,
    flows: &[FlowSpec],
) {
    for flow in flows {
        let from = get_or_create_call_port(
            fg,
            func,
            inst,
            flow.from.clone(),
            Some(callee_name.to_string()),
        );
        let to = get_or_create_call_port(
            fg,
            func,
            inst,
            flow.to.clone(),
            Some(callee_name.to_string()),
        );
        fg.graph.add_edge(
            from,
            to,
            FlowEdge {
                kind: EdgeKind::Summary {
                    rule_id: rule_id.to_string(),
                },
            },
        );
    }
}

fn attach_rule_sources_and_sinks(
    fg: &mut FlowGraph,
    rules: &RuleSet,
    func: FunctionId,
    inst: InstId,
    meta: &CallMeta,
) {
    let Some(call_info) = meta.as_call_info() else {
        return;
    };

    for rule in &rules.sources {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            let src = fg.graph.add_node(FlowNode::SyntheticSource {
                func,
                inst,
                rule_id: rule.id.clone(),
                kind: rule.kind.clone(),
                out: rule.out.clone(),
            });
            fg.synthetic_sources.push(src);
            let out_port = get_or_create_call_port(
                fg,
                func,
                inst,
                rule.out.clone(),
                Some(call_info.callee_name.clone()),
            );
            fg.graph.add_edge(
                src,
                out_port,
                FlowEdge {
                    kind: EdgeKind::Source {
                        rule_id: rule.id.clone(),
                    },
                },
            );
        }
    }

    for rule in &rules.sinks {
        if language_matches(&rule.language, &fg.language) && rule.matcher.matches_call(&call_info) {
            for input in &rule.inputs {
                let sink = fg.graph.add_node(FlowNode::SyntheticSink {
                    func,
                    inst,
                    rule_id: rule.id.clone(),
                    kind: rule.kind.clone(),
                    input: input.clone(),
                });
                fg.synthetic_sinks.push(sink);
                let in_port = get_or_create_call_port(
                    fg,
                    func,
                    inst,
                    input.clone(),
                    Some(call_info.callee_name.clone()),
                );
                fg.graph.add_edge(
                    in_port,
                    sink,
                    FlowEdge {
                        kind: EdgeKind::Sink {
                            rule_id: rule.id.clone(),
                        },
                    },
                );
            }
        }
    }
}

fn get_or_create_call_port(
    fg: &mut FlowGraph,
    func: FunctionId,
    inst: InstId,
    port: Port,
    callee_name: Option<String>,
) -> NodeIndex {
    if let Some(existing) = fg.call_ports.get(&(func, inst, port.clone())).copied() {
        if let Some(name) = callee_name {
            if let FlowNode::CallPort { callee_name: slot, .. } = &mut fg.graph[existing] {
                if slot.is_none() {
                    *slot = Some(name);
                }
            }
        }
        return existing;
    }
    let node = fg.graph.add_node(FlowNode::CallPort {
        func,
        inst,
        port: port.clone(),
        callee_name,
    });
    fg.call_ports.insert((func, inst, port), node);
    node
}

fn static_callee_name(call: &CallInst) -> Option<String> {
    match &call.callee {
        Callee::Static(name) => Some(name.clone()),
        Callee::Dynamic(_) | Callee::Unknown => None,
    }
}

fn build_call_meta(fg: &FlowGraph, func: &Function, inst: InstId, call: &CallInst, span: Span) -> CallMeta {
    let callee_name = static_callee_name(call);
    let mut receiver_type = call
        .receiver
        .and_then(|value| fg.value_types.get(&(func.id, value)).cloned());
    let mut method_name = None;

    if let Some(name) = callee_name.as_deref() {
        let info = CallInfo::from_callee_name(name);
        if receiver_type.is_none() {
            receiver_type = info.receiver_type;
        }
        method_name = info.method_name;
    }

    let receiver_type_candidates = receiver_type
        .as_deref()
        .map(|ty| expand_receiver_type_candidates(&fg.type_hierarchy, ty))
        .unwrap_or_default();
    let arg_types = call
        .args
        .iter()
        .map(|value| fg.value_types.get(&(func.id, *value)).cloned())
        .collect::<Vec<_>>();
    let arg_type_candidates = arg_types
        .iter()
        .map(|ty| {
            ty.as_deref()
                .map(|name| expand_receiver_type_candidates(&fg.type_hierarchy, name))
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();

    CallMeta {
        func: func.id,
        inst,
        function_name: func.name.clone(),
        callee_name,
        receiver_type,
        receiver_type_candidates,
        method_name,
        arg_count: call.args.len(),
        arg_types,
        arg_type_candidates,
        span,
    }
}

fn expand_receiver_type_candidates(type_hierarchy: &HashMap<String, Vec<String>>, ty: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![ty.to_string()];
    while let Some(cur) = stack.pop() {
        if out.iter().any(|existing| existing == &cur) {
            continue;
        }
        if let Some(parents) = type_hierarchy.get(&cur) {
            for parent in parents {
                stack.push(parent.clone());
            }
        }
        out.push(cur);
    }
    out
}


#[cfg(test)]
mod tests {
    use super::{build, ContextSensitivity, DemandEngine, DemandQuery, DemandSeed, EdgeKind, FlowEdge, FlowGraph, FlowNode, QueryBudgetProfile, SparseDirection};
    use uniflow_hir::Language;
    use uniflow_lang_python::{parse_project_sources, PythonParser};
    use uniflow_lowering::lower_program;
    use uniflow_parser_core::SourceParser;
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    use uniflow_ir::{FunctionId, InstId, InstKind, ValueId};
    use uniflow_rules::{Port, RuleSet};

    #[test]
    fn resolves_dynamic_callbacks_returned_from_project_functions() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def choose():
    return load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import choose

def handle(cmd):
    cb = choose()
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }
    #[test]
    fn binds_lambda_capture_values_into_internal_calls() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let lambda = ir.functions.iter().find(|func| func.name.contains("__lambda_")).expect("lambda function");
        let capture_param = fg.function_params.get(&(lambda.id, 1)).copied().expect("capture param node");
        let mut saw_capture_binding = false;
        for edge in fg.graph.edges_directed(capture_param, Direction::Incoming) {
            if !matches!(edge.weight().kind, EdgeKind::ActualToFormal) {
                continue;
            }
            if let FlowNode::FieldCell { field, .. } = &fg.graph[edge.source()] {
                if field == "__capture__cmd" {
                    saw_capture_binding = true;
                    break;
                }
            }
        }
        assert!(saw_capture_binding);
    }

    #[test]
    fn resolves_dynamic_calls_through_local_lambdas() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name.contains("__lambda_")));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_nested_functions() {
        let src = r#"
def choose(cmd):
    def inner(x):
        return cmd
    return inner

def handle(cmd):
    cb = choose(cmd)
    return cb("safe")
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "app.choose.inner"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_field_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass

def install(svc):
    svc.cb = load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, install

def handle(cmd):
    svc = Service()
    install(svc)
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_object_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass

def prepare(svc):
    svc.cb = load
    return svc
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, prepare

def handle(cmd):
    svc = Service()
    ready = prepare(svc)
    return ready.cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_index_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def install(handlers):
    handlers[0] = load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import install

def handle(cmd):
    handlers = [None]
    install(handlers)
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_field_projections() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass

def pick_cb(svc):
    return svc.cb
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, pick_cb, load

def handle(cmd):
    svc = Service()
    svc.cb = load
    cb = pick_cb(svc)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_index_projections() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def pick_cb(handlers):
    return handlers[0]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import pick_cb, load

def handle(cmd):
    handlers = [load]
    cb = pick_cb(handlers)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_nested_interprocedural_object_graphs() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass

def install(svc):
    svc.inner.cb = load
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Node, Service, install

def handle(cmd):
    svc = Service()
    svc.inner = Node()
    install(svc)
    return svc.inner.cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn keeps_index_callback_slots_precise_across_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def pick_cb(handlers):
    return handlers[0]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop, pick_cb

def handle(cmd):
    handlers = [noop, load]
    cb = pick_cb(handlers)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.noop"));
        assert!(!resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn keeps_interprocedural_index_callback_slots_precise() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def install(handlers):
    handlers[1] = load

def prepare(handlers):
    handlers[0] = noop
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import install, prepare

def handle(cmd):
    handlers = [None, None]
    install(handlers)
    prepare(handlers)
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.noop"));
        assert!(!resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_returned_nested_field_paths() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass

def pick_cb(svc):
    return svc.inner.cb
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Node, Service, pick_cb, load

def handle(cmd):
    svc = Service()
    svc.inner = Node()
    svc.inner.cb = load
    cb = pick_cb(svc)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_nested_field_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Node:
    pass

class Service:
    pass

def install(svc):
    svc.inner.cb = load

def pick_cb(svc):
    return svc.inner.cb
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Node, Service, install, pick_cb

def handle(cmd):
    svc = Service()
    svc.inner = Node()
    install(svc)
    cb = pick_cb(svc)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }


    #[test]
    fn resolves_dynamic_calls_through_appended_list_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop

def handle(cmd):
    handlers = []
    handlers.append(noop)
    handlers.append(load)
    cb = handlers.pop()
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_dict_get_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    mapping = {}
    mapping[\"cb\"] = load
    cb = mapping.get(\"cb\")
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_dict_update_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop

def handle(cmd):
    mapping = {\"other\": noop}
    mapping.update({\"cb\": load})
    cb = mapping.get(\"cb\")
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_dynamic_calls_through_interprocedural_setdefault_callbacks() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def install(mapping):
    mapping.setdefault(\"cb\", load)
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import install

def handle(cmd):
    mapping = {}
    install(mapping)
    cb = mapping.get(\"cb\")
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }


    #[test]
    fn resolves_dynamic_calls_through_precise_list_literal_slot_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def pick_cb(handlers):
    return handlers[1]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop, pick_cb

def handle(cmd):
    handlers = [noop, load]
    cb = pick_cb(handlers)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
        assert!(!resolved.iter().any(|name| name == "repo.noop"));
    }

    #[test]
    fn resolves_dynamic_calls_through_precise_dict_literal_slot_returns() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

def noop(cmd):
    return \"safe\"

def pick_cb(mapping):
    return mapping[\"cb\"]
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load, noop, pick_cb

def handle(cmd):
    mapping = {\"safe\": noop, \"cb\": load}
    cb = pick_cb(mapping)
    return cb(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
        assert!(!resolved.iter().any(|name| name == "repo.noop"));
    }


    #[test]
    fn resolves_super_property_backed_receiver_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd

class Base:
    @property
    def repo(self):
        return Repo()

class Service(Base):
    def handle(self, cmd):
        return super().repo.run(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("repo.Service.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_descriptor_backed_callable_fields() {
        let src = r#"
def load(cmd):
    return cmd

class LoaderDescriptor:
    def __get__(self, obj, owner):
        return load

class Service:
    handler = LoaderDescriptor()

    def handle(self, cmd):
        cb = self.handler
        return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("Service.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
    }

    #[test]
    fn resolves_dynamic_calls_through_callable_objects() {
        let src = r#"
class Loader:
    def __call__(self, cmd):
        return cmd

def handle(cmd):
    loader = Loader()
    return loader(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "Loader.__call__"));
    }

    #[test]
    fn resolves_property_backed_receiver_calls() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "class Repo:
    def run(self, cmd):
        return cmd

class Service:
    @property
    def repo(self):
        return Repo()
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service

def handle(cmd):
    svc = Service()
    return svc.repo.run(cmd)
".to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_getattr_receiver_calls_after_setattr() {
        let src = r#"
import os

class Repo:
    def run(self, cmd):
        return os.system(cmd)

class Service:
    pass

def handle(cmd):
    svc = Service()
    setattr(svc, "repo", Repo())
    return getattr(svc, "repo").run(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "Repo.run" || name.ends_with("Repo.run")));
    }

    #[test]
    fn resolves_dynamic_calls_through_getattr_callable_fields() {
        let src = r#"
def load(cmd):
    return cmd

class Holder:
    pass

def handle(cmd):
    holder = Holder()
    setattr(holder, "cb", load)
    cb = getattr(holder, "cb")
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
    }

    #[test]
    fn copies_precise_slots_through_list_constructor_calls() {
        let src = r#"
def load(cmd):
    return cmd

def noop(cmd):
    return "safe"

def handle(cmd):
    handlers = [noop, load]
    alias = list(handlers)
    cb = alias[1]
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
        assert!(!resolved.iter().any(|name| name == "noop"));
    }

    #[test]
    fn resolves_calls_through_importlib_modules() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def load(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import importlib

def handle(cmd):
    mod = importlib.import_module("repo")
    return mod.load(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }

    #[test]
    fn resolves_calls_through_partial_aliases() {
        let src = r#"
from functools import partial

def load(cmd):
    return cmd

def handle(cmd):
    cb = partial(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "load" || name.ends_with(".load")));
    }

    #[test]
    fn resolves_calls_through_module_and_class_monkey_patches() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def old(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"import repo

def load(cmd):
    return cmd

class Service:
    pass

repo.run = load
Service.run = load

def handle_module(cmd):
    return repo.run(cmd)

def handle_service(cmd):
    factory = Service
    svc = factory()
    return svc.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle_module = ir.find_function_by_name("app.handle_module").expect("handle_module function");
        let resolved_module = handle_module
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_module.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_module.iter().any(|name| name == "app.load"));

        let handle_service = ir.find_function_by_name("app.handle_service").expect("handle_service function");
        let resolved_service = handle_service
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_service.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_service.iter().any(|name| name == "app.load"));
    }

    #[test]
    fn resolves_calls_through_static_globals_and_vars_namespace_accesses() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def load(cmd):
    return cmd

globals()["load_alias"] = load

class Service:
    def __init__(self):
        self.__dict__["repo"] = Repo()

    def handle(self, cmd):
        cb = globals()["load_alias"]
        return cb(vars(self)["repo"].run(cmd))
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.Service.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "app.load"));
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_context_manager_enter_aliases() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

class RepoManager:
    def __enter__(self):
        return Repo()

    def __exit__(self, exc_type, exc, tb):
        return None

def handle(cmd):
    with RepoManager() as repo:
        return repo.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_static_namespace_method_helpers() {
        let project = build_python_project(
            &[
                (
                    "examples/python_namespace_method_helpers/repo.py",
                    "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n",
                ),
                (
                    "examples/python_namespace_method_helpers/app.py",
                    "from repo import Repo, load\n\nglobals()[\"cb\"] = load\nglobals()[\"factory\"] = Repo\n\ndef handle_get(cmd):\n    cb = globals().get(\"cb\")\n    return cb(cmd)\n\ndef handle_pop(cmd):\n    cb = globals().pop(\"cb\")\n    return cb(cmd)\n\ndef handle_setdefault(cmd):\n    cb = globals().setdefault(\"cb2\", load)\n    return cb(cmd)\n\ndef handle_factory(cmd):\n    factory = globals().get(\"factory\")\n    repo = factory()\n    return repo.run(cmd)\n",
                ),
            ],
            &["repo.load", "repo.Repo.run"],
        );
        let fg = build_flow(&project);
        let ir = &project.ir;
        for func_name in ["app.handle_get", "app.handle_pop", "app.handle_setdefault"] {
            let func = ir.find_function_by_name(func_name).expect("function");
            let resolved = func
                .body
                .iter()
                .filter_map(|inst| fg.resolved_internal_targets.get(&(func.id, inst.id)).cloned())
                .flatten()
                .collect::<Vec<_>>();
            assert!(resolved.iter().any(|name| name == "repo.load"), "missing repo.load for {func_name}: {resolved:?}");
        }
        let handle_factory = ir.find_function_by_name("app.handle_factory").expect("handle_factory");
        let resolved_factory = handle_factory
            .body
            .iter()
            .filter_map(|inst| fg.resolved_internal_targets.get(&(handle_factory.id, inst.id)).cloned())
            .flatten()
            .collect::<Vec<_>>();
        assert!(resolved_factory.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run: {resolved_factory:?}");
    }

    #[test]
    fn resolves_calls_through_static_eval_and_exec_paths() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

def load(cmd):
    return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo, load

def handle_eval(cmd):
    cb = eval("load")
    return cb(cmd)

def handle_exec(cmd):
    exec("repo = Repo()\ncb = repo.run")
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());

        let handle_eval = ir.find_function_by_name("app.handle_eval").expect("handle_eval function");
        let resolved_eval = handle_eval
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_eval.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_eval.iter().any(|name| name == "repo.load"));

        let handle_exec = ir.find_function_by_name("app.handle_exec").expect("handle_exec function");
        let resolved_exec = handle_exec
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle_exec.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved_exec.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_type_identity_guards() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def handle(obj, cmd):
    if type(obj) is Repo:
        return obj.run(cmd)
    return cmd
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"));
    }

    #[test]
    fn resolves_calls_through_generator_yields() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"def load(cmd):
    return cmd

def callbacks():
    yield load
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import callbacks

def handle(cmd):
    cb = next(callbacks())
    return cb(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.load"));
    }


    #[test]
    fn resolves_calls_through_map_and_sorted_helpers() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Repo

def build(x):
    return Repo()

def handle_map(cmd):
    repo = next(map(build, [1]))
    return repo.run(cmd)

def handle_sorted(cmd):
    repo = sorted([Repo()])[0]
    return repo.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());

        for function_name in ["app.handle_map", "app.handle_sorted"] {
            let function = ir.find_function_by_name(function_name).expect("function");
            let resolved = function
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter())
                .find_map(|inst| fg.resolved_internal_targets.get(&(function.id, inst.id)).cloned())
                .unwrap_or_default();
            assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run for {function_name}: {resolved:?}");
        }
    }



    #[test]
    fn resolves_calls_through_structured_module_level_bindings() {
        let project = build_python_project(
            &[
                (
                    "examples/python_structured_module_bindings/repo.py",
                    "def load(cmd):\n    return cmd\n\nclass Repo:\n    def run(self, cmd):\n        return cmd\n",
                ),
                (
                    "examples/python_structured_module_bindings/app.py",
                    "from repo import Repo, load\n\nclass Service:\n    pass\n\nif flag:\n    cb = load\n    Service.repo = Repo()\nelse:\n    cb = load\n    Service.repo = Repo()\n\ndef handle(cmd):\n    return cb(Service.repo.run(cmd))\n",
                ),
            ],
            &["repo.load", "repo.Repo.run"],
        );
        let fg = build_flow(&project);
        let handle = project.ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .body
            .iter()
            .filter_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .flatten()
            .collect::<Vec<_>>();
        assert!(resolved.iter().any(|name| name == "repo.load"), "missing repo.load: {resolved:?}");
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run: {resolved:?}");
    }

    #[test]
    fn resolves_calls_through_structured_module_try_imports() {
        let project = build_python_project(
            &[
                (
                    "examples/python_structured_module_try_imports/repo.py",
                    "def load(cmd):\n    return cmd\n",
                ),
                (
                    "examples/python_structured_module_try_imports/app.py",
                    "try:\n    from repo import load as cb\nexcept ImportError:\n    from repo import load as cb\n\ndef handle(cmd):\n    return cb(cmd)\n",
                ),
            ],
            &["repo.load"],
        );
        let fg = build_flow(&project);
        let handle = project.ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .body
            .iter()
            .filter_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .flatten()
            .collect::<Vec<_>>();
        assert!(resolved.iter().any(|name| name == "repo.load"), "missing repo.load: {resolved:?}");
    }

    #[test]
    fn resolves_calls_through_constructor_init_summary_replay() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def __init__(self):
        self.repo = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle(cmd):
    svc = Service()
    return svc.repo.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let resolved = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| fg.resolved_internal_targets.get(&(handle.id, inst.id)).cloned())
            .unwrap_or_default();
        assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run: {resolved:?}");
    }

    #[test]
    fn resolves_calls_through_method_summary_side_effect_replay() {
        let entries = vec![
            (
                "repo.py".to_string(),
                r#"class Repo:
    def run(self, cmd):
        return cmd

class Service:
    def install(self):
        self.repo = Repo()

    @classmethod
    def install_class(cls):
        cls.shared = Repo()
"#.to_string(),
            ),
            (
                "app.py".to_string(),
                r#"from repo import Service

def handle_instance(cmd):
    svc = Service()
    svc.install()
    return svc.repo.run(cmd)

def handle_class(cmd):
    Service.install_class()
    return Service.shared.run(cmd)
"#.to_string(),
            ),
        ];
        let hir = parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        for function_name in ["app.handle_instance", "app.handle_class"] {
            let function = ir.find_function_by_name(function_name).expect("function");
            let resolved = function
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter())
                .find_map(|inst| fg.resolved_internal_targets.get(&(function.id, inst.id)).cloned())
                .unwrap_or_default();
            assert!(resolved.iter().any(|name| name == "repo.Repo.run"), "missing repo.Repo.run for {function_name}: {resolved:?}");
        }
    }


    #[test]
    fn tracks_constructor_identity_sites_as_distinct_roots() {
        let src = r#"
class Repo:
    def __init__(self):
        self.value = 1

def handle():
    left = Repo()
    right = Repo()
    return left, right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let constructor_dsts = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => call.dst,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(constructor_dsts.len() >= 2);
        let left_root = fg.object_identity_roots.get(&(handle.id, constructor_dsts[0])).copied();
        let right_root = fg.object_identity_roots.get(&(handle.id, constructor_dsts[1])).copied();
        assert!(left_root.is_some() && right_root.is_some());
        assert_ne!(left_root, right_root);
    }

    #[test]
    fn materializes_sparse_data_adjacency_indexes() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    cb = load
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let stats = fg.stats();
        assert!(stats.sparse_data_edges > 0);
        assert!(!fg.sparse_successors.is_empty());
        assert!(!fg.sparse_predecessors.is_empty());
    }

    #[test]
    fn sparse_reachability_walks_back_to_callable_seed() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(value) => Some(value),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic callee value");
        let start = fg.values.get(&(handle.id, dynamic_call)).copied().expect("start node");
        let reachable = fg.sparse_reachable_nodes(&[start], false, 8);
        assert!(reachable.iter().any(|idx| match &fg.graph[*idx] {
            FlowNode::Value { func, value } => fg.value_types.get(&(*func, *value)).is_some_and(|ty| ty == "load"),
            FlowNode::Param { func, value, .. } => fg.value_types.get(&(*func, *value)).is_some_and(|ty| ty == "load"),
            _ => false,
        }));
    }

    #[test]
    fn propagates_object_identity_across_receiver_and_return() {
        let src = r#"
class Repo:
    def __init__(self):
        self.value = 1

class Service:
    def __init__(self, repo: Repo):
        self.repo = repo

    def current(self):
        return self.repo

def handle():
    repo = Repo()
    service = Service(repo)
    current = service.current()
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let method = ir.find_function_by_name("Service.current").expect("method");
        let repo_constructor = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => call.dst,
                _ => None,
            })
            .next()
            .expect("repo dst");
        let service_constructor = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Service")) => call.dst,
                _ => None,
            })
            .next()
            .expect("service dst");
        let current_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("current")) => call.dst,
                _ => None,
            })
            .next()
            .expect("current dst");
        let repo_site = value_identity_site(&fg, handle.id, repo_constructor).map(|s| s.to_string());
        let service_site = value_identity_site(&fg, handle.id, service_constructor).map(|s| s.to_string());
        let self_param = method.params[0];
        let self_site = value_identity_site(&fg, method.id, self_param).map(|s| s.to_string());
        let current_site = value_identity_site(&fg, handle.id, current_value).map(|s| s.to_string());
        assert!(repo_site.is_some());
        assert!(service_site.is_some());
        assert_eq!(service_site, self_site);
        assert_eq!(repo_site, current_site);
    }

    #[test]
    fn demand_summary_cache_materializes_and_reuses_entries() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(value) => Some(value),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic callee value");
        let first = fg.demand_value_summary(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        let second = fg.demand_value_summary(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        assert_eq!(first.traversal.visited, second.traversal.visited);
        assert!(!fg.demand_summary_cache.borrow().is_empty());
    }

    #[test]
    fn demand_summary_collects_sparse_layers() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(value) => Some(value),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic callee value");
        let summary = fg.demand_value_summary(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        assert!(!summary.traversal.visited.is_empty());
        assert!(!summary.traversal.layers.is_empty());
        assert!(!summary.values.is_empty() || !summary.params.is_empty());
    }


    #[test]
    fn demand_reachable_values_exposes_sparse_value_hits() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let dynamic_call = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(value) => Some(value),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic callee value");
        let reachable = fg.demand_reachable_values(handle.id, dynamic_call, SparseDirection::Backward, 8, 128);
        assert!(!reachable.is_empty());
        assert!(reachable.iter().any(|(func, value)| fg.value_types.get(&(*func, *value)).is_some_and(|ty| ty == "load")));
    }

    #[test]
    fn demand_reaches_value_detects_alias_back_edges() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    cb = load
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let load = ir.find_function_by_name("load").expect("load function");
        let dynamic_call = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(value) => Some(value),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic callee value");
        let load_param = load.params[0];
        assert!(fg.demand_reaches_value(handle.id, dynamic_call, load.id, load_param, SparseDirection::Backward, 8, 128));
    }

    #[test]
    fn distinct_constructor_sites_do_not_cross_bridge_projected_fields() {
        let src = r#"
class Repo:
    def __init__(self):
        self.value = 1

def handle():
    left = Repo()
    right = Repo()
    left.inner = left
    right.inner = right
    return left, right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let constructor_dsts = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => call.dst,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(constructor_dsts.len() >= 2);
        assert!(!heap_projection_values_compatible(
            &fg,
            handle.id,
            constructor_dsts[0],
            handle.id,
            constructor_dsts[1],
        ));
    }


    #[test]
    fn demand_seed_summary_cache_reuses_multi_seed_queries() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let v1 = ValueId(1);
        let v2 = ValueId(2);
        let v3 = ValueId(3);
        let n1 = fg.ensure_value(f, v1);
        let n2 = fg.ensure_value(f, v2);
        let n3 = fg.ensure_value(f, v3);
        fg.graph.add_edge(n1, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let first = fg.demand_summary_from_seeds(&[n1, n2], SparseDirection::Forward, 4, 32);
        let second = fg.demand_summary_from_seeds(&[n2, n1], SparseDirection::Forward, 4, 32);
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_seed_summary_cache.borrow().is_empty());
    }


    #[test]
    fn demand_call_summary_cache_reuses_call_queries() {
        let src = r#"
def load(cmd):
    return cmd

def handle(cmd):
    cb = load
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(_) => Some(inst.id),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic call inst");
        let first = fg
            .demand_call_summary(handle.id, inst, SparseDirection::Backward, 8, 128)
            .expect("call summary");
        let second = fg
            .demand_call_summary(handle.id, inst, SparseDirection::Backward, 8, 128)
            .expect("call summary");
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_call_summary_cache.borrow().is_empty());
    }

    #[test]
    fn loaded_field_object_preserves_identity_site() {
        let src = r#"
class Repo:
    pass

class Service:
    pass

def handle():
    repo = Repo()
    service = Service()
    service.repo = repo
    current = service.repo
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let mut repo_constructor = None;
        let mut current_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_constructor = call.dst;
                }
                uniflow_ir::InstKind::LoadField { field, dst, .. } if field == "repo" => {
                    current_value = Some(*dst);
                }
                _ => {}
            }
        }
        let repo_constructor = repo_constructor.expect("repo constructor");
        let current_value = current_value.expect("loaded field value");
        let repo_site = value_identity_site(&fg, handle.id, repo_constructor).map(|s| s.to_string());
        let current_site = value_identity_site(&fg, handle.id, current_value).map(|s| s.to_string());
        assert_eq!(repo_site, current_site);
    }

    #[test]
    fn demand_reaches_any_value_detects_one_of_multiple_targets() {
        let src = r#"
def load(cmd):
    return cmd

def wrap(cb):
    return cb

def handle(cmd):
    cb = wrap(load)
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let load = ir.find_function_by_name("load").expect("load function");
        let dynamic_call = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call) => match call.callee {
                    uniflow_ir::Callee::Dynamic(value) => Some(value),
                    _ => None,
                },
                _ => None,
            })
            .expect("dynamic callee value");
        assert!(fg.demand_reaches_any_value(
            handle.id,
            dynamic_call,
            &[(load.id, load.params[0]), (handle.id, ValueId(9999))],
            SparseDirection::Backward,
            8,
            128,
        ));
    }

    #[test]
    fn demand_call_port_summary_tracks_receiver_specific_queries() {
        let src = r#"
class Repo:
    pass

def use(repo):
    return repo

def handle():
    repo = Repo()
    return use(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let use_fn = ir.find_function_by_name("use").expect("use function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("use")) => Some(inst.id),
                _ => None,
            })
            .expect("use call inst");
        let summary = fg
            .demand_call_port_summary(handle.id, call_inst, Port::Arg(0), SparseDirection::Forward, 8, 128)
            .expect("call port summary");
        assert!(summary
            .params
            .iter()
            .any(|(func, index, _value)| *func == use_fn.id.0 && *index == 0));
    }

    #[test]
    fn demand_call_port_reaches_value_detects_formal_flow() {
        let src = r#"
def wrap(value):
    return value

def handle(cmd):
    return wrap(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let wrap = ir.find_function_by_name("wrap").expect("wrap function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("wrap")) => Some(inst.id),
                _ => None,
            })
            .expect("wrap call inst");
        assert!(fg.demand_call_port_reaches_value(
            handle.id,
            call_inst,
            Port::Arg(0),
            wrap.id,
            wrap.params[0],
            SparseDirection::Forward,
            8,
            128,
        ));
    }

    #[test]
    fn python_container_get_default_preserves_object_identity() {
        let src = r#"
class Repo:
    pass

def handle(cache):
    repo = Repo()
    current = cache.get("repo", repo)
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("handle").expect("handle function");
        let mut repo_constructor = None;
        let mut current_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_constructor = call.dst;
                }
                uniflow_ir::InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Method(ref name) if name == "get") => {
                    current_value = call.dst;
                }
                _ => {}
            }
        }
        let repo_constructor = repo_constructor.expect("repo constructor");
        let current_value = current_value.expect("current value");
        let repo_site = value_identity_site(&fg, handle.id, repo_constructor).map(|s| s.to_string());
        let current_site = value_identity_site(&fg, handle.id, current_value).map(|s| s.to_string());
        assert_eq!(repo_site, current_site);
    }


    #[test]
    fn sparse_fixpoint_traversal_collapses_cycle_layers() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let n1 = fg.ensure_value(f, ValueId(1));
        let n2 = fg.ensure_value(f, ValueId(2));
        let n3 = fg.ensure_value(f, ValueId(3));
        fg.graph.add_edge(n1, n2, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n1, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let traversal = fg.sparse_fixpoint_traversal(&[n1], SparseDirection::Forward, 8, 64);
        assert_eq!(traversal.layers.len(), 2);
        assert_eq!(traversal.layers[0].len(), 2);
        assert!(traversal.layers[1].contains(&n3.index()));
    }

    #[test]
    fn demand_fixpoint_summary_cache_reuses_cycle_queries() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let n1 = fg.ensure_value(f, ValueId(1));
        let n2 = fg.ensure_value(f, ValueId(2));
        let n3 = fg.ensure_value(f, ValueId(3));
        fg.graph.add_edge(n1, n2, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n1, FlowEdge { kind: EdgeKind::Assign });
        fg.graph.add_edge(n2, n3, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let first = fg.demand_fixpoint_summary_from_seeds(&[n1], SparseDirection::Forward, 8, 64);
        let second = fg.demand_fixpoint_summary_from_seeds(&[n1], SparseDirection::Forward, 8, 64);
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_fixpoint_summary_cache.borrow().is_empty());
    }

    #[test]
    fn demand_fixpoint_call_port_summary_tracks_receiver_specific_queries() {
        let src = r#"
def sink(value):
    return value

def handle(repo, cmd):
    return repo.run(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .body
            .iter()
            .find_map(|inst| matches!(&inst.kind, InstKind::Call(_)).then_some(inst.id))
            .expect("call inst");
        let receiver_value = handle.params[0];
        let summary = fg
            .demand_fixpoint_call_port_summary(handle.id, call_inst, Port::Receiver, SparseDirection::Backward, 8, 128)
            .expect("fixpoint call port summary");
        assert!(summary.params.iter().any(|(func, index, value)| *func == handle.id.0 && *index == 0 && *value == receiver_value.0));
    }

    #[test]
    fn demand_fixpoint_call_port_reaches_value_detects_target_param() {
        let src = r#"
def handle(repo, cmd):
    return repo.run(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .body
            .iter()
            .find_map(|inst| matches!(&inst.kind, InstKind::Call(_)).then_some(inst.id))
            .expect("call inst");
        assert!(fg.demand_fixpoint_call_port_reaches_value(
            handle.id,
            call_inst,
            Port::Receiver,
            handle.id,
            handle.params[0],
            SparseDirection::Backward,
            8,
            128,
        ));
    }


    #[test]
    fn demand_query_with_heap_overlay_reaches_nested_object_values() {
        let src = r#"
class Holder:
    pass

def handle(repo):
    holder = Holder()
    holder.repo = repo
    return holder
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let holder = handle
            .body
            .iter()
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call) => call.dst,
                _ => None,
            })
            .expect("holder dst");
        let plain = DemandQuery {
            seeds: vec![DemandSeed::Value {
                func: handle.id.0,
                value: holder.0,
            }],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: false,
        };
        let heap = DemandQuery {
            seeds: vec![DemandSeed::Value {
                func: handle.id.0,
                value: holder.0,
            }],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        assert!(!fg.demand_query_reaches_value(&plain, handle.id, handle.params[0], 8, 128));
        assert!(fg.demand_query_reaches_value(&heap, handle.id, handle.params[0], 8, 128));
    }

    #[test]
    fn demand_query_cache_reuses_equivalent_query_shapes() {
        let mut fg = FlowGraph::default();
        fg.language = Language::Python;
        let f = FunctionId(1);
        let v1 = ValueId(1);
        let v2 = ValueId(2);
        let n1 = fg.ensure_value(f, v1);
        let n2 = fg.ensure_value(f, v2);
        fg.graph.add_edge(n1, n2, FlowEdge { kind: EdgeKind::Assign });
        fg.materialize_sparse_data_adjacency();
        let query = DemandQuery {
            seeds: vec![DemandSeed::Value {
                func: f.0,
                value: v1.0,
            }],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Fixpoint,
            include_heap: false,
        };
        let first = fg.demand_query_summary(&query, 4, 32).expect("first query");
        let second = fg.demand_query_summary(&query, 4, 32).expect("second query");
        assert_eq!(first.values, second.values);
        assert!(!fg.demand_query_summary_cache.borrow().is_empty());
    }

    #[test]
    fn repeated_loads_do_not_back_alias_through_cell_only_load_history() {
        let src = r#"
class Box:
    pass

def handle(repo):
    box = Box()
    box.repo = repo
    first = box.repo
    second = box.repo
    return second
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let loads = handle
            .body
            .iter()
            .filter_map(|inst| match &inst.kind {
                InstKind::LoadField { field, dst, .. } if field == "repo" => Some(*dst),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(loads.len() >= 2);
        assert!(!fg.demand_reaches_value(
            handle.id,
            loads[1],
            handle.id,
            loads[0],
            SparseDirection::Backward,
            8,
            128,
        ));
    }


    #[test]
    fn strong_update_prefers_latest_unique_object_store() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle():
    box = Box()
    first = Repo()
    second = Other()
    box.item = first
    box.item = second
    current = box.item
    return current
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut first_store = None;
        let mut second_store = None;
        let mut current = None;
        let mut box_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    first_store = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    second_store = call.dst;
                }
                InstKind::LoadField { field, dst, .. } if field == "item" => {
                    current = Some(*dst);
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let first_store = first_store.expect("first store");
        let second_store = second_store.expect("second store");
        let current = current.expect("current value");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        assert!(fg.is_strong_update_cell(cell));
        assert!(fg.demand_reaches_value(
            handle.id,
            current,
            handle.id,
            second_store,
            SparseDirection::Backward,
            8,
            128,
        ));
        assert!(!fg.demand_reaches_value(
            handle.id,
            current,
            handle.id,
            first_store,
            SparseDirection::Backward,
            8,
            128,
        ));
    }

    #[test]
    fn heap_object_overlay_connects_base_cell_and_visible_value() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.item = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_value = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        let box_node = fg.values.get(&(handle.id, box_value)).copied().expect("box node");
        let repo_node = fg.values.get(&(handle.id, repo_value)).copied().expect("repo node");
        assert!(fg.heap_object_successors_of(box_node).contains(&cell));
        assert!(fg.heap_object_successors_of(cell).contains(&repo_node));
        let query = DemandQuery {
            seeds: vec![DemandSeed::Node(cell.index())],
            direction: SparseDirection::Forward,
            engine: DemandEngine::Sparse,
            include_heap: true,
        };
        assert!(fg.demand_query_reaches_value(&query, handle.id, repo_value, 4, 64));
    }

    #[test]
    fn call_context_key_tracks_exact_callee_funcs() {
        let src = r#"
class Repo:
    pass

class Service:
    def echo(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let call = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("echo"))
            .map(|(key, _)| *key)
            .expect("call");
        let ctx = fg.call_context_key(call.0, call.1).expect("context");
        assert!(!ctx.callee_funcs.is_empty());
        let service_echo = ir.find_function_by_name("app.Service.echo").expect("callee");
        assert!(ctx.callee_funcs.iter().any(|func| *func == service_echo.id.0));
    }

    #[test]
    fn interprocedural_call_summary_tracks_exact_callee_funcs() {
        let src = r#"
class Repo:
    pass

class Service:
    def echo(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let call = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("echo"))
            .map(|(key, _)| *key)
            .expect("call");
        let summary = fg
            .interprocedural_call_summary(call.0, call.1, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("summary");
        let service_echo = ir.find_function_by_name("app.Service.echo").expect("callee");
        assert!(summary.callee_funcs.iter().any(|func| *func == service_echo.id.0));
        assert!(!summary.port_to_return.is_empty());
    }

    #[test]
    fn materialized_points_to_partitions_and_stats_are_exposed() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.item = repo
    return box.item
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_value = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        assert!(!fg.value_points_to_classes_of(handle.id, repo_value).is_empty());
        assert!(!fg.cell_points_to_classes_of(cell).is_empty());
        let stats = fg.stats();
        assert!(stats.heap_object_edges > 0);
        assert!(stats.points_to_classes > 0);
        assert!(stats.strong_update_cells > 0);
    }

    #[test]
    fn contextual_call_summary_reuses_shared_receiver_and_arg_context() {
        let src = r#"
def echo(repo):
    return repo

def handle(repo):
    first = echo(repo)
    second = echo(repo)
    return second
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_ids = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("echo")) => Some(inst.id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(call_ids.len(), 2);
        let first = fg
            .contextual_call_summary(
                handle.id,
                call_ids[0],
                ContextSensitivity::ReceiverAndArgs,
                SparseDirection::Backward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("first contextual summary");
        let second = fg
            .contextual_call_summary(
                handle.id,
                call_ids[1],
                ContextSensitivity::ReceiverAndArgs,
                SparseDirection::Backward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("second contextual summary");
        assert_eq!(fg.stats().cached_contextual_summaries, 1);
        assert_eq!(first.values, second.values);
        assert_eq!(first.params, second.params);
    }

    #[test]
    fn function_summaries_cache_param_and_return_queries() {
        let src = r#"
def echo(repo):
    return repo

def handle(repo):
    return echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let echo = ir.find_function_by_name("app.echo").expect("echo function");
        let param = fg
            .function_param_summary(
                echo.id,
                0,
                SparseDirection::Forward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("param summary");
        let ret = fg
            .function_return_summary(
                echo.id,
                SparseDirection::Backward,
                8,
                128,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("return summary");
        let _ = fg.function_param_summary(
            echo.id,
            0,
            SparseDirection::Forward,
            8,
            128,
            DemandEngine::Fixpoint,
            true,
        );
        let _ = fg.function_return_summary(
            echo.id,
            SparseDirection::Backward,
            8,
            128,
            DemandEngine::Fixpoint,
            true,
        );
        assert!(fg.stats().cached_function_summaries >= 2);
        assert!(param
            .call_ports
            .iter()
            .any(|(_func, _inst, port)| port.contains("Return"))
            || param.values.iter().any(|(func, _value)| *func == echo.id.0));
        assert!(ret
            .params
            .iter()
            .any(|(func, index, _value)| *func == echo.id.0 && *index == 0)
            || ret.values.iter().any(|(func, _value)| *func == echo.id.0));
    }

    #[test]
    fn cell_write_generations_preserve_store_order() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle():
    box = Box()
    first = Repo()
    second = Other()
    box.item = first
    box.item = second
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut first_store = None;
        let mut second_store = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    first_store = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    second_store = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let first_store = first_store.expect("first store");
        let second_store = second_store.expect("second store");
        let cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "item".to_string()))
            .copied()
            .expect("item cell");
        let generations = fg.cell_write_generations_of(cell);
        assert_eq!(generations.len(), 2);
        assert_eq!(generations[0], (0, handle.id, first_store));
        assert_eq!(generations[1], (1, handle.id, second_store));
        assert!(fg.stats().cell_write_generations >= 2);
    }

    #[test]
    fn load_field_only_sees_prior_visible_store() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle(flag):
    box = Box()
    first = Repo()
    box.item = first
    seen = box.item
    second = Other()
    box.item = second
    return seen
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut seen_value = None;
        let mut first_store = None;
        let mut second_store = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    first_store = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    second_store = call.dst;
                }
                InstKind::LoadField { field, dst, .. } if field == "item" => {
                    seen_value = Some(*dst);
                }
                _ => {}
            }
        }
        let seen_value = seen_value.expect("seen load dst");
        let first_store = first_store.expect("first store");
        let second_store = second_store.expect("second store");
        assert!(fg.value_may_alias(handle.id, seen_value, handle.id, first_store));
        assert!(!fg.value_may_alias(handle.id, seen_value, handle.id, second_store));
    }

    #[test]
    fn alias_queries_respect_points_to_partitions() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Other:
    pass

def handle():
    left = Repo()
    alias = left
    right = Other()
    box = Box()
    box.left = left
    box.right = right
    return alias
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut left = None;
        let mut alias = None;
        let mut right = None;
        let mut box_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    left = call.dst;
                }
                InstKind::Copy { dst, src } if left == Some(*src) => {
                    alias = Some(*dst);
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Other")) => {
                    right = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                _ => {}
            }
        }
        let left = left.expect("left");
        let alias = alias.expect("alias");
        let right = right.expect("right");
        let box_value = box_value.expect("box");
        assert!(fg.value_may_alias(handle.id, left, handle.id, alias));
        assert!(!fg.value_may_alias(handle.id, left, handle.id, right));
        let left_cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "left".to_string()))
            .copied()
            .expect("left cell");
        let right_cell = fg
            .field_cells
            .get(&(handle.id, canonical_heap_value(&fg, handle.id, box_value), "right".to_string()))
            .copied()
            .expect("right cell");
        assert!(!fg.cell_may_alias(left_cell, right_cell));
    }


    #[test]
    fn object_graph_materializes_labels_and_shapes() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.item = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => {
                    box_value = call.dst;
                }
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => {
                    repo_value = call.dst;
                }
                _ => {}
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let repo_node = *fg.values.get(&(handle.id, repo_value)).expect("repo node");
        assert!(fg.object_graph_successors_of(box_node).contains(&repo_node));
        assert_eq!(fg.object_graph_edge_label(box_node, repo_node), Some("field:item"));
        assert!(fg.object_shape_labels_of(box_node).iter().any(|label| label == "field:item"));
    }

    #[test]
    fn interprocedural_call_summary_materializes_internal_return_edges() {
        let src = r#"
def identity(repo):
    return repo

def handle(repo):
    out = identity(repo)
    return out
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| matches!(&inst.kind, InstKind::Call(_)).then_some(inst.id))
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("interprocedural summary");
        assert!(summary.port_to_return.iter().any(|port| port == "Arg(0)"));
        let mut arg_port = None;
        let mut ret_port = None;
        for ((func, inst, port), node) in &fg.call_ports {
            if *func != handle.id || *inst != call_inst {
                continue;
            }
            match port {
                Port::Arg(0) => arg_port = Some(*node),
                Port::Return => ret_port = Some(*node),
                _ => {}
            }
        }
        let arg_port = arg_port.expect("arg port");
        let ret_port = ret_port.expect("return port");
        let has_summary_edge = fg
            .graph
            .edges_directed(arg_port, Direction::Outgoing)
            .any(|edge| edge.target() == ret_port && matches!(edge.weight().kind, EdgeKind::Summary { ref rule_id } if rule_id == "internal:return"));
        assert!(has_summary_edge);
    }

    #[test]
    fn contextual_demand_query_cache_reuses_call_context() {
        let src = r#"
class Repo:
    pass

class Service:
    def run(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.run(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Dynamic(_)) || call.receiver.is_some() => Some(inst.id),
                _ => None,
            })
            .expect("call inst");
        let query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: handle.id.0, inst: call_inst.0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let first = fg
            .contextual_demand_query_summary(&query, ContextSensitivity::ReceiverAndArgs, 16, 4096)
            .expect("first summary");
        let second = fg
            .contextual_demand_query_summary(&query, ContextSensitivity::ReceiverAndArgs, 16, 4096)
            .expect("second summary");
        assert_eq!(first.values, second.values);
        assert!(!fg.contextual_demand_query_cache.borrow().is_empty());
    }

    #[test]
    fn object_shape_paths_capture_nested_fields() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

class Item:
    pass

def handle():
    box = Box()
    repo = Repo()
    item = Item()
    repo.item = item
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let paths = fg.object_shape_paths_of(box_node);
        assert!(paths.iter().any(|path| path == "field:repo"));
        assert!(paths.iter().any(|path| path == "field:repo.field:item"));
        assert!(fg.stats().object_shape_paths >= 2);
    }

    #[test]
    fn function_transfer_summaries_materialize_param_to_return_edges() {
        let src = r#"
def identity(repo):
    return repo
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let identity = ir.find_function_by_name("app.identity").expect("identity function");
        let param = *fg.function_params.get(&(identity.id, 0)).expect("param");
        let ret = *fg.function_returns.get(&identity.id).expect("return");
        let has_summary_edge = fg
            .graph
            .edges_directed(param, Direction::Outgoing)
            .any(|edge| edge.target() == ret && matches!(edge.weight().kind, EdgeKind::Summary { ref rule_id } if rule_id == "internal:function-return"));
        assert!(has_summary_edge);
    }

    #[test]
    fn contextual_callstring_keeps_distinct_callsites() {
        let src = r#"
class Repo:
    pass

class Service:
    def run(self, repo):
        return repo

def handle(repo):
    left = Service().run(repo)
    right = Service().run(repo)
    return right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle function");
        let call_insts = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Dynamic(_)) || call.receiver.is_some() => Some(inst.id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(call_insts.len() >= 2);
        let left_query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: handle.id.0, inst: call_insts[0].0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let right_query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: handle.id.0, inst: call_insts[1].0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let left = fg
            .contextual_demand_query_summary(&left_query, ContextSensitivity::CallString2, 16, 4096)
            .expect("left summary");
        let right = fg
            .contextual_demand_query_summary(&right_query, ContextSensitivity::CallString2, 16, 4096)
            .expect("right summary");
        assert!(!left.traversal.seeds.is_empty());
        assert!(!right.traversal.seeds.is_empty());
        assert!(fg.contextual_demand_query_cache.borrow().len() >= 2);
    }

    #[test]
    fn recommended_context_sensitivity_prefers_receiver_args_and_callsite_for_heap_calls() {
        let query = DemandQuery {
            seeds: vec![DemandSeed::CallPort {
                func: 1,
                inst: 2,
                port: Port::Receiver,
            }, DemandSeed::CallPort {
                func: 1,
                inst: 2,
                port: Port::Arg(0),
            }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Fixpoint,
            include_heap: true,
        };
        let fg = FlowGraph::default();
        assert_eq!(
            fg.recommended_context_sensitivity(&query),
            ContextSensitivity::ReceiverArgsAndCallSite
        );
    }

    #[test]
    fn solver_closure_materializes_contextual_internal_summary_edges() {
        let src = r#"
class Repo:
    pass

class Service:
    def echo(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.echo(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        assert!(fg.solver_closure_iterations >= 1);
        let edge_count = fg
            .graph
            .edge_references()
            .filter(|edge| matches!(edge.weight().kind, EdgeKind::Summary { ref rule_id } if rule_id == "internal:return" || rule_id == "internal:function-return"))
            .count();
        assert!(edge_count >= 1);
    }

    #[test]
    fn call_context_key_captures_receiver_shape_paths() {
        let src = r#"
class Repo:
    def __init__(self):
        self.item = 1

class Service:
    def use(self, repo):
        return repo

def handle():
    repo = Repo()
    service = Service()
    return service.use(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let call = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("use"))
            .map(|(key, _)| *key)
            .expect("call");
        let ctx = fg.call_context_key(call.0, call.1).expect("context");
        assert!(ctx.receiver_shapes.iter().any(|shape| shape.contains("field:item")) || ctx.arg_shapes.iter().flatten().any(|shape| shape.contains("field:item")));
    }

    #[test]
    fn demand_query_summary_auto_prefers_fixpoint_for_heap_calls() {
        let query = DemandQuery {
            seeds: vec![DemandSeed::CallPort {
                func: 1,
                inst: 2,
                port: Port::Receiver,
            }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Sparse,
            include_heap: true,
        };
        let fg = FlowGraph::default();
        assert_eq!(fg.recommended_demand_engine(&query), DemandEngine::Fixpoint);
        let (max_depth, max_visits) = fg.recommended_query_limits(&query);
        assert!(max_depth >= 18);
        assert!(max_visits >= 8192);
        let plan = fg.solver_plan_for_query(&query);
        assert_eq!(plan.query.engine, DemandEngine::Fixpoint);
        assert!(matches!(plan.budget_profile, QueryBudgetProfile::Standard | QueryBudgetProfile::Deep | QueryBudgetProfile::Exhaustive));
    }

    #[test]
    fn solver_plan_auto_uses_shape_rich_context_and_exhaustive_budget() {
        let src = r#"
class Repo:
    def __init__(self):
        self.item = 1

class Service:
    def use(self, repo):
        return repo

def handle():
    repo = Repo()
    service = Service()
    return service.use(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let (func, inst) = fg
            .call_meta
            .iter()
            .find(|(_, meta)| meta.method_name.as_deref() == Some("use"))
            .map(|(key, _)| *key)
            .expect("call");
        let query = DemandQuery {
            seeds: vec![DemandSeed::Call { func: func.0, inst: inst.0 }],
            direction: SparseDirection::Backward,
            engine: DemandEngine::Sparse,
            include_heap: true,
        };
        let plan = fg.solver_plan_for_query(&query);
        assert_eq!(plan.query.engine, DemandEngine::Fixpoint);
        assert_eq!(plan.context_sensitivity, ContextSensitivity::ReceiverArgsAndCallSite);
        assert_eq!(plan.budget_profile, QueryBudgetProfile::Exhaustive);
        assert!(plan.max_depth >= 24);
        assert!(plan.max_visits >= 16384);
    }

    #[test]
    fn points_to_fixpoint_uses_object_graph_neighbors() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let mut box_value = None;
        let mut repo_value = None;
        for inst in handle.blocks.iter().flat_map(|block| block.insts.iter()) {
            if let InstKind::Call(call) = &inst.kind {
                if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) {
                    box_value = call.dst;
                }
                if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) {
                    repo_value = call.dst;
                }
            }
        }
        let box_value = box_value.expect("box value");
        let repo_value = repo_value.expect("repo value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let repo_classes = fg.value_points_to_classes_of(handle.id, repo_value);
        let box_node_classes = fg.node_points_to_classes_of(box_node);
        assert!(repo_classes.iter().any(|class| box_node_classes.contains(class)));
    }

    #[test]
    fn interprocedural_call_summary_tracks_port_to_return_values() {
        let src = r#"
class Repo:
    pass

class Service:
    def pick(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.pick(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.port_to_return_values.is_empty());
        assert!(summary
            .port_to_return_values
            .iter()
            .any(|(port, _, _)| port.contains("Arg(0)") || port.contains("Receiver")));
    }

    #[test]
    fn points_to_classes_include_shape_signatures() {
        let src = r#"
class Box:
    pass

class Repo:
    def __init__(self):
        self.item = 1

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let classes = fg.value_points_to_classes_of(handle.id, box_value);
        assert!(classes.iter().any(|class| class.starts_with("shape:")));
    }

    #[test]
    fn memory_regions_materialize_for_values_and_cells() {
        let src = r#"
class Box:
    pass

class Repo:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let value_regions = fg.value_memory_regions_of(handle.id, box_value);
        assert!(!value_regions.is_empty());
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let cell_regions = fg.cell_memory_regions_of(cell);
        assert!(!cell_regions.is_empty());
        assert!(fg.stats().memory_regions > 0);
    }

    #[test]
    fn interprocedural_call_summary_tracks_heap_regions() {
        let src = r#"
class Repo:
    pass

class Service:
    def write(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.write(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.port_to_write_regions.is_empty() || !summary.port_to_return_regions.is_empty());
        let stats = fg.stats();
        assert!(stats.cached_heap_effect_summaries > 0 || stats.cached_interprocedural_summaries > 0);
    }

    #[test]
    fn cell_live_values_prefer_latest_unique_store() {
        let src = r#"
class Repo:
    pass

class Box:
    pass

def handle():
    box = Box()
    repo1 = Repo()
    repo2 = Repo()
    box.repo = repo1
    box.repo = repo2
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let mut repo_values = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .filter_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => call.dst,
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(repo_values.len() >= 2);
        repo_values.sort_by_key(|value| value.0);
        let latest_repo = *repo_values.last().expect("latest repo");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let live = fg.cell_live_values_of(cell);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0], (handle.id, latest_repo));
    }

    #[test]
    fn interprocedural_call_summary_tracks_return_value_regions() {
        let src = r#"
class Repo:
    pass

class Service:
    def pick(self, repo):
        return repo

def handle(repo):
    service = Service()
    return service.pick(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.return_value_regions.is_empty() || !summary.port_to_return_value_regions.is_empty());
    }

    #[test]
    fn region_graph_materializes_shared_memory_neighbors() {
        let src = r#"
class Repo:
    pass

class Box:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let box_node = *fg.values.get(&(handle.id, box_value)).expect("box node");
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let succ = fg.region_graph_successors_of(box_node);
        let pred = fg.region_graph_predecessors_of(box_node);
        assert!(succ.contains(&cell) || pred.contains(&cell));
        assert!(fg.stats().region_graph_edges > 0);
    }

    #[test]
    fn live_region_state_tracks_values_from_cells() {
        let src = r#"
class Repo:
    pass

class Box:
    pass

def handle():
    box = Box()
    repo = Repo()
    box.repo = repo
    return box
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let box_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Box")) => call.dst,
                _ => None,
            })
            .expect("box value");
        let repo_value = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .find_map(|inst| match &inst.kind {
                InstKind::Call(call)
                    if matches!(call.callee, uniflow_ir::Callee::Static(ref name) if name.ends_with("Repo")) => call.dst,
                _ => None,
            })
            .expect("repo value");
        let cell = fg
            .field_cells
            .get(&(handle.id, box_value, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let region = fg
            .cell_live_regions_of(cell)
            .into_iter()
            .next()
            .or_else(|| fg.cell_memory_regions_of(cell).into_iter().next())
            .expect("region");
        let live_values = fg.region_live_values_of(&region);
        let live_cells = fg.region_live_cells_of(&region);
        assert!(live_values.contains(&(handle.id, repo_value)));
        assert!(live_cells.contains(&cell));
        assert!(fg.stats().live_region_values > 0);
        assert!(fg.stats().live_region_cells > 0);
    }

    #[test]
    fn interprocedural_call_summary_tracks_live_return_values() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.port_to_return_live_values.is_empty() || !summary.return_live_values.is_empty());
    }

    #[test]
    fn function_heap_effect_summary_tracks_relative_access_paths() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let bind = ir.find_function_by_name("app.Service.bind").expect("bind");
        let summary = fg
            .function_heap_effect_summary(bind.id, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("heap summary");
        assert!(summary.param_to_write_paths.iter().any(|(_index, path)| path == "field:repo"));
        assert!(summary.return_value_paths.iter().any(|(_func, _value, path)| path == "field:repo")
            || summary.return_paths.iter().any(|path| path == "field:repo"));
    }

    #[test]
    fn interprocedural_call_summary_tracks_relative_access_paths() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(summary.port_to_write_paths.iter().any(|(_port, path)| path == "field:repo"));
        assert!(summary.port_to_return_value_paths.iter().any(|(_port, _func, _value, path)| path == "field:repo")
            || summary.return_value_paths.iter().any(|(_func, _value, path)| path == "field:repo"));
    }

    #[test]
    fn cell_write_generations_track_transitive_interprocedural_stores() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self


def handle(repo):
    service = Service()
    service.bind(repo)
    return service
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let bind = ir.find_function_by_name("app.Service.bind").expect("bind");
        let self_param = bind.params.first().copied().expect("self param");
        let cell = fg
            .field_cells
            .get(&(bind.id, self_param, "repo".to_string()))
            .copied()
            .expect("repo cell");
        let generations = fg.cell_write_generations_of(cell);
        assert!(!generations.is_empty());
    }

    #[test]
    fn explicit_points_to_targets_materialize_and_drive_alias_queries() {
        let src = r#"
class Box:
    pass

def handle():
    left = Box()
    alias = left
    right = Box()
    left.tag = 1
    right.tag = 2
    return alias
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let left = find_value_by_name(handle, "left").expect("left");
        let alias = find_value_by_name(handle, "alias").expect("alias");
        let right = find_value_by_name(handle, "right").expect("right");
        assert!(!fg.value_points_to_targets_of(handle.id, left).is_empty());
        assert!(fg.value_must_alias(handle.id, left, handle.id, alias));
        assert!(!fg.value_may_alias(handle.id, left, handle.id, right));
    }

    #[test]
    fn function_heap_effect_summary_tracks_exact_cells() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let bind = ir.find_function_by_name("app.Service.bind").expect("bind");
        let summary = fg
            .function_heap_effect_summary(bind.id, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("heap summary");
        assert!(!summary.param_to_write_cells.is_empty());
        assert!(!summary.return_value_cells.is_empty() || !summary.return_cells.is_empty());
    }

    #[test]
    fn contextual_solver_state_tracks_return_targets() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let ctx = fg.call_context_key(handle.id, call_inst).expect("context");
        assert!(!fg.contextual_return_values_of(&ctx).is_empty());
        assert!(!fg.contextual_return_cells_of(&ctx).is_empty() || !fg.contextual_points_to_targets.get(&ctx).cloned().unwrap_or_default().is_empty());
    }

    #[test]
    fn points_to_object_ids_materialize_and_drive_alias_queries() {
        let src = r#"
class Box:
    pass

def handle():
    left = Box()
    alias = left
    right = Box()
    return alias
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let left = find_value_by_name(handle, "left").expect("left");
        let alias = find_value_by_name(handle, "alias").expect("alias");
        let right = find_value_by_name(handle, "right").expect("right");
        assert!(!fg.value_points_to_object_ids_of(handle.id, left).is_empty());
        assert!(fg.value_must_alias(handle.id, left, handle.id, alias));
        assert!(!fg.value_may_alias(handle.id, left, handle.id, right));
    }

    #[test]
    fn contextual_solver_state_materializes_per_node_object_ids() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let ctx = fg.call_context_key(handle.id, call_inst).expect("context");
        let ret_port = fg
            .call_ports
            .get(&(handle.id, call_inst, Port::Return))
            .copied()
            .expect("return port");
        assert!(!fg.contextual_node_points_to_object_ids_of(&ctx, ret_port).is_empty()
            || !fg.contextual_return_cells_of(&ctx).is_empty());
    }

    #[test]
    fn abstract_objects_materialize_for_precise_sites() {
        let src = r#"
class Box:
    pass

def handle():
    left = Box()
    return left
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let left = find_value_by_name(handle, "left").expect("left");
        let ids = fg.value_points_to_object_ids_of(handle.id, left);
        assert!(!ids.is_empty());
        assert!(ids.iter().all(|id| fg.abstract_objects.contains_key(id)));
    }

    #[test]
    fn interprocedural_call_summary_tracks_return_value_objects() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary(handle.id, call_inst, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        assert!(!summary.return_value_objects.is_empty() || !summary.port_to_return_value_objects.is_empty());
    }


    #[test]
    fn contextual_function_heap_effect_summary_carries_context_metadata() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let context = fg.call_context_key(handle.id, call_inst).expect("context");
        let call_summary = fg
            .interprocedural_call_summary_with_sensitivity(handle.id, call_inst, ContextSensitivity::ReceiverArgsAndCallSite, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("call summary");
        let callee = call_summary.callee_funcs.first().copied().map(FunctionId).expect("callee");
        let summary = fg
            .contextual_function_heap_effect_summary(callee, &context, ContextSensitivity::ReceiverArgsAndCallSite, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("summary");
        assert!(summary.context.is_some());
        assert_eq!(summary.sensitivity, Some(ContextSensitivity::ReceiverArgsAndCallSite));
    }

    #[test]
    fn interprocedural_call_summary_with_sensitivity_records_metadata() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let summary = fg
            .interprocedural_call_summary_with_sensitivity(handle.id, call_inst, ContextSensitivity::CallSite, 16, 4096, DemandEngine::Fixpoint, true)
            .expect("summary");
        assert_eq!(summary.sensitivity, Some(ContextSensitivity::CallSite));
        assert!(!summary.callee_funcs.is_empty());
    }

    #[test]
    fn contextual_function_transfer_summary_filters_to_callee_context() {
        let src = r#"
class Repo:
    pass

class Service:
    def bind(self, repo):
        self.repo = repo
        return self.repo

def handle(repo):
    service = Service()
    return service.bind(repo)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let fg = build(&ir, &RuleSet::default());
        let handle = ir.find_function_by_name("app.handle").expect("handle");
        let call_inst = handle
            .blocks
            .iter()
            .flat_map(|block| block.insts.iter())
            .rfind(|inst| matches!(inst.kind, InstKind::Call(_)))
            .map(|inst| inst.id)
            .expect("call inst");
        let context = fg.call_context_key(handle.id, call_inst).expect("context");
        let callee = fg
            .interprocedural_call_summary_with_sensitivity(
                handle.id,
                call_inst,
                ContextSensitivity::ReceiverArgsAndCallSite,
                16,
                4096,
                DemandEngine::Fixpoint,
                true,
            )
            .and_then(|summary| summary.callee_funcs.first().copied().map(FunctionId))
            .expect("callee");
        let summary = fg
            .contextual_function_transfer_summary(
                callee,
                &context,
                ContextSensitivity::ReceiverArgsAndCallSite,
                16,
                4096,
                DemandEngine::Fixpoint,
                true,
            )
            .expect("transfer");
        assert!(!summary.return_values.is_empty());
    }

}
