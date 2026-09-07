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
    #[serde(default)]
    pub value_names: HashMap<(FunctionId, ValueId), String>,
    #[serde(default)]
    pub value_constants: HashMap<(FunctionId, ValueId), String>,
    pub value_alias_roots: HashMap<(FunctionId, ValueId), ValueId>,
    pub heap_alias_roots: HashMap<(FunctionId, ValueId), ValueId>,
    pub object_identity_roots: HashMap<(FunctionId, ValueId), ValueId>,
    pub object_identity_sites: HashMap<(FunctionId, ValueId), String>,
    pub lifetime_states: HashMap<(FunctionId, ValueId), LifetimeState>,
    pub lifetime_block_states: HashMap<(FunctionId, BlockId, ValueId), LifetimeState>,
    pub lifetime_diagnostics: Vec<LifetimeDiagnostic>,
    pub value_cpp: HashMap<(FunctionId, ValueId), uniflow_hir::CppValueSemantics>,
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
    pub demand_summary_cache:
        RefCell<HashMap<(usize, SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_seed_summary_cache:
        RefCell<HashMap<(Vec<usize>, SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_call_summary_cache:
        RefCell<HashMap<((u32, u32), SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_fixpoint_summary_cache:
        RefCell<HashMap<(Vec<usize>, SparseDirection, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub demand_query_summary_cache:
        RefCell<HashMap<(DemandQuery, usize, usize), SparseValueSummary>>,
    #[serde(skip)]
    pub contextual_call_summary_cache: RefCell<
        HashMap<
            (
                CallContextKey,
                SparseDirection,
                usize,
                usize,
                DemandEngine,
                bool,
            ),
            SparseValueSummary,
        >,
    >,
    #[serde(skip)]
    pub function_summary_cache: RefCell<
        HashMap<
            (
                u32,
                String,
                SparseDirection,
                usize,
                usize,
                DemandEngine,
                bool,
            ),
            SparseValueSummary,
        >,
    >,
    #[serde(skip)]
    pub contextual_demand_query_cache: RefCell<
        HashMap<
            (
                DemandQuery,
                ContextSensitivity,
                Vec<CallContextKey>,
                usize,
                usize,
            ),
            SparseValueSummary,
        >,
    >,
    #[serde(skip)]
    pub interprocedural_call_summary_cache: RefCell<
        HashMap<
            (
                CallContextKey,
                ContextSensitivity,
                usize,
                usize,
                DemandEngine,
                bool,
            ),
            InterproceduralCallSummary,
        >,
    >,
    #[serde(skip)]
    pub function_transfer_summary_cache:
        RefCell<HashMap<(u32, usize, usize, DemandEngine, bool), FunctionTransferSummary>>,
    #[serde(skip)]
    pub contextual_function_transfer_summary_cache: RefCell<
        HashMap<
            (
                u32,
                CallContextKey,
                ContextSensitivity,
                usize,
                usize,
                DemandEngine,
                bool,
            ),
            FunctionTransferSummary,
        >,
    >,
    #[serde(skip)]
    pub function_heap_effect_summary_cache:
        RefCell<HashMap<(u32, usize, usize, DemandEngine, bool), FunctionHeapEffectSummary>>,
    #[serde(skip)]
    pub contextual_function_heap_effect_summary_cache: RefCell<
        HashMap<
            (
                u32,
                CallContextKey,
                ContextSensitivity,
                usize,
                usize,
                DemandEngine,
                bool,
            ),
            FunctionHeapEffectSummary,
        >,
    >,
    pub type_hierarchy: HashMap<String, Vec<String>>,
    pub call_meta: HashMap<(FunctionId, InstId), CallMeta>,
    pub resolved_internal_targets: HashMap<(FunctionId, InstId), Vec<String>>,
    pub synthetic_sources: Vec<NodeIndex>,
    pub synthetic_sinks: Vec<NodeIndex>,
}
impl FlowGraph {
    pub fn lifetime_state_of(&self, func: FunctionId, value: ValueId) -> LifetimeState {
        self.lifetime_states
            .get(&(func, value))
            .copied()
            .unwrap_or(LifetimeState::Unknown)
    }

    pub fn is_definitely_dead(&self, func: FunctionId, value: ValueId) -> bool {
        matches!(
            self.lifetime_state_of(func, value),
            LifetimeState::Destroyed
        )
    }

    pub fn is_moved_from(&self, func: FunctionId, value: ValueId) -> bool {
        matches!(
            self.lifetime_state_of(func, value),
            LifetimeState::MovedFrom | LifetimeState::MaybeMovedFrom
        )
    }
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
            value_names: HashMap::new(),
            value_constants: HashMap::new(),
            value_alias_roots: HashMap::new(),
            heap_alias_roots: HashMap::new(),
            object_identity_roots: HashMap::new(),
            object_identity_sites: HashMap::new(),
            lifetime_states: HashMap::new(),
            lifetime_block_states: HashMap::new(),
            lifetime_diagnostics: Vec::new(),
            value_cpp: HashMap::new(),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifetimeState {
    Uninitialized,
    Alive,
    MaybeAlive,
    MovedFrom,
    MaybeMovedFrom,
    Released,
    MaybeReleased,
    Destroyed,
    MaybeDestroyed,
    Escaped,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallMeta {
    pub func: FunctionId,
    pub inst: InstId,
    pub function_name: String,
    pub callee_name: Option<String>,
    pub receiver_type: Option<String>,
    pub receiver_type_candidates: Vec<String>,
    #[serde(default)]
    pub receiver_parameter: Option<usize>,
    pub method_name: Option<String>,
    pub arg_count: usize,
    pub arg_types: Vec<Option<String>>,
    pub arg_type_candidates: Vec<Vec<String>>,
    #[serde(default)]
    pub receiver_constant: Option<String>,
    /// Name of an unresolved global/module receiver such as `JSON` or
    /// `Object`. It is symbolic provenance, never a literal constant.
    #[serde(default)]
    pub receiver_symbol: Option<String>,
    #[serde(default)]
    pub arg_constants: Vec<Option<String>>,
    /// Whether another SSA instruction or terminator consumes this call's
    /// return value. A call without a destination is necessarily unused.
    #[serde(default)]
    pub return_is_used: bool,
    pub span: Span,
}

impl CallMeta {
    pub fn as_call_info(&self) -> Option<CallInfo> {
        let mut call = CallInfo::new(
            self.callee_name.clone()?,
            self.receiver_type.clone(),
            self.receiver_type_candidates.clone(),
            self.method_name.clone(),
            Some(self.arg_count),
            self.arg_types.clone(),
            self.arg_type_candidates.clone(),
        );
        call.containing_function = Some(self.function_name.clone());
        call.receiver_constant = self.receiver_constant.clone();
        call.receiver_parameter = self.receiver_parameter;
        call.arg_constants = self.arg_constants.clone();
        Some(call)
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub enum QueryCompleteness {
    #[default]
    Complete,
    DepthLimitReached,
    VisitLimitReached,
    ContextLimitReached,
    HeapWidened,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SparseTraversal {
    pub seeds: Vec<usize>,
    pub visited: Vec<usize>,
    pub layers: Vec<Vec<usize>>,
    /// Backward-compatible aggregate flag. Prefer `completeness` for diagnostics.
    pub frontier_cutoff: bool,
    #[serde(default)]
    pub completeness: QueryCompleteness,
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
    // Eagerly materialize only the default high-precision context. Other
    // sensitivities remain fully supported through the contextual query APIs and
    // their caches, but precomputing all five variants for every call site causes
    // multiplicative fixed-point work and severe state explosion on shape-rich code.
    &[ContextSensitivity::ReceiverArgsAndCallSite]
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
