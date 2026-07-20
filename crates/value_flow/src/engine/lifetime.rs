#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifetimeDiagnostic {
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub function: FunctionId,
    pub instruction: Option<InstId>,
    pub value: ValueId,
    pub state: LifetimeState,
    pub potential: bool,
    pub span: Span,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ObjectOwnershipState {
    unique: HashSet<ValueId>,
    shared: HashSet<ValueId>,
    weak: HashSet<ValueId>,
    escaped: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum BorrowValidity {
    #[default]
    Valid,
    MaybeInvalid,
    Invalid,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LifetimeDataflowState {
    handles: HashMap<ValueId, LifetimeState>,
    objects: HashMap<ValueId, LifetimeState>,
    ownership: HashMap<ValueId, ObjectOwnershipState>,
    /// Runtime managed-object identity for owner handles.  This refines the static SSA alias root
    /// when reset(new T), weak_ptr::lock(), or another ownership operation changes the control
    /// block without defining a new source-level owner variable.
    dynamic_roots: HashMap<ValueId, ValueId>,
    /// Raw/reference handles produced from an owning handle (for example unique_ptr::get()).
    borrowed_from: HashMap<ValueId, ValueId>,
    borrow_validity: HashMap<ValueId, BorrowValidity>,
    /// Validity of a weak handle's association with the current shared control block.  This is
    /// separate from the lifetime of the weak_ptr object itself: an expired weak_ptr remains a
    /// live handle on which lock()/expired()/reset() are valid operations.
    weak_validity: HashMap<ValueId, BorrowValidity>,
    /// Field-sensitive ownership/object identities for aggregate stores within the function.
    field_roots: HashMap<(ValueId, String), ValueId>,
    /// Index-insensitive container element identity. All indices of one abstract container share
    /// a conservative cell unless a more precise heap model is available.
    index_roots: HashMap<ValueId, ValueId>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ParamLifetimeEffect {
    #[default]
    None,
    Escape,
    Move,
    Release,
    Destroy,
}

#[derive(Clone, Debug, Default)]
struct FunctionLifetimeContract {
    has_receiver: bool,
    param_effects: Vec<ParamLifetimeEffect>,
    return_param: Option<usize>,
}

#[derive(Clone, Debug, Default)]
struct FunctionLifetimeResult {
    summary: HashMap<ValueId, LifetimeState>,
    block_states: HashMap<(BlockId, ValueId), LifetimeState>,
    diagnostics: Vec<LifetimeDiagnostic>,
}

fn analyze_program_lifetimes(program: &Program) -> (
    HashMap<(FunctionId, ValueId), LifetimeState>,
    HashMap<(FunctionId, BlockId, ValueId), LifetimeState>,
    Vec<LifetimeDiagnostic>,
) {
    let internal_names = program
        .functions
        .iter()
        .map(|function| function.name.as_str())
        .collect::<HashSet<_>>();
    let lifetime_contracts = build_lifetime_contracts(program);
    let mut summary = HashMap::new();
    let mut block_states = HashMap::new();
    let mut diagnostics = Vec::new();
    for function in &program.functions {
        let result = analyze_function_lifetimes(function, &internal_names, &lifetime_contracts);
        for (value, state) in result.summary {
            summary.insert((function.id, value), state);
        }
        for ((block, value), state) in result.block_states {
            block_states.insert((function.id, block, value), state);
        }
        diagnostics.extend(result.diagnostics);
    }
    (summary, block_states, diagnostics)
}

fn analyze_function_lifetimes(
    function: &Function,
    internal_names: &HashSet<&str>,
    lifetime_contracts: &HashMap<String, FunctionLifetimeContract>,
) -> FunctionLifetimeResult {
    let Some(entry) = function.blocks.first().map(|block| block.id) else {
        return FunctionLifetimeResult::default();
    };
    let roots = lifetime_object_roots(function);
    let allocated_roots = lifetime_allocated_roots(function, &roots);
    let blocks = function
        .blocks
        .iter()
        .map(|block| (block.id, block))
        .collect::<HashMap<_, _>>();
    let mut in_states = HashMap::<BlockId, LifetimeDataflowState>::new();
    let mut entry_state = LifetimeDataflowState::default();
    for param in &function.params {
        entry_state.handles.insert(*param, LifetimeState::Alive);
        let root = lifetime_root(&roots, *param);
        entry_state.objects.insert(root, LifetimeState::Alive);
        register_cpp_owner(function, *param, root, &mut entry_state);
    }
    in_states.insert(entry, entry_state);
    let mut out_states = HashMap::<BlockId, LifetimeDataflowState>::new();
    let mut worklist = VecDeque::from([entry]);
    let mut queued = HashSet::from([entry]);
    let mut diagnostic_keys = HashSet::new();
    let mut diagnostics = Vec::new();

    while let Some(block_id) = worklist.pop_front() {
        queued.remove(&block_id);
        let Some(block) = blocks.get(&block_id).copied() else {
            continue;
        };
        let mut state = in_states.get(&block_id).cloned().unwrap_or_default();
        let mut states_before_instruction = HashMap::<InstId, LifetimeDataflowState>::new();
        for instruction in &block.insts {
            states_before_instruction.insert(instruction.id, state.clone());
            transfer_lifetime_instruction(
                function,
                instruction,
                &roots,
                internal_names,
                lifetime_contracts,
                &mut state,
                &mut diagnostics,
                &mut diagnostic_keys,
            );
        }
        transfer_lifetime_terminator(
            function,
            &block.term,
            &roots,
            &allocated_roots,
            &mut state,
            &mut diagnostics,
            &mut diagnostic_keys,
        );
        let changed_out = out_states.get(&block_id) != Some(&state);
        if changed_out {
            out_states.insert(block_id, state.clone());
        }
        for successor in lifetime_successors(&block.term) {
            let merged = match in_states.get(&successor) {
                Some(existing) => join_lifetime_dataflow_states(existing, &state),
                None => state.clone(),
            };
            if in_states.get(&successor) != Some(&merged) {
                in_states.insert(successor, merged);
                if queued.insert(successor) {
                    worklist.push_back(successor);
                }
            }
        }
        for edge in function.exception_edges.iter().filter(|edge| edge.from == block.id) {
            // A call may throw before producing its return value or executing later instructions
            // in the same basic block.  Start from the state immediately before that call instead
            // of the normal block-out state.  Explicit `throw` edges use the terminator state.
            let mut unwind_state = edge
                .source_inst
                .and_then(|inst| states_before_instruction.get(&inst).cloned())
                .unwrap_or_else(|| state.clone());
            // Destroy only automatic owners whose lexical scopes are exited by this edge.
            // Owners declared outside the try/catch region remain alive after a handled
            // exception, as required by C++ object lifetime semantics.
            apply_raii_cleanup_values(
                function,
                &roots,
                &edge.cleanup_values,
                None,
                &mut unwind_state,
            );

            // The handler parameter is materialized by the exceptional edge. It denotes a fresh
            // exception handle whose payload flow is recorded separately in the value-flow graph;
            // it must therefore start alive even when the source local was destroyed during unwind.
            if let Some(catch_value) = edge.catch_value {
                let catch_root = lifetime_root(&roots, catch_value);
                unwind_state
                    .handles
                    .insert(catch_value, LifetimeState::Alive);
                unwind_state
                    .objects
                    .insert(catch_root, LifetimeState::Alive);
                register_cpp_owner(function, catch_value, catch_root, &mut unwind_state);
            }

            let successor = edge.unwind;
            let merged = match in_states.get(&successor) {
                Some(existing) => join_lifetime_dataflow_states(existing, &unwind_state),
                None => unwind_state,
            };
            if in_states.get(&successor) != Some(&merged) {
                in_states.insert(successor, merged);
                if queued.insert(successor) {
                    worklist.push_back(successor);
                }
            }
        }
    }

    let mut summary = HashMap::<ValueId, LifetimeState>::new();
    let mut block_states = HashMap::new();
    for (block, state) in &out_states {
        for value in function.all_values() {
            let handle = lifetime_handle_state(state, value);
            let object = lifetime_object_state(state, &roots, value);
            let combined = combine_handle_and_object_state(handle, object);
            block_states.insert((*block, value), combined);
            summary
                .entry(value)
                .and_modify(|current| *current = join_lifetime_state(*current, combined))
                .or_insert(combined);
        }
    }

    FunctionLifetimeResult {
        summary,
        block_states,
        diagnostics,
    }
}

fn build_lifetime_contracts(program: &Program) -> HashMap<String, FunctionLifetimeContract> {
    let mut exact = HashMap::<String, FunctionLifetimeContract>::new();
    let mut simple_counts = HashMap::<String, usize>::new();
    for function in &program.functions {
        *simple_counts.entry(simple_callable_name(&function.name).to_string()).or_default() += 1;
        exact.insert(function.name.clone(), infer_lifetime_contract(function));
    }
    let additions = program
        .functions
        .iter()
        .filter_map(|function| {
            let simple = simple_callable_name(&function.name).to_string();
            (simple_counts.get(&simple) == Some(&1)).then(|| {
                (simple, exact.get(&function.name).cloned().unwrap_or_default())
            })
        })
        .collect::<Vec<_>>();
    exact.extend(additions);
    exact
}

fn infer_lifetime_contract(function: &Function) -> FunctionLifetimeContract {
    let roots = lifetime_object_roots(function);
    let param_roots = function
        .params
        .iter()
        .enumerate()
        .map(|(index, value)| (lifetime_root(&roots, *value), index))
        .collect::<HashMap<_, _>>();
    let mut contract = FunctionLifetimeContract {
        has_receiver: function.attrs.get("has_receiver").is_some_and(|value| value == "1"),
        param_effects: vec![ParamLifetimeEffect::None; function.params.len()],
        return_param: None,
    };
    for (index, value) in function.params.iter().copied().enumerate() {
        if function.value_cpp.get(&value).is_some_and(|cpp| {
            cpp.ownership == uniflow_hir::CppOwnershipKind::Unique
                && cpp.reference_kind == uniflow_hir::CppReferenceKind::None
        }) {
            // Passing a unique owner by value transfers ownership even when the callee body is
            // unavailable or only destroys the parameter through implicit RAII at function exit.
            contract.param_effects[index] = ParamLifetimeEffect::Move;
        }
    }
    for block in &function.blocks {
        for instruction in &block.insts {
            match &instruction.kind {
                InstKind::Lifetime { value, event } => {
                    if let Some(index) = param_roots.get(&lifetime_root(&roots, *value)).copied() {
                        let effect = match event {
                            LifetimeEvent::Construct => ParamLifetimeEffect::None,
                            LifetimeEvent::MoveFrom => ParamLifetimeEffect::Move,
                            LifetimeEvent::Release => ParamLifetimeEffect::Release,
                            LifetimeEvent::Destroy => ParamLifetimeEffect::Destroy,
                            LifetimeEvent::Escape => ParamLifetimeEffect::Escape,
                        };
                        contract.param_effects[index] = join_param_effect(contract.param_effects[index], effect);
                    }
                }
                InstKind::StoreField { src, .. } | InstKind::StoreIndex { src, .. } => {
                    if let Some(index) = param_roots.get(&lifetime_root(&roots, *src)).copied() {
                        contract.param_effects[index] = join_param_effect(
                            contract.param_effects[index],
                            ParamLifetimeEffect::Escape,
                        );
                    }
                }
                _ => {}
            }
        }
        if let Terminator::Return(Some(value)) = &block.term {
            if let Some(index) = param_roots.get(&lifetime_root(&roots, *value)).copied() {
                contract.return_param = match contract.return_param {
                    None => Some(index),
                    Some(existing) if existing == index => Some(existing),
                    Some(_) => None,
                };
            }
        }
    }
    contract
}

fn join_param_effect(left: ParamLifetimeEffect, right: ParamLifetimeEffect) -> ParamLifetimeEffect {
    use ParamLifetimeEffect::*;
    let rank = |effect| match effect {
        None => 0,
        Escape => 1,
        Move => 2,
        Release => 3,
        Destroy => 4,
    };
    if rank(right) > rank(left) { right } else { left }
}

fn simple_callable_name(name: &str) -> &str {
    name.rsplit(|ch| ch == '.' || ch == ':')
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn resolve_lifetime_contract<'a>(
    call: &CallInst,
    contracts: &'a HashMap<String, FunctionLifetimeContract>,
) -> Option<&'a FunctionLifetimeContract> {
    let Callee::Static(name) = &call.callee else { return None };
    contracts
        .get(name)
        .or_else(|| contracts.get(simple_callable_name(name)))
}

fn apply_lifetime_contract(
    function: &Function,
    call: &CallInst,
    contract: &FunctionLifetimeContract,
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
) {
    let mut actuals = Vec::with_capacity(call.args.len() + if contract.has_receiver { 1 } else { 0 });
    if contract.has_receiver {
        if let Some(receiver) = call.receiver {
            actuals.push(receiver);
        }
    }
    actuals.extend(call.args.iter().copied());
    for (index, effect) in contract.param_effects.iter().copied().enumerate() {
        let Some(value) = actuals.get(index).copied() else { continue };
        let root = effective_lifetime_root(roots, state, value);
        match effect {
            ParamLifetimeEffect::None => {}
            ParamLifetimeEffect::Escape => {
                state.handles.insert(value, LifetimeState::Escaped);
                state.objects.insert(root, LifetimeState::Escaped);
                state.ownership.entry(root).or_default().escaped = true;
            }
            ParamLifetimeEffect::Move => {
                if cpp_move_consumes_source(function, value) {
                    state.handles.insert(value, LifetimeState::MovedFrom);
                }
                state.objects.insert(root, LifetimeState::Escaped);
                state.ownership.entry(root).or_default().escaped = true;
            }
            ParamLifetimeEffect::Release => {
                state.handles.insert(value, LifetimeState::Released);
                state.objects.insert(root, LifetimeState::Escaped);
                state.ownership.entry(root).or_default().escaped = true;
            }
            ParamLifetimeEffect::Destroy => {
                destroy_cpp_owner_handle(function, value, root, state);
            }
        }
    }
    if let (Some(dst), Some(index)) = (call.dst, contract.return_param) {
        if let Some(src) = actuals.get(index).copied() {
            let root = effective_lifetime_root(roots, state, src);
            state.dynamic_roots.insert(dst, root);
            state.handles.insert(dst, lifetime_handle_state(state, src));
            let object_state = lifetime_object_state(state, roots, src);
            state.objects.entry(root).or_insert(object_state);
            propagate_cpp_borrow(dst, src, state);
            register_cpp_owner(function, dst, root, state);
        }
    }
}

fn lifetime_object_roots(function: &Function) -> HashMap<ValueId, ValueId> {
    let mut roots = function
        .all_values()
        .map(|value| (value, value))
        .collect::<HashMap<_, _>>();
    let mut changed = true;
    while changed {
        changed = false;
        for block in &function.blocks {
            for instruction in &block.insts {
                match &instruction.kind {
                    InstKind::Copy { dst, src }
                    | InstKind::Move { dst, src }
                    | InstKind::Cast { dst, src, .. } => {
                        let src_root = lifetime_root(&roots, *src);
                        if roots.get(dst).copied() != Some(src_root) {
                            roots.insert(*dst, src_root);
                            changed = true;
                        }
                    }
                    InstKind::Phi { dst, inputs } => {
                        let mut candidates = inputs
                            .iter()
                            .map(|input| lifetime_root(&roots, *input))
                            .collect::<Vec<_>>();
                        candidates.sort_unstable();
                        candidates.dedup();
                        if candidates.len() == 1 && roots.get(dst).copied() != candidates.first().copied() {
                            roots.insert(*dst, candidates[0]);
                            changed = true;
                        }
                    }
                    InstKind::Call(call) => {
                        let method = match &call.callee {
                            Callee::Static(name) => name
                                .rsplit(|ch| ch == '.' || ch == ':')
                                .next()
                                .unwrap_or(name.as_str()),
                            _ => "",
                        };
                        if matches!(method, "get" | "lock" | "release") {
                            if let (Some(dst), Some(receiver)) = (call.dst, call.receiver) {
                                let receiver_root = lifetime_root(&roots, receiver);
                                if roots.get(&dst).copied() != Some(receiver_root) {
                                    roots.insert(dst, receiver_root);
                                    changed = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    roots
}

fn lifetime_allocated_roots(
    function: &Function,
    roots: &HashMap<ValueId, ValueId>,
) -> HashSet<ValueId> {
    let mut out = HashSet::new();
    for block in &function.blocks {
        for instruction in &block.insts {
            let InstKind::Call(call) = &instruction.kind else { continue };
            let Callee::Static(name) = &call.callee else { continue };
            let simple = name
                .rsplit(|ch| ch == '.' || ch == ':')
                .next()
                .unwrap_or(name.as_str());
            if matches!(simple, "malloc" | "calloc" | "realloc" | "operator new" | "make_unique" | "make_shared") {
                if let Some(dst) = call.dst {
                    out.insert(lifetime_root(roots, dst));
                }
            }
        }
    }
    out
}

fn lifetime_root(roots: &HashMap<ValueId, ValueId>, value: ValueId) -> ValueId {
    roots.get(&value).copied().unwrap_or(value)
}

fn effective_lifetime_root(
    roots: &HashMap<ValueId, ValueId>,
    state: &LifetimeDataflowState,
    value: ValueId,
) -> ValueId {
    state
        .dynamic_roots
        .get(&value)
        .copied()
        .unwrap_or_else(|| lifetime_root(roots, value))
}

fn propagate_dynamic_root(
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
    dst: ValueId,
    src: ValueId,
) {
    let root = effective_lifetime_root(roots, state, src);
    state.dynamic_roots.insert(dst, root);
}

fn merge_dynamic_roots(
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
    dst: ValueId,
    inputs: &[ValueId],
) {
    let mut candidates = inputs
        .iter()
        .map(|value| effective_lifetime_root(roots, state, *value))
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.len() == 1 {
        state.dynamic_roots.insert(dst, candidates[0]);
    } else {
        state.dynamic_roots.remove(&dst);
    }
}

fn transfer_lifetime_instruction(
    function: &Function,
    instruction: &Instruction,
    roots: &HashMap<ValueId, ValueId>,
    internal_names: &HashSet<&str>,
    lifetime_contracts: &HashMap<String, FunctionLifetimeContract>,
    state: &mut LifetimeDataflowState,
    diagnostics: &mut Vec<LifetimeDiagnostic>,
    diagnostic_keys: &mut HashSet<(String, u32, u32, u32)>,
) {
    match &instruction.kind {
        InstKind::Lifetime { value, event } => {
            transfer_explicit_lifetime_event(
                function,
                instruction,
                *value,
                *event,
                roots,
                state,
                diagnostics,
                diagnostic_keys,
            );
            return;
        }
        InstKind::Move { src, .. } => {
            diagnose_lifetime_use(
                function,
                Some(instruction),
                *src,
                roots,
                state,
                diagnostics,
                diagnostic_keys,
            );
        }
        _ => {
            for value in lifetime_instruction_uses(&instruction.kind) {
                diagnose_lifetime_use(
                    function,
                    Some(instruction),
                    value,
                    roots,
                    state,
                    diagnostics,
                    diagnostic_keys,
                );
            }
        }
    }

    match &instruction.kind {
        InstKind::ConstInt { dst, .. } | InstKind::ConstString { dst, .. } => {
            state.handles.insert(*dst, LifetimeState::Alive);
        }
        InstKind::Copy { dst, src } => {
            state.handles.insert(*dst, LifetimeState::Alive);
            propagate_dynamic_root(roots, state, *dst, *src);
            propagate_cpp_borrow(*dst, *src, state);
            transfer_cpp_owner_copy(
                function,
                instruction,
                *dst,
                *src,
                roots,
                state,
                diagnostics,
                diagnostic_keys,
            );
        }
        InstKind::Cast { dst, src, .. } => {
            state.handles.insert(*dst, LifetimeState::Alive);
            propagate_dynamic_root(roots, state, *dst, *src);
            propagate_cpp_borrow(*dst, *src, state);
            transfer_cpp_owner_cast(function, *dst, *src, roots, state);
        }
        InstKind::Move { dst, src } => {
            state.handles.insert(*dst, LifetimeState::Alive);
            propagate_dynamic_root(roots, state, *dst, *src);
            propagate_cpp_borrow(*dst, *src, state);
            if cpp_move_consumes_source(function, *src) {
                state.handles.insert(*src, LifetimeState::MovedFrom);
            }
            let root = effective_lifetime_root(roots, state, *src);
            state.objects.entry(root).or_insert(LifetimeState::Alive);
            transfer_cpp_owner_move(function, *dst, *src, root, state);
        }
        InstKind::Phi { dst, inputs } => {
            let handle = inputs.iter().fold(None, |acc, input| {
                let next = lifetime_handle_state(state, *input);
                Some(acc.map_or(next, |current| join_lifetime_state(current, next)))
            });
            state
                .handles
                .insert(*dst, handle.unwrap_or(LifetimeState::Unknown));
            merge_dynamic_roots(roots, state, *dst, inputs);
            merge_cpp_phi_borrow(*dst, inputs, state);
        }
        InstKind::LoadField { dst, base, field } => {
            state.handles.insert(*dst, LifetimeState::Alive);
            let base_root = effective_lifetime_root(roots, state, *base);
            let root = state
                .field_roots
                .get(&(base_root, field.clone()))
                .copied()
                .unwrap_or_else(|| lifetime_root(roots, *dst));
            state.dynamic_roots.insert(*dst, root);
            state.objects.entry(root).or_insert(LifetimeState::Alive);
            register_cpp_owner(function, *dst, root, state);
        }
        InstKind::LoadIndex { dst, base, .. } => {
            state.handles.insert(*dst, LifetimeState::Alive);
            let base_root = effective_lifetime_root(roots, state, *base);
            let root = state
                .index_roots
                .get(&base_root)
                .copied()
                .unwrap_or_else(|| lifetime_root(roots, *dst));
            state.dynamic_roots.insert(*dst, root);
            state.objects.entry(root).or_insert(LifetimeState::Alive);
            register_cpp_owner(function, *dst, root, state);
        }
        InstKind::Call(call) => {
            if let Some(dst) = call.dst {
                state.handles.insert(dst, LifetimeState::Alive);
                let root = lifetime_root(roots, dst);
                state.dynamic_roots.entry(dst).or_insert(root);
                state.objects.entry(root).or_insert(LifetimeState::Alive);
                register_cpp_owner(function, dst, root, state);
            }
            transfer_smart_pointer_call(function, call, roots, state);
            let applied_contract = resolve_lifetime_contract(call, lifetime_contracts)
                .map(|contract| {
                    apply_lifetime_contract(function, call, contract, roots, state);
                })
                .is_some();
            if !applied_contract && call_is_unresolved_or_external(call, internal_names) {
                for value in call.args.iter().copied().chain(call.receiver) {
                    if cpp_call_may_consume_value(function, value) {
                        let root = effective_lifetime_root(roots, state, value);
                        state.handles.insert(value, LifetimeState::Escaped);
                        state.objects.insert(root, LifetimeState::Escaped);
                    }
                }
            }
        }
        InstKind::StoreField { base, field, src } => {
            let base_root = effective_lifetime_root(roots, state, *base);
            let src_root = effective_lifetime_root(roots, state, *src);
            state.field_roots.insert((base_root, field.clone()), src_root);
            transfer_aggregate_ownership_store(function, *src, src_root, state);
        }
        InstKind::StoreIndex { base, src, .. } => {
            let base_root = effective_lifetime_root(roots, state, *base);
            let src_root = effective_lifetime_root(roots, state, *src);
            state.index_roots.insert(base_root, src_root);
            transfer_aggregate_ownership_store(function, *src, src_root, state);
        }
        InstKind::Lifetime { .. } => {}
    }
}

fn transfer_aggregate_ownership_store(
    function: &Function,
    src: ValueId,
    root: ValueId,
    state: &mut LifetimeDataflowState,
) {
    match cpp_ownership_of(function, src) {
        uniflow_hir::CppOwnershipKind::Unique => {
            state.handles.insert(src, LifetimeState::MovedFrom);
            if let Some(ownership) = state.ownership.get_mut(&root) {
                ownership.unique.remove(&src);
                ownership.escaped = true;
            } else {
                state.ownership.entry(root).or_default().escaped = true;
            }
            state.objects.insert(root, LifetimeState::Escaped);
        }
        uniflow_hir::CppOwnershipKind::Shared => {
            state.ownership.entry(root).or_default().escaped = true;
            state.objects.insert(root, LifetimeState::Escaped);
        }
        uniflow_hir::CppOwnershipKind::Weak
        | uniflow_hir::CppOwnershipKind::Borrowed
        | uniflow_hir::CppOwnershipKind::Raw => {
            state.ownership.entry(root).or_default().escaped = true;
        }
        uniflow_hir::CppOwnershipKind::None => {}
    }
}

fn transfer_explicit_lifetime_event(
    function: &Function,
    instruction: &Instruction,
    value: ValueId,
    event: LifetimeEvent,
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
    diagnostics: &mut Vec<LifetimeDiagnostic>,
    diagnostic_keys: &mut HashSet<(String, u32, u32, u32)>,
) {
    let root = effective_lifetime_root(roots, state, value);
    match event {
        LifetimeEvent::Construct => {
            state.handles.insert(value, LifetimeState::Alive);
            state.dynamic_roots.entry(value).or_insert(root);
            state.objects.insert(root, LifetimeState::Alive);
        }
        LifetimeEvent::MoveFrom => {
            if cpp_move_consumes_source(function, value) {
                state.handles.insert(value, LifetimeState::MovedFrom);
            }
        }
        LifetimeEvent::Release => {
            let prior = lifetime_handle_state(state, value);
            if matches!(prior, LifetimeState::Released | LifetimeState::Destroyed) {
                push_lifetime_diagnostic(
                    function,
                    Some(instruction),
                    value,
                    prior,
                    "CPP.INVALID_RELEASE",
                    "warning",
                    "resource or owner is released more than once",
                    false,
                    diagnostics,
                    diagnostic_keys,
                );
            }
            // unique_ptr::release invalidates ownership but does not destroy the pointee.
            state.handles.insert(value, LifetimeState::Released);
            state.objects.insert(root, LifetimeState::Escaped);
            if let Some(ownership) = state.ownership.get_mut(&root) {
                ownership.unique.remove(&value);
                ownership.shared.remove(&value);
                ownership.escaped = true;
            }
        }
        LifetimeEvent::Destroy => {
            let handle = lifetime_handle_state(state, value);
            if handle == LifetimeState::MovedFrom {
                // Destruction of a moved-from owner is a valid no-op.
                return;
            }
            let prior = lifetime_object_state(state, roots, value);
            match prior {
                LifetimeState::Destroyed => push_lifetime_diagnostic(
                    function,
                    Some(instruction),
                    value,
                    prior,
                    "CPP.DOUBLE_DELETE",
                    "error",
                    "object is destroyed more than once",
                    false,
                    diagnostics,
                    diagnostic_keys,
                ),
                LifetimeState::MaybeDestroyed => push_lifetime_diagnostic(
                    function,
                    Some(instruction),
                    value,
                    prior,
                    "CPP.POTENTIAL_DOUBLE_DELETE",
                    "warning",
                    "object may already have been destroyed on another path",
                    true,
                    diagnostics,
                    diagnostic_keys,
                ),
                _ => {}
            }
            destroy_cpp_owner_handle(function, value, root, state);
        }
        LifetimeEvent::Escape => {
            state.handles.insert(value, LifetimeState::Escaped);
            state.objects.insert(root, LifetimeState::Escaped);
            state.ownership.entry(root).or_default().escaped = true;
        }
    }
}

fn apply_raii_cleanup(
    function: &Function,
    roots: &HashMap<ValueId, ValueId>,
    escaped_value: Option<ValueId>,
    state: &mut LifetimeDataflowState,
) {
    let owned_values = function.value_cpp.keys().copied().collect::<Vec<_>>();
    apply_raii_cleanup_values(function, roots, &owned_values, escaped_value, state);
}

fn apply_raii_cleanup_values(
    function: &Function,
    roots: &HashMap<ValueId, ValueId>,
    values: &[ValueId],
    escaped_value: Option<ValueId>,
    state: &mut LifetimeDataflowState,
) {
    let mut owned_values = values
        .iter()
        .copied()
        .filter(|value| is_cpp_automatic_raii_value(function, *value))
        .collect::<Vec<_>>();
    owned_values.sort_unstable();
    owned_values.dedup();
    // Values are allocated monotonically; reverse order approximates C++ scope destruction order.
    owned_values.sort_unstable_by(|left, right| right.cmp(left));
    for value in owned_values {
        if Some(value) == escaped_value {
            continue;
        }
        let handle = lifetime_handle_state(state, value);
        if matches!(handle, LifetimeState::Alive | LifetimeState::MaybeAlive) {
            let root = effective_lifetime_root(roots, state, value);
            destroy_cpp_owner_handle(function, value, root, state);
        }
    }
}

fn is_cpp_automatic_raii_value(function: &Function, value: ValueId) -> bool {
    if let Some(cpp) = function.value_cpp.get(&value) {
        if matches!(
            cpp.ownership,
            uniflow_hir::CppOwnershipKind::Unique
                | uniflow_hir::CppOwnershipKind::Shared
                | uniflow_hir::CppOwnershipKind::Weak
        ) {
            return true;
        }
        if cpp.reference_kind != uniflow_hir::CppReferenceKind::None
            || matches!(
                cpp.ownership,
                uniflow_hir::CppOwnershipKind::Borrowed
                    | uniflow_hir::CppOwnershipKind::Raw
            )
        {
            return false;
        }
    }
    let Some(ty) = function.value_types.get(&value) else {
        return false;
    };
    let compact = ty
        .replace("const", "")
        .replace("volatile", "")
        .trim()
        .to_string();
    if compact.contains('*') || compact.contains('&') || compact.is_empty() {
        return false;
    }
    let simple = compact
        .rsplit("::")
        .next()
        .unwrap_or(compact.as_str())
        .split('<')
        .next()
        .unwrap_or(compact.as_str());
    !matches!(
        simple,
        "void"
            | "bool"
            | "char"
            | "signed"
            | "unsigned"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "size_t"
            | "ssize_t"
            | "ptrdiff_t"
            | "intptr_t"
            | "uintptr_t"
    )
}

fn transfer_lifetime_terminator(
    function: &Function,
    terminator: &Terminator,
    roots: &HashMap<ValueId, ValueId>,
    allocated_roots: &HashSet<ValueId>,
    state: &mut LifetimeDataflowState,
    diagnostics: &mut Vec<LifetimeDiagnostic>,
    diagnostic_keys: &mut HashSet<(String, u32, u32, u32)>,
) {
    let returned = match terminator {
        Terminator::Return(value) | Terminator::Throw(value) => *value,
        _ => None,
    };
    if let Some(value) = returned {
        diagnose_lifetime_use(
            function,
            None,
            value,
            roots,
            state,
            diagnostics,
            diagnostic_keys,
        );
        if function
            .value_cpp
            .get(&value)
            .is_some_and(|cpp| cpp.ownership == uniflow_hir::CppOwnershipKind::Unique)
        {
            let root = effective_lifetime_root(roots, state, value);
            state.handles.insert(value, LifetimeState::Escaped);
            state.objects.insert(root, LifetimeState::Escaped);
        }
    }

    if matches!(terminator, Terminator::Return(_)) {
        // Normal function exit destroys every remaining automatic owner.  Exceptional exits are
        // handled by source-injected cleanup events and scope-specific ExceptionEdge cleanup lists;
        // applying a function-wide cleanup here would incorrectly destroy owners outside a caught
        // try block.
        apply_raii_cleanup(function, roots, returned, state);
    }

    if matches!(terminator, Terminator::Return(_) | Terminator::Throw(_)) {
        for root in allocated_roots {
            if Some(*root) == returned {
                continue;
            }
            let object_state = state.objects.get(root).copied().unwrap_or(LifetimeState::Unknown);
            if !matches!(object_state, LifetimeState::Alive | LifetimeState::MaybeAlive) {
                continue;
            }
            let owners = function
                .value_cpp
                .iter()
                .filter(|(value, _)| effective_lifetime_root(roots, state, **value) == *root)
                .map(|(_, cpp)| cpp.ownership)
                .collect::<HashSet<_>>();
            if owners.contains(&uniflow_hir::CppOwnershipKind::Unique)
                || owners.contains(&uniflow_hir::CppOwnershipKind::Shared)
                || owners.contains(&uniflow_hir::CppOwnershipKind::Weak)
            {
                continue;
            }
            push_lifetime_diagnostic(
                function,
                None,
                *root,
                object_state,
                "CPP.RESOURCE_LEAK",
                "warning",
                "allocated object may leave the function without release, destruction, or ownership transfer",
                object_state == LifetimeState::MaybeAlive,
                diagnostics,
                diagnostic_keys,
            );
        }
    }
}

fn diagnose_lifetime_use(
    function: &Function,
    instruction: Option<&Instruction>,
    value: ValueId,
    roots: &HashMap<ValueId, ValueId>,
    state: &LifetimeDataflowState,
    diagnostics: &mut Vec<LifetimeDiagnostic>,
    diagnostic_keys: &mut HashSet<(String, u32, u32, u32)>,
) {
    match state.borrow_validity.get(&value).copied() {
        Some(BorrowValidity::Invalid) => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            LifetimeState::Destroyed,
            "CPP.USE_AFTER_FREE",
            "error",
            "borrowed pointer or reference is used after its owning object was replaced or destroyed",
            false,
            diagnostics,
            diagnostic_keys,
        ),
        Some(BorrowValidity::MaybeInvalid) => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            LifetimeState::MaybeDestroyed,
            "CPP.POTENTIAL_USE_AFTER_FREE",
            "warning",
            "borrowed pointer or reference may have been invalidated on another path",
            true,
            diagnostics,
            diagnostic_keys,
        ),
        _ => {}
    }
    if cpp_ownership_of(function, value) == uniflow_hir::CppOwnershipKind::Weak
        && !weak_owner_operation_is_safe(instruction, value)
    {
        push_lifetime_diagnostic(
            function,
            instruction,
            value,
            lifetime_handle_state(state, value),
            "CPP.WEAK_OWNER_DEREFERENCE",
            "warning",
            "weak ownership is used without first acquiring a shared owner with lock()",
            true,
            diagnostics,
            diagnostic_keys,
        );
    }
    let handle = lifetime_handle_state(state, value);
    match handle {
        LifetimeState::MovedFrom => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            handle,
            "CPP.USE_AFTER_MOVE",
            "error",
            "value is used after its ownership was moved",
            false,
            diagnostics,
            diagnostic_keys,
        ),
        LifetimeState::MaybeMovedFrom => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            handle,
            "CPP.POTENTIAL_USE_AFTER_MOVE",
            "warning",
            "value may have been moved on another path",
            true,
            diagnostics,
            diagnostic_keys,
        ),
        LifetimeState::Released => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            handle,
            "CPP.USE_AFTER_RELEASE",
            "warning",
            "owner is used after releasing its resource",
            false,
            diagnostics,
            diagnostic_keys,
        ),
        LifetimeState::MaybeReleased => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            handle,
            "CPP.POTENTIAL_USE_AFTER_RELEASE",
            "warning",
            "owner may have released its resource on another path",
            true,
            diagnostics,
            diagnostic_keys,
        ),
        _ => {}
    }
    let object = lifetime_object_state(state, roots, value);
    match object {
        LifetimeState::Destroyed => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            object,
            "CPP.USE_AFTER_FREE",
            "error",
            "value refers to an object that has already been destroyed",
            false,
            diagnostics,
            diagnostic_keys,
        ),
        LifetimeState::MaybeDestroyed => push_lifetime_diagnostic(
            function,
            instruction,
            value,
            object,
            "CPP.POTENTIAL_USE_AFTER_FREE",
            "warning",
            "value may refer to an object destroyed on another path",
            true,
            diagnostics,
            diagnostic_keys,
        ),
        _ => {}
    }
}

fn weak_owner_operation_is_safe(instruction: Option<&Instruction>, value: ValueId) -> bool {
    let Some(instruction) = instruction else { return true };
    match &instruction.kind {
        InstKind::Copy { src, .. }
        | InstKind::Move { src, .. }
        | InstKind::Cast { src, .. } => *src == value,
        InstKind::Lifetime { value: event_value, .. } => *event_value == value,
        InstKind::Call(call) if call.receiver == Some(value) => {
            let method = match &call.callee {
                Callee::Static(name) => name
                    .rsplit(|ch| ch == '.' || ch == ':')
                    .next()
                    .unwrap_or(name.as_str()),
                _ => "",
            };
            matches!(method, "lock" | "expired" | "use_count" | "reset" | "swap")
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_lifetime_diagnostic(
    function: &Function,
    instruction: Option<&Instruction>,
    value: ValueId,
    state: LifetimeState,
    rule_id: &str,
    severity: &str,
    message: &str,
    potential: bool,
    diagnostics: &mut Vec<LifetimeDiagnostic>,
    diagnostic_keys: &mut HashSet<(String, u32, u32, u32)>,
) {
    let inst_id = instruction.map(|inst| inst.id.0).unwrap_or(u32::MAX);
    let key = (rule_id.to_string(), function.id.0, inst_id, value.0);
    if !diagnostic_keys.insert(key) {
        return;
    }
    diagnostics.push(LifetimeDiagnostic {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
        function: function.id,
        instruction: instruction.map(|inst| inst.id),
        value,
        state,
        potential,
        span: instruction.map(|inst| inst.span).unwrap_or(function.span),
    });
}

fn lifetime_instruction_uses(kind: &InstKind) -> Vec<ValueId> {
    match kind {
        InstKind::ConstInt { .. } | InstKind::ConstString { .. } => Vec::new(),
        InstKind::Copy { src, .. } | InstKind::Cast { src, .. } => vec![*src],
        InstKind::Move { src, .. } => vec![*src],
        InstKind::Lifetime { .. } => Vec::new(),
        InstKind::Phi { inputs, .. } => inputs.clone(),
        InstKind::LoadField { base, .. } => vec![*base],
        InstKind::StoreField { base, src, .. } => vec![*base, *src],
        InstKind::LoadIndex { base, index, .. } => vec![*base, *index],
        InstKind::StoreIndex { base, index, src } => vec![*base, *index, *src],
        InstKind::Call(call) => {
            let mut out = Vec::new();
            if let Some(receiver) = call.receiver {
                out.push(receiver);
            }
            out.extend(call.args.iter().copied());
            if let Callee::Dynamic(value) = &call.callee {
                out.push(*value);
            }
            out
        }
    }
}

fn cpp_ownership_of(function: &Function, value: ValueId) -> uniflow_hir::CppOwnershipKind {
    function
        .value_cpp
        .get(&value)
        .map(|cpp| cpp.ownership)
        .unwrap_or(uniflow_hir::CppOwnershipKind::None)
}

fn register_cpp_owner(
    function: &Function,
    value: ValueId,
    root: ValueId,
    state: &mut LifetimeDataflowState,
) {
    let ownership = state.ownership.entry(root).or_default();
    match cpp_ownership_of(function, value) {
        uniflow_hir::CppOwnershipKind::Unique => {
            ownership.unique.insert(value);
        }
        uniflow_hir::CppOwnershipKind::Shared => {
            ownership.shared.insert(value);
        }
        uniflow_hir::CppOwnershipKind::Weak => {
            ownership.weak.insert(value);
            state
                .weak_validity
                .entry(value)
                .or_insert(BorrowValidity::Valid);
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn transfer_cpp_owner_copy(
    function: &Function,
    instruction: &Instruction,
    dst: ValueId,
    src: ValueId,
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
    diagnostics: &mut Vec<LifetimeDiagnostic>,
    diagnostic_keys: &mut HashSet<(String, u32, u32, u32)>,
) {
    let root = effective_lifetime_root(roots, state, src);
    match cpp_ownership_of(function, dst) {
        uniflow_hir::CppOwnershipKind::Unique => {
            push_lifetime_diagnostic(
                function,
                Some(instruction),
                src,
                lifetime_handle_state(state, src),
                "CPP.UNIQUE_OWNER_COPY",
                "error",
                "unique ownership is copied instead of transferred with move semantics",
                false,
                diagnostics,
                diagnostic_keys,
            );
            let owner = state.ownership.entry(root).or_default();
            owner.unique.insert(src);
            owner.unique.insert(dst);
            state.objects.insert(root, LifetimeState::Unknown);
        }
        uniflow_hir::CppOwnershipKind::Shared => {
            state.ownership.entry(root).or_default().shared.insert(dst);
        }
        uniflow_hir::CppOwnershipKind::Weak => {
            state.ownership.entry(root).or_default().weak.insert(dst);
            let validity = state
                .weak_validity
                .get(&src)
                .copied()
                .unwrap_or(BorrowValidity::Valid);
            state.weak_validity.insert(dst, validity);
        }
        _ => {}
    }
}

fn transfer_cpp_owner_cast(
    function: &Function,
    dst: ValueId,
    src: ValueId,
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
) {
    let root = effective_lifetime_root(roots, state, src);
    match cpp_ownership_of(function, dst) {
        uniflow_hir::CppOwnershipKind::Unique => {
            state.ownership.entry(root).or_default().unique.insert(dst);
        }
        uniflow_hir::CppOwnershipKind::Shared => {
            state.ownership.entry(root).or_default().shared.insert(dst);
        }
        uniflow_hir::CppOwnershipKind::Weak => {
            state.ownership.entry(root).or_default().weak.insert(dst);
            let validity = state
                .weak_validity
                .get(&src)
                .copied()
                .unwrap_or(BorrowValidity::Valid);
            state.weak_validity.insert(dst, validity);
        }
        _ => {}
    }
}

fn transfer_cpp_owner_move(
    function: &Function,
    dst: ValueId,
    src: ValueId,
    root: ValueId,
    state: &mut LifetimeDataflowState,
) {
    let owner = state.ownership.entry(root).or_default();
    match cpp_ownership_of(function, src) {
        uniflow_hir::CppOwnershipKind::Unique => {
            owner.unique.remove(&src);
            owner.unique.insert(dst);
        }
        uniflow_hir::CppOwnershipKind::Shared => {
            owner.shared.remove(&src);
            owner.shared.insert(dst);
        }
        uniflow_hir::CppOwnershipKind::Weak => {
            owner.weak.remove(&src);
            owner.weak.insert(dst);
            let validity = state
                .weak_validity
                .remove(&src)
                .unwrap_or(BorrowValidity::Valid);
            state.weak_validity.insert(dst, validity);
        }
        _ => register_cpp_owner(function, dst, root, state),
    }
}

fn destroy_cpp_owner_handle(
    function: &Function,
    value: ValueId,
    root: ValueId,
    state: &mut LifetimeDataflowState,
) {
    let kind = cpp_ownership_of(function, value);
    match kind {
        uniflow_hir::CppOwnershipKind::Unique => {
            state.ownership.entry(root).or_default().unique.remove(&value);
            state.handles.insert(value, LifetimeState::Destroyed);
            state.objects.insert(root, LifetimeState::Destroyed);
            invalidate_cpp_borrows(root, state);
        }
        uniflow_hir::CppOwnershipKind::Shared => {
            let (remaining, escaped) = {
                let owner = state.ownership.entry(root).or_default();
                owner.shared.remove(&value);
                (owner.shared.iter().copied().collect::<Vec<_>>(), owner.escaped)
            };
            state.handles.insert(value, LifetimeState::Destroyed);
            // Do not hold a mutable borrow of the ownership table while
            // consulting handle states; this also makes the last-owner rule
            // explicit and deterministic.
            let any_live = remaining.into_iter().any(|handle| {
                matches!(
                    state.handles.get(&handle).copied().unwrap_or(LifetimeState::Alive),
                    LifetimeState::Alive | LifetimeState::MaybeAlive | LifetimeState::Escaped
                )
            });
            if !any_live && !escaped {
                state.objects.insert(root, LifetimeState::Destroyed);
                invalidate_cpp_borrows(root, state);
                expire_cpp_weak_handles(root, state);
            }
        }
        uniflow_hir::CppOwnershipKind::Weak => {
            state.ownership.entry(root).or_default().weak.remove(&value);
            state.weak_validity.remove(&value);
            state.handles.insert(value, LifetimeState::Destroyed);
        }
        _ => {
            state.handles.insert(value, LifetimeState::Destroyed);
            state.objects.insert(root, LifetimeState::Destroyed);
            invalidate_cpp_borrows(root, state);
        }
    }
}

fn propagate_cpp_borrow(dst: ValueId, src: ValueId, state: &mut LifetimeDataflowState) {
    if let Some(root) = state.borrowed_from.get(&src).copied() {
        state.borrowed_from.insert(dst, root);
        let validity = state
            .borrow_validity
            .get(&src)
            .copied()
            .unwrap_or(BorrowValidity::Valid);
        state.borrow_validity.insert(dst, validity);
    }
}

fn merge_cpp_phi_borrow(dst: ValueId, inputs: &[ValueId], state: &mut LifetimeDataflowState) {
    let roots = inputs
        .iter()
        .filter_map(|value| state.borrowed_from.get(value).copied())
        .collect::<HashSet<_>>();
    if roots.len() == 1 {
        state.borrowed_from.insert(dst, *roots.iter().next().expect("one borrow root"));
        let validity = inputs.iter().fold(BorrowValidity::Valid, |current, value| {
            join_borrow_validity(
                current,
                state
                    .borrow_validity
                    .get(value)
                    .copied()
                    .unwrap_or(BorrowValidity::Valid),
            )
        });
        state.borrow_validity.insert(dst, validity);
    }
}

fn invalidate_cpp_borrows(root: ValueId, state: &mut LifetimeDataflowState) {
    let borrowed = state
        .borrowed_from
        .iter()
        .filter_map(|(value, owner_root)| (*owner_root == root).then_some(*value))
        .collect::<Vec<_>>();
    for value in borrowed {
        state.borrow_validity.insert(value, BorrowValidity::Invalid);
    }
}

fn expire_cpp_weak_handles(root: ValueId, state: &mut LifetimeDataflowState) {
    let weak_handles = state
        .ownership
        .get(&root)
        .map(|ownership| ownership.weak.iter().copied().collect::<Vec<_>>())
        .unwrap_or_default();
    for handle in weak_handles {
        state
            .weak_validity
            .insert(handle, BorrowValidity::Invalid);
    }
}

fn join_validity_maps(
    left: &HashMap<ValueId, BorrowValidity>,
    right: &HashMap<ValueId, BorrowValidity>,
) -> HashMap<ValueId, BorrowValidity> {
    let mut values = left.keys().copied().collect::<Vec<_>>();
    values.extend(right.keys().copied());
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .map(|value| {
            let a = left.get(&value).copied().unwrap_or(BorrowValidity::Valid);
            let b = right.get(&value).copied().unwrap_or(BorrowValidity::Valid);
            (value, join_borrow_validity(a, b))
        })
        .collect()
}

fn join_borrow_validity(left: BorrowValidity, right: BorrowValidity) -> BorrowValidity {
    use BorrowValidity::{Invalid, MaybeInvalid, Valid};
    match (left, right) {
        (Valid, Valid) => Valid,
        (Invalid, Invalid) => Invalid,
        (MaybeInvalid, _) | (_, MaybeInvalid) | (Valid, Invalid) | (Invalid, Valid) => MaybeInvalid,
    }
}

fn join_cpp_borrows(
    left: &LifetimeDataflowState,
    right: &LifetimeDataflowState,
) -> (HashMap<ValueId, ValueId>, HashMap<ValueId, BorrowValidity>) {
    let mut values = left.borrowed_from.keys().copied().collect::<Vec<_>>();
    values.extend(right.borrowed_from.keys().copied());
    values.sort_unstable();
    values.dedup();
    let mut borrowed_from = HashMap::new();
    let mut validity = HashMap::new();
    for value in values {
        let left_root = left.borrowed_from.get(&value).copied();
        let right_root = right.borrowed_from.get(&value).copied();
        let root = match (left_root, right_root) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(root), None) | (None, Some(root)) => Some(root),
            _ => None,
        };
        let Some(root) = root else { continue };
        borrowed_from.insert(value, root);
        let left_validity = left
            .borrow_validity
            .get(&value)
            .copied()
            .unwrap_or(BorrowValidity::Valid);
        let right_validity = right
            .borrow_validity
            .get(&value)
            .copied()
            .unwrap_or(BorrowValidity::Valid);
        validity.insert(value, join_borrow_validity(left_validity, right_validity));
    }
    (borrowed_from, validity)
}

fn join_ownership_maps(
    left: &HashMap<ValueId, ObjectOwnershipState>,
    right: &HashMap<ValueId, ObjectOwnershipState>,
) -> HashMap<ValueId, ObjectOwnershipState> {
    let mut out = left.clone();
    for (root, state) in right {
        let entry = out.entry(*root).or_default();
        entry.unique.extend(state.unique.iter().copied());
        entry.shared.extend(state.shared.iter().copied());
        entry.weak.extend(state.weak.iter().copied());
        entry.escaped |= state.escaped;
    }
    out
}

fn cpp_move_consumes_source(function: &Function, value: ValueId) -> bool {
    function.value_cpp.get(&value).is_none_or(|cpp| {
        cpp.ownership == uniflow_hir::CppOwnershipKind::Unique
            || cpp.reference_kind == uniflow_hir::CppReferenceKind::RValue
            || function
                .value_types
                .get(&value)
                .is_some_and(|ty| !matches!(ty.as_str(), "int" | "bool" | "float" | "double" | "char"))
    })
}

fn cpp_call_may_consume_value(function: &Function, value: ValueId) -> bool {
    function.value_cpp.get(&value).is_some_and(|cpp| {
        cpp.ownership == uniflow_hir::CppOwnershipKind::Unique
            || cpp.reference_kind == uniflow_hir::CppReferenceKind::RValue
    })
}

fn call_is_unresolved_or_external(call: &CallInst, internal_names: &HashSet<&str>) -> bool {
    match &call.callee {
        Callee::Unknown | Callee::Dynamic(_) => true,
        Callee::Static(name) => !internal_names.contains(name.as_str()),
    }
}

fn transfer_smart_pointer_call(
    function: &Function,
    call: &CallInst,
    roots: &HashMap<ValueId, ValueId>,
    state: &mut LifetimeDataflowState,
) {
    let Callee::Static(name) = &call.callee else {
        return;
    };
    let method = name.rsplit(|ch| ch == '.' || ch == ':').next().unwrap_or(name.as_str());
    let Some(receiver) = call.receiver else {
        return;
    };
    let root = effective_lifetime_root(roots, state, receiver);
    match method {
        "release" => {
            // unique_ptr::release relinquishes ownership without destroying the pointee and
            // returns a live raw owning handle. Existing get()-borrows remain valid because the
            // object itself was not destroyed.
            let owner = state.ownership.entry(root).or_default();
            owner.unique.remove(&receiver);
            owner.escaped = true;
            state.handles.insert(receiver, LifetimeState::Released);
            state.objects.insert(root, LifetimeState::Escaped);
            if let Some(dst) = call.dst {
                state.handles.insert(dst, LifetimeState::Alive);
                state.dynamic_roots.insert(dst, root);
            }
        }
        "reset" => {
            let kind = cpp_ownership_of(function, receiver);
            let replacement_root = call
                .args
                .first()
                .map(|value| effective_lifetime_root(roots, state, *value));
            match kind {
                uniflow_hir::CppOwnershipKind::Unique => {
                    state.ownership.entry(root).or_default().unique.remove(&receiver);
                    state.objects.insert(root, LifetimeState::Destroyed);
                    invalidate_cpp_borrows(root, state);
                    expire_cpp_weak_handles(root, state);
                    if let Some(new_root) = replacement_root {
                        state.dynamic_roots.insert(receiver, new_root);
                        state
                            .ownership
                            .entry(new_root)
                            .or_default()
                            .unique
                            .insert(receiver);
                        state.handles.insert(receiver, LifetimeState::Alive);
                        state.objects.insert(new_root, LifetimeState::Alive);
                    } else {
                        state.dynamic_roots.remove(&receiver);
                        state.handles.insert(receiver, LifetimeState::Released);
                    }
                }
                uniflow_hir::CppOwnershipKind::Shared => {
                    let (remaining, escaped) = {
                        let ownership = state.ownership.entry(root).or_default();
                        ownership.shared.remove(&receiver);
                        (
                            ownership.shared.iter().copied().collect::<Vec<_>>(),
                            ownership.escaped,
                        )
                    };
                    let any_live = remaining.into_iter().any(|handle| {
                        matches!(
                            lifetime_handle_state(state, handle),
                            LifetimeState::Alive
                                | LifetimeState::MaybeAlive
                                | LifetimeState::Escaped
                        )
                    });
                    if !any_live && !escaped {
                        state.objects.insert(root, LifetimeState::Destroyed);
                        invalidate_cpp_borrows(root, state);
                        expire_cpp_weak_handles(root, state);
                    }
                    if let Some(new_root) = replacement_root {
                        state.dynamic_roots.insert(receiver, new_root);
                        state
                            .ownership
                            .entry(new_root)
                            .or_default()
                            .shared
                            .insert(receiver);
                        state.handles.insert(receiver, LifetimeState::Alive);
                        state.objects.insert(new_root, LifetimeState::Alive);
                    } else {
                        state.dynamic_roots.remove(&receiver);
                        state.handles.insert(receiver, LifetimeState::Released);
                    }
                }
                uniflow_hir::CppOwnershipKind::Weak => {
                    state.ownership.entry(root).or_default().weak.remove(&receiver);
                    state
                        .weak_validity
                        .insert(receiver, BorrowValidity::Invalid);
                    state.dynamic_roots.remove(&receiver);
                    // The weak_ptr object remains alive but empty/expired; lock() is still valid.
                    state.handles.insert(receiver, LifetimeState::Alive);
                }
                _ => {
                    state.objects.insert(root, LifetimeState::Destroyed);
                    invalidate_cpp_borrows(root, state);
                    if let Some(new_root) = replacement_root {
                        state.dynamic_roots.insert(receiver, new_root);
                        state.objects.insert(new_root, LifetimeState::Alive);
                        state.handles.insert(receiver, LifetimeState::Alive);
                    } else {
                        state.dynamic_roots.remove(&receiver);
                        state.handles.insert(receiver, LifetimeState::Released);
                    }
                }
            }
        }
        "lock" => {
            if let Some(dst) = call.dst {
                let object = state.objects.get(&root).copied().unwrap_or(LifetimeState::Unknown);
                let weak = state
                    .weak_validity
                    .get(&receiver)
                    .copied()
                    .unwrap_or(BorrowValidity::Valid);
                let acquired = match (weak, object) {
                    (BorrowValidity::Invalid, _) | (_, LifetimeState::Destroyed) => {
                        LifetimeState::Released
                    }
                    (BorrowValidity::MaybeInvalid, _)
                    | (_, LifetimeState::MaybeDestroyed | LifetimeState::Unknown) => {
                        LifetimeState::MaybeReleased
                    }
                    (_, LifetimeState::Alive | LifetimeState::MaybeAlive) => LifetimeState::Alive,
                    (_, other) => other,
                };
                state.handles.insert(dst, acquired);
                state.dynamic_roots.insert(dst, root);
                // The result is governed by the weak handle's control block, not the temporary
                // SSA root registered for the call result before call-specific semantics ran.
                for ownership in state.ownership.values_mut() {
                    ownership.shared.remove(&dst);
                }
                if matches!(acquired, LifetimeState::Alive | LifetimeState::MaybeAlive) {
                    state.ownership.entry(root).or_default().shared.insert(dst);
                }
            }
        }
        "get" => {
            if let Some(dst) = call.dst {
                state.handles.insert(dst, lifetime_object_state(state, roots, receiver));
                state.dynamic_roots.insert(dst, root);
                state.borrowed_from.insert(dst, root);
                state.borrow_validity.insert(dst, BorrowValidity::Valid);
            }
        }
        "swap" => {
            // Object identities are already may-aliased by the flow graph. Conservatively keep both
            // handles alive; a more precise model can be supplied for concrete library wrappers.
            state.handles.insert(receiver, LifetimeState::Alive);
            if let Some(other) = call.args.first() {
                state.handles.insert(*other, LifetimeState::Alive);
            }
        }
        _ => {}
    }
}

fn lifetime_handle_state(state: &LifetimeDataflowState, value: ValueId) -> LifetimeState {
    state
        .handles
        .get(&value)
        .copied()
        .unwrap_or(LifetimeState::Uninitialized)
}

fn lifetime_object_state(
    state: &LifetimeDataflowState,
    roots: &HashMap<ValueId, ValueId>,
    value: ValueId,
) -> LifetimeState {
    state
        .objects
        .get(&effective_lifetime_root(roots, state, value))
        .copied()
        .unwrap_or(LifetimeState::Unknown)
}

fn combine_handle_and_object_state(handle: LifetimeState, object: LifetimeState) -> LifetimeState {
    if matches!(handle, LifetimeState::MovedFrom | LifetimeState::MaybeMovedFrom | LifetimeState::Released | LifetimeState::MaybeReleased) {
        handle
    } else if matches!(object, LifetimeState::Destroyed | LifetimeState::MaybeDestroyed) {
        object
    } else {
        join_lifetime_state(handle, object)
    }
}

fn join_lifetime_dataflow_states(
    left: &LifetimeDataflowState,
    right: &LifetimeDataflowState,
) -> LifetimeDataflowState {
    let (borrowed_from, borrow_validity) = join_cpp_borrows(left, right);
    LifetimeDataflowState {
        handles: join_lifetime_maps(&left.handles, &right.handles),
        objects: join_lifetime_maps(&left.objects, &right.objects),
        ownership: join_ownership_maps(&left.ownership, &right.ownership),
        dynamic_roots: join_dynamic_root_maps(&left.dynamic_roots, &right.dynamic_roots),
        borrowed_from,
        borrow_validity,
        weak_validity: join_validity_maps(&left.weak_validity, &right.weak_validity),
        field_roots: join_exact_root_maps(&left.field_roots, &right.field_roots),
        index_roots: join_exact_root_maps(&left.index_roots, &right.index_roots),
    }
}

fn join_exact_root_maps<K>(
    left: &HashMap<K, ValueId>,
    right: &HashMap<K, ValueId>,
) -> HashMap<K, ValueId>
where
    K: Clone + Eq + Hash,
{
    left.iter()
        .filter_map(|(key, root)| {
            (right.get(key) == Some(root)).then_some((key.clone(), *root))
        })
        .collect()
}

fn join_dynamic_root_maps(
    left: &HashMap<ValueId, ValueId>,
    right: &HashMap<ValueId, ValueId>,
) -> HashMap<ValueId, ValueId> {
    left.iter()
        .filter_map(|(value, root)| {
            (right.get(value) == Some(root)).then_some((*value, *root))
        })
        .collect()
}

fn join_lifetime_maps(
    left: &HashMap<ValueId, LifetimeState>,
    right: &HashMap<ValueId, LifetimeState>,
) -> HashMap<ValueId, LifetimeState> {
    let mut keys = left.keys().copied().collect::<Vec<_>>();
    keys.extend(right.keys().copied());
    keys.sort_unstable();
    keys.dedup();
    keys.into_iter()
        .map(|key| {
            let a = left.get(&key).copied().unwrap_or(LifetimeState::Uninitialized);
            let b = right.get(&key).copied().unwrap_or(LifetimeState::Uninitialized);
            (key, join_lifetime_state(a, b))
        })
        .collect()
}

fn join_lifetime_state(left: LifetimeState, right: LifetimeState) -> LifetimeState {
    use LifetimeState::*;
    if left == right {
        return left;
    }
    match (left, right) {
        (Unknown, _) | (_, Unknown) => Unknown,
        (Uninitialized, Alive) | (Alive, Uninitialized) | (MaybeAlive, _) | (_, MaybeAlive) => MaybeAlive,
        (MovedFrom, Alive | Uninitialized) | (Alive | Uninitialized, MovedFrom) | (MaybeMovedFrom, _) | (_, MaybeMovedFrom) => MaybeMovedFrom,
        (Released, Alive | Uninitialized) | (Alive | Uninitialized, Released) | (MaybeReleased, _) | (_, MaybeReleased) => MaybeReleased,
        (Destroyed, Alive | Uninitialized | Escaped | Released)
        | (Alive | Uninitialized | Escaped | Released, Destroyed)
        | (MaybeDestroyed, _)
        | (_, MaybeDestroyed) => MaybeDestroyed,
        (Escaped, Alive | Uninitialized) | (Alive | Uninitialized, Escaped) => Escaped,
        (MovedFrom, Released) | (Released, MovedFrom) => MaybeReleased,
        (MovedFrom, Destroyed) | (Destroyed, MovedFrom) => MaybeDestroyed,
        (Released, Escaped) | (Escaped, Released) => Escaped,
        _ => Unknown,
    }
}

fn lifetime_successors(terminator: &Terminator) -> Vec<BlockId> {
    match terminator {
        Terminator::Goto(target) => vec![*target],
        Terminator::Branch { then_bb, else_bb, .. } => vec![*then_bb, *else_bb],
        Terminator::Return(_) | Terminator::Throw(_) | Terminator::Unreachable => Vec::new(),
    }
}
