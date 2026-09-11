const ANZU_ARGUMENT_VALIDATION_RULE_ID: &str = "ANZU-ARGUMENT-VALIDATION";

type DefiniteNullnessMap = HashMap<ValueId, NullnessState>;

fn analyze_program_nullness(program: &Program) -> HashMap<(FunctionId, InstId, ValueId), NullnessState> {
    let mut out = HashMap::new();
    for function in &program.functions {
        for ((inst, value), state) in analyze_function_nullness(function) {
            out.insert((function.id, inst, value), state);
        }
    }
    out
}

fn analyze_function_nullness(function: &Function) -> HashMap<(InstId, ValueId), NullnessState> {
    let Some(entry) = function.blocks.first().map(|block| block.id) else {
        return HashMap::new();
    };
    let blocks = function
        .blocks
        .iter()
        .map(|block| (block.id, block))
        .collect::<HashMap<_, _>>();
    let compare_defs = function
        .blocks
        .iter()
        .flat_map(|block| &block.insts)
        .filter_map(|inst| match inst.kind {
            InstKind::Compare { dst, lhs, rhs, op } => Some((dst, (lhs, rhs, op))),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let equivalent_values = nullness_equivalent_values(function);

    let mut block_inputs = HashMap::<BlockId, DefiniteNullnessMap>::new();
    block_inputs.insert(entry, HashMap::new());
    let mut work = VecDeque::from([entry]);
    let mut before_by_inst = HashMap::<InstId, DefiniteNullnessMap>::new();

    while let Some(block_id) = work.pop_front() {
        let Some(block) = blocks.get(&block_id).copied() else {
            continue;
        };
        let mut state = block_inputs.get(&block_id).cloned().unwrap_or_default();

        for inst in &block.insts {
            before_by_inst.insert(inst.id, state.clone());
            transfer_nullness_instruction(function, &mut state, &inst.kind);

            for edge in function
                .exception_edges
                .iter()
                .filter(|edge| edge.from == block_id && edge.source_inst == Some(inst.id))
            {
                if merge_nullness_block_input(
                    entry,
                    edge.unwind,
                    &state,
                    &mut block_inputs,
                ) {
                    work.push_back(edge.unwind);
                }
            }
        }

        for edge in function
            .exception_edges
            .iter()
            .filter(|edge| edge.from == block_id && edge.source_inst.is_none())
        {
            if merge_nullness_block_input(entry, edge.unwind, &state, &mut block_inputs) {
                work.push_back(edge.unwind);
            }
        }

        match block.term {
            Terminator::Goto(target) => {
                if merge_nullness_block_input(entry, target, &state, &mut block_inputs) {
                    work.push_back(target);
                }
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let mut then_state = state.clone();
                let mut else_state = state;
                if let Some(&(lhs, rhs, op)) = compare_defs.get(&cond) {
                    refine_nullness_comparison(
                        &mut then_state,
                        &equivalent_values,
                        lhs,
                        rhs,
                        op,
                        true,
                    );
                    refine_nullness_comparison(
                        &mut else_state,
                        &equivalent_values,
                        lhs,
                        rhs,
                        op,
                        false,
                    );
                }
                if merge_nullness_block_input(entry, then_bb, &then_state, &mut block_inputs) {
                    work.push_back(then_bb);
                }
                if merge_nullness_block_input(entry, else_bb, &else_state, &mut block_inputs) {
                    work.push_back(else_bb);
                }
            }
            Terminator::Return(_) | Terminator::Throw(_) | Terminator::Unreachable => {}
        }
    }

    let mut out = HashMap::new();
    for (inst, values) in before_by_inst {
        for (value, state) in values {
            if state != NullnessState::Unknown {
                out.insert((inst, value), state);
            }
        }
    }
    out
}

fn transfer_nullness_instruction(
    function: &Function,
    state: &mut DefiniteNullnessMap,
    kind: &InstKind,
) {
    match kind {
        InstKind::ConstString { dst, value } if value == "<null>" => {
            set_nullness(state, *dst, NullnessState::DefinitelyNull);
        }
        InstKind::ConstString { dst, .. } => {
            if function
                .value_types
                .get(dst)
                .is_some_and(|ty| cpp_type_is_pointer(ty))
            {
                set_nullness(state, *dst, NullnessState::DefinitelyNonNull);
            } else {
                state.remove(dst);
            }
        }
        InstKind::ConstInt { dst, value } => {
            if *value == 0
                && function
                    .value_types
                    .get(dst)
                    .is_some_and(|ty| cpp_type_is_pointer(ty))
            {
                set_nullness(state, *dst, NullnessState::DefinitelyNull);
            } else {
                state.remove(dst);
            }
        }
        InstKind::Copy { dst, src }
        | InstKind::Move { dst, src }
        | InstKind::Cast { dst, src, .. } => {
            let next = nullness_of(state, *src);
            set_nullness(state, *dst, next);
        }
        InstKind::Phi { dst, inputs } => {
            let joined = if let Some(first) = inputs.first() {
                let first = nullness_of(state, *first);
                if first != NullnessState::Unknown
                    && inputs
                        .iter()
                        .skip(1)
                        .all(|input| nullness_of(state, *input) == first)
                {
                    first
                } else {
                    NullnessState::Unknown
                }
            } else {
                NullnessState::Unknown
            };
            set_nullness(state, *dst, joined);
        }
        InstKind::NumericStep { dst, .. }
        | InstKind::NumericNeg { dst, .. }
        | InstKind::Deref { dst, .. }
        | InstKind::Compare { dst, .. }
        | InstKind::LoadField { dst, .. }
        | InstKind::LoadIndex { dst, .. } => {
            state.remove(dst);
        }
        InstKind::Call(call) => {
            if let Some(dst) = call.dst {
                state.remove(&dst);
            }
        }
        InstKind::Lifetime { .. } | InstKind::StoreField { .. } | InstKind::StoreIndex { .. } => {}
    }
}

fn nullness_equivalent_values(function: &Function) -> HashMap<ValueId, Vec<ValueId>> {
    let mut graph = HashMap::<ValueId, Vec<ValueId>>::new();
    for inst in function.blocks.iter().flat_map(|block| &block.insts) {
        let pair = match inst.kind {
            InstKind::Copy { dst, src }
            | InstKind::Move { dst, src }
            | InstKind::Cast { dst, src, .. } => Some((dst, src)),
            _ => None,
        };
        if let Some((left, right)) = pair {
            graph.entry(left).or_default().push(right);
            graph.entry(right).or_default().push(left);
        }
    }
    graph
}

fn refine_nullness_comparison(
    state: &mut DefiniteNullnessMap,
    equivalent_values: &HashMap<ValueId, Vec<ValueId>>,
    lhs: ValueId,
    rhs: ValueId,
    op: uniflow_ir::ComparisonOp,
    branch_is_true: bool,
) {
    let lhs_state = nullness_of(state, lhs);
    let rhs_state = nullness_of(state, rhs);
    let target = match (lhs_state, rhs_state) {
        (NullnessState::DefinitelyNull, _) => Some(rhs),
        (_, NullnessState::DefinitelyNull) => Some(lhs),
        _ => None,
    };
    let Some(target) = target else {
        return;
    };
    let refined = match (op, branch_is_true) {
        (uniflow_ir::ComparisonOp::Eq, true) | (uniflow_ir::ComparisonOp::Ne, false) => {
            NullnessState::DefinitelyNull
        }
        (uniflow_ir::ComparisonOp::Eq, false) | (uniflow_ir::ComparisonOp::Ne, true) => {
            NullnessState::DefinitelyNonNull
        }
        _ => return,
    };
    refine_equivalent_nullness(state, equivalent_values, target, refined);
}

fn refine_equivalent_nullness(
    state: &mut DefiniteNullnessMap,
    equivalent_values: &HashMap<ValueId, Vec<ValueId>>,
    seed: ValueId,
    refined: NullnessState,
) {
    let mut work = VecDeque::from([seed]);
    let mut seen = HashSet::new();
    while let Some(value) = work.pop_front() {
        if !seen.insert(value) {
            continue;
        }
        set_nullness(state, value, refined);
        for next in equivalent_values.get(&value).into_iter().flatten() {
            work.push_back(*next);
        }
    }
}

fn merge_nullness_block_input(
    entry: BlockId,
    block: BlockId,
    incoming: &DefiniteNullnessMap,
    block_inputs: &mut HashMap<BlockId, DefiniteNullnessMap>,
) -> bool {
    if block == entry {
        return false;
    }
    let Some(current) = block_inputs.get_mut(&block) else {
        block_inputs.insert(block, incoming.clone());
        return true;
    };
    let joined = current
        .iter()
        .filter_map(|(value, current_state)| {
            (incoming.get(value) == Some(current_state)).then_some((*value, *current_state))
        })
        .collect::<HashMap<_, _>>();
    if *current == joined {
        false
    } else {
        *current = joined;
        true
    }
}

fn nullness_of(state: &DefiniteNullnessMap, value: ValueId) -> NullnessState {
    state
        .get(&value)
        .copied()
        .unwrap_or(NullnessState::Unknown)
}

fn set_nullness(state: &mut DefiniteNullnessMap, value: ValueId, next: NullnessState) {
    if next == NullnessState::Unknown {
        state.remove(&value);
    } else {
        state.insert(value, next);
    }
}

fn cpp_type_is_pointer(ty: &str) -> bool {
    let compact = ty
        .replace("const", "")
        .replace("volatile", "")
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    !compact.ends_with('&') && compact.ends_with('*')
}

fn emit_argument_validation_diagnostics(
    flow: &mut FlowGraph,
    caller: &Function,
    inst: &Instruction,
    call: &CallInst,
    resolved_callees: &[&Function],
) {
    if flow.language != Language::Cpp || resolved_callees.len() != 1 {
        return;
    }
    let callee = resolved_callees[0];
    let params = function_param_specs(callee);
    for (index, actual) in call.args.iter().enumerate().take(params.len()) {
        if call
            .arg_origins
            .get(index)
            .is_some_and(|origins| origins.contains(&SourceOriginKind::MacroExpansion))
        {
            continue;
        }
        let Some(actual_type) = caller.value_types.get(actual) else {
            continue;
        };
        if !cpp_type_is_pointer(actual_type)
            || flow
                .nullness_before_insts
                .get(&(caller.id, inst.id, *actual))
                .copied()
                .unwrap_or(NullnessState::Unknown)
                != NullnessState::DefinitelyNull
        {
            continue;
        }
        let Some(span) = call
            .arg_spans
            .get(index)
            .copied()
            .or_else(|| caller.value_spans.get(actual).copied())
        else {
            continue;
        };
        let param_name = params[index].name.clone();
        flow.native_dataflow_diagnostics.push(NativeDataflowDiagnostic {
            rule_id: ANZU_ARGUMENT_VALIDATION_RULE_ID.to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Pointer argument '{}' might be null and should be validated.",
                param_name
            ),
            message_args: vec![param_name],
            function: caller.id,
            instruction: Some(inst.id),
            value: *actual,
            span,
            finding_kind: "native-dataflow".to_string(),
        });
    }
}
