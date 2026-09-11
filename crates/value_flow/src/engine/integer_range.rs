const ANZU_ARRAY_INDEX_RULE_ID: &str = "ANZU-ARRAY-INDEX";
const ANZU_ARRAY_BOUND_RULE_ID: &str = "ANZU-ARRAY-BOUND";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct IntegerRange {
    lower: Option<i64>,
    upper: Option<i64>,
}

impl IntegerRange {
    const fn top() -> Self {
        Self {
            lower: None,
            upper: None,
        }
    }

    const fn constant(value: i64) -> Self {
        Self {
            lower: Some(value),
            upper: Some(value),
        }
    }

    const fn non_negative() -> Self {
        Self {
            lower: Some(0),
            upper: None,
        }
    }

    fn singleton(self) -> Option<i64> {
        match (self.lower, self.upper) {
            (Some(lower), Some(upper)) if lower == upper => Some(lower),
            _ => None,
        }
    }

    fn may_contain_negative(self) -> bool {
        self.lower.is_none_or(|lower| lower < 0)
    }

    fn may_contain_zero(self) -> bool {
        self.lower.is_none_or(|lower| lower <= 0)
            && self.upper.is_none_or(|upper| upper >= 0)
    }

    fn intersect(self, other: Self) -> Option<Self> {
        let lower = match (self.lower, other.lower) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        };
        let upper = match (self.upper, other.upper) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        };
        if matches!((lower, upper), (Some(lower), Some(upper)) if lower > upper) {
            None
        } else {
            Some(Self { lower, upper })
        }
    }

    fn shift(self, delta: i64) -> Self {
        let lower = self.lower.and_then(|value| value.checked_add(delta));
        let upper = self.upper.and_then(|value| value.checked_add(delta));
        Self { lower, upper }
    }

    fn negate(self) -> Self {
        let lower = match self.upper {
            Some(value) => match value.checked_neg() {
                Some(value) => Some(value),
                None => return Self::top(),
            },
            None => None,
        };
        let upper = match self.lower {
            Some(value) => match value.checked_neg() {
                Some(value) => Some(value),
                None => return Self::top(),
            },
            None => None,
        };
        Self { lower, upper }
    }
}

type IntegerRangeState = HashMap<ValueId, IntegerRange>;

fn analyze_array_safety_diagnostics(
    program: &Program,
    check_negative_index: bool,
    check_array_bound: bool,
) -> Vec<NativeDataflowDiagnostic> {
    if !matches!(program.language, Language::C | Language::Cpp) {
        return Vec::new();
    }

    program
        .functions
        .iter()
        .flat_map(|function| {
            analyze_function_array_accesses(function, check_negative_index, check_array_bound)
        })
        .collect()
}

fn analyze_function_array_accesses(
    function: &Function,
    check_negative_index: bool,
    check_array_bound: bool,
) -> Vec<NativeDataflowDiagnostic> {
    let Some(entry) = function.blocks.first().map(|block| block.id) else {
        return Vec::new();
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

    let mut block_inputs = HashMap::<BlockId, IntegerRangeState>::new();
    block_inputs.insert(entry, HashMap::new());
    let mut work = VecDeque::from([entry]);
    let mut diagnostics = HashMap::<(InstId, &'static str), NativeDataflowDiagnostic>::new();

    while let Some(block_id) = work.pop_front() {
        let Some(block) = blocks.get(&block_id).copied() else {
            continue;
        };
        let mut state = block_inputs.get(&block_id).cloned().unwrap_or_default();

        for inst in &block.insts {
            if let Some((base, index)) = array_index_access(&inst.kind) {
                if check_negative_index
                    && c_index_type_is_integer(function.value_types.get(&index).map(String::as_str))
                    && integer_range_of(function, &state, index).may_contain_negative()
                {
                    diagnostics
                        .entry((inst.id, ANZU_ARRAY_INDEX_RULE_ID))
                        .or_insert_with(|| NativeDataflowDiagnostic {
                        rule_id: ANZU_ARRAY_INDEX_RULE_ID.to_string(),
                        severity: "warning".to_string(),
                        message: "Array index is less than zero".to_string(),
                        message_args: Vec::new(),
                        function: function.id,
                        instruction: Some(inst.id),
                        value: index,
                        span: function.value_spans.get(&index).copied().unwrap_or(inst.span),
                        finding_kind: "native-dataflow".to_string(),
                    });
                }
                if check_array_bound
                    && !function.instruction_has_source_origin(
                        inst.id,
                        SourceOriginKind::MacroExpansion,
                    )
                    && c_index_type_is_integer(function.value_types.get(&index).map(String::as_str))
                {
                    if let Some(Some(extent)) = function.value_array_extent(base, 0) {
                        let extent_range = integer_range_of(function, &state, extent);
                        // Match the legacy checker exactly: if the zero-size
                        // state is feasible, the checker returns without
                        // emitting an out-of-bounds report.
                        if !extent_range.may_contain_zero() {
                            let index_range = integer_range_of(function, &state, index);
                            let out_of_bounds_feasible =
                                lower_less_equal_upper(extent_range.lower, index_range.upper);
                            if out_of_bounds_feasible {
                                diagnostics
                                    .entry((inst.id, ANZU_ARRAY_BOUND_RULE_ID))
                                    .or_insert_with(|| {
                                    NativeDataflowDiagnostic {
                                        rule_id: ANZU_ARRAY_BOUND_RULE_ID.to_string(),
                                        severity: "warning".to_string(),
                                        message: "Array bound read/write exceeds size".to_string(),
                                        message_args: Vec::new(),
                                        function: function.id,
                                        instruction: Some(inst.id),
                                        value: index,
                                        span: inst.span,
                                        finding_kind: "native-dataflow".to_string(),
                                    }
                                });
                            }
                        }
                    }
                }
            }

            transfer_integer_range_instruction(function, &mut state, &inst.kind);

            for edge in function
                .exception_edges
                .iter()
                .filter(|edge| edge.from == block_id && edge.source_inst == Some(inst.id))
            {
                if merge_integer_range_block_input(entry, edge.unwind, &state, &mut block_inputs) {
                    work.push_back(edge.unwind);
                }
            }
        }

        for edge in function
            .exception_edges
            .iter()
            .filter(|edge| edge.from == block_id && edge.source_inst.is_none())
        {
            if merge_integer_range_block_input(entry, edge.unwind, &state, &mut block_inputs) {
                work.push_back(edge.unwind);
            }
        }

        match block.term {
            Terminator::Goto(target) => {
                if merge_integer_range_block_input(entry, target, &state, &mut block_inputs) {
                    work.push_back(target);
                }
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                if let Some(&(lhs, rhs, op)) = compare_defs.get(&cond) {
                    if comparison_branch_feasible(function, &state, lhs, rhs, op, true) {
                        let mut then_state = state.clone();
                        if refine_integer_comparison(
                            function,
                            &mut then_state,
                            lhs,
                            rhs,
                            op,
                            true,
                        ) && merge_integer_range_block_input(
                            entry,
                            then_bb,
                            &then_state,
                            &mut block_inputs,
                        ) {
                            work.push_back(then_bb);
                        }
                    }
                    if comparison_branch_feasible(function, &state, lhs, rhs, op, false) {
                        let mut else_state = state;
                        if refine_integer_comparison(
                            function,
                            &mut else_state,
                            lhs,
                            rhs,
                            op,
                            false,
                        ) && merge_integer_range_block_input(
                            entry,
                            else_bb,
                            &else_state,
                            &mut block_inputs,
                        ) {
                            work.push_back(else_bb);
                        }
                    }
                } else {
                    if merge_integer_range_block_input(entry, then_bb, &state, &mut block_inputs) {
                        work.push_back(then_bb);
                    }
                    if merge_integer_range_block_input(entry, else_bb, &state, &mut block_inputs) {
                        work.push_back(else_bb);
                    }
                }
            }
            Terminator::Return(_) | Terminator::Throw(_) | Terminator::Unreachable => {}
        }
    }

    let mut diagnostics = diagnostics.into_values().collect::<Vec<_>>();
    diagnostics.sort_by(|left, right| {
        left.instruction
            .map(|inst| inst.0)
            .unwrap_or(0)
            .cmp(&right.instruction.map(|inst| inst.0).unwrap_or(0))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    diagnostics
}

fn array_index_access(kind: &InstKind) -> Option<(ValueId, ValueId)> {
    match kind {
        InstKind::LoadIndex { base, index, .. } | InstKind::StoreIndex { base, index, .. } => {
            Some((*base, *index))
        }
        _ => None,
    }
}

fn transfer_integer_range_instruction(
    function: &Function,
    state: &mut IntegerRangeState,
    kind: &InstKind,
) {
    match kind {
        InstKind::ConstInt { dst, value } => {
            set_integer_range(function, state, *dst, IntegerRange::constant(*value));
        }
        InstKind::Copy { dst, src } | InstKind::Move { dst, src } => {
            let range = integer_range_of(function, state, *src);
            set_integer_range(function, state, *dst, range);
        }
        InstKind::Cast {
            dst,
            src,
            target_type,
            ..
        } => {
            if c_index_type_is_integer(target_type.as_deref().or_else(|| {
                function.value_types.get(dst).map(String::as_str)
            })) {
                let range = integer_range_of(function, state, *src);
                set_integer_range(function, state, *dst, range);
            } else {
                state.remove(dst);
            }
        }
        InstKind::NumericStep {
            dst,
            src,
            increment,
        } => {
            let range = integer_range_of(function, state, *src)
                .shift(if *increment { 1 } else { -1 });
            set_integer_range(function, state, *dst, range);
        }
        InstKind::NumericNeg { dst, src } => {
            let range = integer_range_of(function, state, *src).negate();
            set_integer_range(function, state, *dst, range);
        }
        InstKind::Phi { dst, inputs } => {
            let range = inputs.iter().copied().fold(None, |joined, input| {
                let incoming = integer_range_of(function, state, input);
                Some(match joined {
                    None => incoming,
                    Some(current) => union_integer_ranges(current, incoming),
                })
            });
            if let Some(range) = range {
                set_integer_range(function, state, *dst, range);
            } else {
                state.remove(dst);
            }
        }
        InstKind::Compare { dst, .. } => {
            state.insert(
                *dst,
                IntegerRange {
                    lower: Some(0),
                    upper: Some(1),
                },
            );
        }
        InstKind::ConstString { dst, .. }
        | InstKind::Deref { dst, .. }
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

fn integer_range_of(
    function: &Function,
    state: &IntegerRangeState,
    value: ValueId,
) -> IntegerRange {
    state.get(&value).copied().unwrap_or_else(|| {
        if c_integer_type_is_unsigned(function.value_types.get(&value).map(String::as_str)) {
            IntegerRange::non_negative()
        } else {
            IntegerRange::top()
        }
    })
}

fn set_integer_range(
    function: &Function,
    state: &mut IntegerRangeState,
    value: ValueId,
    range: IntegerRange,
) {
    let range = if c_integer_type_is_unsigned(function.value_types.get(&value).map(String::as_str)) {
        range
            .intersect(IntegerRange::non_negative())
            .unwrap_or_else(IntegerRange::non_negative)
    } else {
        range
    };
    if range == IntegerRange::top() {
        state.remove(&value);
    } else {
        state.insert(value, range);
    }
}

fn merge_integer_range_block_input(
    entry: BlockId,
    block: BlockId,
    incoming: &IntegerRangeState,
    block_inputs: &mut HashMap<BlockId, IntegerRangeState>,
) -> bool {
    if block == entry {
        return false;
    }
    let Some(current) = block_inputs.get_mut(&block) else {
        block_inputs.insert(block, incoming.clone());
        return true;
    };

    let mut joined = IntegerRangeState::new();
    for (value, current_range) in current.iter() {
        let Some(incoming_range) = incoming.get(value) else {
            continue;
        };
        let widened = widen_integer_ranges(*current_range, *incoming_range);
        if widened != IntegerRange::top() {
            joined.insert(*value, widened);
        }
    }
    if *current == joined {
        false
    } else {
        *current = joined;
        true
    }
}

fn union_integer_ranges(left: IntegerRange, right: IntegerRange) -> IntegerRange {
    IntegerRange {
        lower: match (left.lower, right.lower) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        },
        upper: match (left.upper, right.upper) {
            (Some(left), Some(right)) => Some(left.max(right)),
            _ => None,
        },
    }
}

fn widen_integer_ranges(current: IntegerRange, incoming: IntegerRange) -> IntegerRange {
    IntegerRange {
        lower: match (current.lower, incoming.lower) {
            (Some(current), Some(incoming)) if incoming >= current => Some(current),
            (Some(_), Some(_)) | (Some(_), None) | (None, _) => None,
        },
        upper: match (current.upper, incoming.upper) {
            (Some(current), Some(incoming)) if incoming <= current => Some(current),
            (Some(_), Some(_)) | (Some(_), None) | (None, _) => None,
        },
    }
}

fn comparison_branch_feasible(
    function: &Function,
    state: &IntegerRangeState,
    lhs: ValueId,
    rhs: ValueId,
    op: uniflow_ir::ComparisonOp,
    branch_is_true: bool,
) -> bool {
    let lhs = integer_range_of(function, state, lhs);
    let rhs = integer_range_of(function, state, rhs);
    let true_feasible = match op {
        uniflow_ir::ComparisonOp::Eq => ranges_overlap(lhs, rhs),
        uniflow_ir::ComparisonOp::Ne => lhs.singleton().zip(rhs.singleton()).is_none_or(|(l, r)| l != r),
        uniflow_ir::ComparisonOp::Lt => lower_less_than_upper(lhs.lower, rhs.upper),
        uniflow_ir::ComparisonOp::Le => lower_less_equal_upper(lhs.lower, rhs.upper),
        uniflow_ir::ComparisonOp::Gt => lower_less_than_upper(rhs.lower, lhs.upper),
        uniflow_ir::ComparisonOp::Ge => lower_less_equal_upper(rhs.lower, lhs.upper),
        uniflow_ir::ComparisonOp::In => true,
    };
    let false_feasible = match op {
        uniflow_ir::ComparisonOp::Eq => lhs.singleton().zip(rhs.singleton()).is_none_or(|(l, r)| l != r),
        uniflow_ir::ComparisonOp::Ne => ranges_overlap(lhs, rhs),
        uniflow_ir::ComparisonOp::Lt => upper_greater_equal_lower(lhs.upper, rhs.lower),
        uniflow_ir::ComparisonOp::Le => upper_greater_than_lower(lhs.upper, rhs.lower),
        uniflow_ir::ComparisonOp::Gt => upper_greater_equal_lower(rhs.upper, lhs.lower),
        uniflow_ir::ComparisonOp::Ge => upper_greater_than_lower(rhs.upper, lhs.lower),
        uniflow_ir::ComparisonOp::In => true,
    };
    if branch_is_true {
        true_feasible
    } else {
        false_feasible
    }
}

fn refine_integer_comparison(
    function: &Function,
    state: &mut IntegerRangeState,
    lhs: ValueId,
    rhs: ValueId,
    op: uniflow_ir::ComparisonOp,
    branch_is_true: bool,
) -> bool {
    let lhs_range = integer_range_of(function, state, lhs);
    let rhs_range = integer_range_of(function, state, rhs);
    if let Some(constant) = rhs_range.singleton() {
        if !refine_value_against_constant(function, state, lhs, op, branch_is_true, constant) {
            return false;
        }
    }
    if let Some(constant) = lhs_range.singleton() {
        if !refine_value_against_constant(
            function,
            state,
            rhs,
            reverse_comparison(op),
            branch_is_true,
            constant,
        ) {
            return false;
        }
    }
    true
}

fn refine_value_against_constant(
    function: &Function,
    state: &mut IntegerRangeState,
    value: ValueId,
    op: uniflow_ir::ComparisonOp,
    branch_is_true: bool,
    constant: i64,
) -> bool {
    use uniflow_ir::ComparisonOp::{Eq, Ge, Gt, In, Le, Lt, Ne};

    let constraint = match (op, branch_is_true) {
        (Lt, true) | (Ge, false) => IntegerRange {
            lower: None,
            upper: constant.checked_sub(1),
        },
        (Lt, false) | (Ge, true) => IntegerRange {
            lower: Some(constant),
            upper: None,
        },
        (Le, true) | (Gt, false) => IntegerRange {
            lower: None,
            upper: Some(constant),
        },
        (Le, false) | (Gt, true) => IntegerRange {
            lower: constant.checked_add(1),
            upper: None,
        },
        (Eq, true) | (Ne, false) => IntegerRange::constant(constant),
        (Eq, false) | (Ne, true) | (In, _) => return true,
    };
    let current = integer_range_of(function, state, value);
    let Some(refined) = current.intersect(constraint) else {
        return false;
    };
    set_integer_range(function, state, value, refined);
    true
}

fn reverse_comparison(op: uniflow_ir::ComparisonOp) -> uniflow_ir::ComparisonOp {
    use uniflow_ir::ComparisonOp::{Eq, Ge, Gt, In, Le, Lt, Ne};
    match op {
        Eq => Eq,
        Ne => Ne,
        Lt => Gt,
        Le => Ge,
        Gt => Lt,
        Ge => Le,
        In => In,
    }
}

fn ranges_overlap(left: IntegerRange, right: IntegerRange) -> bool {
    lower_less_equal_upper(left.lower, right.upper)
        && lower_less_equal_upper(right.lower, left.upper)
}

fn lower_less_than_upper(lower: Option<i64>, upper: Option<i64>) -> bool {
    match (lower, upper) {
        (Some(lower), Some(upper)) => lower < upper,
        _ => true,
    }
}

fn lower_less_equal_upper(lower: Option<i64>, upper: Option<i64>) -> bool {
    match (lower, upper) {
        (Some(lower), Some(upper)) => lower <= upper,
        _ => true,
    }
}

fn upper_greater_equal_lower(upper: Option<i64>, lower: Option<i64>) -> bool {
    match (upper, lower) {
        (Some(upper), Some(lower)) => upper >= lower,
        _ => true,
    }
}

fn upper_greater_than_lower(upper: Option<i64>, lower: Option<i64>) -> bool {
    match (upper, lower) {
        (Some(upper), Some(lower)) => upper > lower,
        _ => true,
    }
}

fn c_index_type_is_integer(ty: Option<&str>) -> bool {
    let Some(ty) = ty else {
        return false;
    };
    let normalized = ty.to_ascii_lowercase();
    if normalized.contains('*')
        || normalized.contains('&')
        || normalized.contains("float")
        || normalized.contains("double")
    {
        return false;
    }
    [
        "int", "short", "long", "char", "bool", "size_t", "ssize_t", "ptrdiff_t",
        "wchar_t", "char16_t", "char32_t", "enum",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn c_integer_type_is_unsigned(ty: Option<&str>) -> bool {
    let Some(ty) = ty else {
        return false;
    };
    let normalized = ty.to_ascii_lowercase();
    normalized.contains("unsigned")
        || normalized.contains("size_t") && !normalized.contains("ssize_t")
        || normalized.contains("uint")
}
