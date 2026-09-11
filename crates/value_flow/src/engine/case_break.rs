const ANZU_CASE_BREAK_RULE_ID: &str = "ANZU-CASE-BREAK";
const SOURCE_CASE_PREFIX: &str = "uniflow.source-cfg.case.";
const SOURCE_BREAK_PREFIX: &str = "uniflow.source-cfg.break.";
const SOURCE_RETURN_PREFIX: &str = "uniflow.source-cfg.return.";
const SOURCE_SWITCH_PREFIX: &str = "uniflow.source-cfg.switch.";

#[derive(Clone, Copy, Debug)]
struct SourceCaseBlock {
    block: BlockId,
    span: Span,
    from_macro: bool,
}

fn analyze_case_break_diagnostics(program: &Program) -> Vec<NativeDataflowDiagnostic> {
    if !matches!(program.language, Language::C | Language::Cpp) {
        return Vec::new();
    }

    let mut diagnostics = Vec::new();
    for function in &program.functions {
        let cases = source_case_blocks(function);
        if cases.is_empty() {
            continue;
        }
        let blocks = function
            .blocks
            .iter()
            .map(|block| (block.id, block))
            .collect::<HashMap<_, _>>();
        let case_ids = cases.iter().map(|case| case.block).collect::<HashSet<_>>();

        for case in cases {
            if case.from_macro || case_has_accepted_termination(function, &blocks, &case_ids, case.block)
            {
                continue;
            }
            let value = function
                .params
                .first()
                .or(function.locals.first())
                .copied()
                .unwrap_or(ValueId(u32::MAX));
            diagnostics.push(NativeDataflowDiagnostic {
                rule_id: ANZU_CASE_BREAK_RULE_ID.to_string(),
                severity: "warning".to_string(),
                message: "Case statement without break termination".to_string(),
                message_args: Vec::new(),
                function: function.id,
                instruction: None,
                value,
                span: case.span,
                finding_kind: "native-dataflow".to_string(),
            });
        }
    }
    diagnostics
}

fn source_case_blocks(function: &Function) -> Vec<SourceCaseBlock> {
    let mut cases = function
        .attrs
        .iter()
        .filter_map(|(key, value)| {
            let block = key.strip_prefix(SOURCE_CASE_PREFIX)?.parse::<u32>().ok()?;
            let parts = value.split(',').collect::<Vec<_>>();
            if parts.len() != 8 {
                return None;
            }
            let number = |index: usize| parts[index].parse::<u32>().ok();
            Some(SourceCaseBlock {
                block: BlockId(block),
                span: Span {
                    file: number(0)?,
                    start_byte: number(1)?,
                    end_byte: number(2)?,
                    start_line: number(3)?,
                    start_col: number(4)?,
                    end_line: number(5)?,
                    end_col: number(6)?,
                },
                from_macro: parts[7] == "1",
            })
        })
        .collect::<Vec<_>>();
    cases.sort_by_key(|case| (case.span.file, case.span.start_byte, case.block.0));
    cases
}

fn case_has_accepted_termination(
    function: &Function,
    blocks: &HashMap<BlockId, &uniflow_ir::BasicBlock>,
    case_blocks: &HashSet<BlockId>,
    start: BlockId,
) -> bool {
    let mut visited = HashSet::from([start]);
    let mut queue = VecDeque::from([start]);

    while let Some(current) = queue.pop_front() {
        if current != start && case_blocks.contains(&current) {
            return false;
        }
        if source_cfg_marker(function, SOURCE_BREAK_PREFIX, current) {
            continue;
        }
        if source_cfg_marker(function, SOURCE_SWITCH_PREFIX, current) {
            // Preserve the legacy checker's explicit child-switch exemption.
            return true;
        }

        let Some(block) = blocks.get(&current) else {
            return false;
        };
        if source_cfg_marker(function, SOURCE_RETURN_PREFIX, current) {
            continue;
        }

        let successors = terminator_successors(&block.term);
        let mut found_unvisited_child = false;
        for child in successors {
            if visited.insert(child) {
                queue.push_back(child);
                found_unvisited_child = true;
            }
        }
        if !found_unvisited_child {
            return false;
        }
    }

    true
}

fn source_cfg_marker(function: &Function, prefix: &str, block: BlockId) -> bool {
    function.attrs.contains_key(&format!("{prefix}{}", block.0))
}

fn terminator_successors(term: &Terminator) -> Vec<BlockId> {
    match term {
        Terminator::Goto(target) => vec![*target],
        Terminator::Branch { then_bb, else_bb, .. } => vec![*then_bb, *else_bb],
        Terminator::Return(_) | Terminator::Throw(_) | Terminator::Unreachable => Vec::new(),
    }
}
