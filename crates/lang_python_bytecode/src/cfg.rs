//! Basic-block discovery and per-block entry operand-stack depth for one
//! code object's bytecode — mirrors `lang_java_bytecode::cfg`'s two-phase
//! design (leaders -> blocks -> fixpoint depth propagation), simplified
//! because CPython's stack has no JVM-style wide/category-2 slot concept:
//! every value is exactly one stack entry.

use std::collections::{BTreeSet, HashMap};

use crate::opcodes::{decode_instructions, jump_target, RawInstr};

#[derive(Clone, Debug)]
pub struct Block {
    pub start: u32,
    pub instrs: Vec<RawInstr>,
    pub successors: Vec<u32>,
}

pub struct CodeCfg {
    pub blocks: Vec<Block>,
    pub index_of_start: HashMap<u32, usize>,
    /// Stack depth live at each block's entry, from a fixpoint over ordinary
    /// control flow. Exception-handler entries (`SETUP_FINALLY`/
    /// `SETUP_WITH`/`SETUP_ASYNC_WITH`'s jump target) are seeded with depth
    /// `1` directly — matching `lang_java_bytecode`'s handling of JVM
    /// exception-handler entry shapes — rather than derived, since properly
    /// modeling CPython's multi-item exception-state stack push is out of
    /// scope for a first pass; this is a documented approximation.
    pub entry_depth: Vec<u32>,
}

fn is_block_ender(name: &str) -> bool {
    matches!(
        name,
        "JUMP_FORWARD"
            | "JUMP_ABSOLUTE"
            | "JUMP_IF_FALSE_OR_POP"
            | "JUMP_IF_TRUE_OR_POP"
            | "POP_JUMP_IF_FALSE"
            | "POP_JUMP_IF_TRUE"
            | "JUMP_IF_NOT_EXC_MATCH"
            | "FOR_ITER"
            | "RETURN_VALUE"
            | "RAISE_VARARGS"
            | "RERAISE"
    )
}

fn exception_handler_targets(name: &str) -> bool {
    matches!(name, "SETUP_FINALLY" | "SETUP_WITH" | "SETUP_ASYNC_WITH")
}

pub fn build_cfg(code: &[u8], jump_in_code_units: bool) -> CodeCfg {
    let instrs = decode_instructions(code);
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(0);
    let mut handler_targets: BTreeSet<u32> = BTreeSet::new();
    for (index, instr) in instrs.iter().enumerate() {
        if let Some(target) = jump_target(instr, jump_in_code_units) {
            leaders.insert(target);
            if exception_handler_targets(instr.name) {
                handler_targets.insert(target);
            }
        }
        if is_block_ender(instr.name) {
            if let Some(next) = instrs.get(index + 1) {
                leaders.insert(next.offset);
            }
        }
    }

    let leader_vec: Vec<u32> = leaders.into_iter().collect();
    let code_len = code.len() as u32;
    let mut blocks = Vec::with_capacity(leader_vec.len());
    for (block_index, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(block_index + 1).copied().unwrap_or(code_len);
        let block_instrs: Vec<RawInstr> = instrs.iter().filter(|instr| instr.offset >= start && instr.offset < end).cloned().collect();
        blocks.push(Block { start, instrs: block_instrs, successors: Vec::new() });
    }
    let index_of_start: HashMap<u32, usize> = blocks.iter().enumerate().map(|(index, block)| (block.start, index)).collect();

    for block in &mut blocks {
        let Some(last) = block.instrs.last() else { continue };
        let fallthrough = last.offset + last.size;
        let mut successors = if let Some(target) = jump_target(last, jump_in_code_units) {
            if matches!(last.name, "JUMP_FORWARD" | "JUMP_ABSOLUTE") {
                vec![target]
            } else if matches!(last.name, "RETURN_VALUE" | "RAISE_VARARGS" | "RERAISE") {
                vec![]
            } else {
                // Conditional jumps and FOR_ITER: both the jump target and
                // the fallthrough are reachable.
                vec![target, fallthrough]
            }
        } else if matches!(last.name, "RETURN_VALUE" | "RAISE_VARARGS" | "RERAISE") {
            vec![]
        } else {
            vec![fallthrough]
        };
        successors.retain(|target| index_of_start.contains_key(target));
        successors.sort_unstable();
        successors.dedup();
        block.successors = successors;
    }

    let entry_depth = compute_entry_depths(&blocks, &index_of_start, &handler_targets, jump_in_code_units);

    CodeCfg { blocks, index_of_start, entry_depth }
}

/// The net stack-depth change (push count minus pop count) contributed by
/// one instruction. Values documented inline are CPython's well-known
/// `ceval.c` push/pop counts for CPython 3.6-3.10; a handful of rare
/// exception/async-machinery opcodes use a conservative approximation
/// rather than a fully precise count (noted per-arm) — acceptable because
/// [`compute_entry_depths`] tolerates a depth mismatch at a merge point
/// (takes the first value seen and moves on) rather than treating it as a
/// hard error, so an approximate delta degrades precision, not soundness of
/// construction.
pub(crate) fn stack_delta(name: &str, oparg: u32) -> i32 {
    let arg = oparg as i32;
    match name {
        "POP_TOP" | "STORE_FAST" | "STORE_NAME" | "STORE_GLOBAL" | "DELETE_ATTR" | "PRINT_EXPR" | "IMPORT_STAR" | "RETURN_VALUE" | "STORE_DEREF" | "LIST_APPEND" | "SET_ADD" => -1,
        "ROT_TWO" | "ROT_THREE" | "ROT_FOUR" | "NOP" | "UNARY_POSITIVE" | "UNARY_NEGATIVE" | "UNARY_NOT" | "UNARY_INVERT" | "GET_ITER" | "GET_YIELD_FROM_ITER" | "GET_AITER" | "GET_AWAITABLE" | "LIST_TO_TUPLE" | "SETUP_ANNOTATIONS" | "YIELD_VALUE" | "POP_BLOCK" | "DELETE_NAME" | "DELETE_GLOBAL" | "DELETE_FAST" | "DELETE_DEREF" | "JUMP_FORWARD" | "JUMP_ABSOLUTE" | "LOAD_ATTR" | "EXTENDED_ARG" | "YIELD_FROM" => 0,
        "DUP_TOP" | "LOAD_CONST" | "LOAD_NAME" | "LOAD_GLOBAL" | "LOAD_FAST" | "LOAD_CLOSURE" | "LOAD_DEREF" | "LOAD_CLASSDEREF" | "LOAD_BUILD_CLASS" | "LOAD_ASSERTION_ERROR" | "IMPORT_FROM" | "GET_ANEXT" | "BEFORE_ASYNC_WITH" => 1,
        "DUP_TOP_TWO" => 2,
        "BINARY_MATRIX_MULTIPLY" | "INPLACE_MATRIX_MULTIPLY" | "BINARY_POWER" | "BINARY_MULTIPLY" | "BINARY_MODULO" | "BINARY_ADD" | "BINARY_SUBTRACT" | "BINARY_SUBSCR" | "BINARY_FLOOR_DIVIDE" | "BINARY_TRUE_DIVIDE" | "INPLACE_FLOOR_DIVIDE" | "INPLACE_TRUE_DIVIDE" | "INPLACE_ADD" | "INPLACE_SUBTRACT" | "INPLACE_MULTIPLY" | "INPLACE_MODULO" | "BINARY_LSHIFT" | "BINARY_RSHIFT" | "BINARY_AND" | "BINARY_XOR" | "BINARY_OR" | "INPLACE_POWER" | "INPLACE_LSHIFT" | "INPLACE_RSHIFT" | "INPLACE_AND" | "INPLACE_XOR" | "INPLACE_OR" | "COMPARE_OP" | "IMPORT_NAME" | "IS_OP" | "CONTAINS_OP" | "LIST_EXTEND" | "SET_UPDATE" | "DICT_MERGE" | "DICT_UPDATE" => -1,
        "STORE_SUBSCR" => -3,
        "DELETE_SUBSCR" | "STORE_ATTR" | "JUMP_IF_NOT_EXC_MATCH" | "MAP_ADD" => -2,
        "UNPACK_SEQUENCE" => arg - 1,
        "UNPACK_EX" => (arg & 0xFF) + ((arg >> 8) & 0xFF),
        "BUILD_TUPLE" | "BUILD_LIST" | "BUILD_SET" | "BUILD_STRING" => 1 - arg,
        "BUILD_MAP" => 1 - 2 * arg,
        "BUILD_CONST_KEY_MAP" => -arg,
        "RAISE_VARARGS" => -arg,
        "CALL_FUNCTION" => -arg,
        "CALL_FUNCTION_KW" => -arg - 1,
        "CALL_METHOD" => -arg - 1,
        "CALL_FUNCTION_EX" => -1 - (arg & 1),
        "MAKE_FUNCTION" => -1 - (arg & 0xF).count_ones() as i32,
        "BUILD_SLICE" => {
            if oparg == 3 {
                -2
            } else {
                -1
            }
        }
        "FORMAT_VALUE" => {
            if oparg & 0x04 != 0 {
                -1
            } else {
                0
            }
        }
        "LOAD_METHOD" => 1,
        // Conditional/iteration jumps: the *linear* (non-branching)
        // instruction stream never reaches here for these names in a
        // meaningful way since they always end a block; kept as a sane
        // default (matches the more-common fallthrough/no-jump edge) for
        // any caller that asks anyway. Real per-edge handling lives in
        // `edge_delta`.
        "JUMP_IF_FALSE_OR_POP" | "JUMP_IF_TRUE_OR_POP" => -1,
        "FOR_ITER" => 1,
        "POP_JUMP_IF_FALSE" | "POP_JUMP_IF_TRUE" => -1,
        // Rare exception/async-machinery opcodes: approximate. Getting
        // these exactly right needs modeling CPython's multi-item
        // exception-state stack, out of scope for a first pass (see the
        // module doc comment).
        "RERAISE" | "POP_EXCEPT" | "END_ASYNC_FOR" | "WITH_EXCEPT_START" => -1,
        "SETUP_WITH" | "SETUP_ASYNC_WITH" => 1,
        "SETUP_FINALLY" => 0,
        _ => 0,
    }
}

/// The depth delta specifically for the edge from a block-ending
/// instruction to `successor` — needed because `FOR_ITER` and
/// `JUMP_IF_{FALSE,TRUE}_OR_POP` have *different* effects on their two
/// successors (an ordinary conditional jump like `POP_JUMP_IF_FALSE` pops
/// the condition on both edges, so it doesn't need this).
fn edge_delta(instr: &RawInstr, successor: u32, jump_in_code_units: bool) -> i32 {
    let target = jump_target(instr, jump_in_code_units);
    match instr.name {
        "FOR_ITER" => {
            if target == Some(successor) {
                -1 // exhausted: pops the iterator, jumps past the loop
            } else {
                1 // continues: keeps the iterator, pushes the next item
            }
        }
        "JUMP_IF_FALSE_OR_POP" | "JUMP_IF_TRUE_OR_POP" => {
            if target == Some(successor) {
                0 // condition matched: value stays on the stack
            } else {
                -1 // fell through: value was popped
            }
        }
        other => stack_delta(other, instr.oparg),
    }
}

fn compute_entry_depths(blocks: &[Block], index_of_start: &HashMap<u32, usize>, handler_targets: &BTreeSet<u32>, jump_in_code_units: bool) -> Vec<u32> {
    let mut depth: Vec<Option<u32>> = vec![None; blocks.len()];
    if let Some(&entry) = index_of_start.get(&0) {
        depth[entry] = Some(0);
    }
    for handler_start in handler_targets {
        if let Some(&index) = index_of_start.get(handler_start) {
            depth[index] = Some(1);
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for (index, block) in blocks.iter().enumerate() {
            let Some(mut running) = depth[index] else { continue };
            let Some(last) = block.instrs.last() else {
                for &successor in &block.successors {
                    let successor_index = index_of_start[&successor];
                    if depth[successor_index].is_none() {
                        depth[successor_index] = Some(running);
                        changed = true;
                    }
                }
                continue;
            };
            for instr in &block.instrs[..block.instrs.len() - 1] {
                running = (running as i32 + stack_delta(instr.name, instr.oparg)).max(0) as u32;
            }
            for &successor in &block.successors {
                let successor_index = index_of_start[&successor];
                let exit_depth = (running as i32 + edge_delta(last, successor, jump_in_code_units)).max(0) as u32;
                if depth[successor_index].is_none() {
                    depth[successor_index] = Some(exit_depth);
                    changed = true;
                }
            }
        }
    }

    depth.into_iter().map(|d| d.unwrap_or(0)).collect()
}
