//! Basic-block discovery over one method's already-decoded `Vec<Instruction>`.
//!
//! Unlike JVM bytecode (see `lang_java_bytecode::cfg`), `dotnetdll` already
//! resolves every branch target to an *instruction index* rather than a raw
//! byte offset, so there is no offset arithmetic to redo here — leaders are
//! simply "index 0", "every branch target", "every exception
//! handler/filter start", and "the instruction right after a block-ending
//! instruction".

use std::collections::{BTreeSet, HashMap};

use dotnetdll::resolved::il::Instruction;

#[derive(Debug, Clone)]
pub struct Block {
    pub start: usize,
    pub end: usize,
    pub successors: Vec<usize>,
}

pub struct MethodCfg {
    pub blocks: Vec<Block>,
    pub index_of_start: HashMap<usize, usize>,
}

fn branch_targets(instr: &Instruction) -> Vec<usize> {
    use Instruction::*;
    match instr {
        BranchEqual(t) | BranchNotEqual(t) | Branch(t) | BranchFalsy(t) | BranchTruthy(t) | Leave(t) => vec![*t],
        BranchGreaterOrEqual(_, t) | BranchGreater(_, t) | BranchLessOrEqual(_, t) | BranchLess(_, t) => vec![*t],
        Switch(targets) => targets.clone(),
        _ => Vec::new(),
    }
}

/// True for an instruction that always ends its basic block — an
/// unconditional/conditional branch, a `switch`, a method-level exit
/// (`ret`/`throw`/`rethrow`/tail `jmp`), or a handler-block exit
/// (`endfinally`/`endfilter`, whose real continuation target depends on the
/// original `leave` site and is not modeled precisely here — see
/// `lower.rs`).
fn is_block_ender(instr: &Instruction) -> bool {
    use Instruction::*;
    matches!(
        instr,
        BranchEqual(_)
            | BranchGreaterOrEqual(..)
            | BranchGreater(..)
            | BranchLessOrEqual(..)
            | BranchLess(..)
            | BranchNotEqual(_)
            | Branch(_)
            | BranchFalsy(_)
            | BranchTruthy(_)
            | Switch(_)
            | Leave(_)
            | Return
            | Throw
            | Rethrow
            | Jump(_)
            | EndFinally
            | EndFilter
    )
}

pub fn build_cfg(instructions: &[Instruction], handler_leaders: &[usize]) -> MethodCfg {
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    leaders.extend(handler_leaders.iter().copied());
    for (index, instr) in instructions.iter().enumerate() {
        leaders.extend(branch_targets(instr));
        if is_block_ender(instr) {
            if let Some(next) = index.checked_add(1) {
                if next < instructions.len() {
                    leaders.insert(next);
                }
            }
        }
    }

    let leader_vec: Vec<usize> = leaders.into_iter().collect();
    let len = instructions.len();
    let mut blocks = Vec::with_capacity(leader_vec.len());
    for (block_index, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(block_index + 1).copied().unwrap_or(len);
        blocks.push(Block { start, end, successors: Vec::new() });
    }
    let index_of_start: HashMap<usize, usize> = blocks.iter().enumerate().map(|(index, block)| (block.start, index)).collect();

    for block in &mut blocks {
        if block.start >= block.end {
            continue; // an empty trailing block (e.g. a handler leader at EOF)
        }
        let last = &instructions[block.end - 1];
        let fallthrough = block.end;
        let mut successors = match last {
            Instruction::BranchEqual(_)
            | Instruction::BranchGreaterOrEqual(..)
            | Instruction::BranchGreater(..)
            | Instruction::BranchLessOrEqual(..)
            | Instruction::BranchLess(..)
            | Instruction::BranchNotEqual(_)
            | Instruction::BranchFalsy(_)
            | Instruction::BranchTruthy(_) => {
                let mut targets = branch_targets(last);
                targets.push(fallthrough);
                targets
            }
            Instruction::Branch(_) | Instruction::Leave(_) => branch_targets(last),
            Instruction::Switch(targets) => {
                let mut successors = targets.clone();
                successors.push(fallthrough);
                successors
            }
            Instruction::Return | Instruction::Throw | Instruction::Rethrow | Instruction::Jump(_) | Instruction::EndFinally | Instruction::EndFilter => Vec::new(),
            _ => vec![fallthrough],
        };
        successors.retain(|target| index_of_start.contains_key(target));
        successors.sort_unstable();
        successors.dedup();
        block.successors = successors;
    }

    MethodCfg { blocks, index_of_start }
}
