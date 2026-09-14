//! Basic-block discovery and per-block entry operand-stack shape for one
//! method's bytecode.

use crate::constant_pool::ConstantPool;
use crate::descriptor::{parse_field_descriptor, parse_method_descriptor, JvmType};
use crate::opcodes::{decode_one, MemberKind, MemberRef, OpKind, RawInstr};
use crate::shuffle;
use crate::version::ClassVersion;
use anyhow::{anyhow, Result};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Debug)]
pub struct Block {
    pub start: u32,
    pub instrs: Vec<RawInstr>,
    /// Ordinary control-flow successors (bytecode offsets); exception
    /// unwind edges are tracked separately by the caller using the
    /// classfile exception table.
    pub successors: Vec<u32>,
}

pub struct MethodCfg {
    pub blocks: Vec<Block>,
    pub index_of_start: HashMap<u32, usize>,
    pub predecessors: Vec<Vec<usize>>,
    /// Per-block entry operand-stack shape: `true` = wide (category-2)
    /// entry, ordered bottom-to-top. Handler blocks are seeded with
    /// `[false]` (the caught throwable) rather than derived from ordinary
    /// control flow.
    pub entry_shape: Vec<Vec<bool>>,
}

fn mark_next_leader(instrs: &[RawInstr], index: usize, leaders: &mut BTreeSet<u32>) {
    if let Some(next) = instrs.get(index + 1) {
        leaders.insert(next.offset);
    }
}

fn is_block_ender(kind: &OpKind) -> bool {
    matches!(
        kind,
        OpKind::Goto(_)
            | OpKind::Jsr(_)
            | OpKind::IfZero { .. }
            | OpKind::IfCmp { .. }
            | OpKind::IfNull { .. }
            | OpKind::IfNonNull { .. }
            | OpKind::TableSwitch { .. }
            | OpKind::LookupSwitch { .. }
            | OpKind::Return { .. }
            | OpKind::AThrow
            | OpKind::Ret { .. }
    )
}

pub fn build_cfg(
    code: &[u8],
    pool: &ConstantPool,
    version: ClassVersion,
    handler_starts: &[u32],
) -> Result<MethodCfg> {
    let mut instrs = Vec::new();
    let mut offset = 0usize;
    while offset < code.len() {
        let instr = decode_one(code, offset, pool, version)?;
        offset += instr.size as usize;
        instrs.push(instr);
    }

    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(0);
    for handler_start in handler_starts {
        leaders.insert(*handler_start);
    }
    for (index, instr) in instrs.iter().enumerate() {
        match &instr.kind {
            OpKind::Goto(target) | OpKind::Jsr(target) => {
                leaders.insert(*target);
            }
            OpKind::IfZero { target, .. }
            | OpKind::IfCmp { target, .. }
            | OpKind::IfNull { target }
            | OpKind::IfNonNull { target } => {
                leaders.insert(*target);
            }
            OpKind::TableSwitch { default, targets, .. } => {
                leaders.insert(*default);
                leaders.extend(targets.iter().copied());
            }
            OpKind::LookupSwitch { default, pairs } => {
                leaders.insert(*default);
                leaders.extend(pairs.iter().map(|(_, target)| *target));
            }
            _ => {}
        }
        if is_block_ender(&instr.kind) {
            mark_next_leader(&instrs, index, &mut leaders);
        }
    }

    let leader_vec: Vec<u32> = leaders.into_iter().collect();
    let code_len = code.len() as u32;
    let mut blocks = Vec::with_capacity(leader_vec.len());
    for (block_index, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(block_index + 1).copied().unwrap_or(code_len);
        let block_instrs: Vec<RawInstr> = instrs
            .iter()
            .filter(|instr| instr.offset >= start && instr.offset < end)
            .cloned()
            .collect();
        blocks.push(Block {
            start,
            instrs: block_instrs,
            successors: Vec::new(),
        });
    }
    let index_of_start: HashMap<u32, usize> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| (block.start, index))
        .collect();

    for block in &mut blocks {
        let Some(last) = block.instrs.last() else {
            continue;
        };
        let fallthrough = last.offset + last.size;
        let mut successors = match &last.kind {
            OpKind::Goto(target) | OpKind::Jsr(target) => vec![*target],
            OpKind::IfZero { target, .. }
            | OpKind::IfCmp { target, .. }
            | OpKind::IfNull { target }
            | OpKind::IfNonNull { target } => vec![*target, fallthrough],
            OpKind::TableSwitch { default, targets, .. } => {
                let mut successors = vec![*default];
                successors.extend(targets.iter().copied());
                successors
            }
            OpKind::LookupSwitch { default, pairs } => {
                let mut successors = vec![*default];
                successors.extend(pairs.iter().map(|(_, target)| *target));
                successors
            }
            OpKind::Return { .. } | OpKind::AThrow | OpKind::Ret { .. } => vec![],
            _ => vec![fallthrough],
        };
        successors.retain(|target| index_of_start.contains_key(target));
        successors.sort_unstable();
        successors.dedup();
        block.successors = successors;
    }

    let mut predecessors = vec![Vec::new(); blocks.len()];
    for (index, block) in blocks.iter().enumerate() {
        for successor in &block.successors {
            predecessors[index_of_start[successor]].push(index);
        }
    }

    let entry_shape = compute_entry_shapes(&blocks, &index_of_start, handler_starts)?;

    Ok(MethodCfg {
        blocks,
        index_of_start,
        predecessors,
        entry_shape,
    })
}

fn compute_entry_shapes(
    blocks: &[Block],
    index_of_start: &HashMap<u32, usize>,
    handler_starts: &[u32],
) -> Result<Vec<Vec<bool>>> {
    let mut shape: Vec<Option<Vec<bool>>> = vec![None; blocks.len()];
    if let Some(&entry) = index_of_start.get(&0) {
        shape[entry] = Some(Vec::new());
    }
    for handler_start in handler_starts {
        if let Some(&index) = index_of_start.get(handler_start) {
            // JVMS §2.11.3, §4.10.2.4: control transfers to an exception
            // handler with the operand stack cleared except for the
            // caught throwable, regardless of the stack at the throw site.
            shape[index] = Some(vec![false]);
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for (index, block) in blocks.iter().enumerate() {
            let Some(entry) = shape[index].clone() else {
                continue;
            };
            let exit = simulate_block_shape(block, entry)?;
            for successor in &block.successors {
                let successor_index = index_of_start[successor];
                if shape[successor_index].is_none() {
                    shape[successor_index] = Some(exit.clone());
                    changed = true;
                }
            }
        }
    }

    Ok(shape
        .into_iter()
        .map(|entry| entry.unwrap_or_default())
        .collect())
}

fn simulate_block_shape(block: &Block, entry: Vec<bool>) -> Result<Vec<bool>> {
    let mut stack: Vec<((), bool)> = entry.into_iter().map(|wide| ((), wide)).collect();
    for instr in &block.instrs {
        apply_shape(&instr.kind, &mut stack)?;
    }
    Ok(stack.into_iter().map(|(_, wide)| wide).collect())
}

fn pop_n(stack: &mut Vec<((), bool)>, count: usize) -> Result<()> {
    for _ in 0..count {
        stack
            .pop()
            .ok_or_else(|| anyhow!("operand stack underflow"))?;
    }
    Ok(())
}

fn top_wide(stack: &[((), bool)]) -> Result<bool> {
    Ok(stack
        .last()
        .ok_or_else(|| anyhow!("operand stack underflow"))?
        .1)
}

fn field_slot_width(member: &MemberRef) -> Result<usize> {
    Ok(parse_field_descriptor(&member.descriptor)?.slot_width() as usize)
}

fn apply_shape(kind: &OpKind, stack: &mut Vec<((), bool)>) -> Result<()> {
    match kind {
        OpKind::Nop => {}
        OpKind::ConstNull => stack.push(((), false)),
        OpKind::Ldc { wide, .. } => stack.push(((), *wide)),
        OpKind::Load { wide, .. } => stack.push(((), *wide)),
        OpKind::Store { .. } => pop_n(stack, 1)?,
        OpKind::ArrayLoad { wide } => {
            pop_n(stack, 2)?;
            stack.push(((), *wide));
        }
        OpKind::ArrayStore => pop_n(stack, 3)?,
        OpKind::Pop(count) => shuffle::pop(stack, *count)?,
        OpKind::Dup => shuffle::dup(stack)?,
        OpKind::DupX1 => shuffle::dup_x1(stack)?,
        OpKind::DupX2 => shuffle::dup_x2(stack)?,
        OpKind::Dup2 => shuffle::dup2(stack)?,
        OpKind::Dup2X1 => shuffle::dup2_x1(stack)?,
        OpKind::Dup2X2 => shuffle::dup2_x2(stack)?,
        OpKind::Swap => shuffle::swap(stack)?,
        OpKind::BinaryOp => {
            let wide = top_wide(stack)?;
            pop_n(stack, 2)?;
            stack.push(((), wide));
        }
        OpKind::UnaryNeg => {
            let wide = top_wide(stack)?;
            pop_n(stack, 1)?;
            stack.push(((), wide));
        }
        OpKind::IInc { .. } => {}
        OpKind::Convert { to_wide } => {
            pop_n(stack, 1)?;
            stack.push(((), *to_wide));
        }
        OpKind::Compare => {
            pop_n(stack, 2)?;
            stack.push(((), false));
        }
        OpKind::IfZero { .. } | OpKind::IfNull { .. } | OpKind::IfNonNull { .. } => {
            pop_n(stack, 1)?
        }
        OpKind::IfCmp { .. } => pop_n(stack, 2)?,
        OpKind::Goto(_) | OpKind::Jsr(_) | OpKind::Ret { .. } => {}
        OpKind::TableSwitch { .. } | OpKind::LookupSwitch { .. } => pop_n(stack, 1)?,
        OpKind::Return { has_value } => {
            if *has_value {
                pop_n(stack, 1)?;
            }
        }
        OpKind::GetStatic(member) => stack.push(((), field_slot_width(member)? == 2)),
        OpKind::PutStatic(member) => {
            let _ = field_slot_width(member)?;
            pop_n(stack, 1)?;
        }
        OpKind::GetField(member) => {
            pop_n(stack, 1)?;
            stack.push(((), field_slot_width(member)? == 2));
        }
        // NOTE: every pop/push count below is in *logical entries* (one per
        // JVM value, matching this module's stack model), not raw JVM
        // operand-stack slots — a wide (long/double) value is still exactly
        // one logical entry, just tagged `wide = true`. Only the
        // `shuffle` family (dup/pop2/...) cares about raw slot categories,
        // because those opcodes are themselves defined in terms of them.
        OpKind::PutField(member) => {
            let _ = field_slot_width(member)?; // validates the descriptor parses
            pop_n(stack, 2)?; // objectref, value
        }
        OpKind::Invoke { member, kind } => {
            let (params, ret) = parse_method_descriptor(&member.descriptor)?;
            let receiver = usize::from(!matches!(kind, MemberKind::Static));
            pop_n(stack, params.len() + receiver)?;
            if ret != JvmType::Void {
                stack.push(((), ret.slot_width() == 2));
            }
        }
        OpKind::InvokeDynamic { descriptor, .. } => {
            let (params, ret) = parse_method_descriptor(descriptor)?;
            pop_n(stack, params.len())?;
            if ret != JvmType::Void {
                stack.push(((), ret.slot_width() == 2));
            }
        }
        OpKind::New { .. } => stack.push(((), false)),
        OpKind::NewArray { .. } | OpKind::ANewArray { .. } => {
            pop_n(stack, 1)?;
            stack.push(((), false));
        }
        OpKind::MultiANewArray { dims, .. } => {
            pop_n(stack, *dims as usize)?;
            stack.push(((), false));
        }
        OpKind::ArrayLength => {
            pop_n(stack, 1)?;
            stack.push(((), false));
        }
        OpKind::AThrow => pop_n(stack, 1)?,
        OpKind::CheckCast { .. } => {
            pop_n(stack, 1)?;
            stack.push(((), false));
        }
        OpKind::InstanceOf { .. } => {
            pop_n(stack, 1)?;
            stack.push(((), false));
        }
        OpKind::MonitorEnter | OpKind::MonitorExit => pop_n(stack, 1)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classfile::parse_class_file;

    fn method_code<'a>(
        class: &'a crate::classfile::ClassFile,
        name: &str,
    ) -> &'a crate::classfile::CodeAttr {
        class
            .methods
            .iter()
            .find(|m| m.name == name)
            .and_then(|m| m.code.as_ref())
            .unwrap_or_else(|| panic!("no code for {name}"))
    }

    #[test]
    fn straight_line_method_is_a_single_block() {
        let bytes = include_bytes!("../tests/fixtures/Plain.class");
        let (class, _) = parse_class_file(bytes).unwrap();
        let code = method_code(&class, "run");
        let cfg = build_cfg(&code.code, &class.constant_pool, class.version, &[]).unwrap();
        assert_eq!(cfg.blocks.len(), 1);
        assert_eq!(cfg.entry_shape[0], Vec::<bool>::new());
    }

    #[test]
    fn loop_header_has_two_predecessors_and_empty_entry_shape() {
        let bytes = include_bytes!("../tests/fixtures/Branchy.class");
        let (class, _) = parse_class_file(bytes).unwrap();
        let code = method_code(&class, "loopSum");
        let cfg = build_cfg(&code.code, &class.constant_pool, class.version, &[]).unwrap();
        assert!(cfg.blocks.len() > 3, "{:?}", cfg.blocks.iter().map(|b| b.start).collect::<Vec<_>>());
        let header_index = cfg.index_of_start[&4];
        assert_eq!(cfg.predecessors[header_index].len(), 2);
        assert_eq!(cfg.entry_shape[header_index], Vec::<bool>::new());
        // The if_icmpge at offset 6 ends the header block and branches to
        // the return block at offset 32 (plus the ordinary fallthrough).
        assert!(cfg.blocks[header_index].successors.contains(&32));
    }

    #[test]
    fn exception_handlers_get_a_single_narrow_entry_shape() {
        let bytes = include_bytes!("../tests/fixtures/Branchy.class");
        let (class, _) = parse_class_file(bytes).unwrap();
        let code = method_code(&class, "tryCatch");
        let handler_starts: Vec<u32> = code
            .exception_table
            .iter()
            .map(|entry| entry.handler_pc as u32)
            .collect();
        let cfg = build_cfg(&code.code, &class.constant_pool, class.version, &handler_starts).unwrap();
        for handler_start in [16u32, 31u32] {
            let index = cfg.index_of_start[&handler_start];
            assert_eq!(cfg.entry_shape[index], vec![false], "handler at {handler_start}");
        }
    }
}
