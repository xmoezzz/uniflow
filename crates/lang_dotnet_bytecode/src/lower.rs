//! Stack-machine abstract interpretation: turns one method's CIL
//! instruction stream + `cfg::MethodCfg` into an `ir::Function`, mirroring
//! `lang_java_bytecode::lower`'s design (every non-entry block gets fresh
//! `Phi` placeholders for all locals and its entry operand-stack depth,
//! patched from every predecessor's exit state once every block has been
//! simulated once). Unlike JVM bytecode, CIL has no wide/narrow (category-2)
//! stack-slot distinction, so the entry-depth pre-pass here tracks a plain
//! integer depth instead of a per-slot width tag.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use dotnetdll::resolution::Resolution;
use dotnetdll::resolved::body;
use dotnetdll::resolved::il::Instruction;
use dotnetdll::resolved::members::Method;
use indexmap::IndexMap;
use uniflow_hir::Span;
use uniflow_ir::{BasicBlock, BlockId, CallInst, Callee, ComparisonOp, ExceptionEdge, Function, FunctionId, InstId, InstKind, Instruction as IrInstruction, Terminator, Type as IrType, ValueId};

use crate::cfg::{build_cfg, Block, MethodCfg};
use crate::names::{field_source_name, method_source_name, method_source_signature};

/// Net operand-stack depth change of one instruction, for the entry-depth
/// pre-pass only (no value identities involved). Terminator-only
/// instructions (`ret`/`throw`/`leave`/...) return `0`: their block has no
/// ordinary-flow successor that would need the result, and CIL's verifier
/// requires the stack to already be in the shape those instructions expect
/// (e.g. empty at `leave`) — so leaving them at 0 is not just "don't care",
/// it is required by spec to reflect the correct known state.
fn depth_delta(res: &Resolution, instr: &Instruction) -> i64 {
    use Instruction::*;
    match instr {
        Add | Subtract | Multiply | Divide(_) | Remainder(_) | And | Or | Xor | ShiftLeft | ShiftRight(_) | AddOverflow(_) | SubtractOverflow(_) | MultiplyOverflow(_) | CompareEqual
        | CompareGreater(_) | CompareLess(_) => -1,
        CheckFinite | Negate | Not | Convert(_) | ConvertOverflow(..) | ConvertFloat32 | ConvertFloat64 | ConvertUnsignedToFloat => 0,
        Duplicate => 1,
        Pop => -1,
        LoadConstantInt32(_) | LoadConstantInt64(_) | LoadConstantFloat32(_) | LoadConstantFloat64(_) | LoadString(_) | LoadNull => 1,
        LoadArgument(_) | LoadArgumentAddress(_) | LoadLocal(_) | LoadLocalAddress(_) => 1,
        StoreArgument(_) | StoreLocal(_) => -1,
        LoadIndirect { .. } => 0,
        StoreIndirect { .. } => -2,
        LoadField { .. } | LoadFieldAddress(_) | LoadFieldSkipNullCheck(_) => 0,
        StoreField { .. } | StoreFieldSkipNullCheck(_) => -2,
        LoadStaticField { .. } | LoadStaticFieldAddress(_) => 1,
        StoreStaticField { .. } => -1,
        LoadElement { .. } | LoadElementPrimitive { .. } | LoadElementAddress { .. } | LoadElementAddressReadonly(_) => -1,
        StoreElement { .. } | StoreElementPrimitive { .. } => -3,
        LoadLength => 0,
        NewArray(_) => 0,
        NewObject(method) => 1 - method_signature_arity(res, method),
        Call { param0, .. } | CallVirtual { param0, .. } | CallConstrained(_, param0) | CallVirtualConstrained(_, param0) | CallVirtualTail(param0) => call_delta(res, param0),
        CallIndirect { param0, .. } => {
            let popped = param0.parameters.len() + usize::from(param0.instance) + 1;
            let pushed = usize::from(param0.return_type.1.is_some());
            pushed as i64 - popped as i64
        }
        BoxValue(_) | UnboxIntoAddress { .. } | UnboxIntoValue(_) | CastClass { .. } | IsInstance(_) => 0,
        CopyObject(_) => -2,
        InitializeForObject(_) => -1,
        LoadObject { .. } => 0,
        StoreObject { .. } => -2,
        CopyMemoryBlock { .. } | InitializeMemoryBlock { .. } => -3,
        LocalMemoryAllocate => 0,
        MakeTypedReference(_) | ReadTypedReferenceValue(_) => 0,
        ReadTypedReferenceType => 0,
        Sizeof(_) | LoadTokenField(_) | LoadTokenMethod(_) | LoadTokenType(_) | LoadMethodPointer(_) | ArgumentList => 1,
        LoadVirtualMethodPointer { .. } => 0,
        Switch(_) => -1,
        Breakpoint | NoOperation => 0,
        // Block-ending / terminator-only instructions: their block has no
        // ordinary-flow successor, so the delta is never consumed.
        BranchEqual(_) | BranchGreaterOrEqual(..) | BranchGreater(..) | BranchLessOrEqual(..) | BranchLess(..) | BranchNotEqual(_) => -1,
        BranchFalsy(_) | BranchTruthy(_) => -1,
        Branch(_) | Leave(_) | Return | Throw | Rethrow | Jump(_) | EndFinally | EndFilter => 0,
    }
}

fn method_signature_arity(res: &Resolution, method: &dotnetdll::resolved::members::UserMethod) -> i64 {
    crate::names::user_method_signature(res, method).parameters.len() as i64
}

fn call_delta(res: &Resolution, source: &dotnetdll::resolved::members::MethodSource) -> i64 {
    let sig = method_source_signature(res, source);
    let popped = sig.parameters.len() + usize::from(sig.instance);
    let pushed = usize::from(sig.return_type.1.is_some());
    pushed as i64 - popped as i64
}

fn compute_entry_depths(res: &Resolution, instructions: &[Instruction], cfg: &MethodCfg) -> Vec<usize> {
    let mut depth: Vec<Option<i64>> = vec![None; cfg.blocks.len()];
    if let Some(&entry) = cfg.index_of_start.get(&0) {
        depth[entry] = Some(0);
    }
    let mut changed = true;
    while changed {
        changed = false;
        for (index, block) in cfg.blocks.iter().enumerate() {
            let Some(entry_depth) = depth[index] else { continue };
            if block.start >= block.end {
                continue;
            }
            let exit_depth = instructions[block.start..block.end].iter().fold(entry_depth, |acc, instr| acc + depth_delta(res, instr)).max(0);
            for &successor in &block.successors {
                if let Some(&successor_index) = cfg.index_of_start.get(&successor) {
                    if depth[successor_index].is_none() {
                        depth[successor_index] = Some(exit_depth);
                        changed = true;
                    }
                }
            }
        }
    }
    depth.into_iter().map(|d| d.unwrap_or(0).max(0) as usize).collect()
}

struct MethodBuilder<'a> {
    res: &'a Resolution<'a>,
    label: String,
    next_value: u32,
    next_inst: u32,
    next_block: u32,
    all_values: Vec<ValueId>,
    diagnostics: Vec<String>,
    extra_blocks: Vec<BasicBlock>,
}

impl<'a> MethodBuilder<'a> {
    fn fresh_value(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value += 1;
        self.all_values.push(id);
        id
    }
    fn fresh_inst(&mut self) -> InstId {
        let id = InstId(self.next_inst);
        self.next_inst += 1;
        id
    }
    fn fresh_block_id(&mut self) -> BlockId {
        let id = BlockId(self.next_block);
        self.next_block += 1;
        id
    }
    fn diagnostic(&mut self, message: impl Into<String>) {
        self.diagnostics.push(format!("{}: {}", self.label, message.into()));
    }
}

/// A CIL `switch` pops one selector and jumps to `targets[selector]` (or
/// falls through if out of range) — modeled as a chain of synthetic
/// equality-branch blocks, exactly mirroring
/// `lang_java_bytecode::lower::lower_switch_chain`'s handling of JVM's
/// `tableswitch`/`lookupswitch`.
fn lower_switch_chain(builder: &mut MethodBuilder, selector: ValueId, fallthrough: BlockId, targets: &[BlockId]) -> BlockId {
    let mut next_target = fallthrough;
    for (case_index, &target) in targets.iter().enumerate().rev() {
        let block_id = builder.fresh_block_id();
        let mut insts = Vec::new();
        let case_value = const_int(builder, &mut insts, case_index as i64);
        let cond = builder.fresh_value();
        insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Compare { dst: cond, lhs: selector, rhs: case_value, op: ComparisonOp::Eq }, span: Span::default() });
        let term = Terminator::Branch { cond, then_bb: target, else_bb: next_target };
        builder.extra_blocks.push(BasicBlock { id: block_id, insts, term });
        next_target = block_id;
    }
    next_target
}

fn const_string(builder: &mut MethodBuilder, insts: &mut Vec<IrInstruction>, value: String) -> ValueId {
    let dst = builder.fresh_value();
    insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::ConstString { dst, value }, span: Span::default() });
    dst
}

fn const_int(builder: &mut MethodBuilder, insts: &mut Vec<IrInstruction>, value: i64) -> ValueId {
    let dst = builder.fresh_value();
    insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::ConstInt { dst, value }, span: Span::default() });
    dst
}

fn synthetic_call(builder: &mut MethodBuilder, insts: &mut Vec<IrInstruction>, callee: &str, args: Vec<ValueId>) -> ValueId {
    let dst = builder.fresh_value();
    insts.push(IrInstruction {
        id: builder.fresh_inst(),
        kind: InstKind::Call(CallInst { dst: Some(dst), callee: Callee::Static(callee.to_string()), receiver: None, args, arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }),
        span: Span::default(),
    });
    dst
}

fn pop1(stack: &mut Vec<ValueId>) -> Result<ValueId> {
    stack.pop().ok_or_else(|| anyhow!("operand stack underflow"))
}

fn pop_n(stack: &mut Vec<ValueId>, count: usize) -> Result<Vec<ValueId>> {
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(pop1(stack)?);
    }
    values.reverse();
    Ok(values)
}

/// Lowers every method with a decoded body on `type_def` (identified by
/// `parent_type_name`, already resolved by the caller) into `ir::Function`s.
/// `next_function_id` supplies the (program-wide) `FunctionId` for each
/// method in turn.
/// Lowers one method (if it has a decoded IL body — abstract/`extern`
/// methods have none and are skipped by the caller) into an `ir::Function`
/// named `{parent_type_name}.{method.name}`.
pub fn lower_method(res: &Resolution, parent_type_name: &str, method: &Method, id: FunctionId, diagnostics: &mut Vec<String>) -> Option<Function> {
    let body = method.body.as_ref()?;
    let label = format!("{parent_type_name}.{}", method.name);
    match lower_method_body(res, method, body, &label, id) {
        Ok((function, mut method_diagnostics)) => {
            diagnostics.append(&mut method_diagnostics);
            Some(function)
        }
        Err(error) => {
            diagnostics.push(format!("{label}: failed to lower method body: {error}"));
            None
        }
    }
}

fn exception_handler_leaders(exceptions: &[body::Exception]) -> Vec<usize> {
    let mut leaders = Vec::new();
    for exception in exceptions {
        leaders.push(exception.handler_offset);
        if let body::ExceptionKind::Filter { offset } = exception.kind {
            leaders.push(offset);
        }
    }
    leaders
}

fn lower_method_body(res: &Resolution, method: &Method, body: &body::Method, label: &str, id: FunctionId) -> Result<(Function, Vec<String>)> {
    let instructions = &body.instructions;
    let exceptions: Vec<&body::Exception> = body
        .data_sections
        .iter()
        .filter_map(|section| match section {
            body::DataSection::ExceptionHandlers(exceptions) => Some(exceptions.iter()),
            body::DataSection::Unrecognized { .. } => None,
        })
        .flatten()
        .collect();
    let owned_exceptions: Vec<body::Exception> = exceptions.iter().map(|e| (*e).clone()).collect();
    let handler_leaders = exception_handler_leaders(&owned_exceptions);
    let cfg = build_cfg(instructions, &handler_leaders);
    let entry_depths = compute_entry_depths(res, instructions, &cfg);

    let block_count = cfg.blocks.len();
    let mut builder = MethodBuilder { res, label: label.to_string(), next_value: 0, next_inst: 0, next_block: block_count as u32, all_values: Vec::new(), diagnostics: Vec::new(), extra_blocks: Vec::new() };

    let mut args: Vec<ValueId> = Vec::new();
    if method.signature.instance {
        args.push(builder.fresh_value());
    }
    for _ in &method.signature.parameters {
        args.push(builder.fresh_value());
    }
    let local_count = body.header.local_variables.len();

    let entry_block_index = cfg.index_of_start.get(&0).copied();
    let handler_block_indices: HashSet<usize> = handler_leaders.iter().filter_map(|leader| cfg.index_of_start.get(leader).copied()).collect();

    let mut block_entry_locals: Vec<Vec<Option<ValueId>>> = Vec::with_capacity(block_count);
    let mut block_entry_stack: Vec<Vec<ValueId>> = Vec::with_capacity(block_count);
    let mut is_phi_block = vec![true; block_count];
    for index in 0..block_count {
        if Some(index) == entry_block_index {
            is_phi_block[index] = false;
            block_entry_locals.push(vec![None; local_count]);
            block_entry_stack.push(Vec::new());
        } else if handler_block_indices.contains(&index) {
            // A catch/filter handler begins with the exception object as
            // the sole stack entry (a `finally`/`fault` handler begins with
            // an empty stack instead, but giving it one unused phi slot is
            // harmless — nothing reads it).
            block_entry_locals.push((0..local_count).map(|_| Some(builder.fresh_value())).collect());
            block_entry_stack.push(vec![builder.fresh_value()]);
        } else {
            let locals_phi: Vec<Option<ValueId>> = (0..local_count).map(|_| Some(builder.fresh_value())).collect();
            let stack_phi: Vec<ValueId> = (0..entry_depths[index]).map(|_| builder.fresh_value()).collect();
            block_entry_locals.push(locals_phi);
            block_entry_stack.push(stack_phi);
        }
    }

    let block_id_of_start: HashMap<usize, BlockId> = cfg.index_of_start.iter().map(|(&start, &index)| (start, BlockId(index as u32))).collect();

    let mut results: Vec<(Vec<IrInstruction>, Terminator, Vec<Option<ValueId>>, Vec<ValueId>)> = Vec::with_capacity(block_count);
    for index in 0..block_count {
        let block = &cfg.blocks[index];
        let stack = block_entry_stack[index].clone();
        let locals = block_entry_locals[index].clone();
        let result = lower_block(&mut builder, instructions, block, stack, locals, &args, &block_id_of_start)?;
        results.push(result);
    }

    let mut locals_phi_inputs: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    let mut stack_phi_inputs: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for (from_index, block) in cfg.blocks.iter().enumerate() {
        let (_, _, exit_locals, exit_stack) = &results[from_index];
        for &successor in &block.successors {
            let Some(&successor_index) = cfg.index_of_start.get(&successor) else { continue };
            if !is_phi_block[successor_index] {
                continue;
            }
            for (slot, phi_value) in block_entry_locals[successor_index].iter().enumerate() {
                if let (Some(phi_value), Some(Some(exit_value))) = (phi_value, exit_locals.get(slot)) {
                    locals_phi_inputs.entry(*phi_value).or_default().push(*exit_value);
                }
            }
            if !handler_block_indices.contains(&successor_index) {
                for (stack_index, phi_value) in block_entry_stack[successor_index].iter().enumerate() {
                    if let Some(exit_value) = exit_stack.get(stack_index) {
                        stack_phi_inputs.entry(*phi_value).or_default().push(*exit_value);
                    }
                }
            }
        }
    }

    let mut exception_edges = Vec::new();
    for exception in &owned_exceptions {
        let Some(&handler_index) = cfg.index_of_start.get(&exception.handler_offset) else { continue };
        for (guarded_index, block) in cfg.blocks.iter().enumerate() {
            let overlaps = exception.try_offset < block.end && block.start < exception.try_offset + exception.try_length;
            if !overlaps {
                continue;
            }
            let (_, _, exit_locals, _) = &results[guarded_index];
            for (slot, phi_value) in block_entry_locals[handler_index].iter().enumerate() {
                if let (Some(phi_value), Some(Some(exit_value))) = (phi_value, exit_locals.get(slot)) {
                    locals_phi_inputs.entry(*phi_value).or_default().push(*exit_value);
                }
            }
            let catch_type = match &exception.kind {
                body::ExceptionKind::TypedException(ty) => Some(crate::names::method_type_name(ty, res)),
                _ => None,
            };
            exception_edges.push(ExceptionEdge {
                from: BlockId(guarded_index as u32),
                unwind: BlockId(handler_index as u32),
                source_inst: None,
                thrown_value: None,
                catch_value: block_entry_stack[handler_index].first().copied(),
                catch_type,
                is_cleanup: matches!(exception.kind, body::ExceptionKind::Finally | body::ExceptionKind::Fault),
                cleanup_values: Vec::new(),
            });
        }
    }

    let mut blocks = Vec::with_capacity(block_count);
    for index in 0..block_count {
        let (ordinary_insts, term, ..) = &results[index];
        let mut insts = Vec::new();
        if is_phi_block[index] {
            for phi_value in block_entry_locals[index].iter().flatten() {
                let inputs = locals_phi_inputs.remove(phi_value).unwrap_or_default();
                insts.push(IrInstruction { id: InstId(builder.next_inst), kind: InstKind::Phi { dst: *phi_value, inputs }, span: Span::default() });
                builder.next_inst += 1;
            }
            for phi_value in &block_entry_stack[index] {
                if handler_block_indices.contains(&index) {
                    continue; // covered by `ExceptionEdge::catch_value`.
                }
                let inputs = stack_phi_inputs.remove(phi_value).unwrap_or_default();
                insts.push(IrInstruction { id: InstId(builder.next_inst), kind: InstKind::Phi { dst: *phi_value, inputs }, span: Span::default() });
                builder.next_inst += 1;
            }
        }
        insts.extend(ordinary_insts.iter().cloned());
        blocks.push(BasicBlock { id: BlockId(index as u32), insts, term: term.clone() });
    }
    blocks.extend(builder.extra_blocks.drain(..));

    let return_type = if method.signature.return_type.1.is_some() { IrType::Object("unknown".to_string()) } else { IrType::Void };

    Ok((
        Function {
            id,
            name: label.to_string(),
            params: args,
            locals: builder.all_values,
            blocks,
            return_type,
            is_external: false,
            span: Span::default(),
            attrs: IndexMap::new(),
            value_types: IndexMap::new(),
            value_spans: IndexMap::new(),
            cpp: None,
            cpp_initializers: Vec::new(),
            value_cpp: IndexMap::new(),
            exception_edges,
        },
        builder.diagnostics,
    ))
}

fn set_local(locals: &mut [Option<ValueId>], slot: usize, value: ValueId) {
    if let Some(entry) = locals.get_mut(slot) {
        *entry = Some(value);
    }
}

fn branch(block_id_of_start: &HashMap<usize, BlockId>, target: usize, fallthrough: usize, cond: ValueId) -> Terminator {
    Terminator::Branch { cond, then_bb: block_id_of_start[&target], else_bb: block_id_of_start[&fallthrough] }
}

#[allow(clippy::too_many_arguments)]
fn lower_block(
    builder: &mut MethodBuilder,
    instructions: &[Instruction],
    block: &Block,
    mut stack: Vec<ValueId>,
    mut locals: Vec<Option<ValueId>>,
    args: &[ValueId],
    block_id_of_start: &HashMap<usize, BlockId>,
) -> Result<(Vec<IrInstruction>, Terminator, Vec<Option<ValueId>>, Vec<ValueId>)> {
    use Instruction::*;

    let mut insts = Vec::new();
    let mut term: Option<Terminator> = None;
    let block_instrs = &instructions[block.start..block.end];
    let last_index = block_instrs.len().saturating_sub(1);
    let res = builder.res;

    for (index, instr) in block_instrs.iter().enumerate() {
        let is_last = index == last_index;
        let global_index = block.start + index;
        match instr {
            NoOperation | Breakpoint => {}
            LoadConstantInt32(v) => stack.push(const_int(builder, &mut insts, *v as i64)),
            LoadConstantInt64(v) => stack.push(const_int(builder, &mut insts, *v)),
            LoadConstantFloat32(_) | LoadConstantFloat64(_) => stack.push(const_string(builder, &mut insts, "<literal>".to_string())),
            LoadString(utf16) => stack.push(const_string(builder, &mut insts, String::from_utf16_lossy(utf16))),
            LoadNull => stack.push(const_string(builder, &mut insts, "<null>".to_string())),
            LoadArgument(slot) | LoadArgumentAddress(slot) => {
                let value = args.get(*slot as usize).copied().unwrap_or_else(|| {
                    builder.diagnostic(format!("read of unknown argument slot {slot}"));
                    const_string(builder, &mut insts, "<uninitialized>".to_string())
                });
                stack.push(value);
            }
            StoreArgument(_slot) => {
                pop1(&mut stack)?; // argument writes are rare; the value is still visible via its own producing instruction.
            }
            LoadLocal(slot) | LoadLocalAddress(slot) => {
                let value = locals.get(*slot as usize).copied().flatten().unwrap_or_else(|| {
                    builder.diagnostic(format!("read of uninitialized local slot {slot}"));
                    const_string(builder, &mut insts, "<uninitialized>".to_string())
                });
                stack.push(value);
            }
            StoreLocal(slot) => {
                let value = pop1(&mut stack)?;
                set_local(&mut locals, *slot as usize, value);
            }
            Duplicate => {
                let top = *stack.last().ok_or_else(|| anyhow!("operand stack underflow"))?;
                stack.push(top);
            }
            Pop => {
                pop1(&mut stack)?;
            }
            Add | Subtract | Multiply | Divide(_) | Remainder(_) | And | Or | Xor | ShiftLeft | ShiftRight(_) | AddOverflow(_) | SubtractOverflow(_) | MultiplyOverflow(_) => {
                let rhs = pop1(&mut stack)?;
                let lhs = pop1(&mut stack)?;
                stack.push(synthetic_call(builder, &mut insts, "__uniflow.bytecode.arith", vec![lhs, rhs]));
            }
            Negate | Not => {
                let src = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::NumericNeg { dst, src }, span: Span::default() });
                stack.push(dst);
            }
            Convert(_) | ConvertOverflow(..) | ConvertFloat32 | ConvertFloat64 | ConvertUnsignedToFloat => {
                let src = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Cast { dst, src, kind: uniflow_ir::CppCastKind::Static, target_type: None }, span: Span::default() });
                stack.push(dst);
            }
            CheckFinite => {}
            CompareEqual | CompareGreater(_) | CompareLess(_) if !is_last => {
                let rhs = pop1(&mut stack)?;
                let lhs = pop1(&mut stack)?;
                stack.push(synthetic_call(builder, &mut insts, "__uniflow.bytecode.arith", vec![lhs, rhs]));
            }
            LoadIndirect { .. } => {
                let addr = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Deref { dst, src: addr }, span: Span::default() });
                stack.push(dst);
            }
            StoreIndirect { .. } => {
                let value = pop1(&mut stack)?;
                let addr = pop1(&mut stack)?;
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::StoreField { base: addr, field: "*".to_string(), src: value }, span: Span::default() });
            }
            LoadField { param0, .. } | LoadFieldAddress(param0) | LoadFieldSkipNullCheck(param0) => {
                let base = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::LoadField { dst, base, field: field_source_name(param0, res) }, span: Span::default() });
                stack.push(dst);
            }
            StoreField { param0, .. } | StoreFieldSkipNullCheck(param0) => {
                let value = pop1(&mut stack)?;
                let base = pop1(&mut stack)?;
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::StoreField { base, field: field_source_name(param0, res), src: value }, span: Span::default() });
            }
            LoadStaticField { param0, .. } | LoadStaticFieldAddress(param0) => {
                let name = field_source_name(param0, res);
                let base = const_string(builder, &mut insts, name.clone());
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::LoadField { dst, base, field: name }, span: Span::default() });
                stack.push(dst);
            }
            StoreStaticField { param0, .. } => {
                let value = pop1(&mut stack)?;
                let name = field_source_name(param0, res);
                let base = const_string(builder, &mut insts, name.clone());
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::StoreField { base, field: name, src: value }, span: Span::default() });
            }
            LoadElement { .. } | LoadElementPrimitive { .. } | LoadElementAddress { .. } | LoadElementAddressReadonly(_) => {
                let index_value = pop1(&mut stack)?;
                let base = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::LoadIndex { dst, base, index: index_value }, span: Span::default() });
                stack.push(dst);
            }
            StoreElement { .. } | StoreElementPrimitive { .. } => {
                let value = pop1(&mut stack)?;
                let index_value = pop1(&mut stack)?;
                let base = pop1(&mut stack)?;
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::StoreIndex { base, index: index_value, src: value }, span: Span::default() });
            }
            LoadLength => {
                let base = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::LoadField { dst, base, field: "Length".to_string() }, span: Span::default() });
                stack.push(dst);
            }
            NewArray(_) => {
                let len = pop1(&mut stack)?;
                stack.push(synthetic_call(builder, &mut insts, "__uniflow.bytecode.newarray", vec![len]));
            }
            NewObject(method) => {
                let sig = crate::names::user_method_signature(res, method);
                let arg_count = sig.parameters.len();
                let mut call_args = pop_n(&mut stack, arg_count)?;
                let name = crate::names::method_source_name(&dotnetdll::resolved::members::MethodSource::User(*method), res);
                let dst = builder.fresh_value();
                call_args.push(dst); // keep the constructed instance's dataflow linked to its ctor args, approximated as an extra arg rather than a receiver (no `this` exists until construction completes).
                insts.push(IrInstruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Call(CallInst { dst: Some(dst), callee: Callee::Static(name), receiver: None, args: call_args, arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }),
                    span: Span::default(),
                });
                stack.push(dst);
            }
            Call { param0, .. } | CallVirtual { param0, .. } | CallVirtualTail(param0) => {
                lower_call(builder, &mut insts, &mut stack, param0, None)?;
            }
            CallConstrained(_, param0) | CallVirtualConstrained(_, param0) => {
                lower_call(builder, &mut insts, &mut stack, param0, None)?;
            }
            CallIndirect { param0, .. } => {
                let arg_count = param0.parameters.len() + usize::from(param0.instance);
                let call_args = pop_n(&mut stack, arg_count)?;
                let pointer = pop1(&mut stack)?;
                let dst = if param0.return_type.1.is_some() { Some(builder.fresh_value()) } else { None };
                insts.push(IrInstruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Call(CallInst { dst, callee: Callee::Dynamic(pointer), receiver: None, args: call_args, arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }),
                    span: Span::default(),
                });
                if let Some(dst) = dst {
                    stack.push(dst);
                }
            }
            BoxValue(_) | UnboxIntoValue(_) => {
                let src = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Cast { dst, src, kind: uniflow_ir::CppCastKind::Static, target_type: None }, span: Span::default() });
                stack.push(dst);
            }
            UnboxIntoAddress { .. } => {
                let src = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Deref { dst, src }, span: Span::default() });
                stack.push(dst);
            }
            CastClass { param0, .. } => {
                let src = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                let target_type = Some(crate::names::method_type_name(param0, res));
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Cast { dst, src, kind: uniflow_ir::CppCastKind::Static, target_type }, span: Span::default() });
                stack.push(dst);
            }
            IsInstance(_) => {
                let _src = pop1(&mut stack)?;
                stack.push(const_int(builder, &mut insts, 0));
            }
            CopyObject(_) => {
                pop1(&mut stack)?;
                pop1(&mut stack)?;
            }
            InitializeForObject(_) => {
                pop1(&mut stack)?;
            }
            LoadObject { .. } => {
                let addr = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Deref { dst, src: addr }, span: Span::default() });
                stack.push(dst);
            }
            StoreObject { .. } => {
                let value = pop1(&mut stack)?;
                let addr = pop1(&mut stack)?;
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::StoreField { base: addr, field: "*".to_string(), src: value }, span: Span::default() });
            }
            CopyMemoryBlock { .. } | InitializeMemoryBlock { .. } => {
                pop1(&mut stack)?;
                pop1(&mut stack)?;
                pop1(&mut stack)?;
            }
            LocalMemoryAllocate => {
                let size = pop1(&mut stack)?;
                stack.push(synthetic_call(builder, &mut insts, "__uniflow.bytecode.localloc", vec![size]));
            }
            MakeTypedReference(_) | ReadTypedReferenceValue(_) => {
                let src = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Cast { dst, src, kind: uniflow_ir::CppCastKind::Static, target_type: None }, span: Span::default() });
                stack.push(dst);
            }
            ReadTypedReferenceType => {
                let src = pop1(&mut stack)?;
                stack.push(src);
            }
            Sizeof(_) => stack.push(const_int(builder, &mut insts, 0)),
            LoadTokenField(f) => stack.push(const_string(builder, &mut insts, field_source_name(f, res))),
            LoadTokenMethod(m) => stack.push(const_string(builder, &mut insts, method_source_name(m, res))),
            LoadTokenType(t) => stack.push(const_string(builder, &mut insts, crate::names::method_type_name(t, res))),
            LoadMethodPointer(m) => stack.push(const_string(builder, &mut insts, method_source_name(m, res))),
            LoadVirtualMethodPointer { param0, .. } => {
                let _receiver = pop1(&mut stack)?;
                stack.push(const_string(builder, &mut insts, method_source_name(param0, res)));
            }
            ArgumentList => stack.push(const_string(builder, &mut insts, "<arglist>".to_string())),

            // --- block terminators ---
            BranchEqual(target) | BranchNotEqual(target) if is_last => {
                let rhs = pop1(&mut stack)?;
                let lhs = pop1(&mut stack)?;
                let op = if matches!(instr, BranchEqual(_)) { ComparisonOp::Eq } else { ComparisonOp::Ne };
                let cond = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Compare { dst: cond, lhs, rhs, op }, span: Span::default() });
                term = Some(branch(block_id_of_start, *target, global_index + 1, cond));
            }
            BranchGreaterOrEqual(_, target) | BranchGreater(_, target) | BranchLessOrEqual(_, target) | BranchLess(_, target) if is_last => {
                let rhs = pop1(&mut stack)?;
                let lhs = pop1(&mut stack)?;
                let op = match instr {
                    BranchGreaterOrEqual(..) => ComparisonOp::Ge,
                    BranchGreater(..) => ComparisonOp::Gt,
                    BranchLessOrEqual(..) => ComparisonOp::Le,
                    _ => ComparisonOp::Lt,
                };
                let cond = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Compare { dst: cond, lhs, rhs, op }, span: Span::default() });
                term = Some(branch(block_id_of_start, *target, global_index + 1, cond));
            }
            BranchFalsy(target) | BranchTruthy(target) if is_last => {
                let value = pop1(&mut stack)?;
                let zero = const_int(builder, &mut insts, 0);
                let op = if matches!(instr, BranchFalsy(_)) { ComparisonOp::Eq } else { ComparisonOp::Ne };
                let cond = builder.fresh_value();
                insts.push(IrInstruction { id: builder.fresh_inst(), kind: InstKind::Compare { dst: cond, lhs: value, rhs: zero, op }, span: Span::default() });
                term = Some(branch(block_id_of_start, *target, global_index + 1, cond));
            }
            Branch(target) if is_last => term = Some(Terminator::Goto(block_id_of_start[target])),
            // `leave` clears the evaluation stack by spec — control transfers
            // to `target`, skipping any intervening `finally` blocks that a
            // fully precise model would splice in (documented limitation).
            Leave(target) if is_last => {
                stack.clear();
                term = Some(Terminator::Goto(block_id_of_start[target]));
            }
            Switch(targets) if is_last => {
                let selector = pop1(&mut stack)?;
                let fallthrough = block_id_of_start[&(global_index + 1)];
                let target_ids: Vec<BlockId> = targets.iter().map(|target| block_id_of_start[target]).collect();
                let entry = lower_switch_chain(builder, selector, fallthrough, &target_ids);
                term = Some(Terminator::Goto(entry));
            }
            Return if is_last => {
                let value = if method_returns_value_hint(&stack) { stack.pop() } else { None };
                term = Some(Terminator::Return(value));
            }
            Throw if is_last => {
                let value = pop1(&mut stack)?;
                term = Some(Terminator::Throw(Some(value)));
            }
            Rethrow if is_last => term = Some(Terminator::Throw(None)),
            Jump(method) if is_last => {
                let name = method_source_name(method, res);
                let dst = builder.fresh_value();
                insts.push(IrInstruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Call(CallInst { dst: Some(dst), callee: Callee::Static(name), receiver: None, args: args.to_vec(), arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }),
                    span: Span::default(),
                });
                term = Some(Terminator::Return(Some(dst)));
            }
            EndFinally | EndFilter if is_last => term = Some(Terminator::Unreachable),
            other => {
                if is_last {
                    builder.diagnostic(format!("unexpected non-terminator instruction at end of block: {other:?}"));
                }
            }
        }
    }

    let term = term.unwrap_or(Terminator::Unreachable);
    Ok((insts, term, locals, stack))
}

/// `ret` either pops a value or doesn't, per the method's own signature —
/// but by the time we're at a `Return` in a generic per-block loop we no
/// longer have direct access to the method signature without threading it
/// through; using "is there anything left on the stack" as the signal is
/// exactly equivalent in valid (verifiable) CIL, since a non-void method's
/// `ret` always has its single return value as the sole remaining stack
/// entry, and a void method's `ret` always has an empty stack.
fn method_returns_value_hint(stack: &[ValueId]) -> bool {
    !stack.is_empty()
}

fn lower_call(builder: &mut MethodBuilder, insts: &mut Vec<IrInstruction>, stack: &mut Vec<ValueId>, source: &dotnetdll::resolved::members::MethodSource, _unused: Option<()>) -> Result<()> {
    let res = builder.res;
    let sig = method_source_signature(res, source);
    let arg_count = sig.parameters.len();
    let has_return = sig.return_type.1.is_some();
    let is_instance = sig.instance;
    let call_args = pop_n(stack, arg_count)?;
    let receiver = if is_instance { Some(pop1(stack)?) } else { None };
    let name = method_source_name(source, res);
    let dst = if has_return { Some(builder.fresh_value()) } else { None };
    insts.push(IrInstruction {
        id: builder.fresh_inst(),
        kind: InstKind::Call(CallInst { dst, callee: Callee::Static(name), receiver, args: call_args, arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }),
        span: Span::default(),
    });
    if let Some(dst) = dst {
        stack.push(dst);
    }
    Ok(())
}
