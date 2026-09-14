//! Stack-machine abstract interpretation: turns one method's bytecode CFG
//! (`crate::cfg`) into an `ir::Function`.
//!
//! Every non-entry block is given fresh `Phi` placeholder values for *all*
//! of its live entry state (every local slot, plus its entry operand-stack
//! shape from `cfg::MethodCfg::entry_shape`) rather than only at blocks that
//! are provably merge points. `ir::validate_program` checks whole-function
//! value/id sets, not per-block dominance order (see `uniflow_ir::lib`), so
//! a handful of trivial single-input phis are valid IR and harmless — this
//! trades a little instruction bloat for a much simpler, uniform lowering.

use crate::cfg::{build_cfg, Block};
use crate::classfile::{ClassFile, MethodInfo};
use crate::constant_pool::ClassfileDiagnostic;
use crate::descriptor::{parse_method_descriptor, JvmType};
use crate::invokedynamic::{resolve_bootstrap, ConcatPart, ImplKind, ResolvedBootstrap};
use crate::opcodes::{LdcValue, MemberKind, MemberRef, OpKind};
use crate::shuffle;
use anyhow::Result;
use indexmap::IndexMap;
use std::collections::HashMap;
use uniflow_hir::Span;
use uniflow_ir::{
    BasicBlock, BlockId, CallInst, Callee, ComparisonOp, ExceptionEdge, Function, FunctionId,
    InstId, Instruction, InstKind, Terminator, Type as IrType, ValueId,
};
use uniflow_jni_bridge::NativeMethodDecl;

type StackEntry = (ValueId, bool);

struct MethodBuilder<'a> {
    class: &'a ClassFile,
    label: String,
    next_value: u32,
    next_inst: u32,
    next_block: u32,
    all_values: Vec<ValueId>,
    /// Tracks a value known (within this method only) to be a captured
    /// lambda/method-reference instance: which implementation method a SAM
    /// invocation on it should resolve to, and the values it captured at
    /// creation time (the indy call site's own arguments), which become
    /// the implementation method's leading actual arguments/receiver.
    lambda_values: HashMap<ValueId, (String, String, ImplKind, Vec<ValueId>)>,
    extra_blocks: Vec<BasicBlock>,
    diagnostics: &'a mut Vec<ClassfileDiagnostic>,
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
        self.diagnostics
            .push(ClassfileDiagnostic(format!("{}: {}", self.label, message.into())));
    }
}

fn const_string(builder: &mut MethodBuilder, insts: &mut Vec<Instruction>, value: String) -> ValueId {
    let dst = builder.fresh_value();
    insts.push(Instruction {
        id: builder.fresh_inst(),
        kind: InstKind::ConstString { dst, value },
        span: Span::default(),
    });
    dst
}

fn const_int(builder: &mut MethodBuilder, insts: &mut Vec<Instruction>, value: i64) -> ValueId {
    let dst = builder.fresh_value();
    insts.push(Instruction {
        id: builder.fresh_inst(),
        kind: InstKind::ConstInt { dst, value },
        span: Span::default(),
    });
    dst
}

fn synthetic_call(
    builder: &mut MethodBuilder,
    insts: &mut Vec<Instruction>,
    callee: &str,
    args: Vec<ValueId>,
) -> ValueId {
    let dst = builder.fresh_value();
    insts.push(Instruction {
        id: builder.fresh_inst(),
        kind: InstKind::Call(CallInst {
            dst: Some(dst),
            callee: Callee::Static(callee.to_string()),
            receiver: None,
            args,
            arg_names: Vec::new(),
            arg_spans: Vec::new(),
            arg_origins: Vec::new(),
        }),
        span: Span::default(),
    });
    dst
}

fn member_call_name(member: &MemberRef) -> String {
    format!("{}.{}", member.class, member.name)
}

/// Lowers every method with a `Code` attribute in `class` into `ir::Function`s.
/// `next_function_id` supplies the (program-wide) `FunctionId` for each
/// method in turn and is advanced by one per lowered method. `native_methods`
/// collects a lightweight declaration (no body to lower) for every `native`
/// method instead, so callers can bridge it to a same-named C/C++ JNI
/// implementation.
pub fn lower_class(
    class: &ClassFile,
    next_function_id: &mut u32,
    diagnostics: &mut Vec<ClassfileDiagnostic>,
    native_methods: &mut Vec<NativeMethodDecl>,
) -> Vec<Function> {
    let mut functions = Vec::new();
    for method in &class.methods {
        let Some(code) = &method.code else {
            if method.is_native() {
                let param_count = parse_method_descriptor(&method.descriptor)
                    .map(|(params, _ret)| params.len())
                    .unwrap_or(0);
                native_methods.push(NativeMethodDecl {
                    class: class.this_class.clone(),
                    method: method.name.clone(),
                    param_count,
                    descriptor: Some(method.descriptor.clone()),
                    is_static: method.is_static(),
                });
            }
            continue;
        };
        let label = format!("{}.{}", class.this_class, method.name);
        let handler_starts: Vec<u32> = code
            .exception_table
            .iter()
            .map(|entry| entry.handler_pc as u32)
            .collect();
        let cfg = match build_cfg(&code.code, &class.constant_pool, class.version, &handler_starts) {
            Ok(cfg) => cfg,
            Err(error) => {
                diagnostics.push(ClassfileDiagnostic(format!(
                    "{label}: failed to build control-flow graph: {error}"
                )));
                continue;
            }
        };
        let id = FunctionId(*next_function_id);
        *next_function_id += 1;
        match lower_method_body(class, method, &label, id, &cfg, diagnostics) {
            Ok(function) => functions.push(function),
            Err(error) => diagnostics.push(ClassfileDiagnostic(format!(
                "{label}: failed to lower method body: {error}"
            ))),
        }
    }
    functions
}

fn lower_method_body(
    class: &ClassFile,
    method: &MethodInfo,
    label: &str,
    id: FunctionId,
    cfg: &crate::cfg::MethodCfg,
    diagnostics: &mut Vec<ClassfileDiagnostic>,
) -> Result<Function> {
    let code = method.code.as_ref().expect("caller only lowers methods with code");
    let (param_types, return_type) = parse_method_descriptor(&method.descriptor)?;
    let mut builder = MethodBuilder {
        class,
        label: label.to_string(),
        next_value: 0,
        next_inst: 0,
        next_block: cfg.blocks.len() as u32,
        all_values: Vec::new(),
        lambda_values: HashMap::new(),
        extra_blocks: Vec::new(),
        diagnostics,
    };

    let mut params = Vec::new();
    let mut entry_locals: Vec<Option<ValueId>> = vec![None; code.max_locals as usize];
    let mut slot = 0usize;
    if !method.is_static() {
        let this_value = ValueId(builder.next_value);
        builder.next_value += 1;
        params.push(this_value);
        if slot < entry_locals.len() {
            entry_locals[slot] = Some(this_value);
        }
        slot += 1;
    }
    for param in &param_types {
        let value = ValueId(builder.next_value);
        builder.next_value += 1;
        params.push(value);
        if slot < entry_locals.len() {
            entry_locals[slot] = Some(value);
        }
        slot += param.slot_width() as usize;
    }

    let block_count = cfg.blocks.len();
    let entry_block_index = cfg.index_of_start.get(&0).copied();
    let mut block_entry_locals: Vec<Vec<Option<ValueId>>> = Vec::with_capacity(block_count);
    let mut block_entry_stack: Vec<Vec<StackEntry>> = Vec::with_capacity(block_count);
    let mut is_phi_block = vec![true; block_count];
    for index in 0..block_count {
        if Some(index) == entry_block_index {
            is_phi_block[index] = false;
            block_entry_locals.push(entry_locals.clone());
            block_entry_stack.push(Vec::new());
        } else {
            let locals_phi: Vec<Option<ValueId>> = (0..code.max_locals as usize)
                .map(|_| Some(builder.fresh_value()))
                .collect();
            let stack_phi: Vec<StackEntry> = cfg.entry_shape[index]
                .iter()
                .map(|&wide| (builder.fresh_value(), wide))
                .collect();
            block_entry_locals.push(locals_phi);
            block_entry_stack.push(stack_phi);
        }
    }

    let block_id_of_pc: HashMap<u32, BlockId> = cfg
        .index_of_start
        .iter()
        .map(|(&offset, &index)| (offset, BlockId(index as u32)))
        .collect();

    let mut results: Vec<(Vec<Instruction>, Terminator, Vec<Option<ValueId>>, Vec<StackEntry>)> =
        Vec::with_capacity(block_count);
    for index in 0..block_count {
        let block = &cfg.blocks[index];
        let stack = block_entry_stack[index].clone();
        let locals = block_entry_locals[index].clone();
        let result = lower_block(&mut builder, block, stack, locals, &block_id_of_pc)?;
        results.push(result);
    }

    // Patch phi inputs from every predecessor's recorded exit state. Handler
    // blocks' single stack entry is covered by `ExceptionEdge::catch_value`
    // instead (see below), so it is excluded from ordinary successor-driven
    // patching to avoid defining the same value twice.
    let handler_block_indices: std::collections::HashSet<usize> = code
        .exception_table
        .iter()
        .map(|entry| cfg.index_of_start[&(entry.handler_pc as u32)])
        .collect();
    let mut locals_phi_inputs: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    let mut stack_phi_inputs: HashMap<ValueId, Vec<ValueId>> = HashMap::new();
    for (from_index, block) in cfg.blocks.iter().enumerate() {
        let (_, _, exit_locals, exit_stack) = &results[from_index];
        for successor_offset in &block.successors {
            let successor_index = cfg.index_of_start[successor_offset];
            if !is_phi_block[successor_index] {
                continue;
            }
            for (slot_index, phi_value) in block_entry_locals[successor_index].iter().enumerate() {
                if let (Some(phi_value), Some(Some(exit_value))) =
                    (phi_value, exit_locals.get(slot_index))
                {
                    locals_phi_inputs.entry(*phi_value).or_default().push(*exit_value);
                }
            }
            if !handler_block_indices.contains(&successor_index) {
                for (stack_index, (phi_value, _)) in
                    block_entry_stack[successor_index].iter().enumerate()
                {
                    if let Some((exit_value, _)) = exit_stack.get(stack_index) {
                        stack_phi_inputs.entry(*phi_value).or_default().push(*exit_value);
                    }
                }
            }
        }
    }
    // Exception unwind edges also contribute to a handler's locals phis
    // (approximated at block granularity: any local live at *any* point in
    // the guarded region may be live when the handler runs).
    let mut exception_edges = Vec::new();
    for entry in &code.exception_table {
        let handler_index = cfg.index_of_start[&(entry.handler_pc as u32)];
        for (guarded_index, block) in cfg.blocks.iter().enumerate() {
            let block_end = block
                .instrs
                .last()
                .map(|instr| instr.offset + instr.size)
                .unwrap_or(block.start);
            let overlaps = (entry.start_pc as u32) < block_end && block.start < entry.end_pc as u32;
            if !overlaps {
                continue;
            }
            let (_, _, exit_locals, _) = &results[guarded_index];
            for (slot_index, phi_value) in block_entry_locals[handler_index].iter().enumerate() {
                if let (Some(phi_value), Some(Some(exit_value))) =
                    (phi_value, exit_locals.get(slot_index))
                {
                    locals_phi_inputs.entry(*phi_value).or_default().push(*exit_value);
                }
            }
            exception_edges.push(ExceptionEdge {
                from: BlockId(guarded_index as u32),
                unwind: BlockId(handler_index as u32),
                source_inst: None,
                thrown_value: None,
                catch_value: block_entry_stack[handler_index].first().map(|(value, _)| *value),
                catch_type: entry.catch_type.clone(),
                is_cleanup: entry.catch_type.is_none(),
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
                insts.push(Instruction {
                    id: InstId(builder.next_inst),
                    kind: InstKind::Phi { dst: *phi_value, inputs },
                    span: Span::default(),
                });
                builder.next_inst += 1;
            }
            for (phi_value, _) in &block_entry_stack[index] {
                if handler_block_indices.contains(&index) {
                    continue; // covered by ExceptionEdge::catch_value instead
                }
                let inputs = stack_phi_inputs.remove(phi_value).unwrap_or_default();
                insts.push(Instruction {
                    id: InstId(builder.next_inst),
                    kind: InstKind::Phi { dst: *phi_value, inputs },
                    span: Span::default(),
                });
                builder.next_inst += 1;
            }
        }
        insts.extend(ordinary_insts.iter().cloned());
        blocks.push(BasicBlock {
            id: BlockId(index as u32),
            insts,
            term: term.clone(),
        });
    }
    blocks.extend(builder.extra_blocks.drain(..));

    let mut value_types = IndexMap::new();
    for (index, param) in param_types.iter().enumerate() {
        let offset = usize::from(!method.is_static());
        if let Some(&value) = params.get(index + offset) {
            value_types.insert(value, describe_type(&param.to_ir_type()));
        }
    }

    Ok(Function {
        id,
        name: label.to_string(),
        params,
        locals: builder.all_values,
        blocks,
        return_type: return_type.to_ir_type(),
        is_external: false,
        span: Span::default(),
        attrs: IndexMap::new(),
        value_types,
        value_spans: IndexMap::new(),
        cpp: None,
        cpp_initializers: Vec::new(),
        value_cpp: IndexMap::new(),
        exception_edges,
    })
}

fn describe_type(ty: &IrType) -> String {
    match ty {
        IrType::Void => "void".to_string(),
        IrType::Bool => "bool".to_string(),
        IrType::Int => "int".to_string(),
        IrType::Float => "float".to_string(),
        IrType::String => "String".to_string(),
        IrType::Object(name) => name.clone(),
        IrType::Function => "function".to_string(),
        IrType::Unknown => "unknown".to_string(),
    }
}

#[allow(clippy::type_complexity)]
fn lower_block(
    builder: &mut MethodBuilder,
    block: &Block,
    mut stack: Vec<StackEntry>,
    mut locals: Vec<Option<ValueId>>,
    block_id_of_pc: &HashMap<u32, BlockId>,
) -> Result<(Vec<Instruction>, Terminator, Vec<Option<ValueId>>, Vec<StackEntry>)> {
    let mut insts = Vec::new();
    let mut term: Option<Terminator> = None;
    let last_index = block.instrs.len().saturating_sub(1);

    for (index, instr) in block.instrs.iter().enumerate() {
        let is_last = index == last_index;
        match &instr.kind {
            OpKind::Nop => {}
            OpKind::ConstNull => {
                let dst = const_string(builder, &mut insts, "<null>".to_string());
                stack.push((dst, false));
            }
            OpKind::Ldc { value, wide } => {
                let dst = match value {
                    LdcValue::Int(v) => {
                        let dst = builder.fresh_value();
                        insts.push(Instruction {
                            id: builder.fresh_inst(),
                            kind: InstKind::ConstInt { dst, value: *v },
                            span: Span::default(),
                        });
                        dst
                    }
                    LdcValue::Float(_) => const_string(builder, &mut insts, "<literal>".to_string()),
                    LdcValue::String(text) => const_string(builder, &mut insts, text.clone()),
                    LdcValue::Class(name) => const_string(builder, &mut insts, name.clone()),
                    LdcValue::Opaque => const_string(builder, &mut insts, "<literal>".to_string()),
                };
                stack.push((dst, *wide));
            }
            OpKind::Load { slot, wide } => {
                let value = locals.get(*slot as usize).copied().flatten().unwrap_or_else(|| {
                    builder.diagnostic(format!("read of uninitialized local slot {slot}"));
                    const_string(builder, &mut insts, "<uninitialized>".to_string())
                });
                stack.push((value, *wide));
            }
            OpKind::Store { slot, .. } => {
                let (value, _) = pop1(&mut stack)?;
                set_local(&mut locals, *slot as usize, value);
            }
            OpKind::ArrayLoad { wide } => {
                let (index_value, _) = pop1(&mut stack)?;
                let (base, _) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::LoadIndex { dst, base, index: index_value },
                    span: Span::default(),
                });
                stack.push((dst, *wide));
            }
            OpKind::ArrayStore => {
                let (src, _) = pop1(&mut stack)?;
                let (index_value, _) = pop1(&mut stack)?;
                let (base, _) = pop1(&mut stack)?;
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::StoreIndex { base, index: index_value, src },
                    span: Span::default(),
                });
            }
            OpKind::Pop(count) => shuffle::pop(&mut stack, *count)?,
            OpKind::Dup => shuffle::dup(&mut stack)?,
            OpKind::DupX1 => shuffle::dup_x1(&mut stack)?,
            OpKind::DupX2 => shuffle::dup_x2(&mut stack)?,
            OpKind::Dup2 => shuffle::dup2(&mut stack)?,
            OpKind::Dup2X1 => shuffle::dup2_x1(&mut stack)?,
            OpKind::Dup2X2 => shuffle::dup2_x2(&mut stack)?,
            OpKind::Swap => shuffle::swap(&mut stack)?,
            OpKind::BinaryOp => {
                let (rhs, wide_rhs) = pop1(&mut stack)?;
                let (lhs, wide_lhs) = pop1(&mut stack)?;
                let dst = synthetic_call(builder, &mut insts, "__uniflow.bytecode.arith", vec![lhs, rhs]);
                stack.push((dst, wide_lhs || wide_rhs));
            }
            OpKind::UnaryNeg => {
                let (src, wide) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::NumericNeg { dst, src },
                    span: Span::default(),
                });
                stack.push((dst, wide));
            }
            OpKind::IInc { slot, value } => {
                let current = locals.get(*slot as usize).copied().flatten().unwrap_or_else(|| {
                    builder.diagnostic(format!("iinc on uninitialized local slot {slot}"));
                    const_string(builder, &mut insts, "<uninitialized>".to_string())
                });
                let delta = const_int(builder, &mut insts, *value as i64);
                let dst = synthetic_call(builder, &mut insts, "__uniflow.bytecode.arith", vec![current, delta]);
                set_local(&mut locals, *slot as usize, dst);
            }
            OpKind::Convert { to_wide } => {
                let (src, _) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Cast {
                        dst,
                        src,
                        kind: uniflow_ir::CppCastKind::Static,
                        target_type: None,
                    },
                    span: Span::default(),
                });
                stack.push((dst, *to_wide));
            }
            OpKind::Compare => {
                let (rhs, _) = pop1(&mut stack)?;
                let (lhs, _) = pop1(&mut stack)?;
                let dst = synthetic_call(builder, &mut insts, "__uniflow.bytecode.arith", vec![lhs, rhs]);
                stack.push((dst, false));
            }
            OpKind::GetStatic(member) => {
                let base = static_base(builder, &mut insts, &member.class);
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::LoadField { dst, base, field: member.name.clone() },
                    span: Span::default(),
                });
                let wide = crate::descriptor::parse_field_descriptor(&member.descriptor)
                    .map(|ty| ty.slot_width() == 2)
                    .unwrap_or(false);
                stack.push((dst, wide));
            }
            OpKind::PutStatic(member) => {
                let (src, _) = pop1(&mut stack)?;
                let base = static_base(builder, &mut insts, &member.class);
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::StoreField { base, field: member.name.clone(), src },
                    span: Span::default(),
                });
            }
            OpKind::GetField(member) => {
                let (base, _) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::LoadField { dst, base, field: member.name.clone() },
                    span: Span::default(),
                });
                let wide = crate::descriptor::parse_field_descriptor(&member.descriptor)
                    .map(|ty| ty.slot_width() == 2)
                    .unwrap_or(false);
                stack.push((dst, wide));
            }
            OpKind::PutField(member) => {
                let (src, _) = pop1(&mut stack)?;
                let (base, _) = pop1(&mut stack)?;
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::StoreField { base, field: member.name.clone(), src },
                    span: Span::default(),
                });
            }
            OpKind::Invoke { member, kind } => {
                let (params, ret) = parse_method_descriptor(&member.descriptor)?;
                let mut call_args = Vec::with_capacity(params.len());
                for _ in &params {
                    call_args.push(pop1(&mut stack)?.0);
                }
                call_args.reverse();
                let receiver = if matches!(kind, MemberKind::Static) {
                    None
                } else {
                    Some(pop1(&mut stack)?.0)
                };
                // A SAM invocation on a value produced by a lambda/method
                // reference `invokedynamic` (tracked in `lambda_values`)
                // resolves directly to the captured implementation method
                // instead of the generic functional-interface method,
                // preserving the taint edge through the closure. This only
                // sees uses within the same method as the capture; a
                // lambda that escapes (stored to a field, returned, passed
                // onward) falls back to the ordinary interface-method edge.
                let lambda = receiver.and_then(|value| builder.lambda_values.get(&value).cloned());
                let (callee, args, resolved_receiver) = match lambda {
                    Some((impl_class, impl_name, ImplKind::Static, captured)) => {
                        let mut args = captured;
                        args.extend(call_args);
                        (Callee::Static(format!("{impl_class}.{impl_name}")), args, None)
                    }
                    Some((impl_class, impl_name, ImplKind::Instance, mut captured)) => {
                        if !captured.is_empty() {
                            // Bound reference (e.g. `obj::method`): the
                            // capture list's first entry is the receiver.
                            let receiver = captured.remove(0);
                            captured.extend(call_args);
                            (Callee::Static(format!("{impl_class}.{impl_name}")), captured, Some(receiver))
                        } else {
                            // Unbound reference (e.g. `String::trim`): the
                            // SAM's own first argument is the receiver.
                            let mut call_args = call_args;
                            if call_args.is_empty() {
                                (Callee::Static(format!("{impl_class}.{impl_name}")), Vec::new(), None)
                            } else {
                                let receiver = call_args.remove(0);
                                (Callee::Static(format!("{impl_class}.{impl_name}")), call_args, Some(receiver))
                            }
                        }
                    }
                    None => (Callee::Static(member_call_name(member)), call_args, receiver),
                };
                let dst = if ret == JvmType::Void { None } else { Some(builder.fresh_value()) };
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Call(CallInst {
                        dst,
                        callee,
                        receiver: resolved_receiver,
                        args,
                        arg_names: Vec::new(),
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
                    }),
                    span: Span::default(),
                });
                if let Some(dst) = dst {
                    stack.push((dst, ret.slot_width() == 2));
                }
            }
            OpKind::InvokeDynamic {
                bootstrap_index,
                descriptor,
                name,
            } => {
                let (params, ret) = parse_method_descriptor(descriptor)?;
                let mut args = Vec::with_capacity(params.len());
                for _ in &params {
                    args.push(pop1(&mut stack)?.0);
                }
                args.reverse();
                lower_invokedynamic(
                    builder,
                    &mut insts,
                    &mut stack,
                    *bootstrap_index,
                    name,
                    args,
                    ret,
                )?;
            }
            OpKind::New { class } => {
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Call(CallInst {
                        dst: Some(dst),
                        callee: Callee::Static(format!("{class}.<alloc>")),
                        receiver: None,
                        args: Vec::new(),
                        arg_names: Vec::new(),
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
                    }),
                    span: Span::default(),
                });
                stack.push((dst, false));
            }
            OpKind::NewArray { .. } | OpKind::ANewArray { .. } => {
                let (_len, _) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::ConstString { dst, value: "<array>".to_string() },
                    span: Span::default(),
                });
                stack.push((dst, false));
            }
            OpKind::MultiANewArray { dims, .. } => {
                for _ in 0..*dims {
                    pop1(&mut stack)?;
                }
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::ConstString { dst, value: "<array>".to_string() },
                    span: Span::default(),
                });
                stack.push((dst, false));
            }
            OpKind::ArrayLength => {
                let (base, _) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::LoadField { dst, base, field: "length".to_string() },
                    span: Span::default(),
                });
                stack.push((dst, false));
            }
            OpKind::CheckCast { class } => {
                let (src, wide) = pop1(&mut stack)?;
                let dst = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Cast {
                        dst,
                        src,
                        kind: uniflow_ir::CppCastKind::Static,
                        target_type: Some(class.clone()),
                    },
                    span: Span::default(),
                });
                stack.push((dst, wide));
            }
            OpKind::InstanceOf { .. } => {
                let (_src, _) = pop1(&mut stack)?;
                let dst = const_int(builder, &mut insts, 0);
                stack.push((dst, false));
            }
            OpKind::MonitorEnter | OpKind::MonitorExit => {
                pop1(&mut stack)?;
            }

            // --- block terminators ---
            OpKind::IfZero { cmp, target } if is_last => {
                let (value, _) = pop1(&mut stack)?;
                let zero = const_int(builder, &mut insts, 0);
                let cond = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Compare { dst: cond, lhs: value, rhs: zero, op: *cmp },
                    span: Span::default(),
                });
                term = Some(branch(block_id_of_pc, *target, instr.offset + instr.size, cond));
            }
            OpKind::IfCmp { cmp, target } if is_last => {
                let (rhs, _) = pop1(&mut stack)?;
                let (lhs, _) = pop1(&mut stack)?;
                let cond = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Compare { dst: cond, lhs, rhs, op: *cmp },
                    span: Span::default(),
                });
                term = Some(branch(block_id_of_pc, *target, instr.offset + instr.size, cond));
            }
            OpKind::IfNull { target } | OpKind::IfNonNull { target } if is_last => {
                let (value, _) = pop1(&mut stack)?;
                let null = const_string(builder, &mut insts, "<null>".to_string());
                let op = if matches!(instr.kind, OpKind::IfNull { .. }) {
                    ComparisonOp::Eq
                } else {
                    ComparisonOp::Ne
                };
                let cond = builder.fresh_value();
                insts.push(Instruction {
                    id: builder.fresh_inst(),
                    kind: InstKind::Compare { dst: cond, lhs: value, rhs: null, op },
                    span: Span::default(),
                });
                term = Some(branch(block_id_of_pc, *target, instr.offset + instr.size, cond));
            }
            OpKind::Goto(target) if is_last => {
                term = Some(Terminator::Goto(block_id_of_pc[target]));
            }
            OpKind::Jsr(target) if is_last => {
                // Deprecated subroutine call; approximated as an ordinary
                // jump. A placeholder return-address value is pushed so a
                // subroutine's customary leading `astore` still has
                // something to store.
                let placeholder = const_string(builder, &mut insts, "<returnaddress>".to_string());
                stack.push((placeholder, false));
                term = Some(Terminator::Goto(block_id_of_pc[target]));
            }
            OpKind::Ret { .. } if is_last => {
                term = Some(Terminator::Unreachable);
            }
            OpKind::TableSwitch { default, low, targets } if is_last => {
                let (selector, _) = pop1(&mut stack)?;
                let cases: Vec<(i64, u32)> = targets
                    .iter()
                    .enumerate()
                    .map(|(offset, &target)| (*low as i64 + offset as i64, target))
                    .collect();
                let entry = lower_switch_chain(builder, selector, *default, cases, block_id_of_pc);
                term = Some(Terminator::Goto(entry));
            }
            OpKind::LookupSwitch { default, pairs } if is_last => {
                let (selector, _) = pop1(&mut stack)?;
                let cases: Vec<(i64, u32)> =
                    pairs.iter().map(|(value, target)| (*value as i64, *target)).collect();
                let entry = lower_switch_chain(builder, selector, *default, cases, block_id_of_pc);
                term = Some(Terminator::Goto(entry));
            }
            OpKind::Return { has_value } if is_last => {
                let value = if *has_value { Some(pop1(&mut stack)?.0) } else { None };
                term = Some(Terminator::Return(value));
            }
            OpKind::AThrow if is_last => {
                let (value, _) = pop1(&mut stack)?;
                term = Some(Terminator::Throw(Some(value)));
            }
            other => {
                if is_last {
                    builder.diagnostic(format!(
                        "unexpected non-terminator opcode at end of block: {other:?}"
                    ));
                }
            }
        }
    }

    let term = term.unwrap_or(Terminator::Unreachable);
    Ok((insts, term, locals, stack))
}

fn pop1(stack: &mut Vec<StackEntry>) -> Result<StackEntry> {
    stack
        .pop()
        .ok_or_else(|| anyhow::anyhow!("operand stack underflow"))
}

fn set_local(locals: &mut [Option<ValueId>], slot: usize, value: ValueId) {
    if slot < locals.len() {
        locals[slot] = Some(value);
    }
}

fn branch(
    block_id_of_pc: &HashMap<u32, BlockId>,
    then_target: u32,
    else_target: u32,
    cond: ValueId,
) -> Terminator {
    Terminator::Branch {
        cond,
        then_bb: block_id_of_pc[&then_target],
        else_bb: block_id_of_pc[&else_target],
    }
}

fn static_base(builder: &mut MethodBuilder, insts: &mut Vec<Instruction>, class: &str) -> ValueId {
    const_string(builder, insts, class.to_string())
}

fn lower_switch_chain(
    builder: &mut MethodBuilder,
    selector: ValueId,
    default_target: u32,
    cases: Vec<(i64, u32)>,
    block_id_of_pc: &HashMap<u32, BlockId>,
) -> BlockId {
    let mut next_target = block_id_of_pc[&default_target];
    for (value, target) in cases.into_iter().rev() {
        let block_id = builder.fresh_block_id();
        let mut insts = Vec::new();
        let const_value = const_int(builder, &mut insts, value);
        let cond = builder.fresh_value();
        insts.push(Instruction {
            id: builder.fresh_inst(),
            kind: InstKind::Compare { dst: cond, lhs: selector, rhs: const_value, op: ComparisonOp::Eq },
            span: Span::default(),
        });
        let term = Terminator::Branch {
            cond,
            then_bb: block_id_of_pc[&target],
            else_bb: next_target,
        };
        builder.extra_blocks.push(BasicBlock { id: block_id, insts, term });
        next_target = block_id;
    }
    next_target
}

fn lower_invokedynamic(
    builder: &mut MethodBuilder,
    insts: &mut Vec<Instruction>,
    stack: &mut Vec<StackEntry>,
    bootstrap_index: u16,
    call_site_name: &str,
    args: Vec<ValueId>,
    ret: JvmType,
) -> Result<()> {
    let resolved = resolve_bootstrap(builder.class, bootstrap_index).unwrap_or(ResolvedBootstrap::Unknown);
    match resolved {
        ResolvedBootstrap::Lambda { impl_class, impl_name, impl_kind } => {
            // Creating the lambda/method-reference instance doesn't
            // execute its SAM method yet, but *does* bind its captured
            // arguments — the closure's only taint-relevant channel when
            // the SAM is later invoked by code this crate never decodes
            // (JDK collection/stream/executor internals). Emit that edge
            // immediately, using only the captured args (the SAM's own
            // future call-time args aren't known here). If a SAM
            // invocation on this value *is* later seen within the same
            // method, `lower_block`'s `Invoke` handling resolves directly
            // to `impl_class.impl_name` again with the full argument list
            // (captures + call args) — redundant in that case, but never
            // incorrect, since both calls target the same function.
            let callee = format!("{impl_class}.{impl_name}");
            let dst = synthetic_call(builder, insts, &callee, args.clone());
            builder
                .lambda_values
                .insert(dst, (impl_class, impl_name, impl_kind, args));
            stack.push((dst, false));
        }
        ResolvedBootstrap::StringConcat { parts } => {
            let parts = if parts.is_empty() {
                (0..args.len()).map(ConcatPart::Arg).collect()
            } else {
                parts
            };
            let mut acc: Option<ValueId> = None;
            for part in parts {
                let value = match part {
                    ConcatPart::Arg(index) => args.get(index).copied().unwrap_or_else(|| {
                        builder.diagnostic(format!(
                            "string-concat recipe references missing argument {index} at {call_site_name}"
                        ));
                        const_string(builder, insts, "<literal>".to_string())
                    }),
                    ConcatPart::Literal(text) => const_string(builder, insts, text),
                };
                acc = Some(match acc {
                    None => value,
                    Some(previous) => {
                        synthetic_call(builder, insts, "java.lang.String.concat", vec![previous, value])
                    }
                });
            }
            let dst = acc.unwrap_or_else(|| const_string(builder, insts, String::new()));
            stack.push((dst, false));
        }
        ResolvedBootstrap::Unknown => {
            builder.diagnostic(format!("unresolved invokedynamic bootstrap at {call_site_name}"));
            let dst = builder.fresh_value();
            insts.push(Instruction {
                id: builder.fresh_inst(),
                kind: InstKind::Call(CallInst {
                    dst: Some(dst),
                    callee: Callee::Unknown,
                    receiver: None,
                    args,
                    arg_names: Vec::new(),
                    arg_spans: Vec::new(),
                    arg_origins: Vec::new(),
                }),
                span: Span::default(),
            });
            if ret != JvmType::Void {
                stack.push((dst, ret.slot_width() == 2));
            }
        }
    }
    Ok(())
}
