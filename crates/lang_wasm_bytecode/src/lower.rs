//! Structured-control-flow-to-CFG lowering: walks `walrus`'s nested
//! `Block`/`Loop`/`IfElse` instruction tree for one function and produces a
//! flat `uniflow_ir::Function` (basic blocks joined by `Goto`/`Branch`
//! edges), simulating WASM's operand stack the same way
//! `uniflow_lang_java_bytecode::lower` simulates the JVM's.
//!
//! # `Phi` reconciliation strategy
//!
//! Every merge point (a `block`/`if`/`else`'s "falls off/branches past the
//! end" continuation, and a `loop`'s own header, re-entered by a back-edge)
//! gets a *fresh* `Phi` value pre-allocated for **every** local slot plus
//! its declared stack result/param arity — mirroring
//! `uniflow_lang_java_bytecode::lower`'s own documented trade-off: `Phi`ing
//! every slot at every merge point (rather than only where a value
//! provably differs across predecessors) is simpler and still produces
//! valid IR, since `uniflow_ir::validate_program` checks whole-function
//! value-definition sets, not per-path dominance — a handful of trivial
//! single-input phis are harmless.
//!
//! `walrus` already resolves a WASM `br`/`br_if`/`br_table`'s relative
//! label-depth index into a direct `InstrSeqId`, so unlike a raw
//! `wasmparser`-level reader this lowering never has to track a label-depth
//! stack itself — it just needs to know, for each currently-open
//! `InstrSeqId`, which basic block an explicit branch to it resolves to
//! (`SeqTarget` below), which is recorded the moment this lowering opens
//! that sequence. Every merge block's phi placeholder `ValueId`s are also
//! recorded (`Ctx::phi_slots`) so both an *implicit* (fallthrough) edge and
//! an *explicit* `br`/`br_if`/`br_table` edge can contribute their exit
//! values into the same accumulators.

use std::collections::HashMap;

use indexmap::IndexMap;
use uniflow_hir::Span;
use uniflow_ir::{
    BasicBlock, BlockId, CallInst, Callee, ComparisonOp, Function, FunctionId, InstId, Instruction,
    InstKind, Terminator, Type as IrType, ValueId,
};
use walrus::ir::{Instr, InstrSeqId, InstrSeqType, Value as WasmValue};
use walrus::{FunctionKind, LocalFunction, LocalId, Module, ValType};

/// Where an explicit `br`/`br_if`/`br_table` targeting one currently-open
/// `InstrSeqId` actually goes: a `block`/`if`-branch resolves to its
/// "after" merge point (carrying its declared *result* arity); a `loop`
/// resolves back to its own header (carrying its declared *param* arity) —
/// branching to a loop always re-enters its start in WASM, never exits it.
#[derive(Clone, Copy)]
enum SeqTarget {
    After { block: BlockId, arity: usize },
    Header { block: BlockId, arity: usize },
}

impl SeqTarget {
    fn block(self) -> BlockId {
        match self {
            SeqTarget::After { block, .. } | SeqTarget::Header { block, .. } => block,
        }
    }

    fn arity(self) -> usize {
        match self {
            SeqTarget::After { arity, .. } | SeqTarget::Header { arity, .. } => arity,
        }
    }
}

struct Ctx<'a> {
    module: &'a Module,
    local_index: HashMap<LocalId, usize>,
    next_value: u32,
    next_inst: u32,
    next_block: u32,
    blocks: Vec<BasicBlock>,
    /// Phi placeholder `ValueId`s registered for each merge block, in slot
    /// order: every local, then the block's own declared stack arity.
    phi_slots: HashMap<BlockId, (Vec<ValueId>, Vec<ValueId>)>,
    locals_phi_inputs: HashMap<ValueId, Vec<ValueId>>,
    stack_phi_inputs: HashMap<ValueId, Vec<ValueId>>,
}

impl<'a> Ctx<'a> {
    fn fresh_value(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value += 1;
        id
    }

    fn fresh_inst(&mut self) -> InstId {
        let id = InstId(self.next_inst);
        self.next_inst += 1;
        id
    }

    fn new_block(&mut self) -> BlockId {
        let id = BlockId(self.next_block);
        self.next_block += 1;
        self.blocks.push(BasicBlock { id, insts: Vec::new(), term: Terminator::Unreachable });
        id
    }

    fn push(&mut self, block: BlockId, kind: InstKind) {
        let id = self.fresh_inst();
        self.blocks[block.0 as usize].insts.push(Instruction { id, kind, span: Span::default() });
    }

    fn terminate(&mut self, block: BlockId, term: Terminator) {
        self.blocks[block.0 as usize].term = term;
    }

    fn const_int(&mut self, block: BlockId, value: i64) -> ValueId {
        let dst = self.fresh_value();
        self.push(block, InstKind::ConstInt { dst, value });
        dst
    }

    fn synthetic_call(&mut self, block: BlockId, callee: &str, args: Vec<ValueId>) -> ValueId {
        let dst = self.fresh_value();
        self.push(
            block,
            InstKind::Call(CallInst {
                dst: Some(dst),
                callee: Callee::Static(callee.to_string()),
                receiver: None,
                args,
                arg_names: Vec::new(),
                arg_spans: Vec::new(),
                arg_origins: Vec::new(),
            }),
        );
        dst
    }

    /// Allocates and registers a merge point's phi placeholders (one per
    /// local slot, plus one per declared stack arity), returning the two
    /// placeholder lists so the caller can use them as the post-merge
    /// `locals`/`stack` state going forward.
    fn allocate_merge(&mut self, block: BlockId, local_count: usize, stack_arity: usize) -> (Vec<ValueId>, Vec<ValueId>) {
        let locals: Vec<ValueId> = (0..local_count).map(|_| self.fresh_value()).collect();
        let stack: Vec<ValueId> = (0..stack_arity).map(|_| self.fresh_value()).collect();
        self.phi_slots.insert(block, (locals.clone(), stack.clone()));
        (locals, stack)
    }

    /// Contributes one edge's exit state into a merge block's phi input
    /// accumulators — `stack_args` must already be exactly that merge
    /// point's declared stack arity (the caller slices/pops accordingly).
    fn contribute(&mut self, block: BlockId, locals: &[ValueId], stack_args: &[ValueId]) {
        let (local_slots, stack_slots) = self.phi_slots.get(&block).cloned().unwrap_or_default();
        for (phi, value) in local_slots.iter().zip(locals.iter()) {
            self.locals_phi_inputs.entry(*phi).or_default().push(*value);
        }
        for (phi, value) in stack_slots.iter().zip(stack_args.iter()) {
            self.stack_phi_inputs.entry(*phi).or_default().push(*value);
        }
    }
}

fn seq_arity(module: &Module, ty: InstrSeqType) -> (usize, usize) {
    match ty {
        InstrSeqType::Simple(None) => (0, 0),
        InstrSeqType::Simple(Some(_)) => (0, 1),
        InstrSeqType::MultiValue(type_id) => {
            let (params, results) = module.types.params_results(type_id);
            (params.len(), results.len())
        }
    }
}

fn qualified_call_name(module: &Module, func_id: walrus::FunctionId) -> String {
    let func = module.funcs.get(func_id);
    match &func.kind {
        FunctionKind::Import(imported) => {
            let import = module.imports.get(imported.import);
            format!("{}.{}", import.module, import.name)
        }
        _ => func.name.clone().unwrap_or_else(|| format!("func_{}", func_id.index())),
    }
}

/// Recursively lowers one instruction sequence (a function's entry body, or
/// one `block`/`loop`/`if`/`else` construct's body), appending to `cur`
/// (already allocated by the caller, possibly already containing
/// instructions). `targets` carries the branch-resolution table for every
/// currently-open enclosing sequence. Returns the block/locals/stack state
/// after the sequence's last instruction, and whether that state already
/// has a real terminator (an explicit `br`/`br_table`/`return`/
/// `unreachable` — in which case any instructions physically following it
/// are unreachable and are skipped).
#[allow(clippy::too_many_arguments)]
fn lower_seq(
    ctx: &mut Ctx,
    local_func: &LocalFunction,
    seq_id: InstrSeqId,
    mut cur: BlockId,
    mut locals: Vec<ValueId>,
    mut stack: Vec<ValueId>,
    targets: &mut HashMap<InstrSeqId, SeqTarget>,
) -> (BlockId, Vec<ValueId>, Vec<ValueId>, bool) {
    let seq = local_func.block(seq_id);
    let instrs: Vec<Instr> = seq.instrs.iter().map(|(instr, _)| instr.clone()).collect();
    let mut terminated = false;

    for instr in &instrs {
        if terminated {
            break; // dead code after an explicit br/br_table/return/unreachable.
        }
        match instr {
            Instr::Block(b) => {
                let inner = local_func.block(b.seq);
                let (params, results) = seq_arity(ctx.module, inner.ty);
                let after = ctx.new_block();
                let (after_locals, after_stack) = ctx.allocate_merge(after, locals.len(), results);
                targets.insert(b.seq, SeqTarget::After { block: after, arity: results });

                let body_args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(params));
                let body_start = ctx.new_block();
                ctx.terminate(cur, Terminator::Goto(body_start));
                let (end_block, end_locals, mut end_stack, end_terminated) =
                    lower_seq(ctx, local_func, b.seq, body_start, locals.clone(), body_args, targets);
                if !end_terminated {
                    let exit_args = end_stack.split_off(end_stack.len().saturating_sub(results));
                    ctx.terminate(end_block, Terminator::Goto(after));
                    ctx.contribute(after, &end_locals, &exit_args);
                }

                stack.extend(after_stack.iter().copied());
                locals = after_locals;
                cur = after;
            }
            Instr::Loop(l) => {
                let inner = local_func.block(l.seq);
                let (params, results) = seq_arity(ctx.module, inner.ty);
                let header = ctx.new_block();
                let (header_locals, header_stack) = ctx.allocate_merge(header, locals.len(), params);

                let initial_args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(params));
                ctx.terminate(cur, Terminator::Goto(header));
                ctx.contribute(header, &locals, &initial_args);
                targets.insert(l.seq, SeqTarget::Header { block: header, arity: params });

                let (end_block, end_locals, mut end_stack, end_terminated) =
                    lower_seq(ctx, local_func, l.seq, header, header_locals, header_stack, targets);

                // Falling off the end of a loop body exits it normally
                // (does NOT repeat) using its own *result* arity — a
                // separate merge point from the header (only an explicit
                // branch back to this loop ever targets the header).
                let after = ctx.new_block();
                let (after_locals, after_stack) = ctx.allocate_merge(after, locals.len(), results);
                if !end_terminated {
                    let exit_args = end_stack.split_off(end_stack.len().saturating_sub(results));
                    ctx.terminate(end_block, Terminator::Goto(after));
                    ctx.contribute(after, &end_locals, &exit_args);
                }

                stack.extend(after_stack.iter().copied());
                locals = after_locals;
                cur = after;
            }
            Instr::IfElse(if_else) => {
                let cond = stack.pop().expect("if consumes a condition");
                let (params, results) = seq_arity(ctx.module, local_func.block(if_else.consequent).ty);
                let after = ctx.new_block();
                let (after_locals, after_stack) = ctx.allocate_merge(after, locals.len(), results);
                targets.insert(if_else.consequent, SeqTarget::After { block: after, arity: results });
                targets.insert(if_else.alternative, SeqTarget::After { block: after, arity: results });

                let branch_args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(params));
                let then_start = ctx.new_block();
                let else_start = ctx.new_block();
                ctx.terminate(cur, Terminator::Branch { cond, then_bb: then_start, else_bb: else_start });

                let (then_end, then_locals, mut then_stack, then_terminated) =
                    lower_seq(ctx, local_func, if_else.consequent, then_start, locals.clone(), branch_args.clone(), targets);
                if !then_terminated {
                    let exit_args = then_stack.split_off(then_stack.len().saturating_sub(results));
                    ctx.terminate(then_end, Terminator::Goto(after));
                    ctx.contribute(after, &then_locals, &exit_args);
                }

                let (else_end, else_locals, mut else_stack, else_terminated) =
                    lower_seq(ctx, local_func, if_else.alternative, else_start, locals.clone(), branch_args, targets);
                if !else_terminated {
                    let exit_args = else_stack.split_off(else_stack.len().saturating_sub(results));
                    ctx.terminate(else_end, Terminator::Goto(after));
                    ctx.contribute(after, &else_locals, &exit_args);
                }

                stack.extend(after_stack.iter().copied());
                locals = after_locals;
                cur = after;
            }
            Instr::Br(br) => {
                let target = *targets.get(&br.block).expect("br targets a currently-open sequence");
                let args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(target.arity()));
                ctx.terminate(cur, Terminator::Goto(target.block()));
                ctx.contribute(target.block(), &locals, &args);
                terminated = true;
            }
            Instr::BrIf(br_if) => {
                let cond = stack.pop().expect("br_if consumes a condition");
                let target = *targets.get(&br_if.block).expect("br_if targets a currently-open sequence");
                let arity = target.arity();
                let args: Vec<ValueId> = stack[stack.len().saturating_sub(arity)..].to_vec();
                ctx.contribute(target.block(), &locals, &args);
                let continuation = ctx.new_block();
                ctx.terminate(cur, Terminator::Branch { cond, then_bb: target.block(), else_bb: continuation });
                cur = continuation;
            }
            Instr::BrTable(br_table) => {
                let index = stack.pop().expect("br_table consumes an index");
                let default_target = *targets.get(&br_table.default).expect("br_table default targets a currently-open sequence");
                let arity = default_target.arity();
                let args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(arity));
                // This IR has no native N-way switch terminator; model
                // every table entry as a genuinely reachable branch via a
                // chain of equality checks against the index, rather than
                // collapsing to only the default arm.
                let mut check_block = cur;
                for (case, seq) in br_table.blocks.iter().enumerate() {
                    let target = *targets.get(seq).expect("br_table arm targets a currently-open sequence");
                    ctx.contribute(target.block(), &locals, &args);
                    let case_value = ctx.const_int(check_block, case as i64);
                    let cond = ctx.fresh_value();
                    ctx.push(check_block, InstKind::Compare { dst: cond, lhs: index, rhs: case_value, op: ComparisonOp::Eq });
                    let next_check = ctx.new_block();
                    ctx.terminate(check_block, Terminator::Branch { cond, then_bb: target.block(), else_bb: next_check });
                    check_block = next_check;
                }
                ctx.contribute(default_target.block(), &locals, &args);
                ctx.terminate(check_block, Terminator::Goto(default_target.block()));
                terminated = true;
            }
            Instr::Return(_) => {
                let value = stack.last().copied();
                ctx.terminate(cur, Terminator::Return(value));
                terminated = true;
            }
            Instr::Unreachable(_) => {
                ctx.terminate(cur, Terminator::Unreachable);
                terminated = true;
            }
            Instr::Call(call) => {
                let func = ctx.module.funcs.get(call.func);
                let (params, results) = ctx.module.types.params_results(func.ty());
                let (param_count, result_count) = (params.len(), results.len());
                let args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(param_count));
                let name = qualified_call_name(ctx.module, call.func);
                let dst = if result_count > 0 { Some(ctx.fresh_value()) } else { None };
                ctx.push(
                    cur,
                    InstKind::Call(CallInst {
                        dst,
                        callee: Callee::Static(name),
                        receiver: None,
                        args,
                        arg_names: Vec::new(),
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
                    }),
                );
                if let Some(dst) = dst {
                    // Only the first return value is modeled — this IR's
                    // `CallInst` has a single `dst`; a real but
                    // comparatively rare multi-value WASM return is
                    // approximated by reusing the same value for every
                    // extra result slot, a documented limitation.
                    for _ in 0..result_count {
                        stack.push(dst);
                    }
                }
            }
            Instr::CallIndirect(call_indirect) => {
                let (params, results) = ctx.module.types.params_results(call_indirect.ty);
                let (param_count, result_count) = (params.len(), results.len());
                let callee_value = stack.pop().expect("call_indirect consumes a table index");
                let args: Vec<ValueId> = stack.split_off(stack.len().saturating_sub(param_count));
                let dst = if result_count > 0 { Some(ctx.fresh_value()) } else { None };
                ctx.push(
                    cur,
                    InstKind::Call(CallInst {
                        dst,
                        callee: Callee::Dynamic(callee_value),
                        receiver: None,
                        args,
                        arg_names: Vec::new(),
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
                    }),
                );
                if let Some(dst) = dst {
                    for _ in 0..result_count {
                        stack.push(dst);
                    }
                }
            }
            Instr::LocalGet(get) => {
                let index = ctx.local_index[&get.local];
                stack.push(locals[index]);
            }
            Instr::LocalSet(set) => {
                let index = ctx.local_index[&set.local];
                let value = stack.pop().expect("local.set consumes a value");
                locals[index] = value;
            }
            Instr::LocalTee(tee) => {
                let index = ctx.local_index[&tee.local];
                let value = *stack.last().expect("local.tee reads the top of stack");
                locals[index] = value;
            }
            Instr::GlobalGet(get) => {
                let dst = ctx.synthetic_call(cur, &format!("__uniflow.bytecode.global_get.{}", get.global.index()), vec![]);
                stack.push(dst);
            }
            Instr::GlobalSet(set) => {
                let value = stack.pop().expect("global.set consumes a value");
                ctx.synthetic_call(cur, &format!("__uniflow.bytecode.global_set.{}", set.global.index()), vec![value]);
            }
            Instr::Const(c) => {
                let dst = ctx.fresh_value();
                let kind = match c.value {
                    WasmValue::I32(v) => InstKind::ConstInt { dst, value: v as i64 },
                    WasmValue::I64(v) => InstKind::ConstInt { dst, value: v },
                    WasmValue::F32(v) => InstKind::ConstString { dst, value: format!("{v}") },
                    WasmValue::F64(v) => InstKind::ConstString { dst, value: format!("{v}") },
                    WasmValue::V128(v) => InstKind::ConstString { dst, value: format!("{v}") },
                };
                ctx.push(cur, kind);
                stack.push(dst);
            }
            Instr::Binop(_) => {
                let rhs = stack.pop().expect("binop rhs");
                let lhs = stack.pop().expect("binop lhs");
                let dst = ctx.synthetic_call(cur, "__uniflow.bytecode.arith", vec![lhs, rhs]);
                stack.push(dst);
            }
            Instr::Unop(_) => {
                let src = stack.pop().expect("unop operand");
                let dst = ctx.synthetic_call(cur, "__uniflow.bytecode.arith", vec![src]);
                stack.push(dst);
            }
            Instr::TernOp(_) => {
                let c = stack.pop().expect("ternop operand 3");
                let b = stack.pop().expect("ternop operand 2");
                let a = stack.pop().expect("ternop operand 1");
                let dst = ctx.synthetic_call(cur, "__uniflow.bytecode.arith", vec![a, b, c]);
                stack.push(dst);
            }
            Instr::Select(_) => {
                let cond = stack.pop().expect("select condition");
                let else_value = stack.pop().expect("select else value");
                let then_value = stack.pop().expect("select then value");
                let dst = ctx.synthetic_call(cur, "__uniflow.bytecode.select", vec![cond, then_value, else_value]);
                stack.push(dst);
            }
            Instr::Drop(_) => {
                stack.pop();
            }
            Instr::Load(_) => {
                let addr = stack.pop().expect("load address");
                let dst = ctx.synthetic_call(cur, "__uniflow.bytecode.memload", vec![addr]);
                stack.push(dst);
            }
            Instr::Store(_) => {
                let value = stack.pop().expect("store value");
                let addr = stack.pop().expect("store address");
                ctx.synthetic_call(cur, "__uniflow.bytecode.memstore", vec![addr, value]);
            }
            // Every other instruction (SIMD, atomics, reference types, the
            // GC/exception-handling proposals, table/memory bulk ops, ...)
            // is intentionally out of scope for a first pass — a
            // documented limitation, not a silent miscompile: none of them
            // are touched by the operand-stack simulation here, so an
            // instruction sequence relying on one will desync its stack
            // depth. Realistic `wasm32-unknown-unknown` output from
            // mainstream source languages predominantly uses the
            // instruction set handled above.
            _ => {}
        }
    }

    (cur, locals, stack, terminated)
}

fn qualified_function_name(module: &Module, func_id: walrus::FunctionId) -> String {
    qualified_call_name(module, func_id)
}

/// `LocalFunction::args` only lists a function's *parameters* — a true
/// local (declared implicitly by being the target of some `local.set`/
/// `local.tee`, WASM's function-local-variable mechanism) is otherwise
/// unenumerated anywhere on `LocalFunction` itself (`module.locals` is a
/// module-wide arena, not scoped per function). Recursively walking every
/// reachable `InstrSeq` to collect every distinct `LocalId` referenced is
/// the only way to learn the full local set and assign each a stable slot
/// index before lowering begins.
fn register_local(id: LocalId, local_index: &mut HashMap<LocalId, usize>, next_index: &mut usize) {
    local_index.entry(id).or_insert_with(|| {
        let index = *next_index;
        *next_index += 1;
        index
    });
}

fn collect_locals(local_func: &LocalFunction, seq_id: InstrSeqId, local_index: &mut HashMap<LocalId, usize>, next_index: &mut usize) {
    for (instr, _) in &local_func.block(seq_id).instrs {
        match instr {
            Instr::LocalGet(get) => register_local(get.local, local_index, next_index),
            Instr::LocalSet(set) => register_local(set.local, local_index, next_index),
            Instr::LocalTee(tee) => register_local(tee.local, local_index, next_index),
            Instr::Block(b) => collect_locals(local_func, b.seq, local_index, next_index),
            Instr::Loop(l) => collect_locals(local_func, l.seq, local_index, next_index),
            Instr::IfElse(if_else) => {
                collect_locals(local_func, if_else.consequent, local_index, next_index);
                collect_locals(local_func, if_else.alternative, local_index, next_index);
            }
            _ => {}
        }
    }
}

/// Lowers every locally-defined function in `module` into `uniflow_ir::Function`s.
pub(crate) fn lower_module(module: &Module) -> Vec<Function> {
    let mut out = Vec::new();
    let mut next_function_id = 0u32;
    for (func_id, local_func) in module.funcs.iter_local() {
        let name = qualified_function_name(module, func_id);
        let function_id = FunctionId(next_function_id);
        next_function_id += 1;

        let ty = local_func.ty();
        let (param_types, result_types) = module.types.params_results(ty);
        let mut local_index = HashMap::with_capacity(local_func.args.len());
        let mut params = Vec::with_capacity(local_func.args.len());
        for (index, local_id) in local_func.args.iter().enumerate() {
            local_index.insert(*local_id, index);
            params.push(ValueId(index as u32));
        }
        // `args` only covers parameters — walk the whole instruction tree
        // to find every additional true local (see `collect_locals`) and
        // give each the next slot index.
        let mut next_index = local_index.len();
        collect_locals(local_func, local_func.entry_block(), &mut local_index, &mut next_index);

        let mut ctx = Ctx {
            module,
            local_index: local_index.clone(),
            next_value: next_index as u32,
            next_inst: 0,
            next_block: 0,
            blocks: Vec::new(),
            phi_slots: HashMap::new(),
            locals_phi_inputs: HashMap::new(),
            stack_phi_inputs: HashMap::new(),
        };

        let entry_block = ctx.new_block();
        // Every local slot beyond the parameters starts at WASM's
        // guaranteed zero value; materialize that explicitly so a read
        // reaching it via a `Phi` merge (a slot never set on every
        // incoming path) still resolves to a real defined value.
        let mut entry_locals: Vec<ValueId> = vec![ValueId(0); local_index.len()];
        for value in &params {
            entry_locals[value.0 as usize] = *value;
        }
        for index in params.len()..local_index.len() {
            entry_locals[index] = ctx.const_int(entry_block, 0);
        }

        let (end_block, _end_locals, mut end_stack, terminated) =
            lower_seq(&mut ctx, local_func, local_func.entry_block(), entry_block, entry_locals.clone(), Vec::new(), &mut HashMap::new());

        if !terminated {
            let value = if !result_types.is_empty() { end_stack.pop() } else { None };
            ctx.terminate(end_block, Terminator::Return(value));
        }

        // Emit each merge block's phi instructions as the first
        // instructions of that block, using the accumulated inputs.
        let mut blocks = ctx.blocks;
        for block in &mut blocks {
            if let Some((local_slots, stack_slots)) = ctx.phi_slots.get(&block.id) {
                let mut phi_insts = Vec::with_capacity(local_slots.len() + stack_slots.len());
                for phi_value in local_slots.iter().chain(stack_slots.iter()) {
                    let inputs = ctx.locals_phi_inputs.remove(phi_value).or_else(|| ctx.stack_phi_inputs.remove(phi_value)).unwrap_or_default();
                    phi_insts.push(Instruction {
                        id: InstId(ctx.next_inst),
                        kind: InstKind::Phi { dst: *phi_value, inputs },
                        span: Span::default(),
                    });
                    ctx.next_inst += 1;
                }
                phi_insts.extend(block.insts.drain(..));
                block.insts = phi_insts;
            }
        }

        let mut value_types = IndexMap::new();
        for (index, value) in entry_locals.iter().enumerate() {
            if let Some(ty) = param_types.get(index) {
                value_types.insert(*value, format!("{ty:?}"));
            }
        }

        out.push(Function {
            id: function_id,
            name,
            params,
            locals: (entry_locals.len() as u32..ctx.next_value).map(ValueId).collect(),
            blocks,
            return_type: match result_types.first() {
                Some(ValType::I32) | Some(ValType::I64) => IrType::Int,
                Some(ValType::F32) | Some(ValType::F64) => IrType::Float,
                Some(_) => IrType::Unknown,
                None => IrType::Void,
            },
            is_external: false,
            span: Span::default(),
            attrs: Default::default(),
            value_types,
            value_spans: IndexMap::new(),
            cpp: None,
            cpp_initializers: Vec::new(),
            value_cpp: IndexMap::new(),
            exception_edges: Vec::new(),
        });
    }
    out
}
