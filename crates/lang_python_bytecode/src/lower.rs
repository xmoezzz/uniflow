//! Per-code-object stack-machine abstract interpretation into `ir::Function`
//! — mirrors `lang_java_bytecode::lower`'s two-pass design: allocate `Phi`
//! placeholders for every non-entry block's live-in state (both the fixed
//! `co_varnames` local-slot array and the operand-stack, sized from
//! `crate::cfg`'s depth analysis), lower every block's instructions against
//! that placeholder state to get real per-block exit state, then wire the
//! placeholders' real inputs from every predecessor's exit state.
//!
//! `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_DEREF` (module-level/free-variable reads)
//! are deliberately **not** given this full cross-block SSA treatment — see
//! `NameEnv` below — trading a little precision on rarely-taint-relevant
//! global/closure-cell state for a much simpler implementation; ordinary
//! local variables (`co_varnames`, read via `LOAD_FAST`) and the operand
//! stack — where the vast majority of real dataflow lives — get full,
//! precise treatment.

use std::collections::HashMap;

use py_marshal::Code;
use uniflow_hir::Span;
use uniflow_ir::{BasicBlock, BlockId, CallInst, Callee, Function, FunctionId, InstId, Instruction, InstKind, Terminator, Type as IrType, ValueId};

use crate::cfg::{build_cfg, stack_delta, Block, CodeCfg};
use crate::opcodes::{jump_target, RawInstr};
use crate::version::PyVersion;

struct Builder {
    next_value: u32,
    next_inst: u32,
    all_values: Vec<ValueId>,
}

impl Builder {
    fn value(&mut self) -> ValueId {
        let id = ValueId(self.next_value);
        self.next_value += 1;
        self.all_values.push(id);
        id
    }
    fn inst(&mut self) -> InstId {
        let id = InstId(self.next_inst);
        self.next_inst += 1;
        id
    }
}

fn const_string(builder: &mut Builder, insts: &mut Vec<Instruction>, value: String) -> ValueId {
    let dst = builder.value();
    insts.push(Instruction { id: builder.inst(), kind: InstKind::ConstString { dst, value }, span: Span::default() });
    dst
}

fn const_int(builder: &mut Builder, insts: &mut Vec<Instruction>, value: i64) -> ValueId {
    let dst = builder.value();
    insts.push(Instruction { id: builder.inst(), kind: InstKind::ConstInt { dst, value }, span: Span::default() });
    dst
}

/// One `LOAD_CONST` constant, pre-rendered to whatever this simplified IR
/// can represent it as. Non-string/int/bool constants (float, bytes,
/// tuple/list/dict/set literals, `None`, `Ellipsis`) are rendered as an
/// opaque, human-readable `ConstString` — this IR has no richer literal
/// shape, and a rare/complex constant's *identity* (not its exact value)
/// is what dataflow actually needs.
fn load_const(builder: &mut Builder, insts: &mut Vec<Instruction>, obj: &py_marshal::Obj) -> ValueId {
    use py_marshal::Obj;
    match obj {
        Obj::String(s) => const_string(builder, insts, s.to_string()),
        Obj::Bool(b) => const_int(builder, insts, if *b { 1 } else { 0 }),
        Obj::Long(n) => n.to_string().parse::<i64>().map(|v| const_int(builder, insts, v)).unwrap_or_else(|_| const_string(builder, insts, format!("<int:{n}>"))),
        Obj::None => const_string(builder, insts, "<None>".to_string()),
        Obj::Ellipsis => const_string(builder, insts, "<Ellipsis>".to_string()),
        Obj::Float(f) => const_string(builder, insts, format!("<float:{f}>")),
        Obj::Bytes(b) => const_string(builder, insts, format!("<bytes:{}>", b.len())),
        Obj::Code(code) => const_string(builder, insts, format!("<code:{}>", code.name)),
        _ => const_string(builder, insts, "<const>".to_string()),
    }
}

/// Tracks, for a subset of currently-live SSA values, the qualified-name
/// text a rule-matcher would expect (`os.environ.get`, a nested function's
/// own qualified name, ...) — recovered the same way every other frontend
/// in this workspace recovers a receiver/callee's qualifier: propagated
/// through `LOAD_GLOBAL`/`LOAD_NAME`/`IMPORT_NAME`/`LOAD_ATTR`/
/// `LOAD_METHOD`/`MAKE_FUNCTION`, consulted at `CALL_*`.
type NamedValues = HashMap<ValueId, String>;

/// Per-block cache for `LOAD_NAME`/`LOAD_GLOBAL`/`LOAD_DEREF`/`LOAD_CLOSURE`
/// reads: materializes a fresh SSA value the first time a given name is
/// read within a block (reused for repeat reads in the *same* block), and
/// is reset at every block boundary — see the module doc comment for why
/// these reads don't get full cross-block SSA/Phi treatment.
#[derive(Default)]
struct NameEnv {
    cache: HashMap<String, ValueId>,
}

impl NameEnv {
    fn read(&mut self, builder: &mut Builder, insts: &mut Vec<Instruction>, named: &mut NamedValues, name: &str) -> ValueId {
        if let Some(&value) = self.cache.get(name) {
            return value;
        }
        let value = const_string(builder, insts, format!("<global:{name}>"));
        named.insert(value, name.to_string());
        self.cache.insert(name.to_string(), value);
        value
    }
}

fn num_params(code: &Code) -> usize {
    let mut n = code.argcount as usize + code.kwonlyargcount as usize;
    if code.flags.contains(py_marshal::CodeFlags::VARARGS) {
        n += 1;
    }
    if code.flags.contains(py_marshal::CodeFlags::VARKEYWORDS) {
        n += 1;
    }
    n.min(code.varnames.len())
}

/// Recursively lowers `code` and every code object nested in its
/// `co_consts` into one `Function` each, appending them to `out` in
/// preorder (nested functions first, so a caller building a name->function
/// index sees every function exactly once).
pub fn lower_code_recursive(code: &Code, qualified_name: &str, version: PyVersion, next_function_id: &mut u32, out: &mut Vec<Function>, diagnostics: &mut Vec<String>) {
    let mut nested_names: HashMap<usize, String> = HashMap::new();
    for (index, constant) in code.consts.iter().enumerate() {
        if let py_marshal::Obj::Code(nested) = constant {
            let nested_qualified = format!("{qualified_name}.{}", nested.name);
            nested_names.insert(index, nested_qualified.clone());
            lower_code_recursive(nested, &nested_qualified, version, next_function_id, out, diagnostics);
        }
    }
    match lower_one(code, qualified_name, version, next_function_id, &nested_names) {
        Ok(function) => out.push(function),
        Err(message) => diagnostics.push(format!("{qualified_name}: {message}")),
    }
}

fn lower_one(code: &Code, qualified_name: &str, version: PyVersion, next_function_id: &mut u32, nested_names: &HashMap<usize, String>) -> Result<Function, String> {
    let function_id = FunctionId(*next_function_id);
    *next_function_id += 1;

    let cfg = build_cfg(&code.code, version.jump_oparg_is_in_code_units());
    let block_count = cfg.blocks.len();
    let mut builder = Builder { next_value: 0, next_inst: 0, all_values: Vec::new() };

    let param_count = num_params(code);
    let mut params = Vec::with_capacity(param_count);
    let mut entry_locals: Vec<Option<ValueId>> = vec![None; code.varnames.len()];
    for slot in 0..param_count {
        let value = builder.value();
        entry_locals[slot] = Some(value);
        params.push(value);
    }

    // Phase 1: allocate placeholder Phi values for every non-entry block's
    // live-in locals array and operand-stack shape.
    let entry_block_index = cfg.index_of_start.get(&0).copied();
    let mut block_entry_locals: Vec<Vec<Option<ValueId>>> = Vec::with_capacity(block_count);
    let mut block_entry_stack: Vec<Vec<ValueId>> = Vec::with_capacity(block_count);
    for index in 0..block_count {
        if Some(index) == entry_block_index {
            block_entry_locals.push(entry_locals.clone());
            block_entry_stack.push(Vec::new());
        } else {
            let locals_phi: Vec<Option<ValueId>> = (0..code.varnames.len()).map(|_| Some(builder.value())).collect();
            block_entry_locals.push(locals_phi);
            let stack_phi: Vec<ValueId> = (0..cfg.entry_depth[index]).map(|_| builder.value()).collect();
            block_entry_stack.push(stack_phi);
        }
    }

    let predecessors = compute_predecessors(&cfg);

    // Phase 2: lower every block's instructions against its (placeholder or
    // real) entry state, producing real exit state per block.
    let mut all_blocks: Vec<BasicBlock> = Vec::with_capacity(block_count);
    let mut block_exit_locals: Vec<Vec<Option<ValueId>>> = Vec::with_capacity(block_count);
    let mut block_exit_stack: Vec<Vec<ValueId>> = Vec::with_capacity(block_count);
    let mut named_values: NamedValues = HashMap::new();
    let mut lambda_values: HashMap<ValueId, String> = HashMap::new();

    for index in 0..block_count {
        let block = &cfg.blocks[index];
        let mut locals = block_entry_locals[index].clone();
        let mut stack = block_entry_stack[index].clone();
        let mut insts: Vec<Instruction> = Vec::new();
        let mut names = NameEnv::default();
        let mut terminator = None;

        for (instr_index, instr) in block.instrs.iter().enumerate() {
            let is_last = instr_index + 1 == block.instrs.len();
            terminator = lower_instruction(&mut builder, &mut insts, code, instr, is_last, block, &cfg, &mut locals, &mut stack, &mut names, &mut named_values, &mut lambda_values, nested_names, qualified_name);
        }

        let term = terminator.unwrap_or_else(|| fallthrough_terminator(block, &cfg));
        all_blocks.push(BasicBlock { id: BlockId(index as u32), insts, term });
        block_exit_locals.push(locals);
        block_exit_stack.push(stack);
    }

    // Phase 3: wire real Phi inputs for every placeholder allocated in
    // phase 1, using each block's real predecessors' real exit state. A
    // phi with zero real inputs (no reaching definition on any modeled
    // path — should not happen for well-formed bytecode, but the analysis
    // above is deliberately approximate for a few rare opcodes) gets a
    // synthetic defined-but-opaque value instead of being left undefined.
    for index in 0..block_count {
        if Some(index) == entry_block_index {
            continue;
        }
        let preds = &predecessors[index];
        for (slot, phi_value) in block_entry_locals[index].iter().enumerate() {
            let Some(phi_value) = phi_value else { continue };
            let inputs: Vec<ValueId> = preds.iter().filter_map(|&p| block_exit_locals[p].get(slot).copied().flatten()).collect();
            push_phi_or_fallback(&mut builder, &mut all_blocks[index].insts, *phi_value, inputs);
        }
        for (slot, phi_value) in block_entry_stack[index].iter().enumerate() {
            let inputs: Vec<ValueId> = preds.iter().filter_map(|&p| block_exit_stack[p].get(slot).copied()).collect();
            push_phi_or_fallback(&mut builder, &mut all_blocks[index].insts, *phi_value, inputs);
        }
    }

    let locals: Vec<ValueId> = builder.all_values.iter().copied().filter(|v| !params.contains(v)).collect();

    Ok(Function {
        id: function_id,
        name: qualified_name.to_string(),
        params,
        locals,
        blocks: all_blocks,
        return_type: IrType::Unknown,
        is_external: false,
        span: Span::default(),
        attrs: Default::default(),
        value_types: named_values.into_iter().map(|(k, v)| (k, v)).collect(),
        value_spans: Default::default(),
        cpp: None,
        cpp_initializers: Vec::new(),
        value_cpp: Default::default(),
        exception_edges: Vec::new(),
    })
}

fn push_phi_or_fallback(builder: &mut Builder, insts: &mut Vec<Instruction>, dst: ValueId, inputs: Vec<ValueId>) {
    // A phi must be the first instructions of a block for downstream
    // consumers that expect merge points up front; since this function is
    // called after the block's own instructions were already appended,
    // insert at the front instead of pushing.
    if inputs.is_empty() {
        insts.insert(0, Instruction { id: builder.inst(), kind: InstKind::ConstString { dst, value: "<unreachable-phi>".to_string() }, span: Span::default() });
    } else {
        insts.insert(0, Instruction { id: builder.inst(), kind: InstKind::Phi { dst, inputs }, span: Span::default() });
    }
}

fn compute_predecessors(cfg: &CodeCfg) -> Vec<Vec<usize>> {
    let mut predecessors = vec![Vec::new(); cfg.blocks.len()];
    for (index, block) in cfg.blocks.iter().enumerate() {
        for successor in &block.successors {
            predecessors[cfg.index_of_start[successor]].push(index);
        }
    }
    predecessors
}

fn fallthrough_terminator(block: &Block, cfg: &CodeCfg) -> Terminator {
    match block.successors.first() {
        Some(&target) => Terminator::Goto(BlockId(cfg.index_of_start[&target] as u32)),
        None => Terminator::Unreachable,
    }
}

#[allow(clippy::too_many_arguments)]
fn lower_instruction(
    builder: &mut Builder,
    insts: &mut Vec<Instruction>,
    code: &Code,
    instr: &RawInstr,
    is_last: bool,
    block: &Block,
    cfg: &CodeCfg,
    locals: &mut [Option<ValueId>],
    stack: &mut Vec<ValueId>,
    names: &mut NameEnv,
    named: &mut NamedValues,
    lambda_values: &mut HashMap<ValueId, String>,
    nested_names: &HashMap<usize, String>,
    _self_qualified_name: &str,
) -> Option<Terminator> {

    match instr.name {
        "LOAD_CONST" => {
            if let Some(constant) = code.consts.get(instr.oparg as usize) {
                let value = load_const(builder, insts, constant);
                if let Some(nested_name) = nested_names.get(&(instr.oparg as usize)) {
                    lambda_values.insert(value, nested_name.clone());
                }
                stack.push(value);
            }
        }
        "LOAD_FAST" => {
            let slot = instr.oparg as usize;
            let value = locals.get(slot).copied().flatten().unwrap_or_else(|| const_string(builder, insts, format!("<undefined-local:{slot}>")));
            stack.push(value);
        }
        "STORE_FAST" => {
            let value = pop(stack, builder, insts);
            if let Some(slot) = locals.get_mut(instr.oparg as usize) {
                *slot = Some(value);
            }
        }
        "DELETE_FAST" => {
            if let Some(slot) = locals.get_mut(instr.oparg as usize) {
                *slot = None;
            }
        }
        "LOAD_GLOBAL" | "LOAD_NAME" => {
            let name = code.names.get(instr.oparg as usize).map(|s| s.to_string()).unwrap_or_default();
            stack.push(names.read(builder, insts, named, &name));
        }
        "STORE_GLOBAL" | "STORE_NAME" | "DELETE_GLOBAL" | "DELETE_NAME" => {
            if matches!(instr.name, "STORE_GLOBAL" | "STORE_NAME") {
                pop(stack, builder, insts);
            }
        }
        "LOAD_DEREF" | "LOAD_CLOSURE" | "LOAD_CLASSDEREF" => {
            let idx = instr.oparg as usize;
            let name = code.cellvars.get(idx).or_else(|| code.freevars.get(idx.saturating_sub(code.cellvars.len()))).map(|s| s.to_string()).unwrap_or_else(|| format!("cell{idx}"));
            stack.push(names.read(builder, insts, named, &name));
        }
        "STORE_DEREF" | "DELETE_DEREF" => {
            if instr.name == "STORE_DEREF" {
                pop(stack, builder, insts);
            }
        }
        "LOAD_ATTR" => {
            let base = pop(stack, builder, insts);
            let field = code.names.get(instr.oparg as usize).map(|s| s.to_string()).unwrap_or_default();
            let dst = builder.value();
            insts.push(Instruction { id: builder.inst(), kind: InstKind::LoadField { dst, base, field: field.clone() }, span: Span::default() });
            if let Some(base_name) = named.get(&base) {
                named.insert(dst, format!("{base_name}.{field}"));
            } else {
                named.insert(dst, field);
            }
            stack.push(dst);
        }
        "STORE_ATTR" => {
            let base = pop(stack, builder, insts);
            let value = pop(stack, builder, insts);
            let field = code.names.get(instr.oparg as usize).map(|s| s.to_string()).unwrap_or_default();
            insts.push(Instruction { id: builder.inst(), kind: InstKind::StoreField { base, field, src: value }, span: Span::default() });
        }
        "LOAD_METHOD" => {
            let receiver = pop(stack, builder, insts);
            let method = code.names.get(instr.oparg as usize).map(|s| s.to_string()).unwrap_or_default();
            let marker = builder.value();
            let qualifier = named.get(&receiver).map(|base| format!("{base}.{method}")).unwrap_or_else(|| method.clone());
            named.insert(marker, qualifier);
            stack.push(marker);
            stack.push(receiver);
        }
        "CALL_METHOD" => {
            let arg_count = instr.oparg as usize;
            let args = pop_n(stack, arg_count, builder, insts);
            let receiver = pop(stack, builder, insts);
            let marker = pop(stack, builder, insts);
            let dst = builder.value();
            let callee = named.get(&marker).cloned().map(Callee::Static).unwrap_or(Callee::Dynamic(marker));
            insts.push(Instruction { id: builder.inst(), kind: InstKind::Call(CallInst { dst: Some(dst), callee, receiver: Some(receiver), args, arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }), span: Span::default() });
            stack.push(dst);
        }
        "CALL_FUNCTION" => {
            let arg_count = instr.oparg as usize;
            let args = pop_n(stack, arg_count, builder, insts);
            let callee_value = pop(stack, builder, insts);
            emit_call(builder, insts, named, lambda_values, callee_value, None, args, stack);
        }
        "CALL_FUNCTION_KW" => {
            let arg_count = instr.oparg as usize;
            pop(stack, builder, insts); // kwnames tuple constant — argument names not modeled individually.
            let args = pop_n(stack, arg_count, builder, insts);
            let callee_value = pop(stack, builder, insts);
            emit_call(builder, insts, named, lambda_values, callee_value, None, args, stack);
        }
        "CALL_FUNCTION_EX" => {
            if instr.oparg & 1 != 0 {
                pop(stack, builder, insts); // kwargs dict
            }
            let unpacked_args = pop(stack, builder, insts); // args tuple — individual arguments not modeled.
            let callee_value = pop(stack, builder, insts);
            emit_call(builder, insts, named, lambda_values, callee_value, None, vec![unpacked_args], stack);
        }
        "MAKE_FUNCTION" => {
            let flag_pops = (instr.oparg & 0xF).count_ones() as usize;
            let _extras = pop_n(stack, flag_pops, builder, insts);
            let qualname = pop(stack, builder, insts);
            let code_value = pop(stack, builder, insts);
            let dst = builder.value();
            insts.push(Instruction { id: builder.inst(), kind: InstKind::Copy { dst, src: code_value }, span: Span::default() });
            if let Some(target) = lambda_values.get(&code_value).cloned() {
                named.insert(dst, target);
            } else if let Some(name) = named.get(&qualname).cloned() {
                named.insert(dst, name);
            }
            stack.push(dst);
        }
        "IMPORT_NAME" => {
            pop(stack, builder, insts);
            pop(stack, builder, insts);
            let name = code.names.get(instr.oparg as usize).map(|s| s.to_string()).unwrap_or_default();
            let dst = const_string(builder, insts, format!("<module:{name}>"));
            named.insert(dst, name);
            stack.push(dst);
        }
        "IMPORT_FROM" => {
            let module = stack.last().copied();
            let name = code.names.get(instr.oparg as usize).map(|s| s.to_string()).unwrap_or_default();
            let dst = builder.value();
            insts.push(Instruction { id: builder.inst(), kind: InstKind::ConstString { dst, value: format!("<from:{name}>") }, span: Span::default() });
            let qualifier = module.and_then(|m| named.get(&m)).map(|base| format!("{base}.{name}")).unwrap_or(name);
            named.insert(dst, qualifier);
            stack.push(dst);
        }
        "POP_TOP" | "STORE_SUBSCR" | "DELETE_SUBSCR" | "PRINT_EXPR" | "IMPORT_STAR" => {
            let delta = stack_delta(instr.name, instr.oparg);
            pop_n(stack, (-delta).max(0) as usize, builder, insts);
        }
        "BINARY_SUBSCR" => {
            let index = pop(stack, builder, insts);
            let base = pop(stack, builder, insts);
            let dst = builder.value();
            insts.push(Instruction { id: builder.inst(), kind: InstKind::LoadIndex { dst, base, index }, span: Span::default() });
            stack.push(dst);
        }
        "RETURN_VALUE" => {
            let value = pop(stack, builder, insts);
            return Some(Terminator::Return(Some(value)));
        }
        "RAISE_VARARGS" => {
            let n = instr.oparg as usize;
            let value = if n > 0 { pop_n(stack, n, builder, insts).into_iter().next() } else { None };
            return Some(Terminator::Throw(value));
        }
        "POP_JUMP_IF_FALSE" | "POP_JUMP_IF_TRUE" => {
            let cond = pop(stack, builder, insts);
            if is_last {
                if let Some(target) = jump_target(instr, false) {
                    let then_bb = cfg.index_of_start.get(&target).copied();
                    let fallthrough = instr.offset + instr.size;
                    let else_bb = cfg.index_of_start.get(&fallthrough).copied();
                    if let (Some(then_bb), Some(else_bb)) = (then_bb, else_bb) {
                        return Some(Terminator::Branch { cond, then_bb: BlockId(then_bb as u32), else_bb: BlockId(else_bb as u32) });
                    }
                }
            }
        }
        "FOR_ITER" | "JUMP_IF_FALSE_OR_POP" | "JUMP_IF_TRUE_OR_POP" | "JUMP_IF_NOT_EXC_MATCH" => {
            if is_last {
                if let Some(target) = jump_target(instr, false) {
                    let fallthrough = instr.offset + instr.size;
                    let then_bb = cfg.index_of_start.get(&target).copied();
                    let else_bb = cfg.index_of_start.get(&fallthrough).copied();
                    let cond = stack.last().copied().unwrap_or_else(|| ValueId(u32::MAX));
                    if let (Some(then_bb), Some(else_bb)) = (then_bb, else_bb) {
                        return Some(Terminator::Branch { cond, then_bb: BlockId(then_bb as u32), else_bb: BlockId(else_bb as u32) });
                    }
                }
            }
        }
        "JUMP_FORWARD" | "JUMP_ABSOLUTE" => {
            if is_last {
                if let Some(target) = jump_target(instr, false) {
                    if let Some(&index) = cfg.index_of_start.get(&target) {
                        return Some(Terminator::Goto(BlockId(index as u32)));
                    }
                }
            }
        }
        // Everything else (arithmetic/compare/build-collection/rotate/dup/
        // async/exception-machinery opcodes not given specific meaning
        // above): approximate with a generic stack effect so the
        // simulation stays balanced, without claiming precise semantics —
        // acceptable for a bytecode frontend whose primary purpose is
        // call-graph/dataflow reachability, not exact value computation.
        other => generic_fallback(builder, insts, other, instr.oparg, stack),
    }
    if is_last {
        Some(fallthrough_terminator(block, cfg))
    } else {
        None
    }
}

/// Pops one value, synthesizing a fresh, properly-defined placeholder on
/// underflow rather than a bogus sentinel `ValueId` — the approximate
/// stack-effect handling for rare exception/async opcodes (see
/// `crate::cfg`'s module doc comment) can occasionally under-count a pop
/// relative to what a block actually needs, and this keeps that a harmless
/// precision loss instead of an invalid-IR ("value used without a
/// definition") failure.
fn pop(stack: &mut Vec<ValueId>, builder: &mut Builder, insts: &mut Vec<Instruction>) -> ValueId {
    stack.pop().unwrap_or_else(|| const_string(builder, insts, "<stack-underflow>".to_string()))
}

fn pop_n(stack: &mut Vec<ValueId>, n: usize, builder: &mut Builder, insts: &mut Vec<Instruction>) -> Vec<ValueId> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(pop(stack, builder, insts));
    }
    out.reverse();
    out
}

fn emit_call(builder: &mut Builder, insts: &mut Vec<Instruction>, named: &mut NamedValues, lambda_values: &HashMap<ValueId, String>, callee_value: ValueId, receiver: Option<ValueId>, args: Vec<ValueId>, stack: &mut Vec<ValueId>) {
    let dst = builder.value();
    let callee = lambda_values.get(&callee_value).or_else(|| named.get(&callee_value)).cloned().map(Callee::Static).unwrap_or(Callee::Dynamic(callee_value));
    insts.push(Instruction { id: builder.inst(), kind: InstKind::Call(CallInst { dst: Some(dst), callee, receiver, args, arg_names: Vec::new(), arg_spans: Vec::new(), arg_origins: Vec::new() }), span: Span::default() });
    stack.push(dst);
}

/// A conservative stand-in for any opcode not given precise handling above:
/// pops what `crate::cfg`'s stack-delta table says it pops (never more than
/// what's actually on the stack) and pushes one fresh opaque value if the
/// opcode is net stack-positive, keeping the simulated stack depth
/// consistent with `crate::cfg`'s independently-computed entry depths.
fn generic_fallback(builder: &mut Builder, insts: &mut Vec<Instruction>, name: &str, oparg: u32, stack: &mut Vec<ValueId>) {
    let delta = stack_delta(name, oparg);
    if delta < 0 {
        let pops = (-delta) as usize;
        let start = stack.len().saturating_sub(pops);
        stack.truncate(start);
    }
    if delta > 0 {
        for _ in 0..delta {
            let dst = builder.value();
            insts.push(Instruction { id: builder.inst(), kind: InstKind::ConstString { dst, value: format!("<{name}>") }, span: Span::default() });
            stack.push(dst);
        }
    }
}
