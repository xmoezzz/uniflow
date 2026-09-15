//! Shared IR-walking helpers used by more than one adapter ([`crate::http`],
//! [`crate::lifecycle`]) — kept separate from any one adapter so the
//! techniques (resolving a callable value passed as a call argument,
//! reconstructing the literal/dynamic pieces feeding a string value) read as
//! general-purpose, not owned by whichever adapter needed them first.

use std::collections::{HashMap, HashSet};

use uniflow_hir::Language;
use uniflow_ir::{Callee, Function, InstKind, Program, Terminator, ValueId};

/// Returns whether `function` is the Python frontend's compatibility alias
/// for a root-module function. Project parsing retains `run` next to
/// `worker.run` for local resolution, but they share one body and source
/// span. Boundary adapters must only emit facts for the qualified entry so a
/// single runtime endpoint cannot create duplicate cross-system paths.
pub fn is_python_root_alias(program: &Program, function: &Function) -> bool {
    program.language == Language::Python
        && !function.name.contains('.')
        && program.functions.iter().any(|candidate| {
            candidate.name.ends_with(&format!(".{}", function.name))
                && candidate.span.file == function.span.file
                && candidate.span.start_byte == function.span.start_byte
                && candidate.span.end_byte == function.span.end_byte
        })
}

/// A read-only index of every function across every language group's own
/// `Program`, keyed by the same fully-qualified name convention
/// `Callee::Static`/`ApiMatcher::exact` already use — lets an adapter (e.g.
/// [`crate::http`]) resolve a *different* group's function (its parameter
/// names, in particular) without merging `Program`s or re-parsing.
pub struct FunctionIndex<'a> {
    by_name: HashMap<&'a str, (&'a Language, &'a Function)>,
}

impl<'a> FunctionIndex<'a> {
    pub fn build(programs: &'a [(Language, Program)]) -> Self {
        let mut by_name = HashMap::new();
        for (language, program) in programs {
            for function in &program.functions {
                by_name.insert(function.name.as_str(), (language, function));
            }
        }
        Self { by_name }
    }

    pub fn get(&self, name: &str) -> Option<(&'a Language, &'a Function)> {
        self.by_name.get(name).map(|&(language, function)| (language, function))
    }
}

/// Looks up which function `value` refers to, when it was produced by a
/// closure/lambda literal passed as a call argument (this is how a method
/// reference or lambda argument — e.g. `router.get("/x", Service::handler)`
/// — surfaces in IR: the frontend names the value's *type* after a
/// synthesized function, see `Function.value_types`). When that synthesized
/// function's body is nothing but a single forwarding call to another named
/// function, the *real* target is returned instead (unwrapping one level of
/// "lambda that only calls X" indirection); otherwise the synthesized
/// function's own name is returned, which is still a valid, analyzable
/// target.
pub fn resolve_callable_argument(program: &Program, containing_function: &Function, value: ValueId) -> Option<String> {
    let synthesized_name = containing_function.value_types.get(&value)?;
    let synthesized = program.functions.iter().find(|function| &function.name == synthesized_name)?;
    if let Some(forwarded) = single_forwarding_call_target(synthesized) {
        return Some(forwarded);
    }
    Some(synthesized.name.clone())
}

/// `true` when `function`'s entire body is exactly one `Call` to a *named*
/// static callee (whatever its return does), which is the shape a
/// same-arity method-reference-as-lambda desugaring produces.
fn single_forwarding_call_target(function: &Function) -> Option<String> {
    let mut calls = function
        .blocks
        .iter()
        .flat_map(|block| &block.insts)
        .filter_map(|inst| match &inst.kind {
            InstKind::Call(call) => Some(call),
            _ => None,
        });
    let only_call = calls.next()?;
    if calls.next().is_some() {
        return None;
    }
    match &only_call.callee {
        Callee::Static(name) => Some(name.clone()),
        _ => None,
    }
}

/// One piece of a string value, in left-to-right source order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringPiece {
    Literal(String),
    /// Not further resolvable as a literal — carries the contributing
    /// `ValueId` so a caller can attempt to identify *what* it is (a
    /// formal parameter, a specific call's result, ...).
    Dynamic(ValueId),
}

/// Reconstructs, in left-to-right order, the sequence of literal and
/// dynamic pieces that make up a string value, by walking `function`'s own
/// `Copy`/`Phi` definition chain for it.
///
/// Source-level `a + b + c` string concatenation lowers (in this codebase's
/// current `lang_java` frontend, empirically confirmed, not assumed) to
/// *nested* `Phi` merges matching the expression's own left-associative
/// structure — e.g. `base + "/x?id=" + id` becomes
/// `Phi(Phi(base, "/x?id="), id)` — so expanding each `Phi`'s `inputs` in
/// their listed order (not via a LIFO stack, which would reverse them)
/// recovers the original left-to-right sequence.
///
/// `Phi` nodes are also how this IR represents ordinary control-flow merges
/// (an `if`/`else` join, a loop header), not only concatenation — walking
/// into one *assumes* it is concatenation order, which holds for
/// straight-line URL-building code (this crate's target case) but is not
/// guaranteed for a value built across a conditional; a cycle guard
/// (`visited`) prevents infinite recursion on a genuine loop-carried `Phi`
/// (in that case the loop variable is reported as one opaque `Dynamic`
/// piece rather than expanded).
/// `uniflow_lowering` wraps a JavaScript/Ruby `+`-concatenation's result in
/// a call to one of these (`emit_expression_composition`, gated to those two
/// languages) to carry a separate "literal skeleton" descriptor for other
/// checkers — `args[0]` is always the real, pre-wrap composed value, so
/// seeing through it here is a transparent Copy-like unwrap, not a guess.
const STRING_COMPOSITION_CALLEES: &[&str] = &["__uniflow.compose.string", "__uniflow.compose.map"];

fn composition_source(call: &uniflow_ir::CallInst) -> Option<ValueId> {
    let Callee::Static(name) = &call.callee else { return None };
    if !STRING_COMPOSITION_CALLEES.contains(&name.as_str()) {
        return None;
    }
    call.args.first().copied()
}

pub fn resolve_string_sequence(function: &Function, value: ValueId) -> Vec<StringPiece> {
    let mut defs: HashMap<ValueId, &InstKind> = HashMap::new();
    for block in &function.blocks {
        for inst in &block.insts {
            let dst = match &inst.kind {
                InstKind::ConstString { dst, .. } => Some(*dst),
                InstKind::Copy { dst, .. } => Some(*dst),
                InstKind::Phi { dst, .. } => Some(*dst),
                InstKind::Call(call) if call.dst.is_some() && composition_source(call).is_some() => call.dst,
                _ => None,
            };
            if let Some(dst) = dst {
                defs.insert(dst, &inst.kind);
            }
        }
    }

    let mut visited = HashSet::new();
    let mut out = Vec::new();
    expand(&defs, value, &mut visited, &mut out);
    out
}

fn expand(defs: &HashMap<ValueId, &InstKind>, value: ValueId, visited: &mut HashSet<ValueId>, out: &mut Vec<StringPiece>) {
    if !visited.insert(value) {
        out.push(StringPiece::Dynamic(value));
        return;
    }
    match defs.get(&value) {
        Some(InstKind::ConstString { value: text, .. }) => out.push(StringPiece::Literal(text.clone())),
        Some(InstKind::Copy { src, .. }) => expand(defs, *src, visited, out),
        Some(InstKind::Phi { inputs, .. }) => {
            for &input in inputs {
                expand(defs, input, visited, out);
            }
        }
        Some(InstKind::Call(call)) => match composition_source(call) {
            Some(source) => expand(defs, source, visited, out),
            None => out.push(StringPiece::Dynamic(value)),
        },
        _ => out.push(StringPiece::Dynamic(value)),
    }
}

/// The zero-based index of `function`'s own formal parameter, if `value` is
/// (after unwrapping any `Copy`/`Phi` chain — see [`resolve_string_sequence`])
/// exactly one of its declared parameters. This is what lets a caller-side
/// dynamic string piece be addressed precisely as `Port::Arg(k)` on
/// `function` itself, rather than an unresolvable raw local value.
pub fn parameter_index(function: &Function, value: ValueId) -> Option<usize> {
    function.params.iter().position(|&param| param == value)
}

/// The zero-based parameter index whose declared name is `name`, read from
/// the `param_names` attr every frontend already attaches to a lowered
/// `Function` (unit-separator-`\u{1f}`-joined declared parameter names).
pub fn parameter_index_by_name(function: &Function, name: &str) -> Option<usize> {
    let names = function.attrs.get("param_names")?;
    names.split('\u{1f}').position(|candidate| candidate == name)
}

/// Follows a value's `Copy` definition chain (and a `Phi` only when every
/// input resolves to the same root — the same "agree or give up" rule
/// [`crate::config::getenv_name_for_result`] uses) to its underlying
/// defining value. This is what lets two independent call sites —
/// `let stmt = conn.prepareStatement(sql)` and a later `stmt.setString(...)`
/// — be proven to share *the same object*: the `setString` call's
/// `receiver` resolves to the same root `ValueId` as `prepareStatement`'s
/// own `dst`, with no new IR field needed since object identity is already
/// ordinary `ValueId` identity. Cycle-guarded like [`resolve_string_sequence`].
pub fn resolve_value_root(function: &Function, value: ValueId) -> ValueId {
    let mut defs: HashMap<ValueId, &InstKind> = HashMap::new();
    for block in &function.blocks {
        for inst in &block.insts {
            if let InstKind::Copy { dst, .. } | InstKind::Phi { dst, .. } = &inst.kind {
                defs.insert(*dst, &inst.kind);
            }
        }
    }
    let mut visited = HashSet::new();
    resolve_root(&defs, value, &mut visited)
}

/// The `CallInst` whose destination is `value`, if any — a plain "find the
/// producing call" lookup restricted to this function's own instructions.
/// Combine with [`resolve_value_root`] to walk through the `Copy` alias a
/// declaration's own use of a value typically introduces before finding the
/// call that actually produced it (e.g. an FFI registration-table argument
/// resolving back to the `__compound_array_*`/`__compound_*` call chain
/// `crates/lang_c`'s `rewrite_plain_aggregate_initializers` produces for a
/// real struct/array literal).
pub fn call_defining(function: &Function, value: ValueId) -> Option<&uniflow_ir::CallInst> {
    function.blocks.iter().flat_map(|block| &block.insts).find_map(|inst| match &inst.kind {
        InstKind::Call(call) if call.dst == Some(value) => Some(call),
        _ => None,
    })
}

fn resolve_root(defs: &HashMap<ValueId, &InstKind>, value: ValueId, visited: &mut HashSet<ValueId>) -> ValueId {
    if !visited.insert(value) {
        return value;
    }
    match defs.get(&value) {
        Some(InstKind::Copy { src, .. }) => resolve_root(defs, *src, visited),
        Some(InstKind::Phi { inputs, .. }) if !inputs.is_empty() => {
            let first = resolve_root(defs, inputs[0], visited);
            let all_agree = inputs[1..].iter().all(|&input| resolve_root(defs, input, visited) == first);
            if all_agree { first } else { value }
        }
        _ => value,
    }
}

/// Whether `value` is read anywhere in `function` — as an ordinary
/// instruction operand or as the value carried by a `return`/`throw`/branch
/// terminator. This IR allocates a destination `ValueId` for every call
/// unconditionally (confirmed empirically across every lowering site),
/// whether or not anything actually reads the result, so `call.dst.is_some()`
/// alone cannot distinguish "the caller uses this response" from "the call
/// was issued for its side effect and the result is discarded" — an adapter
/// that wants that distinction (e.g. before modeling a boundary edge onto
/// the call's own result) needs this real, function-wide use check instead.
pub fn value_is_used_in_function(function: &Function, value: ValueId) -> bool {
    for block in &function.blocks {
        if block.insts.iter().any(|inst| instruction_reads_value(&inst.kind, value)) {
            return true;
        }
        let read_by_terminator = match &block.term {
            Terminator::Branch { cond, .. } => *cond == value,
            Terminator::Return(Some(v)) | Terminator::Throw(Some(v)) => *v == value,
            Terminator::Goto(_) | Terminator::Return(None) | Terminator::Throw(None) | Terminator::Unreachable => false,
        };
        if read_by_terminator {
            return true;
        }
    }
    false
}

fn instruction_reads_value(kind: &InstKind, value: ValueId) -> bool {
    match kind {
        InstKind::ConstInt { .. } | InstKind::ConstString { .. } => false,
        InstKind::Copy { src, .. }
        | InstKind::Move { src, .. }
        | InstKind::Cast { src, .. }
        | InstKind::Deref { src, .. }
        | InstKind::NumericStep { src, .. }
        | InstKind::NumericNeg { src, .. } => *src == value,
        InstKind::Lifetime { value: lifetime_value, .. } => *lifetime_value == value,
        InstKind::Compare { lhs, rhs, .. } => *lhs == value || *rhs == value,
        InstKind::Phi { inputs, .. } => inputs.contains(&value),
        InstKind::LoadField { base, .. } => *base == value,
        InstKind::StoreField { base, src, .. } => *base == value || *src == value,
        InstKind::LoadIndex { base, index, .. } => *base == value || *index == value,
        InstKind::StoreIndex { base, index, src } => *base == value || *index == value || *src == value,
        InstKind::Call(call) => {
            call.receiver == Some(value) || call.args.contains(&value) || matches!(&call.callee, Callee::Dynamic(target) if *target == value)
        }
    }
}
