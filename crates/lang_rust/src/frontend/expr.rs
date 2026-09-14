//! Lowers a `syn::Expr` into `uniflow_hir::Expr`.
//!
//! Every construct that carries a real runtime value is modeled precisely
//! (paths/identifiers, field/index access, calls with receiver, `format!`-
//! family macros, binary/assignment/range/cast). A handful of constructs
//! this HIR has no native shape for — most notably a `match`/`if`/`{ }` used
//! directly as a *nested sub-expression* (not a `let` initializer, `return`
//! value, or bare statement, all three of which get full, precise treatment
//! in `crate::frontend::stmt`) — are deliberately simplified; see each arm's
//! comment for the exact simplification and why it is safe for a static
//! data-flow reading of the code.

use proc_macro2::Span as PmSpan;
use syn::spanned::Spanned;
use uniflow_hir::{BinaryOp, CallExpr, CallTarget, CollectionKind, Expr, LValue, LiteralKind, SymbolKind, UnaryOp};
use uniflow_parser_core::{span_from_offsets, ModuleBuilder};

use crate::frontend::env::RustEnv;
use crate::frontend::functions::lower_closure;
use crate::frontend::stmt::lower_function_body;

pub(crate) fn span(builder: &ModuleBuilder, source: &str, pm_span: PmSpan) -> uniflow_hir::Span {
    let range = pm_span.byte_range();
    span_from_offsets(builder.file_id(), source, range.start, range.end)
}

fn opaque(builder: &mut ModuleBuilder, source: &str, pm_span: PmSpan, text: impl Into<String>) -> Expr {
    Expr::Opaque { id: builder.alloc_expr_id(), text: text.into(), span: span(builder, source, pm_span) }
}

fn literal(builder: &mut ModuleBuilder, source: &str, pm_span: PmSpan, kind: LiteralKind) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind, span: span(builder, source, pm_span) }
}

pub(crate) fn path_text(path: &syn::Path) -> String {
    path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>().join(".")
}

pub(crate) fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(ident) => ident.to_string(),
        syn::Member::Unnamed(index) => index.index.to_string(),
    }
}

/// Resolves a plain identifier read to whichever symbol is currently bound
/// to it (allocating a closure capture if it crosses a function boundary),
/// falling back to a fresh, unbound symbol for a genuinely free name (an
/// external item, an undeclared identifier) — treated as an opaque-but-
/// trackable value rather than an error.
pub(crate) fn resolve_identifier(builder: &mut ModuleBuilder, env: &mut RustEnv, name: &str) -> uniflow_hir::SymbolId {
    if let Some(symbol) = env.resolve(builder, name) {
        return symbol;
    }
    let symbol = builder.add_symbol(name, SymbolKind::Global);
    env.declare(name, symbol);
    symbol
}

/// The first path segment's qualified-name provenance: a `use`-imported
/// item, a same-module item, a local binding's own recorded qualifier
/// (`expression_qualifier`), `Self`/`crate`, or — falling back, exactly like
/// `lang_javascript`'s treatment of an unresolved `require`/global — the raw
/// segment text itself (this covers an external crate name such as `std`,
/// `tokio`, `serde_json`, which still makes a perfectly meaningful qualifier
/// for rule matching even though this frontend never resolves it further).
pub(crate) fn resolve_path_qualifier(env: &RustEnv, path: &syn::Path) -> Option<String> {
    let mut segments = path.segments.iter().map(|segment| segment.ident.to_string());
    let first = segments.next()?;
    let mut parts: Vec<String> = match first.as_str() {
        "Self" => vec![env.self_type()?.to_string()],
        "crate" => env.crate_root().map(|root| vec![root.to_string()]).unwrap_or_default(),
        "self" | "super" => Vec::new(),
        _ => {
            if let Some(qualified) = env.use_binding(&first) {
                qualified.split('.').map(str::to_string).collect()
            } else if let Some(qualified) = env.top_level_item(&first) {
                qualified.split('.').map(str::to_string).collect()
            } else if let Some(symbol) = env.peek(&first) {
                match env.value_qualifier(symbol) {
                    Some(qualified) => qualified.split('.').map(str::to_string).collect(),
                    // A plain local variable with no known qualifier and no
                    // further path segments has no static qualified name at
                    // all (e.g. calling a closure stored in a variable).
                    None if path.segments.len() == 1 => return None,
                    None => vec![first],
                }
            } else {
                vec![first]
            }
        }
    };
    parts.extend(segments);
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

/// The qualified-name "provenance" of a value, if it has one — recovered by
/// walking the expression that *produced* it: a qualified path, a call whose
/// own callee was qualified (a call's return value inherits its callee's
/// qualifier, so `Command::new("ls").arg("-l")` names
/// `Command.new.arg`, matching a chained-builder taint rule the same way
/// `lang_javascript::expr::expression_qualifier` does for `mysql2.createConnection().query()`),
/// or a value passed through a borrow/deref/cast/`?`/`.await` wrapper.
pub(crate) fn expression_qualifier(env: &RustEnv, expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path_expr) if path_expr.qself.is_none() => resolve_path_qualifier(env, &path_expr.path),
        syn::Expr::Call(call) => match &*call.func {
            syn::Expr::Path(path_expr) if path_expr.qself.is_none() => resolve_path_qualifier(env, &path_expr.path),
            _ => None,
        },
        syn::Expr::MethodCall(mc) => Some(format!("{}.{}", expression_qualifier(env, &mc.receiver)?, mc.method)),
        syn::Expr::Reference(r) => expression_qualifier(env, &r.expr),
        syn::Expr::Paren(p) => expression_qualifier(env, &p.expr),
        syn::Expr::Group(g) => expression_qualifier(env, &g.expr),
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Deref(_)) => expression_qualifier(env, &u.expr),
        syn::Expr::Try(t) => expression_qualifier(env, &t.expr),
        syn::Expr::Await(a) => expression_qualifier(env, &a.base),
        syn::Expr::Cast(c) => expression_qualifier(env, &c.expr),
        _ => None,
    }
}

fn lower_arguments(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, args: &syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>) -> Vec<Expr> {
    args.iter().map(|arg| lower_expr(builder, env, source, arg)).collect()
}

fn lower_call(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, call: &syn::ExprCall) -> Expr {
    let args = lower_arguments(builder, env, source, &call.args);
    let arg_names = vec![None; args.len()];
    let (target, qualifier_is_explicit) = match &*call.func {
        syn::Expr::Path(path_expr) if path_expr.qself.is_none() && path_expr.path.segments.len() == 1 => {
            let name = path_expr.path.segments[0].ident.to_string();
            let target = env
                .top_level_item(&name)
                .or_else(|| env.use_binding(&name))
                .map(str::to_string)
                .or_else(|| env.peek(&name).and_then(|symbol| env.value_qualifier(symbol)).map(str::to_string))
                .unwrap_or_else(|| name.clone());
            // A bare call that resolved to nothing but its own raw name AND
            // is declared inside an `extern "C" { ... }` block is a genuine
            // FFI import call (Rust's side of calling into a native
            // implementation elsewhere in the scan) — record it for
            // `system_graph::rust_ffi`, mirroring `lang_python`'s
            // `"python.ffi.calls"` fact.
            if target == name && env.is_extern_fn(&name) {
                env.record_ffi_call(name);
            }
            (CallTarget::Named(target), false)
        }
        syn::Expr::Path(path_expr) if path_expr.qself.is_none() => {
            let qualifier = resolve_path_qualifier(env, &path_expr.path).unwrap_or_else(|| path_text(&path_expr.path));
            (CallTarget::Named(qualifier), true)
        }
        other => {
            let callee_expr = lower_expr(builder, env, source, other);
            (CallTarget::Dynamic(Box::new(callee_expr)), false)
        }
    };
    Expr::Call(CallExpr { id: builder.alloc_expr_id(), target, receiver: None, qualifier_is_explicit, args, arg_names, span: span(builder, source, call.span()) })
}

fn lower_method_call(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, mc: &syn::ExprMethodCall) -> Expr {
    let args = lower_arguments(builder, env, source, &mc.args);
    let arg_names = vec![None; args.len()];
    let qualifier = expression_qualifier(env, &mc.receiver);
    let receiver_expr = lower_expr(builder, env, source, &mc.receiver);
    let target = match qualifier {
        Some(qualifier) => CallTarget::Named(format!("{qualifier}.{}", mc.method)),
        None => CallTarget::Named(mc.method.to_string()),
    };
    Expr::Call(CallExpr { id: builder.alloc_expr_id(), target, receiver: Some(Box::new(receiver_expr)), qualifier_is_explicit: true, args, arg_names, span: span(builder, source, mc.span()) })
}

/// `x += y` and friends parse as `syn::ExprBinary` with an assign-flavored
/// `BinOp` (only plain `x = y` is its own `ExprAssign` node) — this maps
/// such an op back to the plain arithmetic/logical operator it combines
/// with the current value, returning `None` for a genuine (non-assigning)
/// binary operator.
fn compound_assign_operator(op: &syn::BinOp) -> Option<BinaryOp> {
    match op {
        syn::BinOp::AddAssign(_) => Some(BinaryOp::Add),
        syn::BinOp::SubAssign(_) => Some(BinaryOp::Sub),
        syn::BinOp::MulAssign(_) => Some(BinaryOp::Mul),
        syn::BinOp::DivAssign(_) => Some(BinaryOp::Div),
        syn::BinOp::RemAssign(_) => Some(BinaryOp::Mod),
        syn::BinOp::BitAndAssign(_) => Some(BinaryOp::BitAnd),
        syn::BinOp::BitOrAssign(_) => Some(BinaryOp::BitOr),
        syn::BinOp::BitXorAssign(_) => Some(BinaryOp::BitXor),
        _ => None,
    }
}

fn map_binary_operator(op: &syn::BinOp) -> BinaryOp {
    match op {
        syn::BinOp::Add(_) => BinaryOp::Add,
        syn::BinOp::Sub(_) => BinaryOp::Sub,
        syn::BinOp::Mul(_) => BinaryOp::Mul,
        syn::BinOp::Div(_) => BinaryOp::Div,
        syn::BinOp::Rem(_) => BinaryOp::Mod,
        syn::BinOp::And(_) => BinaryOp::And,
        syn::BinOp::Or(_) => BinaryOp::Or,
        syn::BinOp::BitXor(_) => BinaryOp::BitXor,
        syn::BinOp::BitAnd(_) => BinaryOp::BitAnd,
        syn::BinOp::BitOr(_) => BinaryOp::BitOr,
        syn::BinOp::Eq(_) => BinaryOp::Eq,
        syn::BinOp::Lt(_) => BinaryOp::Lt,
        syn::BinOp::Le(_) => BinaryOp::Le,
        syn::BinOp::Ne(_) => BinaryOp::Ne,
        syn::BinOp::Ge(_) => BinaryOp::Ge,
        syn::BinOp::Gt(_) => BinaryOp::Gt,
        // Shifts have no dedicated HIR operator; `Add` is a documented
        // approximation (keeps both operands flowing through a generic
        // combination) rather than a correctness claim about the operator's
        // actual semantics — mirrors `lang_javascript`'s treatment of `<<`/
        // `>>`/`**`.
        _ => BinaryOp::Add,
    }
}

pub(crate) fn lvalue_of(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, expr: &syn::Expr) -> LValue {
    match expr {
        syn::Expr::Path(path_expr) if path_expr.qself.is_none() && path_expr.path.segments.len() == 1 => {
            LValue::Var(resolve_identifier(builder, env, &path_expr.path.segments[0].ident.to_string()))
        }
        syn::Expr::Field(field) => {
            let base = lower_expr(builder, env, source, &field.base);
            LValue::Field { base: Box::new(base), field: member_name(&field.member) }
        }
        syn::Expr::Index(index) => {
            let base = lower_expr(builder, env, source, &index.expr);
            let idx = lower_expr(builder, env, source, &index.index);
            LValue::Index { base: Box::new(base), index: Box::new(idx) }
        }
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => lvalue_of(builder, env, source, &unary.expr),
        syn::Expr::Paren(p) => lvalue_of(builder, env, source, &p.expr),
        // Destructuring assignment (`(a, b) = pair;`) has no single
        // addressable location; a synthetic discard local keeps the
        // right-hand side's value (and any taint it carries) visible rather
        // than silently dropping the statement. `crate::frontend::stmt`
        // gives this real per-target projection when it appears as a bare
        // statement, the common shape in practice.
        _ => LValue::Var(builder.add_symbol("__destructure", SymbolKind::Local)),
    }
}

fn lvalue_to_read_expr(builder: &mut ModuleBuilder, lvalue: &LValue, span: uniflow_hir::Span) -> Expr {
    match lvalue {
        LValue::Var(symbol) => Expr::VarRef { id: builder.alloc_expr_id(), symbol: *symbol, span },
        LValue::Field { base, field } => Expr::FieldRead { id: builder.alloc_expr_id(), base: base.clone(), field: field.clone(), span },
        LValue::Index { base, index } => Expr::IndexRead { id: builder.alloc_expr_id(), base: base.clone(), index: index.clone(), span },
    }
}

/// Folds a `match`'s arms into a right-nested `Conditional` chain when the
/// match is consumed as a plain sub-expression (not a `let` initializer,
/// `return` value, or bare statement — those get full per-arm pattern
/// binding and real `Switch` lowering in `crate::frontend::stmt`). The
/// scrutinee is reused as every branch's nominal "condition": a static
/// analysis reading `Conditional` only needs "the result may carry data
/// from either branch", so which branch a runtime condition would actually
/// pick is irrelevant here — this still visits and merges every arm's
/// value. Per-arm pattern bindings are not re-established (documented
/// simplification): an identifier a pattern would bind resolves as an
/// ordinary free identifier instead, same as any other unresolved name.
fn lower_match_value(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, match_expr: &syn::ExprMatch) -> Expr {
    let scrutinee = lower_expr(builder, env, source, &match_expr.expr);
    let match_span = span(builder, source, match_expr.span());
    let mut values: Vec<Expr> = match_expr.arms.iter().map(|arm| lower_expr(builder, env, source, &arm.body)).collect();
    let Some(mut acc) = values.pop() else {
        return literal(builder, source, match_expr.span(), LiteralKind::Null);
    };
    while let Some(value) = values.pop() {
        acc = Expr::Conditional { id: builder.alloc_expr_id(), cond: Box::new(scrutinee.clone()), then_expr: Box::new(value), else_expr: Box::new(acc), span: match_span };
    }
    acc
}

/// Same simplification as [`lower_match_value`] for an `if`/`else` used as a
/// nested sub-expression: both branches are visited and merged, but a
/// multi-statement branch's non-tail statements are dropped (documented —
/// the statement-position case in `crate::frontend::stmt` keeps them).
fn lower_if_value(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, if_expr: &syn::ExprIf) -> Expr {
    let cond = lower_expr(builder, env, source, &if_expr.cond);
    let then_value = block_tail_value(builder, env, source, &if_expr.then_branch);
    let else_value = match &if_expr.else_branch {
        Some((_, else_expr)) => lower_expr(builder, env, source, else_expr),
        None => literal(builder, source, if_expr.span(), LiteralKind::Null),
    };
    Expr::Conditional { id: builder.alloc_expr_id(), cond: Box::new(cond), then_expr: Box::new(then_value), else_expr: Box::new(else_value), span: span(builder, source, if_expr.span()) }
}

/// The value a `{ ... }` block contributes when read as a sub-expression:
/// its trailing tailless expression, or unit (`Null`) when the block ends
/// with a semicolon or is empty. Non-tail statements are otherwise lowered
/// and dropped (documented simplification — see [`lower_if_value`]).
pub(crate) fn block_tail_value(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, block: &syn::Block) -> Expr {
    env.push_block();
    for stmt in block.stmts.iter().take(block.stmts.len().saturating_sub(1)) {
        let _ = crate::frontend::stmt::lower_stmt(builder, env, source, stmt);
    }
    let value = match block.stmts.last() {
        Some(syn::Stmt::Expr(expr, None)) => lower_expr(builder, env, source, expr),
        Some(other) => {
            let _ = crate::frontend::stmt::lower_stmt(builder, env, source, other);
            literal(builder, source, block.span(), LiteralKind::Null)
        }
        None => literal(builder, source, block.span(), LiteralKind::Null),
    };
    env.pop_block();
    value
}

pub(crate) fn lower_expr(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, expr: &syn::Expr) -> Expr {
    match expr {
        syn::Expr::Lit(lit) => lower_literal(builder, source, lit),
        syn::Expr::Path(path_expr) if path_expr.qself.is_none() && path_expr.path.segments.len() == 1 && path_expr.path.leading_colon.is_none() => {
            let name = path_expr.path.segments[0].ident.to_string();
            let symbol = resolve_identifier(builder, env, &name);
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, path_expr.span()) }
        }
        // A qualified path (an enum variant, an associated constant, a
        // fully-qualified item) has no dedicated HIR "qualified value read"
        // shape; its qualifier text is still recorded via `Opaque` so a
        // rule matching that literal qualified name can still see it.
        syn::Expr::Path(path_expr) => {
            let text = resolve_path_qualifier(env, &path_expr.path).unwrap_or_else(|| path_text(&path_expr.path));
            opaque(builder, source, path_expr.span(), text)
        }
        syn::Expr::Field(field) => {
            let base = lower_expr(builder, env, source, &field.base);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: member_name(&field.member), span: span(builder, source, field.span()) }
        }
        syn::Expr::Index(index) => {
            let base = lower_expr(builder, env, source, &index.expr);
            let idx = lower_expr(builder, env, source, &index.index);
            Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(idx), span: span(builder, source, index.span()) }
        }
        syn::Expr::Call(call) => lower_call(builder, env, source, call),
        syn::Expr::MethodCall(mc) => lower_method_call(builder, env, source, mc),
        syn::Expr::Macro(mac) => lower_macro(builder, env, source, &mac.mac, mac.span()),
        syn::Expr::Struct(s) => lower_struct_expr(builder, env, source, s),
        syn::Expr::Array(arr) => {
            let elements = arr.elems.iter().map(|e| lower_expr(builder, env, source, e)).collect();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Array, elements, span: span(builder, source, arr.span()) }
        }
        syn::Expr::Tuple(tuple) => {
            let elements = tuple.elems.iter().map(|e| lower_expr(builder, env, source, e)).collect();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Tuple, elements, span: span(builder, source, tuple.span()) }
        }
        syn::Expr::Repeat(repeat) => {
            let value = lower_expr(builder, env, source, &repeat.expr);
            let len = lower_expr(builder, env, source, &repeat.len);
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Array, elements: vec![value, len], span: span(builder, source, repeat.span()) }
        }
        syn::Expr::Range(range) => {
            let low = range.start.as_ref().map(|e| lower_expr(builder, env, source, e)).unwrap_or_else(|| literal(builder, source, range.span(), LiteralKind::Null));
            let high = range.end.as_ref().map(|e| lower_expr(builder, env, source, e)).unwrap_or_else(|| literal(builder, source, range.span(), LiteralKind::Null));
            let exclusive = matches!(range.limits, syn::RangeLimits::HalfOpen(_));
            Expr::Range { id: builder.alloc_expr_id(), low: Box::new(low), high: Box::new(high), exclusive, span: span(builder, source, range.span()) }
        }
        syn::Expr::Binary(bin) => {
            if let Some(op) = compound_assign_operator(&bin.op) {
                let lvalue = lvalue_of(builder, env, source, &bin.left);
                let rhs = lower_expr(builder, env, source, &bin.right);
                let expr_span = span(builder, source, bin.span());
                let current = lvalue_to_read_expr(builder, &lvalue, expr_span);
                let combined = Expr::Binary { id: builder.alloc_expr_id(), op, lhs: Box::new(current), rhs: Box::new(rhs), span: expr_span };
                return Expr::Assign { id: builder.alloc_expr_id(), lhs: lvalue, rhs: Box::new(combined), span: expr_span };
            }
            let lhs = lower_expr(builder, env, source, &bin.left);
            let rhs = lower_expr(builder, env, source, &bin.right);
            Expr::Binary { id: builder.alloc_expr_id(), op: map_binary_operator(&bin.op), lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, bin.span()) }
        }
        syn::Expr::Assign(assign) => {
            let rhs = lower_expr(builder, env, source, &assign.right);
            let lvalue = lvalue_of(builder, env, source, &assign.left);
            Expr::Assign { id: builder.alloc_expr_id(), lhs: lvalue, rhs: Box::new(rhs), span: span(builder, source, assign.span()) }
        }
        syn::Expr::Unary(unary) => {
            let inner = lower_expr(builder, env, source, &unary.expr);
            let op = match unary.op {
                syn::UnOp::Deref(_) => UnaryOp::Deref,
                syn::UnOp::Not(_) => UnaryOp::Not,
                syn::UnOp::Neg(_) => UnaryOp::Neg,
                _ => return inner,
            };
            Expr::Unary { id: builder.alloc_expr_id(), op, expr: Box::new(inner), span: span(builder, source, unary.span()) }
        }
        // A borrow doesn't change the runtime value's identity for a
        // static data-flow reading of the code; pass the inner value
        // through unchanged (matches `lang_javascript`'s treatment of a
        // parenthesized wrapper).
        syn::Expr::Reference(r) => lower_expr(builder, env, source, &r.expr),
        syn::Expr::Paren(p) => lower_expr(builder, env, source, &p.expr),
        syn::Expr::Group(g) => lower_expr(builder, env, source, &g.expr),
        syn::Expr::Try(t) => lower_expr(builder, env, source, &t.expr),
        syn::Expr::Await(a) => lower_expr(builder, env, source, &a.base),
        syn::Expr::Cast(c) => {
            let inner = lower_expr(builder, env, source, &c.expr);
            Expr::Cast { id: builder.alloc_expr_id(), ty: None, expr: Box::new(inner), span: span(builder, source, c.span()) }
        }
        syn::Expr::Closure(closure) => lower_closure(builder, env, source, &closure.inputs, closure.span(), |builder, env, source| match &*closure.body {
            // A closure's return type is almost always inferred rather than
            // explicitly annotated, so — unlike a named `fn`, where a
            // missing `-> T` reliably means unit — `returns_value: true` is
            // assumed unconditionally here: a block-bodied closure's tail
            // expression is the overwhelmingly common way one produces a
            // value (`.map(|x| { ...; x * 2 })`).
            syn::Expr::Block(block_expr) => lower_function_body(builder, env, source, &block_expr.block, true),
            body => {
                let value = lower_expr(builder, env, source, body);
                let value_span = value.span();
                uniflow_hir::Block { id: builder.alloc_block_id(), stmts: vec![uniflow_hir::Stmt::Return { id: builder.alloc_stmt_id(), value: Some(value), span: value_span }], span: value_span }
            }
        }),
        syn::Expr::If(if_expr) => lower_if_value(builder, env, source, if_expr),
        syn::Expr::Match(match_expr) => lower_match_value(builder, env, source, match_expr),
        syn::Expr::Block(block_expr) => block_tail_value(builder, env, source, &block_expr.block),
        syn::Expr::Unsafe(u) => block_tail_value(builder, env, source, &u.block),
        syn::Expr::Async(a) => block_tail_value(builder, env, source, &a.block),
        syn::Expr::TryBlock(t) => block_tail_value(builder, env, source, &t.block),
        // `while`/`loop`/`for` are overwhelmingly used as statements (full
        // treatment in `crate::frontend::stmt`); as a nested sub-expression
        // their value is unit in the common case (`loop { break value; }`
        // is rare enough that this documented simplification — unit
        // placeholder — is an acceptable trade-off).
        syn::Expr::While(w) => literal(builder, source, w.span(), LiteralKind::Null),
        syn::Expr::Loop(l) => literal(builder, source, l.span(), LiteralKind::Null),
        syn::Expr::ForLoop(f) => literal(builder, source, f.span(), LiteralKind::Null),
        syn::Expr::Return(ret) => {
            let value = ret.expr.as_ref().map(|e| lower_expr(builder, env, source, e));
            opaque(builder, source, ret.span(), format!("return {}", value.map(|_| "<value>").unwrap_or("")))
        }
        syn::Expr::Break(b) => opaque(builder, source, b.span(), "break"),
        syn::Expr::Continue(c) => opaque(builder, source, c.span(), "continue"),
        syn::Expr::Yield(y) => y.expr.as_ref().map(|e| lower_expr(builder, env, source, e)).unwrap_or_else(|| literal(builder, source, y.span(), LiteralKind::Null)),
        syn::Expr::Let(let_expr) => lower_expr(builder, env, source, &let_expr.expr),
        syn::Expr::Infer(i) => opaque(builder, source, i.span(), "_"),
        syn::Expr::Const(c) => block_tail_value(builder, env, source, &c.block),
        _ => opaque(builder, source, expr.span(), "<unsupported-expression>"),
    }
}

fn lower_literal(builder: &mut ModuleBuilder, source: &str, lit: &syn::ExprLit) -> Expr {
    let lit_span = lit.span();
    match &lit.lit {
        syn::Lit::Str(s) => literal(builder, source, lit_span, LiteralKind::String(s.value())),
        syn::Lit::ByteStr(s) => literal(builder, source, lit_span, LiteralKind::Bytes(s.value())),
        syn::Lit::Byte(b) => literal(builder, source, lit_span, LiteralKind::Int(b.value() as i64)),
        syn::Lit::Char(c) => literal(builder, source, lit_span, LiteralKind::String(c.value().to_string())),
        syn::Lit::Int(i) => literal(builder, source, lit_span, LiteralKind::Int(i.base10_parse::<i64>().unwrap_or_default())),
        syn::Lit::Float(f) => literal(builder, source, lit_span, LiteralKind::Float(f.base10_parse::<f64>().unwrap_or_default())),
        syn::Lit::Bool(b) => literal(builder, source, lit_span, LiteralKind::Bool(b.value)),
        _ => opaque(builder, source, lit_span, "<literal>"),
    }
}

fn lower_struct_expr(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, s: &syn::ExprStruct) -> Expr {
    let mut elements = Vec::with_capacity(s.fields.len() * 2);
    for field in &s.fields {
        elements.push(literal(builder, source, field.member.span(), LiteralKind::String(member_name(&field.member))));
        elements.push(lower_expr(builder, env, source, &field.expr));
    }
    if let Some(rest) = &s.rest {
        elements.push(lower_expr(builder, env, source, rest));
    }
    Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Map, elements, span: span(builder, source, s.span()) }
}

/// `format!`/`println!`/`write!`-family macros are Rust's idiomatic string
/// templating mechanism (there is no `+`/template-literal syntax) — modeling
/// them precisely matters for the same reason `lang_javascript` models
/// template literals precisely: a large body of injection-style taint rules
/// (SQL built via `format!("SELECT * FROM t WHERE id = {id}")`, a shell
/// command built via `format!("rm {file}")`) needs to see the literal
/// prefix/suffix text alongside each interpolated value, in source order.
pub(crate) fn lower_macro(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, mac: &syn::Macro, macro_span: PmSpan) -> Expr {
    if let Some(expr) = lower_format_like_macro(builder, env, source, mac, macro_span) {
        return expr;
    }
    match mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::token::Comma>::parse_terminated) {
        Ok(parsed) => {
            let args: Vec<Expr> = parsed.iter().map(|e| lower_expr(builder, env, source, e)).collect();
            let arg_names = vec![None; args.len()];
            // A macro invocation's canonical name keeps its trailing `!` —
            // matching how the opaque-fallback arm below already spells it,
            // and how bundled taint rules for Rust (`portable_models`) name
            // a macro-style sink like `sqlx_query!`.
            let target = CallTarget::Named(format!("{}!", path_text(&mac.path)));
            Expr::Call(CallExpr { id: builder.alloc_expr_id(), target, receiver: None, qualifier_is_explicit: false, args, arg_names, span: span(builder, source, macro_span) })
        }
        Err(_) => opaque(builder, source, macro_span, format!("{}!", path_text(&mac.path))),
    }
}

const FORMAT_LIKE_MACROS: &[&str] = &["format", "print", "println", "eprint", "eprintln", "write", "writeln", "panic", "format_args"];

fn lower_format_like_macro(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, mac: &syn::Macro, macro_span: PmSpan) -> Option<Expr> {
    let macro_name = mac.path.segments.last()?.ident.to_string();
    if !FORMAT_LIKE_MACROS.contains(&macro_name.as_str()) {
        return None;
    }
    let mut items: Vec<syn::Expr> = mac.parse_body_with(syn::punctuated::Punctuated::<syn::Expr, syn::token::Comma>::parse_terminated).ok()?.into_iter().collect();
    let is_write = matches!(macro_name.as_str(), "write" | "writeln");
    let target_expr = if is_write && !items.is_empty() { Some(items.remove(0)) } else { None };
    if items.is_empty() {
        return None;
    }
    let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(fmt_lit), .. }) = &items[0] else { return None };
    let fmt_text = fmt_lit.value();
    let positional_args: Vec<&syn::Expr> = items[1..].iter().collect();
    let parts = split_format_placeholders(builder, env, source, &fmt_text, macro_span, &positional_args);
    let interp = Expr::Interp { id: builder.alloc_expr_id(), parts, span: span(builder, source, macro_span) };

    if let Some(target) = target_expr {
        let receiver_expr = lower_expr(builder, env, source, &target);
        return Some(Expr::Call(CallExpr {
            id: builder.alloc_expr_id(),
            target: CallTarget::Named("write_fmt".to_string()),
            receiver: Some(Box::new(receiver_expr)),
            qualifier_is_explicit: true,
            args: vec![interp],
            arg_names: vec![None],
            span: span(builder, source, macro_span),
        }));
    }
    if matches!(macro_name.as_str(), "panic") {
        return Some(Expr::Call(CallExpr {
            id: builder.alloc_expr_id(),
            target: CallTarget::Named("panic".to_string()),
            receiver: None,
            qualifier_is_explicit: false,
            args: vec![interp],
            arg_names: vec![None],
            span: span(builder, source, macro_span),
        }));
    }
    Some(interp)
}

/// Splits a `format!`-style format string into literal-text/argument parts
/// in source order, matching how `lang_javascript::expr::lower_template_literal`
/// produces `Expr::Interp` from a template literal's quasis/expressions.
/// `{{`/`}}` are escaped literal braces; `{}`/`{:spec}` consume the next
/// positional argument; `{name}`/`{name:spec}` (Rust 2021's captured
/// identifier shorthand) resolve `name` as an ordinary identifier read
/// rather than consuming a positional argument.
fn split_format_placeholders(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, fmt_text: &str, macro_span: PmSpan, positional_args: &[&syn::Expr]) -> Vec<Expr> {
    let mut parts = Vec::new();
    let mut literal_buf = String::new();
    let mut positional = positional_args.iter();
    let chars: Vec<char> = fmt_text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '{' if chars.get(i + 1) == Some(&'{') => {
                literal_buf.push('{');
                i += 2;
            }
            '}' if chars.get(i + 1) == Some(&'}') => {
                literal_buf.push('}');
                i += 2;
            }
            '{' => {
                if let Some(end) = chars[i..].iter().position(|c| *c == '}') {
                    if !literal_buf.is_empty() {
                        parts.push(literal(builder, source, macro_span, LiteralKind::String(std::mem::take(&mut literal_buf))));
                    }
                    let placeholder: String = chars[i + 1..i + end].iter().collect();
                    let name = placeholder.split(':').next().unwrap_or("").trim();
                    let value = if name.is_empty() {
                        positional.next().map(|arg| lower_expr(builder, env, source, arg))
                    } else if name.chars().all(|c| c.is_ascii_digit()) {
                        name.parse::<usize>().ok().and_then(|idx| positional_args.get(idx)).map(|arg| lower_expr(builder, env, source, arg))
                    } else if name.chars().next().is_some_and(|c| c.is_alphabetic() || c == '_') {
                        let symbol = resolve_identifier(builder, env, name);
                        Some(Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, macro_span) })
                    } else {
                        None
                    };
                    if let Some(value) = value {
                        parts.push(value);
                    }
                    i += end + 1;
                } else {
                    literal_buf.push('{');
                    i += 1;
                }
            }
            c => {
                literal_buf.push(c);
                i += 1;
            }
        }
    }
    if !literal_buf.is_empty() {
        parts.push(literal(builder, source, macro_span, LiteralKind::String(literal_buf)));
    }
    parts
}
