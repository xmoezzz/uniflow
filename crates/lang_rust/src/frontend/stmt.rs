//! Lowers `syn` statements/blocks into `uniflow_hir::Stmt`/`Block`.

use syn::spanned::Spanned;
use uniflow_hir::{Block, Expr, LiteralKind, Stmt, SwitchClause, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::RustEnv;
use crate::frontend::expr::{expression_qualifier, lower_expr, lower_macro as lower_macro_expr, lvalue_of, member_name, span};
use crate::frontend::functions::unwrap_pattern_type;

fn int_literal(builder: &mut ModuleBuilder, at: uniflow_hir::Span, value: i64) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Int(value), span: at }
}

/// Declares one destructuring leaf, projecting it off `source_expr` (a
/// `FieldRead`/`IndexRead` chain rooted at the original value) so the value
/// — and any taint it carries — keeps flowing, rather than becoming an
/// uninitialized `Let`. Shared by parameter destructuring, `let` bindings,
/// `for`-loop item patterns, and (with the scrutinee as `source_expr`)
/// `match`/`if let`/`while let` arm patterns. Refutable-only pattern forms
/// (`Pat::Lit`, `Pat::Path` naming a unit variant, `Pat::Range`, `Pat::Or`)
/// bind nothing on their own — they are only ever used to *test* a value,
/// never to name part of it — so they are a documented no-op here.
pub(crate) fn lower_pattern_binding(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, pattern: &syn::Pat, source_expr: &Expr, out: &mut Vec<Stmt>) {
    match pattern {
        syn::Pat::Ident(ident_pat) => {
            let name = ident_pat.ident.to_string();
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.declare(&name, symbol);
            let ident_span = span(builder, source, ident_pat.span());
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(source_expr.clone()), span: ident_span });
            if let Some((_, subpat)) = &ident_pat.subpat {
                lower_pattern_binding(builder, env, source, subpat, source_expr, out);
            }
        }
        syn::Pat::Type(inner) => lower_pattern_binding(builder, env, source, &inner.pat, source_expr, out),
        syn::Pat::Reference(inner) => lower_pattern_binding(builder, env, source, &inner.pat, source_expr, out),
        syn::Pat::Paren(inner) => lower_pattern_binding(builder, env, source, &inner.pat, source_expr, out),
        syn::Pat::Tuple(tuple) => {
            for (index, elem) in tuple.elems.iter().enumerate() {
                if matches!(elem, syn::Pat::Rest(_)) {
                    continue;
                }
                let idx_span = source_expr.span();
                let idx_expr = int_literal(builder, idx_span, index as i64);
                let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(idx_expr), span: idx_span };
                lower_pattern_binding(builder, env, source, elem, &projected, out);
            }
        }
        syn::Pat::TupleStruct(tuple_struct) => {
            for (index, elem) in tuple_struct.elems.iter().enumerate() {
                if matches!(elem, syn::Pat::Rest(_)) {
                    continue;
                }
                let idx_span = source_expr.span();
                let idx_expr = int_literal(builder, idx_span, index as i64);
                let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(idx_expr), span: idx_span };
                lower_pattern_binding(builder, env, source, elem, &projected, out);
            }
        }
        syn::Pat::Slice(slice) => {
            for (index, elem) in slice.elems.iter().enumerate() {
                if matches!(elem, syn::Pat::Rest(_)) {
                    continue;
                }
                let idx_span = source_expr.span();
                let idx_expr = int_literal(builder, idx_span, index as i64);
                let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(idx_expr), span: idx_span };
                lower_pattern_binding(builder, env, source, elem, &projected, out);
            }
        }
        syn::Pat::Struct(pat_struct) => {
            for field in &pat_struct.fields {
                let field_span = source_expr.span();
                let field_read = Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), field: member_name(&field.member), span: field_span };
                lower_pattern_binding(builder, env, source, &field.pat, &field_read, out);
            }
        }
        syn::Pat::Wild(_) => {
            let symbol = builder.add_symbol("_", SymbolKind::Local);
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(source_expr.clone()), span: source_expr.span() });
        }
        _ => {}
    }
}

pub(crate) fn lower_block(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, block: &syn::Block) -> Block {
    env.push_block();
    let stmts = block.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: span(builder, source, block.span()) }
}

/// Same as [`lower_block`], but a trailing *tailless* expression (Rust's
/// implicit return value — `fn add(a: i32, b: i32) -> i32 { a + b }`) is
/// wrapped as a real `Stmt::Return` instead of a plain `Stmt::Expr`, so the
/// value actually reaches the function's callers. A tail expression that is
/// itself `return`/`break`/`continue` already lowers to the right `Stmt`
/// variant through the ordinary path and is left alone.
/// `returns_value` should be `false` for a function/closure with no `-> T`
/// (an implicit-unit return type), in which case a tail expression's value
/// is always irrelevant and is lowered via the ordinary, precise
/// statement-position path (`lower_stmt`) rather than wrapped as a
/// `Return` — this matters because Rust's "no semicolon needed after a
/// block-ending expression" rule applies to `if`/`match`/loops used as
/// plain statements just as much as to a real tail value, and only
/// `lower_stmt`'s precise handling (not `lower_expr`'s simplified nested-
/// sub-expression handling — see `crate::frontend::expr`'s module doc
/// comment) gives an `if let`/`match` used this way its full per-arm
/// pattern-binding treatment.
pub(crate) fn lower_function_body(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, block: &syn::Block, returns_value: bool) -> Block {
    env.push_block();
    let mut stmts = Vec::with_capacity(block.stmts.len());
    let last_index = block.stmts.len().saturating_sub(1);
    for (index, stmt) in block.stmts.iter().enumerate() {
        if returns_value && index == last_index {
            if let syn::Stmt::Expr(tail_expr, None) = stmt {
                if !matches!(tail_expr, syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_)) {
                    let value = lower_expr(builder, env, source, tail_expr);
                    let value_span = value.span();
                    stmts.push(Stmt::Return { id: builder.alloc_stmt_id(), value: Some(value), span: value_span });
                    continue;
                }
            }
        }
        stmts.extend(lower_stmt(builder, env, source, stmt));
    }
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: span(builder, source, block.span()) }
}

pub(crate) fn function_returns_value(output: &syn::ReturnType) -> bool {
    !matches!(output, syn::ReturnType::Default)
}

fn lower_local(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, local: &syn::Local) -> Vec<Stmt> {
    let mut out = Vec::new();
    let Some(init) = &local.init else {
        if let syn::Pat::Ident(ident_pat) = unwrap_pattern_type(&local.pat) {
            let name = ident_pat.ident.to_string();
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.declare(&name, symbol);
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: None, span: span(builder, source, ident_pat.span()) });
        }
        return out;
    };
    // `let PAT = EXPR else { DIVERGE };` — the diverge branch only runs when
    // the pattern fails to match; a real static-analysis approximation would
    // need to know that, but since this frontend already visits every
    // control-flow branch unconditionally elsewhere (see `lower_match_stmt`,
    // `lower_match_value`), splicing the diverge branch's statements in
    // unconditionally is consistent and keeps its dataflow (commonly a
    // `return`/`continue`/`panic!`) visible.
    if let Some((_, diverge_expr)) = &init.diverge {
        out.extend(lower_expr_stmt(builder, env, source, diverge_expr));
    }
    let source_expr = lower_expr(builder, env, source, &init.expr);
    let qualifier = expression_qualifier(env, &init.expr);
    match unwrap_pattern_type(&local.pat) {
        syn::Pat::Ident(ident_pat) => {
            let name = ident_pat.ident.to_string();
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.declare(&name, symbol);
            if let Some(qualifier) = qualifier {
                env.set_value_qualifier(symbol, qualifier);
            }
            let ident_span = span(builder, source, ident_pat.span());
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(source_expr), span: ident_span });
            if let Some((_, subpat)) = &ident_pat.subpat {
                let var_ref = Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: ident_span };
                lower_pattern_binding(builder, env, source, subpat, &var_ref, &mut out);
            }
        }
        other => lower_pattern_binding(builder, env, source, other, &source_expr, &mut out),
    }
    out
}

fn lower_if_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, if_expr: &syn::ExprIf) -> Stmt {
    let (cond_expr, pattern_binding) = match &*if_expr.cond {
        syn::Expr::Let(let_expr) => {
            let scrutinee = lower_expr(builder, env, source, &let_expr.expr);
            (scrutinee.clone(), Some((let_expr.pat.as_ref(), scrutinee)))
        }
        other => (lower_expr(builder, env, source, other), None),
    };
    env.push_block();
    let mut then_stmts = Vec::new();
    if let Some((pattern, scrutinee)) = &pattern_binding {
        lower_pattern_binding(builder, env, source, pattern, scrutinee, &mut then_stmts);
    }
    then_stmts.extend(if_expr.then_branch.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)));
    env.pop_block();
    let then_block = Block { id: builder.alloc_block_id(), stmts: then_stmts, span: span(builder, source, if_expr.then_branch.span()) };

    let else_block = if_expr.else_branch.as_ref().map(|(_, else_expr)| lower_else_branch(builder, env, source, else_expr));
    Stmt::If { id: builder.alloc_stmt_id(), cond: cond_expr, then_block, else_block, span: span(builder, source, if_expr.span()) }
}

fn lower_else_branch(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, else_expr: &syn::Expr) -> Block {
    match else_expr {
        syn::Expr::Block(block_expr) => {
            env.push_block();
            let stmts = block_expr.block.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
            env.pop_block();
            Block { id: builder.alloc_block_id(), stmts, span: span(builder, source, block_expr.span()) }
        }
        syn::Expr::If(nested) => {
            let stmt = lower_if_stmt(builder, env, source, nested);
            Block { id: builder.alloc_block_id(), stmts: vec![stmt], span: span(builder, source, nested.span()) }
        }
        other => Block { id: builder.alloc_block_id(), stmts: lower_expr_stmt(builder, env, source, other), span: span(builder, source, other.span()) },
    }
}

/// A pattern that always matches whatever it's compared against — a bare
/// binding (`x => ...`) or `_` — the only patterns that legally end a
/// `match` as its final, catch-all arm.
fn is_catch_all_pattern(pattern: &syn::Pat) -> bool {
    matches!(pattern, syn::Pat::Wild(_)) || matches!(pattern, syn::Pat::Ident(ident) if ident.subpat.is_none())
}

fn lower_match_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, match_expr: &syn::ExprMatch) -> Stmt {
    let scrutinee = lower_expr(builder, env, source, &match_expr.expr);
    let mut clauses = Vec::new();
    let mut default: Option<Block> = None;
    for arm in &match_expr.arms {
        env.push_block();
        let mut arm_stmts = Vec::new();
        lower_pattern_binding(builder, env, source, &arm.pat, &scrutinee, &mut arm_stmts);
        // A match guard is evaluated unconditionally here (a documented
        // simplification: its filtering effect on which arm actually runs
        // isn't modeled), keeping any taint it reads/produces visible.
        if let Some((_, guard)) = &arm.guard {
            let guard_expr = lower_expr(builder, env, source, guard);
            let guard_span = guard_expr.span();
            arm_stmts.push(Stmt::Expr { id: builder.alloc_stmt_id(), expr: guard_expr, span: guard_span });
        }
        arm_stmts.extend(lower_expr_stmt(builder, env, source, &arm.body));
        env.pop_block();
        let arm_span = span(builder, source, arm.span());
        let body = Block { id: builder.alloc_block_id(), stmts: arm_stmts, span: arm_span };
        if default.is_none() && is_catch_all_pattern(&arm.pat) {
            default = Some(body);
        } else {
            clauses.push(SwitchClause { values: Vec::new(), body, fallthrough: false, span: arm_span });
        }
    }
    Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span: span(builder, source, match_expr.span()) }
}

fn lower_while_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, while_expr: &syn::ExprWhile) -> Stmt {
    let (cond_expr, pattern_binding) = match &*while_expr.cond {
        syn::Expr::Let(let_expr) => {
            let scrutinee = lower_expr(builder, env, source, &let_expr.expr);
            (scrutinee.clone(), Some((let_expr.pat.as_ref(), scrutinee)))
        }
        other => (lower_expr(builder, env, source, other), None),
    };
    env.push_block();
    let mut body_stmts = Vec::new();
    if let Some((pattern, scrutinee)) = &pattern_binding {
        lower_pattern_binding(builder, env, source, pattern, scrutinee, &mut body_stmts);
    }
    body_stmts.extend(while_expr.body.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)));
    env.pop_block();
    let body = Block { id: builder.alloc_block_id(), stmts: body_stmts, span: span(builder, source, while_expr.body.span()) };
    Stmt::While { id: builder.alloc_stmt_id(), cond: cond_expr, body, span: span(builder, source, while_expr.span()) }
}

/// `loop { ... }` is exactly `while true { ... }` for this HIR's purposes.
fn lower_loop_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, loop_expr: &syn::ExprLoop) -> Stmt {
    let body = lower_block(builder, env, source, &loop_expr.body);
    let cond = Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Bool(true), span: span(builder, source, loop_expr.span()) };
    Stmt::While { id: builder.alloc_stmt_id(), cond, body, span: span(builder, source, loop_expr.span()) }
}

fn lower_for_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, for_loop: &syn::ExprForLoop) -> Stmt {
    let iterable = lower_expr(builder, env, source, &for_loop.expr);
    env.push_block();
    let mut body_stmts = Vec::new();
    let item_symbol = match unwrap_pattern_type(&for_loop.pat) {
        syn::Pat::Ident(ident_pat) if ident_pat.subpat.is_none() => {
            let name = ident_pat.ident.to_string();
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.declare(&name, symbol);
            symbol
        }
        other => {
            let symbol = builder.add_symbol("$item", SymbolKind::Local);
            let item_span = span(builder, source, other.span());
            let item_ref = Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: item_span };
            lower_pattern_binding(builder, env, source, other, &item_ref, &mut body_stmts);
            symbol
        }
    };
    body_stmts.extend(for_loop.body.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)));
    env.pop_block();
    let body = Block { id: builder.alloc_block_id(), stmts: body_stmts, span: span(builder, source, for_loop.body.span()) };
    Stmt::ForEach { id: builder.alloc_stmt_id(), item_symbol, iterable, body, span: span(builder, source, for_loop.span()) }
}

fn lower_assign_target(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, target_expr: &syn::Expr, projected: Expr, out: &mut Vec<Stmt>) {
    match target_expr {
        syn::Expr::Tuple(tuple) => {
            for (index, elem) in tuple.elems.iter().enumerate() {
                let idx_span = projected.span();
                let idx_expr = int_literal(builder, idx_span, index as i64);
                let element = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(projected.clone()), index: Box::new(idx_expr), span: idx_span };
                lower_assign_target(builder, env, source, elem, element, out);
            }
        }
        syn::Expr::Array(array) => {
            for (index, elem) in array.elems.iter().enumerate() {
                let idx_span = projected.span();
                let idx_expr = int_literal(builder, idx_span, index as i64);
                let element = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(projected.clone()), index: Box::new(idx_expr), span: idx_span };
                lower_assign_target(builder, env, source, elem, element, out);
            }
        }
        syn::Expr::Struct(s) => {
            for field in &s.fields {
                let field_span = projected.span();
                let field_read = Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(projected.clone()), field: member_name(&field.member), span: field_span };
                lower_assign_target(builder, env, source, &field.expr, field_read, out);
            }
        }
        _ => {
            let lvalue = lvalue_of(builder, env, source, target_expr);
            out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: projected.clone(), span: projected.span() });
        }
    }
}

/// Real per-target projection for a destructuring *assignment*
/// (`(a, b) = pair;`, `[a, b] = arr;`, `Point { x, y } = p;`) used as a bare
/// statement — mirrors [`lower_pattern_binding`]'s structure but targets
/// *existing* bindings via [`crate::frontend::expr::lvalue_of`], since these
/// assignment targets are ordinary `syn::Expr`s (not `syn::Pat`s) in Rust's
/// grammar.
fn lower_assign_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, assign: &syn::ExprAssign) -> Vec<Stmt> {
    match assign.left.as_ref() {
        syn::Expr::Tuple(_) | syn::Expr::Array(_) | syn::Expr::Struct(_) => {
            let rhs = lower_expr(builder, env, source, &assign.right);
            let mut out = Vec::new();
            lower_assign_target(builder, env, source, &assign.left, rhs, &mut out);
            out
        }
        _ => {
            let rhs = lower_expr(builder, env, source, &assign.right);
            let lvalue = lvalue_of(builder, env, source, &assign.left);
            vec![Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs, span: span(builder, source, assign.span()) }]
        }
    }
}

/// Lowers an expression used as a *statement*, giving the highest-value
/// constructs (`if`/`match`/loops/`return`/`break`/`continue`/destructuring
/// assignment) real, precise treatment — as opposed to the same constructs
/// appearing as a nested sub-expression, which `crate::frontend::expr`
/// simplifies (see its module doc comment).
pub(crate) fn lower_expr_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, expr: &syn::Expr) -> Vec<Stmt> {
    match expr {
        syn::Expr::If(if_expr) => vec![lower_if_stmt(builder, env, source, if_expr)],
        syn::Expr::Match(match_expr) => vec![lower_match_stmt(builder, env, source, match_expr)],
        syn::Expr::While(while_expr) => vec![lower_while_stmt(builder, env, source, while_expr)],
        syn::Expr::Loop(loop_expr) => vec![lower_loop_stmt(builder, env, source, loop_expr)],
        syn::Expr::ForLoop(for_loop) => vec![lower_for_stmt(builder, env, source, for_loop)],
        syn::Expr::Block(block_expr) => {
            env.push_block();
            let stmts = block_expr.block.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
            env.pop_block();
            stmts
        }
        syn::Expr::Unsafe(unsafe_expr) => {
            env.push_block();
            let stmts = unsafe_expr.block.stmts.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
            env.pop_block();
            stmts
        }
        syn::Expr::Return(ret) => {
            let value = ret.expr.as_ref().map(|value| lower_expr(builder, env, source, value));
            vec![Stmt::Return { id: builder.alloc_stmt_id(), value, span: span(builder, source, ret.span()) }]
        }
        syn::Expr::Break(brk) => {
            vec![Stmt::Break { id: builder.alloc_stmt_id(), label: brk.label.as_ref().map(|l| l.ident.to_string()), span: span(builder, source, brk.span()) }]
        }
        syn::Expr::Continue(cont) => {
            vec![Stmt::Continue { id: builder.alloc_stmt_id(), label: cont.label.as_ref().map(|l| l.ident.to_string()), span: span(builder, source, cont.span()) }]
        }
        syn::Expr::Assign(assign) => lower_assign_stmt(builder, env, source, assign),
        syn::Expr::Macro(mac) => {
            let value = lower_macro_expr(builder, env, source, &mac.mac, mac.span());
            let value_span = value.span();
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr: value, span: value_span }]
        }
        _ => {
            let value = lower_expr(builder, env, source, expr);
            let value_span = value.span();
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr: value, span: value_span }]
        }
    }
}

pub(crate) fn lower_stmt(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, stmt: &syn::Stmt) -> Vec<Stmt> {
    match stmt {
        syn::Stmt::Local(local) => lower_local(builder, env, source, local),
        // A nested item (`fn`, `struct`, `impl`, ...) declared inside a
        // function body is rare enough in idiomatic Rust (closures cover
        // the common "local, capturing function" need) that skipping it
        // here — rather than building a second, item-lowering entry point
        // just for this nesting — is an acceptable, documented scope cut.
        syn::Stmt::Item(_) => vec![],
        syn::Stmt::Expr(expr, _) => lower_expr_stmt(builder, env, source, expr),
        syn::Stmt::Macro(stmt_macro) => {
            let value = lower_macro_expr(builder, env, source, &stmt_macro.mac, stmt_macro.span());
            let value_span = value.span();
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr: value, span: value_span }]
        }
    }
}
