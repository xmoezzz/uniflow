//! Lowers `gosyn::ast::Statement` into `uniflow_hir::Stmt`/`Block`.

use gosyn::ast as go;
use gosyn::token::{Keyword, Operator};
use uniflow_hir::{BinaryOp, Block, Expr, LValue, LiteralKind, Stmt, SwitchClause, SymbolId, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::GoEnv;
use crate::frontend::expr::{expression_qualifier, lower_expr, resolve_identifier, span_at, span_range, type_qualifier};

pub(crate) fn lower_block(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, block: &go::BlockStmt) -> Block {
    env.push_block();
    let stmts = block.list.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: span_range(builder, source, block.pos.0, block.pos.1) }
}

fn single_stmt_block(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, stmt: &go::Statement) -> Block {
    env.push_block();
    let stmts = lower_stmt(builder, env, source, stmt);
    env.pop_block();
    let span = stmts.first().map(stmt_span).unwrap_or_default();
    Block { id: builder.alloc_block_id(), stmts, span }
}

fn stmt_span(stmt: &Stmt) -> uniflow_hir::Span {
    match stmt {
        Stmt::Let { span, .. }
        | Stmt::Assign { span, .. }
        | Stmt::Expr { span, .. }
        | Stmt::If { span, .. }
        | Stmt::While { span, .. }
        | Stmt::For { span, .. }
        | Stmt::ForEach { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::Throw { span, .. }
        | Stmt::Try { span, .. }
        | Stmt::Break { span, .. }
        | Stmt::Continue { span, .. }
        | Stmt::DoWhile { span, .. }
        | Stmt::Switch { span, .. } => *span,
    }
}

pub(crate) fn lower_lvalue(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, expr: &go::Expression) -> LValue {
    match expr {
        go::Expression::Ident(ident) if ident.name == "_" => LValue::Var(builder.add_symbol("_", SymbolKind::Local)),
        go::Expression::Ident(ident) => LValue::Var(resolve_identifier(builder, env, &ident.name)),
        go::Expression::Selector(selector) => {
            let base = lower_expr(builder, env, source, &selector.x);
            LValue::Field { base: Box::new(base), field: selector.sel.name.clone() }
        }
        go::Expression::Index(index) => {
            let base = lower_expr(builder, env, source, &index.left);
            let idx = lower_expr(builder, env, source, &index.index);
            LValue::Index { base: Box::new(base), index: Box::new(idx) }
        }
        // A pointer-dereferencing assignment target (`*p = v`): approximated
        // as assigning through the pointee's own variable identity, which is
        // the closest addressable location this HIR can express and keeps
        // taint flowing through the common `*p = value` idiom.
        go::Expression::Star(star) => lower_lvalue(builder, env, source, &star.right),
        go::Expression::Paren(paren) => lower_lvalue(builder, env, source, &paren.expr),
        _ => LValue::Var(builder.add_symbol("__assign_target", SymbolKind::Local)),
    }
}

fn lvalue_to_read_expr(builder: &mut ModuleBuilder, lvalue: &LValue, span: uniflow_hir::Span) -> Expr {
    match lvalue {
        LValue::Var(symbol) => Expr::VarRef { id: builder.alloc_expr_id(), symbol: *symbol, span },
        LValue::Field { base, field } => Expr::FieldRead { id: builder.alloc_expr_id(), base: base.clone(), field: field.clone(), span },
        LValue::Index { base, index } => Expr::IndexRead { id: builder.alloc_expr_id(), base: base.clone(), index: index.clone(), span },
    }
}

fn map_compound_operator(op: Operator) -> BinaryOp {
    match op {
        Operator::AddAssign => BinaryOp::Add,
        Operator::SubAssign => BinaryOp::Sub,
        Operator::MulAssign => BinaryOp::Mul,
        Operator::QuoAssign => BinaryOp::Div,
        Operator::RemAssign => BinaryOp::Mod,
        Operator::AndAssign => BinaryOp::BitAnd,
        Operator::OrAssign => BinaryOp::BitOr,
        Operator::XorAssign => BinaryOp::BitXor,
        // No dedicated HIR operator for a compound shift/bit-clear; `Add`
        // keeps both operands flowing (documented approximation).
        Operator::ShlAssign | Operator::ShrAssign | Operator::AndNotAssign => BinaryOp::Add,
        _ => BinaryOp::Add,
    }
}

fn declare_local(builder: &mut ModuleBuilder, env: &mut GoEnv, name: &go::Ident, init: Option<Expr>, qualifier: Option<String>, span: uniflow_hir::Span) -> Stmt {
    if name.name == "_" {
        let symbol = builder.add_symbol("_", SymbolKind::Local);
        return Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init, span };
    }
    let symbol = builder.add_symbol(&name.name, SymbolKind::Local);
    env.declare(&name.name, symbol);
    if let Some(qualifier) = qualifier {
        env.set_value_qualifier(symbol, qualifier);
    }
    Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init, span }
}

/// Shared body for a local `var`/`const` group (`gosyn` gives `VarSpec` and
/// `ConstSpec` the identical `name`/`typ`/`values` shape but as distinct
/// nominal types, so callers pass the three fields directly rather than the
/// spec itself).
fn lower_local_binding_group(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, names: &[go::Ident], typ: &Option<go::Expression>, values: &[go::Expression]) -> Vec<Stmt> {
    let explicit_qualifier = typ.as_ref().and_then(|t| type_qualifier(env, t));
    let mut out = Vec::with_capacity(names.len());
    if names.len() == values.len() {
        for (name, value) in names.iter().zip(values.iter()) {
            let qualifier = explicit_qualifier.clone().or_else(|| expression_qualifier(env, value));
            let value_expr = lower_expr(builder, env, source, value);
            out.push(declare_local(builder, env, name, Some(value_expr), qualifier, span_at(builder, source, name.pos)));
        }
    } else if let Some(first_value) = values.first() {
        // Multi-return-shaped initializer (`var a, b = f()`): every declared
        // name shares the same single lowered value, an approximation that
        // still keeps whatever taint that call produced reachable from
        // every name it's assigned to.
        let value_expr = lower_expr(builder, env, source, first_value);
        for name in names {
            out.push(declare_local(builder, env, name, Some(value_expr.clone()), explicit_qualifier.clone(), span_at(builder, source, name.pos)));
        }
    } else {
        for name in names {
            out.push(declare_local(builder, env, name, None, explicit_qualifier.clone(), span_at(builder, source, name.pos)));
        }
    }
    out
}

fn range_binding_symbol(builder: &mut ModuleBuilder, env: &mut GoEnv, target: &Option<go::Expression>, declares_new: bool) -> Option<SymbolId> {
    let expr = target.as_ref()?;
    match expr {
        go::Expression::Ident(ident) if ident.name == "_" => None,
        go::Expression::Ident(ident) => {
            if declares_new {
                let symbol = builder.add_symbol(&ident.name, SymbolKind::Local);
                env.declare(&ident.name, symbol);
                Some(symbol)
            } else {
                Some(resolve_identifier(builder, env, &ident.name))
            }
        }
        _ => None,
    }
}

fn lower_assign_stmt(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, assign: &go::AssignStmt) -> Vec<Stmt> {
    let span = span_at(builder, source, assign.pos);
    if matches!(assign.op, Operator::Define) {
        let mut out = Vec::with_capacity(assign.left.len());
        if assign.left.len() == assign.right.len() {
            for (lhs, rhs) in assign.left.iter().zip(assign.right.iter()) {
                let qualifier = expression_qualifier(env, rhs);
                let rhs_expr = lower_expr(builder, env, source, rhs);
                out.push(declare_short_var(builder, env, lhs, rhs_expr, qualifier, span));
            }
        } else if let Some(first_rhs) = assign.right.first() {
            let qualifier = expression_qualifier(env, first_rhs);
            let rhs_expr = lower_expr(builder, env, source, first_rhs);
            for lhs in &assign.left {
                out.push(declare_short_var(builder, env, lhs, rhs_expr.clone(), qualifier.clone(), span));
            }
        }
        return out;
    }
    if matches!(assign.op, Operator::Assign) {
        let mut out = Vec::with_capacity(assign.left.len());
        if assign.left.len() == assign.right.len() {
            for (lhs, rhs) in assign.left.iter().zip(assign.right.iter()) {
                let lvalue = lower_lvalue(builder, env, source, lhs);
                let rhs_expr = lower_expr(builder, env, source, rhs);
                out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: rhs_expr, span });
            }
        } else if let Some(first_rhs) = assign.right.first() {
            let rhs_expr = lower_expr(builder, env, source, first_rhs);
            for lhs in &assign.left {
                let lvalue = lower_lvalue(builder, env, source, lhs);
                out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: rhs_expr.clone(), span });
            }
        }
        return out;
    }
    // Compound assignment (`+=`, `-=`, ...): exactly one lhs, one rhs.
    let (Some(lhs_expr), Some(rhs_expr)) = (assign.left.first(), assign.right.first()) else { return Vec::new() };
    let lvalue = lower_lvalue(builder, env, source, lhs_expr);
    let rhs = lower_expr(builder, env, source, rhs_expr);
    let current = lvalue_to_read_expr(builder, &lvalue, span);
    let combined = Expr::Binary { id: builder.alloc_expr_id(), op: map_compound_operator(assign.op), lhs: Box::new(current), rhs: Box::new(rhs), span };
    vec![Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: combined, span }]
}

fn declare_short_var(builder: &mut ModuleBuilder, env: &mut GoEnv, lhs: &go::Expression, rhs_expr: Expr, qualifier: Option<String>, span: uniflow_hir::Span) -> Stmt {
    let go::Expression::Ident(ident) = lhs else {
        let symbol = builder.add_symbol("__short_decl_target", SymbolKind::Local);
        return Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(rhs_expr), span };
    };
    if ident.name == "_" {
        let symbol = builder.add_symbol("_", SymbolKind::Local);
        return Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(rhs_expr), span };
    }
    // `:=` always (re)declares a fresh binding for taint-tracking purposes,
    // even though real Go permits mixing in an already-declared name as
    // long as at least one name in the group is new — a documented,
    // conservative simplification (equivalent to always shadowing).
    let symbol = builder.add_symbol(&ident.name, SymbolKind::Local);
    env.declare(&ident.name, symbol);
    if let Some(qualifier) = qualifier {
        env.set_value_qualifier(symbol, qualifier);
    }
    Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(rhs_expr), span }
}

fn lower_case_block(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, block: &go::CaseBlock) -> (Vec<SwitchClause>, Option<Block>) {
    let mut clauses = Vec::new();
    let mut default = None;
    for case in &block.body {
        let values = case.list.iter().map(|value| lower_expr(builder, env, source, value)).collect::<Vec<_>>();
        // Go's `switch` implicitly breaks between clauses; an explicit
        // trailing `fallthrough` statement is what makes control continue
        // into the next clause (the opposite default from JS/C). Detect and
        // strip that trailing marker rather than lowering it as a generic
        // `Stmt::Break` in this position, which would be actively wrong.
        let has_fallthrough = matches!(case.body.last(), Some(go::Statement::Branch(branch)) if matches!(branch.key, Keyword::FallThrough));
        env.push_block();
        let body_len = case.body.len();
        let mut stmts = Vec::new();
        for (index, stmt) in case.body.iter().enumerate() {
            if has_fallthrough && index + 1 == body_len {
                continue;
            }
            stmts.extend(lower_stmt(builder, env, source, stmt));
        }
        env.pop_block();
        let case_span = span_range(builder, source, case.pos.0, case.pos.1);
        let body = Block { id: builder.alloc_block_id(), stmts, span: case_span };
        if case.list.is_empty() {
            default = Some(body);
        } else {
            clauses.push(SwitchClause { values, body, fallthrough: has_fallthrough, span: case_span });
        }
    }
    (clauses, default)
}

/// The scrutinee half of a `switch x := v.(type) { ... }` — declares `x`
/// (bound, for the whole switch, to `v`'s own value; the per-case narrowed
/// type isn't modeled) and returns `v` itself as the switch's scrutinee.
fn lower_type_switch_tag(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, tag_stmt: &go::Statement) -> Expr {
    match tag_stmt {
        go::Statement::Assign(assign) => {
            if let (Some(lhs), Some(go::Expression::TypeAssert(assertion))) = (assign.left.first(), assign.right.first()) {
                let value = lower_expr(builder, env, source, &assertion.left);
                if let go::Expression::Ident(ident) = lhs {
                    if ident.name != "_" {
                        let symbol = builder.add_symbol(&ident.name, SymbolKind::Local);
                        env.declare(&ident.name, symbol);
                    }
                }
                return value;
            }
            Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Null, span: span_at(builder, source, assign.pos) }
        }
        go::Statement::Expr(expr_stmt) => match &expr_stmt.expr {
            go::Expression::TypeAssert(assertion) => lower_expr(builder, env, source, &assertion.left),
            other => lower_expr(builder, env, source, other),
        },
        other => {
            let _ = lower_stmt(builder, env, source, other);
            Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Null, span: uniflow_hir::Span::default() }
        }
    }
}

pub(crate) fn lower_stmt(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, stmt: &go::Statement) -> Vec<Stmt> {
    match stmt {
        go::Statement::Block(block) => lower_block(builder, env, source, block).stmts,
        go::Statement::Empty(_) => vec![],
        go::Statement::Expr(expr_stmt) => {
            let span = span_at(builder, source, expr_stmt.expr.pos());
            let expr = lower_expr(builder, env, source, &expr_stmt.expr);
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr, span }]
        }
        // `go f(...)`/`defer f(...)`: modeled as an ordinary call expression
        // statement — this drops the concurrent/deferred-timing semantics
        // but keeps the call's arguments (and any taint they carry) visible
        // to the engine, consistent with this codebase's "good enough"
        // static-taint philosophy elsewhere.
        go::Statement::Go(go_stmt) => {
            let span = span_range(builder, source, go_stmt.call.pos.0, go_stmt.call.pos.1);
            let expr = crate::frontend::expr::lower_call(builder, env, source, &go_stmt.call);
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr, span }]
        }
        go::Statement::Defer(defer_stmt) => {
            let span = span_range(builder, source, defer_stmt.call.pos.0, defer_stmt.call.pos.1);
            let expr = crate::frontend::expr::lower_call(builder, env, source, &defer_stmt.call);
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr, span }]
        }
        // `ch <- value`: no channel modeling; visiting the sent value keeps
        // it reachable for taint purposes.
        go::Statement::Send(send_stmt) => {
            let span = span_at(builder, source, send_stmt.pos);
            let expr = lower_expr(builder, env, source, &send_stmt.value);
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr, span }]
        }
        go::Statement::IncDec(inc_dec) => {
            let span = span_at(builder, source, inc_dec.pos);
            let lvalue = lower_lvalue(builder, env, source, &inc_dec.expr);
            let current = lvalue_to_read_expr(builder, &lvalue, span);
            let one = Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Int(1), span };
            let op = if matches!(inc_dec.op, Operator::Inc) { BinaryOp::Add } else { BinaryOp::Sub };
            let combined = Expr::Binary { id: builder.alloc_expr_id(), op, lhs: Box::new(current), rhs: Box::new(one), span };
            vec![Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: combined, span }]
        }
        go::Statement::Assign(assign) => lower_assign_stmt(builder, env, source, assign),
        // Labels have no HIR-level representation; the labeled statement
        // itself still lowers normally.
        go::Statement::Label(labeled) => lower_stmt(builder, env, source, &labeled.stmt),
        go::Statement::Return(ret) => {
            let span = span_at(builder, source, ret.pos);
            let value = match ret.ret.len() {
                0 => None,
                1 => Some(lower_expr(builder, env, source, &ret.ret[0])),
                _ => {
                    let elements = ret.ret.iter().map(|value| lower_expr(builder, env, source, value)).collect();
                    Some(Expr::Collection { id: builder.alloc_expr_id(), container: uniflow_hir::CollectionKind::Tuple, elements, span })
                }
            };
            vec![Stmt::Return { id: builder.alloc_stmt_id(), value, span }]
        }
        go::Statement::Branch(branch) => {
            let span = span_at(builder, source, branch.pos);
            let label = branch.ident.as_ref().map(|ident| ident.name.clone());
            match branch.key {
                Keyword::Break => vec![Stmt::Break { id: builder.alloc_stmt_id(), label, span }],
                Keyword::Continue => vec![Stmt::Continue { id: builder.alloc_stmt_id(), label, span }],
                // `goto`/`fallthrough` outside a case clause's tail position
                // (the only place a real `fallthrough` can legally appear —
                // see `lower_case_block`, which strips it there instead):
                // no HIR equivalent exists, so this is approximated as a
                // `Break`, a documented, best-effort stand-in.
                _ => vec![Stmt::Break { id: builder.alloc_stmt_id(), label, span }],
            }
        }
        go::Statement::If(if_stmt) => {
            env.push_block();
            let mut out = Vec::new();
            if let Some(init) = &if_stmt.init {
                out.extend(lower_stmt(builder, env, source, init));
            }
            let cond = lower_expr(builder, env, source, &if_stmt.cond);
            let then_block = lower_block(builder, env, source, &if_stmt.body);
            let else_block = if_stmt.else_.as_ref().map(|else_stmt| single_stmt_block(builder, env, source, else_stmt));
            let span = span_at(builder, source, if_stmt.pos);
            out.push(Stmt::If { id: builder.alloc_stmt_id(), cond, then_block, else_block, span });
            env.pop_block();
            out
        }
        go::Statement::For(for_stmt) => {
            env.push_block();
            let mut init_stmts = Vec::new();
            if let Some(init) = &for_stmt.init {
                init_stmts.extend(lower_stmt(builder, env, source, init));
            }
            let init_span = init_stmts.first().map(stmt_span).unwrap_or_default();
            let init = Block { id: builder.alloc_block_id(), stmts: init_stmts, span: init_span };
            let cond = for_stmt.cond.as_ref().and_then(|cond_stmt| match &**cond_stmt {
                go::Statement::Expr(expr_stmt) => Some(lower_expr(builder, env, source, &expr_stmt.expr)),
                other => {
                    let _ = lower_stmt(builder, env, source, other);
                    None
                }
            });
            let mut update_stmts = Vec::new();
            if let Some(post) = &for_stmt.post {
                update_stmts.extend(lower_stmt(builder, env, source, post));
            }
            let update_span = update_stmts.first().map(stmt_span).unwrap_or(init_span);
            let update = Block { id: builder.alloc_block_id(), stmts: update_stmts, span: update_span };
            let body = lower_block(builder, env, source, &for_stmt.body);
            env.pop_block();
            vec![Stmt::For { id: builder.alloc_stmt_id(), init_is_scoped: true, init, cond, update, body, span: span_at(builder, source, for_stmt.pos) }]
        }
        go::Statement::Range(range_stmt) => {
            env.push_block();
            let define = matches!(range_stmt.op, Some((_, Operator::Define)));
            // HIR's `ForEach` tracks only one bound symbol per iteration;
            // Go's `for k, v := range m` binds two. `value` is preferred
            // (the element itself is usually the taint-relevant half); `key`
            // is still declared/resolved so the body can reference it, it
            // just isn't the binding taint is propagated through from the
            // iterable.
            let key_symbol = range_binding_symbol(builder, env, &range_stmt.key, define);
            let value_symbol = range_binding_symbol(builder, env, &range_stmt.value, define);
            let item_symbol = value_symbol.or(key_symbol).unwrap_or_else(|| builder.add_symbol("_", SymbolKind::Local));
            let iterable = lower_expr(builder, env, source, &range_stmt.expr);
            let body = lower_block(builder, env, source, &range_stmt.body);
            env.pop_block();
            vec![Stmt::ForEach { id: builder.alloc_stmt_id(), item_symbol, iterable, body, span: span_range(builder, source, range_stmt.pos.0, range_stmt.pos.1) }]
        }
        go::Statement::Switch(switch_stmt) => {
            env.push_block();
            let mut out = Vec::new();
            if let Some(init) = &switch_stmt.init {
                out.extend(lower_stmt(builder, env, source, init));
            }
            let span = span_at(builder, source, switch_stmt.pos);
            // A tag-less `switch { case cond: ... }` is exactly equivalent
            // to `switch true { case cond: ... }` in real Go semantics, so
            // this is not an approximation.
            let scrutinee = match &switch_stmt.tag {
                Some(tag) => lower_expr(builder, env, source, tag),
                None => Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Bool(true), span },
            };
            let (clauses, default) = lower_case_block(builder, env, source, &switch_stmt.block);
            out.push(Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span });
            env.pop_block();
            out
        }
        go::Statement::TypeSwitch(type_switch) => {
            env.push_block();
            let mut out = Vec::new();
            if let Some(init) = &type_switch.init {
                out.extend(lower_stmt(builder, env, source, init));
            }
            let span = span_at(builder, source, type_switch.pos);
            let scrutinee = type_switch.tag.as_ref().map(|tag_stmt| lower_type_switch_tag(builder, env, source, tag_stmt)).unwrap_or(Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Null, span });
            let (clauses, default) = lower_case_block(builder, env, source, &type_switch.block);
            out.push(Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span });
            env.pop_block();
            out
        }
        go::Statement::Select(select_stmt) => {
            let span = span_at(builder, source, select_stmt.pos);
            let scrutinee = Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Null, span };
            let mut clauses = Vec::new();
            let mut default = None;
            for comm in &select_stmt.body.body {
                env.push_block();
                let mut stmts = Vec::new();
                if let Some(comm_stmt) = &comm.comm {
                    stmts.extend(lower_stmt(builder, env, source, comm_stmt));
                }
                for inner in comm.body.iter() {
                    stmts.extend(lower_stmt(builder, env, source, inner));
                }
                env.pop_block();
                let comm_span = span_range(builder, source, comm.pos.0, comm.pos.1);
                let body = Block { id: builder.alloc_block_id(), stmts, span: comm_span };
                if matches!(comm.tok, Keyword::Default) {
                    default = Some(body);
                } else {
                    clauses.push(SwitchClause { values: Vec::new(), body, fallthrough: false, span: comm_span });
                }
            }
            vec![Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span }]
        }
        go::Statement::Declaration(decl_stmt) => match decl_stmt {
            go::DeclStmt::Variable(decl) => decl.specs.iter().flat_map(|spec| lower_local_binding_group(builder, env, source, &spec.name, &spec.typ, &spec.values)).collect(),
            go::DeclStmt::Const(decl) => decl.specs.iter().flat_map(|spec| lower_local_binding_group(builder, env, source, &spec.name, &spec.typ, &spec.values)).collect(),
            // A local type declaration has no data-flow relevance and no
            // HIR item shape at statement scope; skipped rather than
            // partially/incorrectly modeled.
            go::DeclStmt::Type(_) => vec![],
        },
    }
}
