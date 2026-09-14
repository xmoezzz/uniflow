//! Lowers `lib_ruby_parser::Node`s in statement position into
//! `uniflow_hir::Stmt`/`Block`. Gives the highest-value constructs
//! (`if`/`unless`/`case`/`case...in`/loops/`begin`/`rescue`/`ensure`/
//! destructuring assignment) real, precise treatment — as opposed to the
//! same constructs appearing as a nested sub-expression, which
//! `crate::frontend::expr` simplifies (see its module doc comment). Mirrors
//! `lang_rust::frontend::stmt`.

use lib_ruby_parser::{nodes, Node};
use uniflow_hir::{Block, CatchClause, Expr, LiteralKind, Stmt, SwitchClause, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::RubyEnv;
use crate::frontend::expr::{compound_target_lvalue, lower_expr, resolve_or_declare_local, span};

fn int_literal(builder: &mut ModuleBuilder, at: uniflow_hir::Span, value: i64) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Int(value), span: at }
}

fn str_literal(builder: &mut ModuleBuilder, at: uniflow_hir::Span, value: String) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::String(value), span: at }
}

/// A node's own statement list: `Begin`/`KwBegin`'s `statements`, or the
/// single node itself for anything else (the parser only wraps a body in
/// `Begin`/`KwBegin` once it has more than one statement).
pub(crate) fn statement_list(node: &Node) -> Vec<&Node> {
    match node {
        Node::Begin(b) => b.statements.iter().collect(),
        Node::KwBegin(b) => b.statements.iter().collect(),
        other => vec![other],
    }
}

fn empty_block(builder: &mut ModuleBuilder) -> Block {
    builder.empty_block()
}

/// Lowers an optional single body node (a `def`/`if`-branch/loop body/etc.)
/// into a `Block`, opening and closing its own lexical scope.
fn stmt_block(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: Option<&Node>) -> Block {
    env.push_block();
    let (stmts, block_span) = match node {
        None => (Vec::new(), uniflow_hir::Span::default()),
        Some(n) => {
            let stmts = statement_list(n).into_iter().flat_map(|item| lower_stmt(builder, env, source, item)).collect();
            (stmts, span(builder, source, n.expression()))
        }
    };
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: block_span }
}

/// Same as [`stmt_block`], but a trailing tail expression becomes a real
/// `Stmt::Return` so its value actually reaches the method/block's callers —
/// Ruby's implicit-last-expression-is-the-return-value convention applies to
/// every `def`/block/lambda body unconditionally (unlike Rust, which only
/// does this for a function with an explicit `-> T`), so this is the body
/// lowering path used for every `def`/`defs`/block/lambda. A tail that is
/// itself `return`/`break`/`next`/`redo`/`retry` already lowers to the right
/// `Stmt` variant through the ordinary path and is left alone.
pub(crate) fn lower_body_returning_value(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: Option<&Node>) -> Block {
    env.push_block();
    let (stmts, block_span) = match node {
        None => (Vec::new(), uniflow_hir::Span::default()),
        Some(n) => {
            let items = statement_list(n);
            let last_index = items.len().saturating_sub(1);
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                if index == last_index && !matches!(item, Node::Return(_) | Node::Break(_) | Node::Next(_) | Node::Redo(_) | Node::Retry(_)) {
                    let value = lower_expr(builder, env, source, item);
                    let value_span = value.span();
                    out.push(Stmt::Return { id: builder.alloc_stmt_id(), value: Some(value), span: value_span });
                } else {
                    out.extend(lower_stmt(builder, env, source, item));
                }
            }
            (out, span(builder, source, n.expression()))
        }
    };
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: block_span }
}

fn lower_if_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, cond: &Node, if_true: Option<&Node>, if_false: Option<&Node>, loc: &lib_ruby_parser::Loc) -> Stmt {
    let cond_expr = lower_expr(builder, env, source, cond);
    let then_block = stmt_block(builder, env, source, if_true);
    let else_block = if_false.map(|node| stmt_block(builder, env, source, Some(node)));
    Stmt::If { id: builder.alloc_stmt_id(), cond: cond_expr, then_block, else_block, span: span(builder, source, loc) }
}

fn lower_while_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, cond: &Node, body: Option<&Node>, negate: bool, loc: &lib_ruby_parser::Loc) -> Stmt {
    let mut cond_expr = lower_expr(builder, env, source, cond);
    if negate {
        let at = cond_expr.span();
        cond_expr = Expr::Unary { id: builder.alloc_expr_id(), op: uniflow_hir::UnaryOp::Not, expr: Box::new(cond_expr), span: at };
    }
    let body_block = stmt_block(builder, env, source, body);
    Stmt::While { id: builder.alloc_stmt_id(), cond: cond_expr, body: body_block, span: span(builder, source, loc) }
}

fn lower_do_while_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, body: &Node, cond: &Node, negate: bool, loc: &lib_ruby_parser::Loc) -> Stmt {
    let body_block = stmt_block(builder, env, source, Some(body));
    let mut cond_expr = lower_expr(builder, env, source, cond);
    if negate {
        let at = cond_expr.span();
        cond_expr = Expr::Unary { id: builder.alloc_expr_id(), op: uniflow_hir::UnaryOp::Not, expr: Box::new(cond_expr), span: at };
    }
    Stmt::DoWhile { id: builder.alloc_stmt_id(), body: body_block, cond: cond_expr, span: span(builder, source, loc) }
}

fn lower_for_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, f: &nodes::For) -> Stmt {
    let iterable = lower_expr(builder, env, source, &f.iteratee);
    env.push_block();
    let item_symbol = match f.iterator.as_ref() {
        Node::Lvasgn(l) => resolve_or_declare_local(builder, env, &l.name),
        _ => builder.add_symbol("$item", SymbolKind::Local),
    };
    let body = stmt_block(builder, env, source, f.body.as_deref());
    env.pop_block();
    Stmt::ForEach { id: builder.alloc_stmt_id(), item_symbol, iterable, body, span: span(builder, source, &f.expression_l) }
}

fn lower_pattern_value(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: &Node) -> Expr {
    match node {
        Node::Splat(sp) => match &sp.value {
            Some(v) => lower_expr(builder, env, source, v),
            None => Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Null, span: span(builder, source, &sp.expression_l) },
        },
        other => lower_expr(builder, env, source, other),
    }
}

fn lower_case_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, c: &nodes::Case) -> Stmt {
    let scrutinee = match &c.expr {
        Some(e) => lower_expr(builder, env, source, e),
        None => Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Null, span: span(builder, source, &c.expression_l) },
    };
    let mut clauses = Vec::new();
    for when in &c.when_bodies {
        if let Node::When(w) = when {
            let values = w.patterns.iter().map(|p| lower_pattern_value(builder, env, source, p)).collect();
            let body = stmt_block(builder, env, source, w.body.as_deref());
            clauses.push(SwitchClause { values, body, fallthrough: false, span: span(builder, source, &w.expression_l) });
        }
    }
    let default = c.else_body.as_deref().map(|node| stmt_block(builder, env, source, Some(node)));
    Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span: span(builder, source, &c.expression_l) }
}

/// Declares one `case ... in PATTERN` destructuring leaf, projecting it off
/// `source_expr` so the value — and any taint it carries — keeps flowing,
/// mirroring `lang_rust::frontend::stmt::lower_pattern_binding`. Refutable-
/// only pattern forms (a literal, a bare `Const`, `Pin`, `MatchNilPattern`)
/// bind nothing on their own — documented no-op, same as Rust's treatment of
/// `Pat::Lit`/`Pat::Path`. The pattern's own *matching* test (does the value
/// actually have this shape) is not modeled at all; every `in` arm's body
/// is visited unconditionally, the same "visit and merge every branch"
/// simplification `crate::frontend::expr::lower_case_value` and Rust's
/// `lower_match_value` use for `match`/`case`/`when` used as a value.
pub(crate) fn lower_pattern_binding(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, pattern: &Node, source_expr: &Expr, out: &mut Vec<Stmt>) {
    match pattern {
        Node::MatchVar(mv) => {
            let symbol = builder.add_symbol(&mv.name, SymbolKind::Local);
            env.declare(&mv.name, symbol);
            let at = span(builder, source, &mv.expression_l);
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(source_expr.clone()), span: at });
        }
        Node::MatchAs(ma) => {
            lower_pattern_binding(builder, env, source, &ma.value, source_expr, out);
            lower_pattern_binding(builder, env, source, &ma.as_, source_expr, out);
        }
        Node::MatchAlt(alt) => {
            lower_pattern_binding(builder, env, source, &alt.lhs, source_expr, out);
            lower_pattern_binding(builder, env, source, &alt.rhs, source_expr, out);
        }
        Node::ArrayPattern(ap) => project_indexed_elements(builder, env, source, &ap.elements, source_expr, out),
        Node::ArrayPatternWithTail(ap) => project_indexed_elements(builder, env, source, &ap.elements, source_expr, out),
        Node::FindPattern(fp) => project_indexed_elements(builder, env, source, &fp.elements, source_expr, out),
        Node::HashPattern(hp) => {
            for elem in &hp.elements {
                if let Node::Pair(p) = elem {
                    let key_text = match p.key.as_ref() {
                        Node::Sym(s) => s.name.to_string_lossy(),
                        _ => continue,
                    };
                    let field_span = source_expr.span();
                    let key_expr = str_literal(builder, field_span, key_text);
                    let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(key_expr), span: field_span };
                    lower_pattern_binding(builder, env, source, &p.value, &projected, out);
                }
            }
        }
        Node::ConstPattern(cp) => lower_pattern_binding(builder, env, source, &cp.pattern, source_expr, out),
        // `Pin`/`MatchNilPattern`/`MatchRest` (an unnamed `*`/`**`) and any
        // literal/constant used as a refutable-only test bind nothing.
        _ => {}
    }
}

fn project_indexed_elements(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, elements: &[Node], source_expr: &Expr, out: &mut Vec<Stmt>) {
    for (index, elem) in elements.iter().enumerate() {
        if matches!(elem, Node::MatchRest(_)) {
            continue;
        }
        let at = source_expr.span();
        let idx_expr = int_literal(builder, at, index as i64);
        let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(idx_expr), span: at };
        lower_pattern_binding(builder, env, source, elem, &projected, out);
    }
}

fn lower_case_match_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, c: &nodes::CaseMatch) -> Stmt {
    let scrutinee = lower_expr(builder, env, source, &c.expr);
    let mut clauses = Vec::new();
    for in_body in &c.in_bodies {
        if let Node::InPattern(ip) = in_body {
            env.push_block();
            let mut arm_stmts = Vec::new();
            lower_pattern_binding(builder, env, source, &ip.pattern, &scrutinee, &mut arm_stmts);
            if let Some(guard) = &ip.guard {
                let guard_cond = match guard.as_ref() {
                    Node::IfGuard(g) => Some(g.cond.as_ref()),
                    Node::UnlessGuard(g) => Some(g.cond.as_ref()),
                    _ => None,
                };
                if let Some(cond_node) = guard_cond {
                    let guard_expr = lower_expr(builder, env, source, cond_node);
                    let guard_span = guard_expr.span();
                    arm_stmts.push(Stmt::Expr { id: builder.alloc_stmt_id(), expr: guard_expr, span: guard_span });
                }
            }
            if let Some(body) = ip.body.as_deref() {
                arm_stmts.extend(statement_list(body).into_iter().flat_map(|item| lower_stmt(builder, env, source, item)));
            }
            env.pop_block();
            let arm_span = span(builder, source, &ip.expression_l);
            clauses.push(SwitchClause { values: Vec::new(), body: Block { id: builder.alloc_block_id(), stmts: arm_stmts, span: arm_span }, fallthrough: false, span: arm_span });
        }
    }
    let default = c.else_body.as_deref().map(|node| stmt_block(builder, env, source, Some(node)));
    Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span: span(builder, source, &c.expression_l) }
}

fn first_exception_type(builder: &mut ModuleBuilder, env: &RubyEnv, exc_list: Option<&Node>) -> Option<uniflow_hir::TypeId> {
    let list = exc_list?;
    let first = match list {
        Node::Array(a) => a.elements.first(),
        other => Some(other),
    }?;
    let name = crate::frontend::expr::node_qualifier(env, first)?;
    Some(builder.ensure_type(&name))
}

/// `begin ... rescue ... [else ...] ... end`; an enclosing `ensure` (parsed
/// as a separate `Ensure` node wrapping this one — see the exploratory
/// dump in this crate's development notes) is handled by
/// [`lower_try_stmt`]'s `Node::Ensure` arm, which recurses in here for the
/// `rescue` part and supplies its own `finally_block`. The `else` branch
/// (only reachable when no exception was raised) is appended to the end of
/// the ordinary try body — HIR's `Stmt::Try` has no dedicated "else" slot —
/// a documented, conservative approximation: its statements are still
/// visited, just not modeled as conditionally skipped.
fn rescue_parts(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, r: &nodes::Rescue) -> (Block, Vec<CatchClause>) {
    let mut try_block = stmt_block(builder, env, source, r.body.as_deref());
    let mut catches = Vec::new();
    for rescue_body in &r.rescue_bodies {
        if let Node::RescueBody(rb) = rescue_body {
            env.push_block();
            let ty = first_exception_type(builder, env, rb.exc_list.as_deref());
            let symbol = match rb.exc_var.as_deref() {
                Some(Node::Lvasgn(l)) => Some(resolve_or_declare_local(builder, env, &l.name)),
                _ => None,
            };
            let body = stmt_block(builder, env, source, rb.body.as_deref());
            env.pop_block();
            catches.push(CatchClause { symbol, ty, body, span: span(builder, source, &rb.expression_l) });
        }
    }
    if let Some(else_node) = r.else_.as_deref() {
        try_block.stmts.extend(statement_list(else_node).into_iter().flat_map(|item| lower_stmt(builder, env, source, item)));
    }
    (try_block, catches)
}

fn lower_try_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: &Node) -> Stmt {
    match node {
        Node::Ensure(e) => {
            let (try_block, catches) = match e.body.as_deref() {
                Some(Node::Rescue(r)) => rescue_parts(builder, env, source, r),
                Some(other) => (stmt_block(builder, env, source, Some(other)), Vec::new()),
                None => (empty_block(builder), Vec::new()),
            };
            let finally_block = Some(stmt_block(builder, env, source, e.ensure.as_deref()));
            Stmt::Try { id: builder.alloc_stmt_id(), try_block, catches, finally_block, span: span(builder, source, &e.expression_l) }
        }
        Node::Rescue(r) => {
            let (try_block, catches) = rescue_parts(builder, env, source, r);
            Stmt::Try { id: builder.alloc_stmt_id(), try_block, catches, finally_block: None, span: span(builder, source, &r.expression_l) }
        }
        _ => unreachable!("lower_try_stmt only called for Rescue/Ensure"),
    }
}

fn lower_masgn_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, m: &nodes::Masgn) -> Vec<Stmt> {
    let rhs = lower_expr(builder, env, source, &m.rhs);
    let mut out = Vec::new();
    match m.lhs.as_ref() {
        Node::Mlhs(mlhs) => assign_masgn_targets(builder, env, source, &mlhs.items, &rhs, &mut out),
        other => assign_masgn_targets(builder, env, source, std::slice::from_ref(other), &rhs, &mut out),
    }
    out
}

/// Real per-target projection for a destructuring multiple-assignment
/// (`a, b = 1, 2`, `a, (b, c) = 1, [2, 3]`) — mirrors
/// `lang_rust::frontend::stmt::lower_assign_target`, targeting each item via
/// [`compound_target_lvalue`] since Ruby's `Masgn` leaves (`Lvasgn`/
/// `Ivasgn`/... with `value: None`) are the same node shapes `OpAsgn.recv`
/// uses. A splat target (`*rest`) is skipped — a documented scope cut,
/// since it would need to capture a variable-length slice rather than one
/// projected element.
fn assign_masgn_targets(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, items: &[Node], source_expr: &Expr, out: &mut Vec<Stmt>) {
    for (index, item) in items.iter().enumerate() {
        if matches!(item, Node::Splat(_)) {
            continue;
        }
        let at = source_expr.span();
        let idx_expr = int_literal(builder, at, index as i64);
        let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(idx_expr), span: at };
        match item {
            Node::Mlhs(nested) => assign_masgn_targets(builder, env, source, &nested.items, &projected, out),
            _ => {
                let lvalue = compound_target_lvalue(builder, env, source, item);
                out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: projected, span: at });
            }
        }
    }
}

/// Lowers a node used as a *statement*, giving the highest-value constructs
/// real, precise treatment — as opposed to the same constructs appearing as
/// a nested sub-expression, which `crate::frontend::expr` simplifies.
pub(crate) fn lower_stmt(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: &Node) -> Vec<Stmt> {
    match node {
        Node::Begin(b) => b.statements.iter().flat_map(|item| lower_stmt(builder, env, source, item)).collect(),
        Node::KwBegin(b) => b.statements.iter().flat_map(|item| lower_stmt(builder, env, source, item)).collect(),
        Node::If(i) => vec![lower_if_stmt(builder, env, source, &i.cond, i.if_true.as_deref(), i.if_false.as_deref(), &i.expression_l)],
        Node::IfMod(i) => vec![lower_if_stmt(builder, env, source, &i.cond, i.if_true.as_deref(), i.if_false.as_deref(), &i.expression_l)],
        Node::While(w) => vec![lower_while_stmt(builder, env, source, &w.cond, w.body.as_deref(), false, &w.expression_l)],
        Node::Until(u) => vec![lower_while_stmt(builder, env, source, &u.cond, u.body.as_deref(), true, &u.expression_l)],
        Node::WhilePost(w) => vec![lower_do_while_stmt(builder, env, source, &w.body, &w.cond, false, &w.expression_l)],
        Node::UntilPost(u) => vec![lower_do_while_stmt(builder, env, source, &u.body, &u.cond, true, &u.expression_l)],
        // `loop { ... }` has no dedicated node — it parses as an ordinary
        // `Block`-wrapped `Send` (see `crate::frontend::expr::lower_block_like`),
        // so it is not handled here.
        Node::For(f) => vec![lower_for_stmt(builder, env, source, f)],
        Node::Case(c) => vec![lower_case_stmt(builder, env, source, c)],
        Node::CaseMatch(c) => vec![lower_case_match_stmt(builder, env, source, c)],
        Node::Rescue(_) | Node::Ensure(_) => vec![lower_try_stmt(builder, env, source, node)],
        Node::Return(r) => {
            let values: Vec<Expr> = r.args.iter().map(|a| lower_expr(builder, env, source, a)).collect();
            let value = match values.len() {
                0 => None,
                1 => values.into_iter().next(),
                _ => Some(Expr::Collection { id: builder.alloc_expr_id(), container: uniflow_hir::CollectionKind::Array, elements: values, span: span(builder, source, &r.expression_l) }),
            };
            vec![Stmt::Return { id: builder.alloc_stmt_id(), value, span: span(builder, source, &r.expression_l) }]
        }
        Node::Break(b) => {
            let mut out: Vec<Stmt> = b.args.iter().map(|a| {
                let expr = lower_expr(builder, env, source, a);
                let at = expr.span();
                Stmt::Expr { id: builder.alloc_stmt_id(), expr, span: at }
            }).collect();
            out.push(Stmt::Break { id: builder.alloc_stmt_id(), label: None, span: span(builder, source, &b.expression_l) });
            out
        }
        Node::Next(n) => {
            let mut out: Vec<Stmt> = n.args.iter().map(|a| {
                let expr = lower_expr(builder, env, source, a);
                let at = expr.span();
                Stmt::Expr { id: builder.alloc_stmt_id(), expr, span: at }
            }).collect();
            out.push(Stmt::Continue { id: builder.alloc_stmt_id(), label: None, span: span(builder, source, &n.expression_l) });
            out
        }
        // `redo`/`retry` restart the current iteration/`begin` block — no
        // dedicated HIR shape; `Continue` is the closest conservative
        // approximation (control returns to the top of the innermost loop),
        // a documented scope cut.
        Node::Redo(r) => vec![Stmt::Continue { id: builder.alloc_stmt_id(), label: None, span: span(builder, source, &r.expression_l) }],
        Node::Retry(r) => vec![Stmt::Continue { id: builder.alloc_stmt_id(), label: None, span: span(builder, source, &r.expression_l) }],
        Node::Masgn(m) => lower_masgn_stmt(builder, env, source, m),
        _ => {
            let value = lower_expr(builder, env, source, node);
            let value_span = value.span();
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr: value, span: value_span }]
        }
    }
}

