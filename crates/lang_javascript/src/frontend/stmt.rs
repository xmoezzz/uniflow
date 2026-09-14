//! Lowers `oxc_ast` statements into `uniflow_hir::Stmt`/`Block`.

use oxc_ast::ast as js;
use oxc_span::GetSpan;
use uniflow_hir::{Block, CatchClause, Expr, LiteralKind, Stmt, SwitchClause, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use uniflow_hir::LValue;

use crate::frontend::env::JsEnv;
use crate::frontend::expr::{lower_assignment_target_lvalue, lower_expr, resolve_identifier, span};
use crate::frontend::functions::lower_function_like;

fn unwrap_parens<'a, 'b>(mut expr: &'b js::Expression<'a>) -> &'b js::Expression<'a> {
    while let js::Expression::ParenthesizedExpression(inner) = expr {
        expr = &inner.expression;
    }
    expr
}

pub(crate) fn lower_function_body(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, body: &js::FunctionBody) -> Block {
    env.push_block();
    let stmts = body.statements.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: span(builder, source, body.span) }
}

pub(crate) fn lower_block(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, block: &js::BlockStatement) -> Block {
    env.push_block();
    let stmts = block.body.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
    env.pop_block();
    Block { id: builder.alloc_block_id(), stmts, span: span(builder, source, block.span) }
}

fn single_stmt_block(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, stmt: &js::Statement) -> Block {
    env.push_block();
    let stmts = lower_stmt(builder, env, source, stmt);
    env.pop_block();
    let inner_span = stmts.first().map(stmt_span).unwrap_or_default();
    Block { id: builder.alloc_block_id(), stmts, span: inner_span }
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

/// Declares one destructuring leaf: reads it off `source_expr` (a
/// `FieldRead`/`IndexRead` off the already-lowered right-hand side) so the
/// value — and any taint it carries — keeps flowing, rather than becoming
/// an un-initialized `Let`. Defaults (`{a = 1}`) are not substituted: the
/// field is always read as-is, a documented simplification.
pub(crate) fn lower_destructuring_binding(
    builder: &mut ModuleBuilder,
    env: &mut JsEnv,
    source: &str,
    pattern: &js::BindingPattern,
    source_expr: &Expr,
    declare_var: bool,
    out: &mut Vec<Stmt>,
) {
    match pattern {
        js::BindingPattern::BindingIdentifier(ident) => {
            let symbol = builder.add_symbol(ident.name.as_str(), SymbolKind::Local);
            if declare_var {
                env.declare_var(ident.name.as_str(), symbol);
            } else {
                env.declare(ident.name.as_str(), symbol);
            }
            let ident_span = span(builder, source, ident.span);
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(source_expr.clone()), span: ident_span });
        }
        js::BindingPattern::AssignmentPattern(assignment) => {
            lower_destructuring_binding(builder, env, source, &assignment.left, source_expr, declare_var, out);
        }
        js::BindingPattern::ObjectPattern(object) => {
            for property in &object.properties {
                let field = match &property.key {
                    js::PropertyKey::StaticIdentifier(ident) => ident.name.to_string(),
                    _ => continue,
                };
                let field_read = Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), field, span: source_expr.span() };
                lower_destructuring_binding(builder, env, source, &property.value, &field_read, declare_var, out);
            }
            if let Some(rest) = &object.rest {
                lower_destructuring_binding(builder, env, source, &rest.argument, source_expr, declare_var, out);
            }
        }
        js::BindingPattern::ArrayPattern(array) => {
            for (index, element) in array.elements.iter().enumerate() {
                let Some(element) = element else { continue };
                let index_expr = Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Int(index as i64), span: source_expr.span() };
                let index_read = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(index_expr), span: source_expr.span() };
                lower_destructuring_binding(builder, env, source, element, &index_read, declare_var, out);
            }
            if let Some(rest) = &array.rest {
                lower_destructuring_binding(builder, env, source, &rest.argument, source_expr, declare_var, out);
            }
        }
    }
}

/// Real per-target projection for a destructuring *assignment*
/// (`[a, b] = arr;`, `({a} = obj);`) used as a statement — mirrors
/// [`lower_destructuring_binding`]'s structure but targets *existing*
/// bindings (via [`resolve_identifier`]/[`lower_assignment_target_lvalue`])
/// with `Stmt::Assign`, since oxc models an assignment target with an
/// entirely separate `AssignmentTarget` type family from `BindingPattern`.
/// Without this, `({a, b} = obj);` used as a bare statement would silently
/// assign to a throwaway discard local instead of the real `a`/`b`.
fn lower_destructuring_assignment(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, target: &js::AssignmentTarget, source_expr: &Expr, out: &mut Vec<Stmt>) {
    match target {
        js::AssignmentTarget::ArrayAssignmentTarget(array) => {
            for (index, element) in array.elements.iter().enumerate() {
                let Some(element) = element else { continue };
                let index_expr = Expr::Literal { id: builder.alloc_expr_id(), kind: LiteralKind::Int(index as i64), span: source_expr.span() };
                let index_read = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(index_expr), span: source_expr.span() };
                lower_destructuring_assignment_maybe_default(builder, env, source, element, &index_read, out);
            }
            if let Some(rest) = &array.rest {
                lower_destructuring_assignment(builder, env, source, &rest.target, source_expr, out);
            }
        }
        js::AssignmentTarget::ObjectAssignmentTarget(object) => {
            for property in &object.properties {
                match property {
                    js::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(identifier_property) => {
                        let field_read =
                            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), field: identifier_property.binding.name.to_string(), span: source_expr.span() };
                        let symbol = resolve_identifier(builder, env, identifier_property.binding.name.as_str());
                        out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: LValue::Var(symbol), rhs: field_read, span: source_expr.span() });
                    }
                    js::AssignmentTargetProperty::AssignmentTargetPropertyProperty(property_property) => {
                        let field = match &property_property.name {
                            js::PropertyKey::StaticIdentifier(ident) => ident.name.to_string(),
                            _ => continue,
                        };
                        let field_read = Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), field, span: source_expr.span() };
                        lower_destructuring_assignment_maybe_default(builder, env, source, &property_property.binding, &field_read, out);
                    }
                }
            }
            if let Some(rest) = &object.rest {
                lower_destructuring_assignment(builder, env, source, &rest.target, source_expr, out);
            }
        }
        leaf => {
            let lvalue = lower_assignment_target_lvalue(builder, env, source, leaf);
            out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: lvalue, rhs: source_expr.clone(), span: source_expr.span() });
        }
    }
}

fn lower_destructuring_assignment_maybe_default(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, target: &js::AssignmentTargetMaybeDefault, source_expr: &Expr, out: &mut Vec<Stmt>) {
    match target {
        js::AssignmentTargetMaybeDefault::AssignmentTargetWithDefault(with_default) => {
            // A default (`{a = 1}`) is not substituted here — same
            // documented simplification as `lower_destructuring_binding`.
            lower_destructuring_assignment(builder, env, source, &with_default.binding, source_expr, out);
        }
        js::AssignmentTargetMaybeDefault::AssignmentTargetIdentifier(ident) => {
            let symbol = resolve_identifier(builder, env, ident.name.as_str());
            out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: LValue::Var(symbol), rhs: source_expr.clone(), span: source_expr.span() });
        }
        js::AssignmentTargetMaybeDefault::StaticMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            out.push(Stmt::Assign {
                id: builder.alloc_stmt_id(),
                lhs: LValue::Field { base: Box::new(base), field: member.property.name.to_string() },
                rhs: source_expr.clone(),
                span: source_expr.span(),
            });
        }
        js::AssignmentTargetMaybeDefault::ComputedMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            let index = lower_expr(builder, env, source, &member.expression);
            out.push(Stmt::Assign { id: builder.alloc_stmt_id(), lhs: LValue::Index { base: Box::new(base), index: Box::new(index) }, rhs: source_expr.clone(), span: source_expr.span() });
        }
        js::AssignmentTargetMaybeDefault::PrivateFieldExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            out.push(Stmt::Assign {
                id: builder.alloc_stmt_id(),
                lhs: LValue::Field { base: Box::new(base), field: format!("#{}", member.field.name) },
                rhs: source_expr.clone(),
                span: source_expr.span(),
            });
        }
        js::AssignmentTargetMaybeDefault::ArrayAssignmentTarget(_) | js::AssignmentTargetMaybeDefault::ObjectAssignmentTarget(_) => {
            // Nested destructuring inside a destructuring assignment
            // (`[[a, b]] = arr;`) is rare enough, and re-deriving an
            // `AssignmentTarget` from this flattened variant without an
            // arena-safe conversion is not worth the risk — the value is
            // still visible (as `source_expr`) even though its nested
            // sub-targets aren't individually projected here.
            let _ = source_expr;
        }
        // TS type-assertion wrappers around a destructuring leaf
        // (`([a as Foo] = arr)`) are rare enough in practice that
        // re-deriving a real target through them isn't worth the risk;
        // the value is still visible via `source_expr` even without an
        // individual projection here.
        js::AssignmentTargetMaybeDefault::TSAsExpression(_)
        | js::AssignmentTargetMaybeDefault::TSSatisfiesExpression(_)
        | js::AssignmentTargetMaybeDefault::TSNonNullExpression(_)
        | js::AssignmentTargetMaybeDefault::TSTypeAssertion(_) => {
            let _ = source_expr;
        }
    }
}

pub(crate) fn lower_variable_declaration(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, decl: &js::VariableDeclaration, out: &mut Vec<Stmt>) {
    let declare_var = decl.kind.is_var();
    for declarator in &decl.declarations {
        // Computed from the *raw* initializer before lowering consumes it —
        // `expression_qualifier` walks `oxc_ast` nodes, not the already-
        // lowered `Expr`.
        let qualifier = declarator.init.as_ref().and_then(|init| crate::frontend::expr::expression_qualifier(env, init));
        let init = declarator.init.as_ref().map(|init| lower_expr(builder, env, source, init));
        match &declarator.id {
            js::BindingPattern::BindingIdentifier(ident) => {
                let symbol = builder.add_symbol(ident.name.as_str(), SymbolKind::Local);
                if declare_var {
                    env.declare_var(ident.name.as_str(), symbol);
                } else {
                    env.declare(ident.name.as_str(), symbol);
                }
                // A local bound directly to a qualified value
                // (`const view = angular.element("#x")`) propagates that
                // qualifier so further chaining off `view` resolves the
                // same way chaining directly off `angular.element` already
                // does — see `expr::expression_qualifier`.
                if let Some(qualifier) = qualifier {
                    env.set_value_qualifier(symbol, qualifier);
                }
                out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init, span: span(builder, source, ident.span) });
            }
            pattern => {
                let Some(init) = init else { continue };
                lower_destructuring_binding(builder, env, source, pattern, &init, declare_var, out);
            }
        }
    }
}

fn for_statement_left_symbol(builder: &mut ModuleBuilder, env: &mut JsEnv, _source: &str, left: &js::ForStatementLeft) -> uniflow_hir::SymbolId {
    match left {
        js::ForStatementLeft::VariableDeclaration(decl) => {
            let declare_var = decl.kind.is_var();
            match decl.declarations.first().map(|d| &d.id) {
                Some(js::BindingPattern::BindingIdentifier(ident)) => {
                    let symbol = builder.add_symbol(ident.name.as_str(), SymbolKind::Local);
                    if declare_var {
                        env.declare_var(ident.name.as_str(), symbol);
                    } else {
                        env.declare(ident.name.as_str(), symbol);
                    }
                    symbol
                }
                _ => builder.add_symbol("__destructure_item", SymbolKind::Local),
            }
        }
        js::ForStatementLeft::AssignmentTargetIdentifier(ident) => resolve_identifier(builder, env, ident.name.as_str()),
        _ => builder.add_symbol("__for_target", SymbolKind::Local),
    }
}

fn lower_switch_clause(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, case: &js::SwitchCase) -> (Option<Expr>, SwitchClause) {
    let test = case.test.as_ref().map(|test| lower_expr(builder, env, source, test));
    env.push_block();
    let stmts: Vec<Stmt> = case.consequent.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
    env.pop_block();
    let fallthrough = !matches!(stmts.last(), Some(Stmt::Break { label: None, .. }));
    let case_span = span(builder, source, case.span);
    let stmts = if fallthrough { stmts } else { stmts[..stmts.len() - 1].to_vec() };
    (test.clone(), SwitchClause { values: test.into_iter().collect(), body: Block { id: builder.alloc_block_id(), stmts, span: case_span }, fallthrough, span: case_span })
}

pub(crate) fn lower_stmt(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, stmt: &js::Statement) -> Vec<Stmt> {
    match stmt {
        js::Statement::BlockStatement(block) => lower_block(builder, env, source, block).stmts,
        js::Statement::BreakStatement(brk) => {
            vec![Stmt::Break { id: builder.alloc_stmt_id(), label: brk.label.as_ref().map(|l| l.name.to_string()), span: span(builder, source, brk.span) }]
        }
        js::Statement::ContinueStatement(cont) => {
            vec![Stmt::Continue { id: builder.alloc_stmt_id(), label: cont.label.as_ref().map(|l| l.name.to_string()), span: span(builder, source, cont.span) }]
        }
        js::Statement::DebuggerStatement(_) | js::Statement::EmptyStatement(_) => vec![],
        js::Statement::DoWhileStatement(do_while) => {
            let body = single_stmt_block(builder, env, source, &do_while.body);
            let cond = lower_expr(builder, env, source, &do_while.test);
            vec![Stmt::DoWhile { id: builder.alloc_stmt_id(), body, cond, span: span(builder, source, do_while.span) }]
        }
        js::Statement::ExpressionStatement(expr_stmt) => {
            // A destructuring assignment (`[a, b] = arr;`, `({a} = obj);`)
            // used as a bare statement gets real per-target projection here;
            // routed through `lower_expr` it would only produce a single
            // `Expr::Assign` to a throwaway discard local (see
            // `lower_assignment_target_lvalue`), since oxc's `AssignmentTarget`
            // has no single addressable location for a destructuring pattern.
            // An object-pattern assignment (`({a} = obj);`) is always wrapped
            // in a `ParenthesizedExpression` in source (needed to disambiguate
            // the statement from a block whose body starts with `{`), so that
            // wrapper must be unwrapped before this shape is recognizable.
            if let js::Expression::AssignmentExpression(assign) = unwrap_parens(&expr_stmt.expression) {
                if assign.operator.is_assign() && matches!(assign.left, js::AssignmentTarget::ArrayAssignmentTarget(_) | js::AssignmentTarget::ObjectAssignmentTarget(_)) {
                    let rhs = lower_expr(builder, env, source, &assign.right);
                    let mut out = Vec::new();
                    lower_destructuring_assignment(builder, env, source, &assign.left, &rhs, &mut out);
                    return out;
                }
            }
            let expr = lower_expr(builder, env, source, &expr_stmt.expression);
            vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr, span: span(builder, source, expr_stmt.span) }]
        }
        js::Statement::ForInStatement(for_in) => {
            let item_symbol = for_statement_left_symbol(builder, env, source, &for_in.left);
            let iterable = lower_expr(builder, env, source, &for_in.right);
            let body = single_stmt_block(builder, env, source, &for_in.body);
            vec![Stmt::ForEach { id: builder.alloc_stmt_id(), item_symbol, iterable, body, span: span(builder, source, for_in.span) }]
        }
        js::Statement::ForOfStatement(for_of) => {
            let item_symbol = for_statement_left_symbol(builder, env, source, &for_of.left);
            let iterable = lower_expr(builder, env, source, &for_of.right);
            let body = single_stmt_block(builder, env, source, &for_of.body);
            vec![Stmt::ForEach { id: builder.alloc_stmt_id(), item_symbol, iterable, body, span: span(builder, source, for_of.span) }]
        }
        js::Statement::ForStatement(for_stmt) => {
            env.push_block();
            let mut init_stmts = Vec::new();
            let init_is_scoped = match &for_stmt.init {
                Some(js::ForStatementInit::VariableDeclaration(decl)) => {
                    lower_variable_declaration(builder, env, source, decl, &mut init_stmts);
                    !decl.kind.is_var()
                }
                Some(other) => {
                    if let Some(expr) = other.as_expression() {
                        let lowered = lower_expr(builder, env, source, expr);
                        init_stmts.push(Stmt::Expr { id: builder.alloc_stmt_id(), expr: lowered, span: span(builder, source, other.span()) });
                    }
                    false
                }
                None => false,
            };
            let init_span = init_stmts.first().map(stmt_span).unwrap_or_default();
            let init = Block { id: builder.alloc_block_id(), stmts: init_stmts, span: init_span };
            let cond = for_stmt.test.as_ref().map(|test| lower_expr(builder, env, source, test));
            let update_stmts = for_stmt
                .update
                .as_ref()
                .map(|update| {
                    let lowered = lower_expr(builder, env, source, update);
                    vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr: lowered, span: span(builder, source, update.span()) }]
                })
                .unwrap_or_default();
            let update = Block { id: builder.alloc_block_id(), stmts: update_stmts, span: init_span };
            let body = single_stmt_block(builder, env, source, &for_stmt.body);
            env.pop_block();
            vec![Stmt::For { id: builder.alloc_stmt_id(), init_is_scoped, init, cond, update, body, span: span(builder, source, for_stmt.span) }]
        }
        js::Statement::IfStatement(if_stmt) => {
            let cond = lower_expr(builder, env, source, &if_stmt.test);
            let then_block = single_stmt_block(builder, env, source, &if_stmt.consequent);
            let else_block = if_stmt.alternate.as_ref().map(|alt| single_stmt_block(builder, env, source, alt));
            vec![Stmt::If { id: builder.alloc_stmt_id(), cond, then_block, else_block, span: span(builder, source, if_stmt.span) }]
        }
        js::Statement::LabeledStatement(labeled) => lower_stmt(builder, env, source, &labeled.body),
        js::Statement::ReturnStatement(ret) => {
            let value = ret.argument.as_ref().map(|value| lower_expr(builder, env, source, value));
            vec![Stmt::Return { id: builder.alloc_stmt_id(), value, span: span(builder, source, ret.span) }]
        }
        js::Statement::SwitchStatement(switch) => {
            let scrutinee = lower_expr(builder, env, source, &switch.discriminant);
            let mut clauses = Vec::new();
            let mut default = None;
            for case in &switch.cases {
                if case.test.is_none() {
                    env.push_block();
                    let stmts = case.consequent.iter().flat_map(|stmt| lower_stmt(builder, env, source, stmt)).collect();
                    env.pop_block();
                    default = Some(Block { id: builder.alloc_block_id(), stmts, span: span(builder, source, case.span) });
                } else {
                    let (_, clause) = lower_switch_clause(builder, env, source, case);
                    clauses.push(clause);
                }
            }
            vec![Stmt::Switch { id: builder.alloc_stmt_id(), scrutinee, clauses, default, span: span(builder, source, switch.span) }]
        }
        js::Statement::ThrowStatement(throw) => {
            let value = lower_expr(builder, env, source, &throw.argument);
            vec![Stmt::Throw { id: builder.alloc_stmt_id(), value: Some(value), span: span(builder, source, throw.span) }]
        }
        js::Statement::TryStatement(try_stmt) => {
            let try_block = lower_block(builder, env, source, &try_stmt.block);
            let catches = try_stmt
                .handler
                .as_ref()
                .map(|handler| {
                    env.push_block();
                    let symbol = handler.param.as_ref().and_then(|param| match &param.pattern {
                        js::BindingPattern::BindingIdentifier(ident) => {
                            let symbol = builder.add_symbol(ident.name.as_str(), SymbolKind::Local);
                            env.declare(ident.name.as_str(), symbol);
                            Some(symbol)
                        }
                        _ => None,
                    });
                    let body = lower_block(builder, env, source, &handler.body);
                    env.pop_block();
                    vec![CatchClause { symbol, ty: None, body, span: span(builder, source, handler.span) }]
                })
                .unwrap_or_default();
            let finally_block = try_stmt.finalizer.as_ref().map(|block| lower_block(builder, env, source, block));
            vec![Stmt::Try { id: builder.alloc_stmt_id(), try_block, catches, finally_block, span: span(builder, source, try_stmt.span) }]
        }
        js::Statement::WhileStatement(while_stmt) => {
            let cond = lower_expr(builder, env, source, &while_stmt.test);
            let body = single_stmt_block(builder, env, source, &while_stmt.body);
            vec![Stmt::While { id: builder.alloc_stmt_id(), cond, body, span: span(builder, source, while_stmt.span) }]
        }
        js::Statement::WithStatement(with_stmt) => {
            let object = lower_expr(builder, env, source, &with_stmt.object);
            let mut stmts = vec![Stmt::Expr { id: builder.alloc_stmt_id(), expr: object, span: span(builder, source, with_stmt.span) }];
            stmts.extend(lower_stmt(builder, env, source, &with_stmt.body));
            stmts
        }
        js::Statement::VariableDeclaration(decl) => {
            let mut out = Vec::new();
            lower_variable_declaration(builder, env, source, decl, &mut out);
            out
        }
        // A function declaration nested inside another function's body is a
        // real closure at this HIR level too: lowering it as `let name =
        // <lambda>` lets `uniflow_lowering`'s existing generic
        // lambda-hoisting (triggered by a `Let`-bound `Expr::Lambda`)
        // extract it into its own named top-level function automatically —
        // the same mechanism every other frontend's nested closures already
        // rely on, so no JS-specific hoisting code is needed here.
        js::Statement::FunctionDeclaration(function) => {
            let Some(id) = &function.id else { return vec![] };
            let name = id.name.to_string();
            let lambda = lower_function_like(builder, env, source, &function.params, function.span, |builder, env, source| {
                function.body.as_ref().map(|body| lower_function_body(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
            });
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.declare(&name, symbol);
            vec![Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(lambda), span: span(builder, source, function.span) }]
        }
        // A class declared inside a function body: not commonly
        // taint-relevant and this HIR has no nested-item shape for it, so
        // it is skipped rather than partially/incorrectly modeled.
        js::Statement::ClassDeclaration(_) => vec![],
        // TS-only declarations and module import/export syntax are
        // unreachable inside a function body in valid source; skip
        // defensively rather than panic on malformed input.
        _ => vec![],
    }
}
