//! Shared function-parameter and closure-capture handling used by both
//! inline closures (`crate::frontend::expr`'s arrow/function expressions)
//! and named declarations (`crate::frontend::decl`'s function/method
//! declarations) — one place that decides how a `FormalParameters` list
//! (including destructuring, defaults, and rest) becomes `uniflow_hir::Param`s.

use oxc_ast::ast as js;
use oxc_span::{GetSpan, Span as OxcSpan};
use uniflow_hir::{Block, Expr, LambdaCapture, Param, ParamKind, Stmt, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::JsEnv;
use crate::frontend::expr::span;
use crate::frontend::stmt::lower_destructuring_binding;

/// Declares one *top-level* parameter binding: a plain identifier becomes
/// exactly one `Param`, matching the function's real arity. A destructuring
/// pattern (`{a, b}`, `[a, b]`) instead becomes ONE synthetic positional
/// `Param` bound to the whole argument value, with the individual names
/// projected out via prologue statements (`prologue`, prepended to the
/// function body by the caller) — mirroring how real engines desugar
/// destructured parameters. Getting this wrong (binding each destructured
/// name as its own *separate* positional parameter) would silently change
/// the function's apparent arity and misattribute which argument each name
/// actually reads from.
fn lower_top_level_param(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, pattern: &js::BindingPattern, kind: ParamKind, has_default: bool, item_span: uniflow_hir::Span, out: &mut Vec<Param>, prologue: &mut Vec<Stmt>) {
    match pattern {
        js::BindingPattern::BindingIdentifier(ident) => {
            let symbol = builder.add_symbol(ident.name.as_str(), SymbolKind::Param);
            env.declare(ident.name.as_str(), symbol);
            out.push(Param { name: ident.name.to_string(), symbol, ty: None, kind, has_default, keyword_only: false, cpp: Default::default(), span: span(builder, source, ident.span) });
        }
        js::BindingPattern::AssignmentPattern(assignment) => {
            lower_top_level_param(builder, env, source, &assignment.left, kind, true, item_span, out, prologue);
        }
        js::BindingPattern::ObjectPattern(_) | js::BindingPattern::ArrayPattern(_) => {
            let synthetic_name = format!("$param{}", out.len());
            let synthetic_symbol = builder.add_symbol(&synthetic_name, SymbolKind::Param);
            out.push(Param { name: synthetic_name, symbol: synthetic_symbol, ty: None, kind, has_default, keyword_only: false, cpp: Default::default(), span: item_span });
            let synthetic_ref = Expr::VarRef { id: builder.alloc_expr_id(), symbol: synthetic_symbol, span: item_span };
            lower_destructuring_binding(builder, env, source, pattern, &synthetic_ref, false, prologue);
        }
    }
}

pub(crate) fn lower_params(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, params: &js::FormalParameters, prologue: &mut Vec<Stmt>) -> Vec<Param> {
    let mut out = Vec::with_capacity(params.items.len() + usize::from(params.rest.is_some()));
    for item in &params.items {
        let item_span = span(builder, source, item.pattern.span());
        lower_top_level_param(builder, env, source, &item.pattern, ParamKind::Positional, item.initializer.is_some(), item_span, &mut out, prologue);
    }
    if let Some(rest) = &params.rest {
        let rest_span = span(builder, source, rest.rest.argument.span());
        lower_top_level_param(builder, env, source, &rest.rest.argument, ParamKind::VarArgs, false, rest_span, &mut out, prologue);
    }
    out
}

/// Lowers a closure value (arrow function or function expression): opens a
/// fresh function scope, binds parameters into it, runs `build_body` to
/// produce the block (so the caller controls concise-body-arrow vs.
/// ordinary block-body handling), then closes the scope and packages
/// whatever outer-scope references it made into `captures`.
pub(crate) fn lower_function_like(
    builder: &mut ModuleBuilder,
    env: &mut JsEnv,
    source: &str,
    params: &js::FormalParameters,
    oxc_span: OxcSpan,
    build_body: impl FnOnce(&mut ModuleBuilder, &mut JsEnv, &str) -> Block,
) -> Expr {
    env.enter_function();
    let mut prologue = Vec::new();
    let lowered_params = lower_params(builder, env, source, params, &mut prologue);
    let mut body = build_body(builder, env, source);
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    Expr::Lambda { id: builder.alloc_expr_id(), params: lowered_params, captures, body, span: span(builder, source, oxc_span) }
}

/// Same scope/parameter/capture handling as [`lower_function_like`], but
/// returns the pieces needed for a top-level `uniflow_hir::Function` item
/// (a named declaration or class method) instead of an inline `Expr::Lambda`.
pub(crate) fn lower_function_parts(
    builder: &mut ModuleBuilder,
    env: &mut JsEnv,
    source: &str,
    params: &js::FormalParameters,
    build_body: impl FnOnce(&mut ModuleBuilder, &mut JsEnv, &str) -> Block,
) -> (Vec<Param>, Block, Vec<LambdaCapture>) {
    env.enter_function();
    let mut prologue = Vec::new();
    let lowered_params = lower_params(builder, env, source, params, &mut prologue);
    let mut body = build_body(builder, env, source);
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    (lowered_params, body, captures)
}
