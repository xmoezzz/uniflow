//! Shared function-parameter and closure-capture handling used by both
//! top-level declarations (`decl.rs`'s free functions/methods) and inline
//! `FuncLit` closures (`expr.rs`) — mirrors
//! `uniflow_lang_javascript::frontend::functions`.

use gosyn::ast as go;
use uniflow_hir::{Block, Expr, LambdaCapture, Param, ParamKind, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::GoEnv;
use crate::frontend::expr::{span_at, type_qualifier};

/// Lowers one Go parameter list. Go allows grouping several names under one
/// shared type (`func f(a, b int)`), so one `gosyn::ast::Field` can expand
/// into several `uniflow_hir::Param`s; an unnamed field (legal in a bare
/// function-type signature) gets a synthetic name instead of being dropped,
/// preserving the function's real arity. The last field's type may be
/// wrapped in `Expression::Ellipsis` to mark Go's variadic parameter
/// (`func f(items ...string)`); that unwraps to the element type and marks
/// the parameter `ParamKind::VarArgs`.
pub(crate) fn lower_params(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, field_list: &go::FieldList) -> Vec<Param> {
    let mut out = Vec::with_capacity(field_list.list.len());
    for field in &field_list.list {
        let (is_variadic, type_expr) = match &field.typ {
            go::Expression::Ellipsis(ellipsis) => (true, ellipsis.elt.as_deref().unwrap_or(&field.typ)),
            other => (false, other),
        };
        let qualifier = type_qualifier(env, type_expr);
        let kind = if is_variadic { ParamKind::VarArgs } else { ParamKind::Positional };
        let ty = qualifier.as_ref().map(|q| builder.ensure_type(q));
        if field.name.is_empty() {
            let synthetic_name = format!("$param{}", out.len());
            let symbol = builder.add_symbol(&synthetic_name, SymbolKind::Param);
            env.declare(&synthetic_name, symbol);
            if let Some(qualifier) = &qualifier {
                env.set_value_qualifier(symbol, qualifier.clone());
            }
            out.push(Param { name: synthetic_name, symbol, ty, kind, has_default: false, keyword_only: false, cpp: Default::default(), span: span_at(builder, source, field.typ.pos()) });
            continue;
        }
        for ident in &field.name {
            let symbol = builder.add_symbol(&ident.name, SymbolKind::Param);
            env.declare(&ident.name, symbol);
            if let Some(qualifier) = &qualifier {
                env.set_value_qualifier(symbol, qualifier.clone());
            }
            out.push(Param { name: ident.name.clone(), symbol, ty, kind: kind.clone(), has_default: false, keyword_only: false, cpp: Default::default(), span: span_at(builder, source, ident.pos) });
        }
    }
    out
}

/// Opens a fresh function scope, lowers `field_list` into params, runs
/// `build_body`, then closes the scope and returns the pieces needed for a
/// top-level `uniflow_hir::Function` (or an `Expr::Lambda`, via
/// `lower_func_lit`).
pub(crate) fn lower_function_parts(
    builder: &mut ModuleBuilder,
    env: &mut GoEnv,
    source: &str,
    field_list: &go::FieldList,
    build_body: impl FnOnce(&mut ModuleBuilder, &mut GoEnv, &str) -> Block,
) -> (Vec<Param>, Block, Vec<LambdaCapture>) {
    env.enter_function();
    let params = lower_params(builder, env, source, field_list);
    let body = build_body(builder, env, source);
    let captures = env.leave_function();
    (params, body, captures)
}

pub(crate) fn lower_func_lit(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, lit: &go::FuncLit) -> Expr {
    let (params, body, captures) = lower_function_parts(builder, env, source, &lit.typ.params, |builder, env, source| crate::frontend::stmt::lower_block(builder, env, source, &lit.body));
    Expr::Lambda { id: builder.alloc_expr_id(), params, captures, body, span: span_at(builder, source, lit.typ.pos) }
}

/// A closure's captures (`Vec<LambdaCapture>`) and a declared function's
/// captures (`Vec<Param>`, the shape `uniflow_hir::Function` carries) are
/// different types for the same concept — mirrors
/// `uniflow_lang_javascript::frontend::decl::captures_to_params`.
pub(crate) fn captures_to_params(captures: Vec<LambdaCapture>) -> Vec<Param> {
    captures
        .into_iter()
        .map(|capture| Param { name: capture.name, symbol: capture.symbol, ty: capture.ty, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: capture.span })
        .collect()
}
