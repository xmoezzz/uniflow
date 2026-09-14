//! Shared function-parameter and closure-capture handling used by both
//! inline closures (`crate::frontend::expr`) and named declarations
//! (`crate::frontend::decl`) — one place that decides how a `Signature`'s
//! parameter list (including destructuring patterns) becomes
//! `uniflow_hir::Param`s, mirroring `lang_javascript::functions`.

use proc_macro2::Span as PmSpan;
use syn::spanned::Spanned;
use uniflow_hir::{Block, Expr, LambdaCapture, Param, ParamKind, Stmt, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::RustEnv;
use crate::frontend::expr::span;
use crate::frontend::stmt::lower_pattern_binding;

/// Declares one top-level parameter binding: a plain `ident` pattern becomes
/// exactly one `Param`, matching the function's real arity. A destructuring
/// pattern (`(a, b)`, `Point { x, y }`) instead becomes ONE synthetic
/// positional `Param` bound to the whole argument value, with the individual
/// names projected out via prologue statements (prepended to the function
/// body by the caller) — the same desugaring real compilers perform for
/// destructured parameters.
fn lower_top_level_param(
    builder: &mut ModuleBuilder,
    env: &mut RustEnv,
    source: &str,
    pattern: &syn::Pat,
    index: usize,
    item_span: uniflow_hir::Span,
    out: &mut Vec<Param>,
    prologue: &mut Vec<Stmt>,
) {
    match unwrap_pattern_type(pattern) {
        syn::Pat::Ident(ident_pat) => {
            let name = ident_pat.ident.to_string();
            let symbol = builder.add_symbol(&name, SymbolKind::Param);
            env.declare(&name, symbol);
            out.push(Param { name, symbol, ty: None, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: span(builder, source, ident_pat.span()) });
        }
        _ => {
            let synthetic_name = format!("$param{index}");
            let synthetic_symbol = builder.add_symbol(&synthetic_name, SymbolKind::Param);
            out.push(Param { name: synthetic_name, symbol: synthetic_symbol, ty: None, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: item_span });
            let synthetic_ref = Expr::VarRef { id: builder.alloc_expr_id(), symbol: synthetic_symbol, span: item_span };
            lower_pattern_binding(builder, env, source, pattern, &synthetic_ref, prologue);
        }
    }
}

/// Sees through a `Pat::Type` ascription (`x: i32` in a parameter, or the
/// shape `syn` uses for a type-annotated `let`) to the binding pattern
/// underneath — the type itself carries no dataflow-relevant information
/// this HIR needs.
pub(crate) fn unwrap_pattern_type(pattern: &syn::Pat) -> &syn::Pat {
    match pattern {
        syn::Pat::Type(inner) => unwrap_pattern_type(&inner.pat),
        other => other,
    }
}

pub(crate) fn lower_params(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>, prologue: &mut Vec<Stmt>) -> Vec<Param> {
    let mut out = Vec::with_capacity(inputs.len());
    for input in inputs {
        if let syn::FnArg::Typed(typed) = input {
            let item_span = span(builder, source, typed.span());
            lower_top_level_param(builder, env, source, &typed.pat, out.len(), item_span, &mut out, prologue);
        }
    }
    out
}

/// A `&self`/`&mut self`/`self` receiver becomes `Function.receiver`, typed
/// by whatever `Self` type is currently open (see `RustEnv::self_type`).
pub(crate) fn lower_receiver(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, inputs: &syn::punctuated::Punctuated<syn::FnArg, syn::token::Comma>) -> Option<Param> {
    let receiver = inputs.iter().find_map(|input| match input {
        syn::FnArg::Receiver(receiver) => Some(receiver),
        syn::FnArg::Typed(_) => None,
    })?;
    let symbol = builder.add_symbol("self", SymbolKind::Param);
    env.declare("self", symbol);
    let ty = env.self_type().map(|name| builder.ensure_type(name));
    Some(Param { name: "self".to_string(), symbol, ty, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: span(builder, source, receiver.span()) })
}

/// Lowers a closure value (`|a, b| a + b`): opens a fresh function scope,
/// binds parameters into it, runs `build_body` to produce the block, then
/// closes the scope and packages whatever outer-scope references it made
/// into `captures` — mirrors `lang_javascript::functions::lower_function_like`.
pub(crate) fn lower_closure(
    builder: &mut ModuleBuilder,
    env: &mut RustEnv,
    source: &str,
    inputs: &syn::punctuated::Punctuated<syn::Pat, syn::token::Comma>,
    closure_span: PmSpan,
    build_body: impl FnOnce(&mut ModuleBuilder, &mut RustEnv, &str) -> Block,
) -> Expr {
    env.enter_function();
    let mut prologue = Vec::new();
    let mut out = Vec::with_capacity(inputs.len());
    for (index, pattern) in inputs.iter().enumerate() {
        let item_span = span(builder, source, pattern.span());
        lower_top_level_param(builder, env, source, pattern, index, item_span, &mut out, &mut prologue);
    }
    let mut body = build_body(builder, env, source);
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    Expr::Lambda { id: builder.alloc_expr_id(), params: out, captures, body, span: span(builder, source, closure_span) }
}

/// Same scope/parameter/capture handling as [`lower_closure`], but returns
/// the pieces needed for a top-level `uniflow_hir::Function` item (a `fn`
/// item or impl/trait method) instead of an inline `Expr::Lambda`.
pub(crate) fn lower_function_parts(
    builder: &mut ModuleBuilder,
    env: &mut RustEnv,
    source: &str,
    sig: &syn::Signature,
    build_body: impl FnOnce(&mut ModuleBuilder, &mut RustEnv, &str) -> Block,
) -> (Vec<Param>, Option<Param>, Block, Vec<LambdaCapture>) {
    env.enter_function();
    let receiver = lower_receiver(builder, env, source, &sig.inputs);
    let mut prologue = Vec::new();
    let params = lower_params(builder, env, source, &sig.inputs, &mut prologue);
    let mut body = build_body(builder, env, source);
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    (params, receiver, body, captures)
}

pub(crate) fn captures_to_params(captures: Vec<LambdaCapture>) -> Vec<Param> {
    captures
        .into_iter()
        .map(|capture| Param { name: capture.name, symbol: capture.symbol, ty: capture.ty, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: capture.span })
        .collect()
}
