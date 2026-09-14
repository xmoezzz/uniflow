//! Shared parameter and closure-capture handling used by `def`/`defs`
//! methods, block literals (`{ |x| ... }`/`do |x| ... end`), `->`/`lambda`/
//! `proc` lambda forms, and numbered-parameter blocks (`{ _1 }`) — one place
//! that decides how Ruby's several parameter-list node shapes become
//! `uniflow_hir::Param`s. Mirrors `lang_rust::frontend::functions`.

use lib_ruby_parser::Node;
use uniflow_hir::{Block, Expr, LambdaCapture, Param, ParamKind, Stmt, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::RubyEnv;
use crate::frontend::expr::span;

fn declare_param(builder: &mut ModuleBuilder, env: &mut RubyEnv, name: &str, kind: ParamKind, has_default: bool, keyword_only: bool, at: uniflow_hir::Span, out: &mut Vec<Param>) {
    let symbol = builder.add_symbol(name, SymbolKind::Param);
    env.declare(name, symbol);
    out.push(Param { name: name.to_string(), symbol, ty: None, kind, has_default, keyword_only, cpp: Default::default(), span: at });
}

/// Projects each destructured sub-name of a `Procarg0`/`Mlhs` block
/// parameter (`{ |(a, b)| ... }`) off a synthetic whole-argument value, the
/// same desugaring `lang_rust::frontend::functions::lower_top_level_param`
/// performs for a tuple-pattern parameter.
fn project_destructured_names(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, items: &[Node], source_expr: &Expr, prologue: &mut Vec<Stmt>) {
    for (index, item) in items.iter().enumerate() {
        let name = match item {
            Node::Arg(a) => Some((a.name.clone(), span(builder, source, &a.expression_l))),
            Node::Restarg(r) => r.name.clone().map(|n| (n, span(builder, source, &r.expression_l))),
            _ => None,
        };
        let Some((name, item_span)) = name else { continue };
        let idx_expr = Expr::Literal { id: builder.alloc_expr_id(), kind: uniflow_hir::LiteralKind::Int(index as i64), span: item_span };
        let projected = Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(source_expr.clone()), index: Box::new(idx_expr), span: item_span };
        let symbol = builder.add_symbol(&name, SymbolKind::Local);
        env.declare(&name, symbol);
        prologue.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol, ty: None, init: Some(projected), span: item_span });
    }
}

/// Lowers one parameter-list node (`Node::Args`, as found on `Def`/`Defs`/
/// `Block`/`Numblock`) into `Param`s. Any prologue statements needed to
/// project a destructured block parameter's sub-names are appended to
/// `prologue` (spliced at the front of the body by the caller).
pub(crate) fn lower_params(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, args_node: Option<&Node>, prologue: &mut Vec<Stmt>) -> Vec<Param> {
    let Some(Node::Args(args)) = args_node else { return Vec::new() };
    let mut out = Vec::with_capacity(args.args.len());
    for arg in &args.args {
        match arg {
            Node::Arg(a) => declare_param(builder, env, &a.name, ParamKind::Positional, false, false, span(builder, source, &a.expression_l), &mut out),
            Node::Optarg(o) => declare_param(builder, env, &o.name, ParamKind::Positional, true, false, span(builder, source, &o.expression_l), &mut out),
            Node::Restarg(r) => {
                let name = r.name.clone().unwrap_or_else(|| "$rest".to_string());
                declare_param(builder, env, &name, ParamKind::VarArgs, false, false, span(builder, source, &r.expression_l), &mut out);
            }
            Node::Kwarg(k) => declare_param(builder, env, &k.name, ParamKind::KwArgs, false, true, span(builder, source, &k.expression_l), &mut out),
            Node::Kwoptarg(k) => declare_param(builder, env, &k.name, ParamKind::KwArgs, true, true, span(builder, source, &k.expression_l), &mut out),
            Node::Kwrestarg(k) => {
                let name = k.name.clone().unwrap_or_else(|| "$kwrest".to_string());
                declare_param(builder, env, &name, ParamKind::KwArgs, false, true, span(builder, source, &k.expression_l), &mut out);
            }
            Node::Blockarg(b) => {
                let name = b.name.clone().unwrap_or_else(|| "$block".to_string());
                declare_param(builder, env, &name, ParamKind::Positional, false, false, span(builder, source, &b.expression_l), &mut out);
            }
            Node::Shadowarg(s) => declare_param(builder, env, &s.name, ParamKind::Positional, false, false, span(builder, source, &s.expression_l), &mut out),
            Node::Procarg0(p) => {
                if let [Node::Arg(a)] = p.args.as_slice() {
                    declare_param(builder, env, &a.name, ParamKind::Positional, false, false, span(builder, source, &a.expression_l), &mut out);
                } else {
                    let synthetic_name = "$block_arg".to_string();
                    let item_span = span(builder, source, &p.expression_l);
                    let symbol = builder.add_symbol(&synthetic_name, SymbolKind::Param);
                    out.push(Param { name: synthetic_name, symbol, ty: None, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: item_span });
                    let synthetic_ref = Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: item_span };
                    project_destructured_names(builder, env, source, &p.args, &synthetic_ref, prologue);
                }
            }
            Node::Mlhs(m) => {
                let synthetic_name = "$destructure".to_string();
                let item_span = span(builder, source, &m.expression_l);
                let symbol = builder.add_symbol(&synthetic_name, SymbolKind::Param);
                out.push(Param { name: synthetic_name, symbol, ty: None, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: item_span });
                let synthetic_ref = Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: item_span };
                project_destructured_names(builder, env, source, &m.items, &synthetic_ref, prologue);
            }
            // `ForwardArg` (`def m(...); end`) and `Kwnilarg` (`def m(**nil);
            // end`) carry no addressable name to project — a documented,
            // low-value scope cut.
            _ => {}
        }
    }
    out
}

/// A `self`-shaped receiver parameter for an instance method body, typed by
/// whatever class/module is currently open (`RubyEnv::self_type`).
pub(crate) fn declare_self_receiver(builder: &mut ModuleBuilder, env: &mut RubyEnv, at: uniflow_hir::Span) -> Param {
    let symbol = builder.add_symbol("self", SymbolKind::Param);
    env.declare("self", symbol);
    let ty = env.self_type().map(|name| builder.ensure_type(name));
    Param { name: "self".to_string(), symbol, ty, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: at }
}

pub(crate) fn captures_to_params(captures: Vec<LambdaCapture>) -> Vec<Param> {
    captures.into_iter().map(|capture| Param { name: capture.name, symbol: capture.symbol, ty: capture.ty, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: capture.span }).collect()
}

/// Lowers a block/lambda body (`args_node`, `body_node`, both optional):
/// opens a fresh function scope, binds parameters into it, lowers the body
/// (its trailing expression is the block's own value — matching
/// `lang_rust::frontend::functions::lower_closure`'s "closure tail expression
/// always returns" treatment, appropriate since a Ruby block/lambda's last
/// expression is always its result), then closes the scope and packages
/// whatever outer-scope references it made into `captures`.
pub(crate) fn lower_closure_body(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, args_node: Option<&Node>, body_node: Option<&Node>, numargs: u8) -> (Vec<Param>, Vec<LambdaCapture>, Block) {
    env.enter_function();
    let mut prologue = Vec::new();
    let mut params = lower_params(builder, env, source, args_node, &mut prologue);
    if numargs > 0 && params.is_empty() {
        for index in 1..=numargs {
            let name = format!("_{index}");
            let dummy_span = uniflow_hir::Span::default();
            declare_param(builder, env, &name, ParamKind::Positional, false, false, dummy_span, &mut params);
        }
    }
    let mut body = crate::frontend::stmt::lower_body_returning_value(builder, env, source, body_node);
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    (params, captures, body)
}

