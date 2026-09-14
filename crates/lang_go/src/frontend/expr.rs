//! Lowers a `gosyn::ast::Expression` into `uniflow_hir::Expr`, and the two
//! qualifier resolvers everything else in this frontend depends on:
//! `type_qualifier` (walks a TYPE expression — a param's declared type, a
//! receiver's type — to a dotted qualified name) and `expression_qualifier`
//! (walks a VALUE expression's provenance the same way, so a call through a
//! variable bound to a qualified value still resolves).

use gosyn::ast as go;
use gosyn::token::{LitKind, Operator};
use uniflow_hir::{BinaryOp, CallExpr, CallTarget, CollectionKind, Expr, LiteralKind, SymbolId, SymbolKind, UnaryOp};
use uniflow_parser_core::{span_from_offsets, ModuleBuilder};

use crate::frontend::env::GoEnv;

pub(crate) fn span_at(builder: &ModuleBuilder, source: &str, pos: usize) -> uniflow_hir::Span {
    span_from_offsets(builder.file_id(), source, pos, pos)
}

pub(crate) fn span_range(builder: &ModuleBuilder, source: &str, start: usize, end: usize) -> uniflow_hir::Span {
    span_from_offsets(builder.file_id(), source, start, end)
}

fn opaque(builder: &mut ModuleBuilder, source: &str, pos: usize, text: impl Into<String>) -> Expr {
    Expr::Opaque { id: builder.alloc_expr_id(), text: text.into(), span: span_at(builder, source, pos) }
}

fn literal(builder: &mut ModuleBuilder, source: &str, pos: usize, kind: LiteralKind) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind, span: span_at(builder, source, pos) }
}

/// Strips a Go string/rune literal's surrounding quote characters and
/// resolves the handful of escapes that show up in practice
/// (`\n`, `\t`, `\r`, `\\`, `\"`, `\'`); any other backslash escape is
/// passed through with the backslash dropped rather than rejected — a
/// best-effort decode, not a full Go literal grammar implementation.
fn decode_go_escapes(inner: &str) -> String {
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('\'') => out.push('\''),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// A gosyn `BasicLit`/`StringLit`/import path's raw text includes its
/// surrounding quotes (`"..."` or a raw `` `...` `` string) — see
/// `gosyn`'s scanner, which reports the literal's full source span. This
/// strips them and decodes escapes for a double-quoted string; a raw
/// (backtick) string has no escapes to decode.
pub(crate) fn decode_string_literal_value(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('`') && raw.ends_with('`') {
        return raw[1..raw.len() - 1].to_string();
    }
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        return decode_go_escapes(&raw[1..raw.len() - 1]);
    }
    raw.to_string()
}

fn decode_go_rune(raw: &str) -> i64 {
    let inner = raw.trim_matches('\'');
    decode_go_escapes(inner).chars().next().map(|c| c as i64).unwrap_or(0)
}

fn parse_go_int(raw: &str) -> i64 {
    let cleaned: String = raw.chars().filter(|c| *c != '_').collect();
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = cleaned.strip_prefix(prefix) {
            return i64::from_str_radix(digits, radix).unwrap_or(0);
        }
    }
    cleaned.parse::<i64>().unwrap_or(0)
}

fn parse_go_float(raw: &str) -> f64 {
    // Strips a trailing imaginary-literal `i` suffix too — an imaginary
    // literal's real magnitude is the closest approximation this HIR's
    // `LiteralKind` can carry (there is no complex-number literal kind).
    let cleaned: String = raw.chars().filter(|c| *c != '_' && *c != 'i').collect();
    cleaned.parse::<f64>().unwrap_or(0.0)
}

/// Resolves a plain identifier read to whichever symbol is currently bound
/// to it (allocating a closure capture if it crosses a function boundary),
/// falling back to a fresh, unbound symbol for a genuinely free name (a
/// package-level global, an undeclared identifier) — treated as an
/// opaque-but-trackable value rather than an error. The fallback symbol is
/// declared at the current function's boundary scope (not the innermost
/// block) so repeated references to the same free name within one function
/// resolve to the same symbol regardless of which nested block they appear in.
pub(crate) fn resolve_identifier(builder: &mut ModuleBuilder, env: &mut GoEnv, name: &str) -> SymbolId {
    if let Some(symbol) = env.resolve(builder, name) {
        return symbol;
    }
    let symbol = builder.add_symbol(name, SymbolKind::Global);
    env.declare_hoisted(name, symbol);
    symbol
}

/// Walks a TYPE expression (a parameter's declared type, a method
/// receiver's type, a `var`'s explicit type annotation) to the dotted
/// qualified name a bundled rule's `regex`/`method_regex` matcher expects —
/// e.g. `*http.Request` (import `"net/http"`) -> `"net/http.Request"`.
pub(crate) fn type_qualifier(env: &GoEnv, type_expr: &go::Expression) -> Option<String> {
    match type_expr {
        go::Expression::Star(star) => type_qualifier(env, &star.right),
        go::Expression::TypePointer(pointer) => type_qualifier(env, &pointer.typ),
        go::Expression::TypeSlice(slice) => type_qualifier(env, &slice.typ),
        go::Expression::TypeArray(array) => type_qualifier(env, &array.typ),
        go::Expression::TypeChannel(channel) => type_qualifier(env, &channel.typ),
        // A map's value type is the more usually taint-relevant half; the
        // key type is dropped, a documented simplification.
        go::Expression::TypeMap(map) => type_qualifier(env, &map.val),
        go::Expression::Selector(selector) => {
            let go::Expression::Ident(pkg) = &*selector.x else { return None };
            let qualifier = env.import_binding(&pkg.name)?;
            Some(format!("{qualifier}.{}", selector.sel.name))
        }
        go::Expression::Ident(ident) => {
            if env.is_package_type(&ident.name) {
                Some(format!("{}.{}", env.package_qualifier(), ident.name))
            } else {
                // A built-in (`string`, `int`, ...) or an unrecognized name:
                // still usable bare by `exact`/`contains` matchers.
                Some(ident.name.clone())
            }
        }
        go::Expression::Index(index) => type_qualifier(env, &index.left),
        go::Expression::IndexList(index) => type_qualifier(env, &index.left),
        go::Expression::Paren(paren) => type_qualifier(env, &paren.expr),
        go::Expression::Ellipsis(ellipsis) => ellipsis.elt.as_deref().and_then(|inner| type_qualifier(env, inner)),
        _ => None,
    }
}

/// Walks a VALUE expression's qualified-name provenance the same way
/// `type_qualifier` walks a type — an identifier bound to an import
/// (`os.Getenv`), a local/parameter carrying a known `value_qualifier`
/// (`r.FormValue` once `r`'s declared type set one), a member access off an
/// already-qualified value, or a call whose own callee was itself qualified
/// (so its return value keeps the chain going, mirroring
/// `uniflow_lang_javascript::frontend::expr::expression_qualifier`).
pub(crate) fn expression_qualifier(env: &GoEnv, expr: &go::Expression) -> Option<String> {
    match expr {
        go::Expression::Ident(ident) => {
            if let Some(qualifier) = env.import_binding(&ident.name) {
                return Some(qualifier.to_string());
            }
            env.peek(&ident.name).and_then(|symbol| env.value_qualifier(symbol)).map(str::to_string)
        }
        go::Expression::Selector(selector) => Some(format!("{}.{}", expression_qualifier(env, &selector.x)?, selector.sel.name)),
        go::Expression::Star(star) => expression_qualifier(env, &star.right),
        go::Expression::Paren(paren) => expression_qualifier(env, &paren.expr),
        go::Expression::Call(call) => match &*call.func {
            go::Expression::Selector(_) => expression_qualifier(env, &call.func),
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn lower_expr(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, expr: &go::Expression) -> Expr {
    match expr {
        go::Expression::Ident(ident) => {
            let symbol = resolve_identifier(builder, env, &ident.name);
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span_at(builder, source, ident.pos) }
        }
        go::Expression::BasicLit(lit) => match lit.kind {
            LitKind::String => literal(builder, source, lit.pos, LiteralKind::String(decode_string_literal_value(&lit.value))),
            LitKind::Integer => literal(builder, source, lit.pos, LiteralKind::Int(parse_go_int(&lit.value))),
            LitKind::Float => literal(builder, source, lit.pos, LiteralKind::Float(parse_go_float(&lit.value))),
            // No complex-number literal kind exists in this HIR; the real
            // magnitude is the closest available approximation.
            LitKind::Imag => literal(builder, source, lit.pos, LiteralKind::Float(parse_go_float(&lit.value))),
            // A rune literal denotes a Unicode code point, i.e. an integer.
            LitKind::Char => literal(builder, source, lit.pos, LiteralKind::Int(decode_go_rune(&lit.value))),
            LitKind::Ident => opaque(builder, source, lit.pos, lit.value.clone()),
        },
        go::Expression::Selector(selector) => {
            let base = lower_expr(builder, env, source, &selector.x);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: selector.sel.name.clone(), span: span_at(builder, source, selector.pos) }
        }
        go::Expression::Index(index) => {
            let base = lower_expr(builder, env, source, &index.left);
            let idx = lower_expr(builder, env, source, &index.index);
            Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(idx), span: span_range(builder, source, index.pos.0, index.pos.1) }
        }
        // Generic instantiation used as a value (`Box[int]{}`'s type
        // position aside, a bare `Foo[T]` read as a value is rare); the
        // instantiated entity's own value is the closest approximation.
        go::Expression::IndexList(index) => lower_expr(builder, env, source, &index.left),
        go::Expression::Slice(slice) => {
            // `a[low:high]` (and the 3-index full-slice form): modeled as an
            // `IndexRead` off the sliced base so the base's taint keeps
            // flowing — the closest existing HIR shape to "a derived value
            // read out of this collection." The bound expression (whichever
            // of high/low is present) is kept as the index operand so ITS
            // taint is reachable too; this does not claim the result is
            // actually keyed by that value.
            let base = lower_expr(builder, env, source, &slice.left);
            let bound = slice.index[1].as_deref().or(slice.index[0].as_deref());
            let index = match bound {
                Some(inner) => lower_expr(builder, env, source, inner),
                None => literal(builder, source, slice.pos.0, LiteralKind::Int(0)),
            };
            Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(index), span: span_range(builder, source, slice.pos.0, slice.pos.1) }
        }
        go::Expression::FuncLit(lit) => crate::frontend::functions::lower_func_lit(builder, env, source, lit),
        go::Expression::Ellipsis(ellipsis) => match &ellipsis.elt {
            Some(inner) => lower_expr(builder, env, source, inner),
            None => opaque(builder, source, ellipsis.pos, "..."),
        },
        go::Expression::Call(call) => lower_call(builder, env, source, call),
        go::Expression::Paren(paren) => lower_expr(builder, env, source, &paren.expr),
        go::Expression::TypeAssert(assertion) => lower_expr(builder, env, source, &assertion.left),
        go::Expression::CompositeLit(composite) => lower_literal_value(builder, env, source, &composite.val),
        go::Expression::List(items) => {
            let elements = items.iter().map(|item| lower_expr(builder, env, source, item)).collect();
            let span = items.first().map(|item| span_at(builder, source, item.pos())).unwrap_or_default();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Tuple, elements, span }
        }
        go::Expression::Operation(operation) => lower_operation(builder, env, source, operation),
        go::Expression::Range(range_expr) => lower_expr(builder, env, source, &range_expr.right),
        go::Expression::Star(star) => {
            let inner = lower_expr(builder, env, source, &star.right);
            Expr::Unary { id: builder.alloc_expr_id(), op: UnaryOp::Deref, expr: Box::new(inner), span: span_at(builder, source, star.pos) }
        }
        // Type-only expression variants should never appear in value
        // position in valid source; handled defensively as opaque rather
        // than panicking on malformed/unexpected input.
        go::Expression::TypeMap(_)
        | go::Expression::TypeArray(_)
        | go::Expression::TypeSlice(_)
        | go::Expression::TypeFunction(_)
        | go::Expression::TypeStruct(_)
        | go::Expression::TypeChannel(_)
        | go::Expression::TypePointer(_)
        | go::Expression::TypeInterface(_) => opaque(builder, source, expr.pos(), "<type-expression>"),
    }
}

fn lower_element(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, element: &go::Element) -> Expr {
    match element {
        go::Element::Expr(inner) => lower_expr(builder, env, source, inner),
        go::Element::LitValue(nested) => lower_literal_value(builder, env, source, nested),
    }
}

fn lower_literal_value(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, value: &go::LiteralValue) -> Expr {
    let mut elements = Vec::with_capacity(value.values.len() * 2);
    let mut has_key = false;
    for keyed in &value.values {
        if let Some(key) = &keyed.key {
            has_key = true;
            elements.push(lower_element(builder, env, source, key));
        }
        elements.push(lower_element(builder, env, source, &keyed.val));
    }
    let container = if has_key { CollectionKind::Map } else { CollectionKind::List };
    Expr::Collection { id: builder.alloc_expr_id(), container, elements, span: span_range(builder, source, value.pos.0, value.pos.1) }
}

fn map_binary_operator(op: Operator) -> BinaryOp {
    match op {
        Operator::Add => BinaryOp::Add,
        Operator::Sub => BinaryOp::Sub,
        Operator::Star => BinaryOp::Mul,
        Operator::Quo => BinaryOp::Div,
        Operator::Rem => BinaryOp::Mod,
        Operator::And => BinaryOp::BitAnd,
        Operator::Or => BinaryOp::BitOr,
        Operator::Xor => BinaryOp::BitXor,
        Operator::AndAnd => BinaryOp::And,
        Operator::OrOr => BinaryOp::Or,
        Operator::Equal => BinaryOp::Eq,
        Operator::NotEqual => BinaryOp::Ne,
        Operator::Less => BinaryOp::Lt,
        Operator::LessEqual => BinaryOp::Le,
        Operator::Greater => BinaryOp::Gt,
        Operator::GreaterEqual => BinaryOp::Ge,
        // Bit-shift and bit-clear (`&^`) have no dedicated HIR operator;
        // `Add` keeps both operands flowing through as a generic
        // combination without claiming to model the real operator (mirrors
        // `uniflow_lang_javascript`'s own documented approximation for its
        // own operators with no HIR equivalent).
        Operator::Shl | Operator::Shr | Operator::AndNot => BinaryOp::Add,
        _ => BinaryOp::Add,
    }
}

fn lower_operation(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, operation: &go::Operation) -> Expr {
    let lhs = lower_expr(builder, env, source, &operation.x);
    let span = span_at(builder, source, operation.pos);
    let Some(y) = &operation.y else {
        return match operation.op {
            // Unary `+x` is a no-op in Go.
            Operator::Add => lhs,
            Operator::Sub => Expr::Unary { id: builder.alloc_expr_id(), op: UnaryOp::Neg, expr: Box::new(lhs), span },
            Operator::Not => Expr::Unary { id: builder.alloc_expr_id(), op: UnaryOp::Not, expr: Box::new(lhs), span },
            Operator::Xor => Expr::Unary { id: builder.alloc_expr_id(), op: UnaryOp::BitNot, expr: Box::new(lhs), span },
            Operator::And => Expr::Unary { id: builder.alloc_expr_id(), op: UnaryOp::AddrOf, expr: Box::new(lhs), span },
            // Channel receive (`<-ch`): no HIR equivalent for the
            // suspension/queue semantics; the channel's own value is the
            // closest approximation for keeping taint flowing.
            Operator::Arrow => lhs,
            _ => lhs,
        };
    };
    let rhs = lower_expr(builder, env, source, y);
    Expr::Binary { id: builder.alloc_expr_id(), op: map_binary_operator(operation.op), lhs: Box::new(lhs), rhs: Box::new(rhs), span }
}

/// Resolves the callee half of a call expression to a `CallTarget`, kept
/// separate from `lower_call` so a generic-instantiation callee
/// (`Foo[int](...)`) can recurse into its own uninstantiated callee without
/// reconstructing a synthetic `Call` node.
fn resolve_call_target(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, func: &go::Expression) -> (CallTarget, Option<Box<Expr>>, bool) {
    match func {
        go::Expression::Ident(ident) => {
            if let Some(qualified) = env.package_function(&ident.name) {
                return (CallTarget::Named(qualified.to_string()), None, false);
            }
            match expression_qualifier(env, func) {
                Some(qualifier) => (CallTarget::Named(qualifier), None, false),
                None => (CallTarget::Named(ident.name.clone()), None, false),
            }
        }
        go::Expression::Selector(selector) => {
            let qualifier = expression_qualifier(env, &selector.x);
            let is_pure_namespace_call =
                matches!(&*selector.x, go::Expression::Ident(pkg) if env.import_binding(&pkg.name).is_some() && env.peek(&pkg.name).is_none());
            if is_pure_namespace_call {
                // `os.Getenv(...)`/`http.Get(...)`: a package-qualified free
                // function call, not a call through a real receiver value —
                // mirrors `uniflow_lang_javascript`'s `ImportBinding::Namespace`
                // handling.
                let qualifier = qualifier.expect("import binding implies a qualifier");
                return (CallTarget::Named(format!("{qualifier}.{}", selector.sel.name)), None, false);
            }
            // Typed-receiver or plain method call: the receiver expression
            // is always preserved (even when a qualified name is ALSO
            // available) because a `propagators` rule needs the real
            // receiver value present to trace a chained receiver->return
            // flow — discarding it just because a qualified target name was
            // also derivable would silently break that mechanism.
            let receiver_expr = lower_expr(builder, env, source, &selector.x);
            let target = match qualifier {
                Some(qualifier) => CallTarget::Named(format!("{qualifier}.{}", selector.sel.name)),
                None => CallTarget::Named(selector.sel.name.clone()),
            };
            (target, Some(Box::new(receiver_expr)), true)
        }
        go::Expression::Index(index) => resolve_call_target(builder, env, source, &index.left),
        go::Expression::IndexList(index) => resolve_call_target(builder, env, source, &index.left),
        go::Expression::Paren(paren) => resolve_call_target(builder, env, source, &paren.expr),
        other => {
            let callee = lower_expr(builder, env, source, other);
            (CallTarget::Dynamic(Box::new(callee)), None, false)
        }
    }
}

pub(crate) fn lower_call(builder: &mut ModuleBuilder, env: &mut GoEnv, source: &str, call: &go::Call) -> Expr {
    let args = call.args.iter().map(|arg| lower_expr(builder, env, source, arg)).collect::<Vec<_>>();
    let arg_names = vec![None; args.len()];
    let (target, receiver, qualifier_is_explicit) = resolve_call_target(builder, env, source, &call.func);
    Expr::Call(CallExpr {
        id: builder.alloc_expr_id(),
        target,
        receiver,
        qualifier_is_explicit,
        args,
        arg_names,
        span: span_range(builder, source, call.pos.0, call.pos.1),
    })
}
