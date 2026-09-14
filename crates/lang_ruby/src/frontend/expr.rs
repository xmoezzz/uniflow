//! Lowers a `lib_ruby_parser::Node` into `uniflow_hir::Expr`.
//!
//! Every construct that carries a real runtime value is modeled precisely
//! (local/instance/class/global variable and constant reads, calls with a
//! real receiver chain, string interpolation, collection literals,
//! index/field access, binary/assignment operators). A handful of
//! constructs this HIR has no native shape for — most notably `if`/`case`/
//! `begin` used directly as a *nested sub-expression* (not a bare statement
//! or a `def`/block's own tail value, both of which get full, precise
//! treatment in `crate::frontend::stmt`) — are deliberately simplified; see
//! each arm's comment for the exact simplification and why it is safe for a
//! static data-flow reading of the code. Mirrors `lang_rust::frontend::expr`.

use lib_ruby_parser::{nodes, Loc, Node};
use uniflow_hir::{BinaryOp, CallExpr, CallTarget, CollectionKind, Expr, LValue, LiteralKind, SymbolKind};
use uniflow_parser_core::{span_from_offsets, ModuleBuilder};

use crate::frontend::env::RubyEnv;
use crate::frontend::functions::lower_closure_body;

pub(crate) fn span(builder: &ModuleBuilder, source: &str, loc: &Loc) -> uniflow_hir::Span {
    span_from_offsets(builder.file_id(), source, loc.begin, loc.end)
}

fn opaque(builder: &mut ModuleBuilder, source: &str, loc: &Loc, text: impl Into<String>) -> Expr {
    Expr::Opaque { id: builder.alloc_expr_id(), text: text.into(), span: span(builder, source, loc) }
}

fn opaque_node(builder: &mut ModuleBuilder, source: &str, node: &Node) -> Expr {
    opaque(builder, source, node.expression(), format!("<unsupported:{}>", node.str_type()))
}

fn literal(builder: &mut ModuleBuilder, source: &str, loc: &Loc, kind: LiteralKind) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind, span: span(builder, source, loc) }
}

fn null_literal(builder: &mut ModuleBuilder, source: &str, loc: &Loc) -> Expr {
    literal(builder, source, loc, LiteralKind::Null)
}

/// Resolves a plain identifier read to whichever symbol is currently bound
/// to it (allocating a closure capture if it crosses a function boundary),
/// falling back to a fresh, unbound symbol for a genuinely free name (a
/// same-file item read as a bare value, an undeclared identifier) — treated
/// as an opaque-but-trackable value rather than an error. The symbol's own
/// name is always the RAW identifier text (never a resolved qualified
/// name), since this is also the identity `value_names`/`index_sinks`
/// base-name matching keys off (see `crate::frontend::env`'s module doc
/// comment on why `DB`/`session`/`cache` must resolve this way).
pub(crate) fn resolve_identifier(builder: &mut ModuleBuilder, env: &mut RubyEnv, name: &str, kind: SymbolKind) -> uniflow_hir::SymbolId {
    if let Some(symbol) = env.resolve(builder, name) {
        return symbol;
    }
    let symbol = builder.add_symbol(name, kind);
    env.declare(name, symbol);
    symbol
}

/// Resolves-or-declares a local variable's own symbol, reusing the existing
/// binding across a reassignment (`x = 1; x = 2` mutates the same slot,
/// unlike Rust's shadowing `let`) and correctly registering a closure
/// capture when the name already lives in an enclosing function/block (a
/// Ruby block can both read AND write an outer local).
pub(crate) fn resolve_or_declare_local(builder: &mut ModuleBuilder, env: &mut RubyEnv, name: &str) -> uniflow_hir::SymbolId {
    resolve_identifier(builder, env, name, SymbolKind::Local)
}

fn self_read(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, loc: &Loc) -> Expr {
    let symbol = resolve_identifier(builder, env, "self", SymbolKind::Param);
    Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, loc) }
}

/// True for a `Send` with no receiver, no arguments, and no explicit
/// parentheses — Ruby's syntactically ambiguous "either a local variable
/// read or a zero-arg method call" identifier, which the parser can only
/// disambiguate using its own static assignment history. Since this
/// frontend keeps no such history, both readings collapse to the same
/// value-read treatment: [`lower_expr`] resolves this exactly like a plain
/// identifier (see the module doc comment on `crate::frontend::env` for why
/// this is also what the `index_sinks`/`named_value_sources` mechanisms
/// need `session`/`DB`/`cache`/`params` to look like).
fn is_bare_name(send: &nodes::Send) -> bool {
    send.recv.is_none() && send.args.is_empty() && send.begin_l.is_none()
}

/// The qualified-name "provenance" of a value, recovered by walking the
/// (pre-lowering) node that *produced* it — a same-file item, a qualified
/// constant path (`ActiveRecord::Base`), a local binding's own recorded
/// qualifier, or a call chain whose own callee was qualified (so
/// `ActiveRecord::Base.connection.execute(event)` names
/// `ActiveRecord.Base.connection.execute`, matching how
/// `lang_rust::frontend::expr::expression_qualifier` walks a builder-style
/// method chain). Falls back to the raw bare name for an unresolved bare
/// identifier or constant — exactly like Rust's fallback for an unresolved
/// external crate name (`std`/`tokio`) — since these are never locally
/// declared in the analyzed file.
pub(crate) fn node_qualifier(env: &RubyEnv, node: &Node) -> Option<String> {
    match node {
        Node::Const(c) => Some(const_qualifier(env, c)),
        Node::Send(s) if is_bare_name(s) => Some(bare_name_qualifier(env, &s.method_name)),
        Node::Send(s) => match &s.recv {
            Some(inner) => Some(format!("{}.{}", node_qualifier(env, inner)?, s.method_name)),
            None => Some(s.method_name.clone()),
        },
        Node::CSend(s) => Some(format!("{}.{}", node_qualifier(env, &s.recv)?, s.method_name)),
        Node::Lvar(l) => {
            let symbol = env.peek(&l.name)?;
            env.value_qualifier(symbol).map(str::to_string)
        }
        Node::Self_(_) => env.self_type().map(str::to_string),
        Node::Begin(b) if b.statements.len() == 1 => node_qualifier(env, &b.statements[0]),
        Node::KwBegin(b) if b.statements.len() == 1 => node_qualifier(env, &b.statements[0]),
        _ => None,
    }
}

fn bare_name_qualifier(env: &RubyEnv, name: &str) -> String {
    env.top_level_item(name).map(str::to_string).unwrap_or_else(|| name.to_string())
}

fn const_qualifier(env: &RubyEnv, c: &nodes::Const) -> String {
    match &c.scope {
        None => bare_name_qualifier(env, &c.name),
        Some(scope) => match node_qualifier(env, scope) {
            Some(prefix) => format!("{prefix}.{}", c.name),
            None => c.name.clone(),
        },
    }
}

pub(crate) fn bytes_to_string(bytes: &lib_ruby_parser::Bytes) -> String {
    bytes.to_string_lossy()
}

/// Splits an argument list into positional-with-names arguments, flattening
/// a trailing implicit keyword-argument node (`Node::Kwargs`, produced for
/// `foo(a, unit: b)`'s trailing `unit: b`) into individually named
/// arguments — mirroring how `lang_python` populates `arg_names` for its own
/// keyword-argument calling convention, so a sink like `number_to_currency`
/// can address `unit:` via a `named:unit` input port.
fn lower_call_args(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, args: &[Node]) -> (Vec<Expr>, Vec<Option<String>>) {
    let mut values = Vec::with_capacity(args.len());
    let mut names = Vec::with_capacity(args.len());
    for arg in args {
        match arg {
            Node::Kwargs(k) => {
                for pair in &k.pairs {
                    match pair {
                        Node::Pair(p) => {
                            let key_name = match p.key.as_ref() {
                                Node::Sym(s) => Some(bytes_to_string(&s.name)),
                                _ => None,
                            };
                            values.push(lower_expr(builder, env, source, &p.value));
                            names.push(key_name);
                        }
                        Node::Kwsplat(ks) => {
                            values.push(lower_expr(builder, env, source, &ks.value));
                            names.push(None);
                        }
                        other => {
                            values.push(lower_expr(builder, env, source, other));
                            names.push(None);
                        }
                    }
                }
            }
            Node::Splat(sp) => {
                values.push(lower_optional(builder, env, source, sp.value.as_deref(), &sp.expression_l));
                names.push(None);
            }
            Node::BlockPass(bp) => {
                values.push(lower_optional(builder, env, source, bp.value.as_deref(), &bp.expression_l));
                names.push(None);
            }
            other => {
                values.push(lower_expr(builder, env, source, other));
                names.push(None);
            }
        }
    }
    (values, names)
}

fn lower_optional(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: Option<&Node>, fallback_loc: &Loc) -> Expr {
    match node {
        Some(node) => lower_expr(builder, env, source, node),
        None => null_literal(builder, source, fallback_loc),
    }
}

/// Lowers a real method call (`Send`/`CSend` with a receiver, arguments, or
/// explicit parentheses — i.e. anything [`is_bare_name`] rejects — plus
/// `Super`/`ZSuper`, always as a call regardless of arity). Used both by
/// [`lower_expr`]'s ordinary dispatch and, forced, by the `Block`/`Numblock`
/// lowering below (a block always attaches to a real call, even when its
/// own callee node would otherwise look like a bare identifier, e.g. `loop {
/// }`).
pub(crate) fn lower_call_forced(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: &Node) -> Expr {
    match node {
        Node::Send(s) => {
            let (args, arg_names) = lower_call_args(builder, env, source, &s.args);
            let (target, receiver, qualifier_is_explicit) = match &s.recv {
                Some(recv) => {
                    let qualifier = node_qualifier(env, recv);
                    let receiver_expr = lower_expr(builder, env, source, recv);
                    let target = match qualifier {
                        Some(q) => CallTarget::Named(format!("{q}.{}", s.method_name)),
                        None => CallTarget::Named(s.method_name.clone()),
                    };
                    (target, Some(Box::new(receiver_expr)), true)
                }
                None => {
                    let name = bare_name_qualifier(env, &s.method_name);
                    (CallTarget::Named(name), None, false)
                }
            };
            Expr::Call(CallExpr { id: builder.alloc_expr_id(), target, receiver, qualifier_is_explicit, args, arg_names, span: span(builder, source, &s.expression_l) })
        }
        Node::CSend(s) => {
            let (args, arg_names) = lower_call_args(builder, env, source, &s.args);
            let qualifier = node_qualifier(env, &s.recv);
            let receiver_expr = lower_expr(builder, env, source, &s.recv);
            let target = match qualifier {
                Some(q) => CallTarget::Named(format!("{q}.{}", s.method_name)),
                None => CallTarget::Named(s.method_name.clone()),
            };
            Expr::Call(CallExpr { id: builder.alloc_expr_id(), target, receiver: Some(Box::new(receiver_expr)), qualifier_is_explicit: true, args, arg_names, span: span(builder, source, &s.expression_l) })
        }
        Node::Super(s) => {
            let (args, arg_names) = lower_call_args(builder, env, source, &s.args);
            Expr::Call(CallExpr { id: builder.alloc_expr_id(), target: CallTarget::Named("super".to_string()), receiver: None, qualifier_is_explicit: false, args, arg_names, span: span(builder, source, &s.expression_l) })
        }
        Node::ZSuper(s) => Expr::Call(CallExpr { id: builder.alloc_expr_id(), target: CallTarget::Named("super".to_string()), receiver: None, qualifier_is_explicit: false, args: Vec::new(), arg_names: Vec::new(), span: span(builder, source, &s.expression_l) }),
        Node::Yield(y) => lower_yield(builder, env, source, y),
        _ => opaque_node(builder, source, node),
    }
}

fn lower_yield(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, y: &nodes::Yield) -> Expr {
    let (args, arg_names) = lower_call_args(builder, env, source, &y.args);
    Expr::Call(CallExpr { id: builder.alloc_expr_id(), target: CallTarget::Named("yield".to_string()), receiver: None, qualifier_is_explicit: false, args, arg_names, span: span(builder, source, &y.expression_l) })
}

/// The value a `Begin`/`KwBegin` statement sequence contributes when read as
/// a sub-expression (used both for `(a; b)` grouping and for a `#{ ... }`
/// string-interpolation part, which the parser always wraps in a `Begin`):
/// its trailing statement's value, or unit (`Null`) when empty. Earlier
/// statements are lowered and dropped — same documented simplification as
/// `lang_rust::frontend::expr::block_tail_value`.
fn begin_tail_value(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, statements: &[Node], loc: &Loc) -> Expr {
    if statements.is_empty() {
        return null_literal(builder, source, loc);
    }
    env.push_block();
    for stmt in &statements[..statements.len() - 1] {
        let _ = crate::frontend::stmt::lower_stmt(builder, env, source, stmt);
    }
    let value = lower_expr(builder, env, source, &statements[statements.len() - 1]);
    env.pop_block();
    value
}

fn lower_string_parts(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, parts: &[Node], loc: &Loc) -> Expr {
    let parts: Vec<Expr> = parts
        .iter()
        .map(|part| match part {
            Node::Str(s) => literal(builder, source, &s.expression_l, LiteralKind::String(bytes_to_string(&s.value))),
            other => lower_expr(builder, env, source, other),
        })
        .collect();
    if parts.iter().all(|p| matches!(p, Expr::Literal { kind: LiteralKind::String(_), .. })) {
        let combined = parts
            .into_iter()
            .map(|p| match p {
                Expr::Literal { kind: LiteralKind::String(s), .. } => s,
                _ => unreachable!(),
            })
            .collect::<String>();
        return literal(builder, source, loc, LiteralKind::String(combined));
    }
    Expr::Interp { id: builder.alloc_expr_id(), parts, span: span(builder, source, loc) }
}

fn lower_index(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, i: &nodes::Index) -> Expr {
    let base = lower_expr(builder, env, source, &i.recv);
    let index = lower_index_key(builder, env, source, &i.indexes, &i.expression_l);
    Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(index), span: span(builder, source, &i.expression_l) }
}

/// Ruby's `[]`/`[]=` accept any number of index arguments (multi-dimensional
/// or slice-style indexing, e.g. `arr[1, 2]`); the overwhelmingly common
/// single-index case maps directly to `Expr::IndexRead`/`LValue::Index`, and
/// the rare multi-argument form is flattened into one synthetic tuple so its
/// values stay visible rather than being dropped.
fn lower_index_key(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, indexes: &[Node], loc: &Loc) -> Expr {
    match indexes {
        [] => null_literal(builder, source, loc),
        [single] => lower_expr(builder, env, source, single),
        many => {
            let elements = many.iter().map(|n| lower_expr(builder, env, source, n)).collect();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Tuple, elements, span: span(builder, source, loc) }
        }
    }
}

fn map_binary_operator(op: &str) -> BinaryOp {
    match op {
        "+" => BinaryOp::Add,
        "-" => BinaryOp::Sub,
        "*" => BinaryOp::Mul,
        "/" => BinaryOp::Div,
        "%" => BinaryOp::Mod,
        "&" => BinaryOp::BitAnd,
        "|" => BinaryOp::BitOr,
        "^" => BinaryOp::BitXor,
        "==" | "===" => BinaryOp::Eq,
        "!=" => BinaryOp::Ne,
        "<" => BinaryOp::Lt,
        "<=" => BinaryOp::Le,
        ">" => BinaryOp::Gt,
        ">=" => BinaryOp::Ge,
        // Exponentiation, shifts, spaceship (`**`/`<<`/`>>`/`<=>`), regex
        // match (`=~`/`!~`): no dedicated HIR operator — `Add` keeps both
        // operands flowing through a generic combination rather than making
        // a correctness claim about the operator's actual semantics,
        // mirroring `lang_rust::frontend::expr::map_binary_operator`'s
        // treatment of `<<`/`>>`/`**`.
        _ => BinaryOp::Add,
    }
}

/// Ruby has no dedicated arithmetic/comparison/bitwise "binary expression"
/// syntax at all — `a + b`, `a == b`, `a <=> b`, unary `-a`/`!a` all parse as
/// ordinary `Send`/`CSend` method calls (`+`/`==`/`-@`/`!` are the literal
/// method names; only `&&`/`||`/`and`/`or` get their own `And`/`Or` node —
/// see this crate's exploratory parser dump). Recognizing these named-
/// operator sends and lowering them as `Expr::Binary`/`Expr::Unary` (instead
/// of an ordinary `Expr::Call`) is not a nicety: `uniflow_lowering`'s shared
/// engine keys its generic `__uniflow.binary.division` (divide-by-zero) and
/// `__uniflow.compose.string` (string concatenation) composition mechanisms
/// specifically off `Expr::Binary`, so a Ruby `/`/`+` left as a plain method
/// call would silently miss both.
const BINARY_OPERATOR_METHODS: &[&str] = &["+", "-", "*", "/", "%", "**", "==", "===", "!=", "<", "<=", ">", ">=", "<=>", "&", "|", "^", "<<", ">>", "=~", "!~"];

fn lower_operator_send(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, s: &nodes::Send) -> Option<Expr> {
    let recv = s.recv.as_deref()?;
    let at = span(builder, source, &s.expression_l);
    match (s.method_name.as_str(), s.args.as_slice()) {
        ("-@", []) => {
            let inner = lower_expr(builder, env, source, recv);
            Some(Expr::Unary { id: builder.alloc_expr_id(), op: uniflow_hir::UnaryOp::Neg, expr: Box::new(inner), span: at })
        }
        ("+@", []) => Some(lower_expr(builder, env, source, recv)),
        ("!", []) => {
            let inner = lower_expr(builder, env, source, recv);
            Some(Expr::Unary { id: builder.alloc_expr_id(), op: uniflow_hir::UnaryOp::Not, expr: Box::new(inner), span: at })
        }
        ("~", []) => {
            let inner = lower_expr(builder, env, source, recv);
            Some(Expr::Unary { id: builder.alloc_expr_id(), op: uniflow_hir::UnaryOp::BitNot, expr: Box::new(inner), span: at })
        }
        (op, [arg]) if BINARY_OPERATOR_METHODS.contains(&op) => {
            let lhs = lower_expr(builder, env, source, recv);
            let rhs = lower_expr(builder, env, source, arg);
            Some(Expr::Binary { id: builder.alloc_expr_id(), op: map_binary_operator(op), lhs: Box::new(lhs), rhs: Box::new(rhs), span: at })
        }
        _ => None,
    }
}

/// Converts an `OpAsgn`/`AndAsgn`/`OrAsgn` assignment-target node (always a
/// `Lvasgn`/`Ivasgn`/`Cvasgn`/`Gvasgn`/`Casgn` with `value: None`, or an
/// `Index`/attribute `Send`) into the `LValue` it names, without declaring a
/// fresh binding — the compound assignment always reads the *existing*
/// value first.
pub(crate) fn compound_target_lvalue(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: &Node) -> LValue {
    match node {
        Node::Lvasgn(l) => LValue::Var(resolve_or_declare_local(builder, env, &l.name)),
        Node::Ivasgn(i) => {
            env.record_field(i.name.clone());
            LValue::Field { base: Box::new(self_read(builder, env, source, &i.expression_l)), field: i.name.clone() }
        }
        Node::Cvasgn(c) => {
            env.record_field(c.name.clone());
            LValue::Field { base: Box::new(self_read(builder, env, source, &c.expression_l)), field: c.name.clone() }
        }
        Node::Gvasgn(g) => LValue::Var(resolve_or_declare_local(builder, env, &g.name)),
        Node::Casgn(c) => LValue::Var(resolve_or_declare_local(builder, env, &c.name)),
        Node::Index(i) => {
            let base = lower_expr(builder, env, source, &i.recv);
            let index = lower_index_key(builder, env, source, &i.indexes, &i.expression_l);
            LValue::Index { base: Box::new(base), index: Box::new(index) }
        }
        Node::Send(s) => {
            // An attribute-writer compound assignment (`obj.attr += 1`)
            // reads via `obj.attr` and re-assigns via the same field name —
            // modeled as a synthetic field on the receiver rather than a
            // method round-trip through the real `attr=`/`attr` methods.
            let base = s.recv.as_deref().map(|r| lower_expr(builder, env, source, r)).unwrap_or_else(|| self_read(builder, env, source, &s.expression_l));
            LValue::Field { base: Box::new(base), field: s.method_name.clone() }
        }
        _ => LValue::Var(builder.add_symbol("$compound_target", SymbolKind::Local)),
    }
}

fn lvalue_to_read_expr(builder: &mut ModuleBuilder, lvalue: &LValue, at: uniflow_hir::Span) -> Expr {
    match lvalue {
        LValue::Var(symbol) => Expr::VarRef { id: builder.alloc_expr_id(), symbol: *symbol, span: at },
        LValue::Field { base, field } => Expr::FieldRead { id: builder.alloc_expr_id(), base: base.clone(), field: field.clone(), span: at },
        LValue::Index { base, index } => Expr::IndexRead { id: builder.alloc_expr_id(), base: base.clone(), index: index.clone(), span: at },
    }
}

/// `a op= b` (`OpAsgn`), `a &&= b` (`AndAsgn`), `a ||= b` (`OrAsgn`) all
/// read the current value of `a` and conditionally combine it with `b`.
/// Real short-circuit semantics ("only assign when the current value is
/// falsy/truthy") are not modeled — both the kept-old-value and the
/// newly-assigned-value cases are merged via `Conditional` so a checker
/// still sees both, the same "visit and merge every branch" treatment
/// `lang_rust::frontend::expr::lower_match_value` uses for `match`.
pub(crate) fn lower_compound_assign(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, target: &Node, rhs: &Node, op: Option<&str>, loc: &Loc) -> Expr {
    let lvalue = compound_target_lvalue(builder, env, source, target);
    let expr_span = span(builder, source, loc);
    let current = lvalue_to_read_expr(builder, &lvalue, expr_span);
    let new_value = lower_expr(builder, env, source, rhs);
    let combined = match op {
        Some(op) => Expr::Binary { id: builder.alloc_expr_id(), op: map_binary_operator(op), lhs: Box::new(current.clone()), rhs: Box::new(new_value), span: expr_span },
        None => Expr::Conditional { id: builder.alloc_expr_id(), cond: Box::new(current.clone()), then_expr: Box::new(new_value), else_expr: Box::new(current), span: expr_span },
    };
    Expr::Assign { id: builder.alloc_expr_id(), lhs: lvalue, rhs: Box::new(combined), span: expr_span }
}

fn parse_int(value: &str, negative: bool) -> i64 {
    let cleaned: String = value.chars().filter(|c| *c != '_').collect();
    let parsed = cleaned.parse::<i64>().unwrap_or_default();
    if negative { -parsed } else { parsed }
}

fn parse_float(value: &str, negative: bool) -> f64 {
    let cleaned: String = value.chars().filter(|c| *c != '_').collect();
    let parsed = cleaned.parse::<f64>().unwrap_or_default();
    if negative { -parsed } else { parsed }
}

/// Lowers the `call`+`args`+`body` of a `Block`/`Numblock` node (a
/// `do...end`/`{}` block attached to a method call — Ruby's closure
/// mechanism; `each`/`map`/`select`-with-a-block is idiomatic control flow,
/// modeled as `Expr::Lambda` the same way a Rust closure is) into the
/// underlying call with the lambda appended as its final argument — an
/// ordinary argument position, so the generic call-argument taint/capture
/// machinery already threads it through with no special-casing needed
/// (matches how `lang_javascript` lowers a callback argument).
pub(crate) fn lower_block_like(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, call: &Node, args_node: Option<&Node>, body_node: Option<&Node>, numargs: u8, loc: &Loc) -> Expr {
    if matches!(call, Node::Lambda(_)) {
        let (params, captures, body) = lower_closure_body(builder, env, source, args_node, body_node, numargs);
        return Expr::Lambda { id: builder.alloc_expr_id(), params, captures: captures.clone(), body, span: span(builder, source, loc) };
    }
    let (params, captures, body) = lower_closure_body(builder, env, source, args_node, body_node, numargs);
    let lambda = Expr::Lambda { id: builder.alloc_expr_id(), params, captures, body, span: span(builder, source, loc) };
    let call_expr = lower_call_forced(builder, env, source, call);
    match call_expr {
        Expr::Call(mut call_expr) => {
            call_expr.args.push(lambda);
            call_expr.arg_names.push(None);
            call_expr.span = span(builder, source, loc);
            Expr::Call(call_expr)
        }
        other => other,
    }
}

pub(crate) fn lower_expr(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, node: &Node) -> Expr {
    match node {
        Node::Int(i) => literal(builder, source, &i.expression_l, LiteralKind::Int(parse_int(&i.value, i.operator_l.is_some()))),
        Node::Float(f) => literal(builder, source, &f.expression_l, LiteralKind::Float(parse_float(&f.value, f.operator_l.is_some()))),
        Node::Str(s) => literal(builder, source, &s.expression_l, LiteralKind::String(bytes_to_string(&s.value))),
        Node::Sym(s) => literal(builder, source, &s.expression_l, LiteralKind::String(bytes_to_string(&s.name))),
        Node::Dstr(d) => lower_string_parts(builder, env, source, &d.parts, &d.expression_l),
        Node::Dsym(d) => lower_string_parts(builder, env, source, &d.parts, &d.expression_l),
        Node::Heredoc(h) => lower_string_parts(builder, env, source, &h.parts, &h.expression_l),
        Node::XHeredoc(h) => lower_string_parts(builder, env, source, &h.parts, &h.expression_l),
        Node::Xstr(x) => lower_string_parts(builder, env, source, &x.parts, &x.expression_l),
        Node::Regexp(r) => lower_string_parts(builder, env, source, &r.parts, &r.expression_l),
        Node::True(t) => literal(builder, source, &t.expression_l, LiteralKind::Bool(true)),
        Node::False(f) => literal(builder, source, &f.expression_l, LiteralKind::Bool(false)),
        Node::Nil(n) => literal(builder, source, &n.expression_l, LiteralKind::Null),
        Node::Array(a) => {
            let elements = a.elements.iter().map(|e| lower_expr(builder, env, source, e)).collect();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Array, elements, span: span(builder, source, &a.expression_l) }
        }
        Node::Hash(h) => {
            let mut elements = Vec::with_capacity(h.pairs.len() * 2);
            for pair in &h.pairs {
                match pair {
                    Node::Pair(p) => {
                        elements.push(lower_expr(builder, env, source, &p.key));
                        elements.push(lower_expr(builder, env, source, &p.value));
                    }
                    Node::Kwsplat(ks) => elements.push(lower_expr(builder, env, source, &ks.value)),
                    other => elements.push(lower_expr(builder, env, source, other)),
                }
            }
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Map, elements, span: span(builder, source, &h.expression_l) }
        }
        Node::Irange(r) => {
            let low = r.left.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            let high = r.right.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            Expr::Range { id: builder.alloc_expr_id(), low: Box::new(low), high: Box::new(high), exclusive: false, span: span(builder, source, &r.expression_l) }
        }
        Node::Erange(r) => {
            let low = r.left.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            let high = r.right.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            Expr::Range { id: builder.alloc_expr_id(), low: Box::new(low), high: Box::new(high), exclusive: true, span: span(builder, source, &r.expression_l) }
        }
        Node::IFlipFlop(r) => {
            let low = r.left.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            let high = r.right.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            Expr::Range { id: builder.alloc_expr_id(), low: Box::new(low), high: Box::new(high), exclusive: false, span: span(builder, source, &r.expression_l) }
        }
        Node::EFlipFlop(r) => {
            let low = r.left.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            let high = r.right.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &r.expression_l));
            Expr::Range { id: builder.alloc_expr_id(), low: Box::new(low), high: Box::new(high), exclusive: true, span: span(builder, source, &r.expression_l) }
        }
        Node::Index(i) => lower_index(builder, env, source, i),
        Node::IndexAsgn(i) => {
            let base = lower_expr(builder, env, source, &i.recv);
            let index = lower_index_key(builder, env, source, &i.indexes, &i.expression_l);
            let lvalue = LValue::Index { base: Box::new(base), index: Box::new(index) };
            let rhs = lower_optional(builder, env, source, i.value.as_deref(), &i.expression_l);
            Expr::Assign { id: builder.alloc_expr_id(), lhs: lvalue, rhs: Box::new(rhs), span: span(builder, source, &i.expression_l) }
        }
        Node::Lvasgn(l) => {
            let symbol = resolve_or_declare_local(builder, env, &l.name);
            let rhs = lower_optional(builder, env, source, l.value.as_deref(), &l.expression_l);
            if let Some(qualifier) = l.value.as_deref().and_then(|v| node_qualifier(env, v)) {
                env.set_value_qualifier(symbol, qualifier);
            }
            Expr::Assign { id: builder.alloc_expr_id(), lhs: LValue::Var(symbol), rhs: Box::new(rhs), span: span(builder, source, &l.expression_l) }
        }
        Node::Ivasgn(i) => {
            env.record_field(i.name.clone());
            let base = self_read(builder, env, source, &i.expression_l);
            let rhs = lower_optional(builder, env, source, i.value.as_deref(), &i.expression_l);
            Expr::Assign { id: builder.alloc_expr_id(), lhs: LValue::Field { base: Box::new(base), field: i.name.clone() }, rhs: Box::new(rhs), span: span(builder, source, &i.expression_l) }
        }
        Node::Cvasgn(c) => {
            env.record_field(c.name.clone());
            let base = self_read(builder, env, source, &c.expression_l);
            let rhs = lower_optional(builder, env, source, c.value.as_deref(), &c.expression_l);
            Expr::Assign { id: builder.alloc_expr_id(), lhs: LValue::Field { base: Box::new(base), field: c.name.clone() }, rhs: Box::new(rhs), span: span(builder, source, &c.expression_l) }
        }
        Node::Gvasgn(g) => {
            let symbol = resolve_or_declare_local(builder, env, &g.name);
            let rhs = lower_optional(builder, env, source, g.value.as_deref(), &g.expression_l);
            Expr::Assign { id: builder.alloc_expr_id(), lhs: LValue::Var(symbol), rhs: Box::new(rhs), span: span(builder, source, &g.expression_l) }
        }
        Node::Casgn(c) => {
            let symbol = resolve_or_declare_local(builder, env, &c.name);
            let rhs = lower_optional(builder, env, source, c.value.as_deref(), &c.expression_l);
            Expr::Assign { id: builder.alloc_expr_id(), lhs: LValue::Var(symbol), rhs: Box::new(rhs), span: span(builder, source, &c.expression_l) }
        }
        Node::OpAsgn(o) => lower_compound_assign(builder, env, source, &o.recv, &o.value, Some(&o.operator), &o.expression_l),
        Node::AndAsgn(a) => lower_compound_assign(builder, env, source, &a.recv, &a.value, None, &a.expression_l),
        Node::OrAsgn(o) => lower_compound_assign(builder, env, source, &o.recv, &o.value, None, &o.expression_l),
        Node::Lvar(l) => {
            let symbol = resolve_identifier(builder, env, &l.name, SymbolKind::Local);
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, &l.expression_l) }
        }
        Node::Ivar(i) => {
            env.record_field(i.name.clone());
            let base = self_read(builder, env, source, &i.expression_l);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: i.name.clone(), span: span(builder, source, &i.expression_l) }
        }
        Node::Cvar(c) => {
            env.record_field(c.name.clone());
            let base = self_read(builder, env, source, &c.expression_l);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: c.name.clone(), span: span(builder, source, &c.expression_l) }
        }
        Node::Gvar(g) => {
            let symbol = resolve_identifier(builder, env, &g.name, SymbolKind::Global);
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, &g.expression_l) }
        }
        // A Ruby constant is not a mutable local variable.  Lowering an
        // unscoped class/module constant such as `Native` as a `VarRef`
        // caused the shared call resolver to infer a synthetic receiver type
        // (`Native.native.Native`) and prepend it to an already-qualified
        // `native.Native.consume` target.  Preserve every constant as an
        // opaque, stable qualified value instead.  It keeps `Native.foo`
        // statically resolvable while avoiding a false local binding and is
        // also correct for scoped constants (`Outer::Native`).
        Node::Const(c) => opaque(builder, source, &c.expression_l, const_qualifier(env, c)),
        Node::Self_(s) => self_read(builder, env, source, &s.expression_l),
        Node::And(a) => {
            let lhs = lower_expr(builder, env, source, &a.lhs);
            let rhs = lower_expr(builder, env, source, &a.rhs);
            Expr::Binary { id: builder.alloc_expr_id(), op: BinaryOp::And, lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, &a.expression_l) }
        }
        Node::Or(o) => {
            let lhs = lower_expr(builder, env, source, &o.lhs);
            let rhs = lower_expr(builder, env, source, &o.rhs);
            Expr::Binary { id: builder.alloc_expr_id(), op: BinaryOp::Or, lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, &o.expression_l) }
        }
        Node::Send(s) => {
            if let Some(operator_expr) = lower_operator_send(builder, env, source, s) {
                operator_expr
            } else if is_bare_name(s) {
                let symbol = resolve_identifier(builder, env, &s.method_name, SymbolKind::Global);
                Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, &s.expression_l) }
            } else {
                lower_call_forced(builder, env, source, node)
            }
        }
        Node::CSend(_) | Node::Super(_) | Node::ZSuper(_) => lower_call_forced(builder, env, source, node),
        Node::Yield(y) => lower_yield(builder, env, source, y),
        Node::Block(b) => lower_block_like(builder, env, source, &b.call, b.args.as_deref(), b.body.as_deref(), 0, &b.expression_l),
        Node::Numblock(b) => lower_block_like(builder, env, source, &b.call, None, Some(&b.body), b.numargs, &b.expression_l),
        Node::Begin(b) => begin_tail_value(builder, env, source, &b.statements, &b.expression_l),
        Node::KwBegin(b) => begin_tail_value(builder, env, source, &b.statements, &b.expression_l),
        Node::Splat(sp) => lower_optional(builder, env, source, sp.value.as_deref(), &sp.expression_l),
        Node::BlockPass(bp) => lower_optional(builder, env, source, bp.value.as_deref(), &bp.expression_l),
        Node::Kwsplat(ks) => lower_optional(builder, env, source, Some(ks.value.as_ref()), &ks.expression_l),
        // `if`/`case`/`case ... in` used as a nested sub-expression: both/
        // every branch is visited and merged into a right-nested
        // `Conditional` chain (statement position gets full, precise
        // `Stmt::If`/`Stmt::Switch` treatment in `crate::frontend::stmt`) —
        // mirrors `lang_rust::frontend::expr::lower_if_value`/
        // `lower_match_value`.
        Node::If(i) => lower_if_value(builder, env, source, i),
        Node::IfMod(i) => {
            let cond = lower_expr(builder, env, source, &i.cond);
            let then_value = i.if_true.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &i.expression_l));
            let else_value = i.if_false.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &i.expression_l));
            Expr::Conditional { id: builder.alloc_expr_id(), cond: Box::new(cond), then_expr: Box::new(then_value), else_expr: Box::new(else_value), span: span(builder, source, &i.expression_l) }
        }
        Node::Case(c) => lower_case_value(builder, env, source, c),
        // Loops used as a nested sub-expression contribute a unit value in
        // the common case — same documented simplification
        // `lang_rust::frontend::expr` accepts for `while`/`loop`/`for`.
        Node::While(w) => null_literal(builder, source, &w.expression_l),
        Node::Until(u) => null_literal(builder, source, &u.expression_l),
        Node::WhilePost(w) => null_literal(builder, source, &w.expression_l),
        Node::UntilPost(u) => null_literal(builder, source, &u.expression_l),
        Node::For(f) => null_literal(builder, source, &f.expression_l),
        Node::Return(r) => opaque(builder, source, &r.expression_l, "return"),
        Node::Break(b) => opaque(builder, source, &b.expression_l, "break"),
        Node::Next(n) => opaque(builder, source, &n.expression_l, "next"),
        Node::Redo(r) => opaque(builder, source, &r.expression_l, "redo"),
        Node::Retry(r) => opaque(builder, source, &r.expression_l, "retry"),
        // A pattern-matched value (`expr => pattern`/`expr in pattern`) is
        // read here only for its scrutinee; the pattern's own destructuring
        // bindings only matter in statement position (see
        // `crate::frontend::stmt::lower_case_match_stmt`), matching Rust's
        // `syn::Expr::Let` pass-through in `lower_expr`.
        Node::MatchPattern(m) => lower_expr(builder, env, source, &m.value),
        Node::MatchPatternP(m) => lower_expr(builder, env, source, &m.value),
        Node::MatchWithLvasgn(m) => {
            let lhs = lower_expr(builder, env, source, &m.re);
            let rhs = lower_expr(builder, env, source, &m.value);
            Expr::Binary { id: builder.alloc_expr_id(), op: BinaryOp::Eq, lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, &m.expression_l) }
        }
        Node::Defined(d) => {
            let _ = lower_expr(builder, env, source, &d.value);
            literal(builder, source, &d.expression_l, LiteralKind::Bool(true))
        }
        _ => opaque_node(builder, source, node),
    }
}

/// Same simplification as `lang_rust::frontend::expr::lower_match_value` for
/// a `case`/`when` used as a nested sub-expression: the scrutinee is reused
/// as every branch's nominal "condition" (a static reading of `Conditional`
/// only needs "the result may carry data from either branch"), and every
/// `when`/`else` value is visited and merged.
fn lower_case_value(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, c: &nodes::Case) -> Expr {
    let scrutinee = c.expr.as_deref().map(|e| lower_expr(builder, env, source, e)).unwrap_or_else(|| null_literal(builder, source, &c.expression_l));
    let case_span = span(builder, source, &c.expression_l);
    let mut acc = c.else_body.as_deref().map(|e| lower_expr(builder, env, source, e)).unwrap_or_else(|| null_literal(builder, source, &c.expression_l));
    for when in c.when_bodies.iter().rev() {
        if let Node::When(w) = when {
            let value = w.body.as_deref().map(|b| lower_expr(builder, env, source, b)).unwrap_or_else(|| null_literal(builder, source, &c.expression_l));
            acc = Expr::Conditional { id: builder.alloc_expr_id(), cond: Box::new(scrutinee.clone()), then_expr: Box::new(value), else_expr: Box::new(acc), span: case_span };
        }
    }
    acc
}

fn lower_if_value(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, i: &nodes::If) -> Expr {
    let cond = lower_expr(builder, env, source, &i.cond);
    let then_value = i.if_true.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &i.expression_l));
    let else_value = i.if_false.as_deref().map(|n| lower_expr(builder, env, source, n)).unwrap_or_else(|| null_literal(builder, source, &i.expression_l));
    Expr::Conditional { id: builder.alloc_expr_id(), cond: Box::new(cond), then_expr: Box::new(then_value), else_expr: Box::new(else_value), span: span(builder, source, &i.expression_l) }
}
