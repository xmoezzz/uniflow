//! Lowers an `oxc_ast` `Expression` into `uniflow_hir::Expr`.
//!
//! Every construct that carries a real runtime value is modeled precisely
//! (identifiers, member/index access, calls with receiver, template
//! literals, binary/assignment/conditional). A handful of constructs this
//! HIR has no native shape for (JSX, class expressions, TS type-assertion
//! wrappers, `yield`/`await`'s suspension semantics) are deliberately
//! simplified — see each arm's comment for the exact simplification and why
//! it is safe for a static data-flow reading of the code.

use oxc_ast::ast::{self as js, Expression};
use oxc_span::{GetSpan, Span as OxcSpan};
use uniflow_hir::{
    BinaryOp, CallExpr, CallTarget, CollectionKind, Expr, LValue, LiteralKind, SymbolKind, UnaryOp,
};
use uniflow_parser_core::{span_from_offsets, ModuleBuilder};

use crate::frontend::decl::require_source;
use crate::frontend::env::JsEnv;
use crate::frontend::functions::lower_function_like;

pub(crate) fn span(builder: &ModuleBuilder, source: &str, oxc_span: OxcSpan) -> uniflow_hir::Span {
    span_from_offsets(builder.file_id(), source, oxc_span.start as usize, oxc_span.end as usize)
}

fn opaque(builder: &mut ModuleBuilder, source: &str, oxc_span: OxcSpan, text: impl Into<String>) -> Expr {
    Expr::Opaque { id: builder.alloc_expr_id(), text: text.into(), span: span(builder, source, oxc_span) }
}

fn literal(builder: &mut ModuleBuilder, source: &str, oxc_span: OxcSpan, kind: LiteralKind) -> Expr {
    Expr::Literal { id: builder.alloc_expr_id(), kind, span: span(builder, source, oxc_span) }
}

/// Resolves a plain identifier read to whichever symbol is currently bound
/// to it (allocating a closure capture if it crosses a function boundary),
/// falling back to a fresh, unbound symbol for a genuinely free name (a
/// global like `console`, `require`, an undeclared identifier) — treating
/// it as an opaque-but-trackable value rather than an error.
pub(crate) fn resolve_identifier(builder: &mut ModuleBuilder, env: &mut JsEnv, name: &str) -> uniflow_hir::SymbolId {
    if let Some(symbol) = env.resolve(builder, name) {
        return symbol;
    }
    let symbol = builder.add_symbol(name, SymbolKind::Global);
    env.declare_var(name, symbol);
    symbol
}

pub(crate) fn lower_expr(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, expr: &Expression) -> Expr {
    match expr {
        Expression::BooleanLiteral(lit) => literal(builder, source, lit.span, LiteralKind::Bool(lit.value)),
        Expression::NullLiteral(lit) => literal(builder, source, lit.span, LiteralKind::Null),
        Expression::NumericLiteral(lit) => literal(builder, source, lit.span, LiteralKind::Float(lit.value)),
        Expression::StringLiteral(lit) => literal(builder, source, lit.span, LiteralKind::String(lit.value.to_string())),
        Expression::BigIntLiteral(lit) => literal(builder, source, lit.span, LiteralKind::String(lit.raw.as_ref().map(|raw| raw.to_string()).unwrap_or_default())),
        Expression::RegExpLiteral(lit) => opaque(builder, source, lit.span, format!("/{:?}/{}", lit.regex.pattern, lit.regex.flags)),
        Expression::Identifier(ident) => {
            let symbol = resolve_identifier(builder, env, ident.name.as_str());
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, ident.span) }
        }
        Expression::Super(sup) => opaque(builder, source, sup.span, "super"),
        Expression::ThisExpression(this) => {
            let symbol = resolve_identifier(builder, env, "this");
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, this.span) }
        }
        Expression::TemplateLiteral(tpl) => lower_template_literal(builder, env, source, tpl),
        Expression::TaggedTemplateExpression(tte) => {
            let tag = lower_expr(builder, env, source, &tte.tag);
            let quasi = lower_template_literal(builder, env, source, &tte.quasi);
            Expr::Call(CallExpr {
                id: builder.alloc_expr_id(),
                target: CallTarget::Dynamic(Box::new(tag)),
                receiver: None,
                qualifier_is_explicit: false,
                args: vec![quasi],
                arg_names: vec![None],
                span: span(builder, source, tte.span),
            })
        }
        Expression::ArrayExpression(arr) => {
            let elements = arr
                .elements
                .iter()
                .map(|element| match element {
                    js::ArrayExpressionElement::SpreadElement(spread) => lower_expr(builder, env, source, &spread.argument),
                    js::ArrayExpressionElement::Elision(elision) => literal(builder, source, elision.span, LiteralKind::Null),
                    _ => lower_expr(builder, env, source, element.as_expression().expect("non-spread/elision array element is an expression")),
                })
                .collect();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Array, elements, span: span(builder, source, arr.span) }
        }
        Expression::ObjectExpression(object) => {
            let mut elements = Vec::with_capacity(object.properties.len() * 2);
            for property in &object.properties {
                match property {
                    js::ObjectPropertyKind::ObjectProperty(prop) => {
                        elements.push(lower_property_key(builder, env, source, &prop.key));
                        elements.push(lower_expr(builder, env, source, &prop.value));
                    }
                    js::ObjectPropertyKind::SpreadProperty(spread) => {
                        elements.push(lower_expr(builder, env, source, &spread.argument));
                    }
                }
            }
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Map, elements, span: span(builder, source, object.span) }
        }
        Expression::ArrowFunctionExpression(arrow) => lower_function_like(
            builder,
            env,
            source,
            &arrow.params,
            arrow.span,
            |builder, env, source| match &arrow.body {
                js::ArrowFunctionBody::FunctionBody(body) => super::stmt::lower_function_body(builder, env, source, body),
                concise => {
                    let concise = concise.as_expression().expect("a non-FunctionBody arrow body is always an expression");
                    let value = lower_expr(builder, env, source, concise);
                    let value_span = value.span();
                    uniflow_hir::Block { id: builder.alloc_block_id(), stmts: vec![uniflow_hir::Stmt::Return { id: builder.alloc_stmt_id(), value: Some(value), span: value_span }], span: value_span }
                }
            },
        ),
        Expression::FunctionExpression(function) => lower_function_like(
            builder,
            env,
            source,
            &function.params,
            function.span,
            |builder, env, source| {
                function.body.as_ref().map(|body| super::stmt::lower_function_body(builder, env, source, body)).unwrap_or_else(|| builder.empty_block())
            },
        ),
        Expression::ClassExpression(class) => opaque(builder, source, class.span, format!("class {}", class.id.as_ref().map(|id| id.name.as_str()).unwrap_or("<anonymous>"))),
        Expression::AssignmentExpression(assign) => {
            let rhs = lower_expr(builder, env, source, &assign.right);
            let (lhs, rhs) = lower_compound_assignment_target(builder, env, source, &assign.left, assign.operator, rhs);
            Expr::Assign { id: builder.alloc_expr_id(), lhs, rhs: Box::new(rhs), span: span(builder, source, assign.span) }
        }
        Expression::AwaitExpression(await_expr) => lower_expr(builder, env, source, &await_expr.argument),
        Expression::BinaryExpression(bin) => {
            let lhs = lower_expr(builder, env, source, &bin.left);
            let rhs = lower_expr(builder, env, source, &bin.right);
            Expr::Binary { id: builder.alloc_expr_id(), op: map_binary_operator(bin.operator), lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, bin.span) }
        }
        Expression::LogicalExpression(logical) => {
            let lhs = lower_expr(builder, env, source, &logical.left);
            let rhs = lower_expr(builder, env, source, &logical.right);
            let op = match logical.operator {
                js::LogicalOperator::And => BinaryOp::And,
                // `??` has no dedicated HIR operator; `Or` is the closest
                // existing operator and keeps both sides reachable for
                // taint purposes (the actual short-circuit nuance between
                // falsy-or and nullish-coalescing is not preserved).
                js::LogicalOperator::Or | js::LogicalOperator::Coalesce => BinaryOp::Or,
            };
            Expr::Binary { id: builder.alloc_expr_id(), op, lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, logical.span) }
        }
        Expression::UnaryExpression(unary) => {
            let inner = lower_expr(builder, env, source, &unary.argument);
            let op = match unary.operator {
                js::UnaryOperator::UnaryPlus => return inner,
                js::UnaryOperator::UnaryNegation => UnaryOp::Neg,
                js::UnaryOperator::LogicalNot => UnaryOp::Not,
                js::UnaryOperator::BitwiseNot => UnaryOp::BitNot,
                js::UnaryOperator::Typeof | js::UnaryOperator::Void | js::UnaryOperator::Delete => {
                    return opaque(builder, source, unary.span, format!("{:?}", unary.operator));
                }
            };
            Expr::Unary { id: builder.alloc_expr_id(), op, expr: Box::new(inner), span: span(builder, source, unary.span) }
        }
        Expression::UpdateExpression(update) => {
            let target = lower_simple_assignment_target(builder, env, source, &update.argument);
            let op = match (update.operator, update.prefix) {
                (js::UpdateOperator::Increment, true) => UnaryOp::PreIncrement,
                (js::UpdateOperator::Increment, false) => UnaryOp::PostIncrement,
                (js::UpdateOperator::Decrement, true) => UnaryOp::PreDecrement,
                (js::UpdateOperator::Decrement, false) => UnaryOp::PostDecrement,
            };
            Expr::Unary { id: builder.alloc_expr_id(), op, expr: Box::new(target), span: span(builder, source, update.span) }
        }
        Expression::CallExpression(call) => lower_call(builder, env, source, call),
        Expression::NewExpression(new_expr) => {
            let args = lower_arguments(builder, env, source, &new_expr.arguments);
            let type_name = callee_type_name(&new_expr.callee);
            Expr::New { id: builder.alloc_expr_id(), type_name, args, span: span(builder, source, new_expr.span) }
        }
        Expression::ConditionalExpression(cond) => {
            let test = lower_expr(builder, env, source, &cond.test);
            let consequent = lower_expr(builder, env, source, &cond.consequent);
            let alternate = lower_expr(builder, env, source, &cond.alternate);
            Expr::Conditional {
                id: builder.alloc_expr_id(),
                cond: Box::new(test),
                then_expr: Box::new(consequent),
                else_expr: Box::new(alternate),
                span: span(builder, source, cond.span),
            }
        }
        Expression::SequenceExpression(seq) => {
            let elements = seq.expressions.iter().map(|item| lower_expr(builder, env, source, item)).collect();
            Expr::Collection { id: builder.alloc_expr_id(), container: CollectionKind::Tuple, elements, span: span(builder, source, seq.span) }
        }
        Expression::ParenthesizedExpression(paren) => lower_expr(builder, env, source, &paren.expression),
        Expression::ChainExpression(chain) => lower_chain_element(builder, env, source, &chain.expression),
        Expression::YieldExpression(yield_expr) => match &yield_expr.argument {
            Some(inner) => lower_expr(builder, env, source, inner),
            None => literal(builder, source, yield_expr.span, LiteralKind::Null),
        },
        Expression::ImportExpression(import_expr) => {
            let source_arg = lower_expr(builder, env, source, &import_expr.source);
            Expr::Call(CallExpr {
                id: builder.alloc_expr_id(),
                target: CallTarget::Named("import".to_string()),
                receiver: None,
                qualifier_is_explicit: false,
                args: vec![source_arg],
                arg_names: vec![None],
                span: span(builder, source, import_expr.span),
            })
        }
        Expression::PrivateInExpression(priv_in) => {
            let rhs = lower_expr(builder, env, source, &priv_in.right);
            let lhs = opaque(builder, source, priv_in.left.span, format!("#{}", priv_in.left.name));
            Expr::Binary { id: builder.alloc_expr_id(), op: BinaryOp::In, lhs: Box::new(lhs), rhs: Box::new(rhs), span: span(builder, source, priv_in.span) }
        }
        Expression::ImportMeta(m) => opaque(builder, source, m.span, "import.meta"),
        Expression::NewTarget(t) => opaque(builder, source, t.span, "new.target"),
        Expression::JSXElement(jsx) => opaque(builder, source, jsx.span, "<jsx-element>"),
        Expression::JSXFragment(jsx) => opaque(builder, source, jsx.span, "<jsx-fragment>"),
        // Type-only wrappers: the runtime value is unaffected, so unwrap and
        // lower the inner expression directly.
        Expression::TSAsExpression(e) => lower_expr(builder, env, source, &e.expression),
        Expression::TSSatisfiesExpression(e) => lower_expr(builder, env, source, &e.expression),
        Expression::TSNonNullExpression(e) => lower_expr(builder, env, source, &e.expression),
        Expression::TSInstantiationExpression(e) => lower_expr(builder, env, source, &e.expression),
        Expression::TSTypeAssertion(e) => lower_expr(builder, env, source, &e.expression),
        Expression::V8IntrinsicExpression(e) => opaque(builder, source, e.span, "%intrinsic"),
        // `StaticMemberExpression` / `ComputedMemberExpression` /
        // `PrivateFieldExpression` are flattened into `Expression` itself by
        // oxc's `#[ast]` inherit-variants machinery (same discriminants as
        // `MemberExpression`'s own variants), so they are matched directly
        // here rather than through a nested `MemberExpression` value.
        Expression::StaticMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: member.property.name.to_string(), span: span(builder, source, member.span) }
        }
        Expression::ComputedMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            let index = lower_expr(builder, env, source, &member.expression);
            Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(index), span: span(builder, source, member.span) }
        }
        Expression::PrivateFieldExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: format!("#{}", member.field.name), span: span(builder, source, member.span) }
        }
    }
}

fn lower_chain_element(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, element: &js::ChainElement) -> Expr {
    match element {
        js::ChainElement::CallExpression(call) => lower_call(builder, env, source, call),
        js::ChainElement::TSNonNullExpression(e) => lower_expr(builder, env, source, &e.expression),
        js::ChainElement::StaticMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: member.property.name.to_string(), span: span(builder, source, member.span) }
        }
        js::ChainElement::ComputedMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            let index = lower_expr(builder, env, source, &member.expression);
            Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(index), span: span(builder, source, member.span) }
        }
        js::ChainElement::PrivateFieldExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: format!("#{}", member.field.name), span: span(builder, source, member.span) }
        }
    }
}

fn lower_property_key(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, key: &js::PropertyKey) -> Expr {
    match key {
        js::PropertyKey::StaticIdentifier(ident) => literal(builder, source, ident.span, LiteralKind::String(ident.name.to_string())),
        js::PropertyKey::PrivateIdentifier(ident) => literal(builder, source, ident.span, LiteralKind::String(format!("#{}", ident.name))),
        _ => lower_expr(builder, env, source, key.as_expression().expect("non-identifier property key is an expression")),
    }
}

fn lower_template_literal(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, tpl: &js::TemplateLiteral) -> Expr {
    // `quasis`/`expressions` are two separate ordered lists that must be
    // interleaved back into source order: `quasi[0] expr[0] quasi[1]
    // expr[1] ... quasi[n]` (one more quasi than expression). This directly
    // produces `Expr::Interp`'s documented "literal text and embedded
    // expressions in source order" shape, which `uniflow_lowering` lowers
    // to an ordered `Phi` — exactly what `resolve_string_sequence`
    // (`uniflow_system_graph::ir_utils`) already expects, with no template
    // literal-specific handling needed on that side.
    let mut parts = Vec::with_capacity(tpl.quasis.len() + tpl.expressions.len());
    let mut expressions = tpl.expressions.iter();
    for (index, quasi) in tpl.quasis.iter().enumerate() {
        let text = quasi.value.cooked.as_ref().map(|s| s.to_string()).unwrap_or_default();
        if !text.is_empty() {
            parts.push(literal(builder, source, quasi.span, LiteralKind::String(text)));
        }
        if index < tpl.quasis.len() - 1 {
            if let Some(expression) = expressions.next() {
                parts.push(lower_expr(builder, env, source, expression));
            }
        }
    }
    Expr::Interp { id: builder.alloc_expr_id(), parts, span: span(builder, source, tpl.span) }
}

fn lower_arguments(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, arguments: &[js::Argument]) -> Vec<Expr> {
    arguments
        .iter()
        .map(|argument| match argument {
            js::Argument::SpreadElement(spread) => lower_expr(builder, env, source, &spread.argument),
            _ => lower_expr(builder, env, source, argument.as_expression().expect("non-spread argument is an expression")),
        })
        .collect()
}

/// Global namespace objects a call/member chain can originate from without
/// ever going through `require`/`import` — a large body of existing bundled
/// taint rules matches qualified names like `console.log`/`util.format`
/// against these directly (`^(console[.:][A-Za-z0-9_$]+|util[.:]format)$`).
const WELL_KNOWN_GLOBAL_NAMESPACES: &[&str] = &[
    "console", "JSON", "Math", "Object", "Array", "String", "Number", "Boolean", "Reflect", "Promise", "Symbol", "process", "Buffer", "Date", "RegExp", "Error", "globalThis", "window", "document",
    "location", "navigator", "XMLHttpRequest", "angular",
];

/// The qualified-name "provenance" of a value, if it has one — the same
/// dotted-qualifier text a rule's `regex`/`method_regex` matcher expects
/// (`mysql2.createConnection.query`, `console.log`, `vm.runInNewContext`),
/// recovered by walking the expression that *produced* the value: a
/// `require(...)` call, a well-known global namespace identifier, a member
/// access off an already-qualified value, or a call/`new` whose own callee
/// is qualified — a call's return value inherits its callee's qualifier as
/// its own, so further chaining keeps accumulating
/// (`mysql2.createConnection().query()` becomes
/// `mysql2.createConnection.query`, matching what those rules already
/// expect). `None` for a value with no known static provenance (an ordinary
/// local variable, a function parameter, ...) — such a value still lowers
/// correctly, it just can't be named this precisely.
pub(crate) fn expression_qualifier(env: &JsEnv, expr: &Expression) -> Option<String> {
    match expr {
        Expression::Identifier(ident) => {
            let name = ident.name.as_str();
            match env.import_binding(name) {
                Some(crate::frontend::env::ImportBinding::Namespace(module)) => Some(module.clone()),
                Some(crate::frontend::env::ImportBinding::Named(qualified)) => Some(qualified.clone()),
                None => env
                    .peek(name)
                    .and_then(|symbol| env.value_qualifier(symbol))
                    .map(str::to_string)
                    .or_else(|| WELL_KNOWN_GLOBAL_NAMESPACES.contains(&name).then(|| name.to_string())),
            }
        }
        Expression::StaticMemberExpression(member) => Some(format!("{}.{}", expression_qualifier(env, &member.object)?, member.property.name)),
        // A call's return value inherits its callee's qualifier ONLY when
        // the callee was itself a qualified *member access*
        // (`mysql2.createConnection().query()` -> `mysql2.createConnection.query`,
        // matching existing bundled taint rules for chained DB-client
        // builders). A *bare*-identifier call must NOT propagate this way:
        // `const app = express();` calling the `express` module factory
        // returns an unrelated fresh object (an Express `app` instance),
        // not "the express module" — `app.get(path, handler)` needs its
        // real receiver preserved (see `lower_call`'s route-registration
        // handling), not to collapse into a misleading `express.get` target.
        Expression::CallExpression(call) => {
            if let Some(module) = require_source(expr) {
                return Some(module.to_string());
            }
            match &call.callee {
                Expression::StaticMemberExpression(_) => expression_qualifier(env, &call.callee),
                _ => None,
            }
        }
        Expression::NewExpression(new_expr) => expression_qualifier(env, &new_expr.callee),
        Expression::ParenthesizedExpression(inner) => expression_qualifier(env, &inner.expression),
        _ => None,
    }
}

/// `"a".concat(b, c)` is exactly `"a" + b + c` — String.prototype.concat is
/// real string concatenation, just spelled as a method call. Lowering it as
/// a plain call would hide that from `uniflow_lowering`'s existing (and
/// entirely language-generic) "dynamically composed string" detection,
/// which keys specifically off `Expr::Binary { op: Add, .. }` — so a large
/// body of existing format-string/log-injection taint rules would never see
/// `"prefix".concat(name)` as untrusted the way `"prefix" + name` already is.
/// A conservative, syntax-only check that `expr` is provably string-shaped —
/// `Array.prototype.concat` also exists, and this frontend has no real type
/// inference to tell `"a".concat(b)` (strings) apart from
/// `[1, 2].concat(x)` (arrays) other than by looking at how the receiver
/// itself was built. Only a string literal, a template literal, another
/// `+`/`.concat()` composition, or a parenthesized wrapper of one of those
/// counts — an ordinary variable of unknown type does not, so
/// `someValue.concat(x)` is left as a plain (unspecial-cased) call.
fn looks_like_string_receiver(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) | Expression::TemplateLiteral(_) | Expression::TaggedTemplateExpression(_) | Expression::BinaryExpression(_) => true,
        Expression::ParenthesizedExpression(inner) => looks_like_string_receiver(&inner.expression),
        Expression::CallExpression(call) => {
            matches!(&call.callee, Expression::StaticMemberExpression(member) if member.property.name.as_str() == "concat" && looks_like_string_receiver(&member.object))
        }
        _ => false,
    }
}

fn lower_string_concat_call(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, call: &js::CallExpression, member: &js::StaticMemberExpression) -> Option<Expr> {
    if member.property.name.as_str() != "concat" || !looks_like_string_receiver(&member.object) {
        return None;
    }
    let mut acc = lower_expr(builder, env, source, &member.object);
    for argument in &call.arguments {
        let js::Argument::SpreadElement(_) = argument else {
            let piece = lower_expr(builder, env, source, argument.as_expression()?);
            let combined_span = span(builder, source, call.span);
            acc = Expr::Binary { id: builder.alloc_expr_id(), op: BinaryOp::Add, lhs: Box::new(acc), rhs: Box::new(piece), span: combined_span };
            continue;
        };
        return None;
    }
    Some(acc)
}

fn lower_call(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, call: &js::CallExpression) -> Expr {
    if let Expression::StaticMemberExpression(member) = &call.callee {
        if let Some(concatenated) = lower_string_concat_call(builder, env, source, call, member) {
            return concatenated;
        }
    }
    let args = lower_arguments(builder, env, source, &call.arguments);
    let arg_names = vec![None; args.len()];
    let (target, receiver, qualifier_is_explicit) = match &call.callee {
        Expression::Identifier(ident) => match env.import_binding(ident.name.as_str()) {
            // `foo()` where `foo` was imported: target the exporting
            // module's real function directly, matching how a resolved
            // Java/Python cross-file call already carries its qualified
            // name at the frontend level rather than a bare identifier.
            Some(crate::frontend::env::ImportBinding::Named(qualified)) => (CallTarget::Named(qualified.clone()), None, false),
            // `const renderPdf = require("wkhtmltopdf"); renderPdf(url);` —
            // some packages' `require(...)` result is itself directly
            // callable (not a namespace of methods); a large body of
            // existing bundled taint rules matches this exact shape
            // (`matcher: { exact: wkhtmltopdf }`) against the bare module
            // name, so a *bare-called* namespace-bound identifier resolves
            // to its module name directly rather than the local binding text.
            Some(crate::frontend::env::ImportBinding::Namespace(module)) => (CallTarget::Named(module.clone()), None, false),
            _ => match env.top_level_function(ident.name.as_str()) {
                // `sink(id)` calling a function declared elsewhere in the
                // *same* file: must carry this file's own qualified name
                // (`"service.sink"`), not the bare source spelling — the
                // real declaration is only ever registered under its
                // qualified name, so an unqualified target could never
                // resolve to it during static analysis.
                Some(qualified) => (CallTarget::Named(qualified.to_string()), None, false),
                // `const Strategy = require("passport-jwt").Strategy;
                // Strategy({...});` — `Strategy` itself carries a qualifier
                // (`"passport-jwt.Strategy"`) from its own initializer (see
                // `stmt::lower_variable_declaration`), even though calling
                // `Strategy` bare isn't a member-access call at all.
                None => match env.peek(ident.name.as_str()).and_then(|symbol| env.value_qualifier(symbol)) {
                    Some(qualifier) => (CallTarget::Named(qualifier.to_string()), None, false),
                    None => (CallTarget::Named(ident.name.to_string()), None, false),
                },
            },
        },
        Expression::StaticMemberExpression(member) => {
            // `ns.foo()`/`require("vm").foo()`/`console.log(...)`/
            // `mysql2.createConnection().query(...)`: any value with a
            // known qualified-name provenance combines that qualifier with
            // the accessed property, instead of lowering as an ordinary
            // receiver-qualified method call — see `expression_qualifier`.
            // The receiver is always lowered and kept — even when a
            // qualified name is ALSO available — because a `propagators`
            // rule (`method_name: update, flows: [{from: receiver, to:
            // return}]`, entirely name-based and qualifier-agnostic) needs
            // the real receiver value present to trace taint through a
            // chain (`crypto.createHash("md5").update(input).digest(...)`);
            // discarding it just because a qualified target name was ALSO
            // derivable would silently break that separate mechanism.
            let qualifier = expression_qualifier(env, &member.object);
            let receiver_expr = lower_expr(builder, env, source, &member.object);
            let target = match qualifier {
                Some(qualifier) => CallTarget::Named(format!("{qualifier}.{}", member.property.name)),
                None => CallTarget::Named(member.property.name.to_string()),
            };
            (target, Some(Box::new(receiver_expr)), true)
        }
        Expression::ComputedMemberExpression(member) => {
            let receiver_expr = lower_expr(builder, env, source, &member.object);
            let index_expr = lower_expr(builder, env, source, &member.expression);
            (CallTarget::Dynamic(Box::new(index_expr)), Some(Box::new(receiver_expr)), true)
        }
        other => (CallTarget::Dynamic(Box::new(lower_expr(builder, env, source, other))), None, false),
    };
    Expr::Call(CallExpr { id: builder.alloc_expr_id(), target, receiver, qualifier_is_explicit, args, arg_names, span: span(builder, source, call.span) })
}

/// The most specific static text nameable for `new Target(...)`'s callee:
/// a plain identifier, or a best-effort dotted reconstruction for
/// `new a.b.C(...)` — anything more dynamic falls back to `"<computed>"`,
/// which is a legal (if unhelpful) type name rather than a crash.
fn callee_type_name(callee: &Expression) -> String {
    match callee {
        Expression::Identifier(ident) => ident.name.to_string(),
        Expression::StaticMemberExpression(member) => format!("{}.{}", callee_type_name(&member.object), member.property.name),
        _ => "<computed>".to_string(),
    }
}

fn map_binary_operator(op: js::BinaryOperator) -> BinaryOp {
    match op {
        js::BinaryOperator::Equality | js::BinaryOperator::StrictEquality => BinaryOp::Eq,
        js::BinaryOperator::Inequality | js::BinaryOperator::StrictInequality => BinaryOp::Ne,
        js::BinaryOperator::LessThan => BinaryOp::Lt,
        js::BinaryOperator::LessEqualThan => BinaryOp::Le,
        js::BinaryOperator::GreaterThan => BinaryOp::Gt,
        js::BinaryOperator::GreaterEqualThan => BinaryOp::Ge,
        js::BinaryOperator::Addition => BinaryOp::Add,
        js::BinaryOperator::Subtraction => BinaryOp::Sub,
        js::BinaryOperator::Multiplication => BinaryOp::Mul,
        js::BinaryOperator::Division => BinaryOp::Div,
        js::BinaryOperator::Remainder => BinaryOp::Mod,
        js::BinaryOperator::BitwiseAnd => BinaryOp::BitAnd,
        js::BinaryOperator::BitwiseOR => BinaryOp::BitOr,
        js::BinaryOperator::BitwiseXOR => BinaryOp::BitXor,
        js::BinaryOperator::In => BinaryOp::In,
        // Exponent/shifts/instanceof have no dedicated HIR operator; `Eq` is
        // never a sound stand-in, so these keep the operand data flowing
        // through by treating the whole thing as a generic combination via
        // `Add` (a documented approximation, not a correctness claim about
        // the operator's actual semantics).
        js::BinaryOperator::Exponential
        | js::BinaryOperator::ShiftLeft
        | js::BinaryOperator::ShiftRight
        | js::BinaryOperator::ShiftRightZeroFill
        | js::BinaryOperator::Instanceof => BinaryOp::Add,
    }
}

/// Lowers an in-place-mutated target (`++x`, `x--`) to the `Expr` that
/// reads its current value — only a plain identifier is addressable in
/// this HIR's `Expr::Unary`, so a member-expression target (`obj.count++`)
/// is read structurally (`FieldRead`/`IndexRead`) rather than rejected.
fn lower_simple_assignment_target(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, target: &js::SimpleAssignmentTarget) -> Expr {
    match target {
        js::SimpleAssignmentTarget::AssignmentTargetIdentifier(ident) => {
            let symbol = resolve_identifier(builder, env, ident.name.as_str());
            Expr::VarRef { id: builder.alloc_expr_id(), symbol, span: span(builder, source, ident.span) }
        }
        js::SimpleAssignmentTarget::StaticMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: member.property.name.to_string(), span: span(builder, source, member.span) }
        }
        js::SimpleAssignmentTarget::ComputedMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            let index = lower_expr(builder, env, source, &member.expression);
            Expr::IndexRead { id: builder.alloc_expr_id(), base: Box::new(base), index: Box::new(index), span: span(builder, source, member.span) }
        }
        js::SimpleAssignmentTarget::PrivateFieldExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            Expr::FieldRead { id: builder.alloc_expr_id(), base: Box::new(base), field: format!("#{}", member.field.name), span: span(builder, source, member.span) }
        }
        other => opaque(builder, source, other.span(), "complex-assignment-target"),
    }
}

pub(crate) fn lower_assignment_target_lvalue(builder: &mut ModuleBuilder, env: &mut JsEnv, source: &str, target: &js::AssignmentTarget) -> LValue {
    match target {
        js::AssignmentTarget::AssignmentTargetIdentifier(ident) => LValue::Var(resolve_identifier(builder, env, ident.name.as_str())),
        js::AssignmentTarget::StaticMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            LValue::Field { base: Box::new(base), field: member.property.name.to_string() }
        }
        js::AssignmentTarget::ComputedMemberExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            let index = lower_expr(builder, env, source, &member.expression);
            LValue::Index { base: Box::new(base), index: Box::new(index) }
        }
        js::AssignmentTarget::PrivateFieldExpression(member) => {
            let base = lower_expr(builder, env, source, &member.object);
            LValue::Field { base: Box::new(base), field: format!("#{}", member.field.name) }
        }
        // Destructuring assignment (`[a, b] = arr`, `({a} = obj)`): not a
        // single addressable location. A synthetic discard local keeps the
        // right-hand side's value (and any taint it carries) visible to
        // the engine rather than silently dropping the statement.
        js::AssignmentTarget::ArrayAssignmentTarget(_) | js::AssignmentTarget::ObjectAssignmentTarget(_) => {
            let symbol = builder.add_symbol("__destructure", SymbolKind::Local);
            LValue::Var(symbol)
        }
        other => LValue::Var(resolve_identifier(builder, env, &format!("__assign_target_{:?}", other.span()))),
    }
}

/// `x += y` desugars to an ordinary `Assign` whose right-hand side is `x op
/// y`, computed by reading `x` a second time through the same lowering as a
/// plain reference — safe because this only ever runs on an already-lowered
/// target expression (no source-level double side effect is introduced).
fn lower_compound_assignment_target(
    builder: &mut ModuleBuilder,
    env: &mut JsEnv,
    source: &str,
    target: &js::AssignmentTarget,
    operator: js::AssignmentOperator,
    rhs: Expr,
) -> (LValue, Expr) {
    let lvalue = lower_assignment_target_lvalue(builder, env, source, target);
    let Some(op) = compound_assignment_operator(operator) else {
        return (lvalue, rhs);
    };
    let current = lvalue_to_read_expr(builder, source, &lvalue, rhs.span());
    let combined = Expr::Binary { id: builder.alloc_expr_id(), op, lhs: Box::new(current), rhs: Box::new(rhs), span: span_placeholder(builder) };
    (lvalue, combined)
}

fn span_placeholder(builder: &mut ModuleBuilder) -> uniflow_hir::Span {
    let _ = builder.alloc_expr_id();
    uniflow_hir::Span::default()
}

fn lvalue_to_read_expr(builder: &mut ModuleBuilder, _source: &str, lvalue: &LValue, span: uniflow_hir::Span) -> Expr {
    match lvalue {
        LValue::Var(symbol) => Expr::VarRef { id: builder.alloc_expr_id(), symbol: *symbol, span },
        LValue::Field { base, field } => Expr::FieldRead { id: builder.alloc_expr_id(), base: base.clone(), field: field.clone(), span },
        LValue::Index { base, index } => Expr::IndexRead { id: builder.alloc_expr_id(), base: base.clone(), index: index.clone(), span },
    }
}

fn compound_assignment_operator(op: js::AssignmentOperator) -> Option<BinaryOp> {
    match op {
        js::AssignmentOperator::Assign => None,
        js::AssignmentOperator::Addition => Some(BinaryOp::Add),
        js::AssignmentOperator::Subtraction => Some(BinaryOp::Sub),
        js::AssignmentOperator::Multiplication => Some(BinaryOp::Mul),
        js::AssignmentOperator::Division => Some(BinaryOp::Div),
        js::AssignmentOperator::Remainder => Some(BinaryOp::Mod),
        js::AssignmentOperator::BitwiseAnd => Some(BinaryOp::BitAnd),
        js::AssignmentOperator::BitwiseOR => Some(BinaryOp::BitOr),
        js::AssignmentOperator::BitwiseXOR => Some(BinaryOp::BitXor),
        js::AssignmentOperator::LogicalAnd => Some(BinaryOp::And),
        js::AssignmentOperator::LogicalOr | js::AssignmentOperator::LogicalNullish => Some(BinaryOp::Or),
        _ => None,
    }
}
