//! Per-file top-level orchestration: pre-scans every `def`/`defs`/`class`/
//! `module`/top-level-constant declaration (regardless of nesting) into
//! `RubyEnv::top_level_items` before lowering, then dispatches each
//! top-level node to `uniflow_hir::Item::Function`/`Item::Class`/
//! `Item::GlobalVar`, recursing into nested `class`/`module`/`class << self`
//! bodies the same way `lang_rust::frontend::decl` recurses into an inline
//! `mod { ... }` block.
//!
//! **No import system to resolve up front**: `require`/`require_relative`
//! are ordinary method calls (`Node::Send(None, "require", [Str(...)])`)
//! with no static "declares a binding" meaning — a bare `require "foo"`
//! just runs the target file for its side effects (defining classes/methods
//! globally) at real run time. There is therefore no `use`-binding table to
//! build here (contrast `lang_rust::frontend::decl::bind_uses`); same-file
//! call resolution rests entirely on the `top_level_items` pre-scan below.

use lib_ruby_parser::{nodes, Node};
use uniflow_hir::{Block, Class, Field, Function, GlobalVar, Item, Param, ParamKind, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::RubyEnv;
use crate::frontend::expr::{bytes_to_string, lower_expr, span};
use crate::frontend::functions::{captures_to_params, declare_self_receiver, lower_params};
use crate::frontend::stmt::{lower_body_returning_value, statement_list};

/// Joins a module's own qualified prefix with an item's bare name — the
/// file root itself has an *empty* qualified name, in which case an item is
/// just its own bare name, not prefixed with a stray leading `.`. Mirrors
/// `lang_rust::frontend::decl::qualified`.
pub(crate) fn qualified(module_name: &str, name: &str) -> String {
    if module_name.is_empty() {
        name.to_string()
    } else {
        format!("{module_name}.{name}")
    }
}

/// The bare name of a `class`/`module` declaration's own `Const` name node.
/// A scoped name (`class A::B; end`, reopening a nested namespace without
/// lexical nesting) is approximated by its own last segment — a documented
/// scope cut, since resolving `A` itself would need a real project-wide
/// namespace graph this frontend does not build.
fn const_bare_name(node: &Node) -> Option<String> {
    match node {
        Node::Const(c) => Some(c.name.clone()),
        _ => None,
    }
}

/// Bare name -> this file's own qualified name, for every `def`/`defs`/
/// `class`/`module`/top-level constant declared anywhere in it — a pre-scan
/// run *before* any lowering, matching real Ruby name resolution closely
/// enough for same-file static analysis: an unqualified call resolves
/// regardless of whether it textually precedes its own declaration. A
/// single flat, file-wide map (rather than one scoped per class body) is a
/// deliberate simplification: two same-named methods on two different
/// classes in the same file are not distinguished by this map alone (a
/// call's receiver, when present, still resolves via its own qualifier
/// independently — see `crate::frontend::expr::node_qualifier` — so this
/// only affects a *bare*, receiverless call).
fn register_top_level_items(env: &mut RubyEnv, items: &[&Node], module_name: &str) {
    for item in items {
        match item {
            Node::Def(d) => env.register_top_level_item(d.name.clone(), qualified(module_name, &d.name)),
            Node::Defs(d) => env.register_top_level_item(d.name.clone(), qualified(module_name, &d.name)),
            Node::Casgn(c) => env.register_top_level_item(c.name.clone(), qualified(module_name, &c.name)),
            Node::Class(c) => {
                if let Some(name) = const_bare_name(&c.name) {
                    let nested_name = qualified(module_name, &name);
                    env.register_top_level_item(name, nested_name.clone());
                    if let Some(body) = &c.body {
                        register_top_level_items(env, &statement_list(body), &nested_name);
                    }
                }
            }
            Node::Module(m) => {
                if let Some(name) = const_bare_name(&m.name) {
                    let nested_name = qualified(module_name, &name);
                    env.register_top_level_item(name, nested_name.clone());
                    if let Some(body) = &m.body {
                        register_top_level_items(env, &statement_list(body), &nested_name);
                    }
                }
            }
            Node::SClass(s) => {
                if let Some(body) = &s.body {
                    register_top_level_items(env, &statement_list(body), module_name);
                }
            }
            Node::Begin(b) => register_top_level_items(env, &b.statements.iter().collect::<Vec<_>>(), module_name),
            _ => {}
        }
    }
}

fn lower_def_as_function(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, d: &nodes::Def, module_name: &str, as_method: bool) -> Function {
    let name = qualified(module_name, &d.name);
    let symbol = builder.add_symbol(&d.name, if as_method { SymbolKind::Method } else { SymbolKind::Function });
    // Rails has no per-action decorator/annotation (unlike Spring/Flask) —
    // every instance method of a controller subclass is conventionally a
    // reachable HTTP entrypoint (its real route path lives in
    // `config/routes.rb`, not tracked here). This over-includes any
    // `private`/`protected` helper method too (visibility isn't tracked by
    // this frontend at all), a defensible over-approximation consistent
    // with `system_graph`'s own "assume public-facing" default elsewhere.
    if as_method && env.is_rails_controller() {
        builder.set_symbol_attribute(symbol, "ruby.rails.controller_action", "1".to_string());
    }
    env.enter_function();
    let receiver = as_method.then(|| declare_self_receiver(builder, env, span(builder, source, &d.expression_l)));
    let mut prologue = Vec::new();
    let params = lower_params(builder, env, source, d.args.as_deref(), &mut prologue);
    let mut body = lower_body_returning_value(builder, env, source, d.body.as_deref());
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: captures_to_params(captures),
        return_type: None,
        body,
        is_method: as_method,
        receiver,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span(builder, source, &d.expression_l),
    }
}

/// `def self.foo; end` (a singleton/"class" method) — modeled identically to
/// an instance method under the same qualified class name (`is_method:
/// true`, a `self` receiver): Ruby's static-vs-instance method distinction
/// has no dedicated HIR shape, and both forms are equally reachable via a
/// receiver-based call in practice, matching how `lang_rust::frontend::decl`
/// does not distinguish a trait's default method from an inherent one
/// beyond `is_method`/`receiver`.
fn lower_defs_as_function(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, d: &nodes::Defs, module_name: &str) -> Function {
    let name = qualified(module_name, &d.name);
    let symbol = builder.add_symbol(&d.name, SymbolKind::Method);
    env.enter_function();
    let receiver = Some(declare_self_receiver(builder, env, span(builder, source, &d.expression_l)));
    let mut prologue = Vec::new();
    let params = lower_params(builder, env, source, d.args.as_deref(), &mut prologue);
    let mut body = lower_body_returning_value(builder, env, source, d.body.as_deref());
    prologue.append(&mut body.stmts);
    body.stmts = prologue;
    let captures = env.leave_function();
    Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: captures_to_params(captures),
        return_type: None,
        body,
        is_method: true,
        receiver,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span(builder, source, &d.expression_l),
    }
}

fn fields_from_names(builder: &mut ModuleBuilder, source: &str, names: std::collections::BTreeSet<String>, at_span: uniflow_hir::Span) -> Vec<Field> {
    let _ = source;
    names
        .into_iter()
        .map(|name| {
            let symbol = builder.add_symbol(&name, SymbolKind::Field);
            Field { name, symbol: Some(symbol), ty: None, span: at_span }
        })
        .collect()
}

/// Lowers a `class`/`module` body's own direct methods into standalone
/// `Item::Function` entries (mirroring
/// `lang_rust::frontend::decl::lower_impl` pushing each `impl` method as a
/// standalone item rather than nesting it inside a synthesized type), and
/// recurses into any nested `class`/`module`/`class << self` declaration
/// under this class's own qualified name. Any `@ivar`/`@@cvar` name touched
/// anywhere in the body is collected into the pushed `Class.fields` — a
/// best-effort inventory (real Ruby has no static field declaration to read
/// instead), snapshotted via `RubyEnv::take_fields`.
/// The literal Ruby-`Symbol`/string text of an `attach_function` argument
/// (`:name` or `"name"`) — the only two forms that make an FFI symbol
/// name statically provable, mirroring `lang_python`'s ctypes bridge only
/// ever trusting a literal identifier-like symbol.
fn literal_symbol_or_string(node: &Node) -> Option<String> {
    match node {
        Node::Sym(s) => Some(bytes_to_string(&s.name)),
        Node::Str(s) => Some(bytes_to_string(&s.value)),
        _ => None,
    }
}

/// Recognizes the `ffi` gem's `attach_function :ruby_name, :c_symbol,
/// [arg_types], :return_type` call (the 2-arg alternative,
/// `attach_function :name, [arg_types], :return_type`, where the Ruby name
/// doubles as the C symbol, is also accepted). On a match, synthesizes a
/// real `Item::Function` — `{qualified_name}.{ruby_name}`, with as many
/// positional params as `arg_types` lists — carrying a `"ruby.ffi.attach"`
/// symbol attribute recording the literal C symbol, for
/// `system_graph::ruby_ffi` to later bridge into a matching native
/// definition elsewhere in the scan. This gives `attach_function` the same
/// "declared, no body, boundary point" treatment `lang_java_bytecode` gives
/// a `native` method — a *call site* elsewhere in the program targeting
/// `{qualified_name}.{ruby_name}` needs no special recognition at all,
/// since it already resolves to this qualified name exactly like any other
/// same-class method call.
fn attach_function_item(builder: &mut ModuleBuilder, send: &nodes::Send, qualified_name: &str, at: uniflow_hir::Span) -> Option<Function> {
    if send.method_name != "attach_function" || send.recv.is_some() {
        return None;
    }
    let ruby_name = literal_symbol_or_string(send.args.first()?)?;
    let (c_symbol, arg_types) = match send.args.get(1) {
        Some(Node::Array(types)) => (ruby_name.clone(), Some(types)),
        Some(second) => match literal_symbol_or_string(second) {
            Some(symbol) => (symbol, send.args.get(2).and_then(|node| match node {
                Node::Array(types) => Some(types),
                _ => None,
            })),
            None => return None,
        },
        None => (ruby_name.clone(), None),
    };
    let arity = arg_types.map(|types| types.elements.len()).unwrap_or(0);
    let name = qualified(qualified_name, &ruby_name);
    let symbol = builder.add_symbol(&ruby_name, SymbolKind::Method);
    builder.set_symbol_attribute(symbol, "ruby.ffi.attach", c_symbol.clone());
    let params = (0..arity)
        .map(|index| {
            let param_name = format!("arg{index}");
            let param_symbol = builder.add_symbol(&param_name, SymbolKind::Param);
            Param { name: param_name, symbol: param_symbol, ty: None, kind: ParamKind::Positional, has_default: false, keyword_only: false, cpp: Default::default(), span: at }
        })
        .collect();
    Some(Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: Vec::new(),
        return_type: None,
        body: Block { id: builder.alloc_block_id(), stmts: Vec::new(), span: at },
        is_method: true,
        receiver: None,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: at,
    })
}

fn lower_class_like_body(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, body_items: &[&Node], qualified_name: &str) {
    for item in body_items {
        match item {
            Node::Def(d) => {
                let function = lower_def_as_function(builder, env, source, d, qualified_name, true);
                builder.push_item(Item::Function(function));
            }
            Node::Defs(d) => {
                let function = lower_defs_as_function(builder, env, source, d, qualified_name);
                builder.push_item(Item::Function(function));
            }
            Node::Class(c) => lower_class(builder, env, source, c, qualified_name),
            Node::Module(m) => lower_module(builder, env, source, m, qualified_name),
            Node::SClass(s) => {
                if let Some(body) = s.body.as_deref() {
                    lower_class_like_body(builder, env, source, &statement_list(body), qualified_name);
                }
            }
            Node::Casgn(c) => {
                let global = lower_casgn_global(builder, env, source, c, qualified_name);
                builder.push_item(Item::GlobalVar(global));
            }
            Node::Begin(b) => lower_class_like_body(builder, env, source, &b.statements.iter().collect::<Vec<_>>(), qualified_name),
            Node::Send(s) => {
                if let Some(function) = attach_function_item(builder, s, qualified_name, span(builder, source, &s.expression_l)) {
                    builder.push_item(Item::Function(function));
                }
                // Any other class-body-level call (a bare `include Foo`,
                // `attr_accessor :x`, `ffi_lib '...'`, ...) has no further
                // dataflow-relevant static effect on this frontend's model —
                // a documented, low-value scope cut.
            }
            // Any other class-body-level expression is a documented,
            // low-value scope cut (matches Rust dropping a nested item
            // declared inside a function body).
            _ => {}
        }
    }
}

/// A class's declared base is `ApplicationController` (every real Rails app
/// controller's own base, itself inheriting `ActionController::Base`/`::API`)
/// or one of those two directly (an app that skips the usual
/// `ApplicationController` indirection). Real multi-level inheritance
/// resolution (following `ApplicationController`'s own base transitively)
/// isn't tracked anywhere in this frontend, so a controller base further
/// than one hop from a recognized name is a documented scope cut.
fn is_rails_controller_base(base: &str) -> bool {
    matches!(base, "ApplicationController" | "ActionController.Base" | "ActionController.API")
}

fn lower_class(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, c: &nodes::Class, module_name: &str) {
    let bare_name = const_bare_name(&c.name).unwrap_or_else(|| "AnonymousClass".to_string());
    let qualified_name = qualified(module_name, &bare_name);
    let class_symbol = builder.add_symbol(&bare_name, SymbolKind::Class);
    let previous_self = env.set_self_type(Some(qualified_name.clone()));
    let previous_fields = env.take_fields();
    let base = c.superclass.as_deref().and_then(|s| crate::frontend::expr::node_qualifier(env, s));
    let previous_rails_controller = env.set_rails_controller(base.as_deref().is_some_and(is_rails_controller_base));
    let body_items = c.body.as_deref().map(statement_list).unwrap_or_default();
    lower_class_like_body(builder, env, source, &body_items, &qualified_name);
    let fields = fields_from_names(builder, source, env.take_fields(), span(builder, source, &c.expression_l));
    env.set_self_type(previous_self);
    env.set_rails_controller(previous_rails_controller);
    env.swap_fields(previous_fields);
    builder.push_item(Item::Class(Class { name: qualified_name, symbol: Some(class_symbol), bases: base.into_iter().collect(), fields, methods: Vec::new(), span: span(builder, source, &c.expression_l) }));
}

fn lower_module(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, m: &nodes::Module, module_name: &str) {
    let bare_name = const_bare_name(&m.name).unwrap_or_else(|| "AnonymousModule".to_string());
    let qualified_name = qualified(module_name, &bare_name);
    let class_symbol = builder.add_symbol(&bare_name, SymbolKind::Class);
    let previous_self = env.set_self_type(Some(qualified_name.clone()));
    let previous_fields = env.take_fields();
    let body_items = m.body.as_deref().map(statement_list).unwrap_or_default();
    lower_class_like_body(builder, env, source, &body_items, &qualified_name);
    let fields = fields_from_names(builder, source, env.take_fields(), span(builder, source, &m.expression_l));
    env.set_self_type(previous_self);
    env.swap_fields(previous_fields);
    builder.push_item(Item::Class(Class { name: qualified_name, symbol: Some(class_symbol), bases: Vec::new(), fields, methods: Vec::new(), span: span(builder, source, &m.expression_l) }));
}

fn lower_casgn_global(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, c: &nodes::Casgn, module_name: &str) -> GlobalVar {
    let name = qualified(module_name, &c.name);
    let symbol = builder.add_symbol(&c.name, SymbolKind::Global);
    let init = c.value.as_deref().map(|v| lower_expr(builder, env, source, v));
    GlobalVar { name, symbol: Some(symbol), ty: None, init, span: span(builder, source, &c.expression_l) }
}

fn lower_items(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, items: &[&Node], module_name: &str) {
    for item in items {
        match item {
            Node::Def(d) => {
                let function = lower_def_as_function(builder, env, source, d, module_name, false);
                builder.push_item(Item::Function(function));
            }
            Node::Defs(d) => {
                // A top-level `def self.foo` (a singleton method on the
                // top-level `main` object) has no enclosing class to
                // qualify it — treated as an ordinary free function,
                // ignoring the `self.` receiver, a documented scope cut.
                let function = lower_def_as_function(builder, env, source, &to_def_shape(d), module_name, false);
                builder.push_item(Item::Function(function));
            }
            Node::Class(c) => lower_class(builder, env, source, c, module_name),
            Node::Module(m) => lower_module(builder, env, source, m, module_name),
            Node::SClass(s) => {
                if let Some(body) = s.body.as_deref() {
                    lower_items(builder, env, source, &statement_list(body), module_name);
                }
            }
            Node::Casgn(c) => {
                let global = lower_casgn_global(builder, env, source, c, module_name);
                builder.push_item(Item::GlobalVar(global));
            }
            Node::Begin(b) => lower_items(builder, env, source, &b.statements.iter().collect::<Vec<_>>(), module_name),
            // Free-standing top-level executable statements (script-style
            // Ruby, e.g. a bare `require`/`puts` outside any method) have no
            // enclosing `Function` to hold a `Stmt` — dropped, a documented
            // scope cut. The ground-truth taint fixtures and this crate's
            // own unit tests all wrap their logic in a `def`.
            _ => {}
        }
    }
}

/// Reduces a `Defs` node to a same-shaped `Def` (dropping only the
/// `definee`) so top-level singleton methods can share
/// [`lower_def_as_function`] — see that function's caller for why the
/// receiver itself is ignored at file scope.
fn to_def_shape(d: &nodes::Defs) -> nodes::Def {
    nodes::Def { name: d.name.clone(), args: d.args.clone(), body: d.body.clone(), keyword_l: d.keyword_l, name_l: d.name_l, end_l: d.end_l, assignment_l: d.assignment_l, expression_l: d.expression_l }
}

pub(crate) fn lower_file(builder: &mut ModuleBuilder, env: &mut RubyEnv, source: &str, root: Option<&Node>, module_name: &str) {
    let items: Vec<&Node> = root.map(statement_list).unwrap_or_default();
    register_top_level_items(env, &items, module_name);
    lower_items(builder, env, source, &items, module_name);
}
