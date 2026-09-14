//! Per-file top-level orchestration: dispatches `syn::Item`s to
//! `uniflow_hir::Item::Function`/`Item::Class`/`Item::GlobalVar`, resolves
//! `use` bindings, and recurses into inline `mod { ... }` blocks (an
//! out-of-line `mod foo;` is left for `project_index` to resolve against the
//! project's own file, exactly like `lang_javascript` leaves a bare-package
//! `require` unresolved for its own project index).

use syn::spanned::Spanned;
use uniflow_hir::{Class, Field, Function, GlobalVar, Item, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

use crate::frontend::env::RustEnv;
use crate::frontend::expr::{lower_expr, path_text, span};
use crate::frontend::functions::{captures_to_params, lower_function_parts};
use crate::frontend::stmt::{function_returns_value, lower_function_body};

/// Joins a module's own qualified prefix with an item's bare name — the
/// crate root itself (see `project_index::module_name_for_path`, which
/// drops a `main`/`lib`/`mod` file-stem segment) can have an *empty*
/// qualified name, in which case an item is just its own bare name, not
/// prefixed with a stray leading `.`.
pub(crate) fn qualified(module_name: &str, name: &str) -> String {
    if module_name.is_empty() {
        name.to_string()
    } else {
        format!("{module_name}.{name}")
    }
}

fn type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(type_path) if type_path.qself.is_none() => Some(path_text(&type_path.path)),
        syn::Type::Reference(reference) => type_name(&reference.elem),
        syn::Type::Paren(paren) => type_name(&paren.elem),
        syn::Type::Group(group) => type_name(&group.elem),
        _ => None,
    }
}

/// Bare name -> this file's own qualified name, for every fn/struct/enum/
/// trait/const/static declared anywhere in it (including inline `mod`
/// blocks, under their own nested qualified name) — a pre-scan run *before*
/// any statement lowering, matching real Rust name resolution: an item is
/// callable from anywhere in its module, including a call that textually
/// precedes the declaration.
fn register_top_level_items(env: &mut RustEnv, items: &[syn::Item], module_name: &str) {
    for item in items {
        match item {
            syn::Item::Fn(f) => env.register_top_level_item(f.sig.ident.to_string(), qualified(module_name, &f.sig.ident.to_string())),
            syn::Item::Struct(s) => env.register_top_level_item(s.ident.to_string(), qualified(module_name, &s.ident.to_string())),
            syn::Item::Enum(e) => env.register_top_level_item(e.ident.to_string(), qualified(module_name, &e.ident.to_string())),
            syn::Item::Trait(t) => env.register_top_level_item(t.ident.to_string(), qualified(module_name, &t.ident.to_string())),
            syn::Item::Const(c) => env.register_top_level_item(c.ident.to_string(), qualified(module_name, &c.ident.to_string())),
            syn::Item::Static(s) => env.register_top_level_item(s.ident.to_string(), qualified(module_name, &s.ident.to_string())),
            syn::Item::Mod(m) => {
                if let Some((_, nested_items)) = &m.content {
                    let nested_name = qualified(module_name, &m.ident.to_string());
                    register_top_level_items(env, nested_items, &nested_name);
                }
            }
            _ => {}
        }
    }
}

/// Bare names declared inside any `extern "C" { fn foo(...); }` block
/// anywhere in this file (including nested inline `mod`s) — a pre-scan run
/// alongside [`register_top_level_items`], before any statement lowering.
fn register_extern_fns(env: &mut RustEnv, items: &[syn::Item]) {
    for item in items {
        match item {
            syn::Item::ForeignMod(foreign_mod) => {
                for foreign_item in &foreign_mod.items {
                    if let syn::ForeignItem::Fn(f) = foreign_item {
                        env.register_extern_fn(f.sig.ident.to_string());
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, nested_items)) = &m.content {
                    register_extern_fns(env, nested_items);
                }
            }
            _ => {}
        }
    }
}

/// The exported C ABI symbol name for a `#[no_mangle]`/`#[export_name =
/// "..."]`-annotated function, if either attribute is present — `None` for
/// an ordinary Rust function with no external linkage. `#[no_mangle]` alone
/// exports under the function's own Rust name unchanged; `#[export_name]`
/// (which may combine with `#[no_mangle]` or stand alone) overrides it.
fn export_symbol_for(attrs: &[syn::Attribute], bare_name: &str) -> Option<String> {
    let mut no_mangle = false;
    let mut explicit = None;
    for attr in attrs {
        if attr.path().is_ident("no_mangle") {
            no_mangle = true;
        } else if attr.path().is_ident("export_name") {
            if let syn::Meta::NameValue(name_value) = &attr.meta {
                if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(name), .. }) = &name_value.value {
                    explicit = Some(name.value());
                }
            }
        }
    }
    explicit.or_else(|| no_mangle.then(|| bare_name.to_string()))
}

/// Every non-`#[doc = ...]` attribute on an item, as its exact original
/// source text (`#[get("/path")]`, not a token-stream re-serialization,
/// which would risk subtly different spacing) — joined the same way
/// `lang_python`'s `"python.decorators.raw"` is, for
/// `system_graph::http`'s route-macro recognizers (actix-web/Rocket) to
/// parse. Doc comments desugar to `#[doc = "..."]` attributes in `syn` and
/// are excluded — they carry no route information and would otherwise
/// bloat this attribute with arbitrary doc-string text.
fn non_doc_attributes_raw(source: &str, attrs: &[syn::Attribute]) -> Option<String> {
    let raw: Vec<&str> = attrs
        .iter()
        .filter(|attr| !attr.path().is_ident("doc"))
        .filter_map(|attr| {
            let range = attr.span().byte_range();
            source.get(range.start..range.end)
        })
        .collect();
    (!raw.is_empty()).then(|| raw.join("\u{1f}"))
}

/// Attaches whatever extern-declared FFI calls were made while lowering the
/// function/method just finished (drained from `env`) as a single
/// `\u{1f}`-joined `"rust.ffi.calls"` symbol attribute — mirrors
/// `lang_python::declarations`'s `"python.ffi.calls"` encoding exactly, so
/// `system_graph::rust_ffi` can read it the same way `python_ffi.rs` reads
/// its Python counterpart. A no-op when nothing was called.
fn set_ffi_calls_attribute(builder: &mut ModuleBuilder, env: &mut RustEnv, symbol: uniflow_hir::SymbolId) {
    let calls = env.take_ffi_calls();
    if !calls.is_empty() {
        builder.set_symbol_attribute(symbol, "rust.ffi.calls", calls.join("\u{1f}"));
    }
}

/// The crate-root/current-module/parent-module substitution for a `use`
/// path's leading special segment — best-effort, since this frontend has no
/// real module-hierarchy graph: `crate` resolves to the project's crate
/// root (or this module, in standalone parsing); `self` resolves to this
/// module; `super` falls back to this module too (over-broad, but still a
/// meaningful non-empty qualifier rather than nothing).
fn translate_special_segment(segment: &str, env: &RustEnv, module_name: &str) -> Option<String> {
    match segment {
        "crate" => Some(env.crate_root().unwrap_or(module_name).to_string()),
        "self" | "super" => Some(module_name.to_string()),
        _ => None,
    }
}

fn bind_use_tree(builder: &mut ModuleBuilder, env: &mut RustEnv, tree: &syn::UseTree, prefix: &str, module_name: &str) {
    match tree {
        syn::UseTree::Path(path) => {
            let segment = translate_special_segment(&path.ident.to_string(), env, module_name).unwrap_or_else(|| path.ident.to_string());
            let new_prefix = if prefix.is_empty() { segment } else { format!("{prefix}.{segment}") };
            bind_use_tree(builder, env, &path.tree, &new_prefix, module_name);
        }
        syn::UseTree::Name(name) => {
            let local = name.ident.to_string();
            if local == "self" {
                let bare = prefix.rsplit('.').next().unwrap_or(prefix).to_string();
                env.set_use_binding(bare.clone(), prefix.to_string());
                builder.add_import(prefix, Some(bare));
            } else {
                let qualified_path = if prefix.is_empty() { local.clone() } else { format!("{prefix}.{local}") };
                env.set_use_binding(local.clone(), qualified_path.clone());
                builder.add_import(&qualified_path, Some(local));
            }
        }
        syn::UseTree::Rename(rename) => {
            let alias = rename.rename.to_string();
            if rename.ident == "self" {
                env.set_use_binding(alias.clone(), prefix.to_string());
                builder.add_import(prefix, Some(alias));
            } else {
                let target_local = rename.ident.to_string();
                let qualified_path = if prefix.is_empty() { target_local.clone() } else { format!("{prefix}.{target_local}") };
                env.set_use_binding(alias.clone(), qualified_path.clone());
                builder.add_import(&qualified_path, Some(alias));
            }
        }
        // `use foo::*;` introduces no specific local binding; a call through
        // a glob-imported name falls back to the ordinary "unresolved ->
        // raw identifier text" path, the same simplification
        // `lang_javascript` accepts for an unresolved specifier.
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(group) => {
            for sub_tree in &group.items {
                bind_use_tree(builder, env, sub_tree, prefix, module_name);
            }
        }
    }
}

fn bind_uses(builder: &mut ModuleBuilder, env: &mut RustEnv, items: &[syn::Item], module_name: &str) {
    for item in items {
        match item {
            syn::Item::Use(use_item) => bind_use_tree(builder, env, &use_item.tree, "", module_name),
            syn::Item::Mod(m) => {
                if let Some((_, nested_items)) = &m.content {
                    let nested_name = qualified(module_name, &m.ident.to_string());
                    bind_uses(builder, env, nested_items, &nested_name);
                }
            }
            _ => {}
        }
    }
}

fn lower_top_level_fn(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, f: &syn::ItemFn, module_name: &str) -> Function {
    let name = qualified(module_name, &f.sig.ident.to_string());
    let symbol = builder.add_symbol(&f.sig.ident.to_string(), SymbolKind::Function);
    if let Some(raw_attrs) = non_doc_attributes_raw(source, &f.attrs) {
        builder.set_symbol_attribute(symbol, "rust.attributes.raw", raw_attrs);
    }
    if let Some(export_symbol) = export_symbol_for(&f.attrs, &f.sig.ident.to_string()) {
        // A `#[no_mangle]`/`#[export_name]` function is Rust's side of an
        // FFI boundary another language calls INTO (mirrors a JNI `native`
        // method's *implementation* side, or a ctypes bridge's target
        // symbol) — read by `system_graph::rust_ffi` to bridge a matching
        // caller's arguments/return value through.
        builder.set_symbol_attribute(symbol, "rust.ffi.export", export_symbol);
    }
    let (params, receiver, body, captures) = lower_function_parts(builder, env, source, &f.sig, |builder, env, source| lower_function_body(builder, env, source, &f.block, function_returns_value(&f.sig.output)));
    set_ffi_calls_attribute(builder, env, symbol);
    Function {
        id: builder.alloc_function_id(),
        name,
        symbol: Some(symbol),
        params,
        captures: captures_to_params(captures),
        return_type: None,
        body,
        is_method: false,
        receiver,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span(builder, source, f.span()),
    }
}

fn lower_struct(builder: &mut ModuleBuilder, source: &str, s: &syn::ItemStruct, module_name: &str) -> Class {
    let name = qualified(module_name, &s.ident.to_string());
    let class_symbol = builder.add_symbol(&s.ident.to_string(), SymbolKind::Class);
    let fields = match &s.fields {
        syn::Fields::Named(named) => named
            .named
            .iter()
            .filter_map(|field| {
                let field_name = field.ident.as_ref()?.to_string();
                let field_symbol = builder.add_symbol(&field_name, SymbolKind::Field);
                Some(Field { name: field_name, symbol: Some(field_symbol), ty: None, span: span(builder, source, field.span()) })
            })
            .collect(),
        syn::Fields::Unnamed(unnamed) => unnamed
            .unnamed
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let field_name = index.to_string();
                let field_symbol = builder.add_symbol(&field_name, SymbolKind::Field);
                Field { name: field_name, symbol: Some(field_symbol), ty: None, span: span(builder, source, field.span()) }
            })
            .collect(),
        syn::Fields::Unit => Vec::new(),
    };
    Class { name, symbol: Some(class_symbol), bases: Vec::new(), fields, methods: Vec::new(), span: span(builder, source, s.span()) }
}

fn lower_enum(builder: &mut ModuleBuilder, source: &str, e: &syn::ItemEnum, module_name: &str) -> Class {
    let name = qualified(module_name, &e.ident.to_string());
    let class_symbol = builder.add_symbol(&e.ident.to_string(), SymbolKind::Class);
    let fields = e
        .variants
        .iter()
        .map(|variant| {
            let variant_name = variant.ident.to_string();
            let variant_symbol = builder.add_symbol(&variant_name, SymbolKind::Field);
            Field { name: variant_name, symbol: Some(variant_symbol), ty: None, span: span(builder, source, variant.span()) }
        })
        .collect();
    Class { name, symbol: Some(class_symbol), bases: Vec::new(), fields, methods: Vec::new(), span: span(builder, source, e.span()) }
}

/// Each `impl` block's methods are pushed as standalone `Item::Function`
/// entries (`is_method: true`, `receiver: self`) rather than nested inside a
/// synthesized `Class` — `uniflow_lowering::entry` already discovers a
/// method's captures/etc. symmetrically whether it comes from a bare
/// `Item::Function` or a `Class.methods` entry, and a type can have several
/// separate `impl` blocks (including trait impls), which would otherwise
/// mean pushing several partial, same-named `Class` items for one real type.
fn lower_impl(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, imp: &syn::ItemImpl, module_name: &str) {
    let Some(self_name) = type_name(&imp.self_ty) else { return };
    let qualified_type = qualified(module_name, &self_name);
    let previous_self = env.set_self_type(Some(qualified_type.clone()));
    for item in &imp.items {
        if let syn::ImplItem::Fn(method) = item {
            let method_name = method.sig.ident.to_string();
            let symbol = builder.add_symbol(&method_name, SymbolKind::Method);
            if let Some(raw_attrs) = non_doc_attributes_raw(source, &method.attrs) {
                builder.set_symbol_attribute(symbol, "rust.attributes.raw", raw_attrs);
            }
            let (params, receiver, body, captures) = lower_function_parts(builder, env, source, &method.sig, |builder, env, source| lower_function_body(builder, env, source, &method.block, function_returns_value(&method.sig.output)));
            set_ffi_calls_attribute(builder, env, symbol);
            let function_id = builder.alloc_function_id();
            let function_span = span(builder, source, method.span());
            builder.push_item(Item::Function(Function {
                id: function_id,
                name: format!("{qualified_type}.{method_name}"),
                symbol: Some(symbol),
                params,
                captures: captures_to_params(captures),
                return_type: None,
                body,
                is_method: true,
                receiver,
                cpp: None,
                cpp_initializers: Vec::new(),
                span: function_span,
            }));
        }
    }
    env.set_self_type(previous_self);
}

/// Only a trait method with a default body has anything to lower — an
/// abstract method signature with no body carries no dataflow.
fn lower_trait(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, t: &syn::ItemTrait, module_name: &str) {
    let qualified_trait = qualified(module_name, &t.ident.to_string());
    let previous_self = env.set_self_type(Some(qualified_trait.clone()));
    for item in &t.items {
        if let syn::TraitItem::Fn(method) = item {
            if let Some(block) = &method.default {
                let method_name = method.sig.ident.to_string();
                let symbol = builder.add_symbol(&method_name, SymbolKind::Method);
                let (params, receiver, body, captures) = lower_function_parts(builder, env, source, &method.sig, |builder, env, source| lower_function_body(builder, env, source, block, function_returns_value(&method.sig.output)));
                set_ffi_calls_attribute(builder, env, symbol);
                let function_id = builder.alloc_function_id();
                let function_span = span(builder, source, method.span());
                builder.push_item(Item::Function(Function {
                    id: function_id,
                    name: format!("{qualified_trait}.{method_name}"),
                    symbol: Some(symbol),
                    params,
                    captures: captures_to_params(captures),
                    return_type: None,
                    body,
                    is_method: true,
                    receiver,
                    cpp: None,
                    cpp_initializers: Vec::new(),
                    span: function_span,
                }));
            }
        }
    }
    env.set_self_type(previous_self);
}

fn lower_global(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, ident: &syn::Ident, expr: &syn::Expr, item_span: proc_macro2::Span, module_name: &str) -> GlobalVar {
    let name = qualified(module_name, &ident.to_string());
    let symbol = builder.add_symbol(&ident.to_string(), SymbolKind::Global);
    let init = Some(lower_expr(builder, env, source, expr));
    GlobalVar { name, symbol: Some(symbol), ty: None, init, span: span(builder, source, item_span) }
}

fn lower_items(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, items: &[syn::Item], module_name: &str) {
    for item in items {
        match item {
            syn::Item::Use(_) => {} // resolved up front by `bind_uses`.
            syn::Item::Fn(f) => {
                let function = lower_top_level_fn(builder, env, source, f, module_name);
                builder.push_item(Item::Function(function));
            }
            syn::Item::Struct(s) => {
                let class = lower_struct(builder, source, s, module_name);
                builder.push_item(Item::Class(class));
            }
            syn::Item::Enum(e) => {
                let class = lower_enum(builder, source, e, module_name);
                builder.push_item(Item::Class(class));
            }
            syn::Item::Impl(imp) => lower_impl(builder, env, source, imp, module_name),
            syn::Item::Trait(t) => lower_trait(builder, env, source, t, module_name),
            syn::Item::Const(c) => {
                let global = lower_global(builder, env, source, &c.ident, &c.expr, c.span(), module_name);
                builder.push_item(Item::GlobalVar(global));
            }
            syn::Item::Static(s) => {
                let global = lower_global(builder, env, source, &s.ident, &s.expr, s.span(), module_name);
                builder.push_item(Item::GlobalVar(global));
            }
            syn::Item::Mod(m) => {
                if let Some((_, nested_items)) = &m.content {
                    let nested_name = qualified(module_name, &m.ident.to_string());
                    lower_items(builder, env, source, nested_items, &nested_name);
                }
                // An out-of-line `mod foo;` has no content here; the actual
                // `foo.rs`/`foo/mod.rs` is a separate project entry, parsed
                // and merged independently by `project_index`.
            }
            _ => {}
        }
    }
}

pub(crate) fn lower_file(builder: &mut ModuleBuilder, env: &mut RustEnv, source: &str, file: &syn::File, module_name: &str) {
    bind_uses(builder, env, &file.items, module_name);
    register_top_level_items(env, &file.items, module_name);
    register_extern_fns(env, &file.items);
    lower_items(builder, env, source, &file.items, module_name);
}
