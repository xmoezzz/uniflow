//! Lexical scope + closure-capture tracking, plus the same-file name
//! bindings needed to recover a bare call's real qualified name. Ruby has no
//! static `use`/`import` binding form (`require`/`require_relative` are
//! ordinary method calls with no compile-time binding — see
//! `crate::frontend::decl`'s module doc comment), so unlike `RustEnv` there
//! is no `use_bindings` table; same-file name resolution instead rests on
//! one pre-scanned, file-wide map (`top_level_items`): bare name -> this
//! file's own qualified name, for every `def`/`defs`/`class`/`module`/
//! top-level constant declared anywhere in it (including nested inside a
//! `class`/`module` body, under its own qualified name) — populated before
//! any lowering runs, so a bare call (e.g. a sibling instance method called
//! with an implicit `self` receiver) resolves regardless of declaration
//! order. A flat, file-wide map is a deliberate simplification: two
//! same-named methods on two different classes in the same file are not
//! distinguished (see `crate::frontend::decl`'s module doc comment) — a
//! reasonable trade-off given Ruby has no static import table to fall back
//! on the way `RustEnv::use_bindings` does. Mirrors `RustEnv`'s scope-stack/
//! closure-capture shape.

use std::collections::{BTreeSet, HashMap};

use uniflow_hir::{LambdaCapture, SymbolId, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

pub struct RubyEnv {
    scopes: Vec<HashMap<String, SymbolId>>,
    function_boundaries: Vec<usize>,
    pending_captures: Vec<Vec<LambdaCapture>>,
    /// Bare name -> this file's own qualified name, for every top-level
    /// (not nested in any `class`/`module`) `def`/`class`/`module`/constant
    /// assignment — populated by a pre-scan before any statement lowering
    /// runs, so a same-file call resolves regardless of textual declaration
    /// order (mirrors `RustEnv::top_level_items`).
    top_level_items: HashMap<String, String>,
    /// A local binding's own qualified-name provenance, when its initializer
    /// had one (`client = ActiveRecord::Base.connection` records `client ->
    /// "ActiveRecord.Base.connection"`) — read by
    /// `expr::expression_qualifier` so a further chained call
    /// (`client.execute(...)`) resolves to the full builder-style chain.
    value_qualifiers: HashMap<SymbolId, String>,
    /// The current `class`/`module`'s own qualified name while lowering its
    /// body — `None` outside one. Used both to qualify a nested item's own
    /// name and as the type behind an instance method's `self` receiver.
    self_type: Option<String>,
    /// Distinct `@ivar`/`@@cvar` names encountered while lowering the
    /// current class/module body — snapshotted into `Class.fields` once the
    /// body finishes. Reset (saved/restored) at each class/module boundary,
    /// mirroring `self_type`.
    fields_seen: BTreeSet<String>,
    /// Whether the `class`/`module` body currently being lowered is a Rails
    /// controller (its own declared base is `ApplicationController`/
    /// `ActionController::Base`/`ActionController::API`) — every real
    /// `def` lowered while this is `true` gets a `"ruby.rails.controller"`
    /// symbol attribute, read by `system_graph::http` as a structural,
    /// inheritance-based entrypoint fact (no per-method decorator exists in
    /// Rails' convention-over-configuration routing, unlike Spring/Flask).
    /// Saved/restored at each class boundary, mirroring `self_type`.
    rails_controller: bool,
}

impl RubyEnv {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            function_boundaries: vec![0],
            pending_captures: vec![Vec::new()],
            top_level_items: HashMap::new(),
            value_qualifiers: HashMap::new(),
            self_type: None,
            fields_seen: BTreeSet::new(),
            rails_controller: false,
        }
    }

    pub fn set_self_type(&mut self, name: Option<String>) -> Option<String> {
        std::mem::replace(&mut self.self_type, name)
    }

    pub fn self_type(&self) -> Option<&str> {
        self.self_type.as_deref()
    }

    pub fn set_rails_controller(&mut self, value: bool) -> bool {
        std::mem::replace(&mut self.rails_controller, value)
    }

    pub fn is_rails_controller(&self) -> bool {
        self.rails_controller
    }

    pub fn set_value_qualifier(&mut self, symbol: SymbolId, qualifier: impl Into<String>) {
        self.value_qualifiers.insert(symbol, qualifier.into());
    }

    pub fn value_qualifier(&self, symbol: SymbolId) -> Option<&str> {
        self.value_qualifiers.get(&symbol).map(String::as_str)
    }

    /// A read-only lookup across the entire scope stack, ignoring function
    /// boundaries — used only to ask "does this name currently refer to some
    /// symbol" for qualifier propagation, which needs no closure-capture
    /// semantics.
    pub fn peek(&self, name: &str) -> Option<SymbolId> {
        self.scopes.iter().rev().find_map(|frame| frame.get(name).copied())
    }

    pub fn register_top_level_item(&mut self, bare_name: impl Into<String>, qualified_name: impl Into<String>) {
        self.top_level_items.insert(bare_name.into(), qualified_name.into());
    }

    pub fn top_level_item(&self, bare_name: &str) -> Option<&str> {
        self.top_level_items.get(bare_name).map(String::as_str)
    }

    pub fn record_field(&mut self, name: impl Into<String>) {
        self.fields_seen.insert(name.into());
    }

    pub fn take_fields(&mut self) -> BTreeSet<String> {
        std::mem::take(&mut self.fields_seen)
    }

    /// Restores a previously-saved `fields_seen` set (from
    /// [`Self::take_fields`]) once a nested class/module body's own fields
    /// have been snapshotted, so accumulation resumes correctly in the
    /// enclosing class/module (or file scope) after the nested one closes.
    pub fn swap_fields(&mut self, fields: BTreeSet<String>) -> BTreeSet<String> {
        std::mem::replace(&mut self.fields_seen, fields)
    }

    pub fn push_block(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn pop_block(&mut self) {
        self.scopes.pop();
    }

    /// Enters a new method/block/lambda body's scope; must be paired with
    /// [`Self::leave_function`], which returns the captures recorded while
    /// it was open.
    pub fn enter_function(&mut self) {
        self.scopes.push(HashMap::new());
        self.function_boundaries.push(self.scopes.len() - 1);
        self.pending_captures.push(Vec::new());
    }

    pub fn leave_function(&mut self) -> Vec<LambdaCapture> {
        self.scopes.pop();
        self.function_boundaries.pop();
        self.pending_captures.pop().unwrap_or_default()
    }

    /// Declares `name` in the innermost scope.
    pub fn declare(&mut self, name: &str, symbol: SymbolId) {
        self.scopes.last_mut().expect("at least one scope").insert(name.to_string(), symbol);
    }

    /// Resolves `name` against the current function's own scopes first; if
    /// not found there, asks the *immediately* enclosing function to
    /// resolve it (recursively — this is what makes a doubly (or deeper)
    /// nested closure/block work), then relays the result inward as a fresh
    /// capture registered at *this* boundary. Registering a capture at
    /// every intermediate boundary crossed (not just the innermost one) is
    /// what `uniflow_lowering`'s lambda-hoisting requires: each hoisted
    /// closure only sees its own `params`/`captures`, so a value needed by
    /// a doubly-nested closure but never otherwise referenced by the
    /// intermediate one must still be threaded through it as one of ITS
    /// captures too, or the intermediate hoisted function ends up storing a
    /// captured value it was never itself given. Returns `None` for a
    /// genuinely free name (a module-level item read as a bare value, an
    /// undeclared identifier).
    pub fn resolve(&mut self, builder: &mut ModuleBuilder, name: &str) -> Option<SymbolId> {
        let boundary = *self.function_boundaries.last().expect("at least one function boundary");
        for index in (boundary..self.scopes.len()).rev() {
            if let Some(&symbol) = self.scopes[index].get(name) {
                return Some(symbol);
            }
        }
        if self.function_boundaries.len() < 2 {
            return None;
        }
        let this_boundary = self.function_boundaries.pop().expect("checked len >= 2");
        let this_captures = self.pending_captures.pop().expect("one capture frame per boundary");
        let outer_symbol = self.resolve(builder, name);
        self.pending_captures.push(this_captures);
        self.function_boundaries.push(this_boundary);
        let source_symbol = outer_symbol?;
        let capture_symbol = builder.add_symbol(name, SymbolKind::Local);
        self.scopes[this_boundary].insert(name.to_string(), capture_symbol);
        self.pending_captures.last_mut().expect("at least one capture frame").push(LambdaCapture {
            name: name.to_string(),
            source_symbol,
            symbol: capture_symbol,
            ty: None,
            span: uniflow_hir::Span::default(),
        });
        Some(capture_symbol)
    }
}

impl Default for RubyEnv {
    fn default() -> Self {
        Self::new()
    }
}
