//! Lexical scope + closure-capture tracking, plus the `use`-import and
//! same-module item bindings needed to recover a call's real qualified name.
//! Mirrors the `JsEnv` pattern used by `lang_javascript`, adapted for Rust's
//! always-block-scoped `let` (no `var`-style hoisting) and its path-based
//! (rather than member-expression-based) qualified-name syntax.

use std::collections::{HashMap, HashSet};

use uniflow_hir::{LambdaCapture, SymbolId, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

pub struct RustEnv {
    scopes: Vec<HashMap<String, SymbolId>>,
    function_boundaries: Vec<usize>,
    pending_captures: Vec<Vec<LambdaCapture>>,
    /// `use path::to::Item;` (or `as` a rename) — local name -> fully
    /// qualified, dot-joined path (`std.process.Command`).
    use_bindings: HashMap<String, String>,
    /// Bare name -> this module's own qualified name, for every
    /// fn/struct/enum/trait/const/static this file declares — populated by a
    /// pre-scan before any statement lowering runs so a same-module call
    /// resolves regardless of textual declaration order.
    top_level_items: HashMap<String, String>,
    /// A local binding's own qualified-name provenance, when its initializer
    /// had one (`let cmd = Command::new("ls");` records `cmd ->
    /// "Command.new"`) — read by `expr::expression_qualifier` so a further
    /// chained call (`cmd.arg("-l")`) resolves to `Command.new.arg`, matching
    /// how a builder-style API chain is named end to end.
    value_qualifiers: HashMap<SymbolId, String>,
    /// The `Self` type's own qualified name while lowering the body of an
    /// `impl`/`trait` block — `None` outside one.
    self_type: Option<String>,
    /// The project's crate-root module name, used to resolve a leading
    /// `crate::` path segment. `None` in standalone (no-project-index)
    /// parsing, where a `crate::` segment is simply dropped.
    crate_root: Option<String>,
    /// Bare names declared inside an `extern "C" { fn foo(...); }` block
    /// anywhere in this file — populated by a pre-scan before any statement
    /// lowering runs, mirroring `top_level_items`. Read by call lowering to
    /// recognize a bare call as a genuine FFI import (as opposed to an
    /// ordinary unresolved identifier that merely happens to share a name
    /// with some C function elsewhere in the scan) — the same
    /// ambiguity-avoiding "require a literal, statically-provable binding
    /// fact" discipline `lang_python`'s `python.ffi.calls` attribute uses.
    extern_fn_names: HashSet<String>,
    /// Extern-declared function names actually called by the function
    /// currently being lowered — accumulated while lowering one top-level
    /// function/method's body, then drained and attached as a
    /// `"rust.ffi.calls"` symbol attribute once that function is done (see
    /// `decl::lower_top_level_fn`/`lower_impl`/`lower_trait`), for
    /// `system_graph::rust_ffi` to read.
    pending_ffi_calls: Vec<String>,
}

impl RustEnv {
    pub fn new(crate_root: Option<String>) -> Self {
        Self {
            scopes: vec![HashMap::new()],
            function_boundaries: vec![0],
            pending_captures: vec![Vec::new()],
            use_bindings: HashMap::new(),
            top_level_items: HashMap::new(),
            value_qualifiers: HashMap::new(),
            self_type: None,
            crate_root,
            extern_fn_names: HashSet::new(),
            pending_ffi_calls: Vec::new(),
        }
    }

    pub fn register_extern_fn(&mut self, bare_name: impl Into<String>) {
        self.extern_fn_names.insert(bare_name.into());
    }

    pub fn is_extern_fn(&self, bare_name: &str) -> bool {
        self.extern_fn_names.contains(bare_name)
    }

    pub fn record_ffi_call(&mut self, bare_name: impl Into<String>) {
        self.pending_ffi_calls.push(bare_name.into());
    }

    /// Drains the FFI-call list accumulated while lowering one top-level
    /// function/method's body — call once right after that function is
    /// fully lowered.
    pub fn take_ffi_calls(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_ffi_calls)
    }

    pub fn crate_root(&self) -> Option<&str> {
        self.crate_root.as_deref()
    }

    pub fn set_self_type(&mut self, name: Option<String>) -> Option<String> {
        std::mem::replace(&mut self.self_type, name)
    }

    pub fn self_type(&self) -> Option<&str> {
        self.self_type.as_deref()
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

    pub fn set_use_binding(&mut self, local_name: impl Into<String>, qualified: impl Into<String>) {
        self.use_bindings.insert(local_name.into(), qualified.into());
    }

    pub fn use_binding(&self, local_name: &str) -> Option<&str> {
        self.use_bindings.get(local_name).map(String::as_str)
    }

    pub fn register_top_level_item(&mut self, bare_name: impl Into<String>, qualified_name: impl Into<String>) {
        self.top_level_items.insert(bare_name.into(), qualified_name.into());
    }

    pub fn top_level_item(&self, bare_name: &str) -> Option<&str> {
        self.top_level_items.get(bare_name).map(String::as_str)
    }

    pub fn push_block(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn pop_block(&mut self) {
        self.scopes.pop();
    }

    /// Enters a new function/closure body's scope; must be paired with
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

    /// Declares `name` in the innermost (block-scoped `let`) scope — Rust has
    /// no function-hoisted binding form, so every declaration uses this.
    pub fn declare(&mut self, name: &str, symbol: SymbolId) {
        self.scopes.last_mut().expect("at least one scope").insert(name.to_string(), symbol);
    }

    /// Resolves `name`, allocating a fresh capture symbol (and recording the
    /// `LambdaCapture`) the first time a reference crosses into an enclosing
    /// function/closure's scope. Returns `None` for a genuinely free name (a
    /// module-level item read as a bare value, an undeclared identifier).
    /// Resolves `name` against the current function's own scopes first; if
    /// not found there, asks the *immediately* enclosing function to
    /// resolve it (recursively — this is what makes a doubly (or deeper)
    /// nested closure work), then relays the result inward as a fresh
    /// capture registered at *this* boundary. Registering a capture at
    /// every intermediate boundary crossed (not just the innermost one) is
    /// what `uniflow_lowering`'s lambda-hoisting requires: each hoisted
    /// closure only sees its own `params`/`captures`, so a value needed by
    /// a doubly-nested closure but never otherwise referenced by the
    /// intermediate one must still be threaded through it as one of ITS
    /// captures too, or the intermediate hoisted function ends up storing a
    /// captured value it was never itself given.
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
