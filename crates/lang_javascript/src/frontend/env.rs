use std::collections::HashMap;

use uniflow_hir::{LambdaCapture, SymbolId, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

/// What a local name bound by an `import`/`require` resolves to, once the
/// specifier has been matched against the project's export index.
#[derive(Clone, Debug)]
pub enum ImportBinding {
    /// `import { foo } from './utils'` / `const { foo } = require('./utils')`
    /// (or a default import) — calling this name directly targets the
    /// fully qualified function.
    Named(String),
    /// `import * as utils from './utils'` / `const utils = require('./utils')`
    /// — a later `utils.foo(...)` combines this module name with the
    /// accessed property.
    Namespace(String),
}

/// Lexical scope + closure-capture tracking shared by statement and
/// expression lowering. Mirrors the `JavaEnv`/environment pattern other
/// frontends in this workspace use, adapted for JS's block-scoped
/// `let`/`const` (each block pushes its own scope) and `var`'s
/// function-scoped hoisting (declared directly into the nearest enclosing
/// function boundary's scope, not the innermost block).
pub struct JsEnv {
    scopes: Vec<HashMap<String, SymbolId>>,
    /// Index into `scopes` where each currently-open function body begins
    /// (its parameter scope). A name resolved below the top of this stack
    /// belongs to an enclosing function and must be captured, not read
    /// directly — closures cannot reach across a function boundary via a
    /// bare `SymbolId` the way a nested block can.
    function_boundaries: Vec<usize>,
    /// Captures recorded for the function currently being lowered, one
    /// frame per open function boundary.
    pending_captures: Vec<Vec<LambdaCapture>>,
    /// Resolved `import`/`require` bindings for the file currently being
    /// lowered, set once up front by `project_index` before any statement
    /// lowering runs, then read (never mutated) by call lowering.
    import_bindings: HashMap<String, ImportBinding>,
    /// Bare top-level name -> this file's own qualified name, for every
    /// `function`/`class` this file declares at module scope. Populated by
    /// a pre-scan of the whole file *before* any statement lowering runs
    /// (mirroring real JS function-declaration hoisting: the name is
    /// resolvable from anywhere in the file, including a call that appears
    /// textually before the declaration). Without this, a same-file call
    /// like `sink(id)` would lower to an unqualified `Callee::Static("sink")`
    /// that can never match `sink`'s real declared name (`"service.sink"`),
    /// silently breaking intra-file call resolution in the taint engine.
    top_level_functions: HashMap<String, String>,
    /// A local variable's own qualified-name provenance, when its
    /// initializer had one (`const view = angular.element("#x")` records
    /// `view -> "angular.element"`) — keyed by `SymbolId` (not name) since
    /// `SymbolId`s are never reused, so this needs no scope-exit cleanup the
    /// way name-keyed maps would. Read by `expr::expression_qualifier` to
    /// let further chaining off a local (`view.append(...)` ->
    /// `angular.element.append`) resolve the same way chaining directly off
    /// a `require()`/global qualifier already does.
    value_qualifiers: HashMap<SymbolId, String>,
}

impl JsEnv {
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::new()],
            function_boundaries: vec![0],
            pending_captures: vec![Vec::new()],
            import_bindings: HashMap::new(),
            top_level_functions: HashMap::new(),
            value_qualifiers: HashMap::new(),
        }
    }

    pub fn set_value_qualifier(&mut self, symbol: SymbolId, qualifier: impl Into<String>) {
        self.value_qualifiers.insert(symbol, qualifier.into());
    }

    pub fn value_qualifier(&self, symbol: SymbolId) -> Option<&str> {
        self.value_qualifiers.get(&symbol).map(String::as_str)
    }

    /// A read-only lookup across the entire scope stack, ignoring function
    /// boundaries — this is only ever used to ask "does this name currently
    /// refer to some symbol" for qualifier propagation, which needs no
    /// closure-capture semantics (unlike [`Self::resolve`]).
    pub fn peek(&self, name: &str) -> Option<SymbolId> {
        self.scopes.iter().rev().find_map(|frame| frame.get(name).copied())
    }

    pub fn set_import_binding(&mut self, local_name: impl Into<String>, binding: ImportBinding) {
        self.import_bindings.insert(local_name.into(), binding);
    }

    pub fn import_binding(&self, local_name: &str) -> Option<&ImportBinding> {
        self.import_bindings.get(local_name)
    }

    pub fn register_top_level_function(&mut self, bare_name: impl Into<String>, qualified_name: impl Into<String>) {
        self.top_level_functions.insert(bare_name.into(), qualified_name.into());
    }

    pub fn top_level_function(&self, bare_name: &str) -> Option<&str> {
        self.top_level_functions.get(bare_name).map(String::as_str)
    }

    pub fn push_block(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn pop_block(&mut self) {
        self.scopes.pop();
    }

    /// Enters a new function body's scope; returns nothing but must be
    /// paired with [`Self::leave_function`], which returns the captures
    /// recorded while it was open.
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

    /// Declares `name` in the innermost (block-scoped `let`/`const`) scope.
    pub fn declare(&mut self, name: &str, symbol: SymbolId) {
        self.scopes.last_mut().expect("at least one scope").insert(name.to_string(), symbol);
    }

    /// Declares `name` with `var`'s hoisted-to-function-scope semantics:
    /// binds in the scope at the current function's own boundary, not the
    /// innermost block, so `if (x) { var y = 1; } return y;` sees `y`.
    pub fn declare_var(&mut self, name: &str, symbol: SymbolId) {
        let boundary = *self.function_boundaries.last().expect("at least one function boundary");
        self.scopes[boundary].insert(name.to_string(), symbol);
    }

    /// Resolves `name`, allocating a fresh capture symbol (and recording the
    /// `LambdaCapture`) the first time a reference crosses into an
    /// enclosing function's scope. Returns `None` for a genuinely free name
    /// (a global, an undeclared identifier) — callers treat that as an
    /// opaque external reference, not an error.
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
    /// captured value it was never itself given (surfaced as a "value used
    /// without a definition" IR-validation error — see `uniflow_lang_rust`,
    /// where this same bug was first found and fixed via a self-hosting
    /// test lowering a real, deeply-nested-closure-heavy source file).
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

impl Default for JsEnv {
    fn default() -> Self {
        Self::new()
    }
}
