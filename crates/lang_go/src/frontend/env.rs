use std::collections::{HashMap, HashSet};

use uniflow_hir::{LambdaCapture, SymbolId, SymbolKind};
use uniflow_parser_core::ModuleBuilder;

/// Lexical scope + closure-capture tracking for one Go source file, mirroring
/// the `JsEnv` pattern `uniflow_lang_javascript` uses. Go's block scoping is
/// uniform (no `var`-style function-scoped hoisting the way JS has), so this
/// is simpler than `JsEnv` in that respect; it still needs the same
/// function-boundary/capture machinery because `FuncLit` (Go's closure
/// literal) can read variables from an enclosing function.
pub struct GoEnv {
    scopes: Vec<HashMap<String, SymbolId>>,
    /// Index into `scopes` where each currently-open function body begins.
    /// A name resolved below the top of this stack belongs to an enclosing
    /// function and must be captured, not read directly.
    function_boundaries: Vec<usize>,
    /// Captures recorded for the function currently being lowered, one frame
    /// per open function boundary.
    pending_captures: Vec<Vec<LambdaCapture>>,
    /// Local package-identifier -> qualified name to combine with a selected
    /// member (`os` -> `os`, `http` -> `net/http` for `import "net/http"`, or
    /// a project-internal package's own declared name when the import path
    /// resolves to another file in this project — see
    /// `project_index::GoProjectIndex::resolve_import`). Every Go import
    /// binds a namespace identifier only (Go has no `import { x } from
    /// "y"`-style named imports), so this is a plain string qualifier rather
    /// than JS's `ImportBinding` enum.
    import_bindings: HashMap<String, String>,
    /// Bare free-function name -> this PACKAGE's own qualified name for it
    /// (`"main.Helper"`), covering every file that shares this file's
    /// `package` clause — not just this file's own declarations. Populated
    /// up front (see `project_index`/`decl::lower_file`'s pass 0) so a call
    /// to a sibling-file, same-package function resolves correctly even
    /// with zero import, matching real Go package-scope semantics.
    package_functions: HashMap<String, String>,
    /// Bare type names declared anywhere in this package (struct or not),
    /// used by `expr::type_qualifier` to decide whether a bare identifier
    /// used in type position names a locally declared type (-> qualify with
    /// this package's own prefix) or something else (left bare).
    package_types: HashSet<String>,
    /// A local variable/parameter's own qualified-name provenance, when
    /// known (a typed parameter's declared type, a receiver's own type, a
    /// `:=`/`var` binding whose initializer had one) — keyed by `SymbolId`
    /// so no scope-exit cleanup is needed. Read by `expr::expression_qualifier`
    /// to let a call through the value (`r.FormValue(...)`) resolve to a
    /// real qualified callee name.
    value_qualifiers: HashMap<SymbolId, String>,
    /// This file's own package's declared name (`package main` -> "main"),
    /// used as the qualifier prefix for every package-level symbol.
    package_qualifier: String,
}

impl GoEnv {
    pub fn new(package_qualifier: impl Into<String>) -> Self {
        Self {
            scopes: vec![HashMap::new()],
            function_boundaries: vec![0],
            pending_captures: vec![Vec::new()],
            import_bindings: HashMap::new(),
            package_functions: HashMap::new(),
            package_types: HashSet::new(),
            value_qualifiers: HashMap::new(),
            package_qualifier: package_qualifier.into(),
        }
    }

    pub fn package_qualifier(&self) -> &str {
        &self.package_qualifier
    }

    pub fn set_import_binding(&mut self, local_name: impl Into<String>, qualifier: impl Into<String>) {
        self.import_bindings.insert(local_name.into(), qualifier.into());
    }

    pub fn import_binding(&self, local_name: &str) -> Option<&str> {
        self.import_bindings.get(local_name).map(String::as_str)
    }

    pub fn register_package_function(&mut self, bare_name: impl Into<String>, qualified_name: impl Into<String>) {
        self.package_functions.insert(bare_name.into(), qualified_name.into());
    }

    pub fn package_function(&self, bare_name: &str) -> Option<&str> {
        self.package_functions.get(bare_name).map(String::as_str)
    }

    pub fn register_package_type(&mut self, name: impl Into<String>) {
        self.package_types.insert(name.into());
    }

    pub fn is_package_type(&self, name: &str) -> bool {
        self.package_types.contains(name)
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

    pub fn push_block(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub fn pop_block(&mut self) {
        self.scopes.pop();
    }

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

    /// Declares `name` in the innermost (current block) scope.
    pub fn declare(&mut self, name: &str, symbol: SymbolId) {
        self.scopes.last_mut().expect("at least one scope").insert(name.to_string(), symbol);
    }

    /// Declares `name` at the current function's own boundary scope rather
    /// than the innermost block — used only for the "first free reference"
    /// fallback in `expr::resolve_identifier`, so a package-level/global
    /// name referenced from inside a nested block (an `if`, a loop) still
    /// resolves to the SAME symbol the next time it's referenced anywhere
    /// else in the same function, instead of fragmenting into a fresh
    /// symbol per block.
    pub fn declare_hoisted(&mut self, name: &str, symbol: SymbolId) {
        let boundary = *self.function_boundaries.last().expect("at least one function boundary");
        self.scopes[boundary].insert(name.to_string(), symbol);
    }

    /// Resolves `name`, allocating a fresh capture symbol (and recording the
    /// `LambdaCapture`) the first time a reference crosses into an enclosing
    /// function's scope (a `FuncLit` closure reading an outer variable).
    /// Returns `None` for a genuinely free name.
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
