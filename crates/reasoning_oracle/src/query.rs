//! The three question shapes an [`crate::Oracle`] answers, and their result
//! types. Every query is a small, serializable value — never raw source
//! text alone — so a backend (a subprocess, an HTTP call) can receive it
//! without needing to re-parse the caller's own IR/HIR.

use serde::{Deserialize, Serialize};

/// The domain a [`ConstraintQuery`] is expressed in — which formal theory a
/// backend should reason in. A backend that only understands a subset of
/// these (the [`crate::lean::LeanOracle`] only really understands
/// `IntegerArithmetic`/`Boolean`) returns
/// [`crate::OracleError::Unsupported`] for the rest rather than guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Domain {
    /// Linear integer arithmetic — the domain Lean's `omega` tactic (and
    /// most SMT solvers) decide directly.
    IntegerArithmetic,
    Boolean,
    /// String/regex-shaped reasoning ("does this sanitizer's pattern cover
    /// every string this source pattern can produce?") — generally NOT
    /// decidable by a formal backend in the general case; the LLM backend
    /// is the realistic answer here.
    StringPattern,
    /// Anything not covered by a named theory — only a semantic
    /// (LLM-backed) oracle can attempt this.
    Uninterpreted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstraintKind {
    /// Are `lhs` and `rhs` semantically equivalent (same value for every
    /// input)?
    Equivalence,
    /// Is `lhs` (a boolean-valued expression) satisfiable under `context`?
    Satisfiability,
    /// Does `lhs` being true guarantee `rhs` is true (`lhs => rhs`)?
    Implication,
}

/// A request to decide a formal property of one or two expressions, each
/// given as source text in `language` plus small `context` bindings (free
/// variable name -> a type/range hint, e.g. `("x", "0..255")`) — enough for
/// a backend to translate into its own representation without needing the
/// caller's full symbol table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConstraintQuery {
    pub kind: ConstraintKind,
    pub domain: Domain,
    pub language: String,
    pub lhs: String,
    /// Required for `Equivalence`/`Implication`, absent for
    /// `Satisfiability` (which only judges `lhs` on its own).
    pub rhs: Option<String>,
    pub context: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Decision {
    Satisfiable,
    Unsatisfiable,
    Equivalent,
    NotEquivalent,
    Implies,
    DoesNotImply,
    /// The backend engaged with the query but couldn't reach a conclusive
    /// answer (e.g. an LLM backend genuinely unsure) — distinct from
    /// [`crate::OracleError::Unsupported`], which means the backend never
    /// attempted the query at all.
    Unknown,
}

/// A dynamic/reflective call site the static engine could not resolve
/// structurally — e.g. Java `Class.forName(cls).getMethod(name).invoke(...)`,
/// Ruby `send(method_name)`, a JS computed member call through an
/// opaque value. `known_literals` carries whatever fragments the engine
/// *could* recover statically (a partial string, a type hint); when the
/// static engine already enumerated a closed candidate set (e.g. "every
/// method named at least partially like this in scope"),
/// `candidate_targets` narrows the question to "which of these" rather
/// than "guess freely".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicTargetQuery {
    pub language: String,
    pub call_site_text: String,
    pub known_literals: Vec<String>,
    pub candidate_targets: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetSuggestion {
    /// Qualified name -> confidence in `[0.0, 1.0]`, most-likely first.
    pub targets: Vec<(String, f32)>,
    pub rationale: String,
}

/// A natural-language question about a code snippet the engine's own rule
/// matchers can't structurally answer (e.g. "does this function perform an
/// authorization check before touching `record`?").
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticQuery {
    pub language: String,
    pub code_snippet: String,
    pub question: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticAnswer {
    pub answer: String,
    pub confidence: f32,
    pub rationale: String,
}
