//! A pluggable "hard reasoning" helper for the static analysis engine: when
//! the taint/dataflow engine hits a question it cannot decide structurally
//! — is this constraint satisfiable, what does this reflective call target,
//! what does this unfamiliar business logic actually do — it can consult an
//! [`Oracle`] instead of giving up. Two backends are provided:
//!
//! - [`LeanOracle`]: shells out to a real Lean 4 toolchain's `omega` tactic,
//!   a genuine decision procedure for linear integer-arithmetic
//!   satisfiability/equivalence/implication queries. Exact, but narrow —
//!   only [`Domain::IntegerArithmetic`], and only when a `lean` binary is
//!   actually installed ([`LeanOracle::detect`]).
//! - [`LlmOracle`]: delegates any of the three query shapes to an external
//!   LLM API. Broad, but probabilistic, and — because it sends code/text
//!   content over the network — **never constructed implicitly**; a caller
//!   must build one explicitly with real credentials.
//!
//! [`CompositeOracle`] chains backends together, trying each in turn and
//! falling through only on [`OracleError::Unsupported`]/
//! [`OracleError::BackendUnavailable`].
//!
//! This crate defines the abstraction and the two backends; it does not
//! itself decide *where* the taint engine should call an `Oracle` —
//! wiring a specific decision point (e.g. reflective call-target
//! resolution in `uniflow_value_flow`) is a separate, deliberate
//! integration step for whichever crate owns that decision.

mod composite;
mod error;
mod lean;
mod lean_lang;
mod llm;
mod oracle;
mod query;

pub use composite::CompositeOracle;
pub use error::{OracleError, OracleResult};
pub use lean::LeanOracle;
pub use llm::{LlmOracle, LlmOracleConfig};
pub use oracle::Oracle;
pub use query::{ConstraintKind, ConstraintQuery, Decision, Domain, DynamicTargetQuery, SemanticAnswer, SemanticQuery, TargetSuggestion};
