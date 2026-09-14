use crate::error::OracleResult;
use crate::query::{ConstraintQuery, Decision, DynamicTargetQuery, SemanticAnswer, SemanticQuery, TargetSuggestion};

/// A pluggable "hard reasoning" backend for the three question shapes the
/// static analysis engine cannot decide on its own: formal
/// equivalence/satisfiability, dynamic/reflective call-target resolution,
/// and open-ended semantic understanding of unfamiliar business logic. Each
/// method is independent — a backend need not implement all three well (or
/// at all; the default provided methods return
/// [`crate::OracleError::Unsupported`]), so a formal backend like
/// [`crate::LeanOracle`] and a semantic backend like [`crate::LlmOracle`]
/// can be combined via [`crate::CompositeOracle`] without either one
/// pretending to cover the other's strength.
pub trait Oracle: Send + Sync {
    fn name(&self) -> &str;

    fn decide_constraint(&self, _query: &ConstraintQuery) -> OracleResult<Decision> {
        Err(crate::error::OracleError::Unsupported)
    }

    fn resolve_dynamic_target(&self, _query: &DynamicTargetQuery) -> OracleResult<TargetSuggestion> {
        Err(crate::error::OracleError::Unsupported)
    }

    fn interpret_semantics(&self, _query: &SemanticQuery) -> OracleResult<SemanticAnswer> {
        Err(crate::error::OracleError::Unsupported)
    }
}
