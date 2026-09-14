use crate::error::{OracleError, OracleResult};
use crate::oracle::Oracle;
use crate::query::{ConstraintQuery, Decision, DynamicTargetQuery, SemanticAnswer, SemanticQuery, TargetSuggestion};

/// Tries each backend in order for a given query, moving to the next only
/// when the previous one reports [`OracleError::Unsupported`] or
/// [`OracleError::BackendUnavailable`] — a backend that actually attempted
/// the query and failed for another reason (a timeout, a malformed
/// response) is not silently retried against a weaker backend, since that
/// failure is itself meaningful information for the caller.
///
/// Typical composition: put [`crate::LeanOracle`] first (fast, exact, but
/// narrow) and an [`crate::LlmOracle`] last (broad, but never enabled
/// unless the caller explicitly constructed one with real credentials —
/// see that module's doc comment).
#[derive(Default)]
pub struct CompositeOracle {
    backends: Vec<Box<dyn Oracle>>,
}

impl CompositeOracle {
    pub fn new() -> Self {
        Self { backends: Vec::new() }
    }

    pub fn with_backend(mut self, backend: Box<dyn Oracle>) -> Self {
        self.backends.push(backend);
        self
    }

    fn try_each<T>(&self, mut attempt: impl FnMut(&dyn Oracle) -> OracleResult<T>) -> OracleResult<T> {
        let mut last_error = OracleError::Unsupported;
        for backend in &self.backends {
            match attempt(backend.as_ref()) {
                Ok(value) => return Ok(value),
                Err(OracleError::Unsupported) => continue,
                Err(OracleError::BackendUnavailable(reason)) => {
                    last_error = OracleError::BackendUnavailable(reason);
                    continue;
                }
                Err(other) => return Err(other),
            }
        }
        Err(last_error)
    }
}

impl Oracle for CompositeOracle {
    fn name(&self) -> &str {
        "composite"
    }

    fn decide_constraint(&self, query: &ConstraintQuery) -> OracleResult<Decision> {
        self.try_each(|backend| backend.decide_constraint(query))
    }

    fn resolve_dynamic_target(&self, query: &DynamicTargetQuery) -> OracleResult<TargetSuggestion> {
        self.try_each(|backend| backend.resolve_dynamic_target(query))
    }

    fn interpret_semantics(&self, query: &SemanticQuery) -> OracleResult<SemanticAnswer> {
        self.try_each(|backend| backend.interpret_semantics(query))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysUnsupported;
    impl Oracle for AlwaysUnsupported {
        fn name(&self) -> &str {
            "always-unsupported"
        }
    }

    struct AlwaysSatisfiable;
    impl Oracle for AlwaysSatisfiable {
        fn name(&self) -> &str {
            "always-satisfiable"
        }
        fn decide_constraint(&self, _query: &ConstraintQuery) -> OracleResult<Decision> {
            Ok(Decision::Satisfiable)
        }
    }

    fn sample_query() -> ConstraintQuery {
        ConstraintQuery { kind: crate::query::ConstraintKind::Satisfiability, domain: crate::query::Domain::IntegerArithmetic, language: "generic".to_string(), lhs: "true".to_string(), rhs: None, context: Vec::new() }
    }

    #[test]
    fn falls_through_unsupported_backends_to_a_capable_one() {
        let oracle = CompositeOracle::new().with_backend(Box::new(AlwaysUnsupported)).with_backend(Box::new(AlwaysSatisfiable));
        assert_eq!(oracle.decide_constraint(&sample_query()).unwrap(), Decision::Satisfiable);
    }

    #[test]
    fn reports_unsupported_when_no_backend_can_help() {
        let oracle = CompositeOracle::new().with_backend(Box::new(AlwaysUnsupported));
        assert!(matches!(oracle.decide_constraint(&sample_query()), Err(OracleError::Unsupported)));
    }

    #[test]
    fn an_empty_composite_reports_unsupported() {
        let oracle = CompositeOracle::new();
        assert!(matches!(oracle.decide_constraint(&sample_query()), Err(OracleError::Unsupported)));
    }
}
