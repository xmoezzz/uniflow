//! A [`crate::Oracle`] backend for [`crate::Domain::IntegerArithmetic`]
//! constraint queries, backed by a real Lean 4 toolchain's `omega` tactic —
//! a complete decision procedure for linear (Presburger) integer
//! arithmetic. Shells out to a `lean` binary on `PATH` rather than linking
//! Lean's runtime directly: Lean 4 ships as a full compiler toolchain (its
//! own bootstrapped language plus a C runtime), and driving it as a
//! subprocess over a small generated `.lean` file is the practical way to
//! use it as a decision-procedure oracle without vendoring/FFI-linking that
//! whole toolchain into this binary. `LeanOracle::detect` reports whether a
//! usable `lean` is even present so a caller (or [`crate::CompositeOracle`])
//! can skip straight to another backend when it isn't.
//!
//! Only `Domain::IntegerArithmetic` is implemented for real: proving a
//! decision either way is checked by attempting BOTH the positive and the
//! negated goal via `omega` and trusting whichever one Lean's kernel
//! actually accepts (an exit-code check, not error-text parsing) — if
//! neither compiles (the query falls outside the linear-arithmetic fragment
//! `omega` decides, e.g. a product of two free variables), the honest
//! answer is [`crate::Decision::Unknown`], not a guess.
//! `Domain::Boolean`/`StringPattern`/`Uninterpreted` return
//! [`crate::OracleError::Unsupported`] — deliberately not attempted, since
//! this crate was built without a Lean toolchain available to verify
//! non-`omega` tactic behavior against (see the module's test module for
//! what *is* exercised here: the pure parser/codegen, gated independently
//! of any `lean` binary).

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{OracleError, OracleResult};
use crate::lean_lang::{free_vars, parse, render_lean};
use crate::oracle::Oracle;
use crate::query::{ConstraintKind, ConstraintQuery, Decision, Domain};

pub struct LeanOracle {
    lean_binary: PathBuf,
}

impl LeanOracle {
    /// Looks for a `lean` binary on `PATH`; returns `None` (not an error —
    /// this is a normal, expected outcome on most machines) when absent.
    pub fn detect() -> Option<Self> {
        Self::detect_named("lean")
    }

    /// Same as [`Self::detect`], but for a caller that already knows a
    /// specific `lean` binary path (e.g. from a project-local toolchain) —
    /// mainly here so tests/tools don't have to depend on `PATH` layout.
    pub fn detect_named(binary: &str) -> Option<Self> {
        let found = which(binary)?;
        Some(Self { lean_binary: found })
    }

    fn run_lean_source(&self, source: &str) -> std::io::Result<bool> {
        let dir = std::env::temp_dir().join(format!("uniflow-lean-oracle-{}-{}", std::process::id(), unique_suffix()));
        std::fs::create_dir_all(&dir)?;
        let file_path = dir.join("Query.lean");
        {
            let mut file = std::fs::File::create(&file_path)?;
            file.write_all(source.as_bytes())?;
        }
        let output = Command::new(&self.lean_binary).arg(&file_path).output();
        let _ = std::fs::remove_dir_all(&dir);
        Ok(output?.status.success())
    }

    fn bound_hypotheses(vars: &[String], context: &[(String, String)]) -> Vec<String> {
        vars.iter()
            .filter_map(|name| {
                let (_, range) = context.iter().find(|(key, _)| key == name)?;
                let (low, high) = range.split_once("..")?;
                let low: i64 = low.trim().parse().ok()?;
                let high: i64 = high.trim().parse().ok()?;
                Some(format!("({name} \u{2265} {low}) \u{2227} ({name} < {high})"))
            })
            .collect()
    }

    fn conjunction(parts: &[String]) -> Option<String> {
        let mut iter = parts.iter();
        let first = iter.next()?.clone();
        Some(iter.fold(first, |acc, part| format!("({acc} \u{2227} {part})")))
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default()
}

fn which(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).map(|dir| dir.join(binary)).find(|candidate| candidate.is_file())
}

impl Oracle for LeanOracle {
    fn name(&self) -> &str {
        "lean-omega"
    }

    fn decide_constraint(&self, query: &ConstraintQuery) -> OracleResult<Decision> {
        if query.domain != Domain::IntegerArithmetic {
            return Err(OracleError::Unsupported);
        }
        let lhs = parse(&query.lhs).map_err(|error| OracleError::Other(error.to_string()))?;
        let rhs = query.rhs.as_deref().map(parse).transpose().map_err(|error| OracleError::Other(error.to_string()))?;

        let mut vars = Vec::new();
        free_vars(&lhs, &mut vars);
        if let Some(rhs) = &rhs {
            free_vars(rhs, &mut vars);
        }
        let binder = if vars.is_empty() { String::new() } else { format!("({} : Int) ", vars.join(" ")) };
        let bounds = Self::bound_hypotheses(&vars, &query.context);

        let (positive, negative) = match query.kind {
            ConstraintKind::Satisfiability => {
                let mut body_parts = bounds.clone();
                body_parts.push(render_lean(&lhs));
                let body = Self::conjunction(&body_parts).unwrap_or_else(|| render_lean(&lhs));
                let exists_clause = if vars.is_empty() { body } else { format!("\u{2203} {}, {body}", vars.join(" ")) };
                let positive = format!("theorem sat : {exists_clause} := by omega");

                let neg_lhs = format!("(\u{00ac} {})", render_lean(&lhs));
                let negative = match Self::conjunction(&bounds) {
                    Some(hyp) => format!("theorem unsat {binder}(h : {hyp}) : {neg_lhs} := by omega"),
                    None => format!("theorem unsat {binder}: {neg_lhs} := by omega"),
                };
                (positive, negative)
            }
            ConstraintKind::Equivalence => {
                let rhs = rhs.ok_or_else(|| OracleError::Other("equivalence query requires `rhs`".to_string()))?;
                let hyp = Self::conjunction(&bounds);
                let goal = format!("{} = {}", render_lean(&lhs), render_lean(&rhs));
                let positive = match &hyp {
                    Some(hyp) => format!("theorem equiv {binder}(h : {hyp}) : {goal} := by omega"),
                    None => format!("theorem equiv {binder}: {goal} := by omega"),
                };
                let mut counterexample_body = bounds.clone();
                counterexample_body.push(format!("{} \u{2260} {}", render_lean(&lhs), render_lean(&rhs)));
                let body = Self::conjunction(&counterexample_body).unwrap();
                let exists_clause = if vars.is_empty() { body } else { format!("\u{2203} {}, {body}", vars.join(" ")) };
                let negative = format!("theorem not_equiv : {exists_clause} := by omega");
                (positive, negative)
            }
            ConstraintKind::Implication => {
                let rhs = rhs.ok_or_else(|| OracleError::Other("implication query requires `rhs`".to_string()))?;
                let mut hyp_parts = bounds.clone();
                hyp_parts.push(render_lean(&lhs));
                let hyp = Self::conjunction(&hyp_parts).unwrap();
                let positive = format!("theorem implies {binder}(h : {hyp}) : {} := by omega", render_lean(&rhs));
                let mut counterexample_body = bounds.clone();
                counterexample_body.push(render_lean(&lhs));
                counterexample_body.push(format!("\u{00ac} {}", render_lean(&rhs)));
                let body = Self::conjunction(&counterexample_body).unwrap();
                let exists_clause = if vars.is_empty() { body } else { format!("\u{2203} {}, {body}", vars.join(" ")) };
                let negative = format!("theorem not_implies : {exists_clause} := by omega");
                (positive, negative)
            }
        };

        let positive_ok = self.run_lean_source(&positive).map_err(|error| OracleError::Other(error.to_string()))?;
        if positive_ok {
            return Ok(match query.kind {
                ConstraintKind::Satisfiability => Decision::Satisfiable,
                ConstraintKind::Equivalence => Decision::Equivalent,
                ConstraintKind::Implication => Decision::Implies,
            });
        }
        let negative_ok = self.run_lean_source(&negative).map_err(|error| OracleError::Other(error.to_string()))?;
        if negative_ok {
            return Ok(match query.kind {
                ConstraintKind::Satisfiability => Decision::Unsatisfiable,
                ConstraintKind::Equivalence => Decision::NotEquivalent,
                ConstraintKind::Implication => Decision::DoesNotImply,
            });
        }
        Ok(Decision::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraint(kind: ConstraintKind, lhs: &str, rhs: Option<&str>) -> ConstraintQuery {
        ConstraintQuery { kind, domain: Domain::IntegerArithmetic, language: "generic".to_string(), lhs: lhs.to_string(), rhs: rhs.map(str::to_string), context: Vec::new() }
    }

    #[test]
    fn non_integer_domain_is_unsupported_without_needing_a_lean_binary() {
        let oracle = LeanOracle { lean_binary: PathBuf::from("lean") };
        let query = ConstraintQuery { domain: Domain::StringPattern, ..constraint(ConstraintKind::Satisfiability, "true", None) };
        assert!(matches!(oracle.decide_constraint(&query), Err(OracleError::Unsupported)));
    }

    #[test]
    fn bound_hypotheses_parse_inclusive_exclusive_ranges() {
        let bounds = LeanOracle::bound_hypotheses(&["x".to_string()], &[("x".to_string(), "0..256".to_string())]);
        assert_eq!(bounds, vec!["(x \u{2265} 0) \u{2227} (x < 256)".to_string()]);
    }

    #[test]
    fn detect_named_returns_none_for_a_binary_that_does_not_exist() {
        assert!(LeanOracle::detect_named("uniflow-definitely-not-a-real-binary").is_none());
    }

    /// Only runs the actual decision procedure when a real `lean` toolchain
    /// is present on `PATH` — this sandbox does not have one, so this test
    /// is expected to skip in CI here, but will exercise the real subprocess
    /// path (and validate the theorem-generation strategy end to end)
    /// wherever a Lean 4 toolchain with core `omega` support is installed.
    #[test]
    fn a_real_lean_toolchain_decides_a_simple_bounds_satisfiability_query() {
        let Some(oracle) = LeanOracle::detect() else {
            eprintln!("skipping: no `lean` binary on PATH in this environment");
            return;
        };
        let query = constraint(ConstraintKind::Satisfiability, "x >= 0 && x < 10", None);
        let decision = oracle.decide_constraint(&query).expect("lean invocation should succeed");
        assert_eq!(decision, Decision::Satisfiable);

        let unsat_query = constraint(ConstraintKind::Satisfiability, "x >= 10 && x < 0", None);
        let decision = oracle.decide_constraint(&unsat_query).expect("lean invocation should succeed");
        assert_eq!(decision, Decision::Unsatisfiable);

        let equiv_query = constraint(ConstraintKind::Equivalence, "x + 1", Some("1 + x"));
        let decision = oracle.decide_constraint(&equiv_query).expect("lean invocation should succeed");
        assert_eq!(decision, Decision::Equivalent);
    }
}
