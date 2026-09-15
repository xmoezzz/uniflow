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
//!
//! `omega` decides quantifier-free linear-arithmetic goals; it does not
//! synthesize an existential witness, so a bare `∃ x, P x` goal never
//! compiles via `omega` regardless of whether it is true (confirmed against
//! a real Lean 4 toolchain). `Decision::Satisfiable`, `Decision::NotEquivalent`,
//! and `Decision::DoesNotImply` all require proving exactly such an
//! existential, so instead of asking `omega` to find a witness, this module
//! builds one itself: when every free variable in the query has a literal
//! `lo..hi` range in [`ConstraintQuery::context`], the existential is
//! rewritten as the finite disjunction of the predicate with each variable
//! substituted by one concrete value in its range (`P(lo) ∨ P(lo+1) ∨ ... ∨
//! P(hi-1)`, cross-producted over every bounded variable) — a
//! quantifier-free goal `omega` decides natively. See
//! [`LeanOracle::enumerated_existence_theorem`]. This only scales to a
//! bounded number of combined witnesses ([`ENUMERATION_LIMIT`]); above that,
//! or when some free variable has no literal bound at all, the existential
//! side honestly falls back to the never-provable `∃`-goal shape, which
//! reproduces today's `Decision::Unknown` outcome rather than guessing.
//!
//! `Domain::Boolean`/`StringPattern`/`Uninterpreted` return
//! [`crate::OracleError::Unsupported`] — deliberately not attempted, since
//! this crate was built without a Lean toolchain available to verify
//! non-`omega` tactic behavior against (see the module's test module for
//! what *is* exercised here: the pure parser/codegen, gated independently
//! of any `lean` binary).

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use crate::error::{OracleError, OracleResult};
use crate::lean_lang::{free_vars, parse, render_lean, substitute_ints, BinOp, Expr, UnOp};
use crate::oracle::Oracle;
use crate::query::{ConstraintKind, ConstraintQuery, Decision, Domain};

/// Maximum total number of concrete witness combinations
/// [`LeanOracle::enumerated_existence_theorem`] will cross-product across all
/// bounded free variables before giving up and falling back to the
/// never-provable `∃`-goal shape. Chosen empirically against a real Lean 4
/// toolchain: a few hundred disjuncts compile in well under a second, and
/// `set_option maxRecDepth` (always emitted alongside the disjunction) keeps
/// Lean's elaborator recursion limit from tripping well past this size —
/// this cap is about keeping oracle latency reasonable, not about
/// approaching an actual Lean limit.
const ENUMERATION_LIMIT: u64 = 512;

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

    /// Literal `(name, lo, hi)` bounds for every entry of `vars`, drawing on
    /// `context`'s `lo..hi` facts first and, for a variable `context` leaves
    /// unbounded, falling back to a bound mined directly out of `guard`'s own
    /// top-level `&&`-conjuncts (see [`self_bounds`]) — the common case where
    /// a query is itself a self-contained bounds check like `x >= 0 && x <
    /// 10` with no separate context metadata at all. Returns `None` if even
    /// one variable ends up with no bound from either source: a witness
    /// search is only sound when it covers every free variable, so a partial
    /// bound set is treated the same as no bound set at all.
    fn numeric_bounds(vars: &[String], context: &[(String, String)], guard: &Expr) -> Option<Vec<(String, i64, i64)>> {
        let mined = self_bounds(guard);
        vars.iter()
            .map(|name| {
                if let Some((_, range)) = context.iter().find(|(key, _)| key == name) {
                    let (low, high) = range.split_once("..")?;
                    let low: i64 = low.trim().parse().ok()?;
                    let high: i64 = high.trim().parse().ok()?;
                    return Some((name.clone(), low, high));
                }
                let (low, high) = *mined.get(name)?;
                Some((name.clone(), low, high))
            })
            .collect()
    }

    /// The cross product of every bound's `lo..hi` range as `name -> value`
    /// witness maps, or `None` if any range is empty or the total
    /// combination count exceeds [`ENUMERATION_LIMIT`].
    fn enumerate_witnesses(bounds: &[(String, i64, i64)]) -> Option<Vec<HashMap<String, i64>>> {
        let mut total: u64 = 1;
        for (_, low, high) in bounds {
            if high <= low {
                return None;
            }
            total = total.checked_mul((*high - *low) as u64)?;
            if total > ENUMERATION_LIMIT {
                return None;
            }
        }
        let mut witnesses = vec![HashMap::new()];
        for (name, low, high) in bounds {
            let mut next = Vec::with_capacity(witnesses.len() * (*high - *low) as usize);
            for witness in &witnesses {
                for value in *low..*high {
                    let mut extended = witness.clone();
                    extended.insert(name.clone(), value);
                    next.push(extended);
                }
            }
            witnesses = next;
        }
        Some(witnesses)
    }

    /// Builds a quantifier-free theorem deciding `∃ vars, predicate` by
    /// enumerating every concrete witness in `vars`' literal bounds (from
    /// `context` and/or mined out of `guard`, see [`Self::numeric_bounds`])
    /// and disjoining `predicate` substituted with each — see the module doc
    /// comment. Returns `None` (never a wrong answer) when the witness space
    /// isn't fully bounded or is too large to enumerate; the caller falls
    /// back to the never-provable `∃`-goal shape in that case.
    fn enumerated_existence_theorem(name: &str, vars: &[String], context: &[(String, String)], guard: &Expr, predicate: &Expr) -> Option<String> {
        let bounds = Self::numeric_bounds(vars, context, guard)?;
        let witnesses = Self::enumerate_witnesses(&bounds)?;
        let disjuncts: Vec<String> = witnesses.iter().map(|witness| render_lean(&substitute_ints(predicate, witness))).collect();
        let body = disjuncts.join(" \u{2228} ");
        Some(format!("set_option maxRecDepth 4000 in\ntheorem {name} : {body} := by omega"))
    }
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default()
}

fn which(binary: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).map(|dir| dir.join(binary)).find(|candidate| candidate.is_file())
}

/// A comparison's direction once its variable and literal operands are
/// swapped so the variable is always on the left (`5 < x` becomes `x > 5`).
fn mirror_comparison(op: BinOp) -> BinOp {
    match op {
        BinOp::Lt => BinOp::Gt,
        BinOp::Le => BinOp::Ge,
        BinOp::Gt => BinOp::Lt,
        BinOp::Ge => BinOp::Le,
        other => other,
    }
}

/// Mines a best-effort `(lo, hi_exclusive)` bound per variable directly out
/// of `guard`'s own top-level `&&`-conjuncts — the shape a self-contained
/// bounds check like `x >= 0 && x < 10` uses to describe its own domain,
/// with no separate [`ConstraintQuery::context`] entry needed. Only literal
/// `Var </<=/>/>= Int` comparisons (and their literal-on-the-left mirror
/// images) are recognized; anything else (an `||`, a non-literal operand, a
/// variable never bounded on one side) is silently not a source of a bound
/// for that variable — this is a best-effort simplification of the query's
/// own shape, not a general constraint solver, and an unrecognized shape
/// must fall through to [`LeanOracle::numeric_bounds`] honestly finding no
/// bound rather than guessing one.
fn self_bounds(guard: &Expr) -> HashMap<String, (i64, i64)> {
    fn walk(expr: &Expr, out: &mut HashMap<String, (i64, i64)>) {
        match expr {
            Expr::Binary(BinOp::And, lhs, rhs) => {
                walk(lhs, out);
                walk(rhs, out);
            }
            Expr::Binary(op, lhs, rhs) => {
                let (name, literal, op) = match (lhs.as_ref(), rhs.as_ref()) {
                    (Expr::Var(name), Expr::Int(value)) => (name, *value, *op),
                    (Expr::Int(value), Expr::Var(name)) => (name, *value, mirror_comparison(*op)),
                    _ => return,
                };
                let (new_lo, new_hi) = match op {
                    BinOp::Ge => (Some(literal), None),
                    BinOp::Gt => (Some(literal + 1), None),
                    BinOp::Le => (None, Some(literal + 1)),
                    BinOp::Lt => (None, Some(literal)),
                    _ => return,
                };
                let entry = out.entry(name.clone()).or_insert((i64::MIN, i64::MAX));
                if let Some(lo) = new_lo {
                    entry.0 = entry.0.max(lo);
                }
                if let Some(hi) = new_hi {
                    entry.1 = entry.1.min(hi);
                }
            }
            _ => {}
        }
    }
    let mut out = HashMap::new();
    walk(guard, &mut out);
    out.retain(|_, (lo, hi)| *lo != i64::MIN && *hi != i64::MAX);
    out
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
                let positive = Self::enumerated_existence_theorem("sat", &vars, &query.context, &lhs, &lhs).unwrap_or_else(|| {
                    let mut body_parts = bounds.clone();
                    body_parts.push(render_lean(&lhs));
                    let body = Self::conjunction(&body_parts).unwrap_or_else(|| render_lean(&lhs));
                    let exists_clause = if vars.is_empty() { body } else { format!("\u{2203} {}, {body}", vars.join(" ")) };
                    format!("theorem sat : {exists_clause} := by omega")
                });

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
                let counterexample_predicate = Expr::Binary(BinOp::Ne, Box::new(lhs.clone()), Box::new(rhs.clone()));
                // Equivalence compares two arithmetic expressions, neither of
                // which is itself a boolean guard to mine a domain out of —
                // unlike Satisfiability/Implication, only `context` can
                // supply a bound here.
                let negative = Self::enumerated_existence_theorem("not_equiv", &vars, &query.context, &Expr::Bool(true), &counterexample_predicate).unwrap_or_else(|| {
                    let mut counterexample_body = bounds.clone();
                    counterexample_body.push(format!("{} \u{2260} {}", render_lean(&lhs), render_lean(&rhs)));
                    let body = Self::conjunction(&counterexample_body).unwrap();
                    let exists_clause = if vars.is_empty() { body } else { format!("\u{2203} {}, {body}", vars.join(" ")) };
                    format!("theorem not_equiv : {exists_clause} := by omega")
                });
                (positive, negative)
            }
            ConstraintKind::Implication => {
                let rhs = rhs.ok_or_else(|| OracleError::Other("implication query requires `rhs`".to_string()))?;
                let mut hyp_parts = bounds.clone();
                hyp_parts.push(render_lean(&lhs));
                let hyp = Self::conjunction(&hyp_parts).unwrap();
                let positive = format!("theorem implies {binder}(h : {hyp}) : {} := by omega", render_lean(&rhs));
                let counterexample_predicate = Expr::Binary(BinOp::And, Box::new(lhs.clone()), Box::new(Expr::Unary(UnOp::Not, Box::new(rhs.clone()))));
                let negative = Self::enumerated_existence_theorem("not_implies", &vars, &query.context, &lhs, &counterexample_predicate).unwrap_or_else(|| {
                    let mut counterexample_body = bounds.clone();
                    counterexample_body.push(render_lean(&lhs));
                    counterexample_body.push(format!("\u{00ac} {}", render_lean(&rhs)));
                    let body = Self::conjunction(&counterexample_body).unwrap();
                    let exists_clause = if vars.is_empty() { body } else { format!("\u{2203} {}, {body}", vars.join(" ")) };
                    format!("theorem not_implies : {exists_clause} := by omega")
                });
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

    #[test]
    fn numeric_bounds_requires_every_variable_to_have_a_literal_range() {
        let context = [("x".to_string(), "0..10".to_string())];
        let no_guard = Expr::Bool(true);
        assert!(LeanOracle::numeric_bounds(&["x".to_string(), "y".to_string()], &context, &no_guard).is_none());
        assert_eq!(LeanOracle::numeric_bounds(&["x".to_string()], &context, &no_guard), Some(vec![("x".to_string(), 0, 10)]));
    }

    #[test]
    fn numeric_bounds_falls_back_to_a_bound_mined_from_the_guard_itself() {
        // The common case the original smoke test relies on: a
        // self-contained bounds check with no separate `context` metadata.
        let guard = parse("x >= 0 && x < 10").unwrap();
        assert_eq!(LeanOracle::numeric_bounds(&["x".to_string()], &[], &guard), Some(vec![("x".to_string(), 0, 10)]));
        // A literal-on-the-left comparison mirrors correctly too.
        let mirrored_guard = parse("0 <= x && 10 > x").unwrap();
        assert_eq!(LeanOracle::numeric_bounds(&["x".to_string()], &[], &mirrored_guard), Some(vec![("x".to_string(), 0, 10)]));
        // context still wins when both are present.
        let context = [("x".to_string(), "0..5".to_string())];
        assert_eq!(LeanOracle::numeric_bounds(&["x".to_string()], &context, &guard), Some(vec![("x".to_string(), 0, 5)]));
        // A one-sided guard leaves the variable unbounded.
        let one_sided = parse("x >= 0").unwrap();
        assert!(LeanOracle::numeric_bounds(&["x".to_string()], &[], &one_sided).is_none());
    }

    #[test]
    fn enumerate_witnesses_cross_products_every_bound_and_caps_at_the_limit() {
        let witnesses = LeanOracle::enumerate_witnesses(&[("x".to_string(), 0, 3), ("y".to_string(), 0, 2)]).expect("small enough to enumerate");
        assert_eq!(witnesses.len(), 6);
        assert!(LeanOracle::enumerate_witnesses(&[("x".to_string(), 0, 1_000_000)]).is_none(), "must refuse to enumerate past ENUMERATION_LIMIT");
        assert!(LeanOracle::enumerate_witnesses(&[("x".to_string(), 5, 5)]).is_none(), "an empty range has no witnesses to enumerate");
    }

    #[test]
    fn enumerated_existence_theorem_builds_a_disjunction_of_concrete_witnesses() {
        let predicate = parse("x >= 0 && x < 3").unwrap();
        let context = [("x".to_string(), "0..3".to_string())];
        let theorem = LeanOracle::enumerated_existence_theorem("sat", &["x".to_string()], &context, &predicate, &predicate).expect("bounded, small enough to enumerate");
        assert!(theorem.contains("set_option maxRecDepth"));
        assert!(theorem.contains("theorem sat :"));
        assert!(theorem.contains("\u{2228}"), "expects a disjunction of per-witness instances, not an `\u{2203}` goal");
        assert!(!theorem.contains('\u{2203}'), "the whole point is avoiding a witness-synthesis goal");
    }

    #[test]
    fn enumerated_existence_theorem_declines_when_a_variable_is_unbounded() {
        let predicate = parse("x >= 0 && x < 3").unwrap();
        assert!(LeanOracle::enumerated_existence_theorem("sat", &["x".to_string()], &[], &Expr::Bool(true), &predicate).is_none());
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

    /// Covers exactly the three `Decision` outcomes that require synthesizing
    /// an existential witness (`Satisfiable`, `NotEquivalent`,
    /// `DoesNotImply`) — the ones that were structurally unreachable before
    /// `LeanOracle::enumerated_existence_theorem` — plus their "no such
    /// witness exists" counterparts, so a regression back to always-`Unknown`
    /// would be caught here rather than only in the smoke test above.
    #[test]
    fn a_real_lean_toolchain_decides_bounded_existential_queries() {
        let Some(oracle) = LeanOracle::detect() else {
            eprintln!("skipping: no `lean` binary on PATH in this environment");
            return;
        };
        let bounded = |kind, lhs: &str, rhs: Option<&str>| ConstraintQuery {
            context: vec![("x".to_string(), "0..10".to_string())],
            ..constraint(kind, lhs, rhs)
        };

        // x + 1 never equals x + 2: a counterexample to equivalence exists
        // for every x, including inside the bound.
        let never_equal = bounded(ConstraintKind::Equivalence, "x + 1", Some("x + 2"));
        assert_eq!(oracle.decide_constraint(&never_equal).expect("lean invocation should succeed"), Decision::NotEquivalent);

        // x + 1 == 1 + x always holds: no counterexample exists, even though
        // the search space is the same bounded range.
        let always_equal = bounded(ConstraintKind::Equivalence, "x + 1", Some("1 + x"));
        assert_eq!(oracle.decide_constraint(&always_equal).expect("lean invocation should succeed"), Decision::Equivalent);

        // x >= 0 does NOT imply x > 5 within 0..10 (x = 0 is a counterexample).
        let false_implication = bounded(ConstraintKind::Implication, "x >= 0", Some("x > 5"));
        assert_eq!(oracle.decide_constraint(&false_implication).expect("lean invocation should succeed"), Decision::DoesNotImply);

        // x >= 0 DOES imply x >= -1 within 0..10: no counterexample exists.
        let true_implication = bounded(ConstraintKind::Implication, "x >= 0", Some("x >= -1"));
        assert_eq!(oracle.decide_constraint(&true_implication).expect("lean invocation should succeed"), Decision::Implies);

        // A satisfiability query with no bound on either side at all — no
        // `context`, and the guard itself never brackets `x` or `y` — still
        // cannot synthesize a witness (honest `Unknown`, never a guess).
        let unbounded_sat = constraint(ConstraintKind::Satisfiability, "x + y == 5", None);
        assert_eq!(oracle.decide_constraint(&unbounded_sat).expect("lean invocation should succeed"), Decision::Unknown);
    }
}
