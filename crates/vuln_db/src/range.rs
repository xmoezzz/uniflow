//! Ported from sca-main's server-side `api-server/src/routes/v1/vuln/
//! search_best_range.rs`: parse each vulnerability's textual version range(s)
//! into bounds, then use a swept-line interval merge to both (a) check
//! whether a queried version falls inside any vulnerable window and (b)
//! recommend the nearest version past the end of that window as a fix —
//! rather than trusting a single hand-picked "fixed_version" field, which a
//! feed doesn't always carry. `versions::Versioning` (rather than the
//! stricter `semver` crate) is used for the same reason sca-main used it:
//! real dependency versions across ecosystems routinely violate strict
//! semver (a `v` prefix, two-component versions, etc.), and this crate
//! parses those leniently instead of rejecting them.
use std::cmp::Ordering;
use std::ops::Bound;
use versions::Versioning;

#[derive(Clone, Debug, PartialEq)]
pub struct VersionRange {
    pub lower: Bound<Versioning>,
    pub upper: Bound<Versioning>,
}

impl VersionRange {
    pub fn contains(&self, version: &Versioning) -> bool {
        let lower_ok = match &self.lower {
            Bound::Unbounded => true,
            Bound::Included(bound) => version >= bound,
            Bound::Excluded(bound) => version > bound,
        };
        let upper_ok = match &self.upper {
            Bound::Unbounded => true,
            Bound::Included(bound) => version <= bound,
            Bound::Excluded(bound) => version < bound,
        };
        lower_ok && upper_ok
    }

    /// Renders the upper bound as the string a "recommended fix" should
    /// show — the boundary version itself for an exclusive bound (the
    /// common, OSV/GHSA-style "fixed in" convention), or `None` for an
    /// inclusive bound (no next real release is known from range data
    /// alone) or an unbounded window (no known fix at all in this data).
    pub fn safe_version_string(&self) -> Option<String> {
        match &self.upper {
            Bound::Excluded(version) => Some(version.to_string()),
            Bound::Included(_) | Bound::Unbounded => None,
        }
    }
}

enum Op {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

fn split_operator(clause: &str) -> Option<(Op, &str)> {
    for (prefix, op) in [(">=", Op::Ge), ("<=", Op::Le), ("==", Op::Eq)] {
        if let Some(rest) = clause.strip_prefix(prefix) {
            return Some((op, rest));
        }
    }
    for (prefix, op) in [(">", Op::Gt), ("<", Op::Lt), ("=", Op::Eq)] {
        if let Some(rest) = clause.strip_prefix(prefix) {
            return Some((op, rest));
        }
    }
    Some((Op::Eq, clause))
}

fn parse_version(raw: &str) -> Option<Versioning> {
    Versioning::new(raw.trim().trim_start_matches(['v', 'V']))
}

/// Parses one vulnerable-range expression, which may be several
/// `||`-separated alternatives (OR), each an optionally comma/space
/// separated set of bound clauses (AND) such as `>=1.0.0,<1.2.0`. A
/// same-direction clause repeated within one AND-group (rare in real feeds)
/// keeps whichever occurrence parses last rather than computing the
/// tightest — real vulnerability feeds essentially never do this, so a
/// simple, non-panicking fallback is enough.
pub fn parse_ranges(expr: &str) -> Vec<VersionRange> {
    expr.split("||").filter_map(parse_group).collect()
}

fn parse_group(group: &str) -> Option<VersionRange> {
    let mut lower = Bound::Unbounded;
    let mut upper = Bound::Unbounded;
    let mut found_any = false;

    for clause in group.split(|c: char| c == ',' || c.is_whitespace()).filter(|c| !c.is_empty()) {
        let (op, version_str) = split_operator(clause)?;
        let Some(version) = parse_version(version_str) else { continue };
        found_any = true;
        match op {
            Op::Ge => lower = Bound::Included(version),
            Op::Gt => lower = Bound::Excluded(version),
            Op::Le => upper = Bound::Included(version),
            Op::Lt => upper = Bound::Excluded(version),
            Op::Eq => {
                lower = Bound::Included(version.clone());
                upper = Bound::Included(version);
            }
        }
    }
    found_any.then_some(VersionRange { lower, upper })
}

fn lower_value(bound: &Bound<Versioning>) -> Option<&Versioning> {
    match bound {
        Bound::Included(v) | Bound::Excluded(v) => Some(v),
        Bound::Unbounded => None,
    }
}

fn compare_lower(a: &Bound<Versioning>, b: &Bound<Versioning>) -> Ordering {
    match (lower_value(a), lower_value(b)) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(x), Some(y)) => x.cmp(y),
    }
}

fn compare_upper(a: &Bound<Versioning>, b: &Bound<Versioning>) -> Ordering {
    match (lower_value(a), lower_value(b)) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    }
}

/// True if `next`'s lower bound starts at or before `prev`'s upper bound —
/// i.e. the two ranges overlap or are adjacent with no real version able to
/// exist strictly between them (versions are discrete, so an `Excluded(v)`
/// upper meeting an `Included(v)` lower at the same `v` is still a touch,
/// not a gap).
fn touches_or_overlaps(prev_upper: &Bound<Versioning>, next_lower: &Bound<Versioning>) -> bool {
    match (lower_value(prev_upper), lower_value(next_lower)) {
        (None, _) | (_, None) => true,
        (Some(prev), Some(next)) => next <= prev,
    }
}

/// The swept-line step: sorts every range by its lower bound and merges
/// overlapping/touching ones into the minimal set of disjoint "known bad"
/// windows. A version just past the end of one of these merged windows is
/// guaranteed not to fall inside any *other* input range either — if it
/// did, that range would have been merged into the same window.
pub fn merge_ranges(ranges: &[VersionRange]) -> Vec<VersionRange> {
    let mut sorted: Vec<VersionRange> = ranges.to_vec();
    sorted.sort_by(|a, b| compare_lower(&a.lower, &b.lower));

    let mut merged: Vec<VersionRange> = Vec::new();
    for range in sorted {
        match merged.last_mut() {
            Some(last) if touches_or_overlaps(&last.upper, &range.lower) => {
                if compare_upper(&range.upper, &last.upper) == Ordering::Greater {
                    last.upper = range.upper;
                }
            }
            _ => merged.push(range),
        }
    }
    merged
}

/// Finds the merged vulnerable window containing `version` (if any) and
/// returns its safe-version recommendation (see
/// [`VersionRange::safe_version_string`]).
pub fn recommend_fix(ranges: &[VersionRange], version: &Versioning) -> Option<String> {
    merge_ranges(ranges)
        .into_iter()
        .find(|window| window.contains(version))
        .and_then(|window| window.safe_version_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Versioning {
        Versioning::new(s).unwrap_or_else(|| panic!("failed to parse version {s}"))
    }

    #[test]
    fn parses_a_simple_upper_bound() {
        let ranges = parse_ranges("<4.17.21");
        assert_eq!(ranges.len(), 1);
        assert!(ranges[0].contains(&v("4.17.20")));
        assert!(!ranges[0].contains(&v("4.17.21")));
    }

    #[test]
    fn parses_a_comma_separated_and_window() {
        let ranges = parse_ranges(">=1.0.0,<1.2.0");
        assert_eq!(ranges.len(), 1);
        assert!(!ranges[0].contains(&v("0.9.0")));
        assert!(ranges[0].contains(&v("1.0.0")));
        assert!(ranges[0].contains(&v("1.1.9")));
        assert!(!ranges[0].contains(&v("1.2.0")));
    }

    #[test]
    fn parses_or_separated_alternatives() {
        let ranges = parse_ranges("<1.0.0 || >=2.0.0,<2.5.0");
        assert_eq!(ranges.len(), 2);
        assert!(ranges[0].contains(&v("0.5.0")));
        assert!(ranges[1].contains(&v("2.1.0")));
        assert!(!ranges[1].contains(&v("1.5.0")));
    }

    #[test]
    fn handles_a_leading_v_prefix() {
        let ranges = parse_ranges("<v0.9.2");
        assert!(ranges[0].contains(&v("0.9.1")));
        assert!(!ranges[0].contains(&v("0.9.2")));
    }

    #[test]
    fn merges_two_overlapping_ranges_from_different_advisories_into_one_window() {
        let ranges = vec![
            VersionRange { lower: Bound::Unbounded, upper: Bound::Excluded(v("1.2.0")) },
            VersionRange { lower: Bound::Included(v("1.1.0")), upper: Bound::Excluded(v("1.5.0")) },
        ];
        let merged = merge_ranges(&ranges);
        assert_eq!(merged.len(), 1, "{merged:?}");
        assert!(merged[0].contains(&v("1.3.0")));
        assert_eq!(merged[0].safe_version_string().as_deref(), Some("1.5.0"));
    }

    #[test]
    fn does_not_merge_two_genuinely_disjoint_windows() {
        let ranges = vec![
            VersionRange { lower: Bound::Unbounded, upper: Bound::Excluded(v("1.0.0")) },
            VersionRange { lower: Bound::Included(v("2.0.0")), upper: Bound::Excluded(v("2.1.0")) },
        ];
        let merged = merge_ranges(&ranges);
        assert_eq!(merged.len(), 2, "{merged:?}");
    }

    #[test]
    fn recommends_the_version_just_past_a_merged_window() {
        let ranges = parse_ranges("<1.2.6");
        let fix = recommend_fix(&ranges, &v("1.0.0"));
        assert_eq!(fix.as_deref(), Some("1.2.6"));
    }

    #[test]
    fn recommends_no_fix_when_the_window_is_unbounded_above() {
        let ranges = parse_ranges(">=1.0.0");
        let fix = recommend_fix(&ranges, &v("5.0.0"));
        assert_eq!(fix, None, "no known safe version exists above an unbounded-above window");
    }

    #[test]
    fn recommends_no_fix_when_the_queried_version_is_not_vulnerable() {
        let ranges = parse_ranges("<1.0.0");
        assert_eq!(recommend_fix(&ranges, &v("2.0.0")), None);
    }
}
