//! Embedded, exact library return signatures shared by Java parsing and IR
//! lowering. These facts do not add taint, relax rule predicates or infer
//! return types for arbitrary methods with a matching simple name.
use std::{collections::BTreeMap, sync::LazyLock};

const SIGNATURES: &str = include_str!("../../../rules/signatures/java-api-returns.tsv");
static RETURNS: LazyLock<BTreeMap<(&'static str, &'static str, usize), &'static str>> =
    LazyLock::new(|| {
        let mut result = BTreeMap::new();
        for line in SIGNATURES
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
        {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), 4, "invalid Java return signature: {line}");
            assert!(fields[0].contains('.') && fields[3].contains('.'));
            for arity in fields[2].split(',') {
                let arity = arity.parse::<usize>().expect("Java signature arity");
                assert!(
                    result
                        .insert((fields[0], fields[1], arity), fields[3])
                        .is_none(),
                    "duplicate Java signature: {line}"
                );
            }
        }
        result
    });

pub fn java_api_return_type(owner: &str, method: &str, arity: usize) -> Option<&'static str> {
    RETURNS.get(&(owner, method, arity)).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_java_return_signatures_are_exact_and_arity_gated() {
        assert_eq!(RETURNS.len(), 62);
        for (&(owner, method, arity), &result) in RETURNS.iter() {
            assert_eq!(java_api_return_type(owner, method, arity), Some(result));
            assert_eq!(
                java_api_return_type(&format!("custom.{owner}"), method, arity),
                None
            );
            assert_eq!(
                java_api_return_type(owner, &format!("{method}Other"), arity),
                None
            );
            assert_eq!(java_api_return_type(owner, method, 99), None);
        }
        assert_eq!(
            java_api_return_type("java.sql.Connection", "createStatement", 1),
            None
        );
        assert_eq!(java_api_return_type("Runtime", "getRuntime", 0), None);
    }
}
