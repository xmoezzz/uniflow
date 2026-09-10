use regex::Regex;
use regex_syntax::hir::{Class, Hir, HirKind};
use uniflow_hir::Language;
use uniflow_models::legacy_models_for;
use uniflow_rules::{ApiMatcher, CallInfo, Port, TaintCondition};

fn regex_witness(pattern: &str) -> String {
    fn emit(hir: &Hir, out: &mut Vec<u8>) {
        match hir.kind() {
            HirKind::Empty | HirKind::Look(_) => {}
            HirKind::Literal(literal) => out.extend_from_slice(&literal.0),
            HirKind::Class(Class::Unicode(class)) => {
                let ch = class
                    .iter()
                    .next()
                    .expect("non-empty Unicode class")
                    .start();
                let mut bytes = [0; 4];
                out.extend_from_slice(ch.encode_utf8(&mut bytes).as_bytes());
            }
            HirKind::Class(Class::Bytes(class)) => {
                out.push(class.iter().next().expect("non-empty byte class").start())
            }
            HirKind::Repetition(repetition) => {
                for _ in 0..repetition.min {
                    emit(&repetition.sub, out);
                }
            }
            HirKind::Capture(capture) => emit(&capture.sub, out),
            HirKind::Concat(parts) => {
                for part in parts {
                    emit(part, out);
                }
            }
            HirKind::Alternation(parts) => emit(&parts[0], out),
        }
    }
    let hir = regex_syntax::Parser::new()
        .parse(pattern)
        .unwrap_or_else(|error| panic!("{pattern}: {error}"));
    let mut bytes = Vec::new();
    emit(&hir, &mut bytes);
    let witness = String::from_utf8(bytes)
        .unwrap_or_else(|error| panic!("non-UTF-8 witness for {pattern}: {error}"));
    assert!(
        Regex::new(pattern).unwrap().is_match(&witness),
        "regex witness {witness:?} does not match {pattern}"
    );
    witness
}

fn candidates(
    exact: Option<&str>,
    contains: Option<&str>,
    pattern: Option<&str>,
    fallback: &str,
) -> Vec<String> {
    let mut values = vec![fallback.to_string()];
    if let Some(value) = exact {
        values.insert(0, value.to_string());
    }
    if let Some(value) = pattern {
        values.push(regex_witness(value));
    }
    if let Some(value) = contains {
        values.push(format!("prefix{value}suffix"));
    }
    values.sort();
    values.dedup();
    values
}

fn witness(matcher: &ApiMatcher, minimum_arity: usize) -> Option<CallInfo> {
    let owners = candidates(
        matcher.receiver_type.as_deref(),
        matcher.receiver_contains.as_deref(),
        matcher.receiver_regex.as_deref(),
        "java.lang.Object",
    );
    let methods = candidates(
        matcher.method_name.as_deref(),
        matcher.method_contains.as_deref(),
        matcher.method_regex.as_deref(),
        "call",
    );
    let mut callees = candidates(
        matcher.exact.as_deref(),
        matcher.contains.as_deref(),
        matcher.regex.as_deref(),
        "call",
    );
    for owner in &owners {
        for method in &methods {
            callees.push(format!("{owner}.{method}"));
        }
    }
    let arity = matcher.arg_count.unwrap_or_else(|| {
        matcher
            .arg_count_min
            .unwrap_or(0)
            .max(matcher.arg_types.len())
            .max(matcher.arg_type_regexes.len())
            .max(minimum_arity)
    });
    if arity < minimum_arity {
        return None;
    }
    if matcher.arg_count_max.is_some_and(|maximum| arity > maximum) {
        return None;
    }
    let arg_types = (0..arity)
        .map(|index| {
            matcher
                .arg_types
                .get(index)
                .and_then(|value| value.clone())
                .or_else(|| {
                    matcher
                        .arg_type_regexes
                        .get(index)
                        .and_then(|value| value.as_deref())
                        .map(regex_witness)
                })
                .or_else(|| Some("java.lang.Object".to_string()))
        })
        .collect::<Vec<_>>();
    let arg_candidates = arg_types
        .iter()
        .map(|value| value.clone().into_iter().collect())
        .collect::<Vec<_>>();
    for owner in owners {
        for method in &methods {
            for callee in &callees {
                let call = CallInfo::new(
                    callee,
                    Some(owner.clone()),
                    vec![owner.clone()],
                    Some(method.clone()),
                    Some(arity),
                    arg_types.clone(),
                    arg_candidates.clone(),
                );
                if matcher.matches_call(&call) {
                    return Some(call);
                }
            }
        }
    }
    None
}

fn port_arity(port: &Port) -> usize {
    match port {
        Port::Arg(index) => index + 1,
        Port::ArgsFrom(start) => start + 1,
        Port::ArgsRange { end, .. } => end + 1,
        _ => 0,
    }
}

fn condition_arity(condition: &TaintCondition) -> usize {
    match condition {
        TaintCondition::IsType { port, .. }
        | TaintCondition::ValueMatches { port, .. }
        | TaintCondition::IsConstant(port) => port_arity(port),
        TaintCondition::Not(child) => condition_arity(child),
        TaintCondition::All(children) | TaintCondition::Any(children) => {
            children.iter().map(condition_arity).max().unwrap_or(0)
        }
        TaintCondition::HasKind(_) => 0,
    }
}

#[derive(Clone)]
struct Scenario {
    call: CallInfo,
    labels: Vec<String>,
}

fn constrained_value(exact: Option<&str>, pattern: Option<&str>) -> Option<String> {
    if let Some(exact) = exact {
        return pattern
            .is_none_or(|pattern| Regex::new(pattern).unwrap().is_match(exact))
            .then(|| exact.to_string());
    }
    Some(
        pattern
            .map(regex_witness)
            .unwrap_or_else(|| "contract-value".to_string()),
    )
}

fn set_type(
    call: &mut CallInfo,
    port: &Port,
    value: String,
    matching: bool,
    exact: Option<&str>,
    pattern: Option<&str>,
) -> bool {
    let rejects = |candidate: &String| {
        exact.is_some_and(|exact| candidate == exact)
            && pattern.is_none_or(|pattern| Regex::new(pattern).unwrap().is_match(candidate))
            || exact.is_none()
                && pattern.is_some_and(|pattern| Regex::new(pattern).unwrap().is_match(candidate))
    };
    match port {
        Port::Receiver => {
            if matching {
                call.receiver_type_candidates.push(value.clone());
                call.receiver_type = Some(value);
            } else {
                call.receiver_type_candidates
                    .retain(|candidate| !rejects(candidate));
                call.receiver_type = Some(value);
            }
            true
        }
        Port::Arg(index) if *index < call.arg_types.len() => {
            if matching {
                call.arg_type_candidates[*index].push(value.clone());
                call.arg_types[*index] = Some(value);
            } else {
                call.arg_type_candidates[*index].retain(|candidate| !rejects(candidate));
                call.arg_types[*index] = Some(value);
            }
            true
        }
        _ => !matching,
    }
}

fn atom_variant(
    condition: &TaintCondition,
    want: bool,
    mut scenario: Scenario,
) -> Option<Scenario> {
    if condition.matches_call(&scenario.call, &scenario.labels) == want {
        return Some(scenario);
    }
    match condition {
        TaintCondition::HasKind(kind) => {
            scenario.labels.retain(|label| label != kind);
            if want {
                scenario.labels.push(kind.clone());
            }
        }
        TaintCondition::IsType { port, exact, regex } => {
            let value = if want {
                constrained_value(exact.as_deref(), regex.as_deref())?
            } else {
                "uniflow.contract.NonMatchingType".to_string()
            };
            if !set_type(
                &mut scenario.call,
                port,
                value,
                want,
                exact.as_deref(),
                regex.as_deref(),
            ) {
                return None;
            }
        }
        TaintCondition::ValueMatches { port, exact, regex } => {
            let value = want
                .then(|| constrained_value(exact.as_deref(), regex.as_deref()))
                .flatten();
            match port {
                Port::Receiver => scenario.call.receiver_constant = value,
                Port::Arg(index) if *index < scenario.call.arg_types.len() => {
                    scenario
                        .call
                        .arg_constants
                        .resize(scenario.call.arg_types.len(), None);
                    scenario.call.arg_constants[*index] = value;
                }
                _ if want => return None,
                _ => {}
            }
        }
        TaintCondition::IsConstant(port) => match port {
            Port::Receiver => {
                scenario.call.receiver_constant = want.then(|| "constant".to_string())
            }
            Port::Arg(index) if *index < scenario.call.arg_types.len() => {
                scenario
                    .call
                    .arg_constants
                    .resize(scenario.call.arg_types.len(), None);
                scenario.call.arg_constants[*index] = want.then(|| "constant".to_string());
            }
            _ if want => return None,
            _ => {}
        },
        _ => return None,
    }
    Some(scenario)
}

fn condition_variants(condition: &TaintCondition, want: bool, seed: Scenario) -> Vec<Scenario> {
    let mut result = match condition {
        TaintCondition::Not(child) => condition_variants(child, !want, seed),
        TaintCondition::All(children) if want => {
            children.iter().fold(vec![seed], |scenarios, child| {
                scenarios
                    .into_iter()
                    .flat_map(|scenario| condition_variants(child, want, scenario))
                    .take(128)
                    .collect()
            })
        }
        TaintCondition::Any(children) if !want => {
            children.iter().fold(vec![seed], |scenarios, child| {
                scenarios
                    .into_iter()
                    .flat_map(|scenario| condition_variants(child, want, scenario))
                    .take(128)
                    .collect()
            })
        }
        TaintCondition::All(children) | TaintCondition::Any(children) => children
            .iter()
            .flat_map(|child| condition_variants(child, want, seed.clone()))
            .take(128)
            .collect(),
        _ => atom_variant(condition, want, seed).into_iter().collect(),
    };
    result.retain(|scenario| condition.matches_call(&scenario.call, &scenario.labels) == want);
    result
}

fn executable_matcher<'a>(rules: &'a uniflow_rules::RuleSet, id: &str) -> Option<&'a ApiMatcher> {
    rules
        .sources
        .iter()
        .find(|rule| rule.id == id)
        .map(|rule| &rule.matcher)
        .or_else(|| {
            rules
                .sinks
                .iter()
                .find(|rule| rule.id == id)
                .map(|rule| &rule.matcher)
        })
        .or_else(|| {
            rules
                .sanitizers
                .iter()
                .find(|rule| rule.id == id)
                .map(|rule| &rule.matcher)
        })
        .or_else(|| {
            rules
                .taint_transforms
                .iter()
                .find(|rule| rule.id == id)
                .map(|rule| &rule.matcher)
        })
        .or_else(|| {
            rules
                .propagators
                .iter()
                .find(|rule| rule.id == id)
                .map(|rule| &rule.matcher)
        })
}

fn verify<'a>(rules: impl Iterator<Item = (&'a str, &'a ApiMatcher, usize)>, expected: usize) {
    let rules = rules.collect::<Vec<_>>();
    assert_eq!(rules.len(), expected);
    for (id, matcher, minimum_arity) in rules {
        let call = witness(matcher, minimum_arity).unwrap_or_else(|| panic!("no executable matcher/port witness for {id}: {matcher:#?}, minimum arity {minimum_arity}"));
        assert!(matcher.matches_call(&call), "{id}: {matcher:#?}\n{call:#?}");
    }
}

#[test]
fn every_java_legacy_source_matcher_has_an_executable_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    verify(
        rules
            .sources
            .iter()
            .map(|rule| (rule.id.as_str(), &rule.matcher, port_arity(&rule.out))),
        1643,
    );
}

#[test]
fn every_java_legacy_sink_matcher_has_an_executable_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    verify(
        rules.sinks.iter().map(|rule| {
            (
                rule.id.as_str(),
                &rule.matcher,
                rule.inputs.iter().map(port_arity).max().unwrap_or(0),
            )
        }),
        4515,
    );
}

#[test]
fn every_java_legacy_sanitizer_matcher_has_an_executable_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    verify(
        rules.sanitizers.iter().map(|rule| {
            (
                rule.id.as_str(),
                &rule.matcher,
                rule.inputs
                    .iter()
                    .chain(&rule.outputs)
                    .map(port_arity)
                    .max()
                    .unwrap_or(0),
            )
        }),
        403,
    );
}

#[test]
fn every_java_legacy_transform_matcher_has_an_executable_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    verify(
        rules.taint_transforms.iter().map(|rule| {
            (
                rule.id.as_str(),
                &rule.matcher,
                rule.inputs
                    .iter()
                    .chain(&rule.outputs)
                    .map(port_arity)
                    .max()
                    .unwrap_or(0),
            )
        }),
        538,
    );
}

#[test]
fn every_java_legacy_propagator_matcher_has_an_executable_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    verify(
        rules.propagators.iter().map(|rule| {
            (
                rule.id.as_str(),
                &rule.matcher,
                rule.flows
                    .iter()
                    .flat_map(|flow| [&flow.from, &flow.to])
                    .map(port_arity)
                    .max()
                    .unwrap_or(0),
            )
        }),
        3240,
    );
}

#[test]
fn every_java_legacy_call_condition_has_a_matching_call_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    assert_eq!(rules.call_conditions.len(), 278);
    for condition in &rules.call_conditions {
        let matcher = executable_matcher(&rules, &condition.rule_id).unwrap();
        let base = witness(matcher, condition_arity(&condition.condition)).unwrap();
        let seed = Scenario {
            call: base,
            labels: Vec::new(),
        };
        let matched = condition_variants(&condition.condition, true, seed)
            .into_iter()
            .any(|scenario| {
                scenario.labels.is_empty()
                    && matcher.matches_call(&scenario.call)
                    && condition.condition.matches_call(&scenario.call, &[])
            });
        assert!(
            matched,
            "unsatisfied call condition {}: {:#?}",
            condition.rule_id, condition.condition
        );
    }
}

#[test]
fn every_java_legacy_sink_condition_has_a_matching_label_and_call_witness() {
    let rules = legacy_models_for(Language::Java).unwrap();
    assert_eq!(rules.sink_conditions.len(), 4512);
    for condition in &rules.sink_conditions {
        let Some(sink) = rules
            .sinks
            .iter()
            .find(|rule| rule.id == condition.sink_rule_id)
        else {
            let sink = rules
                .unused_return_sinks
                .iter()
                .find(|rule| rule.id == condition.sink_rule_id)
                .expect("condition must reference a regular or unused-return sink");
            let source = rules
                .sources
                .iter()
                .find(|source| source.kind == sink.source_kind && source.out == Port::Return)
                .expect("unused-return sink kind must have a return source");
            let call = witness(&source.matcher, 0).expect("return source matcher witness");
            assert!(condition
                .condition
                .matches_call(&call, std::slice::from_ref(&sink.source_kind)));
            continue;
        };
        let minimum = sink
            .inputs
            .iter()
            .map(port_arity)
            .max()
            .unwrap_or(0)
            .max(condition_arity(&condition.condition));
        let base = witness(&sink.matcher, minimum).unwrap();
        let seed = Scenario {
            call: base,
            labels: Vec::new(),
        };
        let matched = condition_variants(&condition.condition, true, seed)
            .into_iter()
            .any(|scenario| {
                sink.matcher.matches_call(&scenario.call)
                    && condition
                        .condition
                        .matches_call(&scenario.call, &scenario.labels)
            });
        assert!(
            matched,
            "unsatisfied sink condition {}: {:#?}",
            condition.sink_rule_id, condition.condition
        );
    }
}
