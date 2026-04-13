use anyhow::{bail, Result as AnyResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use uniflow_hir::Language;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RuleSet {
    #[serde(default)]
    pub sources: Vec<SourceRule>,
    #[serde(default)]
    pub sinks: Vec<SinkRule>,
    #[serde(default)]
    pub sanitizers: Vec<SanitizerRule>,
    #[serde(default)]
    pub propagators: Vec<PropagatorRule>,
    #[serde(default)]
    pub summaries: Vec<SummaryRule>,
}

impl RuleSet {
    pub fn from_yaml_str(s: &str) -> AnyResult<Self> {
        let rules = serde_yaml::from_str::<RuleSet>(s)?;
        rules.validate()?;
        Ok(rules)
    }

    pub fn merge(&mut self, other: RuleSet) {
        self.sources.extend(other.sources);
        self.sinks.extend(other.sinks);
        self.sanitizers.extend(other.sanitizers);
        self.propagators.extend(other.propagators);
        self.summaries.extend(other.summaries);
    }

    pub fn validate(&self) -> AnyResult<()> {
        for rule in &self.sources {
            rule.matcher.validate()?;
        }
        for rule in &self.sinks {
            rule.matcher.validate()?;
            if rule.inputs.is_empty() {
                bail!("sink rule '{}' must define at least one input", rule.id);
            }
        }
        for rule in &self.sanitizers {
            if rule.inputs.is_empty() || rule.outputs.is_empty() {
                bail!("sanitizer rule '{}' must define both inputs and outputs", rule.id);
            }
            rule.matcher.validate()?;
        }
        for rule in &self.propagators {
            if rule.flows.is_empty() {
                bail!("propagator rule '{}' must define at least one flow", rule.id);
            }
            rule.matcher.validate()?;
        }
        for rule in &self.summaries {
            if rule.flows.is_empty() {
                bail!("summary rule '{}' must define at least one flow", rule.id);
            }
            rule.matcher.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ApiMatcher {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub contains: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub receiver_type: Option<String>,
    #[serde(default)]
    pub receiver_contains: Option<String>,
    #[serde(default)]
    pub receiver_regex: Option<String>,
    #[serde(default)]
    pub method_name: Option<String>,
    #[serde(default)]
    pub method_contains: Option<String>,
    #[serde(default)]
    pub method_regex: Option<String>,
    #[serde(default)]
    pub arg_count: Option<usize>,
}

impl ApiMatcher {
    pub fn validate(&self) -> AnyResult<()> {
        if !self.has_any_constraint() {
            bail!(
                "matcher must define at least one of: exact, contains, regex, receiver_type, receiver_contains, receiver_regex, method_name, method_contains, method_regex, arg_count"
            );
        }
        validate_regex_opt(&self.regex)?;
        validate_regex_opt(&self.receiver_regex)?;
        validate_regex_opt(&self.method_regex)?;
        Ok(())
    }

    pub fn matches(&self, callee_name: &str) -> bool {
        self.matches_call(&CallInfo::from_callee_name(callee_name))
    }

    pub fn matches_call(&self, call: &CallInfo) -> bool {
        if !match_string_constraints(
            self.exact.as_deref(),
            self.contains.as_deref(),
            self.regex.as_deref(),
            &call.callee_name,
        ) {
            return false;
        }
        if !match_receiver_constraints(
            self.receiver_type.as_deref(),
            self.receiver_contains.as_deref(),
            self.receiver_regex.as_deref(),
            call.receiver_type.as_deref(),
            &call.receiver_type_candidates,
        ) {
            return false;
        }
        if !match_optional_string_constraints(
            self.method_name.as_deref(),
            self.method_contains.as_deref(),
            self.method_regex.as_deref(),
            call.method_name.as_deref(),
        ) {
            return false;
        }
        if let Some(expected) = self.arg_count {
            if call.arg_count != Some(expected) {
                return false;
            }
        }
        true
    }

    fn has_any_constraint(&self) -> bool {
        self.exact.is_some()
            || self.contains.is_some()
            || self.regex.is_some()
            || self.receiver_type.is_some()
            || self.receiver_contains.is_some()
            || self.receiver_regex.is_some()
            || self.method_name.is_some()
            || self.method_contains.is_some()
            || self.method_regex.is_some()
            || self.arg_count.is_some()
    }
}

fn validate_regex_opt(expr: &Option<String>) -> AnyResult<()> {
    if let Some(expr) = expr {
        Regex::new(expr)?;
    }
    Ok(())
}

fn match_string_constraints(
    exact: Option<&str>,
    contains: Option<&str>,
    regex: Option<&str>,
    actual: &str,
) -> bool {
    if let Some(exact) = exact {
        if actual != exact {
            return false;
        }
    }
    if let Some(contains) = contains {
        if !actual.contains(contains) {
            return false;
        }
    }
    if let Some(regex) = regex {
        let Ok(re) = Regex::new(regex) else {
            return false;
        };
        if !re.is_match(actual) {
            return false;
        }
    }
    true
}


fn match_receiver_constraints(
    exact: Option<&str>,
    contains: Option<&str>,
    regex: Option<&str>,
    primary: Option<&str>,
    candidates: &[String],
) -> bool {
    if exact.is_none() && contains.is_none() && regex.is_none() {
        return true;
    }

    let mut all = Vec::new();
    if let Some(primary) = primary {
        all.push(primary.to_string());
    }
    for candidate in candidates {
        if !all.iter().any(|existing| existing == candidate) {
            all.push(candidate.clone());
        }
    }
    all.into_iter()
        .any(|actual| match_string_constraints(exact, contains, regex, &actual))
}

fn match_optional_string_constraints(
    exact: Option<&str>,
    contains: Option<&str>,
    regex: Option<&str>,
    actual: Option<&str>,
) -> bool {
    if exact.is_none() && contains.is_none() && regex.is_none() {
        return true;
    }
    let Some(actual) = actual else {
        return false;
    };
    match_string_constraints(exact, contains, regex, actual)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallInfo {
    pub callee_name: String,
    #[serde(default)]
    pub receiver_type: Option<String>,
    #[serde(default)]
    pub receiver_type_candidates: Vec<String>,
    #[serde(default)]
    pub method_name: Option<String>,
    #[serde(default)]
    pub arg_count: Option<usize>,
    #[serde(default)]
    pub arg_types: Vec<Option<String>>,
    #[serde(default)]
    pub arg_type_candidates: Vec<Vec<String>>,
}

impl CallInfo {
    pub fn new(
        callee_name: impl Into<String>,
        receiver_type: Option<String>,
        receiver_type_candidates: Vec<String>,
        method_name: Option<String>,
        arg_count: Option<usize>,
        arg_types: Vec<Option<String>>,
        arg_type_candidates: Vec<Vec<String>>,
    ) -> Self {
        let receiver_type = receiver_type.or_else(|| receiver_type_candidates.first().cloned());
        Self {
            callee_name: callee_name.into(),
            receiver_type,
            receiver_type_candidates,
            method_name,
            arg_count,
            arg_types,
            arg_type_candidates,
        }
    }

    pub fn from_callee_name(callee_name: &str) -> Self {
        let (receiver_type, method_name) = split_callee_name(callee_name);
        let receiver_type_candidates = receiver_type.iter().cloned().collect();
        Self {
            callee_name: callee_name.to_string(),
            receiver_type,
            receiver_type_candidates,
            method_name,
            arg_count: None,
            arg_types: Vec::new(),
            arg_type_candidates: Vec::new(),
        }
    }
}

fn split_callee_name(callee_name: &str) -> (Option<String>, Option<String>) {
    for sep in ["::", "."] {
        if let Some((recv, method)) = callee_name.rsplit_once(sep) {
            return (Some(recv.to_string()), Some(method.to_string()));
        }
    }
    (None, Some(callee_name.to_string()))
}

pub fn language_matches(rule_language: &Option<Language>, active_language: &Language) -> bool {
    rule_language.as_ref().map_or(true, |lang| lang == active_language)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Port {
    Receiver,
    Return,
    Arg(usize),
}

impl Serialize for Port {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Port::Receiver => serializer.serialize_str("receiver"),
            Port::Return => serializer.serialize_str("return"),
            Port::Arg(idx) => serializer.serialize_str(&format!("arg{idx}")),
        }
    }
}

impl<'de> Deserialize<'de> for Port {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_port(&s).map_err(serde::de::Error::custom)
    }
}

fn parse_port(s: &str) -> std::result::Result<Port, String> {
    match s {
        "receiver" => Ok(Port::Receiver),
        "return" => Ok(Port::Return),
        _ => {
            if let Some(rest) = s.strip_prefix("arg") {
                let idx = rest.parse::<usize>().map_err(|_| format!("invalid port: {s}"))?;
                Ok(Port::Arg(idx))
            } else {
                Err(format!("invalid port: {s}"))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: ApiMatcher,
    pub out: Port,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SinkRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: ApiMatcher,
    #[serde(default)]
    pub inputs: Vec<Port>,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizerRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: ApiMatcher,
    #[serde(default)]
    pub inputs: Vec<Port>,
    #[serde(default)]
    pub outputs: Vec<Port>,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PropagatorRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: ApiMatcher,
    #[serde(default)]
    pub flows: Vec<FlowSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SummaryRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: ApiMatcher,
    #[serde(default)]
    pub flows: Vec<FlowSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowSpec {
    pub from: Port,
    pub to: Port,
}

fn default_kind() -> String {
    "generic".to_string()
}
