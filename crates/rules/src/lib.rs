use anyhow::{bail, Result as AnyResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uniflow_hir::Language;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RuleSet {
    #[serde(default)]
    pub metadata: Vec<RuleMetadata>,
    #[serde(default)]
    pub sources: Vec<SourceRule>,
    #[serde(default)]
    pub sinks: Vec<SinkRule>,
    /// Reports a tainted call result only when the returned SSA value is not
    /// consumed by another instruction or terminator.
    #[serde(default)]
    pub unused_return_sinks: Vec<UnusedReturnSinkRule>,
    /// Maps one or more executable sink models to a stable reportable rule id.
    /// This lets a rule use precise method/argument variants without exposing
    /// implementation model ids to users.
    #[serde(default)]
    pub sink_reports: Vec<SinkReportRule>,
    #[serde(default)]
    pub sanitizers: Vec<SanitizerRule>,
    #[serde(default)]
    pub taint_transforms: Vec<TaintTransformRule>,
    #[serde(default)]
    pub propagators: Vec<PropagatorRule>,
    #[serde(default)]
    pub summaries: Vec<SummaryRule>,
    #[serde(default)]
    pub sink_conditions: Vec<SinkConditionRule>,
    #[serde(default)]
    pub call_conditions: Vec<CallConditionRule>,
    #[serde(default)]
    pub field_sources: Vec<FieldSourceRule>,
    #[serde(default)]
    pub named_value_sources: Vec<NamedValueSourceRule>,
    #[serde(default)]
    pub field_sinks: Vec<FieldSinkRule>,
    #[serde(default)]
    pub index_sinks: Vec<IndexSinkRule>,
    #[serde(default)]
    pub field_sanitizers: Vec<FieldSanitizerRule>,
    #[serde(default)]
    pub function_sources: Vec<FunctionSourceRule>,
    #[serde(default)]
    pub function_sinks: Vec<FunctionSinkRule>,
    /// Explicit helper models required by a reportable rule. This keeps
    /// policy filtering precise without loading unrelated transfer models.
    #[serde(default)]
    pub model_dependencies: Vec<RuleModelDependencies>,
}

impl RuleSet {
    pub fn from_yaml_str(s: &str) -> AnyResult<Self> {
        let rules = serde_yaml::from_str::<RuleSet>(s)?;
        rules.validate()?;
        Ok(rules)
    }

    pub fn merge(&mut self, other: RuleSet) {
        self.metadata.extend(other.metadata);
        self.sources.extend(other.sources);
        self.sinks.extend(other.sinks);
        self.unused_return_sinks.extend(other.unused_return_sinks);
        self.sink_reports.extend(other.sink_reports);
        self.sanitizers.extend(other.sanitizers);
        self.taint_transforms.extend(other.taint_transforms);
        self.propagators.extend(other.propagators);
        self.summaries.extend(other.summaries);
        self.sink_conditions.extend(other.sink_conditions);
        self.call_conditions.extend(other.call_conditions);
        self.field_sources.extend(other.field_sources);
        self.named_value_sources.extend(other.named_value_sources);
        self.field_sinks.extend(other.field_sinks);
        self.index_sinks.extend(other.index_sinks);
        self.field_sanitizers.extend(other.field_sanitizers);
        self.function_sources.extend(other.function_sources);
        self.function_sinks.extend(other.function_sinks);
        self.model_dependencies.extend(other.model_dependencies);
        dedup_by_id(&mut self.sources, |rule| &rule.id);
        dedup_by_id(&mut self.sinks, |rule| &rule.id);
        dedup_by_id(&mut self.unused_return_sinks, |rule| &rule.id);
        dedup_by_id(&mut self.sink_reports, |rule| &rule.sink_rule_id);
        dedup_by_id(&mut self.sanitizers, |rule| &rule.id);
        dedup_by_id(&mut self.taint_transforms, |rule| &rule.id);
        dedup_by_id(&mut self.propagators, |rule| &rule.id);
        dedup_by_id(&mut self.summaries, |rule| &rule.id);
        dedup_by_id(&mut self.metadata, |rule| &rule.id);
        dedup_by_id(&mut self.sink_conditions, |rule| &rule.sink_rule_id);
        dedup_by_id(&mut self.call_conditions, |rule| &rule.rule_id);
        dedup_by_id(&mut self.field_sources, |rule| &rule.id);
        dedup_by_id(&mut self.named_value_sources, |rule| &rule.id);
        dedup_by_id(&mut self.field_sinks, |rule| &rule.id);
        dedup_by_id(&mut self.index_sinks, |rule| &rule.id);
        dedup_by_id(&mut self.field_sanitizers, |rule| &rule.id);
        dedup_by_id(&mut self.function_sources, |rule| &rule.id);
        dedup_by_id(&mut self.function_sinks, |rule| &rule.id);
        dedup_by_id(&mut self.model_dependencies, |dependency| {
            &dependency.rule_id
        });
    }

    /// Restrict reportable rules while retaining the source and transfer
    /// models required to execute the selected taint kinds.
    pub fn retain_reportable_ids(&mut self, requested: &[String]) -> AnyResult<()> {
        if requested.is_empty() {
            return Ok(());
        }
        let requested = requested.iter().cloned().collect::<HashSet<_>>();
        let known = self
            .sources
            .iter()
            .map(|rule| rule.id.as_str())
            .chain(self.sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.unused_return_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.sanitizers.iter().map(|rule| rule.id.as_str()))
            .chain(self.taint_transforms.iter().map(|rule| rule.id.as_str()))
            .chain(self.propagators.iter().map(|rule| rule.id.as_str()))
            .chain(self.summaries.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.named_value_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.index_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sanitizers.iter().map(|rule| rule.id.as_str()))
            .chain(self.function_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.function_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.sink_reports.iter().map(|rule| rule.report_rule_id.as_str()))
            .collect::<HashSet<_>>();
        let mut unknown = requested
            .iter()
            .filter(|id| !known.contains(id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        unknown.sort();
        if !unknown.is_empty() {
            bail!("unknown rule ids: {}", unknown.join(", "));
        }

        let dependency_ids = self
            .model_dependencies
            .iter()
            .filter(|dependency| requested.contains(&dependency.rule_id))
            .flat_map(|dependency| dependency.model_ids.iter().cloned())
            .collect::<HashSet<_>>();
        // Older and third-party packs may not declare dependency closure yet.
        // Retain every transfer model in that case: dropping one silently can
        // turn a selected rule into a false negative. Packs with complete
        // declarations get the narrower, deterministic model slice.
        let has_complete_dependency_closure = requested.iter().all(|requested_id| {
            self.model_dependencies
                .iter()
                .any(|dependency| dependency.rule_id == *requested_id)
        });
        let aliased_sink_ids = self
            .sink_reports
            .iter()
            .filter(|alias| requested.contains(&alias.report_rule_id))
            .map(|alias| alias.sink_rule_id.clone())
            .collect::<HashSet<_>>();
        self.sinks
            .retain(|rule| requested.contains(&rule.id) || aliased_sink_ids.contains(&rule.id));
        self.unused_return_sinks
            .retain(|rule| requested.contains(&rule.id));
        let retained_sink_ids = self
            .sinks
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<HashSet<_>>();
        self.sink_reports
            .retain(|alias| retained_sink_ids.contains(alias.sink_rule_id.as_str()));
        self.field_sinks
            .retain(|rule| requested.contains(&rule.id));
        self.index_sinks
            .retain(|rule| requested.contains(&rule.id));
        self.function_sinks
            .retain(|rule| requested.contains(&rule.id));
        let selected_kinds = self
            .sinks
            .iter()
            .map(|rule| normalize_rule_kind(&rule.kind).to_string())
            .chain(
                self.unused_return_sinks
                    .iter()
                    .map(|rule| normalize_rule_kind(&rule.source_kind).to_string()),
            )
            .chain(
                self.field_sinks
                    .iter()
                    .map(|rule| normalize_rule_kind(&rule.kind).to_string()),
            )
            .chain(
                self.index_sinks
                    .iter()
                    .map(|rule| normalize_rule_kind(&rule.kind).to_string()),
            )
            .chain(
                self.function_sinks
                    .iter()
                    .map(|rule| normalize_rule_kind(&rule.kind).to_string()),
            )
            .collect::<HashSet<_>>();
        let keeps_kind = |kind: &str| {
            selected_kinds.contains(normalize_rule_kind(kind))
        };
        self.sources.retain(|rule| {
            !has_complete_dependency_closure
                || requested.contains(&rule.id)
                || dependency_ids.contains(&rule.id)
                || keeps_kind(&rule.kind)
        });
        self.field_sources
            .retain(|rule| {
                !has_complete_dependency_closure
                    || requested.contains(&rule.id)
                    || dependency_ids.contains(&rule.id)
                    || keeps_kind(&rule.kind)
            });
        self.named_value_sources.retain(|rule| {
            !has_complete_dependency_closure
                || requested.contains(&rule.id)
                || dependency_ids.contains(&rule.id)
                || keeps_kind(&rule.kind)
        });
        self.function_sources
            .retain(|rule| {
                !has_complete_dependency_closure
                    || requested.contains(&rule.id)
                    || dependency_ids.contains(&rule.id)
                    || keeps_kind(&rule.kind)
            });
        self.sanitizers
            .retain(|rule| {
                !has_complete_dependency_closure
                    || requested.contains(&rule.id)
                    || dependency_ids.contains(&rule.id)
                    || keeps_kind(&rule.kind)
            });
        self.field_sanitizers
            .retain(|rule| {
                !has_complete_dependency_closure
                    || requested.contains(&rule.id)
                    || dependency_ids.contains(&rule.id)
                    || keeps_kind(&rule.kind)
            });
        self.taint_transforms.retain(|rule| {
            !has_complete_dependency_closure
                || requested.contains(&rule.id)
                || dependency_ids.contains(&rule.id)
        });
        self.propagators.retain(|rule| {
            !has_complete_dependency_closure
                || requested.contains(&rule.id)
                || dependency_ids.contains(&rule.id)
        });
        self.summaries.retain(|rule| {
            !has_complete_dependency_closure
                || requested.contains(&rule.id)
                || dependency_ids.contains(&rule.id)
        });
        self.metadata
            .retain(|metadata| requested.contains(&metadata.id));
        self.sink_conditions
            .retain(|condition| requested.contains(&condition.sink_rule_id));
        self.model_dependencies
            .retain(|dependency| requested.contains(&dependency.rule_id));

        let retained = self
            .sources
            .iter()
            .map(|rule| rule.id.as_str())
            .chain(self.sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.unused_return_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.sanitizers.iter().map(|rule| rule.id.as_str()))
            .chain(self.taint_transforms.iter().map(|rule| rule.id.as_str()))
            .chain(self.propagators.iter().map(|rule| rule.id.as_str()))
            .chain(self.summaries.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.named_value_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.index_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sanitizers.iter().map(|rule| rule.id.as_str()))
            .chain(self.function_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.function_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.sink_reports.iter().map(|rule| rule.report_rule_id.as_str()))
            .collect::<HashSet<_>>();
        self.call_conditions
            .retain(|condition| retained.contains(condition.rule_id.as_str()));
        self.validate()
    }

    pub fn validate(&self) -> AnyResult<()> {
        let executable_ids = self
            .sources
            .iter()
            .map(|rule| rule.id.as_str())
            .chain(self.sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.unused_return_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.sanitizers.iter().map(|rule| rule.id.as_str()))
            .chain(self.taint_transforms.iter().map(|rule| rule.id.as_str()))
            .chain(self.propagators.iter().map(|rule| rule.id.as_str()))
            .chain(self.summaries.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.named_value_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.index_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.field_sanitizers.iter().map(|rule| rule.id.as_str()))
            .chain(self.function_sources.iter().map(|rule| rule.id.as_str()))
            .chain(self.function_sinks.iter().map(|rule| rule.id.as_str()))
            .chain(self.sink_reports.iter().map(|rule| rule.report_rule_id.as_str()))
            .collect::<HashSet<_>>();
        let mut metadata_ids = HashSet::new();
        for metadata in &self.metadata {
            if metadata.id.trim().is_empty() {
                bail!("rule metadata id must not be empty");
            }
            if !metadata_ids.insert(metadata.id.as_str()) {
                bail!("duplicate rule metadata '{}'", metadata.id);
            }
            if !executable_ids.contains(metadata.id.as_str()) {
                bail!("rule metadata '{}' has no executable rule", metadata.id);
            }
            if metadata.title.trim().is_empty() {
                bail!("rule metadata '{}' must define a title", metadata.id);
            }
            if !matches!(
                metadata.severity.as_str(),
                "error" | "warning" | "note" | "none"
            ) {
                bail!(
                    "rule metadata '{}' has unsupported severity '{}'",
                    metadata.id,
                    metadata.severity
                );
            }
        }
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
            if rule.outputs.is_empty() {
                bail!(
                    "sanitizer rule '{}' must define at least one output",
                    rule.id
                );
            }
            rule.matcher.validate()?;
        }
        for rule in &self.taint_transforms {
            if rule.outputs.is_empty() {
                bail!(
                    "taint transform rule '{}' must define at least one output",
                    rule.id
                );
            }
            if rule.add_kinds.is_empty() && rule.remove_kinds.is_empty() {
                bail!(
                    "taint transform rule '{}' must add or remove at least one kind",
                    rule.id
                );
            }
            rule.matcher.validate()?;
        }
        for rule in &self.propagators {
            if rule.flows.is_empty() {
                bail!(
                    "propagator rule '{}' must define at least one flow",
                    rule.id
                );
            }
            rule.matcher.validate()?;
        }
        for rule in &self.summaries {
            if rule.flows.is_empty() {
                bail!("summary rule '{}' must define at least one flow", rule.id);
            }
            rule.matcher.validate()?;
        }
        let executable_sink_ids = self
            .sinks
            .iter()
            .map(|rule| rule.id.as_str())
            .chain(self.unused_return_sinks.iter().map(|rule| rule.id.as_str()))
            .collect::<HashSet<_>>();
        for alias in &self.sink_reports {
            if !executable_sink_ids.contains(alias.sink_rule_id.as_str()) {
                bail!(
                    "sink report '{}' references missing sink model '{}'",
                    alias.report_rule_id,
                    alias.sink_rule_id
                );
            }
        }
        let sink_ids = executable_sink_ids
            .iter()
            .copied()
            .chain(self.sink_reports.iter().map(|alias| alias.report_rule_id.as_str()))
            .collect::<HashSet<_>>();
        for condition in &self.sink_conditions {
            if !sink_ids.contains(condition.sink_rule_id.as_str()) {
                bail!(
                    "sink condition references missing sink rule '{}'",
                    condition.sink_rule_id
                );
            }
        }
        for condition in &self.call_conditions {
            if !executable_ids.contains(condition.rule_id.as_str()) {
                bail!(
                    "call condition references missing executable rule '{}'",
                    condition.rule_id
                );
            }
        }
        for dependency in &self.model_dependencies {
            if !executable_ids.contains(dependency.rule_id.as_str()) {
                bail!(
                    "model dependency references missing reportable rule '{}'",
                    dependency.rule_id
                );
            }
            for model_id in &dependency.model_ids {
                if !executable_ids.contains(model_id.as_str()) {
                    bail!(
                        "model dependency for '{}' references missing model '{}'",
                        dependency.rule_id,
                        model_id
                    );
                }
            }
        }
        for rule in &self.field_sources {
            rule.matcher.validate()?;
        }
        for rule in &self.named_value_sources {
            if rule.id.trim().is_empty() {
                bail!("named value source rule id must not be empty");
            }
            Regex::new(&rule.name_regex).map_err(|error| {
                anyhow::anyhow!(
                    "invalid named value source regex for '{}': {error}",
                    rule.id
                )
            })?;
        }
        for rule in &self.field_sinks {
            rule.matcher.validate()?;
        }
        for rule in &self.index_sinks {
            if rule.id.trim().is_empty() {
                bail!("index sink rule id must not be empty");
            }
            validate_regex_opt(&rule.base_name_regex)?;
            if !rule.on_load && !rule.on_store {
                bail!("index sink rule '{}' must match a load or store", rule.id);
            }
        }
        for rule in &self.field_sanitizers {
            rule.matcher.validate()?;
        }
        for rule in &self.function_sources {
            rule.matcher.validate()?;
        }
        for rule in &self.function_sinks {
            rule.matcher.validate()?;
            if rule.inputs.is_empty() {
                bail!("function sink rule '{}' must define an input", rule.id);
            }
        }
        for rule in &self.unused_return_sinks {
            if rule.id.trim().is_empty() {
                bail!("unused-return sink rule id must not be empty");
            }
            if rule.source_kind.trim().is_empty() {
                bail!("unused-return sink rule '{}' must define a source kind", rule.id);
            }
        }
        Ok(())
    }

    pub fn metadata_for(&self, id: &str) -> Option<&RuleMetadata> {
        self.metadata.iter().find(|metadata| metadata.id == id)
    }

    pub fn report_id_for_sink<'a>(&'a self, sink_rule_id: &'a str) -> &'a str {
        self.sink_reports
            .iter()
            .find(|alias| alias.sink_rule_id == sink_rule_id)
            .map(|alias| alias.report_rule_id.as_str())
            .unwrap_or(sink_rule_id)
    }

    pub fn call_condition_matches(&self, rule_id: &str, call: &CallInfo) -> bool {
        self.call_conditions
            .iter()
            .find(|condition| condition.rule_id == rule_id)
            .is_none_or(|condition| condition.condition.matches_call(call, &[]))
    }
}

/// Matches an instance field without coupling field models to call matching.
///
/// `owner` is the fully-qualified declaring/receiver type.  `owner_regex` is
/// used by model-query rules (for example, framework subclasses).  At least
/// one owner constraint and a non-empty field name are required so a model can
/// never silently taint every same-named field in an untyped program.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldMatcher {
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub owner_regex: Option<String>,
    pub field: String,
}

impl FieldMatcher {
    pub fn validate(&self) -> AnyResult<()> {
        if self
            .owner
            .as_ref()
            .is_none_or(|owner| owner.trim().is_empty())
            && self
                .owner_regex
                .as_ref()
                .is_none_or(|owner| owner.trim().is_empty())
        {
            bail!("field matcher must define owner or owner_regex");
        }
        if self.field.trim().is_empty() {
            bail!("field matcher must define a field");
        }
        validate_regex_opt(&self.owner_regex)?;
        Ok(())
    }

    pub fn matches(&self, owner_candidates: &[String], field: &str) -> bool {
        if self.field != "*" && self.field != field {
            return false;
        }
        owner_candidates.iter().any(|candidate| {
            self.owner.as_ref().is_some_and(|owner| owner == candidate)
                || self.owner_regex.as_ref().is_some_and(|expression| {
                    Regex::new(expression).is_ok_and(|expression| expression.is_match(candidate))
                })
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldSourceRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: FieldMatcher,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamedValueSourceRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub name_regex: String,
    #[serde(default = "default_kind")]
    pub kind: String,
}

impl NamedValueSourceRule {
    pub fn matches_name(&self, name: &str) -> bool {
        Regex::new(&self.name_regex).is_ok_and(|expression| expression.is_match(name))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldSinkRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: FieldMatcher,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexSinkRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    /// When true, ignore computed indices produced by string composition.
    #[serde(default)]
    pub direct_only: bool,
    /// Match index reads (`base[index]`) in addition to the historical
    /// computed-index write sink. This is used by Ruby session access and
    /// Sequel query rules.
    #[serde(default)]
    pub on_load: bool,
    /// Match index writes (`base[index] = value`). Defaults to true for
    /// backwards compatibility with existing rule packs.
    #[serde(default = "default_true")]
    pub on_store: bool,
    /// Optional source-level name constraint for the indexed base value.
    #[serde(default)]
    pub base_name_regex: Option<String>,
    #[serde(default = "default_kind")]
    pub kind: String,
}

fn default_true() -> bool {
    true
}

impl IndexSinkRule {
    pub fn matches_base_name(&self, name: Option<&str>) -> bool {
        self.base_name_regex.as_ref().is_none_or(|expression| {
            name.is_some_and(|name| {
                Regex::new(expression).is_ok_and(|expression| expression.is_match(name))
            })
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldSanitizerRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: FieldMatcher,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FunctionMatcher {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub owner_regex: Option<String>,
    #[serde(default)]
    pub decorator: Option<String>,
    #[serde(default)]
    pub decorator_regex: Option<String>,
}

impl FunctionMatcher {
    pub fn validate(&self) -> AnyResult<()> {
        if self.exact.is_none()
            && self.regex.is_none()
            && self.owner.is_none()
            && self.owner_regex.is_none()
            && self.decorator.is_none()
            && self.decorator_regex.is_none()
        {
            bail!("function matcher must define a constraint");
        }
        validate_regex_opt(&self.regex)?;
        validate_regex_opt(&self.owner_regex)?;
        validate_regex_opt(&self.decorator_regex)?;
        Ok(())
    }

    pub fn matches(&self, name: &str, owners: &[String], decorators: &[String]) -> bool {
        if self.exact.as_ref().is_some_and(|exact| exact != name) {
            return false;
        }
        if self
            .regex
            .as_ref()
            .is_some_and(|regex| !Regex::new(regex).is_ok_and(|regex| regex.is_match(name)))
        {
            return false;
        }
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| !owners.contains(owner))
        {
            return false;
        }
        if self.owner_regex.as_ref().is_some_and(|regex| {
            !Regex::new(regex).is_ok_and(|regex| owners.iter().any(|owner| regex.is_match(owner)))
        }) {
            return false;
        }
        if self
            .decorator
            .as_ref()
            .is_some_and(|expected| !decorators.iter().any(|actual| actual == expected))
        {
            return false;
        }
        if self.decorator_regex.as_ref().is_some_and(|regex| {
            !Regex::new(regex)
                .is_ok_and(|regex| decorators.iter().any(|value| regex.is_match(value)))
        }) {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionSourceRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: FunctionMatcher,
    pub out: Port,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionSinkRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: FunctionMatcher,
    #[serde(default)]
    pub inputs: Vec<Port>,
    #[serde(default = "default_kind")]
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleMetadata {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub message: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default)]
    pub translations: RuleTranslations,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleTranslations {
    #[serde(default, rename = "zh-CN")]
    pub zh_cn: Option<LocalizedRuleText>,
    #[serde(default)]
    pub en: Option<LocalizedRuleText>,
    #[serde(default, rename = "zh-TW")]
    pub zh_tw: Option<LocalizedRuleText>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalizedRuleText {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub message: String,
}

impl RuleTranslations {
    pub fn is_empty(&self) -> bool {
        self.zh_cn.is_none() && self.en.is_none() && self.zh_tw.is_none()
    }

    pub fn get(&self, locale: &str) -> Option<&LocalizedRuleText> {
        match locale.to_ascii_lowercase().replace('_', "-").as_str() {
            "zh" | "zh-cn" | "zh-hans" => self.zh_cn.as_ref(),
            "en" | "en-us" | "en-gb" => self.en.as_ref(),
            "zh-tw" | "zh-hk" | "zh-hant" => self.zh_tw.as_ref(),
            _ => None,
        }
    }
}

impl RuleMetadata {
    pub fn localized_title(&self, locale: &str) -> &str {
        self.translations
            .get(locale)
            .map(|text| text.title.as_str())
            .filter(|text| !text.trim().is_empty())
            .unwrap_or(&self.title)
    }

    pub fn localized_message(&self, locale: &str) -> &str {
        self.translations
            .get(locale)
            .map(|text| text.message.as_str())
            .filter(|text| !text.trim().is_empty())
            .or_else(|| (!self.message.trim().is_empty()).then_some(self.message.as_str()))
            .unwrap_or(&self.title)
    }
}

fn default_severity() -> String {
    "warning".to_string()
}

fn dedup_by_id<T, F>(items: &mut Vec<T>, id: F)
where
    F: Fn(&T) -> &str,
{
    let mut seen = std::collections::HashSet::new();
    items.reverse();
    items.retain(|item| seen.insert(id(item).to_string()));
    items.reverse();
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
    pub containing_function_regex: Option<String>,
    #[serde(default)]
    pub receiver_type: Option<String>,
    #[serde(default)]
    pub receiver_contains: Option<String>,
    #[serde(default)]
    pub receiver_regex: Option<String>,
    /// Zero-based source-level parameter index that must supply the receiver.
    /// This preserves framework roles such as Express' `(request, response)`
    /// without depending on parameter spelling.
    #[serde(default)]
    pub receiver_parameter: Option<usize>,
    #[serde(default)]
    pub method_name: Option<String>,
    #[serde(default)]
    pub method_contains: Option<String>,
    #[serde(default)]
    pub method_regex: Option<String>,
    #[serde(default)]
    pub arg_count: Option<usize>,
    #[serde(default)]
    pub arg_count_min: Option<usize>,
    #[serde(default)]
    pub arg_count_max: Option<usize>,
    /// Positional argument type constraints. Empty entries are wildcards.
    #[serde(default)]
    pub arg_types: Vec<Option<String>>,
    /// Positional argument type regex constraints. Empty entries are wildcards.
    #[serde(default)]
    pub arg_type_regexes: Vec<Option<String>>,
}

impl ApiMatcher {
    pub fn validate(&self) -> AnyResult<()> {
        if !self.has_any_constraint() {
            bail!(
                "matcher must define at least one of: exact, contains, regex, receiver_type, receiver_contains, receiver_regex, method_name, method_contains, method_regex, arg_count"
            );
        }
        validate_regex_opt(&self.regex)?;
        validate_regex_opt(&self.containing_function_regex)?;
        validate_regex_opt(&self.receiver_regex)?;
        validate_regex_opt(&self.method_regex)?;
        for expression in self.arg_type_regexes.iter().flatten() {
            Regex::new(expression)?;
        }
        if let (Some(min), Some(max)) = (self.arg_count_min, self.arg_count_max) {
            if min > max {
                bail!("matcher arg_count_min must not exceed arg_count_max");
            }
        }
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
        if !match_optional_string_constraints(
            None,
            None,
            self.containing_function_regex.as_deref(),
            call.containing_function.as_deref(),
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
        if self.receiver_parameter.is_some()
            && self.receiver_parameter != call.receiver_parameter
        {
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
        if let Some(minimum) = self.arg_count_min {
            if call.arg_count.is_none_or(|actual| actual < minimum) {
                return false;
            }
        }
        if let Some(maximum) = self.arg_count_max {
            if call.arg_count.is_none_or(|actual| actual > maximum) {
                return false;
            }
        }
        if !match_argument_types(self, call) {
            return false;
        }
        true
    }

    fn has_any_constraint(&self) -> bool {
        self.exact.is_some()
            || self.contains.is_some()
            || self.regex.is_some()
            || self.containing_function_regex.is_some()
            || self.receiver_type.is_some()
            || self.receiver_contains.is_some()
            || self.receiver_regex.is_some()
            || self.receiver_parameter.is_some()
            || self.method_name.is_some()
            || self.method_contains.is_some()
            || self.method_regex.is_some()
            || self.arg_count.is_some()
            || self.arg_count_min.is_some()
            || self.arg_count_max.is_some()
            || self.arg_types.iter().any(Option::is_some)
            || self.arg_type_regexes.iter().any(Option::is_some)
    }
}

fn match_argument_types(matcher: &ApiMatcher, call: &CallInfo) -> bool {
    let constraint_count = matcher.arg_types.len().max(matcher.arg_type_regexes.len());
    for index in 0..constraint_count {
        let exact = matcher.arg_types.get(index).and_then(Option::as_deref);
        let regex = matcher
            .arg_type_regexes
            .get(index)
            .and_then(Option::as_deref);
        if exact.is_none() && regex.is_none() {
            continue;
        }
        let mut candidates = call
            .arg_type_candidates
            .get(index)
            .cloned()
            .unwrap_or_default();
        if let Some(primary) = call.arg_types.get(index).and_then(Option::as_ref) {
            if !candidates.contains(primary) {
                candidates.push(primary.clone());
            }
        }
        if candidates.is_empty() {
            return false;
        }
        if let Some(exact) = exact {
            if !candidates.iter().any(|candidate| candidate == exact) {
                return false;
            }
        }
        if let Some(expression) = regex {
            let Ok(expression) = Regex::new(expression) else {
                return false;
            };
            if !candidates
                .iter()
                .any(|candidate| expression.is_match(candidate))
            {
                return false;
            }
        }
    }
    true
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
    pub containing_function: Option<String>,
    #[serde(default)]
    pub receiver_type: Option<String>,
    #[serde(default)]
    pub receiver_type_candidates: Vec<String>,
    #[serde(default)]
    pub receiver_parameter: Option<usize>,
    #[serde(default)]
    pub method_name: Option<String>,
    #[serde(default)]
    pub arg_count: Option<usize>,
    #[serde(default)]
    pub arg_types: Vec<Option<String>>,
    #[serde(default)]
    pub arg_type_candidates: Vec<Vec<String>>,
    #[serde(default)]
    pub receiver_constant: Option<String>,
    #[serde(default)]
    pub arg_constants: Vec<Option<String>>,
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
            containing_function: None,
            receiver_type,
            receiver_type_candidates,
            receiver_parameter: None,
            method_name,
            arg_count,
            arg_types,
            arg_type_candidates,
            receiver_constant: None,
            arg_constants: Vec::new(),
        }
    }

    pub fn from_callee_name(callee_name: &str) -> Self {
        let (receiver_type, method_name) = split_callee_name(callee_name);
        let receiver_type_candidates = receiver_type.iter().cloned().collect();
        Self {
            callee_name: callee_name.to_string(),
            containing_function: None,
            receiver_type,
            receiver_type_candidates,
            receiver_parameter: None,
            method_name,
            arg_count: None,
            arg_types: Vec::new(),
            arg_type_candidates: Vec::new(),
            receiver_constant: None,
            arg_constants: Vec::new(),
        }
    }
}

fn split_callee_name(callee_name: &str) -> (Option<String>, Option<String>) {
    let separator = [(callee_name.rfind("::"), "::"), (callee_name.rfind('.'), ".")]
        .into_iter()
        .filter_map(|(index, separator)| index.map(|index| (index, separator)))
        .max_by_key(|(index, _)| *index);
    if let Some((index, separator)) = separator {
        let method = &callee_name[index + separator.len()..];
        return (
            Some(callee_name[..index].to_string()),
            Some(method.to_string()),
        );
    }
    (None, Some(callee_name.to_string()))
}

pub fn language_matches(rule_language: &Option<Language>, active_language: &Language) -> bool {
    rule_language
        .as_ref()
        .map_or(true, |lang| lang == active_language)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Port {
    Receiver,
    Return,
    Arg(usize),
    /// An argument selected by its source-level label (for example a C#
    /// named argument or a Python keyword argument).
    NamedArg(String),
    /// Select a named argument when its source label is present, otherwise
    /// conservatively select every positional argument. External .NET APIs
    /// commonly expose parameter names only in reference metadata, which may
    /// not be available during source-only analysis.
    NamedArgOrAll(String),
    Member(String),
    ArgsFrom(usize),
    ArgsRange {
        start: usize,
        end: usize,
    },
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
            Port::NamedArg(name) => serializer.serialize_str(&format!("named:{name}")),
            Port::NamedArgOrAll(name) => serializer.serialize_str(&format!("named_or_all:{name}")),
            Port::Member(member) => serializer.serialize_str(&format!("member:{member}")),
            Port::ArgsFrom(start) => serializer.serialize_str(&format!("args_from{start}")),
            Port::ArgsRange { start, end } => {
                serializer.serialize_str(&format!("args{start}..={end}"))
            }
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
            if let Some(name) = s.strip_prefix("named_or_all:") {
                if name.trim().is_empty() {
                    return Err("fallback named argument port must name an argument".to_string());
                }
                return Ok(Port::NamedArgOrAll(name.to_string()));
            }
            if let Some(name) = s.strip_prefix("named:") {
                if name.trim().is_empty() {
                    return Err("named argument port must name an argument".to_string());
                }
                return Ok(Port::NamedArg(name.to_string()));
            }
            if let Some(member) = s.strip_prefix("member:") {
                if member.trim().is_empty() {
                    return Err("member port must name a member".to_string());
                }
                return Ok(Port::Member(member.to_string()));
            }
            if let Some(rest) = s.strip_prefix("args_from") {
                let start = rest
                    .parse::<usize>()
                    .map_err(|_| format!("invalid variadic port: {s}"))?;
                return Ok(Port::ArgsFrom(start));
            }
            if let Some(rest) = s.strip_prefix("args") {
                if let Some((start, end)) = rest.split_once("..=") {
                    let start = start
                        .parse::<usize>()
                        .map_err(|_| format!("invalid argument range port: {s}"))?;
                    let end = end
                        .parse::<usize>()
                        .map_err(|_| format!("invalid argument range port: {s}"))?;
                    if start > end {
                        return Err(format!("invalid descending argument range port: {s}"));
                    }
                    return Ok(Port::ArgsRange { start, end });
                }
            }
            if let Some(rest) = s.strip_prefix("arg") {
                let idx = rest
                    .parse::<usize>()
                    .map_err(|_| format!("invalid port: {s}"))?;
                Ok(Port::Arg(idx))
            } else {
                Err(format!("invalid port: {s}"))
            }
        }
    }
}

pub fn expand_port(port: &Port, arg_count: usize) -> Vec<Port> {
    match port {
        Port::ArgsFrom(start) => (*start..arg_count).map(Port::Arg).collect(),
        Port::ArgsRange { start, end } => (*start..=(*end).min(arg_count.saturating_sub(1)))
            .filter(|_| arg_count != 0)
            .map(Port::Arg)
            .collect(),
        _ => vec![port.clone()],
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
pub struct UnusedReturnSinkRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    #[serde(default = "default_kind")]
    pub kind: String,
    /// Only calls that independently match a return source of this kind can
    /// receive the unused-return sink. This prevents an older taint value from
    /// being reported at an unrelated later call.
    #[serde(default = "default_kind")]
    pub source_kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SinkReportRule {
    pub sink_rule_id: String,
    pub report_rule_id: String,
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

/// Changes the set of taint labels while data crosses a modeled call.
///
/// Empty `inputs` means that every incoming edge to a modeled output is
/// transformed. This is required for legacy cleanse models whose return value
/// is defined independently from a particular argument port.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaintTransformRule {
    pub id: String,
    #[serde(default)]
    pub language: Option<Language>,
    pub matcher: ApiMatcher,
    #[serde(default)]
    pub inputs: Vec<Port>,
    #[serde(default)]
    pub outputs: Vec<Port>,
    #[serde(default)]
    pub add_kinds: Vec<String>,
    #[serde(default)]
    pub remove_kinds: Vec<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowSpec {
    pub from: Port,
    pub to: Port,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SinkConditionRule {
    pub sink_rule_id: String,
    pub condition: TaintCondition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallConditionRule {
    pub rule_id: String,
    pub condition: TaintCondition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleModelDependencies {
    pub rule_id: String,
    #[serde(default)]
    pub model_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", content = "args", rename_all = "snake_case")]
pub enum TaintCondition {
    HasKind(String),
    IsType {
        port: Port,
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        regex: Option<String>,
    },
    ValueMatches {
        port: Port,
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        regex: Option<String>,
    },
    IsConstant(Port),
    Not(Box<TaintCondition>),
    All(Vec<TaintCondition>),
    Any(Vec<TaintCondition>),
}

impl TaintCondition {
    pub fn matches_kind(&self, kind: &str) -> bool {
        match self {
            Self::HasKind(expected) => normalize_rule_kind(expected) == normalize_rule_kind(kind),
            Self::IsType { .. } | Self::ValueMatches { .. } | Self::IsConstant(_) => false,
            Self::Not(child) => !child.matches_kind(kind),
            Self::All(children) => children.iter().all(|child| child.matches_kind(kind)),
            Self::Any(children) => children.iter().any(|child| child.matches_kind(kind)),
        }
    }

    pub fn matches_call(&self, call: &CallInfo, labels: &[String]) -> bool {
        match self {
            Self::HasKind(expected) => labels
                .iter()
                .any(|label| normalize_rule_kind(expected) == normalize_rule_kind(label)),
            Self::IsType { port, exact, regex } => {
                let candidates = match port {
                    Port::Receiver => {
                        let mut candidates = call.receiver_type_candidates.clone();
                        if let Some(primary) = &call.receiver_type {
                            if !candidates.contains(primary) {
                                candidates.push(primary.clone());
                            }
                        }
                        candidates
                    }
                    Port::Arg(index) => {
                        let mut candidates = call
                            .arg_type_candidates
                            .get(*index)
                            .cloned()
                            .unwrap_or_default();
                        if let Some(primary) = call.arg_types.get(*index).and_then(Option::as_ref) {
                            if !candidates.contains(primary) {
                                candidates.push(primary.clone());
                            }
                        }
                        candidates
                    }
                    Port::Return
                    | Port::NamedArg(_)
                    | Port::NamedArgOrAll(_)
                    | Port::Member(_)
                    | Port::ArgsFrom(_)
                    | Port::ArgsRange { .. } => Vec::new(),
                };
                values_match(&candidates, exact.as_deref(), regex.as_deref())
            }
            Self::ValueMatches { port, exact, regex } => {
                let value = match port {
                    Port::Receiver => call.receiver_constant.as_ref(),
                    Port::Arg(index) => call.arg_constants.get(*index).and_then(Option::as_ref),
                    Port::Return
                    | Port::NamedArg(_)
                    | Port::NamedArgOrAll(_)
                    | Port::Member(_)
                    | Port::ArgsFrom(_)
                    | Port::ArgsRange { .. } => None,
                };
                value.is_some_and(|value| {
                    values_match(
                        std::slice::from_ref(value),
                        exact.as_deref(),
                        regex.as_deref(),
                    )
                })
            }
            Self::IsConstant(port) => match port {
                Port::Receiver => call.receiver_constant.is_some(),
                Port::Arg(index) => call.arg_constants.get(*index).is_some_and(Option::is_some),
                Port::Return
                | Port::NamedArg(_)
                | Port::NamedArgOrAll(_)
                | Port::Member(_)
                | Port::ArgsFrom(_)
                | Port::ArgsRange { .. } => false,
            },
            Self::Not(child) => !child.matches_call(call, labels),
            Self::All(children) => children
                .iter()
                .all(|child| child.matches_call(call, labels)),
            Self::Any(children) => children
                .iter()
                .any(|child| child.matches_call(call, labels)),
        }
    }
}

fn values_match(values: &[String], exact: Option<&str>, regex: Option<&str>) -> bool {
    values.iter().any(|value| {
        exact.is_none_or(|expected| value == expected)
            && regex.is_none_or(|expression| {
                Regex::new(expression).is_ok_and(|expression| expression.is_match(value))
            })
    })
}

fn normalize_rule_kind(kind: &str) -> &str {
    let kind = kind.trim();
    if kind.is_empty() {
        "generic"
    } else {
        kind
    }
}

fn default_kind() -> String {
    "generic".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_rule_metadata_round_trips_three_presentations() {
        let rules = RuleSet::from_yaml_str(
            r#"
metadata:
  - id: request-input
    title: Untrusted request input
    message: Treat request input as untrusted.
    severity: error
    standards: [GJB-8114]
    translations:
      zh-CN: { title: 不可信请求输入, message: 请将请求输入视为不可信数据。 }
      en: { title: Untrusted request input, message: Treat request input as untrusted. }
      zh-TW: { title: 不可信請求輸入, message: 請將請求輸入視為不可信資料。 }
sources:
  - id: request-input
    matcher: { exact: request.input }
    out: return
"#,
        )
        .expect("localized taint rules");
        let metadata = rules.metadata_for("request-input").expect("metadata");
        assert_eq!(metadata.localized_title("zh-CN"), "不可信请求输入");
        assert_eq!(metadata.localized_title("en"), "Untrusted request input");
        assert_eq!(metadata.localized_title("zh-Hant"), "不可信請求輸入");
        assert_eq!(metadata.standards, vec!["GJB-8114"]);
    }

    #[test]
    fn orphan_taint_rule_metadata_is_rejected() {
        let result = RuleSet::from_yaml_str(
            r#"
metadata:
  - id: missing-rule
    title: Missing
sources: []
"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn api_matcher_enforces_argument_ranges_and_type_patterns() {
        let matcher = ApiMatcher {
            method_name: Some("execute".to_string()),
            arg_count_min: Some(1),
            arg_count_max: Some(2),
            arg_types: vec![Some("java.lang.String".to_string())],
            arg_type_regexes: vec![None, Some("(int|long)".to_string())],
            ..Default::default()
        };
        matcher.validate().expect("valid typed matcher");
        let matching = CallInfo::new(
            "Statement.execute",
            Some("Statement".to_string()),
            vec!["Statement".to_string()],
            Some("execute".to_string()),
            Some(2),
            vec![
                Some("java.lang.String".to_string()),
                Some("int".to_string()),
            ],
            vec![
                vec!["java.lang.String".to_string()],
                vec!["int".to_string()],
            ],
        );
        assert!(matcher.matches_call(&matching));

        let wrong_type = CallInfo::new(
            "Statement.execute",
            Some("Statement".to_string()),
            Vec::new(),
            Some("execute".to_string()),
            Some(2),
            vec![Some("byte[]".to_string()), Some("int".to_string())],
            Vec::new(),
        );
        assert!(!matcher.matches_call(&wrong_type));
    }

    #[test]
    fn later_rule_pack_entries_override_earlier_ids() {
        let mut base = RuleSet {
            sources: vec![SourceRule {
                id: "patched".to_string(),
                language: None,
                matcher: ApiMatcher {
                    exact: Some("old.source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            }],
            ..Default::default()
        };
        base.merge(RuleSet {
            sources: vec![SourceRule {
                id: "patched".to_string(),
                language: None,
                matcher: ApiMatcher {
                    exact: Some("new.source".to_string()),
                    ..Default::default()
                },
                out: Port::Return,
                kind: "generic".to_string(),
            }],
            ..Default::default()
        });
        assert_eq!(base.sources.len(), 1);
        assert_eq!(base.sources[0].matcher.exact.as_deref(), Some("new.source"));
    }

    #[test]
    fn reportable_rule_filter_keeps_same_kind_dependencies_and_rejects_unknown_ids() {
        let yaml = r#"
metadata:
  - { id: selected-sink, title: Selected }
  - { id: other-sink, title: Other }
sources:
  - { id: selected-source, matcher: { exact: input }, out: return, kind: selected }
  - { id: other-source, matcher: { exact: other }, out: return, kind: other }
sinks:
  - { id: selected-sink, matcher: { exact: consume }, inputs: [arg0], kind: selected }
  - { id: other-sink, matcher: { exact: discard }, inputs: [arg0], kind: other }
propagators:
  - id: transfer
    matcher: { exact: copy }
    flows: [{ from: arg0, to: return }]
model_dependencies:
  - rule_id: selected-sink
    model_ids: [selected-source, transfer]
call_conditions:
  - rule_id: selected-source
    condition: { op: is_constant, args: arg0 }
  - rule_id: other-source
    condition: { op: is_constant, args: arg0 }
"#;
        let mut rules = RuleSet::from_yaml_str(yaml).unwrap();
        rules
            .retain_reportable_ids(&["selected-sink".to_string()])
            .unwrap();
        assert_eq!(rules.metadata.len(), 1);
        assert_eq!(rules.sinks.len(), 1);
        assert_eq!(rules.sources.len(), 1);
        assert_eq!(rules.sources[0].id, "selected-source");
        assert_eq!(rules.propagators.len(), 1);
        assert_eq!(rules.call_conditions.len(), 1);
        assert_eq!(rules.call_conditions[0].rule_id, "selected-source");

        let mut rules = RuleSet::from_yaml_str(yaml).unwrap();
        let error = rules
            .retain_reportable_ids(&["missing".to_string()])
            .unwrap_err();
        assert!(error.to_string().contains("unknown rule ids: missing"));

        let mut legacy_rules = RuleSet::from_yaml_str(&yaml.replace(
            "model_dependencies:\n  - rule_id: selected-sink\n    model_ids: [selected-source, transfer]\n",
            "",
        ))
        .unwrap();
        legacy_rules
            .retain_reportable_ids(&["selected-sink".to_string()])
            .unwrap();
        assert_eq!(legacy_rules.propagators.len(), 1);
        assert_eq!(legacy_rules.propagators[0].id, "transfer");
        assert_eq!(legacy_rules.sources.len(), 2);
    }

    #[test]
    fn member_port_round_trips_in_native_rule_yaml() {
        let encoded = serde_yaml::to_string(&Port::Member("jobName".to_string()))
            .expect("serialize member port");
        assert_eq!(encoded.trim(), "member:jobName");
        let decoded: Port = serde_yaml::from_str(&encoded).expect("deserialize member port");
        assert_eq!(decoded, Port::Member("jobName".to_string()));
    }

    #[test]
    fn api_matcher_can_require_receiver_parameter_role() {
        let matcher: ApiMatcher = serde_yaml::from_str(
            "method_name: redirect\nreceiver_parameter: 1\narg_count: 1\n",
        )
        .unwrap();
        let mut call = CallInfo::from_callee_name("reply.redirect");
        call.arg_count = Some(1);
        call.receiver_parameter = Some(1);
        assert!(matcher.matches_call(&call));
        call.receiver_parameter = Some(0);
        assert!(!matcher.matches_call(&call));
    }

    #[test]
    fn sink_report_aliases_retain_precise_models_under_one_public_id() {
        let mut rules = RuleSet::from_yaml_str(
            r#"
metadata:
  - { id: public-rule, title: Public rule }
sources:
  - { id: source, matcher: { exact: input }, out: return, kind: configured }
sinks:
  - { id: model-arg0, matcher: { exact: consume_one }, inputs: [arg0], kind: configured }
  - { id: model-arg1, matcher: { exact: consume_two }, inputs: [arg1], kind: configured }
sink_reports:
  - { sink_rule_id: model-arg0, report_rule_id: public-rule }
  - { sink_rule_id: model-arg1, report_rule_id: public-rule }
model_dependencies:
  - { rule_id: public-rule, model_ids: [source] }
"#,
        )
        .unwrap();
        assert_eq!(rules.report_id_for_sink("model-arg0"), "public-rule");
        rules.retain_reportable_ids(&["public-rule".to_string()]).unwrap();
        assert_eq!(rules.sinks.len(), 2);
        assert_eq!(rules.sink_reports.len(), 2);
        assert_eq!(rules.metadata.len(), 1);
    }

    #[test]
    fn api_matcher_can_require_containing_function() {
        let matcher: ApiMatcher = serde_yaml::from_str(
            "method_name: parse\ncontaining_function_regex: __lambda_\n",
        )
        .unwrap();
        let mut call = CallInfo::from_callee_name("parser.parse");
        call.containing_function = Some("handler.__lambda_4_2".to_string());
        assert!(matcher.matches_call(&call));
        call.containing_function = Some("handler".to_string());
        assert!(!matcher.matches_call(&call));
    }

    #[test]
    fn named_argument_port_round_trips_in_native_rule_yaml() {
        let encoded = serde_yaml::to_string(&Port::NamedArg("commandText".to_string()))
            .expect("serialize named argument port");
        assert_eq!(encoded.trim(), "named:commandText");
        let decoded: Port = serde_yaml::from_str(&encoded).expect("deserialize named port");
        assert_eq!(decoded, Port::NamedArg("commandText".to_string()));
        assert!(serde_yaml::from_str::<Port>("named:\n").is_err());

        let encoded = serde_yaml::to_string(&Port::NamedArgOrAll("commandText".to_string()))
            .expect("serialize fallback named argument port");
        assert_eq!(encoded.trim(), "named_or_all:commandText");
        let decoded: Port = serde_yaml::from_str(&encoded).expect("deserialize fallback port");
        assert_eq!(decoded, Port::NamedArgOrAll("commandText".to_string()));
    }
}
