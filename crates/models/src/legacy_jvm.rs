use crate::legacy_jvm_metadata::{LegacyJvmKnowledgeCatalog, LegacyJvmMetadataReport};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::Language;
use uniflow_rules::{
    ApiMatcher, CallConditionRule, FlowSpec, Port, PropagatorRule, RuleMetadata, RuleSet,
    SanitizerRule, SinkConditionRule, SinkRule, SourceRule, TaintCondition, TaintTransformRule,
    UnusedReturnSinkRule,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyJvmRuleKind {
    Source,
    Sink,
    Passthrough,
    Cleanse,
    RuleMap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyJvmPattern {
    Exact {
        value: String,
        case_insensitive: bool,
    },
    Regex {
        value: String,
        case_insensitive: bool,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyJvmMethod {
    pub namespace: Option<LegacyJvmPattern>,
    pub class_name: Option<LegacyJvmPattern>,
    pub method_name: Option<LegacyJvmPattern>,
    pub parameter_min: Option<usize>,
    pub parameter_max: Option<usize>,
    pub parameter_types: Vec<LegacyJvmPattern>,
    pub extends: bool,
    pub implements: bool,
    pub overrides: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyJvmPosition {
    Receiver,
    Return,
    Argument(usize),
    ArgumentsFrom(usize),
    ArgumentRange { start: usize, end: usize },
    Member(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyJvmSignChange {
    pub sign: String,
    pub added: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyJvmPoint {
    pub inputs: Vec<LegacyJvmPosition>,
    pub condition: Option<Value>,
    pub master: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyJvmStandardMap {
    pub standard: String,
    pub rule_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyJvmRule {
    pub kind: LegacyJvmRuleKind,
    pub id: String,
    pub vulnerability: Option<String>,
    pub method: Option<LegacyJvmMethod>,
    pub inputs: Vec<LegacyJvmPosition>,
    pub outputs: Vec<LegacyJvmPosition>,
    pub signs: Vec<LegacyJvmSignChange>,
    pub points: Vec<LegacyJvmPoint>,
    pub condition: Option<Value>,
    pub mappings: Vec<LegacyJvmStandardMap>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyJvmRulePack {
    pub rules: Vec<LegacyJvmRule>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyJvmFileStats {
    pub path: String,
    pub rules: usize,
    pub sources: usize,
    pub sinks: usize,
    pub passthroughs: usize,
    pub cleanses: usize,
    pub rule_maps: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyJvmCatalogReport {
    pub root: String,
    pub files: Vec<LegacyJvmFileStats>,
    pub total_rules: usize,
    pub total_executable_rules: usize,
    pub duplicate_executable_ids: Vec<String>,
    pub skipped_non_executable_catalogs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyJvmCompileDiagnostic {
    pub rule_id: String,
    pub feature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyJvmCompilation {
    pub rules: RuleSet,
    pub diagnostics: Vec<LegacyJvmCompileDiagnostic>,
    #[serde(default)]
    pub metadata_report: LegacyJvmMetadataReport,
}

impl LegacyJvmRulePack {
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        let document: Value = serde_yaml::from_str(text).context("invalid legacy JVM rule YAML")?;
        let root = as_mapping(&document, "legacy JVM rule root")?;
        let rules = get(root, "rules")
            .and_then(Value::as_sequence)
            .context("legacy JVM rule pack must contain a rules sequence")?;
        let rules = rules
            .iter()
            .enumerate()
            .map(|(index, value)| {
                parse_rule(value)
                    .with_context(|| format!("invalid legacy JVM rule at index {index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules })
    }

    pub fn count(&self, kind: LegacyJvmRuleKind) -> usize {
        self.rules.iter().filter(|rule| rule.kind == kind).count()
    }
}

pub fn audit_legacy_jvm_rule_tree(root: &Path) -> Result<LegacyJvmCatalogReport> {
    anyhow::ensure!(
        root.is_dir(),
        "legacy JVM rule root is not a directory: {}",
        root.display()
    );
    let mut paths = Vec::new();
    collect_yaml_files(root, &mut paths)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    let mut ids = HashSet::new();
    let mut duplicates = HashSet::new();
    let mut total_rules = 0;
    let mut total_executable_rules = 0;
    let mut skipped_non_executable_catalogs = Vec::new();
    for path in paths {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read legacy JVM rules {}", path.display()))?;
        let document: Value = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse legacy JVM YAML {}", path.display()))?;
        let has_executable_rules = document
            .as_mapping()
            .and_then(|root| get(root, "rules"))
            .and_then(Value::as_sequence)
            .is_some();
        if !has_executable_rules {
            skipped_non_executable_catalogs.push(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            continue;
        }
        let pack = LegacyJvmRulePack::from_yaml_str(&text)
            .with_context(|| format!("failed to parse legacy JVM rules {}", path.display()))?;
        for rule in &pack.rules {
            if rule.kind != LegacyJvmRuleKind::RuleMap {
                total_executable_rules += 1;
                if !ids.insert(rule.id.clone()) {
                    duplicates.insert(rule.id.clone());
                }
            }
        }
        let stats = LegacyJvmFileStats {
            path: path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/"),
            rules: pack.rules.len(),
            sources: pack.count(LegacyJvmRuleKind::Source),
            sinks: pack.count(LegacyJvmRuleKind::Sink),
            passthroughs: pack.count(LegacyJvmRuleKind::Passthrough),
            cleanses: pack.count(LegacyJvmRuleKind::Cleanse),
            rule_maps: pack.count(LegacyJvmRuleKind::RuleMap),
        };
        total_rules += stats.rules;
        files.push(stats);
    }
    let mut duplicate_executable_ids = duplicates.into_iter().collect::<Vec<_>>();
    duplicate_executable_ids.sort();
    Ok(LegacyJvmCatalogReport {
        root: root.display().to_string(),
        files,
        total_rules,
        total_executable_rules,
        duplicate_executable_ids,
        skipped_non_executable_catalogs,
    })
}

pub fn compile_legacy_jvm_taint_pack(
    pack: &LegacyJvmRulePack,
    language: Language,
    namespace: &str,
) -> Result<LegacyJvmCompilation> {
    let mut compilation = LegacyJvmCompilation::default();
    for legacy in &pack.rules {
        if legacy.kind == LegacyJvmRuleKind::RuleMap {
            continue;
        }
        let Some(method) = legacy.method.as_ref() else {
            compilation.diagnostics.push(LegacyJvmCompileDiagnostic {
                rule_id: legacy.id.clone(),
                feature: "missing_method".to_string(),
            });
            continue;
        };
        let matcher = compile_method(method, &legacy.id, &mut compilation.diagnostics)?;
        match legacy.kind {
            LegacyJvmRuleKind::Source => {
                compile_source_rule(&mut compilation, legacy, &language, namespace, &matcher)
            }
            LegacyJvmRuleKind::Sink => {
                compile_sink_rule(&mut compilation, legacy, &language, namespace, &matcher)
            }
            LegacyJvmRuleKind::Passthrough => {
                compile_passthrough_rule(&mut compilation, legacy, &language, namespace, &matcher)
            }
            LegacyJvmRuleKind::Cleanse => {
                compile_cleanse_rule(&mut compilation, legacy, &language, namespace, &matcher)
            }
            LegacyJvmRuleKind::RuleMap => unreachable!(),
        }
    }
    compilation.rules.validate()?;
    Ok(compilation)
}

pub fn compile_legacy_jvm_rule_tree(
    root: &Path,
    language: Language,
    namespace: &str,
) -> Result<LegacyJvmCompilation> {
    anyhow::ensure!(
        root.is_dir(),
        "legacy JVM rule root is not a directory: {}",
        root.display()
    );
    let mut paths = Vec::new();
    collect_yaml_files(root, &mut paths)?;
    paths.sort_by_key(|path| {
        let is_patch = path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.to_ascii_lowercase().contains("patch"));
        (is_patch, path.clone())
    });
    let mut result = LegacyJvmCompilation::default();
    let mut knowledge = LegacyJvmKnowledgeCatalog::default();
    let mut vulnerability_names = BTreeMap::new();
    for path in paths {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read legacy JVM rules {}", path.display()))?;
        let document: Value = serde_yaml::from_str(&text)
            .with_context(|| format!("failed to parse legacy JVM YAML {}", path.display()))?;
        knowledge
            .ingest_document(&document)
            .with_context(|| format!("failed to import JVM knowledge {}", path.display()))?;
        if document
            .as_mapping()
            .and_then(|mapping| get(mapping, "rules"))
            .and_then(Value::as_sequence)
            .is_none()
        {
            continue;
        }
        let pack = LegacyJvmRulePack::from_yaml_str(&text)
            .with_context(|| format!("failed to parse legacy JVM rules {}", path.display()))?;
        knowledge.ingest_rule_maps(&pack);
        for rule in pack
            .rules
            .iter()
            .filter(|rule| rule.kind == LegacyJvmRuleKind::Sink)
        {
            for point in 0..rule.points.len() {
                vulnerability_names.insert(
                    format!("{namespace}.sink.{}.{point}", normalized_id(&rule.id)),
                    rule.vulnerability
                        .clone()
                        .unwrap_or_else(|| "legacy_taint".into()),
                );
            }
        }
        let compiled = compile_legacy_jvm_taint_pack(&pack, language.clone(), namespace)
            .with_context(|| format!("failed to compile legacy JVM rules {}", path.display()))?;
        result.rules.merge(compiled.rules);
        result.diagnostics.extend(compiled.diagnostics);
    }
    result.metadata_report = knowledge.enrich(&mut result.rules.metadata, &vulnerability_names);
    result.rules.validate()?;
    Ok(result)
}

fn compile_source_rule(
    compilation: &mut LegacyJvmCompilation,
    legacy: &LegacyJvmRule,
    language: &Language,
    namespace: &str,
    matcher: &ApiMatcher,
) {
    let signs = legacy
        .signs
        .iter()
        .filter(|change| change.added)
        .map(|change| change.sign.as_str())
        .collect::<Vec<_>>();
    let signs = if signs.is_empty() {
        vec!["generic"]
    } else {
        signs
    };
    for (output_index, position) in legacy.outputs.iter().enumerate() {
        let output = compile_position(compilation, &legacy.id, position);
        for sign in &signs {
            let id = format!(
                "{namespace}.source.{}.{}.{}",
                normalized_id(&legacy.id),
                output_index,
                normalized_id(sign)
            );
            compilation.rules.sources.push(SourceRule {
                id: id.clone(),
                language: Some(language.clone()),
                matcher: matcher.clone(),
                out: output.clone(),
                kind: (*sign).to_string(),
            });
            compile_call_condition(compilation, legacy, &id);
        }
    }
}

fn compile_sink_rule(
    compilation: &mut LegacyJvmCompilation,
    legacy: &LegacyJvmRule,
    language: &Language,
    namespace: &str,
    matcher: &ApiMatcher,
) {
    let vulnerability = legacy.vulnerability.as_deref().unwrap_or("legacy_taint");
    for (point_index, point) in legacy.points.iter().enumerate() {
        let inputs = point
            .inputs
            .iter()
            .map(|position| compile_position(compilation, &legacy.id, position))
            .collect::<Vec<_>>();
        if inputs.is_empty() {
            if legacy.id == "@check_return_value" {
                let id = format!(
                    "{namespace}.sink.{}.{}",
                    normalized_id(&legacy.id),
                    point_index
                );
                compilation
                    .rules
                    .unused_return_sinks
                    .push(UnusedReturnSinkRule {
                        id: id.clone(),
                        language: Some(language.clone()),
                        kind: "@check_return_value".to_string(),
                        source_kind: "@check_return_value".to_string(),
                    });
                compilation.rules.metadata.push(RuleMetadata {
                    id: id.clone(),
                    title: vulnerability.replace('_', " "),
                    message: "Return value carrying @check_return_value was ignored".to_string(),
                    severity: "warning".to_string(),
                    cwe: Vec::new(),
                    standards: Vec::new(),
                    translations: Default::default(),
                });
                let conditions = legacy
                    .condition
                    .iter()
                    .chain(point.condition.iter())
                    .map(compile_taint_condition)
                    .collect::<std::result::Result<Vec<_>, _>>();
                match conditions {
                    Ok(mut conditions) if !conditions.is_empty() => {
                        let condition = if conditions.len() == 1 {
                            conditions.pop().expect("single condition")
                        } else {
                            TaintCondition::All(conditions)
                        };
                        compilation.rules.sink_conditions.push(SinkConditionRule {
                            sink_rule_id: id,
                            condition,
                        });
                    }
                    Ok(_) => {}
                    Err(feature) => compilation.diagnostics.push(LegacyJvmCompileDiagnostic {
                        rule_id: legacy.id.clone(),
                        feature: format!("unsupported_sink_condition:{feature}"),
                    }),
                }
            }
            continue;
        }
        let id = format!(
            "{namespace}.sink.{}.{}",
            normalized_id(&legacy.id),
            point_index
        );
        compilation.rules.sinks.push(SinkRule {
            id: id.clone(),
            language: Some(language.clone()),
            matcher: matcher.clone(),
            inputs,
            kind: "generic".to_string(),
        });
        compilation.rules.metadata.push(RuleMetadata {
            id,
            title: vulnerability.replace('_', " "),
            message: format!("Legacy taint sink matched: {vulnerability}"),
            severity: "warning".to_string(),
            cwe: Vec::new(),
            standards: Vec::new(),
            translations: Default::default(),
        });
        let conditions = legacy
            .condition
            .iter()
            .chain(point.condition.iter())
            .map(compile_taint_condition)
            .collect::<std::result::Result<Vec<_>, _>>();
        match conditions {
            Ok(mut conditions) if !conditions.is_empty() => {
                let condition = if conditions.len() == 1 {
                    conditions.pop().expect("single condition")
                } else {
                    TaintCondition::All(conditions)
                };
                compilation.rules.sink_conditions.push(SinkConditionRule {
                    sink_rule_id: compilation
                        .rules
                        .sinks
                        .last()
                        .expect("sink inserted before condition")
                        .id
                        .clone(),
                    condition,
                });
            }
            Ok(_) => {}
            Err(feature) => compilation.diagnostics.push(LegacyJvmCompileDiagnostic {
                rule_id: legacy.id.clone(),
                feature: format!("unsupported_sink_condition:{feature}"),
            }),
        }
    }
}

fn compile_passthrough_rule(
    compilation: &mut LegacyJvmCompilation,
    legacy: &LegacyJvmRule,
    language: &Language,
    namespace: &str,
    matcher: &ApiMatcher,
) {
    let inputs = legacy
        .inputs
        .iter()
        .map(|position| compile_position(compilation, &legacy.id, position))
        .collect::<Vec<_>>();
    let outputs = legacy
        .outputs
        .iter()
        .map(|position| compile_position(compilation, &legacy.id, position))
        .collect::<Vec<_>>();
    let flows = inputs
        .iter()
        .flat_map(|input| {
            outputs.iter().map(move |output| FlowSpec {
                from: input.clone(),
                to: output.clone(),
            })
        })
        .collect::<Vec<_>>();
    if !flows.is_empty() {
        let id = format!("{namespace}.passthrough.{}", normalized_id(&legacy.id));
        compilation.rules.propagators.push(PropagatorRule {
            id: id.clone(),
            language: Some(language.clone()),
            matcher: matcher.clone(),
            flows,
        });
        compile_call_condition(compilation, legacy, &id);
    }
    let add_kinds = legacy
        .signs
        .iter()
        .filter(|change| change.added)
        .map(|change| change.sign.clone())
        .collect::<Vec<_>>();
    let remove_kinds = legacy
        .signs
        .iter()
        .filter(|change| !change.added)
        .map(|change| change.sign.clone())
        .collect::<Vec<_>>();
    if !add_kinds.is_empty() && !outputs.is_empty() {
        let id = format!(
            "{namespace}.passthrough_transform.{}",
            normalized_id(&legacy.id)
        );
        compilation.rules.taint_transforms.push(TaintTransformRule {
            id: id.clone(),
            language: Some(language.clone()),
            matcher: matcher.clone(),
            inputs: inputs.clone(),
            outputs: outputs.clone(),
            add_kinds,
            remove_kinds,
        });
        compile_call_condition(compilation, legacy, &id);
    } else {
        for change in legacy.signs.iter().filter(|change| !change.added) {
            let id = format!(
                "{namespace}.passthrough_remove.{}.{}",
                normalized_id(&legacy.id),
                normalized_id(&change.sign)
            );
            compilation.rules.sanitizers.push(SanitizerRule {
                id: id.clone(),
                language: Some(language.clone()),
                matcher: matcher.clone(),
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                kind: change.sign.clone(),
            });
            compile_call_condition(compilation, legacy, &id);
        }
    }
}

fn compile_cleanse_rule(
    compilation: &mut LegacyJvmCompilation,
    legacy: &LegacyJvmRule,
    language: &Language,
    namespace: &str,
    matcher: &ApiMatcher,
) {
    let outputs = legacy
        .outputs
        .iter()
        .map(|position| compile_position(compilation, &legacy.id, position))
        .collect::<Vec<_>>();
    if outputs.is_empty() {
        return;
    }
    let mut removed = legacy
        .signs
        .iter()
        .filter(|change| !change.added)
        .map(|change| change.sign.clone())
        .collect::<Vec<_>>();
    let added = legacy
        .signs
        .iter()
        .filter(|change| change.added)
        .map(|change| change.sign.clone())
        .collect::<Vec<_>>();
    if removed.is_empty() {
        removed.push("generic".to_string());
    }
    if !added.is_empty() {
        let id = format!(
            "{namespace}.cleanse_transform.{}",
            normalized_id(&legacy.id)
        );
        compilation.rules.taint_transforms.push(TaintTransformRule {
            id: id.clone(),
            language: Some(language.clone()),
            matcher: matcher.clone(),
            inputs: Vec::new(),
            outputs,
            add_kinds: added,
            remove_kinds: removed,
        });
        compile_call_condition(compilation, legacy, &id);
        return;
    }
    for sign in removed {
        let id = format!(
            "{namespace}.cleanse.{}.{}",
            normalized_id(&legacy.id),
            normalized_id(&sign)
        );
        compilation.rules.sanitizers.push(SanitizerRule {
            id: id.clone(),
            language: Some(language.clone()),
            matcher: matcher.clone(),
            inputs: Vec::new(),
            outputs: outputs.clone(),
            kind: sign,
        });
        compile_call_condition(compilation, legacy, &id);
    }
}

fn compile_call_condition(
    compilation: &mut LegacyJvmCompilation,
    legacy: &LegacyJvmRule,
    rule_id: &str,
) {
    let Some(condition) = &legacy.condition else {
        return;
    };
    match compile_taint_condition(condition) {
        Ok(condition) => compilation.rules.call_conditions.push(CallConditionRule {
            rule_id: rule_id.to_string(),
            condition,
        }),
        Err(feature) => compilation.diagnostics.push(LegacyJvmCompileDiagnostic {
            rule_id: legacy.id.clone(),
            feature: format!("unsupported_call_condition:{feature}"),
        }),
    }
}

fn compile_method(
    method: &LegacyJvmMethod,
    rule_id: &str,
    diagnostics: &mut Vec<LegacyJvmCompileDiagnostic>,
) -> Result<ApiMatcher> {
    let mut matcher = ApiMatcher::default();
    if let Some(name) = &method.method_name {
        match name {
            LegacyJvmPattern::Exact {
                value,
                case_insensitive: false,
            } => matcher.method_name = Some(value.clone()),
            pattern => matcher.method_regex = Some(anchored_pattern(pattern)),
        }
    }
    match (&method.namespace, &method.class_name) {
        (
            Some(LegacyJvmPattern::Exact {
                value: namespace,
                case_insensitive: false,
            }),
            Some(LegacyJvmPattern::Exact {
                value: class_name,
                case_insensitive: false,
            }),
        ) if !namespace.is_empty() => {
            matcher.receiver_type = Some(format!("{namespace}.{class_name}"));
        }
        (namespace, class_name) if namespace.is_some() || class_name.is_some() => {
            let namespace = namespace
                .as_ref()
                .map(pattern_fragment)
                .unwrap_or_else(|| ".*".to_string());
            let class_name = class_name
                .as_ref()
                .map(pattern_fragment)
                .unwrap_or_else(|| ".*".to_string());
            matcher.receiver_regex = Some(format!("^(?:{namespace})\\.(?:{class_name})$"));
        }
        _ => {}
    }
    // The legacy JVM checker's MethodDefinition.matches bytecode never reads
    // MethodParams.otherMin/otherMax. It only checks the positional `types`
    // prefix. Some shipped rules even contain otherMin > otherMax, confirming
    // these fields are inert compatibility data rather than arity bounds.
    for pattern in &method.parameter_types {
        match pattern {
            LegacyJvmPattern::Exact {
                value,
                case_insensitive: false,
            } => {
                matcher.arg_types.push(Some(value.clone()));
                matcher.arg_type_regexes.push(None);
            }
            pattern => {
                matcher.arg_types.push(None);
                matcher
                    .arg_type_regexes
                    .push(Some(anchored_pattern(pattern)));
            }
        }
    }
    let _ = (rule_id, diagnostics);
    matcher.validate()?;
    Ok(matcher)
}

fn compile_position(
    _compilation: &mut LegacyJvmCompilation,
    _rule_id: &str,
    position: &LegacyJvmPosition,
) -> Port {
    match position {
        LegacyJvmPosition::Receiver => Port::Receiver,
        LegacyJvmPosition::Return => Port::Return,
        LegacyJvmPosition::Argument(index) => Port::Arg(*index),
        LegacyJvmPosition::ArgumentsFrom(start) => Port::ArgsFrom(*start),
        LegacyJvmPosition::ArgumentRange { start, end } => Port::ArgsRange {
            start: *start,
            end: *end,
        },
        LegacyJvmPosition::Member(member) => Port::Member(member.clone()),
    }
}

fn compile_taint_condition(value: &Value) -> std::result::Result<TaintCondition, String> {
    let (tag, body) = tagged(value).ok_or_else(|| "missing_tag".to_string())?;
    let map = body
        .as_mapping()
        .ok_or_else(|| format!("{tag}_not_mapping"))?;
    match tag.as_str() {
        "checkSign" => string(map, "sign")
            .map(TaintCondition::HasKind)
            .ok_or_else(|| "checkSign_without_sign".to_string()),
        "not" => get(map, "child")
            .ok_or_else(|| "not_without_child".to_string())
            .and_then(compile_taint_condition)
            .map(|condition| TaintCondition::Not(Box::new(condition))),
        "and" | "or" => {
            let children = get(map, "children")
                .and_then(Value::as_sequence)
                .ok_or_else(|| format!("{tag}_without_children"))?
                .iter()
                .map(compile_taint_condition)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if tag == "and" {
                Ok(TaintCondition::All(children))
            } else {
                Ok(TaintCondition::Any(children))
            }
        }
        "checkIsType" => {
            let port = condition_port(map)?;
            let namespace = non_null(map, "nsName")
                .map(parse_pattern)
                .transpose()
                .map_err(|error| error.to_string())?;
            let class_name = non_null(map, "className")
                .map(parse_pattern)
                .transpose()
                .map_err(|error| error.to_string())?;
            let (exact, regex) = combined_type_constraints(namespace.as_ref(), class_name.as_ref());
            Ok(TaintCondition::IsType { port, exact, regex })
        }
        "checkValueMatches" => {
            let port = condition_port(map)?;
            let pattern = get(map, "pattern")
                .ok_or_else(|| "checkValueMatches_without_pattern".to_string())?;
            let (exact, regex) = if pattern.is_null() {
                (Some("<null>".to_string()), None)
            } else {
                let pattern = parse_pattern(pattern).map_err(|error| error.to_string())?;
                pattern_constraints(&pattern)
            };
            Ok(TaintCondition::ValueMatches { port, exact, regex })
        }
        "checkIsConstant" => Ok(TaintCondition::IsConstant(condition_port(map)?)),
        _ => Err(tag),
    }
}

fn condition_port(map: &Mapping) -> std::result::Result<Port, String> {
    let value = get(map, "argument").ok_or_else(|| "condition_without_argument".to_string())?;
    let position = parse_position(value).map_err(|error| error.to_string())?;
    match position {
        LegacyJvmPosition::Receiver => Ok(Port::Receiver),
        LegacyJvmPosition::Return => Ok(Port::Return),
        LegacyJvmPosition::Argument(index) => Ok(Port::Arg(index)),
        LegacyJvmPosition::ArgumentsFrom(start) => Ok(Port::ArgsFrom(start)),
        LegacyJvmPosition::ArgumentRange { start, end } => Ok(Port::ArgsRange { start, end }),
        LegacyJvmPosition::Member(member) => Err(format!("condition_member_position:{member}")),
    }
}

fn pattern_constraints(pattern: &LegacyJvmPattern) -> (Option<String>, Option<String>) {
    match pattern {
        LegacyJvmPattern::Exact {
            value,
            case_insensitive: false,
        } => (Some(value.clone()), None),
        pattern => (None, Some(anchored_pattern(pattern))),
    }
}

fn combined_type_constraints(
    namespace: Option<&LegacyJvmPattern>,
    class_name: Option<&LegacyJvmPattern>,
) -> (Option<String>, Option<String>) {
    match (namespace, class_name) {
        (
            Some(LegacyJvmPattern::Exact {
                value: namespace,
                case_insensitive: false,
            }),
            Some(LegacyJvmPattern::Exact {
                value: class_name,
                case_insensitive: false,
            }),
        ) => (Some(format!("{namespace}.{class_name}")), None),
        (namespace, class_name) => {
            let namespace = namespace
                .map(pattern_fragment)
                .unwrap_or_else(|| ".*".to_string());
            let class_name = class_name
                .map(pattern_fragment)
                .unwrap_or_else(|| ".*".to_string());
            (None, Some(format!("^(?:{namespace})\\.(?:{class_name})$")))
        }
    }
}

fn pattern_fragment(pattern: &LegacyJvmPattern) -> String {
    match pattern {
        LegacyJvmPattern::Exact {
            value,
            case_insensitive,
        } => {
            let escaped = regex::escape(value);
            if *case_insensitive {
                format!("(?i:{escaped})")
            } else {
                escaped
            }
        }
        LegacyJvmPattern::Regex {
            value,
            case_insensitive,
        } => {
            if *case_insensitive {
                format!("(?i:{value})")
            } else {
                value.clone()
            }
        }
    }
}

fn anchored_pattern(pattern: &LegacyJvmPattern) -> String {
    format!("^(?:{})$", pattern_fragment(pattern))
}

fn normalized_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn collect_yaml_files(directory: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "failed to list legacy JVM rule directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_yaml_files(&path, out)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| {
                    value.eq_ignore_ascii_case("yaml") || value.eq_ignore_ascii_case("yml")
                })
        {
            out.push(path);
        }
    }
    Ok(())
}

fn parse_rule(value: &Value) -> Result<LegacyJvmRule> {
    let (tag, body) = tagged(value).context("legacy JVM rule is missing a YAML tag")?;
    let kind = match tag.as_str() {
        "sourceRule" => LegacyJvmRuleKind::Source,
        "sinkRule" => LegacyJvmRuleKind::Sink,
        "passthroughRule" => LegacyJvmRuleKind::Passthrough,
        "cleanseRule" => LegacyJvmRuleKind::Cleanse,
        "ruleMap" => LegacyJvmRuleKind::RuleMap,
        _ => anyhow::bail!("unsupported legacy JVM rule tag !{tag}"),
    };
    let body = as_mapping(body, "legacy JVM rule")?;
    let id = string(body, "id")
        .or_else(|| string(body, "name"))
        .context("legacy JVM rule has neither id nor name")?;
    let method = get(body, "method").map(parse_method).transpose()?;
    let inputs = positions(body, "ins")?;
    let outputs = positions(body, "outs")?;
    let signs = parse_signs(get(body, "signs"))?;
    let points = get(body, "sinkPoints")
        .or_else(|| get(body, "sourcePoints"))
        .map(parse_points)
        .transpose()?
        .unwrap_or_default();
    let condition = get(body, "check").cloned();
    let mappings = get(body, "maps")
        .map(parse_mappings)
        .transpose()?
        .unwrap_or_default();
    Ok(LegacyJvmRule {
        kind,
        id,
        vulnerability: string(body, "rule"),
        method,
        inputs,
        outputs,
        signs,
        points,
        condition,
        mappings,
    })
}

fn parse_method(value: &Value) -> Result<LegacyJvmMethod> {
    let map = as_mapping(value, "legacy JVM method")?;
    let params = get(map, "params").and_then(Value::as_mapping);
    Ok(LegacyJvmMethod {
        namespace: non_null(map, "nsName").map(parse_pattern).transpose()?,
        class_name: non_null(map, "className").map(parse_pattern).transpose()?,
        method_name: non_null(map, "methodName").map(parse_pattern).transpose()?,
        parameter_min: params.and_then(|value| usize_value(value, "otherMin")),
        parameter_max: params.and_then(|value| usize_value(value, "otherMax")),
        parameter_types: params
            .and_then(|value| get(value, "types"))
            .map(parse_patterns)
            .transpose()?
            .unwrap_or_default(),
        extends: bool_value(map, "extends"),
        implements: bool_value(map, "implements"),
        overrides: bool_value(map, "overrides"),
    })
}

fn parse_pattern(value: &Value) -> Result<LegacyJvmPattern> {
    let (tag, body) = tagged(value).context("legacy JVM pattern is missing a YAML tag")?;
    let map = as_mapping(body, "legacy JVM pattern")?;
    let case_insensitive = bool_value(map, "caseInsensitive");
    match tag.as_str() {
        "exactPattern" => Ok(LegacyJvmPattern::Exact {
            value: string(map, "exact").context("exact pattern has no exact value")?,
            case_insensitive,
        }),
        "regexPattern" => Ok(LegacyJvmPattern::Regex {
            value: string(map, "pattern").context("regex pattern has no value")?,
            case_insensitive,
        }),
        _ => anyhow::bail!("unsupported legacy JVM pattern tag !{tag}"),
    }
}

fn parse_patterns(value: &Value) -> Result<Vec<LegacyJvmPattern>> {
    value
        .as_sequence()
        .context("legacy JVM parameter types must be a sequence")?
        .iter()
        .map(parse_pattern)
        .collect()
}

fn positions(map: &Mapping, key: &str) -> Result<Vec<LegacyJvmPosition>> {
    get(map, key)
        .map(parse_positions)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn parse_positions(value: &Value) -> Result<Vec<LegacyJvmPosition>> {
    value
        .as_sequence()
        .context("legacy JVM value positions must be a sequence")?
        .iter()
        .map(parse_position)
        .collect()
}

fn parse_position(value: &Value) -> Result<LegacyJvmPosition> {
    let (tag, body) = tagged(value).context("legacy JVM position is missing a YAML tag")?;
    let map = as_mapping(body, "legacy JVM position")?;
    match tag.as_str() {
        "valuePositionThis" => Ok(LegacyJvmPosition::Receiver),
        "valuePositionReturn" => Ok(LegacyJvmPosition::Return),
        "valuePositionSingle" => Ok(LegacyJvmPosition::Argument(
            usize_value(map, "position").context("single position has no index")?,
        )),
        "valuePositionRangeLeft" => Ok(LegacyJvmPosition::ArgumentsFrom(
            usize_value(map, "startInclusive").context("left range has no start")?,
        )),
        "valuePositionRangeFull" => Ok(LegacyJvmPosition::ArgumentRange {
            start: usize_value(map, "startInclusive").context("full range has no start")?,
            end: usize_value(map, "endInclusive").context("full range has no end")?,
        }),
        "valuePositionMember" => Ok(LegacyJvmPosition::Member(
            string(map, "member").context("member position has no member name")?,
        )),
        _ => anyhow::bail!("unsupported legacy JVM position tag !{tag}"),
    }
}

fn parse_signs(value: Option<&Value>) -> Result<Vec<LegacyJvmSignChange>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_sequence()
        .context("legacy JVM signs must be a sequence")?
        .iter()
        .map(|value| {
            let (tag, body) = tagged(value).context("legacy JVM sign is missing a YAML tag")?;
            let map = as_mapping(body, "legacy JVM sign")?;
            let added = match tag.as_str() {
                "addSign" => true,
                "removeSign" => false,
                _ => anyhow::bail!("unsupported legacy JVM sign tag !{tag}"),
            };
            Ok(LegacyJvmSignChange {
                sign: string(map, "s").context("legacy JVM sign has no name")?,
                added,
            })
        })
        .collect()
}

fn parse_points(value: &Value) -> Result<Vec<LegacyJvmPoint>> {
    value
        .as_sequence()
        .context("legacy JVM points must be a sequence")?
        .iter()
        .map(|value| {
            let map = as_mapping(value, "legacy JVM point")?;
            Ok(LegacyJvmPoint {
                inputs: positions(map, "ins")?,
                condition: get(map, "check").cloned(),
                master: bool_value(map, "master"),
            })
        })
        .collect()
}

fn parse_mappings(value: &Value) -> Result<Vec<LegacyJvmStandardMap>> {
    value
        .as_sequence()
        .context("legacy JVM rule mappings must be a sequence")?
        .iter()
        .map(|value| {
            let map = as_mapping(value, "legacy JVM standard mapping")?;
            Ok(LegacyJvmStandardMap {
                standard: string(map, "type").context("mapping has no standard type")?,
                rule_id: string(map, "value").context("mapping has no rule id")?,
            })
        })
        .collect()
}

fn tagged(value: &Value) -> Option<(String, &Value)> {
    let Value::Tagged(tagged) = value else {
        return None;
    };
    Some((
        tagged.tag.to_string().trim_start_matches('!').to_string(),
        &tagged.value,
    ))
}

fn as_mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Mapping> {
    value
        .as_mapping()
        .with_context(|| format!("{label} must be a mapping"))
}

fn get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn non_null<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    get(map, key).filter(|value| !matches!(value, Value::Null))
}

fn string(map: &Mapping, key: &str) -> Option<String> {
    get(map, key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })
}

fn usize_value(map: &Mapping, key: &str) -> Option<usize> {
    get(map, key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
}

fn bool_value(map: &Mapping, key: &str) -> bool {
    get(map, key).and_then(Value::as_bool).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tagged_source_sink_passthrough_and_standard_map() {
        let pack = LegacyJvmRulePack::from_yaml_str(
            r#"
rules:
- !sourceRule
  id: source-1
  method:
    nsName: !exactPattern { exact: javax.servlet, caseInsensitive: false }
    className: !regexPattern { pattern: HttpServletRequest.*, caseInsensitive: false }
    methodName: !exactPattern { exact: getParameter, caseInsensitive: false }
    params: { otherMin: 1, otherMax: 1 }
  outs: [!valuePositionReturn {}]
  signs: [!addSign { s: xss }, !addSign { s: sql }]
  check: !checkValueMatches
    argument: !valuePositionSingle { position: 0 }
    pattern: !exactPattern { exact: tenant-a, caseInsensitive: false }
- !sinkRule
  id: sink-1
  rule: sql_injection
  method:
    className: !exactPattern { exact: Statement, caseInsensitive: false }
    methodName: !exactPattern { exact: execute, caseInsensitive: false }
  sinkPoints:
  - ins: [!valuePositionSingle { position: 0 }]
    check: !not { child: !checkSign { sign: safeSql } }
    master: true
- !passthroughRule
  id: pass-1
  method:
    methodName: !exactPattern { exact: format, caseInsensitive: false }
  ins: [!valuePositionRangeLeft { startInclusive: 0 }]
  outs: [!valuePositionReturn {}]
  signs: [!removeSign { s: xss }]
- !ruleMap
  name: sql_injection
  maps: [{ type: GJB, value: '0201' }]
"#,
        )
        .expect("legacy tagged rules");
        assert_eq!(pack.rules.len(), 4);
        assert_eq!(pack.count(LegacyJvmRuleKind::Source), 1);
        assert_eq!(pack.count(LegacyJvmRuleKind::Sink), 1);
        assert_eq!(pack.count(LegacyJvmRuleKind::Passthrough), 1);
        assert_eq!(pack.count(LegacyJvmRuleKind::RuleMap), 1);
        assert_eq!(pack.rules[0].signs.len(), 2);
        assert_eq!(
            pack.rules[1].points[0].inputs,
            vec![LegacyJvmPosition::Argument(0)]
        );
        assert_eq!(
            pack.rules[2].inputs,
            vec![LegacyJvmPosition::ArgumentsFrom(0)]
        );
        assert_eq!(pack.rules[3].mappings[0].standard, "GJB");
    }

    #[test]
    fn rejects_unknown_executable_tags_instead_of_silently_dropping_rules() {
        let error = LegacyJvmRulePack::from_yaml_str("rules:\n- !unknownRule { id: lost-rule }\n")
            .expect_err("unknown legacy rule must fail");
        assert!(error.to_string().contains("index 0"));
    }

    #[test]
    fn compiles_tagged_jvm_rules_into_native_taint_models() {
        let pack = LegacyJvmRulePack::from_yaml_str(
            r#"
rules:
- !sourceRule
  id: source-1
  method:
    nsName: !exactPattern { exact: javax.servlet, caseInsensitive: false }
    className: !exactPattern { exact: HttpServletRequest, caseInsensitive: false }
    methodName: !exactPattern { exact: getParameter, caseInsensitive: false }
    params: { otherMin: 1, otherMax: 1, types: [!exactPattern { exact: java.lang.String, caseInsensitive: false }] }
  outs: [!valuePositionReturn {}]
  signs: [!addSign { s: xss }, !addSign { s: sql }]
  check: !checkValueMatches
    argument: !valuePositionSingle { position: 0 }
    pattern: !exactPattern { exact: tenant-a, caseInsensitive: false }
- !sinkRule
  id: sink-1
  rule: sql_injection
  method:
    className: !exactPattern { exact: Statement, caseInsensitive: false }
    methodName: !exactPattern { exact: execute, caseInsensitive: false }
  sinkPoints:
  - ins: [!valuePositionSingle { position: 0 }]
    check: !not { child: !checkSign { sign: safeSql } }
- !passthroughRule
  id: pass-1
  method:
    methodName: !exactPattern { exact: format, caseInsensitive: false }
  ins: [!valuePositionRangeLeft { startInclusive: 0 }]
  outs: [!valuePositionReturn {}]
  signs: [!removeSign { s: xss }, !addSign { s: safeXss }]
"#,
        )
        .expect("parse legacy JVM rules");
        let compiled = compile_legacy_jvm_taint_pack(&pack, Language::Java, "legacy.java")
            .expect("compile native taint models");
        assert_eq!(compiled.rules.sources.len(), 2);
        assert_eq!(compiled.rules.sinks.len(), 1);
        assert_eq!(compiled.rules.propagators.len(), 1);
        assert!(compiled.rules.sanitizers.is_empty());
        assert_eq!(compiled.rules.taint_transforms.len(), 1);
        assert_eq!(compiled.rules.call_conditions.len(), 2);
        assert_eq!(compiled.rules.taint_transforms[0].remove_kinds, vec!["xss"]);
        assert_eq!(
            compiled.rules.taint_transforms[0].add_kinds,
            vec!["safeXss"]
        );
        assert!(matches!(
            compiled.rules.propagators[0].flows[0].from,
            Port::ArgsFrom(0)
        ));
        assert_eq!(
            compiled.rules.sources[0].matcher.receiver_type.as_deref(),
            Some("javax.servlet.HttpServletRequest")
        );
        assert_eq!(compiled.rules.sources[0].matcher.arg_count, None);
        assert_eq!(compiled.rules.sink_conditions.len(), 1);
        assert!(!compiled.rules.sink_conditions[0]
            .condition
            .matches_kind("safeSql"));
        assert!(compiled.rules.sink_conditions[0]
            .condition
            .matches_kind("sql"));
        assert!(compiled.diagnostics.is_empty());
    }

    #[test]
    fn compiles_cleanse_add_sign_as_an_atomic_label_replacement() {
        let pack = LegacyJvmRulePack::from_yaml_str(
            r#"
rules:
- !cleanseRule
  id: html-encode
  method:
    methodName: !exactPattern { exact: encode, caseInsensitive: false }
  outs: [!valuePositionReturn {}]
  signs: [!removeSign { s: xss }, !addSign { s: safeXss }]
  check: !checkValueMatches
    argument: !valuePositionSingle { position: 1 }
    pattern: null
"#,
        )
        .expect("parse legacy cleanse rule");
        let compiled = compile_legacy_jvm_taint_pack(&pack, Language::Java, "legacy.java")
            .expect("compile label transform");
        assert!(compiled.rules.sanitizers.is_empty());
        assert_eq!(compiled.rules.taint_transforms.len(), 1);
        let transform = &compiled.rules.taint_transforms[0];
        assert!(transform.inputs.is_empty());
        assert_eq!(transform.outputs, vec![Port::Return]);
        assert_eq!(transform.remove_kinds, vec!["xss"]);
        assert_eq!(transform.add_kinds, vec!["safeXss"]);
        assert_eq!(compiled.rules.call_conditions.len(), 1);
        assert!(matches!(
            &compiled.rules.call_conditions[0].condition,
            TaintCondition::ValueMatches {
                port: Port::Arg(1),
                exact: Some(value),
                regex: None
            } if value == "<null>"
        ));
        assert!(compiled.diagnostics.is_empty());
    }

    #[test]
    fn legacy_other_min_max_do_not_become_argument_count_constraints() {
        let pack = LegacyJvmRulePack::from_yaml_str(
            r#"
rules:
- !passthroughRule
  id: legacy-inverted-other-range
  method:
    methodName: !exactPattern { exact: writeBinary, caseInsensitive: false }
    params:
      otherMin: 2
      otherMax: 0
      types: [!exactPattern { exact: 'byte[]', caseInsensitive: false }]
  ins: [!valuePositionSingle { position: 0 }]
  outs: [!valuePositionReturn {}]
  signs: []
"#,
        )
        .expect("parse inert legacy other range");
        let compiled = compile_legacy_jvm_taint_pack(&pack, Language::Java, "legacy.java")
            .expect("compile inert legacy other range");
        let matcher = &compiled.rules.propagators[0].matcher;
        assert_eq!(matcher.arg_count, None);
        assert_eq!(matcher.arg_count_min, None);
        assert_eq!(matcher.arg_count_max, None);
        assert_eq!(matcher.arg_types, vec![Some("byte[]".to_string())]);
        assert!(compiled.diagnostics.is_empty());
    }

    #[test]
    fn audits_each_jvm_rule_file_and_reports_duplicate_executable_ids() {
        let root =
            std::env::temp_dir().join(format!("uniflow-legacy-jvm-catalog-{}", std::process::id()));
        if root.exists() {
            fs::remove_dir_all(&root).expect("remove stale JVM catalog fixture");
        }
        fs::create_dir_all(root.join("java")).expect("create JVM catalog fixture");
        let source = "rules:\n- !sourceRule\n  id: shared\n  method: { methodName: !exactPattern { exact: input, caseInsensitive: false } }\n  outs: [!valuePositionReturn {}]\n  signs: []\n";
        fs::write(root.join("java/a.yaml"), source).expect("write first JVM rule file");
        fs::write(root.join("java/b.yaml"), source).expect("write second JVM rule file");

        let report = audit_legacy_jvm_rule_tree(&root).expect("audit JVM rules");
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.total_rules, 2);
        assert_eq!(report.total_executable_rules, 2);
        assert_eq!(report.duplicate_executable_ids, vec!["shared"]);
        assert!(report.skipped_non_executable_catalogs.is_empty());
        fs::remove_dir_all(&root).expect("remove JVM catalog fixture");
    }
}
