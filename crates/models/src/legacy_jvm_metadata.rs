//! Imports the legacy knowledge base as data. DynamicDescription templates are
//! deliberately not executed: reports use the original static prose instead.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use uniflow_rules::{LocalizedRuleText, RuleMetadata};
use zhhz::{Config, Converter};

use crate::{LegacyJvmRuleKind, LegacyJvmRulePack};

pub fn bundled_java_metadata_report() -> &'static str {
    include_str!("../../../rules/legacy/java-taint-metadata-report.json")
}

/// Legacy product presentation keys that describe the same executable taint
/// sink under a more tentative or framework-specific name. This list is
/// intentionally explicit: fuzzy name matching could silently attach an
/// unrelated security standard to a finding.
pub fn legacy_jvm_rule_map_aliases(vulnerability: &str) -> &'static [&'static str] {
    match vulnerability {
        "@check_return_value" => &[
            "detect_and_handle_file_related_errors",
            "incorrect_check_function_return_value",
        ],
        "command_injection" => &["command_injection_possible"],
        "cross_site_scripting_persistent" => &["cross_site_scripting_persistent_possible"],
        "cross_site_scripting_reflected" => &["cross_site_scripting_reflected_possible"],
        "denial_of_service" => &["denial_of_service_possible"],
        "dynamic_code_evaluation_unsafe_deserialization" => {
            &["dynamic_code_evaluation_unsafe_deserialization_possible"]
        }
        "dynamic_code_evaluation_xmldecoder_injection" => {
            &["dynamic_code_evaluation_xmldecoder_injection_possible"]
        }
        "insecure_ssl_overly_broad_certificate_trust" => {
            &["insecure_ssl_overly_broad_certificate_trust_possible"]
        }
        "ldap_injection" => &["ldap_injection_possible"],
        "process_control" => &["process_control_possible"],
        "sanitize_untrusted_data_passed_to_the_runtime_exec_method" => {
            &["sanitize_untrusted_data_passed_to_the_runtime_exec_method_possible"]
        }
        "server_side_request_forgery" => &["server_side_request_forgery_retrofit"],
        "xml_entity_expansion_injection" => &["xml_entity_expansion_injection_possible"],
        "xml_external_entity_injection" => &["xml_external_entity_injection_possible"],
        _ => &[],
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyJvmMetadataReport {
    /// Rules with complete, bundled presentation text after deterministic
    /// fallback and Simplified-to-Traditional conversion.
    pub enriched_sinks: usize,
    pub mapped_sinks: usize,
    pub chinese_messages: usize,
    pub english_messages: usize,
    pub traditional_chinese_messages: usize,
    /// Coverage supplied by the legacy knowledge base before fallback. These
    /// fields keep provenance gaps visible in audits.
    #[serde(default)]
    pub source_enriched_sinks: usize,
    #[serde(default)]
    pub source_chinese_messages: usize,
    #[serde(default)]
    pub source_english_messages: usize,
    #[serde(default)]
    pub source_traditional_chinese_messages: usize,
    pub unmapped_vulnerabilities: Vec<String>,
    pub unresolved_knowledge_ids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct KnowledgeEntry {
    zh_cn: LocalizedRuleText,
    en: LocalizedRuleText,
    zh_tw: LocalizedRuleText,
    cwe: BTreeSet<String>,
    standards: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub struct LegacyJvmKnowledgeCatalog {
    entries: BTreeMap<String, KnowledgeEntry>,
    mappings: BTreeMap<String, Vec<(String, String)>>,
}

impl LegacyJvmKnowledgeCatalog {
    pub fn from_tree(root: &std::path::Path) -> Result<Self> {
        let mut paths = Vec::new();
        crate::legacy_jvm::collect_yaml_files(root, &mut paths)?;
        paths.sort();
        let mut catalog = Self::default();
        for path in paths {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read JVM knowledge {}", path.display()))?;
            let document: Value = serde_yaml::from_str(&text)
                .with_context(|| format!("parse JVM knowledge {}", path.display()))?;
            catalog.ingest_document(&document)?;
            if document.get("rules").is_some() {
                catalog.ingest_rule_maps(&LegacyJvmRulePack::from_yaml_str(&text)?);
            }
        }
        Ok(catalog)
    }

    /// Register an exact source message id, also used by native AST rules.
    pub fn add_rule_mapping(&mut self, name: &str, standard: &str, id: &str) -> Result<()> {
        anyhow::ensure!(
            !name.trim().is_empty() && !standard.trim().is_empty() && !id.trim().is_empty(),
            "JVM metadata mapping must have a rule, standard and id"
        );
        // AST message identifiers carry a two-digit checker-family prefix;
        // the dataflow ruleMap catalog stores the same bug identifier without
        // that prefix. Import every standards mapping reachable through the
        // shared bug id so coding-style checkers retain CERT/GB/GJB/etc.
        let related = if standard.eq_ignore_ascii_case("ast") {
            id.get(2..)
                .filter(|candidate| candidate.chars().all(|ch| ch.is_ascii_digit()))
                .map(|bug_id| {
                    self.mappings
                        .values()
                        .filter(|mappings| {
                            mappings.iter().any(|(_, mapped_id)| mapped_id == bug_id)
                        })
                        .flatten()
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        self.add_mapping(name, standard.to_owned(), id.to_owned());
        for (kind, mapped_id) in related {
            self.add_mapping(name, kind, mapped_id);
        }
        Ok(())
    }

    pub fn ingest_yaml(&mut self, source: &str) -> Result<()> {
        let document: Value = serde_yaml::from_str(source).context("invalid JVM knowledge YAML")?;
        self.ingest_document(&document)
    }

    pub(crate) fn ingest_document(&mut self, document: &Value) -> Result<()> {
        if let Some(entries) = document.get("BugInfos").and_then(|v| v.get("BugInfo")) {
            for item in entries
                .as_sequence()
                .context("BugInfos.BugInfo must be a sequence")?
            {
                let id = scalar(item.get("id")).context("JVM knowledge entry has no id")?;
                let mut entry = KnowledgeEntry {
                    zh_cn: localized(item, "Categories", "Description", "Advice"),
                    en: localized(item, "Categories_En", "Description_En", "Advice_En"),
                    zh_tw: localized(item, "Categories_Tw", "Description_Tw", "Advice_Tw"),
                    ..Default::default()
                };
                if entry.en.title.is_empty() {
                    entry.en.title = item
                        .get("ENDetailClassChin")
                        .map(text_value)
                        .unwrap_or_default();
                }
                if let Some(references) = item
                    .get("References")
                    .and_then(|v| v.get("Reference"))
                    .and_then(Value::as_sequence)
                {
                    for reference in references {
                        let kind = scalar(reference.get("type")).unwrap_or_default();
                        let value = scalar(reference.get("value")).unwrap_or_default();
                        if kind.eq_ignore_ascii_case("CWE") {
                            let number = value
                                .trim()
                                .strip_prefix("CWE-")
                                .unwrap_or(value.trim())
                                .split(|c: char| !c.is_ascii_digit())
                                .next()
                                .unwrap_or_default();
                            if !number.is_empty() {
                                entry.cwe.insert(format!("CWE-{number}"));
                            }
                        }
                        if !kind.is_empty() && !value.is_empty() {
                            entry.standards.insert(format!("{kind}:{value}"));
                        }
                    }
                }
                let existing = self.entries.entry(id).or_default();
                fill_text(&mut existing.zh_cn, &entry.zh_cn);
                fill_text(&mut existing.en, &entry.en);
                fill_text(&mut existing.zh_tw, &entry.zh_tw);
                existing.cwe.extend(entry.cwe);
                existing.standards.extend(entry.standards);
            }
        }
        if let Some(mappings) = document.get("RuleSets").and_then(|v| v.get("RuleSet")) {
            for mapping in mappings
                .as_sequence()
                .context("RuleSets.RuleSet must be a sequence")?
            {
                let name = scalar(mapping.get("Name")).context("JVM RuleSet has no Name")?;
                if let Some(maps) = mapping.get("Maps").and_then(|v| v.get("Map")) {
                    for map in maps
                        .as_sequence()
                        .context("RuleSet Maps.Map must be a sequence")?
                    {
                        let kind =
                            scalar(map.get("type")).context("JVM rule mapping has no type")?;
                        let id =
                            scalar(map.get("value")).context("JVM rule mapping has no value")?;
                        self.add_mapping(&name, kind, id);
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn ingest_rule_maps(&mut self, pack: &LegacyJvmRulePack) {
        for rule in pack
            .rules
            .iter()
            .filter(|rule| rule.kind == LegacyJvmRuleKind::RuleMap)
        {
            for mapping in &rule.mappings {
                self.add_mapping(&rule.id, mapping.standard.clone(), mapping.rule_id.clone());
            }
        }
    }

    fn add_mapping(&mut self, name: &str, kind: String, id: String) {
        let maps = self.mappings.entry(name.to_owned()).or_default();
        if !maps.contains(&(kind.clone(), id.clone())) {
            maps.push((kind, id));
        }
    }

    /// Names are exact legacy vulnerability keys supplied by the compiler, not
    /// guessed from human-readable titles or from a UUID prefix.
    pub fn enrich(
        &self,
        metadata: &mut [RuleMetadata],
        names: &BTreeMap<String, String>,
    ) -> LegacyJvmMetadataReport {
        let mut report = LegacyJvmMetadataReport::default();
        let mut missing_names = BTreeSet::new();
        let mut missing_ids = BTreeSet::new();
        for meta in metadata.iter_mut() {
            let Some(name) = names.get(&meta.id) else {
                continue;
            };
            let mut mappings = self
                .mappings
                .get(name)
                .into_iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            for alias in legacy_jvm_rule_map_aliases(name) {
                mappings.extend(self.mappings.get(*alias).into_iter().flatten().cloned());
            }
            mappings.sort();
            mappings.dedup();
            if mappings.is_empty() {
                missing_names.insert(name.clone());
                continue;
            }
            report.mapped_sinks += 1;
            // Bug-level text is the canonical diagnostic. Standard-specific
            // descriptions fill absent locales; all references remain attached.
            let mut mappings = mappings.iter().collect::<Vec<_>>();
            mappings.sort_by_key(|(kind, id)| (kind != "bug", kind.as_str(), id.as_str()));
            let mut combined = KnowledgeEntry::default();
            for (kind, id) in mappings {
                combined.standards.insert(format!("LEGACY-MSG-{id}"));
                combined.standards.insert(format!("{kind}:{id}"));
                if let Some(entry) = self.entries.get(id) {
                    fill_text(&mut combined.zh_cn, &entry.zh_cn);
                    fill_text(&mut combined.en, &entry.en);
                    fill_text(&mut combined.zh_tw, &entry.zh_tw);
                    combined.cwe.extend(entry.cwe.iter().cloned());
                    combined.standards.extend(entry.standards.iter().cloned());
                } else {
                    missing_ids.insert(id.clone());
                }
            }
            meta.cwe.extend(combined.cwe);
            meta.cwe.sort();
            meta.cwe.dedup();
            meta.standards.extend(combined.standards);
            meta.standards.sort();
            meta.standards.dedup();
            let zh = nonempty(combined.zh_cn);
            let en = nonempty(combined.en);
            let tw = nonempty(combined.zh_tw);
            report.source_chinese_messages +=
                usize::from(zh.as_ref().is_some_and(|v| !v.message.is_empty()));
            report.source_english_messages +=
                usize::from(en.as_ref().is_some_and(|v| !v.message.is_empty()));
            report.source_traditional_chinese_messages +=
                usize::from(tw.as_ref().is_some_and(|v| !v.message.is_empty()));
            if zh.is_some() || en.is_some() || tw.is_some() {
                report.source_enriched_sinks += 1;
            }
            // English remains the canonical default where the source provides
            // it. Missing presentation locales are completed below.
            if let Some(text) = &en {
                if !text.title.is_empty() {
                    meta.title = text.title.clone();
                }
                if !text.message.is_empty() {
                    meta.message = text.message.clone();
                }
            }
            if zh.is_some() {
                meta.translations.zh_cn = zh;
            }
            if en.is_some() {
                meta.translations.en = en;
            }
            if tw.is_some() {
                meta.translations.zh_tw = tw;
            }
        }
        let converter = Converter::new(Config::S2twp);
        for meta in metadata.iter_mut() {
            complete_presentations(meta, &converter);
            report.chinese_messages += usize::from(has_message(&meta.translations.zh_cn));
            report.english_messages += usize::from(has_message(&meta.translations.en));
            report.traditional_chinese_messages +=
                usize::from(has_message(&meta.translations.zh_tw));
            report.enriched_sinks += usize::from(
                has_message(&meta.translations.zh_cn)
                    && has_message(&meta.translations.en)
                    && has_message(&meta.translations.zh_tw),
            );
        }
        report.unmapped_vulnerabilities = missing_names.into_iter().collect();
        report.unresolved_knowledge_ids = missing_ids.into_iter().collect();
        report
    }
}

fn complete_presentations(meta: &mut RuleMetadata, converter: &Converter) {
    let fallback = LocalizedRuleText {
        title: meta.title.clone(),
        message: if meta.message.trim().is_empty() {
            meta.title.clone()
        } else {
            meta.message.clone()
        },
    };
    let mut zh_cn = meta
        .translations
        .zh_cn
        .take()
        .unwrap_or_else(|| fallback.clone());
    fill_text(&mut zh_cn, &fallback);
    let mut en = meta
        .translations
        .en
        .take()
        .unwrap_or_else(|| fallback.clone());
    fill_text(&mut en, &fallback);
    let generated_tw = LocalizedRuleText {
        title: converter.convert(&zh_cn.title),
        message: converter.convert(&zh_cn.message),
    };
    let mut zh_tw = meta
        .translations
        .zh_tw
        .take()
        .unwrap_or_else(|| generated_tw.clone());
    fill_text(&mut zh_tw, &generated_tw);
    meta.translations.zh_cn = Some(zh_cn);
    meta.translations.en = Some(en);
    meta.translations.zh_tw = Some(zh_tw);
}

fn has_message(text: &Option<LocalizedRuleText>) -> bool {
    text.as_ref()
        .is_some_and(|text| !text.message.trim().is_empty())
}

fn localized(item: &Value, categories: &str, description: &str, advice: &str) -> LocalizedRuleText {
    let title = item
        .get(categories)
        .and_then(|v| v.get("Category"))
        .and_then(Value::as_sequence)
        .and_then(|categories| {
            categories
                .iter()
                .rev()
                .find(|v| scalar(v.get("type")).as_deref() == Some("DetailClassChin"))
        })
        .and_then(|v| scalar(v.get("value")))
        .unwrap_or_default();
    let description = scalar(item.get(description)).unwrap_or_default();
    let advice = scalar(item.get(advice)).unwrap_or_default();
    let message = [description, advice]
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n\n");
    LocalizedRuleText { title, message }
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn text_value(value: &Value) -> String {
    if let Some(values) = value.as_sequence() {
        values
            .iter()
            .filter_map(|value| scalar(Some(value)))
            .collect::<Vec<_>>()
            .join(" / ")
    } else {
        scalar(Some(value)).unwrap_or_default()
    }
}

fn fill_text(target: &mut LocalizedRuleText, candidate: &LocalizedRuleText) {
    if target.title.trim().is_empty() && !candidate.title.trim().is_empty() {
        target.title = candidate.title.clone();
    }
    if target.message.trim().is_empty() && !candidate.message.trim().is_empty() {
        target.message = candidate.message.clone();
    }
}

fn nonempty(text: LocalizedRuleText) -> Option<LocalizedRuleText> {
    (!text.title.trim().is_empty() || !text.message.trim().is_empty()).then_some(text)
}
