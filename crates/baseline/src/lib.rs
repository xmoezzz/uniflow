mod hir_scan;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use uniflow_hir::Language;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselinePack {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub rules: Vec<BaselineRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub languages: Vec<Language>,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Source-level regex. In HIR mode this is evaluated only for rules that do
    /// not declare a structured matcher, preventing duplicate reports.
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub matcher: BaselineMatcher,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default)]
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineMatcher {
    /// Regex matched against the normalized callee name.
    pub callee: String,
    /// Restrict the number of arguments.
    pub min_args: Option<usize>,
    pub max_args: Option<usize>,
    /// Argument indexes that must be literal values.
    pub literal_args: Vec<usize>,
    /// Argument indexes that must not be literal values.
    pub non_literal_args: Vec<usize>,
    /// Regex constraints for positional string-literal arguments.
    pub string_arg_patterns: BTreeMap<usize, String>,
    /// Exact constraints for positional integer arguments.
    pub int_arg_values: BTreeMap<usize, i64>,
    /// Exact constraints for positional boolean arguments.
    pub bool_arg_values: BTreeMap<usize, bool>,
    /// Named boolean argument constraints, for example `shell: true`.
    pub named_bool_args: BTreeMap<String, bool>,
    /// Regex constraints for named string-literal arguments.
    pub named_string_arg_patterns: BTreeMap<String, String>,
    /// Report only when the return value is discarded.
    pub ignored_return: bool,
    /// Report only for direct self-assignment, such as `p = realloc(p, n)`.
    pub self_assignment: bool,
}

impl BaselineMatcher {
    pub(crate) fn is_structured(&self) -> bool {
        !self.callee.is_empty()
            || self.min_args.is_some()
            || self.max_args.is_some()
            || !self.literal_args.is_empty()
            || !self.non_literal_args.is_empty()
            || !self.string_arg_patterns.is_empty()
            || !self.int_arg_values.is_empty()
            || !self.bool_arg_values.is_empty()
            || !self.named_bool_args.is_empty()
            || !self.named_string_arg_patterns.is_empty()
            || self.ignored_return
            || self.self_assignment
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Note,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub message: String,
    pub cwe: Vec<String>,
    pub standards: Vec<String>,
}

impl BaselinePack {
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        let pack: Self = serde_yaml::from_str(text)?;
        pack.validate()?;
        Ok(pack)
    }

    pub fn merge(
        id: impl Into<String>,
        title: impl Into<String>,
        packs: impl IntoIterator<Item = BaselinePack>,
    ) -> Result<Self> {
        let mut merged = Self {
            id: id.into(),
            title: title.into(),
            rules: Vec::new(),
        };
        for pack in packs {
            merged.rules.extend(pack.rules);
        }
        merged.validate()?;
        Ok(merged)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.id.trim().is_empty(), "baseline pack id is empty");
        anyhow::ensure!(!self.title.trim().is_empty(), "baseline pack title is empty");
        let mut ids = HashSet::new();
        for rule in &self.rules {
            anyhow::ensure!(!rule.id.trim().is_empty(), "baseline rule id is empty");
            anyhow::ensure!(
                ids.insert(rule.id.as_str()),
                "duplicate baseline rule id {}",
                rule.id
            );
            anyhow::ensure!(
                !rule.title.trim().is_empty(),
                "baseline rule {} has an empty title",
                rule.id
            );
            anyhow::ensure!(
                !rule.pattern.is_empty() || rule.matcher.is_structured(),
                "baseline rule {} has neither a source pattern nor a structured matcher",
                rule.id
            );
            if !rule.pattern.is_empty() {
                Regex::new(&rule.pattern).with_context(|| {
                    format!("invalid source regex for baseline rule {}", rule.id)
                })?;
            }
            if !rule.matcher.callee.is_empty() {
                Regex::new(&rule.matcher.callee).with_context(|| {
                    format!("invalid callee regex for baseline rule {}", rule.id)
                })?;
            }
            for pattern in rule
                .matcher
                .string_arg_patterns
                .values()
                .chain(rule.matcher.named_string_arg_patterns.values())
            {
                Regex::new(pattern).with_context(|| {
                    format!("invalid string argument regex for baseline rule {}", rule.id)
                })?;
            }
            if let (Some(min), Some(max)) = (rule.matcher.min_args, rule.matcher.max_args) {
                anyhow::ensure!(
                    min <= max,
                    "baseline rule {} has min_args > max_args",
                    rule.id
                );
            }
        }
        Ok(())
    }

    /// Regex-only scan. This is useful when parsing is unavailable. Comments
    /// are masked while strings and byte offsets are preserved.
    pub fn scan_text(
        &self,
        language: &Language,
        path: &Path,
        source: &str,
    ) -> Vec<BaselineFinding> {
        self.scan_source_rules(language, path, source, false)
    }

    pub(crate) fn scan_source_rules(
        &self,
        language: &Language,
        path: &Path,
        source: &str,
        unstructured_only: bool,
    ) -> Vec<BaselineFinding> {
        let sanitized = strip_comments_preserve_layout(language, source);
        let original_lines = source.lines().collect::<Vec<_>>();
        let mut findings = Vec::new();
        for rule in &self.rules {
            if unstructured_only && rule.matcher.is_structured() {
                continue;
            }
            if !rule.languages.is_empty() && !rule.languages.iter().any(|item| item == language) {
                continue;
            }
            if rule.pattern.is_empty() {
                continue;
            }
            let Ok(regex) = Regex::new(&rule.pattern) else {
                continue;
            };
            for (line_index, line) in sanitized.lines().enumerate() {
                for matched in regex.find_iter(line) {
                    findings.push(BaselineFinding {
                        rule_id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: rule.severity.clone(),
                        confidence: rule.confidence.clone(),
                        path: path.display().to_string(),
                        line: line_index + 1,
                        column: matched.start() + 1,
                        snippet: original_lines
                            .get(line_index)
                            .copied()
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                        message: rule_message(rule),
                        cwe: rule.cwe.clone(),
                        standards: rule.standards.clone(),
                    });
                }
            }
        }
        deduplicate_findings(findings)
    }
}

pub(crate) fn rule_message(rule: &BaselineRule) -> String {
    if rule.message.is_empty() {
        rule.title.clone()
    } else {
        rule.message.clone()
    }
}

pub(crate) fn deduplicate_findings(findings: Vec<BaselineFinding>) -> Vec<BaselineFinding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            seen.insert((
                finding.rule_id.clone(),
                finding.path.clone(),
                finding.line,
                finding.column,
            ))
        })
        .collect()
}

fn strip_comments_preserve_layout(language: &Language, source: &str) -> String {
    match language {
        Language::Python => strip_python_comments(source),
        Language::C | Language::Cpp | Language::Java => strip_c_like_comments(source),
        Language::Unknown => source.to_string(),
    }
}

fn strip_c_like_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut block_comment = false;
    while index < bytes.len() {
        if block_comment {
            if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                output[index] = b' ';
                output[index + 1] = b' ';
                block_comment = false;
                index += 2;
            } else {
                if bytes[index] != b'\n' && bytes[index] != b'\r' {
                    output[index] = b' ';
                }
                index += 1;
            }
            continue;
        }
        if let Some(current_quote) = quote {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == current_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output[index] = b' ';
            output[index + 1] = b' ';
            block_comment = true;
            index += 2;
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8")
}

fn strip_python_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote: Option<(u8, bool)> = None;
    let mut escaped = false;
    while index < bytes.len() {
        if let Some((current_quote, triple)) = quote {
            if escaped && !triple {
                escaped = false;
                index += 1;
                continue;
            }
            if !triple && bytes[index] == b'\\' {
                escaped = true;
                index += 1;
                continue;
            }
            if triple {
                if index + 2 < bytes.len()
                    && bytes[index] == current_quote
                    && bytes[index + 1] == current_quote
                    && bytes[index + 2] == current_quote
                {
                    quote = None;
                    index += 3;
                } else {
                    index += 1;
                }
            } else if bytes[index] == current_quote {
                quote = None;
                index += 1;
            } else {
                index += 1;
            }
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            let current = bytes[index];
            let triple = index + 2 < bytes.len()
                && bytes[index + 1] == current
                && bytes[index + 2] == current;
            quote = Some((current, triple));
            index += if triple { 3 } else { 1 };
            continue;
        }
        if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8")
}

pub fn builtin_security_pack() -> Result<BaselinePack> {
    BaselinePack::merge(
        "uniflow-security-1.0",
        "UniFlow security baseline",
        [
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/cert-c-cpp.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/python-security.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/java-security.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/common-security.yml"
            ))?,
        ],
    )
}

pub fn builtin_pack_manifest() -> &'static str {
    include_str!("../../../rules/baseline/manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_pack_is_valid_and_has_expected_rule_count() {
        let pack = builtin_security_pack().expect("built-in baseline pack");
        assert_eq!(pack.id, "uniflow-security-1.0");
        assert_eq!(pack.rules.len(), 200);
        let mut ids = HashSet::new();
        assert!(pack.rules.iter().all(|rule| ids.insert(rule.id.as_str())));
    }

    #[test]
    fn source_scan_ignores_comments_but_not_strings() {
        let pack = BaselinePack::from_yaml_str(
            r#"
id: test
title: Test
rules:
  - id: TEST-GETS
    title: gets
    languages: [c]
    severity: error
    confidence: high
    pattern: '\bgets\s*\('
"#,
        )
        .expect("pack");
        let source = "// gets(commented);\nconst char *s = \"gets(string)\";\ngets(buffer);\n";
        let findings = pack.scan_text(&Language::C, Path::new("demo.c"), source);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[1].line, 3);
    }

    #[test]
    fn merge_rejects_duplicate_rule_ids() {
        let rule = BaselineRule {
            id: "DUPLICATE".to_string(),
            title: "Duplicate".to_string(),
            languages: vec![],
            severity: Severity::Warning,
            confidence: Confidence::High,
            pattern: "x".to_string(),
            matcher: BaselineMatcher::default(),
            cwe: vec![],
            standards: vec![],
            message: String::new(),
        };
        let first = BaselinePack {
            id: "first".to_string(),
            title: "First".to_string(),
            rules: vec![rule.clone()],
        };
        let second = BaselinePack {
            id: "second".to_string(),
            title: "Second".to_string(),
            rules: vec![rule],
        };
        assert!(BaselinePack::merge("merged", "Merged", [first, second]).is_err());
    }
}
