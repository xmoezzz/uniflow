use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::Language;
use uniflow_rules::{
    ApiMatcher, FieldMatcher, FieldSanitizerRule, FieldSinkRule, FieldSourceRule, FlowSpec,
    FunctionMatcher, FunctionSinkRule, FunctionSourceRule, Port, PropagatorRule, RuleMetadata,
    RuleSet, SanitizerRule, SinkRule, SourceRule,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyPysaDiagnostic {
    pub path: String,
    pub line: usize,
    pub feature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyPysaCompilation {
    pub rules: RuleSet,
    pub diagnostics: Vec<LegacyPysaDiagnostic>,
    pub files: usize,
    pub models: usize,
}

#[derive(Clone, Debug)]
struct PysaItem {
    line: usize,
    decorators: Vec<String>,
    text: String,
}

struct Compiler<'a> {
    namespace: &'a str,
    path: String,
    next_id: usize,
    compilation: &'a mut LegacyPysaCompilation,
}

pub fn compile_legacy_pysa_rule_tree(
    root: &Path,
    namespace: &str,
) -> Result<LegacyPysaCompilation> {
    let mut paths = Vec::new();
    collect_pysa_files(root, &mut paths)?;
    paths.sort();
    let mut compilation = LegacyPysaCompilation::default();
    compilation.files = paths.len();
    for path in paths {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read Pysa model {}", path.display()))?;
        let display = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        let mut compiler = Compiler {
            namespace,
            path: display,
            next_id: compilation.models,
            compilation: &mut compilation,
        };
        compiler.compile_text(&text)?;
        compiler.compilation.models = compiler.next_id;
    }
    compilation.rules.validate()?;
    Ok(compilation)
}

pub fn compile_legacy_pysa_str(text: &str, namespace: &str) -> Result<LegacyPysaCompilation> {
    let mut compilation = LegacyPysaCompilation::default();
    compilation.files = 1;
    let mut compiler = Compiler {
        namespace,
        path: "<memory>".to_string(),
        next_id: 0,
        compilation: &mut compilation,
    };
    compiler.compile_text(text)?;
    compiler.compilation.models = compiler.next_id;
    compilation.rules.validate()?;
    Ok(compilation)
}

fn collect_pysa_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path
            .extension()
            .is_some_and(|extension| extension == "pysa")
        {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path)
        .with_context(|| format!("failed to walk Pysa model directory {}", path.display()))?
    {
        collect_pysa_files(&entry?.path(), out)?;
    }
    Ok(())
}

impl Compiler<'_> {
    fn compile_text(&mut self, text: &str) -> Result<()> {
        for item in scan_items(text) {
            let trimmed = item.text.trim();
            if trimmed.starts_with("def ") || trimmed.starts_with("async def ") {
                self.compile_definition(&item);
            } else if trimmed.starts_with("ModelQuery(") {
                self.compile_query(&item)?;
            } else if trimmed.contains(':')
                && (trimmed.contains("TaintSource")
                    || trimmed.contains("TaintSink")
                    || trimmed.contains("TaintInTaintOut")
                    || trimmed.contains("Sanitize"))
            {
                self.compile_attribute(&item)?;
            }
        }
        Ok(())
    }

    fn id(&mut self, category: &str, detail: &str) -> String {
        let id = format!(
            "{}.{}.{}.{}",
            self.namespace,
            category,
            self.next_id,
            normalized_id(detail)
        );
        self.next_id += 1;
        id
    }

    fn diagnostic(&mut self, line: usize, feature: impl Into<String>) {
        self.compilation.diagnostics.push(LegacyPysaDiagnostic {
            path: self.path.clone(),
            line,
            feature: feature.into(),
        });
    }

    fn compile_definition(&mut self, item: &PysaItem) {
        let Some((name, params, return_annotation)) = parse_definition(&item.text) else {
            self.diagnostic(item.line, "invalid function model header");
            return;
        };
        let matcher = ApiMatcher {
            exact: Some(name.clone()),
            ..ApiMatcher::default()
        };
        let parsed_params = parse_parameters(&params);
        let mut flows = Vec::new();
        for parameter in &parsed_params {
            let Some(annotation) = parameter.annotation.as_deref() else {
                continue;
            };
            if annotation.contains("Sanitize[") {
                self.compile_call_sanitize_annotation(
                    &name,
                    &matcher,
                    parameter.port.clone(),
                    annotation,
                );
                continue;
            }
            for kind in taint_kinds(annotation, "TaintSource") {
                let id = self.id("source", &format!("{name}.{kind}"));
                self.compilation.rules.sources.push(SourceRule {
                    id,
                    language: Some(Language::Python),
                    matcher: matcher.clone(),
                    out: parameter.port.clone(),
                    kind,
                });
            }
            for kind in taint_kinds(annotation, "TaintSink") {
                self.push_call_sink(&name, matcher.clone(), vec![parameter.port.clone()], kind);
            }
            if annotation.contains("TaintInTaintOut[") {
                let targets = tito_targets(annotation, &parsed_params);
                flows.extend(targets.into_iter().map(|to| FlowSpec {
                    from: parameter.port.clone(),
                    to,
                }));
            }
        }
        if let Some(annotation) = return_annotation.as_deref() {
            for kind in taint_kinds(annotation, "TaintSource") {
                let id = self.id("source", &format!("{name}.return.{kind}"));
                self.compilation.rules.sources.push(SourceRule {
                    id,
                    language: Some(Language::Python),
                    matcher: matcher.clone(),
                    out: Port::Return,
                    kind,
                });
            }
            for kind in taint_kinds(annotation, "TaintSink") {
                self.push_call_sink(&name, matcher.clone(), vec![Port::Return], kind);
            }
        }
        if !flows.is_empty() {
            flows.sort_by_key(|flow| format!("{:?}:{:?}", flow.from, flow.to));
            flows.dedup_by(|left, right| left.from == right.from && left.to == right.to);
            let id = self.id("propagator", &name);
            self.compilation.rules.propagators.push(PropagatorRule {
                id,
                language: Some(Language::Python),
                matcher: matcher.clone(),
                flows,
            });
        }
        self.compile_decorator_sanitizers(&name, matcher, &item.decorators);
    }

    fn compile_call_sanitize_annotation(
        &mut self,
        name: &str,
        matcher: &ApiMatcher,
        input: Port,
        annotation: &str,
    ) {
        let mut kinds = taint_kinds(annotation, "TaintSink");
        kinds.extend(taint_kinds(annotation, "TaintSource"));
        if kinds.is_empty() {
            kinds.push("generic".to_string());
        }
        let outputs = if annotation.contains("Updates[self]") {
            vec![Port::Receiver]
        } else {
            vec![Port::Return]
        };
        for kind in kinds {
            let id = self.id("sanitizer", &format!("{name}.{kind}"));
            self.compilation.rules.sanitizers.push(SanitizerRule {
                id,
                language: Some(Language::Python),
                matcher: matcher.clone(),
                inputs: vec![input.clone()],
                outputs: outputs.clone(),
                kind,
            });
        }
        let id = self.id("propagator", &format!("{name}.sanitize"));
        self.compilation.rules.propagators.push(PropagatorRule {
            id,
            language: Some(Language::Python),
            matcher: matcher.clone(),
            flows: outputs
                .into_iter()
                .map(|to| FlowSpec {
                    from: input.clone(),
                    to,
                })
                .collect(),
        });
    }

    fn compile_decorator_sanitizers(
        &mut self,
        name: &str,
        matcher: ApiMatcher,
        decorators: &[String],
    ) {
        for decorator in decorators {
            if !decorator.trim_start().starts_with("@Sanitize") {
                continue;
            }
            let mut kinds = taint_kinds(decorator, "TaintSource");
            kinds.extend(taint_kinds(decorator, "TaintSink"));
            if kinds.is_empty() {
                kinds.push("generic".to_string());
            }
            for kind in kinds {
                let id = self.id("sanitizer", &format!("{name}.decorator.{kind}"));
                self.compilation.rules.sanitizers.push(SanitizerRule {
                    id,
                    language: Some(Language::Python),
                    matcher: matcher.clone(),
                    inputs: vec![Port::Receiver, Port::ArgsFrom(0)],
                    outputs: vec![Port::Return],
                    kind,
                });
            }
        }
    }

    fn compile_attribute(&mut self, item: &PysaItem) -> Result<()> {
        let Some((target, annotation)) = split_top_level_once(&item.text, ':') else {
            self.diagnostic(item.line, "invalid attribute model");
            return Ok(());
        };
        let target = target.trim();
        let annotation = split_top_level_once(annotation, '=')
            .map(|(left, _)| left)
            .unwrap_or(annotation)
            .trim();
        let Some((owner, field)) = target.rsplit_once('.') else {
            self.diagnostic(item.line, "attribute model has no declaring owner");
            return Ok(());
        };
        let matcher = FieldMatcher {
            owner: Some(owner.to_string()),
            owner_regex: None,
            field: field.to_string(),
        };
        for kind in taint_kinds(annotation, "TaintSource") {
            let id = self.id("field-source", &format!("{target}.{kind}"));
            self.compilation.rules.field_sources.push(FieldSourceRule {
                id,
                language: Some(Language::Python),
                matcher: matcher.clone(),
                kind,
            });
        }
        for kind in taint_kinds(annotation, "TaintSink") {
            let id = self.id("field-sink", &format!("{target}.{kind}"));
            self.compilation.rules.field_sinks.push(FieldSinkRule {
                id: id.clone(),
                language: Some(Language::Python),
                matcher: matcher.clone(),
                kind: kind.clone(),
            });
            self.push_metadata(id, format!("Python field sink {target}"), kind);
        }
        if annotation == "Sanitize" || annotation.starts_with("Sanitize[") {
            let mut kinds = taint_kinds(annotation, "TaintSource");
            kinds.extend(taint_kinds(annotation, "TaintSink"));
            if kinds.is_empty() {
                kinds.push("generic".to_string());
            }
            for kind in kinds {
                let id = self.id("field-sanitizer", &format!("{target}.{kind}"));
                self.compilation
                    .rules
                    .field_sanitizers
                    .push(FieldSanitizerRule {
                        id,
                        language: Some(Language::Python),
                        matcher: matcher.clone(),
                        kind,
                    });
            }
        }
        Ok(())
    }

    fn compile_query(&mut self, item: &PysaItem) -> Result<()> {
        let query_name = quoted_assignment(&item.text, "name").unwrap_or_else(|| "query".into());
        let find = quoted_assignment(&item.text, "find").unwrap_or_default();
        let name_patterns = quoted_call_arguments(
            &item.text,
            &["name.matches", "fully_qualified_name.matches"],
        );
        let decorators =
            quoted_call_arguments(&item.text, &["Decorator(fully_qualified_name.matches"]);
        let owners = quoted_call_arguments(&item.text, &["cls.extends"]);
        let parameter_text = call_contents(&item.text, "Parameters").join("\n");
        let return_text = call_contents(&item.text, "Returns").join("\n");
        let attribute_text = call_contents(&item.text, "AttributeModel").join("\n");
        let parameter_source_kinds = taint_kinds(&parameter_text, "TaintSource");
        let parameter_sink_kinds = taint_kinds(&parameter_text, "TaintSink");
        let return_source_kinds = taint_kinds(&return_text, "TaintSource");
        let return_sink_kinds = taint_kinds(&return_text, "TaintSink");
        let attribute_source_kinds = taint_kinds(&attribute_text, "TaintSource");
        let attribute_sink_kinds = taint_kinds(&attribute_text, "TaintSink");
        let parameters = item.text.contains("Parameters(");
        let returns = item.text.contains("Returns(");
        let attribute_model = item.text.contains("AttributeModel(") || find == "attributes";

        if attribute_model {
            let owner_regex = exact_values_regex(&owners);
            if owner_regex.is_none() {
                self.diagnostic(
                    item.line,
                    format!("model query {query_name} has no attribute owner"),
                );
                return Ok(());
            }
            let matcher = FieldMatcher {
                owner: None,
                owner_regex,
                field: "*".to_string(),
            };
            for kind in attribute_source_kinds {
                let id = self.id("field-query-source", &format!("{query_name}.{kind}"));
                self.compilation.rules.field_sources.push(FieldSourceRule {
                    id,
                    language: Some(Language::Python),
                    matcher: matcher.clone(),
                    kind,
                });
            }
            for kind in attribute_sink_kinds {
                let id = self.id("field-query-sink", &format!("{query_name}.{kind}"));
                self.compilation.rules.field_sinks.push(FieldSinkRule {
                    id: id.clone(),
                    language: Some(Language::Python),
                    matcher: matcher.clone(),
                    kind: kind.clone(),
                });
                self.push_metadata(id, format!("Python field query {query_name}"), kind);
            }
            return Ok(());
        }

        let definition_query = !decorators.is_empty()
            || !owners.is_empty()
            || (parameters && !parameter_source_kinds.is_empty())
            || (returns && !return_sink_kinds.is_empty());
        if definition_query {
            let matcher = FunctionMatcher {
                regex: patterns_regex(&name_patterns),
                owner_regex: exact_values_regex(&owners),
                decorator_regex: patterns_regex(&decorators),
                ..FunctionMatcher::default()
            };
            if matcher.validate().is_err() {
                self.diagnostic(
                    item.line,
                    format!("model query {query_name} has no executable matcher"),
                );
                return Ok(());
            }
            if parameters {
                for kind in &parameter_source_kinds {
                    let id = self.id("function-source", &format!("{query_name}.{kind}"));
                    self.compilation
                        .rules
                        .function_sources
                        .push(FunctionSourceRule {
                            id,
                            language: Some(Language::Python),
                            matcher: matcher.clone(),
                            out: Port::ArgsFrom(0),
                            kind: kind.clone(),
                        });
                }
                for kind in &parameter_sink_kinds {
                    let id = self.id("function-sink", &format!("{query_name}.param.{kind}"));
                    self.compilation
                        .rules
                        .function_sinks
                        .push(FunctionSinkRule {
                            id: id.clone(),
                            language: Some(Language::Python),
                            matcher: matcher.clone(),
                            inputs: vec![Port::ArgsFrom(0)],
                            kind: kind.clone(),
                        });
                    self.push_metadata(
                        id,
                        format!("Python model query {query_name}"),
                        kind.clone(),
                    );
                }
            }
            if returns {
                for kind in &return_source_kinds {
                    let id = self.id("function-source", &format!("{query_name}.return.{kind}"));
                    self.compilation
                        .rules
                        .function_sources
                        .push(FunctionSourceRule {
                            id,
                            language: Some(Language::Python),
                            matcher: matcher.clone(),
                            out: Port::Return,
                            kind: kind.clone(),
                        });
                }
                for kind in &return_sink_kinds {
                    let id = self.id("function-sink", &format!("{query_name}.return.{kind}"));
                    self.compilation
                        .rules
                        .function_sinks
                        .push(FunctionSinkRule {
                            id: id.clone(),
                            language: Some(Language::Python),
                            matcher: matcher.clone(),
                            inputs: vec![Port::Return],
                            kind: kind.clone(),
                        });
                    self.push_metadata(
                        id,
                        format!("Python model query {query_name}"),
                        kind.clone(),
                    );
                }
            }
            return Ok(());
        }

        let Some(regex) = patterns_regex(&name_patterns) else {
            self.diagnostic(
                item.line,
                format!("model query {query_name} has no name matcher"),
            );
            return Ok(());
        };
        Regex::new(&regex)
            .with_context(|| format!("invalid Pysa model query regex {query_name}"))?;
        let matcher = ApiMatcher {
            regex: Some(regex),
            ..ApiMatcher::default()
        };
        if returns {
            for kind in return_source_kinds {
                let id = self.id("query-source", &format!("{query_name}.{kind}"));
                self.compilation.rules.sources.push(SourceRule {
                    id,
                    language: Some(Language::Python),
                    matcher: matcher.clone(),
                    out: Port::Return,
                    kind,
                });
            }
            for kind in return_sink_kinds {
                self.push_call_sink(&query_name, matcher.clone(), vec![Port::Return], kind);
            }
        } else if parameters {
            for kind in parameter_sink_kinds {
                self.push_call_sink(&query_name, matcher.clone(), vec![Port::ArgsFrom(0)], kind);
            }
        }
        Ok(())
    }

    fn push_call_sink(&mut self, name: &str, matcher: ApiMatcher, inputs: Vec<Port>, kind: String) {
        let id = self.id("sink", &format!("{name}.{kind}"));
        self.compilation.rules.sinks.push(SinkRule {
            id: id.clone(),
            language: Some(Language::Python),
            matcher,
            inputs,
            kind: kind.clone(),
        });
        self.push_metadata(id, format!("Python sink {name}"), kind);
    }

    fn push_metadata(&mut self, id: String, title: String, kind: String) {
        self.compilation.rules.metadata.push(RuleMetadata {
            id,
            title: title.clone(),
            message: format!("Data reaches Python taint sink category {kind} at {title}."),
            severity: "warning".to_string(),
            cwe: Vec::new(),
            standards: Vec::new(),
            translations: Default::default(),
        });
    }
}

#[derive(Clone, Debug)]
struct ParsedParameter {
    name: String,
    port: Port,
    annotation: Option<String>,
}

fn parse_definition(text: &str) -> Option<(String, String, Option<String>)> {
    let trimmed = text.trim();
    let rest = trimmed
        .strip_prefix("async def ")
        .or_else(|| trimmed.strip_prefix("def "))?;
    let open = rest.find('(')?;
    let name = rest[..open].trim().to_string();
    let close = matching_delimiter(rest, open, '(', ')')?;
    let params = rest[open + 1..close].to_string();
    let suffix = rest[close + 1..].trim();
    let return_annotation = suffix
        .strip_prefix("->")
        .and_then(|value| split_top_level_once(value, ':').map(|(left, _)| left.trim().to_string()))
        .filter(|value| !value.is_empty());
    Some((name, params, return_annotation))
}

fn parse_parameters(text: &str) -> Vec<ParsedParameter> {
    let mut parameters = Vec::new();
    let mut index = 0usize;
    for raw in split_top_level(text, ',') {
        let raw = raw.trim();
        if raw.is_empty() || raw == "*" || raw == "/" {
            continue;
        }
        let without_default = split_top_level_once(raw, '=')
            .map(|(left, _)| left)
            .unwrap_or(raw)
            .trim();
        let (name, annotation) = split_top_level_once(without_default, ':')
            .map(|(name, annotation)| (name.trim(), Some(annotation.trim().to_string())))
            .unwrap_or((without_default, None));
        let clean_name = name.trim_start_matches('*').trim().to_string();
        let port = if clean_name == "self" || clean_name == "cls" {
            Port::Receiver
        } else if name.starts_with('*') {
            let port = Port::ArgsFrom(index);
            index += 1;
            port
        } else {
            let port = Port::Arg(index);
            index += 1;
            port
        };
        parameters.push(ParsedParameter {
            name: clean_name,
            port,
            annotation,
        });
    }
    parameters
}

fn tito_targets(annotation: &str, params: &[ParsedParameter]) -> Vec<Port> {
    let mut targets = Vec::new();
    for update in generic_contents(annotation, "Updates") {
        let name = update.trim();
        if name == "self" || name == "cls" {
            targets.push(Port::Receiver);
        } else if let Some(parameter) = params.iter().find(|parameter| parameter.name == name) {
            targets.push(parameter.port.clone());
        }
    }
    if annotation.contains("LocalReturn") || targets.is_empty() {
        targets.push(Port::Return);
    }
    targets.sort_by_key(|port| format!("{port:?}"));
    targets.dedup();
    targets
}

fn taint_kinds(text: &str, generic: &str) -> Vec<String> {
    let mut kinds = Vec::new();
    for content in generic_contents(text, generic) {
        for part in split_top_level(&content, ',') {
            let kind = part.trim();
            if kind.is_empty()
                || kind.starts_with("Via[")
                || kind.starts_with("ViaValueOf[")
                || kind.starts_with("WithTag[")
            {
                continue;
            }
            kinds.push(kind.to_string());
        }
    }
    kinds.sort();
    kinds.dedup();
    kinds
}

fn generic_contents(text: &str, generic: &str) -> Vec<String> {
    let needle = format!("{generic}[");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(offset) = text[cursor..].find(&needle) {
        let open = cursor + offset + generic.len();
        let Some(close) = matching_delimiter(text, open, '[', ']') else {
            break;
        };
        out.push(text[open + 1..close].to_string());
        cursor = close + 1;
    }
    out
}

fn call_contents(text: &str, function: &str) -> Vec<String> {
    let needle = format!("{function}(");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(offset) = text[cursor..].find(&needle) {
        let open = cursor + offset + function.len();
        let Some(close) = matching_delimiter(text, open, '(', ')') else {
            break;
        };
        out.push(text[open + 1..close].to_string());
        cursor = close + 1;
    }
    out
}

fn matching_delimiter(text: &str, open: usize, left: char, right: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (offset, ch) in text[open..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
            continue;
        }
        if quote.is_some() {
            continue;
        }
        if ch == left {
            depth += 1;
        } else if ch == right {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if matches!(ch, '\'' | '"') {
            if quote == Some(ch) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(ch);
            }
            continue;
        }
        if quote.is_some() {
            continue;
        }
        match ch {
            '(' | '[' | '{' => stack.push(ch),
            ')' | ']' | '}' => {
                stack.pop();
            }
            _ if ch == separator && stack.is_empty() => {
                out.push(&text[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&text[start..]);
    out
}

fn split_top_level_once(text: &str, separator: char) -> Option<(&str, &str)> {
    let parts = split_top_level(text, separator);
    (parts.len() > 1).then(|| {
        let left = parts[0];
        let offset = left.len();
        (left, &text[offset + separator.len_utf8()..])
    })
}

fn scan_items(text: &str) -> Vec<PysaItem> {
    let lines = text.lines().collect::<Vec<_>>();
    let mut items = Vec::new();
    let mut decorators = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }
        if trimmed.starts_with('@') {
            decorators.push(trimmed.to_string());
            index += 1;
            continue;
        }
        if trimmed.starts_with("def ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("ModelQuery(")
        {
            let start = index;
            let mut statement = String::new();
            let mut balance = 0isize;
            let mut saw_open = false;
            loop {
                let line = lines[index];
                if !statement.is_empty() {
                    statement.push('\n');
                }
                statement.push_str(line);
                for ch in line.chars() {
                    match ch {
                        '(' | '[' | '{' => {
                            balance += 1;
                            saw_open = true;
                        }
                        ')' | ']' | '}' => balance -= 1,
                        _ => {}
                    }
                }
                index += 1;
                if index >= lines.len()
                    || (saw_open
                        && balance <= 0
                        && (trimmed.starts_with("ModelQuery(") || statement.contains(':')))
                {
                    break;
                }
            }
            items.push(PysaItem {
                line: start + 1,
                decorators: std::mem::take(&mut decorators),
                text: statement,
            });
            continue;
        }
        items.push(PysaItem {
            line: index + 1,
            decorators: std::mem::take(&mut decorators),
            text: lines[index].to_string(),
        });
        index += 1;
    }
    items
}

fn quoted_assignment(text: &str, key: &str) -> Option<String> {
    let expression = Regex::new(&format!(
        r#"(?m)\b{}\s*=\s*[\"']([^\"']+)[\"']"#,
        regex::escape(key)
    ))
    .ok()?;
    expression
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().to_string())
}

fn quoted_call_arguments(text: &str, prefixes: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for prefix in prefixes {
        let mut cursor = 0usize;
        while let Some(offset) = text[cursor..].find(prefix) {
            let rest = &text[cursor + offset + prefix.len()..];
            let Some(quote_offset) = rest.find(['"', '\'']) else {
                break;
            };
            let quote = rest.as_bytes()[quote_offset] as char;
            let quoted = &rest[quote_offset + 1..];
            let mut value = String::new();
            let mut escaped = false;
            let mut consumed = 0usize;
            for ch in quoted.chars() {
                consumed += ch.len_utf8();
                if escaped {
                    value.push('\\');
                    value.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == quote {
                    break;
                } else {
                    value.push(ch);
                }
            }
            values.push(value);
            cursor += offset + prefix.len() + quote_offset + 1 + consumed;
        }
    }
    values.sort();
    values.dedup();
    values
}

fn patterns_regex(patterns: &[String]) -> Option<String> {
    if patterns.is_empty() {
        None
    } else if patterns.len() == 1 {
        Some(patterns[0].clone())
    } else {
        Some(format!("(?:{})", patterns.join(")|(?:")))
    }
}

fn exact_values_regex(values: &[String]) -> Option<String> {
    if values.is_empty() {
        None
    } else {
        Some(format!(
            "^(?:{})$",
            values
                .iter()
                .map(|value| regex::escape(value))
                .collect::<Vec<_>>()
                .join("|")
        ))
    }
}

fn normalized_id(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    normalized.trim_matches('-').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_function_field_query_and_sanitizer_models() {
        let source = r#"
werkzeug.wrappers.BaseRequest.path: TaintSource[UserControlled, URL] = ...
falcon.response.Response.body: TaintSink[ReturnedToUser, XSS] = ...

@Sanitize(TaintInTaintOut[TaintSource[ServerSecrets]])
def aiohttp.client.ClientSession.get(
    self,
    url: TaintSink[RequestSend_URI],
) -> TaintSource[DataFromInternet]: ...

def werkzeug.utils.secure_filename(
    filename: Sanitize[TaintInTaintOut[TaintSink[FileSystem_ReadWrite]]]
): ...

ModelQuery(
  name = "get_route_sources_sinks",
  find = "functions",
  where = [Decorator(fully_qualified_name.matches("app.route"))],
  model = [
    Parameters(TaintSource[UserControlled, UserControlled_Parameter]),
    Returns(TaintSink[ReturnedToUser])
  ]
)
"#;
        let compilation = compile_legacy_pysa_str(source, "legacy.python").expect("compile");
        assert!(compilation.diagnostics.is_empty());
        assert_eq!(compilation.rules.field_sources.len(), 2);
        assert_eq!(compilation.rules.field_sinks.len(), 2);
        assert!(compilation.rules.sources.iter().any(|rule| {
            rule.matcher.exact.as_deref() == Some("aiohttp.client.ClientSession.get")
                && rule.out == Port::Return
                && rule.kind == "DataFromInternet"
        }));
        assert!(compilation.rules.sinks.iter().any(|rule| {
            rule.matcher.exact.as_deref() == Some("aiohttp.client.ClientSession.get")
                && rule.inputs == vec![Port::Arg(0)]
                && rule.kind == "RequestSend_URI"
        }));
        assert!(compilation
            .rules
            .sanitizers
            .iter()
            .any(|rule| { rule.kind == "ServerSecrets" && rule.outputs == vec![Port::Return] }));
        assert_eq!(compilation.rules.function_sources.len(), 2);
        assert_eq!(compilation.rules.function_sinks.len(), 1);
    }

    #[test]
    fn compiles_tito_updates_and_attribute_sanitize() {
        let source = r#"
django.http.request.HttpRequest.GET: Sanitize = ...
def furl.furl.set(
    self: TaintInTaintOut[LocalReturn],
    url: TaintInTaintOut[LocalReturn, Updates[self], Via[furl_url]]
): ...
"#;
        let compilation = compile_legacy_pysa_str(source, "legacy.python").expect("compile");
        assert_eq!(compilation.rules.field_sanitizers.len(), 1);
        let flows = &compilation.rules.propagators[0].flows;
        assert!(flows.contains(&FlowSpec {
            from: Port::Arg(0),
            to: Port::Return,
        }));
        assert!(flows.contains(&FlowSpec {
            from: Port::Arg(0),
            to: Port::Receiver,
        }));
    }
}
