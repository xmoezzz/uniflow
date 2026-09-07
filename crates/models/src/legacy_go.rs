use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use uniflow_hir::Language;
use uniflow_rules::{
    ApiMatcher, CallConditionRule, Port, RuleMetadata, RuleSet, SinkConditionRule, SinkRule,
    SourceRule, TaintCondition,
};

#[derive(Clone, Debug, Deserialize)]
pub struct LegacyGoPack {
    #[serde(default, rename = "Sinks")]
    sinks: Vec<LegacyGoSink>,
    #[serde(default, rename = "Sources")]
    sources: Vec<LegacyGoSource>,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyGoSink {
    #[serde(rename = "CategoryId")]
    category_id: Value,
    #[serde(rename = "DefaultGrade")]
    default_grade: Value,
    #[serde(rename = "MethodDefinition")]
    method: Mapping,
    #[serde(default, rename = "SinkPoint")]
    points: Vec<LegacyGoSinkPoint>,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyGoSinkPoint {
    #[serde(rename = "Check")]
    check: Value,
    #[serde(default, rename = "Ins")]
    inputs: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct LegacyGoSource {
    #[serde(rename = "MethodDefinition")]
    method: Mapping,
    #[serde(default, rename = "Outs")]
    outputs: Vec<Value>,
    #[serde(default, rename = "Signs")]
    signs: LegacyGoSigns,
    #[serde(default, rename = "Check")]
    check: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyGoSigns {
    #[serde(default, rename = "Plus")]
    plus: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyGoDiagnostic {
    pub section: String,
    pub index: usize,
    pub feature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyGoCompilation {
    pub rules: RuleSet,
    pub diagnostics: Vec<LegacyGoDiagnostic>,
}

impl LegacyGoPack {
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        serde_yaml::from_str(text).context("invalid legacy Go dataflow YAML")
    }
}

pub fn compile_legacy_go_pack(pack: &LegacyGoPack, namespace: &str) -> Result<LegacyGoCompilation> {
    let mut out = LegacyGoCompilation::default();
    for (index, source) in pack.sources.iter().enumerate() {
        let matcher = compile_method_matcher(&source.method)
            .with_context(|| format!("invalid Go source method {index}"))?;
        let ports = source
            .outputs
            .iter()
            .map(compile_port)
            .collect::<Result<Vec<_>>>()?;
        let kinds = if source.signs.plus.is_empty() {
            vec!["generic".to_string()]
        } else {
            source.signs.plus.clone()
        };
        for (port_index, port) in ports.iter().enumerate() {
            for kind in &kinds {
                let id = format!(
                    "{namespace}.source.{index}.{port_index}.{}",
                    normalized_id(kind)
                );
                out.rules.sources.push(SourceRule {
                    id: id.clone(),
                    language: Some(Language::Go),
                    matcher: matcher.clone(),
                    out: port.clone(),
                    kind: kind.clone(),
                });
                if let Some(check) = &source.check {
                    match compile_source_check(check) {
                        Ok(condition) => out.rules.call_conditions.push(CallConditionRule {
                            rule_id: id,
                            condition,
                        }),
                        Err(error) => out.diagnostics.push(LegacyGoDiagnostic {
                            section: "source".to_string(),
                            index,
                            feature: error.to_string(),
                        }),
                    }
                }
            }
        }
    }
    for (index, sink) in pack.sinks.iter().enumerate() {
        let matcher = compile_method_matcher(&sink.method)
            .with_context(|| format!("invalid Go sink method {index}"))?;
        let category = scalar_text(&sink.category_id).unwrap_or_else(|| "unknown".to_string());
        for (point_index, point) in sink.points.iter().enumerate() {
            let condition = compile_sign_condition(&point.check)
                .with_context(|| format!("invalid Go sink condition {index}.{point_index}"))?;
            for (port_index, input) in point.inputs.iter().enumerate() {
                let port = compile_port(input)?;
                let id = format!("{namespace}.sink.{index}.{point_index}.{port_index}");
                out.rules.sinks.push(SinkRule {
                    id: id.clone(),
                    language: Some(Language::Go),
                    matcher: matcher.clone(),
                    inputs: vec![port],
                    kind: "generic".to_string(),
                });
                out.rules.sink_conditions.push(SinkConditionRule {
                    sink_rule_id: id.clone(),
                    condition: condition.clone(),
                });
                out.rules.metadata.push(RuleMetadata {
                    id,
                    title: format!("Go security rule {category}"),
                    message: format!("Data reaches Go security sink category {category}."),
                    severity: grade_severity(&sink.default_grade).to_string(),
                    cwe: Vec::new(),
                    standards: Vec::new(),
                    translations: Default::default(),
                });
            }
        }
    }
    out.rules.validate()?;
    Ok(out)
}

fn compile_method_matcher(method: &Mapping) -> Result<ApiMatcher> {
    let method_value = mapping_get(method, "MethodName").context("missing MethodName")?;
    let (method_text, method_pattern) = name_component(method_value)?;
    let namespace = mapping_get(method, "NamespaceName")
        .filter(|value| !value.is_null())
        .map(name_component)
        .transpose()?;
    let class = mapping_get(method, "ClassName")
        .filter(|value| !value.is_null())
        .map(name_component)
        .transpose()?;
    let method_expression = if method_pattern {
        format!("(?:{method_text})")
    } else {
        regex::escape(&method_text)
    };
    let mut prefixes = Vec::new();
    if let Some((namespace, pattern)) = namespace {
        prefixes.push(if pattern {
            format!("(?:{namespace})")
        } else {
            regex::escape(&namespace)
        });
    }
    if let Some((class, pattern)) = class {
        prefixes.push(if pattern {
            format!("(?:{class})")
        } else {
            regex::escape(&class)
        });
    }
    let callee = if prefixes.is_empty() {
        format!(r"(?:^|[./]|::){method_expression}$")
    } else {
        format!(
            r"(?:^|[./]|::){}(?:[./]|::){method_expression}$",
            prefixes.join(r"(?:[./]|::)")
        )
    };
    Ok(ApiMatcher {
        regex: Some(callee),
        method_name: (!method_pattern).then_some(method_text),
        method_regex: method_pattern.then_some(format!("^(?:{method_expression})$")),
        ..ApiMatcher::default()
    })
}

fn name_component(value: &Value) -> Result<(String, bool)> {
    if let Some(text) = scalar_text(value) {
        return Ok((text, false));
    }
    let map = value
        .as_mapping()
        .context("name component must be scalar or mapping")?;
    let kind = mapping_get(map, "kind")
        .and_then(scalar_text)
        .context("pattern component missing kind")?;
    let pattern = mapping_get(map, "type")
        .and_then(scalar_text)
        .is_some_and(|kind| kind == "pattern");
    Ok((kind, pattern))
}

fn compile_port(value: &Value) -> Result<Port> {
    if let Some(index) = value.as_i64() {
        return usize::try_from(index)
            .map(Port::Arg)
            .context("negative Go rule port");
    }
    let text = value
        .as_str()
        .context("Go rule port must be integer or string")?;
    match text {
        "this" => Ok(Port::Receiver),
        "return" => Ok(Port::Return),
        _ if text.ends_with("...") => Ok(Port::ArgsFrom(
            text.trim_end_matches("...").parse::<usize>()?,
        )),
        _ => Ok(Port::Arg(text.parse::<usize>()?)),
    }
}

fn compile_source_check(value: &Value) -> Result<TaintCondition> {
    let map = value
        .as_mapping()
        .context("source check must be a mapping")?;
    let type_check = mapping_get(map, "TypeCheck").context("unsupported source check")?;
    let check = type_check
        .as_mapping()
        .context("TypeCheck must be a mapping")?;
    let argument = mapping_get(check, "argument").context("TypeCheck missing argument")?;
    let port = compile_port(argument)?;
    let namespace = mapping_get(check, "NamespaceName")
        .and_then(scalar_text)
        .unwrap_or_default();
    let class = mapping_get(check, "ClassName")
        .and_then(scalar_text)
        .context("TypeCheck missing ClassName")?;
    let full = if namespace.is_empty() {
        class
    } else {
        format!("{namespace}.{class}")
    };
    Ok(TaintCondition::IsType {
        port,
        exact: None,
        regex: Some(format!(
            r"^(?:{}|{})$",
            regex::escape(&full),
            regex::escape(&full.replace('.', "/"))
        )),
    })
}

fn compile_sign_condition(value: &Value) -> Result<TaintCondition> {
    let map = value.as_mapping().context("condition must be a mapping")?;
    if let Some(sign) = mapping_get(map, "SignCheck") {
        return compile_sign_check(sign);
    }
    for (name, constructor) in [("And", 0u8), ("Or", 1u8), ("Not", 2u8)] {
        let Some(child) = mapping_get(map, name) else {
            continue;
        };
        let children = condition_children(child)?;
        return match constructor {
            0 => Ok(TaintCondition::All(children)),
            1 => Ok(TaintCondition::Any(children)),
            2 if children.len() == 1 => Ok(TaintCondition::Not(Box::new(
                children.into_iter().next().expect("one child"),
            ))),
            2 => Ok(TaintCondition::Not(Box::new(TaintCondition::Any(children)))),
            _ => unreachable!(),
        };
    }
    bail!("unsupported condition operator")
}

fn condition_children(value: &Value) -> Result<Vec<TaintCondition>> {
    if let Some(sequence) = value.as_sequence() {
        return sequence.iter().map(compile_sign_condition).collect();
    }
    if let Some(map) = value.as_mapping() {
        let mut children = Vec::new();
        for (key, child) in map {
            let key = key.as_str().context("condition operator must be string")?;
            let mut wrapper = Mapping::new();
            wrapper.insert(Value::String(key.to_string()), child.clone());
            children.push(compile_sign_condition(&Value::Mapping(wrapper))?);
        }
        return Ok(children);
    }
    compile_sign_check(value).map(|condition| vec![condition])
}

fn compile_sign_check(value: &Value) -> Result<TaintCondition> {
    if let Some(sign) = scalar_text(value) {
        return Ok(TaintCondition::HasKind(sign));
    }
    let signs = value
        .as_sequence()
        .context("SignCheck must be scalar or list")?;
    Ok(TaintCondition::Any(
        signs
            .iter()
            .map(|sign| {
                scalar_text(sign)
                    .map(TaintCondition::HasKind)
                    .context("SignCheck list item must be scalar")
            })
            .collect::<Result<Vec<_>>>()?,
    ))
}

fn mapping_get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn grade_severity(value: &Value) -> &'static str {
    let grade = value.as_f64().unwrap_or(3.0);
    if grade >= 4.0 {
        "error"
    } else if grade >= 2.0 {
        "warning"
    } else {
        "note"
    }
}

fn normalized_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_go_method_patterns_ports_conditions_and_type_checks() {
        let text = r#"
Sinks:
- CategoryId: 15000010060001
  DefaultGrade: 4.0
  MethodDefinition:
    ClassName: DB
    MethodName:
      kind: Exec|Query
      type: pattern
    NamespaceName: database/sql
  SinkPoint:
  - Check:
      And:
        SignCheck: database
        Not:
          SignCheck: safeSqlInjection
    Ins: [0, "1..."]
Sources:
- MethodDefinition:
    MethodName: Getenv
    NamespaceName: os
  Outs: [return]
  Signs:
    Plus: [environment]
- MethodDefinition:
    MethodName: Read
    NamespaceName: io
  Outs: [1]
  Signs:
    Plus: [network]
  Check:
    TypeCheck:
      NamespaceName: net
      ClassName: Conn
      argument: 0
"#;
        let pack = LegacyGoPack::from_yaml_str(text).expect("parse");
        let compiled = compile_legacy_go_pack(&pack, "legacy.go").expect("compile");
        assert!(compiled.diagnostics.is_empty());
        assert_eq!(compiled.rules.sources.len(), 2);
        assert_eq!(compiled.rules.sinks.len(), 2);
        assert_eq!(compiled.rules.sink_conditions.len(), 2);
        assert_eq!(compiled.rules.call_conditions.len(), 1);
        assert_eq!(compiled.rules.sinks[1].inputs, vec![Port::ArgsFrom(1)]);
        assert!(compiled.rules.sources[0].matcher.matches("os.Getenv"));
        assert!(compiled.rules.sinks[0]
            .matcher
            .matches("database/sql.DB.Exec"));
    }
}
