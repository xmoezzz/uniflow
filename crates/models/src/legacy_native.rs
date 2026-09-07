use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use uniflow_hir::Language;
use uniflow_rules::{
    ApiMatcher, FlowSpec, LocalizedRuleText, Port, PropagatorRule, RuleMetadata, RuleSet,
    RuleTranslations, SanitizerRule, SinkConditionRule, SinkRule, SourceRule, TaintCondition,
    TaintTransformRule,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegacyNativeDataflowPack {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub passthroughs: Vec<LegacyNativeTransfer>,
    #[serde(default)]
    pub sources: Vec<LegacyNativeTransfer>,
    #[serde(default)]
    pub sinks: Vec<LegacyNativeSink>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegacyNativeTransfer {
    #[serde(default)]
    pub ids: Vec<String>,
    #[serde(default)]
    pub ins: Vec<Value>,
    #[serde(default)]
    pub outs: Vec<Value>,
    #[serde(default)]
    pub signs: LegacyNativeSigns,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegacyNativeSigns {
    #[serde(default)]
    pub plus: Vec<String>,
    #[serde(default)]
    pub minus: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegacyNativeSink {
    #[serde(default)]
    pub ids: Vec<String>,
    pub key: String,
    #[serde(default)]
    pub format: String,
    #[serde(default, rename = "Format_zh_CN")]
    pub format_zh_cn: String,
    pub sink_point: LegacyNativeSinkPoint,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LegacyNativeSinkPoint {
    pub check: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyNativeCompileDiagnostic {
    pub rule_key: String,
    pub feature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyNativeCompilation {
    pub rules: RuleSet,
    pub diagnostics: Vec<LegacyNativeCompileDiagnostic>,
}

impl LegacyNativeDataflowPack {
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        serde_yaml::from_str(text).context("invalid legacy C-family dataflow YAML")
    }
}

pub fn compile_legacy_native_dataflow_pack(
    pack: &LegacyNativeDataflowPack,
    language: Language,
    namespace: &str,
) -> Result<LegacyNativeCompilation> {
    let mut compilation = LegacyNativeCompilation::default();
    for (index, legacy) in pack.sources.iter().enumerate() {
        compile_sources(&mut compilation, legacy, &language, namespace, index)?;
    }
    for (index, legacy) in pack.passthroughs.iter().enumerate() {
        compile_passthroughs(&mut compilation, legacy, &language, namespace, index)?;
    }
    for (index, legacy) in pack.sinks.iter().enumerate() {
        compile_sinks(&mut compilation, legacy, &language, namespace, index)?;
    }
    compilation.rules.validate()?;
    Ok(compilation)
}

fn compile_sources(
    compilation: &mut LegacyNativeCompilation,
    legacy: &LegacyNativeTransfer,
    language: &Language,
    namespace: &str,
    group: usize,
) -> Result<()> {
    let outputs = compile_ports(&legacy.outs)?;
    let kinds = if legacy.signs.plus.is_empty() {
        vec!["generic".to_string()]
    } else {
        legacy.signs.plus.clone()
    };
    for (api_index, api) in legacy.ids.iter().enumerate() {
        for (output_index, output) in outputs.iter().enumerate() {
            for kind in &kinds {
                compilation.rules.sources.push(SourceRule {
                    id: format!(
                        "{namespace}.source.{group}.{api_index}.{output_index}.{}",
                        normalized_id(kind)
                    ),
                    language: Some(language.clone()),
                    matcher: exact_matcher(api),
                    out: output.clone(),
                    kind: kind.clone(),
                });
            }
        }
    }
    Ok(())
}

fn compile_passthroughs(
    compilation: &mut LegacyNativeCompilation,
    legacy: &LegacyNativeTransfer,
    language: &Language,
    namespace: &str,
    group: usize,
) -> Result<()> {
    let inputs = compile_ports(&legacy.ins)?;
    let outputs = compile_ports(&legacy.outs)?;
    let flows = inputs
        .iter()
        .flat_map(|input| {
            outputs.iter().map(move |output| FlowSpec {
                from: input.clone(),
                to: output.clone(),
            })
        })
        .collect::<Vec<_>>();
    for (api_index, api) in legacy.ids.iter().enumerate() {
        let base = format!("{namespace}.passthrough.{group}.{api_index}");
        if !flows.is_empty() {
            compilation.rules.propagators.push(PropagatorRule {
                id: base.clone(),
                language: Some(language.clone()),
                matcher: exact_matcher(api),
                flows: flows.clone(),
            });
        }
        if !legacy.signs.plus.is_empty() {
            compilation.rules.taint_transforms.push(TaintTransformRule {
                id: format!("{base}.transform"),
                language: Some(language.clone()),
                matcher: exact_matcher(api),
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                add_kinds: legacy.signs.plus.clone(),
                remove_kinds: legacy.signs.minus.clone(),
            });
        } else {
            for kind in &legacy.signs.minus {
                compilation.rules.sanitizers.push(SanitizerRule {
                    id: format!("{base}.remove.{}", normalized_id(kind)),
                    language: Some(language.clone()),
                    matcher: exact_matcher(api),
                    inputs: inputs.clone(),
                    outputs: outputs.clone(),
                    kind: kind.clone(),
                });
            }
        }
    }
    Ok(())
}

fn compile_sinks(
    compilation: &mut LegacyNativeCompilation,
    legacy: &LegacyNativeSink,
    language: &Language,
    namespace: &str,
    group: usize,
) -> Result<()> {
    let branches = compile_sink_check(&legacy.sink_point.check)
        .with_context(|| format!("invalid legacy sink condition '{}'", legacy.key))?;
    for (api_index, api) in legacy.ids.iter().enumerate() {
        for (branch_index, (input, condition)) in branches.iter().enumerate() {
            let id = format!("{namespace}.sink.{group}.{api_index}.{branch_index}");
            compilation.rules.sinks.push(SinkRule {
                id: id.clone(),
                language: Some(language.clone()),
                matcher: exact_matcher(api),
                inputs: vec![input.clone()],
                kind: "generic".to_string(),
            });
            compilation.rules.sink_conditions.push(SinkConditionRule {
                sink_rule_id: id.clone(),
                condition: condition.clone(),
            });
            compilation.rules.metadata.push(RuleMetadata {
                id,
                title: legacy.key.clone(),
                message: legacy.format.clone(),
                severity: "warning".to_string(),
                cwe: Vec::new(),
                standards: Vec::new(),
                translations: RuleTranslations {
                    zh_cn: (!legacy.format_zh_cn.is_empty()).then(|| LocalizedRuleText {
                        title: legacy.key.clone(),
                        message: legacy.format_zh_cn.clone(),
                    }),
                    en: (!legacy.format.is_empty()).then(|| LocalizedRuleText {
                        title: legacy.key.clone(),
                        message: legacy.format.clone(),
                    }),
                    zh_tw: None,
                },
            });
        }
    }
    Ok(())
}

fn compile_sink_check(value: &Value) -> Result<Vec<(Port, TaintCondition)>> {
    let map = value
        .as_mapping()
        .context("legacy native sink check must be a mapping")?;
    if let Some(sign_check) = get(map, "SignCheck") {
        return compile_sign_checks(sign_check);
    }
    if let Some(or) = get(map, "Or") {
        let mut alternatives = Vec::new();
        for child in child_expressions(or)? {
            alternatives.extend(compile_sink_check(child)?);
        }
        return Ok(alternatives);
    }
    if let Some(and) = get(map, "And") {
        let children = child_expressions(and)?;
        let mut combined = Vec::<(Port, TaintCondition)>::new();
        for child in children {
            let branches = compile_sink_check(child)?;
            if combined.is_empty() {
                combined = branches;
                continue;
            }
            let mut next = Vec::new();
            for (left_port, left) in &combined {
                for (right_port, right) in &branches {
                    if left_port != right_port {
                        bail!("cross-port And condition is not representable");
                    }
                    next.push((
                        left_port.clone(),
                        TaintCondition::All(vec![left.clone(), right.clone()]),
                    ));
                }
            }
            combined = next;
        }
        return Ok(combined);
    }
    if let Some(not) = get(map, "Not") {
        return compile_sink_check(not).map(|branches| {
            branches
                .into_iter()
                .map(|(port, condition)| (port, TaintCondition::Not(Box::new(condition))))
                .collect()
        });
    }
    bail!("unsupported legacy native sink check keys")
}

fn compile_sign_checks(value: &Value) -> Result<Vec<(Port, TaintCondition)>> {
    let checks = match value {
        Value::Sequence(values) => values.iter().collect::<Vec<_>>(),
        Value::Mapping(_) => vec![value],
        _ => bail!("SignCheck must be a mapping or sequence"),
    };
    checks
        .into_iter()
        .map(|check| {
            let map = check
                .as_mapping()
                .context("SignCheck entry must be a mapping")?;
            let argument =
                scalar_text(get(map, "argument").context("SignCheck is missing argument")?)?;
            let kind = scalar_text(get(map, "kind").context("SignCheck is missing kind")?)?;
            Ok((compile_port(&argument)?, TaintCondition::HasKind(kind)))
        })
        .collect()
}

fn child_expressions(value: &Value) -> Result<Vec<&Value>> {
    match value {
        Value::Sequence(values) => Ok(values.iter().collect()),
        Value::Mapping(_) => Ok(vec![value]),
        _ => bail!("logical condition children must be a mapping or sequence"),
    }
}

fn compile_ports(values: &[Value]) -> Result<Vec<Port>> {
    values
        .iter()
        .map(|value| scalar_text(value).and_then(|value| compile_port(&value)))
        .collect()
}

fn compile_port(value: &str) -> Result<Port> {
    let value = value.trim();
    match value {
        "-2" => Ok(Port::Receiver),
        "-1" => Ok(Port::Return),
        _ if value.ends_with("...") => {
            let start = value.trim_end_matches("...").parse::<usize>()?;
            Ok(Port::ArgsFrom(start))
        }
        _ if value.contains('-') => {
            let (start, end) = value
                .split_once('-')
                .context("invalid legacy native argument range")?;
            let start = start.parse::<usize>()?;
            let end = end.parse::<usize>()?;
            anyhow::ensure!(start <= end, "descending legacy native argument range");
            Ok(Port::ArgsRange { start, end })
        }
        _ => Ok(Port::Arg(value.parse::<usize>()?)),
    }
}

fn scalar_text(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        _ => bail!("legacy native scalar must be a string or number"),
    }
}

fn exact_matcher(api: &str) -> ApiMatcher {
    ApiMatcher {
        exact: Some(api.to_string()),
        ..Default::default()
    }
}

fn get<'a>(map: &'a Mapping, key: &str) -> Option<&'a Value> {
    map.get(Value::String(key.to_string()))
}

fn normalized_id(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    normalized.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_c_family_ports_sign_changes_and_localized_sinks() {
        let pack = LegacyNativeDataflowPack::from_yaml_str(
            r#"
Name: fixture
Passthroughs:
- Ids: [encode]
  Ins: ['0...']
  Outs: ['-1']
  Signs: { Plus: [safe], Minus: [taint] }
Sources:
- Ids: [read]
  Outs: ['1', '-1']
  Signs: { Plus: [taint] }
Sinks:
- Ids: [execute]
  Key: Security.CommandInjection
  Format: tainted command
  Format_zh_CN: 污染命令
  SinkPoint:
    Check:
      Or:
      - SignCheck: { argument: '0', kind: taint }
      - SignCheck: { argument: '-2', kind: taint }
Version: '1'
"#,
        )
        .expect("parse native dataflow fixture");
        let compiled = compile_legacy_native_dataflow_pack(&pack, Language::Cpp, "legacy.cpp")
            .expect("compile native dataflow fixture");
        assert_eq!(compiled.rules.sources.len(), 2);
        assert_eq!(compiled.rules.propagators.len(), 1);
        assert_eq!(compiled.rules.taint_transforms.len(), 1);
        assert_eq!(compiled.rules.sinks.len(), 2);
        assert!(matches!(
            compiled.rules.propagators[0].flows[0].from,
            Port::ArgsFrom(0)
        ));
        assert_eq!(compiled.rules.sinks[1].inputs, vec![Port::Receiver]);
        let metadata = &compiled.rules.metadata[0];
        assert_eq!(metadata.localized_message("en"), "tainted command");
        assert_eq!(metadata.localized_message("zh-CN"), "污染命令");
        assert!(compiled.diagnostics.is_empty());
    }

    #[test]
    fn rejects_cross_port_and_conditions_instead_of_weakening_them() {
        let check: Value = serde_yaml::from_str(
            "And:\n- SignCheck: { argument: '0', kind: left }\n- SignCheck: { argument: '1', kind: right }\n",
        )
        .expect("condition fixture");
        assert!(compile_sink_check(&check)
            .expect_err("cross-port And must fail")
            .to_string()
            .contains("cross-port"));
    }
}
