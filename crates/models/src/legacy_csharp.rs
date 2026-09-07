use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};
use uniflow_hir::Language;
use uniflow_rules::{
    ApiMatcher, FieldMatcher, FieldSinkRule, FieldSourceRule, FlowSpec, FunctionMatcher,
    FunctionSourceRule, LocalizedRuleText, Port, PropagatorRule, RuleMetadata, RuleSet,
    RuleTranslations, SanitizerRule, SinkRule, SourceRule,
};

#[derive(Clone, Debug, Deserialize)]
pub struct LegacyCsharpPack {
    #[serde(default, rename = "TaintEntryPoints")]
    entry_points: Mapping,
    #[serde(default, rename = "TaintSources")]
    sources: Vec<LegacyEndpoint>,
    #[serde(default, rename = "Sanitizers")]
    sanitizers: Vec<LegacyEndpoint>,
    #[serde(default, rename = "Transfers")]
    transfers: Vec<LegacyEndpoint>,
    #[serde(default, rename = "Sinks")]
    sinks: Vec<LegacyEndpoint>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyEndpoint {
    #[serde(rename = "Type")]
    owner: String,
    #[serde(default, rename = "TaintTypes")]
    taint_types: Vec<String>,
    #[serde(default, rename = "Methods")]
    methods: Vec<LegacyMethod>,
    #[serde(default, rename = "Properties")]
    properties: Vec<String>,
    #[serde(default, rename = "IsAnyStringParameterInConstructorASink")]
    any_constructor_string: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyMethod {
    #[serde(rename = "Name")]
    name: String,
    #[serde(default, rename = "ArgumentCount")]
    argument_count: Option<usize>,
    #[serde(default, rename = "Arguments")]
    arguments: Vec<String>,
    #[serde(default, rename = "InOut")]
    in_out: Vec<BTreeMap<String, String>>,
    #[serde(default, rename = "CleansInstance")]
    cleans_instance: bool,
    #[serde(default, rename = "Condition")]
    _condition: Vec<Value>,
    #[serde(default, rename = "SignatureNot")]
    _signature_not: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyMessage {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    cwe: Option<Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyVulnerabilityFile {
    #[serde(default)]
    rules: BTreeMap<String, LegacyVulnerability>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyVulnerability {
    #[serde(default)]
    category: String,
    #[serde(default)]
    sub_category: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    groups: Vec<LegacyGroup>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct LegacyGroup {
    #[serde(default)]
    name: String,
    #[serde(default)]
    text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyCsharpDiagnostic {
    pub section: String,
    pub index: usize,
    pub feature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LegacyCsharpCompilation {
    pub rules: RuleSet,
    pub diagnostics: Vec<LegacyCsharpDiagnostic>,
}

impl LegacyCsharpPack {
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        serde_yaml::from_str(text.trim_start_matches('\u{feff}'))
            .context("invalid embedded SecurityCodeScan configuration")
    }
}

pub fn compile_legacy_csharp_pack(
    pack: &LegacyCsharpPack,
    messages_yaml: &str,
    vulnerabilities_yaml: &str,
    namespace: &str,
) -> Result<LegacyCsharpCompilation> {
    let messages = serde_yaml::from_str::<BTreeMap<String, LegacyMessage>>(
        messages_yaml.trim_start_matches('\u{feff}'),
    )
    .context("invalid SecurityCodeScan message catalog")?;
    let vulnerabilities = serde_yaml::from_str::<LegacyVulnerabilityFile>(
        vulnerabilities_yaml.trim_start_matches('\u{feff}'),
    )
    .context("invalid C# vulnerability metadata")?;
    let kinds = pack
        .sinks
        .iter()
        .flat_map(|sink| sink.taint_types.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut out = LegacyCsharpCompilation::default();
    compile_sources(pack, &kinds, namespace, &mut out);
    compile_entry_points(pack, &kinds, namespace, &mut out)?;
    compile_sanitizers(pack, &kinds, namespace, &mut out);
    compile_transfers(pack, namespace, &mut out);
    compile_sinks(pack, &messages, &vulnerabilities.rules, namespace, &mut out);
    out.rules.validate()?;
    Ok(out)
}

fn compile_sources(
    pack: &LegacyCsharpPack,
    kinds: &BTreeSet<String>,
    namespace: &str,
    out: &mut LegacyCsharpCompilation,
) {
    for (endpoint_index, endpoint) in pack.sources.iter().enumerate() {
        for (method_index, method) in endpoint.methods.iter().enumerate() {
            for kind in kinds {
                out.rules.sources.push(SourceRule {
                    id: format!(
                        "{namespace}.source.{endpoint_index}.method.{method_index}.{}",
                        normalized_id(kind)
                    ),
                    language: Some(Language::CSharp),
                    matcher: method_matcher(&endpoint.owner, method),
                    out: Port::Return,
                    kind: kind.clone(),
                });
            }
        }
        for (property_index, property) in endpoint.properties.iter().enumerate() {
            for kind in kinds {
                out.rules.field_sources.push(FieldSourceRule {
                    id: format!(
                        "{namespace}.source.{endpoint_index}.property.{property_index}.{}",
                        normalized_id(kind)
                    ),
                    language: Some(Language::CSharp),
                    matcher: FieldMatcher {
                        owner: Some(endpoint.owner.clone()),
                        owner_regex: None,
                        field: property.clone(),
                    },
                    kind: kind.clone(),
                });
            }
        }
        if endpoint.methods.is_empty() && endpoint.properties.is_empty() {
            for kind in kinds {
                out.rules.sources.push(SourceRule {
                    id: format!(
                        "{namespace}.source.{endpoint_index}.instance.{}",
                        normalized_id(kind)
                    ),
                    language: Some(Language::CSharp),
                    matcher: constructor_matcher(&endpoint.owner),
                    out: Port::Return,
                    kind: kind.clone(),
                });
                out.rules.field_sources.push(FieldSourceRule {
                    id: format!(
                        "{namespace}.source.{endpoint_index}.members.{}",
                        normalized_id(kind)
                    ),
                    language: Some(Language::CSharp),
                    matcher: FieldMatcher {
                        owner: Some(endpoint.owner.clone()),
                        owner_regex: None,
                        field: "*".to_string(),
                    },
                    kind: kind.clone(),
                });
            }
        }
    }
}

fn compile_entry_points(
    pack: &LegacyCsharpPack,
    kinds: &BTreeSet<String>,
    namespace: &str,
    out: &mut LegacyCsharpCompilation,
) -> Result<()> {
    for (entry_index, (base, config)) in pack.entry_points.iter().enumerate() {
        let base = scalar_text(base).context("C# entry-point base type is not text")?;
        let config = config
            .as_mapping()
            .context("C# entry-point configuration is not a mapping")?;
        let class = mapping_get(config, "Class").and_then(Value::as_mapping);
        let method = mapping_get(config, "Method").and_then(Value::as_mapping);
        let method_regex = method
            .and_then(|method| mapping_get(method, "Name"))
            .and_then(Value::as_str)
            .and_then(slash_regex);
        let parent = class
            .and_then(|class| mapping_get(class, "Parent"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let suffix = class
            .and_then(|class| mapping_get(class, "Suffix"))
            .and_then(Value::as_mapping)
            .and_then(|suffix| mapping_get(suffix, "Text"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut owner_matchers = Vec::new();
        if let Some(parent) = parent {
            owner_matchers.push((Some(parent), None));
        } else if base != "System.Object" {
            owner_matchers.push((Some(base), None));
        }
        if let Some(suffix) = suffix {
            owner_matchers.push((None, Some(format!("{}$", regex::escape(&suffix)))));
        }
        for (matcher_index, (owner, owner_regex)) in owner_matchers.into_iter().enumerate() {
            for kind in kinds {
                out.rules.function_sources.push(FunctionSourceRule {
                    id: format!(
                        "{namespace}.entry.{entry_index}.{matcher_index}.{}",
                        normalized_id(kind)
                    ),
                    language: Some(Language::CSharp),
                    matcher: FunctionMatcher {
                        regex: method_regex.clone(),
                        owner: owner.clone(),
                        owner_regex: owner_regex.clone(),
                        ..Default::default()
                    },
                    out: Port::ArgsFrom(0),
                    kind: kind.clone(),
                });
            }
        }
    }
    Ok(())
}

fn compile_sanitizers(
    pack: &LegacyCsharpPack,
    all_kinds: &BTreeSet<String>,
    namespace: &str,
    out: &mut LegacyCsharpCompilation,
) {
    for (endpoint_index, endpoint) in pack.sanitizers.iter().enumerate() {
        let kinds = endpoint_kinds(endpoint, all_kinds);
        for (method_index, method) in endpoint.methods.iter().enumerate() {
            let flows = in_out_flows(method);
            let (inputs, outputs) = if method.cleans_instance {
                (vec![Port::Receiver], vec![Port::Receiver])
            } else if flows.is_empty() {
                (vec![Port::ArgsFrom(0)], vec![Port::Return])
            } else {
                (
                    unique_ports(flows.iter().map(|flow| flow.from.clone())),
                    unique_ports(flows.iter().map(|flow| flow.to.clone())),
                )
            };
            for kind in &kinds {
                out.rules.sanitizers.push(SanitizerRule {
                    id: format!(
                        "{namespace}.sanitizer.{endpoint_index}.{method_index}.{}",
                        normalized_id(kind)
                    ),
                    language: Some(Language::CSharp),
                    matcher: method_matcher(&endpoint.owner, method),
                    inputs: inputs.clone(),
                    outputs: outputs.clone(),
                    kind: kind.clone(),
                });
            }
        }
    }
}

fn compile_transfers(pack: &LegacyCsharpPack, namespace: &str, out: &mut LegacyCsharpCompilation) {
    for (endpoint_index, endpoint) in pack.transfers.iter().enumerate() {
        for (method_index, method) in endpoint.methods.iter().enumerate() {
            let flows = in_out_flows(method);
            if !flows.is_empty() {
                out.rules.propagators.push(PropagatorRule {
                    id: format!("{namespace}.transfer.{endpoint_index}.{method_index}"),
                    language: Some(Language::CSharp),
                    matcher: method_matcher(&endpoint.owner, method),
                    flows,
                });
            }
        }
    }
}

fn compile_sinks(
    pack: &LegacyCsharpPack,
    messages: &BTreeMap<String, LegacyMessage>,
    vulnerabilities: &BTreeMap<String, LegacyVulnerability>,
    namespace: &str,
    out: &mut LegacyCsharpCompilation,
) {
    for (endpoint_index, endpoint) in pack.sinks.iter().enumerate() {
        for kind in &endpoint.taint_types {
            for (method_index, method) in endpoint.methods.iter().enumerate() {
                let inputs = if method.arguments.is_empty() {
                    vec![Port::ArgsFrom(0)]
                } else {
                    method
                        .arguments
                        .iter()
                        .cloned()
                        .map(Port::NamedArgOrAll)
                        .collect()
                };
                let id = format!(
                    "{namespace}.sink.{endpoint_index}.method.{method_index}.{}",
                    normalized_id(kind)
                );
                out.rules.sinks.push(SinkRule {
                    id: id.clone(),
                    language: Some(Language::CSharp),
                    matcher: method_matcher(&endpoint.owner, method),
                    inputs,
                    kind: kind.clone(),
                });
                out.rules.metadata.push(metadata_for(
                    id,
                    kind,
                    messages.get(kind),
                    vulnerabilities.get(kind),
                ));
            }
            if endpoint.any_constructor_string {
                let id = format!(
                    "{namespace}.sink.{endpoint_index}.constructor.{}",
                    normalized_id(kind)
                );
                out.rules.sinks.push(SinkRule {
                    id: id.clone(),
                    language: Some(Language::CSharp),
                    matcher: constructor_matcher(&endpoint.owner),
                    inputs: vec![Port::ArgsFrom(0)],
                    kind: kind.clone(),
                });
                out.rules.metadata.push(metadata_for(
                    id,
                    kind,
                    messages.get(kind),
                    vulnerabilities.get(kind),
                ));
            }
            for (property_index, property) in endpoint.properties.iter().enumerate() {
                let id = format!(
                    "{namespace}.sink.{endpoint_index}.property.{property_index}.{}",
                    normalized_id(kind)
                );
                out.rules.field_sinks.push(FieldSinkRule {
                    id: id.clone(),
                    language: Some(Language::CSharp),
                    matcher: FieldMatcher {
                        owner: Some(endpoint.owner.clone()),
                        owner_regex: None,
                        field: property.clone(),
                    },
                    kind: kind.clone(),
                });
                out.rules.metadata.push(metadata_for(
                    id,
                    kind,
                    messages.get(kind),
                    vulnerabilities.get(kind),
                ));
            }
        }
    }
}

fn method_matcher(owner: &str, method: &LegacyMethod) -> ApiMatcher {
    ApiMatcher {
        receiver_type: Some(owner.to_string()),
        method_name: (method.name != ".ctor").then(|| method.name.clone()),
        method_regex: (method.name == ".ctor").then(|| {
            let short = owner.rsplit('.').next().unwrap_or(owner);
            format!(r"^(?:\.ctor|new|{})$", regex::escape(short))
        }),
        arg_count: method.argument_count,
        ..Default::default()
    }
}

fn constructor_matcher(owner: &str) -> ApiMatcher {
    let short = owner.rsplit('.').next().unwrap_or(owner);
    ApiMatcher {
        receiver_type: Some(owner.to_string()),
        method_regex: Some(format!(r"^(?:\.ctor|new|{})$", regex::escape(short))),
        ..Default::default()
    }
}

fn endpoint_kinds(endpoint: &LegacyEndpoint, all: &BTreeSet<String>) -> Vec<String> {
    if endpoint.taint_types.is_empty() {
        all.iter().cloned().collect()
    } else {
        endpoint.taint_types.clone()
    }
}

fn in_out_flows(method: &LegacyMethod) -> Vec<FlowSpec> {
    method
        .in_out
        .iter()
        .flat_map(|mapping| mapping.iter())
        .map(|(from, to)| FlowSpec {
            from: named_endpoint_port(from),
            to: named_endpoint_port(to),
        })
        .collect()
}

fn named_endpoint_port(name: &str) -> Port {
    match name.to_ascii_lowercase().as_str() {
        ".this" | "this" => Port::Receiver,
        ".return" | "return" => Port::Return,
        _ => Port::NamedArg(name.to_string()),
    }
}

fn unique_ports(ports: impl Iterator<Item = Port>) -> Vec<Port> {
    ports.fold(Vec::new(), |mut out, port| {
        if !out.contains(&port) {
            out.push(port);
        }
        out
    })
}

fn metadata_for(
    id: String,
    kind: &str,
    message: Option<&LegacyMessage>,
    vulnerability: Option<&LegacyVulnerability>,
) -> RuleMetadata {
    let english_title = message
        .map(|message| message.title.clone())
        .filter(|title| !title.is_empty())
        .unwrap_or_else(|| format!("C# security rule {kind}"));
    let english_message = message
        .map(|message| message.description.clone())
        .filter(|description| !description.is_empty())
        .unwrap_or_else(|| english_title.clone());
    let chinese_title = vulnerability
        .map(|item| {
            if item.sub_category.is_empty() {
                item.category.clone()
            } else {
                format!("{}：{}", item.category, item.sub_category)
            }
        })
        .filter(|title| !title.is_empty());
    let cwe = message
        .and_then(|message| message.cwe.as_ref())
        .and_then(scalar_text)
        .map(|cwe| vec![format!("CWE-{cwe}")])
        .unwrap_or_default();
    let standards = vulnerability
        .map(|item| {
            item.groups
                .iter()
                .map(|group| format!("{}: {}", group.name, group.text))
                .collect()
        })
        .unwrap_or_default();
    RuleMetadata {
        id,
        title: english_title.clone(),
        message: english_message.clone(),
        severity: vulnerability
            .map(|item| numeric_severity(&item.severity))
            .unwrap_or("warning")
            .to_string(),
        cwe,
        standards,
        translations: RuleTranslations {
            en: Some(LocalizedRuleText {
                title: english_title,
                message: english_message,
            }),
            zh_cn: chinese_title.clone().map(|title| LocalizedRuleText {
                message: title.clone(),
                title,
            }),
            zh_tw: chinese_title.map(|title| LocalizedRuleText {
                message: title.clone(),
                title,
            }),
        },
    }
}

fn numeric_severity(value: &str) -> &'static str {
    match value.parse::<f64>().unwrap_or(2.0) {
        value if value >= 4.0 => "error",
        value if value >= 2.0 => "warning",
        value if value > 0.0 => "note",
        _ => "none",
    }
}

fn normalized_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn mapping_get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_string()))
}

fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn slash_regex(value: &str) -> Option<String> {
    value
        .strip_prefix('/')
        .and_then(|value| value.strip_suffix('/'))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_named_ports_fields_entrypoints_and_localized_metadata() {
        let config = r#"
TaintEntryPoints:
  System.Web.Mvc.ControllerBase:
    Class:
      Parent: System.Web.Mvc.ControllerBase
    Method:
      Name: /^Action$/
TaintSources:
  - Type: Demo.Request
    Methods: [{ Name: Read }]
    Properties: [Query]
Sanitizers:
  - Type: Demo.Encoder
    TaintTypes: [SCS0001]
    Methods:
      - Name: Encode
        InOut: [{ value: .Return }]
Transfers:
  - Type: Demo.Builder
    Methods:
      - Name: Append
        InOut: [{ value: .This }]
Sinks:
  - Type: Demo.Process
    TaintTypes: [SCS0001]
    Methods:
      - Name: Start
        Arguments: [command]
    Properties: [Command]
"#;
        let messages = r#"
SCS0001:
  title: Command injection
  description: Validate command input.
  cwe: 78
"#;
        let vulnerabilities = r#"
rules:
  SCS0001:
    category: 命令注入
    severity: "4.0"
    groups: [{ name: CWE-78, text: OS Command Injection }]
"#;
        let pack = LegacyCsharpPack::from_yaml_str(config).expect("parse fixture");
        let compiled =
            compile_legacy_csharp_pack(&pack, messages, vulnerabilities, "legacy.csharp")
                .expect("compile fixture");
        assert_eq!(compiled.rules.sources.len(), 1);
        assert_eq!(compiled.rules.field_sources.len(), 1);
        assert_eq!(compiled.rules.function_sources.len(), 1);
        assert_eq!(compiled.rules.sanitizers.len(), 1);
        assert_eq!(compiled.rules.propagators.len(), 1);
        assert_eq!(compiled.rules.sinks.len(), 1);
        assert_eq!(compiled.rules.field_sinks.len(), 1);
        assert_eq!(
            compiled.rules.sinks[0].inputs,
            vec![Port::NamedArgOrAll("command".to_string())]
        );
        assert_eq!(compiled.rules.sanitizers[0].outputs, vec![Port::Return]);
        assert_eq!(compiled.rules.propagators[0].flows[0].to, Port::Receiver);
        assert_eq!(compiled.rules.metadata[0].severity, "error");
        assert_eq!(compiled.rules.metadata[0].cwe, vec!["CWE-78"]);
        assert_eq!(
            compiled.rules.metadata[0]
                .translations
                .zh_cn
                .as_ref()
                .map(|text| text.title.as_str()),
            Some("命令注入")
        );
        assert!(compiled.diagnostics.is_empty());
    }
}
