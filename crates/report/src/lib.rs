use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use uniflow_checker_api::{CheckerFinding, CheckerLocation, CheckerManifest, CheckerRule};
use uniflow_taint::TaintFinding;
use uniflow_value_flow::{FlowGraph, FlowStats};

pub fn export_sarif(tool_name: &str, findings: &[TaintFinding]) -> Value {
    export_sarif_with_checkers(tool_name, findings, &[])
}

pub fn export_sarif_with_checkers(
    tool_name: &str,
    findings: &[TaintFinding],
    checker_findings: &[CheckerFinding],
) -> Value {
    export_sarif_with_checker_manifests(tool_name, findings, checker_findings, &[])
}

pub fn export_sarif_with_checker_manifests(
    tool_name: &str,
    findings: &[TaintFinding],
    checker_findings: &[CheckerFinding],
    checker_manifests: &[CheckerManifest],
) -> Value {
    let mut rules = BTreeMap::new();
    for finding in findings {
        rules
            .entry(finding.sink_rule_id.clone())
            .or_insert_with(|| taint_sarif_rule(finding));
    }
    for finding in checker_findings {
        rules
            .entry(finding.rule_id.clone())
            .or_insert_with(|| fallback_sarif_rule(&finding.rule_id));
    }
    for manifest in checker_manifests {
        for rule in &manifest.rules {
            let id = qualified_checker_rule_id(manifest, rule);
            rules.insert(id.clone(), checker_sarif_rule(manifest, rule, id));
        }
    }
    let rules = rules.into_values().collect::<Vec<_>>();

    let mut results = findings
        .iter()
        .map(|finding| {
            let thread_locations = sarif_thread_flow_locations(finding);
            json!({
                "ruleId": finding.sink_rule_id,
                "level": if finding.severity.is_empty() {
                    sarif_level_for_kind(&finding.sink_kind)
                } else {
                    finding.severity.as_str()
                },
                "message": {
                    "text": if finding.message.is_empty() {
                        format!(
                            "Taint of kind '{}' reaches sink '{}' from source '{}'",
                            finding.source_kind,
                            finding.sink_rule_id,
                            finding.source_rule_id,
                        )
                    } else {
                        finding.message.clone()
                    }
                },
                "locations": [sarif_result_location(&finding.sink_location, &finding.sink_label)],
                "relatedLocations": [sarif_related_location(&finding.source_location, &finding.source_label)],
                "properties": {
                    "sourceRuleId": finding.source_rule_id,
                    "sinkRuleId": finding.sink_rule_id,
                    "sourceKind": finding.source_kind,
                    "sinkKind": finding.sink_kind,
                    "pathLabels": finding.path_labels,
                    "provider": if finding.finding_kind == "lifetime" { "builtin-lifetime" } else { "builtin-taint" },
                    "analysisComplete": finding.analysis_complete,
                    "queryCompleteness": format!("{:?}", finding.completeness),
                    "findingKind": finding.finding_kind,
                    "cwe": finding.cwe,
                    "standards": finding.standards,
                    "translations": finding.translations,
                },
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": thread_locations,
                    }]
                }],
            })
        })
        .collect::<Vec<_>>();

    results.extend(checker_findings.iter().map(checker_sarif_result));

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://example.invalid/uniflow",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    })
}

fn taint_sarif_rule(finding: &TaintFinding) -> Value {
    if finding.rule_title.trim().is_empty() {
        return fallback_sarif_rule(&finding.sink_rule_id);
    }
    let description = if finding.message.trim().is_empty() {
        finding.rule_title.as_str()
    } else {
        finding.message.as_str()
    };
    let mut tags = finding.cwe.clone();
    for standard in &finding.standards {
        if !tags.iter().any(|tag| tag == standard) {
            tags.push(standard.clone());
        }
    }
    json!({
        "id": finding.sink_rule_id,
        "shortDescription": { "text": finding.rule_title },
        "fullDescription": { "text": description },
        "defaultConfiguration": {
            "level": if finding.severity.is_empty() {
                sarif_level_for_kind(&finding.sink_kind)
            } else {
                finding.severity.as_str()
            }
        },
        "properties": {
            "tags": tags,
            "cwe": finding.cwe,
            "standards": finding.standards,
            "translations": finding.translations,
        }
    })
}

fn fallback_sarif_rule(id: &str) -> Value {
    json!({
        "id": id,
        "shortDescription": { "text": format!("UniFlow finding for {id}") },
        "fullDescription": { "text": "Source analysis finding emitted by UniFlow or an external checker" },
    })
}

fn qualified_checker_rule_id(manifest: &CheckerManifest, rule: &CheckerRule) -> String {
    if rule.id.starts_with(&format!("{}.", manifest.id)) {
        rule.id.clone()
    } else {
        format!("{}.{}", manifest.id, rule.id)
    }
}

fn checker_sarif_rule(manifest: &CheckerManifest, rule: &CheckerRule, id: String) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert("checkerId".to_string(), json!(manifest.id));
    properties.insert("checkerName".to_string(), json!(manifest.name));
    properties.insert("checkerVersion".to_string(), json!(manifest.version));
    if !rule.tags.is_empty() {
        properties.insert("tags".to_string(), json!(rule.tags));
    }
    for (key, value) in &rule.properties {
        properties.insert(key.clone(), value.clone());
    }
    let description = if rule.description.trim().is_empty() {
        rule.title.as_str()
    } else {
        rule.description.as_str()
    };
    let mut value = json!({
        "id": id,
        "name": rule.id,
        "shortDescription": { "text": rule.title },
        "fullDescription": { "text": description },
        "defaultConfiguration": { "level": rule.default_level },
        "properties": properties,
    });
    if let Some(help_uri) = rule.help_uri.as_deref() {
        value["helpUri"] = json!(help_uri);
    }
    value
}

fn checker_sarif_result(finding: &CheckerFinding) -> Value {
    let related = finding
        .related_locations
        .iter()
        .map(|location| checker_related_location(location))
        .collect::<Vec<_>>();
    let code_flows = if finding.code_flow.is_empty() {
        Vec::new()
    } else {
        vec![json!({
            "threadFlows": [{
                "locations": finding.code_flow.iter().map(|step| {
                    json!({
                        "location": checker_physical_location(&step.location, &step.message),
                    })
                }).collect::<Vec<_>>()
            }]
        })]
    };
    let mut value = json!({
        "ruleId": finding.rule_id,
        "level": finding.level,
        "message": { "text": finding.message },
        "locations": [checker_physical_location(&finding.location, &finding.location.label)],
        "relatedLocations": related,
        "properties": finding.properties,
        "codeFlows": code_flows,
    });
    if let Some(fingerprint) = finding.fingerprint.as_deref() {
        value["partialFingerprints"] = json!({ "uniflow/v1": fingerprint });
    }
    value
}

fn checker_physical_location(location: &CheckerLocation, label: &str) -> Value {
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": location.uri },
            "region": {
                "startLine": location.line.max(1),
                "startColumn": location.column.max(1),
            }
        },
        "message": { "text": label },
    })
}

fn checker_related_location(location: &CheckerLocation) -> Value {
    checker_physical_location(location, &location.label)
}

pub fn export_dot(flow: &FlowGraph, findings: &[TaintFinding]) -> String {
    let highlighted = findings
        .iter()
        .flat_map(|finding| finding.path.iter().copied())
        .collect::<BTreeSet<_>>();

    let mut out = String::new();
    out.push_str("digraph uniflow {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box];\n");

    for idx in flow.graph.node_indices() {
        let label = escape_dot(&flow.describe_node(idx));
        if highlighted.contains(&idx.index()) {
            out.push_str(&format!(
                "  n{} [label=\"{}\", penwidth=2];\n",
                idx.index(),
                label
            ));
        } else {
            out.push_str(&format!("  n{} [label=\"{}\"];\n", idx.index(), label));
        }
    }

    for edge in flow.graph.edge_indices() {
        if let Some((from, to)) = flow.graph.edge_endpoints(edge) {
            let label = flow.describe_edge(from, to);
            out.push_str(&format!(
                "  n{} -> n{} [label=\"{}\"];\n",
                from.index(),
                to.index(),
                escape_dot(&label),
            ));
        }
    }

    out.push_str("}\n");
    out
}

pub fn export_markdown_report(flow: &FlowGraph, findings: &[TaintFinding]) -> String {
    export_markdown_report_with_checkers(flow, findings, &[])
}

pub fn export_markdown_report_with_checkers(
    flow: &FlowGraph,
    findings: &[TaintFinding],
    checker_findings: &[CheckerFinding],
) -> String {
    let stats = flow.stats();
    let call_report = flow.call_report();

    let mut out = String::new();
    out.push_str("# UniFlow analysis report\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&render_stats_table(
        &stats,
        findings.len() + checker_findings.len(),
    ));
    out.push('\n');

    out.push_str("## Built-in findings\n\n");
    if findings.is_empty() {
        out.push_str("No built-in findings.\n\n");
    } else {
        for (idx, finding) in findings.iter().enumerate() {
            out.push_str(&format!("### Built-in finding {}\n\n", idx + 1));
            out.push_str(&format!(
                "- Finding kind: `{}`\n- Rule: `{}`\n- Source kind: `{}`\n- Sink kind: `{}`\n- Severity: `{}`\n- Analysis complete: `{}` (`{:?}`)\n- Source location: `{}`\n- Sink location: `{}`\n- Message: {}\n\n",
                finding.finding_kind,
                finding.sink_rule_id,
                finding.source_kind,
                finding.sink_kind,
                finding.severity,
                finding.analysis_complete,
                finding.completeness,
                finding.source_location,
                finding.sink_location,
                finding.message,
            ));
            out.push_str("Path:\n\n");
            for step in &finding.steps {
                out.push_str(&format!(
                    "- `{}` (`{}`) --{}--> `{}` (`{}`)\n",
                    step.from_label,
                    step.from_location,
                    step.edge_kind,
                    step.to_label,
                    step.to_location,
                ));
            }
            out.push('\n');
        }
    }

    out.push_str("## External checker findings\n\n");
    if checker_findings.is_empty() {
        out.push_str("No external checker findings.\n\n");
    } else {
        for (idx, finding) in checker_findings.iter().enumerate() {
            out.push_str(&format!("### Checker finding {}\n\n", idx + 1));
            out.push_str(&format!(
                "- Rule: `{}`\n- Level: `{}`\n- Location: `{}:{}:{}`\n- Message: {}\n",
                finding.rule_id,
                finding.level,
                finding.location.uri,
                finding.location.line,
                finding.location.column,
                finding.message,
            ));
            if let Some(fingerprint) = finding.fingerprint.as_deref() {
                out.push_str(&format!("- Fingerprint: `{fingerprint}`\n"));
            }
            if !finding.code_flow.is_empty() {
                out.push_str("\nPath:\n\n");
                for step in &finding.code_flow {
                    out.push_str(&format!(
                        "- `{}` at `{}:{}:{}`\n",
                        step.message, step.location.uri, step.location.line, step.location.column,
                    ));
                }
            }
            out.push('\n');
        }
    }

    out.push_str("## Calls\n\n");
    if call_report.is_empty() {
        out.push_str("No calls.\n");
    } else {
        out.push_str("| Function | Location | Callee | Receiver type | Dynamic | Resolved internal targets |\n");
        out.push_str("|---|---|---|---|---:|---|\n");
        for call in call_report {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                escape_md_cell(&call.function_name),
                escape_md_cell(&call.location),
                escape_md_cell(call.callee_name.as_deref().unwrap_or("<dynamic>")),
                escape_md_cell(call.receiver_type.as_deref().unwrap_or("")),
                if call.is_dynamic { "yes" } else { "no" },
                escape_md_cell(&call.resolved_internal_targets.join(", ")),
            ));
        }
    }

    out
}

fn sarif_thread_flow_locations(finding: &TaintFinding) -> Vec<Value> {
    let mut out = Vec::new();
    if finding.steps.is_empty() {
        if !finding.source_location.is_empty() {
            out.push(sarif_thread_flow_location(
                &finding.source_location,
                &format!("source {}", finding.source_label),
            ));
        }
        if !finding.sink_location.is_empty() && finding.sink_location != finding.source_location {
            out.push(sarif_thread_flow_location(
                &finding.sink_location,
                &format!("sink {}", finding.sink_label),
            ));
        }
        return out;
    }

    let first = &finding.steps[0];
    if !first.from_location.is_empty() {
        out.push(sarif_thread_flow_location(
            &first.from_location,
            &format!("source {}", first.from_label),
        ));
    }
    for step in &finding.steps {
        if let Some(last) = out.last() {
            if same_thread_location(last, &step.to_location) {
                continue;
            }
        }
        out.push(sarif_thread_flow_location(
            &step.to_location,
            &format!(
                "{} --{}--> {}",
                step.from_label, step.edge_kind, step.to_label
            ),
        ));
    }
    out
}

fn same_thread_location(value: &Value, location: &str) -> bool {
    let Some(uri) = value
        .pointer("/location/physicalLocation/artifactLocation/uri")
        .and_then(|v| v.as_str())
    else {
        return false;
    };
    let line = value
        .pointer("/location/physicalLocation/region/startLine")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let col = value
        .pointer("/location/physicalLocation/region/startColumn")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let (other_uri, other_line, other_col) = split_location(location);
    uri == other_uri && line == other_line as u64 && col == other_col as u64
}

fn render_stats_table(stats: &FlowStats, findings: usize) -> String {
    let rows = BTreeMap::from([
        ("files", stats.files.to_string()),
        ("functions", stats.functions.to_string()),
        ("value_nodes", stats.value_nodes.to_string()),
        ("total_nodes", stats.total_nodes.to_string()),
        ("total_edges", stats.total_edges.to_string()),
        ("sparse_data_edges", stats.sparse_data_edges.to_string()),
        ("heap_value_edges", stats.heap_value_edges.to_string()),
        ("heap_object_edges", stats.heap_object_edges.to_string()),
        ("object_graph_edges", stats.object_graph_edges.to_string()),
        ("region_graph_edges", stats.region_graph_edges.to_string()),
        ("object_shape_nodes", stats.object_shape_nodes.to_string()),
        ("object_shape_paths", stats.object_shape_paths.to_string()),
        (
            "object_identity_values",
            stats.object_identity_values.to_string(),
        ),
        ("points_to_classes", stats.points_to_classes.to_string()),
        ("points_to_targets", stats.points_to_targets.to_string()),
        ("points_to_objects", stats.points_to_objects.to_string()),
        ("strong_update_cells", stats.strong_update_cells.to_string()),
        (
            "cell_write_generations",
            stats.cell_write_generations.to_string(),
        ),
        ("contextual_states", stats.contextual_states.to_string()),
        (
            "contextual_points_to_objects",
            stats.contextual_points_to_objects.to_string(),
        ),
        (
            "solver_closure_iterations",
            stats.solver_closure_iterations.to_string(),
        ),
        (
            "global_solver_iterations",
            stats.global_solver_iterations.to_string(),
        ),
        ("memory_regions", stats.memory_regions.to_string()),
        ("live_cell_values", stats.live_cell_values.to_string()),
        ("live_cell_regions", stats.live_cell_regions.to_string()),
        ("live_region_values", stats.live_region_values.to_string()),
        ("live_region_cells", stats.live_region_cells.to_string()),
        (
            "cached_sparse_summaries",
            stats.cached_sparse_summaries.to_string(),
        ),
        (
            "cached_demand_queries",
            stats.cached_demand_queries.to_string(),
        ),
        (
            "cached_contextual_queries",
            stats.cached_contextual_queries.to_string(),
        ),
        (
            "cached_contextual_summaries",
            stats.cached_contextual_summaries.to_string(),
        ),
        (
            "cached_function_summaries",
            stats.cached_function_summaries.to_string(),
        ),
        (
            "cached_interprocedural_summaries",
            stats.cached_interprocedural_summaries.to_string(),
        ),
        (
            "cached_transfer_summaries",
            stats.cached_transfer_summaries.to_string(),
        ),
        (
            "cached_heap_effect_summaries",
            stats.cached_heap_effect_summaries.to_string(),
        ),
        ("static_calls", stats.static_calls.to_string()),
        ("dynamic_calls", stats.dynamic_calls.to_string()),
        (
            "resolved_internal_calls",
            stats.resolved_internal_calls.to_string(),
        ),
        (
            "unresolved_static_calls",
            stats.unresolved_static_calls.to_string(),
        ),
        ("synthetic_sources", stats.synthetic_sources.to_string()),
        ("synthetic_sinks", stats.synthetic_sinks.to_string()),
        ("findings", findings.to_string()),
    ]);
    let mut out = String::from("| Metric | Value |\n|---|---:|\n");
    for (k, v) in rows {
        out.push_str(&format!("| {} | {} |\n", k, v));
    }
    out
}

fn sarif_level_for_kind(kind: &str) -> &'static str {
    match kind {
        "command" => "error",
        "sql" => "warning",
        _ => "note",
    }
}

fn sarif_result_location(location: &str, label: &str) -> Value {
    let (uri, start_line, start_column) = split_location(location);
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": uri },
            "region": {
                "startLine": start_line,
                "startColumn": start_column,
            }
        },
        "message": { "text": label },
    })
}

fn sarif_related_location(location: &str, label: &str) -> Value {
    let (uri, start_line, start_column) = split_location(location);
    json!({
        "physicalLocation": {
            "artifactLocation": { "uri": uri },
            "region": {
                "startLine": start_line,
                "startColumn": start_column,
            }
        },
        "message": { "text": label },
    })
}

fn sarif_thread_flow_location(location: &str, label: &str) -> Value {
    let (uri, start_line, start_column) = split_location(location);
    json!({
        "location": {
            "physicalLocation": {
                "artifactLocation": { "uri": uri },
                "region": {
                    "startLine": start_line,
                    "startColumn": start_column,
                }
            },
            "message": { "text": label },
        }
    })
}

fn split_location(location: &str) -> (String, u32, u32) {
    let trimmed = location.trim().trim_start_matches('@');
    if trimmed.is_empty() || trimmed == "unknown" {
        return ("unknown".to_string(), 1, 1);
    }

    let mut parts = trimmed.rsplitn(3, ':').collect::<Vec<_>>();
    parts.reverse();
    if parts.len() == 3 {
        let uri = parts[0].to_string();
        let line = parts[1].parse::<u32>().unwrap_or(1);
        let col = parts[2].parse::<u32>().unwrap_or(1);
        (uri, line, col)
    } else {
        (trimmed.to_string(), 1, 1)
    }
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use uniflow_checker_api::{CheckerFinding, CheckerLocation, CheckerManifest, CheckerRule};

    #[test]
    fn external_checker_finding_is_emitted_as_sarif() {
        let finding = CheckerFinding {
            rule_id: "example.rule".to_string(),
            message: "example diagnostic".to_string(),
            level: "warning".to_string(),
            location: CheckerLocation {
                uri: "demo.c".to_string(),
                line: 7,
                column: 3,
                label: "call".to_string(),
            },
            related_locations: Vec::new(),
            code_flow: Vec::new(),
            properties: BTreeMap::new(),
            fingerprint: Some("stable-id".to_string()),
        };
        let sarif = export_sarif_with_checkers("uniflow", &[], &[finding]);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "example.rule");
        assert_eq!(
            sarif["runs"][0]["results"][0]["partialFingerprints"]["uniflow/v1"],
            "stable-id"
        );
        assert_eq!(
            sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            7
        );
    }

    #[test]
    fn external_checker_rule_metadata_is_emitted_as_sarif() {
        let mut manifest = CheckerManifest::new("example.security", "Security", "2.1.0");
        let mut rule = CheckerRule::new("sql-injection", "SQL injection");
        rule.description = "Untrusted data reaches a SQL execution sink.".to_string();
        rule.default_level = "error".to_string();
        rule.tags = vec!["security".to_string(), "cwe-89".to_string()];
        rule.help_uri = Some("https://example.invalid/sql-injection".to_string());
        rule.properties
            .insert("precision".to_string(), json!("high"));
        manifest.rules.push(rule);

        let sarif = export_sarif_with_checker_manifests("uniflow", &[], &[], &[manifest]);
        let descriptor = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(descriptor["id"], "example.security.sql-injection");
        assert_eq!(descriptor["shortDescription"]["text"], "SQL injection");
        assert_eq!(descriptor["defaultConfiguration"]["level"], "error");
        assert_eq!(descriptor["properties"]["precision"], "high");
        assert_eq!(
            descriptor["helpUri"],
            "https://example.invalid/sql-injection"
        );
    }

    #[test]
    fn localized_taint_rule_metadata_is_emitted_as_sarif() {
        let finding: TaintFinding = serde_json::from_value(json!({
            "source_rule_id": "request-input",
            "sink_rule_id": "command-injection",
            "source_kind": "command",
            "sink_kind": "command",
            "sink_node": 2,
            "path": [1, 2],
            "source_label": "source",
            "sink_label": "sink",
            "source_location": "demo.c:1:1",
            "sink_location": "demo.c:2:1",
            "path_labels": ["source", "sink"],
            "steps": [],
            "severity": "error",
            "message": "Untrusted data reaches command execution.",
            "rule_title": "Command injection",
            "cwe": ["CWE-78"],
            "standards": ["GJB-8114"],
            "translations": {
                "zh-CN": { "title": "命令注入", "message": "不可信数据到达命令执行接口。" },
                "en": { "title": "Command injection", "message": "Untrusted data reaches command execution." },
                "zh-TW": { "title": "命令注入", "message": "不可信資料到達命令執行介面。" }
            }
        }))
        .expect("taint finding");
        let sarif = export_sarif("uniflow", &[finding]);
        let descriptor = &sarif["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(descriptor["shortDescription"]["text"], "Command injection");
        assert_eq!(descriptor["defaultConfiguration"]["level"], "error");
        assert_eq!(descriptor["properties"]["cwe"][0], "CWE-78");
        assert_eq!(descriptor["properties"]["standards"][0], "GJB-8114");
        assert_eq!(
            descriptor["properties"]["translations"]["zh-TW"]["message"],
            "不可信資料到達命令執行介面。"
        );
    }
}
