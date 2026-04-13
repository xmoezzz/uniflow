use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use uniflow_taint::TaintFinding;
use uniflow_value_flow::{FlowGraph, FlowStats};

pub fn export_sarif(tool_name: &str, findings: &[TaintFinding]) -> Value {
    let mut rule_ids = BTreeSet::new();
    for finding in findings {
        rule_ids.insert(finding.sink_rule_id.clone());
    }

    let rules = rule_ids
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": format!("uniflow finding for {id}") },
                "fullDescription": { "text": "Source-level value-flow and taint finding" },
            })
        })
        .collect::<Vec<_>>();

    let results = findings
        .iter()
        .map(|finding| {
            let thread_locations = sarif_thread_flow_locations(finding);
            json!({
                "ruleId": finding.sink_rule_id,
                "level": sarif_level_for_kind(&finding.sink_kind),
                "message": {
                    "text": format!(
                        "Taint of kind '{}' reaches sink '{}' from source '{}'",
                        finding.source_kind,
                        finding.sink_rule_id,
                        finding.source_rule_id,
                    )
                },
                "locations": [sarif_result_location(&finding.sink_location, &finding.sink_label)],
                "relatedLocations": [sarif_related_location(&finding.source_location, &finding.source_label)],
                "properties": {
                    "sourceRuleId": finding.source_rule_id,
                    "sinkRuleId": finding.sink_rule_id,
                    "sourceKind": finding.source_kind,
                    "sinkKind": finding.sink_kind,
                    "pathLabels": finding.path_labels,
                },
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": thread_locations,
                    }]
                }],
            })
        })
        .collect::<Vec<_>>();

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
                idx.index(), label
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
    let stats = flow.stats();
    let call_report = flow.call_report();

    let mut out = String::new();
    out.push_str("# uniflow analysis report\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&render_stats_table(&stats, findings.len()));
    out.push('\n');

    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("No findings.\n\n");
    } else {
        for (idx, finding) in findings.iter().enumerate() {
            out.push_str(&format!("### Finding {}\n\n", idx + 1));
            out.push_str(&format!(
                "- Source rule: `{}`\n- Sink rule: `{}`\n- Source kind: `{}`\n- Sink kind: `{}`\n- Source location: `{}`\n- Sink location: `{}`\n\n",
                finding.source_rule_id,
                finding.sink_rule_id,
                finding.source_kind,
                finding.sink_kind,
                finding.source_location,
                finding.sink_location,
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
            &format!("{} --{}--> {}", step.from_label, step.edge_kind, step.to_label),
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
        ("object_identity_values", stats.object_identity_values.to_string()),
        ("points_to_classes", stats.points_to_classes.to_string()),
        ("points_to_targets", stats.points_to_targets.to_string()),
        ("points_to_objects", stats.points_to_objects.to_string()),
        ("strong_update_cells", stats.strong_update_cells.to_string()),
        ("cell_write_generations", stats.cell_write_generations.to_string()),
        ("contextual_states", stats.contextual_states.to_string()),
        ("contextual_points_to_objects", stats.contextual_points_to_objects.to_string()),
        ("solver_closure_iterations", stats.solver_closure_iterations.to_string()),
        ("global_solver_iterations", stats.global_solver_iterations.to_string()),
        ("memory_regions", stats.memory_regions.to_string()),
        ("live_cell_values", stats.live_cell_values.to_string()),
        ("live_cell_regions", stats.live_cell_regions.to_string()),
        ("live_region_values", stats.live_region_values.to_string()),
        ("live_region_cells", stats.live_region_cells.to_string()),
        ("cached_sparse_summaries", stats.cached_sparse_summaries.to_string()),
        ("cached_demand_queries", stats.cached_demand_queries.to_string()),
        ("cached_contextual_queries", stats.cached_contextual_queries.to_string()),
        ("cached_contextual_summaries", stats.cached_contextual_summaries.to_string()),
        ("cached_function_summaries", stats.cached_function_summaries.to_string()),
        ("cached_interprocedural_summaries", stats.cached_interprocedural_summaries.to_string()),
        ("cached_transfer_summaries", stats.cached_transfer_summaries.to_string()),
        ("cached_heap_effect_summaries", stats.cached_heap_effect_summaries.to_string()),
        ("static_calls", stats.static_calls.to_string()),
        ("dynamic_calls", stats.dynamic_calls.to_string()),
        ("resolved_internal_calls", stats.resolved_internal_calls.to_string()),
        ("unresolved_static_calls", stats.unresolved_static_calls.to_string()),
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
