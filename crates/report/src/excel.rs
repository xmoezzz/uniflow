use polars::prelude::*;
use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook, Worksheet, XlsxError};
use std::path::Path;
use uniflow_checker_api::CheckerFinding;
use uniflow_taint::TaintFinding;
use uniflow_value_flow::FlowGraph;

/// One language/analysis partition included in a consolidated Excel report.
///
/// Mixed-language project scans produce one section per frontend/flow graph,
/// while single-language scans simply pass one section named after the input
/// language (or `analysis` when no language label is available).
pub struct ExcelReportSection<'a> {
    pub name: &'a str,
    pub flow: &'a FlowGraph,
    pub findings: &'a [TaintFinding],
}

/// Write a rich Excel workbook for a single flow graph.
pub fn export_excel_report(
    path: impl AsRef<Path>,
    flow: &FlowGraph,
    findings: &[TaintFinding],
    checker_findings: &[CheckerFinding],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    export_excel_report_sections(
        path,
        &[ExcelReportSection {
            name: "analysis",
            flow,
            findings,
        }],
        checker_findings,
    )
}

/// Write a consolidated Excel workbook for one or more flow graphs.
///
/// Polars is deliberately used as the report analytics layer: raw findings are
/// normalized into DataFrames and summary sheets are computed with lazy
/// group-by queries. `rust_xlsxwriter` remains responsible for the workbook
/// layout/formatting layer.
pub fn export_excel_report_sections(
    path: impl AsRef<Path>,
    sections: &[ExcelReportSection<'_>],
    checker_findings: &[CheckerFinding],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let findings = findings_frame(sections)?;
    let checker = checker_findings_frame(checker_findings)?;
    let index = finding_index_frame(sections, checker_findings)?;
    let rule_summary = rule_summary_frame(&index)?;
    let severity_summary = severity_summary_frame(&index)?;
    let paths = paths_frame(sections)?;
    let calls = calls_frame(sections)?;
    let flow_stats = flow_stats_frame(sections)?;

    let mut workbook = Workbook::new();
    write_summary_sheet(
        &mut workbook,
        sections,
        checker_findings,
        &severity_summary,
    )?;
    write_dataframe_sheet(&mut workbook, "Findings", &findings)?;
    write_dataframe_sheet(&mut workbook, "Checker Findings", &checker)?;
    write_dataframe_sheet(&mut workbook, "Rule Summary", &rule_summary)?;
    write_dataframe_sheet(&mut workbook, "Paths", &paths)?;
    write_dataframe_sheet(&mut workbook, "Calls", &calls)?;
    write_dataframe_sheet(&mut workbook, "Flow Stats", &flow_stats)?;

    if let Some(parent) = path.as_ref().parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    workbook.save(path)?;
    Ok(())
}

fn findings_frame(sections: &[ExcelReportSection<'_>]) -> PolarsResult<DataFrame> {
    let mut language = Vec::new();
    let mut finding_kind = Vec::new();
    let mut rule_id = Vec::new();
    let mut rule_title = Vec::new();
    let mut severity = Vec::new();
    let mut cwe = Vec::new();
    let mut standards = Vec::new();
    let mut source_rule_id = Vec::new();
    let mut source_kind = Vec::new();
    let mut sink_kind = Vec::new();
    let mut source_location = Vec::new();
    let mut sink_location = Vec::new();
    let mut message = Vec::new();
    let mut path_length = Vec::new();
    let mut analysis_complete = Vec::new();
    let mut completeness = Vec::new();

    for section in sections {
        for finding in section.findings {
            language.push(section.name.to_string());
            finding_kind.push(finding.finding_kind.clone());
            rule_id.push(finding.sink_rule_id.clone());
            rule_title.push(finding.rule_title.clone());
            severity.push(finding.severity.clone());
            cwe.push(finding.cwe.join(", "));
            standards.push(finding.standards.join(", "));
            source_rule_id.push(finding.source_rule_id.clone());
            source_kind.push(finding.source_kind.clone());
            sink_kind.push(finding.sink_kind.clone());
            source_location.push(finding.source_location.clone());
            sink_location.push(finding.sink_location.clone());
            message.push(finding.message.clone());
            path_length.push(finding.steps.len() as u32);
            analysis_complete.push(finding.analysis_complete);
            completeness.push(format!("{:?}", finding.completeness));
        }
    }

    df![
        "language" => language,
        "finding_kind" => finding_kind,
        "rule_id" => rule_id,
        "rule_title" => rule_title,
        "severity" => severity,
        "cwe" => cwe,
        "standards" => standards,
        "source_rule_id" => source_rule_id,
        "source_kind" => source_kind,
        "sink_kind" => sink_kind,
        "source_location" => source_location,
        "sink_location" => sink_location,
        "message" => message,
        "path_length" => path_length,
        "analysis_complete" => analysis_complete,
        "completeness" => completeness,
    ]
}

fn checker_findings_frame(findings: &[CheckerFinding]) -> PolarsResult<DataFrame> {
    let mut rule_id = Vec::new();
    let mut severity = Vec::new();
    let mut uri = Vec::new();
    let mut line = Vec::new();
    let mut column = Vec::new();
    let mut message = Vec::new();
    let mut fingerprint = Vec::new();
    let mut path_length = Vec::new();

    for finding in findings {
        rule_id.push(finding.rule_id.clone());
        severity.push(finding.level.clone());
        uri.push(finding.location.uri.clone());
        line.push(finding.location.line);
        column.push(finding.location.column);
        message.push(finding.message.clone());
        fingerprint.push(finding.fingerprint.clone().unwrap_or_default());
        path_length.push(finding.code_flow.len() as u32);
    }

    df![
        "rule_id" => rule_id,
        "severity" => severity,
        "uri" => uri,
        "line" => line,
        "column" => column,
        "message" => message,
        "fingerprint" => fingerprint,
        "path_length" => path_length,
    ]
}

fn finding_index_frame(
    sections: &[ExcelReportSection<'_>],
    checker_findings: &[CheckerFinding],
) -> PolarsResult<DataFrame> {
    let mut language = Vec::new();
    let mut provider = Vec::new();
    let mut rule_id = Vec::new();
    let mut severity = Vec::new();

    for section in sections {
        for finding in section.findings {
            language.push(section.name.to_string());
            provider.push(if finding.finding_kind == "lifetime" {
                "builtin-lifetime".to_string()
            } else {
                "builtin-taint".to_string()
            });
            rule_id.push(finding.sink_rule_id.clone());
            severity.push(normalized_severity(&finding.severity, &finding.sink_kind));
        }
    }
    for finding in checker_findings {
        language.push("external".to_string());
        provider.push("external-checker".to_string());
        rule_id.push(finding.rule_id.clone());
        severity.push(if finding.level.trim().is_empty() {
            "warning".to_string()
        } else {
            finding.level.clone()
        });
    }

    df![
        "language" => language,
        "provider" => provider,
        "rule_id" => rule_id,
        "severity" => severity,
    ]
}

fn rule_summary_frame(index: &DataFrame) -> PolarsResult<DataFrame> {
    index
        .clone()
        .lazy()
        .group_by_stable([
            col("language"),
            col("provider"),
            col("rule_id"),
            col("severity"),
        ])
        .agg([len().alias("count")])
        .collect()
}

fn severity_summary_frame(index: &DataFrame) -> PolarsResult<DataFrame> {
    index
        .clone()
        .lazy()
        .group_by_stable([col("language"), col("provider"), col("severity")])
        .agg([len().alias("count")])
        .collect()
}

fn paths_frame(sections: &[ExcelReportSection<'_>]) -> PolarsResult<DataFrame> {
    let mut language = Vec::new();
    let mut finding_index = Vec::new();
    let mut rule_id = Vec::new();
    let mut step_index = Vec::new();
    let mut from_label = Vec::new();
    let mut from_location = Vec::new();
    let mut edge_kind = Vec::new();
    let mut to_label = Vec::new();
    let mut to_location = Vec::new();

    let mut ordinal = 0u32;
    for section in sections {
        for finding in section.findings {
            ordinal += 1;
            for (step, item) in finding.steps.iter().enumerate() {
                language.push(section.name.to_string());
                finding_index.push(ordinal);
                rule_id.push(finding.sink_rule_id.clone());
                step_index.push((step + 1) as u32);
                from_label.push(item.from_label.clone());
                from_location.push(item.from_location.clone());
                edge_kind.push(item.edge_kind.clone());
                to_label.push(item.to_label.clone());
                to_location.push(item.to_location.clone());
            }
        }
    }

    df![
        "language" => language,
        "finding_index" => finding_index,
        "rule_id" => rule_id,
        "step" => step_index,
        "from_label" => from_label,
        "from_location" => from_location,
        "edge_kind" => edge_kind,
        "to_label" => to_label,
        "to_location" => to_location,
    ]
}

fn calls_frame(sections: &[ExcelReportSection<'_>]) -> PolarsResult<DataFrame> {
    let mut language = Vec::new();
    let mut function = Vec::new();
    let mut location = Vec::new();
    let mut callee = Vec::new();
    let mut receiver_type = Vec::new();
    let mut dynamic = Vec::new();
    let mut arg_count = Vec::new();
    let mut resolved_targets = Vec::new();

    for section in sections {
        for call in section.flow.call_report() {
            language.push(section.name.to_string());
            function.push(call.function_name);
            location.push(call.location);
            callee.push(call.callee_name.unwrap_or_else(|| "<dynamic>".to_string()));
            receiver_type.push(call.receiver_type.unwrap_or_default());
            dynamic.push(call.is_dynamic);
            arg_count.push(call.arg_count as u32);
            resolved_targets.push(call.resolved_internal_targets.join(", "));
        }
    }

    df![
        "language" => language,
        "function" => function,
        "location" => location,
        "callee" => callee,
        "receiver_type" => receiver_type,
        "dynamic" => dynamic,
        "arg_count" => arg_count,
        "resolved_internal_targets" => resolved_targets,
    ]
}

fn flow_stats_frame(sections: &[ExcelReportSection<'_>]) -> PolarsResult<DataFrame> {
    let mut language = Vec::new();
    let mut metric = Vec::new();
    let mut value = Vec::new();

    for section in sections {
        let stats = serde_json::to_value(section.flow.stats())
            .map_err(|err| PolarsError::ComputeError(err.to_string().into()))?;
        if let Some(object) = stats.as_object() {
            for (key, item) in object {
                language.push(section.name.to_string());
                metric.push(key.clone());
                value.push(item.as_u64().unwrap_or_default());
            }
        }
    }

    df![
        "language" => language,
        "metric" => metric,
        "value" => value,
    ]
}

fn normalized_severity(severity: &str, sink_kind: &str) -> String {
    if !severity.trim().is_empty() {
        return severity.to_string();
    }
    match sink_kind {
        "critical" | "error" => "error".to_string(),
        "note" | "info" | "informational" => "note".to_string(),
        _ => "warning".to_string(),
    }
}

fn write_summary_sheet(
    workbook: &mut Workbook,
    sections: &[ExcelReportSection<'_>],
    checker_findings: &[CheckerFinding],
    severity_summary: &DataFrame,
) -> Result<(), XlsxError> {
    let title = Format::new()
        .set_bold()
        .set_font_size(18)
        .set_font_color(Color::White)
        .set_foreground_color(Color::RGB(0x17365D));
    let key = Format::new()
        .set_bold()
        .set_foreground_color(Color::RGB(0xD9EAF7))
        .set_border(FormatBorder::Thin);
    let value = Format::new().set_border(FormatBorder::Thin);

    let worksheet = workbook.add_worksheet().set_name("Summary")?;
    worksheet.merge_range(0, 0, 0, 3, "UniFlow Analysis Report", &title)?;
    worksheet.write_string_with_format(2, 0, "Metric", &key)?;
    worksheet.write_string_with_format(2, 1, "Value", &key)?;

    let builtin = sections.iter().map(|section| section.findings.len()).sum::<usize>();
    let metrics = [
        ("Analysis partitions", sections.len() as u64),
        ("Built-in findings", builtin as u64),
        ("External checker findings", checker_findings.len() as u64),
        ("Total findings", (builtin + checker_findings.len()) as u64),
    ];
    for (offset, (name, number)) in metrics.iter().enumerate() {
        let row = 3 + offset as u32;
        worksheet.write_string_with_format(row, 0, *name, &key)?;
        worksheet.write_number_with_format(row, 1, *number as f64, &value)?;
    }
    worksheet.set_column_width(0, 30)?;
    worksheet.set_column_width(1, 16)?;

    // Put the Polars-generated breakdown beside the top-level metrics.
    write_dataframe_at(worksheet, severity_summary, 2, 3)?;
    worksheet.autofit();
    Ok(())
}

fn write_dataframe_sheet(
    workbook: &mut Workbook,
    name: &str,
    df: &DataFrame,
) -> Result<(), XlsxError> {
    let worksheet = workbook.add_worksheet().set_name(name)?;
    write_dataframe_at(worksheet, df, 0, 0)?;
    worksheet.set_freeze_panes(1, 0)?;
    worksheet.autofit();
    Ok(())
}

fn write_dataframe_at(
    worksheet: &mut Worksheet,
    df: &DataFrame,
    start_row: u32,
    start_col: u16,
) -> Result<(), XlsxError> {
    let header = Format::new()
        .set_bold()
        .set_font_color(Color::White)
        .set_foreground_color(Color::RGB(0x1F4E78))
        .set_align(FormatAlign::Center)
        .set_border(FormatBorder::Thin);

    for (col_index, column) in df.columns().iter().enumerate() {
        worksheet.write_string_with_format(
            start_row,
            start_col + col_index as u16,
            column.name().as_str(),
            &header,
        )?;
    }

    for row_index in 0..df.height() {
        for (col_index, column) in df.columns().iter().enumerate() {
            let value = column
                .get(row_index)
                .map_err(|err| XlsxError::ParameterError(err.to_string()))?;
            write_any_value(
                worksheet,
                start_row + 1 + row_index as u32,
                start_col + col_index as u16,
                value,
            )?;
        }
    }
    Ok(())
}

fn write_any_value(
    worksheet: &mut Worksheet,
    row: u32,
    col: u16,
    value: AnyValue<'_>,
) -> Result<(), XlsxError> {
    match value {
        AnyValue::Null => {}
        AnyValue::Boolean(value) => {
            worksheet.write_boolean(row, col, value)?;
        }
        AnyValue::String(value) => {
            worksheet.write_string(row, col, value)?;
        }
        AnyValue::StringOwned(value) => {
            worksheet.write_string(row, col, value.to_string())?;
        }
        AnyValue::UInt8(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::UInt16(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::UInt32(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::UInt64(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::Int8(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::Int16(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::Int32(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::Int64(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::Float32(value) => {
            worksheet.write_number(row, col, value as f64)?;
        }
        AnyValue::Float64(value) => {
            worksheet.write_number(row, col, value)?;
        }
        other => {
            worksheet.write_string(row, col, other.str_value().into_owned())?;
        }
    }
    Ok(())
}
