use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

use serde::{Deserialize, Serialize};
use sxd_document::Package;
use sxd_xpath::{Context as XPathContext, Factory as XPathFactory, Value as XPathValue};
use uniflow_parser_core::{
    sql_syntax::{SqlBranch, SqlIf, SqlSyntax},
    TokKind,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlStyleCheck {
    AddParenthesesInNestedExpression,
    CollapsibleIfStatements,
    ConcatenationWithNull,
    DeclareSectionWithoutDeclarations,
    DuplicateConditionIfElsif,
    DuplicatedValueInIn,
    EmptyBlock,
    ExplicitInParameter,
    FunctionWithOutParameter,
    IdenticalExpression,
    IfWithExit,
    ReturnOfBooleanExpression,
    SameBranch,
    SameCondition,
    SelectWithRownumAndOrderBy,
    UnnecessaryElse,
    UnnecessaryNullStatement,
    UselessParenthesis,
    VariableInitializationWithFunctionCall,
    VariableInitializationWithNull,
    CommitRollback,
    ColumnsShouldHaveTableName,
    CursorBodyInPackageSpec,
    DeadCode,
    DisabledTest,
    NotASelectedExpression,
    NotFound,
    ParsingError,
    QueryWithoutExceptionHandling,
    RaiseStandardException,
    RedundantExpectation,
    TooManyRowsHandler,
    UnhandledUserDefinedException,
    UnnecessaryAliasInQuery,
    UnusedCursor,
    UnusedParameter,
    UnusedVariable,
    VariableHiding,
    VariableInCount,
    VariableName,
    InvalidReferenceToObject,
    #[serde(rename = "xpath")]
    XPath,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleFormsBlock {
    pub name: String,
    #[serde(default)]
    pub items: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OracleFormsMetadata {
    #[serde(default)]
    pub alerts: Vec<String>,
    #[serde(default)]
    pub blocks: Vec<OracleFormsBlock>,
    #[serde(default)]
    pub lovs: Vec<String>,
}

impl SqlStyleCheck {
    pub(crate) fn matches(
        self,
        syntax: &SqlSyntax,
        forms: Option<&OracleFormsMetadata>,
        xpath_query: &str,
        xpath_message: &str,
    ) -> Vec<(usize, Option<String>)> {
        if matches!(self, Self::InvalidReferenceToObject) {
            return forms
                .map(|forms| invalid_object_reference_offsets(syntax, forms))
                .unwrap_or_default();
        }
        if matches!(self, Self::XPath) {
            if xpath_query.is_empty() {
                return Vec::new();
            }
            let message = (!xpath_message.is_empty()).then(|| xpath_message.to_string());
            return evaluate_xpath(syntax, xpath_query)
                .unwrap_or_default()
                .into_iter()
                .map(|offset| (offset, message.clone()))
                .collect();
        }
        let token_indices = match self {
            Self::AddParenthesesInNestedExpression => mixed_boolean_offsets(syntax),
            Self::CollapsibleIfStatements => collapsible_if_offsets(syntax),
            Self::ConcatenationWithNull => concatenation_null_offsets(syntax),
            Self::DeclareSectionWithoutDeclarations => empty_declare_offsets(syntax),
            Self::DuplicateConditionIfElsif => duplicate_branch_condition_offsets(syntax),
            Self::DuplicatedValueInIn => duplicated_in_offsets(syntax),
            Self::EmptyBlock => empty_block_offsets(syntax),
            Self::ExplicitInParameter => parameter_offsets(syntax, false),
            Self::FunctionWithOutParameter => parameter_offsets(syntax, true),
            Self::IdenticalExpression => identical_expression_offsets(syntax),
            Self::IfWithExit => if_with_exit_offsets(syntax),
            Self::ReturnOfBooleanExpression => boolean_return_offsets(syntax),
            Self::SameBranch => same_branch_offsets(syntax),
            Self::SameCondition => same_condition_offsets(syntax),
            Self::SelectWithRownumAndOrderBy => rownum_order_offsets(syntax),
            Self::UnnecessaryElse => unnecessary_else_offsets(syntax),
            Self::UnnecessaryNullStatement => unnecessary_null_offsets(syntax),
            Self::UselessParenthesis => useless_parenthesis_offsets(syntax),
            Self::VariableInitializationWithFunctionCall => {
                declaration_initializer_offsets(syntax, true)
            }
            Self::VariableInitializationWithNull => declaration_initializer_offsets(syntax, false),
            Self::CommitRollback => commit_rollback_offsets(syntax),
            Self::ColumnsShouldHaveTableName => unqualified_column_offsets(syntax),
            Self::CursorBodyInPackageSpec => package_cursor_body_offsets(syntax),
            Self::DeadCode => dead_code_offsets(syntax),
            Self::DisabledTest => syntax.unexplained_disabled_tests.clone(),
            Self::NotASelectedExpression => distinct_order_offsets(syntax),
            Self::NotFound => not_found_offsets(syntax),
            Self::ParsingError => syntax.parse_errors.clone(),
            Self::QueryWithoutExceptionHandling => query_without_handler_offsets(syntax),
            Self::RaiseStandardException => raise_standard_offsets(syntax),
            Self::RedundantExpectation => redundant_expectation_offsets(syntax),
            Self::TooManyRowsHandler => too_many_rows_handler_offsets(syntax),
            Self::UnhandledUserDefinedException => unhandled_exception_offsets(syntax),
            Self::UnnecessaryAliasInQuery => unnecessary_alias_offsets(syntax),
            Self::UnusedCursor => unused_declaration_offsets(syntax, DeclarationKind::Cursor),
            Self::UnusedParameter => unused_parameter_offsets(syntax),
            Self::UnusedVariable => unused_declaration_offsets(syntax, DeclarationKind::Variable),
            Self::VariableHiding => variable_hiding_offsets(syntax),
            Self::VariableInCount => variable_in_count_offsets(syntax),
            Self::VariableName => variable_name_offsets(syntax),
            Self::InvalidReferenceToObject => unreachable!(),
            Self::XPath => unreachable!(),
        };
        let mut offsets = token_indices
            .into_iter()
            .filter_map(|index| syntax.tokens.get(index).map(|token| token.start))
            .collect::<Vec<_>>();
        offsets.sort_unstable();
        offsets.dedup();
        offsets.into_iter().map(|offset| (offset, None)).collect()
    }
}

pub(crate) fn validate_xpath(query: &str) -> Result<(), String> {
    let xpath = XPathFactory::new()
        .build(query)
        .map_err(|error| error.to_string())?;
    xpath
        .map(|_| ())
        .ok_or_else(|| "XPath query is empty".to_string())
}

fn evaluate_xpath(syntax: &SqlSyntax, query: &str) -> Result<Vec<usize>, String> {
    let package = sql_xpath_document(syntax);
    let document = package.as_document();
    let root = document
        .root()
        .children()
        .into_iter()
        .find_map(|node| node.element())
        .ok_or_else(|| "SQL XPath document has no root".to_string())?;
    let xpath = XPathFactory::new()
        .build(query)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "XPath query is empty".to_string())?;
    let value = xpath
        .evaluate(&XPathContext::new(), root)
        .map_err(|error| error.to_string())?;
    let mut offsets = match value {
        XPathValue::Nodeset(nodes) => nodes
            .document_order()
            .into_iter()
            .filter_map(|node| node.element())
            .filter_map(|element| element.attribute_value("offset"))
            .filter_map(|offset| offset.parse::<usize>().ok())
            .collect(),
        XPathValue::Boolean(true) => vec![0],
        XPathValue::Boolean(false) | XPathValue::Number(_) | XPathValue::String(_) => Vec::new(),
    };
    offsets.sort_unstable();
    offsets.dedup();
    Ok(offsets)
}

fn sql_xpath_document(syntax: &SqlSyntax) -> Package {
    let package = Package::new();
    let document = package.as_document();
    let root = document.create_element("FILE");
    root.set_attribute_value("offset", "0");
    document.root().append_child(root);

    let mut start = 0;
    for end in (0..syntax.tokens.len())
        .filter(|index| syntax.is(*index, ";"))
        .map(|index| index + 1)
        .chain(std::iter::once(syntax.tokens.len()))
    {
        if let Some(first) = syntax
            .tokens
            .get(start..end)
            .and_then(|tokens| tokens.first())
        {
            let statement = document.create_element("STATEMENT");
            statement.set_attribute_value("offset", &first.start.to_string());
            for token in &syntax.tokens[start..end] {
                let node = document.create_element("TOKEN");
                node.set_attribute_value("offset", &token.start.to_string());
                node.set_attribute_value("kind", &format!("{:?}", token.kind));
                node.append_child(document.create_text(&token.original_text));
                statement.append_child(node);
            }
            root.append_child(statement);
        }
        start = end;
    }
    for item in &syntax.ifs {
        let node = document.create_element("IF");
        if let Some(token) = syntax.tokens.get(item.start) {
            node.set_attribute_value("offset", &token.start.to_string());
            root.append_child(node);
        }
    }
    for item in &syntax.blocks {
        let node = document.create_element("BLOCK");
        if let Some(token) = syntax.tokens.get(item.start) {
            node.set_attribute_value("offset", &token.start.to_string());
            root.append_child(node);
        }
    }
    package
}

#[derive(Clone, Copy)]
enum FormsObjectKind {
    Alert,
    Block,
    Item,
    Lov,
}

fn invalid_object_reference_offsets(
    syntax: &SqlSyntax,
    forms: &OracleFormsMetadata,
) -> Vec<(usize, Option<String>)> {
    const CALLS: &[(&str, &[usize], usize, FormsObjectKind)] = &[
        ("find_alert", &[1], 0, FormsObjectKind::Alert),
        ("set_alert_button_property", &[4], 0, FormsObjectKind::Alert),
        ("set_alert_property", &[3], 0, FormsObjectKind::Alert),
        ("show_alert", &[1], 0, FormsObjectKind::Alert),
        ("find_lov", &[1], 0, FormsObjectKind::Lov),
        ("get_lov_property", &[2], 0, FormsObjectKind::Lov),
        ("set_lov_column_property", &[4], 0, FormsObjectKind::Lov),
        ("set_lov_property", &[3, 4], 0, FormsObjectKind::Lov),
        ("show_lov", &[1], 0, FormsObjectKind::Lov),
        ("find_block", &[1], 0, FormsObjectKind::Block),
        ("get_block_property", &[2], 0, FormsObjectKind::Block),
        ("go_block", &[1], 0, FormsObjectKind::Block),
        ("set_block_property", &[3, 4], 0, FormsObjectKind::Block),
        ("checkbox_checked", &[1], 0, FormsObjectKind::Item),
        ("convert_other_value", &[1], 0, FormsObjectKind::Item),
        ("display_item", &[2], 0, FormsObjectKind::Item),
        ("find_item", &[1], 0, FormsObjectKind::Item),
        ("get_item_instance_property", &[3], 0, FormsObjectKind::Item),
        ("get_item_property", &[2], 0, FormsObjectKind::Item),
        ("get_radio_button_property", &[3], 0, FormsObjectKind::Item),
        ("go_item", &[1], 0, FormsObjectKind::Item),
        ("image_scroll", &[3], 0, FormsObjectKind::Item),
        ("image_zoom", &[2, 3], 0, FormsObjectKind::Item),
        ("play_sound", &[1], 0, FormsObjectKind::Item),
        ("read_image_file", &[3], 2, FormsObjectKind::Item),
        ("read_sound_file", &[3], 2, FormsObjectKind::Item),
        ("recalculate", &[1], 0, FormsObjectKind::Item),
        ("set_item_instance_property", &[4], 0, FormsObjectKind::Item),
        ("set_item_property", &[3, 4], 0, FormsObjectKind::Item),
        (
            "set_radio_button_property",
            &[4, 5],
            0,
            FormsObjectKind::Item,
        ),
        ("write_image_file", &[5], 2, FormsObjectKind::Item),
        ("write_sound_file", &[5], 2, FormsObjectKind::Item),
    ];

    let mut result = Vec::new();
    for (index, token) in syntax.tokens.iter().enumerate() {
        let Some((name, arities, argument_index, kind)) = CALLS
            .iter()
            .find(|(name, _, _, _)| token.text.eq_ignore_ascii_case(name))
        else {
            continue;
        };
        if !syntax.is(index + 1, "(") {
            continue;
        }
        let Some(close) = syntax.mates.get(index + 1).copied().flatten() else {
            continue;
        };
        let arguments = syntax.split_top_level(index + 2..close, ",");
        if !arities.contains(&arguments.len()) {
            continue;
        }
        let Some(argument) = arguments.get(*argument_index) else {
            continue;
        };
        let argument = significant_range(syntax, argument.clone());
        if argument.end != argument.start + 1 {
            continue;
        }
        let Some(value_token) = syntax.tokens.get(argument.start) else {
            continue;
        };
        if value_token.kind != TokKind::StringLit {
            continue;
        }
        let value = sql_string_value(&value_token.original_text);
        if forms_object_exists(forms, *kind, &value) {
            continue;
        }
        result.push((
            value_token.start,
            Some(format!(
                "Invalid reference to the object \"{value}\" in this {} call.",
                name.to_ascii_uppercase()
            )),
        ));
    }
    result
}

fn sql_string_value(text: &str) -> String {
    let unquoted = text
        .strip_prefix('\'')
        .and_then(|text| text.strip_suffix('\''))
        .unwrap_or(text);
    unquoted.replace("''", "'")
}

fn forms_object_exists(forms: &OracleFormsMetadata, kind: FormsObjectKind, value: &str) -> bool {
    match kind {
        FormsObjectKind::Alert => forms
            .alerts
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value)),
        FormsObjectKind::Block => forms
            .blocks
            .iter()
            .any(|candidate| candidate.name.eq_ignore_ascii_case(value)),
        FormsObjectKind::Lov => forms
            .lovs
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value)),
        FormsObjectKind::Item => forms.blocks.iter().any(|block| {
            block
                .items
                .iter()
                .any(|item| format!("{}.{}", block.name, item).eq_ignore_ascii_case(value))
        }),
    }
}

fn parent_group(syntax: &SqlSyntax, index: usize) -> Option<(usize, usize)> {
    syntax
        .mates
        .iter()
        .enumerate()
        .filter_map(|(open, close)| close.map(|close| (open, close)))
        .filter(|(open, close)| *open < index && index < *close)
        .min_by_key(|(open, close)| close - open)
}

fn mixed_boolean_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut groups: HashMap<Option<(usize, usize)>, (Vec<usize>, Vec<usize>)> = HashMap::new();
    for index in 0..syntax.tokens.len() {
        if syntax.is(index, "and") || syntax.is(index, "or") {
            let entry = groups.entry(parent_group(syntax, index)).or_default();
            if syntax.is(index, "and") {
                entry.0.push(index);
            } else {
                entry.1.push(index);
            }
        }
    }
    groups
        .into_values()
        .filter(|(ands, ors)| !ands.is_empty() && !ors.is_empty())
        .flat_map(|(ands, _)| ands.into_iter().take(1))
        .collect()
}

fn significant_range(syntax: &SqlSyntax, range: Range<usize>) -> Range<usize> {
    let mut start = range.start;
    let mut end = range.end;
    while start < end && syntax.is(start, ";") {
        start += 1;
    }
    while start < end && syntax.is(end - 1, ";") {
        end -= 1;
    }
    start..end
}

fn normalized(syntax: &SqlSyntax, range: Range<usize>) -> String {
    syntax.normalized(syntax.trim_parens(significant_range(syntax, range)))
}

fn collapsible_if_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    syntax
        .ifs
        .iter()
        .filter(|outer| outer.branches.len() == 1)
        .filter_map(|outer| {
            let body = significant_range(syntax, outer.branches[0].body.clone());
            syntax
                .ifs
                .iter()
                .find(|inner| inner.start == body.start && inner.end == body.end)
                .map(|_| outer.start)
        })
        .collect()
}

fn is_null_or_empty(syntax: &SqlSyntax, index: usize) -> bool {
    syntax.is(index, "null")
        || syntax.tokens.get(index).is_some_and(|token| {
            token.kind == TokKind::StringLit && matches!(token.text.as_str(), "''" | "\"\"")
        })
}

fn concatenation_null_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    (0..syntax.tokens.len())
        .filter(|index| {
            syntax.is(*index, "||")
                && (index
                    .checked_sub(1)
                    .is_some_and(|left| is_null_or_empty(syntax, left))
                    || is_null_or_empty(syntax, index + 1))
        })
        .collect()
}

fn empty_declare_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    (0..syntax.tokens.len())
        .filter(|index| syntax.is(*index, "declare") && syntax.is(index + 1, "begin"))
        .collect()
}

fn duplicate_branch_condition_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for item in &syntax.ifs {
        let mut seen = HashSet::new();
        for branch in &item.branches {
            if let Some(condition) = &branch.condition {
                let value = normalized(syntax, condition.clone());
                if !value.is_empty() && !seen.insert(value) {
                    offsets.push(branch.marker);
                }
            }
        }
    }
    offsets
}

fn duplicated_in_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for index in 0..syntax.tokens.len().saturating_sub(1) {
        if !syntax.is(index, "in") || !syntax.is(index + 1, "(") {
            continue;
        }
        let Some(close) = syntax.mates[index + 1] else {
            continue;
        };
        let mut seen = HashSet::new();
        for part in syntax.split_top_level(index + 2..close, ",") {
            let value = normalized(syntax, part);
            if !value.is_empty() && !seen.insert(value) {
                offsets.push(index);
                break;
            }
        }
    }
    offsets
}

fn empty_block_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    syntax
        .blocks
        .iter()
        .filter(|block| normalized(syntax, block.body.clone()) == "null")
        .map(|block| block.start)
        .collect()
}

fn routine_parameter_groups(syntax: &SqlSyntax) -> Vec<(bool, Vec<Range<usize>>)> {
    let mut result = Vec::new();
    for index in 0..syntax.tokens.len() {
        let is_function = syntax.is(index, "function");
        if !is_function && !syntax.is(index, "procedure") {
            continue;
        }
        let Some(open) =
            (index + 1..syntax.tokens.len()).find(|candidate| syntax.is(*candidate, "("))
        else {
            continue;
        };
        if (index + 1..open).any(|candidate| syntax.is(candidate, ";")) {
            continue;
        }
        let Some(close) = syntax.mates[open] else {
            continue;
        };
        result.push((is_function, syntax.split_top_level(open + 1..close, ",")));
    }
    result
}

fn parameter_offsets(syntax: &SqlSyntax, out_in_function: bool) -> Vec<usize> {
    let mut offsets = Vec::new();
    for (is_function, parameters) in routine_parameter_groups(syntax) {
        if out_in_function && !is_function {
            continue;
        }
        for parameter in parameters {
            let parameter = significant_range(syntax, parameter);
            if parameter.start >= parameter.end {
                continue;
            }
            let has_out = (parameter.clone())
                .any(|index| syntax.is(index, "out") || syntax.is(index, "inout"));
            let has_mode = has_out || (parameter.clone()).any(|index| syntax.is(index, "in"));
            if (out_in_function && has_out) || (!out_in_function && !has_mode) {
                offsets.push(parameter.start);
            }
        }
    }
    offsets
}

fn operand_left(syntax: &SqlSyntax, operator: usize) -> Option<Range<usize>> {
    let end = operator;
    let mut start = operator.checked_sub(1)?;
    if syntax.is(start, ")") {
        start = syntax.mates[start]?;
    } else {
        while start > 0 && !is_operand_boundary(syntax, start - 1) {
            start -= 1;
        }
    }
    Some(start..end)
}

fn operand_right(syntax: &SqlSyntax, operator: usize) -> Option<Range<usize>> {
    let start = operator + 1;
    if start >= syntax.tokens.len() {
        return None;
    }
    if syntax.is(start, "(") {
        return syntax.mates[start].map(|close| start..close + 1);
    }
    let mut end = start + 1;
    while end < syntax.tokens.len() && !is_operand_boundary(syntax, end) {
        end += 1;
    }
    Some(start..end)
}

fn is_operand_boundary(syntax: &SqlSyntax, index: usize) -> bool {
    matches!(
        syntax.tokens[index].text.as_str(),
        ";" | ","
            | "if"
            | "elsif"
            | "where"
            | "having"
            | "and"
            | "or"
            | "then"
            | "when"
            | "="
            | "!="
            | "<>"
            | "<"
            | ">"
            | "<="
            | ">="
    )
}

fn identical_expression_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    (0..syntax.tokens.len())
        .filter(|index| {
            matches!(
                syntax.tokens[*index].text.as_str(),
                "=" | "!=" | "<>" | "<" | ">" | "<=" | ">="
            )
        })
        .filter(|index| {
            operand_left(syntax, *index)
                .zip(operand_right(syntax, *index))
                .is_some_and(|(left, right)| normalized(syntax, left) == normalized(syntax, right))
        })
        .collect()
}

fn body_is(syntax: &SqlSyntax, branch: &SqlBranch, expected: &str) -> bool {
    normalized(syntax, branch.body.clone()) == expected
}

fn if_with_exit_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    syntax
        .ifs
        .iter()
        .filter(|item| item.branches.len() == 1 && body_is(syntax, &item.branches[0], "exit"))
        .map(|item| item.start)
        .collect()
}

fn boolean_return_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    syntax
        .ifs
        .iter()
        .filter(|item| item.branches.len() == 2 && item.branches[1].condition.is_none())
        .filter(|item| {
            let first = normalized(syntax, item.branches[0].body.clone());
            let second = normalized(syntax, item.branches[1].body.clone());
            matches!(
                (first.as_str(), second.as_str()),
                ("return\u{1f}true", "return\u{1f}false")
                    | ("return\u{1f}false", "return\u{1f}true")
            )
        })
        .map(|item| item.start)
        .collect()
}

fn same_branch_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for item in &syntax.ifs {
        let mut seen = HashSet::new();
        for branch in &item.branches {
            let value = normalized(syntax, branch.body.clone());
            if !value.is_empty() && !seen.insert(value) {
                offsets.push(branch.marker);
            }
        }
    }
    offsets
}

fn same_condition_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for item in &syntax.ifs {
        for branch in &item.branches {
            let Some(condition) = &branch.condition else {
                continue;
            };
            for operator in ["and", "or"] {
                let parts = syntax.split_top_level(condition.clone(), operator);
                let mut seen = HashSet::new();
                for part in parts {
                    let value = normalized(syntax, part);
                    if !value.is_empty() && !seen.insert(value) {
                        offsets.push(branch.marker);
                        break;
                    }
                }
            }
        }
    }
    offsets
}

fn rownum_order_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for select in (0..syntax.tokens.len()).filter(|index| syntax.is(*index, "select")) {
        let group = parent_group(syntax, select);
        let end = group.map_or_else(
            || syntax.statement_range_containing(select).end,
            |(_, close)| close,
        );
        let same_scope = |index: usize| parent_group(syntax, index) == group;
        let rownum = (select + 1..end).any(|index| syntax.is(index, "rownum") && same_scope(index));
        let order = (select + 1..end.saturating_sub(1)).any(|index| {
            syntax.is(index, "order") && syntax.is(index + 1, "by") && same_scope(index)
        });
        if rownum && order {
            offsets.push(select);
        }
    }
    offsets
}

fn branch_starts_with_terminal(syntax: &SqlSyntax, branch: &SqlBranch) -> bool {
    let range = significant_range(syntax, branch.body.clone());
    range.start < range.end
        && matches!(
            syntax.tokens[range.start].text.as_str(),
            "return" | "raise" | "exit"
        )
}

fn unnecessary_else_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    syntax
        .ifs
        .iter()
        .flat_map(|item| {
            item.branches
                .iter()
                .enumerate()
                .filter_map(|(index, branch)| {
                    (branch.condition.is_none()
                        && index > 0
                        && item.branches[..index]
                            .iter()
                            .all(|prior| branch_starts_with_terminal(syntax, prior)))
                    .then_some(branch.marker)
                })
        })
        .collect()
}

fn unnecessary_null_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for index in (0..syntax.tokens.len())
        .filter(|index| syntax.is(*index, "null") && syntax.is(index + 1, ";"))
    {
        let owner = syntax
            .blocks
            .iter()
            .filter(|block| block.body.start <= index && index < block.body.end)
            .min_by_key(|block| block.body.end - block.body.start);
        if owner.is_some_and(|block| normalized(syntax, block.body.clone()) != "null") {
            offsets.push(index);
        }
    }
    offsets
}

fn useless_parenthesis_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    (0..syntax.tokens.len().saturating_sub(1))
        .filter(|index| {
            syntax.is(*index, "(")
                && syntax.is(index + 1, "(")
                && syntax.mates[*index]
                    .zip(syntax.mates[index + 1])
                    .is_some_and(|(outer, inner)| outer == inner + 1)
        })
        .collect()
}

fn declaration_sections(syntax: &SqlSyntax) -> Vec<Range<usize>> {
    let mut result = Vec::new();
    for declare in (0..syntax.tokens.len()).filter(|index| syntax.is(*index, "declare")) {
        if let Some(begin) =
            (declare + 1..syntax.tokens.len()).find(|index| syntax.is(*index, "begin"))
        {
            result.push(declare + 1..begin);
        }
    }
    result
}

fn declaration_initializer_offsets(syntax: &SqlSyntax, require_call: bool) -> Vec<usize> {
    let mut offsets = Vec::new();
    for section in declaration_sections(syntax) {
        let mut start = section.start;
        for end in (section.start..=section.end)
            .filter(|index| *index == section.end || syntax.is(*index, ";"))
        {
            if let Some(assign) = (start..end).find(|index| syntax.is(*index, ":=")) {
                let rhs = assign + 1..end;
                let is_null = normalized(syntax, rhs.clone()) == "null";
                let has_call = (rhs.start..rhs.end.saturating_sub(1)).any(|index| {
                    matches!(syntax.tokens[index].kind, TokKind::Ident | TokKind::Keyword)
                        && syntax.is(index + 1, "(")
                });
                if (require_call && has_call) || (!require_call && is_null) {
                    offsets.push(assign);
                }
            }
            start = end.saturating_add(1);
        }
    }
    offsets
}

fn token_count(syntax: &SqlSyntax, name: &str) -> usize {
    syntax
        .tokens
        .iter()
        .filter(|token| token.text.eq_ignore_ascii_case(name))
        .count()
}

fn commit_rollback_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    (0..syntax.tokens.len())
        .filter(|index| matches!(syntax.tokens[*index].text.as_str(), "commit" | "rollback"))
        .filter(|index| {
            syntax
                .blocks
                .iter()
                .any(|block| block.body.start <= *index && *index < block.body.end)
        })
        .filter(|index| {
            let routine_start = (0..*index)
                .rev()
                .find(|candidate| {
                    syntax.is(*candidate, "procedure") || syntax.is(*candidate, "function")
                })
                .unwrap_or(0);
            !(routine_start..*index).any(|candidate| {
                syntax.is(candidate, "pragma") && syntax.is(candidate + 1, "autonomous_transaction")
            })
        })
        .collect()
}

fn select_ranges(syntax: &SqlSyntax) -> Vec<(usize, usize, usize, Option<usize>)> {
    let mut ranges = Vec::new();
    for select in (0..syntax.tokens.len()).filter(|index| syntax.is(*index, "select")) {
        let group = parent_group(syntax, select);
        let end = group.map_or_else(
            || syntax.statement_range_containing(select).end,
            |(_, close)| close,
        );
        let from = (select + 1..end)
            .find(|index| syntax.is(*index, "from") && parent_group(syntax, *index) == group);
        if let Some(from) = from {
            ranges.push((select, from, end, group.map(|(open, _)| open)));
        }
    }
    ranges
}

fn unqualified_column_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for (select, from, _, _) in select_ranges(syntax) {
        let start = if syntax.is(select + 1, "distinct") {
            select + 2
        } else {
            select + 1
        };
        for item in syntax.split_top_level(start..from, ",") {
            let item = significant_range(syntax, item);
            if item.start >= item.end {
                continue;
            }
            let expression_end = (item.clone())
                .find(|index| syntax.is(*index, "as"))
                .unwrap_or(item.end);
            let has_dot = (item.start..expression_end).any(|index| syntax.is(index, "."));
            let has_call = (item.start..expression_end.saturating_sub(1))
                .any(|index| syntax.is(index + 1, "("));
            if !has_dot
                && !has_call
                && expression_end == item.start + 1
                && syntax.tokens[item.start].kind == TokKind::Ident
            {
                offsets.push(item.start);
            }
        }
    }
    offsets
}

fn package_cursor_body_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for package in (0..syntax.tokens.len())
        .filter(|index| syntax.is(*index, "package") && !syntax.is(index + 1, "body"))
    {
        let end = (package + 1..syntax.tokens.len())
            .find(|index| syntax.is(*index, "end"))
            .unwrap_or(syntax.tokens.len());
        for cursor in (package + 1..end).filter(|index| syntax.is(*index, "cursor")) {
            let statement_end = (cursor..end)
                .find(|index| syntax.is(*index, ";"))
                .unwrap_or(end);
            if (cursor..statement_end).any(|index| syntax.is(index, "select")) {
                offsets.push(cursor);
            }
        }
    }
    offsets
}

fn dead_code_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for terminal in (0..syntax.tokens.len()).filter(|index| {
        matches!(
            syntax.tokens[*index].text.as_str(),
            "return" | "raise" | "exit" | "continue"
        )
    }) {
        let Some(semi) = (terminal..syntax.tokens.len()).find(|index| syntax.is(*index, ";"))
        else {
            continue;
        };
        let next = semi + 1;
        if next < syntax.tokens.len()
            && !matches!(
                syntax.tokens[next].text.as_str(),
                "end" | "elsif" | "else" | "exception" | "when"
            )
        {
            let owner = syntax
                .blocks
                .iter()
                .filter(|block| block.body.start <= terminal && terminal < block.body.end)
                .min_by_key(|block| block.body.end - block.body.start);
            if owner.is_some_and(|block| next < block.body.end) {
                offsets.push(next);
            }
        }
    }
    offsets
}

fn projection_values(syntax: &SqlSyntax, start: usize, end: usize) -> HashSet<String> {
    let mut values = HashSet::new();
    for item in syntax.split_top_level(start..end, ",") {
        let as_index = (item.clone()).find(|index| syntax.is(*index, "as"));
        let expression_end = as_index.unwrap_or(item.end);
        values.insert(normalized(syntax, item.start..expression_end));
        if let Some(as_index) = as_index {
            if as_index + 1 < item.end {
                values.insert(normalized(syntax, as_index + 1..item.end));
            }
        }
    }
    values
}

fn distinct_order_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for (select, from, end, _) in select_ranges(syntax) {
        if !syntax.is(select + 1, "distinct") {
            continue;
        }
        let selected = projection_values(syntax, select + 2, from);
        let Some(order) = (from + 1..end.saturating_sub(1))
            .find(|index| syntax.is(*index, "order") && syntax.is(index + 1, "by"))
        else {
            continue;
        };
        for item in syntax.split_top_level(order + 2..end, ",") {
            let mut item = significant_range(syntax, item);
            if item.end > item.start
                && matches!(syntax.tokens[item.end - 1].text.as_str(), "asc" | "desc")
            {
                item.end -= 1;
            }
            if !selected.contains(&normalized(syntax, item)) {
                offsets.push(order);
                break;
            }
        }
    }
    offsets
}

fn not_found_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    (0..syntax.tokens.len().saturating_sub(3))
        .filter(|index| {
            syntax.is(*index, "not") && syntax.is(index + 2, "%") && syntax.is(index + 3, "found")
        })
        .collect()
}

fn query_without_handler_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for select in (0..syntax.tokens.len()).filter(|index| syntax.is(*index, "select")) {
        let statement = syntax.statement_range_containing(select);
        if !(select..statement.end).any(|index| syntax.is(index, "into")) {
            continue;
        }
        let owner = syntax
            .blocks
            .iter()
            .filter(|block| block.body.start <= select && select < block.body.end)
            .min_by_key(|block| block.body.end - block.body.start);
        if !owner.is_some_and(|block| {
            (select..block.body.end).any(|index| syntax.is(index, "exception"))
        }) {
            offsets.push(select);
        }
    }
    offsets
}

fn raise_standard_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    const STANDARD: &[&str] = &[
        "too_many_rows",
        "no_data_found",
        "dup_val_on_index",
        "invalid_cursor",
        "zero_divide",
        "value_error",
        "cursor_already_open",
        "login_denied",
        "not_logged_on",
        "program_error",
        "rowtype_mismatch",
        "self_is_null",
        "storage_error",
        "subscript_beyond_count",
        "subscript_outside_limit",
        "sys_invalid_rowid",
        "timeout_on_resource",
    ];
    (0..syntax.tokens.len().saturating_sub(1))
        .filter(|index| {
            syntax.is(*index, "raise") && STANDARD.iter().any(|name| syntax.is(index + 1, name))
        })
        .collect()
}

fn argument_before_close(syntax: &SqlSyntax, open: usize) -> Option<Range<usize>> {
    let close = syntax.mates.get(open).and_then(|mate| *mate)?;
    Some(open + 1..close)
}

fn redundant_expectation_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for expect in (0..syntax.tokens.len().saturating_sub(1))
        .filter(|index| syntax.is(*index, "expect") && syntax.is(index + 1, "("))
    {
        let Some(actual) = argument_before_close(syntax, expect + 1) else {
            continue;
        };
        let close = syntax.mates[expect + 1].unwrap();
        let matcher = (close + 1..syntax.tokens.len().saturating_sub(1))
            .take(4)
            .find(|index| {
                matches!(
                    syntax.tokens[*index].text.as_str(),
                    "to_equal" | "to_be" | "equal"
                ) && syntax.is(index + 1, "(")
            });
        if let Some(matcher) =
            matcher.and_then(|matcher| argument_before_close(syntax, matcher + 1))
        {
            if normalized(syntax, actual) == normalized(syntax, matcher) {
                offsets.push(expect);
            }
        }
    }
    offsets
}

fn too_many_rows_handler_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for when in (0..syntax.tokens.len().saturating_sub(2)).filter(|index| {
        syntax.is(*index, "when")
            && syntax.is(index + 1, "too_many_rows")
            && syntax.is(index + 2, "then")
    }) {
        let end = (when + 3..syntax.tokens.len())
            .find(|index| syntax.is(*index, "when") || syntax.is(*index, "end"))
            .unwrap_or(syntax.tokens.len());
        if normalized(syntax, when + 3..end) == "null" {
            offsets.push(when);
        }
    }
    offsets
}

fn unhandled_exception_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for index in 0..syntax.tokens.len().saturating_sub(1) {
        if syntax.tokens[index].kind != TokKind::Ident || !syntax.is(index + 1, "exception") {
            continue;
        }
        let name = syntax.tokens[index].text.as_str();
        let raised = (0..syntax.tokens.len().saturating_sub(1))
            .any(|candidate| syntax.is(candidate, "raise") && syntax.is(candidate + 1, name));
        let handled = (0..syntax.tokens.len().saturating_sub(1))
            .any(|candidate| syntax.is(candidate, "when") && syntax.is(candidate + 1, name));
        if raised && !handled {
            offsets.push(index);
        }
    }
    offsets
}

fn unnecessary_alias_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for (_, from, end, _) in select_ranges(syntax) {
        let clause_end = (from + 1..end)
            .find(|index| {
                matches!(
                    syntax.tokens[*index].text.as_str(),
                    "where" | "group" | "order" | "having"
                )
            })
            .unwrap_or(end);
        let mut tables = Vec::<(String, usize, String)>::new();
        for item in syntax.split_top_level(from + 1..clause_end, ",") {
            let item = significant_range(syntax, item);
            if item.end == item.start + 2
                && syntax.tokens[item.start].kind == TokKind::Ident
                && syntax.tokens[item.start + 1].kind == TokKind::Ident
            {
                tables.push((
                    syntax.tokens[item.start].text.clone(),
                    item.start + 1,
                    syntax.tokens[item.start + 1].text.clone(),
                ));
            }
        }
        let self_join = tables
            .iter()
            .enumerate()
            .any(|(i, (name, _, _))| tables.iter().skip(i + 1).any(|(other, _, _)| other == name));
        if !self_join {
            offsets.extend(
                tables
                    .into_iter()
                    .filter(|(_, _, alias)| alias.len() == 1)
                    .map(|(_, offset, _)| offset),
            );
        }
    }
    offsets
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DeclarationKind {
    Cursor,
    Variable,
}

fn declared_items(syntax: &SqlSyntax) -> Vec<(DeclarationKind, usize, String)> {
    let mut items = Vec::new();
    for section in declaration_sections(syntax) {
        let mut start = section.start;
        for end in (section.start..=section.end)
            .filter(|index| *index == section.end || syntax.is(*index, ";"))
        {
            if start < end {
                let (kind, name_index) = if syntax.is(start, "cursor") {
                    (DeclarationKind::Cursor, start + 1)
                } else {
                    (DeclarationKind::Variable, start)
                };
                if syntax
                    .tokens
                    .get(name_index)
                    .is_some_and(|token| token.kind == TokKind::Ident)
                    && !matches!(
                        syntax.tokens[name_index].text.as_str(),
                        "pragma" | "type" | "subtype"
                    )
                    && !syntax.is(name_index + 1, "exception")
                {
                    items.push((kind, name_index, syntax.tokens[name_index].text.clone()));
                }
            }
            start = end.saturating_add(1);
        }
    }
    items
}

fn unused_declaration_offsets(syntax: &SqlSyntax, wanted: DeclarationKind) -> Vec<usize> {
    declared_items(syntax)
        .into_iter()
        .filter(|(kind, _, name)| *kind == wanted && token_count(syntax, name) == 1)
        .map(|(_, index, _)| index)
        .collect()
}

fn unused_parameter_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    routine_parameter_groups(syntax)
        .into_iter()
        .flat_map(|(_, parameters)| parameters)
        .filter_map(|parameter| {
            let parameter = significant_range(syntax, parameter);
            let name = syntax.tokens.get(parameter.start)?.text.as_str();
            (syntax.tokens[parameter.start].kind == TokKind::Ident
                && token_count(syntax, name) == 1)
                .then_some(parameter.start)
        })
        .collect()
}

fn variable_hiding_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let items = declared_items(syntax);
    let mut offsets = Vec::new();
    for (position, (_, index, name)) in items.iter().enumerate() {
        if items[..position]
            .iter()
            .any(|(_, outer, outer_name)| outer_name == name && *outer < *index)
        {
            offsets.push(*index);
        }
    }
    offsets
}

fn variable_in_count_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    let declared = declared_items(syntax)
        .into_iter()
        .map(|(_, _, name)| name)
        .collect::<HashSet<_>>();
    (0..syntax.tokens.len().saturating_sub(2))
        .filter(|index| {
            syntax.is(*index, "count")
                && syntax.is(index + 1, "(")
                && syntax.tokens[index + 2].kind == TokKind::Ident
                && declared.contains(&syntax.tokens[index + 2].text)
        })
        .collect()
}

fn variable_name_offsets(syntax: &SqlSyntax) -> Vec<usize> {
    declared_items(syntax)
        .into_iter()
        .filter(|(_, _, name)| name.ends_with('_'))
        .map(|(_, index, _)| index)
        .collect()
}

#[allow(dead_code)]
fn _assert_if_is_public(_: &SqlIf) {}
