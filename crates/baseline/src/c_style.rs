use serde::{Deserialize, Serialize};
use uniflow_parser_core::java_syntax::{JavaSyntax, JavaSyntaxKind as K};
use uniflow_parser_core::TokKind;
use crate::c_expression_rules::evaluate_c_constant_boolean;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CStyleCheck {
    IfElseBraces,
    LoopBodyBraces,
    ElseIfNeedsElse,
    EmptySwitch,
    SwitchNeedsCase,
    EmptyStatement,
    EmptyControlBody,
    BreakInLoop,
    ConstantLoopCondition,
    EmptyIfBranch,
    EmptyElseBranch,
    EmptyThenOnConditionLine,
    LiteralLoopCondition,
    EmptyHeaderForLoop,
    InfiniteLoopWithoutBreak,
    SuspiciousSameLineEmptyBody,
    CppDestructorOrDeallocationMustBeNoexcept,
    EmptyCaseStatement,
}

impl CStyleCheck {
    pub(crate) fn offsets(self, source: &str, syntax: &JavaSyntax) -> Vec<usize> {
        if matches!(self, Self::CppDestructorOrDeallocationMustBeNoexcept) {
            return cpp_destructor_or_deallocation_without_noexcept(source, syntax);
        }
        let mut offsets = Vec::new();
        let first = |range| {
            syntax
                .tokens_in(range)
                .next()
                .map(|token| token.text.as_str())
        };
        for node in &syntax.nodes {
            let body_first = node.body.clone().and_then(&first);
            match self {
                Self::IfElseBraces if node.kind == K::If => {
                    if body_first != Some("{") {
                        offsets.push(node.range.start);
                    }
                    if let Some(alternative) = &node.alternative {
                        if !matches!(first(alternative.clone()), Some("{" | "if")) {
                            let after_body =
                                node.body.as_ref().map_or(node.range.start, |body| body.end);
                            let offset = syntax
                                .tokens_in(after_body..alternative.start)
                                .find(|token| token.text == "else")
                                .map_or(alternative.start, |token| token.start as usize);
                            offsets.push(offset);
                        }
                    }
                }
                Self::LoopBodyBraces
                    if matches!(node.kind, K::While | K::For | K::Do) =>
                {
                    if body_first != Some("{") {
                        offsets.push(node.range.start);
                    }
                }
                Self::ElseIfNeedsElse if node.kind == K::If && node.alternative.is_none() => {
                    if syntax.nodes.iter().any(|outer| {
                        outer.kind == K::If
                            && outer
                                .alternative
                                .as_ref()
                                .is_some_and(|alternative| alternative.start == node.range.start)
                    }) {
                        offsets.push(node.range.start);
                    }
                }
                Self::EmptySwitch | Self::SwitchNeedsCase if node.kind == K::Switch => {
                    let has_label = syntax.nodes.iter().any(|group| {
                        group.kind == K::SwitchGroup
                            && group.range.start > node.range.start
                            && group.range.end <= node.range.end
                            && (matches!(self, Self::EmptySwitch) || group.label_is_case)
                            && !syntax.nodes.iter().any(|inner| {
                                inner.kind == K::Switch
                                    && inner.range.start > node.range.start
                                    && inner.range.end <= node.range.end
                                    && inner.range.start < group.range.start
                                    && inner.range.end >= group.range.end
                            })
                    });
                    if !has_label {
                        offsets.push(node.range.start);
                    }
                }
                Self::EmptyStatement if node.kind == K::Empty => offsets.push(node.range.start),
                Self::EmptyControlBody if matches!(node.kind, K::If | K::While | K::For) => {
                    if body_first == Some(";") {
                        offsets.push(node.range.start);
                    }
                }
                Self::SuspiciousSameLineEmptyBody
                    if matches!(node.kind, K::If | K::While | K::For | K::Do)
                        && body_first == Some(";") =>
                {
                    let Some(body) = &node.body else {
                        continue;
                    };
                    let line = |offset: usize| source[..offset].bytes().filter(|byte| *byte == b'\n').count();
                    if line(node.range.start) == line(body.start) {
                        offsets.push(body.start);
                    }
                }
                Self::BreakInLoop if node.kind == K::Other => {
                    if first(node.range.clone()) != Some("break") {
                        continue;
                    }
                    if syntax.nodes.iter().any(|parent| {
                        parent.kind == K::Switch
                            && parent.range.start < node.range.start
                            && parent.range.end >= node.range.end
                    }) {
                        continue;
                    }
                    let parent = syntax
                        .nodes
                        .iter()
                        .filter(|parent| {
                            matches!(parent.kind, K::For | K::While | K::Do | K::Method)
                                && parent.range.start < node.range.start
                                && parent.range.end >= node.range.end
                        })
                        .min_by_key(|parent| parent.range.end - parent.range.start);
                    if parent
                        .is_some_and(|parent| matches!(parent.kind, K::For | K::While | K::Do))
                    {
                        offsets.push(node.range.start);
                    }
                }
                Self::ConstantLoopCondition if matches!(node.kind, K::While | K::Do) => {
                    let Some(condition) = node.condition.clone() else {
                        continue;
                    };
                    let mut tokens = syntax.tokens_in(condition);
                    let literal = tokens.next().is_some_and(|token| {
                        matches!(token.kind, TokKind::IntLit | TokKind::FloatLit)
                    }) && tokens.next().is_none();
                    let eligible_body = node.kind == K::Do
                        || node.body.clone().is_some_and(|body| {
                            syntax
                                .tokens_in(body)
                                .map(|token| token.text.as_str())
                                .eq(["{", "}"])
                        });
                    if literal && eligible_body {
                        offsets.push(node.range.start);
                    }
                }
                Self::EmptyIfBranch | Self::EmptyElseBranch if node.kind == K::If => {
                    if matches!(self, Self::EmptyIfBranch) && body_first == Some(";") {
                        if let Some(body) = &node.body {
                            offsets.push(body.start);
                        }
                    }
                    if node
                        .alternative
                        .clone()
                        .and_then(&first)
                        == Some(";")
                    {
                        if let Some(alternative) = &node.alternative {
                            offsets.push(alternative.start);
                        }
                    }
                }
                Self::EmptyThenOnConditionLine if node.kind == K::If && body_first == Some(";") => {
                    if let (Some(condition), Some(body)) = (&node.condition, &node.body) {
                        if !source[condition.end.min(source.len())..body.start.min(source.len())]
                            .contains('\n')
                        {
                            offsets.push(body.start);
                        }
                    }
                }
                Self::LiteralLoopCondition
                    if matches!(node.kind, K::While | K::For | K::Do) =>
                {
                    let Some(condition) = node.condition.clone() else {
                        continue;
                    };
                    let tokens = syntax.tokens_in(condition).collect::<Vec<_>>();
                    let tokens = strip_wrapping_parentheses(&tokens);
                    let direct_literal = match tokens {
                        [token] => {
                            matches!(token.kind, TokKind::IntLit | TokKind::FloatLit)
                                || token.kind == TokKind::StringLit
                                || matches!(token.text.as_str(), "true" | "false")
                        }
                        [number, suffix] => {
                            matches!(number.kind, TokKind::IntLit | TokKind::FloatLit)
                                && matches!(suffix.text.as_str(), "i" | "j")
                        }
                        _ => false,
                    };
                    if direct_literal {
                        offsets.push(tokens[0].start as usize);
                    }
                }
                Self::EmptyHeaderForLoop if node.kind == K::For => {
                    let empty = |range: &Option<std::ops::Range<usize>>| {
                        range
                            .clone()
                            .is_none_or(|range| syntax.tokens_in(range).next().is_none())
                    };
                    if empty(&node.initializer) && empty(&node.condition) && empty(&node.update) {
                        offsets.push(node.range.start);
                    }
                }
                Self::InfiniteLoopWithoutBreak
                    if matches!(node.kind, K::While | K::For | K::Do) =>
                {
                    let constant_true = node.condition.as_ref().is_none_or(|condition| {
                        let tokens = syntax
                            .tokens_in(condition.clone())
                            .cloned()
                            .collect::<Vec<_>>();
                        tokens.is_empty() || evaluate_c_constant_boolean(&tokens) == Some(true)
                    });
                    if !constant_true || loop_has_own_break(syntax, node.range.clone()) {
                        continue;
                    }
                    let offset = node
                        .condition
                        .clone()
                        .and_then(|condition| syntax.tokens_in(condition).next())
                        .map_or(node.range.start, |token| token.start as usize);
                    offsets.push(offset);
                }
                Self::EmptyCaseStatement if node.kind == K::SwitchGroup && node.label_is_case => {
                    let body_tokens = node
                        .body
                        .clone()
                        .map(|range| syntax.tokens_in(range).collect::<Vec<_>>())
                        .unwrap_or_default();
                    let explicit_empty = matches!(body_tokens.as_slice(), [token] if token.text == ";");
                    let final_empty = body_tokens.is_empty()
                        && syntax
                            .nodes
                            .iter()
                            .filter(|parent| {
                                parent.kind == K::Switch
                                    && parent.range.start <= node.range.start
                                    && node.range.end <= parent.range.end
                            })
                            .min_by_key(|parent| parent.range.end - parent.range.start)
                            .is_some_and(|parent| {
                                !syntax.nodes.iter().any(|later| {
                                    later.kind == K::SwitchGroup
                                        && node.range.start < later.range.start
                                        && later.range.end <= parent.range.end
                                })
                            });
                    if explicit_empty || final_empty {
                        offsets.push(node.range.start);
                    }
                }
                _ => {}
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

fn cpp_destructor_or_deallocation_without_noexcept(
    source: &str,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let tokens = syntax.tokens_in(0..source.len()).collect::<Vec<_>>();
    let mut offsets = Vec::new();
    for (open, token) in tokens.iter().enumerate() {
        if token.text != "(" {
            continue;
        }
        let Some((kind_offset, declaration_start)) = cpp_noexcept_candidate(&tokens, open) else {
            continue;
        };
        if !cpp_declaration_context(&tokens, declaration_start) {
            continue;
        }
        let Some(close) = matching_token(&tokens, open, "(", ")") else {
            continue;
        };
        let end = (close + 1..tokens.len())
            .find(|index| matches!(tokens[*index].text.as_str(), "{" | ";"))
            .unwrap_or(tokens.len());
        let suffix = &tokens[close + 1..end];
        if !cpp_suffix_is_nothrow(suffix) {
            offsets.push(kind_offset);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn cpp_noexcept_candidate(
    tokens: &[&uniflow_parser_core::Token],
    open: usize,
) -> Option<(usize, usize)> {
    if open >= 2 && tokens[open - 2].text == "~" && is_identifier_token(tokens[open - 1]) {
        let start = open - 2;
        if start > 0 && matches!(tokens[start - 1].text.as_str(), "." | "->") {
            return None;
        }
        return Some((tokens[start].start as usize, start));
    }
    let delete_at = if open >= 2
        && tokens[open - 2].text == "operator"
        && tokens[open - 1].text == "delete"
    {
        Some(open - 1)
    } else if open >= 4
        && tokens[open - 4].text == "operator"
        && tokens[open - 3].text == "delete"
        && tokens[open - 2].text == "["
        && tokens[open - 1].text == "]"
    {
        Some(open - 3)
    } else {
        None
    }?;
    Some((tokens[delete_at].start as usize, delete_at - 1))
}

fn cpp_declaration_context(tokens: &[&uniflow_parser_core::Token], start: usize) -> bool {
    if tokens[start].text == "~" {
        return start == 0
            || !matches!(tokens[start.saturating_sub(1)].text.as_str(), "." | "->");
    }
    if start == 0 {
        return false;
    }
    let previous = tokens[start - 1].text.as_str();
    !matches!(previous, "{" | "}" | ";" | ":")
}

fn cpp_suffix_is_nothrow(tokens: &[&uniflow_parser_core::Token]) -> bool {
    for (index, token) in tokens.iter().enumerate() {
        if token.text == "throw"
            && tokens.get(index + 1).is_some_and(|token| token.text == "(")
            && tokens.get(index + 2).is_some_and(|token| token.text == ")")
        {
            return true;
        }
        if token.text != "noexcept" {
            continue;
        }
        if tokens.get(index + 1).is_none_or(|token| token.text != "(") {
            return true;
        }
        let Some(close) = matching_token(tokens, index + 1, "(", ")") else {
            return false;
        };
        let expression = &tokens[index + 2..close];
        return !matches!(expression, [value] if matches!(value.text.as_str(), "false" | "0"));
    }
    false
}

fn matching_token(
    tokens: &[&uniflow_parser_core::Token],
    open: usize,
    left: &str,
    right: &str,
) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        if token.text == left {
            depth += 1;
        } else if token.text == right {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn is_identifier_token(token: &uniflow_parser_core::Token) -> bool {
    token.kind == TokKind::Ident
}

fn strip_wrapping_parentheses<'a>(mut tokens: &'a [&'a uniflow_parser_core::Token]) -> &'a [&'a uniflow_parser_core::Token] {
    loop {
        if tokens.len() < 2
            || tokens[0].text != "("
            || tokens[tokens.len() - 1].text != ")"
        {
            return tokens;
        }
        let mut depth = 0usize;
        let mut closes_at_end = false;
        for (at, token) in tokens.iter().enumerate() {
            match token.text.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        closes_at_end = at + 1 == tokens.len();
                        break;
                    }
                }
                _ => {}
            }
        }
        if !closes_at_end {
            return tokens;
        }
        tokens = &tokens[1..tokens.len() - 1];
    }
}

fn loop_has_own_break(syntax: &JavaSyntax, loop_range: std::ops::Range<usize>) -> bool {
    syntax.nodes.iter().any(|statement| {
        if statement.kind != K::Other
            || !syntax
                .tokens_in(statement.range.clone())
                .next()
                .is_some_and(|token| token.text == "break")
            || !(loop_range.start < statement.range.start && statement.range.end <= loop_range.end)
        {
            return false;
        }
        let nearest_control = syntax
            .nodes
            .iter()
            .filter(|candidate| {
                matches!(candidate.kind, K::While | K::For | K::Do | K::Switch)
                    && candidate.range.start < statement.range.start
                    && statement.range.end <= candidate.range.end
            })
            .min_by_key(|candidate| candidate.range.end - candidate.range.start);
        nearest_control.is_some_and(|candidate| candidate.range == loop_range)
    })
}

/// Preprocessor bodies are not executable statements. Keep byte positions and
/// line breaks, including continued directives, for diagnostics in source code.
pub(crate) fn mask_directives(source: &str, code_only: &str) -> String {
    let mut bytes = source.as_bytes().to_vec();
    let mut offset = 0;
    let mut continued = false;
    for line in code_only.split_inclusive('\n') {
        let directive = continued || line.trim_start().starts_with('#');
        continued = directive
            && source[offset..offset + line.len()]
                .trim_end()
                .ends_with('\\');
        if directive {
            for byte in &mut bytes[offset..offset + line.len()] {
                if !matches!(*byte, b'\n' | b'\r') {
                    *byte = b' ';
                }
            }
        }
        offset += line.len();
    }
    String::from_utf8(bytes).expect("masked complete UTF-8 lines")
}
