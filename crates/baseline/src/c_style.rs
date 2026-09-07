use serde::{Deserialize, Serialize};
use uniflow_parser_core::java_syntax::{JavaSyntax, JavaSyntaxKind as K};
use uniflow_parser_core::TokKind;

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
}

impl CStyleCheck {
    pub(crate) fn offsets(self, syntax: &JavaSyntax) -> Vec<usize> {
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
                    if node.kind == K::While
                        || node.kind == K::For && node.initializer.is_some() =>
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
                Self::BreakInLoop if node.kind == K::Other => {
                    if first(node.range.clone()) != Some("break") {
                        continue;
                    }
                    let parent = syntax
                        .nodes
                        .iter()
                        .filter(|parent| {
                            matches!(parent.kind, K::Switch | K::For | K::While | K::Method)
                                && parent.range.start < node.range.start
                                && parent.range.end >= node.range.end
                        })
                        .min_by_key(|parent| parent.range.end - parent.range.start);
                    if parent.is_some_and(|parent| matches!(parent.kind, K::For | K::While)) {
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
                _ => {}
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
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
