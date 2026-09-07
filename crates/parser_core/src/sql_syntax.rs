use std::ops::Range;

use crate::{Lexer, LexerSpec, TokKind};

#[derive(Clone, Debug)]
pub struct SqlToken {
    pub kind: TokKind,
    /// Original spelling retained for diagnostics and case-preserving literal values.
    pub original_text: String,
    /// ASCII-case-normalized spelling used by structural matching.
    pub text: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug)]
pub struct SqlBranch {
    pub marker: usize,
    pub condition: Option<Range<usize>>,
    pub body: Range<usize>,
}

#[derive(Clone, Debug)]
pub struct SqlIf {
    pub start: usize,
    pub branches: Vec<SqlBranch>,
    pub end: usize,
}

#[derive(Clone, Debug)]
pub struct SqlBlock {
    pub start: usize,
    pub body: Range<usize>,
    pub end: usize,
}

#[derive(Clone, Debug, Default)]
pub struct SqlSyntax {
    pub tokens: Vec<SqlToken>,
    pub mates: Vec<Option<usize>>,
    pub ifs: Vec<SqlIf>,
    pub blocks: Vec<SqlBlock>,
    /// Source offsets for `%disabled` test annotations without an explanation.
    pub unexplained_disabled_tests: Vec<usize>,
    /// Recovery diagnostics for unbalanced delimiters and PL/SQL blocks.
    pub parse_errors: Vec<usize>,
}

#[derive(Clone, Debug)]
struct OpenBranch {
    marker: usize,
    condition_start: Option<usize>,
    condition: Option<Range<usize>>,
    body_start: Option<usize>,
}

#[derive(Clone, Debug)]
struct OpenIf {
    start: usize,
    branches: Vec<SqlBranch>,
    current: OpenBranch,
}

impl SqlSyntax {
    pub fn parse(source: &str) -> Self {
        let spec = LexerSpec {
            line_comments: vec!["--"],
            block_comments: vec![("/*", "*/")],
            case_insensitive_keywords: true,
            line_comment_needs_break: false,
            backtick_idents: true,
            ..LexerSpec::default()
        };
        let tokens = Lexer::new(source, &spec)
            .tokenize()
            .into_iter()
            .filter(|token| !matches!(token.kind, TokKind::Eof | TokKind::Newline))
            .map(|token| SqlToken {
                kind: token.kind,
                original_text: token.text.clone(),
                text: token.text.to_ascii_lowercase(),
                start: token.start as usize,
                end: token.end as usize,
            })
            .collect::<Vec<_>>();
        let mates = delimiter_mates(&tokens);
        let ifs = parse_ifs(&tokens);
        let blocks = parse_blocks(&tokens);
        let unexplained_disabled_tests = unexplained_disabled_tests(source);
        let parse_errors = parse_errors(&tokens, &mates, &ifs, &blocks);
        Self { tokens, mates, ifs, blocks, unexplained_disabled_tests, parse_errors }
    }

    pub fn is(&self, index: usize, text: &str) -> bool {
        self.tokens.get(index).is_some_and(|token| token.text.eq_ignore_ascii_case(text))
    }

    pub fn normalized(&self, range: Range<usize>) -> String {
        let mut value = String::new();
        for token in self.tokens.get(range).unwrap_or_default() {
            if token.text == ";" { continue; }
            if !value.is_empty() { value.push('\u{1f}'); }
            value.push_str(&token.text);
        }
        value
    }

    pub fn trim_parens(&self, mut range: Range<usize>) -> Range<usize> {
        while range.start < range.end && self.is(range.start, "(")
            && self.mates.get(range.start).and_then(|mate| *mate) == Some(range.end - 1)
        {
            range = range.start + 1..range.end - 1;
        }
        range
    }

    pub fn split_top_level(&self, range: Range<usize>, separator: &str) -> Vec<Range<usize>> {
        let mut parts = Vec::new();
        let mut start = range.start;
        let mut index = range.start;
        while index < range.end {
            if matches!(self.tokens[index].text.as_str(), "(" | "[" | "{") {
                if let Some(close) = self.mates[index] {
                    index = close.saturating_add(1);
                    continue;
                }
            }
            if self.is(index, separator) {
                parts.push(start..index);
                start = index + 1;
            }
            index += 1;
        }
        parts.push(start..range.end);
        parts
    }

    pub fn statement_range_containing(&self, index: usize) -> Range<usize> {
        let start = (0..index).rev().find(|candidate| self.is(*candidate, ";"))
            .map_or(0, |candidate| candidate + 1);
        let end = (index..self.tokens.len()).find(|candidate| self.is(*candidate, ";"))
            .map_or(self.tokens.len(), |candidate| candidate + 1);
        start..end
    }
}

fn unexplained_disabled_tests(source: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut base = 0;
    for line in source.split_inclusive('\n') {
        if let Some(comment) = line.find("--") {
            let text = line[comment + 2..].trim();
            if text.eq_ignore_ascii_case("%disabled") { offsets.push(base + comment); }
        }
        base += line.len();
    }
    offsets
}

fn parse_errors(tokens: &[SqlToken], mates: &[Option<usize>], ifs: &[SqlIf], blocks: &[SqlBlock]) -> Vec<usize> {
    let mut errors = tokens.iter().enumerate().filter(|(index, token)|
        matches!(token.text.as_str(), "(" | ")" | "[" | "]" | "{" | "}") && mates[*index].is_none())
        .map(|(_, token)| token.start).collect::<Vec<_>>();
    let if_starts = tokens.iter().enumerate().filter(|(index, token)| token.text == "if"
        && (*index == 0 || tokens[*index - 1].text != "end")).count();
    if if_starts != ifs.len() {
        if let Some(token) = tokens.iter().find(|token| token.text == "if") { errors.push(token.start); }
    }
    let begins = tokens.iter().filter(|token| token.text == "begin").count();
    if begins != blocks.len() {
        if let Some(token) = tokens.iter().find(|token| token.text == "begin") { errors.push(token.start); }
    }
    errors.sort_unstable(); errors.dedup(); errors
}

fn delimiter_mates(tokens: &[SqlToken]) -> Vec<Option<usize>> {
    let mut mates = vec![None; tokens.len()];
    let mut stack = Vec::<(String, usize)>::new();
    for (index, token) in tokens.iter().enumerate() {
        if matches!(token.text.as_str(), "(" | "[" | "{") {
            stack.push((token.text.clone(), index));
        } else if matches!(token.text.as_str(), ")" | "]" | "}") {
            let expected = match token.text.as_str() { ")" => "(", "]" => "[", _ => "{" };
            if let Some(position) = stack.iter().rposition(|(open, _)| open == expected) {
                let (_, open) = stack.remove(position);
                mates[open] = Some(index);
                mates[index] = Some(open);
            }
        }
    }
    mates
}

fn finish_branch(open: &mut OpenIf, end: usize) {
    if let Some(body_start) = open.current.body_start {
        open.branches.push(SqlBranch {
            marker: open.current.marker,
            condition: open.current.condition.clone(),
            body: body_start..end,
        });
    }
}

fn parse_ifs(tokens: &[SqlToken]) -> Vec<SqlIf> {
    let mut stack = Vec::<OpenIf>::new();
    let mut result = Vec::new();
    for index in 0..tokens.len() {
        let text = tokens[index].text.as_str();
        if text == "if" && (index == 0 || tokens[index - 1].text != "end") {
            stack.push(OpenIf {
                start: index,
                branches: Vec::new(),
                current: OpenBranch { marker: index, condition_start: Some(index + 1), condition: None, body_start: None },
            });
        } else if text == "then" {
            if let Some(open) = stack.last_mut() {
                if let Some(condition_start) = open.current.condition_start.take() {
                    open.current.condition = Some(condition_start..index);
                    open.current.body_start = Some(index + 1);
                }
            }
        } else if matches!(text, "elsif" | "else") {
            if let Some(open) = stack.last_mut() {
                finish_branch(open, index);
                open.current = OpenBranch {
                    marker: index,
                    condition_start: (text == "elsif").then_some(index + 1),
                    condition: None,
                    body_start: (text == "else").then_some(index + 1),
                };
            }
        } else if text == "end" && tokens.get(index + 1).is_some_and(|token| token.text == "if") {
            if let Some(mut open) = stack.pop() {
                finish_branch(&mut open, index);
                result.push(SqlIf { start: open.start, branches: open.branches, end: index + 2 });
            }
        }
    }
    result.sort_by_key(|item| item.start);
    result
}

fn parse_blocks(tokens: &[SqlToken]) -> Vec<SqlBlock> {
    let mut stack = Vec::new();
    let mut result = Vec::new();
    for index in 0..tokens.len() {
        if tokens[index].text == "begin" {
            stack.push(index);
        } else if tokens[index].text == "end"
            && !tokens.get(index + 1).is_some_and(|token| matches!(token.text.as_str(), "if" | "loop" | "case"))
        {
            if let Some(start) = stack.pop() {
                result.push(SqlBlock { start, body: start + 1..index, end: index + 1 });
            }
        }
    }
    result.sort_by_key(|block| block.start);
    result
}
