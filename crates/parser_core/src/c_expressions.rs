//! Balanced C/C++ expression facts used by source checkers. This index keeps
//! lexical locations and structural group ownership; declarations are supplied
//! separately by callers when grammar distinguishes separators from operators.
use crate::{Lexer, LexerSpec, TokKind, Token};
use std::ops::Range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CExpressionFactKind { Assignment, Update, Call, Conditional, Binary, Comma }

#[derive(Clone, Debug)]
pub struct CExpressionFact {
    pub kind: CExpressionFactKind,
    pub offset: usize,
    pub end: usize,
    pub enclosing_calls: Vec<String>,
    pub inside_for_header: bool,
    pub inside_sizeof: bool,
}

pub struct CExpressionIndex {
    pub facts: Vec<CExpressionFact>,
    pub tokens: Vec<Token>,
    mates: Vec<Option<usize>>,
    parents: Vec<Option<usize>>,
}

impl CExpressionIndex {
    pub fn parse(source: &str) -> Self {
        let tokens = Lexer::new(source, &LexerSpec::default()).tokenize();
        let mut mates = vec![None; tokens.len()];
        let mut parents = vec![None; tokens.len()];
        let mut stack = Vec::new();
        for at in 0..tokens.len() {
            parents[at] = stack.last().copied();
            if tokens[at].kind != TokKind::Symbol { continue; }
            match tokens[at].text.as_str() {
                "(" | "[" | "{" => stack.push(at),
                ")" | "]" | "}" => {
                    let wanted = match tokens[at].text.as_str() { ")" => "(", "]" => "[", _ => "{" };
                    if stack.last().is_some_and(|open| tokens[*open].text == wanted) {
                        let open = stack.pop().unwrap(); mates[open] = Some(at); mates[at] = Some(open);
                        parents[at] = stack.last().copied();
                    }
                }
                _ => {}
            }
        }
        let mut result = Self { facts: Vec::new(), tokens, mates, parents };
        for at in 0..result.tokens.len().saturating_sub(1) {
            let text = result.tokens[at].text.as_str();
            let kind = if matches!(text, "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=" | "&=" | "^=" | "|=") {
                Some(CExpressionFactKind::Assignment)
            } else if matches!(text, "++" | "--") { Some(CExpressionFactKind::Update) }
            else if text == "?" { Some(CExpressionFactKind::Conditional) }
            else if text == "," { Some(CExpressionFactKind::Comma) }
            else if is_binary(text) { Some(CExpressionFactKind::Binary) }
            else if text == "(" && result.call_name(at).is_some() { Some(CExpressionFactKind::Call) }
            else { None };
            if let Some(kind) = kind {
                let (inside_for_header, inside_sizeof, enclosing_calls) = result.context(at);
                let offset = if kind == CExpressionFactKind::Call {
                    result.tokens[at.saturating_sub(1)].start as usize
                } else { result.tokens[at].start as usize };
                result.facts.push(CExpressionFact { kind, offset, end: result.tokens[at].end as usize,
                    enclosing_calls, inside_for_header, inside_sizeof });
            }
        }
        result
    }

    fn context(&self, at: usize) -> (bool, bool, Vec<String>) {
        let mut inside_for = false;
        let mut inside_sizeof = false;
        let mut calls = Vec::new();
        let mut open = self.parents[at];
        while let Some(group) = open {
            if self.tokens[group].text == "(" {
                if self.tokens.get(group.wrapping_sub(1)).is_some_and(|token| token.text == "for") { inside_for = true; }
                if self.tokens.get(group.wrapping_sub(1)).is_some_and(|token| token.text == "sizeof") { inside_sizeof = true; }
                if let Some(name) = self.call_name(group) { calls.push(name); }
            }
            open = self.parents[group];
        }
        // `sizeof ++x` has no parenthesized operand.
        if !inside_sizeof {
            inside_sizeof = (0..at).rev().take_while(|index| !matches!(self.tokens[*index].text.as_str(), ";" | "{" | "}" | ","))
                .any(|index| self.tokens[index].text == "sizeof" && !self.is_group_closed_before(index + 1, at));
        }
        (inside_for, inside_sizeof, calls)
    }

    fn is_group_closed_before(&self, start: usize, at: usize) -> bool {
        self.tokens.get(start).is_some_and(|token| matches!(token.text.as_str(), "(" | "[" | "{")
            && self.mates[start].is_some_and(|close| close < at))
    }

    fn call_name(&self, open: usize) -> Option<String> {
        if !self.tokens.get(open).is_some_and(|token| token.text == "(") || open == 0 { return None; }
        let previous = &self.tokens[open - 1];
        if previous.kind != TokKind::Ident || matches!(previous.text.as_str(), "if" | "for" | "while" | "switch" | "sizeof" | "alignof" | "_Alignof" | "catch" | "decltype") { return None; }
        Some(previous.text.clone())
    }

    pub fn token_at(&self, offset: usize) -> Option<&Token> {
        self.tokens.iter().find(|token| token.start as usize == offset)
    }

    pub fn smallest_group(&self, offset: usize) -> Option<(usize, usize)> {
        self.tokens.iter().enumerate().filter(|(_, token)| token.start as usize <= offset)
            .filter_map(|(open, _)| self.mates[open].map(|close| (open, close)))
            .filter(|(open, close)| self.tokens[*open].start as usize <= offset && self.tokens[*close].end as usize > offset)
            .min_by_key(|(open, close)| close - open)
    }

    pub fn nearest_call_name(&self, offset: usize) -> Option<String> {
        let at = self.tokens.iter().position(|token| token.start as usize == offset)?;
        let mut open = self.parents[at];
        while let Some(group) = open {
            if let Some(name) = self.call_name(group) { return Some(name); }
            open = self.parents[group];
        }
        None
    }

    pub fn inside_control_header(&self, offset: usize, keyword: &str) -> bool {
        let Some(at) = self.tokens.iter().position(|token| token.start as usize == offset) else { return false; };
        let mut open = self.parents[at];
        while let Some(group) = open {
            if self.tokens[group].text == "(" && group > 0 && self.tokens[group - 1].text == keyword { return true; }
            open = self.parents[group];
        }
        false
    }

    pub fn statement_range(&self, offset: usize) -> Option<Range<usize>> {
        let at = self.tokens.iter().position(|token| token.start as usize <= offset && offset < token.end as usize)?;
        let mut container = self.parents[at];
        while let Some(open) = container {
            if self.tokens[open].text == "{" { break; }
            container = self.parents[open];
        }
        let direct = |index: usize| self.parents[index] == container;
        let start = (0..at).rev().find(|index| direct(*index) && matches!(self.tokens[*index].text.as_str(), ";" | "{" | "}"))
            .map_or(0, |index| self.tokens[index].end as usize);
        let end = (at..self.tokens.len()).find(|index| direct(*index) && self.tokens[*index].text == ";")
            .map(|index| self.tokens[index].end as usize)?;
        Some(start..end)
    }
}

fn is_binary(text: &str) -> bool {
    matches!(text, "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "<" | "<=" | ">" | ">="
        | "==" | "!=" | "&" | "^" | "|" | "&&" | "||")
}
