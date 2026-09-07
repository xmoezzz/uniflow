//! Byte-preserving Java statement structure for frontend and coding-style checks.
//! This index does not perform name or type resolution; those belong to HIR.
use crate::{Lexer, LexerSpec, TokKind, Token};
use std::ops::Range;

mod declarations;
pub use declarations::{JavaDeclaration, JavaDeclarationKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JavaSyntaxKind {
    Block, ConstructorBody, Method, If, While, For, Do, Synchronized, Try,
    Switch, SwitchGroup, Empty, Other,
}

#[derive(Clone, Debug)]
pub struct JavaSyntaxNode {
    pub kind: JavaSyntaxKind,
    pub range: Range<usize>,
    pub body: Option<Range<usize>>,
    pub alternative: Option<Range<usize>>,
    pub condition: Option<Range<usize>>,
    pub initializer: Option<Range<usize>>,
    pub update: Option<Range<usize>>,
    pub follows_empty: bool,
    pub followed_by_block: bool,
    pub label_is_case: bool,
    pub arrow_label: bool,
}

pub struct JavaSyntax {
    pub nodes: Vec<JavaSyntaxNode>,
    pub roots: Vec<usize>,
    pub declarations: Vec<JavaDeclaration>,
    tokens: Vec<Token>,
    mates: Vec<Option<usize>>,
    csharp_attributes: bool,
    c_family_types: bool,
}

impl JavaSyntax {
    /// Balanced C-family statement structure, without Java declaration semantics.
    /// The caller must mask preprocessing directives while preserving offsets.
    pub fn parse_c_family_statements(source: &str) -> Self {
        let mut index = Self::lex(source);
        index.c_family_types = true;
        index.declarations(0, index.tokens.len() - 1, "", 0);
        index
    }
    pub fn parse(source: &str) -> Self {
        let mut index = Self::lex(source);
        index.declarations(0, index.tokens.len() - 1, "", 0);
        index.index_declarations();
        index
    }

    /// Declaration ownership and balanced attribute lists for C# source checks.
    /// This does not claim Java and C# have interchangeable expression grammars.
    pub fn parse_csharp_declarations(source: &str) -> Self {
        let mut index = Self::lex(source);
        index.csharp_attributes = true;
        index.index_declarations();
        index
    }

    /// Top-level statement slices, including terminators. A dangling `else`
    /// belongs to the nearest unmatched `if`; do/while is one statement.
    pub fn statement_ranges(source: &str) -> Vec<Range<usize>> {
        let index = Self::parse_statements(source);
        index.roots.iter().map(|&id| index.nodes[id].range.clone()).collect()
    }

    pub fn parse_statements(source: &str) -> Self {
        let mut index = Self::lex(source);
        index.roots = index.sequence(0, index.tokens.len() - 1, 0);
        index
    }

    /// Parse a type's member list. Roots identify only directly owned methods,
    /// not methods of nested/anonymous classes or lambda bodies.
    pub fn parse_members(source: &str) -> Self {
        let mut index = Self::lex(source);
        index.declarations(0, index.tokens.len() - 1, "", 0);
        index
    }

    fn lex(source: &str) -> Self {
        let spec = LexerSpec { triple_quotes: vec!["\"\"\""], ..Default::default() };
        let tokens = Lexer::new(source, &spec).tokenize();
        let mut mates = vec![None; tokens.len()];
        let mut stack = Vec::new();
        for (i, token) in tokens.iter().enumerate() {
            if token.kind != TokKind::Symbol { continue; }
            match token.text.as_str() {
                "(" | "[" | "{" => stack.push(i),
                ")" | "]" | "}" => {
                    let wanted = match token.text.as_str() { ")" => "(", "]" => "[", _ => "{" };
                    if let Some(&open) = stack.last() {
                        if tokens[open].text == wanted {
                            stack.pop();
                            mates[open] = Some(i);
                            mates[i] = Some(open);
                        }
                    }
                }
                _ => {}
            }
        }
        Self { nodes: Vec::new(), roots: Vec::new(), declarations: Vec::new(), tokens, mates,
            csharp_attributes: false, c_family_types: false }
    }

    fn is(&self, i: usize, text: &str) -> bool {
        self.tokens.get(i).is_some_and(|t| t.kind != TokKind::StringLit && t.text == text)
    }

    fn range(&self, start: usize, end: usize) -> Range<usize> {
        let begin = self.tokens[start].start as usize;
        begin..if end > start { self.tokens[end - 1].end as usize } else { begin }
    }

    fn add(&mut self, kind: JavaSyntaxKind, start: usize, end: usize) -> usize {
        let id = self.nodes.len();
        self.nodes.push(JavaSyntaxNode {
            kind, range: self.range(start, end), body: None, alternative: None,
            condition: None, follows_empty: false, followed_by_block: false,
            initializer: None, update: None,
            label_is_case: false, arrow_label: false,
        });
        id
    }

    fn sequence(&mut self, mut pos: usize, end: usize, depth: usize) -> Vec<usize> {
        let mut ids: Vec<usize> = Vec::new();
        while pos < end {
            let (next, id) = self.statement(pos, end, depth + 1);
            if let Some(&previous) = ids.last() {
                self.nodes[id].follows_empty = self.nodes[previous].kind == JavaSyntaxKind::Empty;
                self.nodes[previous].followed_by_block = self.nodes[id].kind == JavaSyntaxKind::Block;
            }
            ids.push(id);
            pos = next.max(pos + 1);
        }
        ids
    }

    fn declarations(&mut self, mut start: usize, end: usize, class_name: &str, depth: usize) {
        if depth > 256 { return; }
        while start < end {
            let mut cursor = start;
            let mut type_name = None;
            let mut method_name = None;
            let mut initializer = false;
            while cursor < end {
                if (["class", "interface", "enum", "record"].iter().any(|s| self.is(cursor, s))
                    || self.c_family_types && ["struct", "union", "namespace"].iter().any(|s| self.is(cursor, s)))
                    && !cursor.checked_sub(1).is_some_and(|p| self.is(p, "."))
                {
                    type_name = self.tokens.get(cursor + 1).map(|t| t.text.clone());
                }
                if self.is(cursor, "=") { initializer = true; }
                if self.is(cursor, "(") {
                    if let Some(close) = self.mates[cursor] {
                        if cursor > start && !initializer && type_name.is_none()
                            && self.tokens[cursor - 1].kind == TokKind::Ident
                            && !(cursor >= 2 && self.is(cursor - 2, "@"))
                        {
                            method_name = Some(self.tokens[cursor - 1].text.clone());
                        }
                        cursor = close + 1;
                        continue;
                    }
                }
                if self.is(cursor, "{") {
                    let Some(close) = self.mates[cursor] else { break; };
                    if let Some(name) = type_name.take() {
                        self.declarations(cursor + 1, close, &name, depth + 1);
                    } else if !initializer && (method_name.is_some()
                        || (cursor == start + 1 && self.is(start, class_name)))
                    {
                        let constructor = method_name.as_deref() == Some(class_name)
                            || method_name.is_none();
                        let id = self.add(JavaSyntaxKind::Method, start, close + 1);
                        if depth == 0 { self.roots.push(id); }
                        self.nodes[id].body = Some(self.range(cursor, close + 1));
                        self.add(if constructor { JavaSyntaxKind::ConstructorBody }
                            else { JavaSyntaxKind::Block }, cursor, close + 1);
                        self.sequence(cursor + 1, close, depth + 1);
                    } else if !initializer && (cursor == start || self.is(start, "static")) {
                        self.add(JavaSyntaxKind::Block, cursor, close + 1);
                        self.sequence(cursor + 1, close, depth + 1);
                    } else {
                        self.expression_bodies(start, close + 1, depth + 1);
                        cursor = close + 1;
                        continue;
                    }
                    cursor = close + 1;
                    break;
                }
                if self.is(cursor, ";") { cursor += 1; break; }
                cursor += 1;
            }
            start = cursor.max(start + 1);
        }
    }

    fn statement(&mut self, start: usize, end: usize, depth: usize) -> (usize, usize) {
        use JavaSyntaxKind as K;
        if depth > 256 { return (end, self.add(K::Other, start, end)); }
        if self.is(start, ";") { return (start + 1, self.add(K::Empty, start, start + 1)); }
        if self.is(start, "{") {
            if let Some(close) = self.mates[start] {
                let id = self.add(K::Block, start, close + 1);
                self.sequence(start + 1, close, depth + 1);
                return (close + 1, id);
            }
        }
        let keyword = self.tokens[start].text.as_str();
        let kind = match keyword {
            "if" => Some(K::If), "while" => Some(K::While), "for" => Some(K::For),
            "synchronized" => Some(K::Synchronized), "switch" => Some(K::Switch), _ => None,
        };
        if let Some(kind) = kind {
            if self.is(start + 1, "(") {
                if let Some(close) = self.mates[start + 1].filter(|&c| c + 1 < end) {
                    let body_start = close + 1;
                    let (mut next, _) = if kind == K::Switch && self.is(body_start, "{") {
                        let switch_end = self.mates[body_start].unwrap_or(end - 1);
                        self.switch_body(body_start + 1, switch_end, depth + 1);
                        (switch_end + 1, 0)
                    } else { self.statement(body_start, end, depth + 1) };
                    let body = self.range(body_start, next);
                    let mut alternative = None;
                    if kind == K::If && self.is(next, "else") && next + 1 < end {
                        let alt_start = next + 1;
                        next = self.statement(alt_start, end, depth + 1).0;
                        alternative = Some(self.range(alt_start, next));
                    }
                    let id = self.add(kind, start, next);
                    self.nodes[id].body = Some(body);
                    self.nodes[id].alternative = alternative;
                    self.nodes[id].condition = if kind == K::For {
                        let mut separators = Vec::new();
                        let mut i = start + 2;
                        while i < close {
                            if self.is(i, ";") { separators.push(i); }
                            i = self.mates[i].filter(|&c| c > i).map_or(i + 1, |c| c + 1);
                        }
                        if separators.len() == 2 {
                            self.nodes[id].initializer = Some(self.range(start + 2, separators[0]));
                            self.nodes[id].update = Some(self.range(separators[1] + 1, close));
                            Some(self.range(separators[0] + 1, separators[1]))
                        } else { None }
                    } else { Some(self.range(start + 2, close)) };
                    self.expression_bodies(start + 2, close, depth + 1);
                    return (next, id);
                }
            }
        }
        if self.is(start, "do") && start + 1 < end {
            let (body_end, _) = self.statement(start + 1, end, depth + 1);
            if self.is(body_end, "while") && self.is(body_end + 1, "(") {
                if let Some(close) = self.mates[body_end + 1] {
                    let next = close + 1 + usize::from(self.is(close + 1, ";"));
                    let id = self.add(K::Do, start, next);
                    self.nodes[id].body = Some(self.range(start + 1, body_end));
                    self.nodes[id].condition = Some(self.range(body_end + 2, close));
                    return (next, id);
                }
            }
        }
        if self.is(start, "try") {
            let mut body = start + 1;
            if self.is(body, "(") { body = self.mates[body].map_or(body, |c| c + 1); }
            if self.is(body, "{") {
                let (body_end, _) = self.statement(body, end, depth + 1);
                let mut next = body_end;
                while next < end && (self.is(next, "catch") || self.is(next, "finally")) {
                    let mut block = next + 1;
                    if self.is(block, "(") { block = self.mates[block].map_or(block, |c| c + 1); }
                    if !self.is(block, "{") { break; }
                    next = self.statement(block, end, depth + 1).0;
                }
                let id = self.add(K::Try, start, next);
                self.nodes[id].body = Some(self.range(body, body_end));
                return (next, id);
            }
        }
        // Labels wrap exactly one statement, rather than consuming the rest of a block.
        if self.tokens[start].kind == TokKind::Ident && self.is(start + 1, ":") && start + 2 < end {
            let next = self.statement(start + 2, end, depth + 1).0;
            return (next, self.add(K::Other, start, next));
        }
        if ["class", "interface", "enum", "record"].iter().any(|s| self.is(start, s)) {
            if let Some(open) = (start + 1..end).find(|&i| self.is(i, "{")) {
                if let Some(close) = self.mates[open] {
                    self.declarations(start, close + 1, "", depth + 1);
                    return (close + 1, self.add(K::Other, start, close + 1));
                }
            }
        }
        let mut next = start;
        while next < end {
            if self.is(next, ";") { next += 1; break; }
            if let Some(close) = self.mates[next].filter(|&c| c > next) { next = close + 1; }
            else { next += 1; }
        }
        self.expression_bodies(start, next, depth + 1);
        (next, self.add(K::Other, start, next))
    }

    fn expression_bodies(&mut self, start: usize, end: usize, depth: usize) {
        if depth > 256 { return; }
        let mut i = start;
        while i < end {
            if self.is(i, "switch") && self.is(i + 1, "(") {
                let next = self.statement(i, end, depth + 1).0;
                i = next.max(i + 1);
                continue;
            }
            if self.is(i, "{") {
                if let Some(close) = self.mates[i] {
                    if i > start && self.is(i - 1, "->") {
                        self.add(JavaSyntaxKind::Block, i, close + 1);
                        self.sequence(i + 1, close, depth + 1);
                    } else if i > start && self.is(i - 1, ")") {
                        // Anonymous class bodies are declarations, not executable blocks.
                        self.declarations(i + 1, close, "", depth + 1);
                    } else { self.expression_bodies(i + 1, close, depth + 1); }
                    i = close + 1;
                    continue;
                }
            }
            i += 1;
        }
    }

    fn switch_body(&mut self, mut start: usize, end: usize, depth: usize) {
        while start < end {
            if self.is(start, "case") || self.is(start, "default") {
                let group_start = start;
                let mut label_is_case = false;
                let mut arrow_label = false;
                loop {
                    label_is_case |= self.is(start, "case");
                    start += 1;
                    while start < end && !self.is(start, ":") && !self.is(start, "->") {
                        start = self.mates[start].filter(|&c| c > start).map_or(start + 1, |c| c + 1);
                    }
                    arrow_label |= self.is(start, "->");
                    start += usize::from(start < end);
                    if start >= end || (!self.is(start, "case") && !self.is(start, "default")) { break; }
                }
                let body_start = start;
                while start < end && !self.is(start, "case") && !self.is(start, "default") {
                    start = self.mates[start].filter(|&c| c > start).map_or(start + 1, |c| c + 1);
                }
                let id = self.add(JavaSyntaxKind::SwitchGroup, group_start, start);
                self.nodes[id].body = Some(self.range(body_start, start));
                self.nodes[id].label_is_case = label_is_case;
                self.nodes[id].arrow_label = arrow_label;
                if body_start < start { self.sequence(body_start, start, depth + 1); }
            } else {
                start = self.statement(start, end, depth + 1).0.max(start + 1);
            }
        }
    }

    pub fn tokens_in(&self, range: Range<usize>) -> impl Iterator<Item = &Token> {
        let start = self.tokens.partition_point(|t| (t.start as usize) < range.start);
        self.tokens[start..].iter().take_while(move |t| (t.start as usize) < range.end)
    }

    pub fn has_token_sequence(&self, range: Range<usize>, sequence: &[&str]) -> bool {
        let tokens = self.tokens_in(range).map(|token| token.text.as_str()).collect::<Vec<_>>();
        tokens.windows(sequence.len()).any(|window| window == sequence)
    }
}
