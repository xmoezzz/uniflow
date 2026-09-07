//! C-family declaration structure for source checkers. Declarator operators
//! are ordered from the declared name outwards, preserving the distinction
//! between `int *f()` (function) and `int (*f)()` (pointer to function).
//! Preprocessing directives must be masked by the caller without moving bytes.
use crate::{Lexer, LexerSpec, TokKind, Token};
use std::ops::Range;

#[derive(Clone, Debug)]
pub enum DerivedDeclarator {
    Pointer,
    Array { size: Range<usize> },
    Function { parameters: Range<usize> },
}

#[derive(Clone, Debug)]
pub struct CDeclarator {
    pub name: Option<String>,
    pub range: Range<usize>,
    pub derived: Vec<DerivedDeclarator>,
    pub initializer: Option<Range<usize>>,
}

#[derive(Clone, Debug)]
pub struct CDeclaration {
    pub range: Range<usize>,
    pub type_name: String,
    pub storage: Vec<String>,
    pub declarators: Vec<CDeclarator>,
    pub enclosing_function: Option<usize>,
    pub in_aggregate: bool,
}

#[derive(Clone, Debug)]
pub struct CFunctionDefinition {
    pub range: Range<usize>,
    pub body: Range<usize>,
    pub parameters: Range<usize>,
    pub name: String,
    pub returns_void: bool,
}

#[derive(Clone, Debug)]
pub struct CParameter {
    pub range: Range<usize>,
    pub has_name: bool,
    pub plain_void: bool,
}

#[derive(Clone, Debug)]
pub struct CAggregate {
    pub range: Range<usize>,
    pub body: Option<Range<usize>>,
    pub kind: String,
    pub name: Option<String>,
    pub inside_struct: bool,
}

#[derive(Clone, Debug)]
pub struct CReturn {
    pub range: Range<usize>,
    pub function: usize,
    pub has_value: bool,
}

pub struct CDeclarationIndex {
    pub declarations: Vec<CDeclaration>,
    pub functions: Vec<CFunctionDefinition>,
    pub parameters: Vec<CParameter>,
    pub aggregates: Vec<CAggregate>,
    pub returns: Vec<CReturn>,
    tokens: Vec<Token>,
    mates: Vec<Option<usize>>,
}

#[derive(Clone, Default)]
struct Scope { function: Option<usize>, aggregates: Vec<String>, field_context: bool }

impl CDeclarationIndex {
    pub fn parse(source: &str) -> Self {
        let tokens = Lexer::new(source, &LexerSpec::default()).tokenize();
        let mut mates = vec![None; tokens.len()];
        let mut stack = Vec::new();
        for (at, token) in tokens.iter().enumerate() {
            if token.kind != TokKind::Symbol { continue; }
            match token.text.as_str() {
                "(" | "[" | "{" => stack.push(at),
                ")" | "]" | "}" => {
                    let wanted = match token.text.as_str() { ")" => "(", "]" => "[", _ => "{" };
                    if let Some(&open) = stack.last() {
                        if tokens[open].text == wanted {
                            stack.pop(); mates[open] = Some(at); mates[at] = Some(open);
                        }
                    }
                }
                _ => {}
            }
        }
        let mut index = Self { declarations: Vec::new(), functions: Vec::new(), parameters: Vec::new(),
            aggregates: Vec::new(), returns: Vec::new(), tokens, mates };
        index.region(0, index.tokens.len() - 1, &Scope::default(), 0);
        index
    }

    pub fn tokens_in(&self, range: Range<usize>) -> impl Iterator<Item = &Token> {
        self.tokens.iter().filter(move |token| token.kind != TokKind::Eof
            && token.start as usize >= range.start && (token.end as usize) <= range.end)
    }

    fn is(&self, at: usize, text: &str) -> bool {
        self.tokens.get(at).is_some_and(|token| token.kind != TokKind::StringLit && token.text == text)
    }

    fn range(&self, start: usize, end: usize) -> Range<usize> {
        let begin = self.tokens[start].start as usize;
        begin..if end > start { self.tokens[end - 1].end as usize } else { begin }
    }

    fn skip_group(&self, at: usize) -> usize {
        self.mates[at].filter(|&close| close > at).map_or(at + 1, |close| close + 1)
    }

    fn attribute_end(&self, at: usize) -> Option<usize> {
        if self.is(at, "__attribute__") || self.is(at, "__declspec") || self.is(at, "alignas") || self.is(at, "_Alignas") {
            if self.is(at + 1, "(") { return self.mates[at + 1].map(|close| close + 1); }
        }
        if self.is(at, "[") && self.is(at + 1, "[") { return self.mates[at].map(|close| close + 1); }
        None
    }

    fn region(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) {
        if depth > 128 { return; }
        while at < end {
            if self.is(at, ";") || self.is(at, "else") { at += 1; continue; }
            if self.is(at, "namespace") || self.is(at, "extern") && self.tokens.get(at + 1).is_some_and(|token| token.kind == TokKind::StringLit) && self.is(at + 2, "{") {
                let mut open = at + 1;
                while open < end && !self.is(open, "{") && !self.is(open, ";") { open += 1; }
                if let Some(close) = self.mates.get(open).copied().flatten() {
                    self.region(open + 1, close, scope, depth + 1); at = close + 1; continue;
                }
            }
            if matches!(self.tokens[at].text.as_str(), "if" | "while" | "for" | "switch" | "catch") && self.is(at + 1, "(") {
                if let Some(close) = self.mates[at + 1] {
                    if self.is(at, "for") { self.region(at + 2, close, scope, depth + 1); }
                    else { self.expression(at + 2, close, scope, depth + 1); }
                    at = close + 1; continue;
                }
            }
            if self.is(at, "do") { at += 1; continue; }
            if self.is(at, "return") {
                let mut next = at + 1;
                while next < end && !self.is(next, ";") { next = self.skip_group(next); }
                if let Some(function) = scope.function {
                    self.returns.push(CReturn { range: self.range(at, (next + 1).min(end)), function, has_value: next > at + 1 });
                }
                self.expression(at + 1, next, scope, depth + 1);
                at = (next + 1).min(end); continue;
            }
            if self.is(at, "{") {
                if let Some(close) = self.mates[at] {
                    self.region(at + 1, close, scope, depth + 1); at = close + 1; continue;
                }
            }
            if self.tokens[at].kind == TokKind::Ident && self.is(at + 1, ":") {
                at += 2; continue;
            }
            if self.is(at, "case") {
                while at < end && !self.is(at, ":") { at = self.skip_group(at); }
                at += usize::from(at < end); continue;
            }
            let checkpoint = (self.declarations.len(), self.functions.len(), self.parameters.len(), self.aggregates.len(), self.returns.len());
            if let Some(next) = self.declaration(at, end, scope, depth + 1) {
                at = next; continue;
            }
            // Declaration recognition is speculative: expression-shaped text
            // must not leave parameter or aggregate records behind.
            self.declarations.truncate(checkpoint.0);
            self.functions.truncate(checkpoint.1);
            self.parameters.truncate(checkpoint.2);
            self.aggregates.truncate(checkpoint.3);
            self.returns.truncate(checkpoint.4);
            let start = at;
            while at < end && !self.is(at, ";") { at = self.skip_group(at); }
            self.expression(start, at, scope, depth + 1);
            at += usize::from(at < end);
        }
    }

    fn specifiers(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) -> Option<(usize, String, Vec<String>)> {
        let mut types = Vec::new();
        let mut storage = Vec::new();
        while at < end {
            if let Some(next) = self.attribute_end(at) { at = next; continue; }
            let text = self.tokens[at].text.clone();
            match text.as_str() {
                "extern" | "static" | "typedef" | "register" | "auto" | "thread_local" | "_Thread_local" => {
                    storage.push(text); at += 1;
                    if self.tokens.get(at).is_some_and(|token| token.kind == TokKind::StringLit) { at += 1; }
                }
                "const" | "volatile" | "restrict" | "inline" | "_Noreturn" | "constexpr" | "virtual" | "friend" => { at += 1; }
                "void" | "char" | "short" | "int" | "long" | "float" | "double" | "signed" | "unsigned" | "bool" | "_Bool" | "_Complex" => { types.push(text); at += 1; }
                "struct" | "union" | "enum" | "class" => {
                    let begin = at; at += 1;
                    if text == "enum" && (self.is(at, "class") || self.is(at, "struct")) { at += 1; }
                    while let Some(next) = self.attribute_end(at) { at = next; }
                    let name = self.tokens.get(at).filter(|token| token.kind == TokKind::Ident).map(|token| token.text.clone());
                    if name.is_some() { at += 1; }
                    let mut body = None;
                    if self.is(at, "{") {
                        let close = self.mates[at]?;
                        body = Some(self.range(at, close + 1));
                        let mut inner = scope.clone(); inner.aggregates.push(text.clone()); inner.field_context = true;
                        if text != "enum" { self.region(at + 1, close, &inner, depth + 1); }
                        at = close + 1;
                    }
                    self.aggregates.push(CAggregate { range: self.range(begin, at), body, kind: text.clone(), name: name.clone(), inside_struct: scope.aggregates.iter().any(|kind| kind == "struct") });
                    types.push(format!("{text} {}", name.unwrap_or_default()));
                }
                "return" | "break" | "continue" | "goto" | "throw" | "delete" | "new" | "sizeof" => break,
                _ if types.is_empty() && self.tokens[at].kind == TokKind::Ident => {
                    types.push(text); at += 1;
                    while self.is(at, "::") && self.tokens.get(at + 1).is_some_and(|token| token.kind == TokKind::Ident) {
                        types.push(format!("::{}", self.tokens[at + 1].text)); at += 2;
                    }
                }
                _ => break,
            }
        }
        (!types.is_empty()).then(|| (at, types.join(" "), storage))
    }

    fn declarator(&mut self, start: usize, end: usize, scope: &Scope, depth: usize) -> Option<(usize, CDeclarator)> {
        if depth > 128 || start >= end { return None; }
        let mut at = start;
        let mut pointers = 0;
        while self.is(at, "*") || self.is(at, "&") || self.is(at, "&&") {
            pointers += 1; at += 1;
            while self.tokens.get(at).is_some_and(|token| matches!(token.text.as_str(), "const" | "volatile" | "restrict")) { at += 1; }
        }
        let mut declaration = CDeclarator { name: None, range: self.range(start, at), derived: Vec::new(), initializer: None };
        if self.tokens.get(at).is_some_and(|token| token.kind == TokKind::Ident) {
            declaration.name = Some(self.tokens[at].text.clone()); at += 1;
            while self.is(at, "::") && self.tokens.get(at + 1).is_some_and(|token| token.kind == TokKind::Ident) {
                declaration.name = Some(self.tokens[at + 1].text.clone()); at += 2;
            }
        } else if self.is(at, "(") && !self.is(at + 1, ")") {
            let close = self.mates[at]?;
            let (next, nested) = self.declarator(at + 1, close, scope, depth + 1)?;
            if next != close { return None; }
            declaration = nested; at = close + 1;
        }
        while at < end {
            if self.is(at, "[") {
                let close = self.mates[at]?;
                declaration.derived.push(DerivedDeclarator::Array { size: self.range(at + 1, close) }); at = close + 1;
            } else if self.is(at, "(") {
                let close = self.mates[at]?;
                self.parameter_list(at + 1, close, scope, depth + 1);
                declaration.derived.push(DerivedDeclarator::Function { parameters: self.range(at + 1, close) }); at = close + 1;
            } else { break; }
        }
        declaration.derived.extend((0..pointers).map(|_| DerivedDeclarator::Pointer));
        declaration.range = self.range(start, at);
        (at > start).then_some((at, declaration))
    }

    fn parameter_list(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) {
        if depth > 128 { return; }
        while at < end {
            let start = at;
            while at < end && !self.is(at, ",") { at = self.skip_group(at); }
            if !self.is(start, "...") {
                if let Some((head, ty, _)) = self.specifiers(start, at, scope, depth + 1) {
                    let declaration = self.declarator(head, at, scope, depth + 1).map(|(_, declaration)| declaration);
                    self.parameters.push(CParameter { range: self.range(start, at), has_name: declaration.as_ref().is_some_and(|declaration| declaration.name.is_some()), plain_void: ty == "void" && head == at && at == start + 1 });
                }
            }
            at += usize::from(at < end);
        }
    }

    fn declaration(&mut self, start: usize, end: usize, scope: &Scope, depth: usize) -> Option<usize> {
        let (mut at, ty, storage) = self.specifiers(start, end, scope, depth)?;
        let mut declarators = Vec::new();
        while at < end && !self.is(at, ";") {
            let (next, mut declaration) = self.declarator(at, end, scope, depth)?;
            at = next;
            while let Some(next) = self.attribute_end(at) { at = next; }
            if self.is(at, "{") {
                if let Some(DerivedDeclarator::Function { parameters }) = declaration.derived.first() {
                    let close = self.mates[at]?;
                    let function = self.functions.len();
                    self.functions.push(CFunctionDefinition { range: self.range(start, close + 1), body: self.range(at, close + 1), parameters: parameters.clone(), name: declaration.name.clone()?, returns_void: ty == "void" && declaration.derived.len() == 1 });
                    let mut inner = scope.clone(); inner.function = Some(function); inner.field_context = false;
                    self.region(at + 1, close, &inner, depth + 1);
                    return Some(close + 1);
                }
            }
            if self.is(at, "=") {
                let init = at + 1; at = init;
                while at < end && !self.is(at, ";") && !self.is(at, ",") { at = self.skip_group(at); }
                declaration.initializer = Some(self.range(init, at));
                self.expression(init, at, scope, depth + 1);
            }
            declarators.push(declaration);
            if self.is(at, ",") { at += 1; } else { break; }
        }
        if !self.is(at, ";") { return None; }
        self.declarations.push(CDeclaration { range: self.range(start, at + 1), type_name: ty, storage, declarators, enclosing_function: scope.function, in_aggregate: scope.field_context });
        Some(at + 1)
    }

    fn expression(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) {
        if depth > 128 { return; }
        let mut lambda = false;
        while at < end {
            if self.is(at, "[") {
                if let Some(close) = self.mates[at] {
                    lambda = self.is(close + 1, "(") || self.is(close + 1, "{") || self.is(close + 1, "mutable");
                }
            }
            if self.is(at, "{") {
                if let Some(close) = self.mates[at] {
                    let mut inner = scope.clone(); if lambda { inner.function = None; }
                    self.region(at + 1, close, &inner, depth + 1); at = close + 1; lambda = false; continue;
                }
            }
            if self.is(at, "(") {
                if let Some(close) = self.mates[at] {
                    self.expression(at + 1, close, scope, depth + 1); at = close + 1; continue;
                }
            }
            at = self.skip_group(at);
        }
    }
}
