//! C-family declaration structure for source checkers. Declarator operators
//! are ordered from the declared name outwards, preserving the distinction
//! between `int *f()` (function) and `int (*f)()` (pointer to function).
//! Preprocessing directives must be masked by the caller without moving bytes.
use crate::{Lexer, LexerSpec, TokKind, Token};
use std::ops::Range;

#[derive(Clone, Debug)]
pub enum DerivedDeclarator {
    Pointer,
    Reference,
    RvalueReference,
    MemberPointer,
    Array { size: Range<usize> },
    Function { parameters: Range<usize> },
}

#[derive(Clone, Debug)]
pub struct CDeclarator {
    pub name: Option<String>,
    pub qualified_name: Option<String>,
    pub name_range: Option<Range<usize>>,
    pub range: Range<usize>,
    pub derived: Vec<DerivedDeclarator>,
    pub initializer: Option<Range<usize>>,
    pub bit_width: Option<Range<usize>>,
    /// C++ qualifiers written after a function declarator, for example the
    /// `const` in `void read() const;`.
    pub trailing_qualifiers: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CDeclaration {
    pub range: Range<usize>,
    pub type_name: String,
    pub storage: Vec<String>,
    pub declarators: Vec<CDeclarator>,
    pub enclosing_function: Option<usize>,
    pub in_aggregate: bool,
    pub extern_c: bool,
    pub qualification: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CFunctionDefinition {
    pub range: Range<usize>,
    pub body: Range<usize>,
    pub parameters: Range<usize>,
    pub name: String,
    pub qualified_name: String,
    pub name_range: Range<usize>,
    pub return_type: String,
    pub return_derived: Vec<DerivedDeclarator>,
    pub returns_void: bool,
    pub is_global: bool,
    pub is_static: bool,
    /// Whether this C++ member-function definition has a trailing `const`.
    pub is_const: bool,
    /// Whether the definition was declared under `extern "C"` linkage.
    /// Function definitions return from the declaration parser before a
    /// `CDeclaration` is recorded, so consumers cannot recover this from the
    /// declaration table after the fact.
    pub extern_c: bool,
    pub is_noreturn: bool,
    pub context: CFunctionContext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CFunctionContext {
    TranslationUnit,
    Namespace {
        name: String,
        qualified_name: String,
    },
    Record {
        qualified_name: String,
    },
    Other,
}

#[derive(Clone, Debug)]
pub struct CParameter {
    pub range: Range<usize>,
    pub type_name: String,
    /// True when the written parameter type contains a C++ placeholder `auto`
    /// whose type is still undeduced at the declaration site. This mirrors
    /// Clang's `Type::isUndeducedType()` predicate used by legacy checkers.
    pub undeduced_type: bool,
    pub name: Option<String>,
    pub name_range: Option<Range<usize>>,
    pub has_name: bool,
    pub plain_void: bool,
    pub derived: Vec<DerivedDeclarator>,
}

#[derive(Clone, Debug)]
pub struct CLabel {
    pub range: Range<usize>,
    pub name: String,
    pub function: usize,
    pub labels_another: bool,
}

#[derive(Clone, Debug)]
pub struct CGoto {
    pub range: Range<usize>,
    pub target: String,
    pub function: usize,
}

#[derive(Clone, Debug)]
pub struct CAggregate {
    pub range: Range<usize>,
    pub body: Option<Range<usize>>,
    pub kind: String,
    pub name: Option<String>,
    pub inside_struct: bool,
    pub enclosing_function: Option<usize>,
    pub qualified_name: String,
    pub bases: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CReturn {
    pub range: Range<usize>,
    pub value: Option<Range<usize>>,
    pub function: usize,
    pub has_value: bool,
    pub direct_child: bool,
}

#[derive(Clone, Debug)]
pub struct CEnumerator {
    pub range: Range<usize>,
    pub name: String,
    pub enum_range: Range<usize>,
    pub enum_name: Option<String>,
    pub scoped: bool,
    pub initializer: Option<Range<usize>>,
    pub enclosing_function: Option<usize>,
    pub qualification: Vec<String>,
}

pub struct CDeclarationIndex {
    pub declarations: Vec<CDeclaration>,
    pub functions: Vec<CFunctionDefinition>,
    pub parameters: Vec<CParameter>,
    pub aggregates: Vec<CAggregate>,
    pub returns: Vec<CReturn>,
    pub labels: Vec<CLabel>,
    pub gotos: Vec<CGoto>,
    pub enumerators: Vec<CEnumerator>,
    tokens: Vec<Token>,
    mates: Vec<Option<usize>>,
}

#[derive(Clone, Default)]
struct Scope {
    function: Option<usize>,
    function_body_depth: Option<usize>,
    aggregates: Vec<String>,
    field_context: bool,
    extern_c: bool,
    qualification: Vec<String>,
    namespace_qualification: Vec<String>,
    record_qualified_name: Option<String>,
}

fn qualified_declarator_name(scope: &Scope, declarator: &CDeclarator) -> String {
    let explicit = declarator.qualified_name.as_deref().unwrap_or_default();
    if explicit.contains("::") || scope.qualification.is_empty() {
        explicit.to_string()
    } else {
        let mut parts = scope.qualification.clone();
        parts.push(explicit.to_string());
        parts.join("::")
    }
}

impl CDeclarationIndex {
    pub fn parse(source: &str) -> Self {
        let tokens = Lexer::new(source, &LexerSpec::default()).tokenize();
        let mut mates = vec![None; tokens.len()];
        let mut stack = Vec::new();
        for (at, token) in tokens.iter().enumerate() {
            if token.kind != TokKind::Symbol {
                continue;
            }
            match token.text.as_str() {
                "(" | "[" | "{" => stack.push(at),
                ")" | "]" | "}" => {
                    let wanted = match token.text.as_str() {
                        ")" => "(",
                        "]" => "[",
                        _ => "{",
                    };
                    if let Some(&open) = stack.last() {
                        if tokens[open].text == wanted {
                            stack.pop();
                            mates[open] = Some(at);
                            mates[at] = Some(open);
                        }
                    }
                }
                _ => {}
            }
        }
        let mut index = Self {
            declarations: Vec::new(),
            functions: Vec::new(),
            parameters: Vec::new(),
            aggregates: Vec::new(),
            returns: Vec::new(),
            labels: Vec::new(),
            gotos: Vec::new(),
            enumerators: Vec::new(),
            tokens,
            mates,
        };
        index.region(0, index.tokens.len() - 1, &Scope::default(), 0);
        index.resolve_out_of_line_record_contexts();
        index
    }

    fn resolve_out_of_line_record_contexts(&mut self) {
        let records = self
            .aggregates
            .iter()
            .filter(|aggregate| aggregate.kind != "enum" && !aggregate.qualified_name.is_empty())
            .map(|aggregate| aggregate.qualified_name.clone())
            .collect::<std::collections::HashSet<_>>();

        for function in &mut self.functions {
            if matches!(function.context, CFunctionContext::Record { .. }) {
                continue;
            }
            let Some((owner, _)) = function.qualified_name.rsplit_once("::") else {
                continue;
            };
            let mut candidates = vec![owner.to_string()];
            if let CFunctionContext::Namespace { qualified_name, .. } = &function.context {
                if !qualified_name.is_empty() && !owner.starts_with(&format!("{qualified_name}::")) {
                    candidates.push(format!("{qualified_name}::{owner}"));
                }
            }
            if let Some(record) = candidates.into_iter().find(|candidate| records.contains(candidate)) {
                function.context = CFunctionContext::Record {
                    qualified_name: record,
                };
            }
        }
    }

    pub fn tokens_in(&self, range: Range<usize>) -> impl Iterator<Item = &Token> {
        self.tokens.iter().filter(move |token| {
            token.kind != TokKind::Eof
                && token.start as usize >= range.start
                && (token.end as usize) <= range.end
        })
    }

    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub fn matching_token_index(&self, index: usize) -> Option<usize> {
        self.mates.get(index).copied().flatten()
    }

    fn is(&self, at: usize, text: &str) -> bool {
        self.tokens
            .get(at)
            .is_some_and(|token| token.kind != TokKind::StringLit && token.text == text)
    }

    fn range(&self, start: usize, end: usize) -> Range<usize> {
        let begin = self.tokens[start].start as usize;
        begin..if end > start {
            self.tokens[end - 1].end as usize
        } else {
            begin
        }
    }

    fn overloaded_operator_name(
        &self,
        at: usize,
        end: usize,
    ) -> Option<(usize, String, Range<usize>)> {
        if !self.is(at, "operator") || at + 1 >= end {
            return None;
        }
        let start = at;
        let mut next = at + 1;
        let suffix = match self.tokens.get(next)?.text.as_str() {
            "new" | "delete" => {
                let word = self.tokens[next].text.clone();
                next += 1;
                if next + 1 < end && self.is(next, "[") && self.is(next + 1, "]") {
                    next += 2;
                    format!(" {word}[]")
                } else {
                    format!(" {word}")
                }
            }
            "(" if next + 1 < end && self.is(next + 1, ")") => {
                next += 2;
                "()".to_string()
            }
            "[" if next + 1 < end && self.is(next + 1, "]") => {
                next += 2;
                "[]".to_string()
            }
            "=" | "+" | "-" | "*" | "/" | "%" | "^" | "&" | "|" | "~" | "!"
            | "<" | ">" | "+=" | "-=" | "*=" | "/=" | "%=" | "^=" | "&=" | "|="
            | "<<" | ">>" | "<<=" | ">>=" | "==" | "!=" | "<=" | ">=" | "<=>"
            | "&&" | "||" | "++" | "--" | "," | "->" => {
                let operator = self.tokens[next].text.clone();
                next += 1;
                operator
            }
            _ => return None,
        };
        Some((
            next,
            format!("operator{suffix}"),
            self.range(start, next),
        ))
    }

    fn skip_group(&self, at: usize) -> usize {
        self.mates[at]
            .filter(|&close| close > at)
            .map_or(at + 1, |close| close + 1)
    }

    fn attribute_end(&self, at: usize) -> Option<usize> {
        if self.is(at, "__attribute__")
            || self.is(at, "__declspec")
            || self.is(at, "alignas")
            || self.is(at, "_Alignas")
        {
            if self.is(at + 1, "(") {
                return self.mates[at + 1].map(|close| close + 1);
            }
        }
        if self.is(at, "[") && self.is(at + 1, "[") {
            return self.mates[at].map(|close| close + 1);
        }
        None
    }

    fn region(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) {
        if depth > 128 {
            return;
        }
        while at < end {
            if self.is(at, ";") || self.is(at, "else") {
                at += 1;
                continue;
            }
            if self.is(at, "namespace")
                || self.is(at, "extern")
                    && self
                        .tokens
                        .get(at + 1)
                        .is_some_and(|token| token.kind == TokKind::StringLit)
                    && self.is(at + 2, "{")
            {
                let mut open = at + 1;
                while open < end && !self.is(open, "{") && !self.is(open, ";") {
                    open += 1;
                }
                if let Some(close) = self.mates.get(open).copied().flatten() {
                    let mut inner = scope.clone();
                    if self.is(at, "extern") {
                        inner.extern_c = true;
                    } else {
                        let names = self.tokens[at + 1..open]
                            .iter()
                            .filter(|token| token.kind == TokKind::Ident)
                            .map(|token| token.text.clone())
                            .collect::<Vec<_>>();
                        inner.qualification.extend(names.iter().cloned());
                        if names.is_empty() {
                            inner.namespace_qualification.push(String::new());
                        } else {
                            inner.namespace_qualification.extend(names);
                        }
                    }
                    self.region(open + 1, close, &inner, depth + 1);
                    at = close + 1;
                    continue;
                }
            }
            if matches!(
                self.tokens[at].text.as_str(),
                "if" | "while" | "for" | "switch" | "catch"
            ) && self.is(at + 1, "(")
            {
                if let Some(close) = self.mates[at + 1] {
                    if self.is(at, "for") {
                        self.region(at + 2, close, scope, depth + 1);
                    } else {
                        self.expression(at + 2, close, scope, depth + 1);
                    }
                    at = close + 1;
                    continue;
                }
            }
            if self.is(at, "do") {
                at += 1;
                continue;
            }
            if self.is(at, "return") {
                let mut next = at + 1;
                while next < end && !self.is(next, ";") {
                    next = self.skip_group(next);
                }
                if let Some(function) = scope.function {
                    self.returns.push(CReturn {
                        range: self.range(at, (next + 1).min(end)),
                        value: (next > at + 1).then(|| self.range(at + 1, next)),
                        function,
                        has_value: next > at + 1,
                        direct_child: scope.function_body_depth == Some(depth),
                    });
                }
                self.expression(at + 1, next, scope, depth + 1);
                at = (next + 1).min(end);
                continue;
            }
            if self.is(at, "goto")
                && self
                    .tokens
                    .get(at + 1)
                    .is_some_and(|token| token.kind == TokKind::Ident)
            {
                if let Some(function) = scope.function {
                    self.gotos.push(CGoto {
                        range: self.range(at, at + 1),
                        target: self.tokens[at + 1].text.clone(),
                        function,
                    });
                }
                while at < end && !self.is(at, ";") {
                    at += 1;
                }
                at += usize::from(at < end);
                continue;
            }
            if self.is(at, "{") {
                if let Some(close) = self.mates[at] {
                    self.region(at + 1, close, scope, depth + 1);
                    at = close + 1;
                    continue;
                }
            }
            if self.tokens[at].kind == TokKind::Ident && self.is(at + 1, ":") {
                if let Some(function) = scope.function {
                    self.labels.push(CLabel {
                        range: self.range(at, at + 1),
                        name: self.tokens[at].text.clone(),
                        function,
                        labels_another: self
                            .tokens
                            .get(at + 2)
                            .is_some_and(|token| token.kind == TokKind::Ident)
                            && self.is(at + 3, ":"),
                    });
                }
                at += 2;
                continue;
            }
            if self.is(at, "case") {
                while at < end && !self.is(at, ":") {
                    at = self.skip_group(at);
                }
                at += usize::from(at < end);
                continue;
            }
            let checkpoint = (
                self.declarations.len(),
                self.functions.len(),
                self.parameters.len(),
                self.aggregates.len(),
                self.returns.len(),
                self.labels.len(),
                self.gotos.len(),
                self.enumerators.len(),
            );
            if let Some(next) = self.declaration(at, end, scope, depth + 1) {
                at = next;
                continue;
            }
            // Declaration recognition is speculative: expression-shaped text
            // must not leave parameter or aggregate records behind.
            self.declarations.truncate(checkpoint.0);
            self.functions.truncate(checkpoint.1);
            self.parameters.truncate(checkpoint.2);
            self.aggregates.truncate(checkpoint.3);
            self.returns.truncate(checkpoint.4);
            self.labels.truncate(checkpoint.5);
            self.gotos.truncate(checkpoint.6);
            self.enumerators.truncate(checkpoint.7);
            let start = at;
            while at < end && !self.is(at, ";") {
                at = self.skip_group(at);
            }
            self.expression(start, at, scope, depth + 1);
            at += usize::from(at < end);
        }
    }

    fn specifiers(
        &mut self,
        mut at: usize,
        end: usize,
        scope: &Scope,
        depth: usize,
    ) -> Option<(usize, String, Vec<String>)> {
        let mut types = Vec::new();
        let mut storage = Vec::new();
        while at < end {
            if let Some(next) = self.attribute_end(at) {
                at = next;
                continue;
            }
            let text = self.tokens[at].text.clone();
            match text.as_str() {
                "extern" | "static" | "typedef" | "register" | "auto" | "thread_local"
                | "_Thread_local" => {
                    storage.push(text);
                    at += 1;
                    if self
                        .tokens
                        .get(at)
                        .is_some_and(|token| token.kind == TokKind::StringLit)
                    {
                        storage.push("extern_c".to_string());
                        at += 1;
                    }
                }
                "const" | "volatile" | "restrict" | "inline" | "_Noreturn" | "constexpr"
                | "virtual" | "friend" => {
                    at += 1;
                }
                "void" | "char" | "short" | "int" | "long" | "float" | "double" | "signed"
                | "unsigned" | "bool" | "_Bool" | "_Complex" => {
                    types.push(text);
                    at += 1;
                }
                "struct" | "union" | "enum" | "class" => {
                    let begin = at;
                    at += 1;
                    let scoped_enum =
                        text == "enum" && (self.is(at, "class") || self.is(at, "struct"));
                    if scoped_enum {
                        at += 1;
                    }
                    while let Some(next) = self.attribute_end(at) {
                        at = next;
                    }
                    let name = self
                        .tokens
                        .get(at)
                        .filter(|token| token.kind == TokKind::Ident)
                        .map(|token| token.text.clone());
                    if name.is_some() {
                        at += 1;
                    }
                    loop {
                        if self.is(at, "final") {
                            at += 1;
                        } else if let Some(next) = self.attribute_end(at) {
                            at = next;
                        } else {
                            break;
                        }
                    }
                    let mut bases = Vec::new();
                    if self.is(at, ":") {
                        at += 1;
                        let mut base_parts = Vec::new();
                        while at < end && !self.is(at, "{") && !self.is(at, ";") {
                            if self.is(at, ",") {
                                if !base_parts.is_empty() {
                                    bases.push(base_parts.join(""));
                                    base_parts.clear();
                                }
                                at += 1;
                                continue;
                            }
                            let token = &self.tokens[at];
                            if token.kind == TokKind::Ident
                                && !matches!(
                                    token.text.as_str(),
                                    "public" | "protected" | "private" | "virtual" | "final"
                                )
                                || token.text == "::"
                            {
                                base_parts.push(token.text.clone());
                            }
                            at += 1;
                        }
                        if !base_parts.is_empty() {
                            bases.push(base_parts.join(""));
                        }
                    }
                    let mut body = None;
                    if self.is(at, "{") {
                        let close = self.mates[at]?;
                        body = Some(self.range(at, close + 1));
                        let mut inner = scope.clone();
                        inner.aggregates.push(text.clone());
                        inner.field_context = true;
                        if let Some(name) = &name {
                            inner.qualification.push(name.clone());
                        }
                        if text != "enum" {
                            inner.record_qualified_name = Some(inner.qualification.join("::"));
                        }
                        if text == "enum" {
                            let mut enumerator = at + 1;
                            while enumerator < close {
                                while enumerator < close
                                    && (self.is(enumerator, ",")
                                        || self.attribute_end(enumerator).is_some())
                                {
                                    enumerator = self
                                        .attribute_end(enumerator)
                                        .unwrap_or(enumerator + 1);
                                }
                                if enumerator >= close {
                                    break;
                                }
                                if self.tokens[enumerator].kind == TokKind::Ident {
                                    let name_at = enumerator;
                                    let mut segment_end = enumerator + 1;
                                    while segment_end < close && !self.is(segment_end, ",") {
                                        segment_end = self.skip_group(segment_end);
                                    }
                                    let initializer = (name_at + 1..segment_end)
                                        .find(|candidate| self.is(*candidate, "="))
                                        .and_then(|equals| {
                                            (equals + 1 < segment_end).then(|| {
                                                self.range(equals + 1, segment_end)
                                            })
                                        });
                                    self.enumerators.push(CEnumerator {
                                        range: self.range(name_at, name_at + 1),
                                        name: self.tokens[name_at].text.clone(),
                                        enum_range: self.range(begin, close + 1),
                                        enum_name: name.clone(),
                                        scoped: scoped_enum,
                                        initializer,
                                        enclosing_function: scope.function,
                                        qualification: scope.qualification.clone(),
                                    });
                                    enumerator = segment_end;
                                }
                                while enumerator < close && !self.is(enumerator, ",") {
                                    enumerator = self.skip_group(enumerator);
                                }
                            }
                        } else {
                            self.region(at + 1, close, &inner, depth + 1);
                        }
                        at = close + 1;
                    }
                    self.aggregates.push(CAggregate {
                        range: self.range(begin, at),
                        body,
                        kind: text.clone(),
                        name: name.clone(),
                        inside_struct: scope.aggregates.iter().any(|kind| kind == "struct"),
                        enclosing_function: scope.function,
                        qualified_name: {
                            let mut parts = scope.qualification.clone();
                            if let Some(name) = &name {
                                parts.push(name.clone());
                            }
                            parts.join("::")
                        },
                        bases,
                    });
                    types.push(format!("{text} {}", name.unwrap_or_default()));
                }
                "return" | "break" | "continue" | "goto" | "throw" | "delete" | "new"
                | "sizeof" => break,
                _ if types.is_empty() && self.tokens[at].kind == TokKind::Ident => {
                    types.push(text);
                    at += 1;
                    while self.is(at, "::")
                        && self
                            .tokens
                            .get(at + 1)
                            .is_some_and(|token| token.kind == TokKind::Ident)
                    {
                        types.push(format!("::{}", self.tokens[at + 1].text));
                        at += 2;
                    }
                    if self.is(at, "<") {
                        let mut template = String::new();
                        let mut angle_depth = 0usize;
                        while at < end {
                            let part = self.tokens[at].text.as_str();
                            template.push_str(part);
                            match part {
                                "<" => angle_depth += 1,
                                ">" => angle_depth = angle_depth.saturating_sub(1),
                                ">>" => angle_depth = angle_depth.saturating_sub(2),
                                _ => {}
                            }
                            at += 1;
                            if angle_depth == 0 {
                                break;
                            }
                        }
                        types.push(template);
                    }
                }
                _ => break,
            }
        }
        (!types.is_empty()).then(|| (at, types.join(" "), storage))
    }

    fn declarator(
        &mut self,
        start: usize,
        end: usize,
        scope: &Scope,
        depth: usize,
    ) -> Option<(usize, CDeclarator)> {
        if depth > 128 || start >= end {
            return None;
        }
        let mut at = start;
        let mut prefix = Vec::new();
        if self
            .tokens
            .get(at)
            .is_some_and(|token| token.kind == TokKind::Ident)
        {
            let mut probe = at;
            while self.is(probe + 1, "::") {
                if self.is(probe + 2, "*") {
                    prefix.push(DerivedDeclarator::MemberPointer);
                    at = probe + 3;
                    break;
                }
                if self
                    .tokens
                    .get(probe + 2)
                    .is_some_and(|token| token.kind == TokKind::Ident)
                {
                    probe += 2;
                } else {
                    break;
                }
            }
        }
        while self.is(at, "*")
            || self.is(at, "**")
            || self.is(at, "&")
            || self.is(at, "&&")
        {
            match self.tokens[at].text.as_str() {
                // The shared lexer recognizes Python-style `**` as one token.
                // In a C declarator the same bytes are always two pointer layers.
                "**" => {
                    prefix.push(DerivedDeclarator::Pointer);
                    prefix.push(DerivedDeclarator::Pointer);
                }
                "*" => prefix.push(DerivedDeclarator::Pointer),
                "&" => prefix.push(DerivedDeclarator::Reference),
                "&&" => prefix.push(DerivedDeclarator::RvalueReference),
                _ => unreachable!("prefix declarator spelling filtered above"),
            }
            at += 1;
            while self.tokens.get(at).is_some_and(|token| {
                matches!(token.text.as_str(), "const" | "volatile" | "restrict")
            }) {
                at += 1;
            }
        }
        let mut declaration = CDeclarator {
            name: None,
            qualified_name: None,
            name_range: None,
            range: self.range(start, at),
            derived: Vec::new(),
            initializer: None,
            bit_width: None,
            trailing_qualifiers: Vec::new(),
        };
        if let Some((next, name, name_range)) = self.overloaded_operator_name(at, end) {
            declaration.name = Some(name.clone());
            declaration.qualified_name = Some(name);
            declaration.name_range = Some(name_range);
            at = next;
        } else if self
            .tokens
            .get(at)
            .is_some_and(|token| token.kind == TokKind::Ident)
        {
            let mut name_range = self.range(at, at + 1);
            let mut name_parts = vec![self.tokens[at].text.clone()];
            at += 1;
            while self.is(at, "::") {
                if let Some((next, name, range)) = self.overloaded_operator_name(at + 1, end) {
                    name_parts.push(name);
                    name_range = range;
                    at = next;
                    break;
                }
                if self
                    .tokens
                    .get(at + 1)
                    .is_some_and(|token| token.kind == TokKind::Ident)
                {
                    name_parts.push(self.tokens[at + 1].text.clone());
                    name_range = self.range(at + 1, at + 2);
                    at += 2;
                } else {
                    break;
                }
            }
            declaration.name = name_parts.last().cloned();
            declaration.qualified_name = Some(name_parts.join("::"));
            declaration.name_range = Some(name_range);
        } else if self.is(at, "(") && !self.is(at + 1, ")") {
            let close = self.mates[at]?;
            let (next, nested) = self.declarator(at + 1, close, scope, depth + 1)?;
            if next != close {
                return None;
            }
            declaration = nested;
            at = close + 1;
        }
        while at < end {
            if self.is(at, "[") {
                let close = self.mates[at]?;
                declaration.derived.push(DerivedDeclarator::Array {
                    size: self.range(at + 1, close),
                });
                at = close + 1;
            } else if self.is(at, "(") {
                let close = self.mates[at]?;
                self.parameter_list(at + 1, close, scope, depth + 1);
                declaration.derived.push(DerivedDeclarator::Function {
                    parameters: self.range(at + 1, close),
                });
                at = close + 1;
            } else {
                break;
            }
        }
        // Prefix declarators are written from the base type toward the name,
        // while `derived` is stored from the declared name outward.
        declaration.derived.extend(prefix.into_iter().rev());
        declaration.range = self.range(start, at);
        (at > start).then_some((at, declaration))
    }

    fn parameter_list(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) {
        if depth > 128 {
            return;
        }
        while at < end {
            let start = at;
            while at < end && !self.is(at, ",") {
                at = self.skip_group(at);
            }
            if !self.is(start, "...") {
                let placeholder = self.undeduced_parameter_specifiers(start, at);
                let parsed = placeholder
                    .map(|(head, ty)| (head, ty, true))
                    .or_else(|| {
                        self.specifiers(start, at, scope, depth + 1)
                            .map(|(head, ty, _)| (head, ty, false))
                    });
                if let Some((head, ty, undeduced_type)) = parsed {
                    let declaration = self
                        .declarator(head, at, scope, depth + 1)
                        .map(|(_, declaration)| declaration);
                    self.parameters.push(CParameter {
                        range: self.range(start, at),
                        type_name: ty.clone(),
                        undeduced_type,
                        name: declaration
                            .as_ref()
                            .and_then(|declaration| declaration.name.clone()),
                        name_range: declaration
                            .as_ref()
                            .and_then(|declaration| declaration.name_range.clone()),
                        has_name: declaration
                            .as_ref()
                            .is_some_and(|declaration| declaration.name.is_some()),
                        plain_void: ty == "void" && head == at && at == start + 1,
                        derived: declaration
                            .map(|declaration| declaration.derived)
                            .unwrap_or_default(),
                    });
                }
            }
            at += usize::from(at < end);
        }
    }

    fn undeduced_parameter_specifiers(
        &self,
        start: usize,
        end: usize,
    ) -> Option<(usize, String)> {
        let mut at = start;
        while at < end {
            if let Some(next) = self.attribute_end(at) {
                at = next;
                continue;
            }
            if self.is(at, "=") {
                break;
            }
            if self.is(at, "auto") {
                return Some((at + 1, "auto".to_string()));
            }
            if matches!(self.tokens[at].text.as_str(), "(" | "[" | "{") {
                at = self.skip_group(at);
            } else {
                at += 1;
            }
        }
        None
    }

    fn declaration(
        &mut self,
        start: usize,
        end: usize,
        scope: &Scope,
        depth: usize,
    ) -> Option<usize> {
        let (mut at, ty, storage) = self.specifiers(start, end, scope, depth)?;
        let mut declarators = Vec::new();
        while at < end && !self.is(at, ";") {
            let (next, mut declaration) = self.declarator(at, end, scope, depth)?;
            at = next;
            while let Some(next) = self.attribute_end(at) {
                at = next;
            }
            while at < end
                && matches!(
                    self.tokens[at].text.as_str(),
                    "const" | "volatile" | "override" | "final" | "&" | "&&"
                )
            {
                declaration
                    .trailing_qualifiers
                    .push(self.tokens[at].text.clone());
                at += 1;
            }
            if self.is(at, "noexcept") {
                declaration.trailing_qualifiers.push("noexcept".to_string());
                at += 1;
                if self.is(at, "(") {
                    at = self.skip_group(at);
                }
            }
            if self.is(at, ":") {
                let width = at + 1;
                at = width;
                while at < end && !self.is(at, ";") && !self.is(at, ",") {
                    at = self.skip_group(at);
                }
                declaration.bit_width = Some(self.range(width, at));
                self.expression(width, at, scope, depth + 1);
            }
            if self.is(at, "{") {
                if let Some(DerivedDeclarator::Function { parameters }) =
                    declaration.derived.first()
                {
                    let close = self.mates[at]?;
                    let function = self.functions.len();
                    let name = declaration.name.clone()?;
                    let name_range = declaration.name_range.clone()?;
                    self.functions.push(CFunctionDefinition {
                        range: self.range(start, close + 1),
                        body: self.range(at, close + 1),
                        parameters: parameters.clone(),
                        name,
                        qualified_name: qualified_declarator_name(scope, &declaration),
                        name_range,
                        return_type: ty.clone(),
                        return_derived: declaration.derived.iter().skip(1).cloned().collect(),
                        returns_void: ty == "void" && declaration.derived.len() == 1,
                        is_global: scope.function.is_none() && !scope.field_context,
                        is_static: storage.iter().any(|item| item == "static"),
                        is_const: declaration
                            .trailing_qualifiers
                            .iter()
                            .any(|qualifier| qualifier == "const"),
                        extern_c: scope.extern_c
                            || storage.iter().any(|item| item == "extern_c"),
                        is_noreturn: self.tokens[start..at]
                            .iter()
                            .any(|token| matches!(token.text.as_str(), "noreturn" | "_Noreturn")),
                        context: if let Some(qualified_name) = &scope.record_qualified_name {
                            CFunctionContext::Record {
                                qualified_name: qualified_name.clone(),
                            }
                        } else if scope.function.is_some() {
                            CFunctionContext::Other
                        } else if let Some(name) = scope.namespace_qualification.last() {
                            CFunctionContext::Namespace {
                                name: name.clone(),
                                qualified_name: scope
                                    .namespace_qualification
                                    .iter()
                                    .filter(|part| !part.is_empty())
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join("::"),
                            }
                        } else {
                            CFunctionContext::TranslationUnit
                        },
                    });
                    let mut inner = scope.clone();
                    inner.function = Some(function);
                    inner.function_body_depth = Some(depth + 1);
                    inner.field_context = false;
                    self.region(at + 1, close, &inner, depth + 1);
                    return Some(close + 1);
                }
            }
            if self.is(at, "=") {
                let init = at + 1;
                at = init;
                while at < end && !self.is(at, ";") && !self.is(at, ",") {
                    at = self.skip_group(at);
                }
                declaration.initializer = Some(self.range(init, at));
                self.expression(init, at, scope, depth + 1);
            }
            declarators.push(declaration);
            if self.is(at, ",") {
                at += 1;
            } else {
                break;
            }
        }
        if !self.is(at, ";") {
            return None;
        }
        let extern_c = scope.extern_c || storage.iter().any(|item| item == "extern_c");
        self.declarations.push(CDeclaration {
            range: self.range(start, at + 1),
            type_name: ty,
            storage,
            declarators,
            enclosing_function: scope.function,
            in_aggregate: scope.field_context,
            extern_c,
            qualification: scope.qualification.clone(),
        });
        Some(at + 1)
    }

    fn expression(&mut self, mut at: usize, end: usize, scope: &Scope, depth: usize) {
        if depth > 128 {
            return;
        }
        let mut lambda = false;
        while at < end {
            if self.is(at, "[") {
                if let Some(close) = self.mates[at] {
                    lambda = self.is(close + 1, "(")
                        || self.is(close + 1, "{")
                        || self.is(close + 1, "mutable");
                }
            }
            if self.is(at, "{") {
                if let Some(close) = self.mates[at] {
                    let mut inner = scope.clone();
                    if lambda {
                        inner.function = None;
                    }
                    self.region(at + 1, close, &inner, depth + 1);
                    at = close + 1;
                    lambda = false;
                    continue;
                }
            }
            if self.is(at, "(") {
                if let Some(close) = self.mates[at] {
                    self.expression(at + 1, close, scope, depth + 1);
                    at = close + 1;
                    continue;
                }
            }
            at = self.skip_group(at);
        }
    }
}
