// Token cursor shared by the generic statement and expression engines.
//
// The cursor owns bracket depth so that languages with significant newlines
// (Python, Ruby, Shell) can suppress line terminators inside `(...)`, `[...]`
// the same way their grammars do, and it produces HIR spans from
// token offsets.

/// A token stream with parser bookkeeping.
pub struct Cursor<'a> {
    pub tokens: Vec<Token>,
    pub pos: usize,
    pub source: &'a str,
    pub spec: &'a LexerSpec,
    pub file: u32,
    /// Nesting depth of `(` and `[`. Braces delimit statement blocks and must
    /// not suppress newlines in Go, Swift, JavaScript, Ruby, or Shell bodies.
    pub depth: i32,
    /// Recoverable syntax problems. Parsing never aborts on them: the frontend
    /// keeps whatever structure it recovered.
    pub errors: Vec<ParseError>,
}

#[derive(Clone, Debug)]
pub struct ParseError {
    pub message: String,
    pub line: u32,
    pub col: u32,
    pub offset: u32,
}

impl<'a> Cursor<'a> {
    pub fn new(source: &'a str, spec: &'a LexerSpec, tokens: Vec<Token>, file: u32) -> Self {
        let mut tokens = tokens;
        if tokens.last().map_or(true, |token| token.kind != TokKind::Eof) {
            let end = source.len() as u32;
            tokens.push(Token {
                kind: TokKind::Eof,
                text: String::new(),
                parts: Vec::new(),
                start: end,
                end,
                line: 1,
                col: 1,
                space_before: false,
                newlines_before: 0,
                is_keyword: false,
            });
        }
        Self {
            tokens,
            pos: 0,
            source,
            spec,
            file,
            depth: 0,
            errors: Vec::new(),
        }
    }

    /// Lex `source` with `spec` and build a cursor over it.
    pub fn lex(source: &'a str, spec: &'a LexerSpec, file: u32) -> Self {
        let tokens = Lexer::new(source, spec).tokenize();
        Self::new(source, spec, tokens, file)
    }

    pub fn eof(&self) -> bool {
        self.current().kind == TokKind::Eof
    }

    /// Token at the cursor position. Always valid: an EOF sentinel is appended.
    pub fn current(&self) -> &Token {
        self.tokens.get(self.pos.min(self.tokens.len() - 1)).unwrap()
    }

    pub fn peek(&self, ahead: usize) -> &Token {
        self.tokens
            .get((self.pos + ahead).min(self.tokens.len() - 1))
            .unwrap()
    }

    /// Current token text, ignoring suppressed line terminators.
    pub fn text(&self) -> &str {
        &self.current().text
    }

    pub fn at(&self, text: &str) -> bool {
        let token = self.current();
        token.kind == TokKind::Symbol && token.text == text
    }

    pub fn at_kw(&self, text: &str) -> bool {
        let token = self.current();
        if token.is_keyword && token.text == text {
            return true;
        }
        // Case-insensitive languages still lex the source spelling.
        self.spec.case_insensitive_keywords
            && token.kind == TokKind::Keyword
            && token.text.eq_ignore_ascii_case(text)
    }

    pub fn at_kw_any(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.at_kw(name))
    }

    pub fn at_any(&self, names: &[&str]) -> bool {
        names.iter().any(|name| self.at(name))
    }

    pub fn at_ident_named(&self, name: &str) -> bool {
        let token = self.current();
        token.kind == TokKind::Ident && token.text == name
    }

    /// True when the current token can start an identifier-shaped name.
    pub fn at_name(&self) -> bool {
        matches!(self.current().kind, TokKind::Ident)
            || (self.spec.dollar_idents && self.current().kind == TokKind::Ident)
    }

    pub fn at_newline(&self) -> bool {
        self.current().kind == TokKind::Newline
    }

    pub fn at_end_of_stmt(&self) -> bool {
        matches!(self.current().kind, TokKind::Newline | TokKind::Eof) || self.at(";")
    }

    pub fn line(&self) -> u32 {
        self.current().line
    }

    pub fn offset(&self) -> u32 {
        self.current().start
    }

    /// Consume the current token and return its text.
    pub fn advance(&mut self) -> String {
        let token = self.current().clone();
        match token.text.as_str() {
            "(" | "[" => self.depth += 1,
            ")" | "]" => self.depth = self.depth.saturating_sub(1),
            _ => {}
        }
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        self.skip_suppressed_newlines();
        token.text
    }

    /// Consume a token without caring about its text.
    pub fn skip(&mut self) {
        self.advance();
    }

    fn skip_suppressed_newlines(&mut self) {
        if self.depth > 0 {
            while self.current().kind == TokKind::Newline && self.pos < self.tokens.len() - 1 {
                self.pos += 1;
            }
        }
    }

    /// Consume line terminators explicitly (used between statements).
    pub fn skip_newlines(&mut self) {
        while self.current().kind == TokKind::Newline && self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
    }

    pub fn eat(&mut self, text: &str) -> bool {
        if self.at(text) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub fn eat_kw(&mut self, text: &str) -> bool {
        if self.at_kw(text) {
            self.advance();
            true
        } else {
            false
        }
    }

    pub fn eat_kw_any(&mut self, names: &[&str]) -> Option<String> {
        for name in names {
            if self.at_kw(name) {
                self.advance();
                return Some((*name).to_string());
            }
        }
        None
    }

    pub fn eat_any(&mut self, names: &[&str]) -> Option<String> {
        for name in names {
            if self.at(name) {
                self.advance();
                return Some((*name).to_string());
            }
        }
        None
    }

    /// Consume `text` or record a recoverable error.
    pub fn expect(&mut self, text: &str) -> bool {
        if self.eat(text) {
            return true;
        }
        let token = self.current().clone();
        self.error_at(
            &format!("expected `{}` but found `{}`", text, token.text),
            &token,
        );
        false
    }

    pub fn error(&mut self, message: &str) {
        let token = self.current().clone();
        self.error_at(message, &token);
    }

    fn error_at(&mut self, message: &str, token: &Token) {
        self.errors.push(ParseError {
            message: message.to_string(),
            line: token.line,
            col: token.col,
            offset: token.start,
        });
    }

    pub fn take_errors(&mut self) -> Vec<ParseError> {
        std::mem::take(&mut self.errors)
    }

    /// Consume a name-like token and return it without its sigil.
    pub fn name(&mut self) -> String {
        let token = self.current().clone();
        if token.kind == TokKind::Ident || token.kind == TokKind::Keyword {
            let text = token.text.clone();
            self.advance();
            return strip_ident_sigils(&text);
        }
        self.error("expected a name");
        String::new()
    }

    /// Consume a name-like token, keeping `$`/`@` sigils (PHP, ObjC).
    pub fn name_with_sigil(&mut self) -> String {
        let token = self.current().clone();
        if token.kind == TokKind::Ident || token.kind == TokKind::Keyword {
            let text = token.text.clone();
            self.advance();
            return text;
        }
        self.error("expected a name");
        String::new()
    }

    pub fn span_of(&self, token: &Token) -> uniflow_hir::Span {
        span_from_offsets_file(self.file, self.source, token.start as usize, token.end as usize)
    }

    /// Span covering tokens `[start_pos, self.pos)`; empty spans extend to the
    /// end of the previous token so a zero-length span still names a line.
    pub fn span_from(&self, start_pos: usize) -> uniflow_hir::Span {
        let start_token = &self.tokens[start_pos.min(self.tokens.len() - 1)];
        let end_token = &self.tokens[end_token_index_clamped(self.pos, self.tokens.len())];
        let start = start_token.start as usize;
        let end = if self.pos > start_pos {
            end_token.end.max(start_token.end) as usize
        } else {
            start_token.end as usize
        };
        span_from_offsets_file(self.file, self.source, start, end)
    }

    /// Span of the current token plus the tokens consumed since `start_pos`.
    pub fn span_covering(&self, start_pos: usize) -> uniflow_hir::Span {
        let start = self.tokens[start_pos.min(self.tokens.len() - 1)]
            .start
            .min(self.current().start) as usize;
        let end = self.current().end as usize;
        span_from_offsets_file(self.file, self.source, start, end.max(start))
    }

    /// Re-lex an interpolation hole and return its tokens.
    pub fn lex_sub(&self, start: u32, end: u32) -> Vec<Token> {
        Lexer::new(self.source, self.spec).tokenize_range(start, end)
    }

    /// Interpret a `/`-starting token as a regex literal.
    pub fn rescan_regex(&mut self) -> Option<Token> {
        let start = self.current().start;
        Lexer::new(self.source, self.spec).scan_regex(start)
    }

    /// Replace the current token with a re-scanned one (regex literals).
    pub fn replace_current(&mut self, token: Token) {
        let index = self.pos.min(self.tokens.len() - 1);
        self.tokens[index] = token;
    }

    /// Skip tokens until a statement boundary, used to recover after an error.
    pub fn recover_to_statement(&mut self) {
        let mut guard = 0usize;
        while !self.eof() && guard < 4096 {
            guard += 1;
            if self.depth <= 0 && (self.at(";") || self.at_newline()) {
                self.advance();
                return;
            }
            self.advance();
        }
    }

    /// Collect a balanced `( ... )` group as raw token texts.
    pub fn balanced_text(&mut self, open: &str, close: &str) -> String {
        if !self.at(open) {
            return String::new();
        }
        let mut depth = 0i32;
        let mut out = String::new();
        while !self.eof() {
            let text = self.current().text.clone();
            if text == open {
                depth += 1;
            } else if text == close {
                depth -= 1;
                if depth == 0 {
                    self.advance();
                    return out;
                }
            }
            if depth > 0 && !out.is_empty() {
                out.push(' ');
            }
            if depth > 0 {
                out.push_str(&text);
            }
            self.advance();
        }
        out
    }
}

fn end_token_index_clamped(pos: usize, len: usize) -> usize {
    if pos == 0 {
        return 0;
    }
    (pos - 1).min(len - 1)
}

/// Remove `$`/`@`/`&`/`*` sigils from an identifier for HIR symbol naming.
pub fn strip_ident_sigils(text: &str) -> String {
    let trimmed = text.trim_start_matches(['$', '@', '&', '*', '%']);
    if trimmed.is_empty() {
        text.to_string()
    } else {
        trimmed.to_string()
    }
}

/// [`Span`] built from byte offsets, using the cursor's file index.
pub fn span_from_offsets_file(file: u32, source: &str, start: usize, end: usize) -> uniflow_hir::Span {
    let start = start.min(source.len());
    let end = end.clamp(start, source.len());
    let (start_line, start_col) = line_col_for_offset(source, start);
    let (end_line, end_col) = line_col_for_offset(source, end);
    uniflow_hir::Span {
        file,
        start_byte: start as u32,
        end_byte: end as u32,
        start_line,
        start_col,
        end_line,
        end_col,
    }
}
