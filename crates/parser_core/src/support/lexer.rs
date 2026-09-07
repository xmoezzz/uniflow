// Configurable, panic-free lexer shared by every UniFlow language frontend.
//
// The lexer is descriptor driven: a language supplies a [`LexerSpec`] that
// describes comment forms, string literal styles, interpolation holes,
// identifier sigils and the operator table. Frontends get byte-accurate spans
// for every token, which the HIR builders turn into [`Span`] values, and
// interpolation holes keep their original source range so a frontend can
// re-lex the embedded expression with the same lexer.

/// Logical classification of a lexed token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokKind {
    Ident,
    Keyword,
    IntLit,
    FloatLit,
    StringLit,
    Symbol,
    Comment,
    Newline,
    Eof,
}

/// One segment of a (possibly interpolated) string literal.
///
/// For interpolation holes `start`/`end` are byte ranges into the original
/// source file, so the embedded expression can be re-lexed verbatim.
#[derive(Clone, Debug, PartialEq)]
pub struct StrPart {
    pub text: String,
    pub is_expr: bool,
    pub start: u32,
    pub end: u32,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub kind: TokKind,
    /// Raw source text of the token, including quotes and sigils.
    pub text: String,
    /// Interpolation segments; empty for non-interpolated tokens.
    pub parts: Vec<StrPart>,
    pub start: u32,
    pub end: u32,
    pub line: u32,
    pub col: u32,
    /// True when the token was preceded by whitespace on the same line.
    pub space_before: bool,
    /// Number of newline characters between the previous token and this one.
    pub newlines_before: u32,
    /// True when the token text is a keyword of the language.
    pub is_keyword: bool,
}

impl Token {
    pub fn is(&self, text: &str) -> bool {
        self.kind == TokKind::Symbol && self.text == text
    }

    pub fn is_symbol(&self, text: &str) -> bool {
        self.kind == TokKind::Symbol && self.text == text
    }

    pub fn is_keyword(&self, text: &str) -> bool {
        self.is_keyword && self.text == text
    }

    pub fn is_ident(&self, text: &str) -> bool {
        self.kind == TokKind::Ident && self.text == text
    }

    pub fn is_eof(&self) -> bool {
        self.kind == TokKind::Eof
    }

    /// Identifier text with language sigils stripped (`$x` -> `x`).
    pub fn bare_name(&self) -> &str {
        let text = &self.text;
        match text.strip_prefix('$').or_else(|| text.strip_prefix('@')) {
            Some(rest) if !rest.is_empty() => rest,
            _ => text.as_str(),
        }
    }

    /// Content of a string literal token with escapes resolved.
    pub fn string_value(&self) -> String {
        if !self.parts.is_empty() {
            let mut out = String::new();
            for part in &self.parts {
                if part.is_expr {
                    continue;
                }
                out.push_str(&part.text);
            }
            return out;
        }
        unescape_source_text(&self.text)
    }
}

/// How `${`/`#{`-style holes are introduced inside string literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterpStyle {
    /// No interpolation at all.
    None,
    /// `${expr}` and `$name` (PHP, Shell, Perl).
    Dollar,
    /// `${expr}` only, `$name` is not interpolated (JavaScript/TypeScript).
    DollarBrace,
    /// `#{expr}` (Ruby, Kotlin string templates, Groovy).
    HashBrace,
    /// `\(expr)` (Swift).
    BackslashParen,
    /// `{expr}` with `{{`/`}}` escapes (Python f-strings).
    Curly,
    /// `%s`, `%d` printf style placeholders (Shell printf, Ruby format).
    Percent,
}

#[derive(Clone, Debug)]
pub struct LexerSpec {
    pub line_comments: Vec<&'static str>,
    pub block_comments: Vec<(&'static str, &'static str)>,
    pub nest_block_comments: bool,
    /// Quote characters that start a normal string literal.
    pub string_quotes: Vec<char>,
    /// Multi-line quote forms, e.g. `"""` or `'''`.
    pub triple_quotes: Vec<&'static str>,
    /// Prefixes that make the following quote a raw string (no escapes).
    pub raw_prefixes: Vec<&'static str>,
    /// Prefixes that additionally enable interpolation (f-strings).
    pub interp_prefixes: Vec<&'static str>,
    pub interp: InterpStyle,
    /// Unprefixed quote characters whose contents support interpolation.
    /// Prefix-only languages such as C# leave this empty.
    pub interpolation_quotes: Vec<char>,
    /// `$name` lexes as a single identifier token (PHP, Shell).
    pub dollar_idents: bool,
    /// `@name` lexes as a single identifier token (Ruby ivars, ObjC keywords).
    pub at_idents: bool,
    /// `?name` lexes as one token (Ruby question predicates, Elixir).
    pub question_idents: bool,
    /// `:name` lexes as a symbol token (Ruby symbols).
    pub colon_idents: bool,
    pub keywords: &'static [&'static str],
    /// Operator table; the lexer tries longest match.
    pub operators: &'static [&'static str],
    /// `<<TAG ... TAG` heredocs (Shell, Ruby, PHP).
    pub here_docs: bool,
    /// Newlines are emitted as [`TokKind::Newline`] tokens.
    pub significant_newlines: bool,
    /// Backslash at end of line joins lines (Shell, Python).
    pub line_continuation: bool,
    /// `/.../flags` regex literals can be produced by [`Lexer::scan_regex`].
    pub regex_literals: bool,
    /// `#!` and `#` at file start is a shebang, not a comment.
    pub shebang: bool,
    /// Keywords match case-insensitively (SQL).
    pub case_insensitive_keywords: bool,
    /// `--` line comment requires a following space (standard SQL).
    pub line_comment_needs_break: bool,
    /// Backticks quote identifiers (MySQL/MariaDB) instead of strings.
    pub backtick_idents: bool,
}

impl Default for LexerSpec {
    fn default() -> Self {
        Self {
            line_comments: vec!["//"],
            block_comments: vec![("/*", "*/")],
            nest_block_comments: false,
            string_quotes: vec!['"', '\''],
            triple_quotes: Vec::new(),
            raw_prefixes: Vec::new(),
            interp_prefixes: Vec::new(),
            interp: InterpStyle::None,
            interpolation_quotes: Vec::new(),
            dollar_idents: false,
            at_idents: false,
            question_idents: false,
            colon_idents: false,
            keywords: &[],
            operators: DEFAULT_OPERATORS,
            here_docs: false,
            significant_newlines: false,
            line_continuation: false,
            regex_literals: false,
            shebang: false,
            case_insensitive_keywords: false,
            line_comment_needs_break: false,
            backtick_idents: false,
        }
    }
}

pub const DEFAULT_OPERATORS: &[&str] = &[
    "<<=", ">>=", "...", "===", "!==", "**=", "&&=", "||=", "??=", "<<<", ">>>", "<=>", ":=", "==",
    "!=", "<=", ">=", "&&", "||", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<",
    ">>", "..", "**", "??", "?.", "::", "->", "=>", "+", "-", "*", "/", "%", "=", "<", ">", "!",
    "&", "|", "^", "~", "?", ":", ";", ",", ".", "(", ")", "[", "]", "{", "}", "@", "#", "$", "\\",
];

/// A lexer bound to a source string and a [`LexerSpec`].
pub struct Lexer<'a> {
    src: &'a [u8],
    source: &'a str,
    spec: &'a LexerSpec,
    pos: usize,
    line: u32,
    line_start: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(source: &'a str, spec: &'a LexerSpec) -> Self {
        Self {
            src: source.as_bytes(),
            source,
            spec,
            pos: 0,
            line: 1,
            line_start: 0,
        }
    }

    /// Tokenize the whole file. Never fails: unrecognized bytes become
    /// [`TokKind::Symbol`] tokens of length one so parsing can continue.
    pub fn tokenize(&mut self) -> Vec<Token> {
        let mut tokens = Vec::new();
        let mut newlines_before = 0u32;
        loop {
            let mut saw_space = false;
            self.skip_trivia(&mut newlines_before, &mut saw_space);
            if self.pos >= self.src.len() {
                tokens.push(Token {
                    kind: TokKind::Eof,
                    text: String::new(),
                    parts: Vec::new(),
                    start: self.pos as u32,
                    end: self.pos as u32,
                    line: self.line,
                    col: (self.pos - self.line_start) as u32 + 1,
                    space_before: saw_space,
                    newlines_before,
                    is_keyword: false,
                });
                return tokens;
            }
            if newlines_before > 0 && self.spec.significant_newlines {
                // One logical terminator per newline run; the parser suppresses
                // it inside brackets (implicit line joining).
                tokens.push(Token {
                    kind: TokKind::Newline,
                    text: "\n".to_string(),
                    parts: Vec::new(),
                    start: self.pos as u32,
                    end: self.pos as u32,
                    line: self.line,
                    col: 1,
                    space_before: saw_space,
                    newlines_before,
                    is_keyword: false,
                });
            }
            let mut token = match self.next_token() {
                Some(token) => token,
                None => {
                    // Unrecognized byte: emit it as a symbol so the parser can
                    // report and recover instead of looping forever.
                    let len = char_len(self.src[self.pos]);
                    let start = self.pos;
                    self.pos += len;
                    Token {
                        kind: TokKind::Symbol,
                        text: self.source[start..self.pos].to_string(),
                        parts: Vec::new(),
                        start: start as u32,
                        end: self.pos as u32,
                        line: self.line,
                        col: (start - self.line_start) as u32 + 1,
                        space_before: saw_space,
                        newlines_before,
                        is_keyword: false,
                    }
                }
            };
            token.space_before = saw_space;
            if !self.spec.significant_newlines {
                token.newlines_before = newlines_before;
            }
            newlines_before = 0;
            tokens.push(token);
        }
    }

    /// Tokenize a byte sub-range of the source (used for interpolation holes).
    pub fn tokenize_range(&mut self, start: u32, end: u32) -> Vec<Token> {
        let start = (start as usize).min(self.source.len());
        let end = (end as usize).clamp(start, self.source.len());
        let mut sub = Lexer::new(self.source, self.spec);
        sub.pos = start;
        sub.line = 1;
        sub.line_start = start;
        let mut out = Vec::new();
        loop {
            let mut nl = 0;
            let mut space = false;
            sub.skip_trivia(&mut nl, &mut space);
            if sub.pos >= end {
                break;
            }
            let before = sub.pos;
            match sub.next_token() {
                Some(mut token) => {
                    if token.end as usize > end {
                        token.end = end as u32;
                    }
                    out.push(token);
                }
                None => sub.pos = (sub.pos + 1).min(end),
            }
            if sub.pos == before {
                sub.pos += 1;
            }
        }
        out.push(Token {
            kind: TokKind::Eof,
            text: String::new(),
            parts: Vec::new(),
            start: end as u32,
            end: end as u32,
            line: 1,
            col: 1,
            space_before: false,
            newlines_before: 0,
            is_keyword: false,
        });
        out
    }

    fn skip_trivia(&mut self, newlines: &mut u32, saw_space: &mut bool) {
        loop {
            if self.pos >= self.src.len() {
                return;
            }
            let b = self.src[self.pos];
            if b == b'\n' {
                *newlines += 1;
                *saw_space = true;
                self.pos += 1;
                self.line += 1;
                self.line_start = self.pos;
                continue;
            }
            if b.is_ascii_whitespace() {
                *saw_space = true;
                self.pos += 1;
                continue;
            }
            if self.spec.line_continuation
                && b == b'\\'
                && self.pos + 1 < self.src.len()
                && (self.src[self.pos + 1] == b'\n' || self.src[self.pos + 1] == b'\r')
            {
                let mut next = self.pos + 1;
                if self.src[next] == b'\r'
                    && next + 1 < self.src.len()
                    && self.src[next + 1] == b'\n'
                {
                    next += 1;
                }
                self.pos = next + 1;
                self.line += 1;
                self.line_start = self.pos;
                *newlines = newlines.saturating_sub(1);
                continue;
            }
            if self.match_line_comment() {
                *saw_space = true;
                continue;
            }
            if self.match_block_comment() {
                *saw_space = true;
                continue;
            }
            return;
        }
    }

    fn match_line_comment(&mut self) -> bool {
        for marker in &self.spec.line_comments {
            if !starts_with(self.src, self.pos, marker.as_bytes()) {
                continue;
            }
            if self.spec.line_comment_needs_break && marker.as_bytes() == b"--" {
                let next = self.src.get(self.pos + 2).copied();
                if !matches!(next, None | Some(b' ') | Some(b'\t')) {
                    continue;
                }
            }
            while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                self.pos += 1;
            }
            return true;
        }
        false
    }

    fn match_block_comment(&mut self) -> bool {
        for (open, close) in &self.spec.block_comments {
            if !starts_with(self.src, self.pos, open.as_bytes()) {
                continue;
            }
            self.pos += open.len();
            let mut depth = 1usize;
            while self.pos < self.src.len() {
                if starts_with(self.src, self.pos, close.as_bytes()) {
                    self.pos += close.len();
                    depth -= 1;
                    if depth == 0 {
                        return true;
                    }
                    continue;
                }
                if self.spec.nest_block_comments && starts_with(self.src, self.pos, open.as_bytes())
                {
                    self.pos += open.len();
                    depth += 1;
                    continue;
                }
                if self.src[self.pos] == b'\n' {
                    self.line += 1;
                    self.line_start = self.pos + 1;
                }
                self.pos += 1;
            }
            return true;
        }
        false
    }

    fn next_token(&mut self) -> Option<Token> {
        if self.pos >= self.src.len() {
            return None;
        }
        let start = self.pos;
        let line = self.line;
        let col = (start - self.line_start) as u32 + 1;
        let b = self.src[self.pos];

        // Backtick-quoted identifiers, e.g. MySQL `` `select` ``.
        if b == b'`' && self.spec.backtick_idents {
            self.pos += 1;
            while self.pos < self.src.len() && self.src[self.pos] != b'`' {
                self.pos += 1;
            }
            if self.pos < self.src.len() {
                self.pos += 1;
            }
            return Some(self.finish(TokKind::Ident, start, line, col));
        }

        // Numbers first: `0x1f`, `1_000`, `3.14e-9`, `0b1010`, `0o17`.
        if b.is_ascii_digit()
            || (b == b'.'
                && self.pos + 1 < self.src.len()
                && self.src[self.pos + 1].is_ascii_digit())
        {
            return Some(self.lex_number(start, line, col));
        }

        // String literals with optional prefix (`r""`, `f""`, `b""`, `@"..."`).
        if let Some(token) = self.lex_prefixed_string(start, line, col) {
            return Some(token);
        }

        // Identifiers, keywords and sigil forms.
        if ident_start(b)
            || (b >= 0x80 && self.src[self.pos..].first().is_some())
            || (self.spec.dollar_idents && b == b'$')
            || (self.spec.at_idents && b == b'@')
        {
            return Some(self.lex_ident(start, line, col));
        }

        // Ruby-style `:sym`.
        if self.spec.colon_idents
            && b == b':'
            && self.pos + 1 < self.src.len()
            && ident_start(self.src[self.pos + 1])
            && !(self.pos + 1 < self.src.len() && self.src[self.pos + 1] == b':')
        {
            self.pos += 1;
            self.lex_ident_body();
            return Some(self.finish(TokKind::Ident, start, line, col));
        }

        // Heredoc: `<<TAG`, `<<-TAG`, `<<~TAG`, `<<<TAG`, `<<"TAG"`.
        if self.spec.here_docs && starts_with(self.src, self.pos, b"<<") {
            if let Some(token) = self.lex_heredoc(start, line, col) {
                return Some(token);
            }
        }

        // Longest-match operator.
        let mut best: Option<&'static str> = None;
        for op in self.spec.operators {
            let bytes = op.as_bytes();
            if !starts_with(self.src, self.pos, bytes) {
                continue;
            }
            if best.map_or(true, |current| bytes.len() > current.len()) {
                best = Some(op);
            }
        }
        if let Some(op) = best {
            self.pos += op.len();
            return Some(self.finish(TokKind::Symbol, start, line, col));
        }

        // Non-ASCII identifier lead (UTF-8 continuation bytes are >= 0x80).
        if b >= 0x80 {
            self.lex_ident_body();
            return Some(self.finish(TokKind::Ident, start, line, col));
        }
        None
    }

    fn lex_number(&mut self, start: usize, line: u32, col: u32) -> Token {
        let mut is_float = false;
        if self.src[self.pos] == b'0'
            && self.pos + 1 < self.src.len()
            && matches!(self.src[self.pos + 1] | 0x20, b'x' | b'o' | b'b')
        {
            self.pos += 2;
            while self.pos < self.src.len()
                && (self.src[self.pos].is_ascii_alphanumeric() || self.src[self.pos] == b'_')
            {
                self.pos += 1;
            }
            return self.finish(TokKind::IntLit, start, line, col);
        }
        while self.pos < self.src.len()
            && (self.src[self.pos].is_ascii_digit() || self.src[self.pos] == b'_')
        {
            self.pos += 1;
        }
        if self.pos < self.src.len() && self.src[self.pos] == b'.' {
            // `1..2` (Ruby/Kotlin ranges) must not swallow the second dot.
            let next_is_dot = self.pos + 1 < self.src.len() && self.src[self.pos + 1] == b'.';
            let next_is_digit =
                self.pos + 1 < self.src.len() && self.src[self.pos + 1].is_ascii_digit();
            if !next_is_dot && (next_is_digit || self.src.get(self.pos + 1) != Some(&b'_')) {
                // Allow `1.` only when followed by a digit.
                if next_is_digit {
                    is_float = true;
                    self.pos += 1;
                    while self.pos < self.src.len()
                        && (self.src[self.pos].is_ascii_digit() || self.src[self.pos] == b'_')
                    {
                        self.pos += 1;
                    }
                }
            }
        }
        if self.pos < self.src.len() && matches!(self.src[self.pos] | 0x20, b'e') {
            let mut probe = self.pos + 1;
            if probe < self.src.len() && matches!(self.src[probe], b'+' | b'-') {
                probe += 1;
            }
            if probe < self.src.len() && self.src[probe].is_ascii_digit() {
                is_float = true;
                self.pos = probe;
                while self.pos < self.src.len() && self.src[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
            }
        }
        // Language numeric suffixes: `10L`, `2.5f`, `3u`, `1_000ul`, `100s` (Swift duration).
        while self.pos < self.src.len()
            && matches!(self.src[self.pos] | 0x20, b'u' | b'l' | b'f' | b'd')
        {
            self.pos += 1;
        }
        // SQL-style `1e` is rare; treat suffix consumption as harmless.
        let _ = is_float;
        let kind = if self.source[start..self.pos].contains('.') {
            TokKind::FloatLit
        } else {
            TokKind::IntLit
        };
        self.finish(kind, start, line, col)
    }

    fn lex_prefixed_string(&mut self, start: usize, line: u32, col: u32) -> Option<Token> {
        let mut raw = false;
        let mut interp = false;
        // C# permits both `$@"..."` and `@$"..."`: verbatim escaping and
        // interpolation are independent properties.
        if self.spec.interp == InterpStyle::Curly
            && self.spec.interp_prefixes.contains(&"$")
            && (starts_with(self.src, self.pos, b"$@\"")
                || starts_with(self.src, self.pos, b"@$\""))
        {
            self.pos += 2;
            raw = true;
            interp = true;
        }
        let b = self.src[self.pos];
        // `@"..."` (ObjC NSString), `@"..."` in C# verbatim.
        if b == b'@' && self.pos + 1 < self.src.len() && self.src[self.pos + 1] == b'"' {
            self.pos += 1;
            raw = true;
            let token_start = start;
            let text_start = self.pos;
            self.pos += 1;
            while self.pos < self.src.len() {
                if self.src[self.pos] == b'"' {
                    if self.src.get(self.pos + 1) == Some(&b'"') {
                        self.pos += 2;
                        continue;
                    }
                    break;
                }
                if self.src[self.pos] == b'\n' {
                    self.line += 1;
                    self.line_start = self.pos + 1;
                }
                self.pos += 1;
            }
            if self.pos < self.src.len() {
                self.pos += 1;
            }
            let _ = text_start;
            return Some(self.finish_string(
                TokKind::StringLit,
                token_start,
                line,
                col,
                raw,
                false,
            ));
        }
        for prefix in &self.spec.raw_prefixes {
            if starts_with(self.src, self.pos, prefix.as_bytes()) {
                let after = self.pos + prefix.len();
                if after < self.src.len() && (self.src[after] == b'"' || self.src[after] == b'\'') {
                    self.pos = after;
                    raw = true;
                    interp = false;
                    break;
                }
            }
        }
        for prefix in &self.spec.interp_prefixes {
            if starts_with(self.src, self.pos, prefix.as_bytes()) {
                let after = self.pos + prefix.len();
                if after < self.src.len() && (self.src[after] == b'"' || self.src[after] == b'\'') {
                    self.pos = after;
                    interp = true;
                    raw = false;
                    break;
                }
            }
        }
        // Triple-quoted strings take priority over single quotes.
        for triple in &self.spec.triple_quotes {
            if starts_with(self.src, self.pos, triple.as_bytes()) {
                if !raw && !interp {
                    interp = triple
                        .chars()
                        .next()
                        .is_some_and(|quote| self.spec.interpolation_quotes.contains(&quote));
                }
                let token_start = start;
                let open = self.pos;
                self.pos += triple.len();
                let content_start = self.pos;
                while self.pos < self.src.len()
                    && !starts_with(self.src, self.pos, triple.as_bytes())
                {
                    if self.src[self.pos] == b'\\' && !raw && self.pos + 1 < self.src.len() {
                        self.pos += 2;
                        continue;
                    }
                    if self.src[self.pos] == b'\n' {
                        self.line += 1;
                        self.line_start = self.pos + 1;
                    }
                    self.pos += 1;
                }
                let content_end = self.pos;
                self.pos = (self.pos + triple.len()).min(self.src.len());
                let mut token = self.finish(TokKind::StringLit, token_start, line, col);
                token.parts = self.split_interpolation(
                    &self.source[content_start..content_end],
                    content_start as u32,
                    raw,
                    interp,
                );
                let _ = open;
                return Some(token);
            }
        }
        let quote = if self.src[self.pos] == b'"' {
            Some(b'"')
        } else if self.src[self.pos] == b'\'' && self.spec.string_quotes.contains(&'\'') {
            Some(b'\'')
        } else if self.src[self.pos] == b'`' && self.spec.string_quotes.contains(&'`') {
            Some(b'`')
        } else {
            None
        };
        let quote = quote?;
        if !self.spec.string_quotes.contains(&(quote as char)) {
            return None;
        }
        if !raw && !interp {
            interp = self.spec.interpolation_quotes.contains(&(quote as char));
        }
        let token_start = start;
        self.pos += 1;
        let content_start = self.pos;
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            if raw && quote == b'"' && c == b'"' && self.src.get(self.pos + 1) == Some(&b'"') {
                self.pos += 2;
                continue;
            }
            if c == b'\\' && !raw && self.pos + 1 < self.src.len() {
                if self.src[self.pos + 1] == b'\n' {
                    self.line += 1;
                    self.line_start = self.pos + 2;
                }
                self.pos += 2;
                continue;
            }
            if c == quote {
                break;
            }
            if c == b'\n' {
                if quote == b'`' {
                    self.line += 1;
                    self.line_start = self.pos + 1;
                    self.pos += 1;
                    continue;
                }
                // Unterminated ordinary string: stop at the newline so a
                // syntax error in one line cannot swallow the whole file.
                break;
            }
            self.pos += 1;
        }
        let content_end = self.pos;
        if self.pos < self.src.len() {
            self.pos += 1;
        }
        let mut token = self.finish(TokKind::StringLit, token_start, line, col);
        token.parts = self.split_interpolation(
            &self.source[content_start..content_end],
            content_start as u32,
            raw,
            interp,
        );
        Some(token)
    }
    /// Split literal content into constant and interpolation segments.
    fn split_interpolation(
        &self,
        content: &str,
        content_base: u32,
        _raw: bool,
        interp_enabled: bool,
    ) -> Vec<StrPart> {
        if !interp_enabled || self.spec.interp == InterpStyle::None {
            return Vec::new();
        }
        let bytes = content.as_bytes();
        let mut parts: Vec<StrPart> = Vec::new();
        let mut literal = String::new();
        let mut literal_start = 0usize;
        let mut index = 0usize;
        while index < bytes.len() {
            // `{{` / `}}` are escaped braces in f-string style literals.
            if self.spec.interp == InterpStyle::Curly
                && matches!(bytes.get(index), Some(b'{') | Some(b'}'))
                && bytes.get(index) == bytes.get(index + 1)
            {
                literal.push(bytes[index] as char);
                index += 2;
                continue;
            }
            if let Some((expr_start, expr_end, consumed)) = self.interp_hole(bytes, index) {
                if !literal.is_empty() {
                    parts.push(StrPart {
                        text: std::mem::take(&mut literal),
                        is_expr: false,
                        start: content_base + literal_start as u32,
                        end: content_base + index as u32,
                    });
                }
                parts.push(StrPart {
                    text: content[expr_start..expr_end].to_string(),
                    is_expr: true,
                    start: content_base + expr_start as u32,
                    end: content_base + expr_end as u32,
                });
                index += consumed;
                literal_start = index;
                continue;
            }
            let len = char_len(bytes[index]).max(1);
            let end = (index + len).min(bytes.len());
            match std::str::from_utf8(&bytes[index..end]) {
                Ok(chunk) => literal.push_str(chunk),
                Err(_) => literal.push(char::REPLACEMENT_CHARACTER),
            }
            index = end;
        }
        if !literal.is_empty() {
            parts.push(StrPart {
                text: literal,
                is_expr: false,
                start: content_base + literal_start as u32,
                end: content_base + bytes.len() as u32,
            });
        }
        if parts.iter().all(|part| !part.is_expr) {
            return Vec::new();
        }
        parts
    }

    /// Locate an interpolation hole starting at `index`.
    ///
    /// Returns `(expr_start, expr_end, consumed)` where the two expression
    /// offsets delimit the embedded expression text and `consumed` is the total
    /// width of the hole including its delimiters.
    fn interp_hole(&self, bytes: &[u8], index: usize) -> Option<(usize, usize, usize)> {
        let style = self.spec.interp;
        let byte = bytes[index];
        let (open_len, close_byte) = match style {
            InterpStyle::Dollar | InterpStyle::DollarBrace => {
                if byte == b'$' && bytes.get(index + 1) == Some(&b'{') {
                    (2usize, b'}')
                } else if style == InterpStyle::Dollar
                    && byte == b'$'
                    && bytes
                        .get(index + 1)
                        .map_or(false, |next| next.is_ascii_alphabetic() || *next == b'_')
                {
                    let start = index + 1;
                    let mut end = start;
                    while end < bytes.len()
                        && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                    {
                        end += 1;
                    }
                    return Some((start, end, end - index));
                } else {
                    return None;
                }
            }
            InterpStyle::HashBrace => {
                if byte == b'#' && bytes.get(index + 1) == Some(&b'{') {
                    (2usize, b'}')
                } else {
                    return None;
                }
            }
            InterpStyle::BackslashParen => {
                if byte == b'\\' && bytes.get(index + 1) == Some(&b'(') {
                    (2usize, b')')
                } else {
                    return None;
                }
            }
            InterpStyle::Curly => {
                if byte == b'{' {
                    (1usize, b'}')
                } else {
                    return None;
                }
            }
            // `printf`-style placeholders are modeled on the call, not the
            // literal, so the lexer leaves them as constant text.
            InterpStyle::Percent | InterpStyle::None => return None,
        };
        let mut depth = 1usize;
        let mut scan = index + open_len;
        while scan < bytes.len() {
            let c = bytes[scan];
            if style == InterpStyle::BackslashParen && c == b'\\' {
                scan += 2;
                continue;
            }
            if c == b'{' && close_byte == b'}' {
                depth += 1;
            } else if c == close_byte {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            scan += 1;
        }
        if scan >= bytes.len() {
            return None;
        }
        Some((index + open_len, scan, scan + 1 - index))
    }

    /// Lex `<<TAG`, `<<-TAG`, `<<~TAG`, `<<<TAG` and quoted-tag heredocs.
    ///
    /// The tag must start immediately after the angle brackets and be at least
    /// two characters long, so a Ruby stream append such as `sql << value` is
    /// not mistaken for a heredoc.
    fn lex_heredoc(&mut self, start: usize, line: u32, col: u32) -> Option<Token> {
        let mut probe = self.pos + 2;
        if self.src.get(probe) == Some(&b'<') {
            probe += 1; // PHP `<<<TAG`
        }
        if matches!(self.src.get(probe), Some(b'-') | Some(b'~')) {
            probe += 1; // Shell `<<-TAG`, Ruby `<<~TAG`
        }
        let quote = match self.src.get(probe) {
            Some(q @ (b'"' | b'\'' | b'`')) => {
                probe += 1;
                Some(*q)
            }
            _ => None,
        };
        let tag_start = probe;
        while probe < self.src.len()
            && (self.src[probe].is_ascii_alphanumeric() || self.src[probe] == b'_')
        {
            probe += 1;
        }
        if probe - tag_start < 2 {
            return None;
        }
        let tag = self.source[tag_start..probe].to_string();
        let mut end_probe = probe;
        if let Some(q) = quote {
            if self.src.get(end_probe) == Some(&q) {
                end_probe += 1;
            }
        }
        // Only whitespace, a terminating `;`, or a shell redirection may follow
        // the opening tag before the newline.
        while end_probe < self.src.len() {
            match self.src[end_probe] {
                b'\n' => break,
                b' ' | b'\t' | b'\r' | b';' | b'0'..=b'9' => end_probe += 1,
                b'<' | b'>' | b'|' | b'&' => {
                    while end_probe < self.src.len()
                        && matches!(self.src[end_probe], b'<' | b'>' | b'|' | b'&')
                    {
                        end_probe += 1;
                    }
                    // Optional redirection target: whitespace, then the file
                    // name up to the next whitespace or `;`.
                    while matches!(self.src.get(end_probe), Some(b' ') | Some(b'\t')) {
                        end_probe += 1;
                    }
                    while end_probe < self.src.len()
                        && !matches!(self.src[end_probe], b' ' | b'\t' | b'\n' | b'\r' | b';')
                    {
                        end_probe += 1;
                    }
                }
                b'\\' if self.src.get(end_probe + 1) == Some(&b'\n') => end_probe += 2,
                _ => return None,
            }
        }
        if end_probe >= self.src.len() {
            return None;
        }
        self.pos = end_probe + 1;
        self.line += 1;
        self.line_start = self.pos;
        let content_start = self.pos;
        let mut content_end = self.src.len();
        let mut line_start_of_scan = self.pos;
        while line_start_of_scan < self.src.len() {
            let mut scan = line_start_of_scan;
            while matches!(self.src[scan], b' ' | b'\t') {
                scan += 1;
            }
            if starts_with(self.src, scan, tag.as_bytes()) {
                let after = scan + tag.len();
                if after >= self.src.len()
                    || self.src[after] == b'\n'
                    || self.src[after] == b';'
                    || self.src[after] == b' '
                {
                    content_end = line_start_of_scan;
                    self.pos = after;
                    break;
                }
            }
            while scan < self.src.len() && self.src[scan] != b'\n' {
                scan += 1;
            }
            if scan >= self.src.len() {
                content_end = self.src.len();
                self.pos = self.src.len();
                break;
            }
            self.line += 1;
            self.pos = scan + 1;
            self.line_start = self.pos;
            line_start_of_scan = scan + 1;
        }
        let mut token = self.finish(TokKind::StringLit, start, line, col);
        // A quoted tag disables interpolation, matching shell and PHP semantics.
        let raw = quote == Some(b'\'');
        token.parts = self.split_interpolation(
            &self.source[content_start..content_end],
            content_start as u32,
            raw || quote.is_some(),
            !raw && quote.is_none() && self.spec.interp != InterpStyle::None,
        );
        Some(token)
    }

    fn lex_ident_body(&mut self) {
        while self.pos < self.src.len() {
            let b = self.src[self.pos];
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b >= 0x80 {
                self.pos += 1;
                continue;
            }
            break;
        }
    }

    fn lex_ident(&mut self, start: usize, line: u32, col: u32) -> Token {
        // A `$`/`@` sigil is part of the name when enabled by the spec.
        if matches!(self.src[self.pos], b'$' | b'@') {
            self.pos += 1;
        }
        if self.pos < self.src.len() && self.src[self.pos] == b'`' {
            // Quoted identifier, e.g. MySQL `` `select` ``.
            self.pos += 1;
            while self.pos < self.src.len() && self.src[self.pos] != b'`' {
                self.pos += 1;
            }
            if self.pos < self.src.len() {
                self.pos += 1;
            }
            return self.finish(TokKind::Ident, start, line, col);
        }
        self.lex_ident_body();
        // Ruby `foo?` / `foo!` predicate names.
        if self.pos < self.src.len() && matches!(self.src[self.pos], b'?' | b'!') {
            let next = self.pos + 1;
            let followed_by_space =
                next >= self.src.len() || self.src[next] == b' ' || self.src[next] == b'\n';
            if followed_by_space && self.spec.question_idents {
                self.pos += 1;
            }
        }
        let mut token = self.finish(TokKind::Ident, start, line, col);
        let name = if self.spec.case_insensitive_keywords {
            token.text.to_ascii_lowercase()
        } else {
            token.text.clone()
        };
        if self.spec.keywords.contains(&name.as_str()) {
            token.kind = TokKind::Keyword;
            token.is_keyword = true;
        }
        token
    }

    /// Re-scan a `/` token as a regex literal. Returns `None` when the closing
    /// delimiter is missing or the literal spans a newline.
    pub fn scan_regex(&mut self, at: u32) -> Option<Token> {
        if !self.spec.regex_literals {
            return None;
        }
        let start = at as usize;
        if self.src.get(start) != Some(&b'/') {
            return None;
        }
        let mut probe = start + 1;
        let mut in_class = false;
        while probe < self.src.len() {
            let c = self.src[probe];
            if c == b'\\' {
                probe += 2;
                continue;
            }
            if c == b'\n' {
                return None;
            }
            if c == b'[' {
                in_class = true;
            } else if c == b']' {
                in_class = false;
            } else if c == b'/' && !in_class {
                probe += 1;
                while probe < self.src.len() && self.src[probe].is_ascii_alphabetic() {
                    probe += 1;
                }
                let line = self.line_at(start);
                let col = (start - self.line_start_at(start)) as u32 + 1;
                let save = self.pos;
                self.pos = probe;
                let mut token = self.finish(TokKind::StringLit, start, line, col);
                self.pos = save;
                token.text = self.source[start..probe].to_string();
                return Some(token);
            }
            probe += 1;
        }
        None
    }

    fn line_at(&self, offset: usize) -> u32 {
        self.source[..offset.min(self.source.len())]
            .bytes()
            .filter(|b| *b == b'\n')
            .count() as u32
            + 1
    }

    fn line_start_at(&self, offset: usize) -> usize {
        let head = &self.source[..offset.min(self.source.len())];
        head.rfind('\n').map(|index| index + 1).unwrap_or(0)
    }

    fn finish(&self, kind: TokKind, start: usize, line: u32, col: u32) -> Token {
        Token {
            kind,
            text: self.source[start..self.pos].to_string(),
            parts: Vec::new(),
            start: start as u32,
            end: self.pos as u32,
            line,
            col,
            space_before: false,
            newlines_before: 0,
            is_keyword: kind == TokKind::Keyword,
        }
    }

    fn finish_string(
        &self,
        kind: TokKind,
        start: usize,
        line: u32,
        col: u32,
        raw: bool,
        interp: bool,
    ) -> Token {
        let mut token = self.finish(kind, start, line, col);
        let content = &self.source[start..self.pos];
        token.parts = self.split_interpolation(
            string_body(content),
            start as u32 + (content.len() - string_body(content).len()) as u32 / 2,
            raw,
            interp,
        );
        token
    }
}

fn string_body(text: &str) -> &str {
    let trimmed = text.trim_start_matches('@').trim_start_matches('r');
    if trimmed.len() >= 2 {
        &trimmed[1..trimmed.len() - 1]
    } else {
        ""
    }
}

fn char_len(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte >> 5 == 0b110 {
        2
    } else if byte >> 4 == 0b1110 {
        3
    } else if byte >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

fn starts_with(haystack: &[u8], at: usize, needle: &[u8]) -> bool {
    at <= haystack.len() && haystack[at..].starts_with(needle)
}

fn ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

/// Resolve escape sequences in string source text into its runtime value.
pub fn unescape_source_text(text: &str) -> String {
    // Strip one layer of surrounding quotes when present.
    let mut body = text;
    let trimmed = text.trim_start_matches(['r', 'b', 'u', 'U', '@', 'f']);
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0];
        if matches!(first, b'"' | b'\'' | b'`') && trimmed.as_bytes()[trimmed.len() - 1] == first {
            body = &trimmed[1..trimmed.len() - 1];
        }
    }
    let raw = text.starts_with('r')
        || text.starts_with('@')
        || text.starts_with("'''")
        || text.starts_with("\"\"\"");
    if raw {
        return body.replace("\"\"", "\"").replace("''", "'");
    }
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut index = 0usize;
    while index < bytes.len() {
        let b = bytes[index];
        if b != b'\\' || index + 1 >= bytes.len() {
            // Copy one character (possibly multi-byte).
            let len = if b < 0x80 { 1 } else { char_len(b) };
            let end = (index + len).min(bytes.len());
            match std::str::from_utf8(&bytes[index..end]) {
                Ok(chunk) => out.push_str(chunk),
                Err(_) => out.push(char::REPLACEMENT_CHARACTER),
            }
            index = end;
            continue;
        }
        let esc = bytes[index + 1];
        index += 2;
        match esc {
            b'n' => out.push('\n'),
            b't' => out.push('\t'),
            b'r' => out.push('\r'),
            b'0' => out.push('\0'),
            b'\\' => out.push('\\'),
            b'"' => out.push('"'),
            b'\'' => out.push('\''),
            b'`' => out.push('`'),
            b'a' => out.push('\u{7}'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'v' => out.push('\u{b}'),
            b'e' => out.push('\u{1b}'),
            b'x' => {
                let mut digits = String::new();
                while index < bytes.len()
                    && digits.len() < 2
                    && (bytes[index] as char).is_ascii_hexdigit()
                {
                    digits.push(bytes[index] as char);
                    index += 1;
                }
                if let Ok(value) = u32::from_str_radix(&digits, 16) {
                    out.push(char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER));
                }
            }
            b'u' => {
                let mut digits = String::new();
                if bytes.get(index) == Some(&b'{') {
                    index += 1;
                    while index < bytes.len() && bytes[index] != b'}' {
                        digits.push(bytes[index] as char);
                        index += 1;
                    }
                    index = (index + 1).min(bytes.len());
                } else {
                    while index < bytes.len()
                        && digits.len() < 4
                        && (bytes[index] as char).is_ascii_hexdigit()
                    {
                        digits.push(bytes[index] as char);
                        index += 1;
                    }
                }
                if let Ok(value) = u32::from_str_radix(&digits, 16) {
                    out.push(char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER));
                }
            }
            other => {
                out.push('\\');
                out.push(other as char);
            }
        }
    }
    let _ = bytes;
    out
}

/// Parse an integer literal token text into a value.
pub fn int_literal_value(text: &str) -> Option<i64> {
    let cleaned: String = text.chars().filter(|c| *c != '_').collect();
    let (digits, radix) = if cleaned.starts_with("0x") || cleaned.starts_with("0X") {
        (&cleaned[2..], 16)
    } else if cleaned.starts_with("0b") || cleaned.starts_with("0B") {
        (&cleaned[2..], 2)
    } else if cleaned.starts_with("0o") || cleaned.starts_with("0O") {
        (&cleaned[2..], 8)
    } else {
        let trimmed = cleaned.as_str();
        if trimmed.starts_with('0')
            && trimmed.len() > 1
            && trimmed.bytes().all(|b| b'0' <= b && b <= b'7')
        {
            // C-style octal.
            return i64::from_str_radix(&trimmed[1..], 8).ok();
        }
        (cleaned.as_str(), 10)
    };
    let suffix_trimmed = digits.trim_end_matches(|c: char| {
        matches!(
            c.to_ascii_lowercase(),
            'u' | 'l' | 'f' | 'd' | 's' | 'x' | 'o' | 'b'
        )
    });
    let unsigned = suffix_trimmed.trim_start_matches(['+', '-']);
    let _ = unsigned;
    i64::from_str_radix(digits.trim_start_matches(['+', '-']), radix)
        .ok()
        .map(|value| {
            if digits.starts_with('-') {
                -value
            } else {
                value
            }
        })
}

/// Parse a float literal token text into a value.
pub fn float_literal_value(text: &str) -> Option<f64> {
    let cleaned: String = text
        .chars()
        .filter(|c| *c != '_' && !matches!(c.to_ascii_lowercase(), 'f' | 'd'))
        .collect();
    cleaned.parse::<f64>().ok()
}
