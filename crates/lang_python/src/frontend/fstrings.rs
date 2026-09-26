// f-strings (PEP 498/701). The text parser used to see `f"echo {p}"` as an
// unknown token, so every value interpolated into an f-string lost its taint
// — and f-strings are how modern Python builds SQL, shell commands, paths
// and HTML. An f-string is lowered to what it evaluates to: its literal
// pieces and interpolated expressions joined by string concatenation, which
// the value-flow engine already propagates through like `"a" + x`.

enum FStringPart {
    Literal(String),
    Expr(String),
}

/// `f"…"`, `F'…'`, `rf"""…"""`, `fr'…'` (any prefix of at most two letters
/// from `rbfu` that includes `f`) → its parts; `None` for anything else.
fn split_fstring(text: &str) -> Option<Vec<FStringPart>> {
    let quote_at = text.find(['"', '\''])?;
    let prefix = &text[..quote_at];
    if prefix.is_empty() || prefix.len() > 2 || !prefix.chars().all(|c| "rRbBfFuU".contains(c)) || !prefix.chars().any(|c| c == 'f' || c == 'F') {
        return None;
    }
    let rest = &text[quote_at..];
    let delimiter = if rest.starts_with("\"\"\"") {
        "\"\"\""
    } else if rest.starts_with("'''") {
        "'''"
    } else {
        &rest[..1]
    };
    if rest.len() < delimiter.len() * 2 || !rest.ends_with(delimiter) {
        return None;
    }
    let body = &rest[delimiter.len()..rest.len() - delimiter.len()];
    parse_fstring_body(body)
}

fn parse_fstring_body(body: &str) -> Option<Vec<FStringPart>> {
    let chars: Vec<char> = body.chars().collect();
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '{' if chars.get(i + 1) == Some(&'{') => {
                literal.push('{');
                i += 2;
            }
            '}' if chars.get(i + 1) == Some(&'}') => {
                literal.push('}');
                i += 2;
            }
            '{' => {
                let end = matching_fstring_brace(&chars, i)?;
                let inner: String = chars[i + 1..end].iter().collect();
                if !literal.is_empty() {
                    parts.push(FStringPart::Literal(std::mem::take(&mut literal)));
                }
                let expr = fstring_replacement_expr(&inner);
                if !expr.is_empty() {
                    parts.push(FStringPart::Expr(expr));
                }
                i = end + 1;
            }
            ch => {
                literal.push(ch);
                i += 1;
            }
        }
    }
    if !literal.is_empty() {
        parts.push(FStringPart::Literal(literal));
    }
    Some(parts)
}

/// Index of the `}` closing the replacement field opened at `open`,
/// skipping nested brackets and string literals (PEP 701 allows the same
/// quote character inside a field: `f'{s.replace('\'', '&apos;')}'`).
fn matching_fstring_brace(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut i = open + 1;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == '\\' {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else {
            match ch {
                '\'' | '"' => quote = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' => depth = depth.saturating_sub(1),
                '}' if depth == 0 => return Some(i),
                '}' => depth -= 1,
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// The expression of a replacement field, without its `=` self-documenting
/// marker, `!r`/`!s`/`!a` conversion and `:format-spec` — those change how
/// the value is rendered, never where it came from.
fn fstring_replacement_expr(field: &str) -> String {
    let chars: Vec<char> = field.chars().collect();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut end = chars.len();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if let Some(q) = quote {
            if ch == '\\' {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else {
            match ch {
                '\'' | '"' => quote = Some(ch),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                '!' if depth == 0 && chars.get(i + 1) != Some(&'=') => {
                    end = i;
                    break;
                }
                ':' if depth == 0 => {
                    end = i;
                    break;
                }
                _ => {}
            }
        }
        i += 1;
    }
    let expr: String = chars[..end].iter().collect();
    let expr = expr.trim();
    // `f"{x=}"` renders `x=<value>`; the value is still `x`.
    let expr = expr.strip_suffix('=').filter(|e| !e.ends_with(['=', '!', '<', '>'])).unwrap_or(expr);
    expr.trim().to_string()
}

fn parse_fstring_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Option<Expr> {
    let parts = split_fstring(text)?;
    let mut result: Option<Expr> = None;
    for part in parts {
        let expr = match part {
            FStringPart::Literal(value) => new_string(builder, &value),
            FStringPart::Expr(source) => parse_expr(builder, &source, imports, known_classes, env, line_no),
        };
        result = Some(match result {
            None => expr,
            Some(lhs) => Expr::Binary {
                id: builder.alloc_expr_id(),
                op: BinaryOp::Add,
                lhs: Box::new(lhs),
                rhs: Box::new(expr),
                span: default_span(),
            },
        });
    }
    Some(with_line_span(result.unwrap_or_else(|| new_string(builder, "")), builder.file_id(), line_no))
}

/// Rewrites every single-line f-string in `source` into the equivalent
/// concatenation — `f'a {x!r:>4} b'` → `('a ' + (x) + ' b')` — keeping line
/// numbers unchanged. This runs once per file, before any statement is
/// split: PEP 701 lets a replacement field reuse the f-string's own quote
/// (`f'{s.replace('\'', '&apos;')}'`), which the frontend's generic
/// quote-aware splitters would otherwise mis-tokenize long before the
/// f-string reached [`parse_fstring_expr`]. After rewriting, the field is a
/// plain parenthesized expression and its inner literals are ordinary ones.
/// Multi-line (triple-quoted, spanning lines) f-strings are left for
/// [`parse_fstring_expr`], which handles them when they are well-formed.
fn desugar_fstrings(source: &str) -> String {
    if !source.contains("f'") && !source.contains("f\"") && !source.contains("F'") && !source.contains("F\"") {
        return source.to_string();
    }
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '#' {
            // Comment to end of line — never contains code.
            while i < chars.len() && chars[i] != '\n' {
                out.push(chars[i]);
                i += 1;
            }
            continue;
        }
        if let Some((prefix_len, quote_len)) = string_start_at(&chars, i) {
            let prefix: String = chars[i..i + prefix_len].iter().collect();
            let is_f = prefix.contains(['f', 'F']);
            let Some(end) = string_end(&chars, i + prefix_len, quote_len, is_f) else {
                out.extend(&chars[i..]);
                break;
            };
            let literal: String = chars[i..end].iter().collect();
            if is_f && !literal.contains('\n') {
                let delimiter: String = chars[i + prefix_len..i + prefix_len + quote_len].iter().collect();
                let body: String = chars[i + prefix_len + quote_len..end - quote_len].iter().collect();
                match rewrite_fstring(&prefix, &delimiter, &body) {
                    Some(rewritten) => out.push_str(&rewritten),
                    None => out.push_str(&literal),
                }
            } else {
                out.push_str(&literal);
            }
            i = end;
            continue;
        }
        out.push(ch);
        i += 1;
    }
    out
}

/// If a string literal starts at `i` (optionally prefixed by up to two of
/// `rbfu`, not preceded by an identifier character), returns
/// `(prefix length, quote length)`.
fn string_start_at(chars: &[char], i: usize) -> Option<(usize, usize)> {
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return None;
    }
    let mut prefix_len = 0;
    while prefix_len < 2 && chars.get(i + prefix_len).is_some_and(|c| "rRbBfFuU".contains(*c)) {
        prefix_len += 1;
    }
    let quote = *chars.get(i + prefix_len)?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let triple = chars.get(i + prefix_len + 1) == Some(&quote) && chars.get(i + prefix_len + 2) == Some(&quote);
    Some((prefix_len, if triple { 3 } else { 1 }))
}

/// Index just past the closing delimiter of the literal whose opening
/// delimiter starts at `open`. In an f-string, `{…}` fields are skipped as
/// code (brackets and nested literals, which may reuse the outer quote).
fn string_end(chars: &[char], open: usize, quote_len: usize, is_f: bool) -> Option<usize> {
    let quote = chars[open];
    let mut i = open + quote_len;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            i += 2;
            continue;
        }
        if is_f && ch == '{' {
            if chars.get(i + 1) == Some(&'{') {
                i += 2;
                continue;
            }
            i = skip_replacement_field(chars, i)?;
            continue;
        }
        if ch == quote && (quote_len == 1 || (chars.get(i + 1) == Some(&quote) && chars.get(i + 2) == Some(&quote))) {
            return Some(i + quote_len);
        }
        if quote_len == 1 && ch == '\n' {
            return None;
        }
        i += 1;
    }
    None
}

/// From a `{` opening a replacement field, index just past its `}`.
fn skip_replacement_field(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open + 1;
    while i < chars.len() {
        if let Some((prefix_len, quote_len)) = string_start_at(chars, i) {
            let prefix: String = chars[i..i + prefix_len].iter().collect();
            i = string_end(chars, i + prefix_len, quote_len, prefix.contains(['f', 'F']))?;
            continue;
        }
        match chars[i] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            '}' if depth == 0 => return Some(i + 1),
            '}' => depth -= 1,
            '\n' => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

fn rewrite_fstring(prefix: &str, delimiter: &str, body: &str) -> Option<String> {
    let literal_prefix: String = prefix.chars().filter(|c| !matches!(c, 'f' | 'F')).collect();
    let parts = parse_fstring_body(body)?;
    if parts.is_empty() {
        return Some(format!("{literal_prefix}{delimiter}{delimiter}"));
    }
    let pieces: Vec<String> = parts
        .into_iter()
        .map(|part| match part {
            // Literal text is copied verbatim between the original
            // delimiters, so its escapes stay valid; `{{`/`}}` were already
            // unescaped to single braces, which plain literals allow.
            FStringPart::Literal(text) => format!("{literal_prefix}{delimiter}{text}{delimiter}"),
            FStringPart::Expr(expr) => format!("({})", desugar_fstrings(&expr)),
        })
        .collect();
    Some(format!("({})", pieces.join(" + ")))
}
