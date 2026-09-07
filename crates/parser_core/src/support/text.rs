pub fn default_span() -> Span {
    Span::default()
}

pub fn line_col_for_offset(source: &str, offset: usize) -> (u32, u32) {
    let capped = offset.min(source.len());
    let mut line = 1u32;
    let mut col = 1u32;
    for ch in source[..capped].chars() {
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

pub fn span_from_offsets(file: FileId, source: &str, start: usize, end: usize) -> Span {
    let start = start.min(source.len());
    let end = end.min(source.len()).max(start);
    let (start_line, start_col) = line_col_for_offset(source, start);
    let (end_line, end_col) = line_col_for_offset(source, end);
    Span {
        file: file.0,
        start_byte: start as u32,
        end_byte: end as u32,
        start_line,
        start_col,
        end_line,
        end_col,
    }
}

pub fn span_from_line_range(file: FileId, start_line: u32, end_line: u32) -> Span {
    Span {
        file: file.0,
        start_byte: 0,
        end_byte: 0,
        start_line,
        start_col: 1,
        end_line,
        end_col: 1,
    }
}

pub fn find_substring_span(file: FileId, source: &str, needle: &str, search_from: usize) -> Span {
    if needle.trim().is_empty() {
        return default_span();
    }
    if let Some(rel) = source[search_from.min(source.len())..].find(needle) {
        let start = search_from.min(source.len()) + rel;
        let end = start + needle.len();
        return span_from_offsets(file, source, start, end);
    }
    if let Some(start) = source.find(needle) {
        let end = start + needle.len();
        return span_from_offsets(file, source, start, end);
    }
    default_span()
}

pub fn module_name_from_path(path: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or(path);
    let without_ext = last.split('.').next().unwrap_or(last);
    if without_ext.is_empty() {
        "main".to_string()
    } else {
        without_ext.to_string()
    }
}

pub fn strip_c_like_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    while index < bytes.len() {
        if line_comment {
            if bytes[index] == b'\n' {
                line_comment = false;
            } else if bytes[index] != b'\r' {
                output[index] = b' ';
            }
            index += 1;
            continue;
        }
        if block_comment {
            if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                output[index] = b' ';
                output[index + 1] = b' ';
                block_comment = false;
                index += 2;
            } else {
                if !matches!(bytes[index], b'\n' | b'\r') {
                    output[index] = b' ';
                }
                index += 1;
            }
            continue;
        }
        if let Some(current_quote) = quote {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == current_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            output[index] = b' ';
            output[index + 1] = b' ';
            line_comment = true;
            index += 2;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output[index] = b' ';
            output[index + 1] = b' ';
            block_comment = true;
            index += 2;
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8")
}

pub fn split_top_level_commas(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;

    for ch in input.chars() {
        if in_string {
            cur.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
                cur.push(ch);
            }
            '(' => {
                paren += 1;
                cur.push(ch);
            }
            ')' => {
                paren = paren.saturating_sub(1);
                cur.push(ch);
            }
            '[' => {
                bracket += 1;
                cur.push(ch);
            }
            ']' => {
                bracket = bracket.saturating_sub(1);
                cur.push(ch);
            }
            '{' => {
                brace += 1;
                cur.push(ch);
            }
            '}' => {
                brace = brace.saturating_sub(1);
                cur.push(ch);
            }
            ',' if paren == 0 && bracket == 0 && brace == 0 => {
                let piece = cur.trim();
                if !piece.is_empty() {
                    out.push(piece.to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }

    let tail = cur.trim();
    if !tail.is_empty() {
        out.push(tail.to_string());
    }
    out
}

fn starts_with_c_like_block_statement(text: &str) -> bool {
    [
        "if", "while", "for", "switch", "try", "synchronized", "do",
    ]
    .iter()
    .any(|keyword| starts_with_c_like_keyword(text, keyword))
}

fn starts_with_c_like_keyword(text: &str, keyword: &str) -> bool {
    text.strip_prefix(keyword).is_some_and(|tail| {
        tail.chars().next().is_none_or(|ch| {
            !ch.is_alphanumeric() && !matches!(ch, '_' | '$')
        })
    })
}

pub fn split_top_level_statements_c_like(body: &str) -> Vec<String> {
    split_top_level_statements_c_like_with_offsets(body)
        .into_iter()
        .map(|(_, _, stmt)| stmt)
        .collect()
}

pub fn split_top_level_statements_c_like_with_offsets(body: &str) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;
    let mut stmt_start = 0usize;

    for (idx, ch) in body.char_indices() {
        if in_string {
            cur.push(ch);
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
                cur.push(ch);
            }
            '(' => {
                paren += 1;
                cur.push(ch);
            }
            ')' => {
                paren = paren.saturating_sub(1);
                cur.push(ch);
            }
            '[' => {
                bracket += 1;
                cur.push(ch);
            }
            ']' => {
                bracket = bracket.saturating_sub(1);
                cur.push(ch);
            }
            '{' => {
                brace += 1;
                cur.push(ch);
            }
            '}' => {
                brace = brace.saturating_sub(1);
                cur.push(ch);
                if paren == 0
                    && brace == 0
                    && bracket == 0
                    && starts_with_c_like_block_statement(cur.trim_start())
                {
                    let rest = body[idx + ch.len_utf8()..].trim_start();
                    if !starts_with_c_like_keyword(rest, "else")
                        && !starts_with_c_like_keyword(rest, "catch")
                        && !starts_with_c_like_keyword(rest, "finally")
                        && !(starts_with_c_like_keyword(cur.trim_start(), "do")
                            && starts_with_c_like_keyword(rest, "while"))
                    {
                        let piece = cur.trim();
                        let trim_prefix = cur.find(piece).unwrap_or(0);
                        let start = stmt_start + trim_prefix;
                        let end = start + piece.len();
                        out.push((start, end, piece.to_string()));
                        cur.clear();
                        stmt_start = idx + ch.len_utf8();
                    }
                }
            }
            ';' if paren == 0 && brace == 0 && bracket == 0 => {
                let piece = cur.trim();
                if !piece.is_empty() {
                    let trim_prefix = cur.find(piece).unwrap_or(0);
                    let start = stmt_start + trim_prefix;
                    let end = start + piece.len();
                    out.push((start, end, piece.to_string()));
                }
                cur.clear();
                stmt_start = idx + ch.len_utf8();
            }
            _ => cur.push(ch),
        }
    }

    let piece = cur.trim();
    if !piece.is_empty() {
        let trim_prefix = cur.find(piece).unwrap_or(0);
        let start = stmt_start + trim_prefix;
        let end = start + piece.len();
        out.push((start, end, piece.to_string()));
    }
    out
}

pub fn matching_delimiter(
    text: &str,
    open: usize,
    open_ch: char,
    close_ch: char,
) -> Option<usize> {
    let tail = text.get(open..)?;
    if tail.chars().next()? != open_ch {
        return None;
    }

    let mut depth = 0usize;
    let mut quote = None::<char>;
    let mut escaped = false;
    for (offset, ch) in tail.char_indices() {
        if let Some(expected) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == expected {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch == open_ch {
            depth += 1;
        } else if ch == close_ch {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

pub fn find_matching_brace(source: &str, open_idx: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open_idx).copied() != Some(b'{') {
        return None;
    }

    let mut depth = 0usize;
    let mut in_string = false;
    let mut quote = b'\0';
    let mut escape = false;

    for (idx, b) in bytes.iter().copied().enumerate().skip(open_idx) {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if b == b'\\' {
                escape = true;
                continue;
            }
            if b == quote {
                in_string = false;
            }
            continue;
        }

        if b == b'"' || b == b'\'' {
            in_string = true;
            quote = b;
            continue;
        }

        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(idx);
            }
        }
    }

    None
}

pub fn split_once_top_level(input: &str, target: char) -> Option<(String, String)> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ if ch == target && paren == 0 && bracket == 0 && brace == 0 => {
                let left = input[..idx].trim().to_string();
                let right = input[idx + ch.len_utf8()..].trim().to_string();
                return Some((left, right));
            }
            _ => {}
        }
    }

    None
}

pub fn split_last_top_level_dot(input: &str) -> Option<(String, String)> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;
    let mut last = None;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            '.' if paren == 0 && bracket == 0 && brace == 0 => last = Some(idx),
            _ => {}
        }
    }

    last.map(|idx| {
        (
            input[..idx].trim().to_string(),
            input[idx + 1..].trim().to_string(),
        )
    })
}

pub fn is_string_literal(text: &str) -> bool {
    let trimmed = text.trim();
    (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
}

pub fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    if is_string_literal(trimmed) && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn is_int_literal(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit())
}

pub fn is_identifier_like(text: &str) -> bool {
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

pub fn is_probable_type_name(text: &str) -> bool {
    let first = text.trim().chars().next();
    matches!(first, Some(ch) if ch.is_ascii_uppercase())
}
