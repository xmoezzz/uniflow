#[derive(Clone, Debug)]
struct CMacro {
    params: Option<Vec<String>>,
    body: String,
}

#[derive(Clone, Debug)]
struct TrackedSource {
    text: String,
    macro_bytes: Vec<bool>,
}

impl TrackedSource {
    fn plain(text: String) -> Self {
        Self {
            macro_bytes: vec![false; text.len()],
            text,
        }
    }

    fn macro_ranges(&self) -> Vec<(u32, u32)> {
        let mut ranges = Vec::new();
        let mut start = None;
        for (index, marked) in self.macro_bytes.iter().copied().enumerate() {
            match (start, marked) {
                (None, true) => start = Some(index),
                (Some(begin), false) => {
                    ranges.push((begin as u32, index as u32));
                    start = None;
                }
                _ => {}
            }
        }
        if let Some(begin) = start {
            ranges.push((begin as u32, self.macro_bytes.len() as u32));
        }
        ranges
    }
}

/// A conservative, deterministic C preprocessor used by the source frontend.
///
/// It deliberately handles only constructs that can be expanded without a filesystem or a
/// compiler configuration: object/function-like macros, `#undef`, and boolean conditional
/// groups. Include directives are retained for import extraction. Unsupported directives are
/// replaced with blank lines so source line numbering remains stable.
pub fn preprocess_c_source(source: &str) -> String {
    preprocess_c_source_with_origins(source).text
}

fn preprocess_c_source_with_origins(source: &str) -> TrackedSource {
    let logical = join_line_continuations(source);
    let mut macros = HashMap::<String, CMacro>::new();
    let mut active_stack = vec![true];
    let mut branch_taken = Vec::<bool>::new();
    let mut out = String::new();
    let mut macro_bytes = Vec::new();

    for line in logical.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            if *active_stack.last().unwrap_or(&true) {
                let expanded = expand_macros_tracked(TrackedSource::plain(line.to_string()), &macros);
                out.push_str(&expanded.text);
                macro_bytes.extend(expanded.macro_bytes);
            }
            out.push('\n');
            macro_bytes.push(false);
            continue;
        }

        let directive = trimmed.trim_start_matches('#').trim_start();
        let parent_active = active_stack
            .get(active_stack.len().saturating_sub(2))
            .copied()
            .unwrap_or(true);

        if let Some(rest) = directive.strip_prefix("define") {
            if *active_stack.last().unwrap_or(&true) {
                parse_define(rest.trim(), &mut macros);
            }
        } else if let Some(rest) = directive.strip_prefix("undef") {
            if *active_stack.last().unwrap_or(&true) {
                macros.remove(rest.trim());
            }
        } else if let Some(rest) = directive.strip_prefix("ifdef") {
            let cond = macros.contains_key(rest.trim());
            let active = *active_stack.last().unwrap_or(&true) && cond;
            active_stack.push(active);
            branch_taken.push(active);
        } else if let Some(rest) = directive.strip_prefix("ifndef") {
            let cond = !macros.contains_key(rest.trim());
            let active = *active_stack.last().unwrap_or(&true) && cond;
            active_stack.push(active);
            branch_taken.push(active);
        } else if let Some(rest) = directive.strip_prefix("if") {
            let cond = evaluate_pp_condition(rest.trim(), &macros);
            let active = *active_stack.last().unwrap_or(&true) && cond;
            active_stack.push(active);
            branch_taken.push(active);
        } else if let Some(rest) = directive.strip_prefix("elif") {
            if active_stack.len() > 1 {
                let taken = branch_taken.last().copied().unwrap_or(false);
                let active = parent_active && !taken && evaluate_pp_condition(rest.trim(), &macros);
                if let Some(last) = active_stack.last_mut() {
                    *last = active;
                }
                if active {
                    if let Some(last) = branch_taken.last_mut() {
                        *last = true;
                    }
                }
            }
        } else if directive.starts_with("else") {
            if active_stack.len() > 1 {
                let taken = branch_taken.last().copied().unwrap_or(false);
                let active = parent_active && !taken;
                if let Some(last) = active_stack.last_mut() {
                    *last = active;
                }
                if let Some(last) = branch_taken.last_mut() {
                    *last = true;
                }
            }
        } else if directive.starts_with("endif") {
            if active_stack.len() > 1 {
                active_stack.pop();
                branch_taken.pop();
            }
        } else if directive.starts_with("include") && *active_stack.last().unwrap_or(&true) {
            out.push_str(line);
            macro_bytes.extend(std::iter::repeat(false).take(line.len()));
        }
        out.push('\n');
        macro_bytes.push(false);
    }

    TrackedSource { text: out, macro_bytes }
}

fn join_line_continuations(source: &str) -> String {
    let mut out = String::new();
    let mut pending = String::new();
    for line in source.lines() {
        let trimmed = line.trim_end();
        if let Some(prefix) = trimmed.strip_suffix('\\') {
            pending.push_str(prefix);
            pending.push(' ');
        } else {
            pending.push_str(line);
            out.push_str(&pending);
            out.push('\n');
            pending.clear();
        }
    }
    if !pending.is_empty() {
        out.push_str(&pending);
    }
    out
}

fn parse_define(text: &str, macros: &mut HashMap<String, CMacro>) {
    let Some(name_end) = text
        .char_indices()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_'))
        .map(|(idx, _)| idx)
        .or(Some(text.len()))
    else {
        return;
    };
    let name = text[..name_end].trim();
    if name.is_empty() {
        return;
    }
    let tail = &text[name_end..];
    if tail.starts_with('(') {
        if let Some(close) = matching_delimiter(tail, 0, '(', ')') {
            let params = tail[1..close]
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(|part| if part == "..." { "__VA_ARGS__" } else { part }.to_string())
                .collect::<Vec<_>>();
            macros.insert(
                name.to_string(),
                CMacro {
                    params: Some(params),
                    body: tail[close + 1..].trim().to_string(),
                },
            );
        }
    } else {
        macros.insert(
            name.to_string(),
            CMacro {
                params: None,
                body: tail.trim().to_string(),
            },
        );
    }
}

fn evaluate_pp_condition(text: &str, macros: &HashMap<String, CMacro>) -> bool {
    let trimmed = text.trim();
    if trimmed == "0" {
        return false;
    }
    if trimmed == "1" {
        return true;
    }
    if let Some(inner) = trimmed.strip_prefix("defined(").and_then(|s| s.strip_suffix(')')) {
        return macros.contains_key(inner.trim());
    }
    if let Some(inner) = trimmed.strip_prefix("defined ") {
        return macros.contains_key(inner.trim());
    }
    if let Some(inner) = trimmed.strip_prefix('!') {
        return !evaluate_pp_condition(inner, macros);
    }
    macros.get(trimmed).is_some_and(|value| value.body.trim() != "0")
}

fn expand_macros(line: &str, macros: &HashMap<String, CMacro>) -> String {
    expand_macros_tracked(TrackedSource::plain(line.to_string()), macros).text
}

fn expand_macros_tracked(mut current: TrackedSource, macros: &HashMap<String, CMacro>) -> TrackedSource {
    for _ in 0..8 {
        let (next, changed) = expand_macros_once_tracked(&current, macros);
        current = next;
        if !changed {
            break;
        }
    }
    current
}

fn expand_macros_once(line: &str, macros: &HashMap<String, CMacro>) -> String {
    expand_macros_once_tracked(&TrackedSource::plain(line.to_string()), macros).0.text
}

fn expand_macros_once_tracked(line: &TrackedSource, macros: &HashMap<String, CMacro>) -> (TrackedSource, bool) {
    let mut out = String::new();
    let mut macro_bytes = Vec::new();
    let mut byte = 0usize;
    let mut in_string = None::<char>;
    let mut escaped = false;
    let mut changed = false;

    let push_original = |start: usize, end: usize, out: &mut String, origins: &mut Vec<bool>| {
        out.push_str(&line.text[start..end]);
        origins.extend_from_slice(&line.macro_bytes[start..end]);
    };

    let push_macro = |text: &str, out: &mut String, origins: &mut Vec<bool>| {
        out.push_str(text);
        origins.extend(std::iter::repeat(true).take(text.len()));
    };

    while byte < line.text.len() {
        let ch = line.text[byte..].chars().next().expect("valid char boundary");
        if let Some(quote) = in_string {
            let end = byte + ch.len_utf8();
            push_original(byte, end, &mut out, &mut macro_bytes);
            byte += ch.len_utf8();
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_string = Some(ch);
            let end = byte + ch.len_utf8();
            push_original(byte, end, &mut out, &mut macro_bytes);
            byte += ch.len_utf8();
            continue;
        }
        if ch.is_ascii_alphabetic() || ch == '_' {
            let start = byte;
            byte += ch.len_utf8();
            while byte < line.text.len() {
                let next = line.text[byte..].chars().next().expect("valid char boundary");
                if next.is_ascii_alphanumeric() || next == '_' {
                    byte += next.len_utf8();
                } else {
                    break;
                }
            }
            let name = &line.text[start..byte];
            let Some(mac) = macros.get(name) else {
                push_original(start, byte, &mut out, &mut macro_bytes);
                continue;
            };
            if let Some(params) = &mac.params {
                let mut cursor = byte;
                while cursor < line.text.len() && line.text.as_bytes()[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                if cursor >= line.text.len() || line.text.as_bytes()[cursor] != b'(' {
                    push_original(start, byte, &mut out, &mut macro_bytes);
                    continue;
                }
                let Some(close) = matching_delimiter(&line.text, cursor, '(', ')') else {
                    push_original(start, byte, &mut out, &mut macro_bytes);
                    continue;
                };
                let args = split_top_level_commas(&line.text[cursor + 1..close]);
                let mut bindings = HashMap::<String, String>::new();
                let variadic = params.last().is_some_and(|param| param == "__VA_ARGS__");
                let fixed = if variadic { params.len().saturating_sub(1) } else { params.len() };
                for (param, arg) in params.iter().take(fixed).zip(args.iter()) {
                    bindings.insert(param.clone(), arg.trim().to_string());
                }
                if variadic {
                    let rest = args.iter().skip(fixed).map(|arg| arg.trim()).collect::<Vec<_>>().join(", ");
                    bindings.insert("__VA_ARGS__".to_string(), rest);
                }
                let body = expand_function_macro_body(&mac.body, &bindings);
                push_macro(&body, &mut out, &mut macro_bytes);
                changed = true;
                byte = close + 1;
            } else {
                push_macro(&mac.body, &mut out, &mut macro_bytes);
                changed = true;
            }
            continue;
        }
        let end = byte + ch.len_utf8();
        push_original(byte, end, &mut out, &mut macro_bytes);
        byte += ch.len_utf8();
    }
    (TrackedSource { text: out, macro_bytes }, changed)
}

fn expand_function_macro_body(body: &str, bindings: &HashMap<String, String>) -> String {
    let mut expanded = body.to_string();

    // Stringification must run before ordinary replacement. Preserve a deterministic spelling
    // instead of attempting compiler-specific whitespace normalization.
    for (param, value) in bindings {
        let pattern = Regex::new(&format!(r"(^|[^#])#\s*\b{}\b", regex::escape(param)))
            .expect("valid regex");
        let quoted = format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\""));
        expanded = pattern
            .replace_all(&expanded, |caps: &regex::Captures<'_>| {
                format!("{}{}", caps.get(1).map_or("", |m| m.as_str()), quoted)
            })
            .into_owned();
    }

    for (param, value) in bindings {
        expanded = replace_identifier(&expanded, param, value);
    }

    // Token pasting joins the immediately adjacent preprocessing tokens. Re-run until stable so
    // chained forms such as a ## b ## c are handled conservatively.
    let paste = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*|[0-9]+)\s*##\s*([A-Za-z_][A-Za-z0-9_]*|[0-9]+)")
        .expect("valid regex");
    for _ in 0..8 {
        let next = paste.replace_all(&expanded, "$1$2").into_owned();
        if next == expanded { break; }
        expanded = next;
    }
    expanded
}

fn replace_identifier(text: &str, target: &str, replacement: &str) -> String {
    let pattern = Regex::new(&format!(r"\b{}\b", regex::escape(target))).expect("valid regex");
    pattern.replace_all(text, replacement).into_owned()
}
