use regex::Regex;
use std::collections::HashMap;
use uniflow_hir::{
    CppConstructorInitializer, CppConstructorInitializerKind, CppMethodSemantics, CppOwnershipKind,
    CppReferenceKind, CppSpecialMemberKind, CppValueSemantics,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct SemanticIndex {
    pub methods: HashMap<String, CppMethodSemantics>,
    /// Fallback declarations that are not tied to a recoverable function scope.
    pub values: HashMap<String, CppValueSemantics>,
    /// Function-local values keyed by qualified function name and explicit parameter count.
    pub scoped_values: HashMap<(String, usize), HashMap<String, CppValueSemantics>>,
    pub initializers: HashMap<String, Vec<CppConstructorInitializer>>,
}

pub(crate) fn collect(source: &str) -> SemanticIndex {
    let mut out = SemanticIndex::default();

    // Qualified definitions carry enough information to build a stable method identity.
    let method_re = Regex::new(
        r"(?m)(virtual\s+)?(?:[A-Za-z_][A-Za-z0-9_:<>*&\s]*\s+)?((?:[A-Za-z_][A-Za-z0-9_]*::)+)(~?[A-Za-z_][A-Za-z0-9_]*|operator\s*[^\s(]+)\s*\(([^;{}]*)\)\s*(const\s*)?(noexcept(?:\s*\([^)]*\))?\s*)?(override\s*)?(final\s*)?(=\s*0\s*)?[;{]",
    )
    .expect("valid C++ method regex");
    for caps in method_re.captures_iter(source) {
        let owner = caps
            .get(2)
            .map(|m| {
                m.as_str()
                    .trim_end_matches("::")
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
            })
            .unwrap_or("")
            .to_string();
        let name = caps
            .get(3)
            .map(|m| m.as_str().replace(' ', ""))
            .unwrap_or_default();
        if owner.is_empty() || name.is_empty() {
            continue;
        }
        let params = caps.get(4).map(|m| m.as_str()).unwrap_or("");
        let qualified = format!("{owner}::{name}");
        let special_member = classify_special_member(&owner, &name, params);
        out.methods.insert(
            qualified,
            CppMethodSemantics {
                owner,
                is_virtual: caps.get(1).is_some(),
                is_pure_virtual: caps.get(9).is_some(),
                is_override: caps.get(7).is_some(),
                is_final: caps.get(8).is_some(),
                is_const: caps.get(5).is_some(),
                is_noexcept: caps.get(6).is_some(),
                special_member,
            },
        );
    }

    for (owner, header) in collect_inline_method_headers(source) {
        let Some((name, params, mut semantics)) = parse_inline_method_header(&owner, &header)
        else {
            continue;
        };
        semantics.owner = owner.clone();
        let qualified = format!("{owner}::{name}");
        semantics.special_member = classify_special_member(&owner, &name, &params);
        out.methods
            .entry(qualified)
            .and_modify(|existing| merge_method_semantics(existing, &semantics))
            .or_insert(semantics);
    }

    let constructor_re = Regex::new(
        r"(?s)\b((?:[A-Za-z_][A-Za-z0-9_]*::)+)([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*(?:noexcept(?:\s*\([^)]*\))?\s*)?:\s*([^\{]+)\{",
    )
    .expect("valid C++ constructor initializer regex");
    for caps in constructor_re.captures_iter(source) {
        let owner = caps
            .get(1)
            .map(|m| {
                m.as_str()
                    .trim_end_matches("::")
                    .rsplit("::")
                    .next()
                    .unwrap_or("")
            })
            .unwrap_or("");
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if owner.is_empty() || name != owner {
            continue;
        }
        let mut initializers = Vec::new();
        for initializer in split_cpp_top_level(caps.get(4).map(|m| m.as_str()).unwrap_or(""), ',') {
            let initializer = initializer.trim();
            let Some(open) = initializer.find(|ch| ch == '(' || ch == '{') else {
                continue;
            };
            let close_ch = if initializer.as_bytes().get(open) == Some(&b'(') {
                ')'
            } else {
                '}'
            };
            let Some(close) = initializer.rfind(close_ch) else {
                continue;
            };
            let target = initializer[..open].trim();
            if target.is_empty() || close <= open {
                continue;
            }
            let arguments = split_cpp_top_level(&initializer[open + 1..close], ',')
                .into_iter()
                .map(str::trim)
                .filter(|argument| !argument.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            let simple_target = target.rsplit("::").next().unwrap_or(target);
            let kind = if simple_target == owner {
                CppConstructorInitializerKind::Delegating
            } else if target.contains("::")
                || simple_target
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_uppercase())
            {
                CppConstructorInitializerKind::Base
            } else {
                CppConstructorInitializerKind::Field
            };
            initializers.push(CppConstructorInitializer {
                kind,
                target: target.to_string(),
                arguments,
            });
        }
        if !initializers.is_empty() {
            out.initializers
                .insert(format!("{owner}::{owner}"), initializers);
        }
    }

    out.values = collect_value_semantics(source);
    for (name, arity, text) in collect_function_value_surfaces(source) {
        out.scoped_values
            .entry((name, arity))
            .or_default()
            .extend(collect_value_semantics(&text));
    }

    out
}

fn collect_value_semantics(source: &str) -> HashMap<String, CppValueSemantics> {
    let mut values = HashMap::new();
    let smart_ptr_re = Regex::new(
        r"(?m)(?:std::)?(unique_ptr|shared_ptr|weak_ptr)\s*<\s*([^;=()]+?)\s*>\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    .expect("valid smart pointer regex");
    for caps in smart_ptr_re.captures_iter(source) {
        let ownership = match caps.get(1).map(|m| m.as_str()) {
            Some("unique_ptr") => CppOwnershipKind::Unique,
            Some("shared_ptr") => CppOwnershipKind::Shared,
            Some("weak_ptr") => CppOwnershipKind::Weak,
            _ => CppOwnershipKind::None,
        };
        if let Some(name) = caps.get(3) {
            values.insert(
                name.as_str().to_string(),
                CppValueSemantics {
                    reference_kind: CppReferenceKind::None,
                    ownership,
                    pointee_type: caps.get(2).map(|m| m.as_str().trim().to_string()),
                },
            );
        }
    }

    let rvalue_ref_re =
        Regex::new(r"(?m)\b([A-Za-z_][A-Za-z0-9_:<>]*)\s*&&\s*([A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid rvalue-reference regex");
    for caps in rvalue_ref_re.captures_iter(source) {
        let Some(name) = caps.get(2) else { continue };
        let entry = values.entry(name.as_str().to_string()).or_default();
        entry.reference_kind = CppReferenceKind::RValue;
        entry.pointee_type.get_or_insert_with(|| {
            caps.get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default()
        });
        if entry.ownership == CppOwnershipKind::None {
            entry.ownership = CppOwnershipKind::Borrowed;
        }
    }
    let lvalue_ref_re =
        Regex::new(r"(?m)\b([A-Za-z_][A-Za-z0-9_:<>]*)\s*&\s*([A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid lvalue-reference regex");
    for caps in lvalue_ref_re.captures_iter(source) {
        let Some(name) = caps.get(2) else { continue };
        let entry = values.entry(name.as_str().to_string()).or_default();
        if entry.reference_kind == CppReferenceKind::None {
            entry.reference_kind = CppReferenceKind::LValue;
        }
        entry.pointee_type.get_or_insert_with(|| {
            caps.get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default()
        });
        if entry.ownership == CppOwnershipKind::None {
            entry.ownership = CppOwnershipKind::Borrowed;
        }
    }

    let raw_ptr_re =
        Regex::new(r"(?m)\b([A-Za-z_][A-Za-z0-9_:<>]*)\s*\*+\s*([A-Za-z_][A-Za-z0-9_]*)")
            .expect("valid raw-pointer regex");
    for caps in raw_ptr_re.captures_iter(source) {
        let Some(name) = caps.get(2) else { continue };
        let entry = values.entry(name.as_str().to_string()).or_default();
        if entry.ownership == CppOwnershipKind::None {
            entry.ownership = CppOwnershipKind::Raw;
        }
        entry.pointee_type.get_or_insert_with(|| {
            caps.get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default()
        });
    }
    values
}

fn collect_function_value_surfaces(source: &str) -> Vec<(String, usize, String)> {
    fn matching(source: &str, open: usize, left: u8, right: u8) -> Option<usize> {
        if source.as_bytes().get(open).copied()? != left {
            return None;
        }
        let bytes = source.as_bytes();
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        let mut index = open;
        while index < bytes.len() {
            let byte = bytes[index];
            if escaped {
                escaped = false;
                index += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == active {
                    quote = None;
                }
                index += 1;
                continue;
            }
            if byte == b'\'' || byte == b'"' {
                quote = Some(byte);
                index += 1;
                continue;
            }
            if byte == left {
                depth += 1;
            } else if byte == right {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    let head =
        Regex::new(r"(?m)([A-Za-z_~][A-Za-z0-9_:~]*)\s*\(").expect("valid function surface regex");
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < source.len() {
        let Some(caps) = head.captures(&source[cursor..]) else {
            break;
        };
        let whole = caps.get(0).expect("whole match");
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let absolute_start = cursor + whole.start();
        let open_paren = cursor + whole.end() - 1;
        if matches!(name, "if" | "while" | "for" | "switch" | "catch") {
            cursor = open_paren + 1;
            continue;
        }
        let Some(close_paren) = matching(source, open_paren, b'(', b')') else {
            cursor = open_paren + 1;
            continue;
        };
        let mut body_open = close_paren + 1;
        while source
            .as_bytes()
            .get(body_open)
            .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            body_open += 1;
        }
        for qualifier in ["const", "noexcept", "override", "final"] {
            if source[body_open..].starts_with(qualifier) {
                body_open += qualifier.len();
                while source
                    .as_bytes()
                    .get(body_open)
                    .is_some_and(|byte| byte.is_ascii_whitespace())
                {
                    body_open += 1;
                }
                if qualifier == "noexcept" && source.as_bytes().get(body_open) == Some(&b'(') {
                    if let Some(close) = matching(source, body_open, b'(', b')') {
                        body_open = close + 1;
                    }
                }
            }
        }
        if source.as_bytes().get(body_open) == Some(&b':') {
            // Constructor initializer lists may contain nested calls/braces and commas.  Walk to
            // the first top-level function body brace instead of dropping the function scope.
            let bytes = source.as_bytes();
            let mut paren = 0usize;
            let mut bracket = 0usize;
            let mut angle = 0usize;
            let mut quote = None;
            let mut escaped = false;
            body_open += 1;
            while body_open < bytes.len() {
                let byte = bytes[body_open];
                if escaped {
                    escaped = false;
                    body_open += 1;
                    continue;
                }
                if let Some(active) = quote {
                    if byte == b'\\' {
                        escaped = true;
                    } else if byte == active {
                        quote = None;
                    }
                    body_open += 1;
                    continue;
                }
                match byte {
                    b'\'' | b'"' => quote = Some(byte),
                    b'(' => paren += 1,
                    b')' => paren = paren.saturating_sub(1),
                    b'[' => bracket += 1,
                    b']' => bracket = bracket.saturating_sub(1),
                    b'<' => angle += 1,
                    b'>' => angle = angle.saturating_sub(1),
                    b'{' if paren == 0 && bracket == 0 && angle == 0 => break,
                    b';' if paren == 0 && bracket == 0 && angle == 0 => break,
                    _ => {}
                }
                body_open += 1;
            }
        }
        if source.as_bytes().get(body_open) != Some(&b'{') {
            cursor = close_paren + 1;
            continue;
        }
        let Some(body_close) = matching(source, body_open, b'{', b'}') else {
            break;
        };
        let params = &source[open_paren + 1..close_paren];
        let arity = split_cpp_top_level(params, ',')
            .into_iter()
            .filter(|param| !param.trim().is_empty() && param.trim() != "void")
            .count();
        let mut surface = String::with_capacity(params.len() + body_close - body_open);
        surface.push_str(params);
        surface.push(';');
        surface.push_str(&source[body_open + 1..body_close]);
        out.push((name.to_string(), arity, surface));
        cursor = body_close + 1;
        let _ = absolute_start;
    }
    out
}

fn merge_method_semantics(target: &mut CppMethodSemantics, incoming: &CppMethodSemantics) {
    target.is_virtual |= incoming.is_virtual;
    target.is_pure_virtual |= incoming.is_pure_virtual;
    target.is_override |= incoming.is_override;
    target.is_final |= incoming.is_final;
    target.is_const |= incoming.is_const;
    target.is_noexcept |= incoming.is_noexcept;
    if target.special_member.is_none() {
        target.special_member = incoming.special_member;
    }
}

fn cpp_matching_brace(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let mut index = open;
    while index < bytes.len() {
        let byte = bytes[index];
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment {
            if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if let Some(active) = quote {
            if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
            line_comment = true;
            index += 2;
            continue;
        }
        if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
            block_comment = true;
            index += 2;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
        } else if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn collect_inline_method_headers(source: &str) -> Vec<(String, String)> {
    let class_re =
        Regex::new(r"\b(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*[^\{]+)?\s*\{")
            .expect("valid class regex");
    let mut out = Vec::new();
    let mut search = 0usize;
    while search < source.len() {
        let Some(caps) = class_re.captures(&source[search..]) else {
            break;
        };
        let whole = caps.get(0).expect("class match");
        let owner = caps
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or_default()
            .to_string();
        let open = search + whole.end() - 1;
        let Some(close) = cpp_matching_brace(source, open) else {
            break;
        };
        let mut cursor = open + 1;
        let mut start = cursor;
        let mut paren = 0usize;
        let mut bracket = 0usize;
        let mut angle = 0usize;
        let mut quote = None;
        let mut escaped = false;
        while cursor < close {
            let byte = source.as_bytes()[cursor];
            if escaped {
                escaped = false;
                cursor += 1;
                continue;
            }
            if let Some(active) = quote {
                if byte == b'\\' {
                    escaped = true;
                } else if byte == active {
                    quote = None;
                }
                cursor += 1;
                continue;
            }
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => paren += 1,
                b')' => paren = paren.saturating_sub(1),
                b'[' => bracket += 1,
                b']' => bracket = bracket.saturating_sub(1),
                b'<' => angle += 1,
                b'>' => angle = angle.saturating_sub(1),
                b';' if paren == 0 && bracket == 0 && angle == 0 => {
                    let header = source[start..cursor].trim();
                    if header.contains('(') {
                        out.push((owner.clone(), header.to_string()));
                    }
                    start = cursor + 1;
                }
                b'{' if paren == 0 && bracket == 0 && angle == 0 => {
                    let header = source[start..cursor].trim();
                    if header.contains('(') {
                        out.push((owner.clone(), header.to_string()));
                    }
                    if let Some(end) = cpp_matching_brace(source, cursor) {
                        cursor = end;
                        start = cursor + 1;
                    }
                }
                _ => {}
            }
            cursor += 1;
        }
        search = close + 1;
    }
    out
}

fn parse_inline_method_header(
    owner: &str,
    header: &str,
) -> Option<(String, String, CppMethodSemantics)> {
    let access_re =
        Regex::new(r"(?m)\b(?:public|protected|private)\s*:\s*").expect("valid access regex");
    let cleaned = access_re.replace_all(header, "");
    let open = cleaned.find('(')?;
    let close = cleaned.rfind(')')?;
    if close < open {
        return None;
    }
    let prefix = cleaned[..open].trim_end();
    if prefix.contains("(*") {
        return None;
    }
    let (name_start, name) = if let Some(operator) = prefix.rfind("operator") {
        (operator, prefix[operator..].replace(' ', ""))
    } else {
        let bytes = prefix.as_bytes();
        let mut start = bytes.len();
        while start > 0 {
            let byte = bytes[start - 1];
            if byte == b'_' || byte == b'~' || byte.is_ascii_alphanumeric() {
                start -= 1;
            } else {
                break;
            }
        }
        if start == bytes.len() {
            return None;
        }
        (start, prefix[start..].to_string())
    };
    let return_surface = prefix[..name_start].trim();
    if return_surface.is_empty() && name != owner && name != format!("~{owner}") {
        return None;
    }
    let suffix = cleaned[close + 1..].trim();
    let params = cleaned[open + 1..close].to_string();
    let is_override = suffix.split_whitespace().any(|word| word == "override");
    let is_pure_virtual = suffix.replace(' ', "").contains("=0");
    Some((
        name,
        params,
        CppMethodSemantics {
            owner: owner.to_string(),
            is_virtual: prefix.split_whitespace().any(|word| word == "virtual")
                || is_override
                || is_pure_virtual,
            is_pure_virtual,
            is_override,
            is_final: suffix.split_whitespace().any(|word| word == "final"),
            is_const: suffix.split_whitespace().any(|word| word == "const"),
            is_noexcept: suffix.contains("noexcept"),
            special_member: None,
        },
    ))
}

fn split_cpp_top_level(input: &str, delimiter: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    let mut angle = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '<' => angle += 1,
            '>' => angle = angle.saturating_sub(1),
            _ if ch == delimiter && paren == 0 && brace == 0 && bracket == 0 && angle == 0 => {
                out.push(input[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(input[start..].trim());
    out
}

fn classify_special_member(owner: &str, name: &str, params: &str) -> Option<CppSpecialMemberKind> {
    if name == owner {
        if params.contains("&&") {
            Some(CppSpecialMemberKind::MoveConstructor)
        } else if params.contains('&') {
            Some(CppSpecialMemberKind::CopyConstructor)
        } else {
            Some(CppSpecialMemberKind::Constructor)
        }
    } else if name == format!("~{owner}") {
        Some(CppSpecialMemberKind::Destructor)
    } else if name == "operator=" {
        if params.contains("&&") {
            Some(CppSpecialMemberKind::MoveAssignment)
        } else if params.contains('&') {
            Some(CppSpecialMemberKind::CopyAssignment)
        } else {
            Some(CppSpecialMemberKind::Assignment)
        }
    } else {
        None
    }
}
