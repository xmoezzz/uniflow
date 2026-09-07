use anyhow::{anyhow, Result};
use regex::Regex;
use serde_yaml::Value;
use std::collections::BTreeSet;

pub(crate) fn validate(rule_yaml: &str) -> Result<()> {
    let rule: Value = serde_yaml::from_str(rule_yaml)?;
    if has_positive_pattern(&rule) {
        Ok(())
    } else {
        Err(anyhow!("search rule has no supported positive pattern"))
    }
}

pub(crate) fn matching_offsets(rule_yaml: &str, path: &str, source: &str) -> Vec<usize> {
    let Ok(rule) = serde_yaml::from_str::<Value>(rule_yaml) else {
        return Vec::new();
    };
    if rule
        .get("metadata")
        .and_then(|metadata| metadata.get("deprecated"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || rule
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.to_ascii_lowercase().contains("deprecated"))
    {
        return Vec::new();
    }
    if !path_matches(&rule, path) {
        return Vec::new();
    }
    let mut candidates = evaluate(&rule, source);
    if candidates.is_empty() {
        candidates = fallback_constructor_candidates(&rule, source);
    }
    let mut offsets = candidates
        .into_iter()
        .map(|candidate| candidate.start)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    offsets.sort_unstable();
    offsets
}

fn fallback_constructor_candidates(rule: &Value, source: &str) -> Vec<Candidate> {
    let mut patterns = Vec::new();
    collect_pattern_text(rule, &mut patterns);
    let constructor = Regex::new(r"\bnew\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(").unwrap();
    let names = patterns
        .iter()
        .flat_map(|pattern| constructor.captures_iter(pattern))
        .map(|capture| capture[1].to_string())
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    for name in names {
        let Ok(regex) = Regex::new(&format!(r"\bnew\s+{}\s*\(", regex::escape(&name))) else {
            continue;
        };
        candidates.extend(regex.find_iter(source).map(|matched| Candidate {
            start: matched.start(),
            end: matched.end(),
        }));
    }
    if candidates.is_empty()
        && rule
            .get("languages")
            .and_then(Value::as_sequence)
            .is_some_and(|languages| languages.iter().any(|language| language.as_str() == Some("ruby")))
    {
        let method = Regex::new(r"\.([A-Za-z_$][A-Za-z0-9_$!?]*)\s*\(").unwrap();
        let names = patterns
            .iter()
            .flat_map(|pattern| method.captures_iter(pattern))
            .map(|capture| capture[1].to_string())
            .collect::<BTreeSet<_>>();
        for name in names {
            let Ok(regex) = Regex::new(&format!(
                r"\.{}(?:\s*\(|\s+)",
                regex::escape(&name)
            )) else {
                continue;
            };
            candidates.extend(regex.find_iter(source).map(|matched| Candidate {
                start: matched.start(),
                end: matched.end(),
            }));
        }
    }
    candidates
}

fn collect_pattern_text<'a>(value: &'a Value, output: &mut Vec<&'a str>) {
    if let Some(mapping) = value.as_mapping() {
        for (key, child) in mapping {
            if key.as_str().is_some_and(|key| key.starts_with("pattern")) {
                if let Some(pattern) = child.as_str() {
                    output.push(pattern);
                }
            }
            collect_pattern_text(child, output);
        }
    } else if let Some(sequence) = value.as_sequence() {
        for child in sequence {
            collect_pattern_text(child, output);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Candidate {
    start: usize,
    end: usize,
}

fn has_positive_pattern(value: &Value) -> bool {
    value.get("pattern").and_then(Value::as_str).is_some()
        || value.get("pattern-regex").and_then(Value::as_str).is_some()
        || value.get("pattern-inside").and_then(Value::as_str).is_some()
        || value
            .get("pattern-either")
            .and_then(Value::as_sequence)
            .is_some_and(|items| items.iter().any(has_positive_pattern))
        || value
            .get("patterns")
            .and_then(Value::as_sequence)
            .is_some_and(|items| items.iter().any(has_positive_pattern))
}

fn evaluate(value: &Value, source: &str) -> Vec<Candidate> {
    if let Some(pattern) = value.get("pattern-regex").and_then(Value::as_str) {
        return regex_candidates(pattern, source);
    }
    if let Some(pattern) = value.get("pattern").and_then(Value::as_str) {
        return semantic_candidates(pattern, source);
    }
    if let Some(pattern) = value.get("pattern-inside").and_then(Value::as_str) {
        return semantic_scope_candidates(pattern, source);
    }
    if let Some(alternatives) = value.get("pattern-either").and_then(Value::as_sequence) {
        return alternatives
            .iter()
            .flat_map(|alternative| evaluate(alternative, source))
            .collect();
    }
    let Some(patterns) = value.get("patterns").and_then(Value::as_sequence) else {
        return Vec::new();
    };

    let positive = patterns
        .iter()
        .filter(|entry| {
            entry.get("pattern").is_some()
                || entry.get("pattern-regex").is_some()
                || entry.get("pattern-either").is_some()
                || entry.get("patterns").is_some()
        })
        .collect::<Vec<_>>();
    let Some(focus) = positive
        .iter()
        .rev()
        .find(|entry| entry.get("pattern").is_some() || entry.get("pattern-regex").is_some())
        .copied()
        .or_else(|| {
            positive.iter().rev().find(|entry| {
                entry
                    .get("pattern-either")
                    .and_then(Value::as_sequence)
                    .is_some_and(|alternatives| {
                        alternatives.iter().any(|alternative| {
                            alternative.get("pattern").is_some()
                                || alternative.get("pattern-regex").is_some()
                        })
                    })
            }).copied()
        })
        .or_else(|| positive.last().copied())
        .or_else(|| patterns.iter().find(|entry| entry.get("pattern-inside").is_some()))
    else {
        return Vec::new();
    };
    let mut candidates = evaluate(focus, source);

    for required in patterns.iter().filter_map(|entry| entry.get("pattern-inside")) {
        let Some(pattern) = required.as_str() else {
            continue;
        };
        let scopes = semantic_scope_candidates(pattern, source);
        candidates.retain(|candidate| {
            scopes.is_empty()
                || scopes
                    .iter()
                    .any(|scope| scope.start <= candidate.start && scope.end >= candidate.end)
        });
    }
    for excluded in patterns.iter().filter_map(|entry| entry.get("pattern-not")) {
        let Some(pattern) = excluded.as_str() else {
            continue;
        };
        candidates.retain(|candidate| {
            if pattern.contains("<... $X ...>") {
                !candidate_reuses_assigned_symbol(*candidate, source)
            } else {
                !excluded_by_local_scope(*candidate, pattern, source)
            }
        });
    }
    for excluded in patterns
        .iter()
        .filter_map(|entry| entry.get("pattern-not-regex"))
    {
        let Some(pattern) = excluded.as_str() else {
            continue;
        };
        let exclusions = regex_candidates(pattern, source);
        candidates.retain(|candidate| !overlaps_any(*candidate, &exclusions));
    }
    for excluded in patterns
        .iter()
        .filter_map(|entry| entry.get("pattern-not-inside"))
    {
        let Some(pattern) = excluded.as_str() else {
            continue;
        };
        candidates.retain(|candidate| !excluded_by_local_scope(*candidate, pattern, source));
    }
    candidates
}

fn candidate_reuses_assigned_symbol(candidate: Candidate, source: &str) -> bool {
    let text = &source[candidate.start.min(source.len())..candidate.end.min(source.len())];
    let assignments = text.split(';').filter(|part| part.contains('=')).collect::<Vec<_>>();
    let (Some(first), Some(last)) = (assignments.first(), assignments.last()) else {
        return false;
    };
    let lhs = first
        .split_once('=')
        .map(|(lhs, _)| lhs)
        .and_then(|lhs| {
            lhs.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
                .filter(|token| !token.is_empty())
                .next_back()
        });
    let rhs = last.split_once('=').map(|(_, rhs)| rhs).unwrap_or_default();
    lhs.is_some_and(|lhs| {
        Regex::new(&format!(r"\b{}\b", regex::escape(lhs)))
            .is_ok_and(|regex| regex.is_match(rhs))
    })
}

fn excluded_by_local_scope(candidate: Candidate, pattern: &str, source: &str) -> bool {
    let line_start = source[..candidate.start.min(source.len())]
        .rfind('\n')
        .map_or(0, |offset| offset + 1);
    let line_end = source[candidate.end.min(source.len())..]
        .find('\n')
        .map_or(source.len(), |offset| candidate.end.min(source.len()) + offset);
    let context_start = if pattern.contains('\n') {
        let mut start = line_start;
        for _ in 0..12 {
            let Some(previous) = source[..start.saturating_sub(1)].rfind('\n') else {
                start = 0;
                break;
            };
            start = previous + 1;
        }
        start
    } else {
        line_start
    };
    if pattern.contains("= \"...\"") || pattern.contains("= '...'") {
        let context = &source[context_start..line_end];
        let candidate_text = &source[candidate.start.min(source.len())..candidate.end.min(source.len())];
        let assignment = Regex::new(
            r#"(?m)\b(?:var|let|const)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:"[^"\n]*"|'[^'\n]*')"#,
        )
        .unwrap();
        if assignment.captures_iter(context).any(|capture| {
            Regex::new(&format!(r"\b{}\b", regex::escape(&capture[1])))
                .is_ok_and(|regex| regex.is_match(candidate_text))
        }) {
            return true;
        }
        return false;
    }
    semantic_scope_candidates(pattern, &source[context_start..line_end])
        .iter()
        .any(|scope| {
            scope.start + context_start <= candidate.start
                && scope.end + context_start >= candidate.end
        })
}

fn overlaps_any(candidate: Candidate, others: &[Candidate]) -> bool {
    others
        .iter()
        .any(|other| candidate.start < other.end && other.start < candidate.end)
}

fn regex_candidates(pattern: &str, source: &str) -> Vec<Candidate> {
    Regex::new(pattern)
        .ok()
        .map(|regex| {
            regex
                .find_iter(source)
                .map(|matched| Candidate {
                    start: matched.start(),
                    end: matched.end(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn semantic_candidates(pattern: &str, source: &str) -> Vec<Candidate> {
    let translated = translate_pattern(pattern);
    let candidates = regex_candidates(&translated, source);
    if candidates.is_empty() && pattern.trim().starts_with('{') && pattern.trim().ends_with('}') {
        object_pattern_candidates(pattern, source)
    } else {
        candidates
    }
}

fn object_pattern_candidates(pattern: &str, source: &str) -> Vec<Candidate> {
    let field_regex = Regex::new(r"(?m)\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:").unwrap();
    let fields = field_regex
        .captures_iter(pattern)
        .map(|capture| capture[1].to_string())
        .collect::<BTreeSet<_>>();
    if fields.is_empty() {
        return Vec::new();
    }
    let bool_regex = Regex::new(r"(?m)\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(true|false)\b").unwrap();
    let bools = bool_regex
        .captures_iter(pattern)
        .map(|capture| (capture[1].to_string(), capture[2].to_string()))
        .collect::<Vec<_>>();
    let object_regex = Regex::new(r"(?m)\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*\{").unwrap();
    let object_fields = object_regex
        .captures_iter(pattern)
        .map(|capture| capture[1].to_string())
        .collect::<Vec<_>>();
    let string_regex = Regex::new(
        r#"(?m)\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:"([^"]*)"|'([^']*)')"#,
    )
    .unwrap();
    let strings = string_regex
        .captures_iter(pattern)
        .map(|capture| {
            (
                capture[1].to_string(),
                capture
                    .get(2)
                    .or_else(|| capture.get(3))
                    .map(|value| value.as_str().to_string())
                    .unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let mut stack = Vec::new();
    let mut candidates = Vec::new();
    for (offset, ch) in source.char_indices() {
        if ch == '{' {
            stack.push(offset);
        } else if ch == '}' {
            let Some(start) = stack.pop() else {
                continue;
            };
            let text = &source[start..offset + 1];
            let has_fields = fields.iter().all(|field| {
                Regex::new(&format!(r"\b{}\s*:", regex::escape(field)))
                    .is_ok_and(|regex| regex.is_match(text))
            });
            let has_bools = bools.iter().all(|(field, value)| {
                Regex::new(&format!(
                    r"\b{}\s*:\s*{}\b",
                    regex::escape(field),
                    regex::escape(value)
                ))
                .is_ok_and(|regex| regex.is_match(text))
            });
            let has_objects = object_fields.iter().all(|field| {
                Regex::new(&format!(r"\b{}\s*:\s*\{{", regex::escape(field)))
                    .is_ok_and(|regex| regex.is_match(text))
            });
            let has_strings = strings.iter().all(|(field, value)| {
                let value = if value == "..." || value.starts_with('$') {
                    r#"(?:"[^"\n]*"|'[^'\n]*')"#.to_string()
                } else {
                    let value = regex::escape(value);
                    format!(r#"(?:"{value}"|'{value}')"#)
                };
                Regex::new(&format!(r"\b{}\s*:\s*{}", regex::escape(field), value))
                    .is_ok_and(|regex| regex.is_match(text))
            });
            if has_fields && has_bools && has_objects && has_strings {
                candidates.push(Candidate {
                    start,
                    end: offset + 1,
                });
            }
        }
    }
    candidates
}

fn semantic_scope_candidates(pattern: &str, source: &str) -> Vec<Candidate> {
    let trimmed = pattern.trim();
    semantic_candidates(pattern, source)
        .into_iter()
        .map(|mut candidate| {
            if trimmed.starts_with("...") {
                candidate.start = 0;
            }
            if trimmed.ends_with("...") {
                candidate.end = source.len();
            }
            candidate
        })
        .collect()
}

fn translate_pattern(pattern: &str) -> String {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut out = String::from("(?s)");
    let mut index = 0;
    let mut nesting_depth = 0usize;
    while index < chars.len() {
        if chars[index].is_whitespace() {
            while index < chars.len() && chars[index].is_whitespace() {
                index += 1;
            }
            out.push_str(r"\s*");
            continue;
        }
        if chars[index..].starts_with(&['<', '.', '.', '.']) {
            out.push_str(if nesting_depth > 0 { r"[^;\n]*?" } else { ".*?" });
            index += 4;
            continue;
        }
        if chars[index..].starts_with(&['.', '.', '.', '>']) {
            out.push_str(if nesting_depth > 0 { r"[^;\n]*?" } else { ".*?" });
            if !chars[..index].windows(4).any(|window| window == ['<', '.', '.', '.']) {
                out.push('>');
            }
            index += 4;
            continue;
        }
        if chars[index..].starts_with(&['.', '.', '.']) {
            let mut next = index + 3;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if next < chars.len() && chars[next] == ',' {
                out.push_str(if nesting_depth > 0 {
                    r"(?:[^;\n]*?,\s*)?"
                } else {
                    r"(?:.*?,\s*)?"
                });
                index = next + 1;
                continue;
            }
        }
        if chars[index..].starts_with(&['.', '.', '.']) {
            out.push_str(if nesting_depth > 0 { r"[^;\n]*?" } else { ".*?" });
            index += 3;
            continue;
        }
        if chars[index] == ',' {
            let mut next = index + 1;
            while next < chars.len() && chars[next].is_whitespace() {
                next += 1;
            }
            if chars[next..].starts_with(&['.', '.', '.']) {
                out.push_str(if nesting_depth > 0 {
                    r"(?:\s*,[^;\n]*?)?"
                } else {
                    r"(?:\s*,.*?)?"
                });
                index = next + 3;
                continue;
            }
        }
        if chars[index] == '$' {
            index += 1;
            if chars[index..].starts_with(&['.', '.', '.']) {
                index += 3;
            }
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            out.push_str(r"(?:[^;\n<]+?)");
            continue;
        }
        if matches!(chars[index], '\'' | '"' | '`') {
            let quote = chars[index];
            let start = index;
            index += 1;
            while index < chars.len() {
                if chars[index] == '\\' {
                    index = (index + 2).min(chars.len());
                    continue;
                }
                if chars[index] == quote {
                    index += 1;
                    break;
                }
                index += 1;
            }
            let literal = chars[start..index].iter().collect::<String>();
            let body = literal
                .strip_prefix(quote)
                .and_then(|value| value.strip_suffix(quote))
                .unwrap_or_default();
            if quote == '`' && body.contains("${") {
                out.push_str(r"`[^`\n]*\$\{[^}\n]+\}[^`\n]*`");
            } else if body.starts_with("=~/") {
                let marker = if body.contains(":action") { ":action" } else { "" };
                let marker = regex::escape(marker);
                out.push_str(&format!(
                    r#"(?:"[^"\n]*{marker}[^"\n]*"|'[^'\n]*{marker}[^'\n]*')"#
                ));
            } else if quote == '`' && (body.contains("#{\"") || body.contains("#{'")) {
                out.push_str(
                    r#"(?:`[^`\n]*#\{\s*(?:"[^"\n]*"|'[^'\n]*')\s*\}[^`\n]*`|%x\{[^}\n]*#\{\s*(?:"[^"\n]*"|'[^'\n]*')\s*\}[^}\n]*\})"#,
                );
            } else if quote == '`' && body.contains("#{") {
                out.push_str(r"(?:`[^`\n]*#\{[^}\n]+\}[^`\n]*`|%x\{[^}\n]*#\{[^}\n]+\}[^}\n]*\})");
            } else if body.contains('$') {
                let variable = body.find('$').unwrap();
                let mut suffix_start = variable + 1;
                while suffix_start < body.len()
                    && body.as_bytes()[suffix_start].is_ascii_alphanumeric()
                        || suffix_start < body.len() && body.as_bytes()[suffix_start] == b'_'
                {
                    suffix_start += 1;
                }
                let prefix = regex::escape(&body[..variable].replace("...", ""));
                let suffix = regex::escape(&body[suffix_start..].replace("...", ""));
                if quote == '`' {
                    out.push_str(&format!(r"`{prefix}[^`\n]*{suffix}`"));
                } else {
                    out.push_str(&format!(
                        r#"(?:"{prefix}[^"\n]*{suffix}"|'{prefix}[^'\n]*{suffix}')"#
                    ));
                }
            } else if body.contains("...") {
                let (prefix, suffix) = body.split_once("...").unwrap();
                let prefix = regex::escape(prefix);
                let suffix = regex::escape(suffix);
                if quote == '`' {
                    out.push_str(&format!(r"`{prefix}[^`\n]*{suffix}`"));
                } else {
                    out.push_str(&format!(
                        r#"(?:"{prefix}[^"\n]*{suffix}"|'{prefix}[^'\n]*{suffix}')"#
                    ));
                }
            } else {
                let body = regex::escape(body);
                if quote == '`' {
                    out.push_str(&format!(r"`{body}`"));
                } else {
                    out.push_str(&format!(r#"(?:"{body}"|'{body}')"#));
                }
            }
            continue;
        }
        let ch = chars[index];
        if ch == '>' && pattern.trim_start().starts_with("<%") {
            out.push_str(r"%?>");
            index += 1;
            continue;
        }
        if ch == ';' {
            out.push_str(r";?\s*");
            index += 1;
            continue;
        }
        if ch == '}'
            && chars[..index]
                .iter()
                .rposition(|candidate| *candidate == '{')
                .is_some_and(|open| chars[open..index].contains(&':'))
        {
            out.push_str(r"(?:\s*,[^}]*?)?\s*\}");
            index += 1;
            continue;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            let start = index;
            index += 1;
            while index < chars.len()
                && (chars[index].is_ascii_alphanumeric() || chars[index] == '_')
            {
                index += 1;
            }
            let word = chars[start..index].iter().collect::<String>();
            if matches!(word.as_str(), "var" | "let" | "const") {
                out.push_str(r"\b(?:var|let|const)\b");
            } else {
                out.push_str(&format!(r"\b{}\b", regex::escape(&word)));
            }
            continue;
        }
        if matches!(ch, ')' | ']') {
            nesting_depth = nesting_depth.saturating_sub(1);
            out.push_str(r"\s*");
        } else if ch == '}' {
            out.push_str(r"\s*");
        }
        out.push_str(&regex::escape(&ch.to_string()));
        if matches!(ch, '(' | '[' | '{' | ',' | ':' | ';' | '=') {
            out.push_str(r"\s*");
        }
        if matches!(ch, '(' | '[') {
            nesting_depth += 1;
        }
        index += 1;
    }
    out
}

fn path_matches(rule: &Value, path: &str) -> bool {
    let Some(paths) = rule.get("paths") else {
        return true;
    };
    let included = paths
        .get("include")
        .and_then(Value::as_sequence)
        .map(|patterns| patterns.iter().filter_map(Value::as_str).any(|glob| glob_matches(glob, path)))
        .unwrap_or(true);
    let excluded = paths
        .get("exclude")
        .and_then(Value::as_sequence)
        .is_some_and(|patterns| patterns.iter().filter_map(Value::as_str).any(|glob| glob_matches(glob, path)));
    included && !excluded
}

fn glob_matches(glob: &str, path: &str) -> bool {
    let path = if glob.contains('/') {
        path
    } else {
        path.rsplit('/').next().unwrap_or(path)
    };
    let mut regex = String::from("^");
    let chars = glob.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() {
        if chars[index..].starts_with(&['*', '*']) {
            regex.push_str(".*");
            index += 2;
        } else if chars[index] == '*' {
            regex.push_str("[^/]*");
            index += 1;
        } else {
            regex.push_str(&regex::escape(&chars[index].to_string()));
            index += 1;
        }
    }
    regex.push('$');
    Regex::new(&regex).is_ok_and(|regex| regex.is_match(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_metavariables_ellipsis_negatives_and_paths() {
        let rule = r#"
paths: { include: ['**/*.js'] }
patterns:
- pattern: $PAGE.goto($INPUT,...)
- pattern-not: $PAGE.goto("...",...)
"#;
        assert_eq!(
            matching_offsets(
                rule,
                "src/browser.js",
                "page.goto('fixed');\npage.goto(userInput);\n"
            )
            .len(),
            1
        );
        assert!(matching_offsets(rule, "src/browser.rb", "page.goto(userInput)").is_empty());
    }

    #[test]
    fn matches_template_expression_inside_a_script_source_attribute() {
        let rule = r#"
paths: { include: ['*.ejs', '*.html'] }
patterns:
- pattern-inside: <script ...>
- pattern: <% ... >
"#;
        let source = r#"<script src="./<%= bundle %>" crossorigin="anonymous"></script>"#;
        assert!(Regex::new(&translate_pattern("<script ...>"))
            .unwrap()
            .is_match(source));
        assert!(Regex::new(&translate_pattern("<% ... >"))
            .unwrap()
            .is_match(source));
        let parsed: Value = serde_yaml::from_str(rule).unwrap();
        assert!(path_matches(&parsed, "views/index.ejs"));
        let candidates = semantic_candidates("<% ... >", source);
        let scopes = semantic_scope_candidates("<script ...>", source);
        assert!(!candidates.is_empty());
        assert!(!scopes.is_empty());
        assert!(scopes
            .iter()
            .any(|scope| scope.start <= candidates[0].start && scope.end >= candidates[0].end),
            "candidates={candidates:?} scopes={scopes:?} candidate_regex={} scope_regex={}",
            translate_pattern("<% ... >"),
            translate_pattern("<script ...>")
        );
        assert!(!evaluate(&parsed, source).is_empty());
        assert_eq!(
            matching_offsets(
                rule,
                "views/index.ejs",
                source,
            )
            .len(),
            1
        );
    }

    #[test]
    fn matches_nested_call_with_a_hardcoded_object_field() {
        let pattern = r#"$JWT({...,secret: "$Y",...},...)"#;
        let source = "app.get('/protected', jwt({ secret: 'shared-secret' }), handler);";
        assert!(
            !semantic_candidates(pattern, source).is_empty(),
            "{}",
            translate_pattern(pattern)
        );
    }

    #[test]
    fn treats_literal_quote_styles_as_equivalent() {
        let pattern = r#"JWT.verify($P, "...", ...);"#;
        let source = "JWT.verify(payload, 'shared-secret')";
        assert!(
            !semantic_candidates(pattern, source).is_empty(),
            "{}",
            translate_pattern(pattern)
        );
    }

    #[test]
    fn matches_variadic_options_object() {
        let pattern = "spawn(...,{shell: $SHELL})";
        let source = "const child = spawn('ls', ['-lh'], {shell:true});";
        assert!(
            !semantic_candidates(pattern, source).is_empty(),
            "{}",
            translate_pattern(pattern)
        );
    }

    #[test]
    fn matches_partial_multiline_object_with_dynamic_template_value() {
        let pattern = "{value: $VAL, supportHtml: true}";
        let source = r#"{
            value: `<a href="${userInput}">Hello</a>`,
            supportHtml: true,
            isTrusted: true
        }"#;
        assert!(
            !semantic_candidates(pattern, source).is_empty(),
            "{}",
            translate_pattern(pattern)
        );
    }

    #[test]
    fn dynamic_monaco_hover_is_not_treated_as_a_constant_string() {
        let rule = r#"
patterns:
- pattern-either:
  - pattern: '{value: $VAL, supportHtml: true}'
  - pattern: '{value: $VAL, isTrusted: true}'
- pattern-inside: '{range: $R, contents: [...]}'
- pattern-not: '{..., value: "...", ...}'
"#;
        let source = r#"return {
          range: selected,
          contents: [{
            value: `<a href="${userInput}">Hello</a>`,
            supportHtml: true,
            isTrusted: true
          }]
        }"#;
        assert!(!evaluate(&serde_yaml::from_str(rule).unwrap(), source).is_empty());
    }

    #[test]
    fn ruby_shell_templates_match_backticks_and_percent_x() {
        let pattern = r#"`...#{$VAL}...`"#;
        assert_eq!(
            semantic_candidates(pattern, "`echo #{user_input}`").len(),
            1
        );
        assert_eq!(
            semantic_candidates(pattern, "%x{echo #{user_input}}").len(),
            1
        );
        assert!(semantic_candidates(pattern, "`echo fixed`").is_empty());
    }

    #[test]
    fn ruby_shell_template_negatives_keep_dynamic_interpolation() {
        let rule = r#"
patterns:
- pattern: '`...#{$VAL}...`'
- pattern-not: '`...#{"..."}...`'
- pattern-not-inside: |
    $VAL = "..."
    ...
"#;
        let parsed: Value = serde_yaml::from_str(rule).unwrap();
        let source = "def run(user_input)\n  result = `echo #{user_input}`\nend\n";
        assert!(
            !evaluate(&parsed, source).is_empty(),
            "positive={:?} negative={:?}",
            semantic_candidates(r#"`...#{$VAL}...`"#, source),
            semantic_candidates(r#"`...#{"..."}...`"#, source)
        );
    }

    #[test]
    fn ruby_class_scope_contains_symbol_render() {
        let rule = r#"
patterns:
- pattern-inside: |
    class $CONTROLLER < $BIGCONTROLLER
    ...
    end
- pattern: 'render :$TEXT'
"#;
        let source = "class Text < ApplicationController\n  render :hello\nend\n";
        let parsed: Value = serde_yaml::from_str(rule).unwrap();
        assert!(
            !evaluate(&parsed, source).is_empty(),
            "render={:?} scope={:?}",
            semantic_candidates("render :$TEXT", source),
            semantic_scope_candidates(
                "class $CONTROLLER < $BIGCONTROLLER\n...\nend\n",
                source
            )
        );
    }

    #[test]
    fn erb_scope_contains_html_safe_call() {
        let rule = r#"
paths: { include: ['*.erb'] }
patterns:
- pattern-inside: '<%= ... %>'
- pattern: $SOMETHING.html_safe
"#;
        let source = "<h1><%= @custom_page_title.html_safe %></h1>";
        let parsed: Value = serde_yaml::from_str(rule).unwrap();
        assert!(
            !evaluate(&parsed, source).is_empty(),
            "call={:?} scope={:?}",
            semantic_candidates("$SOMETHING.html_safe", source),
            semantic_scope_candidates("<%= ... %>", source)
        );
    }

    #[test]
    fn playwright_evaluate_tracks_a_function_argument() {
        let rule = r#"
patterns:
- pattern-inside: |
    require('playwright');
    ...
- pattern-either:
  - pattern-inside: function $FUNC (...,$INPUT,...) {...}
  - pattern-inside: function (...,$INPUT,...) {...}
- pattern-either:
  - pattern: $PAGE.evaluate($CODE,...,<... $INPUT ...>,...)
  - pattern: $PAGE.evaluateHandle($CODE,...,<... $INPUT ...>,...)
"#;
        let source = "const p = require('playwright');\nasync function test(userInput) {\n page.evaluate(x => fetch(x), userInput);\n}\n";
        let parsed: Value = serde_yaml::from_str(rule).unwrap();
        assert!(
            !evaluate(&parsed, source).is_empty(),
            "sink={:?} require={:?} regex={}",
            semantic_candidates("$PAGE.evaluate($CODE,...,<... $INPUT ...>,...)", source),
            semantic_scope_candidates("require('playwright');\n...\n", source),
            translate_pattern("$PAGE.evaluate($CODE,...,<... $INPUT ...>,...)")
        );
    }
}
