use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::Range;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CMacroCheck {
    FunctionReplacementParentheses,
    RedefinedKeyword,
    HashInFunctionReplacement,
    RepeatedHashInFunctionReplacement,
    BasicTypeReplacement,
    TrailingSemicolon,
    UnparenthesizedParameterUse,
    SemicolonBodyWrapper,
    StatementKeyword,
    RedefinedMacro,
    TypeOnlyReplacement,
    IncludeUnsafeCharacters,
    IncludeAbsolutePath,
    SingleKeywordReplacement,
    KeywordNameToKeywordReplacement,
}

struct Definition {
    offset: usize,
    name_offset: usize,
    name: String,
    function_like: bool,
    parameters: Vec<String>,
    replacement: Range<usize>,
}

struct IncludeDirective {
    offset: usize,
    file_name: String,
}

/// Translation-phase line splicing precedes comment recognition. Offsets refer
/// back to the original file, not the spliced buffer used to recognize macros.
pub(crate) struct CPreprocessor {
    spliced: String,
    code: String,
    original: Vec<usize>,
    definitions: Vec<Definition>,
    redefinitions: Vec<usize>,
    includes: Vec<IncludeDirective>,
}

impl CPreprocessor {
    pub(crate) fn parse(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut spliced = Vec::with_capacity(bytes.len());
        let mut original = Vec::with_capacity(bytes.len() + 1);
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at..].starts_with(b"\\\n") {
                at += 2;
                continue;
            }
            if bytes[at..].starts_with(b"\\\r\n") {
                at += 3;
                continue;
            }
            original.push(at);
            spliced.push(bytes[at]);
            at += 1;
        }
        original.push(source.len());
        let spliced = String::from_utf8(spliced).expect("splicing removes only ASCII bytes");
        let comments = super::strip_comments_preserve_layout(&uniflow_hir::Language::C, &spliced);
        let code = super::strip_literals_preserve_layout(&comments);
        let header =
            regex::Regex::new(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z_0-9]*)").unwrap();
        let undef =
            regex::Regex::new(r"^[ \t]*#[ \t]*undef[ \t]+([A-Za-z_][A-Za-z_0-9]*)").unwrap();
        let include = regex::Regex::new(
            r#"^[ \t]*#[ \t]*include[ \t]+(?:<([^>\r\n]+)>|"([^"\r\n]+)")"#,
        )
        .unwrap();
        let mut definitions = Vec::new();
        let mut defined = HashSet::new();
        let mut redefinitions = Vec::new();
        let mut includes = Vec::new();
        let mut start = 0;
        for line in code.split_inclusive('\n') {
            let comment_line = &comments[start..start + line.len()];
            if let Some(capture) = include.captures(comment_line) {
                let file_name = capture.get(1).or_else(|| capture.get(2)).unwrap();
                let delimiter = file_name.start().saturating_sub(1);
                includes.push(IncludeDirective {
                    offset: original[start + delimiter],
                    file_name: file_name.as_str().to_string(),
                });
            }
            if let Some(capture) = header.captures(line) {
                let name = capture.get(1).unwrap();
                if !defined.insert(name.as_str().to_string()) {
                    redefinitions.push(original[start + name.start()]);
                }
                let end = start + line.trim_end_matches(['\r', '\n']).len();
                let mut replacement = start + name.end();
                let function_like = spliced.as_bytes().get(replacement) == Some(&b'(');
                let mut parameters = Vec::new();
                if function_like {
                    // A macro parameter list contains identifiers/ellipsis, not
                    // nested expression parentheses. Comments have been masked.
                    let Some(close) = comments[replacement + 1..end].find(')') else {
                        start += line.len();
                        continue;
                    };
                    let parameter_end = replacement + close + 1;
                    parameters.extend(
                        code[replacement + 1..parameter_end]
                            .split(',')
                            .map(str::trim)
                            .filter(|parameter| {
                                !parameter.is_empty()
                                    && parameter
                                        .bytes()
                                        .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
                                    && parameter
                                        .as_bytes()
                                        .first()
                                        .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
                            })
                            .map(str::to_string),
                    );
                    replacement += close + 2;
                }
                while replacement < end && spliced.as_bytes()[replacement].is_ascii_whitespace() {
                    replacement += 1;
                }
                if replacement < end {
                    let hash = line.find('#').unwrap();
                    definitions.push(Definition {
                        offset: original[start + hash],
                        name_offset: original[start + name.start()],
                        name: name.as_str().to_string(),
                        function_like,
                        parameters,
                        replacement: replacement..end,
                    });
                }
            } else if let Some(capture) = undef.captures(line) {
                defined.remove(capture.get(1).unwrap().as_str());
            }
            start += line.len();
        }
        Self {
            spliced,
            code,
            original,
            definitions,
            redefinitions,
            includes,
        }
    }

    pub(crate) fn offsets(&self, check: CMacroCheck) -> Vec<usize> {
        if matches!(check, CMacroCheck::UnparenthesizedParameterUse) {
            return self.unparenthesized_parameter_offsets();
        }
        if matches!(check, CMacroCheck::SemicolonBodyWrapper) {
            return self.semicolon_body_wrapper_offsets();
        }
        if matches!(check, CMacroCheck::StatementKeyword) {
            return self.statement_keyword_offsets();
        }
        if matches!(check, CMacroCheck::RedefinedMacro) {
            return self.redefinitions.clone();
        }
        if matches!(check, CMacroCheck::TypeOnlyReplacement) {
            return self.type_only_replacement_offsets();
        }
        if matches!(check, CMacroCheck::IncludeUnsafeCharacters) {
            return self
                .includes
                .iter()
                .filter(|include| {
                    include.file_name.contains('\'') || include.file_name.contains('*')
                })
                .map(|include| include.offset)
                .collect();
        }
        if matches!(check, CMacroCheck::IncludeAbsolutePath) {
            return self
                .includes
                .iter()
                .filter(|include| {
                    let bytes = include.file_name.as_bytes();
                    bytes.first() == Some(&b'/') || bytes.get(1) == Some(&b':')
                })
                .map(|include| include.offset)
                .collect();
        }
        if matches!(
            check,
            CMacroCheck::SingleKeywordReplacement | CMacroCheck::KeywordNameToKeywordReplacement
        ) {
            return self
                .definitions
                .iter()
                .filter(|definition| {
                    single_c_or_cpp_keyword(
                        self.code[definition.replacement.clone()].trim(),
                    ) && (!matches!(check, CMacroCheck::KeywordNameToKeywordReplacement)
                        || is_c_or_cpp_keyword(&definition.name))
                })
                .map(|definition| definition.name_offset)
                .collect();
        }
        // These are the legacy preproc_arg predicates, not tokenized operator
        // counts: a literal '#' is deliberately visible, and ## alone does not
        // satisfy the repeated-hash predicate. Function macros include F().
        let pattern = match check {
            CMacroCheck::FunctionReplacementParentheses => "^[^(].*[^)]$",
            CMacroCheck::RedefinedKeyword => {
                "^(bool|char|short|int|long|void|for|if|while|switch)$"
            }
            CMacroCheck::HashInFunctionReplacement => "#",
            CMacroCheck::RepeatedHashInFunctionReplacement => "#[^#].*#",
            CMacroCheck::BasicTypeReplacement => {
                "^(char|short|int|long|unsigned int|unsigned long)$"
            }
            CMacroCheck::TrailingSemicolon => ";$",
            CMacroCheck::UnparenthesizedParameterUse => unreachable!(),
            CMacroCheck::SemicolonBodyWrapper => unreachable!(),
            CMacroCheck::StatementKeyword => unreachable!(),
            CMacroCheck::RedefinedMacro => unreachable!(),
            CMacroCheck::TypeOnlyReplacement => unreachable!(),
            CMacroCheck::IncludeUnsafeCharacters => unreachable!(),
            CMacroCheck::IncludeAbsolutePath => unreachable!(),
            CMacroCheck::SingleKeywordReplacement => unreachable!(),
            CMacroCheck::KeywordNameToKeywordReplacement => unreachable!(),
        };
        let regex = regex::Regex::new(pattern).unwrap();
        self.definitions
            .iter()
            .filter_map(|definition| {
                let function_required = matches!(
                    check,
                    CMacroCheck::FunctionReplacementParentheses
                        | CMacroCheck::HashInFunctionReplacement
                        | CMacroCheck::RepeatedHashInFunctionReplacement
                );
                let object_required = matches!(
                    check,
                    CMacroCheck::RedefinedKeyword | CMacroCheck::BasicTypeReplacement
                );
                if function_required && !definition.function_like
                    || object_required && definition.function_like
                {
                    return None;
                }
                let text = if matches!(check, CMacroCheck::RedefinedKeyword) {
                    definition.name.as_str()
                } else {
                    self.spliced[definition.replacement.clone()].trim_end()
                };
                regex.is_match(text).then_some(definition.offset)
            })
            .collect()
    }

    fn unparenthesized_parameter_offsets(&self) -> Vec<usize> {
        self.definitions
            .iter()
            .filter(|definition| definition.function_like && !definition.parameters.is_empty())
            .filter_map(|definition| {
                let bytes = self.code.as_bytes();
                let mut at = definition.replacement.start;
                while at < definition.replacement.end {
                    if bytes[at] != b'_' && !bytes[at].is_ascii_alphabetic() {
                        at += 1;
                        continue;
                    }
                    let start = at;
                    at += 1;
                    while at < definition.replacement.end
                        && (bytes[at] == b'_' || bytes[at].is_ascii_alphanumeric())
                    {
                        at += 1;
                    }
                    if !definition
                        .parameters
                        .iter()
                        .any(|parameter| parameter == &self.code[start..at])
                    {
                        continue;
                    }
                    let previous = self.code[definition.replacement.start..start]
                        .bytes()
                        .rev()
                        .find(|byte| !byte.is_ascii_whitespace());
                    let next = self.code[at..definition.replacement.end]
                        .bytes()
                        .find(|byte| !byte.is_ascii_whitespace());
                    let stringified_or_pasted = previous == Some(b'#') || next == Some(b'#');
                    let parenthesized = previous == Some(b'(') && next == Some(b')');
                    if !stringified_or_pasted && !parenthesized {
                        return self.original.get(start).copied().or(Some(definition.offset));
                    }
                }
                None
            })
            .collect()
    }

    fn semicolon_body_wrapper_offsets(&self) -> Vec<usize> {
        self.definitions
            .iter()
            .filter(|definition| definition.function_like && !definition.parameters.is_empty())
            .filter_map(|definition| {
                let mut body = self.code[definition.replacement.clone()].trim();
                if !body.contains(';') {
                    return None;
                }
                body = body.strip_suffix(';').map(str::trim_end).unwrap_or(body);
                let wrapped = body.starts_with('(') && body.ends_with(')')
                    || body.starts_with('{') && body.ends_with('}');
                (!wrapped).then_some(definition.name_offset)
            })
            .collect()
    }

    fn statement_keyword_offsets(&self) -> Vec<usize> {
        const KEYWORDS: &[&str] = &["switch", "case", "if", "else", "for", "while", "goto"];
        self.definitions
            .iter()
            .filter_map(|definition| {
                let bytes = self.code.as_bytes();
                let mut at = definition.replacement.start;
                while at < definition.replacement.end {
                    if bytes[at] != b'_' && !bytes[at].is_ascii_alphabetic() {
                        at += 1;
                        continue;
                    }
                    let start = at;
                    at += 1;
                    while at < definition.replacement.end
                        && (bytes[at] == b'_' || bytes[at].is_ascii_alphanumeric())
                    {
                        at += 1;
                    }
                    if KEYWORDS.contains(&&self.code[start..at]) {
                        return self.original.get(start).copied();
                    }
                }
                None
            })
            .collect()
    }

    fn type_only_replacement_offsets(&self) -> Vec<usize> {
        const TYPE_TOKENS: &[&str] = &[
            "void", "bool", "char", "wchar_t", "char16_t", "char32_t", "short", "int",
            "long", "float", "double", "signed", "unsigned", "mutable", "volatile",
            "static", "register",
        ];
        self.definitions
            .iter()
            .filter_map(|definition| {
                let bytes = self.code.as_bytes();
                let mut at = definition.replacement.start;
                let mut found = false;
                while at < definition.replacement.end {
                    if bytes[at].is_ascii_whitespace() {
                        at += 1;
                        continue;
                    }
                    found = true;
                    if matches!(bytes[at], b'*' | b'(' | b')') {
                        at += 1;
                        continue;
                    }
                    if bytes[at] != b'_' && !bytes[at].is_ascii_alphabetic() {
                        return None;
                    }
                    let start = at;
                    at += 1;
                    while at < definition.replacement.end
                        && (bytes[at] == b'_' || bytes[at].is_ascii_alphanumeric())
                    {
                        at += 1;
                    }
                    if !TYPE_TOKENS.contains(&&self.code[start..at]) {
                        return None;
                    }
                }
                found.then_some(definition.name_offset)
            })
            .collect()
    }
}

const C_AND_CPP_KEYWORDS: &[&str] = &[
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "alignas",
    "alignof", "and", "and_eq", "asm", "bitand", "bitor", "bool", "catch", "class",
    "compl", "constexpr", "const_cast", "delete", "dynamic_cast", "explicit", "export",
    "false", "friend", "mutable", "namespace", "new", "not", "not_eq", "nullptr",
    "operator", "or", "or_eq", "private", "protected", "public", "reinterpret_cast",
    "static_assert", "static_cast", "template", "this", "thread_local", "throw", "true",
    "try", "typeid", "typename", "using", "virtual", "wchar_t", "xor", "xor_eq",
];

fn is_c_or_cpp_keyword(text: &str) -> bool {
    C_AND_CPP_KEYWORDS.contains(&text)
}

fn single_c_or_cpp_keyword(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        && is_c_or_cpp_keyword(text)
}
