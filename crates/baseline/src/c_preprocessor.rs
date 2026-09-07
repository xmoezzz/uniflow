use serde::{Deserialize, Serialize};
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
}

struct Definition {
    offset: usize,
    name: String,
    function_like: bool,
    replacement: Range<usize>,
}

/// Translation-phase line splicing precedes comment recognition. Offsets refer
/// back to the original file, not the spliced buffer used to recognize macros.
pub(crate) struct CPreprocessor {
    spliced: String,
    definitions: Vec<Definition>,
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
        let mut definitions = Vec::new();
        let mut start = 0;
        for line in code.split_inclusive('\n') {
            if let Some(capture) = header.captures(line) {
                let name = capture.get(1).unwrap();
                let end = start + line.trim_end_matches(['\r', '\n']).len();
                let mut replacement = start + name.end();
                let function_like = spliced.as_bytes().get(replacement) == Some(&b'(');
                if function_like {
                    // A macro parameter list contains identifiers/ellipsis, not
                    // nested expression parentheses. Comments have been masked.
                    let Some(close) = comments[replacement + 1..end].find(')') else {
                        start += line.len();
                        continue;
                    };
                    replacement += close + 2;
                }
                while replacement < end && spliced.as_bytes()[replacement].is_ascii_whitespace() {
                    replacement += 1;
                }
                if replacement < end {
                    let hash = line.find('#').unwrap();
                    definitions.push(Definition {
                        offset: original[start + hash],
                        name: name.as_str().to_string(),
                        function_like,
                        replacement: replacement..end,
                    });
                }
            }
            start += line.len();
        }
        Self {
            spliced,
            definitions,
        }
    }

    pub(crate) fn offsets(&self, check: CMacroCheck) -> Vec<usize> {
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
}
