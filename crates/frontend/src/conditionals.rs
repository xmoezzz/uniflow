use crate::FrontendOptions;
use std::borrow::Cow;
use std::collections::BTreeMap;
use uniflow_hir::Language;
use uniflow_platform::{PlatformProfile, TruthValue};

pub(crate) fn prepare_source<'a>(
    language: &Language,
    source: &'a str,
    options: &FrontendOptions,
) -> Cow<'a, str> {
    if matches!(language, Language::C | Language::Cpp) {
        let mut profile = options.platform.clone();
        for (name, value) in &options.defines {
            profile.defines.insert(name.clone(), value.clone());
        }
        for name in &options.undefines {
            profile.defines.remove(name);
        }
        if let Some(target) = options.target_triple.as_deref() {
            apply_target_triple_defines(&mut profile, target);
        }
        if let Some(standard) = options.language_standard.as_deref() {
            if matches!(language, Language::Cpp) {
                if let Some(value) = cpp_standard_value(standard) {
                    profile.defines.insert("__cplusplus".to_string(), Some(value.to_string()));
                }
            } else if let Some(value) = c_standard_value(standard) {
                profile.defines.insert("__STDC_VERSION__".to_string(), Some(value.to_string()));
            }
        }
        Cow::Owned(simulate_c_family_conditionals(source, &profile))
    } else {
        Cow::Borrowed(source)
    }
}

fn apply_target_triple_defines(profile: &mut PlatformProfile, target: &str) {
    let target = target.to_ascii_lowercase();
    let mut define = |name: &str| {
        profile.defines.insert(name.to_string(), None);
    };
    if target.contains("windows") || target.contains("msvc") || target.contains("mingw") {
        define("_WIN32");
        if target.contains("x86_64") || target.contains("amd64") {
            define("_WIN64");
            define("_M_X64");
        }
    }
    if target.contains("linux") {
        define("__linux__");
        define("__unix__");
    }
    if target.contains("darwin") || target.contains("apple") || target.contains("macos") {
        define("__APPLE__");
        define("__MACH__");
    }
    if target.contains("x86_64") || target.contains("amd64") {
        define("__x86_64__");
        define("__amd64__");
    }
    if target.contains("aarch64") || target.contains("arm64") {
        define("__aarch64__");
        define("__arm64__");
    }
}

fn cpp_standard_value(standard: &str) -> Option<&'static str> {
    let standard = standard.to_ascii_lowercase();
    if standard.contains("98") || standard.contains("03") {
        Some("199711L")
    } else if standard.contains("11") {
        Some("201103L")
    } else if standard.contains("14") {
        Some("201402L")
    } else if standard.contains("17") {
        Some("201703L")
    } else if standard.contains("20") {
        Some("202002L")
    } else if standard.contains("23") || standard.contains("latest") {
        Some("202302L")
    } else {
        None
    }
}

fn c_standard_value(standard: &str) -> Option<&'static str> {
    let standard = standard.to_ascii_lowercase();
    if standard.contains("90") || standard.contains("89") {
        None
    } else if standard.contains("99") {
        Some("199901L")
    } else if standard.contains("11") {
        Some("201112L")
    } else if standard.contains("17") || standard.contains("18") {
        Some("201710L")
    } else if standard.contains("23") || standard.contains("2x") {
        Some("202311L")
    } else {
        None
    }
}

/// Conservatively evaluates common C/C++ conditional-compilation directives.
///
/// This is not a preprocessor. It preserves line and byte positions, keeps all
/// branches whose conditions may hold under an open-world profile, and removes
/// only branches known to be impossible for the selected platform profile.
pub fn simulate_c_family_conditionals(source: &str, profile: &PlatformProfile) -> String {
    let mut macros = MacroState::from_profile(profile);
    let mut stack = Vec::<ConditionalFrame>::new();
    let mut out = String::with_capacity(source.len());

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let directive = trimmed.strip_prefix('#').map(str::trim_start);
        let possible = stack.last().map_or(true, |frame| frame.current_possible);
        let definite = stack.last().map_or(true, |frame| frame.current_definite);

        let Some(directive) = directive else {
            if possible {
                out.push_str(line);
            } else {
                out.push_str(&blank_preserving_layout(line));
            }
            continue;
        };

        let (keyword, rest) = split_directive(directive);
        match keyword {
            "if" => {
                let condition = eval_cpp_condition(rest, &macros);
                stack.push(ConditionalFrame::new(possible, definite, condition));
                out.push_str(&blank_preserving_layout(line));
            }
            "ifdef" => {
                stack.push(ConditionalFrame::new(
                    possible,
                    definite,
                    macros.truth(rest.trim()),
                ));
                out.push_str(&blank_preserving_layout(line));
            }
            "ifndef" => {
                stack.push(ConditionalFrame::new(
                    possible,
                    definite,
                    macros.truth(rest.trim()).not(),
                ));
                out.push_str(&blank_preserving_layout(line));
            }
            "elif" => {
                if let Some(frame) = stack.last_mut() {
                    frame.select_elif(eval_cpp_condition(rest, &macros));
                }
                out.push_str(&blank_preserving_layout(line));
            }
            "else" => {
                if let Some(frame) = stack.last_mut() {
                    frame.select_else();
                }
                out.push_str(&blank_preserving_layout(line));
            }
            "endif" => {
                stack.pop();
                out.push_str(&blank_preserving_layout(line));
            }
            "define" => {
                if possible {
                    let name = rest
                        .split(|ch: char| ch.is_whitespace() || ch == '(')
                        .next()
                        .unwrap_or_default();
                    if !name.is_empty() {
                        macros.update(name, TruthValue::True, definite);
                    }
                    out.push_str(line);
                } else {
                    out.push_str(&blank_preserving_layout(line));
                }
            }
            "undef" => {
                if possible {
                    let name = rest.split_whitespace().next().unwrap_or_default();
                    if !name.is_empty() {
                        macros.update(name, TruthValue::False, definite);
                    }
                    out.push_str(line);
                } else {
                    out.push_str(&blank_preserving_layout(line));
                }
            }
            _ => {
                if possible {
                    out.push_str(line);
                } else {
                    out.push_str(&blank_preserving_layout(line));
                }
            }
        }
    }

    out
}

#[derive(Clone, Copy, Debug)]
struct ConditionalFrame {
    parent_possible: bool,
    parent_definite: bool,
    prior_may_take: bool,
    prior_definitely_takes: bool,
    current_possible: bool,
    current_definite: bool,
}

impl ConditionalFrame {
    fn new(parent_possible: bool, parent_definite: bool, condition: TruthValue) -> Self {
        Self {
            parent_possible,
            parent_definite,
            prior_may_take: condition.may_be_true(),
            prior_definitely_takes: condition.is_definitely_true(),
            current_possible: parent_possible && condition.may_be_true(),
            current_definite: parent_definite && condition.is_definitely_true(),
        }
    }

    fn select_elif(&mut self, condition: TruthValue) {
        let available_possible = self.parent_possible && !self.prior_definitely_takes;
        let available_definite = self.parent_definite && !self.prior_may_take;
        self.current_possible = available_possible && condition.may_be_true();
        self.current_definite = available_definite && condition.is_definitely_true();
        self.prior_may_take |= condition.may_be_true();
        self.prior_definitely_takes |= condition.is_definitely_true();
    }

    fn select_else(&mut self) {
        self.current_possible = self.parent_possible && !self.prior_definitely_takes;
        self.current_definite = self.parent_definite && !self.prior_may_take;
        self.prior_may_take = true;
        self.prior_definitely_takes = true;
    }
}

#[derive(Clone, Debug)]
struct MacroState {
    values: BTreeMap<String, TruthValue>,
    closed_world: bool,
}

impl MacroState {
    fn from_profile(profile: &PlatformProfile) -> Self {
        Self {
            values: profile
                .defines
                .keys()
                .map(|name| (name.clone(), TruthValue::True))
                .collect(),
            closed_world: profile.closed_world,
        }
    }

    fn truth(&self, name: &str) -> TruthValue {
        self.values.get(name).copied().unwrap_or_else(|| {
            if self.closed_world {
                TruthValue::False
            } else {
                TruthValue::Unknown
            }
        })
    }

    fn update(&mut self, name: &str, value: TruthValue, definite: bool) {
        self.values.insert(
            name.to_string(),
            if definite { value } else { TruthValue::Unknown },
        );
    }
}

fn eval_cpp_condition(input: &str, macros: &MacroState) -> TruthValue {
    let input = strip_balanced_outer_parens(input.trim());
    if input.is_empty() {
        return TruthValue::Unknown;
    }

    if let Some(parts) = split_top_level_operator(input, "||") {
        return parts.into_iter().fold(TruthValue::False, |state, part| {
            state.or(eval_cpp_condition(part, macros))
        });
    }
    if let Some(parts) = split_top_level_operator(input, "&&") {
        return parts.into_iter().fold(TruthValue::True, |state, part| {
            state.and(eval_cpp_condition(part, macros))
        });
    }
    if let Some(rest) = input.strip_prefix('!') {
        return eval_cpp_condition(rest, macros).not();
    }
    if let Some(name) = parse_defined_name(input) {
        return macros.truth(name);
    }
    if let Ok(value) = input.parse::<i64>() {
        return if value == 0 {
            TruthValue::False
        } else {
            TruthValue::True
        };
    }
    if is_macro_identifier(input) {
        return macros.truth(input);
    }
    TruthValue::Unknown
}

fn parse_defined_name(input: &str) -> Option<&str> {
    let rest = input.strip_prefix("defined")?.trim_start();
    if let Some(inner) = rest
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
    {
        let name = inner.trim();
        return is_macro_identifier(name).then_some(name);
    }
    let name = rest.split_whitespace().next()?;
    is_macro_identifier(name).then_some(name)
}

fn is_macro_identifier(input: &str) -> bool {
    let mut chars = input.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn strip_balanced_outer_parens(mut input: &str) -> &str {
    loop {
        let trimmed = input.trim();
        if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
            return trimmed;
        }
        let mut depth = 0usize;
        let mut encloses_all = true;
        for (index, ch) in trimmed.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    if depth == 0 {
                        return trimmed;
                    }
                    depth -= 1;
                    if depth == 0 && index + ch.len_utf8() != trimmed.len() {
                        encloses_all = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !encloses_all || depth != 0 {
            return trimmed;
        }
        input = &trimmed[1..trimmed.len() - 1];
    }
}

fn split_top_level_operator<'a>(input: &'a str, operator: &str) -> Option<Vec<&'a str>> {
    let bytes = input.as_bytes();
    let op = operator.as_bytes();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    let mut index = 0usize;
    while index + op.len() <= bytes.len() {
        match bytes[index] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && &bytes[index..index + op.len()] == op {
            parts.push(input[start..index].trim());
            index += op.len();
            start = index;
            continue;
        }
        index += 1;
    }
    if parts.is_empty() {
        None
    } else {
        parts.push(input[start..].trim());
        Some(parts)
    }
}

fn split_directive(input: &str) -> (&str, &str) {
    let end = input
        .char_indices()
        .find_map(|(index, ch)| ch.is_whitespace().then_some(index))
        .unwrap_or(input.len());
    (&input[..end], input[end..].trim_start())
}

fn blank_preserving_layout(line: &str) -> String {
    let bytes = line
        .as_bytes()
        .iter()
        .map(|&byte| match byte {
            b'\n' | b'\r' | b'\t' => byte,
            _ => b' ',
        })
        .collect::<Vec<_>>();
    String::from_utf8(bytes).expect("layout-preserving blank text is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_windows_branch_for_closed_world_profile() {
        let source = "#ifdef _WIN32\nwin();\n#else\nunix();\n#endif\n";
        let output =
            simulate_c_family_conditionals(source, &PlatformProfile::windows_x86_64_msvc());
        assert!(output.contains("win();"));
        assert!(!output.contains("unix();"));
        assert_eq!(output.len(), source.len());
        assert_eq!(output.lines().count(), source.lines().count());
    }

    #[test]
    fn keeps_both_unknown_branches_for_generic_profile() {
        let source = "#ifdef PROJECT_OS\na();\n#else\nb();\n#endif\n";
        let output = simulate_c_family_conditionals(source, &PlatformProfile::generic());
        assert!(output.contains("a();"));
        assert!(output.contains("b();"));
    }

    #[test]
    fn evaluates_defined_boolean_expressions() {
        let source = "#if defined(__linux__) && !defined(_WIN32)\nlinux();\n#endif\n";
        let output = simulate_c_family_conditionals(source, &PlatformProfile::linux_x86_64_gnu());
        assert!(output.contains("linux();"));
    }

    #[test]
    fn handles_nested_and_elif_conditions_conservatively() {
        let source = "#if defined(_WIN32)\n#if defined(_WIN64)\nwin64();\n#endif\n#elif defined(__linux__)\nlinux();\n#else\nother();\n#endif\n";
        let output = simulate_c_family_conditionals(source, &PlatformProfile::linux_x86_64_gnu());
        assert!(!output.contains("win64();"));
        assert!(output.contains("linux();"));
        assert!(!output.contains("other();"));
        assert_eq!(output.len(), source.len());
    }
}
