// Token boundaries, rather than character searches, keep operators and brackets
// inside comments, string literals and text blocks out of expression structure.
fn java_expression_tokens(text: &str) -> Vec<uniflow_parser_core::Token> {
    use uniflow_parser_core::{Lexer, LexerSpec, TokKind};
    Lexer::new(text, &LexerSpec { triple_quotes: vec!["\"\"\""], ..Default::default() })
        .tokenize().into_iter().filter(|token| token.kind != TokKind::Eof).collect()
}

fn split_java_conditional(text: &str) -> Option<(&str, &str, &str)> {
    let mut question = None;
    let mut depth = 0;
    for token in java_top_level_tokens(text) {
        if token.kind != uniflow_parser_core::TokKind::Symbol { continue; }
        match token.text.as_str() {
            "?" => { question.get_or_insert(token.start as usize); depth += 1; }
            ":" if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    let question = question?;
                    let parts = (text[..question].trim(), text[question + 1..token.start as usize].trim(), text[token.end as usize..].trim());
                    return (!parts.0.is_empty() && !parts.1.is_empty() && !parts.2.is_empty()).then_some(parts);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_java_index(text: &str) -> Option<(&str, &str)> {
    use uniflow_parser_core::TokKind;
    let tokens = java_expression_tokens(text);
    let last = tokens.last()?;
    if last.kind != TokKind::Symbol || last.text != "]" { return None; }
    let mut depth = 0;
    for token in tokens.iter().rev() {
        if token.kind != TokKind::Symbol { continue; }
        match token.text.as_str() {
            "]" => depth += 1,
            "[" => {
                depth -= 1;
                if depth == 0 {
                    let base = text[..token.start as usize].trim();
                    let index = text[token.end as usize..last.start as usize].trim();
                    return (!base.is_empty() && !index.is_empty() && !base.starts_with("new "))
                        .then_some((base, index));
                }
            }
            _ => {}
        }
    }
    None
}

fn split_java_cast<'a>(text: &'a str, env: &JavaEnv) -> Option<(String, &'a str)> {
    use uniflow_parser_core::TokKind;
    let tokens = java_expression_tokens(text);
    if tokens.first()?.text != "(" { return None; }
    let close = tokens.iter().position(|token| token.kind == TokKind::Symbol && token.text == ")")?;
    let type_tokens = &tokens[1..close];
    let first = type_tokens.first()?;
    if first.kind != TokKind::Ident { return None; }
    // A parenthesized local name is a value, not a cast type.
    if type_tokens.len() == 1 && (env.vars.contains_key(&first.text) || env.field_types.contains_key(&first.text)) {
        return None;
    }
    let primitive = matches!(first.text.as_str(), "byte" | "short" | "int" | "long" | "float" | "double" | "boolean" | "char");
    if !type_tokens.iter().all(|token| token.kind == TokKind::Ident ||
        token.kind == TokKind::Symbol && matches!(token.text.as_str(), "." | "[" | "]" | "<" | ">" | ">>" | ">>>" | "," | "?" | "&")) {
        return None;
    }
    let next = tokens.get(close + 1)?;
    // Reference casts cannot precede unary +/- or postfix member/index access.
    if next.kind == TokKind::Symbol && (matches!(next.text.as_str(), "." | "[" | "*" | "/" | "%" | "==" | "!=" | "&&" | "||" | "?" | ":")
        || !primitive && matches!(next.text.as_str(), "+" | "-" | "++" | "--")) {
        return None;
    }
    let ty = type_tokens.iter().map(|token| token.text.as_str()).collect::<String>();
    Some((ty, text[tokens[close].end as usize..].trim()))
}
