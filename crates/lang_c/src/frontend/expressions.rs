fn parse_lvalue(builder: &mut ModuleBuilder, text: &str, env: &mut CLikeEnv) -> LValue {
    let normalized = normalize_member_access(text, env);
    if normalized.ends_with(']') {
        if let Some(open) = normalized.rfind('[') {
            let base_text = normalized[..open].trim();
            let index_text = normalized[open + 1..normalized.len() - 1].trim();
            if !base_text.is_empty() && !index_text.is_empty() {
                return LValue::Index {
                    base: Box::new(parse_expr(builder, base_text, env)),
                    index: Box::new(parse_expr(builder, index_text, env)),
                };
            }
        }
    }
    if let Some((base, field)) = split_last_top_level_dot(&normalized) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, env)),
            field,
        }
    } else {
        let target =
            pointee_alias(normalized.trim(), env).unwrap_or_else(|| normalized.trim().to_string());
        if let Some((base, field)) = split_last_top_level_dot(&target) {
            LValue::Field {
                base: Box::new(parse_expr(builder, &base, env)),
                field,
            }
        } else if target.ends_with(']') {
            if let Some(open) = target.rfind('[') {
                let base_text = target[..open].trim();
                let index_text = target[open + 1..target.len() - 1].trim();
                if !base_text.is_empty() && !index_text.is_empty() {
                    return LValue::Index {
                        base: Box::new(parse_expr(builder, base_text, env)),
                        index: Box::new(parse_expr(builder, index_text, env)),
                    };
                }
            }
            let symbol =
                ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
            LValue::Var(symbol)
        } else {
            let symbol =
                ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
            LValue::Var(symbol)
        }
    }
}

fn parse_expr_at(
    builder: &mut ModuleBuilder,
    text: &str,
    absolute_start: usize,
    env: &mut CLikeEnv,
) -> Expr {
    let leading_ws = text.len().saturating_sub(text.trim_start().len());
    let trimmed = text.trim();
    let mut expr = parse_expr(builder, trimmed, env);
    annotate_expr_occurrence(&mut expr, trimmed, absolute_start + leading_ws);
    expr
}

fn occurrence_span(start: usize, end: usize) -> uniflow_hir::Span {
    uniflow_hir::Span {
        file: 0,
        start_byte: start as u32,
        end_byte: end.max(start) as u32,
        ..uniflow_hir::Span::default()
    }
}

fn set_expr_span(expr: &mut Expr, span: uniflow_hir::Span) {
    match expr {
        Expr::VarRef { span: current, .. }
        | Expr::Literal { span: current, .. }
        | Expr::Unary { span: current, .. }
        | Expr::Binary { span: current, .. }
        | Expr::FieldRead { span: current, .. }
        | Expr::IndexRead { span: current, .. }
        | Expr::Lambda { span: current, .. }
        | Expr::New { span: current, .. }
        | Expr::Cast { span: current, .. }
        | Expr::Conditional { span: current, .. }
        | Expr::Assign { span: current, .. }
        | Expr::Interp { span: current, .. }
        | Expr::Collection { span: current, .. }
        | Expr::Range { span: current, .. }
        | Expr::Opaque { span: current, .. }
        | Expr::Unknown { span: current, .. } => *current = span,
        Expr::Call(call) => call.span = span,
    }
}

fn annotate_expr_occurrence(expr: &mut Expr, source: &str, absolute_start: usize) {
    set_expr_span(
        expr,
        occurrence_span(absolute_start, absolute_start + source.len()),
    );

    let Expr::Call(call) = expr else {
        return;
    };
    let Some(open) = source.char_indices().find_map(|(index, ch)| {
        (ch == '('
            && matching_delimiter(source, index, '(', ')')
                .is_some_and(|close| close + 1 == source.len()))
        .then_some(index)
    }) else {
        return;
    };
    let args_source = &source[open + 1..source.len().saturating_sub(1)];
    let parsed_args = split_top_level_commas(args_source);
    let mut search_from = 0usize;
    for (arg, parsed) in call.args.iter_mut().zip(parsed_args.iter()) {
        let Some(relative) = args_source[search_from..].find(parsed) else {
            break;
        };
        let arg_start = search_from + relative;
        let arg_end = arg_start + parsed.len();
        let absolute_arg_start = absolute_start + open + 1 + arg_start;
        annotate_expr_occurrence(arg, parsed, absolute_arg_start);
        search_from = arg_end;
    }
}

fn parse_expr(builder: &mut ModuleBuilder, text: &str, env: &mut CLikeEnv) -> Expr {
    let trimmed = text.trim();
    if let Some(inner) = strip_balanced_outer_parens(trimmed) {
        return parse_expr(builder, inner, env);
    }
    if trimmed == "nullptr" && matches!(env.language, Some(Language::Cpp)) {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Null,
            span: default_span(),
        };
    }
    if let Some((left, right)) = split_top_level_assignment(trimmed) {
        return Expr::Assign {
            id: builder.alloc_expr_id(),
            lhs: parse_lvalue(builder, left, env),
            rhs: Box::new(parse_expr(builder, right, env)),
            span: default_span(),
        };
    }
    // Normalize pointer-member syntax before scanning relational operators.  Otherwise the `>`
    // in `ptr->field` is indistinguishable from a greater-than operator to the lightweight C
    // expression splitter and the member access is lost before it can become a FieldRead.
    let normalized = normalize_member_access(trimmed, env);
    for (operators, op) in [
        (&["||"][..], BinaryOp::Or),
        (&["&&"][..], BinaryOp::And),
        (&["=="][..], BinaryOp::Eq),
        (&["!="][..], BinaryOp::Ne),
        (&["<="][..], BinaryOp::Le),
        (&[">="][..], BinaryOp::Ge),
        (&["<"][..], BinaryOp::Lt),
        (&[">"][..], BinaryOp::Gt),
    ] {
        if let Some((left, right)) = split_top_level_operator(&normalized, operators) {
            return Expr::Binary {
                id: builder.alloc_expr_id(),
                op,
                lhs: Box::new(parse_expr(builder, left, env)),
                rhs: Box::new(parse_expr(builder, right, env)),
                span: default_span(),
            };
        }
    }
    for operators in [
        &[("+", BinaryOp::Add), ("-", BinaryOp::Sub)][..],
        &[("*", BinaryOp::Mul), ("/", BinaryOp::Div), ("%", BinaryOp::Mod)][..],
    ] {
        if let Some((left, op, right)) = split_top_level_binary_group(&normalized, operators) {
            return Expr::Binary {
                id: builder.alloc_expr_id(),
                op,
                lhs: Box::new(parse_expr(builder, left, env)),
                rhs: Box::new(parse_expr(builder, right, env)),
                span: default_span(),
            };
        }
    }

    if is_string_literal(trimmed) {
        return new_string(builder, &trimmed[1..trimmed.len() - 1]);
    }
    if is_int_literal(trimmed) {
        return new_int(builder, trimmed.parse::<i64>().unwrap_or_default());
    }
    if let Some(inner) = trimmed.strip_prefix('&') {
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::AddrOf,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }
    if let Some(inner) = trimmed.strip_prefix('*') {
        if let Some(alias) = pointee_alias(inner, env) {
            if alias.contains('.') || alias.contains('[') {
                return parse_expr(builder, alias.as_str(), env);
            }
            let symbol =
                ensure_known_symbol(builder, &mut env.vars, alias.as_str(), SymbolKind::Local);
            return new_var_ref(builder, symbol);
        }
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::Deref,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }
    if let Some(inner) = trimmed.strip_prefix('-') {
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::Neg,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }
    if let Some(inner) = trimmed.strip_prefix('!') {
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::Not,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }
    if let Some(inner) = trimmed.strip_prefix('~') {
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::BitNot,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }

    if let Some(expr) = parse_alloc_expr(builder, trimmed, env, None) {
        return expr;
    }

    if normalized.ends_with(']') {
        if let Some(open) = normalized.rfind('[') {
            let base_text = normalized[..open].trim();
            let index_text = normalized[open + 1..normalized.len() - 1].trim();
            if !base_text.is_empty() && !index_text.is_empty() {
                return Expr::IndexRead {
                    id: builder.alloc_expr_id(),
                    base: Box::new(parse_expr(builder, base_text, env)),
                    index: Box::new(parse_expr(builder, index_text, env)),
                    span: default_span(),
                };
            }
        }
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(&normalized) {
        let args = split_top_level_commas(&arg_text)
            .into_iter()
            .map(|arg| parse_expr(builder, &arg, env))
            .collect::<Vec<_>>();

        let bare_callee = callee_text
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim_start_matches('*')
            .trim();

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            let receiver = parse_expr(builder, &prefix, env);
            let callee = if let Some(ty) = env.types.get(prefix.as_str()) {
                format!("{ty}.{method}")
            } else {
                format!("{prefix}.{method}")
            };
            return new_call(builder, &callee, Some(receiver), args);
        }

        if let Some(aliases) = env.function_aliases.get(bare_callee) {
            if aliases.len() == 1 {
                return new_call(builder, &aliases[0], None, args);
            }
        }
        if env.function_pointer_vars.contains(bare_callee) {
            let symbol =
                ensure_known_symbol(builder, &mut env.vars, bare_callee, SymbolKind::Local);
            let callee_expr = new_var_ref(builder, symbol);
            return new_dynamic_call(builder, callee_expr, None, args);
        }

        let callee = callee_text.replace("::", ".");
        return new_call(builder, &callee, None, args);
    }

    if let Some((base, field)) = split_last_top_level_dot(&normalized) {
        let base_expr = parse_expr(builder, &base, env);
        return new_field_read(builder, base_expr, &field);
    }

    let target = pointee_alias(trimmed, env).unwrap_or_else(|| trimmed.to_string());
    let symbol = ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
    new_var_ref(builder, symbol)
}

fn strip_balanced_outer_parens(text: &str) -> Option<&str> {
    if !text.starts_with('(') || !text.ends_with(')') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote = None;
    let mut escape = false;
    for (index, ch) in text.char_indices() {
        if let Some(active) = quote {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 && index + ch.len_utf8() != text.len() {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then(|| text[1..text.len() - 1].trim())
}

fn split_top_level_assignment(text: &str) -> Option<(&str, &str)> {
    let (left, right, index) = split_top_level_operator_at(text, &["="])?;
    let previous = text[..index].chars().next_back();
    let next = text[index + 1..].chars().next();
    if matches!(
        previous,
        Some('=' | '!' | '<' | '>' | '+' | '-' | '*' | '/' | '%')
    ) || next == Some('=')
    {
        return None;
    }
    Some((left, right))
}

fn split_top_level_operator<'a>(text: &'a str, operators: &[&str]) -> Option<(&'a str, &'a str)> {
    split_top_level_operator_at(text, operators).map(|(left, right, _)| (left, right))
}

fn split_top_level_binary_group<'a>(
    text: &'a str,
    operators: &[(&str, BinaryOp)],
) -> Option<(&'a str, BinaryOp, &'a str)> {
    let bytes = text.as_bytes();
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escape = false;
    let mut candidate = None;
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if let Some(active) = quote {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ => {}
        }
        if paren == 0 && bracket == 0 && brace == 0 {
            if let Some((operator, op)) = operators
                .iter()
                .find(|(operator, _)| text[index..].starts_with(*operator))
            {
                let end = index + operator.len();
                let left = text[..index].trim();
                let right = text[end..].trim();
                if !left.is_empty()
                    && !right.is_empty()
                    && !is_unary_binary_operator_position(text, index, operator)
                {
                    candidate = Some((left, *op, right));
                }
                index = end;
                continue;
            }
        }
        index += 1;
    }
    candidate
}

fn is_unary_binary_operator_position(text: &str, index: usize, operator: &str) -> bool {
    if !matches!(operator, "+" | "-" | "*") {
        return false;
    }
    let previous = text[..index].chars().rev().find(|ch| !ch.is_whitespace());
    previous.is_none_or(|ch| {
        matches!(
            ch,
            '(' | '['
                | '{'
                | ','
                | ':'
                | '?'
                | '='
                | '+'
                | '-'
                | '*'
                | '/'
                | '%'
                | '!'
                | '&'
                | '|'
                | '^'
                | '<'
                | '>'
        )
    })
}

fn split_top_level_operator_at<'a>(
    text: &'a str,
    operators: &[&str],
) -> Option<(&'a str, &'a str, usize)> {
    let bytes = text.as_bytes();
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escape = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if let Some(active) = quote {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ => {}
        }
        if paren == 0 && bracket == 0 && brace == 0 {
            if let Some(operator) = operators
                .iter()
                .find(|operator| text[index..].starts_with(**operator))
            {
                let left = text[..index].trim();
                let right = text[index + operator.len()..].trim();
                if !left.is_empty() && !right.is_empty() {
                    return Some((left, right, index));
                }
            }
        }
        index += 1;
    }
    None
}
