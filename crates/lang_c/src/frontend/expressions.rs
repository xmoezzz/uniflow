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
        let target = pointee_alias(normalized.trim(), env).unwrap_or_else(|| normalized.trim().to_string());
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
            let symbol = ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
            LValue::Var(symbol)
        } else {
            let symbol = ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
            LValue::Var(symbol)
        }
    }
}

fn parse_expr(builder: &mut ModuleBuilder, text: &str, env: &mut CLikeEnv) -> Expr {
    let trimmed = text.trim();
    let normalized = normalize_member_access(trimmed, env);

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
            let symbol = ensure_known_symbol(builder, &mut env.vars, alias.as_str(), SymbolKind::Local);
            return new_var_ref(builder, symbol);
        }
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::Deref,
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
            let symbol = ensure_known_symbol(builder, &mut env.vars, bare_callee, SymbolKind::Local);
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

