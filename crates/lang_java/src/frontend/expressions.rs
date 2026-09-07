fn parse_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Expr {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        let unknown = ensure_known_symbol(builder, &mut env.vars, "_", SymbolKind::Local);
        return with_span(new_var_ref(builder, unknown), span);
    }

    let tokens = java_expression_tokens(trimmed);
    if let (Some(first), Some(last)) = (tokens.first(), tokens.last()) {
        if first.start > 0 || (last.end as usize) < trimmed.len() {
            return parse_expr(builder, &trimmed[first.start as usize..last.end as usize], resolver, env, span);
        }
    }

    if trimmed.starts_with('(')
        && matching_delimiter(trimmed, 0, '(', ')') == Some(trimmed.len() - 1)
    {
        return parse_expr(builder, &trimmed[1..trimmed.len() - 1], resolver, env, span);
    }
    let arrow = find_java_top_level_operator(trimmed, "->");
    let conditional = split_java_conditional(trimmed)
        .filter(|(condition, _, _)| arrow.is_none_or(|arrow| condition.len() < arrow));
    if let Some(index) = find_java_top_level_operator(trimmed, "=")
        .filter(|index| conditional.is_none_or(|(condition, _, _)| *index < condition.len())
            && arrow.is_none_or(|arrow| *index < arrow)) {
        return Expr::Assign {
            id: builder.alloc_expr_id(),
            lhs: parse_lvalue(builder, &trimmed[..index], resolver, env, span),
            rhs: Box::new(parse_expr(builder, &trimmed[index + 1..], resolver, env, span)),
            span,
        };
    }

    if let Some((condition, then_text, else_text)) = conditional {
        return Expr::Conditional {
            id: builder.alloc_expr_id(),
            cond: Box::new(parse_expr(builder, condition, resolver, env, span)),
            then_expr: Box::new(parse_expr(builder, then_text, resolver, env, span)),
            else_expr: Box::new(parse_expr(builder, else_text, resolver, env, span)), span,
        };
    }
    if let Some(lambda) = parse_java_lambda(builder, trimmed, resolver, env, span) {
        return lambda;
    }
    if let Some(method_reference) =
        parse_java_method_reference(builder, trimmed, resolver, env, span)
    {
        return method_reference;
    }

    // Preserve the most common Java expression dependencies before call/field
    // recognition. This is especially important in lambda bodies, where a
    // captured value is commonly combined with the explicit parameter.
    for operators in [
        &[("||", BinaryOp::Or)][..],
        &[("&&", BinaryOp::And)][..],
        &[("==", BinaryOp::Eq), ("!=", BinaryOp::Ne)][..],
        &[("<", BinaryOp::Lt), ("<=", BinaryOp::Le), (">", BinaryOp::Gt), (">=", BinaryOp::Ge)][..],
        &[("+", BinaryOp::Add), ("-", BinaryOp::Sub)][..],
        &[("*", BinaryOp::Mul), ("/", BinaryOp::Div), ("%", BinaryOp::Mod)][..],
    ] {
        if operators[0].0 == "<" && trimmed.starts_with("new ") { continue; }
        if let Some((lhs, op, rhs)) = split_java_binary_group(trimmed, operators) {
            return Expr::Binary {
                id: builder.alloc_expr_id(),
                op,
                lhs: Box::new(parse_expr(builder, lhs, resolver, env, span)),
                rhs: Box::new(parse_expr(builder, rhs, resolver, env, span)),
                span,
            };
        }
    }

    // Operators are tokens: comments adjacent to an update and ++ inside a
    // string must not change the shape. Parse after binary operators to retain
    // Java precedence, and before unary '-' so --x is not parsed as -(-x).
    let update = tokens.first().filter(|t| t.kind == uniflow_parser_core::TokKind::Symbol)
        .and_then(|t| match t.text.as_str() {
            "++" => Some((UnaryOp::PreIncrement, &trimmed[t.end as usize..])),
            "--" => Some((UnaryOp::PreDecrement, &trimmed[t.end as usize..])),
            _ => None,
        });
    if let Some((op, operand)) = update {
        let expr = parse_expr(builder, operand, resolver, env, span);
        if matches!(expr, Expr::VarRef { .. } | Expr::FieldRead { .. } | Expr::IndexRead { .. }) {
            return Expr::Unary { id: builder.alloc_expr_id(), op, expr: Box::new(expr), span };
        }
        return Expr::Opaque { id: builder.alloc_expr_id(), text: trimmed.to_string(), span };
    }

    for (prefix, op) in [("!", UnaryOp::Not), ("~", UnaryOp::BitNot), ("-", UnaryOp::Neg)] {
        if let Some(rest) = trimmed.strip_prefix(prefix).filter(|rest| !rest.trim().is_empty()) {
            return Expr::Unary {
                id: builder.alloc_expr_id(), op,
                expr: Box::new(parse_expr(builder, rest, resolver, env, span)), span,
            };
        }
    }

    if let Some((type_name, operand)) = split_java_cast(trimmed, env) {
        return Expr::Cast {
            id: builder.alloc_expr_id(), ty: Some(builder.ensure_type(&resolver.qualify_type_name(&type_name))),
            expr: Box::new(parse_expr(builder, operand, resolver, env, span)), span,
        };
    }

    if let Some(token) = tokens.last().filter(|t| t.kind == uniflow_parser_core::TokKind::Symbol
        && matches!(t.text.as_str(), "++" | "--")) {
        let operand = &trimmed[..token.start as usize];
        let expr = parse_expr(builder, operand, resolver, env, span);
        if matches!(expr, Expr::VarRef { .. } | Expr::FieldRead { .. } | Expr::IndexRead { .. }) {
            let op = if token.text == "++" { UnaryOp::PostIncrement } else { UnaryOp::PostDecrement };
            return Expr::Unary { id: builder.alloc_expr_id(), op, expr: Box::new(expr), span };
        }
        return Expr::Opaque { id: builder.alloc_expr_id(), text: trimmed.to_string(), span };
    }

    if let Some(rest) = trimmed.strip_prefix("new ") {
        if let Some((type_name, arg_text)) = parse_call_parts(rest) {
            let args = split_top_level_commas(&arg_text)
                .into_iter()
                .map(|arg| parse_expr(builder, &arg, resolver, env, span))
                .collect::<Vec<_>>();
            return Expr::New {
                id: builder.alloc_expr_id(),
                type_name: resolver.qualify_type_name(&type_name),
                args,
                span,
            };
        }
    }

    if is_string_literal(trimmed) {
        return with_span(new_string(builder, &trimmed[1..trimmed.len() - 1]), span);
    }

    if trimmed == "null" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Null,
            span,
        };
    }

    if matches!(trimmed, "true" | "false") {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Bool(trimmed == "true"),
            span,
        };
    }

    if is_int_literal(trimmed) {
        let value = trimmed.parse::<i64>().unwrap_or_default();
        return with_span(new_int(builder, value), span);
    }

    let float_text = trimmed
        .strip_suffix('f')
        .or_else(|| trimmed.strip_suffix('F'))
        .or_else(|| trimmed.strip_suffix('d'))
        .or_else(|| trimmed.strip_suffix('D'))
        .unwrap_or(trimmed);
    if float_text.contains('.') {
        if let Ok(value) = float_text.parse::<f64>() {
            return Expr::Literal {
                id: builder.alloc_expr_id(),
                kind: uniflow_hir::LiteralKind::Float(value),
                span,
            };
        }
    }

    if let Some((base, index)) = split_java_index(trimmed) {
        return Expr::IndexRead {
            id: builder.alloc_expr_id(), base: Box::new(parse_expr(builder, base, resolver, env, span)),
            index: Box::new(parse_expr(builder, index, resolver, env, span)), span,
        };
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_top_level_commas(&arg_text)
            .into_iter()
            .map(|arg| parse_expr(builder, &arg, resolver, env, span))
            .collect::<Vec<_>>();

        if let Some(symbol) = env.vars.get(callee_text.trim()).copied() {
            if env.callable_values.contains(&symbol) {
                return Expr::Call(CallExpr {
                    id: builder.alloc_expr_id(),
                    target: CallTarget::Dynamic(Box::new(with_span(
                        new_var_ref(builder, symbol),
                        span,
                    ))),
                    receiver: None,
                    qualifier_is_explicit: false,
                    arg_names: vec![None; args.len()],
                    args,
                    span,
                });
            }
        }

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if let Some(symbol) = env.vars.get(prefix.trim()).copied() {
                if env.callable_values.contains(&symbol)
                    && matches!(
                        method.as_str(),
                        "apply" | "accept" | "run" | "get" | "test" | "call"
                    )
                {
                    return Expr::Call(CallExpr {
                        id: builder.alloc_expr_id(),
                        target: CallTarget::Dynamic(Box::new(with_span(
                            new_var_ref(builder, symbol),
                            span,
                        ))),
                        receiver: None,
                        qualifier_is_explicit: true,
                        arg_names: vec![None; args.len()],
                        args,
                        span,
                    });
                }
            }
            if is_static_receiver(&prefix, env) {
                let qual = resolver.qualify_type_name(prefix.as_str());
                let mut call = with_span(
                    new_call(builder, &format!("{qual}.{method}"), None, args),
                    span,
                );
                if let Expr::Call(call) = &mut call { call.qualifier_is_explicit = true; }
                return call;
            }

            let receiver_type = infer_expr_type_text(&prefix, resolver, env);
            let receiver = parse_expr(builder, &prefix, resolver, env, span);
            let target = receiver_type
                .as_deref()
                .map(|ty| resolver.qualify_method_target(ty, &method))
                .unwrap_or_else(|| resolve_receiver_method_name(&prefix, &method, resolver, env));
            return with_span(new_call(builder, &target, Some(receiver), args), span);
        }

        if let Some(target) = resolver.resolve_static_member_call(&callee_text) {
            return with_span(new_call(builder, &target, None, args), span);
        }

        if !env.current_class.is_empty() {
            let receiver = env.this_symbol.map(|_| this_expr(builder, env, span));
            let target = format!("{}.{}", env.current_class, callee_text);
            let mut call = with_span(new_call(builder, &target, receiver, args), span);
            if let Expr::Call(call) = &mut call { call.qualifier_is_explicit = false; }
            return call;
        }

        let target = resolver.qualify_type_name(&callee_text);
        return with_span(new_call(builder, &target, None, args), span);
    }

    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_expr = parse_expr(builder, &base, resolver, env, span);
        return with_span(new_field_read(builder, base_expr, &field), span);
    }

    if let Some(symbol) = env.vars.get(trimmed).copied() {
        return with_span(new_var_ref(builder, symbol), span);
    }

    if env.field_types.contains_key(trimmed) {
        let this_base = this_expr(builder, env, span);
        return with_span(new_field_read(builder, this_base, trimmed), span);
    }

    let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
    with_span(new_var_ref(builder, symbol), span)
}

fn parse_java_method_reference(
    builder: &mut ModuleBuilder,
    text: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Option<Expr> {
    let separator = find_java_top_level_operator(text, "::")?;
    let owner_text = text[..separator].trim();
    let member = text[separator + 2..].trim();
    if owner_text.is_empty()
        || member.is_empty()
        || !member
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
    {
        return None;
    }

    let outer = env
        .vars
        .iter()
        .map(|(name, symbol)| (*symbol, name.clone()))
        .collect::<HashMap<_, _>>();
    let mut lambda_env = env.clone();
    lambda_env.expected_callable_arity = None;
    let arity = env.expected_callable_arity.unwrap_or(1);
    let mut params = Vec::with_capacity(arity);
    let mut locals = HashSet::new();
    let mut args = Vec::with_capacity(arity);
    for index in 0..arity {
        let name = format!("__arg{index}");
        let symbol = builder.add_symbol(&name, SymbolKind::Param);
        lambda_env.vars.insert(name.clone(), symbol);
        locals.insert(symbol);
        params.push(Param {
            name,
            symbol,
            ty: None,
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span,
        });
        args.push(with_span(new_var_ref(builder, symbol), span));
    }

    let value = if member == "new" {
        Expr::New {
            id: builder.alloc_expr_id(),
            type_name: resolver.qualify_type_name(owner_text),
            args,
            span,
        }
    } else if is_static_receiver(owner_text, env) {
        let owner = resolver.qualify_type_name(owner_text);
        with_span(
            new_call(builder, &format!("{owner}.{member}"), None, args),
            span,
        )
    } else {
        let receiver_type = infer_expr_type_text(owner_text, resolver, env);
        let receiver = parse_expr(builder, owner_text, resolver, &mut lambda_env, span);
        let target = receiver_type
            .as_deref()
            .map(|ty| resolver.qualify_method_target(ty, member))
            .unwrap_or_else(|| resolve_receiver_method_name(owner_text, member, resolver, env));
        with_span(new_call(builder, &target, Some(receiver), args), span)
    };
    let body = Block {
        id: builder.alloc_block_id(),
        stmts: vec![Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: Some(value),
            span,
        }],
        span,
    };
    let mut refs = Vec::new();
    collect_java_block_refs(&body, &mut refs);
    let mut seen = HashSet::new();
    let captures = refs
        .into_iter()
        .filter(|symbol| !locals.contains(symbol))
        .filter_map(|source_symbol| {
            let name = outer.get(&source_symbol)?.clone();
            seen.insert(source_symbol).then_some(LambdaCapture {
                name,
                source_symbol,
                symbol: source_symbol,
                ty: None,
                span,
            })
        })
        .collect();
    Some(Expr::Lambda {
        id: builder.alloc_expr_id(),
        params,
        captures,
        body,
        span,
    })
}

fn parse_java_lambda(
    builder: &mut ModuleBuilder,
    text: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Option<Expr> {
    let arrow = find_java_top_level_operator(text, "->")?;
    let params_text = text[..arrow].trim();
    let body_text = text[arrow + 2..].trim();
    if body_text.is_empty() {
        return None;
    }
    let params_text = params_text
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(params_text);
    let outer = env
        .vars
        .iter()
        .map(|(name, symbol)| (*symbol, name.clone()))
        .collect::<HashMap<_, _>>();
    let mut lambda_env = env.clone();
    let mut params = Vec::new();
    let mut locals = HashSet::new();
    for raw in split_top_level_commas(params_text) {
        let words = raw.split_whitespace().collect::<Vec<_>>();
        let Some(name) = words.last().copied() else {
            continue;
        };
        let symbol = builder.add_symbol(name, SymbolKind::Param);
        lambda_env.vars.insert(name.to_string(), symbol);
        locals.insert(symbol);
        let ty = if words.len() > 1 {
            let qualified = resolver.qualify_type_name(&words[..words.len() - 1].join(" "));
            lambda_env.types.insert(name.to_string(), qualified.clone());
            Some(builder.ensure_type(&qualified))
        } else {
            None
        };
        params.push(Param {
            name: name.to_string(),
            symbol,
            ty,
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span,
        });
    }
    let body = if let Some(inner) = body_text
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    {
        let stmts = parse_block_statements(builder, inner, span, resolver, &mut lambda_env);
        collect_java_local_symbols(&stmts, &mut locals);
        Block {
            id: builder.alloc_block_id(),
            stmts,
            span,
        }
    } else {
        let value = parse_expr(builder, body_text, resolver, &mut lambda_env, span);
        Block {
            id: builder.alloc_block_id(),
            stmts: vec![Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: Some(value),
                span,
            }],
            span,
        }
    };
    let mut refs = Vec::new();
    collect_java_block_refs(&body, &mut refs);
    let mut seen = HashSet::new();
    let captures = refs
        .into_iter()
        .filter(|symbol| !locals.contains(symbol))
        .filter_map(|source_symbol| {
            let name = outer.get(&source_symbol)?.clone();
            seen.insert(source_symbol).then_some(LambdaCapture {
                name,
                source_symbol,
                symbol: source_symbol,
                ty: None,
                span,
            })
        })
        .collect();
    Some(Expr::Lambda {
        id: builder.alloc_expr_id(),
        params,
        captures,
        body,
        span,
    })
}

fn java_top_level_tokens(text: &str) -> Vec<uniflow_parser_core::Token> {
    use uniflow_parser_core::{Lexer, LexerSpec, TokKind};
    let spec = LexerSpec { triple_quotes: vec!["\"\"\""], ..Default::default() };
    let mut depth = 0usize;
    Lexer::new(text, &spec).tokenize().into_iter().filter(|token| {
        if token.kind == TokKind::Symbol {
            match token.text.as_str() {
                "(" | "[" | "{" => { depth += 1; return false; }
                ")" | "]" | "}" => { depth = depth.saturating_sub(1); return false; }
                _ => {}
            }
        }
        depth == 0 && token.kind != TokKind::Eof
    }).collect()
}

fn find_java_top_level_operator(text: &str, operator: &str) -> Option<usize> {
    java_top_level_tokens(text).iter()
        .find(|t| t.kind == uniflow_parser_core::TokKind::Symbol && t.text == operator)
        .map(|t| t.start as usize)
}

fn split_java_binary_group<'a>(text: &'a str, operators: &[(&str, BinaryOp)]) -> Option<(&'a str, BinaryOp, &'a str)> {
    // Java's arithmetic and equality operators are left associative. Splitting
    // at the rightmost operator preserves that tree, including mixed ==/!=.
    for token in java_top_level_tokens(text).into_iter().rev() {
        if token.kind != uniflow_parser_core::TokKind::Symbol { continue; }
        let Some((_, op)) = operators.iter().find(|(operator, _)| *operator == token.text) else { continue; };
        let lhs = text[..token.start as usize].trim();
        let rhs = text[token.end as usize..].trim();
        if matches!(token.text.as_str(), "+" | "-") {
            let previous = java_expression_tokens(lhs).last().cloned();
            if previous.is_some_and(|token| token.kind == uniflow_parser_core::TokKind::Symbol
                && !matches!(token.text.as_str(), ")" | "]" | "++" | "--")) { continue; }
            if lhs.strip_prefix('(').and_then(|value| value.strip_suffix(')'))
                .is_some_and(|ty| matches!(ty.trim(), "byte" | "short" | "int" | "long" | "float" | "double" | "char")) { continue; }
        }
        if !lhs.is_empty() && !rhs.is_empty() { return Some((lhs, *op, rhs)); }
    }
    None
}

fn collect_java_local_symbols(stmts: &[Stmt], out: &mut HashSet<SymbolId>) {
    for stmt in stmts {
        match stmt {
            Stmt::Let { symbol, .. } => {
                out.insert(*symbol);
            }
            Stmt::ForEach {
                item_symbol, body, ..
            } => {
                out.insert(*item_symbol);
                collect_java_local_symbols(&body.stmts, out);
            }
            Stmt::For { init, update, body, .. } => {
                collect_java_local_symbols(&init.stmts, out);
                collect_java_local_symbols(&update.stmts, out);
                collect_java_local_symbols(&body.stmts, out);
            }
            Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                collect_java_local_symbols(&then_block.stmts, out);
                if let Some(block) = else_block {
                    collect_java_local_symbols(&block.stmts, out);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_java_local_symbols(&body.stmts, out)
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_java_local_symbols(&try_block.stmts, out);
                for catch in catches {
                    if let Some(symbol) = catch.symbol {
                        out.insert(symbol);
                    }
                    collect_java_local_symbols(&catch.body.stmts, out);
                }
                if let Some(block) = finally_block {
                    collect_java_local_symbols(&block.stmts, out);
                }
            }
            Stmt::Switch {
                clauses, default, ..
            } => {
                for clause in clauses {
                    collect_java_local_symbols(&clause.body.stmts, out);
                }
                if let Some(block) = default {
                    collect_java_local_symbols(&block.stmts, out);
                }
            }
            Stmt::Assign { .. }
            | Stmt::Expr { .. }
            | Stmt::Return { .. }
            | Stmt::Throw { .. }
            | Stmt::Break { .. }
            | Stmt::Continue { .. } => {}
        }
    }
}

fn collect_java_block_refs(block: &Block, out: &mut Vec<SymbolId>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Let { init, .. } => {
                if let Some(expr) = init {
                    collect_java_expr_refs(expr, out);
                }
            }
            Stmt::Assign { lhs, rhs, .. } => {
                collect_java_lvalue_refs(lhs, out);
                collect_java_expr_refs(rhs, out);
            }
            Stmt::Expr { expr, .. } => collect_java_expr_refs(expr, out),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                collect_java_expr_refs(cond, out);
                collect_java_block_refs(then_block, out);
                if let Some(block) = else_block {
                    collect_java_block_refs(block, out);
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                collect_java_expr_refs(cond, out);
                collect_java_block_refs(body, out);
            }
            Stmt::ForEach { iterable, body, .. } => {
                collect_java_expr_refs(iterable, out);
                collect_java_block_refs(body, out);
            }
            Stmt::For { init, cond, update, body, .. } => {
                collect_java_block_refs(init, out);
                if let Some(cond) = cond { collect_java_expr_refs(cond, out); }
                collect_java_block_refs(update, out);
                collect_java_block_refs(body, out);
            }
            Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
                if let Some(expr) = value {
                    collect_java_expr_refs(expr, out);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_java_block_refs(try_block, out);
                for catch in catches {
                    collect_java_block_refs(&catch.body, out);
                }
                if let Some(block) = finally_block {
                    collect_java_block_refs(block, out);
                }
            }
            Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                collect_java_expr_refs(scrutinee, out);
                for clause in clauses {
                    for value in &clause.values {
                        collect_java_expr_refs(value, out);
                    }
                    collect_java_block_refs(&clause.body, out);
                }
                if let Some(block) = default {
                    collect_java_block_refs(block, out);
                }
            }
            Stmt::Break { .. } | Stmt::Continue { .. } => {}
        }
    }
}

fn collect_java_lvalue_refs(lvalue: &LValue, out: &mut Vec<SymbolId>) {
    match lvalue {
        LValue::Var(symbol) => out.push(*symbol),
        LValue::Field { base, .. } => collect_java_expr_refs(base, out),
        LValue::Index { base, index } => {
            collect_java_expr_refs(base, out);
            collect_java_expr_refs(index, out);
        }
    }
}

fn collect_java_expr_refs(expr: &Expr, out: &mut Vec<SymbolId>) {
    match expr {
        Expr::VarRef { symbol, .. } => out.push(*symbol),
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => collect_java_expr_refs(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_java_expr_refs(lhs, out);
            collect_java_expr_refs(rhs, out);
        }
        Expr::FieldRead { base, .. } => collect_java_expr_refs(base, out),
        Expr::IndexRead { base, index, .. } => {
            collect_java_expr_refs(base, out);
            collect_java_expr_refs(index, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_java_expr_refs(callee, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_java_expr_refs(receiver, out);
            }
            for arg in &call.args {
                collect_java_expr_refs(arg, out);
            }
        }
        Expr::Lambda { captures, .. } => {
            out.extend(captures.iter().map(|capture| capture.source_symbol));
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_java_expr_refs(arg, out);
            }
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_java_expr_refs(cond, out);
            collect_java_expr_refs(then_expr, out);
            collect_java_expr_refs(else_expr, out);
        }
        Expr::Assign { lhs, rhs, .. } => {
            collect_java_lvalue_refs(lhs, out);
            collect_java_expr_refs(rhs, out);
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                collect_java_expr_refs(part, out);
            }
        }
        Expr::Range { low, high, .. } => {
            collect_java_expr_refs(low, out);
            collect_java_expr_refs(high, out);
        }
        Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {}
    }
}

fn with_span(expr: Expr, span: uniflow_hir::Span) -> Expr {
    match expr {
        Expr::VarRef { id, symbol, .. } => Expr::VarRef { id, symbol, span },
        Expr::Literal { id, kind, .. } => Expr::Literal { id, kind, span },
        Expr::Unary { id, op, expr, .. } => Expr::Unary { id, op, expr, span },
        Expr::Binary {
            id, op, lhs, rhs, ..
        } => Expr::Binary {
            id,
            op,
            lhs,
            rhs,
            span,
        },
        Expr::FieldRead {
            id, base, field, ..
        } => Expr::FieldRead {
            id,
            base,
            field,
            span,
        },
        Expr::IndexRead {
            id, base, index, ..
        } => Expr::IndexRead {
            id,
            base,
            index,
            span,
        },
        Expr::Call(mut call) => {
            call.span = span;
            Expr::Call(call)
        }
        Expr::Lambda {
            id,
            params,
            captures,
            body,
            ..
        } => Expr::Lambda {
            id,
            params,
            captures,
            body,
            span,
        },
        Expr::New {
            id,
            type_name,
            args,
            ..
        } => Expr::New {
            id,
            type_name,
            args,
            span,
        },
        Expr::Cast { id, ty, expr, .. } => Expr::Cast { id, ty, expr, span },
        Expr::Conditional {
            id,
            cond,
            then_expr,
            else_expr,
            ..
        } => Expr::Conditional {
            id,
            cond,
            then_expr,
            else_expr,
            span,
        },
        Expr::Assign { id, lhs, rhs, .. } => Expr::Assign { id, lhs, rhs, span },
        Expr::Interp { id, parts, .. } => Expr::Interp { id, parts, span },
        Expr::Collection {
            id,
            container,
            elements,
            ..
        } => Expr::Collection {
            id,
            container,
            elements,
            span,
        },
        Expr::Range {
            id,
            low,
            high,
            exclusive,
            ..
        } => Expr::Range {
            id,
            low,
            high,
            exclusive,
            span,
        },
        Expr::Opaque { id, text, .. } => Expr::Opaque { id, text, span },
        Expr::Unknown { id, .. } => Expr::Unknown { id, span },
    }
}

fn this_expr(builder: &mut ModuleBuilder, env: &mut JavaEnv, span: uniflow_hir::Span) -> Expr {
    let this_symbol = env.this_symbol.unwrap_or_else(|| {
        let symbol = builder.add_symbol("this", SymbolKind::Param);
        env.this_symbol = Some(symbol);
        env.vars.insert("this".to_string(), symbol);
        env.types
            .entry("this".to_string())
            .or_insert_with(|| env.current_class.clone());
        symbol
    });
    with_span(new_var_ref(builder, this_symbol), span)
}

fn is_static_receiver(prefix: &str, env: &JavaEnv) -> bool {
    let first = prefix.split('.').next().unwrap_or(prefix);
    !env.vars.contains_key(first) && !env.field_types.contains_key(first)
        && prefix.split('.').all(|part| !part.is_empty() && part.chars().all(|c| c.is_alphanumeric() || matches!(c, '_' | '$')))
        && prefix.rsplit('.').next().is_some_and(is_probable_type_name)
}

fn normalize_java_type_name(name: &str) -> &str {
    name.split('<').next().unwrap_or(name)
}

fn is_java_primitive_or_builtin(name: &str) -> bool {
    matches!(
        name,
        "void"
            | "boolean"
            | "byte"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "char"
            | "String"
            | "Object"
    )
}

fn default_java_qualifier(name: &str) -> String {
    match name {
        "HttpServletRequest" => "javax.servlet.http.HttpServletRequest".to_string(),
        "Statement" => "java.sql.Statement".to_string(),
        "Runtime" => "java.lang.Runtime".to_string(),
        "System" => "java.lang.System".to_string(),
        "StringBuilder" => "java.lang.StringBuilder".to_string(),
        _ => name.to_string(),
    }
}

fn unique_import_match(
    imports: &HashMap<String, Vec<String>>,
    simple_name: &str,
) -> Option<String> {
    let entries = imports.get(simple_name)?;
    if entries.len() == 1 {
        Some(entries[0].clone())
    } else {
        None
    }
}

fn resolve_unique_wildcard_type(
    index: &JavaProjectIndex,
    wildcards: &[String],
    simple_name: &str,
) -> Option<String> {
    let mut found = Vec::new();
    for wildcard in wildcards {
        if let Some(candidate) = index.resolve_wildcard(wildcard, simple_name) {
            if !found.iter().any(|existing| existing == &candidate) {
                found.push(candidate);
            }
        }
    }
    if found.len() == 1 {
        found.into_iter().next()
    } else {
        None
    }
}

fn select_best_method_return(
    candidates: &[IndexedMethodReturn],
    arg_types: Option<&[Option<String>]>,
    class_bases: &HashMap<String, Vec<String>>,
) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }
    let mut best_score: Option<usize> = None;
    let mut best_return: Option<String> = None;
    let mut ambiguous = false;
    for candidate in candidates {
        let Some(score) = method_signature_score(candidate, arg_types, class_bases) else {
            continue;
        };
        match best_score {
            None => {
                best_score = Some(score);
                best_return = Some(candidate.return_type.clone());
                ambiguous = false;
            }
            Some(existing) if score > existing => {
                best_score = Some(score);
                best_return = Some(candidate.return_type.clone());
                ambiguous = false;
            }
            Some(existing) if score == existing => {
                ambiguous = best_return.as_deref() != Some(candidate.return_type.as_str());
            }
            _ => {}
        }
    }
    if ambiguous {
        None
    } else {
        best_return
    }
}

fn method_signature_score(
    candidate: &IndexedMethodReturn,
    arg_types: Option<&[Option<String>]>,
    class_bases: &HashMap<String, Vec<String>>,
) -> Option<usize> {
    let Some(arg_types) = arg_types else {
        return Some(0);
    };
    if candidate.param_types.len() != arg_types.len() {
        return None;
    }
    let mut score = 0usize;
    let mut seen_known = false;
    for (expected, actual) in candidate.param_types.iter().zip(arg_types.iter()) {
        let Some(actual) = actual.as_deref() else {
            continue;
        };
        seen_known = true;
        if actual == expected {
            score += 2;
            continue;
        }
        if inherits_from(actual, expected, class_bases) {
            score += 1;
            continue;
        }
        return None;
    }
    Some(if seen_known { score } else { 0 })
}

fn inherits_from(actual: &str, expected: &str, class_bases: &HashMap<String, Vec<String>>) -> bool {
    if actual == expected {
        return true;
    }
    let mut stack = vec![actual.to_string()];
    let mut seen = Vec::<String>::new();
    while let Some(cur) = stack.pop() {
        if seen.iter().any(|item| item == &cur) {
            continue;
        }
        seen.push(cur.clone());
        if let Some(parents) = class_bases.get(&cur) {
            for parent in parents {
                if parent == expected {
                    return true;
                }
                stack.push(parent.clone());
            }
        }
    }
    false
}

fn resolve_receiver_method_name(
    prefix: &str,
    method: &str,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> String {
    let root = prefix.split('.').next().unwrap_or(prefix);
    if root == "this" {
        return format!("{}.{}", env.current_class, method);
    }
    if let Some(ty) = env.types.get(root) {
        return resolver.qualify_method_target(ty, method);
    }
    let receiver_name = resolver.qualify_type_name(root);
    format!("{receiver_name}.{method}")
}

fn infer_expr_type_from_expr(
    expr: &Expr,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> Option<String> {
    match expr {
        Expr::VarRef { symbol, .. } => env
            .vars
            .iter()
            .find(|(_, sym)| **sym == *symbol)
            .and_then(|(name, _)| env.types.get(name).cloned()),
        Expr::Literal { kind, .. } => match kind {
            uniflow_hir::LiteralKind::String(_) => Some("java.lang.String".to_string()),
            uniflow_hir::LiteralKind::Int(_) => Some("int".to_string()),
            uniflow_hir::LiteralKind::Bool(_) => Some("boolean".to_string()),
            _ => None,
        },
        Expr::FieldRead { base, field, .. } => {
            let base_ty = infer_expr_type_from_expr(base, resolver, env)?;
            resolver.lookup_field_type(&base_ty, field)
        }
        Expr::Call(call) => infer_call_return_type(call, resolver, env),
        Expr::IndexRead { base, .. } => infer_expr_type_from_expr(base, resolver, env)
            .and_then(|ty| ty.strip_suffix("[]").map(|element| resolver.qualify_type_name(element))),
        Expr::Conditional { then_expr, else_expr, .. } => {
            let left = infer_expr_type_from_expr(then_expr, resolver, env);
            let right = infer_expr_type_from_expr(else_expr, resolver, env);
            if left == right { left } else { None }
        }
        Expr::New { type_name, .. } => Some(type_name.clone()),
        Expr::Cast { expr, .. } => infer_expr_type_from_expr(expr, resolver, env),
        _ => None,
    }
}

fn infer_call_return_type(
    call: &uniflow_hir::CallExpr,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> Option<String> {
    let arg_count = call.args.len();
    match &call.target {
        CallTarget::Named(name) => {
            let method_name = name.rsplit('.').next()?;
            let owner = name.rsplit_once('.')?.0;
            let arg_types = call_arg_type_list(call, resolver, env);
            resolver.lookup_method_return_type(
                owner,
                method_name,
                Some(arg_count),
                Some(&arg_types),
            )
        }
        CallTarget::Dynamic(_) => None,
        CallTarget::Resolved(_) => None,
    }
}

fn call_arg_type_list(
    call: &uniflow_hir::CallExpr,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> Vec<Option<String>> {
    call.args
        .iter()
        .map(|arg| infer_expr_type_from_expr(arg, resolver, env))
        .collect()
}

fn call_arg_type_list_from_text(
    arg_text: &str,
    resolver: &JavaResolver,
    env: &JavaEnv,
) -> Vec<Option<String>> {
    split_top_level_commas(arg_text)
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .map(|part| infer_expr_type_text(&part, resolver, env))
        .collect()
}

fn infer_expr_type_text(text: &str, resolver: &JavaResolver, env: &JavaEnv) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with('(') && matching_delimiter(trimmed, 0, '(', ')') == Some(trimmed.len() - 1) {
        return infer_expr_type_text(&trimmed[1..trimmed.len() - 1], resolver, env);
    }
    if let Some((type_name, _)) = split_java_cast(trimmed, env) {
        return Some(resolver.qualify_type_name(&type_name));
    }
    if let Some((base, _)) = split_java_index(trimmed) {
        return infer_expr_type_text(base, resolver, env)
            .and_then(|ty| ty.strip_suffix("[]").map(|element| resolver.qualify_type_name(element)));
    }
    if let Some((_, then_text, else_text)) = split_java_conditional(trimmed) {
        let left = infer_expr_type_text(then_text, resolver, env);
        let right = infer_expr_type_text(else_text, resolver, env);
        return if left == right { left } else { None };
    }
    if let Some(rest) = trimmed.strip_prefix("new ") {
        if let Some((type_name, _)) = parse_call_parts(rest) {
            return Some(resolver.qualify_type_name(&type_name));
        }
    }
    if is_string_literal(trimmed) {
        return Some("java.lang.String".to_string());
    }
    if is_int_literal(trimmed) {
        return Some("int".to_string());
    }
    if matches!(trimmed, "true" | "false") {
        return Some("boolean".to_string());
    }
    if trimmed == "this" {
        return Some(env.current_class.clone());
    }
    if let Some(ty) = env.types.get(trimmed) {
        return Some(ty.clone());
    }
    if let Some(field_ty) = env.field_types.get(trimmed) {
        return Some(field_ty.clone());
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let arg_count = split_top_level_commas(&arg_text)
            .into_iter()
            .filter(|part| !part.trim().is_empty())
            .count();
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if is_static_receiver(&prefix, env) {
                let owner = resolver.qualify_type_name(prefix.as_str());
                return resolver.lookup_method_return_type(
                    &owner,
                    &method,
                    Some(arg_count),
                    Some(&call_arg_type_list_from_text(&arg_text, resolver, env)),
                );
            }
            let owner = infer_expr_type_text(&prefix, resolver, env)?;
            return resolver.lookup_method_return_type(
                &owner,
                &method,
                Some(arg_count),
                Some(&call_arg_type_list_from_text(&arg_text, resolver, env)),
            );
        }
        if let Some(target) = resolver.resolve_static_member_call(&callee_text) {
            let method_name = target.rsplit('.').next().unwrap_or(target.as_str());
            let owner = target
                .rsplit_once('.')
                .map(|(owner, _)| owner)
                .unwrap_or(target.as_str());
            return resolver.lookup_method_return_type(
                owner,
                method_name,
                Some(arg_count),
                Some(&call_arg_type_list_from_text(&arg_text, resolver, env)),
            );
        }
        if !env.current_class.is_empty() {
            return resolver.lookup_method_return_type(
                &env.current_class,
                &callee_text,
                Some(arg_count),
                Some(&call_arg_type_list_from_text(&arg_text, resolver, env)),
            );
        }
        let owner = resolver.qualify_type_name(&callee_text);
        let method = owner.rsplit('.').next().unwrap_or(owner.as_str());
        return resolver.lookup_method_return_type(
            &owner,
            method,
            Some(arg_count),
            Some(&call_arg_type_list_from_text(&arg_text, resolver, env)),
        );
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_ty = infer_expr_type_text(&base, resolver, env)?;
        return resolver.lookup_field_type(&base_ty, &field);
    }
    None
}
