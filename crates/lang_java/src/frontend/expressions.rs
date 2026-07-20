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

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_top_level_commas(&arg_text)
            .into_iter()
            .map(|arg| parse_expr(builder, &arg, resolver, env, span))
            .collect::<Vec<_>>();

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if is_static_receiver(&prefix, env) {
                let qual = resolver.qualify_type_name(prefix.as_str());
                return with_span(new_call(builder, &format!("{qual}.{method}"), None, args), span);
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
            let receiver = env
                .this_symbol
                .map(|_| this_expr(builder, env, span));
            let target = format!("{}.{}", env.current_class, callee_text);
            return with_span(new_call(builder, &target, receiver, args), span);
        }

        let target = resolver.qualify_type_name(&callee_text);
        return with_span(new_call(builder, &target, None, args), span);
    }

    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_expr = parse_expr(builder, &base, resolver, env, span);
        return with_span(new_field_read(builder, base_expr, &field), span);
    }

    if env.field_types.contains_key(trimmed) {
        let this_base = this_expr(builder, env, span);
        return with_span(new_field_read(builder, this_base, trimmed), span);
    }

    let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
    with_span(new_var_ref(builder, symbol), span)
}

fn with_span(expr: Expr, span: uniflow_hir::Span) -> Expr {
    match expr {
        Expr::VarRef { id, symbol, .. } => Expr::VarRef { id, symbol, span },
        Expr::Literal { id, kind, .. } => Expr::Literal { id, kind, span },
        Expr::Unary { id, op, expr, .. } => Expr::Unary { id, op, expr, span },
        Expr::Binary { id, op, lhs, rhs, .. } => Expr::Binary { id, op, lhs, rhs, span },
        Expr::FieldRead { id, base, field, .. } => Expr::FieldRead { id, base, field, span },
        Expr::IndexRead { id, base, index, .. } => Expr::IndexRead { id, base, index, span },
        Expr::Call(mut call) => {
            call.span = span;
            Expr::Call(call)
        }
        Expr::Lambda { id, params, captures, body, .. } => Expr::Lambda { id, params, captures, body, span },
        Expr::New { id, type_name, args, .. } => Expr::New { id, type_name, args, span },
        Expr::Cast { id, ty, expr, .. } => Expr::Cast { id, ty, expr, span },
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
    !env.vars.contains_key(first) && is_probable_type_name(first)
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

fn unique_import_match(imports: &HashMap<String, Vec<String>>, simple_name: &str) -> Option<String> {
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

fn infer_expr_type_from_expr(expr: &Expr, resolver: &JavaResolver, env: &JavaEnv) -> Option<String> {
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
        Expr::New { type_name, .. } => Some(type_name.clone()),
        Expr::Cast { expr, .. } => infer_expr_type_from_expr(expr, resolver, env),
        _ => None,
    }
}

fn infer_call_return_type(call: &uniflow_hir::CallExpr, resolver: &JavaResolver, env: &JavaEnv) -> Option<String> {
    let arg_count = call.args.len();
    match &call.target {
        CallTarget::Named(name) => {
            let method_name = name.rsplit('.').next()?;
            let owner = name.rsplit_once('.')?.0;
            let arg_types = call_arg_type_list(call, resolver, env);
            resolver.lookup_method_return_type(owner, method_name, Some(arg_count), Some(&arg_types))
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
                return resolver.lookup_method_return_type(&owner, &method, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
            }
            let owner = infer_expr_type_text(&prefix, resolver, env)?;
            return resolver.lookup_method_return_type(&owner, &method, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
        }
        if let Some(target) = resolver.resolve_static_member_call(&callee_text) {
            let method_name = target.rsplit('.').next().unwrap_or(target.as_str());
            let owner = target.rsplit_once('.').map(|(owner, _)| owner).unwrap_or(target.as_str());
            return resolver.lookup_method_return_type(owner, method_name, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
        }
        if !env.current_class.is_empty() {
            return resolver.lookup_method_return_type(&env.current_class, &callee_text, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
        }
        let owner = resolver.qualify_type_name(&callee_text);
        let method = owner.rsplit('.').next().unwrap_or(owner.as_str());
        return resolver.lookup_method_return_type(&owner, method, Some(arg_count), Some(&call_arg_type_list_from_text(&arg_text, resolver, env)));
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_ty = infer_expr_type_text(&base, resolver, env)?;
        return resolver.lookup_field_type(&base_ty, &field);
    }
    None
}

