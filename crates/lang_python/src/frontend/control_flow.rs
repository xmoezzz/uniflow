fn parse_body(
    builder: &mut ModuleBuilder,
    body: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    first_line: u32,
) -> Vec<Stmt> {
    let lines = collect_py_body_lines(body, first_line);
    let mut idx = 0usize;
    parse_stmt_sequence(
        builder,
        &lines,
        &mut idx,
        current_body_indent(&lines),
        imports,
        known_classes,
        env,
    )
}

fn parse_stmt_sequence(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    while *idx < lines.len() {
        let Some(code_idx) = next_code_line(lines, *idx) else {
            *idx = lines.len();
            break;
        };
        *idx = code_idx;
        let line = &lines[*idx];
        let trimmed = line.text.trim();
        if line.indent < current_indent {
            break;
        }
        if line.indent > current_indent {
            *idx += 1;
            continue;
        }
        if is_clause_continuation_header(trimmed) {
            break;
        }
        if trimmed.starts_with("def ") || trimmed.starts_with("async def ") {
            parse_nested_function_definition(builder, lines, idx, current_indent, imports, known_classes, env);
            continue;
        }
        if trimmed.starts_with("class ") {
            *idx += 1;
            continue;
        }

        if trimmed.starts_with("if ") {
            out.push(parse_if_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed.starts_with("while ") {
            out.push(parse_while_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed.starts_with("for ") || trimmed.starts_with("async for ") {
            out.push(parse_for_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed == "try:" {
            out.push(parse_try_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }
        if trimmed.starts_with("with ") || trimmed.starts_with("async with ") {
            out.extend(parse_with_stmt(builder, lines, idx, current_indent, imports, known_classes, env));
            continue;
        }

        out.extend(parse_simple_stmt(builder, trimmed, imports, known_classes, env, line.line_no));
        *idx += 1;
    }
    out
}

fn parse_nested_block(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    parent_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    fallback_line: u32,
) -> Block {
    let Some(start_idx) = next_code_line(lines, *idx) else {
        return build_py_block(builder, Vec::new(), fallback_line, fallback_line);
    };
    if lines[start_idx].indent <= parent_indent {
        return build_py_block(builder, Vec::new(), fallback_line, fallback_line);
    }
    *idx = start_idx;
    let start_line = lines[start_idx].line_no;
    let nested_indent = lines[start_idx].indent;
    let stmts = parse_stmt_sequence(builder, lines, idx, nested_indent, imports, known_classes, env);
    let end_line = stmts.last().map(stmt_end_line).unwrap_or(start_line);
    build_py_block(builder, stmts, start_line, end_line)
}

fn parse_if_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let trimmed = line.text.trim();
    let cond_text = trimmed
        .strip_prefix("if ")
        .or_else(|| trimmed.strip_prefix("elif ") )
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_else(|| "True".to_string());
    let cond = parse_expr(builder, &cond_text, imports, known_classes, env, line.line_no);
    let start_line = line.line_no;
    let base_env = env.clone();
    *idx += 1;
    let mut then_env = base_env.clone();
    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut then_env);
    let then_block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut then_env, start_line);

    let mut else_block = None;
    let mut end_line = then_block.span.end_line.max(start_line);
    let mut else_env_out = None;
    if let Some(next_idx) = next_code_line(lines, *idx) {
        if lines[next_idx].indent == current_indent {
            let header = lines[next_idx].text.trim();
            if header.starts_with("elif ") {
                *idx = next_idx;
                let mut elif_env = base_env.clone();
                apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut elif_env);
                let elif_stmt = parse_if_stmt(builder, lines, idx, current_indent, imports, known_classes, &mut elif_env);
                end_line = stmt_end_line(&elif_stmt).max(end_line);
                else_env_out = Some(elif_env);
                else_block = Some(build_py_block(builder, vec![elif_stmt], lines[next_idx].line_no, end_line));
            } else if header == "else:" {
                let else_line = lines[next_idx].line_no;
                *idx = next_idx + 1;
                let mut else_env = base_env.clone();
                apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut else_env);
                let block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut else_env, else_line);
                end_line = block.span.end_line.max(end_line);
                else_env_out = Some(else_env);
                else_block = Some(block);
            }
        }
    }

    *env = merge_py_envs(&base_env, &then_env, else_env_out.as_ref());

    Stmt::If {
        id: builder.alloc_stmt_id(),
        cond,
        then_block,
        else_block,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn parse_while_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let trimmed = line.text.trim();
    let cond_text = trimmed
        .strip_prefix("while ")
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_else(|| "True".to_string());
    let cond = parse_expr(builder, &cond_text, imports, known_classes, env, line.line_no);
    let start_line = line.line_no;
    let base_env = env.clone();
    *idx += 1;
    let mut loop_env = base_env.clone();
    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut loop_env);
    let body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut loop_env, start_line);
    *env = merge_py_envs(&base_env, &loop_env, Some(&base_env));
    let end_line = body.span.end_line.max(start_line);
    Stmt::While {
        id: builder.alloc_stmt_id(),
        cond,
        body,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn infer_iterable_item_type(iterable_text: &str, imports: &PyImports, env: &PyEnv, known_classes: &HashSet<String>) -> Option<String> {
    let trimmed = iterable_text.trim();
    if trimmed.starts_with("range(") {
        return Some("int".to_string());
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if callee_text == "enumerate" {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            let item_ty = infer_iterable_item_type(first_arg, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
            return Some(format!("tuple<int|{}>", item_ty));
        }
        if callee_text == "zip" {
            let item_types = args
                .iter()
                .filter(|arg| !arg.trim().is_empty())
                .filter_map(|arg| infer_iterable_item_type(arg, imports, env, known_classes))
                .collect::<Vec<_>>();
            if !item_types.is_empty() {
                return Some(format!("tuple<{}>", item_types.join("|")));
            }
        }
        if callee_text == "map" {
            let iterables = args.iter().skip(1).filter(|arg| !arg.trim().is_empty()).collect::<Vec<_>>();
            if !iterables.is_empty() {
                if let Some(ret) = infer_simple_callable_result_type_from_expr(&args[0], iterables.len(), imports, env, known_classes) {
                    return Some(ret);
                }
                return infer_iterable_item_type(iterables[0], imports, env, known_classes);
            }
        }
        if callee_text == "filter" {
            let first_iterable = args.iter().skip(1).find(|arg| !arg.trim().is_empty())?;
            return infer_iterable_item_type(first_iterable, imports, env, known_classes);
        }
        if callee_text == "sorted" {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            return infer_iterable_item_type(first_arg, imports, env, known_classes);
        }
    }
    let iterable_ty = infer_simple_python_type(iterable_text, imports, env, known_classes).or_else(|| {
        is_simple_ident(trimmed)
            .then(|| env.project_index.unique_class_with_method("__iter__"))
            .flatten()
    })?;
    if let Some((base, method)) = split_last_top_level_dot(trimmed) {
        if let Some(base_ty) = infer_simple_python_type(&base, imports, env, known_classes) {
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((key, value)) = split_once_top_level(inner, ',') {
                    let key = key.trim();
                    let value = value.trim();
                    if method == "items" {
                        return Some(format!("tuple<{}|{}>", key, value));
                    }
                    if method == "values" {
                        return Some(value.to_string());
                    }
                    if method == "keys" {
                        return Some(key.to_string());
                    }
                }
            }
        }
    }
    if let Some(inner) = iterable_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = iterable_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, _)) = split_once_top_level(inner, ',') {
            return Some(key.trim().to_string());
        }
    }
    if let Some(items) = parse_tuple_type_elements(&iterable_ty) {
        if items.len() == 1 {
            return items.first().cloned();
        }
    }
    iterable_item_type_from_project_type(&env.project_index, &iterable_ty, &mut HashSet::new())
}

fn parse_for_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let trimmed = line.text.trim();
    let header = trimmed.strip_prefix("async ").unwrap_or(trimmed);
    let rest = header
        .strip_prefix("for ")
        .and_then(|value| value.strip_suffix(':'))
        .map(|value| value.trim().to_string())
        .unwrap_or_default();
    let (item_name, iterable_text) = split_once_top_level_str(&rest, " in ", false)
        .unwrap_or_else(|| ("item".to_string(), rest));
    let base_env = env.clone();
    let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line.line_no);
    let mut loop_env = base_env.clone();
    let destructured_targets = parse_destructuring_targets(item_name.trim());
    let symbol = if destructured_targets.is_empty() {
        ensure_known_symbol(builder, &mut loop_env.vars, item_name.trim(), SymbolKind::Local)
    } else {
        new_unpack_symbol(builder, "iter_item", line.line_no, 0)
    };
    let item_ty = infer_iterable_item_type(&iterable_text, imports, &base_env, known_classes);
    if destructured_targets.is_empty() {
        let item_name = item_name.trim().to_string();
        if let Some(ty) = item_ty.clone() {
            if let Some(path) = callable_path_from_type(&loop_env.project_index, &ty) {
                loop_env.callable_aliases.insert(item_name.clone(), path);
            } else {
                loop_env.callable_aliases.remove(&item_name);
            }
            loop_env.types.insert(item_name, ty);
        }
    } else if let Some(target_types) = item_ty.as_deref().and_then(destructure_type_elements) {
        for (target, ty) in destructured_targets.iter().zip(target_types.into_iter()) {
            loop_env.types.insert(target.clone(), ty);
        }
    }
    let start_line = line.line_no;
    *idx += 1;
    let mut body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut loop_env, start_line);
    if !destructured_targets.is_empty() {
        let inferred_targets = item_ty
            .as_deref()
            .and_then(destructure_type_elements)
            .unwrap_or_default()
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();
        let mut prefix = Vec::new();
        extend_destructuring_bindings(builder, &mut prefix, &destructured_targets, symbol, &inferred_targets, &mut loop_env, line.line_no);
        if !prefix.is_empty() {
            let mut combined = prefix;
            combined.extend(body.stmts);
            body.stmts = combined;
        }
    }
    *env = merge_py_envs(&base_env, &loop_env, Some(&base_env));
    let end_line = body.span.end_line.max(start_line);
    Stmt::ForEach {
        id: builder.alloc_stmt_id(),
        item_symbol: symbol,
        iterable,
        body,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn parse_try_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Stmt {
    let line = &lines[*idx];
    let start_line = line.line_no;
    let base_env = env.clone();
    *idx += 1;

    let mut try_env = base_env.clone();
    let mut try_block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut try_env, start_line);
    let mut catches = Vec::new();
    let mut catch_envs = Vec::new();
    let mut finally_block = None;
    let mut end_line = try_block.span.end_line.max(start_line);
    let mut success_env = try_env.clone();

    loop {
        let Some(next_idx) = next_code_line(lines, *idx) else {
            break;
        };
        if lines[next_idx].indent != current_indent {
            break;
        }
        let header = lines[next_idx].text.trim();
        if header.starts_with("except") {
            let catch_line = lines[next_idx].line_no;
            let spec = header
                .strip_prefix("except")
                .and_then(|rest| rest.strip_suffix(':'))
                .map(|rest| rest.trim().to_string())
                .unwrap_or_default();
            let (ty_text, sym_text) = if let Some((lhs, rhs)) = split_once_top_level_str(&spec, " as ", false) {
                (Some(lhs), Some(rhs))
            } else if spec.is_empty() {
                (None, None)
            } else {
                (Some(spec), None)
            };
            let mut catch_env = base_env.clone();
            let symbol = sym_text.as_deref().filter(|name| is_simple_ident(name)).map(|name| {
                ensure_known_symbol(builder, &mut catch_env.vars, name, SymbolKind::Local)
            });
            let ty_name = ty_text
                .as_deref()
                .and_then(|name| qualify_type_name(&env.current_module, name, imports, Some(&env.project_index)).or_else(|| qualify_type_name(&env.current_module, name, imports, None)));
            if let (Some(name), Some(ty_name)) = (sym_text.as_deref().filter(|name| is_simple_ident(name)), ty_name.clone()) {
                catch_env.types.insert(name.to_string(), canonicalize_project_path(&env.project_index, &ty_name));
            }
            let ty = ty_name.map(|name| builder.ensure_type(&name));
            *idx = next_idx + 1;
            let body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut catch_env, catch_line);
            end_line = body.span.end_line.max(end_line);
            catches.push(CatchClause {
                symbol,
                ty,
                body,
                span: span_from_line_range(builder.file_id(), catch_line, end_line),
            });
            catch_envs.push(catch_env);
            continue;
        }
        if header == "else:" {
            let else_line = lines[next_idx].line_no;
            *idx = next_idx + 1;
            let mut else_env = try_env.clone();
            let else_block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut else_env, else_line);
            end_line = else_block.span.end_line.max(end_line);
            let block_start = try_block.span.start_line;
            let mut combined = try_block.stmts;
            combined.extend(else_block.stmts);
            try_block = build_py_block(builder, combined, block_start, end_line);
            success_env = else_env;
            continue;
        }
        if header == "finally:" {
            let finally_line = lines[next_idx].line_no;
            *idx = next_idx + 1;
            let mut merged_before_finally_paths = vec![success_env.clone()];
            merged_before_finally_paths.extend(catch_envs.iter().cloned());
            let mut merged_before_finally = merge_py_env_paths(&base_env, &merged_before_finally_paths);
            let block = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, &mut merged_before_finally, finally_line);
            end_line = block.span.end_line.max(end_line);
            finally_block = Some(block);
            *env = merged_before_finally;
        }
        break;
    }

    if finally_block.is_none() {
        let mut merged_paths = vec![success_env];
        merged_paths.extend(catch_envs);
        *env = merge_py_env_paths(&base_env, &merged_paths);
    }

    Stmt::Try {
        id: builder.alloc_stmt_id(),
        try_block,
        catches,
        finally_block,
        span: span_from_line_range(builder.file_id(), start_line, end_line),
    }
}

fn parse_with_stmt(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) -> Vec<Stmt> {
    let line = &lines[*idx];
    let header = line.text.trim();
    let inner = header
        .strip_prefix("async with ")
        .or_else(|| header.strip_prefix("with ") )
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default();
    let mut out = Vec::new();
    for item in split_top_level_commas(&inner).into_iter().filter(|part| !part.trim().is_empty()) {
        if let Some((expr_text, alias_text)) = split_once_top_level_str(&item, " as ", false) {
            let alias = alias_text.trim();
            let span = span_from_line_range(builder.file_id(), line.line_no, line.line_no);
            let rhs = parse_expr(builder, &expr_text, imports, known_classes, env, line.line_no);
            let inferred_ty = context_manager_alias_type(&expr_text, imports, env, known_classes)
                .or_else(|| infer_simple_python_type(&expr_text, imports, env, known_classes));
            let existed = env.vars.contains_key(alias);
            let symbol = ensure_known_symbol(builder, &mut env.vars, alias, SymbolKind::Local);
            if let Some(ty) = inferred_ty.clone() {
                env.types.insert(alias.to_string(), ty);
            }
            if let Some(path) = infer_project_callable_value_type(&expr_text, imports, env, known_classes) {
                env.callable_aliases.insert(alias.to_string(), path);
            } else {
                env.callable_aliases.remove(alias);
            }
            env.local_object_aliases.remove(alias);
            env.local_field_types.remove(alias);
            populate_precise_container_slots_from_expr(env, alias, &expr_text, imports, known_classes);
            if existed {
                out.push(Stmt::Assign {
                    id: builder.alloc_stmt_id(),
                    lhs: LValue::Var(symbol),
                    rhs,
                    span,
                });
            } else {
                out.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol,
                    ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                    init: Some(rhs),
                    span,
                });
            }
        } else {
            let span = span_from_line_range(builder.file_id(), line.line_no, line.line_no);
            out.push(Stmt::Expr {
                id: builder.alloc_stmt_id(),
                expr: parse_expr(builder, &item, imports, known_classes, env, line.line_no),
                span,
            });
        }
    }
    *idx += 1;
    let body = parse_nested_block(builder, lines, idx, current_indent, imports, known_classes, env, line.line_no);
    out.extend(body.stmts);
    out
}

