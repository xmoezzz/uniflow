fn parse_simple_stmt(
    builder: &mut ModuleBuilder,
    line: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Vec<Stmt> {
    let span = span_from_line_range(builder.file_id(), line_no, line_no);
    let mut out = Vec::new();

    if let Some(rest) = line.strip_prefix("return ") {
        out.push(Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: Some(parse_expr(builder, rest, imports, known_classes, env, line_no)),
            span,
        });
        return out;
    }
    if line == "return" {
        out.push(Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: None,
            span,
        });
        return out;
    }
    if let Some(rest) = line.strip_prefix("raise ") {
        out.push(Stmt::Throw {
            id: builder.alloc_stmt_id(),
            value: Some(parse_expr(builder, rest, imports, known_classes, env, line_no)),
            span,
        });
        return out;
    }
    if line == "raise" {
        out.push(Stmt::Throw {
            id: builder.alloc_stmt_id(),
            value: None,
            span,
        });
        return out;
    }
    if line == "pass" || line == "break" || line == "continue" {
        return out;
    }
    if let Some(names) = parse_python_name_declaration(line, "global ") {
        for name in names {
            seed_declared_global_name(Some(builder), env, &name);
        }
        return out;
    }
    if let Some(names) = parse_python_name_declaration(line, "nonlocal ") {
        for name in names {
            if let Some(symbol) = env.capturable_vars.get(&name).copied() {
                env.vars.insert(name.clone(), symbol);
            } else {
                let created = ensure_known_symbol(builder, &mut env.vars, &name, SymbolKind::Local);
                env.capturable_vars.insert(name.clone(), created);
            }
        }
        return out;
    }
    if let Some(rest) = line.strip_prefix("yield from ") {
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, rest, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }
    if let Some(rest) = line.strip_prefix("yield ") {
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, rest, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }
    if line == "yield" {
        return out;
    }
    if let Some(rest) = line.strip_prefix("assert ") {
        apply_runtime_condition_refinements(rest, true, imports, known_classes, env);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, rest, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some(lines) = parse_static_exec_body(line) {
        for exec_line in lines {
            out.extend(parse_simple_stmt(builder, &exec_line, imports, known_classes, env, line_no));
        }
        return out;
    }

    if let Some(entries) = parse_static_namespace_update_call(line) {
        for (target, value_text) in entries {
            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
        }
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, line, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some(rest) = line.strip_prefix("del ") {
        for raw_target in split_top_level_commas(rest).into_iter().filter(|part| !part.trim().is_empty()) {
            let target_buf = synthetic_static_namespace_access_text(raw_target.trim());
            let target = target_buf.as_deref().unwrap_or_else(|| raw_target.trim());
            if let Some((base_text, field)) = split_last_top_level_dot(target) {
                clear_python_env_target_effects(target, env);
                if let Some(base_ty) = receiver_type_for_property_deleter(&base_text, &field, imports, env, known_classes) {
                    if env.project_index.class_has_property_deleter(&base_ty, &field) {
                        if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, &field) {
                            let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                            out.push(Stmt::Expr {
                                id: builder.alloc_stmt_id(),
                                expr: with_line_span(new_call(builder, &method_path, Some(receiver), Vec::new()), builder.file_id(), line_no),
                                span,
                            });
                            continue;
                        }
                    }
                }
                out.push(Stmt::Expr {
                    id: builder.alloc_stmt_id(),
                    expr: parse_expr(builder, target, imports, known_classes, env, line_no),
                    span,
                });
                continue;
            }
            if let Some((base_text, index_text)) = split_last_top_level_index(target) {
                if let Some(base_ty) = receiver_type_for_method(&base_text, "__delitem__", imports, env, known_classes) {
                    if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, "__delitem__") {
                        let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                        let index_expr = parse_expr(builder, &index_text, imports, known_classes, env, line_no);
                        out.push(Stmt::Expr {
                            id: builder.alloc_stmt_id(),
                            expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![index_expr]), builder.file_id(), line_no),
                            span,
                        });
                    } else {
                        out.push(Stmt::Expr {
                            id: builder.alloc_stmt_id(),
                            expr: parse_expr(builder, target, imports, known_classes, env, line_no),
                            span,
                        });
                    }
                }
                clear_python_env_target_effects(target, env);
                continue;
            }
            clear_python_env_target_effects(target, env);
        }
        return out;
    }

    if parse_static_namespace_method_call(line).is_some() {
        apply_python_expr_side_effects(line, imports, env, known_classes);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, line, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some((base_text, field, value_text)) = parse_builtin_setattr_call(line) {
        let lhs = LValue::Field {
            base: Box::new(parse_expr(builder, &base_text, imports, known_classes, env, line_no)),
            field: field.clone(),
        };
        let rhs = parse_expr(builder, &value_text, imports, known_classes, env, line_no);
        let inferred_ty = infer_simple_python_type(&value_text, imports, env, known_classes);
        apply_python_env_assignment_effects(&synthetic_attr_expr_text(&base_text, &field), &value_text, imports, env, known_classes);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            let ty = inferred_ty.as_ref().map(|ty| builder.ensure_type(ty));
            env.discovered_fields.entry(field.clone()).or_insert(Field {
                name: field.clone(),
                symbol: Some(builder.add_symbol(&field, SymbolKind::Field)),
                ty,
                span,
            });
        }
        if let Some(base_ty) = receiver_type_for_property_setter(&base_text, &field, imports, env, known_classes) {
            if env.project_index.class_has_property_setter(&base_ty, &field) {
                if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, &field) {
                    let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                    let value_expr = parse_expr(builder, &value_text, imports, known_classes, env, line_no);
                    out.push(Stmt::Expr {
                        id: builder.alloc_stmt_id(),
                        expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![value_expr]), builder.file_id(), line_no),
                        span,
                    });
                    return out;
                }
            }
        }
        out.push(Stmt::Assign {
            id: builder.alloc_stmt_id(),
            lhs,
            rhs,
            span,
        });
        return out;
    }

    if let Some((base_text, field)) = parse_builtin_delattr_call(line) {
        let target_text = synthetic_attr_expr_text(&base_text, &field);
        clear_precise_container_slots(env, &target_text);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            env.field_types.remove(&field);
        } else if is_simple_ident(&base_text) {
            clear_local_object_field_type(env, &base_text, &field);
        }
        if let Some(base_ty) = receiver_type_for_property_deleter(&base_text, &field, imports, env, known_classes) {
            if env.project_index.class_has_property_deleter(&base_ty, &field) {
                if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, &field) {
                    let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                    out.push(Stmt::Expr {
                        id: builder.alloc_stmt_id(),
                        expr: with_line_span(new_call(builder, &method_path, Some(receiver), Vec::new()), builder.file_id(), line_no),
                        span,
                    });
                    return out;
                }
            }
        }
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: parse_expr(builder, line, imports, known_classes, env, line_no),
            span,
        });
        return out;
    }

    if let Some((left, right)) = split_once_top_level(line, '=') {
        if !left.contains("==") && !left.contains("!=") && !left.contains(">=") && !left.contains("<=") {
            let destructured = parse_destructuring_targets(&left);
            if !destructured.is_empty() {
                let values_inner = right.trim()
                    .strip_prefix('(').and_then(|rest| rest.strip_suffix(')'))
                    .or_else(|| right.trim().strip_prefix('[').and_then(|rest| rest.strip_suffix(']')));
                if let Some(inner) = values_inner {
                    let values = split_top_level_commas(inner)
                        .into_iter()
                        .filter(|item| !item.trim().is_empty())
                        .collect::<Vec<_>>();
                    let inferred = infer_simple_destructured_types(&right, imports, env, known_classes);
                    if values.len() == destructured.len() && inferred.len() == destructured.len() {
                        for ((target, value_text), inferred_ty) in destructured.into_iter().zip(values.into_iter()).zip(inferred.into_iter()) {
                            let symbol = ensure_known_symbol(builder, &mut env.vars, &target, SymbolKind::Local);
                            let value = parse_expr(builder, &value_text, imports, known_classes, env, line_no);
                            if let Some(ty) = inferred_ty.clone() {
                                env.types.insert(target.clone(), ty.clone());
                            }
                            if let Some(path) = infer_project_callable_value_type(&value_text, imports, env, known_classes) {
                                env.callable_aliases.insert(target.clone(), path);
                            } else {
                                env.callable_aliases.remove(&target);
                            }
                            env.local_object_aliases.remove(&target);
                            env.local_field_types.remove(&target);
                            out.push(Stmt::Let {
                                id: builder.alloc_stmt_id(),
                                symbol,
                                ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                                init: Some(value),
                                span,
                            });
                        }
                        return out;
                    }
                }
                let inferred = infer_simple_destructured_types(&right, imports, env, known_classes);
                let temp_symbol = new_unpack_symbol(builder, "unpack", line_no, out.len());
                let temp_ty = infer_simple_python_type(&right, imports, env, known_classes);
                out.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol: temp_symbol,
                    ty: temp_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                    init: Some(parse_expr(builder, &right, imports, known_classes, env, line_no)),
                    span,
                });
                extend_destructuring_bindings(builder, &mut out, &destructured, temp_symbol, &inferred, env, line_no);
                return out;
            }

            let normalized_left = synthetic_static_namespace_access_text(left.trim()).unwrap_or_else(|| left.trim().to_string());
            let was_defined = env.vars.contains_key(normalized_left.trim());
            let lhs = parse_lvalue(builder, &normalized_left, imports, known_classes, env, line_no);
            let rhs = parse_expr(builder, &right, imports, known_classes, env, line_no);
            let inferred_ty = infer_simple_python_type(&right, imports, env, known_classes);
            match &lhs {
                LValue::Var(symbol) => {
                    let name = normalized_left.trim();
                    clear_precise_container_slots(env, name);
                    if let Some(path) = infer_project_callable_value_type(&right, imports, env, known_classes) {
                        env.callable_aliases.insert(name.to_string(), path);
                    } else {
                        env.callable_aliases.remove(name);
                    }
                    if is_simple_ident(right.trim()) {
                        propagate_local_object_alias(env, name, &right);
                    } else {
                        env.local_object_aliases.remove(name);
                        env.local_field_types.remove(name);
                    }
                    if let Some(ty) = inferred_ty.clone() {
                        env.types.insert(name.to_string(), ty);
                    } else {
                        env.types.remove(name);
                    }
                    populate_precise_container_slots_from_expr(env, name, &right, imports, known_classes);
                    apply_python_expr_side_effects(&right, imports, env, known_classes);
                    if !was_defined {
                        env.vars.insert(name.to_string(), *symbol);
                        out.push(Stmt::Let {
                            id: builder.alloc_stmt_id(),
                            symbol: *symbol,
                            ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                            init: Some(rhs),
                            span,
                        });
                    } else {
                        out.push(Stmt::Assign {
                            id: builder.alloc_stmt_id(),
                            lhs,
                            rhs,
                            span,
                        });
                    }
                }
                LValue::Field { base, field } => {
                    let target_text = normalized_left.trim();
                    clear_precise_container_slots(env, target_text);
                    if base_is_self(base, env) {
                        let ty = inferred_ty.as_ref().map(|ty| builder.ensure_type(ty));
                        if let Some(inferred) = inferred_ty.clone() {
                            env.field_types.insert(field.clone(), inferred.clone());
                            if let Some(current_class) = env.current_class.clone() {
                                env.class_field_index.set_field(current_class, field.clone(), inferred);
                            }
                        } else {
                            env.field_types.remove(field);
                        }
                        env.discovered_fields.entry(field.clone()).or_insert(Field {
                            name: field.clone(),
                            symbol: Some(builder.add_symbol(field, SymbolKind::Field)),
                            ty,
                            span,
                        });
                    } else if let Some((base_name, _)) = split_last_top_level_dot(normalized_left.trim()) {
                        if is_simple_ident(&base_name) {
                            if let Some(inferred) = inferred_ty.clone() {
                                update_local_object_field_type(env, &base_name, field, &inferred);
                            }
                        }
                    }
                    populate_precise_container_slots_from_expr(env, target_text, &right, imports, known_classes);
                    apply_python_expr_side_effects(&right, imports, env, known_classes);
                    if let Some((base_text, _)) = split_last_top_level_dot(normalized_left.trim()) {
                        if let Some(base_ty) = receiver_type_for_property_setter(&base_text, field, imports, env, known_classes) {
                            if env.project_index.class_has_property_setter(&base_ty, field) {
                                if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, field) {
                                    let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                                    let value_expr = parse_expr(builder, &right, imports, known_classes, env, line_no);
                                    out.push(Stmt::Expr {
                                        id: builder.alloc_stmt_id(),
                                        expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![value_expr]), builder.file_id(), line_no),
                                        span,
                                    });
                                    return out;
                                }
                            }
                        }
                    }
                    out.push(Stmt::Assign {
                        id: builder.alloc_stmt_id(),
                        lhs,
                        rhs,
                        span,
                    });
                }
                LValue::Index { .. } => {
                    if let Some((base_text, index_text)) = split_last_top_level_index(normalized_left.trim()) {
                        if let Some(base_ty) = receiver_type_for_method(&base_text, "__setitem__", imports, env, known_classes) {
                            if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, "__setitem__") {
                                let receiver = parse_expr(builder, &base_text, imports, known_classes, env, line_no);
                                let index_expr = parse_expr(builder, &index_text, imports, known_classes, env, line_no);
                                let value_expr = parse_expr(builder, &right, imports, known_classes, env, line_no);
                                out.push(Stmt::Expr {
                                    id: builder.alloc_stmt_id(),
                                    expr: with_line_span(new_call(builder, &method_path, Some(receiver), vec![index_expr, value_expr]), builder.file_id(), line_no),
                                    span,
                                });
                                return out;
                            }
                        }
                        if let Some(slot_key) = parse_static_index_slot_key(&index_text) {
                            if let Some(inferred) = inferred_ty.clone() {
                                update_precise_container_slot_type(env, &base_text, &slot_key, &inferred);
                                if slot_key.parse::<i64>().is_ok() {
                                    update_container_receiver_type(env, &base_text, &format!("list<{}>", inferred));
                                } else {
                                    update_container_receiver_type(env, &base_text, &format!("dict<str,{}>", inferred));
                                }
                            }
                            let callable = infer_project_callable_value_type(&right, imports, env, known_classes);
                            update_precise_container_slot_callable(env, &base_text, &slot_key, callable.as_deref());
                        }
                    }
                    apply_python_expr_side_effects(&right, imports, env, known_classes);
                    out.push(Stmt::Assign {
                        id: builder.alloc_stmt_id(),
                        lhs,
                        rhs,
                        span,
                    });
                }
            }
            return out;
        }
    }

    apply_container_method_type_effects(line, imports, env, known_classes);
    apply_python_expr_side_effects(line, imports, env, known_classes);
    out.push(Stmt::Expr {
        id: builder.alloc_stmt_id(),
        expr: parse_expr(builder, line, imports, known_classes, env, line_no),
        span,
    });
    out
}

fn infer_simple_python_type(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let _depth_guard = TypeInferenceDepthGuard::enter()?;
    let trimmed = text.trim();
    if looks_like_python_type_annotation(trimmed) {
        if let Some(ty) = normalize_python_annotation_type(
            trimmed,
            &env.current_module,
            imports,
            Some(&env.project_index),
        ) {
            return Some(ty);
        }
    }
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return infer_simple_python_type(&inner, imports, env, known_classes);
    }
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return infer_simple_python_type(&synthetic, imports, env, known_classes)
            .or_else(|| env.project_index.module_value_type(&env.current_module, &synthetic))
            .or_else(|| env.project_index.module_symbol_alias(&env.current_module, &synthetic));
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(ty) = infer_simple_python_type(&synthetic, imports, env, known_classes)
            .or_else(|| env.project_index.module_value_type(&env.current_module, &synthetic))
            .or_else(|| env.project_index.module_symbol_alias(&env.current_module, &synthetic))
        {
            return Some(ty);
        }
        if let Some(default_expr) = default_value {
            return infer_simple_python_type(&default_expr, imports, env, known_classes);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return infer_simple_python_type(inner, imports, env, known_classes);
    }
    // Python conditional expressions carry values from both branches.  For
    // callable values retain a concrete lexical callable path; this is needed
    // for nested functions returned as first-class values.
    if let Some((then_expr, remainder)) = split_once_top_level_str(trimmed, " if ", false) {
        if let Some((_condition, else_expr)) = split_once_top_level_str(&remainder, " else ", false) {
            let then_ty = infer_simple_python_type(&then_expr, imports, env, known_classes);
            let else_ty = infer_simple_python_type(&else_expr, imports, env, known_classes);
            if let Some(else_ty) = else_ty {
                if env.project_index.function_path_exists(&else_ty)
                    || else_ty.starts_with(&format!("{}.", env.current_function))
                {
                    return Some(else_ty);
                }
                if then_ty.as_deref() == Some(else_ty.as_str()) {
                    return Some(else_ty);
                }
            }
            if let Some(then_ty) = then_ty {
                return Some(then_ty);
            }
        }
    }
    if trimmed == "super()" {
        return current_super_type(env);
    }
    if parse_call_parts(trimmed).is_none() {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            return Some(path);
        }
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_types_only(&mut comp_env, &target_text, item_ty.as_deref());
        let result_ty = infer_simple_python_type(&result_expr, imports, &comp_env, known_classes)
            .or_else(|| item_ty.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("list<{}>", result_ty));
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_types_only(&mut comp_env, &target_text, item_ty.as_deref());
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key_ty = infer_simple_python_type(&key_text, imports, &comp_env, known_classes)
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = infer_simple_python_type(&value_text, imports, &comp_env, known_classes)
                .or_else(|| item_ty.clone())
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        let result_ty = infer_simple_python_type(&result_expr, imports, &comp_env, known_classes)
            .or_else(|| item_ty.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{}>", result_ty));
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_types_only(&mut comp_env, &target_text, item_ty.as_deref());
        let result_ty = infer_simple_python_type(&result_expr, imports, &comp_env, known_classes)
            .or_else(|| item_ty.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{}>", result_ty));
    }
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 || (items.len() == 1 && inner.trim_end().ends_with(',')) {
            let parts = items
                .into_iter()
                .map(|item| infer_simple_python_type(&item, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string()))
                .collect::<Vec<_>>();
            return Some(format!("tuple<{}>", parts.join("|")));
        }
    }
    if is_string_literal(trimmed) {
        return Some("str".to_string());
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let result_ty = infer_simple_python_type(&result_expr, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes).unwrap_or_else(|| result_ty.clone());
        return Some(format!("list<{}>", if result_ty == "unknown" { item_ty } else { result_ty }));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key_ty = infer_simple_python_type(&key_text, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
            let value_ty = infer_simple_python_type(&value_text, imports, env, known_classes).unwrap_or_else(|| infer_iterable_item_type(&iterable_text, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string()));
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        let result_ty = infer_simple_python_type(&result_expr, imports, env, known_classes)
            .or_else(|| infer_iterable_item_type(&iterable_text, imports, env, known_classes))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{}>", result_ty));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let result_ty = infer_simple_python_type(&result_expr, imports, env, known_classes)
            .or_else(|| infer_iterable_item_type(&iterable_text, imports, env, known_classes))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{}>", result_ty));
    }
    if is_int_literal(trimmed) {
        return Some("int".to_string());
    }
    if trimmed == "True" || trimmed == "False" {
        return Some("bool".to_string());
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(item) = first.and_then(|item| infer_simple_python_type(&item, imports, env, known_classes)) {
            return Some(format!("list<{}>", item));
        }
        return Some("list".to_string());
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(entry) = first {
            if let Some((key, value)) = split_once_top_level(&entry, ':') {
                let key_ty = infer_simple_python_type(&key, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
                let value_ty = infer_simple_python_type(&value, imports, env, known_classes).unwrap_or_else(|| "unknown".to_string());
                return Some(format!("dict<{},{}>", key_ty, value_ty));
            }
        }
        return Some("dict".to_string());
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(item) = first.and_then(|item| infer_simple_python_type(&item, imports, env, known_classes)) {
            return Some(format!("set<{}>", item));
        }
        return Some("set".to_string());
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(slot_key) = parse_static_index_slot_key(&index_expr) {
            if let Some(slot_ty) = precise_container_slot_type(env, &base, &slot_key) {
                return Some(slot_ty);
            }
        }
        if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
            if let Some(key) = parse_python_string_literal_content(&index_expr) {
                if let Some(field_ty) = env.project_index.typed_dict_key_type(&base_ty, &key) {
                    return Some(field_ty);
                }
            }
            if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                return Some(inner.to_string());
            }
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((_, value)) = split_once_top_level(inner, ',') {
                    return Some(value.trim().to_string());
                }
            }
            if let Some(elems) = parse_tuple_type_elements(&base_ty) {
                if let Ok(idx) = index_expr.trim().parse::<usize>() {
                    if idx < elems.len() {
                        return Some(elems[idx].clone());
                    }
                }
            }
            if let Some(ret_ty) = env.project_index.method_return(&base_ty, "__getitem__", 1) {
                return Some(ret_ty);
            }
            if base_ty.ends_with("request.args") || base_ty.ends_with("request.form") || base_ty.ends_with("request.headers") || base_ty.ends_with("request.values") || base_ty.ends_with("request.GET") || base_ty.ends_with("request.POST") || base_ty.ends_with("request.query_params") || base_ty.ends_with("request.cookies") || base_ty.ends_with("request.json") {
                return Some("str".to_string());
            }
        }
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let raw_args = split_top_level_commas(&arg_text);
        let args = split_python_call_args(&arg_text);
        let arg_types = args
            .iter()
            .map(|arg| infer_simple_python_type(arg, imports, env, known_classes))
            .collect::<Vec<_>>();
        if callee_text == "getattr" {
            if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
                return infer_simple_python_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes));
            }
        }
        if matches!(callee_text.as_str(), "field" | "dataclasses.field" | "Field" | "pydantic.Field" | "sqlmodel.Field" | "attr.ib" | "attr.field" | "attrs.field") {
            let default_factory = raw_args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                if name == "default_factory" || name == "factory" {
                    Some(value)
                } else {
                    None
                }
            });
            if let Some(factory) = default_factory {
                let factory = factory.trim();
                match factory {
                    "list" => return Some("list".to_string()),
                    "dict" => return Some("dict".to_string()),
                    "set" => return Some("set".to_string()),
                    "tuple" => return Some("tuple".to_string()),
                    _ => {}
                }
                if let Some(class_name) = resolve_known_class_name(factory, imports, env, known_classes) {
                    return Some(class_name);
                }
                if let Some(factory_ty) = resolve_dotted_type(factory, imports, env, known_classes) {
                    if env.project_index.class_exists(&factory_ty) {
                        return Some(factory_ty);
                    }
                }
            }
            if let Some(default_expr) = raw_args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "default").then_some(value)
            }) {
                if default_expr.trim() != "None" {
                    if let Some(default_ty) = infer_simple_python_type(&default_expr, imports, env, known_classes) {
                        return Some(default_ty);
                    }
                }
            }
        }
        let resolved_callee = resolve_imported_name(&callee_text, imports, env);
        if matches!(callee_text.as_str(), "Factory" | "attr.Factory" | "attrs.Factory") {
            if let Some(first) = args.get(0) {
                if let Some(ret) = infer_simple_python_type(first, imports, env, known_classes) {
                    return Some(ret);
                }
                if let Some(class_name) = resolve_known_class_name(first, imports, env, known_classes) {
                    return Some(class_name);
                }
            }
        }
        if matches!(callee_text.as_str(), "TypeVar" | "typing.TypeVar") {
            if let Some(bound_expr) = args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "bound").then_some(value)
            }) {
                if let Some(bound_ty) = infer_simple_python_type(&bound_expr, imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(&bound_expr, imports, env, known_classes))
                {
                    return Some(bound_ty);
                }
            }
            for arg in args.iter().skip(1) {
                if split_python_keyword_arg(arg).is_some() {
                    continue;
                }
                if let Some(ty) = infer_simple_python_type(arg, imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(arg, imports, env, known_classes))
                {
                    return Some(ty);
                }
            }
        }
        if matches!(callee_text.as_str(), "NewType" | "typing.NewType") {
            if let Some(base_expr) = args.get(1) {
                if let Some(base_ty) = infer_simple_python_type(base_expr, imports, env, known_classes)
                    .or_else(|| resolve_dotted_type(base_expr, imports, env, known_classes))
                {
                    return Some(base_ty);
                }
            }
        }
        let is_dependency_wrapper = matches!(callee_text.as_str(), "Depends" | "Security" | "Query" | "Path" | "Header" | "Cookie" | "Body" | "Form" | "File")
            || matches!(resolved_callee.as_deref(), Some("fastapi.Depends" | "fastapi.Security" | "fastapi.params.Depends" | "fastapi.params.Security" | "fastapi.Query" | "fastapi.Path" | "fastapi.Header" | "fastapi.Cookie" | "fastapi.Body" | "fastapi.Form" | "fastapi.File" | "fastapi.params.Query" | "fastapi.params.Path" | "fastapi.params.Header" | "fastapi.params.Cookie" | "fastapi.params.Body" | "fastapi.params.Form" | "fastapi.params.File"));
        if is_dependency_wrapper {
            if let Some(first) = args.get(0) {
                if let Some(callable_path) = infer_project_callable_value_type(first, imports, env, known_classes) {
                    if let Some(ret) = project_callable_return_from_type(&env.project_index, &callable_path, 0) {
                        return Some(ret);
                    }
                    if let Some(ty) = env.project_index.module_value_type_by_path(&callable_path) {
                        return Some(ty);
                    }
                    return Some(callable_path);
                }
                if first.trim() != "..." && first.trim() != "None" {
                    if let Some(default_ty) = infer_simple_python_type(first, imports, env, known_classes)
                        .or_else(|| resolve_dotted_type(first, imports, env, known_classes))
                    {
                        return Some(default_ty);
                    }
                }
            }
        }
        if matches!(callee_text.as_str(), "next" | "anext") {
            if let Some(first) = args.get(0) {
                return infer_iterable_item_type(first, imports, env, known_classes);
            }
        }
        if matches!(callee_text.as_str(), "iter" | "aiter" | "reversed") {
            if let Some(first) = args.get(0) {
                if let Some(base_ty) = infer_simple_python_type(first, imports, env, known_classes) {
                    let method = if callee_text == "aiter" { "__aiter__" } else { "__iter__" };
                    if let Some(ret) = env.project_index.method_return(&base_ty, method, 0) {
                        return Some(ret);
                    }
                }
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("generator<{}>", item));
            }
        }
        if matches!(callee_text.as_str(), "enumerate" | "zip" | "map" | "filter") {
            let item = infer_iterable_item_type(trimmed, imports, env, known_classes)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("generator<{}>", item));
        }
        if callee_text == "sorted" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "any" || callee_text == "all" {
            return Some("bool".to_string());
        }
        if let Some(module_path) = static_python_imported_module_path(trimmed, &env.current_module, imports, &env.project_index, Some(env)) {
            return Some(module_path);
        }
        if callee_text == "super" && args.is_empty() {
            return current_super_type(env);
        }
        if callee_text == "hasattr" || callee_text == "isinstance" || callee_text == "issubclass" || callee_text == "callable" {
            return Some("bool".to_string());
        }
        if (callee_text == "cast" || callee_text.ends_with(".cast")) && args.len() >= 2 {
            if let Some(ty) = normalize_runtime_type_name(args[0].trim(), imports, env, known_classes) {
                return Some(ty);
            }
        }
        if callee_text == "list" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "set" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("set<{}>", item));
            }
            return Some("set".to_string());
        }
        if callee_text == "tuple" {
            if let Some(first) = args.get(0) {
                let item = infer_iterable_item_type(first, imports, env, known_classes)
                    .or_else(|| infer_simple_python_type(first, imports, env, known_classes))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("tuple<{}>", item));
            }
            return Some("tuple".to_string());
        }
        if callee_text == "dict" {
            return Some("dict".to_string());
        }
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            let receiver_ty = resolve_dotted_type(&prefix, imports, env, known_classes);
            if method == "cursor" {
                if let Some(base_ty) = receiver_ty.clone() {
                    return Some(format!("{base_ty}.cursor"));
                }
            }
            if let Some(base_ty) = receiver_ty.clone() {
                if method == "get" || method == "pop" || method == "setdefault" {
                    if let Some(first_arg) = args.get(0) {
                        if let Some(key) = parse_python_string_literal_content(first_arg) {
                            if let Some(field_ty) = env.project_index.typed_dict_key_type(&base_ty, &key) {
                                return Some(field_ty);
                            }
                        }
                    }
                }
                if let Some(ret) = env.project_index.typed_dict_method_return_type(&base_ty, &method) {
                    return Some(ret);
                }
                if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                    if let Some((key, value)) = split_once_top_level(inner, ',') {
                        let key = key.trim();
                        let value = value.trim();
                        if method == "keys" {
                            return Some(format!("generator<{}>", key));
                        }
                        if method == "values" {
                            return Some(format!("generator<{}>", value));
                        }
                        if method == "items" {
                            return Some(format!("generator<tuple<{}|{}>>", key, value));
                        }
                    }
                }
                if env.project_index.module_exists(&base_ty) {
                    if let Some(member) = env.project_index.resolve_module_member(&base_ty, &method) {
                        if let Some(ret) = env.project_index.top_level_return(&member, arg_types.len()) {
                            return Some(ret);
                        }
                        if env.project_index.function_path_exists(&member) { return None; }
                        if let Some(ty) = env.project_index.module_value_type_by_path(&member) {
                            return Some(ty);
                        }
                        return (!env.project_index.function_path_exists(&member)).then_some(member);
                    }
                }
                if method == "get" || method == "pop" || method == "setdefault" {
                    if base_ty.ends_with("request.args") || base_ty.ends_with("request.form") || base_ty.ends_with("request.headers") || base_ty.ends_with("request.values") || base_ty.ends_with("request.GET") || base_ty.ends_with("request.POST") || base_ty.ends_with("request.query_params") || base_ty.ends_with("request.cookies") || base_ty.ends_with("request.json") {
                        return Some("str".to_string());
                    }
                    if method == "get" || method == "setdefault" || (method == "pop" && !base_ty.starts_with("list<")) {
                        if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                            if let Some(slot_ty) = precise_container_slot_type(env, &prefix, &slot_key) {
                                return Some(slot_ty);
                            }
                        }
                    }
                    if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                        if let Some((_, value)) = split_once_top_level(inner, ',') {
                            return Some(value.trim().to_string());
                        }
                    }
                }
                if method == "pop" {
                    if args.is_empty() {
                        if let Some(slot_key) = last_precise_list_slot(env, &prefix) {
                            if let Some(slot_ty) = precise_container_slot_type(env, &prefix, &slot_key) {
                                return Some(slot_ty);
                            }
                        }
                    } else if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                        if let Some(slot_ty) = precise_container_slot_type(env, &prefix, &slot_key) {
                            return Some(slot_ty);
                        }
                    }
                    if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                        return Some(inner.to_string());
                    }
                }
                if let Some(ret) = env.project_index.method_return(&base_ty, &method, arg_types.len()) {
                    return Some(ret);
                }
                if method == "append" {
                    return Some(base_ty);
                }
                if method == "copy" {
                    return Some(base_ty);
                }
                if method == "read" || method == "readline" {
                    return Some("str".to_string());
                }
                if method == "cursor" {
                    return Some(format!("{base_ty}.cursor"));
                }
                if method == "dumps" && base_ty == "json" {
                    return Some("str".to_string());
                }
            }
            if method == "connect" {
                if let Some(base_ty) = receiver_ty {
                    return Some(format!("{base_ty}.connection"));
                }
            }
        }
        if let Some(callee_ty) = resolve_dotted_type(&callee_text, imports, env, known_classes) {
            if env.project_index.class_exists(&callee_ty) {
                return Some(callee_ty);
            }
            // A field may itself hold a callable (including a nested closure
            // writeback). Resolve that callable's return rather than treating
            // the field path as an unknown method on the receiver class.
            if env.project_index.function_path_exists(&callee_ty) {
                if let Some(ret) = env.project_index.top_level_return(&callee_ty, arg_types.len()) {
                    return Some(ret);
                }
            }
        }
        if let Some(mapped) = env.callable_aliases.get(&callee_text).cloned() {
            if let Some(ret) = env.project_index.top_level_return(&mapped, arg_types.len()) {
                return Some(ret);
            }
            if env.project_index.function_path_exists(&mapped) { return None; }
            if let Some(ty) = env.project_index.module_value_type_by_path(&mapped) {
                return Some(ty);
            }
            return (!env.project_index.function_path_exists(&mapped)).then_some(mapped);
        }
        if let Some(mapped) = resolve_imported_name(&callee_text, imports, env) {
            if let Some(ret) = env.project_index.top_level_return(&mapped, arg_types.len()) {
                return Some(ret);
            }
            if env.project_index.function_path_exists(&mapped) { return None; }
            if let Some(ty) = env.project_index.module_value_type_by_path(&mapped) {
                return Some(ty);
            }
            return (!env.project_index.function_path_exists(&mapped)).then_some(mapped);
        }
        if let Some(class_name) = resolve_known_class_name(&callee_text, imports, env, known_classes) {
            return Some(class_name);
        }
        if let Some(class_name) = env.current_class.as_ref() {
            if !is_builtin_python_name(&callee_text) {
                if let Some(ret) = env.project_index.method_return(class_name, &callee_text, arg_types.len()) {
                    return Some(ret);
                }
                return Some(format!("{class_name}.{}#ret", callee_text));
            }
        }
        let current_function = format!("{}.{}", env.current_module, callee_text);
        if let Some(ret) = env.project_index.top_level_return(&current_function, arg_types.len()) {
            return Some(ret);
        }
        if callee_text == "str" {
            return Some("str".to_string());
        }
        if callee_text == "int" {
            return Some("int".to_string());
        }
        if callee_text == "bool" {
            return Some("bool".to_string());
        }
    }
    resolve_dotted_type(trimmed, imports, env, known_classes)
}

fn split_last_top_level_index(input: &str) -> Option<(String, String)> {
    let trimmed = input.trim();
    if !trimmed.ends_with(']') {
        return None;
    }
    let mut depth_paren = 0isize;
    let mut depth_brace = 0isize;
    let mut depth_bracket = 0isize;
    let mut in_string = false;
    let mut quote = '\0';
    for (idx, ch) in trimmed.char_indices().rev() {
        if in_string {
            if ch == quote {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => { in_string = true; quote = ch; }
            ']' => depth_bracket += 1,
            '[' => {
                depth_bracket -= 1;
                if depth_bracket == 0 {
                    let base = trimmed[..idx].trim();
                    let index = trimmed[idx + 1..trimmed.len() - 1].trim();
                    if !base.is_empty() && !index.is_empty() {
                        return Some((base.to_string(), index.to_string()));
                    }
                    return None;
                }
            }
            ')' => depth_paren += 1,
            '(' => depth_paren -= 1,
            '}' => depth_brace += 1,
            '{' => depth_brace -= 1,
            _ => {}
        }
        if depth_paren < 0 || depth_brace < 0 || depth_bracket < 0 {
            return None;
        }
    }
    None
}

fn split_once_top_level_str(input: &str, needle: &str, prefer_rightmost: bool) -> Option<(String, String)> {
    if needle.is_empty() {
        return None;
    }
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut in_string = false;
    let mut quote = '\0';
    let mut escape = false;
    let mut found = None;

    for (idx, ch) in input.char_indices() {
        if !in_string && paren == 0 && bracket == 0 && brace == 0 && input[idx..].starts_with(needle) {
            if !prefer_rightmost {
                let left = input[..idx].trim();
                let right = input[idx + needle.len()..].trim();
                return if left.is_empty() || right.is_empty() {
                    None
                } else {
                    Some((left.to_string(), right.to_string()))
                };
            }
            found = Some(idx);
        }
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            if ch == '\\' {
                escape = true;
                continue;
            }
            if ch == quote {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                in_string = true;
                quote = ch;
            }
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ => {}
        }
    }

    let idx = found?;
    let left = input[..idx].trim();
    let right = input[idx + needle.len()..].trim();
    if left.is_empty() || right.is_empty() {
        None
    } else {
        Some((left.to_string(), right.to_string()))
    }
}

fn parse_python_binary_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Option<Expr> {
    let trimmed = text.trim();
    if let Some(inner) = trimmed.strip_prefix("not ") {
        return Some(with_line_span(
            Expr::Unary {
                id: builder.alloc_expr_id(),
                op: UnaryOp::Not,
                expr: Box::new(parse_expr(builder, inner, imports, known_classes, env, line_no)),
                span: default_span(),
            },
            builder.file_id(),
            line_no,
        ));
    }
    for (needle, op) in [
        (" or ", BinaryOp::Or),
        (" and ", BinaryOp::And),
        ("==", BinaryOp::Eq),
        ("!=", BinaryOp::Ne),
        (">=", BinaryOp::Ge),
        ("<=", BinaryOp::Le),
        (" in ", BinaryOp::In),
        (">", BinaryOp::Gt),
        ("<", BinaryOp::Lt),
        (" + ", BinaryOp::Add),
        (" - ", BinaryOp::Sub),
        (" * ", BinaryOp::Mul),
        (" / ", BinaryOp::Div),
        (" % ", BinaryOp::Mod),
    ] {
        if let Some((lhs, rhs)) = split_once_top_level_str(trimmed, needle, true) {
            return Some(with_line_span(
                Expr::Binary {
                    id: builder.alloc_expr_id(),
                    op,
                    lhs: Box::new(parse_expr(builder, &lhs, imports, known_classes, env, line_no)),
                    rhs: Box::new(parse_expr(builder, &rhs, imports, known_classes, env, line_no)),
                    span: default_span(),
                },
                builder.file_id(),
                line_no,
            ));
        }
    }
    None
}

fn parse_lvalue(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> LValue {
    let trimmed = text.trim();
    if let Some((base, index)) = split_last_top_level_index(trimmed) {
        return LValue::Index {
            base: Box::new(parse_expr(builder, &base, imports, known_classes, env, line_no)),
            index: Box::new(parse_expr(builder, &index, imports, known_classes, env, line_no)),
        };
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, imports, known_classes, env, line_no)),
            field,
        }
    } else {
        let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
        LValue::Var(symbol)
    }
}

fn parse_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
    line_no: u32,
) -> Expr {
    let trimmed = text.trim();
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return parse_expr(builder, &synthetic, imports, known_classes, env, line_no);
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = parse_expr(builder, &synthetic, imports, known_classes, env, line_no);
            return with_line_span(wrap_expr_with_explicit_type(builder, expr, &path), builder.file_id(), line_no);
        }
        if resolve_dotted_type(&synthetic, imports, env, known_classes).is_some() {
            return parse_expr(builder, &synthetic, imports, known_classes, env, line_no);
        }
        if let Some(default_expr) = default_value {
            return parse_expr(builder, &default_expr, imports, known_classes, env, line_no);
        }
    }

    if let Some(inner) = trimmed.strip_prefix("await ") {
        return with_line_span(parse_expr(builder, inner, imports, known_classes, env, line_no), builder.file_id(), line_no);
    }
    if let Some(rest) = trimmed.strip_prefix("lambda") {
        let lambda_tail = rest.trim_start();
        let lambda_parts = split_once_top_level_str(lambda_tail, ":", false)
            .or_else(|| lambda_tail.strip_prefix(':').map(|body| (String::new(), body.trim().to_string())));
        if let Some((params_text, body_text)) = lambda_parts {
            let lambda_specs = parse_python_param_specs(&params_text);
            let mut lambda_env = env.clone();
            let outer_symbols = env
                .vars
                .iter()
                .map(|(name, symbol)| (*symbol, name.clone()))
                .collect::<HashMap<_, _>>();
            let mut params = Vec::new();
            let mut local_symbols = HashSet::new();
            for spec in lambda_specs {
                let symbol = builder.add_symbol(&spec.name, SymbolKind::Param);
                lambda_env.vars.insert(spec.name.clone(), symbol);
                local_symbols.insert(symbol);
                params.push(Param {
                    name: spec.name.clone(),
                    symbol,
                    ty: None,
                    kind: match spec.kind {
                        PyParamKind::Positional => ParamKind::Positional,
                        PyParamKind::VarArgs => ParamKind::VarArgs,
                        PyParamKind::KwArgs => ParamKind::KwArgs,
                    },
                    has_default: spec.has_default,
                    keyword_only: spec.keyword_only,
                    cpp: Default::default(),
                    span: span_from_line_range(builder.file_id(), line_no, line_no),
                });
            }
            let body_expr = parse_expr(builder, &body_text, imports, known_classes, &mut lambda_env, line_no);
            let mut seen = HashSet::new();
            let mut free_symbols = Vec::new();
            collect_free_lambda_symbols(&body_expr, &local_symbols, &outer_symbols, &mut seen, &mut free_symbols);
            let mut capture_map = HashMap::new();
            let mut captures = Vec::new();
            for (source_symbol, name) in free_symbols {
                let capture_symbol = builder.add_symbol(&name, SymbolKind::Param);
                capture_map.insert(source_symbol, capture_symbol);
                captures.push(LambdaCapture {
                    name: name.clone(),
                    source_symbol,
                    symbol: capture_symbol,
                    ty: infer_lambda_capture_type(builder, env, &name),
                    span: span_from_line_range(builder.file_id(), line_no, line_no),
                });
            }
            let body_expr = rewrite_lambda_capture_symbols(body_expr, &capture_map);
            let return_stmt_id = builder.alloc_stmt_id();
            let return_span = span_from_line_range(builder.file_id(), line_no, line_no);
            let body_block = build_py_block(
                builder,
                vec![Stmt::Return {
                    id: return_stmt_id,
                    value: Some(body_expr),
                    span: return_span,
                }],
                line_no,
                line_no,
            );
            return with_line_span(
                Expr::Lambda {
                    id: builder.alloc_expr_id(),
                    params,
                    captures,
                    body: body_block,
                    span: default_span(),
                },
                builder.file_id(),
                line_no,
            );
        }
    }
    if let Some(expr) = parse_python_binary_expr(builder, trimmed, imports, known_classes, env, line_no) {
        return expr;
    }
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return parse_expr(builder, &inner, imports, known_classes, env, line_no);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_env(builder, &mut comp_env, &target_text, item_ty.as_deref(), line_no, 0);
        let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line_no);
        let result = parse_expr(builder, &result_expr, imports, known_classes, &mut comp_env, line_no);
        return with_line_span(new_call(builder, "builtins.list_comp", None, vec![iterable, result]), builder.file_id(), line_no);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_env(builder, &mut comp_env, &target_text, item_ty.as_deref(), line_no, 1);
        let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line_no);
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key = parse_expr(builder, &key_text, imports, known_classes, &mut comp_env, line_no);
            let value = parse_expr(builder, &value_text, imports, known_classes, &mut comp_env, line_no);
            return with_line_span(new_call(builder, "builtins.dict_comp", None, vec![iterable, key, value]), builder.file_id(), line_no);
        }
        let result = parse_expr(builder, &result_expr, imports, known_classes, &mut comp_env, line_no);
        return with_line_span(new_call(builder, "builtins.set_comp", None, vec![iterable, result]), builder.file_id(), line_no);
    }
    if let Some((result_expr, target_text, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let mut comp_env = env.clone();
        let item_ty = infer_iterable_item_type(&iterable_text, imports, env, known_classes);
        bind_comprehension_target_env(builder, &mut comp_env, &target_text, item_ty.as_deref(), line_no, 3);
        let iterable = parse_expr(builder, &iterable_text, imports, known_classes, env, line_no);
        let result = parse_expr(builder, &result_expr, imports, known_classes, &mut comp_env, line_no);
        return with_line_span(new_call(builder, "builtins.gen_expr", None, vec![iterable, result]), builder.file_id(), line_no);
    }

    if is_string_literal(trimmed) {
        return new_string(builder, &trimmed[1..trimmed.len() - 1]);
    }
    if is_int_literal(trimmed) {
        return new_int(builder, trimmed.parse::<i64>().unwrap_or_default());
    }
    if trimmed == "True" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Bool(true),
            span: default_span(),
        };
    }
    if trimmed == "False" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Bool(false),
            span: default_span(),
        };
    }
    if trimmed == "None" {
        return Expr::Literal {
            id: builder.alloc_expr_id(),
            kind: uniflow_hir::LiteralKind::Null,
            span: default_span(),
        };
    }

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 || (items.len() == 1 && inner.trim_end().ends_with(',')) {
            let args = items
                .into_iter()
                .map(|arg| parse_expr(builder, &arg, imports, known_classes, env, line_no))
                .collect::<Vec<_>>();
            return with_line_span(new_call(builder, "builtins.tuple", None, args), builder.file_id(), line_no);
        }
    }

    if let Some(inner) = trimmed.strip_prefix('*') {
        return with_line_span(
            Expr::Unary {
                id: builder.alloc_expr_id(),
                op: UnaryOp::Deref,
                expr: Box::new(parse_expr(builder, inner, imports, known_classes, env, line_no)),
                span: default_span(),
            },
            builder.file_id(),
            line_no,
        );
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let arg_entries = parse_python_call_args_detailed(&arg_text);
        let arg_names = arg_entries.iter().map(|arg| arg.name.clone()).collect::<Vec<_>>();
        let args = arg_entries
            .iter()
            .map(|arg| parse_expr(builder, &arg.expr, imports, known_classes, env, line_no))
            .collect::<Vec<_>>();

        if callee_text == "getattr" {
            if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
                let base_expr = parse_expr(builder, &base, imports, known_classes, env, line_no);
                let expr = with_line_span(new_field_read(builder, base_expr, &field), builder.file_id(), line_no);
                if let Some(path) = infer_project_callable_value_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes) {
                    let expr = wrap_expr_with_explicit_type(builder, expr, &path);
                    return with_line_span(expr, builder.file_id(), line_no);
                }
                return expr;
            }
        }
        if (callee_text == "cast" || callee_text.ends_with(".cast")) && arg_entries.len() >= 2 {
            let value_expr = parse_expr(builder, &arg_entries[1].expr, imports, known_classes, env, line_no);
            if let Some(ty) = normalize_runtime_type_name(arg_entries[0].expr.trim(), imports, env, known_classes) {
                let expr = wrap_expr_with_explicit_type(builder, value_expr, &ty);
                return with_line_span(expr, builder.file_id(), line_no);
            }
            return value_expr;
        }
        if callee_text == "super" && arg_entries.is_empty() {
            if let (Some(base_name), Some(self_symbol)) = (current_super_type(env), env.self_symbol) {
                let self_expr = new_var_ref(builder, self_symbol);
                let expr = wrap_expr_with_explicit_type(builder, self_expr, &base_name);
                return with_line_span(expr, builder.file_id(), line_no);
            }
        }

        match callee_text.as_str() {
            "list" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.list", None, args, arg_names), builder.file_id(), line_no);
            }
            "tuple" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.tuple", None, args, arg_names), builder.file_id(), line_no);
            }
            "set" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.set", None, args, arg_names), builder.file_id(), line_no);
            }
            "dict" => {
                let mut dict_args = Vec::new();
                for (entry, value_expr) in arg_entries.iter().zip(args.into_iter()) {
                    if let Some(name) = entry.name.as_ref() {
                        dict_args.push(new_string(builder, name));
                        dict_args.push(value_expr);
                    } else {
                        dict_args.push(value_expr);
                    }
                }
                return with_line_span(new_call(builder, "builtins.dict", None, dict_args), builder.file_id(), line_no);
            }
            "iter" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.iter", None, args, arg_names), builder.file_id(), line_no);
            }
            "aiter" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.aiter", None, args, arg_names), builder.file_id(), line_no);
            }
            "next" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.next", None, args, arg_names), builder.file_id(), line_no);
            }
            "anext" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.anext", None, args, arg_names), builder.file_id(), line_no);
            }
            "reversed" => {
                return with_line_span(new_call_with_arg_names(builder, "builtins.reversed", None, args, arg_names), builder.file_id(), line_no);
            }
            _ => {}
        }

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if prefix == "super()" {
                let base_name = env.current_class_bases.first().cloned().unwrap_or_else(|| {
                    env.current_class.clone().unwrap_or_else(|| "super".to_string())
                });
                let receiver = env
                    .self_symbol
                    .map(|symbol| with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no));
                return with_line_span(
                    new_call_with_arg_names(builder, &format!("{base_name}.{method}"), receiver, args, arg_names),
                    builder.file_id(),
                    line_no,
                );
            }
            let receiver = parse_expr(builder, &prefix, imports, known_classes, env, line_no);
            let method_callee = if env.self_name.as_deref() == Some(prefix.as_str()) {
                if let Some(class_name) = env.current_class.as_ref() {
                    format!("{class_name}.{method}")
                } else {
                    format!("{prefix}.{method}")
                }
            } else if let Some(base_ty) = resolve_dotted_type(&prefix, imports, env, known_classes) {
                format!("{base_ty}.{method}")
            } else {
                format!("{prefix}.{method}")
            };
            if let Some(callable_value) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
                if callable_value != method_callee {
                    return with_line_span(
                        new_call_with_arg_names(builder, &callable_value, None, args, arg_names),
                        builder.file_id(),
                        line_no,
                    );
                }
            }
            return with_line_span(new_call_with_arg_names(builder, &method_callee, Some(receiver), args, arg_names), builder.file_id(), line_no);
        }

        if let Some(mapped) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
            let canonical = canonicalize_project_path(&env.project_index, &mapped);
            if env.project_index.class_exists(&canonical) {
                return with_line_span(
                    Expr::New {
                        id: builder.alloc_expr_id(),
                        type_name: canonical,
                        args,
                        span: default_span(),
                    },
                    builder.file_id(),
                    line_no,
                );
            }
            if env.vars.contains_key(&callee_text) && mapped.ends_with(".__call__") {
                let symbol = env.vars[&callee_text];
                let callee = new_var_ref(builder, symbol);
                return with_line_span(
                    new_dynamic_call_with_arg_names(builder, callee, None, args, arg_names),
                    builder.file_id(),
                    line_no,
                );
            }
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if let Some(mapped) = env.callable_aliases.get(&callee_text).cloned() {
            let canonical = canonicalize_project_path(&env.project_index, &mapped);
            if env.project_index.class_exists(&canonical) {
                return with_line_span(
                    Expr::New {
                        id: builder.alloc_expr_id(),
                        type_name: canonical,
                        args,
                        span: default_span(),
                    },
                    builder.file_id(),
                    line_no,
                );
            }
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if let Some(mapped) = resolve_imported_name(&callee_text, imports, env) {
            if known_classes.contains(callee_text.as_str())
                || mapped.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
                || env.project_index.class_exists(&canonicalize_project_path(&env.project_index, &mapped))
            {
                return with_line_span(
                    Expr::New {
                        id: builder.alloc_expr_id(),
                        type_name: canonicalize_project_path(&env.project_index, &mapped),
                        args,
                        span: default_span(),
                    },
                    builder.file_id(),
                    line_no,
                );
            }
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if let Some(class_name) = resolve_known_class_name(&callee_text, imports, env, known_classes) {
            return with_line_span(
                Expr::New {
                    id: builder.alloc_expr_id(),
                    type_name: class_name,
                    args,
                    span: default_span(),
                },
                builder.file_id(),
                line_no,
            );
        }

        if let Some(class_name) = env.current_class.as_ref() {
            if !is_builtin_python_name(&callee_text) {
                let receiver = env
                    .self_symbol
                    .map(|symbol| with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no));
                return with_line_span(
                    new_call_with_arg_names(builder, &format!("{class_name}.{callee_text}"), receiver, args, arg_names),
                    builder.file_id(),
                    line_no,
                );
            }
        }

        if let Some(callee_ty) = resolve_dotted_type(&callee_text, imports, env, known_classes) {
            if env.project_index.class_exists(&callee_ty) {
                return with_line_span(
                    Expr::New {
                        id: builder.alloc_expr_id(),
                        type_name: callee_ty,
                        args,
                        span: default_span(),
                    },
                    builder.file_id(),
                    line_no,
                );
            }
        }

        if let Some(symbol) = env.vars.get(&callee_text).copied() {
            let callee_expr = if let Some(path) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
                let callee_ref = new_var_ref(builder, symbol);
                with_line_span(wrap_expr_with_explicit_type(builder, callee_ref, &path), builder.file_id(), line_no)
            } else {
                with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no)
            };
            return with_line_span(
                new_dynamic_call_with_arg_names(builder, callee_expr, None, args, arg_names),
                builder.file_id(),
                line_no,
            );
        }

        if let Some(mapped) = infer_project_callable_value_type(&callee_text, imports, env, known_classes) {
            return with_line_span(new_call_with_arg_names(builder, &mapped, None, args, arg_names), builder.file_id(), line_no);
        }

        if !is_simple_ident(&callee_text) {
            let callee_expr = parse_expr(builder, &callee_text, imports, known_classes, env, line_no);
            return with_line_span(
                new_dynamic_call_with_arg_names(builder, callee_expr, None, args, arg_names),
                builder.file_id(),
                line_no,
            );
        }

        return with_line_span(new_call_with_arg_names(builder, &callee_text, None, args, arg_names), builder.file_id(), line_no);
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let args = split_top_level_commas(inner)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(|arg| parse_expr(builder, &arg, imports, known_classes, env, line_no))
            .collect::<Vec<_>>();
        return with_line_span(new_call(builder, "builtins.list", None, args), builder.file_id(), line_no);
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let mut args = Vec::new();
        for entry in split_top_level_commas(inner).into_iter().filter(|arg| !arg.trim().is_empty()) {
            if let Some((key, value)) = split_once_top_level(&entry, ':') {
                args.push(parse_expr(builder, &key, imports, known_classes, env, line_no));
                args.push(parse_expr(builder, &value, imports, known_classes, env, line_no));
            }
        }
        return with_line_span(new_call(builder, "builtins.dict", None, args), builder.file_id(), line_no);
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let args = split_top_level_commas(inner)
            .into_iter()
            .filter(|arg| !arg.trim().is_empty())
            .map(|arg| parse_expr(builder, &arg, imports, known_classes, env, line_no))
            .collect::<Vec<_>>();
        return with_line_span(new_call(builder, "builtins.set", None, args), builder.file_id(), line_no);
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(base_ty) = receiver_type_for_method(&base, "__getitem__", imports, env, known_classes) {
            if let Some(method_path) = project_method_static_path(&env.project_index, &base_ty, "__getitem__") {
                let receiver = parse_expr(builder, &base, imports, known_classes, env, line_no);
                let index = parse_expr(builder, &index_expr, imports, known_classes, env, line_no);
                let expr = with_line_span(
                    new_call(builder, &method_path, Some(receiver), vec![index]),
                    builder.file_id(),
                    line_no,
                );
                return expr;
            }
        }
        let expr = with_line_span(
            Expr::IndexRead {
                id: builder.alloc_expr_id(),
                base: Box::new(parse_expr(builder, &base, imports, known_classes, env, line_no)),
                index: Box::new(parse_expr(builder, &index_expr, imports, known_classes, env, line_no)),
                span: default_span(),
            },
            builder.file_id(),
            line_no,
        );
        return expr;
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        let base_expr = parse_expr(builder, &base, imports, known_classes, env, line_no);
        let expr = with_line_span(new_field_read(builder, base_expr, &field), builder.file_id(), line_no);
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return expr;
    }

    if let Some(symbol) = env.capturable_vars.get(trimmed).copied() {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = new_var_ref(builder, symbol);
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no);
    }

    if let Some(symbol) = env.vars.get(trimmed).copied() {
        if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
            let expr = new_var_ref(builder, symbol);
            let expr = wrap_expr_with_explicit_type(builder, expr, &path);
            return with_line_span(expr, builder.file_id(), line_no);
        }
        return with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no);
    }

    let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        env.types.insert(trimmed.to_string(), path.clone());
        let expr = new_var_ref(builder, symbol);
        let expr = wrap_expr_with_explicit_type(builder, expr, &path);
        return with_line_span(expr, builder.file_id(), line_no);
    }
    with_line_span(new_var_ref(builder, symbol), builder.file_id(), line_no)
}

fn parse_python_comprehension(text: &str, open: char, close: char) -> Option<(String, String, String)> {
    let trimmed = text.trim();
    if !trimmed.starts_with(open) || !trimmed.ends_with(close) {
        return None;
    }
    let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
    let (result_expr, tail) = split_once_top_level_str(inner, " for ", false)?;
    let (target_text, iterable_text) = split_once_top_level_str(&tail, " in ", false)?;
    if result_expr.trim().is_empty() || target_text.trim().is_empty() || iterable_text.trim().is_empty() {
        None
    } else {
        Some((result_expr, target_text, iterable_text))
    }
}


fn resolve_known_class_name(
    name: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    if let Some(mapped) = resolve_imported_name(name, imports, env) {
        return Some(mapped);
    }
    if let Some(unique) = env.project_index.resolve_simple_class(name) {
        return Some(unique);
    }
    if known_classes.contains(name) || name.chars().next().is_some_and(|ch| ch.is_ascii_uppercase()) {
        if let Some(in_module) = env.project_index.resolve_module_member(&env.current_module, name) {
            return Some(in_module);
        }
        return Some(name.to_string());
    }
    None
}

fn resolve_dotted_type(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return resolve_dotted_type(&inner, imports, env, known_classes);
    }
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return resolve_dotted_type(&synthetic, imports, env, known_classes);
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(ty) = resolve_dotted_type(&synthetic, imports, env, known_classes) {
            return Some(ty);
        }
        if let Some(default_expr) = default_value {
            return resolve_dotted_type(&default_expr, imports, env, known_classes);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return infer_simple_python_type(inner, imports, env, known_classes);
    }
    // Python conditional expressions carry values from both branches.  For
    // callable values retain a concrete lexical callable path; this is needed
    // for nested functions returned as first-class values.
    if let Some((then_expr, remainder)) = split_once_top_level_str(trimmed, " if ", false) {
        if let Some((_condition, else_expr)) = split_once_top_level_str(&remainder, " else ", false) {
            let then_ty = infer_simple_python_type(&then_expr, imports, env, known_classes);
            let else_ty = infer_simple_python_type(&else_expr, imports, env, known_classes);
            if let Some(else_ty) = else_ty {
                if env.project_index.function_path_exists(&else_ty)
                    || else_ty.starts_with(&format!("{}.", env.current_function))
                {
                    return Some(else_ty);
                }
                if then_ty.as_deref() == Some(else_ty.as_str()) {
                    return Some(else_ty);
                }
            }
            if let Some(then_ty) = then_ty {
                return Some(then_ty);
            }
        }
    }
    if trimmed == "super()" {
        return current_super_type(env);
    }
    if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
        return resolve_dotted_type(&synthetic_attr_expr_text(&base, &field), imports, env, known_classes);
    }
    if let Some(ty) = env.types.get(trimmed) {
        return Some(ty.clone());
    }
    if let Some(mapped) = resolve_imported_name(trimmed, imports, env) {
        if let Some(ty) = env.project_index.module_value_type_by_path(&mapped) {
            return Some(ty);
        }
        if !trimmed.contains('.')
            || env.project_index.class_exists(&mapped)
            || env.project_index.module_exists(&mapped)
            || env.project_index.function_path_exists(&mapped)
        {
            return Some(mapped);
        }
        // Prefix substitution for a dotted expression may denote a field,
        // not a declared symbol (for example `Service.repo`).
    }
    if let Some(prefixed) = resolve_prefixed_imported_name(trimmed, imports, env) {
        if let Some(ty) = env.project_index.module_value_type_by_path(&prefixed) {
            return Some(ty);
        }
        if env.project_index.class_exists(&prefixed)
            || env.project_index.module_exists(&prefixed)
            || env.project_index.function_path_exists(&prefixed)
        {
            return Some(prefixed);
        }
        // A prefixed imported path may still be an instance/class field such
        // as `Service.repo`; defer to field-sensitive resolution below.
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if (callee_text == "cast" || callee_text.ends_with(".cast")) && args.len() >= 2 {
            if let Some(ty) = normalize_runtime_type_name(args[0].trim(), imports, env, known_classes) {
                return Some(ty);
            }
        }
    }
    if let Some((base, _index)) = split_last_top_level_index(trimmed) {
        if let Some(base_ty) = infer_simple_python_type(&base, imports, env, known_classes)
            .or_else(|| resolve_dotted_type(&base, imports, env, known_classes))
        {
            if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                return Some(inner.to_string());
            }
            if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                if let Some((_, value)) = split_once_top_level(inner, ',') {
                    return Some(value.trim().to_string());
                }
            }
            if base_ty.ends_with("request.args") || base_ty.ends_with("request.form") || base_ty.ends_with("request.headers") || base_ty.ends_with("request.values") || base_ty.ends_with("request.GET") || base_ty.ends_with("request.POST") || base_ty.ends_with("request.query_params") || base_ty.ends_with("request.cookies") || base_ty.ends_with("request.json") {
                return Some("str".to_string());
            }
        }
    }
    if split_last_top_level_dot(trimmed).is_none() {
        if let Some(class_name) = resolve_known_class_name(trimmed, imports, env, known_classes) {
            return Some(class_name);
        }
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        if env.self_name.as_deref() == Some(base.as_str()) {
            if let Some(ty) = direct_env_field_access_type(env, &field) {
                return Some(ty);
            }
        }
        if let Some(ty) = direct_local_field_access_type(env, &base, &field) {
            return Some(ty);
        }
        if is_simple_ident(&base) {
            if let Some(root) = local_object_alias_root(env, &base) {
                if let Some(ty) = direct_local_field_access_type(env, &root, &field) {
                    return Some(ty);
                }
            }
        } else if let Some(canonical) = canonical_container_path(env, &base) {
            if let Some(ty) = direct_local_field_access_type(env, &canonical, &field) {
                return Some(ty);
            }
        }
        let base_ty = resolve_dotted_type(&base, imports, env, known_classes)?;
        if let Some(class_fields) = env.class_field_index.get(&base_ty) {
            if let Some(raw_ty) = class_fields.get(&field).cloned() {
                return descriptor_access_type(&env.project_index, &raw_ty).or(Some(raw_ty));
            }
        }
        if let Some(ty) = direct_field_access_type(&env.project_index, &base_ty, &field) {
            return Some(ty);
        }
        if env.project_index.module_exists(&base_ty) {
            if let Some(member) = env.project_index.resolve_module_member(&base_ty, &field) {
                if let Some(ty) = env.project_index.module_value_type_by_path(&member) {
                    return Some(ty);
                }
                return Some(member);
            }
        }
        return Some(format!("{base_ty}.{field}"));
    }
    None
}

fn base_is_self(base: &Expr, env: &PyEnv) -> bool {
    match base {
        Expr::VarRef { symbol, .. } => env.self_symbol == Some(*symbol),
        _ => false,
    }
}

fn is_simple_ident(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_builtin_python_name(name: &str) -> bool {
    matches!(
        name,
        "str" | "int" | "bool" | "float" | "list" | "dict" | "set" | "tuple" | "len" | "print" | "range" | "enumerate"
    )
}

fn with_line_span(expr: Expr, file_id: uniflow_hir::FileId, line_no: u32) -> Expr {
    let span = span_from_line_range(file_id, line_no, line_no);
    set_span(expr, span)
}

fn set_span(expr: Expr, span: Span) -> Expr {
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
        Expr::Conditional { id, cond, then_expr, else_expr, .. } => {
            Expr::Conditional { id, cond, then_expr, else_expr, span }
        }
        Expr::Assign { id, lhs, rhs, .. } => Expr::Assign { id, lhs, rhs, span },
        Expr::Interp { id, parts, .. } => Expr::Interp { id, parts, span },
        Expr::Collection { id, container, elements, .. } => {
            Expr::Collection { id, container, elements, span }
        }
        Expr::Range { id, low, high, exclusive, .. } => {
            Expr::Range { id, low, high, exclusive, span }
        }
        Expr::Opaque { id, text, .. } => Expr::Opaque { id, text, span },
        Expr::Unknown { id, .. } => Expr::Unknown { id, span },
    }
}
