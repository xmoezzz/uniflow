fn local_object_alias_root(env: &PyEnv, name: &str) -> Option<String> {
    if !is_simple_ident(name) {
        return None;
    }
    let mut cur = name.trim().to_string();
    let mut seen = HashSet::new();
    while let Some(next) = env.local_object_aliases.get(&cur) {
        if !seen.insert(cur.clone()) || next == &cur {
            break;
        }
        cur = next.clone();
    }
    Some(cur)
}

fn propagate_local_object_alias(env: &mut PyEnv, target: &str, source_expr: &str) {
    let source = source_expr.trim();
    if !is_simple_ident(target) {
        return;
    }
    let source_root = if env.self_name.as_deref() == Some(source) {
        Some(source.to_string())
    } else {
        local_object_alias_root(env, source)
    };
    let Some(root) = source_root else {
        env.local_object_aliases.remove(target);
        env.local_field_types.remove(target);
        return;
    };
    env.local_object_aliases.insert(target.to_string(), root.clone());
    let field_map = env
        .local_field_types
        .get(source)
        .cloned()
        .or_else(|| env.local_field_types.get(&root).cloned())
        .or_else(|| {
            if env.self_name.as_deref() == Some(root.as_str()) {
                Some(env.field_types.clone())
            } else {
                None
            }
        });
    if let Some(fields) = field_map {
        env.local_field_types.insert(target.to_string(), fields);
    }
}

fn update_local_object_field_type(env: &mut PyEnv, base_name: &str, field: &str, ty: &str) {
    let base = base_name.trim();
    if base.is_empty() {
        return;
    }
    if !is_simple_ident(base) {
        // Keep both the source-level dotted root and its canonical object path.
        // Nested closure summaries may write through `holder.inner`, while a
        // later lookup canonicalizes the same receiver through its class type.
        env.local_field_types
            .entry(base.to_string())
            .or_default()
            .insert(field.to_string(), ty.to_string());
        if let Some(canonical) = canonical_container_path(env, base) {
            env.local_field_types
                .entry(canonical)
                .or_default()
                .insert(field.to_string(), ty.to_string());
        }
        return;
    }
    let root = local_object_alias_root(env, base).unwrap_or_else(|| base.to_string());
    let mut names = vec![base.to_string()];
    if root != base {
        names.push(root.clone());
    }
    for (alias, alias_root) in env.local_object_aliases.clone() {
        if alias_root == root && !names.iter().any(|name| name == &alias) {
            names.push(alias);
        }
    }
    for name in names {
        env.local_field_types
            .entry(name)
            .or_default()
            .insert(field.to_string(), ty.to_string());
    }
}


fn clear_local_object_field_type(env: &mut PyEnv, base_name: &str, field: &str) {
    let base = base_name.trim();
    if base.is_empty() {
        return;
    }
    if !is_simple_ident(base) {
        if let Some(canonical) = canonical_container_path(env, base) {
            let mut should_remove = false;
            if let Some(fields) = env.local_field_types.get_mut(&canonical) {
                fields.remove(field);
                should_remove = fields.is_empty();
            }
            if should_remove {
                env.local_field_types.remove(&canonical);
            }
        }
        return;
    }
    let root = local_object_alias_root(env, base).unwrap_or_else(|| base.to_string());
    let mut names = vec![base.to_string()];
    if root != base {
        names.push(root.clone());
    }
    for (alias, alias_root) in env.local_object_aliases.clone() {
        if alias_root == root && !names.iter().any(|name| name == &alias) {
            names.push(alias);
        }
    }
    for name in names {
        let mut should_remove = false;
        if let Some(fields) = env.local_field_types.get_mut(&name) {
            fields.remove(field);
            should_remove = fields.is_empty();
        }
        if should_remove {
            env.local_field_types.remove(&name);
        }
    }
}

fn strip_python_string_literal(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let quote = trimmed.chars().next()?;
    if (quote == '\'' || quote == '"') && trimmed.ends_with(quote) {
        return Some(trimmed[1..trimmed.len() - 1].to_string());
    }
    None
}

fn decode_python_string_literal(text: &str) -> Option<String> {
    let raw = strip_python_string_literal(text)?;
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('\'') => out.push('\''),
            Some('"') => out.push('"'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    Some(out)
}
fn parse_static_eval_expr_text(text: &str) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee = callee_text.trim();
    if callee != "eval" && callee != "builtins.eval" {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let decoded = decode_python_string_literal(args.get(0)?)?;
    let expr = decoded.trim();
    (!expr.is_empty()).then(|| expr.to_string())
}

fn parse_static_exec_body(text: &str) -> Option<Vec<String>> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee = callee_text.trim();
    if callee != "exec" && callee != "builtins.exec" {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let decoded = decode_python_string_literal(args.get(0)?)?;
    let lines = decoded
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    (!lines.is_empty()).then_some(lines)
}

fn parse_static_index_slot_key(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if let Some(value) = strip_python_string_literal(trimmed) {
        return Some(value);
    }
    if let Ok(value) = trimmed.parse::<i64>() {
        return Some(value.to_string());
    }
    None
}


fn parse_builtin_static_attr_call(text: &str, builtin_name: &str) -> Option<(String, String, Vec<String>)> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    if callee_text.trim() != builtin_name {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let base = args.get(0)?.trim().to_string();
    let field = args.get(1).and_then(|value| strip_python_string_literal(&value))?;
    Some((base, field, args))
}

fn synthetic_attr_expr_text(base: &str, field: &str) -> String {
    format!("{}.{}", base.trim(), field.trim())
}

fn synthetic_static_namespace_access_text(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let (base_text, index_text) = split_last_top_level_index(trimmed)?;
    let slot_key = parse_static_index_slot_key(&index_text)?;
    let base_trimmed = base_text.trim();
    if base_trimmed == "globals()" || base_trimmed == "locals()" {
        return Some(slot_key);
    }
    if let Some(owner) = base_trimmed.strip_suffix(".__dict__") {
        return Some(synthetic_attr_expr_text(owner, &slot_key));
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(base_trimmed) {
        if callee_text.trim() == "vars" {
            let args = split_python_call_args(&arg_text);
            if args.len() == 1 {
                return Some(synthetic_attr_expr_text(args[0].trim(), &slot_key));
            }
        }
    }
    None
}
 
fn static_namespace_update_target(base_text: &str, key: &str) -> Option<String> {
    let base_trimmed = base_text.trim();
    if base_trimmed == "globals()" || base_trimmed == "locals()" {
        return Some(key.to_string());
    }
    if let Some(owner) = base_trimmed.strip_suffix(".__dict__") {
        return Some(synthetic_attr_expr_text(owner, key));
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(base_trimmed) {
        if callee_text.trim() == "vars" {
            let args = split_python_call_args(&arg_text);
            if args.len() == 1 {
                return Some(synthetic_attr_expr_text(args[0].trim(), key));
            }
        }
    }
    None
}

fn parse_static_namespace_method_call(text: &str) -> Option<(String, StaticNamespaceMethodKind, Option<String>)> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let (receiver_text, method) = split_last_top_level_dot(callee_text.trim())?;
    let kind = match method.as_str() {
        "get" => StaticNamespaceMethodKind::Get,
        "pop" => StaticNamespaceMethodKind::Pop,
        "setdefault" => StaticNamespaceMethodKind::SetDefault,
        _ => return None,
    };
    let args = split_python_call_args(&arg_text);
    let key = args.get(0).and_then(|arg| strip_python_string_literal(arg))?;
    let target = static_namespace_update_target(&receiver_text, &key)?;
    let default_value = args.get(1).map(|value| value.trim().to_string());
    Some((target, kind, default_value))
}

fn parse_static_namespace_update_call(text: &str) -> Option<Vec<(String, String)>> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let (receiver_text, method) = split_last_top_level_dot(callee_text.trim())?;
    if method != "update" {
        return None;
    }
    let mut out = Vec::new();
    let mut push_entry = |key: String, value_text: String| {
        if let Some(target) = static_namespace_update_target(&receiver_text, &key) {
            out.push((target, value_text));
        }
    };
    for arg in parse_python_call_args_detailed(&arg_text) {
        let item = arg.expr.trim();
        if item.is_empty() {
            continue;
        }
        if let Some(name) = arg.name {
            push_entry(name, item.to_string());
            continue;
        }
        if let Some(entries) = parse_static_mapping_entries(item) {
            for (key, value_text) in entries {
                push_entry(key, value_text);
            }
            continue;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn context_manager_alias_type(
    expr_text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let manager_ty = infer_simple_python_type(expr_text, imports, env, known_classes)?;
    env.project_index
        .method_return(&manager_ty, "__aenter__", 0)
        .or_else(|| env.project_index.method_return(&manager_ty, "__enter__", 0))
        .or(Some(manager_ty))
}

fn parse_builtin_setattr_call(text: &str) -> Option<(String, String, String)> {
    let (base, field, args) = parse_builtin_static_attr_call(text, "setattr")?;
    let value = args.get(2)?.trim().to_string();
    Some((base, field, value))
}

fn parse_builtin_delattr_call(text: &str) -> Option<(String, String)> {
    let (base, field, _args) = parse_builtin_static_attr_call(text, "delattr")?;
    Some((base, field))
}


fn parse_builtin_type_guard_call(text: &str, builtin_name: &str) -> Option<(String, String)> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee = callee_text.trim();
    if callee != builtin_name && !callee.ends_with(&format!(".{builtin_name}")) {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let target = args.get(0)?.trim().to_string();
    let ty_text = args.get(1)?.trim();
    if ty_text.starts_with('(') && ty_text.ends_with(')') {
        return None;
    }
    let ty = strip_python_string_literal(ty_text).unwrap_or_else(|| ty_text.to_string());
    Some((target, ty))
}

fn normalize_runtime_type_name(
    type_text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = type_text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(class_name) = resolve_known_class_name(trimmed, imports, env, known_classes) {
        return Some(class_name);
    }
    if let Some(resolved) = resolve_dotted_type(trimmed, imports, env, known_classes) {
        return Some(resolved);
    }
    qualify_type_name(&env.current_module, trimmed, imports, Some(&env.project_index))
}

fn apply_refined_target_type(env: &mut PyEnv, target_text: &str, ty: &str) {
    let target = target_text.trim();
    if target.is_empty() {
        return;
    }
    if is_simple_ident(target) {
        env.types.insert(target.to_string(), ty.to_string());
        return;
    }
    if let Some((base_text, field)) = split_last_top_level_dot(target) {
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            env.field_types.insert(field.clone(), ty.to_string());
            if let Some(current_class) = env.current_class.clone() {
                env.class_field_index
                    .entry(current_class)
                    .or_default()
                    .insert(field, ty.to_string());
            }
            return;
        }
        if is_simple_ident(&base_text) {
            update_local_object_field_type(env, &base_text, &field, ty);
        }
    }
}

fn parse_runtime_type_identity_guard(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    for op in [" is ", " == "] {
        if let Some((left, right)) = split_once_top_level_str(trimmed, op, false) {
            if let Some(target) = left.trim().strip_prefix("type(").and_then(|rest| rest.strip_suffix(')')) {
                return Some((target.trim().to_string(), right.trim().to_string()));
            }
            if let Some(target) = right.trim().strip_prefix("type(").and_then(|rest| rest.strip_suffix(')')) {
                return Some((target.trim().to_string(), left.trim().to_string()));
            }
        }
    }
    None
}

fn apply_runtime_condition_refinements(
    cond_text: &str,
    positive: bool,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) {
    let trimmed = cond_text.trim();
    if trimmed.is_empty() {
        return;
    }
    if let Some(inner) = trimmed.strip_prefix("not ") {
        apply_runtime_condition_refinements(inner, !positive, imports, known_classes, env);
        return;
    }
    if positive {
        if let Some((left, right)) = split_once_top_level_str(trimmed, " and ", false) {
            apply_runtime_condition_refinements(&left, true, imports, known_classes, env);
            apply_runtime_condition_refinements(&right, true, imports, known_classes, env);
            return;
        }
    } else if let Some((left, right)) = split_once_top_level_str(trimmed, " or ", false) {
        apply_runtime_condition_refinements(&left, false, imports, known_classes, env);
        apply_runtime_condition_refinements(&right, false, imports, known_classes, env);
        return;
    }

    if positive {
        if let Some((target, ty_text)) = parse_runtime_type_identity_guard(trimmed) {
            if let Some(ty) = normalize_runtime_type_name(&ty_text, imports, env, known_classes) {
                apply_refined_target_type(env, &target, &ty);
            }
            return;
        }
        if let Some((target, ty_text)) = parse_builtin_type_guard_call(trimmed, "isinstance") {
            if let Some(ty) = normalize_runtime_type_name(&ty_text, imports, env, known_classes) {
                apply_refined_target_type(env, &target, &ty);
            }
            return;
        }
        if let Some((target, ty_text)) = parse_builtin_type_guard_call(trimmed, "issubclass") {
            if let Some(ty) = normalize_runtime_type_name(&ty_text, imports, env, known_classes) {
                apply_refined_target_type(env, &target, &ty);
            }
            return;
        }
        if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "hasattr") {
            let synthetic = synthetic_attr_expr_text(&base, &field);
            if let Some(ty) = resolve_dotted_type(&synthetic, imports, env, known_classes) {
                apply_refined_target_type(env, &synthetic, &ty);
            } else if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
                if let Some(field_ty) = env.project_index.field_type(&base_ty, &field) {
                    apply_refined_target_type(env, &synthetic, &field_ty);
                }
            }
        }
    }
}

fn infer_typing_alias_assignment_type(
    value: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let (callee, arg_text) = parse_call_parts(value.trim())?;
    let resolved = resolve_imported_name(&callee, imports, env).unwrap_or(callee);
    let raw_args = split_top_level_commas(&arg_text);
    if matches!(resolved.as_str(), "typing.NewType" | "NewType") {
        let base = raw_args.get(1)?.trim();
        return normalize_python_annotation_type(
            base,
            &env.current_module,
            imports,
            Some(&env.project_index),
        )
        .or_else(|| {
            matches!(base, "str" | "int" | "float" | "bool" | "bytes")
                .then(|| base.to_string())
        });
    }
    if matches!(resolved.as_str(), "typing.TypeVar" | "TypeVar") {
        if let Some(bound) = raw_args.iter().find_map(|arg| {
            let (name, value) = split_python_keyword_arg(arg)?;
            (name == "bound").then_some(value)
        }) {
            return normalize_python_annotation_type(
                &bound,
                &env.current_module,
                imports,
                Some(&env.project_index),
            );
        }
        for candidate in raw_args.iter().skip(1) {
            if split_python_keyword_arg(candidate).is_none() {
                if let Some(ty) = normalize_python_annotation_type(
                    candidate,
                    &env.current_module,
                    imports,
                    Some(&env.project_index),
                ) {
                    return Some(ty);
                }
            }
        }
    }
    let _ = known_classes;
    None
}

fn apply_python_env_assignment_effects(
    target_text: &str,
    value_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let target = target_text.trim();
    let value = value_text.trim();
    if target.is_empty() {
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    if is_simple_ident(target) {
        clear_precise_container_slots(env, target);
        if let Some(alias_ty) = infer_typing_alias_assignment_type(value, imports, env, known_classes) {
            env.callable_aliases.remove(target);
            env.types.insert(target.to_string(), alias_ty);
            env.local_object_aliases.remove(target);
            env.local_field_types.remove(target);
            return;
        }
        if let Some(path) = infer_project_callable_value_type(value, imports, env, known_classes) {
            env.callable_aliases.insert(target.to_string(), path);
        } else {
            env.callable_aliases.remove(target);
        }
        if is_simple_ident(value) {
            propagate_local_object_alias(env, target, value);
        } else {
            env.local_object_aliases.remove(target);
            env.local_field_types.remove(target);
        }
        let inferred_ty = infer_simple_python_type(value, imports, env, known_classes);
        if let Some(ty) = inferred_ty.clone() {
            env.types.insert(target.to_string(), ty.clone());
            if let Some((callee_text, _)) = parse_call_parts(value) {
                if let Some(callee_ty) = resolve_dotted_type(callee_text.trim(), imports, env, known_classes) {
                    let canonical_callee = canonicalize_project_path(&env.project_index, &callee_ty);
                    let canonical_ty = canonicalize_project_path(&env.project_index, &ty);
                    if canonical_callee == canonical_ty && env.project_index.class_exists(&canonical_ty) {
                        replay_constructor_summary_effects(target, &canonical_ty, &env.current_module.clone(), imports, env, known_classes);
                    }
                }
            }
        } else {
            env.types.remove(target);
        }
        populate_precise_container_slots_from_expr(env, target, value, imports, known_classes);
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    if let Some((base_text, field)) = split_last_top_level_dot(target) {
        clear_precise_container_slots(env, target);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
                env.field_types.insert(field.clone(), inferred.clone());
                if let Some(current_class) = env.current_class.clone() {
                    env.class_field_index.entry(current_class).or_default().insert(field, inferred);
                }
            } else {
                env.field_types.remove(&field);
            }
        } else if is_simple_ident(&base_text) {
            if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
                update_local_object_field_type(env, &base_text, &field, &inferred);

                // A namespace write through `vars(Class).update(...)` or
                // `Class.__dict__[name] = value` targets the class object, not
                // an instance stored in a local variable.  Resolve the base as
                // a known class even when it has no entry in `env.types`.
                let owner_class = env
                    .types
                    .get(&base_text)
                    .cloned()
                    .and_then(|base_ty| {
                        let canonical = canonicalize_project_path(&env.project_index, &base_ty);
                        env.project_index.class_exists(&canonical).then_some(canonical)
                    })
                    .or_else(|| resolve_known_class_name(&base_text, imports, env, known_classes));
                if let Some(owner_class) = owner_class {
                    env.class_field_index
                        .entry(owner_class)
                        .or_default()
                        .insert(field.clone(), inferred);
                }
            } else {
                clear_local_object_field_type(env, &base_text, &field);
            }
        } else {
            // Preserve writes through nested object paths such as
            // `holder.inner.cb = alt`. These are closure-visible heap effects
            // and must survive summary construction and replay.
            if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
                update_local_object_field_type(env, &base_text, &field, &inferred);
            } else {
                clear_local_object_field_type(env, &base_text, &field);
            }
        }
        populate_precise_container_slots_from_expr(env, target, value, imports, known_classes);
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    if let Some((base_text, index_text)) = split_last_top_level_index(target) {
        let slot_key = parse_static_index_slot_key(&index_text).unwrap_or_else(|| "*".to_string());
        if let Some(inferred) = infer_simple_python_type(value, imports, env, known_classes) {
            update_precise_container_slot_type(env, &base_text, &slot_key, &inferred);
            if let Some(base_ty) = env.types.get(base_text.trim()).cloned() {
                let merged = merge_container_type(Some(base_ty.as_str()), &inferred);
                env.types.insert(base_text.trim().to_string(), merged);
            }
        }
        let callable = infer_project_callable_value_type(value, imports, env, known_classes);
        update_precise_container_slot_callable(env, &base_text, &slot_key, callable.as_deref());
        apply_python_expr_side_effects(value, imports, env, known_classes);
        return;
    }

    apply_python_expr_side_effects(value, imports, env, known_classes);
}

fn clear_python_env_target_effects(target_text: &str, env: &mut PyEnv) {
    let target = target_text.trim();
    if target.is_empty() {
        return;
    }
    if is_simple_ident(target) {
        env.types.remove(target);
        env.callable_aliases.remove(target);
        env.local_object_aliases.remove(target);
        env.local_field_types.remove(target);
        clear_precise_container_slots(env, target);
        return;
    }
    if let Some((base_text, field)) = split_last_top_level_dot(target) {
        clear_precise_container_slots(env, target);
        if base_text == "self" || env.self_name.as_deref() == Some(base_text.as_str()) {
            env.field_types.remove(&field);
            if let Some(current_class) = env.current_class.clone() {
                if let Some(fields) = env.class_field_index.get_mut(&current_class) {
                    fields.remove(&field);
                }
            }
        } else if is_simple_ident(&base_text) {
            clear_local_object_field_type(env, &base_text, &field);
        }
        return;
    }
    if let Some((base_text, index_text)) = split_last_top_level_index(target) {
        if let Some(slot_key) = parse_static_index_slot_key(&index_text) {
            let base = canonical_container_path(env, &base_text).unwrap_or_else(|| base_text.trim().to_string());
            if let Some(slots) = env.precise_index_types.get_mut(&base) {
                slots.remove(&slot_key);
                if slots.is_empty() {
                    env.precise_index_types.remove(&base);
                }
            }
            if let Some(slots) = env.precise_index_callables.get_mut(&base) {
                slots.remove(&slot_key);
                if slots.is_empty() {
                    env.precise_index_callables.remove(&base);
                }
            }
        }
    }
}

fn apply_python_expr_side_effects(
    expr_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let trimmed = expr_text.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
        let module_name = env.current_module.clone();
        let index = env.project_index.clone();
        apply_project_module_import_line_effects(trimmed, &module_name, &index, env);
        return;
    }
    if let Some(lines) = parse_static_exec_body(trimmed) {
        for line in lines {
            apply_project_summary_line_effects(&line, imports, env, known_classes);
        }
        return;
    }
    if let Some(entries) = parse_static_namespace_update_call(trimmed) {
        for (target, value_text) in entries {
            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
        }
        return;
    }
    if let Some((base_text, field, value_text)) = parse_builtin_setattr_call(trimmed) {
        apply_python_env_assignment_effects(&synthetic_attr_expr_text(&base_text, &field), &value_text, imports, env, known_classes);
        return;
    }
    if let Some((base_text, field)) = parse_builtin_delattr_call(trimmed) {
        clear_python_env_target_effects(&synthetic_attr_expr_text(&base_text, &field), env);
        return;
    }
    if let Some((target, kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        match kind {
            StaticNamespaceMethodKind::Get => {}
            StaticNamespaceMethodKind::Pop => clear_python_env_target_effects(&target, env),
            StaticNamespaceMethodKind::SetDefault => {
                if !env.types.contains_key(&target) && !env.callable_aliases.contains_key(&target) {
                    if let Some(default_value) = default_value.as_deref() {
                        apply_python_env_assignment_effects(&target, default_value, imports, env, known_classes);
                    }
                }
            }
        }
        return;
    }

    if parse_call_parts(trimmed).is_some() {
        let module_name = env.current_module.clone();
        let index = env.project_index.clone();
        apply_direct_call_summary_effects(
            trimmed,
            &module_name,
            imports,
            &index,
            env,
            known_classes,
            None,
        );
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        if let Some((receiver_text, method)) = split_last_top_level_dot(callee_text.trim()) {
            let args = split_python_call_args(&arg_text);
            match method.as_str() {
                "append" => {
                    if let Some(arg_text) = args.get(0) {
                        if let Some(inferred) = infer_simple_python_type(arg_text, imports, env, known_classes) {
                            let merged = merge_container_type(env.types.get(receiver_text.trim()).map(|v| v.as_str()), &format!("list<{}>", inferred));
                            env.types.insert(receiver_text.trim().to_string(), merged);
                            let slot_key = next_precise_list_slot(env, receiver_text.trim()).to_string();
                            update_precise_container_slot_type(env, receiver_text.trim(), &slot_key, &inferred);
                        }
                        let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
                        let slot_key = next_precise_list_slot(env, receiver_text.trim()).to_string();
                        update_precise_container_slot_callable(env, receiver_text.trim(), &slot_key, callable.as_deref());
                    }
                }
                "insert" => {
                    if let (Some(index_text), Some(arg_text)) = (args.get(0), args.get(1)) {
                        let slot_key = parse_static_index_slot_key(index_text).unwrap_or_else(|| next_precise_list_slot(env, receiver_text.trim()).to_string());
                        if let Some(inferred) = infer_simple_python_type(arg_text, imports, env, known_classes) {
                            update_precise_container_slot_type(env, receiver_text.trim(), &slot_key, &inferred);
                        }
                        let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
                        update_precise_container_slot_callable(env, receiver_text.trim(), &slot_key, callable.as_deref());
                    }
                }
                "extend" => {
                    if let Some(arg_text) = args.get(0) {
                        for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes) {
                            if let Some(ty) = ty.as_deref() {
                                let next_key = if slot_key == "*" { next_precise_list_slot(env, receiver_text.trim()).to_string() } else { slot_key.clone() };
                                update_precise_container_slot_type(env, receiver_text.trim(), &next_key, ty);
                                update_precise_container_slot_callable(env, receiver_text.trim(), &next_key, callable.as_deref());
                            }
                        }
                        if let Some(item_ty) = infer_iterable_item_type(arg_text, imports, env, known_classes)
                            .or_else(|| infer_iterable_item_type(arg_text, imports, env, known_classes)) {
                            let merged = merge_container_type(env.types.get(receiver_text.trim()).map(|v| v.as_str()), &format!("list<{}>", item_ty));
                            env.types.insert(receiver_text.trim().to_string(), merged);
                        }
                    }
                }
                "update" => {
                    if let Some(arg_text) = args.get(0) {
                        for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes) {
                            if let Some(ty) = ty.as_deref() {
                                update_precise_container_slot_type(env, receiver_text.trim(), &slot_key, ty);
                            }
                            update_precise_container_slot_callable(env, receiver_text.trim(), &slot_key, callable.as_deref());
                        }
                    }
                }
                "setdefault" => {
                    if let Some(key_text) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                        if precise_container_slot_type(env, receiver_text.trim(), &key_text).is_none()
                            && precise_container_slot_callable(env, receiver_text.trim(), &key_text).is_none() {
                            if let Some(default_text) = args.get(1) {
                                if let Some(ty) = infer_simple_python_type(default_text, imports, env, known_classes) {
                                    update_precise_container_slot_type(env, receiver_text.trim(), &key_text, &ty);
                                }
                                let callable = infer_project_callable_value_type(default_text, imports, env, known_classes);
                                update_precise_container_slot_callable(env, receiver_text.trim(), &key_text, callable.as_deref());
                            }
                        }
                    }
                }
                "pop" => {
                    if let Some(key_text) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                        clear_python_env_target_effects(&format!("{}[{}]", receiver_text.trim(), key_text), env);
                    } else if let Some(last) = last_precise_list_slot(env, receiver_text.trim()) {
                        clear_python_env_target_effects(&format!("{}[{}]", receiver_text.trim(), last), env);
                    }
                }
                _ => {}
            }
        }
    }
}

