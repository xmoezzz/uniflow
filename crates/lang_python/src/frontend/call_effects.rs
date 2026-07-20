fn apply_project_summary_line_effects(
    line: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return;
    }
    if trimmed.starts_with("import ") || trimmed.starts_with("from ") {
        let module_name = env.current_module.clone();
        let index = env.project_index.clone();
        apply_project_module_import_line_effects(trimmed, &module_name, &index, env);
        return;
    }
    if parse_python_name_declaration(trimmed, "global ").is_some() || parse_python_name_declaration(trimmed, "nonlocal ").is_some() {
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
    if let Some(rest) = trimmed.strip_prefix("del ") {
        for raw_target in split_top_level_commas(rest) {
            let target = synthetic_static_namespace_access_text(raw_target.trim()).unwrap_or_else(|| raw_target.trim().to_string());
            clear_python_env_target_effects(&target, env);
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
    if let Some((left, right)) = split_once_top_level(trimmed, '=') {
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
                    if values.len() == destructured.len() {
                        for (target, value_text) in destructured.into_iter().zip(values.into_iter()) {
                            apply_python_env_assignment_effects(&target, &value_text, imports, env, known_classes);
                        }
                        return;
                    }
                }
                for target in destructured {
                    clear_python_env_target_effects(&target, env);
                }
                apply_python_expr_side_effects(right.trim(), imports, env, known_classes);
                return;
            }
            let normalized_left = synthetic_static_namespace_access_text(left.trim()).unwrap_or_else(|| left.trim().to_string());
            apply_python_env_assignment_effects(&normalized_left, right.trim(), imports, env, known_classes);
            return;
        }
    }
    apply_python_expr_side_effects(trimmed, imports, env, known_classes);
}

fn merge_project_summary_writebacks_into_env(summary: &ProjectFunctionSummary, env: &mut PyEnv) {
    for (name, ty) in &summary.writeback_types {
        env.types.insert(name.clone(), ty.clone());
    }
    for (name, path) in &summary.writeback_callables {
        env.callable_aliases.insert(name.clone(), path.clone());
    }
}

fn merge_project_summary_effects_into_env(summary: &ProjectFunctionSummary, env: &mut PyEnv) {
    merge_project_summary_writebacks_into_env(summary, env);
    for (root, fields) in &summary.local_field_writes {
        for (field, ty) in fields {
            if root == "self" || env.self_name.as_deref() == Some(root.as_str()) {
                env.field_types.insert(field.clone(), ty.clone());
                if let Some(current_class) = env.current_class.clone() {
                    env.class_field_index.entry(current_class).or_default().insert(field.clone(), ty.clone());
                }
                continue;
            }
            update_local_object_field_type(env, root, field, ty);
            if let Some(base_ty) = env.types.get(root).cloned() {
                let canonical = canonicalize_project_path(&env.project_index, &base_ty);
                if env.project_index.class_exists(&canonical) {
                    env.class_field_index.entry(canonical).or_default().insert(field.clone(), ty.clone());
                }
            }
        }
    }
    for (root, slots) in &summary.precise_index_type_writes {
        for (slot_key, ty) in slots {
            update_precise_container_slot_type(env, root, slot_key, ty);
        }
    }
    for (root, slots) in &summary.precise_index_callable_writes {
        for (slot_key, path) in slots {
            update_precise_container_slot_callable(env, root, slot_key, Some(path));
        }
    }
}

fn project_method_receiver_param_name(func: &PyFunctionText, owner_class: &str) -> Option<String> {
    if function_has_decorator(func, "staticmethod") {
        return None;
    }
    let specs = parse_python_param_specs(&func.params);
    let first = specs.first()?;
    if first.name == "self" || first.name == "cls" || function_has_decorator(func, "classmethod") {
        return Some(first.name.clone());
    }
    if owner_class.is_empty() {
        None
    } else {
        Some(first.name.clone())
    }
}

fn apply_receiver_summary_effects(
    receiver_text: &str,
    receiver_ty: &str,
    receiver_param: &str,
    summary: &ProjectFunctionSummary,
    env: &mut PyEnv,
) {
    let receiver = receiver_text.trim();
    if receiver.is_empty() {
        return;
    }
    for (root, fields) in &summary.local_field_writes {
        if root != receiver_param {
            continue;
        }
        for (field, ty) in fields {
            if is_simple_ident(receiver) {
                update_local_object_field_type(env, receiver, field, ty);
                let canonical = canonicalize_project_path(&env.project_index, receiver_ty);
                if env.project_index.class_exists(&canonical) {
                    env.class_field_index.entry(canonical).or_default().insert(field.clone(), ty.clone());
                }
            }
        }
    }
    for (root, slots) in &summary.precise_index_type_writes {
        if root != receiver_param {
            continue;
        }
        for (slot_key, ty) in slots {
            update_precise_container_slot_type(env, receiver, slot_key, ty);
        }
    }
    for (root, slots) in &summary.precise_index_callable_writes {
        if root != receiver_param {
            continue;
        }
        for (slot_key, path) in slots {
            update_precise_container_slot_callable(env, receiver, slot_key, Some(path));
        }
    }
}

fn bind_python_call_arguments(
    func: &PyFunctionText,
    bound_leading: Option<(&str, &str)>,
    arg_text: &str,
    env: &PyEnv,
) -> HashMap<String, String> {
    let specs = parse_python_param_specs(&func.params);
    let mut bindings = HashMap::new();
    let mut positional_specs: Vec<&PyParamSpec> = Vec::new();
    let mut keyword_specs: HashMap<String, &PyParamSpec> = HashMap::new();
    let mut varargs_name: Option<String> = None;
    let mut kwargs_name: Option<String> = None;
    let mut skip_first = false;
    if let Some((formal, actual)) = bound_leading {
        if let Some(first) = specs.first() {
            if first.name == formal {
                bindings.insert(formal.to_string(), actual.trim().to_string());
                skip_first = true;
            }
        }
    }
    for (idx, spec) in specs.iter().enumerate() {
        if skip_first && idx == 0 {
            continue;
        }
        match spec.kind {
            PyParamKind::Positional => {
                if !spec.keyword_only {
                    positional_specs.push(spec);
                }
                keyword_specs.insert(spec.name.clone(), spec);
            }
            PyParamKind::VarArgs => {
                varargs_name = Some(spec.name.clone());
                keyword_specs.insert(spec.name.clone(), spec);
            }
            PyParamKind::KwArgs => {
                kwargs_name = Some(spec.name.clone());
                keyword_specs.insert(spec.name.clone(), spec);
            }
        }
    }
    let mut positional_idx = 0usize;
    let mut pending_varargs = Vec::new();
    let mut pending_kwargs: Vec<(String, String)> = Vec::new();
    for arg in parse_python_call_args_detailed(arg_text) {
        if let Some(name) = arg.name {
            if let Some(spec) = keyword_specs.get(&name) {
                bindings.entry(spec.name.clone()).or_insert(arg.expr.trim().to_string());
            } else if kwargs_name.is_some() {
                pending_kwargs.push((name, arg.expr.trim().to_string()));
            }
            continue;
        }
        match arg.spread {
            PyCallArgSpread::Star => {
                if let Some(items) = parse_static_sequence_items(&arg.expr) {
                    for item in items {
                        while positional_idx < positional_specs.len() {
                            let spec = positional_specs[positional_idx];
                            positional_idx += 1;
                            if spec.kind == PyParamKind::Positional {
                                bindings.entry(spec.name.clone()).or_insert(item.trim().to_string());
                                break;
                            }
                        }
                    }
                } else if let Some(slots) = env.precise_index_types.get(arg.expr.trim()) {
                    let mut ordered = slots.iter().collect::<Vec<_>>();
                    ordered.sort_by_key(|(key, _)| key.parse::<usize>().unwrap_or(usize::MAX));
                    for (_, ty) in ordered {
                        while positional_idx < positional_specs.len() {
                            let spec = positional_specs[positional_idx];
                            positional_idx += 1;
                            if spec.kind == PyParamKind::Positional {
                                bindings.entry(spec.name.clone()).or_insert(format!("@type:{ty}"));
                                break;
                            }
                        }
                    }
                } else if let Some(tuple_ty) = env.types.get(arg.expr.trim()) {
                    if let Some(inner) = tuple_ty.strip_prefix("tuple<").and_then(|rest| rest.strip_suffix('>')) {
                        for ty in split_top_level_commas(inner) {
                            while positional_idx < positional_specs.len() {
                                let spec = positional_specs[positional_idx];
                                positional_idx += 1;
                                if spec.kind == PyParamKind::Positional {
                                    bindings.entry(spec.name.clone()).or_insert(format!("@type:{}", ty.trim()));
                                    break;
                                }
                            }
                        }
                    } else if varargs_name.is_some() {
                        pending_varargs.push(arg.expr.trim().to_string());
                    }
                } else if varargs_name.is_some() {
                    pending_varargs.push(arg.expr.trim().to_string());
                }
            }
            PyCallArgSpread::StarStar => {
                if let Some(entries) = parse_static_mapping_entries(&arg.expr) {
                    for (name, value) in entries {
                        if let Some(spec) = keyword_specs.get(&name) {
                            bindings.entry(spec.name.clone()).or_insert(value.trim().to_string());
                        } else if kwargs_name.is_some() {
                            pending_kwargs.push((name, value.trim().to_string()));
                        }
                    }
                } else if let Some(slots) = env.precise_index_types.get(arg.expr.trim()) {
                    for (name, ty) in slots {
                        if let Some(spec) = keyword_specs.get(name) {
                            bindings.entry(spec.name.clone()).or_insert(format!("@type:{ty}"));
                        }
                    }
                } else if let Some(kwargs_name) = kwargs_name.as_ref() {
                    bindings.entry(kwargs_name.clone()).or_insert(arg.expr.trim().to_string());
                }
            }
            PyCallArgSpread::None => {
                while positional_idx < positional_specs.len() {
                    let spec = positional_specs[positional_idx];
                    positional_idx += 1;
                    if spec.kind == PyParamKind::Positional {
                        bindings.entry(spec.name.clone()).or_insert(arg.expr.trim().to_string());
                        break;
                    }
                }
            }
        }
    }
    if let Some(varargs_name) = varargs_name {
        if !pending_varargs.is_empty() {
            bindings
                .entry(varargs_name)
                .or_insert(format!("tuple<{}>", pending_varargs.join("|")));
        }
    }
    if let Some(kwargs_name) = kwargs_name {
        if !pending_kwargs.is_empty() {
            let mut entries = Vec::new();
            for (name, value) in pending_kwargs {
                entries.push(format!("{name}:{value}"));
            }
            bindings
                .entry(kwargs_name)
                .or_insert(format!("dict<{}>", entries.join("|")));
        }
    }
    bindings
}

fn apply_bound_summary_effects(
    bindings: &HashMap<String, String>,
    summary: &ProjectFunctionSummary,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    for (formal, actual_expr) in bindings {
        let type_only = actual_expr.trim().strip_prefix("@type:").map(str::to_string);
        let actual = if type_only.is_some() {
            String::new()
        } else {
            synthetic_static_namespace_access_text(actual_expr)
                .unwrap_or_else(|| actual_expr.trim().to_string())
        };
        if actual.is_empty() && type_only.is_none() {
            continue;
        }
        let actual_ty = type_only.or_else(|| {
            infer_simple_python_type(&actual, imports, env, known_classes)
                .or_else(|| infer_project_expr_type(&actual, module_name, imports, index, &env.field_types, env.current_class.as_deref()))
        });
        for (root, fields) in &summary.local_field_writes {
            if root != formal {
                continue;
            }
            for (field, ty) in fields {
                if !actual.is_empty() {
                    update_local_object_field_type(env, &actual, field, ty);
                }
                if let Some(actual_ty) = actual_ty.as_deref() {
                    let canonical = canonicalize_project_path(index, actual_ty);
                    if index.class_exists(&canonical) {
                        env.class_field_index.entry(canonical).or_default().insert(field.clone(), ty.clone());
                    }
                }
            }
        }
        for (root, slots) in &summary.precise_index_type_writes {
            if root != formal {
                continue;
            }
            for (slot_key, ty) in slots {
                update_precise_container_slot_type(env, &actual, slot_key, ty);
            }
        }
        for (root, slots) in &summary.precise_index_callable_writes {
            if root != formal {
                continue;
            }
            for (slot_key, path) in slots {
                update_precise_container_slot_callable(env, &actual, slot_key, Some(path));
            }
        }
    }
}

fn decorated_summary_target_path_for_callable(
    func: &PyFunctionText,
    owner_module: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    base_path: &str,
) -> Option<String> {
    let base_canonical = canonicalize_project_path(index, base_path);
    let decorated_ty = decorate_project_callable_type(func, owner_module, imports, index, &base_canonical);
    let decorated_canonical = canonicalize_project_path(index, &decorated_ty);
    if decorated_canonical == base_canonical {
        return None;
    }
    if index.function_path_exists(&decorated_canonical)
        || index.method_text(&decorated_canonical).is_some()
        || index.top_level_function_text(&decorated_canonical).is_some()
        || infer_project_summary_by_callable_path(&decorated_canonical, index).is_some()
    {
        return Some(decorated_canonical);
    }
    if let Some(callable_path) = callable_path_from_type(index, &decorated_canonical) {
        let callable_canonical = canonicalize_project_path(index, &callable_path);
        if callable_canonical != base_canonical {
            return Some(callable_canonical);
        }
    }
    if index.class_exists(&decorated_canonical) {
        if let Some(call_path) = index.method_path(&decorated_canonical, "__call__") {
            return Some(call_path);
        }
    }
    None
}

fn replay_plain_project_method_summary_effects(
    method_path: &str,
    receiver_text: &str,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> Option<(PyFunctionText, String, PyImports)> {
    let func = index.method_text(method_path)?.clone();
    let (owner_class, _) = method_path.rsplit_once('.')?;
    let (owner_module, _) = owner_class.rsplit_once('.')?;
    let func_imports = index.module_imports_for(owner_module)?.clone();
    let current_fields = index.field_types.get(owner_class).cloned().unwrap_or_default();
    let class_bases = index.class_bases.get(owner_class).cloned().unwrap_or_default();
    let summary = infer_project_function_summary_with_locals(
        &func,
        owner_module,
        &func_imports,
        index,
        Some(owner_class),
        &class_bases,
        &current_fields,
        None,
    );
    merge_project_summary_writebacks_into_env(&summary, env);
    let receiver_param = project_method_receiver_param_name(&func, owner_class);
    if let Some(receiver_param) = receiver_param.as_deref() {
        let receiver_ty = infer_simple_python_type(receiver_text.trim(), caller_imports, env, caller_known_classes)
            .unwrap_or_else(|| env.types.get(receiver_text.trim()).cloned().unwrap_or_else(|| owner_class.to_string()));
        apply_receiver_summary_effects(receiver_text, &receiver_ty, receiver_param, &summary, env);
    }
    let bindings = bind_python_call_arguments(
        &func,
        receiver_param.as_deref().map(|formal| (formal, receiver_text)),
        arg_text,
        env,
    );
    apply_bound_summary_effects(
        &bindings,
        &summary,
        caller_module_name,
        caller_imports,
        index,
        env,
        caller_known_classes,
    );
    Some((func, owner_module.to_string(), func_imports))
}

fn replay_plain_top_level_function_summary_effects(
    function_path: &str,
    bound_leading: Option<(&str, &str)>,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> Option<(PyFunctionText, String, PyImports)> {
    let (func, owner_module, _owner_class) = infer_project_function_text_context_by_callable_path(function_path, index)?;
    let func_imports = index.module_imports_for(&owner_module)?.clone();
    let summary = infer_project_summary_by_callable_path(function_path, index)?;
    // Replay writes to module/class/closure roots as well as plain global or
    // nonlocal rebinding. Parameter-rooted effects are subsequently remapped
    // to actual arguments by `apply_bound_summary_effects`.
    merge_project_summary_effects_into_env(&summary, env);
    let bindings = bind_python_call_arguments(&func, bound_leading, arg_text, env);
    apply_bound_summary_effects(
        &bindings,
        &summary,
        caller_module_name,
        caller_imports,
        index,
        env,
        caller_known_classes,
    );
    Some((func, owner_module.to_string(), func_imports))
}

fn replay_project_method_summary_effects(
    method_path: &str,
    receiver_text: &str,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> bool {
    let Some((func, owner_module, func_imports)) = replay_plain_project_method_summary_effects(
        method_path,
        receiver_text,
        arg_text,
        caller_module_name,
        caller_imports,
        caller_known_classes,
        index,
        env,
    ) else {
        return false;
    };
    if let Some(wrapper_path) = decorated_summary_target_path_for_callable(&func, &owner_module, &func_imports, index, method_path) {
        if wrapper_path != canonicalize_project_path(index, method_path) {
            // A decorator commonly returns a lexically nested wrapper.  Such a
            // wrapper is not a top-level function entry, but its summary is
            // still available by lexical path and its `self` effects must be
            // rebound to the original method receiver.
            if index.method_text(&wrapper_path).is_none()
                && index.top_level_function_text(&wrapper_path).is_none()
            {
                if let Some(wrapper_summary) = infer_project_summary_by_callable_path(&wrapper_path, index) {
                    merge_project_summary_writebacks_into_env(&wrapper_summary, env);
                    let receiver_ty = infer_simple_python_type(receiver_text, caller_imports, env, caller_known_classes)
                        .unwrap_or_else(|| owner_module.clone());
                    apply_receiver_summary_effects(receiver_text, &receiver_ty, "self", &wrapper_summary, env);
                }
            }
            if index.method_text(&wrapper_path).is_some() {
                let _ = replay_plain_project_method_summary_effects(
                    &wrapper_path,
                    receiver_text,
                    arg_text,
                    caller_module_name,
                    caller_imports,
                    caller_known_classes,
                    index,
                    env,
                );
            } else {
                let wrapper_bound_leading = index
                    .top_level_function_text(&wrapper_path)
                    .and_then(|wrapper| parse_python_param_specs(&wrapper.params).first().cloned())
                    .and_then(|spec| (spec.name == "self" || spec.name == "cls").then(|| (spec.name.clone(), receiver_text.to_string())));
                let _ = replay_plain_top_level_function_summary_effects(
                    &wrapper_path,
                    wrapper_bound_leading.as_ref().map(|(formal, actual)| (formal.as_str(), actual.as_str())),
                    arg_text,
                    caller_module_name,
                    caller_imports,
                    caller_known_classes,
                    index,
                    env,
                );
            }
        }
    }
    true
}

fn replay_top_level_function_summary_effects(
    function_path: &str,
    arg_text: &str,
    caller_module_name: &str,
    caller_imports: &PyImports,
    caller_known_classes: &HashSet<String>,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) -> bool {
    let Some((func, owner_module, func_imports)) = replay_plain_top_level_function_summary_effects(
        function_path,
        None,
        arg_text,
        caller_module_name,
        caller_imports,
        caller_known_classes,
        index,
        env,
    ) else {
        return false;
    };
    if let Some(wrapper_path) = decorated_summary_target_path_for_callable(&func, &owner_module, &func_imports, index, function_path) {
        if wrapper_path != canonicalize_project_path(index, function_path) {
            if index.method_text(&wrapper_path).is_none() {
                let _ = replay_plain_top_level_function_summary_effects(
                &wrapper_path,
                None,
                arg_text,
                caller_module_name,
                caller_imports,
                caller_known_classes,
                index,
                env,
            );
            }
        }
    }
    true
}

fn replay_constructor_summary_effects(
    target_text: &str,
    constructed_type: &str,
    module_name: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let target = target_text.trim();
    if target.is_empty() || !is_simple_ident(target) {
        return;
    }
    let canonical_ty = canonicalize_project_path(&env.project_index, constructed_type);
    let Some(init_path) = env.project_index.method_path(&canonical_ty, "__init__") else {
        return;
    };
    let _ = replay_project_method_summary_effects(
        &init_path,
        target,
        "",
        module_name,
        imports,
        known_classes,
        &env.project_index.clone(),
        env,
    );
}

fn apply_direct_call_summary_effects(
    line: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
    nested_summaries: Option<&HashMap<String, ProjectFunctionSummary>>,
) {
    let Some((callee_text, _arg_text)) = parse_call_parts(line.trim()) else {
        return;
    };
    let callee = callee_text.trim();
    if callee.is_empty() {
        return;
    }

    let mut candidate = env
        .callable_aliases
        .get(callee)
        .cloned()
        .or_else(|| env.types.get(callee).and_then(|ty| callable_path_from_type(index, ty)));

    if candidate.is_none() {
        if let Some(nested) = nested_summaries {
            let direct_nested = format!("{}.{}", env.current_function, callee);
            if nested.contains_key(&direct_nested) {
                candidate = Some(direct_nested);
            }
        }
    }

    if candidate.is_none() {
        candidate = infer_project_symbol_path_in_env(callee, module_name, imports, index, env, known_classes);
    }

    let Some(path) = candidate else {
        return;
    };
    let canonical = canonicalize_project_path(index, &path);
    if canonical == env.current_function {
        return;
    }

    if let Some(nested) = nested_summaries.and_then(|items| items.get(&canonical).or_else(|| items.get(&path))) {
        merge_project_summary_effects_into_env(nested, env);
        return;
    }

    if let Some((receiver_text, _)) = split_last_top_level_dot(callee) {
        if replay_project_method_summary_effects(&canonical, &receiver_text, &_arg_text, module_name, imports, known_classes, index, env) {
            return;
        }
    }

    let _ = replay_top_level_function_summary_effects(
        &canonical,
        &_arg_text,
        module_name,
        imports,
        known_classes,
        index,
        env,
    );
}

