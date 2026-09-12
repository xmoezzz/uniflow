fn infer_project_function_summary_lines_flat(
    lines: &[PyBodyLine],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
    nested_map: &HashMap<u32, PyFunctionText>,
    nested_summaries: &mut HashMap<String, ProjectFunctionSummary>,
    summary: &mut ProjectFunctionSummary,
    rebound_names: &mut HashSet<String>,
    generator_item: &mut Option<String>,
) -> bool {
    let mut idx = 0usize;
    while idx < lines.len() {
        let raw_line = &lines[idx];
        let line = raw_line.text.trim();
        if line.is_empty() || line.starts_with('#') {
            idx += 1;
            continue;
        }
        if let Some(nested) = nested_map.get(&raw_line.line_no) {
            let nested_summary = infer_project_function_summary_with_locals(
                nested,
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                Some(env),
            );
            let qualified_name = format!("{}.{}", env.current_function, nested.name);
            nested_summaries.insert(qualified_name.clone(), nested_summary.clone());
            let decorated_callable_ty = decorate_project_callable_type(
                nested,
                module_name,
                imports,
                index,
                &qualified_name,
            );
            env.types.insert(nested.name.clone(), decorated_callable_ty.clone());
            if let Some(path) = callable_path_from_type(index, &decorated_callable_ty)
                .or_else(|| index.function_path_exists(&qualified_name).then(|| qualified_name.clone()))
            {
                env.callable_aliases.insert(nested.name.clone(), path);
            }
            while idx < lines.len() && lines[idx].line_no <= nested.end_line {
                idx += 1;
            }
            continue;
        }
        if let Some(names) = parse_python_name_declaration(line, "global ") {
            for name in names {
                rebound_names.insert(name);
            }
        }
        if let Some(names) = parse_python_name_declaration(line, "nonlocal ") {
            for name in names {
                rebound_names.insert(name);
            }
        }

        if line.starts_with("if ") {
            let mut fallthrough_paths = Vec::new();
            let mut current_false_env = env.clone();
            let mut next_idx = idx;
            let mut cursor = idx;
            let mut saw_else = false;
            loop {
                let header = lines[cursor].text.trim();
                if header.starts_with("if ") || header.starts_with("elif ") {
                    let cond_text = header
                        .split_once(' ')
                        .map(|(_, rest)| rest)
                        .and_then(|rest| rest.strip_suffix(':'))
                        .map(|rest| rest.trim().to_string())
                        .unwrap_or_else(|| "True".to_string());
                    let body_start = cursor + 1;
                    let body_end = summary_find_nested_block_end(lines, body_start, lines[cursor].indent);
                    let mut branch_env = current_false_env.clone();
                    apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut branch_env);
                    let branch_live = infer_project_function_summary_lines_flat(
                        &lines[body_start..body_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut branch_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if branch_live {
                        fallthrough_paths.push(branch_env);
                    }
                    apply_runtime_condition_refinements(&cond_text, false, imports, known_classes, &mut current_false_env);
                    next_idx = body_end;
                    let Some(next_header_idx) = next_code_line(lines, body_end) else {
                        break;
                    };
                    if lines[next_header_idx].indent != raw_line.indent {
                        break;
                    }
                    let next_header = lines[next_header_idx].text.trim();
                    if next_header.starts_with("elif ") {
                        cursor = next_header_idx;
                        continue;
                    }
                    if next_header == "else:" {
                        let else_start = next_header_idx + 1;
                        let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                        let mut else_env = current_false_env.clone();
                        let else_live = infer_project_function_summary_lines_flat(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            current_class,
                            current_class_bases,
                            current_fields,
                            &mut else_env,
                            known_classes,
                            nested_map,
            nested_summaries,
                            summary,
                            rebound_names,
                            generator_item,
                        );
                        if else_live {
                            fallthrough_paths.push(else_env);
                        }
                        next_idx = else_end;
                        saw_else = true;
                    }
                    break;
                }
                break;
            }
            if !saw_else {
                fallthrough_paths.push(current_false_env);
            }
            if fallthrough_paths.is_empty() {
                return false;
            }
            *env = merge_py_env_paths(env, &fallthrough_paths);
            idx = next_idx;
            continue;
        }

        if line == "try:" {
            let base_env = env.clone();
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut try_env = base_env.clone();
            let try_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut try_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            let mut success_env = try_env.clone();
            let mut fallthrough_paths = Vec::new();
            if try_live {
                fallthrough_paths.push(try_env.clone());
            }
            let mut next_idx = body_end;
            let mut finally_header_idx = None;
            while let Some(header_idx) = next_code_line(lines, next_idx) {
                if lines[header_idx].indent != raw_line.indent {
                    break;
                }
                let header = lines[header_idx].text.trim();
                if header.starts_with("except") {
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
                    let catch_start = header_idx + 1;
                    let catch_end = summary_find_nested_block_end(lines, catch_start, raw_line.indent);
                    let mut catch_env = base_env.clone();
                    if let (Some(name), Some(ty_name)) = (
                        sym_text.as_deref().filter(|name| is_simple_ident(name)),
                        ty_text.as_deref().and_then(|name| {
                            qualify_type_name(&env.current_module, name, imports, Some(&env.project_index))
                                .or_else(|| qualify_type_name(&env.current_module, name, imports, None))
                        }),
                    ) {
                        catch_env.types.insert(name.to_string(), canonicalize_project_path(&env.project_index, &ty_name));
                    }
                    let catch_live = infer_project_function_summary_lines_flat(
                        &lines[catch_start..catch_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut catch_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if catch_live {
                        fallthrough_paths.push(catch_env);
                    }
                    next_idx = catch_end;
                    continue;
                }
                if header == "else:" {
                    let else_start = header_idx + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    if try_live {
                        let mut else_env = success_env.clone();
                        let else_live = infer_project_function_summary_lines_flat(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            current_class,
                            current_class_bases,
                            current_fields,
                            &mut else_env,
                            known_classes,
                            nested_map,
            nested_summaries,
                            summary,
                            rebound_names,
                            generator_item,
                        );
                        if else_live {
                            success_env = else_env;
                            if let Some(first) = fallthrough_paths.first_mut() {
                                *first = success_env.clone();
                            }
                        } else if !fallthrough_paths.is_empty() {
                            fallthrough_paths.remove(0);
                        }
                    }
                    next_idx = else_end;
                    continue;
                }
                if header == "finally:" {
                    finally_header_idx = Some(header_idx);
                    break;
                }
                break;
            }
            if let Some(finally_idx) = finally_header_idx {
                let finally_start = finally_idx + 1;
                let finally_end = summary_find_nested_block_end(lines, finally_start, raw_line.indent);
                let incoming_live = !fallthrough_paths.is_empty();
                let mut finally_env = if incoming_live {
                    merge_py_env_paths(&base_env, &fallthrough_paths)
                } else {
                    base_env.clone()
                };
                let finally_live = infer_project_function_summary_lines_flat(
                    &lines[finally_start..finally_end],
                    module_name,
                    imports,
                    index,
                    current_class,
                    current_class_bases,
                    current_fields,
                    &mut finally_env,
                    known_classes,
                    nested_map,
            nested_summaries,
                    summary,
                    rebound_names,
                    generator_item,
                );
                idx = finally_end;
                if incoming_live && finally_live {
                    *env = finally_env;
                    continue;
                }
                return false;
            }
            idx = next_idx;
            if fallthrough_paths.is_empty() {
                return false;
            }
            *env = merge_py_env_paths(&base_env, &fallthrough_paths);
            continue;
        }

        if line.starts_with("for ") || line.starts_with("async for ") {
            let header = line.strip_prefix("async ").unwrap_or(line);
            let rest = header
                .strip_prefix("for ")
                .and_then(|value| value.strip_suffix(':'))
                .map(|value| value.trim().to_string())
                .unwrap_or_default();
            let (target_text, iterable_text) = split_once_top_level_str(&rest, " in ", false)
                .unwrap_or_else(|| ("item".to_string(), rest));
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut loop_env = env.clone();
            bind_project_summary_loop_target(&target_text, &iterable_text, imports, &mut loop_env, known_classes);
            let loop_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut loop_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            let mut merged_paths = vec![env.clone()];
            if loop_live {
                merged_paths.push(loop_env);
            }
            let mut next_idx = body_end;
            if body_end < lines.len() {
                let next_header = lines[body_end].text.trim();
                if lines[body_end].indent == raw_line.indent && next_header == "else:" {
                    let else_start = body_end + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    let mut else_env = env.clone();
                    let else_live = infer_project_function_summary_lines_flat(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut else_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if else_live {
                        merged_paths.push(else_env);
                    }
                    next_idx = else_end;
                }
            }
            *env = merge_py_env_paths(env, &merged_paths);
            idx = next_idx;
            continue;
        }

        if line.starts_with("while ") {
            let cond_text = line
                .strip_prefix("while ")
                .and_then(|rest| rest.strip_suffix(':'))
                .map(|rest| rest.trim().to_string())
                .unwrap_or_else(|| "True".to_string());
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut loop_env = env.clone();
            apply_runtime_condition_refinements(&cond_text, true, imports, known_classes, &mut loop_env);
            let loop_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut loop_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            let mut merged_paths = vec![env.clone()];
            if loop_live {
                merged_paths.push(loop_env);
            }
            let mut next_idx = body_end;
            if body_end < lines.len() {
                let next_header = lines[body_end].text.trim();
                if lines[body_end].indent == raw_line.indent && next_header == "else:" {
                    let else_start = body_end + 1;
                    let else_end = summary_find_nested_block_end(lines, else_start, raw_line.indent);
                    let mut else_env = env.clone();
                    let else_live = infer_project_function_summary_lines_flat(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        current_class,
                        current_class_bases,
                        current_fields,
                        &mut else_env,
                        known_classes,
                        nested_map,
                        nested_summaries,
                        summary,
                        rebound_names,
                        generator_item,
                    );
                    if else_live {
                        merged_paths.push(else_env);
                    }
                    next_idx = else_end;
                }
            }
            *env = merge_py_env_paths(env, &merged_paths);
            idx = next_idx;
            continue;
        }

        if line.starts_with("with ") || line.starts_with("async with ") {
            let body_start = idx + 1;
            let body_end = summary_find_nested_block_end(lines, body_start, raw_line.indent);
            let mut with_env = env.clone();
            apply_project_summary_with_alias_bindings(line, imports, &mut with_env, known_classes);
            let with_live = infer_project_function_summary_lines_flat(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                current_class,
                current_class_bases,
                current_fields,
                &mut with_env,
                known_classes,
                nested_map,
                nested_summaries,
                summary,
                rebound_names,
                generator_item,
            );
            if !with_live {
                return false;
            }
            *env = with_env;
            idx = body_end;
            continue;
        }

        if let Some(rest) = line.strip_prefix("yield from ") {
            if let Some(ty) = infer_iterable_item_type(rest, imports, env, known_classes)
                .or_else(|| infer_simple_python_type(rest, imports, env, known_classes))
            {
                *generator_item = Some(merge_container_type(generator_item.as_deref(), &ty));
            }
            idx += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("yield ") {
            let ty = infer_simple_python_type(rest, imports, env, known_classes)
                .unwrap_or_else(|| "unknown".to_string());
            *generator_item = Some(merge_container_type(generator_item.as_deref(), &ty));
            idx += 1;
            continue;
        }
        if line == "yield" {
            *generator_item = Some(merge_container_type(generator_item.as_deref(), "unknown"));
            idx += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix("return ") {
            if generator_item.is_none() {
                if let Some(ty) = infer_simple_python_type(rest, imports, env, known_classes) {
                    summary.return_type = Some(merge_container_type(summary.return_type.as_deref(), &ty));
                }
            }
            return false;
        }
        if line == "return" {
            return false;
        }
        if line.starts_with("raise ") || line == "raise" || line == "break" || line == "continue" {
            return false;
        }
        if let Some((left, _)) = split_once_top_level(line, '=') {
            let normalized_left = synthetic_static_namespace_access_text(left.trim())
                .unwrap_or_else(|| left.trim().to_string());
            let target = normalized_left.trim();
            if is_simple_ident(target) && rebound_names.contains(target) {
                apply_project_summary_line_effects(line, imports, env, known_classes);
                if let Some(ty) = env.types.get(target).cloned() {
                    summary.writeback_types.insert(target.to_string(), ty);
                }
                if let Some(path) = env.callable_aliases.get(target).cloned() {
                    summary.writeback_callables.insert(target.to_string(), path);
                }
                idx += 1;
                continue;
            }
        }
        if let Some(rest) = line.strip_prefix("del ") {
            let mut captured = false;
            for target in split_top_level_commas(rest) {
                let target = target.trim();
                if is_simple_ident(target) && rebound_names.contains(target) {
                    captured = true;
                    summary.writeback_types.remove(target);
                    summary.writeback_callables.remove(target);
                }
            }
            if captured {
                apply_project_summary_line_effects(line, imports, env, known_classes);
                idx += 1;
                continue;
            }
        }
        apply_project_summary_line_effects(line, imports, env, known_classes);
        apply_direct_call_summary_effects(
            line,
            module_name,
            imports,
            index,
            env,
            known_classes,
            Some(nested_summaries),
        );
        idx += 1;
    }
    true
}

fn project_summary_writeback_heads(
    func: &PyFunctionText,
    env: &PyEnv,
    outer_env: Option<&PyEnv>,
    rebound_names: &HashSet<String>,
) -> HashSet<String> {
    let mut heads = rebound_names.clone();
    for spec in parse_python_param_specs(&func.params) {
        heads.insert(spec.name);
    }
    if let Some(self_name) = env.self_name.as_ref() {
        heads.insert(self_name.clone());
    }
    // Module globals and class objects referenced by a helper function are
    // externally visible roots. Writes such as `Service.repo = Repo` must be
    // replayed when the helper is called, even though Service is not a formal
    // parameter or an explicit global declaration.
    for (name, ty) in &env.types {
        let canonical = canonicalize_project_path(&env.project_index, ty);
        if env.project_index.class_exists(&canonical) || env.project_index.module_exists(&canonical) {
            heads.insert(name.clone());
        }
    }
    if let Some(outer) = outer_env {
        heads.extend(outer.types.keys().cloned());
        heads.extend(outer.callable_aliases.keys().cloned());
        heads.extend(outer.local_object_aliases.keys().cloned());
        heads.extend(outer.local_field_types.keys().filter(|name| is_simple_ident(name)).cloned());
        heads.extend(outer.precise_index_types.keys().filter(|name| is_simple_ident(name)).cloned());
        heads.extend(outer.precise_index_callables.keys().filter(|name| is_simple_ident(name)).cloned());
        if let Some(self_name) = outer.self_name.as_ref() {
            heads.insert(self_name.clone());
        }
    }
    heads
}

fn project_summary_root_head(root: &str) -> String {
    let trimmed = root.trim();
    if let Some((base, _)) = split_last_top_level_index(trimmed) {
        return project_summary_root_head(&base);
    }
    if let Some((base, _)) = split_last_top_level_dot(trimmed) {
        return project_summary_root_head(&base);
    }
    trimmed.to_string()
}

fn project_summary_root_is_writeback_candidate(root: &str, allowed_heads: &HashSet<String>) -> bool {
    let head = project_summary_root_head(root);
    !head.is_empty() && allowed_heads.contains(&head)
}

fn infer_project_function_summary_bundle_with_locals(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    outer_env: Option<&PyEnv>,
) -> (ProjectFunctionSummary, HashMap<String, ProjectFunctionSummary>) {
    let (mut env, known_classes) = seed_project_inference_env_with_outer(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        outer_env,
    );
    let mut summary = ProjectFunctionSummary::default();
    let mut nested_summaries: HashMap<String, ProjectFunctionSummary> = HashMap::new();
    let body_lines = collect_py_body_lines(&func.body, func.start_line + 1);
    let required_indent = current_body_indent(&body_lines);
    let nested_map = extract_functions_at_indent(&func.body, required_indent, func.start_line + 1)
        .into_iter()
        .map(|nested| (nested.start_line, nested))
        .collect::<HashMap<_, _>>();
    let mut rebound_names = HashSet::new();
    let mut generator_item: Option<String> = None;
    let _ = infer_project_function_summary_lines_flat(
        &body_lines,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        &mut env,
        &known_classes,
        &nested_map,
        &mut nested_summaries,
        &mut summary,
        &mut rebound_names,
        &mut generator_item,
    );
    let allowed_writeback_heads = project_summary_writeback_heads(func, &env, outer_env, &rebound_names);
    for (root, fields) in &env.local_field_types {
        if project_summary_root_is_writeback_candidate(root, &allowed_writeback_heads) {
            summary.local_field_writes.insert(root.clone(), fields.clone());
        }
    }
    // `self.field = ...` is stored in the dedicated field environment even for
    // decorator wrappers and other free functions whose first parameter is
    // conventionally named self. Preserve those writes in the call summary.
    if !env.field_types.is_empty() {
        if let Some(receiver_name) = parse_python_param_specs(&func.params)
            .first()
            .filter(|spec| spec.name == "self" || spec.name == "cls")
            .map(|spec| spec.name.clone())
        {
            summary
                .local_field_writes
                .entry(receiver_name)
                .or_default()
                .extend(env.field_types.clone());
        }
    }
    for (root, slots) in &env.precise_index_types {
        if project_summary_root_is_writeback_candidate(root, &allowed_writeback_heads) {
            summary.precise_index_type_writes.insert(root.clone(), slots.clone());
        }
    }
    for (root, slots) in &env.precise_index_callables {
        if project_summary_root_is_writeback_candidate(root, &allowed_writeback_heads) {
            summary.precise_index_callable_writes.insert(root.clone(), slots.clone());
        }
    }
    if let Some(item_ty) = generator_item {
        summary.return_type = Some(format!("generator<{}>", item_ty));
    }
    if let Some(annotation) = &func.return_annotation {
        let annotation = annotation.trim();
        let annotated = current_class
            .and_then(|class_name| {
                let lookup = split_project_instantiated_type(class_name)
                    .map(|(base, _)| base)
                    .unwrap_or_else(|| class_name.to_string());
                index
                    .class_type_params
                    .get(&lookup)
                    .is_some_and(|params| params.iter().any(|param| param == annotation))
                    .then(|| annotation.to_string())
            })
            .or_else(|| normalize_python_annotation_type(annotation, module_name, imports, Some(index)));
        if let Some(annotated) = annotated {
            summary.return_type = Some(substitute_self_type_in_type(
                &annotated,
                current_class.unwrap_or(&annotated),
            ));
        }
    }
    (summary, nested_summaries)
}

fn infer_project_function_summary_with_locals(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    outer_env: Option<&PyEnv>,
) -> ProjectFunctionSummary {
    infer_project_function_summary_bundle_with_locals(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        outer_env,
    )
    .0
}

fn infer_project_function_text_context_by_callable_path(
    callable_path: &str,
    index: &PyProjectIndex,
) -> Option<(PyFunctionText, String, Option<String>)> {
    if let Some(func) = index.top_level_function_text(callable_path) {
        let (owner_module, _) = callable_path.rsplit_once('.')?;
        return Some((func.clone(), owner_module.to_string(), None));
    }
    if let Some(func) = index.method_text(callable_path) {
        let (owner_class, _) = callable_path.rsplit_once('.')?;
        let (owner_module, _) = owner_class.rsplit_once('.')?;
        return Some((func.clone(), owner_module.to_string(), Some(owner_class.to_string())));
    }
    let mut owner_path = callable_path.to_string();
    while let Some((prefix, _)) = owner_path.rsplit_once('.') {
        owner_path = prefix.to_string();
        if let Some(owner) = index.top_level_function_text(&owner_path) {
            let (owner_module, _) = owner_path.rsplit_once('.')?;
            let body_lines = collect_py_body_lines(&owner.body, owner.start_line + 1);
            let required_indent = current_body_indent(&body_lines);
            for nested in extract_functions_at_indent(&owner.body, required_indent, owner.start_line + 1) {
                if format!("{owner_path}.{}", nested.name) == callable_path {
                    return Some((nested, owner_module.to_string(), None));
                }
            }
        }
        if let Some(owner) = index.method_text(&owner_path) {
            let (owner_class, _) = owner_path.rsplit_once('.')?;
            let (owner_module, _) = owner_class.rsplit_once('.')?;
            let body_lines = collect_py_body_lines(&owner.body, owner.start_line + 1);
            let required_indent = current_body_indent(&body_lines);
            for nested in extract_functions_at_indent(&owner.body, required_indent, owner.start_line + 1) {
                if format!("{owner_path}.{}", nested.name) == callable_path {
                    return Some((nested, owner_module.to_string(), Some(owner_class.to_string())));
                }
            }
        }
    }
    None
}

thread_local! {
    static IN_PROGRESS_SUMMARY_PATHS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
    static PROJECT_SUMMARY_DEPTH: Cell<usize> = const { Cell::new(0) };
}

// A path guard catches exact cycles. A bounded depth also protects against
// extremely wide indirect call chains or synthetic paths whose spelling does
// not canonicalize identically at every hop. The fallback is deliberately
// conservative: stop replaying effects for that path, rather than letting an
// untrusted source abort the entire process through stack exhaustion.
const MAX_PROJECT_SUMMARY_DEPTH: usize = 64;

/// Real Python call graphs are not acyclic: direct and mutual recursion are
/// common, and nothing upstream of this function tracks which callable paths
/// are already being summarized. Without this guard a recursive (or
/// mutually recursive) project function sends this straight back into
/// itself with no shrinking input, hanging forever instead of terminating.
struct SummaryPathGuard<'a> {
    path: &'a str,
}

impl<'a> SummaryPathGuard<'a> {
    fn enter(path: &'a str) -> Option<Self> {
        let inserted = IN_PROGRESS_SUMMARY_PATHS.with(|paths| {
            paths.borrow_mut().insert(path.to_string())
        });
        if !inserted {
            return None;
        }
        let within_budget = PROJECT_SUMMARY_DEPTH.with(|depth| {
            let current = depth.get();
            if current >= MAX_PROJECT_SUMMARY_DEPTH {
                false
            } else {
                depth.set(current + 1);
                true
            }
        });
        if within_budget {
            Some(Self { path })
        } else {
            IN_PROGRESS_SUMMARY_PATHS.with(|paths| {
                paths.borrow_mut().remove(path);
            });
            None
        }
    }
}

impl Drop for SummaryPathGuard<'_> {
    fn drop(&mut self) {
        IN_PROGRESS_SUMMARY_PATHS.with(|paths| {
            paths.borrow_mut().remove(self.path);
        });
        PROJECT_SUMMARY_DEPTH.with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

fn infer_project_summary_by_callable_path(
    callable_path: &str,
    index: &PyProjectIndex,
) -> Option<ProjectFunctionSummary> {
    let _guard = SummaryPathGuard::enter(callable_path)?;
    if let Some(func) = index.top_level_function_text(callable_path) {
        let (owner_module, _) = callable_path.rsplit_once('.')?;
        let imports = index.module_imports_for(owner_module)?;
        let (summary, nested) = infer_project_function_summary_bundle_with_locals(
            func,
            owner_module,
            imports,
            index,
            None,
            &[],
            &HashMap::new(),
            None,
        );
        return nested.get(callable_path).cloned().or(Some(summary));
    }
    if let Some(func) = index.method_text(callable_path) {
        let (owner_class, _) = callable_path.rsplit_once('.')?;
        let (owner_module, _) = owner_class.rsplit_once('.')?;
        let imports = index.module_imports_for(owner_module)?;
        let current_fields = index.field_types.get(owner_class).cloned().unwrap_or_default();
        let class_bases = index.class_bases.get(owner_class).cloned().unwrap_or_default();
        let (summary, nested) = infer_project_function_summary_bundle_with_locals(
            func,
            owner_module,
            imports,
            index,
            Some(owner_class),
            &class_bases,
            &current_fields,
            None,
        );
        return nested.get(callable_path).cloned().or(Some(summary));
    }
    let mut owner_path = callable_path.to_string();
    while let Some((prefix, _)) = owner_path.rsplit_once('.') {
        owner_path = prefix.to_string();
        if let Some(func) = index.top_level_function_text(&owner_path) {
            let (owner_module, _) = owner_path.rsplit_once('.')?;
            let imports = index.module_imports_for(owner_module)?;
            let (_, nested) = infer_project_function_summary_bundle_with_locals(
                func,
                owner_module,
                imports,
                index,
                None,
                &[],
                &HashMap::new(),
                None,
            );
            return nested.get(callable_path).cloned();
        }
        if let Some(func) = index.method_text(&owner_path) {
            let (owner_class, _) = owner_path.rsplit_once('.')?;
            let (owner_module, _) = owner_class.rsplit_once('.')?;
            let imports = index.module_imports_for(owner_module)?;
            let current_fields = index.field_types.get(owner_class).cloned().unwrap_or_default();
            let class_bases = index.class_bases.get(owner_class).cloned().unwrap_or_default();
            let (_, nested) = infer_project_function_summary_bundle_with_locals(
                func,
                owner_module,
                imports,
                index,
                Some(owner_class),
                &class_bases,
                &current_fields,
                None,
            );
            return nested.get(callable_path).cloned();
        }
    }
    None
}

fn infer_project_function_return_with_locals(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
) -> Option<String> {
    infer_project_function_summary_with_locals(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
        None,
    )
    .return_type
}

fn infer_project_top_level_return(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Option<String> {
    infer_project_function_return_with_locals(func, module_name, imports, index, None, &[], &HashMap::new())
}

fn infer_project_symbol_path(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains('[') || trimmed.contains('{') {
        return None;
    }
    if let Some(module_path) = static_python_imported_module_path(trimmed, module_name, imports, index, None) {
        return Some(module_path);
    }
    if trimmed.contains('(') {
        return None;
    }
    if let Some(mapped) = imports.aliases.get(trimmed) {
        return Some(canonicalize_project_path(index, mapped));
    }
    if let Some(prefixed) = canonicalize_prefixed_project_path(index, trimmed) {
        if prefixed != trimmed || index.module_exists(trimmed) || trimmed.contains('.') {
            return Some(prefixed);
        }
    }
    if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
        return Some(canonicalize_project_path(index, &in_module));
    }
    if let Some(unique) = index.resolve_simple_class(trimmed) {
        return Some(canonicalize_project_path(index, &unique));
    }
    if let Some(unique_fn) = index.resolve_simple_function(trimmed) {
        return Some(canonicalize_project_path(index, &unique_fn));
    }
    None
}

fn infer_project_callable_path(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Option<String> {
    let path = infer_project_symbol_path(text, module_name, imports, index)?;
    if index.function_path_exists(&path) {
        Some(index.resolve_canonical_member_path(&path, &mut HashSet::new()))
    } else {
        None
    }
}

fn receiver_type_for_method(
    base_text: &str,
    method: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    resolve_dotted_type(base_text, imports, env, known_classes)
        .or_else(|| env.project_index.unique_class_with_method(method))
        .or_else(|| {
            let base_name = base_text.trim().rsplit('.').next().unwrap_or(base_text.trim());
            let mut candidates = known_classes.iter().cloned().collect::<Vec<_>>();
            candidates.sort();
            candidates.dedup();
            let matched = candidates
                .iter()
                .find(|class_name| class_name.eq_ignore_ascii_case(base_name))
                .cloned()
                .or_else(|| (candidates.len() == 1).then(|| candidates[0].clone()))?;
            env.project_index
                .resolve_module_member(&env.current_module, &matched)
                .or_else(|| Some(format!("{}.{}", env.current_module, matched)))
        })
}

fn receiver_type_for_property_setter(
    base_text: &str,
    field: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    resolve_dotted_type(base_text, imports, env, known_classes)
        .or_else(|| env.project_index.unique_class_with_property_setter(field))
}

fn receiver_type_for_property_deleter(
    base_text: &str,
    field: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    resolve_dotted_type(base_text, imports, env, known_classes)
        .or_else(|| env.project_index.unique_class_with_property_deleter(field))
}

fn project_method_static_path(index: &PyProjectIndex, class_name: &str, method: &str) -> Option<String> {
    if let Some(path) = index.method_path(class_name, method) {
        return Some(path);
    }
    if index.class_has_method(class_name, method) {
        return Some(format!("{class_name}.{method}"));
    }
    let simple = class_name.rsplit('.').next().unwrap_or(class_name);
    if let Some(resolved) = index.resolve_simple_class(simple) {
        return Some(format!("{resolved}.{method}"));
    }
    let is_builtin_container_component = |component: &str| {
        let component = component.trim();
        let simple = component.rsplit('.').next().unwrap_or(component);
        matches!(simple, "list" | "dict" | "tuple" | "set" | "generator" | "str" | "bytes")
            || component.starts_with("list<")
            || component.starts_with("dict<")
            || component.starts_with("tuple<")
            || component.starts_with("set<")
            || component.starts_with("generator<")
    };
    let is_builtin_container = class_name.split('|').all(is_builtin_container_component);
    (!is_builtin_container).then(|| format!("{class_name}.{method}"))
}

fn callable_path_from_type(index: &PyProjectIndex, ty: &str) -> Option<String> {
    if index.function_path_exists(ty) {
        return Some(index.resolve_canonical_member_path(ty, &mut HashSet::new()));
    }
    index.method_path(ty, "__call__")
}

fn iterable_item_type_from_project_type(index: &PyProjectIndex, ty: &str, visited: &mut HashSet<String>) -> Option<String> {
    if !visited.insert(ty.to_string()) {
        return None;
    }
    if let Some(inner) = ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, _)) = split_once_top_level(inner, ',') {
            return Some(key.trim().to_string());
        }
    }
    if let Some(inner) = ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(items) = parse_tuple_type_elements(ty) {
        if items.len() == 1 {
            return items.first().cloned();
        }
    }
    if let Some(iter_ty) = index.method_return(ty, "__iter__", 0) {
        if let Some(item) = iterable_item_type_from_project_type(index, &iter_ty, visited) {
            return Some(item);
        }
        if let Some(next_ty) = index.method_return(&iter_ty, "__next__", 0) {
            return Some(next_ty);
        }
    }
    if let Some(next_ty) = index.method_return(ty, "__next__", 0) {
        return Some(next_ty);
    }
    if let Some(iter_ty) = index.method_return(ty, "__aiter__", 0) {
        if let Some(item) = iterable_item_type_from_project_type(index, &iter_ty, visited) {
            return Some(item);
        }
        if let Some(next_ty) = index.method_return(&iter_ty, "__anext__", 0) {
            return Some(next_ty);
        }
    }
    if let Some(next_ty) = index.method_return(ty, "__anext__", 0) {
        return Some(next_ty);
    }
    None
}

fn infer_project_callable_value_type(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return infer_project_callable_value_type(&inner, imports, env, known_classes);
    }
    if let Some(synthetic) = synthetic_static_namespace_access_text(trimmed) {
        return infer_project_callable_value_type(&synthetic, imports, env, known_classes)
            .or_else(|| env.project_index.module_symbol_alias(&env.current_module, &synthetic));
    }
    if let Some((synthetic, _kind, default_value)) = parse_static_namespace_method_call(trimmed) {
        if let Some(mapped) = infer_project_callable_value_type(&synthetic, imports, env, known_classes)
            .or_else(|| env.project_index.module_symbol_alias(&env.current_module, &synthetic))
        {
            return Some(mapped);
        }
        if let Some(default_expr) = default_value {
            return infer_project_callable_value_type(&default_expr, imports, env, known_classes);
        }
    }
    if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
        let synthetic = synthetic_attr_expr_text(&base, &field);
        if let Some(mapped) = infer_project_callable_value_type(&synthetic, imports, env, known_classes) {
            return Some(mapped);
        }
    }
    if let Some(path) = static_python_partial_target_path(trimmed, imports, env, known_classes) {
        return Some(path);
    }
    if let Some(mapped) = env.callable_aliases.get(trimmed) {
        return Some(mapped.clone());
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(slot_key) = parse_static_index_slot_key(&index_expr) {
            if let Some(mapped) = precise_container_slot_callable(env, &base, &slot_key) {
                return Some(mapped);
            }
        }
        if let Some(base_ty) = resolve_dotted_type(&base, imports, env, known_classes) {
            if let Some(ret_ty) = env.project_index.method_return(&base_ty, "__getitem__", 1) {
                if let Some(path) = callable_path_from_type(&env.project_index, &ret_ty) {
                    return Some(path);
                }
            }
        }
    }
    if parse_call_parts(trimmed).is_none() {
        if let Some(path) = infer_project_callable_path(trimmed, &env.current_module, imports, &env.project_index) {
            return Some(path);
        }
        if let Some(ty) = resolve_dotted_type(trimmed, imports, env, known_classes) {
            if env.project_index.function_path_exists(&ty) {
                return Some(env.project_index.resolve_canonical_member_path(&ty, &mut HashSet::new()));
            }
            if let Some(call_path) = env.project_index.method_path(&ty, "__call__") {
                return Some(call_path);
            }
        }
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if matches!(callee_text.as_str(), "next" | "anext") {
            if let Some(first) = args.get(0) {
                if let Some(item_ty) = infer_iterable_item_type(first, imports, env, known_classes) {
                    if let Some(path) = callable_path_from_type(&env.project_index, &item_ty) {
                        return Some(path);
                    }
                }
            }
        }
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if method == "pop" {
                if args.is_empty() {
                    if let Some(slot_key) = last_precise_list_slot(env, &prefix) {
                        if let Some(mapped) = precise_container_slot_callable(env, &prefix, &slot_key) {
                            return Some(mapped);
                        }
                    }
                } else if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                    if let Some(mapped) = precise_container_slot_callable(env, &prefix, &slot_key) {
                        return Some(mapped);
                    }
                }
            }
            if method == "get" || method == "setdefault" || method == "pop" {
                if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                    if let Some(mapped) = precise_container_slot_callable(env, &prefix, &slot_key) {
                        return Some(mapped);
                    }
                }
            }
            if let Some(base_ty) = resolve_dotted_type(&prefix, imports, env, known_classes) {
                if method == "pop" {
                    if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                        let candidate = inner.trim();
                        if env.project_index.function_path_exists(candidate) {
                            return Some(env.project_index.resolve_canonical_member_path(candidate, &mut HashSet::new()));
                        }
                    }
                }
                if method == "get" || method == "pop" || method == "setdefault" {
                    if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                        if let Some((_, value)) = split_once_top_level(inner, ',') {
                            let candidate = value.trim();
                            if env.project_index.function_path_exists(candidate) {
                                return Some(env.project_index.resolve_canonical_member_path(candidate, &mut HashSet::new()));
                            }
                        }
                    }
                }
            }
        }
    }

    // A call returns a value; its callee's symbol is not the identity of that
    // value. Only an actual inferred callable return may establish an alias.
    if parse_call_parts(trimmed).is_some() {
        return infer_simple_python_type(trimmed, imports, env, known_classes)
            .and_then(|ty| callable_path_from_type(&env.project_index, &ty));
    }
    if let Some((prefix, method)) = split_last_top_level_dot(trimmed) {
        let field_ty = if env.self_name.as_deref() == Some(prefix.as_str()) {
            direct_env_field_access_type(env, &method)
        } else {
            direct_local_field_access_type(env, &prefix, &method).or_else(|| {
                resolve_dotted_type(&prefix, imports, env, known_classes)
                    .and_then(|owner| direct_field_access_type(&env.project_index, &owner, &method))
            })
        };
        if let Some(field_ty) = field_ty {
            if let Some(path) = callable_path_from_type(&env.project_index, &field_ty) {
                return Some(path);
            }
        }
        let candidate = if prefix == "super()" {
            env.current_class_bases
                .first()
                .map(|base| format!("{base}.{method}"))
        } else if env.self_name.as_deref() == Some(prefix.as_str()) {
            env.current_class
                .as_ref()
                .map(|class_name| format!("{class_name}.{method}"))
        } else if let Some(base_ty) = resolve_dotted_type(&prefix, imports, env, known_classes) {
            Some(format!("{base_ty}.{method}"))
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if env.project_index.function_path_exists(&candidate) {
                return Some(env.project_index.resolve_canonical_member_path(&candidate, &mut HashSet::new()));
            }
            if let Some((owner, method)) = candidate.rsplit_once('.') {
                if let Some(path) = env.project_index.method_path(owner, method) {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn wrap_expr_with_explicit_type(builder: &mut ModuleBuilder, expr: Expr, ty_name: &str) -> Expr {
    Expr::Cast {
        id: builder.alloc_expr_id(),
        ty: Some(builder.ensure_type(ty_name)),
        expr: Box::new(expr),
        span: default_span(),
    }
}

fn infer_project_method_returns(
    class: &PyClassText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
) -> HashMap<String, String> {
    let current_class = qualify_class_name(module_name, &class.name, Some(index));
    let current_bases = class
        .bases
        .iter()
        .map(|base| qualify_type_name(module_name, base, imports, Some(index)).unwrap_or_else(|| base.clone()))
        .collect::<Vec<_>>();
    let mut returns = HashMap::new();
    for method in extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1) {
        let receiver_adjusted = !function_has_decorator(&method, "staticmethod");
        let arities = python_callable_arities(&parse_python_param_specs(&method.params), receiver_adjusted);
        let method_path = format!("{}.{}", current_class, method.name);
        let Some(_summary_guard) = SummaryPathGuard::enter(&method_path) else {
            continue;
        };
        let base_ty = infer_project_function_return_with_locals(
            &method,
            module_name,
            imports,
            index,
            Some(&current_class),
            &current_bases,
            current_fields,
        );
        let decorated_callable_ty = decorate_project_callable_type(&method, module_name, imports, index, &method_path);
        for arity in &arities {
            if let Some(ty) = project_callable_return_from_type(index, &decorated_callable_ty, *arity)
                .or_else(|| base_ty.clone())
            {
                let key = method_signature_key(&method.name, *arity);
                returns.entry(key).or_insert(ty);
            }
        }
    }
    returns
}
