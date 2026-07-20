fn merge_py_envs(base: &PyEnv, then_env: &PyEnv, else_env: Option<&PyEnv>) -> PyEnv {
    let mut out = base.clone();
    out.synthetic_functions = base.synthetic_functions.clone();
    for func in then_env.synthetic_functions.iter().chain(else_env.into_iter().flat_map(|env| env.synthetic_functions.iter())) {
        if !out.synthetic_functions.iter().any(|existing| existing.name == func.name) {
            out.synthetic_functions.push(func.clone());
        }
    }
    out.discovered_fields.extend(then_env.discovered_fields.clone());
    if let Some(other) = else_env {
        out.discovered_fields.extend(other.discovered_fields.clone());
    }

    if let Some(other) = else_env {
        let mut merged_vars = base.vars.clone();
        for (name, symbol) in then_env.vars.iter().chain(other.vars.iter()) {
            merged_vars.entry(name.clone()).or_insert(*symbol);
        }
        out.vars = merged_vars;
        let mut merged_caps = base.capturable_vars.clone();
        for (name, symbol) in then_env.capturable_vars.iter().chain(other.capturable_vars.iter()) {
            merged_caps.entry(name.clone()).or_insert(*symbol);
        }
        out.capturable_vars = merged_caps;

        let all_type_keys = then_env
            .types
            .keys()
            .chain(other.types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for key in all_type_keys {
            match (then_env.types.get(&key), other.types.get(&key)) {
                (Some(left), Some(right)) => {
                    out.types.insert(key.clone(), merge_container_type(Some(left.as_str()), right));
                }
                _ => {
                    out.types.remove(&key);
                }
            }
        }

        let all_callable_keys = then_env
            .callable_aliases
            .keys()
            .chain(other.callable_aliases.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for key in all_callable_keys {
            match (then_env.callable_aliases.get(&key), other.callable_aliases.get(&key)) {
                (Some(left), Some(right)) if left == right => {
                    out.callable_aliases.insert(key.clone(), left.clone());
                }
                _ => {
                    out.callable_aliases.remove(&key);
                }
            }
        }

        let all_field_keys = then_env
            .field_types
            .keys()
            .chain(other.field_types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for key in all_field_keys {
            match (then_env.field_types.get(&key), other.field_types.get(&key)) {
                (Some(left), Some(right)) => {
                    out.field_types.insert(key.clone(), merge_container_type(Some(left.as_str()), right));
                }
                _ => {
                    out.field_types.remove(&key);
                }
            }
        }

        let local_roots = then_env
            .local_field_types
            .keys()
            .chain(other.local_field_types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for root in local_roots {
            let left = then_env.local_field_types.get(&root);
            let right = other.local_field_types.get(&root);
            match (left, right) {
                (Some(left_fields), Some(right_fields)) => {
                    let mut merged = HashMap::new();
                    let field_names = left_fields
                        .keys()
                        .chain(right_fields.keys())
                        .cloned()
                        .collect::<HashSet<_>>();
                    for field in field_names {
                        if let (Some(left_ty), Some(right_ty)) = (left_fields.get(&field), right_fields.get(&field)) {
                            merged.insert(field.clone(), merge_container_type(Some(left_ty.as_str()), right_ty));
                        }
                    }
                    if merged.is_empty() {
                        out.local_field_types.remove(&root);
                    } else {
                        out.local_field_types.insert(root.clone(), merged);
                    }
                }
                _ => {
                    out.local_field_types.remove(&root);
                }
            }
        }

        let alias_names = then_env
            .local_object_aliases
            .keys()
            .chain(other.local_object_aliases.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for name in alias_names {
            match (then_env.local_object_aliases.get(&name), other.local_object_aliases.get(&name)) {
                (Some(left), Some(right)) if left == right => {
                    out.local_object_aliases.insert(name.clone(), left.clone());
                }
                _ => {
                    out.local_object_aliases.remove(&name);
                }
            }
        }

        let precise_roots = then_env
            .precise_index_types
            .keys()
            .chain(other.precise_index_types.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for root in precise_roots {
            let left = then_env.precise_index_types.get(&root);
            let right = other.precise_index_types.get(&root);
            match (left, right) {
                (Some(left_slots), Some(right_slots)) => {
                    let mut merged = HashMap::new();
                    let slot_names = left_slots
                        .keys()
                        .chain(right_slots.keys())
                        .cloned()
                        .collect::<HashSet<_>>();
                    for slot in slot_names {
                        if let (Some(left_ty), Some(right_ty)) = (left_slots.get(&slot), right_slots.get(&slot)) {
                            merged.insert(slot.clone(), merge_container_type(Some(left_ty.as_str()), right_ty));
                        }
                    }
                    if merged.is_empty() {
                        out.precise_index_types.remove(&root);
                    } else {
                        out.precise_index_types.insert(root.clone(), merged);
                    }
                }
                _ => {
                    out.precise_index_types.remove(&root);
                }
            }
        }

        let precise_callable_roots = then_env
            .precise_index_callables
            .keys()
            .chain(other.precise_index_callables.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for root in precise_callable_roots {
            let left = then_env.precise_index_callables.get(&root);
            let right = other.precise_index_callables.get(&root);
            match (left, right) {
                (Some(left_slots), Some(right_slots)) => {
                    let mut merged = HashMap::new();
                    let slot_names = left_slots
                        .keys()
                        .chain(right_slots.keys())
                        .cloned()
                        .collect::<HashSet<_>>();
                    for slot in slot_names {
                        if let (Some(left_path), Some(right_path)) = (left_slots.get(&slot), right_slots.get(&slot)) {
                            if left_path == right_path {
                                merged.insert(slot.clone(), left_path.clone());
                            }
                        }
                    }
                    if merged.is_empty() {
                        out.precise_index_callables.remove(&root);
                    } else {
                        out.precise_index_callables.insert(root.clone(), merged);
                    }
                }
                _ => {
                    out.precise_index_callables.remove(&root);
                }
            }
        }
    }
    out
}

fn merge_py_env_paths(base: &PyEnv, paths: &[PyEnv]) -> PyEnv {
    let mut iter = paths.iter();
    let Some(first) = iter.next() else {
        return base.clone();
    };
    let mut merged = first.clone();
    for path in iter {
        merged = merge_py_envs(base, &merged, Some(path));
    }
    merged
}

fn canonical_container_path(env: &PyEnv, receiver_text: &str) -> Option<String> {
    let receiver = receiver_text.trim();
    if receiver.is_empty() {
        return None;
    }
    if is_simple_ident(receiver) {
        return Some(env.local_object_aliases.get(receiver).cloned().unwrap_or_else(|| receiver.to_string()));
    }
    if let Some((base, field)) = split_last_top_level_dot(receiver) {
        let base_path = canonical_container_path(env, &base)?;
        return Some(format!("{base_path}.{field}"));
    }
    None
}

fn clear_precise_container_slots(env: &mut PyEnv, receiver_text: &str) {
    let receiver = receiver_text.trim();
    if receiver.is_empty() {
        return;
    }
    env.precise_index_types.remove(receiver);
    env.precise_index_callables.remove(receiver);
    if let Some(canonical) = canonical_container_path(env, receiver) {
        if canonical == receiver || receiver.contains('.') {
            env.precise_index_types.remove(&canonical);
            env.precise_index_callables.remove(&canonical);
        }
    }
}

fn update_precise_container_slot_type(env: &mut PyEnv, receiver_text: &str, slot_key: &str, ty: &str) {
    if ty.trim().is_empty() {
        return;
    }
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return;
    };
    let merged = merge_container_type(
        env.precise_index_types
            .get(&base)
            .and_then(|slots| slots.get(slot_key))
            .map(|value| value.as_str()),
        ty,
    );
    env.precise_index_types
        .entry(base)
        .or_default()
        .insert(slot_key.to_string(), merged);
}

fn update_precise_container_slot_callable(env: &mut PyEnv, receiver_text: &str, slot_key: &str, callable: Option<&str>) {
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return;
    };
    let slots = env.precise_index_callables.entry(base.clone()).or_default();
    if let Some(callable) = callable.filter(|value| !value.trim().is_empty()) {
        slots.insert(slot_key.to_string(), callable.to_string());
    } else {
        slots.remove(slot_key);
        if slots.is_empty() {
            env.precise_index_callables.remove(&base);
        }
    }
}

fn precise_container_slot_type(env: &PyEnv, receiver_text: &str, slot_key: &str) -> Option<String> {
    let base = canonical_container_path(env, receiver_text)?;
    env.precise_index_types
        .get(&base)
        .and_then(|slots| slots.get(slot_key))
        .cloned()
}

fn precise_container_slot_callable(env: &PyEnv, receiver_text: &str, slot_key: &str) -> Option<String> {
    let base = canonical_container_path(env, receiver_text)?;
    env.precise_index_callables
        .get(&base)
        .and_then(|slots| slots.get(slot_key))
        .cloned()
}

fn next_precise_list_slot(env: &PyEnv, receiver_text: &str) -> usize {
    let Some(base) = canonical_container_path(env, receiver_text) else {
        return 0;
    };
    let mut next = 0usize;
    if let Some(slots) = env.precise_index_types.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                next = next.max(value.saturating_add(1));
            }
        }
    }
    if let Some(slots) = env.precise_index_callables.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                next = next.max(value.saturating_add(1));
            }
        }
    }
    next
}

fn last_precise_list_slot(env: &PyEnv, receiver_text: &str) -> Option<String> {
    let base = canonical_container_path(env, receiver_text)?;
    let mut best: Option<usize> = None;
    if let Some(slots) = env.precise_index_types.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                best = Some(best.map(|current| current.max(value)).unwrap_or(value));
            }
        }
    }
    if let Some(slots) = env.precise_index_callables.get(&base) {
        for key in slots.keys() {
            if let Ok(value) = key.parse::<usize>() {
                best = Some(best.map(|current| current.max(value)).unwrap_or(value));
            }
        }
    }
    best.map(|value| value.to_string())
}

fn collect_precise_container_slots_from_expr(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Vec<(String, Option<String>, Option<String>)> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return split_top_level_commas(&trimmed[1..trimmed.len().saturating_sub(1)])
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .enumerate()
            .map(|(idx, item)| {
                let ty = infer_simple_python_type(&item, imports, env, known_classes);
                let callable = infer_project_callable_value_type(&item, imports, env, known_classes);
                (idx.to_string(), ty, callable)
            })
            .collect();
    }

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let items = split_top_level_commas(&trimmed[1..trimmed.len().saturating_sub(1)])
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if items.len() >= 2 {
            return items
                .into_iter()
                .enumerate()
                .map(|(idx, item)| {
                    let ty = infer_simple_python_type(&item, imports, env, known_classes);
                    let callable = infer_project_callable_value_type(&item, imports, env, known_classes);
                    (idx.to_string(), ty, callable)
                })
                .collect();
        }
    }

    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let mut out = Vec::new();
        for entry in split_top_level_commas(&trimmed[1..trimmed.len().saturating_sub(1)])
            .into_iter()
            .filter(|item| !item.trim().is_empty())
        {
            if let Some((key_text, value_text)) = split_once_top_level(&entry, ':') {
                if let Some(slot_key) = parse_static_index_slot_key(&key_text) {
                    let ty = infer_simple_python_type(&value_text, imports, env, known_classes);
                    let callable = infer_project_callable_value_type(&value_text, imports, env, known_classes);
                    out.push((slot_key, ty, callable));
                }
            }
        }
        return out;
    }

    if let Some(base) = canonical_container_path(env, trimmed) {
        let mut out = Vec::new();
        let mut keys = Vec::new();
        if let Some(slots) = env.precise_index_types.get(&base) {
            keys.extend(slots.keys().cloned());
        }
        if let Some(slots) = env.precise_index_callables.get(&base) {
            for key in slots.keys() {
                if !keys.iter().any(|existing| existing == key) {
                    keys.push(key.clone());
                }
            }
        }
        keys.sort();
        for key in keys {
            out.push((
                key.clone(),
                env.precise_index_types.get(&base).and_then(|slots| slots.get(&key)).cloned(),
                env.precise_index_callables.get(&base).and_then(|slots| slots.get(&key)).cloned(),
            ));
        }
        return out;
    }

    Vec::new()
}

fn populate_precise_container_slots_from_expr(
    env: &mut PyEnv,
    receiver_text: &str,
    text: &str,
    imports: &PyImports,
    known_classes: &HashSet<String>,
) {
    clear_precise_container_slots(env, receiver_text);
    for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(text, imports, env, known_classes) {
        if let Some(ty) = ty.as_deref() {
            update_precise_container_slot_type(env, receiver_text, &slot_key, ty);
        }
        update_precise_container_slot_callable(env, receiver_text, &slot_key, callable.as_deref());
    }
}

fn merge_container_type(existing: Option<&str>, incoming: &str) -> String {
    let incoming = incoming.trim();
    if incoming.is_empty() {
        return existing.unwrap_or("unknown").to_string();
    }
    let Some(current) = existing.map(|value| value.trim()).filter(|value| !value.is_empty()) else {
        return incoming.to_string();
    };
    if current == incoming {
        return current.to_string();
    }

    fn parse_unary_container<'a>(ty: &'a str, prefix: &str) -> Option<&'a str> {
        ty.strip_prefix(prefix).and_then(|rest| rest.strip_suffix('>'))
    }

    fn merge_atoms(left: &str, right: &str) -> String {
        let mut parts = left
            .split('|')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect::<Vec<_>>();
        for part in right.split('|').map(|part| part.trim()).filter(|part| !part.is_empty()) {
            if !parts.iter().any(|existing| existing == part) {
                parts.push(part.to_string());
            }
        }
        if parts.is_empty() {
            "unknown".to_string()
        } else if parts.len() == 1 {
            parts.remove(0)
        } else {
            parts.join("|")
        }
    }

    if let (Some(cur_inner), Some(new_inner)) = (
        parse_unary_container(current, "list<"),
        parse_unary_container(incoming, "list<"),
    ) {
        return format!("list<{}>", merge_atoms(cur_inner, new_inner));
    }
    if let (Some(cur_inner), Some(new_inner)) = (
        parse_unary_container(current, "set<"),
        parse_unary_container(incoming, "set<"),
    ) {
        return format!("set<{}>", merge_atoms(cur_inner, new_inner));
    }
    if let (Some(cur_inner), Some(new_inner)) = (
        parse_unary_container(current, "generator<"),
        parse_unary_container(incoming, "generator<"),
    ) {
        return format!("generator<{}>", merge_atoms(cur_inner, new_inner));
    }
    if let (Some(cur_inner), Some(new_inner)) = (
        current.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')),
        incoming.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')),
    ) {
        if let (Some((cur_key, cur_value)), Some((new_key, new_value))) = (
            split_once_top_level(cur_inner, ','),
            split_once_top_level(new_inner, ','),
        ) {
            return format!(
                "dict<{},{}>",
                merge_atoms(cur_key.trim(), new_key.trim()),
                merge_atoms(cur_value.trim(), new_value.trim())
            );
        }
    }
    merge_atoms(current, incoming)
}

fn update_container_receiver_type(
    env: &mut PyEnv,
    receiver_text: &str,
    ty: &str,
) {
    let receiver = receiver_text.trim();
    if receiver.is_empty() || ty.trim().is_empty() {
        return;
    }
    if is_simple_ident(receiver) {
        let merged = merge_container_type(env.types.get(receiver).map(|value| value.as_str()), ty);
        env.types.insert(receiver.to_string(), merged);
        return;
    }
    if let Some((base, field)) = split_last_top_level_dot(receiver) {
        if env.self_name.as_deref() == Some(base.as_str()) {
            let merged = merge_container_type(env.field_types.get(&field).map(|value| value.as_str()), ty);
            env.field_types.insert(field.clone(), merged.clone());
            if let Some(current_class) = env.current_class.clone() {
                env.class_field_index.entry(current_class).or_default().insert(field.clone(), merged.clone());
            }
            update_local_object_field_type(env, &base, &field, &merged);
        } else if is_simple_ident(&base) {
            let existing = env
                .local_field_types
                .get(&base)
                .and_then(|fields| fields.get(&field))
                .map(|value| value.as_str());
            let merged = merge_container_type(existing, ty);
            update_local_object_field_type(env, &base, &field, &merged);
        }
    }
}

fn apply_container_method_type_effects(
    line: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let Some((callee_text, arg_text)) = parse_call_parts(line.trim()) else {
        return;
    };
    let Some((receiver_text, method)) = split_last_top_level_dot(&callee_text) else {
        return;
    };
    let args = split_python_call_args(&arg_text);
    let receiver_existing = resolve_dotted_type(&receiver_text, imports, env, known_classes);
    match method.as_str() {
        "append" => {
            let Some(arg_text) = args.get(0) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            update_container_receiver_type(env, &receiver_text, &format!("list<{arg_ty}>"));
            let slot_key = next_precise_list_slot(env, &receiver_text).to_string();
            update_precise_container_slot_type(env, &receiver_text, &slot_key, &arg_ty);
            let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
            update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
        }
        "insert" => {
            let Some(arg_text) = args.get(1) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            update_container_receiver_type(env, &receiver_text, &format!("list<{arg_ty}>"));
            if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                update_precise_container_slot_type(env, &receiver_text, &slot_key, &arg_ty);
                let callable = infer_project_callable_value_type(arg_text, imports, env, known_classes);
                update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
            }
        }
        "extend" => {
            let Some(arg_text) = args.get(0) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            if let Some(inner) = arg_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("list<{}>", inner.trim()));
                let base = next_precise_list_slot(env, &receiver_text);
                let mut slots = collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes);
                slots.sort_by_key(|(key, _, _)| key.parse::<usize>().unwrap_or(usize::MAX));
                for (offset, (_, ty, callable)) in slots.into_iter().enumerate() {
                    let slot_key = (base + offset).to_string();
                    if let Some(ty) = ty.as_deref() {
                        update_precise_container_slot_type(env, &receiver_text, &slot_key, ty);
                    }
                    update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
                }
            } else if let Some(inner) = arg_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("set<{}>", inner.trim()));
            } else if let Some(inner) = arg_ty.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("list<{}>", inner.trim()));
            }
        }
        "update" => {
            let Some(arg_text) = args.get(0) else {
                return;
            };
            let Some(arg_ty) = infer_simple_python_type(arg_text, imports, env, known_classes) else {
                return;
            };
            if arg_ty.starts_with("dict<") {
                update_container_receiver_type(env, &receiver_text, &arg_ty);
                for (slot_key, ty, callable) in collect_precise_container_slots_from_expr(arg_text, imports, env, known_classes) {
                    if let Some(ty) = ty.as_deref() {
                        update_precise_container_slot_type(env, &receiver_text, &slot_key, ty);
                    }
                    update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
                }
            } else if let Some(inner) = arg_ty.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
                update_container_receiver_type(env, &receiver_text, &format!("set<{}>", inner.trim()));
            }
        }
        "setdefault" => {
            let key_ty = args
                .get(0)
                .and_then(|arg| infer_simple_python_type(arg, imports, env, known_classes))
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = args
                .get(1)
                .and_then(|arg| infer_simple_python_type(arg, imports, env, known_classes))
                .unwrap_or_else(|| receiver_existing
                    .as_deref()
                    .and_then(|ty| ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')))
                    .and_then(|inner| split_once_top_level(inner, ',').map(|(_, value)| value.trim().to_string()))
                    .unwrap_or_else(|| "unknown".to_string()));
            update_container_receiver_type(env, &receiver_text, &format!("dict<{},{}>", key_ty.trim(), value_ty.trim()));
            if let Some(slot_key) = args.get(0).and_then(|arg| parse_static_index_slot_key(arg)) {
                if precise_container_slot_type(env, &receiver_text, &slot_key).is_none() {
                    update_precise_container_slot_type(env, &receiver_text, &slot_key, &value_ty);
                    let callable = args
                        .get(1)
                        .and_then(|arg| infer_project_callable_value_type(arg, imports, env, known_classes));
                    update_precise_container_slot_callable(env, &receiver_text, &slot_key, callable.as_deref());
                }
            }
        }
        _ => {}
    }
}


