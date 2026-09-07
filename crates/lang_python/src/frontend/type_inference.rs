fn infer_project_callable_result_type_from_expr(
    callable_text: &str,
    arg_count: usize,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = callable_text.trim();
    if trimmed == "None" {
        return None;
    }
    if let Some(path) = infer_project_symbol_path(trimmed, module_name, imports, index) {
        if let Some(ret) = project_callable_return_from_type(index, &path, arg_count) {
            return Some(ret);
        }
    }
    let ty = infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class)?;
    project_callable_return_from_type(index, &ty, arg_count)
}

fn infer_simple_callable_result_type_from_expr(
    callable_text: &str,
    arg_count: usize,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = callable_text.trim();
    if trimmed == "None" {
        return None;
    }
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        if let Some(ret) = project_callable_return_from_type(&env.project_index, &path, arg_count) {
            return Some(ret);
        }
    }
    let ty = infer_simple_python_type(trimmed, imports, env, known_classes)?;
    project_callable_return_from_type(&env.project_index, &ty, arg_count)
}

fn infer_project_iterable_item_type(
    iterable_text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = iterable_text.trim();
    if trimmed.starts_with("range(") {
        return Some("int".to_string());
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let args = split_python_call_args(&arg_text);
        if callee_text == "enumerate" {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            let item_ty = infer_project_iterable_item_type(first_arg, module_name, imports, index, current_fields, current_class)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("tuple<int|{}>", item_ty));
        }
        if callee_text == "zip" {
            let item_types = args
                .iter()
                .filter(|arg| !arg.trim().is_empty())
                .filter_map(|arg| infer_project_iterable_item_type(arg, module_name, imports, index, current_fields, current_class))
                .collect::<Vec<_>>();
            if !item_types.is_empty() {
                return Some(format!("tuple<{}>", item_types.join("|")));
            }
        }
        if callee_text == "map" {
            let iterables = args.iter().skip(1).filter(|arg| !arg.trim().is_empty()).collect::<Vec<_>>();
            if !iterables.is_empty() {
                if let Some(ret) = infer_project_callable_result_type_from_expr(&args[0], iterables.len(), module_name, imports, index, current_fields, current_class) {
                    return Some(ret);
                }
                return infer_project_iterable_item_type(iterables[0], module_name, imports, index, current_fields, current_class);
            }
        }
        if callee_text == "filter" {
            let first_iterable = args.iter().skip(1).find(|arg| !arg.trim().is_empty())?;
            return infer_project_iterable_item_type(first_iterable, module_name, imports, index, current_fields, current_class);
        }
        if matches!(callee_text.as_str(), "iter" | "aiter" | "reversed" | "next" | "anext" | "sorted") {
            let first_arg = args.iter().find(|arg| !arg.trim().is_empty())?;
            return infer_project_iterable_item_type(first_arg, module_name, imports, index, current_fields, current_class);
        }
    }
    let iterable_ty = infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class)?;
    if let Some((base, method)) = split_last_top_level_dot(trimmed) {
        if let Some(base_ty) = infer_project_expr_type(&base, module_name, imports, index, current_fields, current_class) {
            if let Some(td_item) = index.typed_dict_method_return_type(&base_ty, &method) {
                if method == "items" {
                    return td_item
                        .strip_prefix("generator<")
                        .and_then(|rest| rest.strip_suffix('>'))
                        .map(|item| item.to_string());
                }
                if method == "values" || method == "keys" {
                    return td_item
                        .strip_prefix("generator<")
                        .and_then(|rest| rest.strip_suffix('>'))
                        .map(|item| item.to_string());
                }
            }
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
    iterable_item_type_from_project_type(index, &iterable_ty, &mut HashSet::new())
}

fn infer_project_expr_type(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed == "True" || trimmed == "False" {
        return Some("bool".to_string());
    }
    if trimmed == "None" {
        return Some("None".to_string());
    }
    if trimmed.parse::<i128>().is_ok() {
        return Some("int".to_string());
    }
    if trimmed.parse::<f64>().is_ok() && trimmed.contains('.') {
        return Some("float".to_string());
    }
    if (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('"') && trimmed.ends_with('"'))
    {
        return Some("str".to_string());
    }
    if looks_like_python_type_annotation(trimmed) {
        if let Some(ty) = normalize_python_annotation_type(trimmed, module_name, imports, Some(index)) {
            return Some(ty);
        }
    }
    if let Some(inner) = parse_static_eval_expr_text(trimmed) {
        return infer_project_expr_type(&inner, module_name, imports, index, current_fields, current_class);
    }
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return infer_project_expr_type(inner, module_name, imports, index, current_fields, current_class);
    }
    if trimmed == "super()" {
        return current_project_super_type(index, current_class);
    }
    if (trimmed == "self" || trimmed == "cls") && current_class.is_some() {
        return current_class.map(|name| name.to_string());
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '[', ']') {
        let result_ty = infer_project_expr_type(&result_expr, module_name, imports, index, current_fields, current_class)
            .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("list<{}>", result_ty));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '{', '}') {
        if let Some((key_text, value_text)) = split_once_top_level(&result_expr, ':') {
            let key_ty = infer_project_expr_type(&key_text, module_name, imports, index, current_fields, current_class)
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = infer_project_expr_type(&value_text, module_name, imports, index, current_fields, current_class)
                .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        let result_ty = infer_project_expr_type(&result_expr, module_name, imports, index, current_fields, current_class)
            .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{}>", result_ty));
    }
    if let Some((result_expr, _, iterable_text)) = parse_python_comprehension(trimmed, '(', ')') {
        let result_ty = infer_project_expr_type(&result_expr, module_name, imports, index, current_fields, current_class)
            .or_else(|| infer_project_iterable_item_type(&iterable_text, module_name, imports, index, current_fields, current_class))
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
                .map(|item| {
                    infer_project_expr_type(&item, module_name, imports, index, current_fields, current_class)
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .collect::<Vec<_>>();
            return Some(format!("tuple<{}>", parts.join("|")));
        }
    }
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .collect::<Vec<_>>();
        if let Some(first) = items.into_iter().next() {
            if let Some(item) = infer_project_expr_type(&first, module_name, imports, index, current_fields, current_class) {
                return Some(format!("list<{}>", item));
            }
        }
        return Some("list".to_string());
    }
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let first = split_top_level_commas(inner).into_iter().find(|item| !item.trim().is_empty());
        if let Some(entry) = first {
            if let Some((key, value)) = split_once_top_level(&entry, ':') {
                let key_ty = infer_project_expr_type(&key, module_name, imports, index, current_fields, current_class)
                    .unwrap_or_else(|| "unknown".to_string());
                let value_ty = infer_project_expr_type(&value, module_name, imports, index, current_fields, current_class)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("dict<{},{}>", key_ty, value_ty));
            }
        }
        return Some("dict".to_string());
    }
    if let Some((base, index_expr)) = split_last_top_level_index(trimmed) {
        if let Some(base_ty) = infer_project_expr_type(&base, module_name, imports, index, current_fields, current_class) {
            if let Some(key) = parse_python_string_literal_content(&index_expr) {
                if let Some(field_ty) = index.typed_dict_key_type(&base_ty, &key) {
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
            if let Some(ret) = index.method_return(&base_ty, "__getitem__", 1) {
                return Some(ret);
            }
        }
    }
    if let Some((callee_text, arg_text)) = parse_call_parts(trimmed) {
        let raw_args = split_top_level_commas(&arg_text);
        let args = split_python_call_args(&arg_text);
        let arg_count = args.len();
        if callee_text == "getattr" {
            if let Some((base, field, _)) = parse_builtin_static_attr_call(trimmed, "getattr") {
                return infer_project_expr_type(&synthetic_attr_expr_text(&base, &field), module_name, imports, index, current_fields, current_class);
            }
        }
        if let Some(module_path) = static_python_imported_module_path(trimmed, module_name, imports, index, None) {
            return Some(module_path);
        }
        if callee_text == "hasattr" {
            return Some("bool".to_string());
        }
        if matches!(callee_text.as_str(), "TypeVar" | "typing.TypeVar") {
            if let Some(bound_expr) = raw_args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "bound").then_some(value)
            }) {
                if let Some(bound_ty) = infer_project_expr_type(&bound_expr, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(&bound_expr, module_name, imports, Some(index)))
                {
                    return Some(bound_ty);
                }
            }
            for arg in args.iter().skip(1) {
                if split_python_keyword_arg(arg).is_some() {
                    continue;
                }
                if let Some(ty) = infer_project_expr_type(arg, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(arg, module_name, imports, Some(index)))
                {
                    return Some(ty);
                }
            }
        }
        if matches!(callee_text.as_str(), "NewType" | "typing.NewType") {
            if let Some(base_expr) = args.get(1) {
                if let Some(base_ty) = infer_project_expr_type(base_expr, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(base_expr, module_name, imports, Some(index)))
                {
                    return Some(base_ty);
                }
            }
        }
        if matches!(callee_text.as_str(), "field" | "dataclasses.field" | "Field" | "pydantic.Field" | "sqlmodel.Field" | "attr.ib" | "attr.field" | "attrs.field") {
            let default_factory = raw_args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "default_factory" || name == "factory").then_some(value)
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
                if let Some(ty) = infer_project_expr_type(factory, module_name, imports, index, current_fields, current_class)
                    .or_else(|| normalize_python_annotation_type(factory, module_name, imports, Some(index)))
                {
                    return Some(ty);
                }
            }
            if let Some(default_expr) = raw_args.iter().find_map(|arg| {
                let (name, value) = split_python_keyword_arg(arg)?;
                (name == "default").then_some(value)
            }) {
                if default_expr.trim() != "None" {
                    if let Some(default_ty) = infer_project_expr_type(&default_expr, module_name, imports, index, current_fields, current_class) {
                        return Some(default_ty);
                    }
                }
            }
        }
        if matches!(callee_text.as_str(), "Factory" | "attr.Factory" | "attrs.Factory") {
            if let Some(first) = args.get(0) {
                if let Some(ty) = infer_project_expr_type(first, module_name, imports, index, current_fields, current_class) {
                    return Some(ty);
                }
            }
        }
        let resolved_callee = resolve_imported_name(&callee_text, imports, &PyEnv::default());
        let is_dependency_wrapper = matches!(callee_text.as_str(), "Depends" | "Security" | "Query" | "Path" | "Header" | "Cookie" | "Body" | "Form" | "File")
            || matches!(resolved_callee.as_deref(), Some("fastapi.Depends" | "fastapi.Security" | "fastapi.params.Depends" | "fastapi.params.Security" | "fastapi.Query" | "fastapi.Path" | "fastapi.Header" | "fastapi.Cookie" | "fastapi.Body" | "fastapi.Form" | "fastapi.File" | "fastapi.params.Query" | "fastapi.params.Path" | "fastapi.params.Header" | "fastapi.params.Cookie" | "fastapi.params.Body" | "fastapi.params.Form" | "fastapi.params.File"));
        if is_dependency_wrapper {
            if let Some(first) = args.get(0) {
                if let Some(callable_path) = infer_project_symbol_path(first, module_name, imports, index) {
                    if let Some(ret) = index.top_level_return(&callable_path, 0).or_else(|| project_callable_return_from_type(index, &callable_path, 0)) {
                        return Some(ret);
                    }
                    if let Some(ty) = index.module_value_type_by_path(&callable_path) {
                        return Some(ty);
                    }
                    return Some(callable_path);
                }
                if first.trim() != "..." && first.trim() != "None" {
                    if let Some(default_ty) = infer_project_expr_type(first, module_name, imports, index, current_fields, current_class) {
                        return Some(default_ty);
                    }
                }
            }
        }
        if matches!(callee_text.as_str(), "next" | "anext") {
            if let Some(first) = args.get(0) {
                return infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class);
            }
        }
        if matches!(callee_text.as_str(), "iter" | "aiter" | "reversed") {
            if let Some(first) = args.get(0) {
                if let Some(base_ty) = infer_project_expr_type(first, module_name, imports, index, current_fields, current_class) {
                    let method = if callee_text == "aiter" { "__aiter__" } else { "__iter__" };
                    if let Some(ret) = index.method_return(&base_ty, method, 0) {
                        return Some(ret);
                    }
                }
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("generator<{}>", item));
            }
        }
        if matches!(callee_text.as_str(), "enumerate" | "zip" | "map" | "filter") {
            let item = infer_project_iterable_item_type(trimmed, module_name, imports, index, current_fields, current_class)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("generator<{}>", item));
        }
        if callee_text == "sorted" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "any" || callee_text == "all" {
            return Some("bool".to_string());
        }
        if callee_text == "list" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{}>", item));
            }
            return Some("list".to_string());
        }
        if callee_text == "set" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("set<{}>", item));
            }
            return Some("set".to_string());
        }
        if callee_text == "tuple" {
            if let Some(first) = args.get(0) {
                let item = infer_project_iterable_item_type(first, module_name, imports, index, current_fields, current_class)
                    .or_else(|| infer_project_expr_type(first, module_name, imports, index, current_fields, current_class))
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("tuple<{}>", item));
            }
            return Some("tuple".to_string());
        }
        if callee_text == "dict" {
            return Some("dict".to_string());
        }
        if let Some(relation_ty) = infer_relation_constructor_type(&callee_text, &raw_args, module_name, imports, index, current_fields, current_class) {
            return Some(relation_ty);
        }
        let resolved_callee = imports.aliases.get(&callee_text).cloned();
        if callee_text == "functools.partial" || resolved_callee.as_deref() == Some("functools.partial") {
            if let Some(first) = args.get(0) {
                if let Some(path) = infer_project_symbol_path(first, module_name, imports, index) {
                    return Some(path);
                }
            }
        }
        if let Some(relation_ty) = infer_relation_constructor_type(&callee_text, &raw_args, module_name, imports, index, current_fields, current_class) {
            return Some(relation_ty);
        }
        if let Some(mapped) = imports.aliases.get(&callee_text) {
            let canonical = canonicalize_project_path(index, mapped);
            if let Some(ret) = index.top_level_return(&canonical, arg_count) {
                return Some(ret);
            }
            if index.function_path_exists(&canonical) { return None; }
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(ty);
            }
            return Some(canonical);
        }
        if let Some(prefixed) = canonicalize_prefixed_project_path(index, &callee_text) {
            if let Some(ret) = index.top_level_return(&prefixed, arg_count) {
                return Some(ret);
            }
            if index.function_path_exists(&prefixed) { return None; }
            if let Some(ty) = index.module_value_type_by_path(&prefixed) {
                return Some(ty);
            }
            return Some(prefixed);
        }
        if let Some(in_module) = index.resolve_module_member(module_name, &callee_text) {
            let canonical = canonicalize_project_path(index, &in_module);
            if let Some(ret) = index.top_level_return(&canonical, arg_count) {
                return Some(ret);
            }
            if index.function_path_exists(&canonical) { return None; }
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(ty);
            }
            return Some(canonical);
        }
        if let Some(unique) = index.resolve_simple_class(&callee_text) {
            return Some(canonicalize_project_path(index, &unique));
        }
        if let Some(unique_fn) = index.resolve_simple_function(&callee_text) {
            if let Some(ret) = index.top_level_return(&unique_fn, arg_count) {
                return Some(ret);
            }
            return None;
        }
        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            if let Some(base_ty) = infer_project_expr_type(&prefix, module_name, imports, index, current_fields, current_class) {
                if index.module_exists(&base_ty) {
                    if let Some(member) = index.resolve_module_member(&base_ty, &method) {
                        let canonical = canonicalize_project_path(index, &member);
                        if let Some(ret) = index.top_level_return(&canonical, arg_count) {
                            return Some(ret);
                        }
                        if index.function_path_exists(&canonical) { return None; }
                        if let Some(ty) = index.module_value_type_by_path(&canonical) {
                            return Some(ty);
                        }
                        return Some(canonical);
                    }
                }
                if method == "get" || method == "pop" || method == "setdefault" {
                    if let Some(first_arg) = args.get(0) {
                        if let Some(key) = parse_python_string_literal_content(first_arg) {
                            if let Some(field_ty) = index.typed_dict_key_type(&base_ty, &key) {
                                return Some(field_ty);
                            }
                        }
                    }
                    if let Some(inner) = base_ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                        if let Some((_, value)) = split_once_top_level(inner, ',') {
                            return Some(value.trim().to_string());
                        }
                    }
                }
                if let Some(ret) = index.typed_dict_method_return_type(&base_ty, &method) {
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
                if method == "pop" {
                    if let Some(inner) = base_ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                        return Some(inner.to_string());
                    }
                }
                if let Some(ret) = index.method_return(&base_ty, &method, arg_count) {
                    return Some(ret);
                }
                if method == "copy" {
                    return Some(base_ty);
                }
                if method == "dumps" && base_ty == "json" {
                    return Some("str".to_string());
                }
                return Some(format!("{base_ty}.{method}#ret"));
            }
        }
        if let Some(class_name) = current_class {
            if let Some(ret) = index.method_return(class_name, &callee_text, arg_count) {
                return Some(ret);
            }
        }
        let current_function = format!("{module_name}.{callee_text}");
        if let Some(ret) = index.top_level_return(&current_function, arg_count) {
            return Some(ret);
        }
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        if base == "self" {
            if let Some(ty) = current_fields.get(&field).cloned() {
                return descriptor_access_type(index, &ty).or(Some(ty));
            }
            if let Some(class_name) = current_class {
                if let Some(ty) = direct_field_access_type(index, class_name, &field) {
                    return Some(ty);
                }
            }
        }
        if let Some(base_ty) = infer_project_expr_type(&base, module_name, imports, index, current_fields, current_class) {
            if let Some(ty) = direct_field_access_type(index, &base_ty, &field) {
                return Some(ty);
            }
            if index.module_exists(&base_ty) {
                if let Some(member) = index.resolve_module_member(&base_ty, &field) {
                    let canonical = canonicalize_project_path(index, &member);
                    if let Some(ty) = index.module_value_type_by_path(&canonical) {
                        return Some(ty);
                    }
                    return Some(canonical);
                }
            }
            return Some(format!("{base_ty}.{field}"));
        }
    }
    if let Some(mapped) = imports.aliases.get(trimmed) {
        let canonical = canonicalize_project_path(index, mapped);
        if let Some(ty) = index.module_value_type_by_path(&canonical) {
            return Some(ty);
        }
        return Some(canonical);
    }
    if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
        let canonical = canonicalize_project_path(index, &in_module);
        if let Some(ty) = index.module_value_type_by_path(&canonical) {
            return Some(ty);
        }
        return Some(canonical);
    }
    if let Some(unique) = index.resolve_simple_class(trimmed) {
        return Some(canonicalize_project_path(index, &unique));
    }
    if let Some(unique_fn) = index.resolve_simple_function(trimmed) {
        return Some(canonicalize_project_path(index, &unique_fn));
    }
    None
}

fn infer_project_class_fields(
    class: &PyClassText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    existing: &HashMap<String, String>,
) -> HashMap<String, String> {
    let current_class = qualify_class_name(module_name, &class.name, Some(index));
    let current_bases = class
        .bases
        .iter()
        .map(|base| qualify_type_name(module_name, base, imports, Some(index)).unwrap_or_else(|| base.clone()))
        .collect::<Vec<_>>();
    let mut fields = existing.clone();
    for (field, ty) in infer_project_class_body_fields(class, module_name, imports, index) {
        fields.entry(field).or_insert(ty);
    }
    for method in extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1) {
        let (mut env, known_classes) = seed_project_inference_env(
            &method,
            module_name,
            imports,
            index,
            Some(&current_class),
            &current_bases,
            &fields,
        );
        for raw_line in method.body.lines() {
            apply_project_summary_line_effects(raw_line.trim(), imports, &mut env, &known_classes);
        }
        for (field, ty) in env.field_types.clone() {
            fields.insert(field, ty);
        }
        if function_has_decorator(&method, "property") {
            for raw_line in method.body.lines() {
                let line = raw_line.trim();
                if let Some(rest) = line.strip_prefix("return ") {
                    if let Some(ty) = infer_simple_python_type(rest, imports, &env, &known_classes) {
                        fields.insert(method.name.clone(), ty);
                        break;
                    }
                }
            }
        }
        if let Some(property_name) = property_decorator_target(&method, "setter") {
            if let Some(ty) = env.field_types.get(&property_name).cloned() {
                fields.insert(property_name, ty);
            }
        }
    }
    fields
}

fn method_signature_key(method: &str, arg_count: usize) -> String {
    format!("{method}#{arg_count}")
}

fn top_level_signature_key(function_name: &str, arg_count: usize) -> String {
    format!("{function_name}#{arg_count}")
}


fn resolve_relative_python_module(anchor_module: &str, spec: &str) -> Option<String> {
    let trimmed = spec.trim();
    if !trimmed.starts_with('.') {
        return Some(trimmed.to_string());
    }
    let leading = trimmed.chars().take_while(|ch| *ch == '.').count();
    let suffix = trimmed[leading..].trim_matches('.');
    let mut parts = anchor_module
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    // A top-level package ``__init__.py`` is represented by the package name
    // itself, so ``from .repo`` must stay anchored at that package. For a
    // regular submodule, one leading dot moves to its containing package.
    let pops = if leading == 1 && parts.len() == 1 { 0 } else { leading };
    for _ in 0..pops {
        if !parts.is_empty() {
            parts.pop();
        }
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').filter(|part| !part.is_empty()));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

fn static_python_imported_module_path(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: Option<&PyEnv>,
) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee_text = callee_text.trim();
    let resolved_callee = env
        .and_then(|env| resolve_imported_name(callee_text, imports, env))
        .or_else(|| imports.aliases.get(callee_text).cloned());
    let is_import_module = callee_text == "importlib.import_module"
        || resolved_callee.as_deref() == Some("importlib.import_module");
    let is_dunder_import = callee_text == "__import__";
    if !is_import_module && !is_dunder_import {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let mut target = strip_python_string_literal(args.get(0)?)?;
    let package = args.iter().find_map(|arg| {
        let (name, value) = split_once_top_level(arg, '=')?;
        (name.trim() == "package").then(|| strip_python_string_literal(&value)).flatten()
    });
    if target.starts_with('.') {
        let anchor = package.as_deref().unwrap_or(module_name);
        target = resolve_relative_python_module(anchor, &target)?;
    }
    if is_dunder_import {
        let has_fromlist = args.iter().any(|arg| {
            split_once_top_level(arg, '=')
                .is_some_and(|(name, value)| name.trim() == "fromlist" && value.trim() != "[]" && value.trim() != "()")
        });
        if !has_fromlist {
            target = target.split('.').next()?.to_string();
        }
    }
    if index.module_exists(&target) {
        Some(target)
    } else {
        Some(canonicalize_project_path(index, &target))
    }
}

fn static_python_partial_target_path(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let callee_text = callee_text.trim();
    let resolved_callee = resolve_imported_name(callee_text, imports, env);
    let is_partial = callee_text == "functools.partial" || resolved_callee.as_deref() == Some("functools.partial");
    if !is_partial {
        return None;
    }
    let args = split_python_call_args(&arg_text);
    let target = args.get(0)?;
    infer_project_callable_value_type(target, imports, env, known_classes)
}


fn import_effect_modules_for_alias_path(index: &PyProjectIndex, path: &str) -> Vec<String> {
    let canonical_path = canonicalize_project_path(index, path);
    if index.module_exists(&canonical_path) {
        return vec![canonical_path];
    }
    let mut out = Vec::new();
    if let Some((module, _)) = canonical_path.rsplit_once('.') {
        out.push(module.to_string());
    }
    if out.is_empty() {
        out.push(canonical_path);
    }
    out
}

fn apply_project_module_import_line_effects(
    line: &str,
    module_name: &str,
    index: &PyProjectIndex,
    env: &mut PyEnv,
) {
    let line_imports = parse_imports_shallow_for_module(line, module_name);
    for path in line_imports.aliases.values() {
        for imported_module in import_effect_modules_for_alias_path(index, path) {
            if env.executed_modules.insert(imported_module.clone()) {
                env.project_index
                    .apply_imported_module_effects(&imported_module, &mut HashSet::new());
            }
        }
    }
    for (alias, path) in line_imports.aliases {
        let canonical_path = canonicalize_project_path(&env.project_index, &path);
        let ty = env
            .project_index
            .module_value_type_by_path(&path)
            .or_else(|| env.project_index.module_value_type_by_path(&canonical_path))
            .unwrap_or_else(|| canonical_path.clone());
        env.types.insert(alias.clone(), ty.clone());
        if let Some(call_path) = callable_path_from_type(&env.project_index, &ty) {
            env.callable_aliases.insert(alias.clone(), call_path);
        } else if env.project_index.function_path_exists(&canonical_path) || env.project_index.class_exists(&canonical_path) {
            env.callable_aliases.insert(alias.clone(), canonical_path.clone());
        } else {
            env.callable_aliases.remove(&alias);
        }
    }
}

fn summary_skip_range_end(start_line: u32, skip_ranges: &[(u32, u32)]) -> Option<u32> {
    skip_ranges
        .iter()
        .find_map(|(start, end)| (*start == start_line).then_some(*end))
}

fn infer_project_module_bindings_lines_structured(
    lines: &[PyBodyLine],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
    skip_ranges: &[(u32, u32)],
) -> bool {
    let mut idx = 0usize;
    while idx < lines.len() {
        let raw_line = &lines[idx];
        if let Some(end_line) = summary_skip_range_end(raw_line.line_no, skip_ranges) {
            while idx < lines.len() && lines[idx].line_no <= end_line {
                idx += 1;
            }
            continue;
        }
        let line = raw_line.text.trim();
        if line.is_empty() || line.starts_with('#') {
            idx += 1;
            continue;
        }
        if line.starts_with("import ") || line.starts_with("from ") {
            apply_project_module_import_line_effects(line, module_name, index, env);
            idx += 1;
            continue;
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
                    let branch_live = infer_project_module_bindings_lines_structured(
                        &lines[body_start..body_end],
                        module_name,
                        imports,
                        index,
                        &mut branch_env,
                        known_classes,
                        skip_ranges,
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
                        let else_live = infer_project_module_bindings_lines_structured(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            &mut else_env,
                            known_classes,
                            skip_ranges,
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
            let try_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut try_env,
                known_classes,
                skip_ranges,
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
                    let catch_live = infer_project_module_bindings_lines_structured(
                        &lines[catch_start..catch_end],
                        module_name,
                        imports,
                        index,
                        &mut catch_env,
                        known_classes,
                        skip_ranges,
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
                        let else_live = infer_project_module_bindings_lines_structured(
                            &lines[else_start..else_end],
                            module_name,
                            imports,
                            index,
                            &mut else_env,
                            known_classes,
                            skip_ranges,
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
                let finally_live = infer_project_module_bindings_lines_structured(
                    &lines[finally_start..finally_end],
                    module_name,
                    imports,
                    index,
                    &mut finally_env,
                    known_classes,
                    skip_ranges,
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
            let loop_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut loop_env,
                known_classes,
                skip_ranges,
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
                    let else_live = infer_project_module_bindings_lines_structured(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        &mut else_env,
                        known_classes,
                        skip_ranges,
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
            let loop_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut loop_env,
                known_classes,
                skip_ranges,
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
                    let else_live = infer_project_module_bindings_lines_structured(
                        &lines[else_start..else_end],
                        module_name,
                        imports,
                        index,
                        &mut else_env,
                        known_classes,
                        skip_ranges,
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
            let with_live = infer_project_module_bindings_lines_structured(
                &lines[body_start..body_end],
                module_name,
                imports,
                index,
                &mut with_env,
                known_classes,
                skip_ranges,
            );
            if !with_live {
                return false;
            }
            *env = with_env;
            idx = body_end;
            continue;
        }

        if line.starts_with("raise ") || line == "raise" {
            return false;
        }
        apply_project_summary_line_effects(line, imports, env, known_classes);
        apply_direct_call_summary_effects(
            line,
            module_name,
            imports,
            index,
            env,
            known_classes,
            None,
        );
        idx += 1;
    }
    true
}

fn infer_project_symbol_path_in_env(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = static_python_imported_module_path(trimmed, module_name, imports, index, Some(env)) {
        return Some(path);
    }
    if let Some(path) = infer_project_callable_value_type(trimmed, imports, env, known_classes) {
        return Some(canonicalize_project_path(index, &path));
    }
    if let Some(mapped) = env.callable_aliases.get(trimmed) {
        return Some(canonicalize_project_path(index, mapped));
    }
    if let Some(ty) = resolve_dotted_type(trimmed, imports, env, known_classes) {
        let canonical = canonicalize_project_path(index, &ty);
        if index.function_path_exists(&canonical) || index.module_exists(&canonical) {
            return Some(canonical);
        }
    }
    infer_project_symbol_path(trimmed, module_name, imports, index)
}

fn infer_project_module_bindings(
    source: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> (
    HashMap<String, String>,
    HashMap<String, String>,
    HashMap<String, HashMap<String, String>>,
    HashMap<String, HashMap<String, String>>,
) {
    let mut values = HashMap::new();
    let mut aliases = HashMap::new();
    let mut env = PyEnv::default();
    env.current_module = module_name.to_string();
    env.current_function = format!("{module_name}.<module>");
    env.project_index = index.clone();
    env.executed_modules.insert(module_name.to_string());
    if let Some(classes) = index.classes_by_module.get(module_name) {
        for class_name in classes {
            env.types.insert(class_name.clone(), format!("{module_name}.{class_name}"));
        }
    }
    for function in extract_functions_at_indent(source, 0, 1) {
        let qualified = format!("{module_name}.{}", function.name);
        let decorated_callable_ty = decorate_project_callable_type(&function, module_name, imports, index, &qualified);
        env.types.insert(function.name.clone(), decorated_callable_ty.clone());
        if let Some(path) = callable_path_from_type(index, &decorated_callable_ty)
            .or_else(|| index.function_path_exists(&qualified).then(|| qualified.clone()))
        {
            env.callable_aliases.insert(function.name.clone(), path);
        }
        values.insert(function.name.clone(), decorated_callable_ty);
    }
    let known_classes = infer_project_known_classes(index);
    let body_lines = collect_py_body_lines(source, 1);
    let skip_ranges = extract_functions_at_indent(source, 0, 1)
        .into_iter()
        .map(|func| (func.start_line, func.end_line))
        .chain(extract_classes(source).into_iter().map(|class| (class.start_line, class.end_line)))
        .collect::<Vec<_>>();
    let _ = infer_project_module_bindings_lines_structured(
        &body_lines,
        module_name,
        imports,
        index,
        &mut env,
        &known_classes,
        &skip_ranges,
    );

    for (name, ty) in &env.types {
        if is_simple_ident(name) {
            let canonical = canonicalize_project_path(index, ty);
            values.insert(name.clone(), canonical.clone());
            if index.module_exists(&canonical)
                || index.function_path_exists(&canonical)
                || index.class_exists(&canonical)
            {
                aliases.insert(name.clone(), canonical);
            }
        }
    }
    for (name, path) in &env.callable_aliases {
        if is_simple_ident(name) {
            aliases.insert(name.clone(), canonicalize_project_path(index, path));
        }
    }

    // Preserve symbolic identity for simple module-level aliases, including
    // non-callable imported objects (for example, `get_conn = conn`).  Type
    // propagation alone would collapse these to the object's class and lose
    // the source member path needed by re-exports and precise container slots.
    for raw_line in source.lines() {
        if raw_line.chars().take_while(|ch| ch.is_whitespace()).count() != 0 {
            continue;
        }
        let line = raw_line.trim();
        let Some((left, right)) = split_once_top_level(line, '=') else {
            continue;
        };
        let target = left.trim();
        let value = right.trim();
        if !is_simple_ident(target) || !is_simple_ident(value) {
            continue;
        }
        if let Some(path) = imports
            .aliases
            .get(value)
            .cloned()
            .or_else(|| aliases.get(value).cloned())
            .or_else(|| index.module_symbol_alias(module_name, value))
        {
            // This source-level fallback must not overwrite a later runtime
            // rebinding already observed while executing the module body (for
            // example `cb = load; patch();` where patch assigns `cb = alt`).
            let canonical = canonicalize_project_path(index, &path);
            if env.callable_aliases.contains_key(target) {
                aliases.entry(target.to_string()).or_insert(canonical);
            } else {
                aliases.insert(target.to_string(), canonical);
            }
        }
    }

    let mut module_member_values: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut class_field_patches: HashMap<String, HashMap<String, String>> = env
        .class_field_index
        .iter()
        .map(|(owner, fields)| {
            (
                canonicalize_project_path(index, owner),
                fields
                    .iter()
                    .map(|(field, ty)| {
                        (field.clone(), canonicalize_project_path(index, ty))
                    })
                    .collect(),
            )
        })
        .collect();
    for (base_name, fields) in &env.local_field_types {
        let Some(owner_ty) = env.types.get(base_name).cloned() else {
            continue;
        };
        let owner_ty = canonicalize_project_path(index, &owner_ty);
        if index.module_exists(&owner_ty) {
            let slot = module_member_values.entry(owner_ty).or_default();
            for (field, ty) in fields {
                slot.insert(field.clone(), canonicalize_project_path(index, ty));
            }
            continue;
        }
        if index.class_exists(&owner_ty) {
            let slot = class_field_patches.entry(owner_ty).or_default();
            for (field, ty) in fields {
                slot.insert(field.clone(), canonicalize_project_path(index, ty));
            }
        }
    }

    (values, aliases, module_member_values, class_field_patches)
}
