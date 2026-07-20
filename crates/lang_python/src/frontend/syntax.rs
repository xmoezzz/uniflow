#[derive(Clone, Debug)]
struct PyFunctionText {
    name: String,
    params: String,
    return_annotation: Option<String>,
    body: String,
    start_line: u32,
    end_line: u32,
    decorators: Vec<String>,
}

#[derive(Clone, Debug)]
struct PyClassText {
    name: String,
    bases: Vec<String>,
    body: String,
    start_line: u32,
    end_line: u32,
    indent: usize,
}

#[derive(Clone, Debug, Default)]
struct ProjectFunctionSummary {
    return_type: Option<String>,
    writeback_types: HashMap<String, String>,
    writeback_callables: HashMap<String, String>,
    local_field_writes: HashMap<String, HashMap<String, String>>,
    precise_index_type_writes: HashMap<String, HashMap<String, String>>,
    precise_index_callable_writes: HashMap<String, HashMap<String, String>>,
}

#[derive(Clone, Debug)]
struct ParsedFunction {
    function: uniflow_hir::Function,
    discovered_fields: Vec<Field>,
    synthetic_functions: Vec<uniflow_hir::Function>,
}

#[derive(Clone, Debug, Default)]
struct PyImports {
    aliases: HashMap<String, String>,
    wildcard_bases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PyParamKind {
    Positional,
    VarArgs,
    KwArgs,
}

#[derive(Clone, Debug)]
struct PyParamSpec {
    name: String,
    kind: PyParamKind,
    has_default: bool,
    keyword_only: bool,
    annotation: Option<String>,
    default_expr: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PyCallArgSpread {
    None,
    Star,
    StarStar,
}

#[derive(Clone, Debug)]
struct PyCallArgText {
    name: Option<String>,
    expr: String,
    spread: PyCallArgSpread,
}

fn parse_python_param_specs(param_text: &str) -> Vec<PyParamSpec> {
    let mut out = Vec::new();
    let mut keyword_only = false;
    for raw in split_top_level_commas(param_text) {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "/" {
            continue;
        }
        if trimmed == "*" {
            keyword_only = true;
            continue;
        }
        let (kind, raw_name) = if let Some(rest) = trimmed.strip_prefix("**") {
            (PyParamKind::KwArgs, rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix('*') {
            keyword_only = true;
            (PyParamKind::VarArgs, rest.trim())
        } else {
            (PyParamKind::Positional, trimmed)
        };
        let default_split = split_once_top_level(raw_name, '=');
        let has_default = default_split.is_some();
        let default_expr = default_split.as_ref().map(|(_, right)| right.trim().to_string());
        let before_default = default_split
            .map(|(left, _)| left.trim().to_string())
            .unwrap_or_else(|| raw_name.trim().to_string());
        let annotation_split = split_once_top_level(&before_default, ':');
        let annotation = annotation_split
            .as_ref()
            .map(|(_, right)| right.trim().to_string())
            .filter(|value| !value.is_empty());
        let name = annotation_split
            .map(|(left, _)| left.trim().to_string())
            .unwrap_or(before_default)
            .trim()
            .to_string();
        if name.is_empty() {
            continue;
        }
        let is_keyword_only = keyword_only && kind == PyParamKind::Positional;
        out.push(PyParamSpec {
            name,
            kind,
            has_default,
            keyword_only: is_keyword_only,
            annotation,
            default_expr,
        });
    }
    out
}

fn python_callable_arities(param_specs: &[PyParamSpec], drop_receiver: bool) -> Vec<usize> {
    let specs = if drop_receiver && !param_specs.is_empty() {
        &param_specs[1..]
    } else {
        param_specs
    };
    let mut min = 0usize;
    let mut max = 0usize;
    for spec in specs {
        match spec.kind {
            PyParamKind::Positional => {
                max += 1;
                if !spec.has_default {
                    min += 1;
                }
            }
            PyParamKind::VarArgs | PyParamKind::KwArgs => {}
        }
    }
    (min..=max).collect()
}

fn parse_python_call_args_detailed(arg_text: &str) -> Vec<PyCallArgText> {
    split_top_level_commas(arg_text)
        .into_iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            if let Some((left, right)) = split_python_keyword_arg(trimmed) {
                return Some(PyCallArgText {
                    name: Some(left),
                    expr: normalize_python_argument_expr(&right),
                    spread: PyCallArgSpread::None,
                });
            }
            let spread = if trimmed.starts_with("**") {
                PyCallArgSpread::StarStar
            } else if trimmed.starts_with('*') {
                PyCallArgSpread::Star
            } else {
                PyCallArgSpread::None
            };
            Some(PyCallArgText {
                name: None,
                expr: normalize_python_argument_expr(trimmed),
                spread,
            })
        })
        .collect()
}

fn resolve_relative_import_base(current_module: &str, raw_base: &str, current_is_package: bool) -> String {
    let trimmed = raw_base.trim();
    if !trimmed.starts_with('.') {
        return trimmed.to_string();
    }
    let leading_dots = trimmed.chars().take_while(|ch| *ch == '.').count();
    let suffix = trimmed[leading_dots..].trim_matches('.');
    let mut parts = current_module
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if !current_is_package && !parts.is_empty() {
        parts.pop();
    }
    let pops = leading_dots.saturating_sub(1);
    for _ in 0..pops {
        if !parts.is_empty() {
            parts.pop();
        }
    }
    if !suffix.is_empty() {
        parts.extend(suffix.split('.').filter(|part| !part.is_empty()));
    }
    if parts.is_empty() {
        trimmed.trim_start_matches('.').to_string()
    } else {
        parts.join(".")
    }
}

fn canonicalize_project_path(index: &PyProjectIndex, path: &str) -> String {
    if path.contains('.') {
        index.resolve_canonical_member_path(path, &mut HashSet::new())
    } else {
        path.to_string()
    }
}

fn parse_destructuring_targets(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    let inner = if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        &trimmed[1..trimmed.len().saturating_sub(1)]
    } else {
        trimmed
    };
    let parts = split_top_level_commas(inner)
        .into_iter()
        .map(|part| part.trim().to_string())
        .filter(|part| is_simple_ident(part))
        .collect::<Vec<_>>();
    if parts.len() >= 2 { parts } else { Vec::new() }
}

fn parse_tuple_type_elements(text: &str) -> Option<Vec<String>> {
    let inner = text.strip_prefix("tuple<")?.strip_suffix('>')?;
    let elems = inner.split('|').map(|part| part.trim().to_string()).filter(|part| !part.is_empty()).collect::<Vec<_>>();
    if elems.is_empty() { None } else { Some(elems) }
}

fn infer_simple_destructured_types(
    text: &str,
    imports: &PyImports,
    env: &PyEnv,
    known_classes: &HashSet<String>,
) -> Vec<Option<String>> {
    let trimmed = text.trim();
    if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner).into_iter().filter(|item| !item.trim().is_empty()).collect::<Vec<_>>();
        if items.len() >= 2 {
            return items.into_iter().map(|item| infer_simple_python_type(&item, imports, env, known_classes)).collect();
        }
    }
    if let Some(ty) = infer_simple_python_type(trimmed, imports, env, known_classes) {
        if let Some(elems) = destructure_type_elements(&ty) {
            return elems.into_iter().map(Some).collect();
        }
    }
    Vec::new()
}

fn destructure_type_elements(ty: &str) -> Option<Vec<String>> {
    if let Some(items) = parse_tuple_type_elements(ty) {
        return Some(items);
    }
    if let Some(inner) = ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some(items) = parse_tuple_type_elements(inner) {
            return Some(items);
        }
    }
    None
}

fn new_unpack_symbol(builder: &mut ModuleBuilder, prefix: &str, line_no: u32, slot: usize) -> SymbolId {
    builder.add_symbol(&format!("__py_{}_{}_{}", prefix, line_no, slot), SymbolKind::Local)
}

fn build_unpack_index_expr(
    builder: &mut ModuleBuilder,
    source_symbol: SymbolId,
    index: usize,
    line_no: u32,
) -> Expr {
    with_line_span(
        Expr::IndexRead {
            id: builder.alloc_expr_id(),
            base: Box::new(with_line_span(new_var_ref(builder, source_symbol), builder.file_id(), line_no)),
            index: Box::new(new_int(builder, index as i64)),
            span: default_span(),
        },
        builder.file_id(),
        line_no,
    )
}

fn extend_destructuring_bindings(
    builder: &mut ModuleBuilder,
    out: &mut Vec<Stmt>,
    targets: &[String],
    source_symbol: SymbolId,
    inferred_types: &[Option<String>],
    env: &mut PyEnv,
    line_no: u32,
) {
    let span = span_from_line_range(builder.file_id(), line_no, line_no);
    for (idx, target) in targets.iter().enumerate() {
        let existed_before = env.vars.contains_key(target);
        let symbol = if let Some(existing) = env.vars.get(target).copied() {
            existing
        } else {
            let created = ensure_known_symbol(builder, &mut env.vars, target, SymbolKind::Local);
            env.vars.insert(target.clone(), created);
            created
        };
        let rhs = build_unpack_index_expr(builder, source_symbol, idx, line_no);
        let inferred_ty = inferred_types.get(idx).and_then(|ty| ty.clone());
        if let Some(ty) = inferred_ty.clone() {
            env.types.insert(target.clone(), ty);
        }
        if !existed_before {
            out.push(Stmt::Let {
                id: builder.alloc_stmt_id(),
                symbol,
                ty: inferred_ty.as_ref().map(|ty| builder.ensure_type(ty)),
                init: Some(rhs),
                span,
            });
        } else {
            out.push(Stmt::Assign {
                id: builder.alloc_stmt_id(),
                lhs: LValue::Var(symbol),
                rhs,
                span,
            });
        }
    }
}

fn bind_comprehension_target_env(
    builder: &mut ModuleBuilder,
    env: &mut PyEnv,
    target_text: &str,
    item_ty: Option<&str>,
    line_no: u32,
    slot_base: usize,
) {
    let trimmed = target_text.trim();
    let destructured = parse_destructuring_targets(trimmed);
    if destructured.is_empty() {
        if is_simple_ident(trimmed) {
            env.vars.insert(trimmed.to_string(), new_unpack_symbol(builder, "comp_item", line_no, slot_base));
            if let Some(ty) = item_ty {
                env.types.insert(trimmed.to_string(), ty.to_string());
            }
        }
        return;
    }
    let target_types = item_ty.and_then(destructure_type_elements).unwrap_or_default();
    for (idx, target) in destructured.into_iter().enumerate() {
        env.vars.insert(target.clone(), new_unpack_symbol(builder, "comp_item", line_no, slot_base + idx));
        if let Some(ty) = target_types.get(idx) {
            env.types.insert(target, ty.clone());
        }
    }
}

fn bind_comprehension_target_types_only(env: &mut PyEnv, target_text: &str, item_ty: Option<&str>) {
    let trimmed = target_text.trim();
    let destructured = parse_destructuring_targets(trimmed);
    if destructured.is_empty() {
        if is_simple_ident(trimmed) {
            if let Some(ty) = item_ty {
                env.types.insert(trimmed.to_string(), ty.to_string());
            }
        }
        return;
    }
    let target_types = item_ty.and_then(destructure_type_elements).unwrap_or_default();
    for (idx, target) in destructured.into_iter().enumerate() {
        if let Some(ty) = target_types.get(idx) {
            env.types.insert(target, ty.clone());
        }
    }
}

fn parse_imports_shallow_for_module(source: &str, module_name: &str) -> PyImports {
    parse_imports_shallow_for_module_kind(source, module_name, false)
}

fn parse_imports_shallow_for_module_kind(
    source: &str,
    module_name: &str,
    current_is_package: bool,
) -> PyImports {
    let mut imports = PyImports::default();

    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("import ") {
            for part in split_top_level_commas(rest) {
                let entry = part.trim();
                if entry.is_empty() {
                    continue;
                }
                let (path, alias) = if let Some((lhs, rhs)) = entry.split_once(" as ") {
                    (lhs.trim(), Some(rhs.trim().to_string()))
                } else {
                    (entry, None)
                };
                let path = resolve_relative_import_base(module_name, path, current_is_package);
                let alias = alias.unwrap_or_else(|| {
                    path.split('.')
                        .next()
                        .unwrap_or(path.as_str())
                        .to_string()
                });
                imports.aliases.insert(alias, path);
            }
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("from ") {
            let Some((base, names)) = rest.split_once(" import ") else {
                continue;
            };
            let base = resolve_relative_import_base(module_name, base.trim(), current_is_package);
            for part in split_top_level_commas(names) {
                let entry = part.trim();
                if entry.is_empty() {
                    continue;
                }
                if entry == "*" {
                    imports.wildcard_bases.push(base.to_string());
                    continue;
                }
                let (name, alias) = if let Some((lhs, rhs)) = entry.split_once(" as ") {
                    (lhs.trim(), Some(rhs.trim().to_string()))
                } else {
                    (entry, None)
                };
                let full = if name == "." || name.is_empty() {
                    base.to_string()
                } else {
                    format!("{base}.{name}")
                };
                let alias = alias.unwrap_or_else(|| name.to_string());
                imports.aliases.insert(alias, full);
            }
        }
    }

    imports
}

fn parse_imports(source: &str, builder: &mut ModuleBuilder, module_name: &str) -> PyImports {
    let imports = parse_imports_shallow_for_module(source, module_name);
    for (alias, path) in &imports.aliases {
        builder.add_import(path, Some(alias.clone()));
    }
    for base in &imports.wildcard_bases {
        builder.add_import(&format!("{base}.*"), Some("*".to_string()));
    }
    imports
}

fn parse_module_exports_all(source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if let Some((left, right)) = split_once_top_level(line, '=') {
            if left.trim() != "__all__" {
                continue;
            }
            let rhs = right.trim();
            if !(rhs.starts_with('[') && rhs.ends_with(']')) && !(rhs.starts_with('(') && rhs.ends_with(')')) {
                continue;
            }
            let inner = &rhs[1..rhs.len().saturating_sub(1)];
            for item in split_top_level_commas(inner) {
                let value = item.trim();
                if is_string_literal(value) && value.len() >= 2 {
                    out.insert(value[1..value.len() - 1].to_string());
                }
            }
        }
    }
    out
}

fn canonicalize_prefixed_project_path(index: &PyProjectIndex, path: &str) -> Option<String> {
    let mut parts = path.split('.').filter(|part| !part.is_empty());
    let first = parts.next()?;
    let mut current = first.to_string();
    for part in parts {
        if index.module_exists(&current) {
            if let Some(member) = index.resolve_module_member(&current, part) {
                current = member;
                continue;
            }
        }
        current = format!("{current}.{part}");
    }
    Some(canonicalize_project_path(index, &current))
}

fn resolve_prefixed_imported_name(name: &str, imports: &PyImports, env: &PyEnv) -> Option<String> {
    let (head, tail) = split_once_top_level(name, '.')?;
    let head = head.trim();
    let tail = tail.trim();
    if head.is_empty() || tail.is_empty() {
        return None;
    }
    if let Some(base) = imports.aliases.get(head) {
        return canonicalize_prefixed_project_path(&env.project_index, &format!("{base}.{tail}"));
    }
    if let Some(base) = env.project_index.resolve_module_member(&env.current_module, head) {
        return canonicalize_prefixed_project_path(&env.project_index, &format!("{base}.{tail}"));
    }
    if env.project_index.module_exists(head) {
        return canonicalize_prefixed_project_path(&env.project_index, name);
    }
    None
}

fn resolve_imported_name(name: &str, imports: &PyImports, env: &PyEnv) -> Option<String> {
    if let Some(prefixed) = resolve_prefixed_imported_name(name, imports, env) {
        return Some(prefixed);
    }
    if let Some(mapped) = imports.aliases.get(name) {
        return Some(canonicalize_project_path(&env.project_index, mapped));
    }
    let mut candidates = Vec::new();
    for base in &imports.wildcard_bases {
        if let Some(member) = env.project_index.resolve_module_member(base, name) {
            candidates.push(canonicalize_project_path(&env.project_index, &member));
        } else {
            candidates.push(canonicalize_project_path(&env.project_index, &format!("{base}.{name}")));
        }
    }
    if let Some(in_module) = env.project_index.resolve_module_member(&env.current_module, name) {
        candidates.push(canonicalize_project_path(&env.project_index, &in_module));
    }
    if let Some(unique) = env.project_index.resolve_simple_class(name) {
        candidates.push(canonicalize_project_path(&env.project_index, &unique));
    }
    if let Some(unique_fn) = env.project_index.resolve_simple_function(name) {
        candidates.push(canonicalize_project_path(&env.project_index, &unique_fn));
    }
    candidates.sort();
    candidates.dedup();
    if candidates.len() == 1 {
        return candidates.into_iter().next();
    }
    None
}

fn qualify_class_name(module_name: &str, class_name: &str, project_index: Option<&PyProjectIndex>) -> String {
    project_index
        .and_then(|index| index.resolve_module_member(module_name, class_name))
        .unwrap_or_else(|| {
            if class_name.contains('.') || module_name.is_empty() {
                class_name.to_string()
            } else {
                format!("{module_name}.{class_name}")
            }
        })
}

fn qualify_local_python_type(ty: &str, module_name: &str, known_classes: &HashSet<String>) -> String {
    let trimmed = ty.trim();
    if known_classes.contains(trimmed) && !trimmed.contains('.') {
        return format!("{module_name}.{trimmed}");
    }
    for prefix in ["list<", "set<", "generator<", "callable<"] {
        if let Some(inner) = trimmed.strip_prefix(prefix).and_then(|rest| rest.strip_suffix('>')) {
            return format!("{}{}>", prefix, qualify_local_python_type(inner, module_name, known_classes));
        }
    }
    if let Some(inner) = trimmed.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, value)) = split_once_top_level(inner, ',') {
            return format!(
                "dict<{},{}>",
                qualify_local_python_type(key.trim(), module_name, known_classes),
                qualify_local_python_type(value.trim(), module_name, known_classes)
            );
        }
    }
    if let Some(inner) = trimmed.strip_prefix("tuple<").and_then(|rest| rest.strip_suffix('>')) {
        let parts = split_top_level_separator(inner, '|')
            .into_iter()
            .map(|part| qualify_local_python_type(part.trim(), module_name, known_classes))
            .collect::<Vec<_>>();
        return format!("tuple<{}>", parts.join("|"));
    }
    trimmed.to_string()
}

fn qualify_type_name(
    module_name: &str,
    name: &str,
    imports: &PyImports,
    project_index: Option<&PyProjectIndex>,
) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((base, _inner)) = split_python_generic_annotation(trimmed) {
        if base != trimmed {
            return qualify_type_name(module_name, &base, imports, project_index);
        }
    }
    if let Some(index) = project_index {
        if let Some(mapped) = imports.aliases.get(trimmed) {
            return Some(canonicalize_project_path(index, mapped));
        }
        if trimmed.contains('.') {
            if let Some((head, tail)) = split_once_top_level(trimmed, '.') {
                if let Some(mapped) = imports.aliases.get(head.trim()) {
                    return canonicalize_prefixed_project_path(index, &format!("{}.{}", mapped, tail.trim()));
                }
            }
            return Some(canonicalize_project_path(index, trimmed));
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
    }
    if let Some(mapped) = imports.aliases.get(trimmed) {
        return Some(mapped.clone());
    }
    if trimmed.contains('.') {
        return Some(trimmed.to_string());
    }
    Some(trimmed.to_string())
}

fn split_python_generic_annotation(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if !trimmed.ends_with(']') {
        return None;
    }
    let mut depth_paren = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            '[' if depth_paren == 0 && depth_brace == 0 && depth_angle == 0 => {
                let base = trimmed[..idx].trim();
                let inner = &trimmed[idx + 1..trimmed.len().saturating_sub(1)];
                if !base.is_empty() {
                    return Some((base.to_string(), inner.to_string()));
                }
                return None;
            }
            _ => {}
        }
    }
    None
}

fn is_builtin_generic_type_name(name: &str) -> bool {
    matches!(
        name,
        "list" | "set" | "dict" | "tuple" | "generator" | "callable" | "defaultdict" | "deque"
    )
}

fn split_project_instantiated_type(text: &str) -> Option<(String, Vec<String>)> {
    let trimmed = text.trim();
    if !trimmed.ends_with('>') {
        return None;
    }
    let mut depth_paren = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_bracket = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '<' if depth_paren == 0 && depth_brace == 0 && depth_bracket == 0 => {
                let base = trimmed[..idx].trim();
                if base.is_empty() || !base.contains('.') || is_builtin_generic_type_name(base) {
                    return None;
                }
                let inner = &trimmed[idx + 1..trimmed.len().saturating_sub(1)];
                let args = split_top_level_commas(inner)
                    .into_iter()
                    .map(|part| part.trim().to_string())
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>();
                if args.is_empty() {
                    return None;
                }
                return Some((base.to_string(), args));
            }
            _ => {}
        }
    }
    None
}

fn project_instantiated_type_mapping(
    params: &[String],
    args: &[String],
) -> HashMap<String, String> {
    params
        .iter()
        .cloned()
        .zip(args.iter().cloned())
        .filter(|(param, arg)| !param.is_empty() && !arg.is_empty())
        .collect()
}

fn infer_class_type_params(raw_bases: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in raw_bases {
        let Some((base, inner)) = split_python_generic_annotation(raw) else {
            continue;
        };
        if !matches!(
            base.as_str(),
            "Generic" | "typing.Generic" | "Protocol" | "typing.Protocol" | "typing_extensions.Protocol"
        ) && !base.ends_with(".Generic")
            && !base.ends_with(".Protocol")
        {
            continue;
        }
        for part in split_top_level_commas(&inner) {
            let name = part.trim();
            if is_simple_ident(name) && !out.iter().any(|existing| existing == name) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn infer_class_base_type_args(
    raw_bases: &[String],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for raw in raw_bases {
        let Some((base, inner)) = split_python_generic_annotation(raw) else {
            continue;
        };
        let Some(canonical_base) = qualify_type_name(module_name, &base, imports, Some(index)) else {
            continue;
        };
        let args = split_top_level_commas(&inner)
            .into_iter()
            .filter_map(|part| {
                let part = part.trim();
                if part.is_empty() {
                    return None;
                }
                normalize_python_annotation_type(part, module_name, imports, Some(index))
                    .or_else(|| qualify_type_name(module_name, part, imports, Some(index)))
                    .or_else(|| Some(part.to_string()))
            })
            .collect::<Vec<_>>();
        if !args.is_empty() {
            out.insert(canonical_base, args);
        }
    }
    out
}

fn has_top_level_separator(text: &str, separator: char) -> bool {
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for ch in text.chars() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            _ if ch == separator && depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && depth_angle == 0 => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn split_top_level_separator(text: &str, separator: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for (idx, ch) in text.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            _ if ch == separator && depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && depth_angle == 0 => {
                out.push(text[start..idx].trim().to_string());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(text[start..].trim().to_string());
    out
}

fn split_angle_type_args(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if !trimmed.ends_with('>') {
        return None;
    }
    let mut depth_paren = 0usize;
    let mut depth_bracket = 0usize;
    let mut depth_brace = 0usize;
    let mut depth_angle = 0usize;
    for (idx, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth_paren += 1,
            ')' => depth_paren = depth_paren.saturating_sub(1),
            '[' => depth_bracket += 1,
            ']' => depth_bracket = depth_bracket.saturating_sub(1),
            '{' => depth_brace += 1,
            '}' => depth_brace = depth_brace.saturating_sub(1),
            '<' if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && depth_angle == 0 => {
                let base = trimmed[..idx].trim();
                let inner = &trimmed[idx + 1..trimmed.len().saturating_sub(1)];
                if !base.is_empty() {
                    return Some((base.to_string(), inner.to_string()));
                }
                return None;
            }
            '<' => depth_angle += 1,
            '>' => depth_angle = depth_angle.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn substitute_project_type_params_in_type(ty: &str, mapping: &HashMap<String, String>) -> String {
    let trimmed = ty.trim();
    if trimmed.is_empty() || mapping.is_empty() {
        return trimmed.to_string();
    }
    if let Some(mapped) = mapping.get(trimmed) {
        return mapped.clone();
    }
    if has_top_level_separator(trimmed, '|') {
        let parts = split_top_level_separator(trimmed, '|')
            .into_iter()
            .map(|part| substitute_project_type_params_in_type(&part, mapping))
            .collect::<Vec<_>>();
        return parts.join("|");
    }
    if let Some((base, inner)) = split_angle_type_args(trimmed) {
        let separator = if base == "tuple" { '|' } else { ',' };
        let sep = separator.to_string();
        let parts = split_top_level_separator(&inner, separator)
            .into_iter()
            .map(|part| substitute_project_type_params_in_type(&part, mapping))
            .collect::<Vec<_>>();
        return format!("{base}<{}>", parts.join(&sep));
    }
    trimmed.to_string()
}

fn substitute_self_type_in_type(ty: &str, concrete_class: &str) -> String {
    let trimmed = ty.trim();
    if matches!(trimmed, "Self" | "typing.Self" | "typing_extensions.Self") {
        return concrete_class.to_string();
    }
    if has_top_level_separator(trimmed, '|') {
        let parts = split_top_level_separator(trimmed, '|')
            .into_iter()
            .map(|part| substitute_self_type_in_type(&part, concrete_class))
            .collect::<Vec<_>>();
        return parts.join("|");
    }
    if let Some(inner) = trimmed.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("list<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("set<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("set<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("generator<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("generator<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("callable<").and_then(|rest| rest.strip_suffix('>')) {
        return format!("callable<{}>", substitute_self_type_in_type(inner, concrete_class));
    }
    if let Some(inner) = trimmed.strip_prefix("tuple<").and_then(|rest| rest.strip_suffix('>')) {
        let parts = split_top_level_commas(inner)
            .into_iter()
            .map(|part| substitute_self_type_in_type(&part, concrete_class))
            .collect::<Vec<_>>();
        return format!("tuple<{}>", parts.join("|"));
    }
    if let Some(inner) = trimmed.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
        if let Some((key, value)) = split_once_top_level(inner, ',') {
            return format!(
                "dict<{},{}>",
                substitute_self_type_in_type(key.trim(), concrete_class),
                substitute_self_type_in_type(value.trim(), concrete_class)
            );
        }
    }
    trimmed.to_string()
}

fn split_python_keyword_arg(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if ["==", "!=", ">=", "<=", ":="]
        .iter()
        .any(|token| trimmed.contains(token))
    {
        return None;
    }
    let (left, right) = split_once_top_level(trimmed, '=')?;
    if !is_simple_ident(left.trim()) {
        return None;
    }
    Some((left.trim().to_string(), right.trim().to_string()))
}

fn normalize_python_argument_expr(text: &str) -> String {
    let trimmed = text.trim();
    if let Some(inner) = trimmed.strip_prefix("await ") {
        return normalize_python_argument_expr(inner);
    }
    if let Some(inner) = trimmed.strip_prefix("**") {
        return inner.trim().to_string();
    }
    if let Some(inner) = trimmed.strip_prefix('*') {
        return inner.trim().to_string();
    }
    if let Some((_, right)) = split_python_keyword_arg(trimmed) {
        return right;
    }
    trimmed.to_string()
}

fn split_python_call_args(arg_text: &str) -> Vec<String> {
    parse_python_call_args_detailed(arg_text)
        .into_iter()
        .map(|arg| arg.expr)
        .collect()
}

fn parse_static_sequence_items(text: &str) -> Option<Vec<String>> {
    let trimmed = text.trim();
    if (trimmed.starts_with('(') && trimmed.ends_with(')')) || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        let items = split_top_level_commas(inner)
            .into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect::<Vec<_>>();
        return Some(items);
    }
    None
}

fn parse_static_mapping_entries(text: &str) -> Option<Vec<(String, String)>> {
    let trimmed = text.trim();
    let mut out = Vec::new();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        let inner = &trimmed[1..trimmed.len().saturating_sub(1)];
        for entry in split_top_level_commas(inner).into_iter().filter(|part| !part.trim().is_empty()) {
            if let Some((key_text, value_text)) = split_once_top_level(&entry, ':') {
                if let Some(key) = strip_python_string_literal(&key_text).or_else(|| {
                    let key = key_text.trim();
                    is_simple_ident(key).then(|| key.to_string())
                }) {
                    out.push((key, value_text.trim().to_string()));
                }
            }
        }
        return (!out.is_empty()).then_some(out);
    }
    if let Some((dict_callee, dict_args)) = parse_call_parts(trimmed) {
        let dict_name = dict_callee.trim();
        if dict_name == "dict" || dict_name == "builtins.dict" {
            for entry in parse_python_call_args_detailed(&dict_args) {
                if entry.spread == PyCallArgSpread::StarStar {
                    if let Some(items) = parse_static_mapping_entries(&entry.expr) {
                        out.extend(items);
                    }
                    continue;
                }
                if let Some(name) = entry.name {
                    out.push((name, entry.expr.trim().to_string()));
                }
            }
            return (!out.is_empty()).then_some(out);
        }
    }
    None
}

fn current_super_type(env: &PyEnv) -> Option<String> {
    env.current_class_bases
        .first()
        .cloned()
        .or_else(|| env.current_class.clone())
}

fn current_project_super_type(index: &PyProjectIndex, current_class: Option<&str>) -> Option<String> {
    let class_name = current_class?;
    index
        .class_bases
        .get(class_name)
        .and_then(|bases| bases.first().cloned())
        .or_else(|| Some(class_name.to_string()))
}

fn descriptor_access_type(index: &PyProjectIndex, ty: &str) -> Option<String> {
    index
        .method_return(ty, "__get__", 2)
        .or_else(|| index.method_return(ty, "__get__", 1))
}

fn direct_field_access_type(index: &PyProjectIndex, owner_type: &str, field: &str) -> Option<String> {
    let ty = index.field_type(owner_type, field)?;
    descriptor_access_type(index, &ty).or(Some(ty))
}

fn direct_local_field_access_type(env: &PyEnv, owner_name: &str, field: &str) -> Option<String> {
    let raw = env
        .local_field_types
        .get(owner_name)
        .and_then(|fields| fields.get(field))
        .cloned()?;
    descriptor_access_type(&env.project_index, &raw).or(Some(raw))
}

fn direct_env_field_access_type(env: &PyEnv, field: &str) -> Option<String> {
    let raw = env.field_types.get(field).cloned()?;
    descriptor_access_type(&env.project_index, &raw).or(Some(raw))
}

