#[derive(Clone, Default)]
struct CLikeEnv {
    language: Option<Language>,
    vars: HashMap<String, SymbolId>,
    types: HashMap<String, String>,
    pointer_aliases: HashMap<String, String>,
    heap_types: HashMap<String, String>,
    struct_field_types: HashMap<String, HashMap<String, String>>,
    function_pointer_vars: HashSet<String>,
    function_aliases: HashMap<String, Vec<String>>,
    known_functions: HashSet<String>,
}

#[derive(Clone, Debug)]
struct FunctionPointerDecl {
    name: String,
    ty: String,
    alias: Option<String>,
}

fn parse_function_pointer_declaration(stmt: &str) -> Option<FunctionPointerDecl> {
    let re = Regex::new(
        r"(?x)
        ^\s*
        (.+?)
        \(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)
        \s*\([^)]*\)
        (?:\s*=\s*([A-Za-z_][A-Za-z0-9_]*))?
        \s*$
        ",
    )
    .expect("valid regex");
    let caps = re.captures(stmt)?;
    let ret = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("void");
    let name = caps.get(2).map(|m| m.as_str()).unwrap_or("fp").to_string();
    let alias = caps.get(3).map(|m| m.as_str().to_string());
    Some(FunctionPointerDecl {
        name,
        ty: format!("fnptr<{ret}>"),
        alias,
    })
}

fn infer_function_aliases(text: &str, env: &CLikeEnv) -> Option<Vec<String>> {
    let trimmed = text.trim().trim_start_matches('&').trim();
    if let Some(existing) = env.function_aliases.get(trimmed) {
        return Some(existing.clone());
    }
    if env.known_functions.contains(trimmed) {
        return Some(vec![trimmed.to_string()]);
    }
    let ident_re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("valid regex");
    if ident_re.is_match(trimmed) && !env.vars.contains_key(trimmed) {
        return Some(vec![trimmed.to_string()]);
    }
    None
}

fn is_storage_access_path(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains('(') || trimmed.contains(')') {
        return false;
    }
    let mut bracket_depth = 0usize;
    for ch in trimmed.chars() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                if bracket_depth == 0 {
                    return false;
                }
                bracket_depth -= 1;
            }
            '+' | '-' | '/' | '%' | '=' | '!' | '?' | ':' | ',' if bracket_depth == 0 => {
                return false;
            }
            _ => {}
        }
    }
    if bracket_depth != 0 {
        return false;
    }
    let base = trimmed
        .split(['.', '['])
        .next()
        .unwrap_or_default()
        .trim();
    !base.is_empty()
        && base
            .chars()
            .enumerate()
            .all(|(idx, ch)| ch == '_' || ch.is_ascii_alphanumeric() && (idx > 0 || !ch.is_ascii_digit()))
}

fn infer_pointer_alias_target(text: &str, env: &CLikeEnv) -> Option<String> {
    let trimmed = text.trim();
    if let Some(alias) = trimmed.strip_prefix('&').map(|s| normalize_member_access(s.trim(), env)) {
        if env.vars.contains_key(&alias) || alias.contains('.') || alias.contains('[') {
            return Some(alias);
        }
    }
    let normalized = normalize_member_access(trimmed, env);
    if let Some(alias) = env.pointer_aliases.get(normalized.as_str()) {
        return Some(alias.clone());
    }
    if let Some(alias) = pointee_alias(normalized.as_str(), env) {
        return Some(alias);
    }
    if is_storage_access_path(&normalized)
        && (normalized.contains('.') || normalized.contains('['))
    {
        return Some(normalized);
    }
    if env.types.get(normalized.as_str()).is_some_and(|ty| ty.contains('*')) {
        return Some(normalized);
    }
    None
}

fn infer_copy_result_alias(text: &str, env: &CLikeEnv) -> Option<String> {
    let (callee_text, arg_text) = parse_call_parts(text.trim())?;
    let bare = callee_text
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_start_matches('*')
        .trim();
    let args = split_top_level_commas(&arg_text);
    let source_idx = match bare {
        "strdup" | "strndup" | "strdupa" | "strndupa" => 0,
        "strcpy" | "strncpy" | "stpncpy" | "strcat" | "strncat" | "memcpy" | "memmove" | "stpcpy" | "mempcpy" | "memccpy" | "strlcpy" | "strlcat" => {
            let dst = args.get(0)?.trim();
            return infer_pointer_alias_target(dst, env).or_else(|| Some(normalize_member_access(dst, env)));
        }
        "strchr" | "strrchr" | "memchr" | "memrchr" | "rawmemchr" | "strchrnul" | "index" | "rindex" | "strstr" | "strcasestr" | "strpbrk" | "memmem" | "strnstr" | "basename" | "dirname" | "realpath" => 0,
        "strtok" => 0,
        "strtok_r" | "strsep" => 0,
        _ => return None,
    };
    let src = args.get(source_idx)?.trim();
    infer_pointer_alias_target(src, env).or_else(|| Some(normalize_member_access(src, env)))
}

fn is_declaration(left: &str, env: &CLikeEnv) -> bool {
    let pieces: Vec<&str> = left.split_whitespace().collect();
    if pieces.len() < 2 {
        return false;
    }
    let name = pieces[pieces.len() - 1].trim_matches('*').trim_matches('&');
    !env.vars.contains_key(name)
}


fn split_array_declarator_suffix(text: &str) -> (String, Vec<Option<String>>) {
    let mut declarator = text.trim().trim_end_matches(';').trim().to_string();
    let mut extents = Vec::new();
    loop {
        let trimmed = declarator.trim_end();
        if !trimmed.ends_with(']') {
            break;
        }
        let mut depth = 0usize;
        let mut open = None;
        for (idx, ch) in trimmed.char_indices().rev() {
            match ch {
                ']' => depth += 1,
                '[' => {
                    if depth == 0 {
                        return (declarator, Vec::new());
                    }
                    depth -= 1;
                    if depth == 0 {
                        open = Some(idx);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(open) = open else {
            break;
        };
        let extent = trimmed[open + 1..trimmed.len() - 1].trim();
        extents.push((!extent.is_empty()).then(|| extent.to_string()));
        declarator.truncate(open);
        declarator = declarator.trim_end().to_string();
    }
    extents.reverse();
    (declarator, extents)
}

fn parse_typed_name(text: &str) -> Option<(String, String)> {
    let (trimmed, _) = split_array_declarator_suffix(text);
    if trimmed.is_empty() {
        return None;
    }
    let ident_re = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*$").expect("valid regex");
    let caps = ident_re.captures(&trimmed)?;
    let name_match = caps.get(1)?;
    let name = name_match.as_str().to_string();
    let mut ty = trimmed[..name_match.start()].trim().to_string();
    if ty.is_empty() {
        return None;
    }
    ty = ty
        .split_whitespace()
        .filter(|part| !matches!(*part, "register" | "auto" | "extern" | "static"))
        .collect::<Vec<_>>()
        .join(" ");
    Some((name, ty))
}

fn record_array_extents(
    builder: &mut ModuleBuilder,
    symbol: SymbolId,
    declaration: &str,
    env: &mut CLikeEnv,
) {
    let (_, extent_texts) = split_array_declarator_suffix(declaration);
    if extent_texts.is_empty() {
        return;
    }
    let extents = extent_texts
        .into_iter()
        .map(|extent| extent.map(|text| parse_expr(builder, &text, env)))
        .collect();
    builder.set_symbol_array_extents(symbol, extents);
}

fn parse_variable_declaration(stmt: &str) -> Option<(String, String)> {
    let trimmed = stmt.trim();
    if trimmed.contains('=') || trimmed.contains('(') || trimmed.contains(',') {
        return None;
    }
    parse_typed_name(trimmed)
}

fn pointee_alias(text: &str, env: &CLikeEnv) -> Option<String> {
    let trimmed = text.trim().trim_start_matches('(').trim_end_matches(')').trim();
    env.pointer_aliases.get(trimmed).cloned()
}

fn normalize_member_access(text: &str, env: &CLikeEnv) -> String {
    let mut normalized = text.trim().replace("->", ".");
    let re = Regex::new(r"\(\s*\*\s*([^)]+?)\s*\)\s*\.").expect("valid regex");
    normalized = re
        .replace_all(&normalized, |caps: &regex::Captures| {
            let expr = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let inner = normalize_member_access(expr, env);
            let target = env.pointer_aliases.get(inner.as_str()).cloned().unwrap_or(inner);
            format!("{target}.")
        })
        .into_owned();
    let re_arrow = Regex::new(r"\(\s*\*\s*([^)]+?)\s*\)\s*->").expect("valid regex");
    normalized = re_arrow
        .replace_all(&normalized, |caps: &regex::Captures| {
            let expr = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let inner = normalize_member_access(expr, env);
            let target = env.pointer_aliases.get(inner.as_str()).cloned().unwrap_or(inner);
            format!("{target}.")
        })
        .into_owned();
    normalized
}

fn normalized_storage_key(text: &str, env: &CLikeEnv) -> String {
    let normalized = normalize_member_access(text, env);
    pointee_alias(normalized.trim(), env).unwrap_or(normalized)
}

fn inferred_rhs_type(text: &str, env: &CLikeEnv) -> Option<String> {
    resolve_access_type(text, env)
        .or_else(|| env.heap_types.get(normalize_member_access(text, env).as_str()).cloned())
        .map(|ty| strip_pointer_qualifiers(&ty))
        .filter(|ty| !ty.is_empty())
}

fn strip_pointer_qualifiers(ty: &str) -> String {
    ty.replace('*', "").replace('&', "").trim().to_string()
}

fn resolve_access_type(text: &str, env: &CLikeEnv) -> Option<String> {
    let normalized = normalize_member_access(text, env);
    if let Some(ty) = env.types.get(normalized.as_str()) {
        let stripped = strip_pointer_qualifiers(ty);
        if !stripped.is_empty() {
            return Some(stripped);
        }
    }
    if let Some(ty) = env.heap_types.get(normalized.as_str()) {
        let stripped = strip_pointer_qualifiers(ty);
        if !stripped.is_empty() {
            return Some(stripped);
        }
    }
    if let Some(alias) = env.pointer_aliases.get(normalized.as_str()) {
        if alias != &normalized {
            if let Some(ty) = resolve_access_type(alias, env) {
                return Some(ty);
            }
        }
    }
    if normalized.ends_with(']') {
        if let Some(open) = normalized.rfind('[') {
            let base_text = normalized[..open].trim();
            return resolve_access_type(base_text, env);
        }
    }
    if let Some((base, field)) = split_last_top_level_dot(&normalized) {
        let base_ty = resolve_access_type(&base, env)?;
        if let Some(fields) = env.struct_field_types.get(&base_ty) {
            if let Some(field_ty) = fields.get(&field) {
                let stripped = strip_pointer_qualifiers(field_ty);
                if !stripped.is_empty() {
                    return Some(stripped);
                }
            }
        }
        if let Some(field_ty) = env.heap_types.get(normalized.as_str()) {
            let stripped = strip_pointer_qualifiers(field_ty);
            if !stripped.is_empty() {
                return Some(stripped);
            }
        }
    }
    None
}

fn infer_alloc_type_from_sizeof_expr(trimmed: &str, env: &CLikeEnv) -> Option<String> {
    let sizeof_ptr = Regex::new(r"sizeof\s*\(\s*\*\s*([^)]+?)\s*\)").expect("valid regex");
    if let Some(caps) = sizeof_ptr.captures(trimmed) {
        let expr = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(ty) = resolve_access_type(expr, env) {
            return Some(ty);
        }
    }
    let sizeof_name = Regex::new(r"sizeof\s*\(?\s*([A-Za-z_][A-Za-z0-9_\.\->\[\]\(\)]+)\s*\)?").expect("valid regex");
    if let Some(caps) = sizeof_name.captures(trimmed) {
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        if let Some(ty) = resolve_access_type(name, env) {
            return Some(ty);
        }
    }
    None
}

fn parse_alloc_expr(
    builder: &mut ModuleBuilder,
    text: &str,
    env: &mut CLikeEnv,
    declared_type: Option<&str>,
) -> Option<Expr> {
    let trimmed = text.trim();
    // Match the allocator identifier itself, not an arbitrary substring. In
    // particular `_aligned_malloc(...)` must stay a normal named call so
    // path-sensitive checkers can distinguish its provenance from malloc.
    let allocator_re =
        Regex::new(r"(?:^|[^A-Za-z0-9_])(?P<name>malloc|calloc)\s*\(").expect("valid regex");
    let alloc_caps = allocator_re.captures(trimmed)?;
    let alloc_name = alloc_caps.name("name")?.as_str();

    let type_name = declared_type
        .map(strip_pointer_qualifiers)
        .filter(|ty| !ty.is_empty())
        .or_else(|| {
            let sizeof_re = Regex::new(r"sizeof\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)").expect("valid regex");
            sizeof_re
                .captures(trimmed)
                .and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        })
        .or_else(|| infer_alloc_type_from_sizeof_expr(trimmed, env))?;

    let call_start = trimmed.find(alloc_name)?;
    let call_text = &trimmed[call_start..];
    let (_, arg_text) = parse_call_parts(call_text)?;
    let args = split_top_level_commas(&arg_text)
        .into_iter()
        .map(|arg| parse_expr(builder, &arg, env))
        .collect::<Vec<_>>();

    Some(Expr::New {
        id: builder.alloc_expr_id(),
        type_name,
        args,
        span: default_span(),
    })
}


fn parse_copy_propagation_stmt(
    builder: &mut ModuleBuilder,
    stmt: &str,
    env: &mut CLikeEnv,
) -> Option<Vec<Stmt>> {
    let (callee_text, arg_text) = parse_call_parts(stmt.trim())?;
    let bare = callee_text
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim_start_matches('*')
        .trim();
    let args = split_top_level_commas(&arg_text);
    let (lhs_idx, source_idx) = match bare {
        "memcpy" | "memmove" | "memccpy" | "strcpy" | "strncpy" | "stpncpy" | "strcat" | "strncat" | "stpcpy" | "mempcpy" | "strlcpy" | "strlcat" => (0, 1),
        "bcopy" => (1, 0),
        _ => return None,
    };
    if args.len() <= source_idx || args.len() <= lhs_idx {
        return None;
    }
    let lhs_text = args[lhs_idx].trim();
    let src_text = args[source_idx].trim();
    let lhs_name = normalized_storage_key(lhs_text, env);
    if let Some(alias) = infer_pointer_alias_target(src_text, env) {
        env.pointer_aliases.insert(lhs_name.clone(), alias);
    }
    if let Some(rhs_ty) = inferred_rhs_type(src_text, env) {
        env.heap_types.insert(lhs_name.clone(), rhs_ty);
    }
    let lhs = parse_lvalue(builder, lhs_text, env);
    let rhs = parse_expr(builder, src_text, env);
    let span = default_span();
    let call_expr = parse_expr(builder, stmt, env);
    Some(vec![
        Stmt::Assign {
            id: builder.alloc_stmt_id(),
            lhs,
            rhs,
            span,
        },
        Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: call_expr,
            span,
        },
    ])
}
