use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use uniflow_hir::{
    Block, Class, Expr, Field, Item, Language, LValue, Param, ParamKind, Stmt, SymbolId, SymbolKind,
    UnaryOp,
};
use uniflow_parser_core::{
    default_span, ensure_known_symbol, find_matching_brace, is_int_literal, is_string_literal,
    module_name_from_path, new_call, new_dynamic_call, new_field_read, new_int, new_string,
    new_var_ref, parse_call_parts, split_last_top_level_dot, split_once_top_level,
    split_top_level_commas, split_top_level_statements_c_like, strip_c_like_comments,
    ModuleBuilder, SourceParser,
};

#[derive(Default)]
pub struct CParser;

impl SourceParser for CParser {
    fn language(&self) -> Language {
        Language::C
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<uniflow_hir::Program> {
        parse_c_like_file(Language::C, path, source)
    }
}

pub fn parse_c_like_file(language: Language, path: &str, source: &str) -> Result<uniflow_hir::Program> {
    let source = strip_c_like_comments(source);
    let module_name = module_name_from_path(path);
    let mut builder = ModuleBuilder::new(language, path, &module_name);
    parse_includes(&source, &mut builder);

    let classes = extract_struct_items(&source, &mut builder);
    let struct_field_types = classes
        .iter()
        .map(|class| {
            let fields = class
                .fields
                .iter()
                .filter_map(|field| {
                    field
                        .ty
                        .and_then(|id| builder.find_type_name(id))
                        .map(|ty| (field.name.clone(), ty.to_string()))
                })
                .collect::<HashMap<_, _>>();
            (class.name.clone(), fields)
        })
        .collect::<HashMap<_, _>>();
    for class in classes {
        builder.push_item(Item::Class(class));
    }

    let functions = extract_functions(&source);
    let known_functions = functions
        .iter()
        .map(|func| func.name.clone())
        .collect::<HashSet<_>>();

    for func in functions {
        let hir_func = parse_function(&mut builder, &func, &known_functions, &struct_field_types);
        builder.push_item(Item::Function(hir_func));
    }

    Ok(builder.finish())
}

#[derive(Clone, Debug)]
struct CFunctionText {
    ret_type: String,
    name: String,
    params: String,
    body: String,
}

fn parse_includes(source: &str, builder: &mut ModuleBuilder) {
    let re = Regex::new(r#"(?m)^\s*#\s*include\s*([<"][^>"]+[>"])"#).expect("valid regex");
    for caps in re.captures_iter(source) {
        let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default().trim();
        if raw.len() >= 2 {
            let alias = raw
                .trim_matches('<')
                .trim_matches('>')
                .trim_matches('"')
                .rsplit('/')
                .next()
                .map(|s| s.to_string());
            builder.add_import(raw, alias);
        }
    }
}

fn extract_struct_items(source: &str, builder: &mut ModuleBuilder) -> Vec<Class> {
    let mut out = Vec::new();
    let re = Regex::new(
        r"(?s)(?:typedef\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)?\s*\{(.*?)\}\s*([A-Za-z_][A-Za-z0-9_]*)?\s*;",
    )
    .expect("valid regex");

    for caps in re.captures_iter(source) {
        let head = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
        let tail = caps.get(3).map(|m| m.as_str()).unwrap_or("").trim();
        let name = if !tail.is_empty() { tail } else { head };
        if name.is_empty() {
            continue;
        }
        let body = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let mut fields = Vec::new();
        for stmt in split_top_level_statements_c_like(body) {
            if let Some((field_name, ty_name)) = parse_variable_declaration(stmt.trim()) {
                fields.push(Field {
                    name: field_name.clone(),
                    symbol: Some(builder.add_symbol(&field_name, SymbolKind::Field)),
                    ty: Some(builder.ensure_type(&ty_name)),
                    span: default_span(),
                });
            }
        }
        out.push(Class {
            name: name.to_string(),
            symbol: Some(builder.add_symbol(name, SymbolKind::Class)),
            bases: Vec::new(),
            fields,
            methods: Vec::new(),
            span: default_span(),
        });
    }
    out
}

fn extract_functions(source: &str) -> Vec<CFunctionText> {
    let mut out = Vec::new();
    let sig_re = Regex::new(
        r"(?x)
        ([A-Za-z_][A-Za-z0-9_\s\*\&:<>]*?)
        \s+
        ([A-Za-z_][A-Za-z0-9_:]*)
        \s*
        \(([^)]*)\)
        \s*\{
        ",
    )
    .expect("valid regex");

    let mut idx = 0usize;
    while idx < source.len() {
        let Some(caps) = sig_re.captures(&source[idx..]) else {
            break;
        };
        let m = caps.get(0).expect("whole match must exist");
        let open = idx + m.end() - 1;
        let Some(close) = find_matching_brace(source, open) else {
            break;
        };

        let ret_type = caps.get(1).map(|m| m.as_str()).unwrap_or("void").trim().to_string();
        let name = caps.get(2).map(|m| m.as_str()).unwrap_or("function").trim().to_string();
        let params = caps.get(3).map(|m| m.as_str()).unwrap_or("").to_string();
        let body = source[open + 1..close].to_string();

        if !["if", "for", "while", "switch"].contains(&name.as_str()) {
            out.push(CFunctionText {
                ret_type,
                name,
                params,
                body,
            });
        }

        idx = close + 1;
    }

    out
}

fn parse_function(
    builder: &mut ModuleBuilder,
    func: &CFunctionText,
    known_functions: &HashSet<String>,
    struct_field_types: &HashMap<String, HashMap<String, String>>,
) -> uniflow_hir::Function {
    let mut env = CLikeEnv::default();
    env.known_functions = known_functions.clone();
    env.struct_field_types = struct_field_types.clone();
    let mut params = Vec::new();
    for param in split_top_level_commas(&func.params) {
        let part = param.trim();
        if part.is_empty() || part == "void" {
            continue;
        }
        let pieces: Vec<&str> = part.split_whitespace().collect();
        if pieces.is_empty() {
            continue;
        }
        let name = pieces[pieces.len() - 1].trim_matches('*').trim_matches('&').to_string();
        let ty_name = if pieces.len() >= 2 {
            pieces[..pieces.len() - 1].join(" ")
        } else {
            "unknown".to_string()
        };
        let symbol = builder.add_symbol(&name, SymbolKind::Param);
        env.vars.insert(name.clone(), symbol);
        env.types.insert(name.clone(), ty_name.clone());
        params.push(Param {
            name,
            symbol,
            ty: Some(builder.ensure_type(&ty_name)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            span: default_span(),
        });
    }

    let mut stmts = Vec::new();
    for raw in split_top_level_statements_c_like(&func.body) {
        let stmt = raw.trim();
        if stmt.is_empty() {
            continue;
        }

        if let Some(rest) = stmt.strip_prefix("return ") {
            let value = parse_expr(builder, rest, &mut env);
            stmts.push(Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: Some(value),
                span: default_span(),
            });
            continue;
        }
        if stmt == "return" {
            stmts.push(Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: None,
                span: default_span(),
            });
            continue;
        }

        if let Some(fp) = parse_function_pointer_declaration(stmt) {
            let symbol = builder.add_symbol(&fp.name, SymbolKind::Local);
            env.vars.insert(fp.name.clone(), symbol);
            env.types.insert(fp.name.clone(), fp.ty.clone());
            env.function_pointer_vars.insert(fp.name.clone());
            if let Some(alias) = fp.alias {
                env.function_aliases.insert(fp.name.clone(), vec![alias]);
            }
            stmts.push(Stmt::Let {
                id: builder.alloc_stmt_id(),
                symbol,
                ty: Some(builder.ensure_type(&fp.ty)),
                init: None,
                span: default_span(),
            });
            continue;
        }

        if let Some((left, right)) = split_once_top_level(stmt, '=') {
            if is_declaration(left.as_str(), &env) {
                let pieces: Vec<&str> = left.split_whitespace().collect();
                if pieces.len() < 2 {
                    continue;
                }
                let raw_name = pieces[pieces.len() - 1];
                let name = raw_name.trim_matches('*').trim_matches('&').to_string();
                let ty_name = pieces[..pieces.len() - 1].join(" ");
                let symbol = builder.add_symbol(&name, SymbolKind::Local);
                env.vars.insert(name.clone(), symbol);
                env.types.insert(name.clone(), ty_name.clone());
                if let Some(alias) = infer_pointer_alias_target(right.trim(), &env)
                    .or_else(|| infer_copy_result_alias(right.trim(), &env))
                {
                    env.pointer_aliases.insert(name.clone(), alias);
                }
                if let Some(rhs_ty) = inferred_rhs_type(right.trim(), &env) {
                    env.heap_types.insert(name.clone(), rhs_ty);
                }
                if let Some(aliases) = infer_function_aliases(right.trim(), &env) {
                    env.function_pointer_vars.insert(name.clone());
                    env.function_aliases.insert(name.clone(), aliases);
                }
                let alloc_init = parse_alloc_expr(builder, &right, &mut env, Some(&ty_name));
                if let Some(Expr::New { type_name, .. }) = alloc_init.as_ref() {
                    env.heap_types.insert(name.clone(), type_name.clone());
                }
                let init = alloc_init.unwrap_or_else(|| parse_expr(builder, &right, &mut env));
                stmts.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol,
                    ty: Some(builder.ensure_type(&ty_name)),
                    init: Some(init),
                    span: default_span(),
                });
            } else {
                let lhs_name = left.trim().to_string();
                let lhs_key = normalized_storage_key(&left, &env);
                if let Some(alias) = infer_pointer_alias_target(right.trim(), &env)
                    .or_else(|| infer_copy_result_alias(right.trim(), &env))
                {
                    env.pointer_aliases.insert(lhs_key.clone(), alias);
                }
                if let Some(rhs_ty) = inferred_rhs_type(right.trim(), &env) {
                    env.heap_types.insert(lhs_key.clone(), rhs_ty);
                }
                if let Some(aliases) = infer_function_aliases(right.trim(), &env) {
                    env.function_pointer_vars.insert(lhs_name.clone());
                    env.function_aliases.insert(lhs_name.clone(), aliases);
                }
                let lhs = parse_lvalue(builder, &left, &mut env);
                let lhs_existing_ty = env.types.get(&lhs_name).map(String::as_str).map(str::to_string);
                let alloc_rhs = parse_alloc_expr(builder, &right, &mut env, lhs_existing_ty.as_deref());
                if let Some(Expr::New { type_name, .. }) = alloc_rhs.as_ref() {
                    env.heap_types.insert(lhs_key.clone(), type_name.clone());
                }
                let rhs = alloc_rhs.unwrap_or_else(|| parse_expr(builder, &right, &mut env));
                stmts.push(Stmt::Assign {
                    id: builder.alloc_stmt_id(),
                    lhs,
                    rhs,
                    span: default_span(),
                });
            }
            continue;
        }

        if let Some((name, ty_name)) = parse_variable_declaration(stmt) {
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.vars.insert(name.clone(), symbol);
            env.types.insert(name.clone(), ty_name.clone());
            stmts.push(Stmt::Let {
                id: builder.alloc_stmt_id(),
                symbol,
                ty: Some(builder.ensure_type(&ty_name)),
                init: None,
                span: default_span(),
            });
            continue;
        }

        if let Some(extra_stmts) = parse_copy_propagation_stmt(builder, stmt, &mut env) {
            stmts.extend(extra_stmts);
            continue;
        }

        let expr = parse_expr(builder, stmt, &mut env);
        stmts.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr,
            span: default_span(),
        });
    }

    let body = Block {
        id: builder.alloc_block_id(),
        stmts,
        span: default_span(),
    };

    uniflow_hir::Function {
        id: builder.alloc_function_id(),
        name: func.name.clone(),
        symbol: Some(builder.add_symbol(&func.name, SymbolKind::Function)),
        params,
        captures: Vec::new(),
        return_type: Some(builder.ensure_type(&func.ret_type)),
        body,
        is_method: false,
        receiver: None,
        span: default_span(),
    }
}

#[derive(Default)]
struct CLikeEnv {
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
    if normalized.contains('.') || normalized.contains('[') {
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
        "strtok_r" | "strsep" => 1,
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

fn parse_variable_declaration(stmt: &str) -> Option<(String, String)> {
    let trimmed = stmt.trim();
    if trimmed.contains('=') || trimmed.contains('(') {
        return None;
    }
    let pieces: Vec<&str> = trimmed.split_whitespace().collect();
    if pieces.len() < 2 {
        return None;
    }
    let raw_name = pieces[pieces.len() - 1];
    let name = raw_name.trim_matches('*').trim_matches('&').trim_end_matches(';').to_string();
    if name.is_empty() {
        return None;
    }
    let ty_name = pieces[..pieces.len() - 1].join(" ");
    Some((name, ty_name))
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
    let alloc_name = if trimmed.contains("malloc(") {
        Some("malloc")
    } else if trimmed.contains("calloc(") {
        Some("calloc")
    } else if trimmed.contains("realloc(") {
        Some("realloc")
    } else {
        None
    }?;

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

fn parse_lvalue(builder: &mut ModuleBuilder, text: &str, env: &mut CLikeEnv) -> LValue {
    let normalized = normalize_member_access(text, env);
    if normalized.ends_with(']') {
        if let Some(open) = normalized.rfind('[') {
            let base_text = normalized[..open].trim();
            let index_text = normalized[open + 1..normalized.len() - 1].trim();
            if !base_text.is_empty() && !index_text.is_empty() {
                return LValue::Index {
                    base: Box::new(parse_expr(builder, base_text, env)),
                    index: Box::new(parse_expr(builder, index_text, env)),
                };
            }
        }
    }
    if let Some((base, field)) = split_last_top_level_dot(&normalized) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, env)),
            field,
        }
    } else {
        let target = pointee_alias(normalized.trim(), env).unwrap_or_else(|| normalized.trim().to_string());
        if let Some((base, field)) = split_last_top_level_dot(&target) {
            LValue::Field {
                base: Box::new(parse_expr(builder, &base, env)),
                field,
            }
        } else if target.ends_with(']') {
            if let Some(open) = target.rfind('[') {
                let base_text = target[..open].trim();
                let index_text = target[open + 1..target.len() - 1].trim();
                if !base_text.is_empty() && !index_text.is_empty() {
                    return LValue::Index {
                        base: Box::new(parse_expr(builder, base_text, env)),
                        index: Box::new(parse_expr(builder, index_text, env)),
                    };
                }
            }
            let symbol = ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
            LValue::Var(symbol)
        } else {
            let symbol = ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
            LValue::Var(symbol)
        }
    }
}

fn parse_expr(builder: &mut ModuleBuilder, text: &str, env: &mut CLikeEnv) -> Expr {
    let trimmed = text.trim();
    let normalized = normalize_member_access(trimmed, env);

    if is_string_literal(trimmed) {
        return new_string(builder, &trimmed[1..trimmed.len() - 1]);
    }
    if is_int_literal(trimmed) {
        return new_int(builder, trimmed.parse::<i64>().unwrap_or_default());
    }
    if let Some(inner) = trimmed.strip_prefix('&') {
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::AddrOf,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }
    if let Some(inner) = trimmed.strip_prefix('*') {
        if let Some(alias) = pointee_alias(inner, env) {
            if alias.contains('.') || alias.contains('[') {
                return parse_expr(builder, alias.as_str(), env);
            }
            let symbol = ensure_known_symbol(builder, &mut env.vars, alias.as_str(), SymbolKind::Local);
            return new_var_ref(builder, symbol);
        }
        return Expr::Unary {
            id: builder.alloc_expr_id(),
            op: UnaryOp::Deref,
            expr: Box::new(parse_expr(builder, inner, env)),
            span: default_span(),
        };
    }

    if let Some(expr) = parse_alloc_expr(builder, trimmed, env, None) {
        return expr;
    }

    if normalized.ends_with(']') {
        if let Some(open) = normalized.rfind('[') {
            let base_text = normalized[..open].trim();
            let index_text = normalized[open + 1..normalized.len() - 1].trim();
            if !base_text.is_empty() && !index_text.is_empty() {
                return Expr::IndexRead {
                    id: builder.alloc_expr_id(),
                    base: Box::new(parse_expr(builder, base_text, env)),
                    index: Box::new(parse_expr(builder, index_text, env)),
                    span: default_span(),
                };
            }
        }
    }

    if let Some((callee_text, arg_text)) = parse_call_parts(&normalized) {
        let args = split_top_level_commas(&arg_text)
            .into_iter()
            .map(|arg| parse_expr(builder, &arg, env))
            .collect::<Vec<_>>();

        let bare_callee = callee_text
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim_start_matches('*')
            .trim();

        if let Some((prefix, method)) = split_last_top_level_dot(&callee_text) {
            let receiver = parse_expr(builder, &prefix, env);
            let callee = if let Some(ty) = env.types.get(prefix.as_str()) {
                format!("{ty}.{method}")
            } else {
                format!("{prefix}.{method}")
            };
            return new_call(builder, &callee, Some(receiver), args);
        }

        if let Some(aliases) = env.function_aliases.get(bare_callee) {
            if aliases.len() == 1 {
                return new_call(builder, &aliases[0], None, args);
            }
        }
        if env.function_pointer_vars.contains(bare_callee) {
            let symbol = ensure_known_symbol(builder, &mut env.vars, bare_callee, SymbolKind::Local);
            let callee_expr = new_var_ref(builder, symbol);
            return new_dynamic_call(builder, callee_expr, None, args);
        }

        let callee = callee_text.replace("::", ".");
        return new_call(builder, &callee, None, args);
    }

    if let Some((base, field)) = split_last_top_level_dot(&normalized) {
        let base_expr = parse_expr(builder, &base, env);
        return new_field_read(builder, base_expr, &field);
    }

    let target = pointee_alias(trimmed, env).unwrap_or_else(|| trimmed.to_string());
    let symbol = ensure_known_symbol(builder, &mut env.vars, target.as_str(), SymbolKind::Local);
    new_var_ref(builder, symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn parses_struct_and_field_flow_starter() {
        let src = r#"
typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request req;
  req.cmd = getenv("CMD");
  system(req.cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("demo.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Request")));
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn parses_heap_and_pointer_alias_starter() {
        let src = r#"
typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request *req = (Request *)malloc(sizeof(Request));
  req->cmd = getenv("CMD");
  char *alias = req->cmd;
  char **pp = &alias;
  system(*pp);
  return 0;
}
"#;
        let program = CParser.parse_file("heap.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }
    #[test]
    fn propagates_pointer_alias_assignment_starter() {
        let src = r#"
int main(void) {
  char *cmd = getenv("CMD");
  char *p = cmd;
  char **pp = &p;
  system(*pp);
  return 0;
}
"#;
        let program = CParser.parse_file("alias.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn propagates_deref_alias_to_field_path_starter() {
        let src = r#"
typedef struct Request {
  char *cmd;
} Request;

int main(void) {
  Request req;
  req.cmd = getenv("CMD");
  char *alias = req.cmd;
  char **pp = &alias;
  system(*pp);
  return 0;
}
"#;
        let program = CParser.parse_file("field_alias.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn parses_nested_struct_pointer_field_chain_starter() {
        let src = r#"
typedef struct DB { char *cmd; } DB;
typedef struct Request { DB *db; } Request;

int main(void) {
  Request *req = (Request *)malloc(sizeof(Request));
  req->db = (DB *)malloc(sizeof(DB));
  req->db->cmd = getenv("CMD");
  system(req->db->cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("nested.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Class(class) if class.name == "Request")));
    }

    #[test]
    fn infers_alloc_type_from_sizeof_pointee_starter() {
        let src = r#"
typedef struct Request { char *cmd; } Request;

int main(void) {
  Request *req;
  req = malloc(sizeof(*req));
  req->cmd = getenv("CMD");
  system(req->cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("sizeof_ptr.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn infers_nested_heap_alloc_and_strdup_alias_starter() {
        let src = r#"
typedef struct Node {
  char *cmd;
  struct Node *next;
} Node;

int main(void) {
  char *cmd = getenv("CMD");
  Node *req = malloc(sizeof(*req));
  req->next = malloc(sizeof(*req->next));
  req->next->cmd = strdup(cmd);
  system(req->next->cmd);
  return 0;
}
"#;
        let program = CParser.parse_file("nested_heap.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn propagates_copy_alias_into_heap_field_starter() {
        let src = r#"
typedef struct DB { char *cmd; } DB;
typedef struct Request { DB *db; } Request;

int main(void) {
  char *cmd = getenv("CMD");
  Request *req = malloc(sizeof(*req));
  req->db = malloc(sizeof(*req->db));
  req->db->cmd = strdup(cmd);
  char *alias = req->db->cmd;
  system(alias);
  return 0;
}
"#;
        let program = CParser.parse_file("heap_field_alias.c", src).expect("parse ok");
        let module = &program.modules[0];
        assert!(module.items.iter().any(|item| matches!(item, Item::Function(func) if func.name == "main")));
    }

    #[test]
    fn infers_copy_result_alias_from_mempcpy_assignment_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            void *mempcpy(void *dst, const void *src, unsigned long n);
            void run(void) {
                char buf[64];
                char *cmd = getenv("CMD");
                char *p = mempcpy(buf, cmd, 4);
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("mempcpy"));
        assert!(rendered.contains("system"));
    }

    #[test]
    fn infers_copy_result_alias_from_strcpy_assignment_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            char *strcpy(char *dst, const char *src);
            void run(void) {
                char buf[64];
                char *cmd = getenv("CMD");
                char *p = strcpy(buf, cmd);
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("strcpy"));
        assert!(rendered.contains("system"));
    }


    #[test]
    fn infers_alias_from_strtok_r_and_stpncpy_starter() {
        let env = CLikeEnv::default();
        let alias = infer_copy_result_alias("stpncpy(dst, src, 8)", &env);
        assert_eq!(alias.as_deref(), Some("dst"));
        let alias2 = infer_copy_result_alias(r#"strtok_r(cmd, ",", &save)"#, &env);
        assert_eq!(alias2.as_deref(), Some("cmd"));
    }


    #[test]
    fn resolves_copy_stmt_and_wild_return_pointer_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            char *stpcpy(char *dst, const char *src);
            char *rawmemchr(const char *s, int c);
            void run(void) {
                char buf[64];
                char *cmd = getenv("CMD");
                stpcpy(buf, cmd);
                char *p = rawmemchr(buf, 'A');
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("stpcpy"));
        assert!(rendered.contains("rawmemchr"));
    }

    #[test]
    fn infers_copy_result_alias_from_strstr_and_basename_starter() {
        let env = CLikeEnv::default();
        let alias = infer_copy_result_alias(r#"strstr(cmd, "x")"#, &env);
        assert_eq!(alias.as_deref(), Some("cmd"));
        let alias2 = infer_copy_result_alias("basename(path)", &env);
        assert_eq!(alias2.as_deref(), Some("path"));
    }

    #[test]
    fn infers_alias_from_memmem_and_strdupa_starter() {
        let env = CLikeEnv::default();
        let alias = infer_copy_result_alias(r#"memmem(buf, 8, needle, 2)"#, &env);
        assert_eq!(alias.as_deref(), Some("buf"));
        let alias2 = infer_copy_result_alias("strdupa(cmd)", &env);
        assert_eq!(alias2.as_deref(), Some("cmd"));
    }

    #[test]
    fn resolves_bcopy_and_nested_deref_chain_starter() {
        let parser = CParser::default();
        let src = r#"
            int system(const char *cmd);
            char *getenv(const char *name);
            void bcopy(const void *src, void *dst, unsigned long n);
            char *memmem(const void *haystack, unsigned long haystacklen, const void *needle, unsigned long needlelen);
            typedef struct Node { struct Node *next; char *cmd; } Node;
            void run(Node *head) {
                char *src = getenv("CMD");
                bcopy(src, head->next->cmd, 4);
                char *p = memmem(head->next->cmd, 4, "A", 1);
                system(p);
            }
        "#;
        let program = parser.parse_file("demo.c", src).expect("parse ok");
        let rendered = format!("{:#?}", program);
        assert!(rendered.contains("memmem"));
        assert!(rendered.contains("head"));
    }


}
