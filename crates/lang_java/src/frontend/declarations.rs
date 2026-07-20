#[derive(Clone, Debug)]
struct JavaClassDecl {
    simple_name: String,
    bases: Vec<String>,
    span: uniflow_hir::Span,
}

#[derive(Clone, Debug)]
struct JavaMethodText {
    signature: String,
    body: String,
    span: uniflow_hir::Span,
    body_start_byte: usize,
}

#[derive(Clone, Debug)]
struct ParsedMethodSignature {
    method_name: String,
    return_type: Option<String>,
    params_text: String,
    param_types: Vec<String>,
    is_static: bool,
    is_constructor: bool,
}

#[derive(Clone, Debug)]
struct ParsedField {
    field: Field,
    qualified_ty: String,
}

#[derive(Clone, Debug)]
struct IndexedMethodReturnEntry {
    name: String,
    param_types: Vec<String>,
    return_type: String,
}

#[derive(Default)]
struct JavaEnv {
    vars: HashMap<String, SymbolId>,
    types: HashMap<String, String>,
    field_types: HashMap<String, String>,
    this_symbol: Option<SymbolId>,
    current_class: String,
}

fn parse_package(source: &str) -> Option<String> {
    let re = Regex::new(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*;").expect("valid regex");
    re.captures(source)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().trim().to_string())
}

fn qualify_local_class_name(package_name: Option<&str>, simple_class_name: &str) -> String {
    match package_name {
        Some(pkg) if !pkg.is_empty() => format!("{pkg}.{simple_class_name}"),
        _ => simple_class_name.to_string(),
    }
}

fn detect_class_decl(source: &str) -> Option<JavaClassDecl> {
    let re = Regex::new(
        r"(?x)
        \b(?:class|interface|record)\s+([A-Za-z_][A-Za-z0-9_]*)
        (?:\s+extends\s+([A-Za-z0-9_.$]+))?
        (?:\s+implements\s+([A-Za-z0-9_.$,\s]+))?
        "
    )
    .expect("valid regex");
    let caps = re.captures(source)?;
    let whole = caps.get(0)?;
    let simple_name = caps.get(1).map(|m| m.as_str()).unwrap_or("Main").to_string();
    let mut bases = Vec::new();
    if let Some(ext) = caps.get(2) {
        bases.push(ext.as_str().trim().to_string());
    }
    if let Some(impls) = caps.get(3) {
        for part in impls.as_str().split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                bases.push(trimmed.to_string());
            }
        }
    }
    Some(JavaClassDecl {
        simple_name,
        bases,
        span: span_from_offsets(uniflow_hir::FileId(0), source, whole.start(), whole.end()),
    })
}

fn parse_imports(source: &str, builder: &mut ModuleBuilder, mut resolver: JavaResolver) -> JavaResolver {
    let re = Regex::new(r"(?m)^\s*import\s+(static\s+)?([A-Za-z0-9_.*]+)\s*;").expect("valid regex");
    for caps in re.captures_iter(source) {
        let is_static = caps.get(1).is_some();
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let alias = path.rsplit('.').next().unwrap_or(path).to_string();
        builder.add_import(path, Some(alias.clone()));
        if is_static {
            if path.ends_with(".*") {
                resolver
                    .static_wildcard_imports
                    .push(path.trim_end_matches(".*").to_string());
            } else {
                resolver.static_exact_imports.entry(alias).or_default().push(path.to_string());
            }
            continue;
        }
        if path.ends_with(".*") {
            resolver
                .wildcard_imports
                .push(path.trim_end_matches(".*").to_string());
        } else {
            resolver.exact_imports.entry(alias).or_default().push(path.to_string());
        }
    }
    resolver
}

fn extract_class_body(source: &str) -> Option<&str> {
    let decl_re = Regex::new(r"\b(?:class|interface|record)\b").expect("valid regex");
    let decl = decl_re.find(source)?;
    let open = source[decl.start()..].find('{')? + decl.start();
    let close = find_matching_brace(source, open)?;
    Some(&source[open + 1..close])
}

fn extract_methods(body: &str) -> Vec<JavaMethodText> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < body.len() {
        let Some(open_rel) = body[idx..].find('{') else {
            break;
        };
        let open = idx + open_rel;
        let line_start = body[..open].rfind('\n').map(|n| n + 1).unwrap_or(0);
        let signature = body[line_start..open].trim();
        if is_method_signature(signature) {
            if let Some(close) = find_matching_brace(body, open) {
                let inner = body[open + 1..close].to_string();
                out.push(JavaMethodText {
                    signature: signature.to_string(),
                    body: inner,
                    span: span_from_offsets(uniflow_hir::FileId(0), body, line_start, close + 1),
                    body_start_byte: open + 1,
                });
                idx = close + 1;
                continue;
            }
        }
        idx = open + 1;
    }
    out
}

fn extract_fields(builder: &mut ModuleBuilder, body: &str, resolver: &JavaResolver) -> Vec<ParsedField> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut idx = 0usize;
    let bytes = body.as_bytes();

    while idx < bytes.len() {
        match bytes[idx] as char {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ';' if depth == 0 => {
                let stmt = body[start..=idx].trim();
                if let Some(field) = parse_field_decl(builder, stmt, resolver, start, idx + 1, body) {
                    out.push(field);
                }
                start = idx + 1;
            }
            _ => {}
        }
        idx += 1;
    }

    out
}

fn parse_field_decl(
    builder: &mut ModuleBuilder,
    stmt: &str,
    resolver: &JavaResolver,
    start: usize,
    end: usize,
    body: &str,
) -> Option<ParsedField> {
    let trimmed = stmt.trim().trim_end_matches(';').trim();
    if trimmed.is_empty() || trimmed.contains('(') {
        return None;
    }
    if ["class ", "interface ", "enum ", "@", "return ", "package ", "import "]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
    {
        return None;
    }

    let decl = split_once_top_level(trimmed, '=')
        .map(|(left, _)| left)
        .unwrap_or_else(|| trimmed.to_string());
    let mut pieces = decl
        .split_whitespace()
        .filter(|piece| {
            !matches!(
                *piece,
                "public" | "private" | "protected" | "static" | "final" | "volatile" | "transient"
            )
        })
        .collect::<Vec<_>>();
    if pieces.len() < 2 {
        return None;
    }
    let name = pieces.pop()?.trim().trim_end_matches(';').to_string();
    if name.is_empty() {
        return None;
    }
    let ty_name = pieces.join(" ");
    let qualified_ty = resolver.qualify_type_name(&ty_name);
    let symbol = builder.add_symbol(&name, SymbolKind::Field);
    Some(ParsedField {
        field: Field {
            name,
            symbol: Some(symbol),
            ty: Some(builder.ensure_type(&qualified_ty)),
            span: span_from_offsets(builder.file_id(), body, start, end),
        },
        qualified_ty,
    })
}

fn is_method_signature(signature: &str) -> bool {
    let trimmed = signature.trim();
    trimmed.contains('(')
        && trimmed.contains(')')
        && !trimmed.contains('=')
        && !["if", "for", "while", "switch", "catch", "try", "else"]
            .iter()
            .any(|kw| trimmed.starts_with(kw))
}

fn parse_method_signature(signature: &str, simple_class_name: &str) -> Option<ParsedMethodSignature> {
    let open = signature.find('(')?;
    let close = signature.rfind(')')?;
    if close <= open {
        return None;
    }
    let prefix = signature[..open].trim();
    let params_text = signature[open + 1..close].trim().to_string();
    let raw_params = split_top_level_commas(&params_text)
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect::<Vec<_>>();
    let param_types = raw_params
        .iter()
        .map(|part| {
            let pieces = part.split_whitespace().collect::<Vec<_>>();
            if pieces.len() >= 2 {
                pieces[..pieces.len() - 1].join(" ")
            } else {
                "Object".to_string()
            }
        })
        .collect::<Vec<_>>();

    let mut filtered = prefix
        .split_whitespace()
        .filter(|tok| !tok.starts_with('@'))
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return None;
    }

    let is_static = filtered.iter().any(|tok| *tok == "static");
    filtered.retain(|tok| {
        !matches!(
            *tok,
            "public"
                | "private"
                | "protected"
                | "static"
                | "final"
                | "synchronized"
                | "abstract"
                | "native"
                | "default"
                | "strictfp"
        )
    });

    if filtered.is_empty() {
        return None;
    }

    if filtered.len() == 1 {
        let method_name = filtered[0].to_string();
        return Some(ParsedMethodSignature {
            is_constructor: method_name == simple_class_name,
            method_name,
            return_type: None,
            params_text,
            param_types,
            is_static,
        });
    }

    let method_name = filtered.pop()?.to_string();
    let return_type = filtered.join(" ");
    Some(ParsedMethodSignature {
        is_constructor: method_name == simple_class_name,
        method_name,
        return_type: Some(return_type),
        params_text,
        param_types,
        is_static,
    })
}

