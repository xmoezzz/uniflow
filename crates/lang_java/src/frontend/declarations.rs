#[derive(Clone, Debug)]
struct JavaClassDecl {
    simple_name: String,
    bases: Vec<String>,
    span: uniflow_hir::Span,
}

#[derive(Clone, Debug)]
struct JavaMethodText {
    signature: String,
    signature_span: uniflow_hir::Span,
    body: String,
    span: uniflow_hir::Span,
    body_span: uniflow_hir::Span,
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

#[derive(Clone, Default)]
struct JavaEnv {
    vars: HashMap<String, SymbolId>,
    types: HashMap<String, String>,
    field_types: HashMap<String, String>,
    this_symbol: Option<SymbolId>,
    current_class: String,
    callable_values: HashSet<SymbolId>,
    expected_callable_arity: Option<usize>,
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
        ",
    )
    .expect("valid regex");
    let caps = re.captures(source)?;
    let whole = caps.get(0)?;
    let simple_name = caps
        .get(1)
        .map(|m| m.as_str())
        .unwrap_or("Main")
        .to_string();
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

fn parse_imports(
    source: &str,
    builder: &mut ModuleBuilder,
    mut resolver: JavaResolver,
) -> JavaResolver {
    let re =
        Regex::new(r"(?m)^\s*import\s+(static\s+)?([A-Za-z0-9_.*]+)\s*;").expect("valid regex");
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
                resolver
                    .static_exact_imports
                    .entry(alias)
                    .or_default()
                    .push(path.to_string());
            }
            continue;
        }
        if path.ends_with(".*") {
            resolver
                .wildcard_imports
                .push(path.trim_end_matches(".*").to_string());
        } else {
            resolver
                .exact_imports
                .entry(alias)
                .or_default()
                .push(path.to_string());
        }
    }
    resolver
}

fn extract_class_body(source: &str) -> Option<&str> {
    Some(&source[extract_class_body_range(source)?])
}

fn extract_class_body_range(source: &str) -> Option<std::ops::Range<usize>> {
    let decl_re = Regex::new(r"\b(?:class|interface|record)\b").expect("valid regex");
    let decl = decl_re.find(source)?;
    let open = source[decl.start()..].find('{')? + decl.start();
    let close = find_matching_brace(source, open)?;
    Some(open + 1..close)
}

fn extract_methods(body: &str) -> Vec<JavaMethodText> {
    let syntax = uniflow_parser_core::java_syntax::JavaSyntax::parse_members(body);
    syntax.roots.iter().filter_map(|&id| {
        let method = &syntax.nodes[id];
        let block = method.body.clone()?;
        let open = block.start;
        let close = block.end - 1;
        let signature = &body[method.range.start..open];
        Some(JavaMethodText {
            signature: signature.trim().to_string(),
            signature_span: span_from_offsets(
                uniflow_hir::FileId(0), body, method.range.start, open,
            ),
            body: body[open + 1..close].to_string(),
            span: span_from_offsets(
                uniflow_hir::FileId(0), body, method.range.start, block.end,
            ),
            body_span: span_from_offsets(
                uniflow_hir::FileId(0), body, open + 1, open + 1,
            ),
        })
    }).collect()
}

fn extract_fields(
    builder: &mut ModuleBuilder,
    body: &str,
    resolver: &JavaResolver,
) -> Vec<ParsedField> {
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
                let raw = &body[start..=idx];
                let stmt = raw.trim();
                let declaration_start = start + raw.len() - raw.trim_start().len();
                if let Some(field) = parse_field_decl(builder, stmt, resolver, declaration_start, idx + 1, body)
                {
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
    if [
        "class ",
        "interface ",
        "enum ",
        "@",
        "return ",
        "package ",
        "import ",
    ]
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

fn parse_method_signature(
    signature: &str,
    simple_class_name: &str,
) -> Option<ParsedMethodSignature> {
    let cleaned = mask_java_annotations(signature);
    let signature = cleaned.as_str();
    let open = signature.find('(')?;
    let close = matching_delimiter(signature, open, '(', ')')?;
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

fn mask_java_annotations(text: &str) -> String {
    use uniflow_parser_core::{Lexer, LexerSpec, TokKind};
    let tokens = Lexer::new(text, &LexerSpec::default()).tokenize();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i].text != "@" { i += 1; continue; }
        let start = tokens[i].start as usize;
        i += 1;
        if !tokens.get(i).is_some_and(|t| t.kind == TokKind::Ident) { continue; }
        let mut end = tokens[i].end as usize;
        i += 1;
        while i + 1 < tokens.len() && tokens[i].text == "." && tokens[i + 1].kind == TokKind::Ident {
            end = tokens[i + 1].end as usize;
            i += 2;
        }
        if tokens.get(i).is_some_and(|t| t.text == "(") {
            if let Some(close) = matching_delimiter(text, tokens[i].start as usize, '(', ')') {
                end = close + 1;
                while i < tokens.len() && (tokens[i].start as usize) < end { i += 1; }
            }
        }
        ranges.push(start..end);
    }
    let mut result = text.to_owned();
    for range in ranges.into_iter().rev() {
        let blank = text[range.clone()].bytes().map(|b| if b == b'\n' { '\n' } else { ' ' }).collect::<String>();
        result.replace_range(range, &blank);
    }
    result
}
