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

pub fn parse_c_like_file(
    language: Language,
    path: &str,
    source: &str,
) -> Result<uniflow_hir::Program> {
    let source = preprocess_c_source_with_origins(source);
    let source = normalize_c_surface_tracked(source);
    let macro_ranges = source.macro_ranges();
    let source = strip_c_like_comments(&source.text);
    let module_name = module_name_from_path(path);
    let mut builder = ModuleBuilder::new(language.clone(), path, &module_name);
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

    let function_pointer_typedefs = extract_function_pointer_typedefs(&source);
    let functions = extract_functions(&source);
    let known_functions = functions
        .iter()
        .map(|func| func.name.clone())
        .collect::<HashSet<_>>();

    for func in functions {
        let hir_func = parse_function(
            &mut builder,
            &func,
            language.clone(),
            &known_functions,
            &struct_field_types,
            &function_pointer_typedefs,
        );
        builder.push_item(Item::Function(hir_func));
    }

    let mut program = builder.finish();
    if let Some(file) = program.files.first() {
        program.source_origins.extend(macro_ranges.into_iter().map(|(start_byte, end_byte)| {
            uniflow_hir::SourceOriginRange {
                file: file.id,
                start_byte,
                end_byte,
                kind: uniflow_hir::SourceOriginKind::MacroExpansion,
            }
        }));
    }
    Ok(program)
}

/// Normalize C declaration and initializer sugar into the conservative HIR grammar.
fn normalize_c_surface(source: &str) -> String {
    normalize_c_surface_tracked(TrackedSource::plain(source.to_string())).text
}

fn rewrite_tracked_regex<F>(input: TrackedSource, regex: &Regex, mut replacement: F) -> TrackedSource
where
    F: FnMut(&regex::Captures<'_>) -> String,
{
    let mut text = String::with_capacity(input.text.len());
    let mut macro_bytes = Vec::with_capacity(input.macro_bytes.len());
    let mut cursor = 0usize;
    for captures in regex.captures_iter(&input.text) {
        let Some(matched) = captures.get(0) else {
            continue;
        };
        text.push_str(&input.text[cursor..matched.start()]);
        macro_bytes.extend_from_slice(&input.macro_bytes[cursor..matched.start()]);
        let rewritten = replacement(&captures);
        let macro_origin = input.macro_bytes[matched.start()..matched.end()]
            .iter()
            .copied()
            .any(|marked| marked);
        text.push_str(&rewritten);
        macro_bytes.extend(std::iter::repeat(macro_origin).take(rewritten.len()));
        cursor = matched.end();
    }
    text.push_str(&input.text[cursor..]);
    macro_bytes.extend_from_slice(&input.macro_bytes[cursor..]);
    TrackedSource { text, macro_bytes }
}

fn normalize_c_surface_tracked(mut out: TrackedSource) -> TrackedSource {
    let enum_re = Regex::new(
        r"(?s)(?:typedef\s+)?enum\s+([A-Za-z_][A-Za-z0-9_]*)?\s*\{([^}]*)\}\s*([A-Za-z_][A-Za-z0-9_]*)?\s*;",
    ).expect("valid regex");
    out = rewrite_tracked_regex(out, &enum_re, |caps: &regex::Captures<'_>| {
            let head = caps.get(1).map_or("", |m| m.as_str());
            let tail = caps.get(3).map_or("", |m| m.as_str());
            let name = if !tail.is_empty() { tail } else { head };
            if name.is_empty() {
                String::new()
            } else {
                format!("typedef int {name};")
            }
        });

    let compound_re = Regex::new(
        r"\(\s*([A-Za-z_][A-Za-z0-9_]*(?:\s+[A-Za-z_][A-Za-z0-9_]*)*)\s*\)\s*\{(\s*\.[^{}]*)\}",
    )
    .expect("valid regex");
    out = rewrite_tracked_regex(out, &compound_re, |caps: &regex::Captures<'_>| {
            let ty = caps
                .get(1)
                .map_or("compound", |m| m.as_str())
                .trim()
                .replace(' ', "_");
            let body = caps.get(2).map_or("", |m| m.as_str());
            let values = split_top_level_commas(body)
                .into_iter()
                .map(|part| {
                    let part = part.trim();
                    part.split_once('=')
                        .map_or_else(|| part.to_string(), |(_, value)| value.trim().to_string())
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("__compound_{ty}({values})")
        });

    out
}

#[derive(Clone, Debug)]
struct CFunctionText {
    ret_type: String,
    name: String,
    params: String,
    body: String,
    body_start: usize,
}

fn parse_c_like_block(
    builder: &mut ModuleBuilder,
    body: &str,
    base_offset: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < body.len() {
        cursor = skip_c_like_ws(body, cursor);
        if cursor >= body.len() {
            break;
        }

        if keyword_at(body, cursor, "if") {
            if let Some((stmt, next)) =
                parse_c_like_if(builder, body, base_offset, cursor, env, function_pointer_typedefs)
            {
                out.push(stmt);
                cursor = next;
                continue;
            }
        }
        if keyword_at(body, cursor, "while") {
            if let Some((stmt, next)) =
                parse_c_like_while(builder, body, base_offset, cursor, env, function_pointer_typedefs)
            {
                out.push(stmt);
                cursor = next;
                continue;
            }
        }
        if keyword_at(body, cursor, "switch") {
            if let Some((stmt, next)) = parse_c_like_switch(
                builder,
                body,
                base_offset,
                cursor,
                env,
                function_pointer_typedefs,
            ) {
                out.push(stmt);
                cursor = next;
                continue;
            }
        }
        if keyword_at(body, cursor, "try") {
            if let Some((stmt, next)) =
                parse_c_like_try(builder, body, base_offset, cursor, env, function_pointer_typedefs)
            {
                out.push(stmt);
                cursor = next;
                continue;
            }
        }

        if body.as_bytes().get(cursor) == Some(&b'{') {
            if let Some(close) = find_matching_brace(body, cursor) {
                out.extend(parse_c_like_block(
                    builder,
                    &body[cursor + 1..close],
                    base_offset + cursor + 1,
                    env,
                    function_pointer_typedefs,
                ));
                cursor = close + 1;
                continue;
            }
        }

        let end = find_c_like_statement_end(body, cursor).unwrap_or(body.len());
        let raw = body[cursor..end].trim().trim_end_matches(';').trim();
        if !raw.is_empty() {
            let raw_offset = body[cursor..end]
                .find(raw)
                .map_or(base_offset + cursor, |relative| base_offset + cursor + relative);
            parse_c_like_simple_statement(
                builder,
                raw,
                raw_offset,
                env,
                function_pointer_typedefs,
                &mut out,
            );
        }
        cursor = if end < body.len() { end + 1 } else { end };
    }
    out
}

fn parse_c_like_if(
    builder: &mut ModuleBuilder,
    source: &str,
    base_offset: usize,
    start: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
) -> Option<(Stmt, usize)> {
    let open_paren = skip_c_like_ws(source, start + "if".len());
    if source.as_bytes().get(open_paren) != Some(&b'(') {
        return None;
    }
    let close_paren = matching_delimiter(source, open_paren, '(', ')')?;
    let condition = parse_expr_at(
        builder,
        &source[open_paren + 1..close_paren],
        base_offset + open_paren + 1,
        env,
    );
    let mut then_env = env.clone();
    let (then_block, then_end) = parse_c_like_embedded_block(
        builder,
        source,
        base_offset,
        close_paren + 1,
        &mut then_env,
        function_pointer_typedefs,
    )?;

    let mut next = skip_c_like_ws(source, then_end);
    let else_block = if keyword_at(source, next, "else") {
        next = skip_c_like_ws(source, next + "else".len());
        let mut else_env = env.clone();
        let (block, else_end) = parse_c_like_embedded_block(
            builder,
            source,
            base_offset,
            next,
            &mut else_env,
            function_pointer_typedefs,
        )?;
        next = else_end;
        Some(block)
    } else {
        None
    };

    Some((
        Stmt::If {
            id: builder.alloc_stmt_id(),
            cond: condition,
            then_block,
            else_block,
            span: default_span(),
        },
        next,
    ))
}

fn parse_c_like_while(
    builder: &mut ModuleBuilder,
    source: &str,
    base_offset: usize,
    start: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
) -> Option<(Stmt, usize)> {
    let open_paren = skip_c_like_ws(source, start + "while".len());
    if source.as_bytes().get(open_paren) != Some(&b'(') {
        return None;
    }
    let close_paren = matching_delimiter(source, open_paren, '(', ')')?;
    let condition = parse_expr_at(
        builder,
        &source[open_paren + 1..close_paren],
        base_offset + open_paren + 1,
        env,
    );
    let mut loop_env = env.clone();
    let (body, next) = parse_c_like_embedded_block(
        builder,
        source,
        base_offset,
        close_paren + 1,
        &mut loop_env,
        function_pointer_typedefs,
    )?;
    Some((
        Stmt::While {
            id: builder.alloc_stmt_id(),
            cond: condition,
            body,
            span: default_span(),
        },
        next,
    ))
}

fn parse_c_like_embedded_block(
    builder: &mut ModuleBuilder,
    source: &str,
    base_offset: usize,
    start: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
) -> Option<(Block, usize)> {
    let start = skip_c_like_ws(source, start);
    if source.as_bytes().get(start) == Some(&b'{') {
        let close = find_matching_brace(source, start)?;
        let stmts = parse_c_like_block(
            builder,
            &source[start + 1..close],
            base_offset + start + 1,
            env,
            function_pointer_typedefs,
        );
        return Some((
            Block {
                id: builder.alloc_block_id(),
                stmts,
                span: occurrence_span(base_offset + start, base_offset + close + 1),
            },
            close + 1,
        ));
    }

    let structured = if keyword_at(source, start, "if") {
        parse_c_like_if(
            builder,
            source,
            base_offset,
            start,
            env,
            function_pointer_typedefs,
        )
    } else if keyword_at(source, start, "while") {
        parse_c_like_while(
            builder,
            source,
            base_offset,
            start,
            env,
            function_pointer_typedefs,
        )
    } else if keyword_at(source, start, "switch") {
        parse_c_like_switch(
            builder,
            source,
            base_offset,
            start,
            env,
            function_pointer_typedefs,
        )
    } else if keyword_at(source, start, "try") {
        parse_c_like_try(
            builder,
            source,
            base_offset,
            start,
            env,
            function_pointer_typedefs,
        )
    } else {
        None
    };
    if let Some((stmt, next)) = structured {
        return Some((
            Block {
                id: builder.alloc_block_id(),
                stmts: vec![stmt],
                span: occurrence_span(base_offset + start, base_offset + next),
            },
            next,
        ));
    }

    let end = find_c_like_statement_end(source, start)?;
    let raw = source[start..end].trim();
    let raw_offset = source[start..end]
        .find(raw)
        .map_or(base_offset + start, |relative| base_offset + start + relative);
    let mut stmts = Vec::new();
    if !raw.is_empty() {
        parse_c_like_simple_statement(
            builder,
            raw,
            raw_offset,
            env,
            function_pointer_typedefs,
            &mut stmts,
        );
    }
    Some((
        Block {
            id: builder.alloc_block_id(),
            stmts,
            span: occurrence_span(base_offset + start, base_offset + end + 1),
        },
        end + 1,
    ))
}

#[derive(Clone, Copy, Debug)]
struct CLikeSwitchLabel {
    start: usize,
    value_start: usize,
    colon: usize,
    is_default: bool,
}

fn parse_c_like_switch(
    builder: &mut ModuleBuilder,
    source: &str,
    base_offset: usize,
    start: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
) -> Option<(Stmt, usize)> {
    let open_paren = skip_c_like_ws(source, start + "switch".len());
    if source.as_bytes().get(open_paren) != Some(&b'(') {
        return None;
    }
    let close_paren = matching_delimiter(source, open_paren, '(', ')')?;
    let scrutinee = parse_expr_at(
        builder,
        &source[open_paren + 1..close_paren],
        base_offset + open_paren + 1,
        env,
    );
    let open_body = skip_c_like_ws(source, close_paren + 1);
    if source.as_bytes().get(open_body) != Some(&b'{') {
        return None;
    }
    let close_body = find_matching_brace(source, open_body)?;
    let switch_body = &source[open_body + 1..close_body];
    let switch_body_offset = base_offset + open_body + 1;
    let labels = find_c_like_switch_labels(switch_body);
    let mut clauses = Vec::new();
    let mut default: Option<Block> = None;
    let mut switch_env = env.clone();

    for (index, label) in labels.iter().enumerate() {
        let body_end = labels
            .get(index + 1)
            .map_or(switch_body.len(), |next| next.start);
        let body_start = label.colon + 1;
        let stmts = parse_c_like_block(
            builder,
            &switch_body[body_start..body_end],
            switch_body_offset + body_start,
            &mut switch_env,
            function_pointer_typedefs,
        );
        let clause_span = occurrence_span(
            switch_body_offset + label.start,
            switch_body_offset + label.colon + 1,
        );
        let block = Block {
            id: builder.alloc_block_id(),
            stmts,
            span: occurrence_span(
                switch_body_offset + body_start,
                switch_body_offset + body_end,
            ),
        };
        if label.is_default {
            if let Some(existing) = &mut default {
                existing.stmts.extend(block.stmts);
            } else {
                default = Some(block);
            }
            continue;
        }

        let value_text = switch_body[label.value_start..label.colon].trim();
        if value_text.is_empty() {
            continue;
        }
        let value_relative = switch_body[label.value_start..label.colon]
            .find(value_text)
            .unwrap_or(0);
        let value = parse_expr_at(
            builder,
            value_text,
            switch_body_offset + label.value_start + value_relative,
            &mut switch_env,
        );
        let fallthrough = !body_ends_control_flow(&block);
        clauses.push(SwitchClause {
            values: vec![value],
            body: block,
            fallthrough,
            span: clause_span,
        });
    }

    Some((
        Stmt::Switch {
            id: builder.alloc_stmt_id(),
            scrutinee,
            clauses,
            default,
            span: occurrence_span(base_offset + start, base_offset + close_body + 1),
        },
        close_body + 1,
    ))
}

fn find_c_like_switch_labels(source: &str) -> Vec<CLikeSwitchLabel> {
    let mut labels = Vec::new();
    let mut cursor = 0usize;
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escaped = false;

    while cursor < source.len() {
        let byte = source.as_bytes()[cursor];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            cursor += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => {
                quote = Some(byte);
                cursor += 1;
                continue;
            }
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            _ => {}
        }
        if paren == 0 && bracket == 0 && brace == 0 {
            let (keyword, is_default) = if keyword_at(source, cursor, "case") {
                ("case", false)
            } else if keyword_at(source, cursor, "default") {
                ("default", true)
            } else {
                cursor += 1;
                continue;
            };
            let value_start = skip_c_like_ws(source, cursor + keyword.len());
            if let Some(colon) = find_c_like_case_colon(source, value_start) {
                labels.push(CLikeSwitchLabel {
                    start: cursor,
                    value_start,
                    colon,
                    is_default,
                });
                cursor = colon + 1;
                continue;
            }
        }
        cursor += 1;
    }
    labels
}

fn find_c_like_case_colon(source: &str, start: usize) -> Option<usize> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut ternary = 0usize;
    let mut quote = None;
    let mut escaped = false;
    let mut cursor = start;
    while cursor < source.len() {
        let byte = source.as_bytes()[cursor];
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            cursor += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => {
                if brace == 0 && paren == 0 && bracket == 0 {
                    return None;
                }
                brace = brace.saturating_sub(1);
            }
            b'?' if paren == 0 && bracket == 0 && brace == 0 => ternary += 1,
            b':' if paren == 0 && bracket == 0 && brace == 0 => {
                let previous_is_colon = cursor > 0 && source.as_bytes()[cursor - 1] == b':';
                let next_is_colon = source.as_bytes().get(cursor + 1) == Some(&b':');
                if previous_is_colon || next_is_colon {
                    cursor += 1;
                    continue;
                }
                if ternary > 0 {
                    ternary -= 1;
                } else {
                    return Some(cursor);
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn parse_c_like_try(
    builder: &mut ModuleBuilder,
    source: &str,
    base_offset: usize,
    start: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
) -> Option<(Stmt, usize)> {
    let open_try = skip_c_like_ws(source, start + "try".len());
    if source.as_bytes().get(open_try) != Some(&b'{') {
        return None;
    }
    let close_try = find_matching_brace(source, open_try)?;
    let mut try_env = env.clone();
    let try_block = Block {
        id: builder.alloc_block_id(),
        stmts: parse_c_like_block(
            builder,
            &source[open_try + 1..close_try],
            base_offset + open_try + 1,
            &mut try_env,
            function_pointer_typedefs,
        ),
        span: default_span(),
    };

    let mut catches = Vec::new();
    let mut cursor = skip_c_like_ws(source, close_try + 1);
    while keyword_at(source, cursor, "catch") {
        let open_paren = skip_c_like_ws(source, cursor + "catch".len());
        if source.as_bytes().get(open_paren) != Some(&b'(') {
            break;
        }
        let close_paren = matching_delimiter(source, open_paren, '(', ')')?;
        let declaration = source[open_paren + 1..close_paren].trim();
        let (symbol, ty) = if declaration == "..." || declaration.is_empty() {
            (None, None)
        } else if let Some((name, ty_name)) = parse_typed_name(declaration) {
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            (Some(symbol), Some(builder.ensure_type(&ty_name)))
        } else {
            (None, Some(builder.ensure_type(declaration)))
        };
        let open_body = skip_c_like_ws(source, close_paren + 1);
        if source.as_bytes().get(open_body) != Some(&b'{') {
            break;
        }
        let close_body = find_matching_brace(source, open_body)?;
        let mut catch_env = env.clone();
        if let Some(symbol) = symbol {
            let name = declaration
                .split_whitespace()
                .last()
                .unwrap_or("exception")
                .trim_matches('&')
                .trim_matches('*')
                .to_string();
            catch_env.vars.insert(name, symbol);
        }
        catches.push(CatchClause {
            symbol,
            ty,
            body: Block {
                id: builder.alloc_block_id(),
                stmts: parse_c_like_block(
                    builder,
                    &source[open_body + 1..close_body],
                    base_offset + open_body + 1,
                    &mut catch_env,
                    function_pointer_typedefs,
                ),
                span: default_span(),
            },
            span: default_span(),
        });
        cursor = skip_c_like_ws(source, close_body + 1);
    }

    Some((
        Stmt::Try {
            id: builder.alloc_stmt_id(),
            try_block,
            catches,
            finally_block: None,
            span: default_span(),
        },
        cursor,
    ))
}

fn parse_c_like_simple_statement(
    builder: &mut ModuleBuilder,
    stmt: &str,
    stmt_offset: usize,
    env: &mut CLikeEnv,
    function_pointer_typedefs: &HashSet<String>,
    out: &mut Vec<Stmt>,
) {
    if stmt == "break" {
        out.push(Stmt::Break {
            id: builder.alloc_stmt_id(),
            label: None,
            span: occurrence_span(stmt_offset, stmt_offset + stmt.len()),
        });
        return;
    }
    if stmt == "continue" {
        out.push(Stmt::Continue {
            id: builder.alloc_stmt_id(),
            label: None,
            span: occurrence_span(stmt_offset, stmt_offset + stmt.len()),
        });
        return;
    }
    if let Some(rest) = stmt.strip_prefix("return ") {
        out.push(Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: Some(parse_expr_at(builder, rest, stmt_offset + "return ".len(), env)),
            span: default_span(),
        });
        return;
    }
    if stmt == "return" {
        out.push(Stmt::Return {
            id: builder.alloc_stmt_id(),
            value: None,
            span: default_span(),
        });
        return;
    }
    if let Some(rest) = stmt.strip_prefix("throw ") {
        out.push(Stmt::Throw {
            id: builder.alloc_stmt_id(),
            value: Some(parse_expr_at(builder, rest, stmt_offset + "throw ".len(), env)),
            span: default_span(),
        });
        return;
    }
    if stmt == "throw" {
        out.push(Stmt::Throw {
            id: builder.alloc_stmt_id(),
            value: None,
            span: default_span(),
        });
        return;
    }

    if let Some(fp) = parse_function_pointer_declaration(stmt) {
        let symbol = builder.add_symbol(&fp.name, SymbolKind::Local);
        env.vars.insert(fp.name.clone(), symbol);
        env.types.insert(fp.name.clone(), fp.ty.clone());
        env.function_pointer_vars.insert(fp.name.clone());
        if let Some(alias) = fp.alias {
            env.function_aliases.insert(fp.name.clone(), vec![alias]);
        }
        out.push(Stmt::Let {
            id: builder.alloc_stmt_id(),
            symbol,
            ty: Some(builder.ensure_type(&fp.ty)),
            init: None,
            span: default_span(),
        });
        return;
    }

    if let Some((left, right)) = split_once_top_level(stmt, '=') {
        if is_declaration(left.as_str(), env) {
            let Some((name, ty_name)) = parse_typed_name(&left) else {
                return;
            };
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            record_storage_duration(builder, symbol, &left);
            env.vars.insert(name.clone(), symbol);
            env.types.insert(name.clone(), ty_name.clone());
            record_array_extents(builder, symbol, &left, env);
            if function_pointer_typedefs.contains(ty_name.trim()) {
                env.function_pointer_vars.insert(name.clone());
            }
            if let Some(alias) = infer_pointer_alias_target(right.trim(), env)
                .or_else(|| infer_copy_result_alias(right.trim(), env))
            {
                env.pointer_aliases.insert(name.clone(), alias);
            }
            if let Some(rhs_ty) = inferred_rhs_type(right.trim(), env) {
                env.heap_types.insert(name.clone(), rhs_ty);
            }
            if let Some(aliases) = infer_function_aliases(right.trim(), env) {
                env.function_pointer_vars.insert(name.clone());
                env.function_aliases.insert(name.clone(), aliases);
            }
            let alloc_init = parse_alloc_expr(builder, &right, env, Some(&ty_name));
            if let Some(Expr::New { type_name, .. }) = alloc_init.as_ref() {
                env.heap_types.insert(name.clone(), type_name.clone());
            }
            let right_offset = stmt
                .find(&right)
                .map_or(stmt_offset, |relative| stmt_offset + relative);
            let init = alloc_init.unwrap_or_else(|| parse_expr_at(builder, &right, right_offset, env));
            out.push(Stmt::Let {
                id: builder.alloc_stmt_id(),
                symbol,
                ty: Some(builder.ensure_type(&ty_name)),
                init: Some(init),
                span: default_span(),
            });
        } else {
            let lhs_name = left.trim().to_string();
            let lhs_key = normalized_storage_key(&left, env);
            if let Some(alias) = infer_pointer_alias_target(right.trim(), env)
                .or_else(|| infer_copy_result_alias(right.trim(), env))
            {
                env.pointer_aliases.insert(lhs_key.clone(), alias);
            }
            if let Some(rhs_ty) = inferred_rhs_type(right.trim(), env) {
                env.heap_types.insert(lhs_key.clone(), rhs_ty);
            }
            if let Some(aliases) = infer_function_aliases(right.trim(), env) {
                env.function_pointer_vars.insert(lhs_name.clone());
                env.function_aliases.insert(lhs_name.clone(), aliases);
            }
            let lhs = parse_lvalue(builder, &left, env);
            let lhs_existing_ty = env
                .types
                .get(&lhs_name)
                .map(String::as_str)
                .map(str::to_string);
            let alloc_rhs = parse_alloc_expr(builder, &right, env, lhs_existing_ty.as_deref());
            if let Some(Expr::New { type_name, .. }) = alloc_rhs.as_ref() {
                env.heap_types.insert(lhs_key.clone(), type_name.clone());
            }
            let right_offset = stmt
                .find(&right)
                .map_or(stmt_offset, |relative| stmt_offset + relative);
            let rhs = alloc_rhs.unwrap_or_else(|| parse_expr_at(builder, &right, right_offset, env));
            out.push(Stmt::Assign {
                id: builder.alloc_stmt_id(),
                lhs,
                rhs,
                span: default_span(),
            });
        }
        return;
    }

    if let Some((name, ty_name)) = parse_variable_declaration(stmt) {
        let symbol = builder.add_symbol(&name, SymbolKind::Local);
        record_storage_duration(builder, symbol, stmt);
        env.vars.insert(name.clone(), symbol);
        env.types.insert(name.clone(), ty_name.clone());
        record_array_extents(builder, symbol, stmt, env);
        out.push(Stmt::Let {
            id: builder.alloc_stmt_id(),
            symbol,
            ty: Some(builder.ensure_type(&ty_name)),
            init: None,
            span: default_span(),
        });
        return;
    }

    if let Some(extra_stmts) = parse_copy_propagation_stmt(builder, stmt, env) {
        out.extend(extra_stmts);
        return;
    }

    out.push(Stmt::Expr {
        id: builder.alloc_stmt_id(),
        expr: parse_expr_at(builder, stmt, stmt_offset, env),
        span: default_span(),
    });
}

fn record_storage_duration(builder: &mut ModuleBuilder, symbol: SymbolId, declaration: &str) {
    if declaration.split_whitespace().any(|token| {
        matches!(
            token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_'),
            "static" | "extern" | "thread_local" | "_Thread_local"
        )
    }) {
        builder.set_symbol_attribute(symbol, "storage_duration", "static".to_string());
    }
}

fn skip_c_like_ws(source: &str, mut cursor: usize) -> usize {
    while cursor < source.len() && source.as_bytes()[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

fn keyword_at(source: &str, cursor: usize, keyword: &str) -> bool {
    if !source[cursor..].starts_with(keyword) {
        return false;
    }
    let before_ok = cursor == 0
        || !source.as_bytes()[cursor - 1].is_ascii_alphanumeric()
            && source.as_bytes()[cursor - 1] != b'_';
    let after = cursor + keyword.len();
    let after_ok = after >= source.len()
        || !source.as_bytes()[after].is_ascii_alphanumeric() && source.as_bytes()[after] != b'_';
    before_ok && after_ok
}

fn find_c_like_statement_end(source: &str, start: usize) -> Option<usize> {
    let mut paren = 0usize;
    let mut bracket = 0usize;
    let mut brace = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (relative, ch) in source[start..].char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '[' => bracket += 1,
            ']' => bracket = bracket.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            ';' if paren == 0 && bracket == 0 && brace == 0 => return Some(start + relative),
            _ => {}
        }
    }
    None
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
        r"(?s)(?:typedef\s+)?(?:struct|union)\s+([A-Za-z_][A-Za-z0-9_]*)?\s*\{(.*?)\}\s*([A-Za-z_][A-Za-z0-9_]*)?\s*;",
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

fn extract_function_pointer_typedefs(source: &str) -> HashSet<String> {
    let re =
        Regex::new(r"(?x)typedef\s+[^;()]+\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\([^;]*\)\s*;")
            .expect("valid regex");
    re.captures_iter(source)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn extract_functions(source: &str) -> Vec<CFunctionText> {
    let mut out = Vec::new();
    let head_re = Regex::new(
        r"(?x)
        ([A-Za-z_][A-Za-z0-9_\s\*\&:<>~,]*?)
        \s+
        ([A-Za-z_~][A-Za-z0-9_:~]*)
        \s*\(
        ",
    )
    .expect("valid regex");

    let mut search_from = 0usize;
    while search_from < source.len() {
        let Some(caps) = head_re.captures(&source[search_from..]) else {
            break;
        };
        let whole = caps.get(0).expect("whole match");
        let absolute_start = search_from + whole.start();
        let open = search_from + whole.end() - 1;
        let Some(close_paren) = matching_delimiter(source, open, '(', ')') else {
            search_from = open + 1;
            continue;
        };
        let mut cursor = close_paren + 1;
        while cursor < source.len() && source.as_bytes()[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        for qualifier in ["const", "noexcept", "override", "final"] {
            if source[cursor..].starts_with(qualifier) {
                cursor += qualifier.len();
                while cursor < source.len() && source.as_bytes()[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
            }
        }
        if source[cursor..].starts_with("->") {
            cursor += 2;
            while cursor < source.len()
                && source.as_bytes()[cursor] != b'{'
                && source.as_bytes()[cursor] != b';'
            {
                cursor += 1;
            }
        }
        if cursor >= source.len() || source.as_bytes()[cursor] != b'{' {
            search_from = close_paren + 1;
            continue;
        }
        let Some(close_body) = find_matching_brace(source, cursor) else {
            break;
        };

        let ret_type = caps
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("void")
            .trim()
            .to_string();
        let name = caps
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("function")
            .trim()
            .to_string();
        if !["if", "for", "while", "switch", "catch"].contains(&name.as_str()) {
            out.push(CFunctionText {
                ret_type,
                name,
                params: source[open + 1..close_paren].to_string(),
                body: source[cursor + 1..close_body].to_string(),
                body_start: cursor + 1,
            });
        }
        search_from = close_body + 1;
        let _ = absolute_start;
    }
    out
}

fn parse_function(
    builder: &mut ModuleBuilder,
    func: &CFunctionText,
    language: Language,
    known_functions: &HashSet<String>,
    struct_field_types: &HashMap<String, HashMap<String, String>>,
    function_pointer_typedefs: &HashSet<String>,
) -> uniflow_hir::Function {
    let mut env = CLikeEnv::default();
    env.language = Some(language);
    env.known_functions = known_functions.clone();
    env.struct_field_types = struct_field_types.clone();
    let mut params = Vec::new();
    for param in split_top_level_commas(&func.params) {
        let part = param.trim();
        if part.is_empty() || part == "void" {
            continue;
        }
        let Some((name, ty_name)) = parse_typed_name(part) else {
            continue;
        };
        let symbol = builder.add_symbol(&name, SymbolKind::Param);
        env.vars.insert(name.clone(), symbol);
        env.types.insert(name.clone(), ty_name.clone());
        record_array_extents(builder, symbol, part, &mut env);
        if function_pointer_typedefs.contains(ty_name.trim()) {
            env.function_pointer_vars.insert(name.clone());
        }
        params.push(Param {
            name,
            symbol,
            ty: Some(builder.ensure_type(&ty_name)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span: default_span(),
        });
    }

    let stmts = parse_c_like_block(
        builder,
        &func.body,
        func.body_start,
        &mut env,
        function_pointer_typedefs,
    );

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
        cpp: None,
        cpp_initializers: Vec::new(),
        span: default_span(),
    }
}
