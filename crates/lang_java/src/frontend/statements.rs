fn parse_method(
    builder: &mut ModuleBuilder,
    class_name: &str,
    simple_class_name: &str,
    method_text: &JavaMethodText,
    resolver: &JavaResolver,
    class_fields: &[ParsedField],
) -> Option<uniflow_hir::Function> {
    let sig = parse_method_signature(method_text.signature.trim(), simple_class_name)?;
    let mut env = JavaEnv {
        current_class: class_name.to_string(),
        ..Default::default()
    };

    let receiver = if sig.is_static {
        None
    } else {
        let this_symbol = builder.add_symbol("this", SymbolKind::Param);
        env.this_symbol = Some(this_symbol);
        env.vars.insert("this".to_string(), this_symbol);
        env.types.insert("this".to_string(), class_name.to_string());
        Some(Param {
            name: "this".to_string(),
            symbol: this_symbol,
            ty: Some(builder.ensure_type(class_name)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span: method_text.span,
        })
    };

    for field in class_fields {
        env.field_types
            .insert(field.field.name.clone(), field.qualified_ty.clone());
    }

    let mut params = Vec::new();
    for param in split_top_level_commas(&sig.params_text) {
        let part = param.trim();
        if part.is_empty() {
            continue;
        }
        let pieces: Vec<&str> = part.split_whitespace().collect();
        if pieces.is_empty() {
            continue;
        }
        let name = pieces[pieces.len() - 1].to_string();
        let ty_name = if pieces.len() >= 2 {
            pieces[..pieces.len() - 1].join(" ")
        } else {
            "Object".to_string()
        };
        let qualified_ty = resolver.qualify_type_name(&ty_name);
        let symbol = builder.add_symbol(&name, SymbolKind::Param);
        env.vars.insert(name.clone(), symbol);
        env.types.insert(name.clone(), qualified_ty.clone());
        params.push(Param {
            name,
            symbol,
            ty: Some(builder.ensure_type(&qualified_ty)),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span: offset_java_span(method_text.signature_span, find_substring_span(
                builder.file_id(), &method_text.signature, part, 0,
            )),
        });
    }

    let stmts = parse_block_statements(
        builder,
        &method_text.body,
        method_text.body_span,
        resolver,
        &mut env,
    );
    let body = Block {
        id: builder.alloc_block_id(),
        stmts,
        span: method_text.span,
    };

    let return_type = sig
        .return_type
        .as_ref()
        .map(|ty| builder.ensure_type(&resolver.qualify_type_name(ty)));

    Some(uniflow_hir::Function {
        id: builder.alloc_function_id(),
        name: if sig.is_constructor {
            format!("{class_name}.<init>")
        } else {
            format!("{class_name}.{}", sig.method_name)
        },
        symbol: Some(builder.add_symbol(
            if sig.is_constructor {
                "<init>"
            } else {
                &sig.method_name
            },
            SymbolKind::Method,
        )),
        params,
        captures: Vec::new(),
        return_type,
        body,
        is_method: true,
        receiver,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: method_text.span,
    })
}

fn parse_block_statements(
    builder: &mut ModuleBuilder,
    body_text: &str,
    base_span: uniflow_hir::Span,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    for range in uniflow_parser_core::java_syntax::JavaSyntax::statement_ranges(body_text) {
        let (start, end) = (range.start, range.end);
        let raw_stmt = &body_text[range];
        let stmt = raw_stmt.trim().strip_suffix(';').unwrap_or(raw_stmt.trim()).trim_end();
        if stmt.is_empty() {
            continue;
        }
        let span = offset_java_span(
            base_span,
            span_from_offsets(builder.file_id(), body_text, start, end),
        );

        if let Some(branch) = parse_java_control_statement(builder, raw_stmt, resolver, env, span) {
            out.push(branch);
            continue;
        }

        if let Some(try_stmt) = parse_try_statement(builder, stmt, resolver, env, span) {
            out.push(try_stmt);
            continue;
        }

        if stmt == "break" || stmt.starts_with("break ") {
            out.push(Stmt::Break { id: builder.alloc_stmt_id(),
                label: stmt.strip_prefix("break ").map(|s| s.trim().to_string()), span });
            continue;
        }
        if stmt == "continue" || stmt.starts_with("continue ") {
            out.push(Stmt::Continue { id: builder.alloc_stmt_id(),
                label: stmt.strip_prefix("continue ").map(|s| s.trim().to_string()), span });
            continue;
        }

        if let Some(update) = parse_java_update_statement(builder, stmt, resolver, env, span) {
            out.push(update);
            continue;
        }

        if let Some(rest) = stmt.strip_prefix("return ") {
            let value = parse_expr(builder, rest, resolver, env, span);
            out.push(Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: Some(value),
                span,
            });
            continue;
        }

        if stmt == "return" {
            out.push(Stmt::Return {
                id: builder.alloc_stmt_id(),
                value: None,
                span,
            });
            continue;
        }

        if let Some(rest) = stmt.strip_prefix("throw ") {
            let value = parse_expr(builder, rest, resolver, env, span);
            out.push(Stmt::Throw {
                id: builder.alloc_stmt_id(),
                value: Some(value),
                span,
            });
            continue;
        }

        if let Some(declarations) = parse_java_local_declaration_list(builder, stmt, resolver, env, span) {
            out.extend(declarations);
            continue;
        }

        if let Some(index) = find_java_top_level_operator(stmt, "=") {
            let (left, right) = (stmt[..index].trim().to_string(), stmt[index + 1..].trim().to_string());
            if is_declaration(left.as_str(), env) {
                let pieces: Vec<&str> = left.split_whitespace().collect();
                if pieces.len() < 2 {
                    continue;
                }
                let name = pieces[pieces.len() - 1].to_string();
                let raw_ty_name = pieces[..pieces.len() - 1]
                    .iter()
                    .copied()
                    .filter(|piece| !matches!(*piece, "final"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let previous_expected_arity = env.expected_callable_arity;
                env.expected_callable_arity = java_functional_interface_arity(&raw_ty_name);
                let init = parse_expr(builder, &right, resolver, env, span);
                env.expected_callable_arity = previous_expected_arity;
                let qualified_ty = if raw_ty_name.trim() == "var" {
                    infer_expr_type_from_expr(&init, resolver, env)
                        .unwrap_or_else(|| "Object".to_string())
                } else {
                    resolver.qualify_type_name(&raw_ty_name)
                };
                let symbol = builder.add_symbol(&name, SymbolKind::Local);
                env.vars.insert(name.clone(), symbol);
                env.types.insert(name.clone(), qualified_ty.clone());
                if matches!(&init, Expr::Lambda { .. }) {
                    env.callable_values.insert(symbol);
                }
                out.push(Stmt::Let {
                    id: builder.alloc_stmt_id(),
                    symbol,
                    ty: Some(builder.ensure_type(&qualified_ty)),
                    init: Some(init),
                    span,
                });
            } else {
                let lhs = parse_lvalue(builder, &left, resolver, env, span);
                let rhs = parse_expr(builder, &right, resolver, env, span);
                out.push(Stmt::Assign {
                    id: builder.alloc_stmt_id(),
                    lhs,
                    rhs,
                    span,
                });
            }
            continue;
        }

        if let Some((name, raw_type)) = java_uninitialized_local(stmt) {
            let qualified_type = resolver.qualify_type_name(&raw_type);
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.vars.insert(name.clone(), symbol);
            env.types.insert(name, qualified_type.clone());
            out.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol,
                ty: Some(builder.ensure_type(&qualified_type)), init: None, span });
            continue;
        }

        let expr = parse_expr(builder, stmt, resolver, env, span);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr,
            span,
        });
    }
    out
}

fn parse_java_local_declaration_list(
    builder: &mut ModuleBuilder, stmt: &str, resolver: &JavaResolver,
    env: &mut JavaEnv, span: uniflow_hir::Span,
) -> Option<Vec<Stmt>> {
    let parts = split_top_level_commas(stmt);
    if parts.len() < 2 { return None; }
    let first = parts.first()?.trim();
    let first_assignment = find_java_top_level_operator(first, "=");
    let first_left = first_assignment.map_or(first, |index| first[..index].trim());
    let (first_name, raw_type) = java_uninitialized_local(first_left)?;
    if !is_declaration(first_left, env) { return None; }
    let mut output = Vec::new();
    for (index, part) in parts.into_iter().enumerate() {
        let part = part.trim();
        let assignment = find_java_top_level_operator(part, "=");
        let left = assignment.map_or(part, |at| part[..at].trim());
        let (name, declarator_type) = if index == 0 {
            (first_name.clone(), raw_type.clone())
        } else {
            java_uninitialized_local(&format!("{raw_type} {left}"))?
        };
        let previous_expected_arity = env.expected_callable_arity;
        env.expected_callable_arity = java_functional_interface_arity(&declarator_type);
        let init = assignment.map(|at| parse_expr(builder, &part[at + 1..], resolver, env, span));
        env.expected_callable_arity = previous_expected_arity;
        let qualified_type = resolver.qualify_type_name(&declarator_type);
        let symbol = builder.add_symbol(&name, SymbolKind::Local);
        env.vars.insert(name.clone(), symbol);
        env.types.insert(name, qualified_type.clone());
        if init.as_ref().is_some_and(|value| matches!(value, Expr::Lambda { .. })) {
            env.callable_values.insert(symbol);
        }
        output.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol,
            ty: Some(builder.ensure_type(&qualified_type)), init, span });
    }
    Some(output)
}

fn parse_java_update_statement(
    builder: &mut ModuleBuilder, stmt: &str, resolver: &JavaResolver,
    env: &mut JavaEnv, span: uniflow_hir::Span,
) -> Option<Stmt> {
    // ++/-- use the expression parser even in statement position, so receiver
    // and subscript side effects have the same single-evaluation semantics.
    for (operator, op) in [("+=", BinaryOp::Add), ("-=", BinaryOp::Sub),
        ("*=", BinaryOp::Mul), ("/=", BinaryOp::Div), ("%=", BinaryOp::Mod),
        ("&=", BinaryOp::BitAnd), ("|=", BinaryOp::BitOr), ("^=", BinaryOp::BitXor)]
    {
        if let Some(index) = find_java_top_level_operator(stmt, operator) {
            let operand = stmt[..index].trim();
            if operand.contains('(') || operand.contains("++") || operand.contains("--") { return None; }
            let lhs = parse_lvalue(builder, operand, resolver, env, span);
            let left = parse_expr(builder, operand, resolver, env, span);
            let right = parse_expr(builder, &stmt[index + operator.len()..], resolver, env, span);
            let rhs = Expr::Binary { id: builder.alloc_expr_id(), op,
                lhs: Box::new(left), rhs: Box::new(right), span };
            return Some(Stmt::Assign { id: builder.alloc_stmt_id(), lhs, rhs, span });
        }
    }
    None
}

fn java_uninitialized_local(stmt: &str) -> Option<(String, String)> {
    static DECLARATION: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| Regex::new(
        r"(?s)^(?:final\s+)?([\p{L}_$][\p{L}\p{N}_$.]*(?:\s*<[^;=]+>)?(?:\s*\[\s*\])*)\s+([\p{L}_$][\p{L}\p{N}_$]*)(\s*(?:\[\s*\])*)$"
    ).expect("valid Java declaration regex"));
    let captures = DECLARATION.captures(stmt)?;
    let ty = captures.get(1)?.as_str();
    if matches!(ty, "assert" | "yield" | "throw" | "return" | "case" | "new") { return None; }
    Some((captures.get(2)?.as_str().to_string(), format!("{ty}{}", captures.get(3)?.as_str())))
}

fn offset_java_span(base: uniflow_hir::Span, local: uniflow_hir::Span) -> uniflow_hir::Span {
    let start_line = base.start_line + local.start_line.saturating_sub(1);
    let end_line = base.start_line + local.end_line.saturating_sub(1);
    uniflow_hir::Span {
        file: base.file,
        start_byte: base.start_byte.saturating_add(local.start_byte),
        end_byte: base.start_byte.saturating_add(local.end_byte),
        start_line,
        start_col: if local.start_line == 1 {
            base.start_col + local.start_col.saturating_sub(1)
        } else {
            local.start_col
        },
        end_line,
        end_col: if local.end_line == 1 {
            base.start_col + local.end_col.saturating_sub(1)
        } else {
            local.end_col
        },
    }
}

fn parse_java_control_statement(
    builder: &mut ModuleBuilder,
    stmt: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Option<Stmt> {
    use uniflow_parser_core::java_syntax::{JavaSyntax, JavaSyntaxKind as K};
    let first = stmt.split(|c: char| !c.is_alphanumeric() && c != '_').next()?;
    if !matches!(first, "if" | "while" | "do" | "for") { return None; }
    let syntax = JavaSyntax::parse_statements(stmt);
    let node = syntax.nodes.get(*syntax.roots.first()?)?;
    if node.kind == K::For && node.condition.is_some() {
        let mut loop_env = env.clone();
        let init = parse_java_for_clause(builder, stmt, node.initializer.clone()?, true, resolver, &mut loop_env, span);
        let condition = node.condition.clone()?;
        let cond_span = offset_java_span(span, span_from_offsets(builder.file_id(), stmt, condition.start, condition.end));
        let cond = (!stmt[condition.clone()].trim().is_empty())
            .then(|| parse_expr(builder, &stmt[condition], resolver, &mut loop_env, cond_span));
        let update = parse_java_for_clause(builder, stmt, node.update.clone()?, false, resolver, &mut loop_env, span);
        let body = java_statement_body(builder, stmt, node.body.clone()?, resolver, &mut loop_env, span);
        return Some(Stmt::For { id: builder.alloc_stmt_id(), init_is_scoped: true, init, cond, update, body, span });
    }
    if node.kind == K::For && node.condition.is_none() {
        let open = stmt.find('(')?;
        let close = matching_delimiter(stmt, open, '(', ')')?;
        let (declaration, iterable_text) = split_once_top_level(&stmt[open + 1..close], ':')?;
        let pieces = declaration.split_whitespace().filter(|p| *p != "final").collect::<Vec<_>>();
        if pieces.len() < 2 { return None; }
        let name = *pieces.last()?;
        let ty = resolver.qualify_type_name(&pieces[..pieces.len() - 1].join(" "));
        let iterable = parse_expr(builder, &iterable_text, resolver, env, span);
        let mut loop_env = env.clone();
        let item_symbol = builder.add_symbol(name, SymbolKind::Local);
        loop_env.vars.insert(name.to_string(), item_symbol);
        loop_env.types.insert(name.to_string(), ty);
        let body = java_statement_body(builder, stmt, node.body.clone()?, resolver, &mut loop_env, span);
        return Some(Stmt::ForEach { id: builder.alloc_stmt_id(), item_symbol, iterable, body, span });
    }
    if !matches!(node.kind, K::If | K::While | K::Do) { return None; }
    let condition = node.condition.clone()?;
    let condition_span = offset_java_span(span, span_from_offsets(
        builder.file_id(), stmt, condition.start, condition.end,
    ));
    let cond = parse_expr(builder, &stmt[condition], resolver, env, condition_span);
    let body = java_statement_body(builder, stmt, node.body.clone()?, resolver, env, span);
    let id = builder.alloc_stmt_id();
    Some(match node.kind {
        K::While => Stmt::While { id, cond, body, span },
        K::Do => Stmt::DoWhile { id, cond, body, span },
        K::If => {
            let else_block = node.alternative.clone()
                .map(|r| java_statement_body(builder, stmt, r, resolver, env, span));
            Stmt::If { id, cond, then_block: body, else_block, span }
        }
        _ => unreachable!(),
    })
}

fn parse_java_for_clause(
    builder: &mut ModuleBuilder,
    stmt: &str,
    range: std::ops::Range<usize>,
    declarations: bool,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Block {
    let mut stmts = Vec::new();
    let mut cursor = range.start;
    let mut declaration_type = None;
    for part in split_top_level_commas(&stmt[range.clone()]) {
        let part = part.trim();
        if part.is_empty() { continue; }
        let start = stmt[cursor..range.end].find(part).map_or(cursor, |offset| cursor + offset);
        cursor = start + part.len();
        let local_span = offset_java_span(span, span_from_offsets(builder.file_id(), stmt, start, cursor));
        let assignment = find_java_top_level_operator(part, "=");
        let left = assignment.map_or(part, |index| part[..index].trim());
        let declaration = if declarations {
            java_uninitialized_local(left).or_else(|| declaration_type.as_ref()
                .map(|ty: &String| (left.to_string(), ty.clone())))
        } else { None };
        if let Some((name, ty)) = declaration {
            declaration_type = Some(ty.clone());
            let init = assignment.map(|index| parse_expr(builder, &part[index + 1..], resolver, env, local_span));
            let ty = resolver.qualify_type_name(&ty);
            let symbol = builder.add_symbol(&name, SymbolKind::Local);
            env.vars.insert(name.clone(), symbol);
            env.types.insert(name, ty.clone());
            stmts.push(Stmt::Let { id: builder.alloc_stmt_id(), symbol,
                ty: Some(builder.ensure_type(&ty)), init, span: local_span });
        } else {
            stmts.extend(parse_block_statements(builder, part, local_span, resolver, env));
        }
    }
    Block { id: builder.alloc_block_id(), stmts,
        span: offset_java_span(span, span_from_offsets(builder.file_id(), stmt, range.start, range.end)) }
}

fn java_statement_body(
    builder: &mut ModuleBuilder,
    stmt: &str,
    range: std::ops::Range<usize>,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Block {
    let body_span = offset_java_span(span, span_from_offsets(
        builder.file_id(), stmt, range.start, range.end,
    ));
    let inner = if stmt[range.clone()].starts_with('{') {
        range.start + 1..range.end - 1
    } else { range };
    let base = offset_java_span(span, span_from_offsets(
        builder.file_id(), stmt, inner.start, inner.start,
    ));
    let mut block_env = env.clone();
    Block {
        id: builder.alloc_block_id(),
        stmts: parse_block_statements(builder, &stmt[inner], base, resolver, &mut block_env),
        span: body_span,
    }
}

fn parse_try_statement(
    builder: &mut ModuleBuilder,
    stmt: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Option<Stmt> {
    let mut cursor = "try".len();
    if !stmt.starts_with("try")
        || stmt[cursor..]
            .chars()
            .next()
            .is_some_and(|ch| !ch.is_whitespace() && ch != '(' && ch != '{')
    {
        return None;
    }
    cursor += stmt[cursor..].len() - stmt[cursor..].trim_start().len();
    if stmt[cursor..].starts_with('(') {
        cursor = matching_delimiter(stmt, cursor, '(', ')')? + 1;
    }
    let try_open = stmt[cursor..].find('{')? + cursor;
    let try_close = matching_delimiter(stmt, try_open, '{', '}')?;
    let try_block = java_block_from_slice(
        builder,
        stmt,
        try_open,
        try_close,
        resolver,
        env,
        span,
    );
    cursor = try_close + 1;

    let mut catches = Vec::new();
    let mut finally_block = None;
    loop {
        cursor += stmt[cursor..].len() - stmt[cursor..].trim_start().len();
        if stmt[cursor..].starts_with("catch") {
            let catch_start = cursor;
            let mut catch_env = env.clone();
            cursor += "catch".len();
            cursor += stmt[cursor..].len() - stmt[cursor..].trim_start().len();
            let binding_open = cursor;
            let binding_close = matching_delimiter(stmt, binding_open, '(', ')')?;
            let binding = stmt[binding_open + 1..binding_close].trim();
            let parts = binding.split_whitespace().collect::<Vec<_>>();
            let (symbol, ty) = if parts.len() >= 2 {
                let name = parts[parts.len() - 1];
                let raw_ty = parts[..parts.len() - 1].join(" ");
                let symbol = builder.add_symbol(name, SymbolKind::Local);
                catch_env.vars.insert(name.to_string(), symbol);
                catch_env.types
                    .insert(name.to_string(), resolver.qualify_type_name(&raw_ty));
                (
                    Some(symbol),
                    Some(builder.ensure_type(&resolver.qualify_type_name(&raw_ty))),
                )
            } else {
                (None, None)
            };
            cursor = binding_close + 1;
            let open = stmt[cursor..].find('{')? + cursor;
            let close = matching_delimiter(stmt, open, '{', '}')?;
            catches.push(uniflow_hir::CatchClause {
                symbol,
                ty,
                body: java_block_from_slice(builder, stmt, open, close, resolver, &mut catch_env, span),
                span: offset_java_span(span, span_from_offsets(
                    builder.file_id(), stmt, catch_start, close + 1,
                )),
            });
            cursor = close + 1;
            continue;
        }
        if stmt[cursor..].starts_with("finally") {
            cursor += "finally".len();
            let open = stmt[cursor..].find('{')? + cursor;
            let close = matching_delimiter(stmt, open, '{', '}')?;
            finally_block = Some(java_block_from_slice(
                builder, stmt, open, close, resolver, env, span,
            ));
            cursor = close + 1;
        }
        break;
    }
    if !stmt[cursor..].trim().is_empty() {
        return None;
    }
    Some(Stmt::Try {
        id: builder.alloc_stmt_id(),
        try_block,
        catches,
        finally_block,
        span,
    })
}

fn java_block_from_slice(
    builder: &mut ModuleBuilder,
    stmt: &str,
    open: usize,
    close: usize,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> Block {
    let mut block_env = env.clone();
    Block {
        id: builder.alloc_block_id(),
        stmts: parse_block_statements(
            builder,
            &stmt[open + 1..close],
            offset_java_span(
                span,
                span_from_offsets(builder.file_id(), stmt, open + 1, open + 1),
            ),
            resolver,
            &mut block_env,
        ),
        span,
    }
}


fn java_functional_interface_arity(type_name: &str) -> Option<usize> {
    let base = type_name
        .split('<')
        .next()
        .unwrap_or(type_name)
        .trim()
        .rsplit('.')
        .next()
        .unwrap_or(type_name);
    match base {
        "Runnable" | "Supplier" | "Callable" => Some(0),
        "Function" | "Consumer" | "Predicate" | "UnaryOperator" => Some(1),
        "BiFunction" | "BiConsumer" | "BiPredicate" | "BinaryOperator" => Some(2),
        _ if base.starts_with("Int") || base.starts_with("Long") || base.starts_with("Double") => {
            if base.contains("BinaryOperator") || base.starts_with("Obj") {
                Some(2)
            } else {
                Some(1)
            }
        }
        _ => None,
    }
}

fn is_declaration(left: &str, env: &JavaEnv) -> bool {
    let pieces: Vec<&str> = left.split_whitespace().collect();
    if pieces.len() < 2 {
        return false;
    }
    let name = pieces[pieces.len() - 1];
    !env.vars.contains_key(name)
}

fn parse_lvalue(
    builder: &mut ModuleBuilder,
    text: &str,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
    span: uniflow_hir::Span,
) -> LValue {
    let trimmed = text.trim();
    if let Some((base, index)) = split_java_index(trimmed) {
        return LValue::Index {
            base: Box::new(parse_expr(builder, base, resolver, env, span)),
            index: Box::new(parse_expr(builder, index, resolver, env, span)),
        };
    }
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, resolver, env, span)),
            field,
        }
    } else if let Some(symbol) = env.vars.get(trimmed).copied() {
        LValue::Var(symbol)
    } else if env.field_types.contains_key(trimmed) {
        LValue::Field {
            base: Box::new(this_expr(builder, env, span)),
            field: trimmed.to_string(),
        }
    } else {
        let symbol = ensure_known_symbol(builder, &mut env.vars, trimmed, SymbolKind::Local);
        LValue::Var(symbol)
    }
}
