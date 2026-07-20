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
            span: find_substring_span(builder.file_id(), &method_text.body, part, 0),
        });
    }

    let stmts =
        parse_block_statements(builder, &method_text.body, method_text.body_start_byte, resolver, &mut env);
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
    _body_start_byte: usize,
    resolver: &JavaResolver,
    env: &mut JavaEnv,
) -> Vec<Stmt> {
    let mut out = Vec::new();
    for (start, end, raw_stmt) in split_top_level_statements_c_like_with_offsets(body_text) {
        let stmt = raw_stmt.trim();
        if stmt.is_empty() {
            continue;
        }
        let span = span_from_offsets(builder.file_id(), body_text, start, end);

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

        if let Some((left, right)) = split_once_top_level(stmt, '=') {
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
                let init = parse_expr(builder, &right, resolver, env, span);
                let qualified_ty = if raw_ty_name.trim() == "var" {
                    infer_expr_type_from_expr(&init, resolver, env)
                        .unwrap_or_else(|| "Object".to_string())
                } else {
                    resolver.qualify_type_name(&raw_ty_name)
                };
                let symbol = builder.add_symbol(&name, SymbolKind::Local);
                env.vars.insert(name.clone(), symbol);
                env.types.insert(name.clone(), qualified_ty.clone());
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

        let expr = parse_expr(builder, stmt, resolver, env, span);
        out.push(Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr,
            span,
        });
    }
    out
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
    if let Some((base, field)) = split_last_top_level_dot(trimmed) {
        LValue::Field {
            base: Box::new(parse_expr(builder, &base, resolver, env, span)),
            field,
        }
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

