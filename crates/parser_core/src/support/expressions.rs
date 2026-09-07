pub fn parse_call_parts(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim();
    if !trimmed.ends_with(')') {
        return None;
    }

    // Match the opening parenthesis belonging to the final call rather than
    // taking the first `(` in the expression.  This is required for Python
    // receiver expressions such as `globals().get("x")`, `vars(obj).update(...)`
    // and `getattr(obj, "cb")()`.
    let bytes = trimmed.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let mut open = None;

    for index in (0..bytes.len()).rev() {
        let byte = bytes[index];
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
            } else if byte == active_quote {
                quote = None;
            }
            continue;
        }

        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b')' => depth += 1,
            b'(' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    open = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }

    let open = open?;
    let callee = trimmed[..open].trim();
    if callee.is_empty() {
        return None;
    }
    let args = trimmed[open + 1..trimmed.len() - 1].trim();
    Some((callee.to_string(), args.to_string()))
}

pub fn new_var_ref(builder: &mut ModuleBuilder, symbol: SymbolId) -> Expr {
    Expr::VarRef {
        id: builder.alloc_expr_id(),
        symbol,
        span: default_span(),
    }
}

pub fn new_string(builder: &mut ModuleBuilder, value: &str) -> Expr {
    Expr::Literal {
        id: builder.alloc_expr_id(),
        kind: LiteralKind::String(value.to_string()),
        span: default_span(),
    }
}

pub fn new_int(builder: &mut ModuleBuilder, value: i64) -> Expr {
    Expr::Literal {
        id: builder.alloc_expr_id(),
        kind: LiteralKind::Int(value),
        span: default_span(),
    }
}

pub fn new_call(
    builder: &mut ModuleBuilder,
    target_name: &str,
    receiver: Option<Expr>,
    args: Vec<Expr>,
) -> Expr {
    new_call_with_arg_names(builder, target_name, receiver, args, Vec::new())
}

pub fn new_call_with_arg_names(
    builder: &mut ModuleBuilder,
    target_name: &str,
    receiver: Option<Expr>,
    args: Vec<Expr>,
    arg_names: Vec<Option<String>>,
) -> Expr {
    let qualifier_is_explicit = receiver.is_some();
    Expr::Call(CallExpr {
        id: builder.alloc_expr_id(),
        target: CallTarget::Named(target_name.to_string()),
        receiver: receiver.map(Box::new),
        qualifier_is_explicit,
        args,
        arg_names,
        span: default_span(),
    })
}

pub fn new_dynamic_call(
    builder: &mut ModuleBuilder,
    callee: Expr,
    receiver: Option<Expr>,
    args: Vec<Expr>,
) -> Expr {
    new_dynamic_call_with_arg_names(builder, callee, receiver, args, Vec::new())
}

pub fn new_dynamic_call_with_arg_names(
    builder: &mut ModuleBuilder,
    callee: Expr,
    receiver: Option<Expr>,
    args: Vec<Expr>,
    arg_names: Vec<Option<String>>,
) -> Expr {
    let qualifier_is_explicit = receiver.is_some();
    Expr::Call(CallExpr {
        id: builder.alloc_expr_id(),
        target: CallTarget::Dynamic(Box::new(callee)),
        receiver: receiver.map(Box::new),
        qualifier_is_explicit,
        args,
        arg_names,
        span: default_span(),
    })
}

pub fn new_field_read(builder: &mut ModuleBuilder, base: Expr, field: &str) -> Expr {
    Expr::FieldRead {
        id: builder.alloc_expr_id(),
        base: Box::new(base),
        field: field.to_string(),
        span: default_span(),
    }
}

pub fn new_binary(builder: &mut ModuleBuilder, lhs: Expr, rhs: Expr, op: BinaryOp) -> Expr {
    Expr::Binary {
        id: builder.alloc_expr_id(),
        op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        span: default_span(),
    }
}

pub fn ensure_known_symbol(
    builder: &mut ModuleBuilder,
    env: &mut HashMap<String, SymbolId>,
    name: &str,
    kind: SymbolKind,
) -> SymbolId {
    if let Some(existing) = env.get(name).copied() {
        existing
    } else {
        let id = builder.add_symbol(name, kind);
        env.insert(name.to_string(), id);
        id
    }
}

pub fn empty_try_catch(builder: &mut ModuleBuilder) -> CatchClause {
    CatchClause {
        symbol: None,
        ty: None,
        body: builder.empty_block(),
        span: default_span(),
    }
}

pub fn unsupported<T>(msg: &str) -> Result<T> {
    Err(anyhow!(msg.to_string()))
}
