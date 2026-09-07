fn extract_classes(source: &str) -> Vec<PyClassText> {
    let lines: Vec<&str> = source.lines().collect();
    let class_re = Regex::new(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)(?:\(([^)]*)\))?\s*:")
        .expect("valid regex");
    let mut out = Vec::new();
    let mut idx = 0usize;

    while idx < lines.len() {
        let line = lines[idx];
        let Some(caps) = class_re.captures(line) else {
            idx += 1;
            continue;
        };
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        if indent != 0 {
            idx += 1;
            continue;
        }
        let name = caps
            .get(1)
            .map(|m| m.as_str())
            .unwrap_or("Class")
            .to_string();
        let bases = caps
            .get(2)
            .map(|m| split_top_level_commas(m.as_str()))
            .unwrap_or_default();
        let start_line = idx as u32 + 1;

        idx += 1;
        let mut body_lines = Vec::new();
        let mut end_line = start_line;
        while idx < lines.len() {
            let next = lines[idx];
            if next.trim().is_empty() {
                body_lines.push(next.to_string());
                end_line = idx as u32 + 1;
                idx += 1;
                continue;
            }
            let next_indent = next.chars().take_while(|c| c.is_whitespace()).count();
            if next_indent <= indent {
                break;
            }
            body_lines.push(next.to_string());
            end_line = idx as u32 + 1;
            idx += 1;
        }

        out.push(PyClassText {
            name,
            bases,
            body: body_lines.join("\n"),
            start_line,
            end_line,
            indent,
        });
    }

    out
}

fn parse_python_function_header(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("async def ")
        .or_else(|| trimmed.strip_prefix("def "))?;

    let open = rest.find('(')?;
    let name = rest[..open].trim();
    if name.is_empty()
        || !name.chars().enumerate().all(|(idx, ch)| {
            ch == '_' || ch.is_ascii_alphanumeric() && (idx > 0 || !ch.is_ascii_digit())
        })
    {
        return None;
    }

    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut close = None;
    for (offset, ch) in rest[open..].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let suffix = rest[close + 1..].trim();
    if !suffix.ends_with(':') {
        return None;
    }
    let before_colon = suffix[..suffix.len() - 1].trim();
    if !before_colon.is_empty() && !before_colon.starts_with("->") {
        return None;
    }

    Some((name.to_string(), rest[open + 1..close].to_string()))
}

fn parse_python_function_return_annotation(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("async def ")
        .or_else(|| trimmed.strip_prefix("def "))?;
    let open = rest.find('(')?;
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut close = None;
    for (offset, ch) in rest[open..].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active_quote {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let suffix = rest[close + 1..].trim();
    let before_colon = suffix.strip_suffix(':')?.trim();
    before_colon
        .strip_prefix("->")
        .map(str::trim)
        .filter(|annotation| !annotation.is_empty())
        .map(str::to_string)
}

fn extract_functions_at_indent(
    source: &str,
    required_indent: usize,
    base_line: u32,
) -> Vec<PyFunctionText> {
    let mut out = Vec::new();
    let lines: Vec<&str> = source.lines().collect();

    let mut idx = 0usize;
    let mut pending_decorators: Vec<String> = Vec::new();
    while idx < lines.len() {
        let line = lines[idx];
        let indent = line.chars().take_while(|c| c.is_whitespace()).count();
        let trimmed = line.trim();
        if indent == required_indent && trimmed.starts_with('@') {
            pending_decorators.push(trimmed.to_string());
            idx += 1;
            continue;
        }
        let Some((name, params)) = parse_python_function_header(line) else {
            if indent == required_indent && !trimmed.is_empty() && !trimmed.starts_with('#') {
                pending_decorators.clear();
            }
            idx += 1;
            continue;
        };
        if indent != required_indent {
            idx += 1;
            continue;
        }
        let start_line = base_line + idx as u32;
        let decorators = std::mem::take(&mut pending_decorators);

        idx += 1;
        let mut body_lines = Vec::new();
        let mut end_line = start_line;
        while idx < lines.len() {
            let next = lines[idx];
            if next.trim().is_empty() {
                body_lines.push(next.to_string());
                end_line = base_line + idx as u32;
                idx += 1;
                continue;
            }
            let next_indent = next.chars().take_while(|c| c.is_whitespace()).count();
            if next_indent <= indent {
                break;
            }
            body_lines.push(next.to_string());
            end_line = base_line + idx as u32;
            idx += 1;
        }

        let return_annotation = parse_python_function_return_annotation(line);
        out.push(PyFunctionText {
            name,
            params,
            return_annotation,
            body: body_lines.join("\n"),
            start_line,
            end_line,
            decorators,
        });
    }

    out
}

fn parse_class(
    builder: &mut ModuleBuilder,
    class: &PyClassText,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    class_field_index: &HashMap<String, HashMap<String, String>>,
    module_name: &str,
    project_index: Option<&PyProjectIndex>,
) -> Class {
    let mut methods = Vec::new();
    let mut field_map = HashMap::<String, Field>::new();
    let mut field_types = HashMap::<String, String>::new();
    let qualified_class_name = qualify_class_name(module_name, &class.name, project_index);
    let hir_class_name = if project_index.is_some() {
        qualified_class_name.clone()
    } else {
        class.name.clone()
    };

    for (idx, raw_line) in class.body.lines().enumerate() {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        if indent != class.indent + 4 {
            continue;
        }
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("def ")
            || line.starts_with('@')
        {
            continue;
        }
        if let Some((name, annotation, value)) = parse_class_body_annotated_field(line) {
            let inferred =
                normalize_python_annotation_type(&annotation, module_name, imports, project_index)
                    .or_else(|| {
                        value.as_deref().and_then(|expr| {
                            infer_simple_python_type(
                                expr,
                                imports,
                                &PyEnv::default(),
                                known_classes,
                            )
                        })
                    })
                    .map(|ty| qualify_local_python_type(&ty, module_name, known_classes));
            let ty = inferred.as_ref().map(|ty| builder.ensure_type(ty));
            let span = span_from_line_range(
                builder.file_id(),
                class.start_line + 1 + idx as u32,
                class.start_line + 1 + idx as u32,
            );
            if let Some(inferred) = inferred {
                field_types.insert(name.clone(), inferred);
            }
            field_map.entry(name.clone()).or_insert(Field {
                name: name.clone(),
                symbol: Some(builder.add_symbol(&name, SymbolKind::Field)),
                ty,
                span,
            });
            continue;
        }
        if let Some((left, right)) = split_once_top_level(line, '=') {
            let name = left.trim();
            if !name.contains('.') && is_simple_ident(name) {
                let inferred = infer_python_field_factory_type(
                    &right,
                    module_name,
                    imports,
                    project_index,
                    known_classes,
                )
                .or_else(|| {
                    project_index.and_then(|index| {
                        infer_project_expr_type(
                            &right,
                            module_name,
                            imports,
                            index,
                            &field_types,
                            Some(&qualified_class_name),
                        )
                    })
                })
                .or_else(|| {
                    infer_simple_python_type(&right, imports, &PyEnv::default(), known_classes)
                })
                .map(|ty| qualify_local_python_type(&ty, module_name, known_classes));
                let ty = inferred.as_ref().map(|ty| builder.ensure_type(ty));
                let span = span_from_line_range(
                    builder.file_id(),
                    class.start_line + 1 + idx as u32,
                    class.start_line + 1 + idx as u32,
                );
                if let Some(inferred) = inferred {
                    field_types.insert(name.to_string(), inferred);
                }
                field_map.entry(name.to_string()).or_insert(Field {
                    name: name.to_string(),
                    symbol: Some(builder.add_symbol(name, SymbolKind::Field)),
                    ty,
                    span,
                });
            }
        }
    }

    for method in extract_functions_at_indent(&class.body, class.indent + 4, class.start_line + 1) {
        let parsed = parse_function(
            builder,
            &method,
            imports,
            known_classes,
            Some(&hir_class_name),
            &class
                .bases
                .iter()
                .map(|base| {
                    qualify_type_name(module_name, base, imports, project_index)
                        .unwrap_or_else(|| base.clone())
                })
                .collect::<Vec<_>>(),
            &field_types,
            class_field_index,
            module_name,
            project_index,
            None,
            None,
        );
        let ParsedFunction {
            function,
            discovered_fields,
            synthetic_functions,
        } = parsed;
        for field in discovered_fields {
            field_map.entry(field.name.clone()).or_insert(field);
        }
        if function_has_decorator(&method, "property") {
            if let Some(ret_ty) = function
                .return_type
                .and_then(|id| builder.find_type_name(id))
                .map(|name| name.to_string())
            {
                let span =
                    span_from_line_range(builder.file_id(), method.start_line, method.end_line);
                field_types.insert(method.name.clone(), ret_ty.clone());
                field_map.entry(method.name.clone()).or_insert(Field {
                    name: method.name.clone(),
                    symbol: Some(builder.add_symbol(&method.name, SymbolKind::Field)),
                    ty: Some(builder.ensure_type(&ret_ty)),
                    span,
                });
            }
        }
        if let Some(property_name) = property_decorator_target(&method, "setter")
            .or_else(|| property_decorator_target(&method, "deleter"))
        {
            if let Some(ret_ty) = field_types.get(&property_name).cloned() {
                let span =
                    span_from_line_range(builder.file_id(), method.start_line, method.end_line);
                field_map.entry(property_name.clone()).or_insert(Field {
                    name: property_name.clone(),
                    symbol: Some(builder.add_symbol(&property_name, SymbolKind::Field)),
                    ty: Some(builder.ensure_type(&ret_ty)),
                    span,
                });
            }
        }
        for field in field_map.values() {
            if let Some(ty) = field.ty.and_then(|id| builder.find_type_name(id)) {
                field_types.insert(field.name.clone(), ty.to_string());
            }
        }
        for synthetic in synthetic_functions {
            builder.push_item(Item::Function(synthetic));
        }
        methods.push(function);
    }

    Class {
        name: if project_index.is_some() {
            qualified_class_name.clone()
        } else {
            class.name.clone()
        },
        symbol: Some(builder.add_symbol(&class.name, SymbolKind::Class)),
        bases: class
            .bases
            .iter()
            .map(|base| {
                qualify_type_name(module_name, base, imports, project_index)
                    .unwrap_or_else(|| base.clone())
            })
            .collect(),
        fields: field_map.into_values().collect(),
        methods,
        span: span_from_line_range(builder.file_id(), class.start_line, class.end_line),
    }
}

fn parse_function(
    builder: &mut ModuleBuilder,
    func: &PyFunctionText,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    class_name: Option<&str>,
    class_bases: &[String],
    class_field_types: &HashMap<String, String>,
    class_field_index: &HashMap<String, HashMap<String, String>>,
    module_name: &str,
    project_index: Option<&PyProjectIndex>,
    qualified_name: Option<&str>,
    outer_env: Option<&PyEnv>,
) -> ParsedFunction {
    let mut env = PyEnv::default();
    env.current_class = class_name.map(|name| name.to_string());
    env.current_class_bases = class_bases.to_vec();
    env.field_types = class_field_types.clone();
    env.class_field_index = class_field_index.clone();
    env.current_module = module_name.to_string();
    let qualified_function_name =
        qualified_name
            .map(|name| name.to_string())
            .unwrap_or_else(|| {
                if let Some(class_name) = class_name {
                    format!("{class_name}.{}", func.name)
                } else {
                    format!("{module_name}.{}", func.name)
                }
            });
    env.current_function = qualified_function_name.clone();
    env.project_index = project_index.cloned().unwrap_or_default();
    if let Some(outer_env) = outer_env {
        env.capturable_vars = outer_env.vars.clone();
        env.types.extend(outer_env.types.clone());
        env.callable_aliases
            .extend(outer_env.callable_aliases.clone());
    }
    let mut params = Vec::new();
    let mut receiver = None;
    let param_specs = parse_python_param_specs(&func.params);
    let is_staticmethod = function_has_decorator(func, "staticmethod");
    let is_classmethod = function_has_decorator(func, "classmethod");

    for (idx, spec) in param_specs.iter().enumerate() {
        let symbol = builder.add_symbol(&spec.name, SymbolKind::Param);
        env.vars.insert(spec.name.clone(), symbol);
        let treat_as_receiver = idx == 0
            && class_name.is_some()
            && !is_staticmethod
            && (spec.name == "self" || spec.name == "cls" || is_classmethod);
        if treat_as_receiver {
            let ty = class_name.map(|name| builder.ensure_type(name));
            if let Some(class_name) = class_name {
                env.types.insert(spec.name.clone(), class_name.to_string());
            }
            env.self_name = Some(spec.name.clone());
            env.self_symbol = Some(symbol);
            receiver = Some(Param {
                name: spec.name.clone(),
                symbol,
                ty,
                kind: ParamKind::Positional,
                has_default: spec.has_default,
                keyword_only: spec.keyword_only,
                cpp: Default::default(),
                span: span_from_line_range(builder.file_id(), func.start_line, func.start_line),
            });
            continue;
        }
        params.push(Param {
            name: spec.name.clone(),
            symbol,
            ty: None,
            kind: match spec.kind {
                PyParamKind::Positional => ParamKind::Positional,
                PyParamKind::VarArgs => ParamKind::VarArgs,
                PyParamKind::KwArgs => ParamKind::KwArgs,
            },
            has_default: spec.has_default,
            keyword_only: spec.keyword_only,
            cpp: Default::default(),
            span: span_from_line_range(builder.file_id(), func.start_line, func.start_line),
        });
    }

    let stmts = parse_body(
        builder,
        &func.body,
        imports,
        known_classes,
        &mut env,
        func.start_line + 1,
    );
    let receiver_adjusted = class_name.is_some() && !is_staticmethod;
    let return_key = method_signature_key(
        &func.name,
        python_callable_arities(&param_specs, receiver_adjusted)
            .into_iter()
            .next_back()
            .unwrap_or(0),
    );
    let body = Block {
        id: builder.alloc_block_id(),
        stmts,
        span: span_from_line_range(builder.file_id(), func.start_line, func.end_line),
    };

    let name = if let Some(class_name) = class_name {
        format!("{class_name}.{}", func.name)
    } else if project_index.is_some() {
        qualified_function_name.clone()
    } else {
        func.name.clone()
    };
    let symbol_kind = if class_name.is_some() {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };

    let mut synthetic_functions = std::mem::take(&mut env.synthetic_functions);
    collect_block_lambda_functions(
        builder,
        &body,
        &qualified_function_name,
        &mut synthetic_functions,
    );

    let function_symbol = builder.add_symbol(&func.name, symbol_kind);
    if !func.decorators.is_empty() {
        builder.set_symbol_attribute(
            function_symbol,
            "python.decorators",
            func.decorators
                .iter()
                .map(|decorator| normalize_py_decorator_name(decorator))
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
    }
    let mut function = uniflow_hir::Function {
        id: builder.alloc_function_id(),
        name: qualified_name.map(|name| name.to_string()).unwrap_or(name),
        symbol: Some(function_symbol),
        params,
        captures: Vec::new(),
        return_type: class_name
            .and_then(|owner| project_index.and_then(|index| index.method_returns.get(owner)))
            .and_then(|methods| methods.get(&return_key))
            .map(|ty| builder.ensure_type(ty)),
        body,
        is_method: class_name.is_some() && qualified_name.is_none() && !is_staticmethod,
        receiver,
        cpp: None,
        cpp_initializers: Vec::new(),
        span: span_from_line_range(builder.file_id(), func.start_line, func.end_line),
    };

    if let Some(outer_env) = outer_env {
        finalize_nested_function_captures(builder, &mut function, outer_env);
    }

    ParsedFunction {
        function,
        discovered_fields: env.discovered_fields.into_values().collect(),
        synthetic_functions,
    }
}

#[derive(Clone, Default)]
struct PyEnv {
    vars: HashMap<String, SymbolId>,
    capturable_vars: HashMap<String, SymbolId>,
    types: HashMap<String, String>,
    callable_aliases: HashMap<String, String>,
    field_types: HashMap<String, String>,
    local_field_types: HashMap<String, HashMap<String, String>>,
    local_object_aliases: HashMap<String, String>,
    precise_index_types: HashMap<String, HashMap<String, String>>,
    precise_index_callables: HashMap<String, HashMap<String, String>>,
    current_class: Option<String>,
    current_class_bases: Vec<String>,
    self_name: Option<String>,
    self_symbol: Option<SymbolId>,
    discovered_fields: HashMap<String, Field>,
    class_field_index: HashMap<String, HashMap<String, String>>,
    current_module: String,
    current_function: String,
    synthetic_functions: Vec<uniflow_hir::Function>,
    project_index: PyProjectIndex,
    executed_modules: HashSet<String>,
}

#[derive(Clone, Debug)]
struct PyBodyLine {
    indent: usize,
    text: String,
    line_no: u32,
}

fn collect_py_body_lines(body: &str, first_line: u32) -> Vec<PyBodyLine> {
    body.lines()
        .enumerate()
        .map(|(idx, raw_line)| PyBodyLine {
            indent: raw_line.chars().take_while(|c| c.is_whitespace()).count(),
            text: raw_line.to_string(),
            line_no: first_line + idx as u32,
        })
        .collect()
}

fn next_code_line(lines: &[PyBodyLine], mut idx: usize) -> Option<usize> {
    while idx < lines.len() {
        let trimmed = lines[idx].text.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn current_body_indent(lines: &[PyBodyLine]) -> usize {
    lines
        .iter()
        .filter_map(|line| {
            let trimmed = line.text.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(line.indent)
            }
        })
        .min()
        .unwrap_or(0)
}

fn is_clause_continuation_header(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.starts_with("elif ")
        || trimmed == "else:"
        || trimmed.starts_with("except")
        || trimmed == "finally:"
}

fn stmt_end_line(stmt: &Stmt) -> u32 {
    match stmt {
        Stmt::Let { span, .. }
        | Stmt::Assign { span, .. }
        | Stmt::Expr { span, .. }
        | Stmt::If { span, .. }
        | Stmt::While { span, .. }
        | Stmt::ForEach { span, .. }
        | Stmt::For { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::Throw { span, .. }
        | Stmt::Try { span, .. }
        | Stmt::DoWhile { span, .. }
        | Stmt::Switch { span, .. }
        | Stmt::Break { span, .. }
        | Stmt::Continue { span, .. } => span.end_line,
    }
}

fn build_py_block(
    builder: &mut ModuleBuilder,
    stmts: Vec<Stmt>,
    start_line: u32,
    end_line: u32,
) -> Block {
    Block {
        id: builder.alloc_block_id(),
        stmts,
        span: span_from_line_range(builder.file_id(), start_line, end_line.max(start_line)),
    }
}

fn lambda_function_name(enclosing_function: &str, id: ExprId, line_no: u32) -> String {
    format!("{enclosing_function}.__lambda_{}_{}", line_no, id.0)
}

fn lambda_capture_field_name(name: &str) -> String {
    format!("__capture__{name}")
}

fn collect_free_lambda_symbols(
    expr: &Expr,
    locals: &HashSet<SymbolId>,
    outer_symbols: &HashMap<SymbolId, String>,
    seen: &mut HashSet<SymbolId>,
    out: &mut Vec<(SymbolId, String)>,
) {
    match expr {
        Expr::VarRef { symbol, .. } => {
            if !locals.contains(symbol) {
                if let Some(name) = outer_symbols.get(symbol) {
                    if seen.insert(*symbol) {
                        out.push((*symbol, name.clone()));
                    }
                }
            }
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out);
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_free_lambda_symbols(lhs, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(rhs, locals, outer_symbols, seen, out);
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(then_expr, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(else_expr, locals, outer_symbols, seen, out);
        }
        Expr::Assign { lhs, rhs, .. } => {
            match lhs {
                uniflow_hir::LValue::Var(_) => {}
                uniflow_hir::LValue::Field { base, .. } => {
                    collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
                }
                uniflow_hir::LValue::Index { base, index } => {
                    collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
                    collect_free_lambda_symbols(index, locals, outer_symbols, seen, out);
                }
            }
            collect_free_lambda_symbols(rhs, locals, outer_symbols, seen, out);
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                collect_free_lambda_symbols(part, locals, outer_symbols, seen, out);
            }
        }
        Expr::Range { low, high, .. } => {
            collect_free_lambda_symbols(low, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(high, locals, outer_symbols, seen, out);
        }
        Expr::FieldRead { base, .. } => {
            collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
        }
        Expr::IndexRead { base, index, .. } => {
            collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
            collect_free_lambda_symbols(index, locals, outer_symbols, seen, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_free_lambda_symbols(callee, locals, outer_symbols, seen, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_free_lambda_symbols(receiver, locals, outer_symbols, seen, out);
            }
            for arg in &call.args {
                collect_free_lambda_symbols(arg, locals, outer_symbols, seen, out);
            }
        }
        Expr::Lambda { captures, .. } => {
            for capture in captures {
                if !locals.contains(&capture.source_symbol) {
                    if let Some(name) = outer_symbols.get(&capture.source_symbol) {
                        if seen.insert(capture.source_symbol) {
                            out.push((capture.source_symbol, name.clone()));
                        }
                    }
                }
            }
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_free_lambda_symbols(arg, locals, outer_symbols, seen, out);
            }
        }
        Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {}
    }
}

fn rewrite_lambda_capture_symbols(expr: Expr, capture_map: &HashMap<SymbolId, SymbolId>) -> Expr {
    match expr {
        Expr::VarRef { id, symbol, span } => Expr::VarRef {
            id,
            symbol: capture_map.get(&symbol).copied().unwrap_or(symbol),
            span,
        },
        Expr::Unary { id, op, expr, span } => Expr::Unary {
            id,
            op,
            expr: Box::new(rewrite_lambda_capture_symbols(*expr, capture_map)),
            span,
        },
        Expr::Binary {
            id,
            op,
            lhs,
            rhs,
            span,
        } => Expr::Binary {
            id,
            op,
            lhs: Box::new(rewrite_lambda_capture_symbols(*lhs, capture_map)),
            rhs: Box::new(rewrite_lambda_capture_symbols(*rhs, capture_map)),
            span,
        },
        Expr::Conditional {
            id,
            cond,
            then_expr,
            else_expr,
            span,
        } => Expr::Conditional {
            id,
            cond: Box::new(rewrite_lambda_capture_symbols(*cond, capture_map)),
            then_expr: Box::new(rewrite_lambda_capture_symbols(*then_expr, capture_map)),
            else_expr: Box::new(rewrite_lambda_capture_symbols(*else_expr, capture_map)),
            span,
        },
        Expr::Assign { id, lhs, rhs, span } => Expr::Assign {
            id,
            lhs: rewrite_lambda_capture_lvalue(lhs, capture_map),
            rhs: Box::new(rewrite_lambda_capture_symbols(*rhs, capture_map)),
            span,
        },
        Expr::Interp { id, parts, span } => Expr::Interp {
            id,
            parts: parts
                .into_iter()
                .map(|part| rewrite_lambda_capture_symbols(part, capture_map))
                .collect(),
            span,
        },
        Expr::Collection {
            id,
            container,
            elements,
            span,
        } => Expr::Collection {
            id,
            container,
            elements: elements
                .into_iter()
                .map(|element| rewrite_lambda_capture_symbols(element, capture_map))
                .collect(),
            span,
        },
        Expr::Range {
            id,
            low,
            high,
            exclusive,
            span,
        } => Expr::Range {
            id,
            low: Box::new(rewrite_lambda_capture_symbols(*low, capture_map)),
            high: Box::new(rewrite_lambda_capture_symbols(*high, capture_map)),
            exclusive,
            span,
        },
        Expr::FieldRead {
            id,
            base,
            field,
            span,
        } => Expr::FieldRead {
            id,
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            field,
            span,
        },
        Expr::IndexRead {
            id,
            base,
            index,
            span,
        } => Expr::IndexRead {
            id,
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            index: Box::new(rewrite_lambda_capture_symbols(*index, capture_map)),
            span,
        },
        Expr::Call(mut call) => {
            if let CallTarget::Dynamic(callee) = call.target {
                call.target = CallTarget::Dynamic(Box::new(rewrite_lambda_capture_symbols(
                    *callee,
                    capture_map,
                )));
            }
            if let Some(receiver) = call.receiver.take() {
                call.receiver = Some(Box::new(rewrite_lambda_capture_symbols(
                    *receiver,
                    capture_map,
                )));
            }
            call.args = call
                .args
                .into_iter()
                .map(|arg| rewrite_lambda_capture_symbols(arg, capture_map))
                .collect();
            Expr::Call(call)
        }
        Expr::Lambda {
            id,
            params,
            mut captures,
            body,
            span,
        } => {
            for capture in &mut captures {
                if let Some(mapped) = capture_map.get(&capture.source_symbol).copied() {
                    capture.source_symbol = mapped;
                }
            }
            Expr::Lambda {
                id,
                params,
                captures,
                body,
                span,
            }
        }
        Expr::New {
            id,
            type_name,
            args,
            span,
        } => Expr::New {
            id,
            type_name,
            args: args
                .into_iter()
                .map(|arg| rewrite_lambda_capture_symbols(arg, capture_map))
                .collect(),
            span,
        },
        Expr::Cast { id, ty, expr, span } => Expr::Cast {
            id,
            ty,
            expr: Box::new(rewrite_lambda_capture_symbols(*expr, capture_map)),
            span,
        },
        other @ Expr::Literal { .. }
        | other @ Expr::Opaque { .. }
        | other @ Expr::Unknown { .. } => other,
    }
}

fn rewrite_lambda_capture_lvalue(
    lvalue: uniflow_hir::LValue,
    capture_map: &HashMap<SymbolId, SymbolId>,
) -> uniflow_hir::LValue {
    match lvalue {
        uniflow_hir::LValue::Var(symbol) => {
            uniflow_hir::LValue::Var(capture_map.get(&symbol).copied().unwrap_or(symbol))
        }
        uniflow_hir::LValue::Field { base, field } => uniflow_hir::LValue::Field {
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            field,
        },
        uniflow_hir::LValue::Index { base, index } => uniflow_hir::LValue::Index {
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            index: Box::new(rewrite_lambda_capture_symbols(*index, capture_map)),
        },
    }
}

fn infer_lambda_capture_type(
    builder: &mut ModuleBuilder,
    env: &PyEnv,
    name: &str,
) -> Option<uniflow_hir::TypeId> {
    env.callable_aliases
        .get(name)
        .or_else(|| env.types.get(name))
        .map(|ty| builder.ensure_type(ty))
}

fn collect_expr_lambda_functions(
    builder: &mut ModuleBuilder,
    expr: &Expr,
    enclosing_function: &str,
    out: &mut Vec<uniflow_hir::Function>,
) {
    match expr {
        Expr::Unary { expr, .. } => {
            collect_expr_lambda_functions(builder, expr, enclosing_function, out)
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_expr_lambda_functions(builder, lhs, enclosing_function, out);
            collect_expr_lambda_functions(builder, rhs, enclosing_function, out);
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_expr_lambda_functions(builder, cond, enclosing_function, out);
            collect_expr_lambda_functions(builder, then_expr, enclosing_function, out);
            collect_expr_lambda_functions(builder, else_expr, enclosing_function, out);
        }
        Expr::Assign { lhs, rhs, .. } => {
            match lhs {
                uniflow_hir::LValue::Var(_) => {}
                uniflow_hir::LValue::Field { base, .. } => {
                    collect_expr_lambda_functions(builder, base, enclosing_function, out);
                }
                uniflow_hir::LValue::Index { base, index } => {
                    collect_expr_lambda_functions(builder, base, enclosing_function, out);
                    collect_expr_lambda_functions(builder, index, enclosing_function, out);
                }
            }
            collect_expr_lambda_functions(builder, rhs, enclosing_function, out);
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                collect_expr_lambda_functions(builder, part, enclosing_function, out);
            }
        }
        Expr::Range { low, high, .. } => {
            collect_expr_lambda_functions(builder, low, enclosing_function, out);
            collect_expr_lambda_functions(builder, high, enclosing_function, out);
        }
        Expr::FieldRead { base, .. } => {
            collect_expr_lambda_functions(builder, base, enclosing_function, out)
        }
        Expr::IndexRead { base, index, .. } => {
            collect_expr_lambda_functions(builder, base, enclosing_function, out);
            collect_expr_lambda_functions(builder, index, enclosing_function, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_expr_lambda_functions(builder, callee, enclosing_function, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_expr_lambda_functions(builder, receiver, enclosing_function, out);
            }
            for arg in &call.args {
                collect_expr_lambda_functions(builder, arg, enclosing_function, out);
            }
        }
        Expr::Lambda {
            id,
            params,
            captures,
            body,
            span,
        } => {
            out.push(uniflow_hir::Function {
                id: builder.alloc_function_id(),
                name: lambda_function_name(enclosing_function, *id, span.start_line.max(1)),
                symbol: Some(builder.add_symbol("<lambda>", SymbolKind::Function)),
                params: params.clone(),
                captures: captures
                    .iter()
                    .map(|capture| uniflow_hir::Param {
                        name: capture.name.clone(),
                        symbol: capture.symbol,
                        ty: capture.ty,
                        kind: ParamKind::Positional,
                        has_default: false,
                        keyword_only: false,
                        cpp: Default::default(),
                        span: capture.span,
                    })
                    .collect(),
                return_type: None,
                body: body.clone(),
                is_method: false,
                receiver: None,
                cpp: None,
                cpp_initializers: Vec::new(),
                span: *span,
            });
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_expr_lambda_functions(builder, arg, enclosing_function, out);
            }
        }
        Expr::Cast { expr, .. } => {
            collect_expr_lambda_functions(builder, expr, enclosing_function, out)
        }
        Expr::VarRef { .. } | Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {
        }
    }
}

fn collect_stmt_lambda_functions(
    builder: &mut ModuleBuilder,
    stmt: &Stmt,
    enclosing_function: &str,
    out: &mut Vec<uniflow_hir::Function>,
) {
    match stmt {
        Stmt::Let { init, .. } => {
            if let Some(expr) = init {
                collect_expr_lambda_functions(builder, expr, enclosing_function, out);
            }
        }
        Stmt::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Field { base, .. } => {
                    collect_expr_lambda_functions(builder, base, enclosing_function, out)
                }
                LValue::Index { base, index } => {
                    collect_expr_lambda_functions(builder, base, enclosing_function, out);
                    collect_expr_lambda_functions(builder, index, enclosing_function, out);
                }
                LValue::Var(_) => {}
            }
            collect_expr_lambda_functions(builder, rhs, enclosing_function, out);
        }
        Stmt::Expr { expr, .. } => {
            collect_expr_lambda_functions(builder, expr, enclosing_function, out)
        }
        Stmt::DoWhile { body, cond, .. } => {
            collect_expr_lambda_functions(builder, cond, enclosing_function, out);
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Stmt::Switch {
            scrutinee,
            clauses,
            default,
            ..
        } => {
            collect_expr_lambda_functions(builder, scrutinee, enclosing_function, out);
            for clause in clauses {
                for value in &clause.values {
                    collect_expr_lambda_functions(builder, value, enclosing_function, out);
                }
                collect_block_lambda_functions(builder, &clause.body, enclosing_function, out);
            }
            if let Some(block) = default {
                collect_block_lambda_functions(builder, block, enclosing_function, out);
            }
        }
        Stmt::Break { .. } | Stmt::Continue { .. } => {}
        Stmt::If {
            cond,
            then_block,
            else_block,
            ..
        } => {
            collect_expr_lambda_functions(builder, cond, enclosing_function, out);
            collect_block_lambda_functions(builder, then_block, enclosing_function, out);
            if let Some(block) = else_block {
                collect_block_lambda_functions(builder, block, enclosing_function, out);
            }
        }
        Stmt::While { cond, body, .. } => {
            collect_expr_lambda_functions(builder, cond, enclosing_function, out);
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Stmt::ForEach { iterable, body, .. } => {
            collect_expr_lambda_functions(builder, iterable, enclosing_function, out);
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Stmt::For { init, cond, update, body, .. } => {
            collect_block_lambda_functions(builder, init, enclosing_function, out);
            if let Some(cond) = cond { collect_expr_lambda_functions(builder, cond, enclosing_function, out); }
            collect_block_lambda_functions(builder, update, enclosing_function, out);
            collect_block_lambda_functions(builder, body, enclosing_function, out);
        }
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
            if let Some(expr) = value {
                collect_expr_lambda_functions(builder, expr, enclosing_function, out);
            }
        }
        Stmt::Try {
            try_block,
            catches,
            finally_block,
            ..
        } => {
            collect_block_lambda_functions(builder, try_block, enclosing_function, out);
            for catch in catches {
                collect_block_lambda_functions(builder, &catch.body, enclosing_function, out);
            }
            if let Some(block) = finally_block {
                collect_block_lambda_functions(builder, block, enclosing_function, out);
            }
        }
    }
}

fn collect_block_lambda_functions(
    builder: &mut ModuleBuilder,
    block: &Block,
    enclosing_function: &str,
    out: &mut Vec<uniflow_hir::Function>,
) {
    for stmt in &block.stmts {
        collect_stmt_lambda_functions(builder, stmt, enclosing_function, out);
    }
}

fn collect_stmt_local_symbols(stmt: &Stmt, locals: &mut HashSet<SymbolId>) {
    match stmt {
        Stmt::For { init, update, body, .. } => {
            collect_block_local_symbols(init, locals);
            collect_block_local_symbols(update, locals);
            collect_block_local_symbols(body, locals);
        }
        Stmt::Let { symbol, .. } => {
            locals.insert(*symbol);
        }
        Stmt::ForEach {
            item_symbol, body, ..
        } => {
            locals.insert(*item_symbol);
            collect_block_local_symbols(body, locals);
        }
        Stmt::DoWhile { body, .. } => collect_block_local_symbols(body, locals),
        Stmt::Switch {
            clauses, default, ..
        } => {
            for clause in clauses {
                collect_block_local_symbols(&clause.body, locals);
            }
            if let Some(block) = default {
                collect_block_local_symbols(block, locals);
            }
        }
        Stmt::Break { .. } | Stmt::Continue { .. } => {}
        Stmt::If {
            then_block,
            else_block,
            ..
        } => {
            collect_block_local_symbols(then_block, locals);
            if let Some(block) = else_block {
                collect_block_local_symbols(block, locals);
            }
        }
        Stmt::While { body, .. } => collect_block_local_symbols(body, locals),
        Stmt::Try {
            try_block,
            catches,
            finally_block,
            ..
        } => {
            collect_block_local_symbols(try_block, locals);
            for catch in catches {
                if let Some(symbol) = catch.symbol {
                    locals.insert(symbol);
                }
                collect_block_local_symbols(&catch.body, locals);
            }
            if let Some(block) = finally_block {
                collect_block_local_symbols(block, locals);
            }
        }
        Stmt::Assign { .. } | Stmt::Expr { .. } | Stmt::Return { .. } | Stmt::Throw { .. } => {}
    }
}

fn collect_block_local_symbols(block: &Block, locals: &mut HashSet<SymbolId>) {
    for stmt in &block.stmts {
        collect_stmt_local_symbols(stmt, locals);
    }
}

fn collect_stmt_free_symbols(
    stmt: &Stmt,
    locals: &HashSet<SymbolId>,
    outer_symbols: &HashMap<SymbolId, String>,
    seen: &mut HashSet<SymbolId>,
    out: &mut Vec<(SymbolId, String)>,
) {
    match stmt {
        Stmt::Let { init, .. } => {
            if let Some(expr) = init {
                collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out);
            }
        }
        Stmt::Assign { lhs, rhs, .. } => {
            match lhs {
                LValue::Field { base, .. } => {
                    collect_free_lambda_symbols(base, locals, outer_symbols, seen, out)
                }
                LValue::Index { base, index } => {
                    collect_free_lambda_symbols(base, locals, outer_symbols, seen, out);
                    collect_free_lambda_symbols(index, locals, outer_symbols, seen, out);
                }
                LValue::Var(_) => {}
            }
            collect_free_lambda_symbols(rhs, locals, outer_symbols, seen, out);
        }
        Stmt::Expr { expr, .. } => {
            collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out)
        }
        Stmt::DoWhile { cond, body, .. } => {
            collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out);
            collect_block_free_symbols(body, locals, outer_symbols, seen, out);
        }
        Stmt::Switch {
            scrutinee,
            clauses,
            default,
            ..
        } => {
            collect_free_lambda_symbols(scrutinee, locals, outer_symbols, seen, out);
            for clause in clauses {
                for value in &clause.values {
                    collect_free_lambda_symbols(value, locals, outer_symbols, seen, out);
                }
                collect_block_free_symbols(&clause.body, locals, outer_symbols, seen, out);
            }
            if let Some(block) = default {
                collect_block_free_symbols(block, locals, outer_symbols, seen, out);
            }
        }
        Stmt::Break { .. } | Stmt::Continue { .. } => {}
        Stmt::If {
            cond,
            then_block,
            else_block,
            ..
        } => {
            collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out);
            collect_block_free_symbols(then_block, locals, outer_symbols, seen, out);
            if let Some(block) = else_block {
                collect_block_free_symbols(block, locals, outer_symbols, seen, out);
            }
        }
        Stmt::While { cond, body, .. } => {
            collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out);
            collect_block_free_symbols(body, locals, outer_symbols, seen, out);
        }
        Stmt::ForEach { iterable, body, .. } => {
            collect_free_lambda_symbols(iterable, locals, outer_symbols, seen, out);
            collect_block_free_symbols(body, locals, outer_symbols, seen, out);
        }
        Stmt::For { init, cond, update, body, .. } => {
            collect_block_free_symbols(init, locals, outer_symbols, seen, out);
            if let Some(cond) = cond { collect_free_lambda_symbols(cond, locals, outer_symbols, seen, out); }
            collect_block_free_symbols(update, locals, outer_symbols, seen, out);
            collect_block_free_symbols(body, locals, outer_symbols, seen, out);
        }
        Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
            if let Some(expr) = value {
                collect_free_lambda_symbols(expr, locals, outer_symbols, seen, out);
            }
        }
        Stmt::Try {
            try_block,
            catches,
            finally_block,
            ..
        } => {
            collect_block_free_symbols(try_block, locals, outer_symbols, seen, out);
            for catch in catches {
                collect_block_free_symbols(&catch.body, locals, outer_symbols, seen, out);
            }
            if let Some(block) = finally_block {
                collect_block_free_symbols(block, locals, outer_symbols, seen, out);
            }
        }
    }
}

fn collect_block_free_symbols(
    block: &Block,
    locals: &HashSet<SymbolId>,
    outer_symbols: &HashMap<SymbolId, String>,
    seen: &mut HashSet<SymbolId>,
    out: &mut Vec<(SymbolId, String)>,
) {
    for stmt in &block.stmts {
        collect_stmt_free_symbols(stmt, locals, outer_symbols, seen, out);
    }
}

fn rewrite_lvalue_capture_symbols(
    lhs: LValue,
    capture_map: &HashMap<SymbolId, SymbolId>,
) -> LValue {
    match lhs {
        LValue::Var(symbol) => LValue::Var(capture_map.get(&symbol).copied().unwrap_or(symbol)),
        LValue::Field { base, field } => LValue::Field {
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            field,
        },
        LValue::Index { base, index } => LValue::Index {
            base: Box::new(rewrite_lambda_capture_symbols(*base, capture_map)),
            index: Box::new(rewrite_lambda_capture_symbols(*index, capture_map)),
        },
    }
}

fn rewrite_stmt_capture_symbols(stmt: Stmt, capture_map: &HashMap<SymbolId, SymbolId>) -> Stmt {
    match stmt {
        Stmt::Break { id, label, span } => Stmt::Break { id, label, span },
        Stmt::Continue { id, label, span } => Stmt::Continue { id, label, span },
        Stmt::DoWhile {
            id,
            body,
            cond,
            span,
        } => Stmt::DoWhile {
            id,
            body: rewrite_block_capture_symbols(body, capture_map),
            cond: rewrite_lambda_capture_symbols(cond, capture_map),
            span,
        },
        Stmt::Switch {
            id,
            scrutinee,
            clauses,
            default,
            span,
        } => Stmt::Switch {
            id,
            scrutinee: rewrite_lambda_capture_symbols(scrutinee, capture_map),
            clauses: clauses
                .into_iter()
                .map(|clause| uniflow_hir::SwitchClause {
                    values: clause
                        .values
                        .into_iter()
                        .map(|value| rewrite_lambda_capture_symbols(value, capture_map))
                        .collect(),
                    body: rewrite_block_capture_symbols(clause.body, capture_map),
                    fallthrough: clause.fallthrough,
                    span: clause.span,
                })
                .collect(),
            default: default.map(|block| rewrite_block_capture_symbols(block, capture_map)),
            span,
        },
        Stmt::Let {
            id,
            symbol,
            ty,
            init,
            span,
        } => Stmt::Let {
            id,
            symbol,
            ty,
            init: init.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            span,
        },
        Stmt::Assign { id, lhs, rhs, span } => Stmt::Assign {
            id,
            lhs: rewrite_lvalue_capture_symbols(lhs, capture_map),
            rhs: rewrite_lambda_capture_symbols(rhs, capture_map),
            span,
        },
        Stmt::Expr { id, expr, span } => Stmt::Expr {
            id,
            expr: rewrite_lambda_capture_symbols(expr, capture_map),
            span,
        },
        Stmt::If {
            id,
            cond,
            then_block,
            else_block,
            span,
        } => Stmt::If {
            id,
            cond: rewrite_lambda_capture_symbols(cond, capture_map),
            then_block: rewrite_block_capture_symbols(then_block, capture_map),
            else_block: else_block.map(|block| rewrite_block_capture_symbols(block, capture_map)),
            span,
        },
        Stmt::While {
            id,
            cond,
            body,
            span,
        } => Stmt::While {
            id,
            cond: rewrite_lambda_capture_symbols(cond, capture_map),
            body: rewrite_block_capture_symbols(body, capture_map),
            span,
        },
        Stmt::For { id, init_is_scoped, init, cond, update, body, span } => Stmt::For {
            id,
            init_is_scoped,
            init: rewrite_block_capture_symbols(init, capture_map),
            cond: cond.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            update: rewrite_block_capture_symbols(update, capture_map),
            body: rewrite_block_capture_symbols(body, capture_map),
            span,
        },
        Stmt::ForEach {
            id,
            item_symbol,
            iterable,
            body,
            span,
        } => Stmt::ForEach {
            id,
            item_symbol,
            iterable: rewrite_lambda_capture_symbols(iterable, capture_map),
            body: rewrite_block_capture_symbols(body, capture_map),
            span,
        },
        Stmt::Return { id, value, span } => Stmt::Return {
            id,
            value: value.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            span,
        },
        Stmt::Throw { id, value, span } => Stmt::Throw {
            id,
            value: value.map(|expr| rewrite_lambda_capture_symbols(expr, capture_map)),
            span,
        },
        Stmt::Try {
            id,
            try_block,
            catches,
            finally_block,
            span,
        } => Stmt::Try {
            id,
            try_block: rewrite_block_capture_symbols(try_block, capture_map),
            catches: catches
                .into_iter()
                .map(|catch| CatchClause {
                    symbol: catch.symbol,
                    ty: catch.ty,
                    body: rewrite_block_capture_symbols(catch.body, capture_map),
                    span: catch.span,
                })
                .collect(),
            finally_block: finally_block
                .map(|block| rewrite_block_capture_symbols(block, capture_map)),
            span,
        },
    }
}

fn rewrite_block_capture_symbols(block: Block, capture_map: &HashMap<SymbolId, SymbolId>) -> Block {
    Block {
        id: block.id,
        stmts: block
            .stmts
            .into_iter()
            .map(|stmt| rewrite_stmt_capture_symbols(stmt, capture_map))
            .collect(),
        span: block.span,
    }
}

fn finalize_nested_function_captures(
    builder: &mut ModuleBuilder,
    function: &mut uniflow_hir::Function,
    outer_env: &PyEnv,
) {
    let mut locals = HashSet::new();
    if let Some(receiver) = &function.receiver {
        locals.insert(receiver.symbol);
    }
    for param in &function.params {
        locals.insert(param.symbol);
    }
    collect_block_local_symbols(&function.body, &mut locals);
    let outer_symbols = outer_env
        .vars
        .iter()
        .map(|(name, symbol)| (*symbol, name.clone()))
        .collect::<HashMap<_, _>>();
    let mut captures = Vec::new();
    let mut seen = HashSet::new();
    collect_block_free_symbols(
        &function.body,
        &locals,
        &outer_symbols,
        &mut seen,
        &mut captures,
    );
    if captures.is_empty() {
        return;
    }
    let mut capture_map = HashMap::new();
    let mut capture_params = Vec::new();
    for (source_symbol, name) in captures {
        let symbol = builder.add_symbol(&lambda_capture_field_name(&name), SymbolKind::Local);
        capture_map.insert(source_symbol, symbol);
        capture_params.push(uniflow_hir::Param {
            name,
            symbol,
            ty: infer_lambda_capture_type(builder, outer_env, &outer_symbols[&source_symbol]),
            kind: ParamKind::Positional,
            has_default: false,
            keyword_only: false,
            cpp: Default::default(),
            span: function.span,
        });
    }
    function.body = rewrite_block_capture_symbols(function.body.clone(), &capture_map);
    function.captures = capture_params;
}

fn parse_nested_function_definition(
    builder: &mut ModuleBuilder,
    lines: &[PyBodyLine],
    idx: &mut usize,
    current_indent: usize,
    imports: &PyImports,
    known_classes: &HashSet<String>,
    env: &mut PyEnv,
) {
    let line = &lines[*idx];
    let Some((name, params)) = parse_python_function_header(&line.text) else {
        *idx += 1;
        return;
    };
    let start = *idx;
    let mut end = start + 1;
    while end < lines.len() {
        let trimmed = lines[end].text.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && lines[end].indent <= current_indent {
            break;
        }
        end += 1;
    }
    let body = lines[start + 1..end]
        .iter()
        .map(|entry| entry.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    let nested = PyFunctionText {
        name: name.clone(),
        params,
        return_annotation: parse_python_function_return_annotation(&line.text),
        body,
        start_line: line.line_no,
        end_line: lines[end.saturating_sub(1)].line_no.max(line.line_no),
        decorators: Vec::new(),
    };
    let qualified_name = format!("{}.{}", env.current_function, name);
    let current_module = env.current_module.clone();
    let project_index = env.project_index.clone();
    let parsed = parse_function(
        builder,
        &nested,
        imports,
        known_classes,
        None,
        &[],
        &HashMap::new(),
        &HashMap::new(),
        &current_module,
        Some(&project_index),
        Some(&qualified_name),
        Some(env),
    );
    env.callable_aliases
        .insert(name.clone(), qualified_name.clone());
    env.types.insert(name.clone(), qualified_name.clone());
    env.synthetic_functions.push(parsed.function);
    env.synthetic_functions.extend(parsed.synthetic_functions);
    *idx = end;
}
