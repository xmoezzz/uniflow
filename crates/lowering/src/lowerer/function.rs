#[derive(Clone)]
struct FinallyFrame {
    body: Block,
    break_depth: usize,
    continue_depth: usize,
}

#[derive(Clone, Copy)]
enum AbruptTransfer { Return, Break, Continue }

fn expression_literal_fragments(
    expr: &Expr,
    symbol_names: &HashMap<SymbolId, String>,
    out: &mut String,
) {
    match expr {
        Expr::Literal {
            kind: LiteralKind::String(value),
            ..
        } => {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(value);
        }
        Expr::Literal {
            kind: LiteralKind::Bool(value),
            ..
        } => {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(if *value { "true" } else { "false" });
        }
        Expr::Literal {
            kind: LiteralKind::Int(value),
            ..
        } => {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&value.to_string());
        }
        Expr::VarRef { .. } => {}
        Expr::FieldRead { base, field, .. } => {
            if let Some(path) = expression_symbol_path(base, symbol_names) {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&path);
                out.push('.');
                out.push_str(field);
            }
        }
        Expr::Binary { lhs, rhs, .. } => {
            expression_literal_fragments(lhs, symbol_names, out);
            expression_literal_fragments(rhs, symbol_names, out);
        }
        Expr::Interp { parts, .. } => {
            for part in parts {
                expression_literal_fragments(part, symbol_names, out);
            }
        }
        Expr::Collection { container, elements, .. } => {
            if matches!(container, uniflow_hir::CollectionKind::Map) {
                for pair in elements.chunks_exact(2) {
                    let key = match &pair[0] {
                        Expr::Literal { kind: LiteralKind::String(value), .. } => Some(value.as_str()),
                        Expr::VarRef { symbol, .. } => symbol_names.get(symbol).map(String::as_str),
                        _ => None,
                    };
                    if let Some(key) = key {
                        if !out.is_empty() {
                            out.push(' ');
                        }
                        out.push_str(key);
                    }
                    expression_literal_fragments(&pair[1], symbol_names, out);
                }
            } else {
                for part in elements {
                    expression_literal_fragments(part, symbol_names, out);
                }
            }
        }
        _ => {}
    }
}

fn expression_symbol_path(
    expr: &Expr,
    symbol_names: &HashMap<SymbolId, String>,
) -> Option<String> {
    match expr {
        Expr::VarRef { symbol, .. } => symbol_names.get(symbol).cloned(),
        Expr::FieldRead { base, field, .. } => {
            expression_symbol_path(base, symbol_names).map(|base| format!("{base}.{field}"))
        }
        _ => None,
    }
}

fn expression_contains_dynamic_data(expr: &Expr) -> bool {
    match expr {
        Expr::Literal { .. } => false,
        Expr::VarRef { .. } => true,
        Expr::Binary { lhs, rhs, .. } => {
            expression_contains_dynamic_data(lhs) || expression_contains_dynamic_data(rhs)
        }
        Expr::Interp { parts, .. } => parts.iter().any(expression_contains_dynamic_data),
        Expr::Collection {
            container,
            elements,
            ..
        } => {
            if matches!(container, uniflow_hir::CollectionKind::Map) {
                elements
                    .chunks_exact(2)
                    .any(|pair| expression_contains_dynamic_data(&pair[1]))
            } else {
                elements.iter().any(expression_contains_dynamic_data)
            }
        }
        _ => true,
    }
}

fn mark_dynamic_composition(expr: &Expr, descriptor: &mut String) {
    if expression_contains_dynamic_data(expr) {
        if !descriptor.is_empty() {
            descriptor.push(' ');
        }
        descriptor.push_str("__uniflow.dynamic__");
    }
}

fn map_value_index(
    elements: &[Expr],
    key: &str,
    symbol_names: &HashMap<SymbolId, String>,
) -> Option<usize> {
    elements.chunks_exact(2).enumerate().find_map(|(pair, elements)| {
        let matches = match &elements[0] {
            Expr::Literal {
                kind: LiteralKind::String(value),
                ..
            } => value == key,
            Expr::VarRef { symbol, .. } => {
                symbol_names.get(symbol).is_some_and(|name| name == key)
            }
            _ => false,
        };
        matches.then_some(pair * 2 + 1)
    })
}

struct FunctionLoweringContext<'a> {
    owner: &'a mut Lowerer,
    current_function_name: String,
    exception_edges: Vec<ExceptionEdge>,
    value_array_extents: IndexMap<ValueId, Vec<Option<ValueId>>>,
    /// Source CFG metadata retained for path-sensitive source checkers whose
    /// semantics depend on Clang-style case labels / control terminators.
    source_case_blocks: Vec<(BlockId, uniflow_hir::Span, bool)>,
    source_break_blocks: HashSet<BlockId>,
    source_return_blocks: HashSet<BlockId>,
    source_switch_blocks: HashSet<BlockId>,
    /// Block each enclosing `switch` (or loop) jumps to on `break`, innermost last.
    break_stack: Vec<BlockId>,
    /// Block each enclosing loop jumps to on `continue`, innermost last.
    continue_stack: Vec<BlockId>,
    /// Environments carried by explicit edges to loop update/exit blocks.
    edge_environments: HashMap<BlockId, Vec<HashMap<SymbolId, ValueId>>>,
    watched_edge_targets: HashSet<BlockId>,
    finally_stack: Vec<FinallyFrame>,
}

impl<'a> FunctionLoweringContext<'a> {
    #[allow(clippy::too_many_arguments)]
    fn lower_java_assignment(
        &mut self, lhs: &LValue, rhs: &Expr, span: uniflow_hir::Span,
        insts: &mut Vec<Instruction>, value_map: &mut HashMap<SymbolId, ValueId>,
        symbol_types: &mut HashMap<SymbolId, String>, locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (ValueId, Option<String>) {
        // Java evaluates the left-hand receiver and index before the RHS.
        // This order is language-specific; Python assignment remains RHS-first.
        enum Location { Var(SymbolId), Field(ValueId, String), Index(ValueId, ValueId) }
        let location = match lhs {
            LValue::Var(symbol) => Location::Var(*symbol),
            LValue::Field { base, field } => {
                let (base, _) = self.lower_expr(base, insts, value_map, symbol_types,
                    locals, value_types, value_spans);
                Location::Field(base, field.clone())
            }
            LValue::Index { base, index } => {
                let (base, _) = self.lower_expr(base, insts, value_map, symbol_types,
                    locals, value_types, value_spans);
                let (index, _) = self.lower_expr(index, insts, value_map, symbol_types,
                    locals, value_types, value_spans);
                Location::Index(base, index)
            }
        };
        let (src, inferred) = self.lower_expr(rhs, insts, value_map, symbol_types,
            locals, value_types, value_spans);
        match location {
            Location::Var(symbol) => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_map.insert(symbol, dst);
                value_spans.insert(dst, span);
                self.push_inst(insts, InstKind::Copy { dst, src }, span);
                if let Some(ty) = symbol_types.get(&symbol).cloned().or_else(|| inferred.clone()) {
                    symbol_types.insert(symbol, ty.clone());
                    value_types.insert(dst, ty);
                }
                (dst, inferred)
            }
            Location::Field(base, field) => {
                self.push_inst(insts, InstKind::StoreField { base, field, src }, span);
                (src, inferred)
            }
            Location::Index(base, index) => {
                self.push_inst(insts, InstKind::StoreIndex { base, index, src }, span);
                (src, inferred)
            }
        }
    }

    fn new(owner: &'a mut Lowerer, current_function_name: String) -> Self {
        Self {
            owner,
            current_function_name,
            exception_edges: Vec::new(),
            value_array_extents: IndexMap::new(),
            source_case_blocks: Vec::new(),
            source_break_blocks: HashSet::new(),
            source_return_blocks: HashSet::new(),
            source_switch_blocks: HashSet::new(),
            break_stack: Vec::new(),
            continue_stack: Vec::new(),
            edge_environments: HashMap::new(),
            watched_edge_targets: HashSet::new(),
            finally_stack: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_cpp_initializers(
        &mut self,
        function: &HirFunction,
        value_map: &HashMap<SymbolId, ValueId>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> Vec<Instruction> {
        let Some(receiver) = function
            .receiver
            .as_ref()
            .and_then(|receiver| value_map.get(&receiver.symbol).copied())
        else {
            return Vec::new();
        };
        let mut insts = Vec::new();
        if function
            .cpp
            .as_ref()
            .and_then(|cpp| cpp.special_member)
            .is_some_and(|kind| {
                matches!(
                    kind,
                    uniflow_hir::CppSpecialMemberKind::Constructor
                        | uniflow_hir::CppSpecialMemberKind::CopyConstructor
                        | uniflow_hir::CppSpecialMemberKind::MoveConstructor
                )
            })
        {
            self.push_inst(
                &mut insts,
                InstKind::Lifetime {
                    value: receiver,
                    event: uniflow_ir::LifetimeEvent::Construct,
                },
                function.span,
            );
        }

        for initializer in &function.cpp_initializers {
            let args = initializer
                .arguments
                .iter()
                .map(|argument| {
                    self.lower_cpp_initializer_argument(
                        argument,
                        value_map,
                        &mut insts,
                        locals,
                        value_types,
                        value_spans,
                        function.span,
                    )
                })
                .collect::<Vec<_>>();
            match initializer.kind {
                CppConstructorInitializerKind::Base | CppConstructorInitializerKind::Delegating => {
                    self.push_inst(
                        &mut insts,
                        InstKind::Call(CallInst {
                            dst: None,
                            callee: Callee::Static(format!(
                                "{}::{}",
                                initializer.target,
                                initializer
                                    .target
                                    .rsplit("::")
                                    .next()
                                    .unwrap_or(&initializer.target)
                            )),
                            receiver: Some(receiver),
                            args,
                            arg_names: Vec::new(),
                            arg_spans: Vec::new(),
                            arg_origins: Vec::new(),
                        }),
                        function.span,
                    );
                }
                CppConstructorInitializerKind::Field => {
                    if args.len() == 1 {
                        self.push_inst(
                            &mut insts,
                            InstKind::StoreField {
                                base: receiver,
                                field: initializer.target.clone(),
                                src: args[0],
                            },
                            function.span,
                        );
                    } else {
                        let dst = self.alloc_value();
                        locals.push(dst);
                        value_spans.insert(dst, function.span);
                        self.push_inst(
                            &mut insts,
                            InstKind::Call(CallInst {
                                dst: Some(dst),
                                callee: Callee::Static(format!(
                                    "__uniflow_cpp_member_construct::{}",
                                    initializer.target
                                )),
                                receiver: Some(receiver),
                                args,
                                arg_names: Vec::new(),
                                arg_spans: Vec::new(),
                                arg_origins: Vec::new(),
                            }),
                            function.span,
                        );
                        self.push_inst(
                            &mut insts,
                            InstKind::StoreField {
                                base: receiver,
                                field: initializer.target.clone(),
                                src: dst,
                            },
                            function.span,
                        );
                        self.push_inst(
                            &mut insts,
                            InstKind::Lifetime {
                                value: dst,
                                event: uniflow_ir::LifetimeEvent::Construct,
                            },
                            function.span,
                        );
                    }
                }
            }
        }
        insts
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_cpp_initializer_argument(
        &mut self,
        argument: &str,
        value_map: &HashMap<SymbolId, ValueId>,
        insts: &mut Vec<Instruction>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
        span: uniflow_hir::Span,
    ) -> ValueId {
        let trimmed = argument.trim();
        let moved = trimmed
            .strip_prefix("std::move(")
            .or_else(|| trimmed.strip_prefix("move("))
            .and_then(|inner| inner.strip_suffix(')'));
        let lookup = moved.unwrap_or(trimmed).trim();
        if let Some((_, value)) = value_map.iter().find(|(symbol, _)| {
            self.owner
                .hir_symbol_names
                .get(symbol)
                .is_some_and(|name| name == lookup || name.rsplit("::").next() == Some(lookup))
        }) {
            if moved.is_some() {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, span);
                self.push_inst(insts, InstKind::Move { dst, src: *value }, span);
                self.push_inst(
                    insts,
                    InstKind::Lifetime {
                        value: *value,
                        event: uniflow_ir::LifetimeEvent::MoveFrom,
                    },
                    span,
                );
                return dst;
            }
            return *value;
        }
        let dst = self.alloc_value();
        locals.push(dst);
        value_spans.insert(dst, span);
        if let Ok(value) = trimmed.parse::<i64>() {
            self.push_inst(insts, InstKind::ConstInt { dst, value }, span);
            value_types.insert(dst, "int".to_string());
        } else {
            self.push_inst(
                insts,
                InstKind::ConstString {
                    dst,
                    value: format!("<cpp-initializer:{trimmed}>"),
                },
                span,
            );
        }
        dst
    }

    fn alloc_block_id(&mut self) -> BlockId {
        let id = BlockId(self.owner.next_block_id);
        self.owner.next_block_id += 1;
        id
    }

    fn alloc_inst_id(&mut self) -> InstId {
        let id = InstId(self.owner.next_inst_id);
        self.owner.next_inst_id += 1;
        id
    }

    fn alloc_value(&mut self) -> ValueId {
        let id = ValueId(self.owner.next_value_id);
        self.owner.next_value_id += 1;
        id
    }

    fn push_inst(&mut self, insts: &mut Vec<Instruction>, kind: InstKind, span: uniflow_hir::Span) {
        insts.push(Instruction {
            id: self.alloc_inst_id(),
            kind,
            span,
        });
    }

    fn lower_expr_drop(
        &mut self,
        expr: &Expr,
        insts: &mut Vec<Instruction>,
        value_map: &mut HashMap<SymbolId, ValueId>,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) {
        let _ = self.lower_expr(
            expr,
            insts,
            value_map,
            symbol_types,
            locals,
            value_types,
            value_spans,
        );
    }

    fn emit_expression_composition(
        &mut self,
        insts: &mut Vec<Instruction>,
        locals: &mut Vec<ValueId>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
        callee: &str,
        value: ValueId,
        descriptor: String,
        span: uniflow_hir::Span,
    ) -> ValueId {
        if !matches!(self.owner.language, Language::JavaScript | Language::Ruby)
            || descriptor.trim().is_empty()
        {
            return value;
        }
        let descriptor_value = self.alloc_value();
        locals.push(descriptor_value);
        value_spans.insert(descriptor_value, span);
        self.push_inst(
            insts,
            InstKind::ConstString {
                dst: descriptor_value,
                value: descriptor,
            },
            span,
        );
        let composed_value = self.alloc_value();
        locals.push(composed_value);
        value_spans.insert(composed_value, span);
        self.push_inst(
            insts,
            InstKind::Call(CallInst {
                dst: Some(composed_value),
                callee: Callee::Static(callee.to_string()),
                receiver: None,
                args: vec![value, descriptor_value],
                arg_names: vec![None, None],
                arg_spans: Vec::new(),
                arg_origins: Vec::new(),
            }),
            span,
        );
        composed_value
    }

    fn lower_expr(
        &mut self,
        expr: &Expr,
        insts: &mut Vec<Instruction>,
        value_map: &mut HashMap<SymbolId, ValueId>,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (ValueId, Option<String>) {
        match expr {
            Expr::VarRef { symbol, span, .. } => {
                let value = value_map.get(symbol).copied().unwrap_or_else(|| {
                    // Imported modules, unresolved globals, and other externally provided symbols
                    // can legitimately appear as HIR variable references without a local HIR
                    // declaration. Materialize a conservative external-symbol definition so the IR
                    // remains well formed while preserving the value as an opaque analysis root.
                    let fresh = self.alloc_value();
                    locals.push(fresh);
                    value_map.insert(*symbol, fresh);
                    value_spans.insert(fresh, *span);
                    self.push_inst(
                        insts,
                        InstKind::ConstString {
                            dst: fresh,
                            value: {
                                let name = self.owner
                                    .hir_symbol_names
                                    .get(symbol)
                                    .map(String::as_str)
                                    .unwrap_or("unknown");
                                let qualified = self.owner
                                    .current_import_aliases
                                    .get(name)
                                    .map(String::as_str)
                                    .unwrap_or(name);
                                format!("<external-symbol:{qualified}>")
                            },
                        },
                        *span,
                    );
                    fresh
                });
                if self.owner.language == Language::Jsp {
                    if let Some(ty) = self
                        .owner
                        .hir_symbol_names
                        .get(symbol)
                        .and_then(|name| jsp_implicit_object_type(name))
                    {
                        symbol_types.entry(*symbol).or_insert_with(|| ty.to_string());
                        value_types.entry(value).or_insert_with(|| ty.to_string());
                    }
                }
                (value, symbol_types.get(symbol).cloned())
            }
            Expr::Literal { kind, span, .. } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                let ty = match kind {
                    LiteralKind::Int(value) => {
                        self.push_inst(insts, InstKind::ConstInt { dst, value: *value }, *span);
                        Some("int".to_string())
                    }
                    LiteralKind::String(value) => {
                        self.push_inst(
                            insts,
                            InstKind::ConstString {
                                dst,
                                value: value.clone(),
                            },
                            *span,
                        );
                        Some("String".to_string())
                    }
                    LiteralKind::Bool(value) => {
                        self.push_inst(
                            insts,
                            InstKind::ConstInt {
                                dst,
                                value: i64::from(*value),
                            },
                            *span,
                        );
                        Some("bool".to_string())
                    }
                    LiteralKind::Null => {
                        self.push_inst(
                            insts,
                            InstKind::ConstString {
                                dst,
                                value: "<null>".to_string(),
                            },
                            *span,
                        );
                        None
                    }
                    LiteralKind::Float(_) | LiteralKind::Bytes(_) => {
                        self.push_inst(
                            insts,
                            InstKind::ConstString {
                                dst,
                                value: "<literal>".to_string(),
                            },
                            *span,
                        );
                        None
                    }
                };
                if let Some(name) = ty.clone() {
                    value_types.insert(dst, name);
                }
                (dst, ty)
            }
            Expr::FieldRead {
                base, field, span, ..
            } => {
                let (base_value, _) = self.lower_expr(
                    base,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::LoadField {
                        dst,
                        base: base_value,
                        field: field.clone(),
                    },
                    *span,
                );
                (dst, None)
            }
            Expr::IndexRead {
                base, index, span, ..
            } => {
                let (base_value, _) = self.lower_expr(
                    base,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let (index_value, _) = self.lower_expr(
                    index,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::LoadIndex {
                        dst,
                        base: base_value,
                        index: index_value,
                    },
                    *span,
                );
                (dst, None)
            }
            Expr::Call(call) => {
                let arg_spans = call.args.iter().map(Expr::span).collect::<Vec<_>>();
                let arg_origins = arg_spans
                    .iter()
                    .map(|span| {
                        let mut origins = Vec::new();
                        if span_has_source_origin(
                            &self.owner.source_origins,
                            *span,
                            SourceOriginKind::MacroExpansion,
                        ) {
                            origins.push(SourceOriginKind::MacroExpansion);
                        }
                        origins
                    })
                    .collect::<Vec<_>>();
                let cpp_lambda_bind_target = match (&call.target, call.args.first()) {
                    (CallTarget::Named(name), Some(Expr::VarRef { symbol, .. }))
                        if name == "__uniflow_cpp_lambda_bind" =>
                    {
                        self.owner.hir_symbol_names.get(symbol).cloned()
                    }
                    _ => None,
                };
                let (receiver, receiver_ty) = if let Some(expr) = call.receiver.as_ref() {
                    let (value, ty) = self.lower_expr(
                        expr,
                        insts,
                        value_map,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    (Some(value), ty)
                } else {
                    (None, None)
                };
                let cpp_cast_target = call.args.first().and_then(|arg| match arg {
                    Expr::Literal {
                        kind: LiteralKind::String(value),
                        ..
                    } => Some(value.clone()),
                    _ => None,
                });
                let args = call
                    .args
                    .iter()
                    .map(|arg| {
                        self.lower_expr(
                            arg,
                            insts,
                            value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        )
                        .0
                    })
                    .collect::<Vec<_>>();
                let external_receiver_name = receiver.and_then(|receiver| {
                    insts.iter().rev().find_map(|inst| match &inst.kind {
                        InstKind::ConstString { dst, value } if *dst == receiver => value
                            .strip_prefix("<external-symbol:")
                            .and_then(|value| value.strip_suffix('>'))
                            .map(str::to_string),
                        _ => None,
                    })
                });
                let callee = match &call.target {
                    CallTarget::Named(name) if external_receiver_name.is_some() => Callee::Static(
                        format!("{}.{}", external_receiver_name.as_deref().unwrap(), name),
                    ),
                    CallTarget::Named(name) if self.owner.current_import_aliases.contains_key(name) => {
                        Callee::Static(self.owner.current_import_aliases[name].clone())
                    }
                    CallTarget::Named(name) => {
                        let local_callable = value_map.iter().find_map(|(symbol, value)| {
                            (self.owner.hir_symbol_names.get(symbol).map(String::as_str)
                                == Some(name.as_str())
                                && value_types
                                    .get(value)
                                    .is_some_and(|ty| ty.contains("lambda_")))
                            .then_some(*value)
                        });
                        local_callable.map_or_else(|| Callee::Static(name.clone()), Callee::Dynamic)
                    }
                    CallTarget::Resolved(symbol) => Callee::Static(
                        self.owner
                            .hir_symbol_names
                            .get(symbol)
                            .cloned()
                            .unwrap_or_else(|| format!("symbol#{}", symbol.0)),
                    ),
                    CallTarget::Dynamic(expr) => {
                        let (callee_value, _) = self.lower_expr(
                            expr,
                            insts,
                            value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        Callee::Dynamic(callee_value)
                    }
                };
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, call.span);
                let special_name = match &callee {
                    Callee::Static(name) => Some(name.clone()),
                    _ => None,
                };
                let is_cpp_cast = special_name
                    .as_deref()
                    .is_some_and(|name| name.starts_with("__uniflow_cpp_cast_"));
                match special_name.as_deref() {
                    Some("__uniflow_cpp_lambda_bind")
                        if cpp_lambda_bind_target.is_some() && args.len() >= 2 =>
                    {
                        let target = cpp_lambda_bind_target
                            .clone()
                            .expect("checked C++ lambda target");
                        self.push_inst(
                            insts,
                            InstKind::ConstString {
                                dst,
                                value: "<lambda>".to_string(),
                            },
                            call.span,
                        );
                        let capture_names = self
                            .owner
                            .lambda_captures
                            .get(&target)
                            .cloned()
                            .unwrap_or_else(|| {
                                (0..args.len().saturating_sub(1))
                                    .map(|index| format!("capture_{index}"))
                                    .collect()
                            });
                        for (name, src) in capture_names.iter().zip(args.iter().skip(1)) {
                            self.push_inst(
                                insts,
                                InstKind::StoreField {
                                    base: dst,
                                    field: format!("__capture__{name}"),
                                    src: *src,
                                },
                                call.span,
                            );
                        }
                        value_types.insert(dst, target);
                    }
                    Some("__uniflow_cpp_move") | Some("__uniflow_cpp_forward")
                        if args.len() == 1 =>
                    {
                        self.push_inst(insts, InstKind::Move { dst, src: args[0] }, call.span);
                        self.push_inst(
                            insts,
                            InstKind::Lifetime {
                                value: args[0],
                                event: uniflow_ir::LifetimeEvent::MoveFrom,
                            },
                            call.span,
                        );
                    }
                    Some("__uniflow_cpp_capture_ref") | Some("__uniflow_cpp_capture_value")
                        if args.len() == 1 =>
                    {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                    }
                    Some("__uniflow_cpp_cast_static") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 {
                            args[1]
                        } else {
                            args[0]
                        };
                        self.push_inst(
                            insts,
                            InstKind::Cast {
                                dst,
                                src,
                                kind: uniflow_ir::CppCastKind::Static,
                                target_type: cpp_cast_target.clone(),
                            },
                            call.span,
                        )
                    }
                    Some("__uniflow_cpp_cast_dynamic") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 {
                            args[1]
                        } else {
                            args[0]
                        };
                        self.push_inst(
                            insts,
                            InstKind::Cast {
                                dst,
                                src,
                                kind: uniflow_ir::CppCastKind::Dynamic,
                                target_type: cpp_cast_target.clone(),
                            },
                            call.span,
                        )
                    }
                    Some("__uniflow_cpp_cast_reinterpret") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 {
                            args[1]
                        } else {
                            args[0]
                        };
                        self.push_inst(
                            insts,
                            InstKind::Cast {
                                dst,
                                src,
                                kind: uniflow_ir::CppCastKind::Reinterpret,
                                target_type: cpp_cast_target.clone(),
                            },
                            call.span,
                        )
                    }
                    Some("__uniflow_cpp_cast_const") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 {
                            args[1]
                        } else {
                            args[0]
                        };
                        self.push_inst(
                            insts,
                            InstKind::Cast {
                                dst,
                                src,
                                kind: uniflow_ir::CppCastKind::Const,
                                target_type: cpp_cast_target.clone(),
                            },
                            call.span,
                        )
                    }
                    Some("__uniflow_cpp_destroy") if args.len() == 1 => {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                        self.push_inst(
                            insts,
                            InstKind::Lifetime {
                                value: args[0],
                                event: uniflow_ir::LifetimeEvent::Destroy,
                            },
                            call.span,
                        );
                    }
                    Some("__uniflow_cpp_delete") if args.len() == 1 => {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                        self.push_inst(
                            insts,
                            InstKind::Lifetime {
                                value: args[0],
                                event: uniflow_ir::LifetimeEvent::Free,
                            },
                            call.span,
                        );
                        self.push_inst(
                            insts,
                            InstKind::Lifetime {
                                value: args[0],
                                event: uniflow_ir::LifetimeEvent::Destroy,
                            },
                            call.span,
                        );
                    }
                    Some("__uniflow_cpp_release") if args.len() == 1 => {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                        self.push_inst(
                            insts,
                            InstKind::Lifetime {
                                value: args[0],
                                event: uniflow_ir::LifetimeEvent::Release,
                            },
                            call.span,
                        );
                    }
                    Some(name)
                        if !args.is_empty()
                            && matches!(
                                name.rsplit("::").next().unwrap_or(name),
                                "free" | "operator delete" | "operator delete[]"
                            ) =>
                    {
                        self.push_inst(
                            insts,
                            InstKind::Call(CallInst {
                                dst: Some(dst),
                                callee,
                                receiver,
                                args: args.clone(),
                                arg_names: call.arg_names.clone(),
                                arg_spans: arg_spans.clone(),
                                arg_origins: arg_origins.clone(),
                            }),
                            call.span,
                        );
                        self.push_inst(
                            insts,
                            InstKind::Lifetime {
                                value: args[0],
                                event: uniflow_ir::LifetimeEvent::Free,
                            },
                            call.span,
                        );
                    }
                    _ => self.push_inst(
                        insts,
                        InstKind::Call(CallInst {
                            dst: Some(dst),
                            callee,
                            receiver,
                            args,
                            arg_names: call.arg_names.clone(),
                            arg_spans,
                            arg_origins,
                        }),
                        call.span,
                    ),
                }
                let inferred = if let Some(target) = cpp_lambda_bind_target {
                    Some(target)
                } else if is_cpp_cast {
                    cpp_cast_target.clone()
                } else {
                    infer_call_return_type(call, receiver_ty.as_deref())
                };
                if let Some(name) = inferred.clone() {
                    value_types.insert(dst, name);
                }
                (dst, inferred)
            }
            Expr::Cast { expr, ty, span, .. } => {
                let (value, inner_ty) = self.lower_expr(
                    expr,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let explicit_ty = self.owner.type_name_for(*ty).or(inner_ty);
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::Cast {
                        dst,
                        src: value,
                        kind: uniflow_ir::CppCastKind::Static,
                        target_type: explicit_ty.clone(),
                    },
                    *span,
                );
                if let Some(name) = explicit_ty.clone() {
                    value_types.insert(dst, name);
                }
                (dst, explicit_ty)
            }
            Expr::Unary { op, expr, span, .. } if matches!(op,
                uniflow_hir::UnaryOp::PreIncrement | uniflow_hir::UnaryOp::PostIncrement
                | uniflow_hir::UnaryOp::PreDecrement | uniflow_hir::UnaryOp::PostDecrement) => {
                // Capture the storage location before loading it. Re-lowering
                // an lvalue for the store would call getObject()/nextIndex()
                // twice, or observe the wrong index in array[i++]++.
                enum Location { Var(SymbolId), Field(ValueId, String), Index(ValueId, ValueId) }
                let (location, src, ty) = match expr.as_ref() {
                    Expr::VarRef { symbol, .. } => {
                        let (src, ty) = self.lower_expr(expr, insts, value_map, symbol_types,
                            locals, value_types, value_spans);
                        (Location::Var(*symbol), src, ty)
                    }
                    Expr::FieldRead { base, field, .. } => {
                        let (base, _) = self.lower_expr(base, insts, value_map, symbol_types,
                            locals, value_types, value_spans);
                        let src = self.alloc_value();
                        locals.push(src);
                        value_spans.insert(src, *span);
                        self.push_inst(insts, InstKind::LoadField { dst: src, base, field: field.clone() }, *span);
                        (Location::Field(base, field.clone()), src, None)
                    }
                    Expr::IndexRead { base, index, .. } => {
                        let (base, base_ty) = self.lower_expr(base, insts, value_map, symbol_types,
                            locals, value_types, value_spans);
                        let (index, _) = self.lower_expr(index, insts, value_map, symbol_types,
                            locals, value_types, value_spans);
                        let src = self.alloc_value();
                        locals.push(src);
                        value_spans.insert(src, *span);
                        self.push_inst(insts, InstKind::LoadIndex { dst: src, base, index }, *span);
                        let ty = base_ty.and_then(|ty| ty.strip_suffix("[]").map(str::to_string));
                        if let Some(ty) = &ty { value_types.insert(src, ty.clone()); }
                        (Location::Index(base, index), src, ty)
                    }
                    // Invalid update operands are left for frontend diagnostics;
                    // never manufacture a write to a non-storage expression.
                    _ => return self.lower_expr(expr, insts, value_map, symbol_types,
                        locals, value_types, value_spans),
                };
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                if let Some(ty) = &ty { value_types.insert(dst, ty.clone()); }
                self.push_inst(insts, InstKind::NumericStep { dst, src,
                    increment: matches!(op, uniflow_hir::UnaryOp::PreIncrement | uniflow_hir::UnaryOp::PostIncrement) }, *span);
                match location {
                    Location::Var(symbol) => { value_map.insert(symbol, dst); }
                    Location::Field(base, field) => {
                        self.push_inst(insts, InstKind::StoreField { base, field, src: dst }, *span);
                    }
                    Location::Index(base, index) => {
                        self.push_inst(insts, InstKind::StoreIndex { base, index, src: dst }, *span);
                    }
                }
                let postfix = matches!(op, uniflow_hir::UnaryOp::PostIncrement | uniflow_hir::UnaryOp::PostDecrement);
                (if postfix { src } else { dst }, ty)
            }
            Expr::Unary { op: uniflow_hir::UnaryOp::Deref, expr, span, .. } => {
                let (src, ty) = self.lower_expr(
                    expr,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                if let Some(ty) = ty.as_deref().and_then(|ty| ty.strip_suffix('*')) {
                    value_types.insert(dst, ty.trim().to_string());
                }
                self.push_inst(insts, InstKind::Deref { dst, src }, *span);
                (dst, value_types.get(&dst).cloned())
            }
            Expr::Unary { op: uniflow_hir::UnaryOp::Neg, expr, span, .. } => {
                let (src, ty) = self.lower_expr(
                    expr,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                if let Some(ty) = &ty {
                    value_types.insert(dst, ty.clone());
                }
                self.push_inst(insts, InstKind::NumericNeg { dst, src }, *span);
                (dst, ty)
            }
            Expr::Unary { expr, .. } => self.lower_expr(
                expr,
                insts,
                value_map,
                symbol_types,
                locals,
                value_types,
                value_spans,
            ),
            Expr::Binary { op, lhs, rhs, span, .. } => {
                let mut composition_descriptor = String::new();
                if matches!(op, uniflow_hir::BinaryOp::Add) {
                    expression_literal_fragments(lhs, &self.owner.hir_symbol_names, &mut composition_descriptor);
                    expression_literal_fragments(rhs, &self.owner.hir_symbol_names, &mut composition_descriptor);
                    if expression_contains_dynamic_data(lhs) || expression_contains_dynamic_data(rhs) {
                        if !composition_descriptor.is_empty() {
                            composition_descriptor.push(' ');
                        }
                        composition_descriptor.push_str("__uniflow.dynamic__");
                    }
                }
                let (left, left_ty) = self.lower_expr(
                    lhs,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let (right, right_ty) = self.lower_expr(
                    rhs,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                let comparison = match op {
                    uniflow_hir::BinaryOp::Eq => Some(ComparisonOp::Eq),
                    uniflow_hir::BinaryOp::Ne => Some(ComparisonOp::Ne),
                    uniflow_hir::BinaryOp::Lt => Some(ComparisonOp::Lt),
                    uniflow_hir::BinaryOp::Le => Some(ComparisonOp::Le),
                    uniflow_hir::BinaryOp::Gt => Some(ComparisonOp::Gt),
                    uniflow_hir::BinaryOp::Ge => Some(ComparisonOp::Ge),
                    uniflow_hir::BinaryOp::In => Some(ComparisonOp::In),
                    _ => None,
                };
                if let Some(op) = comparison {
                    self.push_inst(
                        insts,
                        InstKind::Compare {
                            dst,
                            lhs: left,
                            rhs: right,
                            op,
                        },
                        *span,
                    );
                    value_types.insert(dst, "bool".to_string());
                    return (dst, Some("bool".to_string()));
                }
                self.push_inst(
                    insts,
                    InstKind::Phi {
                        dst,
                        inputs: vec![left, right],
                    },
                    *span,
                );
                let ty = left_ty.or(right_ty);
                if let Some(name) = ty.clone() {
                    value_types.insert(dst, name);
                }
                let result = if self.owner.language == Language::Ruby
                    && matches!(op, uniflow_hir::BinaryOp::Div)
                {
                    let divided = self.alloc_value();
                    locals.push(divided);
                    value_spans.insert(divided, *span);
                    self.push_inst(
                        insts,
                        InstKind::Call(CallInst {
                            dst: Some(divided),
                            callee: Callee::Static("__uniflow.binary.division".to_string()),
                            receiver: None,
                            args: vec![left, right],
                            arg_names: vec![None, None],
                            arg_spans: Vec::new(),
                            arg_origins: Vec::new(),
                        }),
                        *span,
                    );
                    divided
                } else {
                    self.emit_expression_composition(
                        insts,
                        locals,
                        value_spans,
                        "__uniflow.compose.string",
                        dst,
                        composition_descriptor,
                        *span,
                    )
                };
                if result != dst {
                    if let Some(name) = ty.clone() {
                        value_types.insert(result, name);
                    }
                }
                (result, ty)
            }
            Expr::Conditional {
                cond,
                then_expr,
                else_expr,
                span,
                ..
            } => {
                // The condition is evaluated for side effects/control inputs;
                // the expression value is the merge of the two result arms.
                let _ = self.lower_expr(
                    cond,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                if let Expr::Literal { kind: LiteralKind::Bool(taken), .. } = cond.as_ref() {
                    return self.lower_expr(if *taken { then_expr } else { else_expr },
                        insts, value_map, symbol_types, locals, value_types, value_spans);
                }
                // Each arm starts after the condition, not after the other arm.
                // Merge assigned locals as well as the expression's result;
                // otherwise a safe assignment in the else arm erases taint
                // assigned on the then path before a following sink.
                let entry_env = value_map.clone();
                let entry_types = symbol_types.clone();
                let (then_value, then_ty) = self.lower_expr(
                    then_expr,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let then_env = value_map.clone();
                *value_map = entry_env;
                *symbol_types = entry_types;
                let (else_value, else_ty) = self.lower_expr(
                    else_expr,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let (merged_env, mut assignments) = self.merge_environments(
                    &then_env, value_map, *span, symbol_types, locals, value_types, value_spans,
                );
                *value_map = merged_env;
                insts.append(&mut assignments);
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::Phi {
                        dst,
                        inputs: vec![then_value, else_value],
                    },
                    *span,
                );
                let ty = then_ty.or(else_ty);
                if let Some(name) = ty.clone() {
                    value_types.insert(dst, name);
                }
                (dst, ty)
            }
            Expr::Assign { lhs, rhs, span, .. } => {
                if self.owner.language == Language::Java {
                    return self.lower_java_assignment(lhs, rhs, *span, insts, value_map,
                        symbol_types, locals, value_types, value_spans);
                }
                let (src, inferred) = self.lower_expr(
                    rhs,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                match lhs {
                    LValue::Var(symbol) => {
                        let dst = self.alloc_value();
                        locals.push(dst);
                        value_map.insert(*symbol, dst);
                        value_spans.insert(dst, *span);
                        self.push_inst(insts, InstKind::Copy { dst, src }, *span);
                        if let Some(name) = inferred
                            .clone()
                            .or_else(|| symbol_types.get(symbol).cloned())
                        {
                            symbol_types.insert(*symbol, name.clone());
                            value_types.insert(dst, name);
                        }
                        (dst, inferred)
                    }
                    LValue::Field { base, field } => {
                        let (base_value, _) = self.lower_expr(
                            base,
                            insts,
                            value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        self.push_inst(
                            insts,
                            InstKind::StoreField {
                                base: base_value,
                                field: field.clone(),
                                src,
                            },
                            *span,
                        );
                        (src, inferred)
                    }
                    LValue::Index { base, index } => {
                        let (base_value, _) = self.lower_expr(
                            base,
                            insts,
                            value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        let (index_value, _) = self.lower_expr(
                            index,
                            insts,
                            value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        self.push_inst(
                            insts,
                            InstKind::StoreIndex {
                                base: base_value,
                                index: index_value,
                                src,
                            },
                            *span,
                        );
                        (src, inferred)
                    }
                }
            }
            Expr::Interp { parts, span, .. }
            | Expr::Collection { elements: parts, span, .. } => {
                let is_map = matches!(expr, Expr::Collection { container: uniflow_hir::CollectionKind::Map, .. });
                let mut composition_descriptor = String::new();
                expression_literal_fragments(expr, &self.owner.hir_symbol_names, &mut composition_descriptor);
                mark_dynamic_composition(expr, &mut composition_descriptor);
                let map_payload_index = is_map
                    .then(|| {
                        [
                            "body",
                            "cmd",
                            "expression",
                            "url",
                            "headerTemplate",
                            "footerTemplate",
                            "html",
                        ]
                        .iter()
                        .find_map(|field| {
                            map_value_index(parts, field, &self.owner.hir_symbol_names)
                        })
                    })
                    .flatten();
                let mut inputs = Vec::with_capacity(parts.len());
                let mut ty = None;
                for part in parts {
                    let (value, part_ty) = self.lower_expr(
                        part,
                        insts,
                        value_map,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    inputs.push(value);
                    ty = ty.or(part_ty);
                }
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                let composition_value = map_payload_index
                    .and_then(|index| inputs.get(index).copied())
                    .unwrap_or(dst);
                if inputs.is_empty() {
                    self.push_inst(
                        insts,
                        InstKind::ConstString {
                            dst,
                            value: String::new(),
                        },
                        *span,
                    );
                } else {
                    self.push_inst(insts, InstKind::Phi { dst, inputs }, *span);
                }
                if let Some(name) = ty.clone() {
                    value_types.insert(dst, name);
                }
                let composition_callee = if is_map {
                    "__uniflow.compose.map"
                } else {
                    "__uniflow.compose.string"
                };
                let result = self.emit_expression_composition(
                    insts,
                    locals,
                    value_spans,
                    composition_callee,
                    composition_value,
                    composition_descriptor,
                    *span,
                );
                if result != dst {
                    if let Some(name) = ty.clone() {
                        value_types.insert(result, name);
                    }
                }
                (result, ty)
            }
            Expr::Range {
                low, high, span, ..
            } => {
                let (low, low_ty) = self.lower_expr(
                    low,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let (high, high_ty) = self.lower_expr(
                    high,
                    insts,
                    value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                );
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::Phi {
                        dst,
                        inputs: vec![low, high],
                    },
                    *span,
                );
                let ty = low_ty.or(high_ty);
                (dst, ty)
            }
            Expr::Lambda {
                id, captures, span, ..
            } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::ConstString {
                        dst,
                        value: "<lambda>".to_string(),
                    },
                    *span,
                );
                for capture in captures {
                    let src = value_map
                        .get(&capture.source_symbol)
                        .copied()
                        .unwrap_or_else(|| {
                            let fresh = self.alloc_value();
                            locals.push(fresh);
                            value_spans.insert(fresh, capture.span);
                            value_map.insert(capture.source_symbol, fresh);
                            fresh
                        });
                    self.push_inst(
                        insts,
                        InstKind::StoreField {
                            base: dst,
                            field: format!("__capture__{}", capture.name),
                            src,
                        },
                        capture.span,
                    );
                }
                let name =
                    lambda_function_name(&self.current_function_name, *id, span.start_line.max(1));
                value_types.insert(dst, name.clone());
                (dst, Some(name))
            }
            Expr::New {
                type_name,
                args,
                span,
                ..
            } => {
                let args = args
                    .iter()
                    .map(|arg| {
                        self.lower_expr(
                            arg,
                            insts,
                            value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        )
                        .0
                    })
                    .collect::<Vec<_>>();
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::Call(CallInst {
                        dst: Some(dst),
                        callee: Callee::Static(type_name.clone()),
                        receiver: None,
                        arg_names: vec![None; args.len()],
                        args,
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
                    }),
                    *span,
                );
                value_types.insert(dst, type_name.clone());
                (dst, Some(type_name.clone()))
            }
            Expr::Opaque { text, span, .. } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::ConstString {
                        dst,
                        value: text.clone(),
                    },
                    *span,
                );
                (dst, None)
            }
            Expr::Unknown { span, .. } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(
                    insts,
                    InstKind::ConstString {
                        dst,
                        value: "<unknown>".to_string(),
                    },
                    *span,
                );
                (dst, None)
            }
        }
    }
}

fn jsp_implicit_object_type(name: &str) -> Option<&'static str> {
    match name {
        "request" => Some("javax.servlet.http.HttpServletRequest"),
        "response" => Some("javax.servlet.http.HttpServletResponse"),
        "session" => Some("javax.servlet.http.HttpSession"),
        "application" => Some("javax.servlet.ServletContext"),
        "out" => Some("javax.servlet.jsp.JspWriter"),
        "pageContext" => Some("javax.servlet.jsp.PageContext"),
        "config" => Some("javax.servlet.ServletConfig"),
        "page" => Some("java.lang.Object"),
        "exception" => Some("java.lang.Throwable"),
        _ => None,
    }
}
