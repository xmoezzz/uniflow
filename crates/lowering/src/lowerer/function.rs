struct FunctionLoweringContext<'a> {
    owner: &'a mut Lowerer,
    function_id: FunctionId,
    current_function_name: String,
    exception_edges: Vec<ExceptionEdge>,
}

impl<'a> FunctionLoweringContext<'a> {
    fn new(owner: &'a mut Lowerer, function_id: FunctionId, current_function_name: String) -> Self {
        Self { owner, function_id, current_function_name, exception_edges: Vec::new() }
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
            .is_some_and(|kind| matches!(
                kind,
                uniflow_hir::CppSpecialMemberKind::Constructor
                    | uniflow_hir::CppSpecialMemberKind::CopyConstructor
                    | uniflow_hir::CppSpecialMemberKind::MoveConstructor
            ))
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
                CppConstructorInitializerKind::Base
                | CppConstructorInitializerKind::Delegating => {
                    self.push_inst(
                        &mut insts,
                        InstKind::Call(CallInst {
                            dst: None,
                            callee: Callee::Static(format!(
                                "{}::{}",
                                initializer.target,
                                initializer.target.rsplit("::").next().unwrap_or(&initializer.target)
                            )),
                            receiver: Some(receiver),
                            args,
                            arg_names: Vec::new(),
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

    fn lower_block_into(
        &mut self,
        block: &Block,
        insts: &mut Vec<Instruction>,
        value_map: &mut HashMap<SymbolId, ValueId>,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> Terminator {
        let mut term = Terminator::Return(None);

        for stmt in &block.stmts {
            match stmt {
                Stmt::Let { symbol, ty, init, span, .. } => {
                    let dst = self.alloc_value();
                    locals.push(dst);
                    value_map.insert(*symbol, dst);
                    value_spans.insert(dst, *span);

                    let declared_ty = self.owner.type_name_for(*ty);
                    if let Some(name) = declared_ty.clone() {
                        symbol_types.insert(*symbol, name.clone());
                        value_types.insert(dst, name);
                    }

                    if let Some(expr) = init {
                        let (src, inferred) = self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
                        self.push_inst(insts, InstKind::Copy { dst, src }, *span);
                        if let Some(name) = declared_ty.or(inferred) {
                            symbol_types.insert(*symbol, name.clone());
                            value_types.insert(dst, name);
                        }
                    }
                }
                Stmt::Assign { lhs, rhs, span, .. } => {
                    let (src, inferred) = self.lower_expr(rhs, insts, value_map, symbol_types, locals, value_types, value_spans);
                    match lhs {
                        LValue::Var(symbol) => {
                            // Every assignment creates a fresh definition. Reusing the previous
                            // ValueId conflates killed and live definitions and makes even simple
                            // reassignment unsound for data-flow and taint analysis.
                            let dst = self.alloc_value();
                            locals.push(dst);
                            value_map.insert(*symbol, dst);
                            value_spans.insert(dst, *span);
                            self.push_inst(insts, InstKind::Copy { dst, src }, *span);
                            if let Some(name) = inferred.or_else(|| symbol_types.get(symbol).cloned()) {
                                symbol_types.insert(*symbol, name.clone());
                                value_types.insert(dst, name);
                            }
                        }
                        LValue::Field { base, field } => {
                            let (base_value, _) = self.lower_expr(base, insts, value_map, symbol_types, locals, value_types, value_spans);
                            self.push_inst(
                                insts,
                                InstKind::StoreField { base: base_value, field: field.clone(), src },
                                *span,
                            );
                        }
                        LValue::Index { base, index } => {
                            let (base_value, _) = self.lower_expr(base, insts, value_map, symbol_types, locals, value_types, value_spans);
                            let (index_value, _) = self.lower_expr(index, insts, value_map, symbol_types, locals, value_types, value_spans);
                            self.push_inst(
                                insts,
                                InstKind::StoreIndex { base: base_value, index: index_value, src },
                                *span,
                            );
                        }
                    }
                }
                Stmt::Expr { expr, .. } => {
                    self.lower_expr_drop(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
                }
                Stmt::Return { value, .. } => {
                    term = Terminator::Return(value.as_ref().map(|expr| {
                        self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans).0
                    }));
                    break;
                }
                Stmt::Throw { value, .. } => {
                    term = Terminator::Throw(value.as_ref().map(|expr| {
                        self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans).0
                    }));
                    break;
                }
                Stmt::If { cond, then_block, else_block, .. } => {
                    self.lower_expr_drop(cond, insts, value_map, symbol_types, locals, value_types, value_spans);
                    let _ = self.lower_block_into(then_block, insts, value_map, symbol_types, locals, value_types, value_spans);
                    if let Some(else_block) = else_block {
                        let _ = self.lower_block_into(else_block, insts, value_map, symbol_types, locals, value_types, value_spans);
                    }
                }
                Stmt::While { cond, body, .. } => {
                    self.lower_expr_drop(cond, insts, value_map, symbol_types, locals, value_types, value_spans);
                    let _ = self.lower_block_into(body, insts, value_map, symbol_types, locals, value_types, value_spans);
                }
                Stmt::ForEach { item_symbol, iterable, body, span, .. } => {
                    let (iter_value, inferred) = self.lower_expr(iterable, insts, value_map, symbol_types, locals, value_types, value_spans);
                    let item_value = value_map.get(item_symbol).copied().unwrap_or_else(|| {
                        let fresh = self.alloc_value();
                        locals.push(fresh);
                        value_map.insert(*item_symbol, fresh);
                        value_spans.insert(fresh, *span);
                        fresh
                    });
                    self.push_inst(insts, InstKind::Copy { dst: item_value, src: iter_value }, *span);
                    if let Some(name) = inferred.or_else(|| symbol_types.get(item_symbol).cloned()) {
                        symbol_types.insert(*item_symbol, name.clone());
                        value_types.insert(item_value, name);
                    }
                    let _ = self.lower_block_into(body, insts, value_map, symbol_types, locals, value_types, value_spans);
                }
                Stmt::Try { try_block, catches, finally_block, .. } => {
                    let _ = self.lower_block_into(try_block, insts, value_map, symbol_types, locals, value_types, value_spans);
                    for catch in catches {
                        let _ = self.lower_block_into(&catch.body, insts, value_map, symbol_types, locals, value_types, value_spans);
                    }
                    if let Some(finally_block) = finally_block {
                        let _ = self.lower_block_into(finally_block, insts, value_map, symbol_types, locals, value_types, value_spans);
                    }
                }
            }
        }

        term
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
        let _ = self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
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
                            value: format!("<external-symbol:{}>", symbol.0),
                        },
                        *span,
                    );
                    fresh
                });
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
                        self.push_inst(insts, InstKind::ConstString { dst, value: value.clone() }, *span);
                        Some("String".to_string())
                    }
                    LiteralKind::Bool(value) => {
                        self.push_inst(insts, InstKind::ConstInt { dst, value: i64::from(*value) }, *span);
                        Some("bool".to_string())
                    }
                    LiteralKind::Null | LiteralKind::Float(_) | LiteralKind::Bytes(_) => {
                        self.push_inst(insts, InstKind::ConstString { dst, value: "<literal>".to_string() }, *span);
                        None
                    }
                };
                if let Some(name) = ty.clone() {
                    value_types.insert(dst, name);
                }
                (dst, ty)
            }
            Expr::FieldRead { base, field, span, .. } => {
                let (base_value, _) = self.lower_expr(base, insts, value_map, symbol_types, locals, value_types, value_spans);
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::LoadField { dst, base: base_value, field: field.clone() }, *span);
                (dst, None)
            }
            Expr::IndexRead { base, index, span, .. } => {
                let (base_value, _) = self.lower_expr(base, insts, value_map, symbol_types, locals, value_types, value_spans);
                let (index_value, _) = self.lower_expr(index, insts, value_map, symbol_types, locals, value_types, value_spans);
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::LoadIndex { dst, base: base_value, index: index_value }, *span);
                (dst, None)
            }
            Expr::Call(call) => {
                let (receiver, receiver_ty) = if let Some(expr) = call.receiver.as_ref() {
                    let (value, ty) = self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
                    (Some(value), ty)
                } else {
                    (None, None)
                };
                let cpp_cast_target = call.args.first().and_then(|arg| match arg {
                    Expr::Literal { kind: LiteralKind::String(value), .. } => Some(value.clone()),
                    _ => None,
                });
                let args = call
                    .args
                    .iter()
                    .map(|arg| self.lower_expr(arg, insts, value_map, symbol_types, locals, value_types, value_spans).0)
                    .collect::<Vec<_>>();
                let callee = match &call.target {
                    CallTarget::Named(name) => Callee::Static(name.clone()),
                    CallTarget::Resolved(symbol) => Callee::Static(format!("symbol#{}", symbol.0)),
                    CallTarget::Dynamic(expr) => {
                        let (callee_value, _) = self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
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
                    Some("__uniflow_cpp_move") | Some("__uniflow_cpp_forward") if args.len() == 1 => {
                        self.push_inst(insts, InstKind::Move { dst, src: args[0] }, call.span);
                        self.push_inst(insts, InstKind::Lifetime { value: args[0], event: uniflow_ir::LifetimeEvent::MoveFrom }, call.span);
                    }
                    Some("__uniflow_cpp_capture_ref") | Some("__uniflow_cpp_capture_value")
                        if args.len() == 1 =>
                    {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                    }
                    Some("__uniflow_cpp_cast_static") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 { args[1] } else { args[0] };
                        self.push_inst(insts, InstKind::Cast {
                            dst, src, kind: uniflow_ir::CppCastKind::Static, target_type: cpp_cast_target.clone(),
                        }, call.span)
                    }
                    Some("__uniflow_cpp_cast_dynamic") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 { args[1] } else { args[0] };
                        self.push_inst(insts, InstKind::Cast {
                            dst, src, kind: uniflow_ir::CppCastKind::Dynamic, target_type: cpp_cast_target.clone(),
                        }, call.span)
                    }
                    Some("__uniflow_cpp_cast_reinterpret") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 { args[1] } else { args[0] };
                        self.push_inst(insts, InstKind::Cast {
                            dst, src, kind: uniflow_ir::CppCastKind::Reinterpret, target_type: cpp_cast_target.clone(),
                        }, call.span)
                    }
                    Some("__uniflow_cpp_cast_const") if !args.is_empty() => {
                        let src = if cpp_cast_target.is_some() && args.len() >= 2 { args[1] } else { args[0] };
                        self.push_inst(insts, InstKind::Cast {
                            dst, src, kind: uniflow_ir::CppCastKind::Const, target_type: cpp_cast_target.clone(),
                        }, call.span)
                    }
                    Some("__uniflow_cpp_destroy") if args.len() == 1 => {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                        self.push_inst(insts, InstKind::Lifetime { value: args[0], event: uniflow_ir::LifetimeEvent::Destroy }, call.span);
                    }
                    Some("__uniflow_cpp_release") if args.len() == 1 => {
                        self.push_inst(insts, InstKind::Copy { dst, src: args[0] }, call.span);
                        self.push_inst(insts, InstKind::Lifetime { value: args[0], event: uniflow_ir::LifetimeEvent::Release }, call.span);
                    }
                    _ => self.push_inst(insts, InstKind::Call(CallInst {
                        dst: Some(dst),
                        callee,
                        receiver,
                        args,
                        arg_names: call.arg_names.clone(),
                    }), call.span),
                }
                let inferred = if is_cpp_cast {
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
                let (value, inner_ty) = self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
                let explicit_ty = self.owner.type_name_for(*ty).or(inner_ty);
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::Cast {
                    dst,
                    src: value,
                    kind: uniflow_ir::CppCastKind::Static,
                    target_type: explicit_ty.clone(),
                }, *span);
                if let Some(name) = explicit_ty.clone() {
                    value_types.insert(dst, name);
                }
                (dst, explicit_ty)
            }
            Expr::Unary { expr, .. } => self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans),
            Expr::Binary { lhs, rhs, span, .. } => {
                let (left, left_ty) = self.lower_expr(lhs, insts, value_map, symbol_types, locals, value_types, value_spans);
                let (right, right_ty) = self.lower_expr(rhs, insts, value_map, symbol_types, locals, value_types, value_spans);
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::Phi { dst, inputs: vec![left, right] }, *span);
                let ty = left_ty.or(right_ty);
                if let Some(name) = ty.clone() {
                    value_types.insert(dst, name);
                }
                (dst, ty)
            }
            Expr::Lambda { id, captures, span, .. } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::ConstString { dst, value: "<lambda>".to_string() }, *span);
                for capture in captures {
                    let src = value_map.get(&capture.source_symbol).copied().unwrap_or_else(|| {
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
                let name = lambda_function_name(&self.current_function_name, *id, span.start_line.max(1));
                value_types.insert(dst, name.clone());
                (dst, Some(name))
            }
            Expr::New { type_name, args, span, .. } => {
                let args = args
                    .iter()
                    .map(|arg| self.lower_expr(arg, insts, value_map, symbol_types, locals, value_types, value_spans).0)
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
                    }),
                    *span,
                );
                value_types.insert(dst, type_name.clone());
                (dst, Some(type_name.clone()))
            }
            Expr::Unknown { span, .. } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::ConstString { dst, value: "<unknown>".to_string() }, *span);
                (dst, None)
            }
        }
    }
}

