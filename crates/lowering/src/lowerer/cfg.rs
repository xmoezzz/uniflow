impl FunctionLoweringContext<'_> {
    fn lower_cfg_body(
        &mut self,
        block: &Block,
        value_map: HashMap<SymbolId, ValueId>,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (Vec<BasicBlock>, HashMap<SymbolId, ValueId>) {
        let entry = self.alloc_block_id();
        self.lower_stmt_sequence(
            &block.stmts,
            entry,
            value_map,
            Terminator::Return(None),
            symbol_types,
            locals,
            value_types,
            value_spans,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_stmt_sequence(
        &mut self,
        stmts: &[Stmt],
        current_id: BlockId,
        mut value_map: HashMap<SymbolId, ValueId>,
        fallthrough: Terminator,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (Vec<BasicBlock>, HashMap<SymbolId, ValueId>) {
        let mut insts = Vec::new();
        let mut index = 0;

        while index < stmts.len() {
            let stmt = &stmts[index];
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
                        let (src, inferred) = self.lower_expr(
                            expr,
                            &mut insts,
                            &mut value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        self.push_inst(&mut insts, InstKind::Copy { dst, src }, *span);
                        if let Some(name) = declared_ty.or(inferred) {
                            symbol_types.insert(*symbol, name.clone());
                            value_types.insert(dst, name);
                        }
                    }
                }
                Stmt::Assign { lhs, rhs, span, .. } => {
                    let (src, inferred) = self.lower_expr(
                        rhs,
                        &mut insts,
                        &mut value_map,
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
                            self.push_inst(&mut insts, InstKind::Copy { dst, src }, *span);
                            if let Some(name) = inferred.or_else(|| symbol_types.get(symbol).cloned()) {
                                symbol_types.insert(*symbol, name.clone());
                                value_types.insert(dst, name);
                            }
                        }
                        LValue::Field { base, field } => {
                            let (base_value, _) = self.lower_expr(
                                base,
                                &mut insts,
                                &mut value_map,
                                symbol_types,
                                locals,
                                value_types,
                                value_spans,
                            );
                            self.push_inst(
                                &mut insts,
                                InstKind::StoreField {
                                    base: base_value,
                                    field: field.clone(),
                                    src,
                                },
                                *span,
                            );
                        }
                        LValue::Index { base, index } => {
                            let (base_value, _) = self.lower_expr(
                                base,
                                &mut insts,
                                &mut value_map,
                                symbol_types,
                                locals,
                                value_types,
                                value_spans,
                            );
                            let (index_value, _) = self.lower_expr(
                                index,
                                &mut insts,
                                &mut value_map,
                                symbol_types,
                                locals,
                                value_types,
                                value_spans,
                            );
                            self.push_inst(
                                &mut insts,
                                InstKind::StoreIndex {
                                    base: base_value,
                                    index: index_value,
                                    src,
                                },
                                *span,
                            );
                        }
                    }
                }
                Stmt::Expr { expr, .. } => self.lower_expr_drop(
                    expr,
                    &mut insts,
                    &mut value_map,
                    symbol_types,
                    locals,
                    value_types,
                    value_spans,
                ),
                Stmt::Return { value, .. } => {
                    let return_value = value.as_ref().map(|expr| {
                        self.lower_expr(
                            expr,
                            &mut insts,
                            &mut value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        )
                        .0
                    });
                    return (
                        vec![BasicBlock {
                            id: current_id,
                            insts,
                            term: Terminator::Return(return_value),
                        }],
                        value_map,
                    );
                }
                Stmt::Throw { value, .. } => {
                    let throw_value = value.as_ref().map(|expr| {
                        self.lower_expr(
                            expr,
                            &mut insts,
                            &mut value_map,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        )
                        .0
                    });
                    return (
                        vec![BasicBlock {
                            id: current_id,
                            insts,
                            term: Terminator::Throw(throw_value),
                        }],
                        value_map,
                    );
                }
                Stmt::If {
                    cond,
                    then_block,
                    else_block,
                    span,
                    ..
                } => {
                    let (cond_value, _) = self.lower_expr(
                        cond,
                        &mut insts,
                        &mut value_map,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let then_id = self.alloc_block_id();
                    let else_id = self.alloc_block_id();
                    let join_id = self.alloc_block_id();
                    let mut blocks = vec![BasicBlock {
                        id: current_id,
                        insts,
                        term: Terminator::Branch {
                            cond: cond_value,
                            then_bb: then_id,
                            else_bb: else_id,
                        },
                    }];
                    let (mut then_blocks, then_env) = self.lower_stmt_sequence(
                        &then_block.stmts,
                        then_id,
                        value_map.clone(),
                        Terminator::Goto(join_id),
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let (mut else_blocks, else_env) = if let Some(else_block) = else_block {
                        self.lower_stmt_sequence(
                            &else_block.stmts,
                            else_id,
                            value_map.clone(),
                            Terminator::Goto(join_id),
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        )
                    } else {
                        (
                            vec![BasicBlock {
                                id: else_id,
                                insts: Vec::new(),
                                term: Terminator::Goto(join_id),
                            }],
                            value_map.clone(),
                        )
                    };
                    blocks.append(&mut then_blocks);
                    blocks.append(&mut else_blocks);

                    let (merged_env, join_insts) = self.merge_environments(
                        &then_env,
                        &else_env,
                        *span,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let (mut continuation, final_env) = self.lower_stmt_sequence_with_prefix(
                        &stmts[index + 1..],
                        join_id,
                        join_insts,
                        merged_env,
                        fallthrough,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.append(&mut continuation);
                    return (blocks, final_env);
                }
                Stmt::While { cond, body, span, .. } => {
                    let header_id = self.alloc_block_id();
                    let body_id = self.alloc_block_id();
                    let exit_id = self.alloc_block_id();
                    let mut blocks = vec![BasicBlock {
                        id: current_id,
                        insts,
                        term: Terminator::Goto(header_id),
                    }];
                    let mut header_insts = Vec::new();
                    let mut header_env = value_map.clone();
                    let (cond_value, _) = self.lower_expr(
                        cond,
                        &mut header_insts,
                        &mut header_env,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.push(BasicBlock {
                        id: header_id,
                        insts: header_insts,
                        term: Terminator::Branch {
                            cond: cond_value,
                            then_bb: body_id,
                            else_bb: exit_id,
                        },
                    });
                    let (mut body_blocks, body_env) = self.lower_stmt_sequence(
                        &body.stmts,
                        body_id,
                        header_env.clone(),
                        Terminator::Goto(header_id),
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.append(&mut body_blocks);
                    let (merged_env, exit_insts) = self.merge_environments(
                        &header_env,
                        &body_env,
                        *span,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let (mut continuation, final_env) = self.lower_stmt_sequence_with_prefix(
                        &stmts[index + 1..],
                        exit_id,
                        exit_insts,
                        merged_env,
                        fallthrough,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.append(&mut continuation);
                    return (blocks, final_env);
                }
                Stmt::ForEach {
                    item_symbol,
                    iterable,
                    body,
                    span,
                    ..
                } => {
                    let header_id = self.alloc_block_id();
                    let body_id = self.alloc_block_id();
                    let exit_id = self.alloc_block_id();
                    let (iter_value, inferred) = self.lower_expr(
                        iterable,
                        &mut insts,
                        &mut value_map,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let mut blocks = vec![BasicBlock {
                        id: current_id,
                        insts,
                        term: Terminator::Goto(header_id),
                    }];
                    blocks.push(BasicBlock {
                        id: header_id,
                        insts: Vec::new(),
                        term: Terminator::Branch {
                            cond: iter_value,
                            then_bb: body_id,
                            else_bb: exit_id,
                        },
                    });
                    let mut body_env = value_map.clone();
                    let item_value = self.alloc_value();
                    locals.push(item_value);
                    body_env.insert(*item_symbol, item_value);
                    value_spans.insert(item_value, *span);
                    if let Some(name) = inferred.or_else(|| symbol_types.get(item_symbol).cloned()) {
                        symbol_types.insert(*item_symbol, name.clone());
                        value_types.insert(item_value, name);
                    }
                    let item_copy = Instruction {
                        id: self.alloc_inst_id(),
                        kind: InstKind::Copy {
                            dst: item_value,
                            src: iter_value,
                        },
                        span: *span,
                    };
                    let (mut body_blocks, loop_env) = self.lower_stmt_sequence_with_prefix(
                        &body.stmts,
                        body_id,
                        vec![item_copy],
                        body_env,
                        Terminator::Goto(header_id),
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.append(&mut body_blocks);
                    let (merged_env, exit_insts) = self.merge_environments(
                        &value_map,
                        &loop_env,
                        *span,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let (mut continuation, final_env) = self.lower_stmt_sequence_with_prefix(
                        &stmts[index + 1..],
                        exit_id,
                        exit_insts,
                        merged_env,
                        fallthrough,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.append(&mut continuation);
                    return (blocks, final_env);
                }
                Stmt::Try {
                    try_block,
                    catches,
                    finally_block,
                    span,
                    ..
                } => {
                    // Normal and exceptional successors are represented separately.  Each catch
                    // gets its own typed unwind edge; consumers may conservatively consider all
                    // compatible handlers without pretending exception dispatch is a data branch.
                    let try_id = self.alloc_block_id();
                    let merge_id = self.alloc_block_id();
                    let finally_id = finally_block.as_ref().map(|_| self.alloc_block_id());
                    let catch_ids = if catches.is_empty() {
                        vec![finally_id.unwrap_or(merge_id)]
                    } else {
                        catches
                            .iter()
                            .map(|_| self.alloc_block_id())
                            .collect::<Vec<_>>()
                    };
                    let mut blocks = vec![BasicBlock {
                        id: current_id,
                        insts,
                        term: Terminator::Goto(try_id),
                    }];
                    let normal_target = finally_id.unwrap_or(merge_id);

                    // A named catch parameter is an SSA definition produced by the exceptional
                    // edge, not by an instruction in the handler block. Allocate it before the
                    // try body so every source block targeting the same handler binds the same
                    // value and the handler can use it through its ordinary symbol environment.
                    let catch_type_names = catches
                        .iter()
                        .map(|catch| {
                            catch
                                .ty
                                .and_then(|ty| self.owner.type_name_for(Some(ty)))
                        })
                        .collect::<Vec<_>>();
                    let catch_values = catches
                        .iter()
                        .zip(catch_type_names.iter())
                        .map(|(catch, catch_type)| {
                            let symbol = catch.symbol?;
                            let value = self.alloc_value();
                            locals.push(value);
                            value_spans.insert(value, catch.span);
                            if let Some(name) = catch_type.clone() {
                                symbol_types.insert(symbol, name.clone());
                                value_types.insert(value, name);
                            }
                            Some(value)
                        })
                        .collect::<Vec<_>>();

                    let (mut try_blocks, try_env) = self.lower_stmt_sequence(
                        &try_block.stmts,
                        try_id,
                        value_map.clone(),
                        Terminator::Goto(normal_target),
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    let try_cleanup_values =
                        Self::cpp_scope_values(try_block, &try_env);
                    for block in &try_blocks {
                        for (source_inst, thrown_value) in Self::cpp_block_throw_sites(block) {
                            let thrown_type = thrown_value
                                .and_then(|value| value_types.get(&value).map(String::as_str));
                            if catches.is_empty() {
                                self.exception_edges.push(ExceptionEdge {
                                    from: block.id,
                                    unwind: catch_ids[0],
                                    source_inst,
                                    thrown_value,
                                    catch_value: None,
                                    catch_type: None,
                                    is_cleanup: finally_block.is_some()
                                        || !try_cleanup_values.is_empty(),
                                    cleanup_values: try_cleanup_values.clone(),
                                });
                            } else {
                                let handlers = self.cpp_exception_handler_indices(
                                    &catch_type_names,
                                    thrown_type,
                                );
                                if handlers.is_empty() {
                                    // An unhandled exception still executes a finally/cleanup block.
                                    if let Some(finally_id) = finally_id {
                                        self.exception_edges.push(ExceptionEdge {
                                            from: block.id,
                                            unwind: finally_id,
                                            source_inst,
                                            thrown_value,
                                            catch_value: None,
                                            catch_type: None,
                                            is_cleanup: true,
                                            cleanup_values: try_cleanup_values.clone(),
                                        });
                                    }
                                    continue;
                                }
                                for index in handlers {
                                    self.exception_edges.push(ExceptionEdge {
                                        from: block.id,
                                        unwind: catch_ids[index],
                                        source_inst,
                                        thrown_value,
                                        catch_value: catch_values[index],
                                        catch_type: catch_type_names[index].clone(),
                                        is_cleanup: finally_block.is_some()
                                            || !try_cleanup_values.is_empty(),
                                        cleanup_values: try_cleanup_values.clone(),
                                    });
                                }
                            }
                        }
                    }
                    blocks.append(&mut try_blocks);

                    let mut catch_envs = Vec::new();
                    for ((catch, catch_id), catch_value) in catches
                        .iter()
                        .zip(catch_ids.iter().copied())
                        .zip(catch_values.iter().copied())
                    {
                        // A catch observes outer variables at the exceptional program point, not
                        // necessarily their values before entering the try.  We do not yet retain
                        // one SSA environment per throwing instruction, so conservatively merge
                        // the pre-try and final try versions for symbols that were already in
                        // scope. Try-local declarations remain out of scope in the handler.
                        let try_outer_env = value_map
                            .keys()
                            .filter_map(|symbol| {
                                try_env.get(symbol).copied().map(|value| (*symbol, value))
                            })
                            .collect::<HashMap<_, _>>();
                        let (mut handler_env, catch_prefix) = self.merge_environments(
                            &value_map,
                            &try_outer_env,
                            *span,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        if let (Some(symbol), Some(value)) = (catch.symbol, catch_value) {
                            handler_env.insert(symbol, value);
                        }
                        let (mut catch_blocks, mut catch_env) =
                            self.lower_stmt_sequence_with_prefix(
                                &catch.body.stmts,
                                catch_id,
                                catch_prefix,
                                handler_env,
                                Terminator::Goto(normal_target),
                                symbol_types,
                                locals,
                                value_types,
                                value_spans,
                            );
                        let mut catch_cleanup_values =
                            Self::cpp_scope_values(&catch.body, &catch_env);
                        if let Some(catch_value) = catch_value {
                            catch_cleanup_values.push(catch_value);
                            catch_cleanup_values.sort_unstable();
                            catch_cleanup_values.dedup();
                        }
                        // Catch parameters are scoped to the handler and must not leak into the
                        // environment merged after the try statement.
                        if let Some(symbol) = catch.symbol {
                            catch_env.remove(&symbol);
                        }
                        catch_env.retain(|symbol, _| value_map.contains_key(symbol));
                        // An exception raised while a handler is running must still execute the
                        // function's cleanup/finally path.
                        if let Some(finally_id) = finally_id {
                            for block in &catch_blocks {
                                for (source_inst, thrown_value) in
                                    Self::cpp_block_throw_sites(block)
                                {
                                    self.exception_edges.push(ExceptionEdge {
                                        from: block.id,
                                        unwind: finally_id,
                                        source_inst,
                                        thrown_value,
                                        catch_value: None,
                                        catch_type: None,
                                        is_cleanup: true,
                                        cleanup_values: catch_cleanup_values.clone(),
                                    });
                                }
                            }
                        }
                        blocks.append(&mut catch_blocks);
                        catch_envs.push(catch_env);
                    }

                    let mut merged_env = value_map
                        .keys()
                        .filter_map(|symbol| {
                            try_env.get(symbol).copied().map(|value| (*symbol, value))
                        })
                        .collect::<HashMap<_, _>>();
                    let mut merge_insts = Vec::new();
                    for catch_env in catch_envs {
                        let (next_env, mut phis) = self.merge_environments(
                            &merged_env,
                            &catch_env,
                            *span,
                            symbol_types,
                            locals,
                            value_types,
                            value_spans,
                        );
                        merged_env = next_env;
                        merge_insts.append(&mut phis);
                    }

                    if let (Some(finally_block), Some(finally_id)) = (finally_block, finally_id) {
                        let visible_symbols = merged_env.keys().copied().collect::<HashSet<_>>();
                        let (mut finally_blocks, mut finally_env) =
                            self.lower_stmt_sequence_with_prefix(
                                &finally_block.stmts,
                                finally_id,
                                merge_insts,
                                merged_env,
                                fallthrough.clone(),
                                symbol_types,
                                locals,
                                value_types,
                                value_spans,
                            );
                        finally_env.retain(|symbol, _| visible_symbols.contains(symbol));
                        blocks.append(&mut finally_blocks);
                        return (blocks, finally_env);
                    }

                    let (mut continuation, final_env) = self.lower_stmt_sequence_with_prefix(
                        &stmts[index + 1..],
                        merge_id,
                        merge_insts,
                        merged_env,
                        fallthrough,
                        symbol_types,
                        locals,
                        value_types,
                        value_spans,
                    );
                    blocks.append(&mut continuation);
                    return (blocks, final_env);
                }
            }
            index += 1;
        }

        (
            vec![BasicBlock {
                id: current_id,
                insts,
                term: fallthrough,
            }],
            value_map,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_stmt_sequence_with_prefix(
        &mut self,
        stmts: &[Stmt],
        current_id: BlockId,
        prefix: Vec<Instruction>,
        value_map: HashMap<SymbolId, ValueId>,
        fallthrough: Terminator,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (Vec<BasicBlock>, HashMap<SymbolId, ValueId>) {
        if prefix.is_empty() {
            return self.lower_stmt_sequence(
                stmts,
                current_id,
                value_map,
                fallthrough,
                symbol_types,
                locals,
                value_types,
                value_spans,
            );
        }
        if stmts.is_empty() {
            return (
                vec![BasicBlock {
                    id: current_id,
                    insts: prefix,
                    term: fallthrough,
                }],
                value_map,
            );
        }
        let bridge = self.alloc_block_id();
        let mut blocks = vec![BasicBlock {
            id: current_id,
            insts: prefix,
            term: Terminator::Goto(bridge),
        }];
        let (mut rest, env) = self.lower_stmt_sequence(
            stmts,
            bridge,
            value_map,
            fallthrough,
            symbol_types,
            locals,
            value_types,
            value_spans,
        );
        blocks.append(&mut rest);
        (blocks, env)
    }

    fn cpp_scope_values(
        block: &uniflow_hir::Block,
        environment: &HashMap<SymbolId, ValueId>,
    ) -> Vec<ValueId> {
        fn collect(block: &uniflow_hir::Block, symbols: &mut Vec<SymbolId>) {
            for statement in &block.stmts {
                match statement {
                    Stmt::Let { symbol, .. } => symbols.push(*symbol),
                    Stmt::If {
                        then_block,
                        else_block,
                        ..
                    } => {
                        collect(then_block, symbols);
                        if let Some(else_block) = else_block {
                            collect(else_block, symbols);
                        }
                    }
                    Stmt::While { body, .. } => collect(body, symbols),
                    Stmt::ForEach {
                        item_symbol, body, ..
                    } => {
                        symbols.push(*item_symbol);
                        collect(body, symbols);
                    }
                    Stmt::Try {
                        try_block,
                        catches,
                        finally_block,
                        ..
                    } => {
                        collect(try_block, symbols);
                        for catch in catches {
                            if let Some(symbol) = catch.symbol {
                                symbols.push(symbol);
                            }
                            collect(&catch.body, symbols);
                        }
                        if let Some(finally_block) = finally_block {
                            collect(finally_block, symbols);
                        }
                    }
                    Stmt::Assign { .. }
                    | Stmt::Expr { .. }
                    | Stmt::Return { .. }
                    | Stmt::Throw { .. } => {}
                }
            }
        }

        let mut symbols = Vec::new();
        collect(block, &mut symbols);
        let mut values = symbols
            .into_iter()
            .filter_map(|symbol| environment.get(&symbol).copied())
            .collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        values
    }

    fn cpp_block_throw_sites(block: &BasicBlock) -> Vec<(Option<InstId>, Option<ValueId>)> {
        let mut sites = block
            .insts
            .iter()
            .filter_map(|instruction| {
                matches!(&instruction.kind, InstKind::Call(_))
                    .then_some((Some(instruction.id), None))
            })
            .collect::<Vec<_>>();
        if let Terminator::Throw(value) = &block.term {
            sites.push((None, *value));
        }
        sites
    }

    fn cpp_exception_handler_indices(
        &self,
        catch_types: &[Option<String>],
        thrown_type: Option<&str>,
    ) -> Vec<usize> {
        if let Some(thrown_type) = thrown_type {
            // C++ selects the first compatible handler.  A catch-all is represented by a
            // missing type and therefore naturally terminates the search.
            return catch_types
                .iter()
                .enumerate()
                .find_map(|(index, catch_type)| {
                    self.cpp_exception_type_matches(thrown_type, catch_type.as_deref())
                        .then_some(index)
                })
                .into_iter()
                .collect();
        }

        // For a call whose dynamic exception type is unknown, every typed handler before the
        // first catch-all is feasible; handlers after catch(...) are unreachable.
        let mut out = Vec::new();
        for (index, catch_type) in catch_types.iter().enumerate() {
            out.push(index);
            if catch_type.is_none() {
                break;
            }
        }
        out
    }

    fn cpp_exception_type_matches(&self, thrown_type: &str, catch_type: Option<&str>) -> bool {
        let Some(catch_type) = catch_type else {
            return true;
        };
        fn normalize(value: &str) -> String {
            value
                .replace("const ", "")
                .replace("volatile ", "")
                .trim_end_matches("&&")
                .trim_end_matches('&')
                .trim()
                .to_string()
        }
        let thrown = normalize(thrown_type);
        let caught = normalize(catch_type);
        if thrown == caught {
            return true;
        }
        let thrown_base = thrown.trim_end_matches('*').trim();
        let caught_base = caught.trim_end_matches('*').trim();
        if thrown.ends_with('*') != caught.ends_with('*') {
            return false;
        }
        let mut work = vec![thrown_base.to_string()];
        let mut seen = std::collections::HashSet::new();
        while let Some(current) = work.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            for parent in self.owner.type_hierarchy.get(&current).into_iter().flatten() {
                if parent == caught_base {
                    return true;
                }
                work.push(parent.clone());
            }
        }
        false
    }

    #[allow(clippy::too_many_arguments)]
    fn merge_environments(
        &mut self,
        left: &HashMap<SymbolId, ValueId>,
        right: &HashMap<SymbolId, ValueId>,
        span: uniflow_hir::Span,
        symbol_types: &mut HashMap<SymbolId, String>,
        locals: &mut Vec<ValueId>,
        value_types: &mut IndexMap<ValueId, String>,
        value_spans: &mut IndexMap<ValueId, uniflow_hir::Span>,
    ) -> (HashMap<SymbolId, ValueId>, Vec<Instruction>) {
        let mut symbols = left.keys().copied().collect::<Vec<_>>();
        symbols.extend(right.keys().copied());
        symbols.sort_by_key(|symbol| symbol.0);
        symbols.dedup();

        let mut merged = HashMap::new();
        let mut insts = Vec::new();
        for symbol in symbols {
            match (left.get(&symbol).copied(), right.get(&symbol).copied()) {
                (Some(a), Some(b)) if a != b => {
                    let dst = self.alloc_value();
                    locals.push(dst);
                    value_spans.insert(dst, span);
                    if let Some(name) = symbol_types.get(&symbol).cloned() {
                        value_types.insert(dst, name);
                    }
                    insts.push(Instruction {
                        id: self.alloc_inst_id(),
                        kind: InstKind::Phi {
                            dst,
                            inputs: vec![a, b],
                        },
                        span,
                    });
                    merged.insert(symbol, dst);
                }
                (Some(value), _) | (_, Some(value)) => {
                    merged.insert(symbol, value);
                }
                (None, None) => {}
            }
        }
        (merged, insts)
    }
}
