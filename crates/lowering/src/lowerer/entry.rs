pub fn lower_program(program: &Program) -> IrProgram {
    let mut lowerer = Lowerer::new(program);
    for module in &program.modules {
        lowerer.lower_module(module);
    }
    lowerer.propagate_internal_call_return_types();
    lowerer.propagate_cpp_value_semantics();
    lowerer.finish()
}

fn propagate_value_array_extents(
    blocks: &[BasicBlock],
    extents: &mut IndexMap<ValueId, Vec<Option<ValueId>>>,
) {
    let mut changed = true;
    while changed {
        changed = false;
        for inst in blocks.iter().flat_map(|block| block.insts.iter()) {
            let propagated = match &inst.kind {
                InstKind::Copy { dst, src }
                | InstKind::Move { dst, src }
                | InstKind::Cast { dst, src, .. } => {
                    extents.get(src).cloned().map(|dims| (*dst, dims))
                }
                InstKind::LoadIndex { dst, base, .. } => extents.get(base).and_then(|dims| {
                    (dims.len() > 1).then(|| (*dst, dims[1..].to_vec()))
                }),
                InstKind::Phi { dst, inputs } if !inputs.is_empty() => {
                    extents.get(&inputs[0]).cloned().and_then(|candidate| {
                        inputs[1..]
                            .iter()
                            .all(|input| extents.get(input) == Some(&candidate))
                            .then_some((*dst, candidate))
                    })
                }
                _ => None,
            };
            if let Some((dst, dims)) = propagated {
                if extents.get(&dst) != Some(&dims) {
                    extents.insert(dst, dims);
                    changed = true;
                }
            }
        }
    }
}

fn lambda_function_name(enclosing_function: &str, id: uniflow_hir::ExprId, line_no: u32) -> String {
    format!("{enclosing_function}.__lambda_{}_{}", line_no, id.0)
}

/// Extract closures directly from HIR instead of requiring every language
/// frontend to manufacture duplicate top-level function items. The lambda
/// expression still remains in its enclosing body and represents construction
/// of the closure environment; this synthetic function represents invocation.
fn direct_lambda_functions(
    func: &HirFunction,
    symbol_names: &HashMap<SymbolId, String>,
) -> Vec<HirFunction> {
    let mut out = Vec::new();
    collect_block_lambdas(&func.body, &func.name, symbol_names, &mut out);
    out
}

fn assigned_lambda(expr: &Expr, name: &str) -> Option<HirFunction> {
    let Expr::Lambda { params, captures, body, span, .. } = expr else {
        return None;
    };
    Some(HirFunction {
        id: uniflow_hir::FunctionId(0),
        name: name.to_string(),
        symbol: None,
        params: params.clone(),
        captures: captures
            .iter()
            .map(|capture| uniflow_hir::Param {
                name: capture.name.clone(),
                symbol: capture.symbol,
                ty: capture.ty,
                kind: uniflow_hir::ParamKind::Positional,
                has_default: false,
                keyword_only: false,
                cpp: CppValueSemantics::default(),
                span: capture.span,
            })
            .collect(),
        receiver: None,
        return_type: None,
        cpp_initializers: Vec::new(),
        body: body.clone(),
        is_method: false,
        span: *span,
        cpp: None,
    })
}

fn collect_block_lambdas(
    block: &Block,
    enclosing: &str,
    symbol_names: &HashMap<SymbolId, String>,
    out: &mut Vec<HirFunction>,
) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Let { symbol, init, .. } => {
                if let Some(expr) = init {
                    if let Some(name) = symbol_names.get(symbol) {
                        if let Some(lambda) = assigned_lambda(expr, name) {
                            out.push(lambda);
                        } else {
                            collect_expr_lambdas(expr, enclosing, out);
                        }
                    } else {
                        collect_expr_lambdas(expr, enclosing, out);
                    }
                }
            }
            Stmt::Assign { lhs, rhs, .. } => {
                collect_lvalue_lambdas(lhs, enclosing, out);
                let assigned_name = match lhs {
                    LValue::Field { base, field } => match &**base {
                        Expr::VarRef { symbol, .. } => symbol_names
                            .get(symbol)
                            .map(|base| format!("{base}.{field}")),
                        _ => None,
                    },
                    LValue::Var(symbol) => symbol_names.get(symbol).cloned(),
                    LValue::Index { .. } => None,
                };
                if let Some(lambda) = assigned_name
                    .as_deref()
                    .and_then(|name| assigned_lambda(rhs, name))
                {
                    out.push(lambda);
                } else {
                    collect_expr_lambdas(rhs, enclosing, out);
                }
            }
            Stmt::Expr { expr, .. } => collect_expr_lambdas(expr, enclosing, out),
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                collect_expr_lambdas(cond, enclosing, out);
                collect_block_lambdas(then_block, enclosing, symbol_names, out);
                if let Some(block) = else_block {
                    collect_block_lambdas(block, enclosing, symbol_names, out);
                }
            }
            Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
                collect_expr_lambdas(cond, enclosing, out);
                collect_block_lambdas(body, enclosing, symbol_names, out);
            }
            Stmt::ForEach { iterable, body, .. } => {
                collect_expr_lambdas(iterable, enclosing, out);
                collect_block_lambdas(body, enclosing, symbol_names, out);
            }
            Stmt::For { init, cond, update, body, .. } => {
                collect_block_lambdas(init, enclosing, symbol_names, out);
                if let Some(cond) = cond { collect_expr_lambdas(cond, enclosing, out); }
                collect_block_lambdas(update, enclosing, symbol_names, out);
                collect_block_lambdas(body, enclosing, symbol_names, out);
            }
            Stmt::Return { value, .. } | Stmt::Throw { value, .. } => {
                if let Some(expr) = value {
                    collect_expr_lambdas(expr, enclosing, out);
                }
            }
            Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_block_lambdas(try_block, enclosing, symbol_names, out);
                for catch in catches {
                    collect_block_lambdas(&catch.body, enclosing, symbol_names, out);
                }
                if let Some(block) = finally_block {
                    collect_block_lambdas(block, enclosing, symbol_names, out);
                }
            }
            Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                collect_expr_lambdas(scrutinee, enclosing, out);
                for clause in clauses {
                    for value in &clause.values {
                        collect_expr_lambdas(value, enclosing, out);
                    }
                    collect_block_lambdas(&clause.body, enclosing, symbol_names, out);
                }
                if let Some(block) = default {
                    collect_block_lambdas(block, enclosing, symbol_names, out);
                }
            }
            Stmt::Break { .. } | Stmt::Continue { .. } => {}
        }
    }
}

fn collect_lvalue_lambdas(lvalue: &LValue, enclosing: &str, out: &mut Vec<HirFunction>) {
    match lvalue {
        LValue::Var(_) => {}
        LValue::Field { base, .. } => collect_expr_lambdas(base, enclosing, out),
        LValue::Index { base, index } => {
            collect_expr_lambdas(base, enclosing, out);
            collect_expr_lambdas(index, enclosing, out);
        }
    }
}

fn collect_expr_lambdas(expr: &Expr, enclosing: &str, out: &mut Vec<HirFunction>) {
    match expr {
        Expr::Lambda {
            id,
            params,
            captures,
            body,
            span,
        } => {
            out.push(HirFunction {
                id: uniflow_hir::FunctionId(0),
                name: lambda_function_name(enclosing, *id, span.start_line.max(1)),
                symbol: None,
                params: params.clone(),
                captures: captures
                    .iter()
                    .map(|capture| uniflow_hir::Param {
                        name: capture.name.clone(),
                        symbol: capture.symbol,
                        ty: capture.ty,
                        kind: uniflow_hir::ParamKind::Positional,
                        has_default: false,
                        keyword_only: false,
                        cpp: CppValueSemantics::default(),
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
        }
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => {
            collect_expr_lambdas(expr, enclosing, out)
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_expr_lambdas(lhs, enclosing, out);
            collect_expr_lambdas(rhs, enclosing, out);
        }
        Expr::FieldRead { base, .. } => collect_expr_lambdas(base, enclosing, out),
        Expr::IndexRead { base, index, .. } => {
            collect_expr_lambdas(base, enclosing, out);
            collect_expr_lambdas(index, enclosing, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_expr_lambdas(callee, enclosing, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_expr_lambdas(receiver, enclosing, out);
            }
            for arg in &call.args {
                collect_expr_lambdas(arg, enclosing, out);
            }
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_expr_lambdas(arg, enclosing, out);
            }
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_expr_lambdas(cond, enclosing, out);
            collect_expr_lambdas(then_expr, enclosing, out);
            collect_expr_lambdas(else_expr, enclosing, out);
        }
        Expr::Assign { lhs, rhs, .. } => {
            collect_lvalue_lambdas(lhs, enclosing, out);
            collect_expr_lambdas(rhs, enclosing, out);
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                collect_expr_lambdas(part, enclosing, out);
            }
        }
        Expr::Range { low, high, .. } => {
            collect_expr_lambdas(low, enclosing, out);
            collect_expr_lambdas(high, enclosing, out);
        }
        Expr::VarRef { .. } | Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {
        }
    }
}

fn remap_ir_span(source_maps: &[SourceMap], span: uniflow_hir::Span) -> uniflow_hir::Span {
    source_maps
        .iter()
        .find(|map| map.file.0 == span.file)
        .map_or(span, |map| map.remap_span(span))
}

fn span_has_source_origin(
    source_origins: &[SourceOriginRange],
    span: uniflow_hir::Span,
    kind: SourceOriginKind,
) -> bool {
    source_origins.iter().any(|origin| {
        origin.kind == kind
            && origin.file.0 == span.file
            && span.start_byte < origin.end_byte
            && origin.start_byte < span.end_byte
    })
}

struct Lowerer {
    language: Language,
    source_files: Vec<IrSourceFile>,
    functions: Vec<Function>,
    entry_points: Vec<FunctionId>,
    next_function_id: u32,
    next_block_id: u32,
    next_inst_id: u32,
    next_value_id: u32,
    hir_type_names: HashMap<TypeId, String>,
    hir_symbol_names: HashMap<SymbolId, String>,
    current_import_aliases: HashMap<String, String>,
    program_symbols: HashMap<SymbolId, uniflow_hir::Symbol>,
    lambda_captures: HashMap<String, Vec<String>>,
    type_hierarchy: IndexMap<String, Vec<String>>,
    source_maps: Vec<SourceMap>,
    source_origins: Vec<SourceOriginRange>,
}

impl Lowerer {
    fn new(program: &Program) -> Self {
        let mut hir_type_names = HashMap::new();
        for ty in &program.types {
            hir_type_names.insert(ty.id, ty.name.clone());
        }

        let hir_symbol_names = program
            .symbols
            .iter()
            .map(|symbol| (symbol.id, symbol.name.clone()))
            .collect::<HashMap<_, _>>();

        let mut lambda_captures = HashMap::new();
        for module in &program.modules {
            for item in &module.items {
                match item {
                    Item::Function(function) if !function.captures.is_empty() => {
                        lambda_captures.insert(
                            function.name.clone(),
                            function
                                .captures
                                .iter()
                                .map(|capture| capture.name.clone())
                                .collect(),
                        );
                    }
                    Item::Class(class) => {
                        for function in &class.methods {
                            if !function.captures.is_empty() {
                                lambda_captures.insert(
                                    function.name.clone(),
                                    function
                                        .captures
                                        .iter()
                                        .map(|capture| capture.name.clone())
                                        .collect(),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut type_hierarchy = IndexMap::new();
        for module in &program.modules {
            for item in &module.items {
                if let Item::Class(class) = item {
                    type_hierarchy.insert(class.name.clone(), class.bases.clone());
                }
            }
        }

        Self {
            language: program.language.clone(),
            source_files: program
                .files
                .iter()
                .map(|file| IrSourceFile {
                    id: file.id.0,
                    path: file.path.clone(),
                })
                .collect(),
            functions: Vec::new(),
            entry_points: Vec::new(),
            next_function_id: 0,
            next_block_id: 0,
            next_inst_id: 0,
            next_value_id: 0,
            hir_type_names,
            hir_symbol_names,
            current_import_aliases: HashMap::new(),
            program_symbols: program.symbols.iter().cloned().map(|s| (s.id, s)).collect(),
            lambda_captures,
            type_hierarchy,
            source_maps: program.source_maps.clone(),
            source_origins: program.source_origins.clone(),
        }
    }

    fn propagate_internal_call_return_types(&mut self) {
        let mut return_types = HashMap::new();
        let mut owner_method = HashMap::new();
        for func in &self.functions {
            if let Some(name) = ir_return_type_name(&func.return_type) {
                return_types.insert(func.name.clone(), name.to_string());
                if let Some(owner) = func.attrs.get("owner_type") {
                    if let Some(method) = func.name.rsplit('.').next() {
                        owner_method.insert((owner.clone(), method.to_string()), name.to_string());
                    }
                }
            }
        }

        for func in &mut self.functions {
            let known_types = func.value_types.clone();
            for block in &mut func.blocks {
                for inst in &block.insts {
                    let InstKind::Call(call) = &inst.kind else {
                        continue;
                    };
                    let Some(dst) = call.dst else {
                        continue;
                    };
                    if func.value_types.contains_key(&dst) {
                        continue;
                    }
                    let inferred = match &call.callee {
                        Callee::Static(name) => return_types.get(name).cloned().or_else(|| {
                            if let Some(receiver) = call
                                .receiver
                                .and_then(|value| known_types.get(&value).cloned())
                            {
                                if let Some(method) = name.rsplit('.').next() {
                                    owner_method.get(&(receiver, method.to_string())).cloned()
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }),
                        _ => None,
                    };
                    if let Some(name) = inferred {
                        func.value_types.insert(dst, name);
                    }
                }
            }
        }
    }

    fn propagate_cpp_value_semantics(&mut self) {
        for func in &mut self.functions {
            let mut changed = true;
            while changed {
                changed = false;
                for block in &func.blocks {
                    for inst in &block.insts {
                        match &inst.kind {
                            InstKind::Copy { dst, src }
                            | InstKind::Move { dst, src }
                            | InstKind::Cast { dst, src, .. } => {
                                if let Some(semantics) = func.value_cpp.get(src).cloned() {
                                    if func.value_cpp.get(dst) != Some(&semantics) {
                                        func.value_cpp.insert(*dst, semantics);
                                        changed = true;
                                    }
                                }
                            }
                            InstKind::Phi { dst, inputs } => {
                                let mut values = inputs
                                    .iter()
                                    .filter_map(|value| func.value_cpp.get(value).cloned())
                                    .collect::<Vec<_>>();
                                values.sort_by_key(|value| format!("{value:?}"));
                                values.dedup();
                                if values.len() == 1 && func.value_cpp.get(dst) != values.first() {
                                    func.value_cpp.insert(*dst, values.remove(0));
                                    changed = true;
                                }
                            }
                            InstKind::Call(call) => {
                                let Some(dst) = call.dst else { continue };
                                let method = match &call.callee {
                                    Callee::Static(name) => name
                                        .rsplit(|ch| ch == '.' || ch == ':')
                                        .next()
                                        .unwrap_or(name.as_str()),
                                    _ => "",
                                };
                                let inferred = match method {
                                    "lock" => call.receiver.and_then(|receiver| {
                                        func.value_cpp.get(&receiver).cloned().map(|mut cpp| {
                                            cpp.ownership = uniflow_hir::CppOwnershipKind::Shared;
                                            cpp.reference_kind =
                                                uniflow_hir::CppReferenceKind::None;
                                            cpp
                                        })
                                    }),
                                    "get" => call.receiver.and_then(|receiver| {
                                        func.value_cpp.get(&receiver).cloned().map(|mut cpp| {
                                            cpp.ownership = uniflow_hir::CppOwnershipKind::Borrowed;
                                            cpp.reference_kind =
                                                uniflow_hir::CppReferenceKind::LValue;
                                            cpp
                                        })
                                    }),
                                    _ => None,
                                };
                                if let Some(cpp) = inferred {
                                    if func.value_cpp.get(&dst) != Some(&cpp) {
                                        func.value_cpp.insert(dst, cpp);
                                        changed = true;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    fn finish(mut self) -> IrProgram {
        for function in &mut self.functions {
            let macro_values = function
                .value_spans
                .iter()
                .filter_map(|(value, span)| {
                    span_has_source_origin(
                        &self.source_origins,
                        *span,
                        SourceOriginKind::MacroExpansion,
                    )
                    .then_some(*value)
                })
                .collect::<Vec<_>>();
            let macro_insts = function
                .blocks
                .iter()
                .flat_map(|block| block.insts.iter())
                .filter_map(|instruction| {
                    span_has_source_origin(
                        &self.source_origins,
                        instruction.span,
                        SourceOriginKind::MacroExpansion,
                    )
                    .then_some(instruction.id)
                })
                .collect::<Vec<_>>();
            for value in macro_values {
                function.mark_value_source_origin(value, SourceOriginKind::MacroExpansion);
            }
            for inst in macro_insts {
                function.mark_instruction_source_origin(inst, SourceOriginKind::MacroExpansion);
            }
            function.span = remap_ir_span(&self.source_maps, function.span);
            for span in function.value_spans.values_mut() {
                *span = remap_ir_span(&self.source_maps, *span);
            }
            for block in &mut function.blocks {
                for instruction in &mut block.insts {
                    if let InstKind::Call(call) = &mut instruction.kind {
                        for span in &mut call.arg_spans {
                            *span = remap_ir_span(&self.source_maps, *span);
                        }
                    }
                    instruction.span = remap_ir_span(&self.source_maps, instruction.span);
                }
            }
        }
        IrProgram {
            language: self.language,
            source_files: self.source_files,
            functions: self.functions,
            entry_points: self.entry_points,
            type_hierarchy: self.type_hierarchy,
        }
    }

    fn lower_module(&mut self, module: &Module) {
        self.current_import_aliases.clear();
        for import in &module.imports {
            if let Some(alias) = import.alias.as_ref().filter(|alias| !alias.trim().is_empty()) {
                self.current_import_aliases
                    .insert(alias.clone(), import.path.clone());
            } else if let Some(name) = import
                .path
                .rsplit(['.', '/', ':'])
                .find(|name| !name.is_empty())
            {
                self.current_import_aliases
                    .insert(name.to_string(), import.path.clone());
            }
        }
        let mut queue = std::collections::VecDeque::<(HirFunction, Option<String>)>::new();
        let mut declared = HashSet::new();
        for item in &module.items {
            match item {
                Item::Function(func) => {
                    declared.insert(func.name.clone());
                    queue.push_back((func.clone(), None));
                }
                Item::Class(class) => {
                    for method in &class.methods {
                        declared.insert(method.name.clone());
                        queue.push_back((method.clone(), Some(class.name.clone())));
                    }
                }
                Item::GlobalVar(_) => {}
            }
        }
        let mut lowered = HashSet::new();
        while let Some((func, owner)) = queue.pop_front() {
            if !lowered.insert(func.name.clone()) {
                continue;
            }
            self.lower_function(&func, owner.as_deref());
            for lambda in direct_lambda_functions(&func, &self.hir_symbol_names) {
                if !declared.contains(&lambda.name) && !lowered.contains(&lambda.name) {
                    queue.push_back((lambda, None));
                }
            }
        }
    }

    fn lower_function(&mut self, func: &HirFunction, owner_type: Option<&str>) {
        let function_id = FunctionId(self.next_function_id);
        self.next_function_id += 1;
        self.entry_points.push(function_id);

        let param_type_names = func
            .params
            .iter()
            .map(|param| self.type_name_for(param.ty))
            .collect::<Vec<_>>();
        let capture_type_names = func
            .captures
            .iter()
            .map(|capture| self.type_name_for(capture.ty))
            .collect::<Vec<_>>();
        let receiver_type_name = func
            .receiver
            .as_ref()
            .and_then(|receiver| self.type_name_for(receiver.ty));
        let return_type_name = self.type_name_for(func.return_type);

        let mut ctx = FunctionLoweringContext::new(self, func.name.clone());
        let mut params = Vec::new();
        let mut locals = Vec::new();
        let mut value_map = HashMap::new();
        let mut symbol_types = HashMap::new();
        let mut value_types = IndexMap::new();
        let mut value_spans = IndexMap::new();
        let mut value_cpp = IndexMap::<ValueId, CppValueSemantics>::new();

        if let Some(receiver) = func.receiver.as_ref() {
            let value = ctx.alloc_value();
            params.push(value);
            value_map.insert(receiver.symbol, value);
            value_spans.insert(value, receiver.span);
            if let Some(name) = receiver_type_name.clone() {
                symbol_types.insert(receiver.symbol, name.clone());
                value_types.insert(value, name);
            }
            if receiver.cpp != CppValueSemantics::default() {
                value_cpp.insert(value, receiver.cpp.clone());
            }
        }

        for (param, param_type_name) in func.params.iter().zip(param_type_names.into_iter()) {
            let value = ctx.alloc_value();
            params.push(value);
            value_map.insert(param.symbol, value);
            value_spans.insert(value, param.span);
            if let Some(name) = param_type_name {
                symbol_types.insert(param.symbol, name.clone());
                value_types.insert(value, name);
            }
            if param.cpp != CppValueSemantics::default() {
                value_cpp.insert(value, param.cpp.clone());
            }
        }
        for (capture, capture_type_name) in func.captures.iter().zip(capture_type_names.into_iter())
        {
            let value = ctx.alloc_value();
            params.push(value);
            value_map.insert(capture.symbol, value);
            value_spans.insert(value, capture.span);
            if let Some(name) = capture_type_name {
                symbol_types.insert(capture.symbol, name.clone());
                value_types.insert(value, name);
            }
            if capture.cpp != CppValueSemantics::default() {
                value_cpp.insert(value, capture.cpp.clone());
            }
        }

        let mut extent_prelude = Vec::new();
        for param in &func.params {
            let array_extents = ctx
                .owner
                .program_symbols
                .get(&param.symbol)
                .map(|symbol| symbol.array_extents.clone())
                .unwrap_or_default();
            let Some(base) = value_map.get(&param.symbol).copied() else {
                continue;
            };
            if array_extents.is_empty() {
                continue;
            }
            let mut lowered_extents = Vec::with_capacity(array_extents.len());
            for extent in array_extents {
                let value = extent.map(|extent| {
                    ctx.lower_expr(
                        &extent,
                        &mut extent_prelude,
                        &mut value_map,
                        &mut symbol_types,
                        &mut locals,
                        &mut value_types,
                        &mut value_spans,
                    )
                    .0
                });
                lowered_extents.push(value);
            }
            ctx.value_array_extents.insert(base, lowered_extents);
        }

        let initializer_insts = ctx.lower_cpp_initializers(
            func,
            &value_map,
            &mut locals,
            &mut value_types,
            &mut value_spans,
        );
        let (mut blocks, final_value_map) = ctx.lower_cfg_body(
            &func.body,
            value_map,
            &mut symbol_types,
            &mut locals,
            &mut value_types,
            &mut value_spans,
        );
        if !extent_prelude.is_empty() || !initializer_insts.is_empty() {
            if let Some(entry) = blocks.first_mut() {
                let mut combined = extent_prelude;
                combined.extend(initializer_insts);
                combined.append(&mut entry.insts);
                entry.insts = combined;
            }
        }
        value_map = final_value_map;
        let exception_edges = std::mem::take(&mut ctx.exception_edges);
        let mut value_array_extents = std::mem::take(&mut ctx.value_array_extents);
        let source_case_blocks = std::mem::take(&mut ctx.source_case_blocks);
        let source_break_blocks = std::mem::take(&mut ctx.source_break_blocks);
        let source_return_blocks = std::mem::take(&mut ctx.source_return_blocks);
        let source_switch_blocks = std::mem::take(&mut ctx.source_switch_blocks);
        drop(ctx);
        propagate_value_array_extents(&blocks, &mut value_array_extents);
        for (symbol_id, value) in &value_map {
            if let Some(symbol) = self.program_symbols.get(symbol_id) {
                let semantics = symbol.cpp_value_semantics();
                if semantics != CppValueSemantics::default() {
                    value_cpp.insert(*value, semantics);
                }
            }
        }

        let mut attrs = IndexMap::new();
        if let Some(symbol_id) = func.symbol {
            if let Some(symbol) = self.program_symbols.get(&symbol_id) {
                for (key, value) in &symbol.attributes {
                    if key.starts_with("cpp.") || key.starts_with("python.") {
                        attrs.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        attrs.insert(
            "has_receiver".to_string(),
            if func.receiver.is_some() { "1" } else { "0" }.to_string(),
        );
        if let Some(owner_type) = owner_type {
            attrs.insert("owner_type".to_string(), owner_type.to_string());
            attrs.insert("arity".to_string(), func.params.len().to_string());
        } else {
            attrs.insert("arity".to_string(), func.params.len().to_string());
        }
        attrs.insert(
            "param_names".to_string(),
            func.params
                .iter()
                .map(|param| param.name.clone())
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
        attrs.insert(
            "param_kinds".to_string(),
            func.params
                .iter()
                .map(|param| match &param.kind {
                    uniflow_hir::ParamKind::Positional => "pos",
                    uniflow_hir::ParamKind::VarArgs => "var",
                    uniflow_hir::ParamKind::KwArgs => "kw",
                })
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
        attrs.insert(
            "param_defaults".to_string(),
            func.params
                .iter()
                .map(|param| if param.has_default { "1" } else { "0" })
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
        attrs.insert(
            "param_keyword_only".to_string(),
            func.params
                .iter()
                .map(|param| if param.keyword_only { "1" } else { "0" })
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
        attrs.insert(
            "capture_names".to_string(),
            func.captures
                .iter()
                .map(|capture| capture.name.clone())
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
        let mut value_names = value_map
            .iter()
            .filter_map(|(symbol, value)| {
                self.hir_symbol_names
                    .get(symbol)
                    .map(|name| (*value, name.clone()))
            })
            .collect::<Vec<_>>();
        value_names.sort_by_key(|(value, _)| value.0);
        value_names.dedup_by(|left, right| left.0 == right.0);
        attrs.insert(
            "value_names".to_string(),
            value_names
                .into_iter()
                .map(|(value, name)| format!("{}={name}", value.0))
                .collect::<Vec<_>>()
                .join("\u{1f}"),
        );
        for (block, span, from_macro) in source_case_blocks {
            let span = remap_ir_span(&self.source_maps, span);
            attrs.insert(
                format!("uniflow.source-cfg.case.{}", block.0),
                format!(
                    "{},{},{},{},{},{},{},{}",
                    span.file,
                    span.start_byte,
                    span.end_byte,
                    span.start_line,
                    span.start_col,
                    span.end_line,
                    span.end_col,
                    u8::from(from_macro)
                ),
            );
        }
        for block in source_break_blocks {
            attrs.insert(
                format!("uniflow.source-cfg.break.{}", block.0),
                "1".to_string(),
            );
        }
        for block in source_return_blocks {
            attrs.insert(
                format!("uniflow.source-cfg.return.{}", block.0),
                "1".to_string(),
            );
        }
        for block in source_switch_blocks {
            attrs.insert(
                format!("uniflow.source-cfg.switch.{}", block.0),
                "1".to_string(),
            );
        }

        let mut lowered_function = Function {
            id: function_id,
            name: func.name.clone(),
            params,
            locals,
            blocks,
            return_type: lower_type_name(return_type_name.as_deref()),
            is_external: false,
            span: func.span,
            attrs,
            value_types,
            value_spans,
            cpp: func.cpp.clone(),
            cpp_initializers: func.cpp_initializers.clone(),
            value_cpp,
            exception_edges,
        };
        for (value, extents) in value_array_extents {
            lowered_function.set_value_array_extents(value, &extents);
        }
        self.functions.push(lowered_function);
    }

    fn type_name_for(&self, ty: Option<TypeId>) -> Option<String> {
        ty.and_then(|id| self.hir_type_names.get(&id).cloned())
    }
}
