pub fn lower_program(program: &Program) -> IrProgram {
    let mut lowerer = Lowerer::new(program);
    for module in &program.modules {
        lowerer.lower_module(module);
    }
    lowerer.propagate_internal_call_return_types();
    lowerer.propagate_cpp_value_semantics();
    lowerer.finish()
}

fn lambda_function_name(enclosing_function: &str, id: uniflow_hir::ExprId, line_no: u32) -> String {
    format!("{enclosing_function}.__lambda_{}_{}", line_no, id.0)
}

fn remap_ir_span(source_maps: &[SourceMap], span: uniflow_hir::Span) -> uniflow_hir::Span {
    source_maps
        .iter()
        .find(|map| map.file.0 == span.file)
        .map_or(span, |map| map.remap_span(span))
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
    program_symbols: HashMap<SymbolId, uniflow_hir::Symbol>,
    type_hierarchy: IndexMap<String, Vec<String>>,
    source_maps: Vec<SourceMap>,
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
            program_symbols: program.symbols.iter().cloned().map(|s| (s.id, s)).collect(),
            type_hierarchy,
            source_maps: program.source_maps.clone(),
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
                            if let Some(receiver) = call.receiver.and_then(|value| known_types.get(&value).cloned()) {
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
                                            cpp.reference_kind = uniflow_hir::CppReferenceKind::None;
                                            cpp
                                        })
                                    }),
                                    "get" => call.receiver.and_then(|receiver| {
                                        func.value_cpp.get(&receiver).cloned().map(|mut cpp| {
                                            cpp.ownership = uniflow_hir::CppOwnershipKind::Borrowed;
                                            cpp.reference_kind = uniflow_hir::CppReferenceKind::LValue;
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
            function.span = remap_ir_span(&self.source_maps, function.span);
            for span in function.value_spans.values_mut() {
                *span = remap_ir_span(&self.source_maps, *span);
            }
            for block in &mut function.blocks {
                for instruction in &mut block.insts {
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
        for item in &module.items {
            match item {
                Item::Function(func) => self.lower_function(func, None),
                Item::Class(class) => {
                    for method in &class.methods {
                        self.lower_function(method, Some(class.name.as_str()));
                    }
                }
                Item::GlobalVar(_) => {}
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

        let mut ctx = FunctionLoweringContext::new(self, function_id, func.name.clone());
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
        for (capture, capture_type_name) in func.captures.iter().zip(capture_type_names.into_iter()) {
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
        if !initializer_insts.is_empty() {
            if let Some(entry) = blocks.first_mut() {
                let mut combined = initializer_insts;
                combined.append(&mut entry.insts);
                entry.insts = combined;
            }
        }
        value_map = final_value_map;
        let exception_edges = std::mem::take(&mut ctx.exception_edges);
        drop(ctx);
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
                    if key.starts_with("cpp.") {
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

        self.functions.push(Function {
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
        });
    }

    fn type_name_for(&self, ty: Option<TypeId>) -> Option<String> {
        ty.and_then(|id| self.hir_type_names.get(&id).cloned())
    }
}

