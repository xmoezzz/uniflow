use indexmap::IndexMap;
use std::collections::HashMap;
use uniflow_hir::{
    Block, CallExpr, CallTarget, Expr, Function as HirFunction, Item, Language, LiteralKind, LValue,
    Module, Program, Stmt, SymbolId, TypeId,
};
use uniflow_ir::{
    BasicBlock, BlockId, CallInst, Callee, Function, FunctionId, InstId, InstKind, Instruction,
    Program as IrProgram, SourceFile as IrSourceFile, Terminator, Type, ValueId,
};

pub fn lower_program(program: &Program) -> IrProgram {
    let mut lowerer = Lowerer::new(program);
    for module in &program.modules {
        lowerer.lower_module(module);
    }
    lowerer.propagate_internal_call_return_types();
    lowerer.finish()
}

fn lambda_function_name(enclosing_function: &str, id: uniflow_hir::ExprId, line_no: u32) -> String {
    format!("{enclosing_function}.__lambda_{}_{}", line_no, id.0)
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
    type_hierarchy: IndexMap<String, Vec<String>>,
}

impl Lowerer {
    fn new(program: &Program) -> Self {
        let mut hir_type_names = HashMap::new();
        for ty in &program.types {
            hir_type_names.insert(ty.id, ty.name.clone());
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
            type_hierarchy,
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

    fn finish(self) -> IrProgram {
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

        if let Some(receiver) = func.receiver.as_ref() {
            let value = ctx.alloc_value();
            params.push(value);
            value_map.insert(receiver.symbol, value);
            value_spans.insert(value, receiver.span);
            if let Some(name) = receiver_type_name.clone() {
                symbol_types.insert(receiver.symbol, name.clone());
                value_types.insert(value, name);
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
        }

        let mut insts = Vec::new();
        let term = ctx.lower_block_into(
            &func.body,
            &mut insts,
            &mut value_map,
            &mut symbol_types,
            &mut locals,
            &mut value_types,
            &mut value_spans,
        );
        let block_id = ctx.alloc_block_id();
        drop(ctx);

        let mut attrs = IndexMap::new();
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
                .map(|param| match param.kind {
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

        self.functions.push(Function {
            id: function_id,
            name: func.name.clone(),
            params,
            locals,
            blocks: vec![BasicBlock {
                id: block_id,
                insts,
                term,
            }],
            return_type: lower_type_name(return_type_name.as_deref()),
            is_external: false,
            span: func.span,
            attrs,
            value_types,
            value_spans,
        });
    }

    fn type_name_for(&self, ty: Option<TypeId>) -> Option<String> {
        ty.and_then(|id| self.hir_type_names.get(&id).cloned())
    }
}

struct FunctionLoweringContext<'a> {
    owner: &'a mut Lowerer,
    function_id: FunctionId,
    current_function_name: String,
}

impl<'a> FunctionLoweringContext<'a> {
    fn new(owner: &'a mut Lowerer, function_id: FunctionId, current_function_name: String) -> Self {
        Self { owner, function_id, current_function_name }
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
                            let dst = value_map.get(symbol).copied().unwrap_or_else(|| {
                                let new_value = self.alloc_value();
                                locals.push(new_value);
                                value_map.insert(*symbol, new_value);
                                value_spans.insert(new_value, *span);
                                new_value
                            });
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
                    let fresh = self.alloc_value();
                    locals.push(fresh);
                    value_map.insert(*symbol, fresh);
                    value_spans.insert(fresh, *span);
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
                self.push_inst(insts, InstKind::Call(CallInst {
                    dst: Some(dst),
                    callee,
                    receiver,
                    args,
                    arg_names: call.arg_names.clone(),
                }), call.span);
                let inferred = infer_call_return_type(call, receiver_ty.as_deref());
                if let Some(name) = inferred.clone() {
                    value_types.insert(dst, name);
                }
                (dst, inferred)
            }
            Expr::Cast { expr, ty, .. } => {
                let (value, inner_ty) = self.lower_expr(expr, insts, value_map, symbol_types, locals, value_types, value_spans);
                let explicit_ty = self.owner.type_name_for(*ty).or(inner_ty);
                if let Some(name) = explicit_ty.clone() {
                    value_types.insert(value, name);
                }
                (value, explicit_ty)
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
            Expr::New { type_name, span, .. } => {
                let dst = self.alloc_value();
                locals.push(dst);
                value_spans.insert(dst, *span);
                self.push_inst(insts, InstKind::ConstString { dst, value: format!("<new:{type_name}>") }, *span);
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

fn infer_call_return_type(call: &CallExpr, receiver_ty: Option<&str>) -> Option<String> {
    match &call.target {
        CallTarget::Named(name) => {
            if let Some(ty) = receiver_ty {
                if let Some(method) = name.rsplit('.').next() {
                    if matches!(method, "append" | "add" | "put" | "push") {
                        return Some(ty.to_string());
                    }
                    if method == "pop" {
                        if let Some(inner) = ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                            return Some(inner.to_string());
                        }
                        if let Some(inner) = ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                            if let Some((_, value)) = inner.split_once(',') {
                                return Some(value.trim().to_string());
                            }
                        }
                    }
                    if matches!(method, "get" | "setdefault") {
                        if let Some(inner) = ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                            if let Some((_, value)) = inner.split_once(',') {
                                return Some(value.trim().to_string());
                            }
                        }
                    }
                    if method == "copy" {
                        return Some(ty.to_string());
                    }
                    if method == "dumps" && ty == "json" {
                        return Some("str".to_string());
                    }
                }
            }
            if let Some((prefix, method)) = name.rsplit_once('.') {
                if method == "builder" || method == "newBuilder" {
                    return Some(prefix.to_string());
                }
            }
            match name.as_str() {
                "str" | "java.lang.String.valueOf" => Some("String".to_string()),
                "json.dumps" => Some("str".to_string()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn ir_return_type_name(ty: &Type) -> Option<&str> {
    match ty {
        Type::Void | Type::Unknown => None,
        Type::Bool => Some("boolean"),
        Type::Int => Some("int"),
        Type::Float => Some("double"),
        Type::String => Some("java.lang.String"),
        Type::Object(name) => Some(name.as_str()),
        Type::Function => Some("Function"),
    }
}

fn lower_callee(target: &CallTarget) -> Callee {
    match target {
        CallTarget::Named(name) => Callee::Static(name.clone()),
        CallTarget::Dynamic(_) => Callee::Unknown,
        CallTarget::Resolved(symbol) => Callee::Static(format!("symbol#{}", symbol.0)),
    }
}

fn lower_type_name(name: Option<&str>) -> Type {
    match name.unwrap_or("unknown") {
        "void" => Type::Void,
        "bool" | "boolean" => Type::Bool,
        "int" | "i32" | "i64" => Type::Int,
        "float" | "double" => Type::Float,
        "String" | "str" | "java.lang.String" => Type::String,
        other => Type::Object(other.to_string()),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_lang_python::PythonParser;
    use uniflow_parser_core::SourceParser;

    #[test]
    fn lowering_expands_python_destructuring_into_index_loads() {
        let src = r#"
def load_pair():
    return source()

def handle(payload):
    left, right = load_pair()
    for key, value in payload.items():
        right = value
    return right
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(inst.kind, InstKind::LoadIndex { .. })));
    }

    #[test]
    fn lowering_preserves_resolved_python_callable_alias_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    runner = load
    return runner(cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }


    #[test]
    fn lowering_keeps_python_control_flow_inputs_live() {
        let src = r#"
from flask import request

def handle(items):
    if request.args.get("cmd"):
        pass
    for item in items:
        value = item
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(inst.kind, InstKind::Call(_))));
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| matches!(inst.kind, InstKind::Copy { .. })));
    }
    #[test]
    fn lowering_preserves_callable_field_value_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

class Service:
    def handle(self, cmd):
        self.cb = load
        return self.cb(cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.Service.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_indexed_callable_value_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import load

def handle(cmd):
    handlers = [load]
    return handlers[0](cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_alias_backed_callable_field_targets() {
        let entries = vec![
            (
                "repo.py".to_string(),
                "def load(cmd):
    return cmd

class Service:
    pass
".to_string(),
            ),
            (
                "app.py".to_string(),
                "from repo import Service, load

def handle(cmd):
    svc = Service()
    alias = svc
    alias.cb = load
    return svc.cb(cmd)
".to_string(),
            ),
        ];
        let hir = uniflow_lang_python::parse_project_sources(&entries).expect("parse project");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("app.handle").expect("function");
        assert!(func.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::Call(call) => matches!(&call.callee, Callee::Static(name) if name == "repo.load"),
            _ => false,
        }));
    }

    #[test]
    fn lowering_preserves_lambda_capture_bindings() {
        let src = r#"
def handle(cmd):
    cb = lambda x: cmd
    return cb("safe")
"#;
        let hir = uniflow_lang_python::PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let handle = ir.find_function_by_name("handle").expect("handle function");
        assert!(handle.blocks.iter().flat_map(|block| block.insts.iter()).any(|inst| match &inst.kind {
            InstKind::StoreField { field, .. } => field == "__capture__cmd",
            _ => false,
        }));
        let lambda = ir.functions.iter().find(|func| func.name.contains("__lambda_")).expect("lambda function");
        assert_eq!(lambda.attrs.get("capture_names").map(|s| s.as_str()), Some("cmd"));
        assert_eq!(lambda.params.len(), 2);
    }

    #[test]
    fn lowering_preserves_lambda_callable_value_types() {
        let src = r#"
def handle(cmd):
    cb = lambda x: x
    return cb(cmd)
"#;
        let hir = PythonParser.parse_file("app.py", src).expect("parse ok");
        let ir = lower_program(&hir);
        let func = ir.find_function_by_name("handle").expect("function");
        assert!(func.value_types.values().any(|ty| ty.contains("__lambda_")));
    }

}
