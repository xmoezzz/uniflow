impl Program {
    pub fn empty(language: Language) -> Self {
        Self {
            language,
            files: Vec::new(),
            modules: Vec::new(),
            symbols: Vec::new(),
            types: Vec::new(),
            source_maps: Vec::new(),
            source_origins: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: Program) {
        if matches!(&self.language, Language::Unknown) {
            self.language = other.language.clone();
        }
        let offsets = self.next_id_offsets();
        self.merge_with_offsets(other, offsets);
    }

    fn merge_with_offsets(&mut self, other: Program, offsets: IdOffsets) {

        let mut files = other.files;
        for file in &mut files {
            file.id.0 += offsets.file;
        }

        let mut symbols = other.symbols;
        for sym in &mut symbols {
            sym.id.0 += offsets.symbol;
            if let Some(module) = &mut sym.declared_in {
                module.0 += offsets.module;
            }
            remap_span(&mut sym.span, offsets.file);
            for extent in sym.array_extents.iter_mut().flatten() {
                remap_expr(extent, &offsets);
            }
        }

        let mut types = other.types;
        for ty in &mut types {
            ty.id.0 += offsets.ty;
        }

        let mut modules = other.modules;
        for module in &mut modules {
            remap_module(module, &offsets);
        }

        let mut source_maps = other.source_maps;
        for source_map in &mut source_maps {
            source_map.file.0 += offsets.file;
        }

        let mut source_origins = other.source_origins;
        for source_origin in &mut source_origins {
            source_origin.file.0 += offsets.file;
        }

        self.files.extend(files);
        self.modules.extend(modules);
        self.symbols.extend(symbols);
        self.types.extend(types);
        self.source_maps.extend(source_maps);
        self.source_origins.extend(source_origins);
    }

    fn next_id_offsets(&self) -> IdOffsets {
        let mut nested = NestedIdMaxima::default();
        let mut function = None;
        for symbol in &self.symbols {
            for extent in symbol.array_extents.iter().flatten() {
                observe_expr_ids(extent, &mut nested);
            }
        }
        for module in &self.modules {
            for item in &module.items {
                match item {
                    Item::Function(func) => {
                        observe_id(&mut function, func.id.0);
                        observe_block_ids(&func.body, &mut nested);
                    }
                    Item::Class(class) => {
                        for method in &class.methods {
                            observe_id(&mut function, method.id.0);
                            observe_block_ids(&method.body, &mut nested);
                        }
                    }
                    Item::GlobalVar(var) => {
                        if let Some(init) = &var.init {
                            observe_expr_ids(init, &mut nested);
                        }
                    }
                }
            }
        }

        IdOffsets {
            file: next_id(self.files.iter().map(|file| file.id.0).max()),
            module: next_id(self.modules.iter().map(|module| module.id.0).max()),
            function: next_id(function),
            block: next_id(nested.block),
            stmt: next_id(nested.stmt),
            expr: next_id(nested.expr),
            symbol: next_id(self.symbols.iter().map(|symbol| symbol.id.0).max()),
            ty: next_id(self.types.iter().map(|ty| ty.id.0).max()),
        }
    }
}

/// Incremental project-program merger that computes the existing program's ID
/// bounds once and then advances them from each incoming compilation unit.
///
/// Repeatedly calling [`Program::merge`] must rediscover the maximum IDs in the
/// entire accumulated program before every append, which is quadratic for a
/// project assembled from many files. Project frontends should keep one merger
/// for the whole scan instead.
pub struct ProgramMerger {
    program: Program,
    next: IdOffsets,
}

impl ProgramMerger {
    pub fn new(language: Language) -> Self {
        Self::from_program(Program::empty(language))
    }

    pub fn from_program(program: Program) -> Self {
        let next = program.next_id_offsets();
        Self { program, next }
    }

    pub fn merge(&mut self, other: Program) {
        if matches!(&self.program.language, Language::Unknown) {
            self.program.language = other.language.clone();
        }
        let incoming = other.next_id_offsets();
        self.program.merge_with_offsets(other, self.next);
        self.next.add(incoming);
    }

    pub fn finish(self) -> Program {
        self.program
    }
}

#[derive(Clone, Copy)]
struct IdOffsets {
    file: u32,
    module: u32,
    function: u32,
    block: u32,
    stmt: u32,
    expr: u32,
    symbol: u32,
    ty: u32,
}

impl IdOffsets {
    fn add(&mut self, other: Self) {
        self.file += other.file;
        self.module += other.module;
        self.function += other.function;
        self.block += other.block;
        self.stmt += other.stmt;
        self.expr += other.expr;
        self.symbol += other.symbol;
        self.ty += other.ty;
    }
}

#[derive(Default)]
struct NestedIdMaxima {
    block: Option<u32>,
    stmt: Option<u32>,
    expr: Option<u32>,
}

fn next_id(maximum: Option<u32>) -> u32 {
    maximum.map_or(0, |id| id + 1)
}

fn observe_id(maximum: &mut Option<u32>, id: u32) {
    *maximum = Some(maximum.map_or(id, |current| current.max(id)));
}

fn remap_span(span: &mut Span, file_offset: u32) {
    span.file += file_offset;
}

fn remap_module(module: &mut Module, offsets: &IdOffsets) {
    module.id.0 += offsets.module;
    module.file.0 += offsets.file;
    remap_span(&mut module.span, offsets.file);
    for import in &mut module.imports {
        remap_span(&mut import.span, offsets.file);
    }
    for item in &mut module.items {
        remap_item(item, offsets);
    }
}

fn remap_item(item: &mut Item, offsets: &IdOffsets) {
    match item {
        Item::Function(func) => remap_function(func, offsets),
        Item::Class(class) => {
            if let Some(symbol) = &mut class.symbol {
                symbol.0 += offsets.symbol;
            }
            remap_span(&mut class.span, offsets.file);
            for field in &mut class.fields {
                if let Some(symbol) = &mut field.symbol {
                    symbol.0 += offsets.symbol;
                }
                if let Some(ty) = &mut field.ty {
                    ty.0 += offsets.ty;
                }
                remap_span(&mut field.span, offsets.file);
            }
            for method in &mut class.methods {
                remap_function(method, offsets);
            }
        }
        Item::GlobalVar(var) => {
            if let Some(symbol) = &mut var.symbol {
                symbol.0 += offsets.symbol;
            }
            if let Some(ty) = &mut var.ty {
                ty.0 += offsets.ty;
            }
            if let Some(init) = &mut var.init {
                remap_expr(init, offsets);
            }
            remap_span(&mut var.span, offsets.file);
        }
    }
}

fn remap_function(func: &mut Function, offsets: &IdOffsets) {
    func.id.0 += offsets.function;
    if let Some(symbol) = &mut func.symbol {
        symbol.0 += offsets.symbol;
    }
    if let Some(ret) = &mut func.return_type {
        ret.0 += offsets.ty;
    }
    for param in &mut func.params {
        remap_param(param, offsets);
    }
    for capture in &mut func.captures {
        remap_param(capture, offsets);
    }
    if let Some(receiver) = &mut func.receiver {
        remap_param(receiver, offsets);
    }
    remap_block(&mut func.body, offsets);
    remap_span(&mut func.span, offsets.file);
}

fn remap_param(param: &mut Param, offsets: &IdOffsets) {
    param.symbol.0 += offsets.symbol;
    if let Some(ty) = &mut param.ty {
        ty.0 += offsets.ty;
    }
    remap_span(&mut param.span, offsets.file);
}

fn remap_block(block: &mut Block, offsets: &IdOffsets) {
    block.id.0 += offsets.block;
    remap_span(&mut block.span, offsets.file);
    for stmt in &mut block.stmts {
        remap_stmt(stmt, offsets);
    }
}

fn remap_stmt(stmt: &mut Stmt, offsets: &IdOffsets) {
    match stmt {
        Stmt::Let { id, symbol, ty, init, span } => {
            id.0 += offsets.stmt;
            symbol.0 += offsets.symbol;
            if let Some(ty) = ty {
                ty.0 += offsets.ty;
            }
            if let Some(init) = init {
                remap_expr(init, offsets);
            }
            remap_span(span, offsets.file);
        }
        Stmt::Assign { id, lhs, rhs, span } => {
            id.0 += offsets.stmt;
            remap_lvalue(lhs, offsets);
            remap_expr(rhs, offsets);
            remap_span(span, offsets.file);
        }
        Stmt::Expr { id, expr, span } => {
            id.0 += offsets.stmt;
            remap_expr(expr, offsets);
            remap_span(span, offsets.file);
        }
        Stmt::If { id, cond, then_block, else_block, span } => {
            id.0 += offsets.stmt;
            remap_expr(cond, offsets);
            remap_block(then_block, offsets);
            if let Some(else_block) = else_block {
                remap_block(else_block, offsets);
            }
            remap_span(span, offsets.file);
        }
        Stmt::While { id, cond, body, span } => {
            id.0 += offsets.stmt;
            remap_expr(cond, offsets);
            remap_block(body, offsets);
            remap_span(span, offsets.file);
        }
        Stmt::For { id, init, cond, update, body, span, .. } => {
            id.0 += offsets.stmt;
            remap_block(init, offsets);
            if let Some(cond) = cond { remap_expr(cond, offsets); }
            remap_block(update, offsets);
            remap_block(body, offsets);
            remap_span(span, offsets.file);
        }
        Stmt::ForEach { id, item_symbol, iterable, body, span } => {
            id.0 += offsets.stmt;
            item_symbol.0 += offsets.symbol;
            remap_expr(iterable, offsets);
            remap_block(body, offsets);
            remap_span(span, offsets.file);
        }
        Stmt::Return { id, value, span } | Stmt::Throw { id, value, span } => {
            id.0 += offsets.stmt;
            if let Some(value) = value {
                remap_expr(value, offsets);
            }
            remap_span(span, offsets.file);
        }
        Stmt::Break { id, span, .. } | Stmt::Continue { id, span, .. } => {
            id.0 += offsets.stmt;
            remap_span(span, offsets.file);
        }
        Stmt::DoWhile { id, body, cond, span } => {
            id.0 += offsets.stmt;
            remap_block(body, offsets);
            remap_expr(cond, offsets);
            remap_span(span, offsets.file);
        }
        Stmt::Switch { id, scrutinee, clauses, default, span } => {
            id.0 += offsets.stmt;
            remap_expr(scrutinee, offsets);
            for clause in clauses {
                for value in &mut clause.values {
                    remap_expr(value, offsets);
                }
                remap_block(&mut clause.body, offsets);
                remap_span(&mut clause.span, offsets.file);
            }
            if let Some(default) = default {
                remap_block(default, offsets);
            }
            remap_span(span, offsets.file);
        }
        Stmt::Try { id, try_block, catches, finally_block, span } => {
            id.0 += offsets.stmt;
            remap_block(try_block, offsets);
            for catch in catches {
                if let Some(symbol) = &mut catch.symbol {
                    symbol.0 += offsets.symbol;
                }
                if let Some(ty) = &mut catch.ty {
                    ty.0 += offsets.ty;
                }
                remap_block(&mut catch.body, offsets);
                remap_span(&mut catch.span, offsets.file);
            }
            if let Some(finally_block) = finally_block {
                remap_block(finally_block, offsets);
            }
            remap_span(span, offsets.file);
        }
    }
}

fn remap_lvalue(lhs: &mut LValue, offsets: &IdOffsets) {
    match lhs {
        LValue::Var(symbol) => symbol.0 += offsets.symbol,
        LValue::Field { base, .. } => remap_expr(base, offsets),
        LValue::Index { base, index } => {
            remap_expr(base, offsets);
            remap_expr(index, offsets);
        }
    }
}

fn remap_expr(expr: &mut Expr, offsets: &IdOffsets) {
    match expr {
        Expr::VarRef { id, symbol, span } => {
            id.0 += offsets.expr;
            symbol.0 += offsets.symbol;
            remap_span(span, offsets.file);
        }
        Expr::Literal { id, span, .. } => {
            id.0 += offsets.expr;
            remap_span(span, offsets.file);
        }
        Expr::Unary { id, expr, span, .. } => {
            id.0 += offsets.expr;
            remap_expr(expr, offsets);
            remap_span(span, offsets.file);
        }
        Expr::Binary { id, lhs, rhs, span, .. } => {
            id.0 += offsets.expr;
            remap_expr(lhs, offsets);
            remap_expr(rhs, offsets);
            remap_span(span, offsets.file);
        }
        Expr::FieldRead { id, base, span, .. } => {
            id.0 += offsets.expr;
            remap_expr(base, offsets);
            remap_span(span, offsets.file);
        }
        Expr::IndexRead { id, base, index, span } => {
            id.0 += offsets.expr;
            remap_expr(base, offsets);
            remap_expr(index, offsets);
            remap_span(span, offsets.file);
        }
        Expr::Call(call) => {
            call.id.0 += offsets.expr;
            match &mut call.target {
                CallTarget::Dynamic(callee) => remap_expr(callee, offsets),
                CallTarget::Resolved(symbol) => symbol.0 += offsets.symbol,
                CallTarget::Named(_) => {}
            }
            if let Some(receiver) = &mut call.receiver {
                remap_expr(receiver, offsets);
            }
            for arg in &mut call.args {
                remap_expr(arg, offsets);
            }
            remap_span(&mut call.span, offsets.file);
        }
        Expr::Lambda { id, params, captures, body, span } => {
            id.0 += offsets.expr;
            for param in params {
                remap_param(param, offsets);
            }
            for capture in captures {
                capture.source_symbol.0 += offsets.symbol;
                capture.symbol.0 += offsets.symbol;
                if let Some(ty) = &mut capture.ty {
                    ty.0 += offsets.ty;
                }
                remap_span(&mut capture.span, offsets.file);
            }
            remap_block(body, offsets);
            remap_span(span, offsets.file);
        }
        Expr::New { id, args, span, .. } => {
            id.0 += offsets.expr;
            for arg in args {
                remap_expr(arg, offsets);
            }
            remap_span(span, offsets.file);
        }
        Expr::Cast { id, ty, expr, span } => {
            id.0 += offsets.expr;
            if let Some(ty) = ty {
                ty.0 += offsets.ty;
            }
            remap_expr(expr, offsets);
            remap_span(span, offsets.file);
        }
        Expr::Conditional { id, cond, then_expr, else_expr, span } => {
            id.0 += offsets.expr;
            remap_expr(cond, offsets);
            remap_expr(then_expr, offsets);
            remap_expr(else_expr, offsets);
            remap_span(span, offsets.file);
        }
        Expr::Assign { id, lhs, rhs, span } => {
            id.0 += offsets.expr;
            remap_lvalue(lhs, offsets);
            remap_expr(rhs, offsets);
            remap_span(span, offsets.file);
        }
        Expr::Interp { id, parts, span } => {
            id.0 += offsets.expr;
            for part in parts {
                remap_expr(part, offsets);
            }
            remap_span(span, offsets.file);
        }
        Expr::Collection { id, elements, span, .. } => {
            id.0 += offsets.expr;
            for element in elements {
                remap_expr(element, offsets);
            }
            remap_span(span, offsets.file);
        }
        Expr::Range { id, low, high, span, .. } => {
            id.0 += offsets.expr;
            remap_expr(low, offsets);
            remap_expr(high, offsets);
            remap_span(span, offsets.file);
        }
        Expr::Opaque { id, span, .. } => {
            id.0 += offsets.expr;
            remap_span(span, offsets.file);
        }
        Expr::Unknown { id, span, .. } => {
            id.0 += offsets.expr;
            remap_span(span, offsets.file);
        }
    }
}

fn observe_block_ids(block: &Block, ids: &mut NestedIdMaxima) {
    observe_id(&mut ids.block, block.id.0);
    for stmt in &block.stmts {
        observe_stmt_ids(stmt, ids);
    }
}

fn observe_stmt_ids(stmt: &Stmt, ids: &mut NestedIdMaxima) {
    let stmt_id = match stmt {
        Stmt::Let { id, init, .. } => {
            if let Some(init) = init {
                observe_expr_ids(init, ids);
            }
            id
        }
        Stmt::Assign { id, lhs, rhs, .. } => {
            observe_lvalue_expr_ids(lhs, ids);
            observe_expr_ids(rhs, ids);
            id
        }
        Stmt::Expr { id, expr, .. } => {
            observe_expr_ids(expr, ids);
            id
        }
        Stmt::If { id, cond, then_block, else_block, .. } => {
            observe_expr_ids(cond, ids);
            observe_block_ids(then_block, ids);
            if let Some(else_block) = else_block {
                observe_block_ids(else_block, ids);
            }
            id
        }
        Stmt::While { id, cond, body, .. } => {
            observe_expr_ids(cond, ids);
            observe_block_ids(body, ids);
            id
        }
        Stmt::For { id, init, cond, update, body, .. } => {
            observe_block_ids(init, ids);
            if let Some(cond) = cond {
                observe_expr_ids(cond, ids);
            }
            observe_block_ids(update, ids);
            observe_block_ids(body, ids);
            id
        }
        Stmt::ForEach { id, iterable, body, .. } => {
            observe_expr_ids(iterable, ids);
            observe_block_ids(body, ids);
            id
        }
        Stmt::Return { id, value, .. } | Stmt::Throw { id, value, .. } => {
            if let Some(value) = value {
                observe_expr_ids(value, ids);
            }
            id
        }
        Stmt::Break { id, .. } | Stmt::Continue { id, .. } => id,
        Stmt::DoWhile { id, body, cond, .. } => {
            observe_block_ids(body, ids);
            observe_expr_ids(cond, ids);
            id
        }
        Stmt::Switch { id, scrutinee, clauses, default, .. } => {
            observe_expr_ids(scrutinee, ids);
            for clause in clauses {
                for value in &clause.values {
                    observe_expr_ids(value, ids);
                }
                observe_block_ids(&clause.body, ids);
            }
            if let Some(default) = default {
                observe_block_ids(default, ids);
            }
            id
        }
        Stmt::Try { id, try_block, catches, finally_block, .. } => {
            observe_block_ids(try_block, ids);
            for catch in catches {
                observe_block_ids(&catch.body, ids);
            }
            if let Some(finally_block) = finally_block {
                observe_block_ids(finally_block, ids);
            }
            id
        }
    };
    observe_id(&mut ids.stmt, stmt_id.0);
}

fn observe_lvalue_expr_ids(lhs: &LValue, ids: &mut NestedIdMaxima) {
    match lhs {
        LValue::Var(_) => {}
        LValue::Field { base, .. } => observe_expr_ids(base, ids),
        LValue::Index { base, index } => {
            observe_expr_ids(base, ids);
            observe_expr_ids(index, ids);
        }
    }
}

fn observe_expr_ids(expr: &Expr, ids: &mut NestedIdMaxima) {
    let expr_id = match expr {
        Expr::VarRef { id, .. } | Expr::Literal { id, .. } | Expr::Unknown { id, .. } => id,
        Expr::Unary { id, expr, .. } | Expr::Cast { id, expr, .. } => {
            observe_expr_ids(expr, ids);
            id
        }
        Expr::Binary { id, lhs, rhs, .. } => {
            observe_expr_ids(lhs, ids);
            observe_expr_ids(rhs, ids);
            id
        }
        Expr::FieldRead { id, base, .. } => {
            observe_expr_ids(base, ids);
            id
        }
        Expr::IndexRead { id, base, index, .. } => {
            observe_expr_ids(base, ids);
            observe_expr_ids(index, ids);
            id
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                observe_expr_ids(callee, ids);
            }
            if let Some(receiver) = &call.receiver {
                observe_expr_ids(receiver, ids);
            }
            for arg in &call.args {
                observe_expr_ids(arg, ids);
            }
            &call.id
        }
        Expr::Lambda { id, body, .. } => {
            observe_block_ids(body, ids);
            id
        }
        Expr::New { id, args, .. } => {
            for arg in args {
                observe_expr_ids(arg, ids);
            }
            id
        }
        Expr::Conditional { id, cond, then_expr, else_expr, .. } => {
            observe_expr_ids(cond, ids);
            observe_expr_ids(then_expr, ids);
            observe_expr_ids(else_expr, ids);
            id
        }
        Expr::Assign { id, lhs, rhs, .. } => {
            observe_lvalue_expr_ids(lhs, ids);
            observe_expr_ids(rhs, ids);
            id
        }
        Expr::Interp { id, parts, .. } | Expr::Collection { id, elements: parts, .. } => {
            for part in parts {
                observe_expr_ids(part, ids);
            }
            id
        }
        Expr::Range { id, low, high, .. } => {
            observe_expr_ids(low, ids);
            observe_expr_ids(high, ids);
            id
        }
        Expr::Opaque { id, .. } => id,
    };
    observe_id(&mut ids.expr, expr_id.0);
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    fn program_with_lambda_ids() -> Program {
        let span = Span::default();
        Program {
            language: Language::Rust,
            files: vec![SourceFile {
                id: FileId(0),
                path: "unit.rs".to_string(),
            }],
            modules: vec![Module {
                id: ModuleId(0),
                file: FileId(0),
                name: "unit".to_string(),
                imports: vec![],
                items: vec![Item::Function(Function {
                    id: FunctionId(0),
                    name: "outer".to_string(),
                    symbol: None,
                    params: vec![],
                    captures: vec![],
                    return_type: None,
                    body: Block {
                        id: BlockId(0),
                        stmts: vec![Stmt::Expr {
                            id: StmtId(200),
                            expr: Expr::Lambda {
                                id: ExprId(3),
                                params: vec![],
                                captures: vec![],
                                body: Block {
                                    id: BlockId(1),
                                    stmts: vec![Stmt::Expr {
                                        id: StmtId(2),
                                        expr: Expr::Literal {
                                            id: ExprId(10),
                                            kind: LiteralKind::Int(1),
                                            span,
                                        },
                                        span,
                                    }],
                                    span,
                                },
                                span,
                            },
                            span,
                        }],
                        span,
                    },
                    is_method: false,
                    receiver: None,
                    cpp: None,
                    cpp_initializers: vec![],
                    span,
                })],
                span,
            }],
            symbols: vec![],
            types: vec![],
            source_maps: vec![],
            source_origins: vec![],
        }
    }

    #[test]
    fn call_targets_participate_in_id_remapping_and_collection() {
        let offsets = IdOffsets { file: 4, module: 0, function: 0, block: 0, stmt: 0, expr: 100, symbol: 20, ty: 30 };
        let span = Span { file: 1, ..Span::default() };
        let mut call = Expr::Call(CallExpr {
            id: ExprId(1),
            target: CallTarget::Dynamic(Box::new(Expr::Cast {
                id: ExprId(90), ty: Some(TypeId(2)), span,
                expr: Box::new(Expr::VarRef { id: ExprId(99), symbol: SymbolId(3), span }),
            })),
            receiver: None, qualifier_is_explicit: false, args: vec![], arg_names: vec![], span,
        });
        let mut ids = NestedIdMaxima::default();
        observe_expr_ids(&call, &mut ids);
        assert_eq!(ids.expr, Some(99), "callee IDs can exceed the outer call ID");
        remap_expr(&mut call, &offsets);
        let Expr::Call(call) = &mut call else { unreachable!() };
        let CallTarget::Dynamic(callee) = &call.target else { unreachable!() };
        let Expr::Cast { id, ty, expr, span } = callee.as_ref() else { unreachable!() };
        assert_eq!((*id, *ty, span.file), (ExprId(190), Some(TypeId(32)), 5));
        let Expr::VarRef { id, symbol, span } = expr.as_ref() else { unreachable!() };
        assert_eq!((*id, *symbol, span.file), (ExprId(199), SymbolId(23), 5));
        call.target = CallTarget::Resolved(SymbolId(7));
        let mut resolved = Expr::Call(call.clone());
        remap_expr(&mut resolved, &offsets);
        assert!(matches!(resolved, Expr::Call(CallExpr { target: CallTarget::Resolved(SymbolId(27)), .. })));
    }

    #[test]
    fn project_merger_tracks_lambda_blocks_and_independent_id_namespaces() {
        let unit = program_with_lambda_ids();
        let mut merger = ProgramMerger::new(Language::Rust);
        merger.merge(unit.clone());
        merger.merge(unit);
        let project = merger.finish();

        let Item::Function(second) = &project.modules[1].items[0] else {
            panic!("expected second function");
        };
        assert_eq!(second.body.id, BlockId(2));
        let Stmt::Expr { id, expr, .. } = &second.body.stmts[0] else {
            panic!("expected outer expression statement");
        };
        assert_eq!(*id, StmtId(401));
        let Expr::Lambda { id, body, .. } = expr else {
            panic!("expected lambda");
        };
        assert_eq!(*id, ExprId(14));
        assert_eq!(body.id, BlockId(3));
        let Stmt::Expr { id, expr, .. } = &body.stmts[0] else {
            panic!("expected lambda expression statement");
        };
        assert_eq!(*id, StmtId(203));
        assert!(matches!(expr, Expr::Literal { id: ExprId(21), .. }));
    }
}
