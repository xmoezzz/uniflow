impl Program {
    pub fn empty(language: Language) -> Self {
        Self {
            language,
            files: Vec::new(),
            modules: Vec::new(),
            symbols: Vec::new(),
            types: Vec::new(),
            source_maps: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: Program) {
        if matches!(&self.language, Language::Unknown) {
            self.language = other.language.clone();
        }
        let offsets = IdOffsets {
            file: self.next_file_id(),
            module: self.next_module_id(),
            function: self.next_function_id(),
            block: self.next_block_id(),
            stmt: self.next_stmt_id(),
            expr: self.next_expr_id(),
            symbol: self.next_symbol_id(),
            ty: self.next_type_id(),
        };

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

        self.files.extend(files);
        self.modules.extend(modules);
        self.symbols.extend(symbols);
        self.types.extend(types);
        self.source_maps.extend(source_maps);
    }

    fn next_file_id(&self) -> u32 {
        self.files.iter().map(|f| f.id.0).max().map_or(0, |v| v + 1)
    }
    fn next_module_id(&self) -> u32 {
        self.modules.iter().map(|m| m.id.0).max().map_or(0, |v| v + 1)
    }
    fn next_function_id(&self) -> u32 {
        let mut max_id = 0;
        for module in &self.modules {
            for item in &module.items {
                match item {
                    Item::Function(func) => max_id = max_id.max(func.id.0),
                    Item::Class(class) => {
                        for method in &class.methods {
                            max_id = max_id.max(method.id.0);
                        }
                    }
                    Item::GlobalVar(_) => {}
                }
            }
        }
        if self.modules.is_empty() { 0 } else { max_id + 1 }
    }
    fn next_block_id(&self) -> u32 {
        let mut ids = Vec::new();
        for module in &self.modules {
            for item in &module.items {
                collect_item_block_ids(item, &mut ids);
            }
        }
        ids.into_iter().max().map_or(0, |v| v + 1)
    }
    fn next_stmt_id(&self) -> u32 {
        let mut ids = Vec::new();
        for module in &self.modules {
            for item in &module.items {
                collect_item_stmt_ids(item, &mut ids);
            }
        }
        ids.into_iter().max().map_or(0, |v| v + 1)
    }
    fn next_expr_id(&self) -> u32 {
        let mut ids = Vec::new();
        for module in &self.modules {
            for item in &module.items {
                collect_item_expr_ids(item, &mut ids);
            }
        }
        ids.into_iter().max().map_or(0, |v| v + 1)
    }
    fn next_symbol_id(&self) -> u32 {
        self.symbols.iter().map(|s| s.id.0).max().map_or(0, |v| v + 1)
    }
    fn next_type_id(&self) -> u32 {
        self.types.iter().map(|t| t.id.0).max().map_or(0, |v| v + 1)
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

fn collect_item_block_ids(item: &Item, out: &mut Vec<u32>) {
    match item {
        Item::Function(func) => collect_function_block_ids(func, out),
        Item::Class(class) => {
            for method in &class.methods {
                collect_function_block_ids(method, out);
            }
        }
        Item::GlobalVar(_) => {}
    }
}
fn collect_function_block_ids(func: &Function, out: &mut Vec<u32>) {
    collect_block_ids(&func.body, out);
}
fn collect_block_ids(block: &Block, out: &mut Vec<u32>) {
    out.push(block.id.0);
    for stmt in &block.stmts {
        match stmt {
            Stmt::For { init, update, body, .. } => {
                collect_block_ids(init, out);
                collect_block_ids(update, out);
                collect_block_ids(body, out);
            }
            Stmt::If { then_block, else_block, .. } => {
                collect_block_ids(then_block, out);
                if let Some(else_block) = else_block {
                    collect_block_ids(else_block, out);
                }
            }
            Stmt::While { body, .. } | Stmt::ForEach { body, .. } | Stmt::DoWhile { body, .. } => {
                collect_block_ids(body, out)
            }
            Stmt::Switch { clauses, default, .. } => {
                for clause in clauses {
                    collect_block_ids(&clause.body, out);
                }
                if let Some(default) = default {
                    collect_block_ids(default, out);
                }
            }
            Stmt::Try { try_block, catches, finally_block, .. } => {
                collect_block_ids(try_block, out);
                for catch in catches {
                    collect_block_ids(&catch.body, out);
                }
                if let Some(finally_block) = finally_block {
                    collect_block_ids(finally_block, out);
                }
            }
            _ => {}
        }
    }
}
fn collect_item_stmt_ids(item: &Item, out: &mut Vec<u32>) {
    match item {
        Item::Function(func) => collect_stmt_ids(&func.body, out),
        Item::Class(class) => {
            for method in &class.methods {
                collect_stmt_ids(&method.body, out);
            }
        }
        Item::GlobalVar(_) => {}
    }
}
fn collect_stmt_ids(block: &Block, out: &mut Vec<u32>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::For { id, init, cond, update, body, .. } => {
                out.push(id.0);
                collect_stmt_ids(init, out);
                if let Some(cond) = cond { collect_expr_ids(cond, out); }
                collect_stmt_ids(update, out);
                collect_stmt_ids(body, out);
            }
            Stmt::Let { id, init, .. } => {
                out.push(id.0);
                if let Some(init) = init { collect_expr_ids(init, out); }
            }
            Stmt::Assign { id, lhs, rhs, .. } => {
                out.push(id.0);
                collect_lvalue_expr_ids(lhs, out);
                collect_expr_ids(rhs, out);
            }
            Stmt::Expr { id, expr, .. } => { out.push(id.0); collect_expr_ids(expr, out); }
            Stmt::If { id, cond, then_block, else_block, .. } => {
                out.push(id.0); collect_expr_ids(cond, out); collect_stmt_ids(then_block, out); if let Some(else_block)=else_block { collect_stmt_ids(else_block, out); }
            }
            Stmt::While { id, cond, body, .. } => { out.push(id.0); collect_expr_ids(cond, out); collect_stmt_ids(body, out); }
            Stmt::ForEach { id, iterable, body, .. } => { out.push(id.0); collect_expr_ids(iterable, out); collect_stmt_ids(body, out); }
            Stmt::Return { id, value, .. } | Stmt::Throw { id, value, .. } => { out.push(id.0); if let Some(value)=value { collect_expr_ids(value, out); } }
            Stmt::Try { id, try_block, catches, finally_block, .. } => {
                out.push(id.0); collect_stmt_ids(try_block, out); for catch in catches { collect_stmt_ids(&catch.body, out); } if let Some(finally_block)=finally_block { collect_stmt_ids(finally_block, out); }
            }
            Stmt::Break { id, .. } | Stmt::Continue { id, .. } => { out.push(id.0); }
            Stmt::DoWhile { id, body, cond, .. } => {
                out.push(id.0); collect_expr_ids(cond, out); collect_stmt_ids(body, out);
            }
            Stmt::Switch { id, scrutinee, clauses, default, .. } => {
                out.push(id.0);
                collect_expr_ids(scrutinee, out);
                for clause in clauses {
                    for value in &clause.values { collect_expr_ids(value, out); }
                    collect_stmt_ids(&clause.body, out);
                }
                if let Some(default) = default { collect_stmt_ids(default, out); }
            }
        }
    }
}
fn collect_item_expr_ids(item: &Item, out: &mut Vec<u32>) {
    match item {
        Item::Function(func) => collect_stmt_ids(&func.body, out),
        Item::Class(class) => {
            for method in &class.methods {
                collect_stmt_ids(&method.body, out);
            }
        }
        Item::GlobalVar(var) => { if let Some(init)=&var.init { collect_expr_ids(init, out); } }
    }
}
fn collect_lvalue_expr_ids(lhs: &LValue, out: &mut Vec<u32>) {
    match lhs {
        LValue::Var(_) => {}
        LValue::Field { base, .. } => collect_expr_ids(base, out),
        LValue::Index { base, index } => { collect_expr_ids(base, out); collect_expr_ids(index, out); }
    }
}
fn collect_expr_ids(expr: &Expr, out: &mut Vec<u32>) {
    match expr {
        Expr::VarRef { id, .. } | Expr::Literal { id, .. } | Expr::Unknown { id, .. } => out.push(id.0),
        Expr::Unary { id, expr, .. } | Expr::Cast { id, expr, .. } => { out.push(id.0); collect_expr_ids(expr, out); }
        Expr::Binary { id, lhs, rhs, .. } => { out.push(id.0); collect_expr_ids(lhs, out); collect_expr_ids(rhs, out); }
        Expr::FieldRead { id, base, .. } => { out.push(id.0); collect_expr_ids(base, out); }
        Expr::IndexRead { id, base, index, .. } => { out.push(id.0); collect_expr_ids(base, out); collect_expr_ids(index, out); }
        Expr::Call(call) => {
            out.push(call.id.0);
            if let CallTarget::Dynamic(callee) = &call.target { collect_expr_ids(callee, out); }
            if let Some(receiver)=&call.receiver { collect_expr_ids(receiver, out); }
            for arg in &call.args { collect_expr_ids(arg, out); }
        }
        Expr::Lambda { id, body, .. } => { out.push(id.0); collect_stmt_ids(body, out); }
        Expr::New { id, args, .. } => { out.push(id.0); for arg in args { collect_expr_ids(arg, out); } }
        Expr::Conditional { id, cond, then_expr, else_expr, .. } => {
            out.push(id.0);
            collect_expr_ids(cond, out);
            collect_expr_ids(then_expr, out);
            collect_expr_ids(else_expr, out);
        }
        Expr::Assign { id, lhs, rhs, .. } => {
            out.push(id.0);
            collect_lvalue_expr_ids(lhs, out);
            collect_expr_ids(rhs, out);
        }
        Expr::Interp { id, parts, .. } | Expr::Collection { id, elements: parts, .. } => {
            out.push(id.0);
            for part in parts {
                collect_expr_ids(part, out);
            }
        }
        Expr::Range { id, low, high, .. } => {
            out.push(id.0);
            collect_expr_ids(low, out);
            collect_expr_ids(high, out);
        }
        Expr::Opaque { id, .. } => out.push(id.0),
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

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
        let mut ids = Vec::new();
        collect_expr_ids(&call, &mut ids);
        assert_eq!(ids, [1, 90, 99], "callee IDs can exceed the outer call ID");
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
}
