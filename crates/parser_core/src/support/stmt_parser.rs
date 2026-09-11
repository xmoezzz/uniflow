// Generic statement engine. `Pg` owns the cursor, the HIR builder, the lexical
// scope and the language descriptor; per-language oddities are delegated to a
// `LangHooks` implementation that receives `&mut Pg` and can call back in.

/// The generic parser for one source file.
pub struct Pg<'a> {
    pub cur: Cursor<'a>,
    pub b: ModuleBuilder,
    pub sc: Scope,
    pub d: &'a LangDescriptor,
    /// Module-level statements, collected into a synthetic entry function so
    /// script languages (Shell, Python, Ruby, PHP, JS) get real control flow.
    pub module_body: Vec<uniflow_hir::Stmt>,
    arg_names: Vec<Option<String>>,
    pub map_literal_depth: u32,
    names: std::collections::HashMap<uniflow_hir::SymbolId, String>,
    /// Symbols currently known to hold closure/callable values. Calls through
    /// these symbols must remain dynamic instead of being normalized as a
    /// direct external function call with the variable's spelling.
    callable_values: std::collections::HashSet<uniflow_hir::SymbolId>,
    receiver: Option<uniflow_hir::SymbolId>,
    pub current_class: Option<String>,
    pub nested: u32,
    /// Extra statements produced by surface constructs that lower to sequences.
    pending_stmts: std::collections::VecDeque<uniflow_hir::Stmt>,
}

/// Name of the synthetic function that carries file-level statements.
pub const TOP_LEVEL_FUNCTION: &str = "__top_level__";

impl<'a> Pg<'a> {
    pub fn new(
        language: uniflow_hir::Language,
        path: &str,
        source: &'a str,
        d: &'a LangDescriptor,
    ) -> Self {
        let _ = language;
        let tokens = Lexer::new(source, &d.lexer).tokenize();
        let file = 0u32;
        Self {
            cur: Cursor::new(source, &d.lexer, tokens, file),
            b: ModuleBuilder::new(d.language.clone(), path, &module_name_from_path(path)),
            sc: Scope::new(),
            d,
            module_body: Vec::new(),
            arg_names: Vec::new(),
            map_literal_depth: 0,
            names: std::collections::HashMap::new(),
            callable_values: std::collections::HashSet::new(),
            receiver: None,
            current_class: None,
            nested: 0,
            pending_stmts: std::collections::VecDeque::new(),
        }
    }

    /// Consume the parser and produce the merged HIR program.
    pub fn finish(mut self) -> uniflow_hir::Program {
        if !self.module_body.is_empty() {
            let body = Block {
                id: self.b.alloc_block_id(),
                stmts: std::mem::take(&mut self.module_body),
                span: self.cur.span_from(0),
            };
            let function = uniflow_hir::Function {
                id: self.b.alloc_function_id(),
                name: TOP_LEVEL_FUNCTION.to_string(),
                symbol: None,
                params: Vec::new(),
                captures: Vec::new(),
                return_type: None,
                body,
                is_method: false,
                receiver: None,
                cpp: None,
                cpp_initializers: Vec::new(),
                span: self.cur.span_from(0),
            };
            self.b.push_item(Item::Function(function));
        }
        self.b.finish()
    }

    // ---------------------------------------------------------------- symbols

    pub fn resolve_or_create(
        &mut self,
        name: &str,
        kind: uniflow_hir::SymbolKind,
    ) -> uniflow_hir::SymbolId {
        let name = name.to_string();
        if let Some(existing) = self.sc.get(&name) {
            return existing;
        }
        let symbol = self.b.add_symbol(&name, kind);
        self.names.insert(symbol, name.clone());
        self.sc.define(&name, symbol);
        symbol
    }

    pub fn symbol_name(&self, symbol: uniflow_hir::SymbolId) -> Option<&str> {
        self.names.get(&symbol).map(|name| name.as_str())
    }

    /// Define a symbol in the current scope (used by declaration statements).
    pub fn define(&mut self, name: &str, kind: uniflow_hir::SymbolKind) -> uniflow_hir::SymbolId {
        let symbol = self.b.add_symbol(name, kind);
        self.names.insert(symbol, name.to_string());
        self.sc.define(name, symbol);
        symbol
    }

    pub fn self_symbol(&mut self) -> uniflow_hir::SymbolId {
        if let Some(receiver) = self.receiver {
            return receiver;
        }
        let symbol = self.define("self", uniflow_hir::SymbolKind::Local);
        self.receiver = Some(symbol);
        symbol
    }

    pub fn boolean(&mut self, value: bool) -> Expr {
        Expr::Literal {
            id: self.b.alloc_expr_id(),
            kind: LiteralKind::Bool(value),
            span: self.cur.span_from(self.cur.pos),
        }
    }

    pub fn string_literal(&mut self, text: &str) -> Expr {
        Expr::Literal {
            id: self.b.alloc_expr_id(),
            kind: LiteralKind::String(text.to_string()),
            span: self.cur.span_from(self.cur.pos),
        }
    }

    /// Build a call with a plain name, e.g. `puts(x)`.
    pub fn call(
        &mut self,
        name: &str,
        receiver: Option<Expr>,
        args: Vec<Expr>,
        span: uniflow_hir::Span,
    ) -> Expr {
        let arg_names = std::mem::take(&mut self.arg_names);
        let qualifier_is_explicit = receiver.is_some();
        Expr::Call(CallExpr {
            id: self.b.alloc_expr_id(),
            target: CallTarget::Named(name.to_string()),
            receiver: receiver.map(Box::new),
            qualifier_is_explicit,
            args,
            arg_names,
            span,
        })
    }

    /// Build `base.name(args)`.
    pub fn method_call(
        &mut self,
        base: Expr,
        name: String,
        args: Vec<Expr>,
        span: uniflow_hir::Span,
    ) -> Expr {
        let arg_names = std::mem::take(&mut self.arg_names);
        Expr::Call(CallExpr {
            id: self.b.alloc_expr_id(),
            target: CallTarget::Named(name),
            receiver: Some(Box::new(base)),
            qualifier_is_explicit: true,
            args,
            arg_names,
            span,
        })
    }

    /// `(receiver, callee_name)` for a call-shaped expression.
    ///
    /// The receiver is cloned so callers can keep parsing arguments before they
    /// consume the result.
    pub fn describe_callee(&self, expr: &Expr) -> Option<(Option<Expr>, String)> {
        match expr {
            Expr::VarRef { symbol, .. } => self
                .symbol_name(*symbol)
                .map(|name| (None, name.to_string())),
            Expr::FieldRead { base, field, .. } => {
                Some((Some(base.as_ref().clone()), field.clone()))
            }
            Expr::Cast { expr, .. } => self.describe_callee(expr),
            Expr::Unary { expr, .. } => self.describe_callee(expr),
            _ => None,
        }
    }

    /// Read the current value of an lvalue (used to model compound assignment).
    pub fn lvalue_read(&mut self, lvalue: &uniflow_hir::LValue, span: uniflow_hir::Span) -> Expr {
        match lvalue {
            uniflow_hir::LValue::Var(symbol) => Expr::VarRef {
                id: self.b.alloc_expr_id(),
                symbol: *symbol,
                span,
            },
            uniflow_hir::LValue::Field { base, field } => Expr::FieldRead {
                id: self.b.alloc_expr_id(),
                base: Box::new(base.as_ref().clone()),
                field: field.clone(),
                span,
            },
            uniflow_hir::LValue::Index { base, index } => Expr::IndexRead {
                id: self.b.alloc_expr_id(),
                base: Box::new(base.as_ref().clone()),
                index: Box::new(index.as_ref().clone()),
                span,
            },
        }
    }

    /// `i++` / `--i`: modeled as an assignment of `i +/- 1` so the incremented
    /// value keeps its data dependency on `i`.
    pub fn increment_expr(
        &mut self,
        operand: Expr,
        op: &str,
        prefix: bool,
        span: uniflow_hir::Span,
    ) -> Expr {
        let Some(lvalue) = to_lvalue(operand.clone()) else {
            return operand;
        };
        let one = Expr::Literal {
            id: self.b.alloc_expr_id(),
            kind: LiteralKind::Int(1),
            span,
        };
        let binary = if op == "++" {
            uniflow_hir::BinaryOp::Add
        } else {
            uniflow_hir::BinaryOp::Sub
        };
        let value = Expr::Binary {
            id: self.b.alloc_expr_id(),
            op: binary,
            lhs: Box::new(operand),
            rhs: Box::new(one),
            span,
        };
        let _ = prefix;
        Expr::Assign {
            id: self.b.alloc_expr_id(),
            lhs: lvalue,
            rhs: Box::new(value),
            span,
        }
    }

    // ------------------------------------------------------------- token tests

    pub fn at_statement_boundary(&self) -> bool {
        self.cur.eof()
            || self.cur.at_newline()
            || self.cur.at(";")
            || self.cur.at(")")
            || self.cur.at("]")
            || self.cur.at("}")
            || self.cur.at(",")
            || self.at_block_end()
    }

    pub fn at_block_end(&self) -> bool {
        self.cur.at("}") || self.d.kw.end_kw.iter().any(|end| self.cur.at_kw(end))
    }

    /// True for the keywords that start a statement or block, so an expression
    /// parser can stop instead of reading them as names.
    pub fn is_block_keyword(&self, text: &str) -> bool {
        let kw = &self.d.kw;
        let lowered = text.to_ascii_lowercase();
        let candidates: Vec<&str> = vec![
            kw.if_kw,
            kw.while_kw,
            kw.for_kw,
            kw.return_kw.unwrap_or("return"),
        ]
        .into_iter()
        .chain(kw.else_if.iter().copied())
        .chain(kw.end_kw.iter().copied())
        .chain(kw.break_kw.iter().copied())
        .chain(kw.continue_kw.iter().copied())
        .chain(kw.throw_kw.iter().copied())
        .chain(kw.try_kw.into_iter())
        .chain(kw.catch_kw.iter().copied())
        .chain(kw.finally_kw.iter().copied())
        .chain(kw.class_kw.iter().copied())
        .chain(kw.case_kw.into_iter())
        .chain(kw.default_kw.into_iter())
        .chain(self.d.decl_introducers.iter().copied())
        .collect();
        candidates
            .iter()
            .any(|name| name.eq_ignore_ascii_case(lowered.as_str()) && lowered == *lowered)
            || matches!(
                lowered.as_str(),
                "if" | "else"
                    | "while"
                    | "for"
                    | "foreach"
                    | "do"
                    | "switch"
                    | "select"
                    | "case"
                    | "default"
                    | "try"
                    | "catch"
                    | "finally"
                    | "return"
                    | "break"
                    | "continue"
                    | "throw"
                    | "raise"
                    | "class"
                    | "function"
                    | "def"
                    | "func"
                    | "fn"
                    | "end"
                    | "then"
                    | "until"
                    | "unless"
                    | "elsif"
                    | "elseif"
                    | "elif"
                    | "rescue"
                    | "ensure"
                    | "except"
            )
    }

    // ------------------------------------------------------------- terminators

    /// Consume the statement terminator (`;`, newline, or nothing).
    pub fn terminator(&mut self) {
        if self.cur.eat(";") {
            return;
        }
        if self.d.newline_terminated && self.cur.at_newline() {
            self.cur.advance();
            return;
        }
        if !self.d.newline_terminated {
            // Missing `;` is recoverable; do not consume a following statement.
            return;
        }
        self.cur.skip_newlines();
    }

    /// Consume `then`/`do`/`:` words that may follow a condition.
    fn consume_condition_lead(&mut self) {
        loop {
            if self.cur.eat(":") && self.d.lexer.significant_newlines {
                continue;
            }
            if self.d.kw.then_kw.iter().any(|word| self.cur.at_kw(word)) {
                self.cur.advance();
                continue;
            }
            break;
        }
    }

    // ------------------------------------------------------------------ blocks

    /// Parse a statement list terminated by `}` or one of `ends`.
    pub fn statements<H: LangHooks>(
        &mut self,
        hooks: &mut H,
        ends: &[&str],
    ) -> anyhow::Result<Vec<uniflow_hir::Stmt>> {
        let saved = self.sc.depth();
        self.sc.push();
        let mut out = Vec::new();
        loop {
            if let Some(stmt) = self.pending_stmts.pop_front() {
                out.push(stmt);
                continue;
            }
            self.cur.skip_newlines();
            if self.cur.eof() {
                break;
            }
            if self.at_end_word(ends) {
                break;
            }
            if self.cur.at("}") || ends.iter().any(|end| self.cur.at_kw(end)) {
                break;
            }
            if self.cur.eat(";") {
                continue;
            }
            match self.statement(hooks) {
                Ok(Some(stmt)) => out.push(stmt),
                Ok(None) => {
                    if self.at_end_word(ends) || self.cur.eof() {
                        break;
                    }
                    // No progress: skip a token so the loop cannot spin.
                    if !self.cur.at_newline() {
                        self.cur.advance();
                    } else {
                        self.cur.skip_newlines();
                    }
                }
                Err(error) => {
                    self.cur.error(&error.to_string());
                    self.cur.recover_to_statement();
                }
            }
            self.cur.skip_newlines();
        }
        while self.sc.depth() > saved {
            self.sc.pop();
        }
        Ok(out)
    }

    fn at_end_word(&self, ends: &[&str]) -> bool {
        ends.iter()
            .any(|end| self.cur.at_kw(end) || self.cur.at(end))
    }

    /// Parse `{ ... }`, `then ... end`, `do ... done`, `:` + indented suite, or a
    /// single statement, and return it as a HIR block.
    pub fn body<H: LangHooks>(&mut self, hooks: &mut H, ends: &[&str]) -> anyhow::Result<Block> {
        self.cur.skip_newlines();
        let start = self.cur.pos;
        if self.cur.at("{") {
            self.cur.advance();
            let stmts = self.statements(hooks, &["}"])?;
            self.cur.skip_newlines();
            self.cur.expect("}");
            let span = self.cur.span_from(start);
            return Ok(Block {
                id: self.b.alloc_block_id(),
                stmts,
                span,
            });
        }
        self.consume_condition_lead();
        self.cur.skip_newlines();
        if self.d.block_style == BlockStyle::None
            || self.cur.at_newline() && self.d.newline_terminated
        {
            // `if cond; stmt` written on one line, or an empty suite.
        }
        let stmts = self.statements(hooks, ends)?;
        if self.cur.at_newline() {
            self.cur.advance();
        }
        if ends
            .iter()
            .any(|end| self.cur.at_kw(end) || self.cur.at(end))
        {
            self.cur.advance();
        } else if self.d.block_style == BlockStyle::Braces && stmts.is_empty() {
            self.cur.error("expected a block");
        }
        let span = self.cur.span_from(start);
        Ok(Block {
            id: self.b.alloc_block_id(),
            stmts,
            span,
        })
    }

    // -------------------------------------------------------------- statements

    /// Parse one statement. `Ok(None)` means "nothing to record here".
    pub fn statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        if let Some(stmt) = self.pending_stmts.pop_front() {
            return Ok(Some(stmt));
        }
        self.cur.skip_newlines();
        if self.cur.eof() || self.cur.at("}") {
            return Ok(None);
        }
        if self.cur.eat(";") {
            return Ok(None);
        }
        if let Some(stmt) = hooks.statement(self)? {
            self.terminator();
            return Ok(Some(stmt));
        }
        // `label:` (Go, Shell, C) — recorded as a no-op marker statement.
        if self.cur.peek(1).text == ":"
            && self.cur.current().kind == TokKind::Ident
            && !self.d.ops.ternary
        {
            self.cur.advance();
            self.cur.advance();
            return Ok(None);
        }
        let kw = &self.d.kw;

        if self.cur.at_kw(kw.if_kw) || self.d.kw.unless.map_or(false, |word| self.cur.at_kw(word)) {
            return self.if_statement(hooks);
        }
        if self.cur.at_kw(kw.while_kw) || self.d.kw.until.map_or(false, |word| self.cur.at_kw(word))
        {
            return self.while_statement(hooks);
        }
        if self.d.kw.do_kw.map_or(false, |word| self.cur.at_kw(word)) && self.do_loop_ahead() {
            return self.do_while_statement(hooks);
        }
        if self.cur.at_kw(kw.for_kw) || kw.foreach_kw.iter().any(|word| self.cur.at_kw(word)) {
            return self.for_statement(hooks);
        }
        if kw.switch_kw.iter().any(|word| self.cur.at_kw(word)) {
            return self.switch_statement(hooks);
        }
        if kw.case_kw.map_or(false, |word| self.cur.at_kw(word))
            || kw.default_kw.map_or(false, |word| self.cur.at_kw(word))
        {
            // A stray `case`/`default` outside a switch: skip its label.
            self.cur.advance();
            return Ok(None);
        }
        if kw.try_kw.map_or(false, |word| self.cur.at_kw(word))
            || kw.catch_kw.iter().any(|word| self.cur.at_kw(word))
            || kw.finally_kw.iter().any(|word| self.cur.at_kw(word))
        {
            return self.try_statement(hooks);
        }
        if kw.return_kw.map_or(false, |word| self.cur.at_kw(word)) {
            return self.return_statement(hooks);
        }
        if kw.break_kw.iter().any(|word| self.cur.at_kw(word)) {
            let start = self.cur.pos;
            let label = self.label_argument();
            let span = self.cur.span_from(start);
            self.terminator();
            return Ok(Some(uniflow_hir::Stmt::Break {
                id: self.b.alloc_stmt_id(),
                label,
                span,
            }));
        }
        if kw.continue_kw.iter().any(|word| self.cur.at_kw(word)) {
            let start = self.cur.pos;
            let label = self.label_argument();
            let span = self.cur.span_from(start);
            self.terminator();
            return Ok(Some(uniflow_hir::Stmt::Continue {
                id: self.b.alloc_stmt_id(),
                label,
                span,
            }));
        }
        if kw.throw_kw.iter().any(|word| self.cur.at_kw(word)) {
            return self.throw_statement(hooks);
        }
        if self
            .d
            .decl_introducers
            .iter()
            .any(|word| self.cur.at_kw(word))
        {
            return self.declaration_statement(hooks);
        }
        if self.d.walrus.map_or(false, |walrus| self.cur.at(walrus)) {
            return Ok(None);
        }
        if self.d.type_before_name && self.looks_like_local_declaration() {
            return self.declaration_statement(hooks);
        }
        if kw.pass_kw.iter().any(|word| self.cur.at_kw(word)) {
            self.cur.advance();
            self.terminator();
            return Ok(None);
        }
        if kw.function_kw.iter().any(|word| self.cur.at_kw(word)) && self.nested > 0 {
            // A nested function definition: parse and register it as an item.
            if let Some(function) = self.function_definition(hooks)? {
                self.b.push_item(Item::Function(function));
                return Ok(None);
            }
        }
        if kw.class_kw.iter().any(|word| self.cur.at_kw(word)) && self.nested > 0 {
            if let Some(class) = self.class_definition(hooks)? {
                self.b.push_item(Item::Class(class));
                return Ok(None);
            }
        }
        self.expression_statement(hooks)
    }

    fn do_loop_ahead(&self) -> bool {
        // `do { ... } while (cond)` versus a bare `do` block.
        true
    }

    fn label_argument(&mut self) -> Option<String> {
        let word = self.cur.current().text.clone();
        self.cur.advance();
        if self.cur.current().kind == TokKind::Ident && !self.cur.current().space_before {
            let label = self.cur.current().text.clone();
            self.cur.advance();
            return Some(label);
        }
        let _ = word;
        None
    }

    // ------------------------------------------------------------------- if

    fn if_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        let negated = self.d.kw.unless.map_or(false, |word| self.cur.at_kw(word));
        self.cur.advance();
        self.cur.skip_newlines();
        let mut cond = self.expression()?;
        if negated {
            cond = Expr::Unary {
                id: self.b.alloc_expr_id(),
                op: uniflow_hir::UnaryOp::Not,
                expr: Box::new(cond),
                span: self.cur.span_from(start),
            };
        }
        self.consume_condition_lead();
        self.cur.skip_newlines();
        let then_block = self.block_for(
            hooks,
            &["else", "elif", "elseif", "elsif", "end", "fi", "endif", "}"],
        )?;
        self.cur.skip_newlines();
        let mut else_block = None;
        loop {
            if self
                .d
                .kw
                .else_if
                .iter()
                .any(|word| self.two_word_keyword(word))
                || self.cur.at_kw("elsif")
                || self.cur.at_kw("elseif")
                || self.cur.at_kw("elif")
            {
                let nested = self.if_statement(hooks)?;
                let block = Block {
                    id: self.b.alloc_block_id(),
                    stmts: nested.into_iter().collect(),
                    span: self.cur.span_from(start),
                };
                else_block = Some(block);
                break;
            }
            if self.d.kw.else_kw.map_or(false, |word| self.cur.at_kw(word)) {
                self.cur.advance();
                if self.cur.at_kw(self.d.kw.if_kw) {
                    self.cur.advance();
                }
                let block = self.block_for(
                    hooks,
                    &["else", "end", "fi", "endif", "elif", "elseif", "elsif", "}"],
                )?;
                else_block = Some(block);
                break;
            }
            break;
        }
        if self.cur.at_kw("end") || self.cur.at_kw("fi") || self.cur.at_kw("endif") {
            self.cur.advance();
        }
        let span = self.cur.span_from(start);
        self.terminator();
        Ok(Some(uniflow_hir::Stmt::If {
            id: self.b.alloc_stmt_id(),
            cond,
            then_block,
            else_block,
            span,
        }))
    }

    /// Match a two-word keyword such as `else if` written as two tokens.
    pub fn two_word_keyword(&self, phrase: &str) -> bool {
        let mut parts = phrase.split_whitespace();
        let Some(first) = parts.next() else {
            return false;
        };
        let Some(second) = parts.next() else {
            return false;
        };
        self.cur.at_kw(first) && self.cur.peek(1).text.eq_ignore_ascii_case(second)
    }

    /// Parse a block, wrapping a single statement in a block when the language
    /// allows brace-less bodies.
    pub fn block_for<H: LangHooks>(
        &mut self,
        hooks: &mut H,
        ends: &[&str],
    ) -> anyhow::Result<Block> {
        let start = self.cur.pos;
        self.cur.skip_newlines();
        if self.cur.at("{") {
            self.cur.advance();
            let stmts = self.statements(hooks, &["}"])?;
            self.cur.skip_newlines();
            self.cur.expect("}");
            let span = self.cur.span_from(start);
            return Ok(Block {
                id: self.b.alloc_block_id(),
                stmts,
                span,
            });
        }
        self.consume_condition_lead();
        self.cur.skip_newlines();
        if self.d.block_style == BlockStyle::Braces && !self.d.newline_terminated {
            // C-family: a single statement body.
            if let Some(stmt) = self.statement(hooks)? {
                let span = self.cur.span_from(start);
                return Ok(Block {
                    id: self.b.alloc_block_id(),
                    stmts: vec![stmt],
                    span,
                });
            }
            self.cur.error("expected a block");
            return Ok(self.b.empty_block());
        }
        let stmts = self.statements(hooks, ends)?;
        let span = self.cur.span_from(start);
        Ok(Block {
            id: self.b.alloc_block_id(),
            stmts,
            span,
        })
    }

    // ----------------------------------------------------------------- while

    fn while_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        let negated = self.d.kw.until.map_or(false, |word| self.cur.at_kw(word));
        self.cur.advance();
        self.cur.skip_newlines();
        let mut cond = self.expression()?;
        if negated {
            cond = Expr::Unary {
                id: self.b.alloc_expr_id(),
                op: uniflow_hir::UnaryOp::Not,
                expr: Box::new(cond),
                span: self.cur.span_from(start),
            };
        }
        // Trailing `end while` (Shell) and `... while cond` suffixes.
        self.consume_condition_lead();
        if self.cur.at_kw("done") {
            self.cur.advance();
        }
        self.cur.skip_newlines();
        let body = self.block_for(hooks, &["end", "done", "od", "else", "endwhile", "}"])?;
        if self.cur.at_kw("end")
            || self.cur.at_kw("done")
            || self.cur.at_kw("endwhile")
            || self.cur.at_kw("od")
        {
            self.cur.advance();
        }
        if self.d.trailing_while && self.cur.at_kw(self.d.kw.while_kw) {
            // `begin ... end while cond` (Ruby): the body runs first.
            self.cur.advance();
            let cond = self.expression()?;
            let span = self.cur.span_from(start);
            self.terminator();
            return Ok(Some(uniflow_hir::Stmt::DoWhile {
                id: self.b.alloc_stmt_id(),
                body,
                cond,
                span,
            }));
        }
        let span = self.cur.span_from(start);
        self.terminator();
        Ok(Some(uniflow_hir::Stmt::While {
            id: self.b.alloc_stmt_id(),
            cond,
            body,
            span,
        }))
    }

    fn do_while_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        self.cur.advance();
        self.cur.skip_newlines();
        let body = self.block_for(hooks, &["while", "until", "end", "done", "}"])?;
        self.cur.skip_newlines();
        let negated = self.d.kw.until.map_or(false, |word| self.cur.at_kw(word));
        if !(self.cur.at_kw(self.d.kw.while_kw) || negated) {
            // `do ... end` with no condition is an infinite loop (Rust `loop`).
            let span = self.cur.span_from(start);
            if self.cur.at_kw("end") || self.cur.at_kw("done") {
                self.cur.advance();
            }
            self.terminator();
            let cond = Expr::Literal {
                id: self.b.alloc_expr_id(),
                kind: LiteralKind::Bool(true),
                span,
            };
            return Ok(Some(uniflow_hir::Stmt::While {
                id: self.b.alloc_stmt_id(),
                cond,
                body,
                span,
            }));
        }
        self.cur.advance();
        let mut cond = self.expression()?;
        if negated {
            cond = Expr::Unary {
                id: self.b.alloc_expr_id(),
                op: uniflow_hir::UnaryOp::Not,
                expr: Box::new(cond),
                span: self.cur.span_from(start),
            };
        }
        if self.cur.at_kw("done") {
            self.cur.advance();
        }
        let span = self.cur.span_from(start);
        self.terminator();
        Ok(Some(uniflow_hir::Stmt::DoWhile {
            id: self.b.alloc_stmt_id(),
            body,
            cond,
            span,
        }))
    }

    // ---------------------------------------------------------------- switch

    /// `switch (x) { case 1: ... default: ... }`, Go `switch`, PHP `match`-style.
    fn switch_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        self.cur.advance();
        self.cur.skip_newlines();
        let scrutinee = if self.cur.at("{") {
            Expr::Unknown {
                id: self.b.alloc_expr_id(),
                span: self.cur.span_from(start),
            }
        } else {
            let value = self.expression()?;
            // Go's `switch x.(type)` keeps the probed value as the scrutinee.
            if self.cur.at(".") {
                self.cur.advance();
                if self.cur.eat("(") {
                    let _ = self.cur.balanced_text("(", ")");
                }
            }
            value
        };
        self.cur.skip_newlines();
        let mut clauses: Vec<uniflow_hir::SwitchClause> = Vec::new();
        let mut default: Option<Block> = None;
        if !self.cur.eat("{") {
            // `switch x when a then ...` and other one-line forms go to hooks.
            let span = self.cur.span_from(start);
            self.cur.recover_to_statement();
            return Ok(Some(uniflow_hir::Stmt::Switch {
                id: self.b.alloc_stmt_id(),
                scrutinee,
                clauses,
                default,
                span,
            }));
        }
        loop {
            self.cur.skip_newlines();
            if self.cur.at("}") || self.cur.eof() {
                self.cur.advance();
                break;
            }
            let clause_start = self.cur.pos;
            let is_case = self.d.kw.case_kw.map_or(false, |word| self.cur.at_kw(word));
            let is_default = self
                .d
                .kw
                .default_kw
                .map_or(false, |word| self.cur.at_kw(word));
            if !is_case && !is_default {
                // Go allows a statement before the case list, and a `fallthrough`
                // keyword appears inside bodies; parse it as a normal statement.
                if let Some(stmt) = self.statement(hooks)? {
                    if let Some(last) = clauses.last_mut() {
                        last.body.stmts.push(stmt);
                        continue;
                    }
                }
                if !self.cur.at_newline() && !self.cur.at("}") {
                    self.cur.advance();
                }
                continue;
            }
            self.cur.advance();
            self.cur.skip_newlines();
            let mut values = Vec::new();
            if is_case {
                loop {
                    // Go type switch: `case []int:`, Ruby `when Integer`, range `1..3`.
                    if self.cur.at(":")
                        || self.cur.at("=>")
                        || self.cur.at_newline()
                        || self.cur.at("}")
                    {
                        break;
                    }
                    values.push(self.expression()?);
                    self.cur.skip_newlines();
                    if !self.cur.eat(",") {
                        break;
                    }
                    self.cur.skip_newlines();
                }
            }
            if self.cur.eat(":") || self.cur.eat("=>") {
                // `case 1: stmt` on one line stays inside this clause.
            } else if self.cur.at_kw("do") {
                self.cur.advance();
            }
            let body = self.switch_case_body(hooks)?;
            let span = self.cur.span_from(clause_start);
            let fallthrough = self.d.switch_falls_through && !body_ends_control_flow(&body);
            if is_default || values.is_empty() && is_default {
                match &mut default {
                    Some(block) => block.stmts.extend(body.stmts),
                    None => {
                        default = Some(Block {
                            id: self.b.alloc_block_id(),
                            stmts: body.stmts,
                            span,
                        })
                    }
                }
            } else {
                clauses.push(uniflow_hir::SwitchClause {
                    values,
                    body,
                    fallthrough,
                    span,
                });
            }
        }
        let span = self.cur.span_from(start);
        self.terminator();
        Ok(Some(uniflow_hir::Stmt::Switch {
            id: self.b.alloc_stmt_id(),
            scrutinee,
            clauses,
            default,
            span,
        }))
    }

    /// Statements belonging to one `case`, stopping at the next `case`,
    /// `default`, or the closing brace.
    fn switch_case_body<H: LangHooks>(&mut self, hooks: &mut H) -> anyhow::Result<Block> {
        let start = self.cur.pos;
        if self.cur.at("{") {
            return self.body(hooks, &["}"]);
        }
        let ends = ["}", "case", "default", "end", "esac", "when"];
        let stmts = self.statements(hooks, &ends)?;
        let span = self.cur.span_from(start);
        Ok(Block {
            id: self.b.alloc_block_id(),
            stmts,
            span,
        })
    }

    // ------------------------------------------------------- declaration test

    /// `int x = 1;`, `NSString *s;`, `final List<String> names = ...`.
    fn looks_like_local_declaration(&self) -> bool {
        let mut probe = 0usize;
        loop {
            let word = self.cur.peek(probe).text.to_ascii_lowercase();
            if is_type_modifier_word(&word) {
                probe += 1;
                continue;
            }
            break;
        }
        let lead = self.cur.peek(probe);
        if !matches!(lead.kind, TokKind::Ident | TokKind::Keyword) {
            return false;
        }
        if self.d.self_names.contains(&lead.text.as_str()) {
            return false;
        }
        // A name bound in scope is a variable, so `count total` is not a decl.
        if self.sc.get(&lead.text).is_some() {
            return false;
        }
        let lead_lower = lead.text.to_ascii_lowercase();
        let qualified_jsp_type = if self.d.language == Language::Jsp {
            let mut index = probe;
            while matches!(self.cur.peek(index + 1).text.as_str(), "." | "::")
                && matches!(
                    self.cur.peek(index + 2).kind,
                    TokKind::Ident | TokKind::Keyword
                )
            {
                index += 2;
            }
            index > probe && is_probable_type_name(&self.cur.peek(index).text)
        } else {
            false
        };
        let looks_typed = primitive_type_word(&lead_lower)
            || is_probable_type_name(&lead.text)
            || qualified_jsp_type;
        if !looks_typed {
            return false;
        }
        probe += 1;
        // Consume complete qualified type names.  Stopping immediately after
        // `.` made static calls such as `File.Create(path)` look like C++
        // direct-initialization declarations (`File. Create(path)`).
        while matches!(self.cur.peek(probe).text.as_str(), "." | "::")
            && matches!(self.cur.peek(probe + 1).kind, TokKind::Ident | TokKind::Keyword)
        {
            probe += 2;
        }
        // Generics, qualified names, pointers and array marks belong to the type.
        let mut guard = 0usize;
        while matches!(
            self.cur.peek(probe).text.as_str(),
            "<" | "*" | "&" | "[" | "]"
        ) && guard < 64
        {
            if self.cur.peek(probe).text == "<" {
                // Stop if the generic argument list never closes.
                let mut depth = 0i32;
                let mut index = probe;
                while index < self.cur.tokens.len() {
                    match self.cur.tokens[index].text.as_str() {
                        "<" => depth += 1,
                        ">" => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        ";" | "{" | "}" if depth > 0 => break,
                        _ => {}
                    }
                    index += 1;
                }
                probe = index + 1;
                guard += 1;
                continue;
            }
            probe += 1;
            guard += 1;
        }
        let name = self.cur.peek(probe);
        if name.kind != TokKind::Ident {
            return false;
        }
        let after = self.cur.peek(probe + 1).text.clone();
        matches!(
            after.as_str(),
            "=" | ";" | "," | "[" | "(" | "." | "!" | "?"
        ) || self.d.type_annotation.map(|marker| after == marker) == Some(true)
    }

    // ------------------------------------------------------------------- for

    fn for_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        self.cur.advance();
        self.cur.skip_newlines();
        let parenthesized = self.cur.eat("(");
        // Locate the header end so the header tokens can be re-parsed in place:
        // re-parsing (instead of rebuilding text) keeps every span accurate.
        let header_end = if parenthesized {
            self.match_index(")")
        } else {
            self.header_end_index()
        };
        let header_start = self.cur.pos;
        let shape = self.classify_for_header(header_start, header_end);
        self.cur.pos = header_start;
        self.cur.depth = if parenthesized { 1 } else { 0 };
        match shape {
            ForShape::Empty => {
                self.cur.pos = header_end;
                self.cur.depth = 0;
                if parenthesized {
                    self.cur.eat(")");
                }
                let body = self.block_for(hooks, &["end", "done", "od", "}"])?;
                self.consume_loop_end();
                let span = self.cur.span_from(start);
                self.terminator();
                let cond = Expr::Literal {
                    id: self.b.alloc_expr_id(),
                    kind: LiteralKind::Bool(true),
                    span,
                };
                return Ok(Some(uniflow_hir::Stmt::While {
                    id: self.b.alloc_stmt_id(),
                    cond,
                    body,
                    span,
                }));
            }
            ForShape::Iteration { item, iterable_at } => {
                let item_name = item.unwrap_or_else(|| "_".to_string());
                let item_symbol = if item_name == "_" {
                    self.b.add_symbol("_", uniflow_hir::SymbolKind::Local)
                } else {
                    self.define(
                        &strip_ident_sigils(&item_name),
                        uniflow_hir::SymbolKind::Local,
                    )
                };
                self.cur.pos = iterable_at;
                let iterable = if self.cur.at(")") || self.at_block_end() {
                    Expr::Unknown {
                        id: self.b.alloc_expr_id(),
                        span: self.cur.span_from(start),
                    }
                } else {
                    self.expression()?
                };
                self.cur.pos = header_end;
                self.cur.depth = 0;
                if parenthesized {
                    self.cur.eat(")");
                }
                let body = self.block_for(hooks, &["end", "done", "od", "}"])?;
                self.consume_loop_end();
                let span = self.cur.span_from(start);
                self.terminator();
                return Ok(Some(uniflow_hir::Stmt::ForEach {
                    id: self.b.alloc_stmt_id(),
                    item_symbol,
                    iterable,
                    body,
                    span,
                }));
            }
            ForShape::IterationRev {
                iterable_at,
                item_at,
            } => {
                // `foreach ($xs as $x)`: parse the collection first, then bind
                // the iteration variable named after `as`.
                self.cur.pos = iterable_at;
                let iterable = self.expression()?;
                let item_name = self.name_before(item_at).unwrap_or_else(|| "_".to_string());
                let item_symbol = if item_name == "_" {
                    self.b.add_symbol("_", uniflow_hir::SymbolKind::Local)
                } else {
                    self.define(
                        &strip_ident_sigils(&item_name),
                        uniflow_hir::SymbolKind::Local,
                    )
                };
                self.cur.pos = header_end;
                self.cur.depth = 0;
                if parenthesized {
                    self.cur.eat(")");
                }
                let body = self.block_for(hooks, &["end", "done", "od", "}"])?;
                self.consume_loop_end();
                let span = self.cur.span_from(start);
                self.terminator();
                return Ok(Some(uniflow_hir::Stmt::ForEach {
                    id: self.b.alloc_stmt_id(),
                    item_symbol,
                    iterable,
                    body,
                    span,
                }));
            }
            ForShape::Classic => {
                return self.classic_for_statement(hooks, start, header_start, header_end, parenthesized);
            }
            ForShape::Condition => {
                let cond = self.expression()?;
                self.cur.pos = header_end;
                self.cur.depth = 0;
                if parenthesized { self.cur.eat(")"); }
                let body = self.block_for(hooks, &["end", "done", "od", "}"])?;
                self.consume_loop_end();
                let span = self.cur.span_from(start);
                self.terminator();
                return Ok(Some(uniflow_hir::Stmt::While {
                    id: self.b.alloc_stmt_id(), cond, body, span,
                }));
            }
        }
    }

    /// Index of the token closing a parenthesized header, or the token that ends
    /// a brace-less header (`do`, `{`, or the line end).
    fn match_index(&self, close: &str) -> usize {
        let mut depth = 0i32;
        let mut index = self.cur.pos;
        while index < self.cur.tokens.len() {
            let token = &self.cur.tokens[index];
            match token.text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => {
                    if depth == 0 && token.text == close {
                        return index;
                    }
                    if depth > 0 {
                        depth -= 1;
                    }
                }
                _ => {}
            }
            index += 1;
        }
        self.cur.tokens.len().saturating_sub(1)
    }

    fn header_end_index(&self) -> usize {
        let mut depth = 0i32;
        let mut index = self.cur.pos;
        while index < self.cur.tokens.len() {
            let token = &self.cur.tokens[index];
            if depth == 0 {
                if token.text == "{" || token.kind == TokKind::Newline {
                    return index;
                }
                if token.kind == TokKind::Keyword
                    && matches!(token.text.as_str(), "do" | "then" | ":")
                {
                    return index;
                }
                if token.text == ":" && self.d.lexer.significant_newlines {
                    return index;
                }
            }
            match token.text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                _ => {}
            }
            index += 1;
        }
        self.cur.tokens.len().saturating_sub(1)
    }

    fn classify_for_header(&self, start: usize, end: usize) -> ForShape {
        let end = end.min(self.cur.tokens.len());
        let semicolons = self.for_header_separators(start, end).len();
        let mut non_empty = false;
        for index in start..end {
            let token = &self.cur.tokens[index];
            if token.text == ";" {
                continue;
            }
            if token.kind != TokKind::Newline {
                non_empty = true;
            }
        }
        if semicolons == 2 {
            return ForShape::Classic;
        }
        if semicolons > 2 {
            return ForShape::Classic;
        }
        if !non_empty { return ForShape::Empty; }
        // Iteration forms.
        for index in start..end {
            let token = &self.cur.tokens[index];
            let word = token.text.as_str();
            let is_range = word == "range";
            let is_in = (self.d.kw.in_kw.map_or(false, |name| word == name)
                || matches!(word, "in" | "of"))
                && !(word == "as" && matches!(self.d.language, uniflow_hir::Language::Php));
            let is_colon_iteration = self.d.type_before_name && word == ":";
            let is_walrus_range = self.d.walrus.map_or(false, |walrus| word == walrus)
                && self.tokens_have_word(index + 1, end, "range");
            if !is_in && !is_range && !is_colon_iteration && !is_walrus_range {
                continue;
            }
            if is_range && !is_walrus_range {
                // `for x := range xs` / `for range xs`
                let item = self.name_before(index);
                let iterable_at = index + 1;
                return ForShape::Iteration {
                    item,
                    iterable_at: iterable_at.min(end),
                };
            }
            if is_walrus_range {
                let item = self.name_before(index);
                let range_at = index + 1;
                return ForShape::Iteration {
                    item,
                    iterable_at: (range_at + 1).min(end),
                };
            }
            if is_colon_iteration {
                let item = self.name_before(index);
                return ForShape::Iteration {
                    item,
                    iterable_at: (index + 1).min(end),
                };
            }
            // `for ($k => $v in $map)` style: keep the last name before the word.
            let item = self.name_before(index);
            return ForShape::Iteration {
                item,
                iterable_at: (index + 1).min(end),
            };
        }
        // PHP `foreach ($arr as $k => $v)`: the iterable comes first, then `as`.
        if matches!(self.d.language, uniflow_hir::Language::Php) {
            if let Some(index) = self.word_index(start, end, "as") {
                return ForShape::IterationRev {
                    iterable_at: start,
                    item_at: (index + 1).min(end),
                };
            }
        }
        if semicolons == 0 { ForShape::Condition } else { ForShape::Classic }
    }

    fn tokens_have_word(&self, start: usize, end: usize, word: &str) -> bool {
        (start..end.min(self.cur.tokens.len())).any(|index| self.cur.tokens[index].text == word)
    }

    fn word_index(&self, start: usize, end: usize, word: &str) -> Option<usize> {
        (start..end.min(self.cur.tokens.len()))
            .find(|index| self.cur.tokens[*index].text.eq_ignore_ascii_case(word))
    }

    /// Last plain identifier before `index`, used as the iteration variable.
    fn name_before(&self, index: usize) -> Option<String> {
        let mut probe = index;
        while probe > 0 {
            probe -= 1;
            let token = &self.cur.tokens[probe];
            if matches!(token.text.as_str(), "," | ":=" | "=" | ";" | "(" | ":") {
                continue;
            }
            if token.kind == TokKind::Ident {
                return Some(token.text.clone());
            }
            if token.kind == TokKind::Keyword {
                continue;
            }
            break;
        }
        None
    }

    fn consume_loop_end(&mut self) {
        if self.cur.at_kw("end")
            || self.cur.at_kw("done")
            || self.cur.at_kw("od")
            || self.cur.at_kw("endfor")
        {
            self.cur.advance();
        }
    }
    // ------------------------------------------------------------------ try

    fn try_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        let kw = &self.d.kw;
        let begins_without_try = !kw.try_kw.map_or(false, |word| self.cur.at_kw(word));
        let try_block = if begins_without_try {
            // Ruby `begin ... rescue ... end` / Java `try` with no keyword seen.
            self.block_for(
                hooks,
                &["catch", "except", "rescue", "finally", "ensure", "end", "}"],
            )?
        } else {
            self.cur.advance();
            self.consume_condition_lead();
            self.block_for(
                hooks,
                &["catch", "except", "rescue", "finally", "ensure", "end", "}"],
            )?
        };
        let mut catches = Vec::new();
        let mut finally_block = None;
        loop {
            self.cur.skip_newlines();
            let caught = kw
                .catch_kw
                .iter()
                .chain(kw.finally_kw.iter())
                .any(|word| self.cur.at_kw(word));
            if !caught {
                break;
            }
            let is_finally = kw.finally_kw.iter().any(|word| self.cur.at_kw(word));
            let clause_start = self.cur.pos;
            let _ = self.cur.advance();
            self.cur.skip_newlines();
            self.sc.push();
            let binding_start = self.cur.pos;
            let symbol = if is_finally {
                None
            } else {
                self.catch_binding()
            };
            let ty = if !is_finally && self.d.language == Language::CSharp {
                let mut header = self.cur.tokens[binding_start..self.cur.pos].iter()
                    .filter(|token| !matches!(token.text.as_str(), "(" | ")")
                        && token.kind != TokKind::Newline).collect::<Vec<_>>();
                if symbol.is_some() { header.pop(); }
                let type_name = header.iter().map(|token| token.text.as_str()).collect::<String>();
                (!type_name.is_empty()).then(|| self.b.ensure_type(&type_name))
            } else { None };
            self.consume_condition_lead();
            let body = self.block_for(
                hooks,
                &["catch", "except", "rescue", "finally", "ensure", "end", "}"],
            );
            self.sc.pop();
            let body = body?;
            if is_finally {
                finally_block = Some(body);
            } else {
                catches.push(uniflow_hir::CatchClause {
                    symbol,
                    ty,
                    body,
                    span: self.cur.span_from(clause_start),
                });
            }
        }
        if self.cur.at_kw("end") || self.cur.at_kw("done") {
            self.cur.advance();
        }
        let span = self.cur.span_from(start);
        self.terminator();
        Ok(Some(uniflow_hir::Stmt::Try {
            id: self.b.alloc_stmt_id(),
            try_block,
            catches,
            finally_block,
            span,
        }))
    }

    /// `catch (IOException e)`, `except IOError as e`, `rescue => e`, `catch e`.
    fn catch_binding(&mut self) -> Option<uniflow_hir::SymbolId> {
        self.cur.skip_newlines();
        if !self.cur.eat("(") {
            if self.cur.at(":") {
                self.cur.advance();
            }
            if self.cur.eat("=>") {
                self.cur.skip_newlines();
                let name = self.cur.name();
                return Some(
                    self.define(&strip_ident_sigils(&name), uniflow_hir::SymbolKind::Local),
                );
            }
            if self.cur.current().kind == TokKind::Ident {
                let name = self.cur.name();
                if self.cur.at("=") || self.cur.at_kw("as") {
                    self.cur.advance();
                    let bound = self.cur.name();
                    return Some(
                        self.define(&strip_ident_sigils(&bound), uniflow_hir::SymbolKind::Local),
                    );
                }
                return Some(
                    self.define(&strip_ident_sigils(&name), uniflow_hir::SymbolKind::Local),
                );
            }
            return None;
        }
        // Collect the clause text and pick out the declared variable.
        let header = self.header_until(")");
        self.cur.expect(")");
        let parts = split_top_level(&header, '|');
        let last = parts
            .last()
            .map(|part| part.trim().to_string())
            .unwrap_or_default();
        let words: Vec<&str> = last.split_whitespace().collect();
        let name = match words.as_slice() {
            [] => return None,
            [_] if self.d.language == Language::CSharp => return None,
            [name] => (*name).to_string(),
            [_, name] => (*name).to_string(),
            _ => words.last()?.to_string(),
        };
        if name.is_empty() {
            return None;
        }
        Some(self.define(&strip_ident_sigils(&name), uniflow_hir::SymbolKind::Local))
    }

    // ---------------------------------------------------------- return / throw

    fn return_statement<H: LangHooks>(
        &mut self,
        _hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        self.cur.advance();
        self.cur.skip_newlines();
        let value = if self.at_statement_boundary() {
            None
        } else {
            Some(self.expression()?)
        };
        let return_span = self.cur.span_from(start);
        let return_stmt = uniflow_hir::Stmt::Return {
            id: self.b.alloc_stmt_id(),
            value,
            span: return_span,
        };
        if self.d.trailing_if
            && (self.cur.at_kw(self.d.kw.if_kw)
                || self.d.kw.unless.is_some_and(|word| self.cur.at_kw(word)))
        {
            let negated = self.d.kw.unless.is_some_and(|word| self.cur.at_kw(word));
            self.cur.advance();
            self.cur.skip_newlines();
            let mut cond = self.expression()?;
            if negated {
                cond = Expr::Unary {
                    id: self.b.alloc_expr_id(),
                    op: uniflow_hir::UnaryOp::Not,
                    expr: Box::new(cond),
                    span: self.cur.span_from(start),
                };
            }
            let span = self.cur.span_from(start);
            self.terminator();
            return Ok(Some(uniflow_hir::Stmt::If {
                id: self.b.alloc_stmt_id(),
                cond,
                then_block: Block {
                    id: self.b.alloc_block_id(),
                    stmts: vec![return_stmt],
                    span: return_span,
                },
                else_block: None,
                span,
            }));
        }
        self.terminator();
        Ok(Some(return_stmt))
    }

    fn throw_statement<H: LangHooks>(
        &mut self,
        _hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        self.cur.advance();
        self.cur.skip_newlines();
        let value = if self.at_statement_boundary() {
            None
        } else {
            Some(self.expression()?)
        };
        let span = self.cur.span_from(start);
        self.terminator();
        Ok(Some(uniflow_hir::Stmt::Throw {
            id: self.b.alloc_stmt_id(),
            value,
            span,
        }))
    }

    // ----------------------------------------------------------- declarations

    /// `int x = 1, y = 2;`, `let x = 1`, `var x int`, `x := 1`, `Dim s As String`.
    fn declaration_statement<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        let introducer = if self
            .d
            .decl_introducers
            .iter()
            .any(|word| self.cur.at_kw(word))
        {
            Some(self.cur.current().text.to_ascii_lowercase())
        } else {
            None
        };
        // Skip modifiers that never name a variable.
        loop {
            let lowered = self.cur.current().text.to_ascii_lowercase();
            if matches!(
                lowered.as_str(),
                "static"
                    | "final"
                    | "public"
                    | "private"
                    | "protected"
                    | "internal"
                    | "const"
                    | "readonly"
                    | "mut"
                    | "let"
                    | "var"
                    | "val"
                    | "volatile"
                    | "transient"
                    | "abstract"
                    | "override"
                    | "open"
                    | "sealed"
                    | "implicit"
                    | "explicit"
                    | "unsigned"
                    | "signed"
                    | "synchronized"
                    | "native"
                    | "strictfp"
                    | "default"
                    | "extern"
                    | "register"
                    | "my"
                    | "our"
                    | "local"
                    | "dim"
                    | "public!"
                    | "private!"
            ) {
                // A modifier or introducer: keep going until the declared name.
                if matches!(
                    lowered.as_str(),
                    "let" | "var" | "val" | "my" | "our" | "local" | "dim"
                ) {
                    if self.is_decl_introducer(&lowered) {
                        self.cur.advance();
                        continue;
                    }
                }
                self.cur.advance();
                continue;
            }
            break;
        }
        if self.cur.at_kw("as") {
            self.cur.advance();
        }
        let (type_text, prefetched_name) = if self.d.type_before_name {
            self.type_and_declarator_name()
        } else {
            (String::new(), None)
        };
        if prefetched_name.is_none()
            && (self.cur.at_newline() || self.cur.at(";") || self.cur.eof())
        {
            // A bare type name with no declarator: a forward declaration.
            self.terminator();
            let _ = type_text;
            return Ok(None);
        }
        let name = prefetched_name.unwrap_or_else(|| self.cur.name_with_sigil());
        if name.is_empty() {
            self.cur.recover_to_statement();
            return Ok(None);
        }
        // Declarator suffixes belong to the variable, not to a following
        // expression statement (`char buf[16];`, `T values[N][M]`).
        while self.cur.eat("[") {
            let mut depth = 1i32;
            while !self.cur.eof() && depth > 0 {
                if self.cur.eat("[") {
                    depth += 1;
                } else if self.cur.eat("]") {
                    depth -= 1;
                } else {
                    self.cur.advance();
                }
            }
        }
        let annotation = self.type_annotation_suffix()?;
        let combined = combine_types(&type_text, &annotation, self.d.type_before_name);
        let ty = if combined.is_empty() {
            None
        } else {
            Some(self.b.ensure_type(&combined))
        };
        let symbol = self.define(
            &strip_ident_sigils(&name),
            if self.nested == 0 {
                uniflow_hir::SymbolKind::Global
            } else {
                uniflow_hir::SymbolKind::Local
            },
        );
        self.cur.skip_newlines();
        let init =
            if self.cur.eat("=") || self.d.walrus.map_or(false, |walrus| self.cur.eat(walrus)) {
                self.cur.skip_newlines();
                Some(self.expression()?)
            } else if self.cur.at("(") && !self.d.newline_terminated {
                // `int x(3);` / `Foo x(3)` constructor initialization.
                let args = self.argument_list()?;
                Some(Expr::New {
                    id: self.b.alloc_expr_id(),
                    type_name: if combined.is_empty() {
                        "object".to_string()
                    } else {
                        combined.clone()
                    },
                    args,
                    span: self.cur.span_from(start),
                })
            } else if self.cur.at("{") && !self.d.newline_terminated {
                self.cur.advance();
                self.map_literal_depth += 1;
                let elements = self.initializer_elements("}")?;
                self.map_literal_depth -= 1;
                self.cur.expect("}");
                Some(Expr::Collection {
                    id: self.b.alloc_expr_id(),
                    container: CollectionKind::Array,
                    elements,
                    span: self.cur.span_from(start),
                })
            } else {
                None
            };
        if init
            .as_ref()
            .is_some_and(|expr| self.expr_is_callable(expr))
        {
            self.callable_values.insert(symbol);
        }
        let span = self.cur.span_from(start);
        self.terminator();
        let _ = introducer;
        let stmt = uniflow_hir::Stmt::Let {
            id: self.b.alloc_stmt_id(),
            symbol,
            ty,
            init,
            span,
        };
        let _ = hooks;
        Ok(Some(stmt))
    }

    fn is_decl_introducer(&self, word: &str) -> bool {
        self.d.decl_introducers.contains(&word)
    }

    /// Split a type-before-name declaration without consuming the initializer.
    /// The declarator is the last identifier before `=`, `;`, `,`, an array
    /// suffix, constructor initializer, or block initializer.
    fn type_and_declarator_name(&mut self) -> (String, Option<String>) {
        let start = self.cur.pos;
        let mut index = start;
        let mut angle = 0i32;
        let mut name_index = None;
        while index < self.cur.tokens.len() {
            let token = &self.cur.tokens[index];
            match token.text.as_str() {
                "<" => angle += 1,
                ">" if angle > 0 => angle -= 1,
                "=" | ";" | "," | "(" | "{" | "[" if angle == 0 => break,
                "}" | ")" if angle == 0 => break,
                _ => {}
            }
            if angle == 0 && token.kind == TokKind::Ident {
                name_index = Some(index);
            }
            index += 1;
        }
        let Some(name_index) = name_index else {
            return (self.type_text(), None);
        };
        let type_text = self.tokens_text(start, name_index);
        self.cur.pos = name_index;
        let name = self.cur.name_with_sigil();
        (type_text, Some(name))
    }

    fn tokens_text(&self, start: usize, end: usize) -> String {
        let mut out = String::new();
        for token in &self.cur.tokens[start..end.min(self.cur.tokens.len())] {
            if !out.is_empty()
                && !matches!(
                    token.text.as_str(),
                    "*" | "&" | ">" | "]" | "," | "." | "::"
                )
                && !out.ends_with(['<', '[', '.', ':', '*', '&'])
            {
                out.push(' ');
            }
            out.push_str(&token.text);
        }
        out.trim().to_string()
    }

    /// `: Type`, `-> Type`, `as Type` annotations that follow a declarator.
    fn type_annotation_suffix(&mut self) -> anyhow::Result<String> {
        self.cur.skip_newlines();
        let Some(marker) = self.d.type_annotation else {
            return Ok(String::new());
        };
        if !self.cur.at(marker) {
            return Ok(String::new());
        }
        self.cur.advance();
        self.cur.skip_newlines();
        Ok(self.type_text())
    }

    /// Read a type name: qualifiers, generics, pointers, arrays, nullable marks.
    pub fn type_text(&mut self) -> String {
        let mut out = String::new();
        let mut generic_depth = 0usize;
        loop {
            self.cur.skip_newlines();
            let token = self.cur.current().clone();
            let word = token.text.clone();
            let is_word = matches!(token.kind, TokKind::Ident | TokKind::Keyword);
            if is_word && !matches!(word.as_str(), "=" | ";" | "(" | "," | ")" | "=>" | "{") {
                if !out.is_empty() && out.ends_with(' ') {
                    // keep
                }
                if !out.is_empty()
                    && !out.ends_with(' ')
                    && !out.ends_with('*')
                    && !out.ends_with('&')
                    && !out.ends_with(['.', ':', '<', '['])
                {
                    out.push(' ');
                }
                out.push_str(&word);
                self.cur.advance();
                continue;
            }
            if word == "," && generic_depth != 0 {
                out.push(',');
                self.cur.advance();
                continue;
            }
            if word == "<" {
                generic_depth += 1;
                out.push('<');
                self.cur.advance();
                continue;
            }
            if word == ">" {
                generic_depth = generic_depth.saturating_sub(1);
                out.push('>');
                self.cur.advance();
                continue;
            }
            if word == ">>" && generic_depth != 0 {
                generic_depth = generic_depth.saturating_sub(2);
                out.push_str(">>");
                self.cur.advance();
                continue;
            }
            if matches!(
                word.as_str(),
                "*" | "&" | "[" | "]" | "." | "::" | "?" | "!" | "_"
            ) {
                out.push_str(&word);
                self.cur.advance();
                continue;
            }
            if word == "..." {
                out.push_str("...");
                self.cur.advance();
                continue;
            }
            break;
        }
        out.replace("  ", " ").trim().to_string()
    }

    // ------------------------------------------------------- expression stmt

    fn expression_statement<H: LangHooks>(
        &mut self,
        _hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let start = self.cur.pos;
        let expr = self.expression()?;
        let span = self.cur.span_from(start);
        if matches!(expr, Expr::Unknown { .. }) {
            // Nothing recognizable: consume to the next boundary.
            if !self.at_statement_boundary() {
                self.cur.advance();
            }
            self.terminator();
            return Ok(None);
        }
        self.terminator();
        Ok(Some(stmt_from_expr(&mut self.b, expr, span)))
    }

    // ------------------------------------------------------------------ items

    /// Parse the file: imports, types, functions, and module-level statements.
    pub fn parse_items<H: LangHooks>(&mut self, hooks: &mut H) -> anyhow::Result<()> {
        loop {
            self.cur.skip_newlines();
            if self.cur.eof() {
                break;
            }
            if self.cur.eat(";") || self.cur.eat(",") {
                continue;
            }
            if hooks.item(self)? {
                continue;
            }
            if self.at_import() {
                self.parse_import();
                continue;
            }
            if self.d.kw.class_kw.iter().any(|word| self.cur.at_kw(word)) {
                if let Some(class) = self.class_definition(hooks)? {
                    self.b.push_item(Item::Class(class));
                    continue;
                }
            }
            if self
                .d
                .kw
                .function_kw
                .iter()
                .any(|word| self.cur.at_kw(word))
            {
                if let Some(function) = self.function_definition(hooks)? {
                    self.b.push_item(Item::Function(function));
                    continue;
                }
            }
            if self.d.type_before_name && self.top_level_function_ahead() {
                if let Some(function) = self.function_definition(hooks)? {
                    self.b.push_item(Item::Function(function));
                    continue;
                }
            }
            // Module-level statement.
            match self.statement(hooks) {
                Ok(Some(stmt)) => self.module_body.push(stmt),
                Ok(None) => {
                    if !self.cur.at_newline() && !self.cur.eof() {
                        self.cur.advance();
                    }
                }
                Err(error) => {
                    self.cur.error(&error.to_string());
                    self.cur.recover_to_statement();
                }
            }
        }
        Ok(())
    }

    fn at_import(&self) -> bool {
        matches!(
            self.cur.current().text.to_ascii_lowercase().as_str(),
            "import"
                | "include"
                | "require"
                | "using"
                | "use"
                | "package"
                | "namespace"
                | "from"
                | "load"
                | "add"
                | "source"
        ) && self.cur.current().kind == TokKind::Keyword
    }

    fn parse_import(&mut self) {
        let header: String = self.header_until_statement();
        if header.trim().is_empty() {
            self.cur.recover_to_statement();
            return;
        }
        for (path, alias) in import_records(&header) {
            self.b.add_import(&path, alias);
        }
    }

    /// Collect the raw token text up to a balanced `close`, without parsing it.
    /// Only used where the *names* matter (catch clauses, Go receivers).
    pub fn header_until(&mut self, close: &str) -> String {
        let mut depth = 0i32;
        let mut out = String::new();
        let mut guard = 0usize;
        while !self.cur.eof() && guard < 65536 {
            guard += 1;
            let token = self.cur.current().clone();
            if depth == 0 && token.text == close {
                break;
            }
            match token.text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                _ => {}
            }
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&token.text);
            self.cur.advance();
        }
        out
    }

    fn header_until_statement(&mut self) -> String {
        let mut out = String::new();
        while !self.cur.eof() && !self.cur.at_newline() && !self.cur.at(";") {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(self.cur.current().text.clone().as_str());
            self.cur.advance();
        }
        self.cur.eat(";");
        out
    }

    // ---------------------------------------------------------------- classes

    pub fn class_definition<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Class>> {
        let start = self.cur.pos;
        while self.d.kw.class_kw.iter().any(|word| self.cur.at_kw(word))
            || matches!(
                self.cur.current().text.to_ascii_lowercase().as_str(),
                "public"
                    | "private"
                    | "protected"
                    | "abstract"
                    | "final"
                    | "static"
                    | "sealed"
                    | "open"
                    | "internal"
                    | "data"
                    | "struct"
                    | "interface"
                    | "enum"
                    | "protocol"
                    | "trait"
                    | "type"
                    | "class"
                    | "new"
                    | "partial"
                    | "nested"
            )
        {
            self.cur.advance();
            self.cur.skip_newlines();
        }
        let name = self.cur.name();
        if name.is_empty() {
            self.cur.recover_to_statement();
            return Ok(None);
        }
        let mut bases = Vec::new();
        // `extends A implements B`, `: A, B`, `{ A }`, `extends A`.
        while !self.cur.at("{") && !self.cur.at_newline() && !self.cur.eof() && !self.at_block_end()
        {
            let word = self.cur.current().text.clone();
            if word == ":"
                || word == "<:"
                || self.cur.at_kw("extends")
                || self.cur.at_kw("implements")
            {
                self.cur.advance();
                loop {
                    let base = self.cur.name();
                    if !base.is_empty() {
                        bases.push(base);
                    }
                    if !self.cur.eat(",") {
                        break;
                    }
                    self.cur.skip_newlines();
                }
                continue;
            }
            self.cur.advance();
        }
        self.cur.skip_newlines();
        let symbol = self.define(&name, uniflow_hir::SymbolKind::Class);
        let outer_class = self.current_class.replace(name.clone());
        let mut fields = Vec::new();
        let mut methods = Vec::new();
        if self.cur.eat("{") {
            loop {
                self.cur.skip_newlines();
                if self.cur.at("}") || self.cur.eof() {
                    self.cur.advance();
                    break;
                }
                if self.cur.eat(";") || self.cur.eat(",") {
                    continue;
                }
                if hooks.item(self)? {
                    continue;
                }
                if self.d.kw.class_kw.iter().any(|word| self.cur.at_kw(word)) {
                    // Nested type: skip its body.
                    self.skip_balanced_body();
                    continue;
                }
                let member_start = self.cur.pos;
                let looks_like_method = self.method_ahead();
                if looks_like_method {
                    let saved_nested = self.nested;
                    self.nested = saved_nested + 1;
                    match self.function_definition(hooks) {
                        Ok(Some(mut function)) => {
                            self.nested = saved_nested;
                            if function.receiver.is_none() {
                                let receiver = self.define(
                                    &self
                                        .d
                                        .self_names
                                        .first()
                                        .copied()
                                        .unwrap_or("self")
                                        .to_string(),
                                    uniflow_hir::SymbolKind::Local,
                                );
                                function.receiver = Some(uniflow_hir::Param {
                                    name: "self".to_string(),
                                    symbol: receiver,
                                    ty: None,
                                    kind: uniflow_hir::ParamKind::Positional,
                                    has_default: false,
                                    keyword_only: false,
                                    cpp: uniflow_hir::CppValueSemantics::default(),
                                    span: function.span,
                                });
                            }
                            function.is_method = true;
                            methods.push(function);
                            continue;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            self.cur.error(&error.to_string());
                            self.cur.recover_to_statement();
                        }
                    }
                    self.nested = saved_nested;
                }
                // Field or property declaration.
                match self.statement(hooks) {
                    Ok(Some(uniflow_hir::Stmt::Let {
                        symbol, ty, span, ..
                    })) => {
                        let field_name = self
                            .names
                            .get(&symbol)
                            .cloned()
                            .unwrap_or_else(|| "field".to_string());
                        fields.push(uniflow_hir::Field {
                            name: field_name,
                            symbol: Some(symbol),
                            ty,
                            span,
                        });
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        if !self.cur.at_newline() && !self.cur.at("}") && !self.cur.eof() {
                            self.cur.advance();
                        }
                    }
                    Err(error) => {
                        self.cur.error(&error.to_string());
                        self.cur.recover_to_statement();
                    }
                }
                let _ = member_start;
            }
        }
        self.current_class = outer_class;
        let span = self.cur.span_from(start);
        Ok(Some(uniflow_hir::Class {
            name,
            symbol: Some(symbol),
            bases,
            fields,
            methods,
            span,
        }))
    }

    /// Heuristic: does the upcoming member look like a method signature?
    fn method_ahead(&self) -> bool {
        if self
            .d
            .kw
            .function_kw
            .iter()
            .any(|word| self.cur.at_kw(word))
        {
            return true;
        }
        let mut probe = 0usize;
        while matches!(
            self.cur.peek(probe).text.to_ascii_lowercase().as_str(),
            "public"
                | "private"
                | "protected"
                | "static"
                | "final"
                | "abstract"
                | "virtual"
                | "override"
                | "async"
                | "default"
                | "const"
                | "readonly"
                | "extern"
                | "inline"
                | "friend"
                | "explicit"
                | "implicit"
                | "internal"
                | "open"
                | "sealed"
                | "synchronized"
                | "native"
                | "fn"
                | "func"
                | "def"
                | "function"
                | "sub"
                | "public!"
                | "private!"
        ) {
            probe += 1;
        }
        let name = self.cur.peek(probe);
        if !matches!(name.kind, TokKind::Ident | TokKind::Keyword) {
            return false;
        }
        // `name(` or `name ... (` — a parameter list makes it a method.
        let mut probe = probe + 1;
        let mut depth = 0i32;
        while probe < self.cur.tokens.len() {
            let token = self.cur.peek(probe);
            match token.text.as_str() {
                "(" if depth == 0 => return true,
                "<" | "[" | "(" => depth += 1,
                ">" | "]" | ")" => {
                    if depth == 0 {
                        return false;
                    }
                    depth -= 1;
                }
                "{" | ";" | "=" | ":" if depth == 0 => {
                    // Kotlin/Swift require the parameter list first, so `{` or `;`
                    // here means a property, not a method.
                    return false;
                }
                _ => {}
            }
            probe += 1;
        }
        false
    }

    /// A top-level type-before-name function must have at least one token of
    /// return type before the name and a parameter list before any statement
    /// boundary. Requiring the return type prevents `foo(bar);` calls from
    /// being mistaken for prototypes.
    fn top_level_function_ahead(&self) -> bool {
        self.function_name_index().is_some_and(|name_index| {
            if name_index <= self.cur.pos {
                return false;
            }
            // `receiver.method(...)` in a JSP scriptlet or another top-level
            // code region is an expression, not a return type plus function
            // name. A qualified return type still has its final type identifier
            // immediately before the declared function name, never `.`/`->`.
            !matches!(
                self.cur.tokens[name_index - 1].text.as_str(),
                "." | "?." | "->" | "?->"
            )
        })
    }

    fn function_name_index(&self) -> Option<usize> {
        let mut angle = 0i32;
        let mut index = self.cur.pos;
        while index < self.cur.tokens.len() {
            let token = &self.cur.tokens[index];
            match token.text.as_str() {
                "<" => angle += 1,
                ">" if angle > 0 => angle -= 1,
                "(" if angle == 0 => {
                    return (self.cur.pos..index)
                        .rev()
                        .find(|candidate| self.cur.tokens[*candidate].kind == TokKind::Ident);
                }
                ";" | "=" | "{" | "}" if angle == 0 => return None,
                _ if token.kind == TokKind::Newline || token.kind == TokKind::Eof => return None,
                _ => {}
            }
            index += 1;
        }
        None
    }

    fn skip_balanced_body(&mut self) {
        while !self.cur.eof() && !self.cur.at("{") && !self.cur.at_newline() {
            self.cur.advance();
        }
        if !self.cur.eat("{") {
            return;
        }
        let mut depth = 1i32;
        while !self.cur.eof() {
            if self.cur.eat("{") {
                depth += 1;
            } else if self.cur.eat("}") {
                depth -= 1;
                if depth == 0 {
                    return;
                }
            } else {
                self.cur.advance();
            }
        }
    }

    // --------------------------------------------------------------- functions

    /// Parse a function or method definition. Handles both `type name(args)` and
    /// `name(args): type` spellings.
    pub fn function_definition<H: LangHooks>(
        &mut self,
        hooks: &mut H,
    ) -> anyhow::Result<Option<uniflow_hir::Function>> {
        let start = self.cur.pos;
        let saved_errors = self.cur.errors.len();
        let is_function_keyword = self
            .d
            .kw
            .function_kw
            .iter()
            .any(|word| self.cur.at_kw(word));
        if is_function_keyword {
            self.cur.advance();
            self.cur.skip_newlines();
        }
        // Receiver: Go `func (r *T) Name(...)`, Python-style `self` params handle themselves.
        let mut receiver_type = String::new();
        if self.d.receiver_in_parens && self.cur.at("(") {
            receiver_type = self.header_until(")");
            self.cur.expect(")");
            self.cur.skip_newlines();
        }
        let mut leading_type = String::new();
        if self.d.type_before_name {
            let Some(name_index) = self.function_name_index() else {
                self.cur.errors.truncate(saved_errors);
                return Ok(None);
            };
            leading_type = self.tokens_text(self.cur.pos, name_index);
            self.cur.pos = name_index;
            if self.cur.at_newline() || self.cur.at(";") {
                self.cur.errors.truncate(saved_errors);
                return Ok(None);
            }
        }
        let name = self.cur.name_with_sigil();
        if name.is_empty() || name.contains(' ') {
            self.cur.errors.truncate(saved_errors);
            return Ok(None);
        }
        let bare_keyword_header = is_function_keyword
            && (self.cur.at_newline()
                || self.d.block_style == BlockStyle::EndKeyword
                || self.cur.at("{")
                || self.cur.at(":"));
        if !bare_keyword_header {
            self.cur.skip_newlines();
        }
        if !self.cur.at("(") && !bare_keyword_header {
            self.cur.errors.truncate(saved_errors);
            return Ok(None);
        }
        let params = if self.cur.at("(") {
            self.param_list()?
        } else {
            Vec::new()
        };
        self.cur.skip_newlines();
        let return_type = self
            .return_type_suffix()?
            .or_else(|| (!leading_type.is_empty()).then_some(leading_type.clone()));
        self.cur.skip_newlines();
        if self.cur.eat(";") {
            // A prototype with no body: still record the signature so call sites
            // and API models can resolve it.
            return Ok(Some(self.make_function(
                start,
                &name,
                params,
                return_type,
                Vec::new(),
                receiver_type,
            )));
        }
        if self.cur.at("=>") {
            // Expression body: `int add(int a, int b) => a + b;`, C#/Kotlin/Swift/Rust.
            self.cur.advance();
            let value = self.expression()?;
            let stmt = uniflow_hir::Stmt::Return {
                id: self.b.alloc_stmt_id(),
                value: Some(value),
                span: self.cur.span_from(start),
            };
            self.terminator();
            return Ok(Some(self.make_function(
                start,
                &name,
                params,
                return_type,
                vec![stmt],
                receiver_type,
            )));
        }
        let stmts = if self.cur.at("{") {
            self.cur.advance();
            let saved_nested = self.nested;
            self.nested += 1;
            let stmts = self.statements(hooks, &["}"]);
            self.nested = saved_nested;
            let stmts = stmts?;
            self.cur.skip_newlines();
            self.cur.expect("}");
            stmts
        } else if self.d.block_style == BlockStyle::EndKeyword
            || self.d.newline_terminated
            || self.cur.at_newline()
            || self.cur.at(":")
        {
            self.consume_condition_lead();
            let ends: Vec<&str> = self
                .d
                .kw
                .end_kw
                .iter()
                .copied()
                .filter(|end| !self.d.kw.catch_kw.contains(end))
                .collect();
            let saved_nested = self.nested;
            self.nested += 1;
            let stmts = self.statements(hooks, &ends);
            self.nested = saved_nested;
            let stmts = stmts?;
            if ends
                .iter()
                .any(|end| self.cur.at_kw(end) || self.cur.at(end))
            {
                self.cur.advance();
            }
            stmts
        } else if self.cur.at_newline() || self.at_statement_boundary() {
            Vec::new()
        } else {
            self.cur.errors.truncate(saved_errors);
            return Ok(None);
        };
        let function = self.make_function(start, &name, params, return_type, stmts, receiver_type);
        self.terminator();
        Ok(Some(function))
    }

    pub fn make_function(
        &mut self,
        start: usize,
        name: &str,
        params: Vec<uniflow_hir::Param>,
        return_type: Option<String>,
        stmts: Vec<uniflow_hir::Stmt>,
        receiver_type: String,
    ) -> uniflow_hir::Function {
        let qualified = match &self.current_class {
            Some(class) if !receiver_type.is_empty() || self.d.methods_qualified => {
                format!("{}.{}", class, name)
            }
            _ => name.to_string(),
        };
        let symbol = self
            .sc
            .get(&qualified)
            .or_else(|| self.sc.get(name))
            .unwrap_or_else(|| self.define(&qualified, uniflow_hir::SymbolKind::Function));
        let body = Block {
            id: self.b.alloc_block_id(),
            stmts,
            span: self.cur.span_from(start),
        };
        let span = self.cur.span_from(start);
        let _ = receiver_type;
        uniflow_hir::Function {
            id: self.b.alloc_function_id(),
            name: qualified,
            symbol: Some(symbol),
            params,
            captures: Vec::new(),
            return_type: return_type.map(|name| self.b.ensure_type(&name)),
            body,
            is_method: self.current_class.is_some(),
            receiver: None,
            cpp: None,
            cpp_initializers: Vec::new(),
            span,
        }
    }

    /// Parse `(a, b)`, `(int a, char *b)`, `(x: T = 1)`, `(x int, y int)`, `(|x, y|)`.
    pub fn param_list(&mut self) -> anyhow::Result<Vec<uniflow_hir::Param>> {
        self.cur.expect("(");
        let mut params = Vec::new();
        loop {
            self.cur.skip_newlines();
            if self.cur.at(")") || self.cur.eof() {
                break;
            }
            let group_start = self.cur.pos;
            let mut group: Vec<String> = Vec::new();
            let mut depth = 0i32;
            let mut default: Option<String> = None;
            let mut varargs = false;
            loop {
                self.cur.skip_newlines();
                if self.cur.eof() {
                    break;
                }
                let token = self.cur.current().clone();
                if depth == 0 && (token.text == "," || token.text == ")") {
                    break;
                }
                match token.text.as_str() {
                    "(" | "[" | "<" => depth += 1,
                    ")" | "]" | ">" => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    "..." | "*" if depth == 0 && group.is_empty() => {
                        varargs = true;
                        self.cur.advance();
                        continue;
                    }
                    "=" if depth == 0 => {
                        // Everything after `=` is the default value.
                        self.cur.advance();
                        let mut text = String::new();
                        let mut inner = 0i32;
                        loop {
                            if self.cur.eof() {
                                break;
                            }
                            let next = self.cur.current().clone();
                            if inner == 0 && (next.text == "," || next.text == ")") {
                                break;
                            }
                            match next.text.as_str() {
                                "(" | "[" => inner += 1,
                                ")" | "]" => inner -= 1,
                                _ => {}
                            }
                            if !text.is_empty() {
                                text.push(' ');
                            }
                            text.push_str(&next.text);
                            self.cur.advance();
                        }
                        default = Some(text);
                        continue;
                    }
                    _ => {}
                }
                group.push(token.text.clone());
                self.cur.advance();
            }
            let group_text = group.join(" ").replace("  ", " ").trim().to_string();
            if !group_text.is_empty() {
                let (param_name, param_type) = self.split_param(&group_text);
                if !param_name.is_empty() {
                    let symbol = self.define(
                        &strip_ident_sigils(&param_name),
                        uniflow_hir::SymbolKind::Param,
                    );
                    params.push(uniflow_hir::Param {
                        name: param_name,
                        symbol,
                        ty: if param_type.is_empty() {
                            None
                        } else {
                            Some(self.b.ensure_type(&param_type))
                        },
                        kind: if varargs {
                            uniflow_hir::ParamKind::VarArgs
                        } else {
                            uniflow_hir::ParamKind::Positional
                        },
                        has_default: default.is_some(),
                        keyword_only: false,
                        cpp: uniflow_hir::CppValueSemantics::default(),
                        span: self.cur.span_from(group_start),
                    });
                }
            }
            if !self.cur.eat(",") {
                break;
            }
        }
        self.cur.skip_newlines();
        self.cur.expect(")");
        Ok(params)
    }

    /// Decide which word in a parameter group is the name and which is the type.
    fn split_param(&mut self, group: &str) -> (String, String) {
        let words: Vec<&str> = group
            .split_whitespace()
            .map(|word| word.trim())
            .filter(|word| !word.is_empty())
            .collect();
        let joined = words.join(" ");
        // `name: Type` (Kotlin, Swift, Rust, TypeScript, Python annotations).
        if let Some(position) = find_word(&joined, ": ") {
            let name = joined[..position]
                .replace(['*', '&'], "")
                .trim()
                .to_string();
            let ty = normalize_parameter_type(&joined[position + 2..]);
            return (name, ty);
        }
        if words.len() == 1 {
            let only = words[0].to_string();
            return (only.replace(['*', '&', '?', '!'], ""), String::new());
        }
        if self.d.type_before_name {
            // `char *buf`, `final String s`, `map[string]int m`.
            let name = words.last().copied().unwrap_or_default().to_string();
            let ty = normalize_parameter_type(&words[..words.len() - 1].join(" "));
            let name = name.trim_start_matches('*').replace(['?', '!'], "");
            return (name, ty);
        }
        // `x int`, `self`, `...args`.
        let name = words[0].to_string();
        let ty = normalize_parameter_type(&words[1..].join(" "));
        (name.replace(['*', '&'], ""), ty)
    }

    fn return_type_suffix(&mut self) -> anyhow::Result<Option<String>> {
        self.cur.skip_newlines();
        if self.cur.at("->")
            || self.cur.at("=>")
            || self.cur.at_kw("throws")
            || self.cur.at_kw("raises")
        {
            self.cur.advance();
            self.cur.skip_newlines();
            let text = self.type_text();
            if !text.is_empty() {
                return Ok(Some(text));
            }
            return Ok(None);
        }
        if self.d.type_annotation.map(|marker| self.cur.at(marker)) == Some(true) {
            self.cur.advance();
            self.cur.skip_newlines();
            let text = self.type_text();
            if !text.is_empty() {
                return Ok(Some(text));
            }
        }
        Ok(None)
    }
}

fn import_records(header: &str) -> Vec<(String, Option<String>)> {
    fn clean(value: &str) -> String {
        value
            .trim()
            .trim_matches(|ch: char| matches!(ch, '"' | '\'' | ';' | '<' | '>'))
            .trim()
            .to_string()
    }
    fn aliased(value: &str) -> (String, Option<String>) {
        if let Some(position) = find_word(value, " as ") {
            let original = clean(&value[..position]);
            let alias = clean(&value[position + 4..]);
            (original, (!alias.is_empty()).then_some(alias))
        } else {
            (clean(value), None)
        }
    }
    fn bindings(module: &str, text: &str) -> Vec<(String, Option<String>)> {
        let text = text.trim();
        if text.starts_with('*') {
            let (_, alias) = aliased(text);
            return alias.into_iter().map(|alias| (module.to_string(), Some(alias))).collect();
        }
        if let (Some(open), Some(close)) = (text.find('{'), text.rfind('}')) {
            return text[open + 1..close]
                .split(',')
                .filter_map(|binding| {
                    let (original, alias) = aliased(binding);
                    (!original.is_empty() && original != "...").then(|| {
                        let local = alias.unwrap_or_else(|| original.clone());
                        (format!("{module}.{original}"), Some(local))
                    })
                })
                .collect();
        }
        let default = clean(text.split(',').next().unwrap_or_default());
        (!default.is_empty())
            .then(|| vec![(module.to_string(), Some(default))])
            .unwrap_or_default()
    }

    let header = header.trim();
    let lower = header.to_ascii_lowercase();
    if lower.starts_with("from ") {
        if let Some(position) = find_word(&lower, " import ") {
            let module = clean(&header[5..position]);
            return bindings(&module, &header[position + 8..]);
        }
    }
    if lower.starts_with("import ") {
        let body = &header[7..];
        let body_lower = &lower[7..];
        if let Some(position) = find_word(body_lower, " from ") {
            let module = clean(&body[position + 6..]);
            return bindings(&module, &body[..position]);
        }
        if body.trim_start().starts_with(['"', '\'']) {
            return vec![(clean(body), None)];
        }
        return body
            .split(',')
            .filter_map(|item| {
                let (path, alias) = aliased(item);
                (!path.is_empty()).then_some((path, alias))
            })
            .collect();
    }

    let words = header.split_whitespace().collect::<Vec<_>>();
    let target = words
        .iter()
        .rev()
        .find(|word| {
            !matches!(
                word.to_ascii_lowercase().as_str(),
                "include" | "require" | "using" | "use" | "load" | "add" | "source" | "as" | "in"
            )
        })
        .map(|word| clean(word))
        .unwrap_or_default();
    (!target.is_empty()).then(|| vec![(target, None)]).unwrap_or_default()
}

/// Parse one source file with the generic engine and a hook set.
pub fn parse_program_with<H: LangHooks>(
    descriptor: &LangDescriptor,
    path: &str,
    source: &str,
    hooks: &mut H,
) -> anyhow::Result<(uniflow_hir::Program, Vec<ParseError>)> {
    let mut parser = Pg::new(descriptor.language.clone(), path, source, descriptor);
    parser.parse_items(hooks)?;
    let errors = parser.cur.take_errors();
    Ok((parser.finish(), errors))
}

/// Parse one source file with no language-specific hooks.
pub fn parse_program(
    descriptor: &LangDescriptor,
    path: &str,
    source: &str,
) -> anyhow::Result<(uniflow_hir::Program, Vec<ParseError>)> {
    parse_program_with(descriptor, path, source, &mut NoHooks)
}

/// Convert a parsed expression into the right statement form.
pub fn stmt_from_expr(
    builder: &mut ModuleBuilder,
    expr: Expr,
    span: uniflow_hir::Span,
) -> uniflow_hir::Stmt {
    match expr {
        Expr::Assign { lhs, rhs, .. } => uniflow_hir::Stmt::Assign {
            id: builder.alloc_stmt_id(),
            lhs,
            rhs: *rhs,
            span,
        },
        other => uniflow_hir::Stmt::Expr {
            id: builder.alloc_stmt_id(),
            expr: other,
            span,
        },
    }
}

fn combine_types(declared: &str, annotation: &str, type_before_name: bool) -> String {
    let annotation = annotation.trim();
    let declared = declared.trim();
    if type_before_name {
        if declared.is_empty() {
            annotation.to_string()
        } else {
            declared.to_string()
        }
    } else if annotation.is_empty() {
        declared.to_string()
    } else {
        annotation.to_string()
    }
}

/// Parameter groups are collected token-by-token and joined with spaces before
/// their name/type split. Remove only whitespace adjacent to punctuation that
/// is structural inside a type, while retaining meaningful word separators in
/// types such as `unsigned long` and function types such as `String -> Unit`.
fn normalize_parameter_type(text: &str) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    let structural = |ch: char| matches!(ch, '.' | ':' | '<' | '>' | '[' | ']' | ',' | '?' | '!');
    let mut out = String::with_capacity(text.len());
    for (index, ch) in chars.iter().copied().enumerate() {
        if ch.is_whitespace() {
            let previous = out.chars().next_back();
            let next = chars[index + 1..]
                .iter()
                .copied()
                .find(|candidate| !candidate.is_whitespace());
            if previous.is_some_and(structural) || next.is_some_and(structural) {
                continue;
            }
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

/// Find `needle` outside brackets and quotes.
pub fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let target = needle.as_bytes();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut index = 0usize;
    while index + target.len() <= bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' | b'\'' | b'`' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            _ => {}
        }
        if depth == 0 && &bytes[index..index + target.len()] == target {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// Split on `separator` outside brackets and quotes.
pub fn split_top_level(input: &str, separator: char) -> Vec<String> {
    let bytes = input.as_bytes();
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            current.push(byte as char);
            if byte == b'\\' && index + 1 < bytes.len() {
                index += 1;
                current.push(bytes[index] as char);
            } else if byte == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' | b'\'' | b'`' => {
                quote = Some(byte);
                current.push(byte as char);
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                current.push(byte as char);
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                current.push(byte as char);
            }
            _ if depth == 0 && byte == separator as u8 => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(byte as char),
        }
        index += 1;
    }
    parts.push(current);
    parts
}

/// The recognized shapes of a `for` header.
#[derive(Clone, Debug)]
pub enum ForShape {
    /// `for(;;)` / `loop {}` — an unconditional loop.
    Empty,
    /// Go's `for condition { ... }` form.
    Condition,
    /// `for x in xs`, `for x := range xs`, `for (Type x : xs)`.
    Iteration {
        item: Option<String>,
        iterable_at: usize,
    },
    /// `foreach ($xs as $x)` — iterable before the iteration word.
    IterationRev { iterable_at: usize, item_at: usize },
    /// `for (init; cond; step)`.
    Classic,
}

/// Words that may precede a declared variable without naming its type.
pub fn is_type_modifier_word(word: &str) -> bool {
    matches!(
        word,
        "public"
            | "private"
            | "protected"
            | "internal"
            | "static"
            | "final"
            | "const"
            | "readonly"
            | "volatile"
            | "transient"
            | "abstract"
            | "virtual"
            | "override"
            | "sealed"
            | "open"
            | "synchronized"
            | "native"
            | "strictfp"
            | "extern"
            | "register"
            | "auto"
            | "unsigned"
            | "signed"
            | "long"
            | "short"
            | "mut"
            | "my"
            | "our"
            | "local"
            | "dim"
            | "new"
            | "in"
            | "out"
            | "ref"
            | "inout"
            | "class"
            | "struct"
            | "interface"
            | "enum"
            | "protocol"
            | "trait"
    )
}

/// C-family primitive type keywords.
pub fn primitive_type_word(word: &str) -> bool {
    matches!(
        word,
        "int"
            | "char"
            | "float"
            | "double"
            | "long"
            | "short"
            | "void"
            | "bool"
            | "boolean"
            | "byte"
            | "sbyte"
            | "ubyte"
            | "uint"
            | "ulong"
            | "ushort"
            | "wchar_t"
            | "size_t"
            | "ssize_t"
            | "intptr_t"
            | "uintptr_t"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "f32"
            | "f64"
            | "str"
            | "string"
            | "nsstring"
            | "nsinteger"
            | "nsuinteger"
            | "id"
            | "var"
            | "let"
            | "val"
            | "rune"
            | "complex64"
            | "complex128"
            | "error"
            | "any"
            | "object"
    )
}

/// True when a `case` body already transfers control, so it does not fall through.
pub fn body_ends_control_flow(block: &uniflow_hir::Block) -> bool {
    match block.stmts.last() {
        Some(uniflow_hir::Stmt::Break { .. })
        | Some(uniflow_hir::Stmt::Continue { .. })
        | Some(uniflow_hir::Stmt::Return { .. })
        | Some(uniflow_hir::Stmt::Throw { .. }) => true,
        Some(uniflow_hir::Stmt::If {
            then_block,
            else_block,
            ..
        }) => {
            body_ends_control_flow(then_block)
                && else_block
                    .as_ref()
                    .map_or(false, |block| body_ends_control_flow(block))
        }
        _ => false,
    }
}
