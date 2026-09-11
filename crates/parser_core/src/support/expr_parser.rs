// Generic expression engine: precedence-climbing parsing over the token cursor,
// producing unified HIR expressions for every brace and newline language in the
// product. Constructs a descriptor cannot express go through `LangHooks`, which
// receive `&mut Pg` and may call back into these methods.

impl<'a> Pg<'a> {
    /// Parse a full expression, including assignment operators.
    pub fn expression(&mut self) -> anyhow::Result<Expr> {
        self.assignment_expression()
    }

    pub fn assignment_expression(&mut self) -> anyhow::Result<Expr> {
        if let Some(lambda) = self.try_lambda_expression()? {
            return Ok(lambda);
        }
        let start = self.cur.pos;
        let lhs = self.conditional_expression()?;
        self.cur.skip_newlines();
        let op = self.current_assignment_op();
        if op.is_empty() {
            return Ok(lhs);
        }
        self.cur.advance();
        self.cur.skip_newlines();
        let rhs = self.assignment_expression()?;
        let span = self.cur.span_from(start);
        let Some(lvalue) = to_lvalue(lhs) else {
            self.cur
                .error("left-hand side of assignment is not assignable");
            return Ok(rhs);
        };
        // Compound assignment keeps the previous value as a data dependency, so
        // `buf += tainted` stays connected to `buf`.
        let value = if op == "=" || self.d.walrus == Some(op) {
            rhs
        } else if let Some(binary) = self
            .d
            .ops
            .compound
            .iter()
            .find(|(name, _)| *name == op)
            .map(|(_, binary)| *binary)
        {
            let previous = self.lvalue_read(&lvalue, span);
            self.binary(previous, rhs, binary, span)
        } else if matches!(op, "||=" | "&&=" | "??=" | ".=" | "~=") {
            let previous = self.lvalue_read(&lvalue, span);
            let keep = previous.clone();
            Expr::Conditional {
                id: self.b.alloc_expr_id(),
                cond: Box::new(previous),
                then_expr: Box::new(keep),
                else_expr: Box::new(rhs),
                span,
            }
        } else {
            rhs
        };
        if let uniflow_hir::LValue::Var(symbol) = &lvalue {
            if self.expr_is_callable(&value) {
                self.callable_values.insert(*symbol);
            } else if op == "=" || self.d.walrus == Some(op) {
                self.callable_values.remove(symbol);
            }
        }
        Ok(Expr::Assign {
            id: self.b.alloc_expr_id(),
            lhs: lvalue,
            rhs: Box::new(value),
            span,
        })
    }

    /// Parse expression-bodied closures used by the descriptor languages:
    /// `x => f(x)`, `(x: T) => f(x)`, Rust `|x| f(x)`, Go `func(x T) { ... }`,
    /// and PHP `fn($x) => f($x)`. A closure body gets its own lexical scope;
    /// references resolved to an outer scope are recorded explicitly as HIR
    /// captures so lowering can materialize the closure environment.
    fn try_lambda_expression(&mut self) -> anyhow::Result<Option<Expr>> {
        let start = self.cur.pos;
        // Lambda probing sits on the hot path for every expression.  Do the
        // token-only check before cloning the lexical scope: ordinary
        // expressions overwhelmingly are not closures, and copying every
        // scope layer here made large files approach quadratic parse time as
        // more locals came into scope.
        let kind = self.lambda_start_kind();
        let Some(kind) = kind else {
            return Ok(None);
        };

        let saved_scope = self.sc.save();
        let outer = self
            .sc
            .names()
            .into_iter()
            .filter_map(|name| self.sc.get(&name).map(|symbol| (symbol, name)))
            .collect::<std::collections::HashMap<_, _>>();

        self.sc.push();
        let params_result = match kind {
            LambdaStart::SingleParam { async_prefix } => {
                if async_prefix {
                    self.cur.advance();
                    self.cur.skip_newlines();
                }
                let param_start = self.cur.pos;
                let name = self.cur.name_with_sigil();
                let symbol =
                    self.define(&strip_ident_sigils(&name), uniflow_hir::SymbolKind::Param);
                Ok(vec![uniflow_hir::Param {
                    name: strip_ident_sigils(&name),
                    symbol,
                    ty: None,
                    kind: uniflow_hir::ParamKind::Positional,
                    has_default: false,
                    keyword_only: false,
                    cpp: uniflow_hir::CppValueSemantics::default(),
                    span: self.cur.span_from(param_start),
                }])
            }
            LambdaStart::Parenthesized { prefix_tokens, .. } => {
                for _ in 0..prefix_tokens {
                    self.cur.advance();
                    self.cur.skip_newlines();
                }
                self.param_list()
            }
            LambdaStart::RustPipe { move_prefix } => {
                if move_prefix {
                    self.cur.advance();
                    self.cur.skip_newlines();
                }
                self.rust_lambda_params()
            }
            LambdaStart::Brace { separator } => self.brace_lambda_params(separator),
        };
        let params = match params_result {
            Ok(params) => params,
            Err(error) => {
                self.sc.restore(saved_scope);
                self.cur.pos = start;
                return Err(error);
            }
        };

        self.cur.skip_newlines();
        match kind {
            LambdaStart::RustPipe { .. } => {}
            LambdaStart::Brace { .. } => {}
            LambdaStart::Parenthesized {
                arrow_required: false,
                ..
            } => {}
            _ => {
                if !self
                    .d
                    .ops
                    .lambda_arrows
                    .iter()
                    .any(|arrow| self.cur.eat(arrow))
                {
                    self.sc.restore(saved_scope);
                    self.cur.pos = start;
                    return Ok(None);
                }
            }
        }
        self.cur.skip_newlines();

        // PHP's long-form anonymous function declares captures between the
        // parameter list and body: `function ($x) use ($outer) { ... }`.
        // Outer symbols already remain visible below the closure scope; the
        // generic free-variable collector turns actual uses into HIR captures.
        if self.d.language == Language::Php && self.cur.at_kw("use") {
            self.cur.advance();
            self.cur.skip_newlines();
            if self.cur.eat("(") {
                let mut depth = 1i32;
                while !self.cur.eof() && depth > 0 {
                    if self.cur.eat("(") {
                        depth += 1;
                    } else if self.cur.eat(")") {
                        depth -= 1;
                    } else {
                        self.cur.advance();
                    }
                }
            } else {
                self.cur.error("expected PHP closure use-list");
            }
            self.cur.skip_newlines();
        }

        // Go function literals may declare one return type or a parenthesized
        // result list before the body. Types do not affect value dependencies,
        // but consuming the header is required to reach and analyze the body.
        if self.d.language == Language::Go
            && matches!(
                kind,
                LambdaStart::Parenthesized {
                    arrow_required: false,
                    ..
                }
            )
            && !self.cur.at("{")
        {
            let mut parens = 0i32;
            while !self.cur.eof() {
                if self.cur.at("{") && parens == 0 {
                    break;
                }
                if self.cur.eat("(") {
                    parens += 1;
                } else if self.cur.eat(")") {
                    parens -= 1;
                } else {
                    self.cur.advance();
                }
            }
            self.cur.skip_newlines();
        }

        let body = if matches!(kind, LambdaStart::Brace { .. }) {
            self.brace_lambda_body(start)?
        } else if self.cur.at("{") {
            let mut hooks = NoHooks;
            self.block_for(&mut hooks, &["}"])?
        } else {
            let expr = self.assignment_expression()?;
            let span = expr_span(&expr);
            Block {
                id: self.b.alloc_block_id(),
                stmts: vec![uniflow_hir::Stmt::Return {
                    id: self.b.alloc_stmt_id(),
                    value: Some(expr),
                    span,
                }],
                span: self.cur.span_from(start),
            }
        };

        let local_symbols = params
            .iter()
            .map(|param| param.symbol)
            .chain(block_local_symbols(&body))
            .collect::<std::collections::HashSet<_>>();
        let mut referenced = Vec::new();
        collect_block_var_refs(&body, &mut referenced);
        let mut seen = std::collections::HashSet::new();
        let captures = referenced
            .into_iter()
            .filter(|symbol| !local_symbols.contains(symbol))
            .filter_map(|source_symbol| {
                let name = outer.get(&source_symbol)?.clone();
                seen.insert(source_symbol)
                    .then_some(uniflow_hir::LambdaCapture {
                        name,
                        source_symbol,
                        // Reusing the resolved symbol is intentional: the synthetic
                        // lambda function receives it as a capture parameter, while
                        // the enclosing function reads the same id into the closure.
                        symbol: source_symbol,
                        ty: None,
                        span: self.cur.span_from(start),
                    })
            })
            .collect();
        self.sc.restore(saved_scope);
        let span = self.cur.span_from(start);
        Ok(Some(Expr::Lambda {
            id: self.b.alloc_expr_id(),
            params,
            captures,
            body,
            span,
        }))
    }

    fn lambda_start_kind(&self) -> Option<LambdaStart> {
        let arrow_after = |mut index: usize| {
            while self.cur.peek(index).kind == TokKind::Newline {
                index += 1;
            }
            self.d
                .ops
                .lambda_arrows
                .iter()
                .any(|arrow| self.cur.peek(index).text == *arrow)
        };
        if self.cur.at_name() && arrow_after(1) {
            return Some(LambdaStart::SingleParam {
                async_prefix: false,
            });
        }
        if self.cur.at_kw("async") && self.cur.peek(1).kind == TokKind::Ident && arrow_after(2) {
            return Some(LambdaStart::SingleParam { async_prefix: true });
        }
        // Only languages with a parenthesized arrow-lambda surface need the
        // balanced look-ahead.  In particular Rust closures use pipes, so
        // scanning to the matching `)` for every parenthesized Rust expression
        // is pure overhead and becomes quadratic for deeply nested code.
        if !self.d.ops.lambda_arrows.is_empty() && self.cur.at("(") {
            if let Some(after) = self.token_after_balanced(self.cur.pos, "(", ")") {
                if self.d.ops.lambda_arrows.iter().any(|arrow| {
                    self.cur
                        .tokens
                        .get(after)
                        .is_some_and(|token| token.text == *arrow)
                }) {
                    return Some(LambdaStart::Parenthesized {
                        prefix_tokens: 0,
                        arrow_required: true,
                    });
                }
            }
        }
        if !self.d.ops.lambda_arrows.is_empty()
            && self.cur.at_kw("async")
            && self.cur.peek(1).text == "("
        {
            if let Some(after) = self.token_after_balanced(self.cur.pos + 1, "(", ")") {
                if self.d.ops.lambda_arrows.iter().any(|arrow| {
                    self.cur
                        .tokens
                        .get(after)
                        .is_some_and(|token| token.text == *arrow)
                }) {
                    return Some(LambdaStart::Parenthesized {
                        prefix_tokens: 1,
                        arrow_required: true,
                    });
                }
            }
        }
        if self.d.language == Language::Go && self.cur.at_kw("func") && self.cur.peek(1).text == "("
        {
            return Some(LambdaStart::Parenthesized {
                prefix_tokens: 1,
                arrow_required: false,
            });
        }
        if self.d.language == Language::Php
            && matches!(self.cur.text(), "fn" | "function")
            && self.cur.peek(1).text == "("
        {
            return Some(LambdaStart::Parenthesized {
                prefix_tokens: 1,
                arrow_required: self.cur.text() == "fn",
            });
        }
        if self.d.language == Language::JavaScript
            && self.cur.at_kw("function")
            && self.cur.peek(1).text == "("
        {
            return Some(LambdaStart::Parenthesized {
                prefix_tokens: 1,
                arrow_required: false,
            });
        }
        if self.d.language == Language::CSharp
            && self.cur.text() == "delegate"
            && self.cur.peek(1).text == "("
        {
            return Some(LambdaStart::Parenthesized {
                prefix_tokens: 1,
                arrow_required: false,
            });
        }
        if matches!(self.d.language, Language::Kotlin | Language::Swift) && self.cur.at("{") {
            return Some(LambdaStart::Brace {
                separator: self.brace_lambda_separator(),
            });
        }
        if self.d.language == Language::Ruby && self.cur.at("->") && self.cur.peek(1).text == "(" {
            return Some(LambdaStart::Parenthesized {
                prefix_tokens: 1,
                arrow_required: false,
            });
        }
        if matches!(self.d.language, Language::ObjC | Language::ObjCpp)
            && self.cur.at("^")
            && self.cur.peek(1).text == "("
        {
            return Some(LambdaStart::Parenthesized {
                prefix_tokens: 1,
                arrow_required: false,
            });
        }
        if self.d.language == Language::Rust && (self.cur.at("|") || self.cur.at("||")) {
            return Some(LambdaStart::RustPipe { move_prefix: false });
        }
        if self.d.language == Language::Rust
            && self.cur.text() == "move"
            && matches!(self.cur.peek(1).text.as_str(), "|" | "||")
        {
            return Some(LambdaStart::RustPipe { move_prefix: true });
        }
        None
    }

    fn brace_lambda_separator(&self) -> Option<&'static str> {
        let wanted = if self.d.language == Language::Kotlin {
            "->"
        } else {
            "in"
        };
        let mut depth = 0i32;
        for token in self.cur.tokens.iter().skip(self.cur.pos) {
            match token.text.as_str() {
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                text if depth == 1 && text == wanted => return Some(wanted),
                _ => {}
            }
        }
        None
    }

    fn brace_lambda_params(
        &mut self,
        separator: Option<&'static str>,
    ) -> anyhow::Result<Vec<uniflow_hir::Param>> {
        self.cur.expect("{");
        self.cur.skip_newlines();
        let Some(separator) = separator else {
            if self.d.language != Language::Kotlin {
                return Ok(Vec::new());
            }
            let symbol = self.define("it", uniflow_hir::SymbolKind::Param);
            return Ok(vec![uniflow_hir::Param {
                name: "it".to_string(),
                symbol,
                ty: None,
                kind: uniflow_hir::ParamKind::Positional,
                has_default: false,
                keyword_only: false,
                cpp: uniflow_hir::CppValueSemantics::default(),
                span: self.cur.span_from(self.cur.pos),
            }]);
        };
        let mut params = Vec::new();
        while !self.cur.eof() && self.cur.text() != separator {
            let start = self.cur.pos;
            let mut group = Vec::new();
            while !self.cur.eof() && !self.cur.at(",") && self.cur.text() != separator {
                group.push(self.cur.advance());
            }
            let text = group.join(" ");
            let (name, ty) = self.split_param(text.trim());
            if !name.is_empty() {
                let symbol = self.define(&name, uniflow_hir::SymbolKind::Param);
                params.push(uniflow_hir::Param {
                    name,
                    symbol,
                    ty: (!ty.is_empty()).then(|| self.b.ensure_type(&ty)),
                    kind: uniflow_hir::ParamKind::Positional,
                    has_default: false,
                    keyword_only: false,
                    cpp: uniflow_hir::CppValueSemantics::default(),
                    span: self.cur.span_from(start),
                });
            }
            if !self.cur.eat(",") {
                break;
            }
            self.cur.skip_newlines();
        }
        if self.cur.text() == separator {
            self.cur.advance();
        } else {
            self.cur.error("expected closure parameter separator");
        }
        self.cur.skip_newlines();
        Ok(params)
    }

    fn brace_lambda_body(&mut self, start: usize) -> anyhow::Result<Block> {
        if self.cur.at_kw("return")
            || self.cur.at_kw("throw")
            || self
                .d
                .decl_introducers
                .iter()
                .any(|word| self.cur.at_kw(word))
        {
            let mut hooks = NoHooks;
            let stmts = self.statements(&mut hooks, &["}"])?;
            self.cur.skip_newlines();
            self.cur.expect("}");
            return Ok(Block {
                id: self.b.alloc_block_id(),
                stmts,
                span: self.cur.span_from(start),
            });
        }
        let expr = self.assignment_expression()?;
        self.cur.skip_newlines();
        self.cur.expect("}");
        let span = expr_span(&expr);
        Ok(Block {
            id: self.b.alloc_block_id(),
            stmts: vec![uniflow_hir::Stmt::Return {
                id: self.b.alloc_stmt_id(),
                value: Some(expr),
                span,
            }],
            span: self.cur.span_from(start),
        })
    }

    fn token_after_balanced(&self, start: usize, open: &str, close: &str) -> Option<usize> {
        let mut depth = 0i32;
        for index in start..self.cur.tokens.len() {
            match self.cur.tokens[index].text.as_str() {
                text if text == open => depth += 1,
                text if text == close => {
                    depth -= 1;
                    if depth == 0 {
                        let mut after = index + 1;
                        while self.cur.tokens.get(after)?.kind == TokKind::Newline {
                            after += 1;
                        }
                        return Some(after);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn rust_lambda_params(&mut self) -> anyhow::Result<Vec<uniflow_hir::Param>> {
        if self.cur.eat("||") {
            return Ok(Vec::new());
        }
        self.cur.expect("|");
        let mut params = Vec::new();
        while !self.cur.eof() && !self.cur.at("|") {
            self.cur.skip_newlines();
            let start = self.cur.pos;
            let name = self.cur.name();
            if name.is_empty() {
                self.cur.error("expected Rust closure parameter");
                self.cur.advance();
                continue;
            }
            let symbol = self.define(&name, uniflow_hir::SymbolKind::Param);
            let ty = if self.cur.eat(":") {
                let text = self.type_text();
                (!text.is_empty()).then(|| self.b.ensure_type(&text))
            } else {
                None
            };
            params.push(uniflow_hir::Param {
                name,
                symbol,
                ty,
                kind: uniflow_hir::ParamKind::Positional,
                has_default: false,
                keyword_only: false,
                cpp: uniflow_hir::CppValueSemantics::default(),
                span: self.cur.span_from(start),
            });
            if !self.cur.eat(",") {
                break;
            }
        }
        self.cur.expect("|");
        Ok(params)
    }

    fn current_assignment_op(&self) -> &'static str {
        for op in self.d.ops.assignment_ops {
            if self.cur.at(op) {
                return op;
            }
        }
        for (op, _) in self.d.ops.compound {
            if self.cur.at(op) {
                return op;
            }
        }
        if self.d.walrus.map_or(false, |walrus| self.cur.at(walrus)) {
            return self.d.walrus.unwrap_or(":=");
        }
        for op in ["||=", "&&=", "??=", ".=", "~="] {
            if self.cur.at(op) {
                return op;
            }
        }
        ""
    }

    fn conditional_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        let cond = self.binary_expression(1)?;
        self.cur.skip_newlines();
        if !self.d.ops.ternary || !self.cur.at("?") {
            return Ok(cond);
        }
        self.cur.advance();
        // `a ?: b` (PHP, Ruby) reuses the condition as the true branch.
        let then_expr = if self.cur.at(":") {
            cond.clone()
        } else {
            self.assignment_expression()?
        };
        self.cur.skip_newlines();
        if !self.cur.expect(":") {
            let span = self.cur.span_from(start);
            return Ok(Expr::Conditional {
                id: self.b.alloc_expr_id(),
                cond: Box::new(cond),
                then_expr: Box::new(then_expr),
                else_expr: Box::new(Expr::Unknown {
                    id: self.b.alloc_expr_id(),
                    span,
                }),
                span,
            });
        }
        self.cur.skip_newlines();
        let else_expr = self.assignment_expression()?;
        let span = self.cur.span_from(start);
        Ok(Expr::Conditional {
            id: self.b.alloc_expr_id(),
            cond: Box::new(cond),
            then_expr: Box::new(then_expr),
            else_expr: Box::new(else_expr),
            span,
        })
    }

    /// Precedence climbing; `min_precedence` is inclusive.
    pub fn binary_expression(&mut self, min_precedence: u8) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        let mut lhs = self.unary_expression()?;
        loop {
            self.cur.skip_newlines();
            let token = self.cur.current().clone();
            let mut op_text = token.text.clone();
            let mut consumed = 1usize;
            if self.d.ops.word_logic
                && token.kind == TokKind::Keyword
                && matches!(token.text.as_str(), "not" | "is")
                && self.word_at(1) == Some("in")
            {
                op_text = "not in".to_string();
                consumed = 2;
            } else if self.d.ops.word_logic
                && token.kind == TokKind::Keyword
                && token.text == "is"
                && self.word_at(1) == Some("not")
            {
                op_text = "is not".to_string();
                consumed = 2;
            }
            let Some(precedence) = self.d.binary_precedence(&op_text) else {
                break;
            };
            if precedence < min_precedence {
                break;
            }
            if self.cur.at(&op_text) || self.cur.at_kw(&op_text) || self.cur.at_name() {
                for _ in 0..consumed {
                    self.cur.advance();
                }
            } else {
                break;
            }
            self.cur.skip_newlines();
            let next_min = if op_text == "**" {
                precedence
            } else {
                precedence + 1
            };
            let rhs = self.binary_expression(next_min)?;
            let span = self.cur.span_from(start);
            lhs = self.combine(lhs, rhs, &op_text, span);
        }
        Ok(lhs)
    }

    fn word_at(&self, ahead: usize) -> Option<&'static str> {
        let token = self.cur.peek(ahead);
        match token.text.as_str() {
            "in" => Some("in"),
            "not" => Some("not"),
            _ => None,
        }
    }

    /// Combine two operands under `op`, choosing the HIR node that preserves the
    /// data dependencies a checker needs.
    fn combine(&mut self, lhs: Expr, rhs: Expr, op: &str, span: uniflow_hir::Span) -> Expr {
        match op {
            "instanceof" | "isa" | "is" | "has" | "in" | "not in" | "is not" | "between" => {
                let binary = match op {
                    "not in" | "is not" => uniflow_hir::BinaryOp::Ne,
                    _ => uniflow_hir::BinaryOp::In,
                };
                self.binary(lhs, rhs, binary, span)
            }
            ".." | "..." => {
                let exclusive = op != "..";
                Expr::Range {
                    id: self.b.alloc_expr_id(),
                    low: Box::new(lhs),
                    high: Box::new(rhs),
                    exclusive,
                    span,
                }
            }
            _ => match binary_op_from_symbol(op) {
                Some(binary) => self.binary(lhs, rhs, binary, span),
                None => Expr::Opaque {
                    id: self.b.alloc_expr_id(),
                    text: format!("unsupported operator `{}`", op),
                    span,
                },
            },
        }
    }

    pub fn binary(
        &mut self,
        lhs: Expr,
        rhs: Expr,
        op: uniflow_hir::BinaryOp,
        span: uniflow_hir::Span,
    ) -> Expr {
        Expr::Binary {
            id: self.b.alloc_expr_id(),
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            span,
        }
    }

    pub fn unary_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        self.cur.skip_newlines();
        let token = self.cur.current().clone();
        for (symbol, op) in self.d.ops.prefix.iter() {
            let matched = self.cur.at(symbol)
                || (self.d.ops.word_logic && *symbol == "!" && self.cur.at_kw("not"));
            if matched {
                self.cur.advance();
                self.cur.skip_newlines();
                let expr = self.unary_expression()?;
                let span = self.cur.span_from(start);
                return Ok(Expr::Unary {
                    id: self.b.alloc_expr_id(),
                    op: *op,
                    expr: Box::new(expr),
                    span,
                });
            }
        }
        if self.d.ops.word_logic && self.cur.at_kw("not") {
            self.cur.advance();
            self.cur.skip_newlines();
            let expr = self.unary_expression()?;
            let span = self.cur.span_from(start);
            return Ok(Expr::Unary {
                id: self.b.alloc_expr_id(),
                op: uniflow_hir::UnaryOp::Not,
                expr: Box::new(expr),
                span,
            });
        }
        if self.d.increment_ops.iter().any(|op| self.cur.at(op)) {
            let op = self.cur.advance();
            self.cur.skip_newlines();
            let operand = self.unary_expression()?;
            let span = self.cur.span_from(start);
            return Ok(self.increment_expr(operand, &op, true, span));
        }
        // Keyword prefix operators that behave like calls.
        let mut prefix_keywords: Vec<&str> = Vec::new();
        for name in ["sizeof", "delete", "unset", "await", "yield", "print"] {
            if self.cur.at_kw(name) {
                prefix_keywords.push(name);
            }
        }
        for keyword in prefix_keywords {
            if !self.cur.at_kw(keyword) {
                continue;
            }
            let name = self.cur.current().text.clone();
            self.cur.advance();
            let span = self.cur.span_from(start);
            let args = if self.at_statement_boundary() || self.cur.at(")") || self.cur.at(",") {
                Vec::new()
            } else {
                vec![self.unary_expression()?]
            };
            return Ok(self.call(&name, None, args, span));
        }
        let _ = token;
        self.postfix_expression()
    }

    pub fn postfix_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        let mut expr = self.primary_expression()?;
        loop {
            self.cur.skip_newlines();
            let token = self.cur.current().clone();
            if self.d.language == Language::Rust
                && self.cur.at("!")
                && !self.cur.current().space_before
            {
                let callee = self.describe_callee(&expr);
                self.cur.advance();
                self.cur.skip_newlines();
                let (open, close) = match self.cur.text() {
                    "(" => ("(", ")"),
                    "[" => ("[", "]"),
                    "{" => ("{", "}"),
                    _ => {
                        self.cur.error("expected Rust macro token tree");
                        break;
                    }
                };
                self.cur.expect(open);
                let args = self.initializer_elements(close)?;
                self.cur.expect(close);
                let span = self.cur.span_from(start);
                expr = match callee {
                    Some((Some(base), name)) => {
                        self.method_call(base, format!("{name}!"), args, span)
                    }
                    Some((None, name)) => self.call(&format!("{name}!"), None, args, span),
                    None => Expr::Call(CallExpr {
                        id: self.b.alloc_expr_id(),
                        target: CallTarget::Dynamic(Box::new(expr)),
                        receiver: None,
                        qualifier_is_explicit: false,
                        args,
                        arg_names: Vec::new(),
                        span,
                    }),
                };
                continue;
            }
            let member_like = self.cur.at(".") || self.d.member_ops.contains(&token.text.as_str());
            if member_like {
                self.cur.advance();
                self.cur.skip_newlines();
                if self.cur.at("(") {
                    // Null-safe call `obj?.(args)`.
                    let args = self.argument_list()?;
                    let span = self.cur.span_from(start);
                    expr = Expr::Call(CallExpr {
                        id: self.b.alloc_expr_id(),
                        target: CallTarget::Dynamic(Box::new(expr)),
                        receiver: None,
                        qualifier_is_explicit: true,
                        args,
                        arg_names: Vec::new(),
                        span,
                    });
                    continue;
                }
                let field = self.cur.name();
                if self.cur.at("(") {
                    let args = self.argument_list()?;
                    let span = self.cur.span_from(start);
                    expr = if self.d.language == Language::Kotlin
                        && looks_like_kotlin_type_name(&field)
                    {
                        let type_name = self
                            .qualified_name(&expr)
                            .map(|base| format!("{base}.{field}"))
                            .unwrap_or(field);
                        Expr::New {
                            id: self.b.alloc_expr_id(),
                            type_name,
                            args,
                            span,
                        }
                    } else {
                        self.method_call(expr, field, args, span)
                    };
                } else if self.d.language == Language::Ruby
                    && !matches!(self.cur.text(), "=" | "+=" | "-=" | "*=" | "/=" | "%=")
                    && !(self.cur.at(".")
                        || self
                            .d
                            .member_ops
                            .contains(&self.cur.current().text.as_str()))
                {
                    // In Ruby, `receiver.method` is a zero-argument method call, not a
                    // field read. Keeping it as a call is required for security models
                    // such as `value.to_json`, chained reflection, and Rails helpers.
                    // Assignment targets stay field writes and are handled below.
                    let span = self.cur.span_from(start);
                    expr = self.method_call(expr, field, Vec::new(), span);
                } else {
                    let span = self.cur.span_from(start);
                    expr = Expr::FieldRead {
                        id: self.b.alloc_expr_id(),
                        base: Box::new(expr),
                        field,
                        span,
                    };
                }
                continue;
            }
            if self.cur.at("(") {
                let callee = self.describe_callee(&expr);
                // Kotlin has no `new` keyword: invoking a type name is a
                // constructor expression.  Preserve that distinction in HIR
                // so constructor rules see `T.init^` after lowering, including
                // fully-qualified external types such as `java.net.URL(...)`.
                // Calls through known function values stay dynamic below.
                let kotlin_constructor = if self.d.language == Language::Kotlin {
                    match &callee {
                        Some((Some(base), name)) if looks_like_kotlin_type_name(name) => self
                            .qualified_name(base)
                            .map(|base| format!("{base}.{name}")),
                        Some((None, name)) if looks_like_kotlin_type_name(name) => {
                            Some(name.clone())
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let args = self.argument_list()?;
                let span = self.cur.span_from(start);
                expr = if matches!(
                    &expr,
                    Expr::VarRef { symbol, .. } if self.callable_values.contains(symbol)
                ) {
                    Expr::Call(CallExpr {
                        id: self.b.alloc_expr_id(),
                        target: CallTarget::Dynamic(Box::new(expr)),
                        receiver: None,
                        qualifier_is_explicit: false,
                        args,
                        arg_names: Vec::new(),
                        span,
                    })
                } else if let Some(type_name) = kotlin_constructor {
                    Expr::New {
                        id: self.b.alloc_expr_id(),
                        type_name,
                        args,
                        span,
                    }
                } else {
                    match callee {
                        Some((Some(base), name)) => {
                            self.method_call(base.clone(), name, args, span)
                        }
                        Some((None, name)) => self.call(&name, None, args, span),
                        None => Expr::Call(CallExpr {
                            id: self.b.alloc_expr_id(),
                            target: CallTarget::Dynamic(Box::new(expr)),
                            receiver: None,
                            qualifier_is_explicit: false,
                            args,
                            arg_names: Vec::new(),
                            span,
                        }),
                    }
                };
                continue;
            }
            if self.cur.at("[") {
                self.cur.advance();
                self.cur.skip_newlines();
                let index = if self.cur.at("]") {
                    Expr::Unknown {
                        id: self.b.alloc_expr_id(),
                        span: self.cur.span_of(self.cur.current()),
                    }
                } else {
                    self.expression()?
                };
                self.cur.skip_newlines();
                // Slice syntax `a[1:2]` keeps both bounds as data sources.
                if self.cur.at(":") {
                    self.cur.advance();
                    let high = if self.cur.at("]") {
                        Expr::Unknown {
                            id: self.b.alloc_expr_id(),
                            span: self.cur.span_from(start),
                        }
                    } else {
                        self.expression()?
                    };
                    self.cur.expect("]");
                    let span = self.cur.span_from(start);
                    expr = Expr::Collection {
                        id: self.b.alloc_expr_id(),
                        container: CollectionKind::List,
                        elements: vec![expr, index, high],
                        span,
                    };
                    continue;
                }
                self.cur.expect("]");
                let span = self.cur.span_from(start);
                expr = Expr::IndexRead {
                    id: self.b.alloc_expr_id(),
                    base: Box::new(expr),
                    index: Box::new(index),
                    span,
                };
                continue;
            }
            if self.d.increment_ops.iter().any(|op| self.cur.at(op))
                && !self.cur.current().space_before
            {
                let op = self.cur.advance();
                let span = self.cur.span_from(start);
                expr = self.increment_expr(expr, &op, false, span);
                continue;
            }
            if (token.kind == TokKind::Keyword || token.kind == TokKind::Ident)
                && self
                    .d
                    .ops
                    .relational_keywords
                    .contains(&token.text.as_str())
            {
                let op = token.text.clone();
                self.cur.advance();
                self.cur.skip_newlines();
                let rhs = self.unary_expression()?;
                let span = self.cur.span_from(start);
                expr = self.combine(expr, rhs, &op, span);
                continue;
            }
            break;
        }
        Ok(expr)
    }

    fn qualified_name(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::VarRef { symbol, .. } => self.symbol_name(*symbol).map(str::to_string),
            Expr::FieldRead { base, field, .. } => self
                .qualified_name(base)
                .map(|base| format!("{base}.{field}")),
            Expr::Cast { expr, .. } | Expr::Unary { expr, .. } => self.qualified_name(expr),
            _ => None,
        }
    }

    pub fn expr_is_callable(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Lambda { .. } => true,
            Expr::VarRef { symbol, .. } => self.callable_values.contains(symbol),
            Expr::Cast { expr, .. } => self.expr_is_callable(expr),
            _ => false,
        }
    }

    pub fn primary_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        self.cur.skip_newlines();
        if self.cur.eof() {
            let span = self.cur.span_of(self.cur.current());
            return Ok(Expr::Unknown {
                id: self.b.alloc_expr_id(),
                span,
            });
        }
        let token = self.cur.current().clone();
        match token.kind {
            TokKind::IntLit => {
                self.cur.advance();
                let value = int_literal_value(&token.text).unwrap_or(i64::MAX);
                return Ok(Expr::Literal {
                    id: self.b.alloc_expr_id(),
                    kind: LiteralKind::Int(value),
                    span: self.cur.span_from(start),
                });
            }
            TokKind::FloatLit => {
                self.cur.advance();
                return Ok(Expr::Literal {
                    id: self.b.alloc_expr_id(),
                    kind: LiteralKind::Float(float_literal_value(&token.text).unwrap_or(0.0)),
                    span: self.cur.span_from(start),
                });
            }
            TokKind::StringLit => {
                self.cur.advance();
                return Ok(self.string_expression(&token, start));
            }
            TokKind::Newline => {
                let span = self.cur.span_of(&token);
                return Ok(Expr::Unknown {
                    id: self.b.alloc_expr_id(),
                    span,
                });
            }
            _ => {}
        }
        if self.cur.at("(") {
            return self.parenthesized_expression();
        }
        if self.d.language == Language::Shell && token.text == "$" && self.cur.peek(1).text == "(" {
            self.cur.advance();
            self.cur.expect("(");
            self.cur.skip_newlines();
            let command = self.expression()?;
            self.cur.skip_newlines();
            self.cur.expect(")");
            let span = self.cur.span_from(start);
            return Ok(self.call("shell.command_substitution", None, vec![command], span));
        }
        if self.cur.at("[") {
            if matches!(self.d.language, Language::ObjC | Language::ObjCpp) {
                return self.objc_message_expression();
            }
            self.cur.advance();
            let container = self.map_literal_depth;
            let elements = self.initializer_elements("]")?;
            self.cur.skip_newlines();
            self.cur.expect("]");
            let span = self.cur.span_from(start);
            let _ = container;
            return Ok(Expr::Collection {
                id: self.b.alloc_expr_id(),
                container: CollectionKind::List,
                elements,
                span,
            });
        }
        if self.cur.at("{") {
            // Map/object literal reached in expression position (the statement
            // engine handles `{` as a block before it gets here).
            self.cur.advance();
            self.map_literal_depth += 1;
            let elements = self.initializer_elements("}");
            self.map_literal_depth -= 1;
            let elements = elements?;
            self.cur.skip_newlines();
            self.cur.expect("}");
            let span = self.cur.span_from(start);
            return Ok(Expr::Collection {
                id: self.b.alloc_expr_id(),
                container: CollectionKind::Map,
                elements,
                span,
            });
        }
        if self.d.language == Language::Shell && self.cur.at("`") {
            self.cur.advance();
            self.cur.skip_newlines();
            let command = self.expression()?;
            self.cur.skip_newlines();
            self.cur.expect("`");
            let span = self.cur.span_from(start);
            return Ok(self.call("shell.command_substitution", None, vec![command], span));
        }
        if self.cur.at("`") {
            let text = self.cur.balanced_text("`", "`");
            let span = self.cur.span_from(start);
            return Ok(Expr::Opaque {
                id: self.b.alloc_expr_id(),
                text,
                span,
            });
        }
        if matches!(token.kind, TokKind::Ident | TokKind::Keyword) {
            return self.name_expression();
        }
        self.cur
            .error(&format!("unexpected token `{}`", token.text));
        self.cur.advance();
        Ok(Expr::Unknown {
            id: self.b.alloc_expr_id(),
            span: self.cur.span_from(start),
        })
    }

    /// Objective-C message send: `[receiver selector:arg other:arg]`.
    /// Selector colons are retained in the normalized callee name because they
    /// are part of an Objective-C method's identity.
    fn objc_message_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        self.cur.expect("[");
        self.cur.skip_newlines();
        let receiver = self.unary_expression()?;
        self.cur.skip_newlines();
        let mut selector = String::new();
        let mut args = Vec::new();
        while !self.cur.eof() && !self.cur.at("]") {
            if !self.cur.at_name() {
                self.cur.error("expected Objective-C selector component");
                self.cur.advance();
                continue;
            }
            selector.push_str(&self.cur.name());
            if self.cur.eat(":") {
                selector.push(':');
                self.cur.skip_newlines();
                args.push(self.binary_expression(1)?);
            }
            self.cur.skip_newlines();
        }
        self.cur.expect("]");
        let span = self.cur.span_from(start);
        if selector.is_empty() {
            self.cur.error("Objective-C message has no selector");
            return Ok(Expr::Unknown {
                id: self.b.alloc_expr_id(),
                span,
            });
        }
        Ok(self.method_call(receiver, selector, args, span))
    }

    /// A name-shaped primary: literals, `self`, `new`, `sizeof`, variables.
    fn name_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        let token = self.cur.current().clone();
        let lowered = token.text.to_ascii_lowercase();
        if matches!(self.d.language, Language::Cpp | Language::ObjCpp)
            && token.text == "nullptr"
        {
            self.cur.advance();
            return Ok(Expr::Literal {
                id: self.b.alloc_expr_id(),
                kind: LiteralKind::Null,
                span: self.cur.span_from(start),
            });
        }
        match lowered.as_str() {
            "true" | "TRUE" => {
                self.cur.advance();
                return Ok(self.boolean(true));
            }
            "false" | "FALSE" => {
                self.cur.advance();
                return Ok(self.boolean(false));
            }
            "null" | "NULL" | "nil" | "None" | "undefined" | "Nothing" | "nothing" => {
                self.cur.advance();
                return Ok(Expr::Literal {
                    id: self.b.alloc_expr_id(),
                    kind: LiteralKind::Null,
                    span: self.cur.span_from(start),
                });
            }
            _ => {}
        }
        if self.d.self_names.contains(&token.text.as_str())
            || self.d.self_names.contains(&lowered.as_str())
        {
            self.cur.advance();
            let symbol = self.self_symbol();
            let span = self.cur.span_from(start);
            return Ok(Expr::VarRef {
                id: self.b.alloc_expr_id(),
                symbol,
                span,
            });
        }
        if self.d.language == Language::Php {
            let name = strip_ident_sigils(&token.text);
            if matches!(
                name.as_str(),
                "_GET" | "_POST" | "_COOKIE" | "_REQUEST" | "_FILES" | "_SERVER" | "_ENV"
            ) {
                self.cur.advance();
                let span = self.cur.span_from(start);
                return Ok(self.call(
                    &format!("php.superglobal.{}", name.trim_start_matches('_')),
                    None,
                    Vec::new(),
                    span,
                ));
            }
        }
        if lowered == "new" && token.kind == TokKind::Keyword {
            self.cur.advance();
            self.cur.skip_newlines();
            let type_name = self.type_text();
            let args = if self.cur.at("(") {
                self.argument_list()?
            } else {
                Vec::new()
            };
            let span = self.cur.span_from(start);
            if self.cur.at("{") {
                // `new T[]{a, b}` / `new T[] { tainted }`: the elements are the
                // data the object carries.
                self.cur.advance();
                let elements = self.initializer_elements("}")?;
                self.cur.expect("}");
                if !elements.is_empty() {
                    return Ok(Expr::Collection {
                        id: self.b.alloc_expr_id(),
                        container: CollectionKind::Array,
                        elements,
                        span: self.cur.span_from(start),
                    });
                }
            }
            return Ok(Expr::New {
                id: self.b.alloc_expr_id(),
                type_name,
                args,
                span,
            });
        }
        let contextual_keyword_call = token.kind == TokKind::Keyword
            && self.cur.peek(1).text == "("
            && self.d.decl_introducers.contains(&token.text.as_str());
        if token.kind == TokKind::Keyword
            && self.is_block_keyword(&token.text)
            && !contextual_keyword_call
        {
            let span = self.cur.span_of(&token);
            return Ok(Expr::Unknown {
                id: self.b.alloc_expr_id(),
                span,
            });
        }
        if token.kind == TokKind::Keyword
            && !self
                .d
                .ops
                .relational_keywords
                .contains(&token.text.as_str())
            && !self.d.kw.function_kw.contains(&token.text.as_str())
            && self.cur.peek(1).text != "("
        {
            self.cur
                .error(&format!("unexpected keyword `{}`", token.text));
            let span = self.cur.span_of(&token);
            self.cur.advance();
            return Ok(Expr::Unknown {
                id: self.b.alloc_expr_id(),
                span,
            });
        }
        let name = token.text.clone();
        self.cur.advance();
        // `foo bar` in Ruby/Shell/PHP is an implicit-paren call when the next
        // token starts an argument.
        if self.d.implicit_call_parens
            && !self.cur.at("(")
            && !self.at_statement_boundary()
            && (self.d.language != Language::Ruby || self.cur.current().space_before)
            && self.starts_argument()
        {
            let mut args = Vec::new();
            loop {
                args.push(self.binary_expression(3)?);
                self.cur.skip_newlines();
                if !(self.cur.at(",")
                    || (self.d.ops.word_logic
                        && !self.at_statement_boundary()
                        && self.starts_argument()))
                {
                    break;
                }
                self.cur.eat(",");
            }
            let span = self.cur.span_from(start);
            return Ok(self.call(&strip_ident_sigils(&name), None, args, span));
        }
        let symbol = self.resolve_or_create(&strip_ident_sigils(&name), SymbolKind::Local);
        let span = self.cur.span_from(start);
        Ok(Expr::VarRef {
            id: self.b.alloc_expr_id(),
            symbol,
            span,
        })
    }

    fn starts_argument(&self) -> bool {
        matches!(
            self.cur.current().kind,
            TokKind::Ident | TokKind::IntLit | TokKind::FloatLit | TokKind::StringLit
        ) || matches!(self.cur.text(), "(" | "[" | "-" | "!" | "&")
    }

    /// `(expr)`, `(a, b)`, or a `(Type) expr` cast.
    fn parenthesized_expression(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        self.cur.expect("(");
        self.cur.skip_newlines();
        if self.cur.eat(")") {
            let span = self.cur.span_from(start);
            return Ok(Expr::Literal {
                id: self.b.alloc_expr_id(),
                kind: LiteralKind::Null,
                span,
            });
        }
        if self.looks_like_cast() {
            let type_name = self.type_text();
            self.cur.skip_newlines();
            self.cur.expect(")");
            self.cur.skip_newlines();
            let inner = self.unary_expression()?;
            let span = self.cur.span_from(start);
            let type_id = Some(self.b.ensure_type(&type_name));
            return Ok(Expr::Cast {
                id: self.b.alloc_expr_id(),
                ty: type_id,
                expr: Box::new(inner),
                span,
            });
        }
        let first = self.expression()?;
        self.cur.skip_newlines();
        if !self.cur.at(",") {
            self.cur.expect(")");
            return Ok(first);
        }
        let mut elements = vec![first];
        while self.cur.eat(",") {
            self.cur.skip_newlines();
            if self.cur.at(")") {
                break;
            }
            elements.push(self.expression()?);
            self.cur.skip_newlines();
        }
        self.cur.expect(")");
        let span = self.cur.span_from(start);
        Ok(Expr::Collection {
            id: self.b.alloc_expr_id(),
            container: CollectionKind::Tuple,
            elements,
            span,
        })
    }

    fn looks_like_cast(&self) -> bool {
        if !self.d.c_casts {
            return false;
        }
        // The opening `(` has already been consumed by
        // `parenthesized_expression`, so the current token is the first type
        // token rather than an offset from the opening delimiter.
        let first = self.cur.current();
        if !matches!(first.kind, TokKind::Ident | TokKind::Keyword) {
            return false;
        }
        // A name bound in scope is a parenthesized expression, not a type.
        if self.sc.get(&first.text).is_some() {
            return false;
        }
        let name = first.text.as_str();
        let primitive = matches!(
            name,
            "int"
                | "char"
                | "float"
                | "double"
                | "long"
                | "short"
                | "unsigned"
                | "signed"
                | "void"
                | "bool"
                | "boolean"
                | "byte"
                | "wchar_t"
                | "size_t"
                | "NSString"
                | "NSInteger"
                | "NSUInteger"
                | "id"
                | "auto"
                | "String"
                | "var"
        );
        let mut probe = 1usize;
        while matches!(self.cur.peek(probe).text.as_str(), "*" | "&") {
            probe += 1;
        }
        let closed = self.cur.peek(probe).text == ")";
        let operand = {
            let next = self.cur.peek(probe + 1);
            matches!(
                next.kind,
                TokKind::Ident | TokKind::IntLit | TokKind::FloatLit | TokKind::StringLit
            ) || matches!(next.text.as_str(), "(" | "!" | "-" | "~" | "*")
        };
        (primitive || is_probable_type_name(name)) && closed && operand
    }

    /// Parse a comma separated element list up to `close`, flattening
    /// `key: value` and `key => value` pairs so a `Map` alternates them.
    pub fn initializer_elements(&mut self, close: &str) -> anyhow::Result<Vec<Expr>> {
        let mut out = Vec::new();
        loop {
            self.cur.skip_newlines();
            if self.cur.at(close) || self.cur.eof() {
                break;
            }
            if !out.is_empty() {
                if !(self.cur.eat(",") || self.cur.eat(";") || self.cur.at_newline()) {
                    break;
                }
                self.cur.skip_newlines();
                if self.cur.at(close) {
                    break;
                }
            }
            if self.looks_like_pair() {
                let key = self.primary_expression()?;
                self.cur.expect(":");
                self.cur.skip_newlines();
                let value = self.expression()?;
                out.push(key);
                out.push(value);
                continue;
            }
            if self.d.map_fat_arrow && self.at_fat_arrow_pair() {
                let key = self.expression()?;
                self.cur.advance();
                self.cur.skip_newlines();
                let value = self.expression()?;
                out.push(key);
                out.push(value);
                continue;
            }
            out.push(self.expression()?);
        }
        Ok(out)
    }

    fn looks_like_pair(&self) -> bool {
        if self.map_literal_depth == 0 {
            return false;
        }
        let name = self.cur.current();
        if !matches!(
            name.kind,
            TokKind::Ident | TokKind::StringLit | TokKind::IntLit
        ) {
            return false;
        }
        // At the beginning of a map element, `key:` is unambiguously a pair.
        // A ternary reaches its colon only after the preceding `?` arm has
        // already been parsed, so enabling ternaries must not disable object
        // literal properties (notably in JavaScript).
        self.cur.peek(1).text == ":"
    }

    fn at_fat_arrow_pair(&self) -> bool {
        let mut probe = 1usize;
        while matches!(self.cur.peek(probe).kind, TokKind::Ident | TokKind::IntLit) {
            probe += 1;
        }
        self.cur.peek(probe).text == "=>"
    }

    /// Argument list `(a, b, name: c)`; named arguments are recorded when the
    /// language uses that spelling.
    pub fn argument_list(&mut self) -> anyhow::Result<Vec<Expr>> {
        self.cur.expect("(");
        // Keep the enclosing list local: a nested call used as an argument
        // also parses an argument list and must not overwrite its parent's
        // labels or accumulated expressions.
        let mut args = Vec::new();
        let mut arg_names = Vec::new();
        loop {
            self.cur.skip_newlines();
            if self.cur.at(")") || self.cur.eof() {
                break;
            }
            if self.d.named_arguments && self.at_named_argument() {
                let label = self.cur.current().text.clone();
                self.cur.advance();
                self.cur.expect(":");
                self.cur.skip_newlines();
                arg_names.push(Some(label));
                let value = self.expression()?;
                args.push(value);
            } else {
                arg_names.push(None);
                let value = self.expression()?;
                args.push(value);
            }
            self.cur.skip_newlines();
            if !self.cur.eat(",") {
                break;
            }
        }
        self.cur.skip_newlines();
        self.cur.expect(")");
        self.arg_names = arg_names;
        Ok(args)
    }

    fn at_named_argument(&self) -> bool {
        self.cur.peek(1).text == ":" && self.cur.current().kind == TokKind::Ident
    }

    /// HIR for a string token, expanding interpolation holes.
    ///
    /// The hole tokens are spliced into the cursor as `__interp(lit, expr, lit)`
    /// and re-parsed, which keeps every embedded expression parsed by the real
    /// expression engine with its original spans.
    pub fn string_expression(&mut self, token: &Token, start: usize) -> Expr {
        let span = self.cur.span_from(start);
        if token.parts.is_empty() {
            return Expr::Literal {
                id: self.b.alloc_expr_id(),
                kind: LiteralKind::String(unescape_source_text(&token.text)),
                span,
            };
        }
        let mut sequence: Vec<Token> = Vec::new();
        sequence.push(synthetic_ident("__interp", token));
        sequence.push(synthetic_symbol("(", token));
        for (index, part) in token.parts.iter().enumerate() {
            if index > 0 {
                sequence.push(synthetic_symbol(",", token));
            }
            if part.is_expr {
                let mut hole = self.cur.lex_sub(part.start, part.end);
                if hole.last().map_or(false, |last| last.kind == TokKind::Eof) {
                    hole.pop();
                }
                if hole.is_empty() {
                    sequence.push(synthetic_symbol(")", token));
                }
                sequence.extend(hole);
            } else {
                sequence.push(synthetic_string(&part.text, token));
            }
        }
        sequence.push(synthetic_symbol(")", token));
        let index = self.cur.pos;
        self.cur.tokens.splice(index..index, sequence);
        match self.parse_interp_call() {
            Ok(expr) => expr,
            Err(error) => {
                self.cur.error(&error.to_string());
                Expr::Literal {
                    id: self.b.alloc_expr_id(),
                    kind: LiteralKind::String(token.string_value()),
                    span,
                }
            }
        }
    }

    fn parse_interp_call(&mut self) -> anyhow::Result<Expr> {
        let start = self.cur.pos;
        if self.cur.text() != "__interp" {
            anyhow::bail!("expected an interpolation marker");
        }
        self.cur.advance();
        let parts = self.argument_list()?;
        let span = self.cur.span_from(start);
        Ok(Expr::Interp {
            id: self.b.alloc_expr_id(),
            parts,
            span,
        })
    }
}

fn looks_like_kotlin_type_name(name: &str) -> bool {
    name.rsplit('.')
        .next()
        .and_then(|segment| segment.trim_matches('`').chars().next())
        .is_some_and(char::is_uppercase)
}

#[derive(Clone, Copy, Debug)]
enum LambdaStart {
    SingleParam {
        async_prefix: bool,
    },
    Parenthesized {
        prefix_tokens: usize,
        arrow_required: bool,
    },
    RustPipe {
        move_prefix: bool,
    },
    Brace {
        separator: Option<&'static str>,
    },
}

fn expr_span(expr: &Expr) -> uniflow_hir::Span {
    match expr {
        Expr::VarRef { span, .. }
        | Expr::Literal { span, .. }
        | Expr::Unary { span, .. }
        | Expr::Binary { span, .. }
        | Expr::FieldRead { span, .. }
        | Expr::IndexRead { span, .. }
        | Expr::Lambda { span, .. }
        | Expr::New { span, .. }
        | Expr::Cast { span, .. }
        | Expr::Conditional { span, .. }
        | Expr::Assign { span, .. }
        | Expr::Interp { span, .. }
        | Expr::Collection { span, .. }
        | Expr::Range { span, .. }
        | Expr::Opaque { span, .. }
        | Expr::Unknown { span, .. } => *span,
        Expr::Call(call) => call.span,
    }
}

fn block_local_symbols(block: &Block) -> std::vec::IntoIter<uniflow_hir::SymbolId> {
    let mut out = Vec::new();
    collect_block_local_symbols(block, &mut out);
    out.into_iter()
}

fn collect_block_local_symbols(block: &Block, out: &mut Vec<uniflow_hir::SymbolId>) {
    for stmt in &block.stmts {
        match stmt {
            uniflow_hir::Stmt::Let { symbol, .. } => out.push(*symbol),
            uniflow_hir::Stmt::ForEach {
                item_symbol, body, ..
            } => {
                out.push(*item_symbol);
                collect_block_local_symbols(body, out);
            }
            uniflow_hir::Stmt::For { init, update, body, .. } => {
                collect_block_local_symbols(init, out);
                collect_block_local_symbols(update, out);
                collect_block_local_symbols(body, out);
            }
            uniflow_hir::Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                collect_block_local_symbols(then_block, out);
                if let Some(block) = else_block {
                    collect_block_local_symbols(block, out);
                }
            }
            uniflow_hir::Stmt::While { body, .. } | uniflow_hir::Stmt::DoWhile { body, .. } => {
                collect_block_local_symbols(body, out)
            }
            uniflow_hir::Stmt::Switch {
                clauses, default, ..
            } => {
                for clause in clauses {
                    collect_block_local_symbols(&clause.body, out);
                }
                if let Some(block) = default {
                    collect_block_local_symbols(block, out);
                }
            }
            uniflow_hir::Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_block_local_symbols(try_block, out);
                for catch in catches {
                    if let Some(symbol) = catch.symbol {
                        out.push(symbol);
                    }
                    collect_block_local_symbols(&catch.body, out);
                }
                if let Some(block) = finally_block {
                    collect_block_local_symbols(block, out);
                }
            }
            uniflow_hir::Stmt::Assign { .. }
            | uniflow_hir::Stmt::Expr { .. }
            | uniflow_hir::Stmt::Return { .. }
            | uniflow_hir::Stmt::Throw { .. }
            | uniflow_hir::Stmt::Break { .. }
            | uniflow_hir::Stmt::Continue { .. } => {}
        }
    }
}

fn collect_block_var_refs(block: &Block, out: &mut Vec<uniflow_hir::SymbolId>) {
    for stmt in &block.stmts {
        match stmt {
            uniflow_hir::Stmt::Let { init, .. } => {
                if let Some(expr) = init {
                    collect_expr_var_refs(expr, out);
                }
            }
            uniflow_hir::Stmt::Assign { lhs, rhs, .. } => {
                collect_lvalue_var_refs(lhs, out);
                collect_expr_var_refs(rhs, out);
            }
            uniflow_hir::Stmt::Expr { expr, .. } => collect_expr_var_refs(expr, out),
            uniflow_hir::Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                collect_expr_var_refs(cond, out);
                collect_block_var_refs(then_block, out);
                if let Some(block) = else_block {
                    collect_block_var_refs(block, out);
                }
            }
            uniflow_hir::Stmt::While { cond, body, .. }
            | uniflow_hir::Stmt::DoWhile { cond, body, .. } => {
                collect_expr_var_refs(cond, out);
                collect_block_var_refs(body, out);
            }
            uniflow_hir::Stmt::ForEach { iterable, body, .. } => {
                collect_expr_var_refs(iterable, out);
                collect_block_var_refs(body, out);
            }
            uniflow_hir::Stmt::For { init, cond, update, body, .. } => {
                collect_block_var_refs(init, out);
                if let Some(cond) = cond { collect_expr_var_refs(cond, out); }
                collect_block_var_refs(update, out);
                collect_block_var_refs(body, out);
            }
            uniflow_hir::Stmt::Return { value, .. } | uniflow_hir::Stmt::Throw { value, .. } => {
                if let Some(expr) = value {
                    collect_expr_var_refs(expr, out);
                }
            }
            uniflow_hir::Stmt::Try {
                try_block,
                catches,
                finally_block,
                ..
            } => {
                collect_block_var_refs(try_block, out);
                for catch in catches {
                    collect_block_var_refs(&catch.body, out);
                }
                if let Some(block) = finally_block {
                    collect_block_var_refs(block, out);
                }
            }
            uniflow_hir::Stmt::Switch {
                scrutinee,
                clauses,
                default,
                ..
            } => {
                collect_expr_var_refs(scrutinee, out);
                for clause in clauses {
                    for value in &clause.values {
                        collect_expr_var_refs(value, out);
                    }
                    collect_block_var_refs(&clause.body, out);
                }
                if let Some(block) = default {
                    collect_block_var_refs(block, out);
                }
            }
            uniflow_hir::Stmt::Break { .. } | uniflow_hir::Stmt::Continue { .. } => {}
        }
    }
}

fn collect_lvalue_var_refs(lvalue: &uniflow_hir::LValue, out: &mut Vec<uniflow_hir::SymbolId>) {
    match lvalue {
        uniflow_hir::LValue::Var(symbol) => out.push(*symbol),
        uniflow_hir::LValue::Field { base, .. } => collect_expr_var_refs(base, out),
        uniflow_hir::LValue::Index { base, index } => {
            collect_expr_var_refs(base, out);
            collect_expr_var_refs(index, out);
        }
    }
}

fn collect_expr_var_refs(expr: &Expr, out: &mut Vec<uniflow_hir::SymbolId>) {
    match expr {
        Expr::VarRef { symbol, .. } => out.push(*symbol),
        Expr::Unary { expr, .. } | Expr::Cast { expr, .. } => collect_expr_var_refs(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_expr_var_refs(lhs, out);
            collect_expr_var_refs(rhs, out);
        }
        Expr::FieldRead { base, .. } => collect_expr_var_refs(base, out),
        Expr::IndexRead { base, index, .. } => {
            collect_expr_var_refs(base, out);
            collect_expr_var_refs(index, out);
        }
        Expr::Call(call) => {
            if let CallTarget::Dynamic(callee) = &call.target {
                collect_expr_var_refs(callee, out);
            }
            if let Some(receiver) = &call.receiver {
                collect_expr_var_refs(receiver, out);
            }
            for arg in &call.args {
                collect_expr_var_refs(arg, out);
            }
        }
        Expr::Lambda { captures, .. } => {
            out.extend(captures.iter().map(|capture| capture.source_symbol));
        }
        Expr::New { args, .. } => {
            for arg in args {
                collect_expr_var_refs(arg, out);
            }
        }
        Expr::Conditional {
            cond,
            then_expr,
            else_expr,
            ..
        } => {
            collect_expr_var_refs(cond, out);
            collect_expr_var_refs(then_expr, out);
            collect_expr_var_refs(else_expr, out);
        }
        Expr::Assign { lhs, rhs, .. } => {
            collect_lvalue_var_refs(lhs, out);
            collect_expr_var_refs(rhs, out);
        }
        Expr::Interp { parts, .. }
        | Expr::Collection {
            elements: parts, ..
        } => {
            for part in parts {
                collect_expr_var_refs(part, out);
            }
        }
        Expr::Range { low, high, .. } => {
            collect_expr_var_refs(low, out);
            collect_expr_var_refs(high, out);
        }
        Expr::Literal { .. } | Expr::Opaque { .. } | Expr::Unknown { .. } => {}
    }
}

/// Turn a parsed expression into an lvalue when it names a storage location.
pub fn to_lvalue(expr: Expr) -> Option<uniflow_hir::LValue> {
    match expr {
        Expr::VarRef { symbol, .. } => Some(uniflow_hir::LValue::Var(symbol)),
        Expr::FieldRead { base, field, .. } => Some(uniflow_hir::LValue::Field { base, field }),
        Expr::IndexRead { base, index, .. } => Some(uniflow_hir::LValue::Index { base, index }),
        _ => None,
    }
}

/// Map an operator token onto HIR arithmetic.
pub fn binary_op_from_symbol(op: &str) -> Option<uniflow_hir::BinaryOp> {
    Some(match op {
        "+" => uniflow_hir::BinaryOp::Add,
        "-" => uniflow_hir::BinaryOp::Sub,
        "*" => uniflow_hir::BinaryOp::Mul,
        "/" => uniflow_hir::BinaryOp::Div,
        "%" | "mod" => uniflow_hir::BinaryOp::Mod,
        "&&" | "and" => uniflow_hir::BinaryOp::And,
        "||" | "or" => uniflow_hir::BinaryOp::Or,
        "&" => uniflow_hir::BinaryOp::BitAnd,
        "|" => uniflow_hir::BinaryOp::BitOr,
        "^" => uniflow_hir::BinaryOp::BitXor,
        "==" | "===" | "eq" => uniflow_hir::BinaryOp::Eq,
        "!=" | "!==" | "ne" | "<>" => uniflow_hir::BinaryOp::Ne,
        "<" | "lt" => uniflow_hir::BinaryOp::Lt,
        "<=" | "le" => uniflow_hir::BinaryOp::Le,
        ">" | "gt" => uniflow_hir::BinaryOp::Gt,
        ">=" | "ge" => uniflow_hir::BinaryOp::Ge,
        "in" | "contains" | "has" | "between" | "like" | "RLIKE" | "REGEXP" => {
            uniflow_hir::BinaryOp::In
        }
        _ => return None,
    })
}

fn synthetic_ident(text: &str, source: &Token) -> Token {
    Token {
        kind: TokKind::Ident,
        text: text.to_string(),
        parts: Vec::new(),
        start: source.start,
        end: source.end,
        line: source.line,
        col: source.col,
        space_before: false,
        newlines_before: 0,
        is_keyword: false,
    }
}

fn synthetic_symbol(text: &str, source: &Token) -> Token {
    Token {
        kind: TokKind::Symbol,
        text: text.to_string(),
        ..synthetic_ident(text, source)
    }
}

fn synthetic_string(text: &str, source: &Token) -> Token {
    Token {
        kind: TokKind::StringLit,
        text: format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")),
        ..synthetic_ident(text, source)
    }
}
