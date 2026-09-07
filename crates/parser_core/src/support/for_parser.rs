impl<'a> Pg<'a> {
    fn classic_for_statement<H: LangHooks>(
        &mut self, hooks: &mut H, start: usize, header_start: usize,
        header_end: usize, parenthesized: bool,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        let separators = self.for_header_separators(header_start, header_end);
        anyhow::ensure!(separators.len() == 2, "three-clause for requires exactly two separators");
        let first = &self.cur.tokens[header_start].text;
        let init_is_scoped = match self.d.language {
            uniflow_hir::Language::Php | uniflow_hir::Language::Shell => false,
            uniflow_hir::Language::JavaScript => matches!(first.as_str(), "let" | "const"),
            _ => true,
        };
        let saved_scope = self.sc.depth();
        if init_is_scoped { self.sc.push(); }
        let result = (|| {
            let init = self.for_clause(hooks, header_start, separators[0], true)?;
            let condition_start = separators[0] + 1;
            let condition_end = separators[1];
            let cond = if self.cur.tokens[condition_start..condition_end].iter()
                .all(|token| token.kind == TokKind::Newline)
            { None } else {
                Some(self.in_for_range(condition_start, condition_end, |pg| {
                    let expr = pg.expression()?;
                    pg.cur.skip_newlines();
                    anyhow::ensure!(pg.cur.eof(), "unconsumed for condition tokens");
                    Ok(expr)
                })?)
            };
            let update = self.for_clause(hooks, separators[1] + 1, header_end, false)?;
            self.cur.pos = header_end;
            self.cur.depth = 0;
            if parenthesized { self.cur.expect(")"); }
            let body = self.block_for(hooks, &["end", "done", "od", "}"])?;
            self.consume_loop_end();
            let span = self.cur.span_from(start);
            self.terminator();
            Ok(Some(uniflow_hir::Stmt::For {
                id: self.b.alloc_stmt_id(), init_is_scoped, init, cond, update, body, span,
            }))
        })();
        while self.sc.depth() > saved_scope { self.sc.pop(); }
        result
    }

    /// Only top-level semicolons split the header. Function literals, strings
    /// and calls inside a clause cannot introduce an extra header boundary.
    fn for_header_separators(&self, start: usize, end: usize) -> Vec<usize> {
        let mut depth = 0usize;
        let mut result = Vec::new();
        for index in start..end {
            let token = &self.cur.tokens[index];
            if token.kind != TokKind::Symbol { continue; }
            match token.text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => depth = depth.saturating_sub(1),
                ";" if depth == 0 => result.push(index),
                _ => {}
            }
        }
        result
    }

    /// Bound parsing to one original token range, without rebuilding source
    /// text. The local EOF prevents a statement parser from eating the next
    /// clause or body; all byte/line locations remain those of the input file.
    fn in_for_range<T>(
        &mut self, start: usize, end: usize,
        parse: impl FnOnce(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut tokens = self.cur.tokens[start..end].to_vec();
        let mut eof = self.cur.tokens[end].clone();
        eof.kind = TokKind::Eof;
        eof.text.clear();
        eof.end = eof.start;
        eof.is_keyword = false;
        tokens.push(eof);
        let mut cursor = Cursor::new(self.cur.source, self.cur.spec, tokens, self.cur.file);
        cursor.depth = 1;
        let outer = std::mem::replace(&mut self.cur, cursor);
        let pending = std::mem::take(&mut self.pending_stmts);
        let result = parse(self);
        let errors = std::mem::take(&mut self.cur.errors);
        self.cur = outer;
        self.cur.errors.extend(errors);
        self.pending_stmts = pending;
        result
    }

    fn for_clause<H: LangHooks>(
        &mut self, hooks: &mut H, start: usize, end: usize, initializer: bool,
    ) -> anyhow::Result<Block> {
        let start_byte = self.cur.tokens[start].start as usize;
        let end_byte = self.cur.tokens[end].start as usize;
        let span = span_from_offsets_file(self.cur.file, self.cur.source, start_byte, end_byte);
        let stmts = self.in_for_range(start, end, |pg| {
            let mut stmts = Vec::new();
            let mut declaration_type = None;
            while !pg.cur.eof() {
                pg.cur.skip_newlines();
                if pg.cur.eof() { break; }
                let before = pg.cur.pos;
                if pg.cur.eat(",") {
                    if let Some(ty) = declaration_type {
                        let begin = pg.cur.pos;
                        let name = pg.cur.name_with_sigil();
                        anyhow::ensure!(!name.is_empty(), "missing for declarator");
                        let init = if pg.cur.eat("=") { Some(pg.expression()?) } else { None };
                        let symbol = pg.define(&strip_ident_sigils(&name), uniflow_hir::SymbolKind::Local);
                        if init.as_ref().is_some_and(|expr| pg.expr_is_callable(expr)) {
                            pg.callable_values.insert(symbol);
                        }
                        stmts.push(uniflow_hir::Stmt::Let { id: pg.b.alloc_stmt_id(), symbol, ty, init,
                            span: pg.cur.span_from(begin) });
                        continue;
                    }
                    continue;
                }
                // Go short declarations introduce a new header-local binding,
                // even when an outer scope already contains the same name.
                let short_decl = initializer && pg.d.language == uniflow_hir::Language::Go
                    && pg.cur.current().kind == TokKind::Ident && pg.cur.peek(1).text == ":=";
                let statement = if short_decl {
                    let name = pg.cur.name_with_sigil();
                    pg.cur.expect(":=");
                    let value = pg.expression()?;
                    let symbol = pg.define(&name, uniflow_hir::SymbolKind::Local);
                    Some(uniflow_hir::Stmt::Let { id: pg.b.alloc_stmt_id(), symbol, ty: None,
                        init: Some(value), span: pg.cur.span_from(before) })
                } else { pg.statement(hooks)? };
                if let Some(statement) = statement {
                    if initializer && stmts.is_empty() {
                        if let uniflow_hir::Stmt::Let { ty, .. } = &statement { declaration_type = Some(*ty); }
                    }
                    stmts.push(statement);
                }
                anyhow::ensure!(pg.cur.pos > before || pg.cur.eof(), "for clause parser made no progress");
            }
            Ok(stmts)
        })?;
        Ok(Block { id: self.b.alloc_block_id(), stmts, span })
    }
}
