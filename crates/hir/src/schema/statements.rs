#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Stmt {
    Let {
        id: StmtId,
        symbol: SymbolId,
        ty: Option<TypeId>,
        init: Option<Expr>,
        span: Span,
    },
    Assign {
        id: StmtId,
        lhs: LValue,
        rhs: Expr,
        span: Span,
    },
    Expr {
        id: StmtId,
        expr: Expr,
        span: Span,
    },
    If {
        id: StmtId,
        cond: Expr,
        then_block: Block,
        else_block: Option<Block>,
        span: Span,
    },
    While {
        id: StmtId,
        cond: Expr,
        body: Block,
        span: Span,
    },
    ForEach {
        id: StmtId,
        item_symbol: SymbolId,
        iterable: Expr,
        body: Block,
        span: Span,
    },
    Return {
        id: StmtId,
        value: Option<Expr>,
        span: Span,
    },
    Throw {
        id: StmtId,
        value: Option<Expr>,
        span: Span,
    },
    Try {
        id: StmtId,
        try_block: Block,
        catches: Vec<CatchClause>,
        finally_block: Option<Block>,
        span: Span,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatchClause {
    pub symbol: Option<SymbolId>,
    pub ty: Option<TypeId>,
    pub body: Block,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LambdaCapture {
    pub name: String,
    pub source_symbol: SymbolId,
    pub symbol: SymbolId,
    pub ty: Option<TypeId>,
    pub span: Span,
}
