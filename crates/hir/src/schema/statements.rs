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
    /// A three-clause loop. Initialization runs once; continue targets update,
    /// and update completes before the next condition evaluation.
    For {
        id: StmtId,
        /// Whether names introduced by the initializer belong to the loop's
        /// lexical scope (false for PHP variables and JavaScript `var`).
        #[serde(default)]
        init_is_scoped: bool,
        init: Block,
        cond: Option<Expr>,
        update: Block,
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
    /// `break` / `exit` / a labeled break. Control leaves the innermost loop
    /// (or the labelled one) without producing a value.
    Break {
        id: StmtId,
        label: Option<String>,
        span: Span,
    },
    /// `continue` / `next` / a labeled continue. Control restarts the loop.
    Continue {
        id: StmtId,
        label: Option<String>,
        span: Span,
    },
    /// `do { body } while (cond)` and Ruby's `begin ... end while`.
    DoWhile {
        id: StmtId,
        body: Block,
        cond: Expr,
        span: Span,
    },
    /// `switch`/`select`/`case`. `clauses` keep their values so a checker can
    /// reason about exhaustiveness; `fallthrough` marks C-style implicit flow.
    Switch {
        id: StmtId,
        scrutinee: Expr,
        clauses: Vec<SwitchClause>,
        default: Option<Block>,
        span: Span,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchClause {
    /// Case expressions; empty for a `default` clause carried in the list.
    pub values: Vec<Expr>,
    pub body: Block,
    /// True when control continues into the following clause.
    pub fallthrough: bool,
    pub span: Span,
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
