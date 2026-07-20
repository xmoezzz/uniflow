#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Expr {
    VarRef {
        id: ExprId,
        symbol: SymbolId,
        span: Span,
    },
    Literal {
        id: ExprId,
        kind: LiteralKind,
        span: Span,
    },
    Unary {
        id: ExprId,
        op: UnaryOp,
        expr: Box<Expr>,
        span: Span,
    },
    Binary {
        id: ExprId,
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
        span: Span,
    },
    FieldRead {
        id: ExprId,
        base: Box<Expr>,
        field: String,
        span: Span,
    },
    IndexRead {
        id: ExprId,
        base: Box<Expr>,
        index: Box<Expr>,
        span: Span,
    },
    Call(CallExpr),
    Lambda {
        id: ExprId,
        params: Vec<Param>,
        captures: Vec<LambdaCapture>,
        body: Block,
        span: Span,
    },
    New {
        id: ExprId,
        type_name: String,
        args: Vec<Expr>,
        span: Span,
    },
    Cast {
        id: ExprId,
        ty: Option<TypeId>,
        expr: Box<Expr>,
        span: Span,
    },
    Unknown {
        id: ExprId,
        span: Span,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallExpr {
    pub id: ExprId,
    pub target: CallTarget,
    pub receiver: Option<Box<Expr>>,
    pub args: Vec<Expr>,
    pub arg_names: Vec<Option<String>>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CallTarget {
    Resolved(SymbolId),
    Named(String),
    Dynamic(Box<Expr>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LValue {
    Var(SymbolId),
    Field { base: Box<Expr>, field: String },
    Index { base: Box<Expr>, index: Box<Expr> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LiteralKind {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UnaryOp {
    Neg,
    Not,
    BitNot,
    AddrOf,
    Deref,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
}
