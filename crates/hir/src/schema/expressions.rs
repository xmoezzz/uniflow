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
    /// `cond ? a : b`, `a and b or c`, Ruby/Shell ternaries. The result carries
    /// data from whichever branch is taken.
    Conditional {
        id: ExprId,
        cond: Box<Expr>,
        then_expr: Box<Expr>,
        else_expr: Box<Expr>,
        span: Span,
    },
    /// Assignment used in expression position, e.g. `while ((line = read()) != nil)`.
    /// The value of the expression is the assigned value.
    Assign {
        id: ExprId,
        lhs: LValue,
        rhs: Box<Expr>,
        span: Span,
    },
    /// String interpolation: the literal text and the embedded expressions in
    /// source order. Frontends keep constant parts so a checker can still read
    /// the command prefix a tainted value was interpolated into.
    Interp {
        id: ExprId,
        parts: Vec<Expr>,
        span: Span,
    },
    /// Container literal (`[a, b]`, `{k: v}`, `(a, b)`, `${a}`, `$(a)`). Elements
    /// are stored flat; a `Dict` alternates key and value.
    Collection {
        id: ExprId,
        container: CollectionKind,
        elements: Vec<Expr>,
        span: Span,
    },
    /// Ranges (`1..5`, `1...n`, Ruby `..`, Go/SQL `between`).
    Range {
        id: ExprId,
        low: Box<Expr>,
        high: Box<Expr>,
        /// True for exclusive upper bounds.
        exclusive: bool,
        span: Span,
    },
    /// A construct the frontend recognized but cannot model (JSX, a JSP tag, a
    /// shell pipeline stage). Keeps the source text for diagnostics.
    Opaque {
        id: ExprId,
        text: String,
        span: Span,
    },
    Unknown {
        id: ExprId,
        span: Span,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollectionKind {
    List,
    Set,
    Tuple,
    Map,
    Array,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallExpr {
    pub id: ExprId,
    pub target: CallTarget,
    pub receiver: Option<Box<Expr>>,
    /// True when source syntax contained an explicit qualifier (`value.call`
    /// or `Type.call`), rather than a frontend-injected implicit receiver.
    #[serde(default)]
    pub qualifier_is_explicit: bool,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    PreIncrement,
    PostIncrement,
    PreDecrement,
    PostDecrement,
    Neg,
    Not,
    BitNot,
    AddrOf,
    Deref,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
