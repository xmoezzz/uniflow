#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub id: SymbolId,
    pub name: String,
    pub kind: SymbolKind,
    pub declared_in: Option<ModuleId>,
    pub span: Span,
    pub attributes: IndexMap<String, String>,
    #[serde(default)]
    pub cpp: Option<CppSymbolSemantics>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SymbolKind {
    Local,
    Param,
    Function,
    Method,
    Field,
    Global,
    Class,
    Module,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Type {
    pub id: TypeId,
    pub name: String,
    pub kind: TypeKind,
    #[serde(default)]
    pub cpp: CppValueSemantics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TypeKind {
    Primitive,
    Named,
    Pointer(TypeId),
    Array(TypeId),
    Function {
        params: Vec<TypeId>,
        ret: Option<TypeId>,
    },
    Unknown,
}


