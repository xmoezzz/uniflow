#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    C,
    Cpp,
    Java,
    Python,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub file: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Program {
    pub language: Language,
    pub files: Vec<SourceFile>,
    pub modules: Vec<Module>,
    pub symbols: Vec<Symbol>,
    pub types: Vec<Type>,
    #[serde(default)]
    pub source_maps: Vec<SourceMap>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMap {
    pub file: FileId,
    pub original_len: u32,
    pub normalized_len: u32,
    #[serde(default)]
    pub original_line_starts: Vec<u32>,
    #[serde(default)]
    pub segments: Vec<SourceMapSegment>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMapSegment {
    pub normalized_start: u32,
    pub normalized_end: u32,
    pub original_start: u32,
    pub original_end: u32,
}

impl SourceMap {
    pub fn map_offset(&self, normalized: u32) -> u32 {
        let normalized = normalized.min(self.normalized_len);
        if normalized == self.normalized_len {
            return self.original_len;
        }
        let Some(segment) = self.segments.iter().find(|segment| {
            normalized >= segment.normalized_start && normalized < segment.normalized_end
        }) else {
            return normalized.min(self.original_len);
        };
        let normalized_width = segment.normalized_end.saturating_sub(segment.normalized_start);
        let original_width = segment.original_end.saturating_sub(segment.original_start);
        if normalized_width == 0 {
            return segment.original_start.min(self.original_len);
        }
        let relative = normalized.saturating_sub(segment.normalized_start);
        segment
            .original_start
            .saturating_add(((relative as u64 * original_width as u64) / normalized_width as u64) as u32)
            .min(self.original_len)
    }

    pub fn remap_span(&self, span: Span) -> Span {
        if span.file != self.file.0 {
            return span;
        }
        let start_byte = self.map_offset(span.start_byte);
        let end_byte = self.map_offset(span.end_byte).max(start_byte);
        let (start_line, start_col) = self.line_col(start_byte);
        let (end_line, end_col) = self.line_col(end_byte);
        Span {
            file: span.file,
            start_byte,
            end_byte,
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }

    fn line_col(&self, offset: u32) -> (u32, u32) {
        if self.original_line_starts.is_empty() {
            return (1, offset.saturating_add(1));
        }
        let index = self
            .original_line_starts
            .partition_point(|start| *start <= offset)
            .saturating_sub(1);
        let line_start = self.original_line_starts[index];
        (index as u32 + 1, offset.saturating_sub(line_start) + 1)
    }
}

impl Program {
    pub fn remap_span_to_original(&self, span: Span) -> Span {
        self.source_maps
            .iter()
            .find(|map| map.file.0 == span.file)
            .map_or(span, |map| map.remap_span(span))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceFile {
    pub id: FileId,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Module {
    pub id: ModuleId,
    pub file: FileId,
    pub name: String,
    pub imports: Vec<Import>,
    pub items: Vec<Item>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Import {
    pub path: String,
    pub alias: Option<String>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Item {
    Function(Function),
    Class(Class),
    GlobalVar(GlobalVar),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Function {
    pub id: FunctionId,
    pub name: String,
    pub symbol: Option<SymbolId>,
    pub params: Vec<Param>,
    pub captures: Vec<Param>,
    pub return_type: Option<TypeId>,
    pub body: Block,
    pub is_method: bool,
    pub receiver: Option<Param>,
    #[serde(default)]
    pub cpp: Option<CppMethodSemantics>,
    #[serde(default)]
    pub cpp_initializers: Vec<CppConstructorInitializer>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ParamKind {
    Positional,
    VarArgs,
    KwArgs,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub symbol: SymbolId,
    pub ty: Option<TypeId>,
    pub kind: ParamKind,
    pub has_default: bool,
    pub keyword_only: bool,
    #[serde(default)]
    pub cpp: CppValueSemantics,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Class {
    pub name: String,
    pub symbol: Option<SymbolId>,
    pub bases: Vec<String>,
    pub fields: Vec<Field>,
    pub methods: Vec<Function>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub symbol: Option<SymbolId>,
    pub ty: Option<TypeId>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalVar {
    pub name: String,
    pub symbol: Option<SymbolId>,
    pub ty: Option<TypeId>,
    pub init: Option<Expr>,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub id: BlockId,
    pub stmts: Vec<Stmt>,
    pub span: Span,
}
