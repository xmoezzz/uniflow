pub struct ModuleBuilder {
    language: Language,
    file: SourceFile,
    module: Module,
    symbols: Vec<Symbol>,
    types: Vec<Type>,
    next_function_id: u32,
    next_block_id: u32,
    next_stmt_id: u32,
    next_expr_id: u32,
    next_symbol_id: u32,
    next_type_id: u32,
}

impl ModuleBuilder {
    pub fn new(language: Language, path: &str, module_name: &str) -> Self {
        let file = SourceFile {
            id: FileId(0),
            path: path.to_string(),
        };
        let module = Module {
            id: ModuleId(0),
            file: file.id,
            name: module_name.to_string(),
            imports: Vec::new(),
            items: Vec::new(),
            span: default_span(),
        };
        Self {
            language,
            file,
            module,
            symbols: Vec::new(),
            types: Vec::new(),
            next_function_id: 0,
            next_block_id: 0,
            next_stmt_id: 0,
            next_expr_id: 0,
            next_symbol_id: 0,
            next_type_id: 0,
        }
    }

    pub fn add_import(&mut self, path: &str, alias: Option<String>) {
        self.module.imports.push(Import {
            path: path.to_string(),
            alias,
            span: default_span(),
        });
    }

    pub fn file_id(&self) -> FileId {
        self.file.id
    }

    pub fn alloc_function_id(&mut self) -> FunctionId {
        let id = FunctionId(self.next_function_id);
        self.next_function_id += 1;
        id
    }

    pub fn alloc_block_id(&mut self) -> BlockId {
        let id = BlockId(self.next_block_id);
        self.next_block_id += 1;
        id
    }

    pub fn alloc_stmt_id(&mut self) -> StmtId {
        let id = StmtId(self.next_stmt_id);
        self.next_stmt_id += 1;
        id
    }

    pub fn alloc_expr_id(&mut self) -> ExprId {
        let id = ExprId(self.next_expr_id);
        self.next_expr_id += 1;
        id
    }

    pub fn add_symbol(&mut self, name: &str, kind: SymbolKind) -> SymbolId {
        let id = SymbolId(self.next_symbol_id);
        self.next_symbol_id += 1;
        self.symbols.push(Symbol {
            id,
            name: name.to_string(),
            kind,
            declared_in: Some(self.module.id),
            span: default_span(),
            attributes: IndexMap::new(),
            cpp: None,
        });
        id
    }

    pub fn set_symbol_attribute(&mut self, id: SymbolId, key: &str, value: String) {
        if let Some(symbol) = self.symbols.iter_mut().find(|symbol| symbol.id == id) {
            symbol.attributes.insert(key.to_string(), value);
        }
    }

    pub fn ensure_type(&mut self, name: &str) -> TypeId {
        if let Some(existing) = self.types.iter().find(|t| t.name == name) {
            return existing.id;
        }
        let id = TypeId(self.next_type_id);
        self.next_type_id += 1;
        self.types.push(Type {
            id,
            name: name.to_string(),
            kind: classify_type_kind(name),
            cpp: CppValueSemantics::default(),
        });
        id
    }

    pub fn empty_block(&mut self) -> Block {
        Block {
            id: self.alloc_block_id(),
            stmts: Vec::new(),
            span: default_span(),
        }
    }

    pub fn push_item(&mut self, item: Item) {
        self.module.items.push(item);
    }

    pub fn find_type_name(&self, id: TypeId) -> Option<&str> {
        self.types
            .iter()
            .find(|ty| ty.id == id)
            .map(|ty| ty.name.as_str())
    }

    pub fn finish(self) -> Program {
        Program {
            language: self.language,
            files: vec![self.file],
            modules: vec![self.module],
            symbols: self.symbols,
            types: self.types,
            source_maps: Vec::new(),
        }
    }
}

fn classify_type_kind(name: &str) -> TypeKind {
    match name {
        "void" | "bool" | "boolean" | "int" | "i32" | "i64" | "String" | "str" | "float"
        | "double" | "char" => TypeKind::Primitive,
        _ => TypeKind::Named,
    }
}
