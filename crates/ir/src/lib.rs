use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use uniflow_hir::{Language, Span};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(pub u32);
    };
}

id_type!(FunctionId);
id_type!(BlockId);
id_type!(InstId);
id_type!(ValueId);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Program {
    pub language: Language,
    pub source_files: Vec<SourceFile>,
    pub functions: Vec<Function>,
    pub entry_points: Vec<FunctionId>,
    pub type_hierarchy: IndexMap<String, Vec<String>>,
}

impl Program {
    pub fn find_function_by_name(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == name)
    }

    pub fn function(&self, id: FunctionId) -> Option<&Function> {
        self.functions.iter().find(|f| f.id == id)
    }

    pub fn file_path(&self, file_id: u32) -> Option<&str> {
        self.source_files
            .iter()
            .find(|f| f.id == file_id)
            .map(|f| f.path.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceFile {
    pub id: u32,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Function {
    pub id: FunctionId,
    pub name: String,
    pub params: Vec<ValueId>,
    pub locals: Vec<ValueId>,
    pub blocks: Vec<BasicBlock>,
    pub return_type: Type,
    pub is_external: bool,
    pub span: Span,
    pub attrs: IndexMap<String, String>,
    pub value_types: IndexMap<ValueId, String>,
    pub value_spans: IndexMap<ValueId, Span>,
}

impl Function {
    pub fn all_values(&self) -> impl Iterator<Item = ValueId> + '_ {
        self.params.iter().copied().chain(self.locals.iter().copied())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub insts: Vec<Instruction>,
    pub term: Terminator,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub id: InstId,
    pub kind: InstKind,
    pub span: Span,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InstKind {
    ConstInt {
        dst: ValueId,
        value: i64,
    },
    ConstString {
        dst: ValueId,
        value: String,
    },
    Copy {
        dst: ValueId,
        src: ValueId,
    },
    Phi {
        dst: ValueId,
        inputs: Vec<ValueId>,
    },
    LoadField {
        dst: ValueId,
        base: ValueId,
        field: String,
    },
    StoreField {
        base: ValueId,
        field: String,
        src: ValueId,
    },
    LoadIndex {
        dst: ValueId,
        base: ValueId,
        index: ValueId,
    },
    StoreIndex {
        base: ValueId,
        index: ValueId,
        src: ValueId,
    },
    Call(CallInst),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallInst {
    pub dst: Option<ValueId>,
    pub callee: Callee,
    pub receiver: Option<ValueId>,
    pub args: Vec<ValueId>,
    pub arg_names: Vec<Option<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Callee {
    Static(String),
    Dynamic(ValueId),
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Terminator {
    Goto(BlockId),
    Branch {
        cond: ValueId,
        then_bb: BlockId,
        else_bb: BlockId,
    },
    Return(Option<ValueId>),
    Throw(Option<ValueId>),
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Type {
    Void,
    Bool,
    Int,
    Float,
    String,
    Object(String),
    Function,
    Unknown,
}

pub fn sample_java_sql_program() -> Program {
    let controller_id = FunctionId(0);
    let req_param = ValueId(0);
    let v_query = ValueId(1);
    let v_sql = ValueId(2);
    let v_stmt = ValueId(3);
    let v_sanitized = ValueId(4);

    let controller = Function {
        id: controller_id,
        name: "ExampleController.handle".to_string(),
        params: vec![req_param],
        locals: vec![v_query, v_sql, v_stmt, v_sanitized],
        blocks: vec![BasicBlock {
            id: BlockId(0),
            insts: vec![
                Instruction {
                    id: InstId(0),
                    kind: InstKind::Call(CallInst {
                        dst: Some(v_query),
                        callee: Callee::Static(
                            "javax.servlet.http.HttpServletRequest.getParameter".to_string(),
                        ),
                        receiver: Some(req_param),
                        args: vec![],
                        arg_names: Vec::new(),
                    }),
                    span: Span::default(),
                },
                Instruction {
                    id: InstId(1),
                    kind: InstKind::Call(CallInst {
                        dst: Some(v_sanitized),
                        callee: Callee::Static("com.example.SafeSql.escapeSql".to_string()),
                        receiver: None,
                        args: vec![v_query],
                        arg_names: Vec::new(),
                    }),
                    span: Span::default(),
                },
                Instruction {
                    id: InstId(2),
                    kind: InstKind::Copy {
                        dst: v_sql,
                        src: v_sanitized,
                    },
                    span: Span::default(),
                },
                Instruction {
                    id: InstId(3),
                    kind: InstKind::Call(CallInst {
                        dst: None,
                        callee: Callee::Static("java.sql.Statement.executeQuery".to_string()),
                        receiver: Some(v_stmt),
                        args: vec![v_sql],
                        arg_names: Vec::new(),
                    }),
                    span: Span::default(),
                },
            ],
            term: Terminator::Return(None),
        }],
        return_type: Type::Void,
        is_external: false,
        span: Span::default(),
        attrs: IndexMap::new(),
        value_types: IndexMap::new(),
        value_spans: IndexMap::new(),
    };

    Program {
        language: Language::Java,
        source_files: Vec::new(),
        functions: vec![controller],
        entry_points: vec![controller_id],
        type_hierarchy: IndexMap::new(),
    }
}
