use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use uniflow_hir::{
    CppConstructorInitializer, CppMethodSemantics, CppValueSemantics, Language, SourceOriginKind,
    Span,
};

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
        if let Some(exact) = self.functions.iter().find(|f| f.name == name) {
            return Some(exact);
        }
        let simple = name
            .rsplit(|ch| ch == '.' || ch == ':')
            .find(|part| !part.is_empty())
            .unwrap_or(name);
        let mut matches = self.functions.iter().filter(|function| {
            let function_simple = function
                .name
                .rsplit(|ch| ch == '.' || ch == ':')
                .find(|part| !part.is_empty())
                .unwrap_or(function.name.as_str());
            function.name == simple || function_simple == simple
        });
        let first = matches.next()?;
        if matches.next().is_some() {
            None
        } else {
            Some(first)
        }
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
    #[serde(default)]
    pub cpp: Option<CppMethodSemantics>,
    #[serde(default)]
    pub cpp_initializers: Vec<CppConstructorInitializer>,
    #[serde(default)]
    pub value_cpp: IndexMap<ValueId, CppValueSemantics>,
    #[serde(default)]
    pub exception_edges: Vec<ExceptionEdge>,
}

impl Function {
    pub fn all_values(&self) -> impl Iterator<Item = ValueId> + '_ {
        self.params
            .iter()
            .copied()
            .chain(self.locals.iter().copied())
    }

    pub fn mark_value_source_origin(&mut self, value: ValueId, kind: SourceOriginKind) {
        self.attrs.insert(source_origin_attr_key("value", value.0, kind), "true".to_string());
    }

    pub fn value_has_source_origin(&self, value: ValueId, kind: SourceOriginKind) -> bool {
        self.attrs
            .contains_key(&source_origin_attr_key("value", value.0, kind))
    }

    pub fn mark_instruction_source_origin(&mut self, inst: InstId, kind: SourceOriginKind) {
        self.attrs.insert(source_origin_attr_key("inst", inst.0, kind), "true".to_string());
    }

    pub fn instruction_has_source_origin(&self, inst: InstId, kind: SourceOriginKind) -> bool {
        self.attrs
            .contains_key(&source_origin_attr_key("inst", inst.0, kind))
    }

    /// Record source-level array extents carried by an SSA value. `None`
    /// preserves an explicitly unsized/unknown dimension while retaining
    /// later dimensions for nested indexing.
    pub fn set_value_array_extents(
        &mut self,
        value: ValueId,
        extents: &[Option<ValueId>],
    ) {
        let encoded = extents
            .iter()
            .map(|extent| extent.map_or_else(|| "?".to_string(), |value| value.0.to_string()))
            .collect::<Vec<_>>()
            .join(",");
        self.attrs.insert(array_extents_attr_key(value), encoded);
    }

    pub fn value_array_extents(&self, value: ValueId) -> Option<Vec<Option<ValueId>>> {
        let encoded = self.attrs.get(&array_extents_attr_key(value))?;
        if encoded.is_empty() {
            return Some(Vec::new());
        }
        encoded
            .split(',')
            .map(|part| {
                if part == "?" {
                    Some(None)
                } else {
                    part.parse::<u32>().ok().map(|id| Some(ValueId(id)))
                }
            })
            .collect()
    }

    pub fn value_array_extent(
        &self,
        value: ValueId,
        dimension: usize,
    ) -> Option<Option<ValueId>> {
        self.value_array_extents(value)
            .and_then(|extents| extents.get(dimension).copied())
    }
}

fn source_origin_attr_key(target: &str, id: u32, kind: SourceOriginKind) -> String {
    let kind = match kind {
        SourceOriginKind::MacroExpansion => "macro-expansion",
    };
    format!("uniflow.source-origin.{kind}.{target}.{id}")
}

fn array_extents_attr_key(value: ValueId) -> String {
    format!("uniflow.array-extents.value.{}", value.0)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    pub insts: Vec<Instruction>,
    pub term: Terminator,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionEdge {
    pub from: BlockId,
    pub unwind: BlockId,
    /// Call instruction at which the exceptional transfer occurs. `None` denotes an explicit
    /// block terminator such as `throw`.
    #[serde(default)]
    pub source_inst: Option<InstId>,
    /// Payload produced by an explicit `throw` in the source block, when recoverable.
    #[serde(default)]
    pub thrown_value: Option<ValueId>,
    /// SSA value bound to the selected catch parameter, when the handler names one.
    #[serde(default)]
    pub catch_value: Option<ValueId>,
    #[serde(default)]
    pub catch_type: Option<String>,
    #[serde(default)]
    pub is_cleanup: bool,
    /// Automatic-owner values whose lexical scopes are exited by this exceptional edge.
    /// The lifetime solver destroys only these values, preserving owners declared outside
    /// the corresponding try/catch scope.
    #[serde(default)]
    pub cleanup_values: Vec<ValueId>,
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
    /// Numeric successor/predecessor, converted back to the operand's numeric
    /// type (including Java narrowing). Produces a new value, not an alias.
    /// The frontend/lowerer separately models storage and prefix/postfix result.
    NumericStep {
        dst: ValueId,
        src: ValueId,
        increment: bool,
    },
    /// Arithmetic unary negation. This is a numeric value transform, not an
    /// aliasing copy, and must remain explicit for range/value analyses.
    NumericNeg {
        dst: ValueId,
        src: ValueId,
    },
    /// C++ ownership transfer. Unlike Copy, the source enters MovedFrom state.
    Move {
        dst: ValueId,
        src: ValueId,
    },
    /// A typed C++ cast retained for type/alias filtering.
    Cast {
        dst: ValueId,
        src: ValueId,
        kind: CppCastKind,
        target_type: Option<String>,
    },
    /// Explicit pointer/reference dereference. This is retained in IR so
    /// path-sensitive lifetime checkers can distinguish `*p` from a plain
    /// value read/copy.
    Deref {
        dst: ValueId,
        src: ValueId,
    },
    /// Explicit object-lifetime transition.
    Lifetime {
        value: ValueId,
        event: LifetimeEvent,
    },
    /// Boolean comparison.  This must remain distinct from `Phi`: a comparison
    /// does not propagate either operand's data value into the boolean result,
    /// and branch-sensitive analyses need the predicate to refine successor
    /// states (for example `p == nullptr`).
    Compare {
        dst: ValueId,
        lhs: ValueId,
        rhs: ValueId,
        op: ComparisonOp,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CppCastKind {
    Static,
    Dynamic,
    Reinterpret,
    Const,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifetimeEvent {
    Construct,
    MoveFrom,
    Release,
    /// Raw deallocation (`free`, `operator delete`, `operator delete[]`).
    /// This is intentionally distinct from owner `Release`: freeing a raw
    /// pointee invalidates aliases while unique_ptr::release merely transfers
    /// ownership of a still-live object.
    Free,
    Destroy,
    Escape,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallInst {
    pub dst: Option<ValueId>,
    pub callee: Callee,
    pub receiver: Option<ValueId>,
    pub args: Vec<ValueId>,
    pub arg_names: Vec<Option<String>>,
    #[serde(default)]
    pub arg_spans: Vec<Span>,
    #[serde(default)]
    pub arg_origins: Vec<Vec<SourceOriginKind>>,
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
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
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
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
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
                        arg_spans: Vec::new(),
                        arg_origins: Vec::new(),
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
        cpp: None,
        cpp_initializers: Vec::new(),
        value_cpp: IndexMap::new(),
        exception_edges: Vec::new(),
    };

    Program {
        language: Language::Java,
        source_files: Vec::new(),
        functions: vec![controller],
        entry_points: vec![controller_id],
        type_hierarchy: IndexMap::new(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrValidationError {
    pub function: String,
    pub message: String,
}

pub fn validate_program(program: &Program) -> Result<(), Vec<IrValidationError>> {
    let mut errors = Vec::new();
    let function_ids = program
        .functions
        .iter()
        .map(|f| f.id)
        .collect::<std::collections::HashSet<_>>();
    for entry in &program.entry_points {
        if !function_ids.contains(entry) {
            errors.push(IrValidationError {
                function: "<program>".to_string(),
                message: format!("entry point {:?} does not reference a function", entry),
            });
        }
    }
    for function in &program.functions {
        validate_function(function, &mut errors);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_function(function: &Function, errors: &mut Vec<IrValidationError>) {
    let block_ids = function
        .blocks
        .iter()
        .map(|block| block.id)
        .collect::<std::collections::HashSet<_>>();
    if block_ids.len() != function.blocks.len() {
        errors.push(IrValidationError {
            function: function.name.clone(),
            message: "duplicate basic-block id".to_string(),
        });
    }
    for edge in &function.exception_edges {
        if !block_ids.contains(&edge.from) {
            errors.push(IrValidationError {
                function: function.name.clone(),
                message: format!("exception edge starts at missing block {:?}", edge.from),
            });
        }
        if !block_ids.contains(&edge.unwind) {
            errors.push(IrValidationError {
                function: function.name.clone(),
                message: format!("exception edge targets missing block {:?}", edge.unwind),
            });
        }
        if let Some(inst) = edge.source_inst {
            let source_block = function.blocks.iter().find(|block| block.id == edge.from);
            let source_instruction = source_block.and_then(|block| {
                block
                    .insts
                    .iter()
                    .find(|instruction| instruction.id == inst)
            });
            if !source_instruction
                .is_some_and(|instruction| matches!(&instruction.kind, InstKind::Call(_)))
            {
                errors.push(IrValidationError {
                    function: function.name.clone(),
                    message: format!(
                        "exception edge source instruction {:?} is missing or not a call in block {:?}",
                        inst, edge.from
                    ),
                });
            }
        }
        if let Some(value) = edge.thrown_value {
            if !function.all_values().any(|candidate| candidate == value) {
                errors.push(IrValidationError {
                    function: function.name.clone(),
                    message: format!("exception edge uses unknown thrown value {:?}", value),
                });
            }
        }
        if let Some(value) = edge.catch_value {
            if !function.all_values().any(|candidate| candidate == value) {
                errors.push(IrValidationError {
                    function: function.name.clone(),
                    message: format!("exception edge binds unknown catch value {:?}", value),
                });
            }
        }
        for value in &edge.cleanup_values {
            if !function.all_values().any(|candidate| candidate == *value) {
                errors.push(IrValidationError {
                    function: function.name.clone(),
                    message: format!("exception edge cleans up unknown value {:?}", value),
                });
            }
        }
    }

    let mut defined = function
        .params
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    // Catch parameters are SSA definitions produced by exceptional edges. They intentionally
    // have no defining instruction in the handler block, so register them before validating uses.
    for edge in &function.exception_edges {
        if let Some(value) = edge.catch_value {
            defined.insert(value);
        }
    }
    for block in &function.blocks {
        for inst in &block.insts {
            if let Some(dst) = defined_value(&inst.kind) {
                if !defined.insert(dst) {
                    errors.push(IrValidationError {
                        function: function.name.clone(),
                        message: format!("value {:?} is defined more than once", dst),
                    });
                }
            }
        }
    }

    let mut inst_ids = std::collections::HashSet::new();
    for block in &function.blocks {
        for inst in &block.insts {
            if !inst_ids.insert(inst.id) {
                errors.push(IrValidationError {
                    function: function.name.clone(),
                    message: format!("duplicate instruction id {:?}", inst.id),
                });
            }
            for used in used_values(&inst.kind) {
                if !defined.contains(&used) {
                    errors.push(IrValidationError {
                        function: function.name.clone(),
                        message: format!("value {:?} is used without a definition", used),
                    });
                }
            }
        }
        match &block.term {
            Terminator::Goto(target) => validate_target(function, *target, &block_ids, errors),
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                if !defined.contains(cond) {
                    errors.push(IrValidationError {
                        function: function.name.clone(),
                        message: format!("branch condition {:?} is undefined", cond),
                    });
                }
                validate_target(function, *then_bb, &block_ids, errors);
                validate_target(function, *else_bb, &block_ids, errors);
            }
            Terminator::Return(value) | Terminator::Throw(value) => {
                if let Some(value) = value {
                    if !defined.contains(value) {
                        errors.push(IrValidationError {
                            function: function.name.clone(),
                            message: format!("terminator uses undefined value {:?}", value),
                        });
                    }
                }
            }
            Terminator::Unreachable => {}
        }
    }
}

fn validate_target(
    function: &Function,
    target: BlockId,
    block_ids: &std::collections::HashSet<BlockId>,
    errors: &mut Vec<IrValidationError>,
) {
    if !block_ids.contains(&target) {
        errors.push(IrValidationError {
            function: function.name.clone(),
            message: format!("terminator targets missing block {:?}", target),
        });
    }
}

fn defined_value(kind: &InstKind) -> Option<ValueId> {
    match kind {
        InstKind::ConstInt { dst, .. }
        | InstKind::ConstString { dst, .. }
        | InstKind::Copy { dst, .. }
        | InstKind::NumericStep { dst, .. }
        | InstKind::NumericNeg { dst, .. }
        | InstKind::Move { dst, .. }
        | InstKind::Cast { dst, .. }
        | InstKind::Deref { dst, .. }
        | InstKind::Compare { dst, .. }
        | InstKind::Phi { dst, .. }
        | InstKind::LoadField { dst, .. }
        | InstKind::LoadIndex { dst, .. } => Some(*dst),
        InstKind::Call(call) => call.dst,
        InstKind::Lifetime { .. } | InstKind::StoreField { .. } | InstKind::StoreIndex { .. } => {
            None
        }
    }
}

fn used_values(kind: &InstKind) -> Vec<ValueId> {
    match kind {
        InstKind::ConstInt { .. } | InstKind::ConstString { .. } => Vec::new(),
        InstKind::Copy { src, .. }
        | InstKind::Move { src, .. }
        | InstKind::Cast { src, .. }
        | InstKind::Deref { src, .. } => {
            vec![*src]
        }
        InstKind::NumericStep { src, .. } | InstKind::NumericNeg { src, .. } => vec![*src],
        InstKind::Lifetime { value, .. } => vec![*value],
        InstKind::Compare { lhs, rhs, .. } => vec![*lhs, *rhs],
        InstKind::Phi { inputs, .. } => inputs.clone(),
        InstKind::LoadField { base, .. } => vec![*base],
        InstKind::StoreField { base, src, .. } => vec![*base, *src],
        InstKind::LoadIndex { base, index, .. } => vec![*base, *index],
        InstKind::StoreIndex { base, index, src } => vec![*base, *index, *src],
        InstKind::Call(call) => {
            let mut values = Vec::new();
            if let Some(receiver) = call.receiver {
                values.push(receiver);
            }
            values.extend(call.args.iter().copied());
            if let Callee::Dynamic(value) = &call.callee {
                values.push(*value);
            }
            values
        }
    }
}
