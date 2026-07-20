
macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        pub struct $name(pub u32);
    };
}

id_type!(FileId);
id_type!(ModuleId);
id_type!(ItemId);
id_type!(FunctionId);
id_type!(BlockId);
id_type!(StmtId);
id_type!(ExprId);
id_type!(SymbolId);
id_type!(TypeId);
