#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CppReferenceKind {
    #[default]
    None,
    LValue,
    RValue,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CppOwnershipKind {
    #[default]
    None,
    Borrowed,
    Unique,
    Shared,
    Weak,
    Raw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CppSpecialMemberKind {
    Constructor,
    Destructor,
    CopyConstructor,
    MoveConstructor,
    CopyAssignment,
    MoveAssignment,
    Assignment,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CppValueSemantics {
    pub reference_kind: CppReferenceKind,
    pub ownership: CppOwnershipKind,
    /// Pointee or wrapped object type when it is recoverable from source syntax.
    pub pointee_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CppMethodSemantics {
    pub owner: String,
    pub is_virtual: bool,
    pub is_pure_virtual: bool,
    pub is_override: bool,
    pub is_final: bool,
    pub is_const: bool,
    pub is_noexcept: bool,
    pub special_member: Option<CppSpecialMemberKind>,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CppConstructorInitializerKind {
    Base,
    Field,
    Delegating,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CppConstructorInitializer {
    pub kind: CppConstructorInitializerKind,
    pub target: String,
    #[serde(default)]
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CppSymbolSemantics {
    pub method: Option<CppMethodSemantics>,
    pub value: CppValueSemantics,
}

impl Symbol {
    /// Return the typed C++ method semantics. New producers populate `cpp` directly;
    /// the attribute decoder is retained for backward-compatible cached HIR.
    pub fn cpp_method_semantics(&self) -> Option<CppMethodSemantics> {
        if let Some(cpp) = self.cpp.as_ref().and_then(|cpp| cpp.method.clone()) {
            return Some(cpp);
        }
        let owner = self.attributes.get("cpp.owner")?.clone();
        let flag = |name: &str| self.attributes.get(name).is_some_and(|v| v == "true");
        let special_member = self.attributes.get("cpp.special_member").and_then(|value| match value.as_str() {
            "constructor" => Some(CppSpecialMemberKind::Constructor),
            "destructor" => Some(CppSpecialMemberKind::Destructor),
            "copy_constructor" => Some(CppSpecialMemberKind::CopyConstructor),
            "move_constructor" => Some(CppSpecialMemberKind::MoveConstructor),
            "copy_assignment" => Some(CppSpecialMemberKind::CopyAssignment),
            "move_assignment" => Some(CppSpecialMemberKind::MoveAssignment),
            "assignment" => Some(CppSpecialMemberKind::Assignment),
            _ => None,
        });
        Some(CppMethodSemantics {
            owner,
            is_virtual: flag("cpp.virtual"),
            is_pure_virtual: flag("cpp.pure_virtual"),
            is_override: flag("cpp.override"),
            is_final: flag("cpp.final"),
            is_const: flag("cpp.const"),
            is_noexcept: flag("cpp.noexcept"),
            special_member,
        })
    }

    pub fn cpp_value_semantics(&self) -> CppValueSemantics {
        if let Some(cpp) = &self.cpp {
            return cpp.value.clone();
        }
        let ownership = self.attributes.get("cpp.ownership").map(String::as_str).map_or(
            CppOwnershipKind::None,
            |value| match value {
                "borrowed" => CppOwnershipKind::Borrowed,
                "unique" => CppOwnershipKind::Unique,
                "shared" => CppOwnershipKind::Shared,
                "weak" => CppOwnershipKind::Weak,
                "raw" => CppOwnershipKind::Raw,
                _ => CppOwnershipKind::None,
            },
        );
        let reference_kind = self.attributes.get("cpp.reference").map(String::as_str).map_or(
            CppReferenceKind::None,
            |value| match value {
                "lvalue" => CppReferenceKind::LValue,
                "rvalue" => CppReferenceKind::RValue,
                _ => CppReferenceKind::None,
            },
        );
        CppValueSemantics {
            reference_kind,
            ownership,
            pointee_type: self.attributes.get("cpp.pointee_type").cloned(),
        }
    }

    pub fn cpp_ownership(&self) -> Option<CppOwnershipKind> {
        let ownership = self.cpp_value_semantics().ownership;
        (ownership != CppOwnershipKind::None).then_some(ownership)
    }
}
