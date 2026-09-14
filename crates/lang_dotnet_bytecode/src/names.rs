//! Qualified-name resolution: turns a `dotnetdll` type/method/field
//! reference into the dotted `Namespace.Type.Member` text this codebase's
//! rule catalogs expect (mirroring `lang_java_bytecode`'s
//! `com.example.Foo.bar` convention). Deliberately avoids `ResolvedDebug`'s
//! own `.show()` impls for types, which produce verbose declaration text
//! (`"public class Foo"`) or an assembly-bracketed prefix (`"[mscorlib]System.Console"`)
//! rather than a plain qualified name.

use dotnetdll::prelude::*;
use dotnetdll::resolution::Resolution;
use dotnetdll::resolved::members::{FieldReferenceParent, FieldSource, MethodReferenceParent, MethodSource, UserMethod};
use dotnetdll::resolved::signature::ManagedMethod;
use dotnetdll::resolved::types::{BaseType, MethodType, TypeSource};

pub(crate) fn type_source_name<T>(source: &TypeSource<T>, res: &Resolution) -> String {
    match source {
        TypeSource::User(user) => user.type_name(res),
        TypeSource::Generic { base, .. } => base.type_name(res),
    }
}

fn base_type_name<T: ResolvedDebug>(base: &BaseType<T>, res: &Resolution) -> String {
    match base {
        BaseType::Type { source, .. } => type_source_name(source, res),
        BaseType::Boolean => "bool".to_string(),
        BaseType::Char => "char".to_string(),
        BaseType::Int8 => "sbyte".to_string(),
        BaseType::UInt8 => "byte".to_string(),
        BaseType::Int16 => "short".to_string(),
        BaseType::UInt16 => "ushort".to_string(),
        BaseType::Int32 => "int".to_string(),
        BaseType::UInt32 => "uint".to_string(),
        BaseType::Int64 => "long".to_string(),
        BaseType::UInt64 => "ulong".to_string(),
        BaseType::Float32 => "float".to_string(),
        BaseType::Float64 => "double".to_string(),
        BaseType::IntPtr => "nint".to_string(),
        BaseType::UIntPtr => "nuint".to_string(),
        BaseType::Object => "object".to_string(),
        BaseType::String => "string".to_string(),
        // Arrays/pointers/function pointers as a call-target type are rare
        // enough that falling back to the library's own (more verbose,
        // assembly-qualified) text is an acceptable simplification.
        other => other.show(res),
    }
}

pub(crate) fn method_type_name(ty: &MethodType, res: &Resolution) -> String {
    match ty {
        MethodType::Base(base) => base_type_name(base, res),
        MethodType::TypeGeneric(i) => format!("T{i}"),
        MethodType::MethodGeneric(i) => format!("M{i}"),
    }
}

fn user_method_name(method: &UserMethod, res: &Resolution) -> String {
    match method {
        UserMethod::Definition(idx) => format!("{}.{}", res[idx.parent_type()].nested_type_name(res), res[*idx].name),
        UserMethod::Reference(idx) => {
            let reference = &res[*idx];
            let parent = match &reference.parent {
                MethodReferenceParent::Type(ty) => method_type_name(ty, res),
                MethodReferenceParent::Module(module) => res[*module].name.to_string(),
                MethodReferenceParent::VarargMethod(idx) => res[idx.parent_type()].nested_type_name(res),
            };
            format!("{parent}.{}", reference.name)
        }
    }
}

pub(crate) fn method_source_name(source: &MethodSource, res: &Resolution) -> String {
    match source {
        MethodSource::User(user) => user_method_name(user, res),
        // A generic method instantiation's qualified name is the same as
        // its unbound base method — the type-argument list is dropped, the
        // same simplification `lang_rust`/`lang_go` make for generics.
        MethodSource::Generic(instantiation) => user_method_name(&instantiation.base, res),
    }
}

pub(crate) fn field_source_name(source: &FieldSource, res: &Resolution) -> String {
    match source {
        FieldSource::Definition(idx) => format!("{}.{}", res[idx.parent_type()].nested_type_name(res), res[*idx].name),
        FieldSource::Reference(idx) => {
            let reference = &res[*idx];
            let parent = match &reference.parent {
                FieldReferenceParent::Type(ty) => method_type_name(ty, res),
                FieldReferenceParent::Module(module) => res[*module].name.to_string(),
            };
            format!("{parent}.{}", reference.name)
        }
    }
}

pub(crate) fn user_method_signature<'a>(res: &'a Resolution, method: &UserMethod) -> &'a ManagedMethod<MethodType> {
    match method {
        UserMethod::Definition(idx) => &res[*idx].signature,
        UserMethod::Reference(idx) => &res[*idx].signature,
    }
}

pub(crate) fn method_source_signature<'a>(res: &'a Resolution, source: &MethodSource) -> &'a ManagedMethod<MethodType> {
    match source {
        MethodSource::User(user) => user_method_signature(res, user),
        MethodSource::Generic(instantiation) => user_method_signature(res, &instantiation.base),
    }
}
