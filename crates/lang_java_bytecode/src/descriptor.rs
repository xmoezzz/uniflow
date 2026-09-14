//! Field and method descriptor parsing (JVMS §4.3).

use crate::constant_pool::internal_name_to_dotted;
use anyhow::{bail, Result};
use uniflow_ir::Type as IrType;

/// A JVM-level type as it appears in a descriptor. This is kept distinct
/// from `ir::Type` because slot width (1 vs 2 locals/stack entries) depends
/// on the exact JVM primitive, which `ir::Type` collapses (`Int` covers
/// `int`/`long`/`short`/`byte`/`char`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JvmType {
    Boolean,
    Byte,
    Char,
    Short,
    Int,
    Long,
    Float,
    Double,
    Object(String),
    Array { element: Box<JvmType>, dims: u32 },
    Void,
}

impl JvmType {
    /// 1 for every JVM type except `long`/`double`, which occupy two local
    /// variable/operand stack slots (JVMS §2.6.1, §2.11.1).
    pub fn slot_width(&self) -> u16 {
        match self {
            JvmType::Long | JvmType::Double => 2,
            _ => 1,
        }
    }

    pub fn to_ir_type(&self) -> IrType {
        match self {
            JvmType::Boolean => IrType::Bool,
            JvmType::Byte | JvmType::Char | JvmType::Short | JvmType::Int | JvmType::Long => {
                IrType::Int
            }
            JvmType::Float | JvmType::Double => IrType::Float,
            JvmType::Object(name) if name == "java.lang.String" => IrType::String,
            JvmType::Object(name) => IrType::Object(name.clone()),
            JvmType::Array { element, .. } => IrType::Object(format!("{}[]", element.descriptor_name())),
            JvmType::Void => IrType::Void,
        }
    }

    fn descriptor_name(&self) -> String {
        match self {
            JvmType::Boolean => "boolean".to_string(),
            JvmType::Byte => "byte".to_string(),
            JvmType::Char => "char".to_string(),
            JvmType::Short => "short".to_string(),
            JvmType::Int => "int".to_string(),
            JvmType::Long => "long".to_string(),
            JvmType::Float => "float".to_string(),
            JvmType::Double => "double".to_string(),
            JvmType::Object(name) => name.clone(),
            JvmType::Array { element, dims } => format!("{}{}", element.descriptor_name(), "[]".repeat(*dims as usize)),
            JvmType::Void => "void".to_string(),
        }
    }
}

/// Parses one field/return descriptor starting at `bytes[*pos]`, advancing
/// `*pos` past it. Handles arrays (`[[I`) and object types (`Ljava/lang/String;`).
fn parse_one(bytes: &[u8], pos: &mut usize) -> Result<JvmType> {
    let mut dims = 0u32;
    while bytes.get(*pos) == Some(&b'[') {
        dims += 1;
        *pos += 1;
    }
    let base = match bytes.get(*pos) {
        Some(b'B') => JvmType::Byte,
        Some(b'C') => JvmType::Char,
        Some(b'D') => JvmType::Double,
        Some(b'F') => JvmType::Float,
        Some(b'I') => JvmType::Int,
        Some(b'J') => JvmType::Long,
        Some(b'S') => JvmType::Short,
        Some(b'Z') => JvmType::Boolean,
        Some(b'V') => JvmType::Void,
        Some(b'L') => {
            *pos += 1;
            let start = *pos;
            while bytes.get(*pos) != Some(&b';') {
                if *pos >= bytes.len() {
                    bail!("unterminated object descriptor");
                }
                *pos += 1;
            }
            let internal = std::str::from_utf8(&bytes[start..*pos])
                .map_err(|_| anyhow::anyhow!("non-utf8 descriptor"))?;
            let name = internal_name_to_dotted(internal);
            *pos += 1; // consume ';'
            return Ok(if dims > 0 {
                JvmType::Array {
                    element: Box::new(JvmType::Object(name)),
                    dims,
                }
            } else {
                JvmType::Object(name)
            });
        }
        other => bail!("unrecognized descriptor byte {other:?} at {}", pos),
    };
    *pos += 1;
    Ok(if dims > 0 {
        JvmType::Array {
            element: Box::new(base),
            dims,
        }
    } else {
        base
    })
}

pub fn parse_field_descriptor(descriptor: &str) -> Result<JvmType> {
    let bytes = descriptor.as_bytes();
    let mut pos = 0;
    let ty = parse_one(bytes, &mut pos)?;
    if pos != bytes.len() {
        bail!("trailing bytes in field descriptor {descriptor}");
    }
    Ok(ty)
}

/// Parses a method descriptor `(ParamTypes)ReturnType` into ordered
/// parameter types and a return type.
pub fn parse_method_descriptor(descriptor: &str) -> Result<(Vec<JvmType>, JvmType)> {
    let bytes = descriptor.as_bytes();
    if bytes.first() != Some(&b'(') {
        bail!("method descriptor must start with '(': {descriptor}");
    }
    let mut pos = 1usize;
    let mut params = Vec::new();
    while bytes.get(pos) != Some(&b')') {
        if pos >= bytes.len() {
            bail!("unterminated parameter list in {descriptor}");
        }
        params.push(parse_one(bytes, &mut pos)?);
    }
    pos += 1; // consume ')'
    let ret = parse_one(bytes, &mut pos)?;
    Ok((params, ret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_primitive_and_object_field_descriptors() {
        assert_eq!(parse_field_descriptor("I").unwrap(), JvmType::Int);
        assert_eq!(parse_field_descriptor("J").unwrap(), JvmType::Long);
        assert_eq!(
            parse_field_descriptor("Ljava/lang/String;").unwrap(),
            JvmType::Object("java.lang.String".to_string())
        );
        assert_eq!(
            parse_field_descriptor("[I").unwrap(),
            JvmType::Array {
                element: Box::new(JvmType::Int),
                dims: 1
            }
        );
        assert_eq!(
            parse_field_descriptor("[[Ljava/lang/String;").unwrap(),
            JvmType::Array {
                element: Box::new(JvmType::Object("java.lang.String".to_string())),
                dims: 2
            }
        );
    }

    #[test]
    fn parses_method_descriptor_params_and_return() {
        let (params, ret) = parse_method_descriptor("(ILjava/lang/String;)V").unwrap();
        assert_eq!(params, vec![JvmType::Int, JvmType::Object("java.lang.String".to_string())]);
        assert_eq!(ret, JvmType::Void);
    }

    #[test]
    fn long_and_double_report_two_slots() {
        assert_eq!(JvmType::Long.slot_width(), 2);
        assert_eq!(JvmType::Double.slot_width(), 2);
        assert_eq!(JvmType::Int.slot_width(), 1);
    }

    #[test]
    fn no_arg_descriptor_parses_empty_params() {
        let (params, ret) = parse_method_descriptor("()I").unwrap();
        assert!(params.is_empty());
        assert_eq!(ret, JvmType::Int);
    }
}
