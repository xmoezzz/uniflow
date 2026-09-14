//! Top-level classfile structure (JVMS §4.1) built on top of
//! [`crate::constant_pool`] and [`crate::reader`].

use crate::constant_pool::{ClassfileDiagnostic, ConstantPool};
use crate::reader::Reader;
use crate::version::{validate_container_version, ClassVersion};
use anyhow::{bail, Context, Result};

pub const ACC_STATIC: u16 = 0x0008;
pub const ACC_NATIVE: u16 = 0x0100;
pub const ACC_INTERFACE: u16 = 0x0200;

#[derive(Clone, Debug)]
pub struct ExceptionTableEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    /// Dotted exception class name; `None` means "any" (the pattern used
    /// by pre-Java-7 `finally` blocks compiled with `jsr`/`ret`, and by the
    /// synthetic cleanup handlers `javac` still emits for try-with-resources
    /// and modern `finally`).
    pub catch_type: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CodeAttr {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code: Vec<u8>,
    pub exception_table: Vec<ExceptionTableEntry>,
}

#[derive(Clone, Debug)]
pub struct MethodInfo {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
    pub code: Option<CodeAttr>,
}

impl MethodInfo {
    pub fn is_static(&self) -> bool {
        self.access_flags & ACC_STATIC != 0
    }

    pub fn is_native(&self) -> bool {
        self.access_flags & ACC_NATIVE != 0
    }
}

#[derive(Clone, Debug)]
pub struct FieldInfo {
    pub access_flags: u16,
    pub name: String,
    pub descriptor: String,
}

/// One entry of the class-level `BootstrapMethods` attribute (JVMS §4.7.23),
/// referenced by `CONSTANT_InvokeDynamic`/`CONSTANT_Dynamic` constants.
#[derive(Clone, Debug)]
pub struct BootstrapMethod {
    /// Constant pool index of the `CONSTANT_MethodHandle` naming the
    /// bootstrap method itself (e.g. `LambdaMetafactory.metafactory`).
    pub method_handle_index: u16,
    /// Constant pool indices of the bootstrap method's static arguments.
    pub arguments: Vec<u16>,
}

#[derive(Clone, Debug)]
pub struct ClassFile {
    pub version: ClassVersion,
    pub constant_pool: ConstantPool,
    pub access_flags: u16,
    pub this_class: String,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    pub bootstrap_methods: Vec<BootstrapMethod>,
}

impl ClassFile {
    pub fn is_interface(&self) -> bool {
        self.access_flags & ACC_INTERFACE != 0
    }
}

pub fn parse_class_file(bytes: &[u8]) -> Result<(ClassFile, Vec<ClassfileDiagnostic>)> {
    let mut reader = Reader::new(bytes);
    let magic = reader.u32()?;
    if magic != 0xCAFEBABE {
        bail!("not a class file: bad magic {magic:#x}");
    }
    let minor = reader.u16()?;
    let major = reader.u16()?;
    let version = ClassVersion::new(major, minor);
    validate_container_version(version).map_err(|message| anyhow::anyhow!(message))?;

    let mut diagnostics = Vec::new();
    let constant_pool = ConstantPool::parse(&mut reader, version, &mut diagnostics)
        .context("failed to parse constant pool")?;

    let access_flags = reader.u16()?;
    let this_class_index = reader.u16()?;
    let this_class = constant_pool.class_name(this_class_index)?;
    let super_class_index = reader.u16()?;
    let super_class = if super_class_index == 0 {
        None
    } else {
        Some(constant_pool.class_name(super_class_index)?)
    };

    let interfaces_count = reader.u16()?;
    let mut interfaces = Vec::with_capacity(interfaces_count as usize);
    for _ in 0..interfaces_count {
        let index = reader.u16()?;
        interfaces.push(constant_pool.class_name(index)?);
    }

    let fields_count = reader.u16()?;
    let mut fields = Vec::with_capacity(fields_count as usize);
    for _ in 0..fields_count {
        fields.push(parse_field(&mut reader, &constant_pool)?);
    }

    let methods_count = reader.u16()?;
    let mut methods = Vec::with_capacity(methods_count as usize);
    for _ in 0..methods_count {
        methods.push(parse_method(&mut reader, &constant_pool, &mut diagnostics)?);
    }

    let mut bootstrap_methods = Vec::new();
    let class_attributes_count = reader.u16()?;
    for _ in 0..class_attributes_count {
        let name_index = reader.u16()?;
        let length = reader.u32()? as usize;
        let name = constant_pool.utf8(name_index)?;
        if name == "BootstrapMethods" {
            let attr_bytes = reader.bytes(length)?;
            bootstrap_methods = parse_bootstrap_methods(attr_bytes)?;
        } else {
            reader.skip(length)?;
        }
    }

    Ok((
        ClassFile {
            version,
            constant_pool,
            access_flags,
            this_class,
            super_class,
            interfaces,
            fields,
            methods,
            bootstrap_methods,
        },
        diagnostics,
    ))
}

fn parse_field(reader: &mut Reader<'_>, pool: &ConstantPool) -> Result<FieldInfo> {
    let access_flags = reader.u16()?;
    let name_index = reader.u16()?;
    let descriptor_index = reader.u16()?;
    let name = pool.utf8(name_index)?.to_string();
    let descriptor = pool.utf8(descriptor_index)?.to_string();
    let attributes_count = reader.u16()?;
    for _ in 0..attributes_count {
        let _name_index = reader.u16()?;
        let length = reader.u32()? as usize;
        reader.skip(length)?;
    }
    Ok(FieldInfo {
        access_flags,
        name,
        descriptor,
    })
}

fn parse_method(
    reader: &mut Reader<'_>,
    pool: &ConstantPool,
    diagnostics: &mut Vec<ClassfileDiagnostic>,
) -> Result<MethodInfo> {
    let access_flags = reader.u16()?;
    let name_index = reader.u16()?;
    let descriptor_index = reader.u16()?;
    let name = pool.utf8(name_index)?.to_string();
    let descriptor = pool.utf8(descriptor_index)?.to_string();
    let attributes_count = reader.u16()?;
    let mut code = None;
    for _ in 0..attributes_count {
        let attr_name_index = reader.u16()?;
        let length = reader.u32()? as usize;
        let attr_name = pool.utf8(attr_name_index)?;
        if attr_name == "Code" {
            let attr_bytes = reader.bytes(length)?;
            match parse_code_attribute(attr_bytes, pool) {
                Ok(parsed) => code = Some(parsed),
                Err(error) => diagnostics.push(ClassfileDiagnostic(format!(
                    "method {name}{descriptor}: failed to decode Code attribute: {error}"
                ))),
            }
        } else {
            reader.skip(length)?;
        }
    }
    Ok(MethodInfo {
        access_flags,
        name,
        descriptor,
        code,
    })
}

fn parse_code_attribute(bytes: &[u8], pool: &ConstantPool) -> Result<CodeAttr> {
    let mut reader = Reader::new(bytes);
    let max_stack = reader.u16()?;
    let max_locals = reader.u16()?;
    let code_length = reader.u32()? as usize;
    let code = reader.bytes(code_length)?.to_vec();
    let exception_table_length = reader.u16()?;
    let mut exception_table = Vec::with_capacity(exception_table_length as usize);
    for _ in 0..exception_table_length {
        let start_pc = reader.u16()?;
        let end_pc = reader.u16()?;
        let handler_pc = reader.u16()?;
        let catch_type_index = reader.u16()?;
        let catch_type = if catch_type_index == 0 {
            None
        } else {
            Some(pool.class_name(catch_type_index)?)
        };
        exception_table.push(ExceptionTableEntry {
            start_pc,
            end_pc,
            handler_pc,
            catch_type,
        });
    }
    // Nested attributes (LineNumberTable, LocalVariableTable, StackMapTable,
    // ...) carry no information this IR needs; skip them by length.
    let nested_attributes_count = reader.u16()?;
    for _ in 0..nested_attributes_count {
        let _name_index = reader.u16()?;
        let length = reader.u32()? as usize;
        reader.skip(length)?;
    }
    Ok(CodeAttr {
        max_stack,
        max_locals,
        code,
        exception_table,
    })
}

fn parse_bootstrap_methods(bytes: &[u8]) -> Result<Vec<BootstrapMethod>> {
    let mut reader = Reader::new(bytes);
    let count = reader.u16()?;
    let mut methods = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let method_handle_index = reader.u16()?;
        let arg_count = reader.u16()?;
        let mut arguments = Vec::with_capacity(arg_count as usize);
        for _ in 0..arg_count {
            arguments.push(reader.u16()?);
        }
        methods.push(BootstrapMethod {
            method_handle_index,
            arguments,
        });
    }
    Ok(methods)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        let bytes = [0u8, 0, 0, 0];
        assert!(parse_class_file(&bytes).is_err());
    }

    #[test]
    fn parses_real_javac_output() {
        let bytes = include_bytes!("../tests/fixtures/Plain.class");
        let (class, diagnostics) = parse_class_file(bytes).expect("parse Plain.class");
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(class.this_class, "Plain");
        assert_eq!(class.super_class.as_deref(), Some("java.lang.Object"));
        let names: Vec<&str> = class.methods.iter().map(|m| m.name.as_str()).collect();
        assert!(names.contains(&"source"));
        assert!(names.contains(&"sink"));
        assert!(names.contains(&"run"));
        let run = class.methods.iter().find(|m| m.name == "run").unwrap();
        assert!(run.code.is_some());
        assert!(run.is_static());
    }

    #[test]
    fn rejects_pre_java_1_1_container_before_decoding_its_pool() {
        let mut bytes = include_bytes!("../tests/fixtures/Plain.class").to_vec();
        // magic occupies bytes 0..4, minor 4..6, major 6..8.
        bytes[6..8].copy_from_slice(&44u16.to_be_bytes());
        let error = parse_class_file(&bytes).expect_err("old container must fail");
        assert!(error.to_string().contains("older than the minimum"), "{error:#}");
    }
}
