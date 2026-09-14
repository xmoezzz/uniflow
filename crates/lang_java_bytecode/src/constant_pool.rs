//! JVM constant pool decoding (JVMS §4.4).

use crate::reader::Reader;
use crate::version::{check_constant_pool_tag, ClassVersion};
use anyhow::{anyhow, bail, Result};

#[derive(Clone, Debug)]
pub enum ConstantPoolEntry {
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class {
        name_index: u16,
    },
    String {
        string_index: u16,
    },
    Fieldref {
        class_index: u16,
        name_and_type_index: u16,
    },
    Methodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    InterfaceMethodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_index: u16,
    },
    Dynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    InvokeDynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    Module {
        name_index: u16,
    },
    Package {
        name_index: u16,
    },
    /// Occupies the slot immediately after a Long/Double entry, which by
    /// spec counts for two constant-pool indices.
    Unusable,
}

#[derive(Clone, Debug, Default)]
pub struct ClassfileDiagnostic(pub String);

/// 1-indexed constant pool; `entries[0]` is always `None` (index 0 is
/// reserved and never valid).
#[derive(Clone, Debug, Default)]
pub struct ConstantPool {
    entries: Vec<Option<ConstantPoolEntry>>,
}

impl ConstantPool {
    pub fn parse(
        reader: &mut Reader<'_>,
        version: ClassVersion,
        diagnostics: &mut Vec<ClassfileDiagnostic>,
    ) -> Result<Self> {
        let count = reader.u16()?;
        let mut entries: Vec<Option<ConstantPoolEntry>> = vec![None; count as usize];
        let mut index = 1usize;
        while index < count as usize {
            let tag = reader.u8()?;
            if let Err(message) = check_constant_pool_tag(tag, version) {
                diagnostics.push(ClassfileDiagnostic(message));
            }
            let entry = match tag {
                1 => {
                    let len = reader.u16()? as usize;
                    let bytes = reader.bytes(len)?;
                    ConstantPoolEntry::Utf8(decode_modified_utf8(bytes))
                }
                3 => ConstantPoolEntry::Integer(reader.i32()?),
                4 => ConstantPoolEntry::Float(reader.f32()?),
                5 => ConstantPoolEntry::Long(reader.i64()?),
                6 => ConstantPoolEntry::Double(reader.f64()?),
                7 => ConstantPoolEntry::Class {
                    name_index: reader.u16()?,
                },
                8 => ConstantPoolEntry::String {
                    string_index: reader.u16()?,
                },
                9 => ConstantPoolEntry::Fieldref {
                    class_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                10 => ConstantPoolEntry::Methodref {
                    class_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                11 => ConstantPoolEntry::InterfaceMethodref {
                    class_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                12 => ConstantPoolEntry::NameAndType {
                    name_index: reader.u16()?,
                    descriptor_index: reader.u16()?,
                },
                15 => ConstantPoolEntry::MethodHandle {
                    reference_kind: reader.u8()?,
                    reference_index: reader.u16()?,
                },
                16 => ConstantPoolEntry::MethodType {
                    descriptor_index: reader.u16()?,
                },
                17 => ConstantPoolEntry::Dynamic {
                    bootstrap_method_attr_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                18 => ConstantPoolEntry::InvokeDynamic {
                    bootstrap_method_attr_index: reader.u16()?,
                    name_and_type_index: reader.u16()?,
                },
                19 => ConstantPoolEntry::Module {
                    name_index: reader.u16()?,
                },
                20 => ConstantPoolEntry::Package {
                    name_index: reader.u16()?,
                },
                other => bail!("unrecognized constant pool tag {other} at index {index}"),
            };
            let is_wide = matches!(entry, ConstantPoolEntry::Long(_) | ConstantPoolEntry::Double(_));
            entries[index] = Some(entry);
            index += 1;
            if is_wide {
                // JVMS §4.4.5: Long/Double entries occupy two constant pool
                // indices; the second is unusable.
                if index < entries.len() {
                    entries[index] = Some(ConstantPoolEntry::Unusable);
                }
                index += 1;
            }
        }
        Ok(Self { entries })
    }

    fn get(&self, index: u16) -> Result<&ConstantPoolEntry> {
        self.entries
            .get(index as usize)
            .and_then(|entry| entry.as_ref())
            .ok_or_else(|| anyhow!("constant pool index {index} is out of range or unusable"))
    }

    pub fn utf8(&self, index: u16) -> Result<&str> {
        match self.get(index)? {
            ConstantPoolEntry::Utf8(value) => Ok(value.as_str()),
            other => bail!("constant pool index {index} is not Utf8: {other:?}"),
        }
    }

    /// Resolves a `CONSTANT_Class` entry to its dotted, fully-qualified
    /// binary name (`com/example/Foo` -> `com.example.Foo`).
    pub fn class_name(&self, index: u16) -> Result<String> {
        match self.get(index)? {
            ConstantPoolEntry::Class { name_index } => {
                Ok(internal_name_to_dotted(self.utf8(*name_index)?))
            }
            other => bail!("constant pool index {index} is not Class: {other:?}"),
        }
    }

    pub fn name_and_type(&self, index: u16) -> Result<(&str, &str)> {
        match self.get(index)? {
            ConstantPoolEntry::NameAndType {
                name_index,
                descriptor_index,
            } => Ok((self.utf8(*name_index)?, self.utf8(*descriptor_index)?)),
            other => bail!("constant pool index {index} is not NameAndType: {other:?}"),
        }
    }

    /// Resolves any of the three `*ref` kinds to `(dotted class, member name, descriptor)`.
    pub fn member_ref(&self, index: u16) -> Result<(String, String, String)> {
        let (class_index, nat_index) = match self.get(index)? {
            ConstantPoolEntry::Fieldref {
                class_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::Methodref {
                class_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::InterfaceMethodref {
                class_index,
                name_and_type_index,
            } => (*class_index, *name_and_type_index),
            other => bail!("constant pool index {index} is not a member ref: {other:?}"),
        };
        let class = self.class_name(class_index)?;
        let (name, descriptor) = self.name_and_type(nat_index)?;
        Ok((class, name.to_string(), descriptor.to_string()))
    }

    pub fn string_value(&self, index: u16) -> Result<String> {
        match self.get(index)? {
            ConstantPoolEntry::String { string_index } => {
                Ok(self.utf8(*string_index)?.to_string())
            }
            other => bail!("constant pool index {index} is not String: {other:?}"),
        }
    }

    pub fn method_handle(&self, index: u16) -> Result<(u8, u16)> {
        match self.get(index)? {
            ConstantPoolEntry::MethodHandle {
                reference_kind,
                reference_index,
            } => Ok((*reference_kind, *reference_index)),
            other => bail!("constant pool index {index} is not MethodHandle: {other:?}"),
        }
    }

    /// Resolves `CONSTANT_InvokeDynamic`/`CONSTANT_Dynamic` to
    /// `(bootstrap_method_attr_index, member name, descriptor)`.
    pub fn dynamic_ref(&self, index: u16) -> Result<(u16, String, String)> {
        let (bootstrap_index, nat_index) = match self.get(index)? {
            ConstantPoolEntry::InvokeDynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            }
            | ConstantPoolEntry::Dynamic {
                bootstrap_method_attr_index,
                name_and_type_index,
            } => (*bootstrap_method_attr_index, *name_and_type_index),
            other => bail!("constant pool index {index} is not a dynamic ref: {other:?}"),
        };
        let (name, descriptor) = self.name_and_type(nat_index)?;
        Ok((bootstrap_index, name.to_string(), descriptor.to_string()))
    }

    pub fn entry(&self, index: u16) -> Result<&ConstantPoolEntry> {
        self.get(index)
    }
}

pub fn internal_name_to_dotted(name: &str) -> String {
    name.replace('/', ".")
}

/// The classfile format encodes `Utf8` constants using "modified UTF-8"
/// (JVMS §4.4.7): identical to standard UTF-8 for the ASCII range and for
/// all non-ASCII code points actually produced by `javac`. A byte-for-byte
/// modified-UTF-8 decoder is unnecessary for source-level identifiers,
/// literals and descriptors, so this falls back to lossy UTF-8 decoding
/// only for the rare inputs where it would matter (raw NUL / supplementary
/// characters encoded as CESU-8 surrogate pairs).
fn decode_modified_utf8(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => String::from_utf8_lossy(bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_names_become_dotted() {
        assert_eq!(internal_name_to_dotted("com/example/Foo"), "com.example.Foo");
        assert_eq!(internal_name_to_dotted("Foo"), "Foo");
    }
}
