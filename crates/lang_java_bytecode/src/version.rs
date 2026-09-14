//! Major-version gating for classfile constant-pool tags and opcodes.
//!
//! The classfile container format (constant pool table, method table,
//! attribute framing) has been stable since Java 1.0.2. What changes across
//! releases is which constant-pool tags and which opcodes are legal to
//! appear. This module is consulted during decode so that a tag/opcode used
//! in a class older than its introduction produces a recoverable diagnostic
//! instead of being silently accepted or misinterpreted.

/// `major_version` values, keyed by the Java release that introduced them.
pub const JAVA_1_1: u16 = 45;
pub const JAVA_7: u16 = 51;
pub const JAVA_9: u16 = 53;
pub const JAVA_11: u16 = 55;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassVersion {
    pub major: u16,
    pub minor: u16,
}

impl ClassVersion {
    pub fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

/// Validate the classfile container before interpreting its table contents.
/// Future JDK versions are intentionally not capped here: their framing is
/// stable and individual tags/opcodes are checked separately.
pub fn validate_container_version(version: ClassVersion) -> Result<(), String> {
    if version.major < JAVA_1_1 {
        return Err(format!(
            "class file major version {} is older than the minimum supported JVM classfile version {JAVA_1_1}",
            version.major
        ));
    }
    Ok(())
}

/// Returns `Ok(())` when constant-pool `tag` is legal for `version`, otherwise
/// a human-readable reason describing which release introduced it.
pub fn check_constant_pool_tag(tag: u8, version: ClassVersion) -> Result<(), String> {
    let introduced = match tag {
        // CONSTANT_Utf8, Integer, Float, Long, Double, Class, String,
        // Fieldref, Methodref, InterfaceMethodref, NameAndType: present
        // since the very first classfile format.
        1 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 => JAVA_1_1,
        // CONSTANT_MethodHandle, MethodType, InvokeDynamic (JSR 292).
        15 | 16 | 18 => JAVA_7,
        // CONSTANT_Module, Package (JPMS).
        19 | 20 => JAVA_9,
        // CONSTANT_Dynamic (JEP 309 condy).
        17 => JAVA_11,
        _ => {
            return Err(format!("unknown constant pool tag {tag}"));
        }
    };
    if version.major < introduced {
        return Err(format!(
            "constant pool tag {tag} requires class file major version >= {introduced}, found {}",
            version.major
        ));
    }
    Ok(())
}

/// Returns `Ok(())` when `opcode` is legal for `version`.
pub fn check_opcode(opcode: u8, version: ClassVersion) -> Result<(), String> {
    // `invokedynamic` (0xBA / 186) was a reserved-but-unusable opcode before
    // JSR 292 shipped in Java 7.
    if opcode == 0xBA && version.major < JAVA_7 {
        return Err(format!(
            "invokedynamic requires class file major version >= {JAVA_7}, found {}",
            version.major
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invokedynamic_constant_pool_tag_rejected_before_java7() {
        let old = ClassVersion::new(50, 0);
        assert!(check_constant_pool_tag(18, old).is_err());
        let new = ClassVersion::new(51, 0);
        assert!(check_constant_pool_tag(18, new).is_ok());
    }

    #[test]
    fn condy_tag_requires_java11() {
        assert!(check_constant_pool_tag(17, ClassVersion::new(54, 0)).is_err());
        assert!(check_constant_pool_tag(17, ClassVersion::new(55, 0)).is_ok());
    }

    #[test]
    fn invokedynamic_opcode_gated_by_version() {
        assert!(check_opcode(0xBA, ClassVersion::new(50, 0)).is_err());
        assert!(check_opcode(0xBA, ClassVersion::new(51, 0)).is_ok());
    }

    #[test]
    fn unknown_tag_is_an_error() {
        assert!(check_constant_pool_tag(200, ClassVersion::new(68, 0)).is_err());
    }

    #[test]
    fn pre_java_1_1_container_version_is_rejected() {
        assert!(validate_container_version(ClassVersion::new(44, 0)).is_err());
        assert!(validate_container_version(ClassVersion::new(45, 3)).is_ok());
        assert!(validate_container_version(ClassVersion::new(255, 0)).is_ok());
    }
}
