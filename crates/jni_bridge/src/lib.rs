//! Shared types and the JNI symbol-mangling algorithm used to bridge a Java
//! `native` method declaration to the C/C++ function that implements it.
//!
//! This crate has no dependency on any parser: `uniflow-lang-java` and
//! `uniflow-lang-java-bytecode` each produce [`NativeMethodDecl`] values from
//! their own AST/classfile representation, and `uniflow-cli` consumes both
//! [`NativeMethodDecl`] and [`mangle_jni_short_name`] to match a Java native
//! declaration against a same-named C/C++ function.

/// One `native` method declaration discovered in Java source or bytecode.
/// Carries just enough information to compute its JNI-mangled symbol name
/// and its Java-side fully-qualified call name — it does not need a function
/// body, since native methods have none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeMethodDecl {
    /// Dotted fully-qualified class name, e.g. `com.example.Foo`.
    pub class: String,
    pub method: String,
    /// Number of Java-visible formal parameters (excludes the JNI-implicit
    /// leading `JNIEnv*`/`jobject`|`jclass` the native implementation itself
    /// receives).
    pub param_count: usize,
    /// Raw JVM method descriptor, e.g. `(Ljava/lang/String;)I`, when the
    /// declaration came from bytecode. Source-derived declarations don't
    /// resolve one (it would require full source-level-to-JVM-descriptor
    /// type resolution, which nothing else in this codebase needs) and leave
    /// this `None`.
    pub descriptor: Option<String>,
    pub is_static: bool,
}

impl NativeMethodDecl {
    /// The dotted `Class.method` name used by Java source/sink/propagator
    /// rule matchers elsewhere in the codebase (e.g. `App.source`).
    pub fn qualified_name(&self) -> String {
        format!("{}.{}", self.class, self.method)
    }

    /// The short-form (non-overload-qualified) JNI symbol name a C/C++
    /// implementation of this native method is expected to export.
    pub fn mangled_short_name(&self) -> String {
        mangle_jni_short_name(&self.class, &self.method)
    }
}

/// Computes the short-form JNI native method name for a native method named
/// `method` declared in `class` (dotted or slash-separated, either is
/// accepted), per the JNI spec's "Resolving Native Method Names" algorithm:
/// `Java_` + mangled class name + `_` + mangled method name, where mangling
/// replaces each package/class separator with `_`, escapes a literal `_` as
/// `_1`, `;` as `_2`, `[` as `_3`, and any other non-ASCII-alphanumeric
/// character as `_0hhhh` (its lowercase 4-hex-digit UTF-16 code unit).
///
/// This is the *short* form only: it omits the `__<encoded-signature>` suffix
/// the JNI spec adds to disambiguate overloaded natives, so two overloaded
/// native methods in the same class collide on this name — callers must
/// detect and handle that collision themselves.
pub fn mangle_jni_short_name(class: &str, method: &str) -> String {
    let class = class.replace('.', "/");
    let mut out = String::from("Java_");
    mangle_component(&class, &mut out);
    out.push('_');
    mangle_component(method, &mut out);
    out
}

fn mangle_component(component: &str, out: &mut String) {
    for ch in component.chars() {
        match ch {
            '/' => out.push('_'),
            '_' => out.push_str("_1"),
            ';' => out.push_str("_2"),
            '[' => out.push_str("_3"),
            c if c.is_ascii_alphanumeric() => out.push(c),
            c => {
                for unit in c.encode_utf16(&mut [0u16; 2]) {
                    out.push_str(&format!("_0{:04x}", unit));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mangles_a_plain_ascii_name() {
        assert_eq!(
            mangle_jni_short_name("com.example.Foo", "bar"),
            "Java_com_example_Foo_bar"
        );
    }

    #[test]
    fn accepts_slash_separated_class_names() {
        assert_eq!(
            mangle_jni_short_name("com/example/Foo", "bar"),
            "Java_com_example_Foo_bar"
        );
    }

    #[test]
    fn escapes_underscores_in_identifiers() {
        assert_eq!(
            mangle_jni_short_name("com.example.My_Class", "do_it"),
            "Java_com_example_My_1Class_do_1it"
        );
    }

    #[test]
    fn escapes_inner_class_dollar_sign_as_unicode() {
        assert_eq!(
            mangle_jni_short_name("com.example.Outer$Inner", "bar"),
            "Java_com_example_Outer_00024Inner_bar"
        );
    }

    #[test]
    fn qualified_name_uses_dotted_java_convention() {
        let decl = NativeMethodDecl {
            class: "com.example.Foo".to_string(),
            method: "bar".to_string(),
            param_count: 0,
            descriptor: Some("()V".to_string()),
            is_static: false,
        };
        assert_eq!(decl.qualified_name(), "com.example.Foo.bar");
        assert_eq!(decl.mangled_short_name(), "Java_com_example_Foo_bar");
    }
}
