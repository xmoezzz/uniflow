//! Bootstrap-method resolution for `invokedynamic` (JVMS §4.7.23, §6.5
//! `invokedynamic`). Real coverage is deliberately scoped to the two
//! bootstraps that account for the overwhelming majority of `invokedynamic`
//! call sites in ordinary (non-metaprogramming) Java/Kotlin/Android
//! bytecode: `LambdaMetafactory` (lambdas, method references) and
//! `StringConcatFactory` (`+`-concatenation compiled under `-target 9+`).
//! Anything else resolves to `ResolvedBootstrap::Unknown`.

use crate::classfile::ClassFile;
use anyhow::{bail, Result};

/// Whether a resolved lambda implementation method takes an explicit
/// receiver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImplKind {
    Static,
    Instance,
}

#[derive(Clone, Debug)]
pub enum ConcatPart {
    Arg(usize),
    Literal(String),
}

#[derive(Clone, Debug)]
pub enum ResolvedBootstrap {
    Lambda {
        impl_class: String,
        impl_name: String,
        impl_kind: ImplKind,
    },
    StringConcat {
        parts: Vec<ConcatPart>,
    },
    Unknown,
}

// JVMS Table 5.4.3.5-A method handle reference kinds.
const REF_INVOKE_VIRTUAL: u8 = 5;
const REF_INVOKE_STATIC: u8 = 6;
const REF_INVOKE_SPECIAL: u8 = 7;
const REF_NEW_INVOKE_SPECIAL: u8 = 8;
const REF_INVOKE_INTERFACE: u8 = 9;

pub fn resolve_bootstrap(class: &ClassFile, bootstrap_index: u16) -> Result<ResolvedBootstrap> {
    let Some(bootstrap) = class.bootstrap_methods.get(bootstrap_index as usize) else {
        bail!("bootstrap method index {bootstrap_index} out of range");
    };
    let (_ref_kind, ref_index) = class
        .constant_pool
        .method_handle(bootstrap.method_handle_index)?;
    let (bsm_class, bsm_name, _bsm_descriptor) = class.constant_pool.member_ref(ref_index)?;

    match (bsm_class.as_str(), bsm_name.as_str()) {
        ("java.lang.invoke.LambdaMetafactory", "metafactory" | "altMetafactory") => {
            // JVMS-adjacent convention (java.lang.invoke.LambdaMetafactory):
            // static arg[0] = samMethodType, arg[1] = implMethod, arg[2] =
            // instantiatedMethodType. Only arg[1] (the actual implementation)
            // matters for call-graph purposes.
            let Some(&impl_handle_index) = bootstrap.arguments.get(1) else {
                return Ok(ResolvedBootstrap::Unknown);
            };
            let (impl_ref_kind, impl_ref_index) =
                class.constant_pool.method_handle(impl_handle_index)?;
            let (impl_class, impl_name, _impl_descriptor) =
                class.constant_pool.member_ref(impl_ref_index)?;
            let impl_kind = match impl_ref_kind {
                REF_INVOKE_STATIC => ImplKind::Static,
                // A constructor reference (`Foo::new`) has no receiver
                // among the SAM's arguments either; treat it like a static
                // call over the same argument list.
                REF_NEW_INVOKE_SPECIAL => ImplKind::Static,
                REF_INVOKE_VIRTUAL | REF_INVOKE_SPECIAL | REF_INVOKE_INTERFACE => {
                    ImplKind::Instance
                }
                _ => ImplKind::Static,
            };
            Ok(ResolvedBootstrap::Lambda {
                impl_class,
                impl_name,
                impl_kind,
            })
        }
        ("java.lang.invoke.StringConcatFactory", "makeConcatWithConstants") => {
            let recipe = match bootstrap.arguments.first() {
                Some(&index) => class.constant_pool.string_value(index)?,
                None => String::new(),
            };
            Ok(ResolvedBootstrap::StringConcat {
                parts: parse_concat_recipe(&recipe),
            })
        }
        ("java.lang.invoke.StringConcatFactory", "makeConcat") => {
            // No recipe string: every dynamic argument is concatenated in
            // order with no literal text between them. The caller knows the
            // argument count from the call site's own descriptor, so a
            // dedicated marker (one `Arg` per position, resolved by the
            // caller) is produced lazily instead of guessing a count here.
            Ok(ResolvedBootstrap::StringConcat { parts: Vec::new() })
        }
        _ => Ok(ResolvedBootstrap::Unknown),
    }
}

/// Parses a `StringConcatFactory` recipe (JEP 280): `` marks the next
/// dynamic argument, `` marks an extra static constant (rare; not
/// resolved to its real value, since the exact literal text never matters
/// for taint propagation), and every other character is literal text,
/// accumulated until the next marker.
fn parse_concat_recipe(recipe: &str) -> Vec<ConcatPart> {
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut arg_index = 0usize;
    for ch in recipe.chars() {
        match ch {
            '\u{1}' => {
                if !literal.is_empty() {
                    parts.push(ConcatPart::Literal(std::mem::take(&mut literal)));
                }
                parts.push(ConcatPart::Arg(arg_index));
                arg_index += 1;
            }
            '\u{2}' => {
                if !literal.is_empty() {
                    parts.push(ConcatPart::Literal(std::mem::take(&mut literal)));
                }
                parts.push(ConcatPart::Literal("<literal>".to_string()));
            }
            other => literal.push(other),
        }
    }
    if !literal.is_empty() {
        parts.push(ConcatPart::Literal(literal));
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_alternates_literal_and_arg_parts() {
        let parts = parse_concat_recipe("prefix-\u{1}-\u{1}-suffix");
        let rendered: Vec<String> = parts
            .iter()
            .map(|part| match part {
                ConcatPart::Arg(index) => format!("arg{index}"),
                ConcatPart::Literal(text) => format!("lit:{text}"),
            })
            .collect();
        assert_eq!(
            rendered,
            vec!["lit:prefix-", "arg0", "lit:-", "arg1", "lit:-suffix"]
        );
    }
}
