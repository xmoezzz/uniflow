use serde::{Deserialize, Serialize};
use uniflow_parser_core::c_declarations::{CDeclarationIndex, DerivedDeclarator as D};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CDeclarationCheck {
    VoidReturnValue,
    NonVoidMissingReturn,
    NonVoidEmptyReturn,
    EmptyDefinitionParameters,
    UnnamedParameter,
    UnnamedAggregate,
    UnionInsideStruct,
    UnsizedInitializedArray,
    LocalExtern,
    InitializedExtern,
    NullPointerZero,
}

impl CDeclarationCheck {
    pub(crate) fn offsets(self, source: &str, index: &CDeclarationIndex) -> Vec<usize> {
        let mut offsets = Vec::new();
        match self {
            Self::VoidReturnValue | Self::NonVoidEmptyReturn => {
                for statement in &index.returns {
                    // The source rule applies a raw-text regex, not an AST
                    // absence-of-expression predicate (comments matter).
                    let bare = source[statement.range.clone()]
                        .strip_prefix("return")
                        .and_then(|text| text.strip_suffix(';'))
                        .is_some_and(|text| text.chars().all(char::is_whitespace));
                    let void = index.functions[statement.function].returns_void;
                    if matches!(self, Self::VoidReturnValue) && void && !bare
                        || matches!(self, Self::NonVoidEmptyReturn) && !void && bare
                    {
                        offsets.push(statement.range.start);
                    }
                }
            }
            Self::NonVoidMissingReturn | Self::EmptyDefinitionParameters => {
                for (id, function) in index.functions.iter().enumerate() {
                    let matches = match self {
                        Self::NonVoidMissingReturn => {
                            !function.returns_void
                                && !index
                                    .returns
                                    .iter()
                                    .any(|statement| statement.function == id)
                        }
                        _ => index
                            .tokens_in(function.parameters.clone())
                            .next()
                            .is_none(),
                    };
                    if matches {
                        offsets.push(function.range.start);
                    }
                }
            }
            Self::UnnamedParameter => {
                for parameter in &index.parameters {
                    let contains = |range: &std::ops::Range<usize>| {
                        range.start >= parameter.range.start && range.end <= parameter.range.end
                    };
                    // Legacy `has identifier field: declarator stopBy: end`
                    // also accepts names in nested function-pointer parameters.
                    let named = parameter.has_name
                        || index
                            .parameters
                            .iter()
                            .any(|nested| nested.has_name && contains(&nested.range))
                        || index.declarations.iter().any(|nested| {
                            contains(&nested.range)
                                && nested
                                    .declarators
                                    .iter()
                                    .any(|declarator| declarator.name.is_some())
                        });
                    if !named && source[parameter.range.clone()] != *"void" {
                        offsets.push(parameter.range.start);
                    }
                }
            }
            Self::UnnamedAggregate | Self::UnionInsideStruct => {
                for aggregate in &index.aggregates {
                    match self {
                        Self::UnnamedAggregate if aggregate.name.is_none() => {
                            if let Some(body) = &aggregate.body {
                                offsets.push(body.start);
                            }
                        }
                        Self::UnionInsideStruct
                            if aggregate.kind == "union" && aggregate.inside_struct =>
                        {
                            offsets.push(aggregate.range.start)
                        }
                        _ => {}
                    }
                }
            }
            Self::UnsizedInitializedArray
            | Self::LocalExtern
            | Self::InitializedExtern
            | Self::NullPointerZero => {
                for declaration in &index.declarations {
                    if declaration.in_aggregate {
                        continue;
                    }
                    let external = declaration
                        .storage
                        .iter()
                        .any(|storage| storage == "extern");
                    let matches = match self {
                        Self::LocalExtern => external && declaration.enclosing_function.is_some(),
                        Self::InitializedExtern => external && declaration.declarators.iter().any(|declarator| declarator.initializer.is_some()),
                        Self::NullPointerZero => declaration.declarators.len() == 1 && declaration.declarators.iter().any(|declarator|
                            matches!(declarator.derived.as_slice(), [D::Pointer])
                                && declarator.initializer.as_ref().is_some_and(|initializer| {
                                    let mut tokens = index.tokens_in(initializer.clone());
                                    tokens.next().is_some_and(|token| token.kind == uniflow_parser_core::TokKind::IntLit && token.text == "0")
                                        && tokens.next().is_none()
                                })),
                        _ => declaration.declarators.len() == 1 && declaration.declarators.iter().any(|declarator|
                            matches!(declarator.derived.as_slice(), [D::Array { size }] if index.tokens_in(size.clone()).next().is_none())
                                && declarator.initializer.as_ref().is_some_and(|initializer|
                                    index.tokens_in(initializer.clone()).next().is_some_and(|token| token.text == "{"))),
                    };
                    if matches {
                        offsets.push(declaration.range.start);
                    }
                }
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}
