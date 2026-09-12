use serde::{Deserialize, Serialize};
use crate::c_expression_rules::evaluate_c_constant_integer;
use std::collections::{HashMap, HashSet};
use uniflow_parser_core::c_declarations::{
    CDeclaration, CDeclarationIndex, CDeclarator, CFunctionContext, DerivedDeclarator as D,
};
use uniflow_parser_core::TokKind;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CDeclarationCheck {
    VoidReturnValue,
    NonVoidMissingReturn,
    NonVoidEmptyReturn,
    EmptyDefinitionParameters,
    UndeducedParameterType,
    UnnamedParameter,
    UnnamedAggregate,
    UnionInsideStruct,
    UnsizedInitializedArray,
    LocalExtern,
    InitializedExtern,
    NullPointerZero,
    MultipleLocalVariables,
    PointerTypedef,
    VariadicFunction,
    TriplePointerVariable,
    SignedLongLongVariable,
    IncompleteStructDeclaration,
    PlainCharVariable,
    EmptyFunctionParameters,
    IncompleteArrayVariable,
    NamedPrototypeParameter,
    TypedefOfTypedef,
    TooManyFunctionParameters,
    FunctionPointerReturn,
    SizedCharArrayStringInitializer,
    FunctionPointerParameter,
    AmbiguousCVariable,
    AmbiguousCppVariable,
    FunctionOver200Lines,
    KeywordUnderlyingTypedef,
    InvalidMainSignature,
    LabelNameCollision,
    AdjacentLabels,
    AnonymousNestedAggregateWithoutTypedef,
    FunctionNameAsVariable,
    BackwardGoto,
    NonVoidReturnUse,
    ReservedNamespaceDeclaration,
    UnusedLabel,
    NoReturnDirectReturn,
    PointerThrow,
    NonPrivateClassField,
    PrivateStaticDataMember,
    NonExplicitSingleParameterConstructor,
    NonConstPostfixOperatorReturn,
    AmbiguousMultipleInheritanceMember,
    LocalStdArray,
    VariableMatchesEarlierTypedef,
    VariableEnumeratorNameCollision,
    RepeatedEnumeratorValue,
    InconsistentEnumInitialization,
    RawFunctionPointerVariable,
    UnterminatedFixedCharArrayInitializer,
    UninitializedPointerVariable,
    ParameterShadowsGlobalVariable,
    LocalVariableShadowsGlobalVariable,
    ClassConversionOperator,
    DefaultArgumentInVirtualMethod,
    NonVirtualConstMismatchWithVirtual,
    HidingNonVirtualBaseMethod,
    IncompleteVirtualOverloadSet,
    RawPointerFieldWithoutCopyControl,
    SensitiveCharArrayBeforePointer,
    StandardLibraryFunctionRedefinition,
    AllocationDeallocationScalarPair,
    AllocationDeallocationArrayPair,
}

impl CDeclarationCheck {
    pub(crate) fn offsets(self, source: &str, index: &CDeclarationIndex) -> Vec<usize> {
        let mut offsets = Vec::new();
        let long_long_aliases = signed_long_long_aliases(index);
        let plain_char_aliases = plain_char_aliases(index);
        let function_pointer_aliases = function_pointer_aliases(index);
        let char_type_aliases = char_type_aliases(index);
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
            Self::EmptyFunctionParameters => {
                offsets.extend(
                    index
                        .functions
                        .iter()
                        .filter(|function| index.tokens_in(function.parameters.clone()).next().is_none())
                        .map(|function| function.parameters.start.saturating_sub(1)),
                );
                for declaration in &index.declarations {
                    offsets.extend(declaration.declarators.iter().filter_map(|declarator| {
                        match declarator.derived.first() {
                            Some(D::Function { parameters })
                                if index.tokens_in(parameters.clone()).next().is_none() =>
                            {
                                Some(parameters.start.saturating_sub(1))
                            }
                            _ => None,
                        }
                    }));
                }
            }
            Self::StandardLibraryFunctionRedefinition => {
                const STANDARD_NAMES: &[&str] = &[
                    "printf", "scanf", "malloc", "free", "exit", "getchar", "putchar",
                    "fopen", "fclose", "memset", "memcpy", "strcmp", "strlen", "strcat",
                    "atoi", "atof", "sin", "cos", "tan", "sqrt", "pow",
                ];
                offsets.extend(
                    index
                        .functions
                        .iter()
                        .filter(|function| STANDARD_NAMES.contains(&function.name.as_str()))
                        .map(|function| function.range.start),
                );
                offsets.extend(index.declarations.iter().flat_map(|declaration| {
                    declaration.declarators.iter().filter_map(|declarator| {
                        matches!(declarator.derived.first(), Some(D::Function { .. }))
                            .then_some(())?;
                        STANDARD_NAMES
                            .contains(&declarator.name.as_deref()?)
                            .then_some(declaration.range.start)
                    })
                }));
            }
            Self::AllocationDeallocationScalarPair => {
                offsets.extend(allocation_deallocation_offsets(index, false));
            }
            Self::AllocationDeallocationArrayPair => {
                offsets.extend(allocation_deallocation_offsets(index, true));
            }
            Self::UndeducedParameterType => {
                for function in &index.functions {
                    offsets.extend(
                        direct_parameters(index, function.parameters.clone())
                            .into_iter()
                            .filter(|parameter| parameter.undeduced_type)
                            .map(|parameter| {
                                parameter
                                    .name_range
                                    .as_ref()
                                    .map_or(parameter.range.start, |range| range.start)
                            }),
                    );
                }
            }
            Self::UnnamedParameter => {
                for declaration in &index.declarations {
                    for parameters in declaration.declarators.iter().filter_map(|declarator| {
                        match declarator.derived.first() {
                            Some(D::Function { parameters }) => Some(parameters.clone()),
                            _ => None,
                        }
                    }) {
                        let candidates = index
                            .parameters
                            .iter()
                            .filter(|parameter| {
                                parameters.start <= parameter.range.start
                                    && parameter.range.end <= parameters.end
                            })
                            .collect::<Vec<_>>();
                        for parameter in candidates.iter().filter(|parameter| {
                            !candidates.iter().any(|outer| {
                                outer.range.start <= parameter.range.start
                                    && parameter.range.end <= outer.range.end
                                    && outer.range != parameter.range
                            })
                        }) {
                            if !parameter.has_name && !parameter.plain_void {
                                offsets.push(parameter.range.start);
                            }
                        }
                    }
                }
            }
            Self::NamedPrototypeParameter => {
                for declaration in &index.declarations {
                    for parameters in declaration.declarators.iter().filter_map(|declarator| {
                        match declarator.derived.first() {
                            Some(D::Function { parameters }) => Some(parameters.clone()),
                            _ => None,
                        }
                    }) {
                        let candidates = index
                            .parameters
                            .iter()
                            .filter(|parameter| {
                                parameters.start <= parameter.range.start
                                    && parameter.range.end <= parameters.end
                            })
                            .collect::<Vec<_>>();
                        offsets.extend(
                            candidates
                                .iter()
                                .filter(|parameter| {
                                    parameter.has_name
                                        && !candidates.iter().any(|outer| {
                                            outer.range.start <= parameter.range.start
                                                && parameter.range.end <= outer.range.end
                                                && outer.range != parameter.range
                                        })
                                })
                                .map(|parameter| parameter.range.start),
                        );
                    }
                }
            }
            Self::TypedefOfTypedef => {
                let mut aliases = HashSet::new();
                let mut declarations = index.declarations.iter().collect::<Vec<_>>();
                declarations.sort_by_key(|declaration| declaration.range.start);
                for declaration in declarations {
                    if !declaration
                        .storage
                        .iter()
                        .any(|storage| storage == "typedef")
                    {
                        continue;
                    }
                    if aliases.contains(&declaration.type_name) {
                        offsets.extend(
                            declaration
                                .declarators
                                .iter()
                                .filter(|declarator| declarator.derived.is_empty())
                                .map(|declarator| declarator.range.start),
                        );
                    }
                    aliases.extend(
                        declaration
                            .declarators
                            .iter()
                            .filter_map(|declarator| declarator.name.clone()),
                    );
                }
            }
            Self::KeywordUnderlyingTypedef => {
                const KEYWORDS: &[&str] = &[
                    "void", "bool", "char", "wchar_t", "char16_t", "char32_t", "short",
                    "int", "long", "float", "double", "signed", "unsigned", "mutable",
                    "volatile", "static", "register",
                ];
                for declaration in &index.declarations {
                    if !declaration
                        .storage
                        .iter()
                        .any(|storage| storage == "typedef")
                        || !KEYWORDS.contains(&declaration.type_name.as_str())
                    {
                        continue;
                    }
                    let plain = declaration.declarators.iter().any(|declarator| {
                        declarator.derived.is_empty()
                            && !index
                                .tokens_in(declaration.range.start..declarator.range.start)
                                .any(|token| {
                                    matches!(token.text.as_str(), "const" | "volatile" | "restrict")
                                })
                    });
                    if plain {
                        offsets.push(declaration.range.start);
                    }
                }
            }
            Self::TooManyFunctionParameters => {
                offsets.extend(
                    index
                        .functions
                        .iter()
                        .filter(|function| {
                            direct_parameter_count(index, function.parameters.clone()) > 20
                        })
                        .map(|function| function.range.start),
                );
                for declaration in &index.declarations {
                    if declaration.declarators.iter().any(|declarator| {
                        matches!(
                            declarator.derived.first(),
                            Some(D::Function { parameters })
                                if direct_parameter_count(index, parameters.clone()) > 20
                        )
                    }) {
                        offsets.push(declaration.range.start);
                    }
                }
            }
            Self::FunctionPointerReturn => {
                offsets.extend(
                    index
                        .functions
                        .iter()
                        .filter(|function| {
                            function_pointer_aliases.contains(&function.return_type)
                        })
                        .map(|function| function.range.start),
                );
                for declaration in &index.declarations {
                    if function_pointer_aliases.contains(&declaration.type_name)
                        && declaration
                            .declarators
                            .iter()
                            .any(|declarator| {
                                matches!(
                                    declarator.derived.first(),
                                    Some(D::Function { .. })
                                )
                            })
                        || declaration.declarators.iter().any(|declarator| {
                            matches!(
                                declarator.derived.as_slice(),
                                [D::Function { .. }, D::Pointer, D::Function { .. }, ..]
                            )
                        })
                    {
                        offsets.push(declaration.range.start);
                    }
                }
            }
            Self::FunctionPointerParameter => {
                let mut function_ranges = index
                    .functions
                    .iter()
                    .map(|function| function.parameters.clone())
                    .collect::<Vec<_>>();
                function_ranges.extend(index.declarations.iter().flat_map(|declaration| {
                    declaration.declarators.iter().filter_map(|declarator| {
                        match declarator.derived.first() {
                            Some(D::Function { parameters }) => Some(parameters.clone()),
                            _ => None,
                        }
                    })
                }));
                for range in function_ranges {
                    let candidates = index
                        .parameters
                        .iter()
                        .filter(|parameter| {
                            range.start <= parameter.range.start
                                && parameter.range.end <= range.end
                        })
                        .collect::<Vec<_>>();
                    offsets.extend(
                        candidates
                            .iter()
                            .filter(|parameter| {
                                !candidates.iter().any(|outer| {
                                    outer.range.start <= parameter.range.start
                                        && parameter.range.end <= outer.range.end
                                        && outer.range != parameter.range
                                })
                            })
                            .filter(|parameter| {
                                function_pointer_aliases.contains(&parameter.type_name)
                                    || matches!(
                                        parameter.derived.as_slice(),
                                        [D::Pointer, D::Function { .. }, ..]
                                            | [D::MemberPointer, D::Function { .. }, ..]
                                    )
                            })
                            .map(|parameter| parameter.range.start),
                    );
                }
            }
            Self::AmbiguousCVariable | Self::AmbiguousCppVariable => {
                for declaration in &index.declarations {
                    if declaration.in_aggregate
                        || declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "typedef")
                    {
                        continue;
                    }
                    let local = declaration.enclosing_function.is_some();
                    let c_linkage_global = declaration.enclosing_function.is_none()
                        && !declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "static")
                        && (matches!(self, Self::AmbiguousCVariable)
                            || declaration.extern_c);
                    if !local && !c_linkage_global {
                        continue;
                    }
                    offsets.extend(
                        declaration
                            .declarators
                            .iter()
                            .filter(|declarator| {
                                matches!(declarator.name.as_deref(), Some("l" | "O"))
                                    && !matches!(
                                        declarator.derived.first(),
                                        Some(D::Function { .. })
                                    )
                            })
                            .map(|declarator| declarator.range.start),
                    );
                }
            }
            Self::FunctionOver200Lines => {
                offsets.extend(
                    index
                        .functions
                        .iter()
                        .filter(|function| {
                            source[function.range.clone()]
                                .bytes()
                                .filter(|byte| *byte == b'\n')
                                .count()
                                > 200
                        })
                        .map(|function| function.range.start),
                );
            }
            Self::InvalidMainSignature => {
                let pointer_aliases = pointer_type_aliases(index);
                for function in &index.functions {
                    if function.name == "main"
                        && function.is_global
                        && !valid_main_signature(
                            index,
                            &pointer_aliases,
                            &function.return_type,
                            function.parameters.clone(),
                        )
                    {
                        offsets.push(function.range.start);
                    }
                }
                for declaration in &index.declarations {
                    if declaration.enclosing_function.is_some() || declaration.in_aggregate {
                        continue;
                    }
                    for declarator in &declaration.declarators {
                        if declarator.name.as_deref() != Some("main") {
                            continue;
                        }
                        let Some(D::Function { parameters }) = declarator.derived.first() else {
                            continue;
                        };
                        if !valid_main_signature(
                            index,
                            &pointer_aliases,
                            &declaration.type_name,
                            parameters.clone(),
                        ) {
                            offsets.push(declaration.range.start);
                        }
                    }
                }
            }
            Self::LabelNameCollision => {
                for (function_id, function) in index.functions.iter().enumerate() {
                    let mut names = direct_parameters(index, function.parameters.clone())
                        .into_iter()
                        .filter_map(|parameter| parameter.name.clone())
                        .collect::<HashSet<_>>();
                    names.extend(
                        index
                            .declarations
                            .iter()
                            .filter(|declaration| {
                                declaration.enclosing_function == Some(function_id)
                            })
                            .flat_map(|declaration| declaration.declarators.iter())
                            .filter_map(|declarator| declarator.name.clone()),
                    );
                    names.extend(
                        index
                            .aggregates
                            .iter()
                            .filter(|aggregate| {
                                aggregate.enclosing_function == Some(function_id)
                            })
                            .filter_map(|aggregate| aggregate.name.clone()),
                    );
                    offsets.extend(
                        index
                            .labels
                            .iter()
                            .filter(|label| {
                                label.function == function_id && names.contains(&label.name)
                            })
                            .map(|label| label.range.start),
                    );
                }
            }
            Self::AdjacentLabels => {
                offsets.extend(
                    index
                        .labels
                        .iter()
                        .filter(|label| label.labels_another)
                        .map(|label| label.range.start),
                );
            }
            Self::AnonymousNestedAggregateWithoutTypedef => {
                offsets.extend(
                    index
                        .aggregates
                        .iter()
                        .filter(|aggregate| {
                            aggregate.inside_struct
                                && aggregate.name.is_none()
                                && matches!(aggregate.kind.as_str(), "struct" | "union" | "enum")
                                && !index.declarations.iter().any(|declaration| {
                                    declaration.range.start <= aggregate.range.start
                                        && aggregate.range.end <= declaration.range.end
                                        && declaration
                                            .storage
                                            .iter()
                                            .any(|storage| storage == "typedef")
                                })
                        })
                        .map(|aggregate| aggregate.range.start),
                );
            }
            Self::FunctionNameAsVariable => {
                let mut function_names = index
                    .functions
                    .iter()
                    .map(|function| function.qualified_name.clone())
                    .collect::<HashSet<_>>();
                for declaration in &index.declarations {
                    for declarator in &declaration.declarators {
                        if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                            function_names.insert(declaration_qualified_name(
                                declaration,
                                declarator,
                            ));
                        }
                    }
                }
                for declaration in &index.declarations {
                    offsets.extend(
                        declaration
                            .declarators
                            .iter()
                            .filter(|declarator| {
                                !matches!(
                                    declarator.derived.first(),
                                    Some(D::Function { .. })
                                ) && function_names.contains(&declaration_qualified_name(
                                    declaration,
                                    declarator,
                                ))
                            })
                            .map(|declarator| declarator.range.start),
                    );
                }
                offsets.extend(index.parameters.iter().filter_map(|parameter| {
                    parameter.name.as_ref().and_then(|name| {
                        function_names
                            .contains(name)
                            .then_some(parameter.range.start)
                    })
                }));
            }
            Self::BackwardGoto => {
                offsets.extend(index.gotos.iter().filter_map(|jump| {
                    index
                        .labels
                        .iter()
                        .any(|label| {
                            label.function == jump.function
                                && label.name == jump.target
                                && label.range.start < jump.range.start
                        })
                        .then_some(jump.range.start)
                }));
            }
            Self::NonVoidReturnUse => {
                let void_aliases = void_type_aliases(index);
                for (function_id, function) in index.functions.iter().enumerate() {
                    if function.returns_void || void_aliases.contains(&function.return_type) {
                        continue;
                    }
                    let returns = index
                        .returns
                        .iter()
                        .filter(|statement| statement.function == function_id)
                        .collect::<Vec<_>>();
                    if returns.is_empty() {
                        offsets.push(function.body.end.saturating_sub(1));
                    } else {
                        offsets.extend(
                            returns
                                .into_iter()
                                .filter(|statement| !statement.has_value)
                                .map(|statement| statement.range.start),
                        );
                    }
                }
            }
            Self::ReservedNamespaceDeclaration => {
                offsets.extend(index.declarations.iter().filter_map(|declaration| {
                    declaration
                        .qualification
                        .first()
                        .is_some_and(|part| matches!(part.as_str(), "std" | "posix"))
                        .then(|| {
                            declaration
                                .declarators
                                .first()
                                .map_or(declaration.range.start, |declarator| {
                                    declarator.range.start
                                })
                        })
                }));
                offsets.extend(index.functions.iter().filter_map(|function| {
                    function
                        .qualified_name
                        .split("::")
                        .next()
                        .is_some_and(|part| matches!(part, "std" | "posix"))
                        .then_some(function.range.start)
                }));
                offsets.extend(index.aggregates.iter().filter_map(|aggregate| {
                    let offset = aggregate.range.start;
                    index.declarations.iter().any(|declaration| {
                        declaration.range.start <= offset
                            && offset < declaration.range.end
                            && declaration
                                .qualification
                                .first()
                                .is_some_and(|part| matches!(part.as_str(), "std" | "posix"))
                    }).then_some(offset)
                }));
            }
            Self::UnusedLabel => offsets.extend(index.labels.iter().filter_map(|label| {
                (!index.gotos.iter().any(|jump| {
                    jump.function == label.function && jump.target == label.name
                }))
                .then_some(label.range.start)
            })),
            Self::NoReturnDirectReturn => {
                for (function_id, function) in index.functions.iter().enumerate() {
                    if !function.is_noreturn {
                        continue;
                    }
                    offsets.extend(
                        index
                            .returns
                            .iter()
                            .filter(|statement| {
                                statement.function == function_id && statement.direct_child
                            })
                            .map(|statement| statement.range.start),
                    );
                }
            }
            Self::PointerThrow => {
                for (function_id, function) in index.functions.iter().enumerate() {
                    let tokens = index.tokens_in(function.body.clone()).collect::<Vec<_>>();
                    for (at, token) in tokens.iter().enumerate() {
                        if token.text != "throw" {
                            continue;
                        }
                        let Some(operand) = tokens.get(at + 1) else {
                            continue;
                        };
                        if operand.text == ";" {
                            continue;
                        }
                        let intrinsic_pointer = matches!(
                            operand.text.as_str(),
                            "&" | "new" | "nullptr" | "this"
                        ) || operand.kind == uniflow_parser_core::TokKind::StringLit;
                        let declared_pointer = operand.kind == uniflow_parser_core::TokKind::Ident
                            && (index.declarations.iter().any(|declaration| {
                                (declaration.enclosing_function == Some(function_id)
                                    || declaration.enclosing_function.is_none())
                                    && declaration.declarators.iter().any(|declarator| {
                                        declarator.name.as_deref() == Some(operand.text.as_str())
                                            && declarator.derived.iter().any(|derived| {
                                                matches!(derived, D::Pointer | D::Array { .. })
                                            })
                                    })
                            }) || index.parameters.iter().any(|parameter| {
                                function.parameters.start <= parameter.range.start
                                    && parameter.range.end <= function.parameters.end
                                    && parameter.name.as_deref() == Some(operand.text.as_str())
                                    && parameter.derived.iter().any(|derived| {
                                        matches!(derived, D::Pointer | D::Array { .. })
                                    })
                            }));
                        if intrinsic_pointer || declared_pointer {
                            offsets.push(token.start as usize);
                        }
                    }
                }
            }
            Self::NonPrivateClassField | Self::PrivateStaticDataMember => {
                for aggregate in index
                    .aggregates
                    .iter()
                    .filter(|aggregate| aggregate.kind == "class")
                {
                    let Some(body) = aggregate.body.clone() else {
                        continue;
                    };
                    for declaration in index.declarations.iter().filter(|declaration| {
                        declaration.in_aggregate
                            && declaration.qualification.join("::") == aggregate.qualified_name
                            && body.start <= declaration.range.start
                            && declaration.range.end <= body.end
                    }) {
                        let access = class_access_at(index, body.clone(), declaration.range.start);
                        let is_static = declaration.storage.iter().any(|item| item == "static");
                        offsets.extend(
                            declaration
                                .declarators
                                .iter()
                                .filter(|declarator| {
                                    !declarator
                                        .derived
                                        .iter()
                                        .any(|derived| matches!(derived, D::Function { .. }))
                                })
                                .filter(|_| match self {
                                    Self::NonPrivateClassField => !is_static && access != "private",
                                    Self::PrivateStaticDataMember => {
                                        is_static && access == "private"
                                    }
                                    _ => false,
                                })
                                .map(|_| declaration.range.start),
                        );
                    }
                }
            }
            Self::NonExplicitSingleParameterConstructor => {
                offsets.extend(non_explicit_single_parameter_constructors(index))
            }
            Self::NonConstPostfixOperatorReturn => {
                offsets.extend(non_const_postfix_operator_returns(index))
            }
            Self::AmbiguousMultipleInheritanceMember => {
                offsets.extend(ambiguous_multiple_inheritance_members(index))
            }
            Self::LocalStdArray => offsets.extend(index.declarations.iter().filter_map(
                |declaration| {
                    let normalized = declaration.type_name.replace(' ', "");
                    (declaration.enclosing_function.is_some()
                        && normalized.starts_with("std::array<"))
                    .then_some(declaration.range.start)
                },
            )),
            Self::VariableMatchesEarlierTypedef => {
                let typedefs = index
                    .declarations
                    .iter()
                    .filter(|declaration| declaration.storage.iter().any(|item| item == "typedef"))
                    .flat_map(|declaration| {
                        declaration.declarators.iter().filter_map(|declarator| {
                            declarator
                                .name
                                .as_deref()
                                .map(|name| (name, declaration.range.start))
                        })
                    })
                    .collect::<Vec<_>>();
                offsets.extend(
                    index
                        .declarations
                        .iter()
                        .filter(|declaration| {
                            !declaration.storage.iter().any(|item| item == "typedef")
                        })
                        .filter_map(|declaration| {
                            declaration
                                .declarators
                                .iter()
                                .any(|declarator| {
                                    !matches!(declarator.derived.first(), Some(D::Function { .. }))
                                        && declarator.name.as_deref().is_some_and(|name| {
                                            typedefs.iter().any(|(typedef, offset)| {
                                                *typedef == name
                                                    && *offset < declaration.range.start
                                            })
                                        })
                                })
                                .then_some(declaration.range.start)
                        }),
                );
            }
            Self::VariableEnumeratorNameCollision => {
                let variables = index
                    .declarations
                    .iter()
                    .filter(|declaration| {
                        !declaration.storage.iter().any(|item| item == "typedef")
                    })
                    .flat_map(|declaration| {
                        declaration.declarators.iter().filter_map(|declarator| {
                            if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                                return None;
                            }
                            Some((
                                declarator.name.as_deref()?,
                                declaration.range.start,
                                declaration.enclosing_function,
                                declaration.qualification.as_slice(),
                            ))
                        })
                    })
                    .collect::<Vec<_>>();
                for (name, offset, function, qualification) in &variables {
                    if index.enumerators.iter().any(|enumerator| {
                        enumerator.name == *name
                            && enumerator.range.start < *offset
                            && declaration_context_is_ancestor(
                                enumerator.enclosing_function,
                                &enumerator.qualification,
                                *function,
                                qualification,
                            )
                    }) {
                        offsets.push(*offset);
                    }
                }
                for enumerator in &index.enumerators {
                    if variables.iter().any(|(name, offset, function, qualification)| {
                        *name == enumerator.name
                            && *offset < enumerator.range.start
                            && declaration_context_is_ancestor(
                                *function,
                                qualification,
                                enumerator.enclosing_function,
                                &enumerator.qualification,
                            )
                    }) {
                        offsets.push(enumerator.range.start);
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
            Self::IncompleteStructDeclaration => {
                let mut seen = HashSet::new();
                let mut aggregates = index.aggregates.iter().collect::<Vec<_>>();
                aggregates.sort_by_key(|aggregate| aggregate.range.start);
                for aggregate in aggregates {
                    if aggregate.kind != "struct" {
                        continue;
                    }
                    let Some(name) = aggregate.name.as_ref() else {
                        continue;
                    };
                    if aggregate.body.is_some() {
                        seen.insert(name.clone());
                        continue;
                    }
                    let explicit_forward = index.declarations.iter().any(|declaration| {
                        declaration.range.start <= aggregate.range.start
                            && aggregate.range.end <= declaration.range.end
                            && declaration.declarators.is_empty()
                    });
                    if explicit_forward || !seen.contains(name) {
                        offsets.push(aggregate.range.start);
                    }
                    seen.insert(name.clone());
                }
            }
            Self::UnsizedInitializedArray
            | Self::LocalExtern
            | Self::InitializedExtern
            | Self::NullPointerZero
            | Self::MultipleLocalVariables
            | Self::PointerTypedef
            | Self::VariadicFunction
            | Self::TriplePointerVariable
            | Self::SignedLongLongVariable
            | Self::PlainCharVariable
            | Self::IncompleteArrayVariable
            | Self::SizedCharArrayStringInitializer => {
                if matches!(self, Self::VariadicFunction) {
                    offsets.extend(
                        index
                            .functions
                            .iter()
                            .filter(|function| {
                                has_top_level_ellipsis(index, function.parameters.clone())
                            })
                            .map(|function| function.range.start),
                    );
                }
                if matches!(self, Self::TriplePointerVariable) {
                    offsets.extend(
                        index
                            .parameters
                            .iter()
                            .filter(|parameter| {
                                matches!(
                                    parameter.derived.as_slice(),
                                    [D::Pointer, D::Pointer, D::Pointer, ..]
                                )
                            })
                            .map(|parameter| parameter.range.start),
                    );
                }
                if matches!(self, Self::SignedLongLongVariable) {
                    offsets.extend(
                        index
                            .parameters
                            .iter()
                            .filter(|parameter| {
                                parameter.derived.is_empty()
                                    && is_signed_long_long(
                                        &parameter.type_name,
                                        &long_long_aliases,
                                    )
                            })
                            .map(|parameter| parameter.range.start),
                    );
                }
                if matches!(self, Self::PlainCharVariable) {
                    offsets.extend(
                        index
                            .parameters
                            .iter()
                            .filter(|parameter| {
                                parameter.derived.is_empty()
                                    && is_plain_char(&parameter.type_name, &plain_char_aliases)
                            })
                            .map(|parameter| parameter.range.start),
                    );
                }
                for declaration in &index.declarations {
                    let static_member = declaration.in_aggregate
                        && declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "static");
                    if declaration.in_aggregate
                        && !(matches!(
                            self,
                            Self::SignedLongLongVariable | Self::PlainCharVariable
                        ) && static_member)
                    {
                        continue;
                    }
                    let external = declaration
                        .storage
                        .iter()
                        .any(|storage| storage == "extern");
                    if matches!(self, Self::LocalExtern)
                        && external
                        && declaration.enclosing_function.is_some()
                    {
                        if declaration.declarators.iter().any(|declarator| {
                            !matches!(declarator.derived.first(), Some(D::Function { .. }))
                        }) {
                            offsets.push(declaration.range.start);
                        }
                        continue;
                    }
                    if matches!(self, Self::InitializedExtern) && external {
                        offsets.extend(
                            declaration
                                .declarators
                                .iter()
                                .filter_map(|declarator| declarator.initializer.as_ref())
                                .map(|initializer| initializer.start),
                        );
                        continue;
                    }
                    if matches!(self, Self::TriplePointerVariable) {
                        if !declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "typedef")
                        {
                            offsets.extend(
                                declaration
                                    .declarators
                                    .iter()
                                    .filter(|declarator| {
                                        matches!(
                                            declarator.derived.as_slice(),
                                            [D::Pointer, D::Pointer, D::Pointer, ..]
                                        )
                                    })
                                    .map(|declarator| declarator.range.start),
                            );
                        }
                        continue;
                    }
                    if matches!(self, Self::SignedLongLongVariable) {
                        if !declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "typedef")
                            && is_signed_long_long(
                                &declaration.type_name,
                                &long_long_aliases,
                            )
                        {
                            offsets.extend(
                                declaration
                                    .declarators
                                    .iter()
                                    .filter(|declarator| declarator.derived.is_empty())
                                    .map(|declarator| declarator.range.start),
                            );
                        }
                        continue;
                    }
                    if matches!(self, Self::IncompleteArrayVariable) {
                        if !declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "typedef")
                        {
                            offsets.extend(
                                declaration
                                    .declarators
                                    .iter()
                                    .filter(|declarator| {
                                        matches!(
                                            declarator.derived.first(),
                                            Some(D::Array { size })
                                                if index.tokens_in(size.clone()).next().is_none()
                                        ) && declarator.initializer.is_none()
                                    })
                                    .map(|declarator| declarator.range.start),
                            );
                        }
                        continue;
                    }
                    if matches!(self, Self::SizedCharArrayStringInitializer) {
                        if is_char_type(&declaration.type_name, &char_type_aliases) {
                            offsets.extend(
                                declaration
                                    .declarators
                                    .iter()
                                    .filter(|declarator| {
                                        matches!(
                                            declarator.derived.first(),
                                            Some(D::Array { size })
                                                if index.tokens_in(size.clone()).next().is_some()
                                        ) && declarator.initializer.as_ref().is_some_and(
                                            |initializer| {
                                                initializer_is_string(index, initializer.clone())
                                            },
                                        )
                                    })
                                    .map(|_| declaration.range.start),
                            );
                        }
                        continue;
                    }
                    if matches!(self, Self::PlainCharVariable) {
                        if !declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "typedef")
                            && is_plain_char(&declaration.type_name, &plain_char_aliases)
                        {
                            offsets.extend(
                                declaration
                                    .declarators
                                    .iter()
                                    .filter(|declarator| declarator.derived.is_empty())
                                    .map(|declarator| declarator.range.start),
                            );
                        }
                        continue;
                    }
                    let matches = match self {
                        Self::LocalExtern => false,
                        Self::InitializedExtern => false,
                        Self::MultipleLocalVariables => {
                            declaration.enclosing_function.is_some()
                                && declaration.declarators.len() > 1
                        }
                        Self::PointerTypedef => declaration
                            .storage
                            .iter()
                            .any(|storage| storage == "typedef")
                            && declaration.declarators.iter().any(|declarator| {
                                matches!(declarator.derived.first(), Some(D::Pointer))
                                    && !matches!(
                                        declarator.derived.get(1),
                                        Some(D::Function { .. })
                                    )
                            }),
                        Self::VariadicFunction => declaration.declarators.iter().any(
                            |declarator| {
                                matches!(
                                    declarator.derived.first(),
                                    Some(D::Function { parameters })
                                        if has_top_level_ellipsis(index, parameters.clone())
                                )
                            }),
                        Self::TriplePointerVariable => false,
                        Self::SignedLongLongVariable => false,
                        Self::PlainCharVariable => false,
                        Self::IncompleteArrayVariable => false,
                        Self::SizedCharArrayStringInitializer => false,
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
            Self::RepeatedEnumeratorValue => {
                offsets.extend(repeated_enumerator_values(index));
            }
            Self::InconsistentEnumInitialization => {
                offsets.extend(inconsistently_initialized_enums(index));
            }
            Self::RawFunctionPointerVariable => {
                offsets.extend(index.declarations.iter().filter_map(|declaration| {
                    (!declaration.storage.iter().any(|storage| storage == "typedef")
                        && !function_pointer_aliases.contains(&declaration.type_name)
                        && declaration.declarators.iter().any(|declarator| {
                            matches!(
                                declarator.derived.as_slice(),
                                [D::Pointer | D::MemberPointer, D::Function { .. }, ..]
                            )
                        }))
                    .then_some(declaration.range.start)
                }));
            }
            Self::UnterminatedFixedCharArrayInitializer => {
                offsets.extend(unterminated_char_array_offsets(index));
            }
            Self::UninitializedPointerVariable => {
                offsets.extend(uninitialized_pointer_offsets(index));
            }
            Self::ParameterShadowsGlobalVariable => {
                offsets.extend(parameter_shadow_offsets(index));
            }
            Self::LocalVariableShadowsGlobalVariable => {
                offsets.extend(local_variable_shadow_offsets(index));
            }
            Self::ClassConversionOperator => {
                offsets.extend(class_conversion_operator_offsets(index));
            }
            Self::DefaultArgumentInVirtualMethod => {
                offsets.extend(default_arguments_in_virtual_methods(index));
            }
            Self::NonVirtualConstMismatchWithVirtual => {
                offsets.extend(nonvirtual_const_mismatch_with_virtual_offsets(index));
            }
            Self::HidingNonVirtualBaseMethod => {
                offsets.extend(hiding_nonvirtual_base_method_offsets(index));
            }
            Self::IncompleteVirtualOverloadSet => {
                offsets.extend(incomplete_virtual_overload_set_offsets(index));
            }
            Self::RawPointerFieldWithoutCopyControl => {
                offsets.extend(raw_pointer_field_without_copy_control_offsets(index));
            }
            Self::SensitiveCharArrayBeforePointer => {
                offsets.extend(sensitive_char_array_before_pointer_offsets(index));
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

#[derive(Default)]
struct AllocationPairState {
    has_new: bool,
    has_delete: bool,
    has_array_new: bool,
    has_array_delete: bool,
    last_scalar: Option<usize>,
    last_array: Option<usize>,
    last_operator: Option<usize>,
}

fn update_allocation_pair(state: &mut AllocationPairState, name: &str, offset: usize, all: bool) {
    match name {
        "operator new" => {
            state.has_new = true;
            state.last_scalar = Some(state.last_scalar.map_or(offset, |last| last.max(offset)));
        }
        "operator delete" => {
            state.has_delete = true;
            state.last_scalar = Some(state.last_scalar.map_or(offset, |last| last.max(offset)));
        }
        "operator new[]" => {
            state.has_array_new = true;
            state.last_array = Some(state.last_array.map_or(offset, |last| last.max(offset)));
        }
        "operator delete[]" => {
            state.has_array_delete = true;
            state.last_array = Some(state.last_array.map_or(offset, |last| last.max(offset)));
        }
        _ => {}
    }
    if all && name.starts_with("operator") {
        state.last_operator = Some(state.last_operator.map_or(offset, |last| last.max(offset)));
    }
}

fn allocation_deallocation_offsets(index: &CDeclarationIndex, array: bool) -> Vec<usize> {
    let defined_records = index
        .aggregates
        .iter()
        .filter(|aggregate| {
            aggregate.kind != "enum"
                && aggregate.body.is_some()
                && !aggregate.qualified_name.is_empty()
        })
        .map(|aggregate| aggregate.qualified_name.as_str())
        .collect::<HashSet<_>>();
    let mut records = HashMap::<String, AllocationPairState>::new();

    for declaration in &index.declarations {
        if !declaration.in_aggregate {
            continue;
        }
        let owner = declaration.qualification.join("::");
        if !defined_records.contains(owner.as_str()) {
            continue;
        }
        for declarator in &declaration.declarators {
            if !matches!(declarator.derived.first(), Some(D::Function { .. })) {
                continue;
            }
            if let Some(name) = declarator.name.as_deref() {
                update_allocation_pair(
                    records.entry(owner.clone()).or_default(),
                    name,
                    declaration.range.start,
                    false,
                );
            }
        }
    }

    for function in &index.functions {
        let CFunctionContext::Record { qualified_name } = &function.context else {
            continue;
        };
        if !defined_records.contains(qualified_name.as_str()) {
            continue;
        }
        update_allocation_pair(
            records.entry(qualified_name.clone()).or_default(),
            &function.name,
            function.range.start,
            false,
        );
    }

    let mut offsets = records
        .values()
        .filter_map(|state| {
            if array {
                (state.has_array_new != state.has_array_delete)
                    .then_some(state.last_array)
                    .flatten()
            } else {
                (state.has_new != state.has_delete)
                    .then_some(state.last_scalar)
                    .flatten()
            }
        })
        .collect::<Vec<_>>();

    let mut free_functions = HashMap::<String, AllocationPairState>::new();
    for function in &index.functions {
        let domain = match &function.context {
            CFunctionContext::TranslationUnit => "".to_string(),
            CFunctionContext::Namespace { name, .. } => name.clone(),
            CFunctionContext::Record { .. } | CFunctionContext::Other => continue,
        };
        if !function.name.starts_with("operator") {
            continue;
        }
        update_allocation_pair(
            free_functions.entry(domain).or_default(),
            &function.name,
            function.range.start,
            true,
        );
    }
    offsets.extend(free_functions.values().filter_map(|state| {
        let mismatch = if array {
            state.has_array_new != state.has_array_delete
        } else {
            state.has_new != state.has_delete
        };
        mismatch.then_some(state.last_operator).flatten()
    }));
    offsets
}

fn uninitialized_pointer_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    index
        .declarations
        .iter()
        .filter(|declaration| !declaration.storage.iter().any(|item| item == "typedef"))
        .filter_map(|declaration| {
            declaration
                .declarators
                .iter()
                .any(|declarator| {
                    matches!(declarator.derived.first(), Some(D::Pointer))
                        && declarator.initializer.is_none()
                })
                .then_some(declaration.range.start)
        })
        .collect()
}

fn parameter_shadow_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let globals = global_variable_names(index);
    index
        .parameters
        .iter()
        .filter_map(|parameter| {
            let name = parameter.name.as_deref()?;
            let function = index.functions.iter().find(|function| {
                function.parameters.start <= parameter.range.start
                    && parameter.range.end <= function.parameters.end
            })?;
            let owner = function
                .qualified_name
                .rsplit_once("::")
                .map(|(owner, _)| owner);
            globals
                .iter()
                .any(|global| {
                    global.name == name
                        && match owner {
                            Some(owner) => global.owner.as_deref() == Some(owner),
                            None => global.owner.is_none(),
                        }
                })
                .then_some(parameter.range.start)
        })
        .collect()
}

fn local_variable_shadow_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let globals = global_variable_names(index);
    let mut offsets = Vec::new();
    for declaration in index.declarations.iter().filter(|declaration| {
        declaration.enclosing_function.is_some()
            && !declaration.storage.iter().any(|item| item == "static")
    }) {
        let Some(function) = declaration
            .enclosing_function
            .and_then(|function| index.functions.get(function))
        else {
            continue;
        };
        let owner = function
            .qualified_name
            .rsplit_once("::")
            .map(|(owner, _)| owner);
        if declaration.declarators.iter().any(|declarator| {
            let Some(name) = declarator.name.as_deref() else {
                return false;
            };
            globals.iter().any(|global| {
                global.name == name
                    && (global.owner.is_none()
                        || owner.is_some_and(|owner| {
                            global.owner.as_deref().is_some_and(|global_owner| {
                                owner == global_owner
                                    || owner.starts_with(&format!("{global_owner}::"))
                            })
                        }))
            })
        }) {
            offsets.push(declaration.range.start);
        }
    }
    offsets
}

struct GlobalVariableName<'a> {
    name: &'a str,
    owner: Option<String>,
}

fn global_variable_names(index: &CDeclarationIndex) -> Vec<GlobalVariableName<'_>> {
    index
        .declarations
        .iter()
        .filter(|declaration| declaration.enclosing_function.is_none())
        .filter(|declaration| {
            !declaration.in_aggregate
                || declaration.storage.iter().any(|item| item == "static")
        })
        .flat_map(|declaration| {
            declaration.declarators.iter().filter_map(move |declarator| {
                let name = declarator.name.as_deref()?;
                if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                    return None;
                }
                Some(GlobalVariableName {
                    name,
                    owner: declaration
                        .in_aggregate
                        .then(|| declaration.qualification.join("::")),
                })
            })
        })
        .collect()
}

fn class_conversion_operator_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for body in index
        .aggregates
        .iter()
        .filter(|aggregate| aggregate.kind == "class")
        .filter_map(|aggregate| aggregate.body.as_ref())
    {
        let tokens = index.tokens_in(body.clone()).collect::<Vec<_>>();
        let mut depth = 0usize;
        for at in 0..tokens.len() {
            match tokens[at].text.as_str() {
                "{" => {
                    depth += 1;
                    continue;
                }
                "}" => {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                _ => {}
            }
            if depth != 1 || tokens[at].text != "operator" {
                continue;
            }
            let Some(next) = tokens.get(at + 1) else {
                continue;
            };
            if next.kind != TokKind::Ident
                || matches!(next.text.as_str(), "new" | "delete" | "co_await")
            {
                continue;
            }
            let mut begin = at;
            while begin > 0
                && !matches!(tokens[begin - 1].text.as_str(), ";" | "{" | "}" | ":")
            {
                begin -= 1;
            }
            offsets.push(tokens[begin].start as usize);
        }
    }
    offsets
}

#[derive(Clone)]
struct CppMethodInfo {
    owner: String,
    name: String,
    offset: usize,
    parameters: std::ops::Range<usize>,
    signature: Vec<String>,
    is_const: bool,
    direct_virtual: bool,
    is_defaulted: bool,
    is_static: bool,
}

fn default_arguments_in_virtual_methods(index: &CDeclarationIndex) -> Vec<usize> {
    let methods = cpp_method_infos(index);
    let aggregates = index
        .aggregates
        .iter()
        .filter(|aggregate| matches!(aggregate.kind.as_str(), "class" | "struct"))
        .filter(|aggregate| !aggregate.qualified_name.is_empty())
        .map(|aggregate| (aggregate.qualified_name.as_str(), aggregate))
        .collect::<HashMap<_, _>>();
    let mut offsets = Vec::new();
    for method in &methods {
        if method.is_static
            || !method_is_virtual(method, &methods, &aggregates, &mut HashSet::new())
        {
            continue;
        }
        for parameter in direct_parameters(index, method.parameters.clone()) {
            if let Some(offset) = default_argument_offset(index, parameter.range.clone()) {
                offsets.push(offset);
            }
        }
    }
    offsets
}

fn cpp_method_infos(index: &CDeclarationIndex) -> Vec<CppMethodInfo> {
    let mut methods = Vec::new();
    for function in &index.functions {
        let Some((owner, name)) = function.qualified_name.rsplit_once("::") else {
            continue;
        };
        methods.push(CppMethodInfo {
            owner: owner.to_string(),
            name: name.to_string(),
            offset: function.range.start,
            parameters: function.parameters.clone(),
            signature: method_parameter_signature(index, function.parameters.clone()),
            is_const: function.is_const,
            direct_virtual: range_has_word(
                index,
                function.range.start..function.body.start,
                "virtual",
            ) || range_has_word(
                index,
                function.range.start..function.body.start,
                "override",
            ),
            is_static: range_has_word(
                index,
                function.range.start..function.body.start,
                "static",
            ),
            is_defaulted: false,
        });
    }
    for declaration in index
        .declarations
        .iter()
        .filter(|declaration| declaration.in_aggregate)
    {
        let owner = declaration.qualification.join("::");
        if owner.is_empty() {
            continue;
        }
        for declarator in &declaration.declarators {
            let Some(D::Function { parameters }) = declarator.derived.first() else {
                continue;
            };
            let Some(name) = declarator.name.as_ref() else {
                continue;
            };
            methods.push(CppMethodInfo {
                owner: owner.clone(),
                name: name.clone(),
                offset: declaration.range.start,
                parameters: parameters.clone(),
                signature: method_parameter_signature(index, parameters.clone()),
                is_const: declarator
                    .trailing_qualifiers
                    .iter()
                    .any(|qualifier| qualifier == "const"),
                direct_virtual: range_has_word(index, declaration.range.clone(), "virtual")
                    || range_has_word(index, declaration.range.clone(), "override"),
                is_static: declaration.storage.iter().any(|item| item == "static"),
                is_defaulted: range_has_word(index, declaration.range.clone(), "default"),
            });
        }
    }
    methods
}

fn method_parameter_signature(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Vec<String> {
    direct_parameters(index, range)
        .into_iter()
        .map(|parameter| {
            let mut signature = parameter.type_name.split_whitespace().collect::<String>();
            for derived in &parameter.derived {
                signature.push_str(match derived {
                    D::Pointer => "*",
                    D::Reference => "&",
                    D::RvalueReference => "&&",
                    D::MemberPointer => "::*",
                    D::Array { .. } => "[]",
                    D::Function { .. } => "()",
                });
            }
            signature
        })
        .collect()
}

fn range_has_word(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
    word: &str,
) -> bool {
    index.tokens_in(range).any(|token| token.text == word)
}

fn method_is_virtual(
    method: &CppMethodInfo,
    methods: &[CppMethodInfo],
    aggregates: &HashMap<&str, &uniflow_parser_core::c_declarations::CAggregate>,
    visiting: &mut HashSet<String>,
) -> bool {
    if method.direct_virtual {
        return true;
    }
    if !visiting.insert(method.owner.clone()) {
        return false;
    }
    let Some(owner) = aggregates.get(method.owner.as_str()) else {
        return false;
    };
    for base in &owner.bases {
        let base_name = aggregates
            .keys()
            .find(|candidate| **candidate == base || candidate.ends_with(&format!("::{base}")))
            .copied()
            .unwrap_or(base.as_str());
        for base_method in methods.iter().filter(|candidate| {
            candidate.owner == base_name
                && candidate.name == method.name
                && candidate.signature == method.signature
                && candidate.is_const == method.is_const
        }) {
            if method_is_virtual(base_method, methods, aggregates, visiting) {
                return true;
            }
        }
    }
    false
}

/// Finds non-virtual methods that differ only by trailing `const` from a
/// virtual method declared by the same class or one of its bases. Such a
/// method hides the virtual slot instead of overriding it; this mirrors the
/// legacy Clang checker, including its bounded base-class traversal.
fn nonvirtual_const_mismatch_with_virtual_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let methods = cpp_method_infos(index);
    let aggregates = index
        .aggregates
        .iter()
        .filter(|aggregate| matches!(aggregate.kind.as_str(), "class" | "struct"))
        .filter(|aggregate| !aggregate.qualified_name.is_empty())
        .map(|aggregate| (aggregate.qualified_name.as_str(), aggregate))
        .collect::<HashMap<_, _>>();
    methods
        .iter()
        .filter(|method| !method.direct_virtual)
        .filter(|method| {
            !method_is_virtual(method, &methods, &aggregates, &mut HashSet::new())
                && record_or_base_has_opposite_const_virtual(
                    &method.owner,
                    method,
                    &methods,
                    &aggregates,
                    &mut HashSet::new(),
                    10,
                )
        })
        .map(|method| method.offset)
        .collect()
}

/// Matches the legacy record-declaration checker: a non-virtual method in a
/// class may hide any same-named non-virtual, non-defaulted method in a direct
/// base class, regardless of overload signature. Findings intentionally point
/// to the hidden base declaration, as Clang's checker does.
fn hiding_nonvirtual_base_method_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let methods = cpp_method_infos(index);
    let aggregates = index
        .aggregates
        .iter()
        .filter(|aggregate| matches!(aggregate.kind.as_str(), "class" | "struct"))
        .filter(|aggregate| !aggregate.qualified_name.is_empty())
        .map(|aggregate| (aggregate.qualified_name.as_str(), aggregate))
        .collect::<HashMap<_, _>>();
    let mut offsets = Vec::new();
    for derived in aggregates.values().filter(|aggregate| aggregate.kind == "class") {
        for base in &derived.bases {
            let base_name = aggregates
                .keys()
                .find(|candidate| **candidate == base || candidate.ends_with(&format!("::{base}")))
                .copied()
                .unwrap_or(base.as_str());
            for method in methods.iter().filter(|method| method.owner == derived.qualified_name) {
                if method_is_virtual(method, &methods, &aggregates, &mut HashSet::new()) {
                    continue;
                }
                offsets.extend(
                    methods
                        .iter()
                        .filter(|candidate| {
                            candidate.owner == base_name
                                && candidate.name == method.name
                                && !candidate.is_defaulted
                                && !method_is_virtual(
                                    candidate,
                                    &methods,
                                    &aggregates,
                                    &mut HashSet::new(),
                                )
                        })
                        .map(|candidate| candidate.offset),
                );
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// When a derived class overrides one overload of a virtual base method, it
/// should override every overload under that name. The legacy checker scopes
/// this to direct bases and reports each omitted base declaration.
fn incomplete_virtual_overload_set_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let methods = cpp_method_infos(index);
    let aggregates = index
        .aggregates
        .iter()
        .filter(|aggregate| matches!(aggregate.kind.as_str(), "class" | "struct"))
        .filter(|aggregate| !aggregate.qualified_name.is_empty())
        .map(|aggregate| (aggregate.qualified_name.as_str(), aggregate))
        .collect::<HashMap<_, _>>();
    let mut offsets = Vec::new();
    for derived in aggregates.values().filter(|aggregate| aggregate.kind == "class") {
        let derived_methods = methods
            .iter()
            .filter(|method| method.owner == derived.qualified_name)
            .collect::<Vec<_>>();
        for base in &derived.bases {
            let base_name = aggregates
                .keys()
                .find(|candidate| **candidate == base || candidate.ends_with(&format!("::{base}")))
                .copied()
                .unwrap_or(base.as_str());
            for name in derived_methods
                .iter()
                .filter(|method| method_is_virtual(method, &methods, &aggregates, &mut HashSet::new()))
                .map(|method| method.name.as_str())
                .collect::<HashSet<_>>()
            {
                let implemented = derived_methods
                    .iter()
                    .filter(|method| method.name == name)
                    .filter(|method| method_is_virtual(method, &methods, &aggregates, &mut HashSet::new()))
                    .map(|method| (method.signature.clone(), method.is_const))
                    .collect::<HashSet<_>>();
                offsets.extend(
                    methods
                        .iter()
                        .filter(|method| method.owner == base_name && method.name == name)
                        .filter(|method| !implemented.contains(&(method.signature.clone(), method.is_const)))
                        .map(|method| method.offset),
                );
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

/// A class with a direct raw-pointer field needs user-declared copy control.
/// Constructors are not ordinary C declarators, so recognize only the narrow
/// copy-control spellings in the record body rather than guessing from calls.
fn raw_pointer_field_without_copy_control_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for record in index
        .aggregates
        .iter()
        .filter(|aggregate| matches!(aggregate.kind.as_str(), "class" | "struct"))
        .filter(|aggregate| !aggregate.qualified_name.is_empty())
    {
        let has_raw_pointer_field = index.declarations.iter().any(|declaration| {
            declaration.in_aggregate
                && declaration.qualification.join("::") == record.qualified_name
                && declaration.declarators.iter().any(|declarator| {
                    declarator.derived.iter().any(|item| matches!(item, D::Pointer))
                        && !declarator
                            .derived
                            .iter()
                            .any(|item| matches!(item, D::Function { .. }))
                })
        });
        if !has_raw_pointer_field {
            continue;
        }
        let Some(class_name) = record.name.as_deref() else {
            continue;
        };
        let tokens = record
            .body
            .as_ref()
            .map(|body| index.tokens_in(body.clone()).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut has_copy_constructor = false;
        let mut has_copy_assignment = false;
        for at in 0..tokens.len().saturating_sub(1) {
            if tokens[at].text == class_name && tokens[at + 1].text == "(" {
                if let Some(close) = matching_parenthesis_in_tokens(&tokens, at + 1) {
                    has_copy_constructor |= copy_control_parameter(&tokens[at + 2..close], class_name);
                }
            }
            if tokens[at].text == "operator"
                && tokens.get(at + 1).is_some_and(|token| token.text == "=")
                && tokens.get(at + 2).is_some_and(|token| token.text == "(")
            {
                if let Some(close) = matching_parenthesis_in_tokens(&tokens, at + 2) {
                    has_copy_assignment |= copy_control_parameter(&tokens[at + 3..close], class_name);
                }
            }
        }
        if !has_copy_constructor && !has_copy_assignment {
            offsets.push(record.range.start);
        }
    }
    offsets
}

/// Mirrors the legacy record-field order check: once a character array has
/// appeared in a record, a subsequent pointer may place sensitive pointer data
/// after a string buffer in memory. The finding is attached to that buffer.
fn sensitive_char_array_before_pointer_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for record in index.aggregates.iter().filter(|aggregate| aggregate.body.is_some()) {
        let mut latest_char_array = None;
        let mut fields = index
            .declarations
            .iter()
            .filter(|declaration| {
                declaration.in_aggregate
                    && declaration.qualification.join("::") == record.qualified_name
            })
            .flat_map(|declaration| {
                declaration
                    .declarators
                    .iter()
                    .map(move |declarator| (declaration, declarator))
            })
            .collect::<Vec<_>>();
        fields.sort_by_key(|(declaration, declarator)| {
            declarator.name_range.as_ref().map_or(declaration.range.start, |range| range.start)
        });
        for (declaration, declarator) in fields {
            let is_array = declarator
                .derived
                .iter()
                .any(|item| matches!(item, D::Array { .. }));
            if is_array && character_array_type(&declaration.type_name) {
                latest_char_array = Some(declaration.range.start);
            }
            if declarator
                .derived
                .iter()
                .any(|item| matches!(item, D::Pointer))
            {
                if let Some(offset) = latest_char_array {
                    offsets.push(offset);
                }
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn character_array_type(type_name: &str) -> bool {
    matches!(
        type_name.split_whitespace().collect::<String>().as_str(),
        "char" | "signedchar" | "unsignedchar" | "wchar_t" | "char8_t" | "char16_t" | "char32_t"
    )
}

fn matching_parenthesis_in_tokens(tokens: &[&uniflow_parser_core::Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.text.as_str() {
            "(" => depth += 1,
            ")" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

fn copy_control_parameter(tokens: &[&uniflow_parser_core::Token], class_name: &str) -> bool {
    tokens.windows(2).any(|pair| {
        pair[0].kind == TokKind::Ident
            && pair[0].text == class_name
            && pair[1].text == "&"
    })
}

fn record_or_base_has_opposite_const_virtual(
    owner: &str,
    method: &CppMethodInfo,
    methods: &[CppMethodInfo],
    aggregates: &HashMap<&str, &uniflow_parser_core::c_declarations::CAggregate>,
    visiting: &mut HashSet<String>,
    remaining: usize,
) -> bool {
    if remaining == 0 || !visiting.insert(owner.to_string()) {
        return false;
    }
    if methods.iter().any(|candidate| {
        candidate.owner == owner
            && candidate.name == method.name
            && candidate.signature == method.signature
            && candidate.is_const != method.is_const
            && method_is_virtual(candidate, methods, aggregates, &mut HashSet::new())
    }) {
        return true;
    }
    let Some(record) = aggregates.get(owner) else {
        return false;
    };
    record.bases.iter().any(|base| {
        let base_name = aggregates
            .keys()
            .find(|candidate| **candidate == base || candidate.ends_with(&format!("::{base}")))
            .copied()
            .unwrap_or(base.as_str());
        record_or_base_has_opposite_const_virtual(
            base_name,
            method,
            methods,
            aggregates,
            visiting,
            remaining - 1,
        )
    })
}

fn default_argument_offset(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Option<usize> {
    let tokens = index.tokens_in(range).collect::<Vec<_>>();
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate() {
        match token.text.as_str() {
            "(" | "[" | "{" | "<" => depth += 1,
            ")" | "]" | "}" | ">" => depth = depth.saturating_sub(1),
            "=" if depth == 0 => return tokens.get(at + 1).map(|token| token.start as usize),
            _ => {}
        }
    }
    None
}

fn unterminated_char_array_offsets(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in index
        .declarations
        .iter()
        .filter(|declaration| !declaration.in_aggregate)
    {
        for declarator in &declaration.declarators {
            if let Some(initializer) = &declarator.initializer {
                analyze_char_array_initializer(
                    index,
                    &declaration.type_name,
                    &declarator.derived,
                    initializer.clone(),
                    &mut offsets,
                    0,
                );
            }
        }
    }
    offsets
}

fn analyze_char_array_initializer(
    index: &CDeclarationIndex,
    type_name: &str,
    derived: &[D],
    initializer: std::ops::Range<usize>,
    offsets: &mut Vec<usize>,
    depth: usize,
) {
    if depth > 32 {
        return;
    }
    if let Some(D::Array { size }) = derived.first() {
        if derived.len() == 1 && type_name.split_whitespace().collect::<Vec<_>>() == ["char"] {
            let size = evaluate_c_constant_integer(
                &index.tokens_in(size.clone()).cloned().collect::<Vec<_>>(),
            );
            let literal = direct_narrow_string_sequence(index, initializer.clone());
            if let (Some(size), Some((offset, length))) = (size, literal) {
                if size >= 0 && size <= length as i128 {
                    offsets.push(offset);
                }
            }
            return;
        }
        if let Some(items) = initializer_list_items(index, initializer) {
            for item in items {
                analyze_char_array_initializer(
                    index,
                    type_name,
                    &derived[1..],
                    item,
                    offsets,
                    depth + 1,
                );
            }
        }
        return;
    }
    if !derived.is_empty() {
        return;
    }
    let aggregate_name = type_name
        .split_whitespace()
        .last()
        .unwrap_or(type_name)
        .trim_start_matches("::");
    let Some(aggregate) = index.aggregates.iter().find(|aggregate| {
        aggregate.name.as_deref() == Some(aggregate_name)
            || aggregate.qualified_name == aggregate_name
    }) else {
        return;
    };
    let Some(body) = &aggregate.body else {
        return;
    };
    let Some(items) = initializer_list_items(index, initializer) else {
        return;
    };
    let fields = index
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.in_aggregate
                && body.start <= declaration.range.start
                && declaration.range.end <= body.end
                && declaration.qualification.join("::") == aggregate.qualified_name
        })
        .flat_map(|declaration| {
            declaration
                .declarators
                .iter()
                .map(move |declarator| (declaration.type_name.as_str(), declarator))
        });
    for ((field_type, field), item) in fields.zip(items) {
        analyze_char_array_initializer(
            index,
            field_type,
            &field.derived,
            item,
            offsets,
            depth + 1,
        );
    }
}

fn initializer_list_items(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Option<Vec<std::ops::Range<usize>>> {
    let tokens = index.tokens_in(range).collect::<Vec<_>>();
    if tokens.first()?.text != "{" || tokens.last()?.text != "}" {
        return None;
    }
    if tokens.len() == 2 {
        return Some(Vec::new());
    }
    let mut depth = 0usize;
    let mut start = 1usize;
    let mut items = Vec::new();
    for at in 1..tokens.len() - 1 {
        match tokens[at].text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            "," if depth == 0 => {
                if start < at {
                    items.push(tokens[start].start as usize..tokens[at - 1].end as usize);
                }
                start = at + 1;
            }
            _ => {}
        }
    }
    if start < tokens.len() - 1 {
        items.push(tokens[start].start as usize..tokens[tokens.len() - 2].end as usize);
    }
    Some(items)
}

fn direct_narrow_string_sequence(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Option<(usize, usize)> {
    let tokens = index.tokens_in(range).collect::<Vec<_>>();
    let first_offset = tokens.first()?.start as usize;
    let mut length = 0usize;
    for token in tokens {
        if token.kind != TokKind::StringLit {
            return None;
        }
        let quote = token.text.find('"')?;
        if quote != 0 {
            return None;
        }
        length += decoded_c_string_length(&token.text[quote + 1..token.text.len() - 1]);
    }
    Some((first_offset, length))
}

fn decoded_c_string_length(content: &str) -> usize {
    let bytes = content.as_bytes();
    let mut length = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        length += 1;
        if bytes[at] != b'\\' || at + 1 >= bytes.len() {
            at += 1;
            continue;
        }
        at += 1;
        match bytes[at] {
            b'x' => {
                at += 1;
                while at < bytes.len() && bytes[at].is_ascii_hexdigit() {
                    at += 1;
                }
            }
            b'0'..=b'7' => {
                let start = at;
                at += 1;
                while at < bytes.len() && at - start < 3 && matches!(bytes[at], b'0'..=b'7') {
                    at += 1;
                }
            }
            b'u' => at = (at + 5).min(bytes.len()),
            b'U' => at = (at + 9).min(bytes.len()),
            _ => at += 1,
        }
    }
    length
}

fn repeated_enumerator_values(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut group_start = 0usize;
    while group_start < index.enumerators.len() {
        let enum_range = index.enumerators[group_start].enum_range.clone();
        let group_end = index.enumerators[group_start..]
            .iter()
            .position(|enumerator| enumerator.enum_range != enum_range)
            .map_or(index.enumerators.len(), |relative| group_start + relative);
        let mut names = HashMap::<String, i128>::new();
        let mut values = HashSet::new();
        let mut previous = None::<i128>;
        for enumerator in &index.enumerators[group_start..group_end] {
            let value = if let Some(initializer) = &enumerator.initializer {
                let mut tokens = index.tokens_in(initializer.clone()).cloned().collect::<Vec<_>>();
                for token in &mut tokens {
                    if let Some(value) = names.get(&token.text) {
                        token.kind = uniflow_parser_core::TokKind::IntLit;
                        token.text = value.to_string();
                    }
                }
                evaluate_c_constant_integer(&tokens)
            } else {
                previous.map_or(Some(0), |value| value.checked_add(1))
            };
            let Some(value) = value else {
                previous = None;
                continue;
            };
            if !values.insert(value) {
                offsets.push(enumerator.range.start);
                break;
            }
            names.insert(enumerator.name.clone(), value);
            previous = Some(value);
        }
        group_start = group_end;
    }
    offsets
}

fn inconsistently_initialized_enums(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut group_start = 0usize;
    while group_start < index.enumerators.len() {
        let enum_range = index.enumerators[group_start].enum_range.clone();
        let group_end = index.enumerators[group_start..]
            .iter()
            .position(|enumerator| enumerator.enum_range != enum_range)
            .map_or(index.enumerators.len(), |relative| group_start + relative);
        let group = &index.enumerators[group_start..group_end];
        let initialized = group
            .iter()
            .filter(|enumerator| enumerator.initializer.is_some())
            .count();
        if initialized != group.len()
            && !(initialized == 1 && group[0].initializer.is_some())
        {
            offsets.push(enum_range.start);
        }
        group_start = group_end;
    }
    offsets
}

fn signed_long_long_aliases(index: &CDeclarationIndex) -> HashSet<String> {
    let mut aliases = HashSet::new();
    loop {
        let before = aliases.len();
        for declaration in &index.declarations {
            if !declaration
                .storage
                .iter()
                .any(|storage| storage == "typedef")
                || !is_signed_long_long(&declaration.type_name, &aliases)
            {
                continue;
            }
            aliases.extend(
                declaration
                    .declarators
                    .iter()
                    .filter(|declarator| declarator.derived.is_empty())
                    .filter_map(|declarator| declarator.name.clone()),
            );
        }
        if aliases.len() == before {
            return aliases;
        }
    }
}

fn is_signed_long_long(type_name: &str, aliases: &HashSet<String>) -> bool {
    if aliases.contains(type_name) {
        return true;
    }
    let words = type_name.split_whitespace().collect::<Vec<_>>();
    !words.contains(&"unsigned")
        && words.iter().filter(|word| **word == "long").count() == 2
        && words
            .iter()
            .all(|word| matches!(*word, "signed" | "long" | "int"))
}

fn plain_char_aliases(index: &CDeclarationIndex) -> HashSet<String> {
    let mut aliases = HashSet::new();
    loop {
        let before = aliases.len();
        for declaration in &index.declarations {
            if !declaration
                .storage
                .iter()
                .any(|storage| storage == "typedef")
                || !is_plain_char(&declaration.type_name, &aliases)
            {
                continue;
            }
            aliases.extend(
                declaration
                    .declarators
                    .iter()
                    .filter(|declarator| declarator.derived.is_empty())
                    .filter_map(|declarator| declarator.name.clone()),
            );
        }
        if aliases.len() == before {
            return aliases;
        }
    }
}

fn is_plain_char(type_name: &str, aliases: &HashSet<String>) -> bool {
    type_name == "char" || aliases.contains(type_name)
}

fn function_pointer_aliases(index: &CDeclarationIndex) -> HashSet<String> {
    let mut aliases = HashSet::new();
    loop {
        let before = aliases.len();
        for declaration in &index.declarations {
            if !declaration
                .storage
                .iter()
                .any(|storage| storage == "typedef")
            {
                continue;
            }
            for declarator in &declaration.declarators {
                let directly_function_pointer = matches!(
                    declarator.derived.as_slice(),
                    [D::Pointer, D::Function { .. }, ..]
                );
                let aliases_function_pointer = declarator.derived.is_empty()
                    && aliases.contains(&declaration.type_name);
                if directly_function_pointer || aliases_function_pointer {
                    if let Some(name) = &declarator.name {
                        aliases.insert(name.clone());
                    }
                }
            }
        }
        if aliases.len() == before {
            return aliases;
        }
    }
}

fn char_type_aliases(index: &CDeclarationIndex) -> HashSet<String> {
    let mut aliases = HashSet::new();
    loop {
        let before = aliases.len();
        for declaration in &index.declarations {
            if !declaration
                .storage
                .iter()
                .any(|storage| storage == "typedef")
                || !is_char_type(&declaration.type_name, &aliases)
            {
                continue;
            }
            aliases.extend(
                declaration
                    .declarators
                    .iter()
                    .filter(|declarator| declarator.derived.is_empty())
                    .filter_map(|declarator| declarator.name.clone()),
            );
        }
        if aliases.len() == before {
            return aliases;
        }
    }
}

fn is_char_type(type_name: &str, aliases: &HashSet<String>) -> bool {
    matches!(type_name, "char" | "signed char" | "unsigned char")
        || aliases.contains(type_name)
}

fn initializer_is_string(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> bool {
    let tokens = index.tokens_in(range).collect::<Vec<_>>();
    let mut start = 0usize;
    let mut end = tokens.len();
    while end >= start + 2 && tokens[start].text == "(" && tokens[end - 1].text == ")" {
        start += 1;
        end -= 1;
    }
    end == start + 1
        && tokens[start].kind == uniflow_parser_core::TokKind::StringLit
        && tokens[start].text.contains('"')
}

fn has_top_level_ellipsis(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> bool {
    let mut depth = 0usize;
    for token in index.tokens_in(range) {
        match token.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            "..." if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

fn direct_parameter_count(
    index: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> usize {
    direct_parameters(index, range).len()
}

fn direct_parameters<'a>(
    index: &'a CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Vec<&'a uniflow_parser_core::c_declarations::CParameter> {
    let candidates = index
        .parameters
        .iter()
        .filter(|parameter| {
            range.start <= parameter.range.start && parameter.range.end <= range.end
        })
        .collect::<Vec<_>>();
    candidates
        .iter()
        .filter(|parameter| {
            !parameter.plain_void
                && !candidates.iter().any(|outer| {
                    outer.range.start <= parameter.range.start
                        && parameter.range.end <= outer.range.end
                        && outer.range != parameter.range
                })
        })
        .copied()
        .collect()
}

fn pointer_type_aliases(index: &CDeclarationIndex) -> HashSet<String> {
    let mut aliases = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for declaration in &index.declarations {
            if !declaration
                .storage
                .iter()
                .any(|storage| storage == "typedef")
            {
                continue;
            }
            for declarator in &declaration.declarators {
                if aliases.contains(&declaration.type_name)
                    || matches!(declarator.derived.first(), Some(D::Pointer))
                {
                    if let Some(name) = &declarator.name {
                        changed |= aliases.insert(name.clone());
                    }
                }
            }
        }
    }
    aliases
}

fn void_type_aliases(index: &CDeclarationIndex) -> HashSet<String> {
    let mut aliases = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for declaration in &index.declarations {
            if !declaration
                .storage
                .iter()
                .any(|storage| storage == "typedef")
                || !(declaration.type_name == "void"
                    || aliases.contains(&declaration.type_name))
            {
                continue;
            }
            for declarator in &declaration.declarators {
                if declarator.derived.is_empty() {
                    if let Some(name) = &declarator.name {
                        changed |= aliases.insert(name.clone());
                    }
                }
            }
        }
    }
    aliases
}

fn valid_main_signature(
    index: &CDeclarationIndex,
    pointer_aliases: &HashSet<String>,
    return_type: &str,
    parameter_range: std::ops::Range<usize>,
) -> bool {
    if !matches!(return_type, "int" | "signed" | "signed int") {
        return false;
    }
    let parameters = direct_parameters(index, parameter_range);
    if parameters.is_empty() {
        return true;
    }
    parameters.len() == 2
        && matches!(parameters[0].type_name.as_str(), "int" | "signed" | "signed int")
        && (pointer_aliases.contains(&parameters[1].type_name)
            || parameters[1]
                .derived
                .iter()
                .any(|derived| matches!(derived, D::Pointer | D::Array { .. })))
}

fn declaration_qualified_name(
    declaration: &CDeclaration,
    declarator: &CDeclarator,
) -> String {
    let explicit = declarator.qualified_name.as_deref().unwrap_or_default();
    if explicit.contains("::")
        || declaration.enclosing_function.is_some()
        || declaration.qualification.is_empty()
    {
        explicit.to_string()
    } else {
        let mut parts = declaration.qualification.clone();
        parts.push(explicit.to_string());
        parts.join("::")
    }
}

fn class_access_at(
    index: &CDeclarationIndex,
    body: std::ops::Range<usize>,
    target: usize,
) -> &'static str {
    let tokens = index.tokens_in(body).collect::<Vec<_>>();
    let mut access = "private";
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate() {
        if token.start as usize >= target {
            break;
        }
        match token.text.as_str() {
            "{" => depth += 1,
            "}" => depth = depth.saturating_sub(1),
            "public" | "protected" | "private"
                if depth == 1
                    && tokens.get(at + 1).is_some_and(|next| next.text == ":") =>
            {
                access = match token.text.as_str() {
                    "public" => "public",
                    "protected" => "protected",
                    _ => "private",
                };
            }
            _ => {}
        }
    }
    access
}

fn non_explicit_single_parameter_constructors(index: &CDeclarationIndex) -> Vec<usize> {
    let tokens = index.tokens();
    let mut offsets = Vec::new();
    for aggregate in index.aggregates.iter().filter(|aggregate| {
        matches!(aggregate.kind.as_str(), "class" | "struct") && aggregate.name.is_some()
    }) {
        let Some(body) = &aggregate.body else {
            continue;
        };
        let name = aggregate.name.as_deref().unwrap_or_default();
        let mut depth = 0usize;
        for at in 0..tokens.len().saturating_sub(1) {
            let token = &tokens[at];
            if (token.start as usize) < body.start || (token.end as usize) > body.end {
                continue;
            }
            match token.text.as_str() {
                "{" => {
                    depth += 1;
                    continue;
                }
                "}" => {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                _ => {}
            }
            if depth != 1
                || token.text != name
                || tokens[at + 1].text != "("
                || at > 0 && tokens[at - 1].text == "~"
            {
                continue;
            }
            let Some(close) = index.matching_token_index(at + 1) else {
                continue;
            };
            let parameter_tokens = &tokens[at + 2..close];
            let parameter_count = if parameter_tokens.is_empty()
                || parameter_tokens.len() == 1 && parameter_tokens[0].text == "void"
            {
                0
            } else {
                let mut nested = 0usize;
                let mut count = 1usize;
                for parameter in parameter_tokens {
                    match parameter.text.as_str() {
                        "(" | "[" | "{" => nested += 1,
                        ")" | "]" | "}" => nested = nested.saturating_sub(1),
                        "," if nested == 0 => count += 1,
                        _ => {}
                    }
                }
                count
            };
            if parameter_count != 1 {
                continue;
            }
            let declaration_start = (0..at)
                .rev()
                .find(|candidate| matches!(tokens[*candidate].text.as_str(), ";" | "{" | "}"))
                .map_or(0, |candidate| candidate + 1);
            if tokens[declaration_start..at]
                .iter()
                .any(|token| token.text == "explicit")
            {
                continue;
            }
            offsets.push(token.start as usize);
        }
    }
    offsets
}

fn non_const_postfix_operator_returns(index: &CDeclarationIndex) -> Vec<usize> {
    let tokens = index.tokens();
    let mut offsets = Vec::new();
    for operator_at in 0..tokens.len().saturating_sub(2) {
        if tokens[operator_at].text != "operator"
            || !matches!(tokens[operator_at + 1].text.as_str(), "++" | "--")
            || tokens[operator_at + 2].text != "("
        {
            continue;
        }
        let Some(close) = index.matching_token_index(operator_at + 2) else {
            continue;
        };
        let parameter_tokens = &tokens[operator_at + 3..close];
        let parameter_count = direct_token_parameter_count(parameter_tokens);
        let containing_class = index.aggregates.iter().find(|aggregate| {
            matches!(aggregate.kind.as_str(), "class" | "struct")
                && aggregate.body.as_ref().is_some_and(|body| {
                    body.start <= tokens[operator_at].start as usize
                        && (tokens[operator_at].end as usize) <= body.end
                })
        });
        let is_member = containing_class.is_some_and(|aggregate| {
            aggregate.body.as_ref().is_some_and(|body| {
                body.start <= tokens[operator_at].start as usize
                    && (tokens[operator_at].end as usize) <= body.end
            })
        });
        let mut after = close + 1;
        while after < tokens.len()
            && !matches!(tokens[after].text.as_str(), ";" | "{")
        {
            after += 1;
        }
        let eligible = is_member && parameter_count == 1
            || !is_member
                && parameter_count == 2
                && tokens.get(after).is_some_and(|token| token.text == "{");
        if !eligible {
            continue;
        }
        let declaration_start = (0..operator_at)
            .rev()
            .find(|candidate| {
                matches!(tokens[*candidate].text.as_str(), ";" | "{" | "}" | ":")
            })
            .map_or(0, |candidate| candidate + 1);
        if tokens[declaration_start..operator_at]
            .iter()
            .any(|token| token.text == "const")
        {
            continue;
        }
        offsets.push(tokens[declaration_start].start as usize);
    }
    offsets
}

fn direct_token_parameter_count(tokens: &[uniflow_parser_core::Token]) -> usize {
    if tokens.is_empty() || tokens.len() == 1 && tokens[0].text == "void" {
        return 0;
    }
    let mut depth = 0usize;
    let mut count = 1usize;
    for token in tokens {
        match token.text.as_str() {
            "(" | "[" | "{" | "<" => depth += 1,
            ")" | "]" | "}" | ">" => depth = depth.saturating_sub(1),
            "," if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

fn ambiguous_multiple_inheritance_members(index: &CDeclarationIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for derived in index
        .aggregates
        .iter()
        .filter(|aggregate| aggregate.kind == "class" && aggregate.bases.len() >= 2)
    {
        let mut seen = HashSet::new();
        let mut ambiguous = false;
        for base_name in &derived.bases {
            let Some(base) = index.aggregates.iter().find(|aggregate| {
                aggregate.name.as_deref() == Some(base_name.as_str())
                    || aggregate.qualified_name == *base_name
                    || aggregate
                        .qualified_name
                        .strip_suffix(base_name)
                        .is_some_and(|prefix| prefix.ends_with("::"))
            }) else {
                continue;
            };
            let member_names = index
                .declarations
                .iter()
                .filter(|declaration| {
                    declaration.in_aggregate
                        && declaration.qualification.join("::") == base.qualified_name
                })
                .flat_map(|declaration| &declaration.declarators)
                .filter_map(|declarator| declarator.name.as_deref())
                .chain(index.functions.iter().filter_map(|function| {
                    function
                        .qualified_name
                        .strip_prefix(&format!("{}::", base.qualified_name))
                        .filter(|tail| !tail.contains("::"))
                }));
            for member in member_names {
                if !seen.insert(member.to_string()) {
                    ambiguous = true;
                }
            }
        }
        if ambiguous {
            offsets.push(derived.range.start);
        }
    }
    offsets
}

fn declaration_context_is_ancestor(
    ancestor_function: Option<usize>,
    ancestor_qualification: &[String],
    descendant_function: Option<usize>,
    descendant_qualification: &[String],
) -> bool {
    (ancestor_function.is_none()
        || ancestor_function.is_some() && ancestor_function == descendant_function)
        && ancestor_qualification.len() <= descendant_qualification.len()
        && ancestor_qualification
            .iter()
            .zip(descendant_qualification)
            .all(|(ancestor, descendant)| ancestor == descendant)
}
