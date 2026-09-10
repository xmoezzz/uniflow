use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uniflow_parser_core::{
    c_declarations::{CDeclarationIndex, DerivedDeclarator as D},
    c_expressions::{CExpressionFact, CExpressionFactKind as K, CExpressionIndex},
    java_syntax::{JavaSyntax, JavaSyntaxKind},
    TokKind, Token,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CExpressionCheck {
    AssignmentOutsideStatement,
    UpdateInExpression,
    SideEffectInSizeof,
    CommaExpression,
    AssignmentInIf,
    AssignmentInCondition,
    FalseStaticAssert,
    DeleteThis,
    VforkCall,
    LogicalNotConstant,
    NonAsciiNarrowString,
    ConstantTrueAssert,
    ConstantFalseAssert,
    ConditionalExpression,
    BinaryInConditional,
    DangerousRegistryAccessMacro,
    AddOrSubtractAssignment,
    LegacyCommaOperator,
    BooleanSwitchCondition,
    GlobalLoopControl,
    FloatingForInitializer,
    NonLocalForInitializer,
    CStyleCast,
    SizeofArrayParameter,
    AddAssignStringOperationResult,
    CtypeSignedCharArgument,
    AbortAfterExitRegistration,
    RelationalCharacterLiteralInCondition,
    StandalonePostfixUpdate,
    IncompatibleEnumComparison,
    EnumValueAssignedToNonEnum,
    EnumCastOutsideDeclaredRange,
    DirectAssignmentInSizeof,
    UncastAllocationCallResult,
    BitwiseBooleanOperand,
    BooleanAddShiftOrUpdate,
    BooleanArithmeticOperand,
    FloatingEqualityEitherOperand,
    FloatingEqualityLeftOperand,
    UnsignedComparisonWithZero,
    MixedSignednessComparison,
    BooleanRelationalComparison,
    IncompleteEnumSwitchWithoutDefault,
    UpdateUsedAsBinaryOrCallOperand,
    RedundantVoidCastOfVoidCall,
    NoOpExplicitConversion,
    PointerIntegerExplicitCast,
    ForcedCStylePointerCast,
    UnsafePointerTypeCast,
    StaticCastBetweenRecordPointers,
    AssignmentOrUpdateInSizeof,
    StringLiteralToSignedOrUnsignedCharStorage,
    SignedOddEvenRepresentationAssumption,
    ConstantAllocationLengthWithoutSizeof,
    LogicalNotIntegerLiteral,
    StringLiteralAssignedToMutableCharPointer,
    MixedNarrowAndWideStringLiteral,
    MisusedFunctionAddress,
    EqualityLoopWithLargeStep,
    FunctionAddressAssignmentWithoutAddressOf,
    PointerParameterAssignment,
    BuiltinLimitMacroInCondition,
    ChainedRelationalOrEquality,
    BitwiseMixedWithoutParentheses,
    ShiftOnSmallInteger,
    EofComparisonOnCharacterInput,
    MultipleUngetSameStream,
    DeclarationBeforeFirstSwitchCase,
    RawAllocationForClass,
    StdFindOnSet,
    ExitHandlerMustReturnNormally,
    DirectTimeArithmetic,
    TooFewPrintfArguments,
    MissingPrintfStarArgument,
    NonConstantPrintfStarArgument,
    ScanfUnboundedString,
    FsetposRequiresFgetposValue,
    InterleavedStreamIoWithoutPositioning,
    AliasedRestrictArguments,
    ReadlinkLengthOutOfBounds,
    FileObjectCopy,
    ErrnoReturnRequiresErrnoT,
    ErrnoResultProtocol,
    WriteToStringLiteral,
    WriteThroughConstStorage,
    SignedCharPromotionAssignment,
    CtypeExplicitSignedCharArgument,
    VariableArrayInvalidSentinelSize,
    NullCharTraitsLengthArgument,
    InvalidPrintfFormatSpecifier,
    UnicodeOutputBufferSizeMismatch,
    UnicodeInputOutputAliasing,
    CaseInsensitiveLocalRedeclaration,
    ConfusingLowerLAndOneNames,
    ConfusingUpperOAndZeroNames,
    VisuallyConfusingVariableNames,
    SignedBitFieldWidthAtMostOne,
    PlainCharArithmeticOperand,
    DoubleToFloatNonliteralAssignment,
    FloatingToIntegerInitialization,
    FloatingToIntegerAssignment,
    IntegerToPlainCharAssignment,
    IntegerArithmeticToFloatingAssignment,
    WiderIntegerTargetFromBinaryExpression,
    NonzeroIntegerExplicitPointerCastAssignment,
    NegatedComparisonIfCondition,
    CIfNonIntegerCondition,
    CppIfNumericNonBooleanCondition,
    CBooleanSwitchCondition,
    CppBooleanSwitchCondition,
    InnerBlockVariableRedefinition,
    PthreadMutexNormalType,
    RecursiveCallInLocalInitializer,
    MixedShiftAndArithmeticVariable,
    NegativeShiftCount,
    ShiftCountExceedsPromotedWidth,
    NonconstantSignedShift,
    PossiblyNegativeSignedToUnsignedAssignment,
    NonconstantIntegerNarrowingAssignment,
    ImplicitIntegerNarrowingMayOverflow,
    ExplicitIntegerNarrowingMayOverflow,
    InconsistentNumericAssignmentType,
    HardcodedCryptoKey,
    WeakOpenSslCrypto,
}

impl CExpressionCheck {
    pub(crate) fn offsets(
        self,
        index: &CExpressionIndex,
        declarations: &CDeclarationIndex,
        syntax: &JavaSyntax,
    ) -> Vec<usize> {
        let init_separators = initializer_separators(index, declarations);
        let mut offsets = Vec::new();
        match self {
            Self::AssignmentOutsideStatement => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Assignment
                            && !init_separators.contains(&fact.offset)
                            && !inside_expression_statement(fact, declarations, syntax, index)
                    })
                    .map(|fact| fact.offset),
            ),
            Self::UpdateInExpression => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Update
                            && (!fact.enclosing_calls.is_empty()
                                || expression_region_has(index, syntax, fact.offset, K::Binary))
                    })
                    .map(|fact| fact.offset),
            ),
            Self::SideEffectInSizeof => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.inside_sizeof
                            && matches!(fact.kind, K::Assignment | K::Update | K::Call)
                    })
                    .map(|fact| fact.offset),
            ),
            Self::CommaExpression => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Comma
                            && !fact.inside_for_header
                            && fact.enclosing_calls.is_empty()
                            && !is_separator_comma(index, declarations, fact.offset)
                    })
                    .map(|fact| fact.offset),
            ),
            Self::AssignmentInIf => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Assignment
                            && (index.inside_control_header(fact.offset, "if")
                                || syntax.nodes.iter().any(|node| {
                                    node.kind == JavaSyntaxKind::If
                                        && node.condition.as_ref().is_some_and(|range| {
                                            range.start <= fact.offset && fact.offset < range.end
                                        })
                                }))
                    })
                    .map(|fact| fact.offset),
            ),
            Self::AssignmentInCondition => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Assignment
                            && index.inside_control_condition(fact.offset)
                    })
                    .map(|fact| fact.offset),
            ),
            Self::FalseStaticAssert => offsets.extend(false_static_assert_offsets(index)),
            Self::DeleteThis => offsets.extend(delete_this_offsets(index)),
            Self::VforkCall => offsets.extend(vfork_call_offsets(index, declarations)),
            Self::LogicalNotConstant => {
                offsets.extend(logical_not_constant_offsets(index, declarations))
            }
            Self::NonAsciiNarrowString => {
                offsets.extend(non_ascii_narrow_string_offsets(index, declarations))
            }
            Self::ConstantTrueAssert => {
                offsets.extend(constant_assert_offsets(index, declarations, true))
            }
            Self::ConstantFalseAssert => {
                offsets.extend(constant_assert_offsets(index, declarations, false))
            }
            Self::ConditionalExpression => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| fact.kind == K::Conditional)
                    .map(|fact| fact.offset),
            ),
            Self::BinaryInConditional => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Binary
                            && expression_region_has(index, syntax, fact.offset, K::Conditional)
                    })
                    .map(|fact| fact.offset),
            ),
            Self::DangerousRegistryAccessMacro => {
                for token in &index.tokens {
                    if token.kind == TokKind::Ident
                        && matches!(token.text.as_str(), "KEY_ALL_ACCESS" | "ALL_ACCESS")
                        && index
                            .nearest_call_name(token.start as usize)
                            .is_some_and(|name| {
                                matches!(
                                    name.as_str(),
                                    "RegOpenKeyEx"
                                        | "RegOpenKeyExA"
                                        | "RegOpenKeyExW"
                                        | "RegCreateKeyEx"
                                        | "RegCreateKeyExA"
                                        | "RegCreateKeyExW"
                                        | "SHRegCreateUSKey"
                                        | "SHRegCreateUSKeyA"
                                        | "SHRegCreateUSKeyW"
                                )
                            })
                    {
                        offsets.push(token.start as usize);
                    }
                }
            }
            Self::AddOrSubtractAssignment => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Assignment
                            && index
                                .token_at(fact.offset)
                                .is_some_and(|token| matches!(token.text.as_str(), "+=" | "-="))
                            && declarations.functions.iter().any(|function| {
                                function.body.start <= fact.offset && fact.offset < function.body.end
                            })
                    })
                    .map(|fact| fact.offset),
            ),
            Self::LegacyCommaOperator => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| fact.kind == K::Comma)
                    .filter(|fact| {
                        declarations.functions.iter().any(|function| {
                            function.body.start <= fact.offset && fact.offset < function.body.end
                        })
                    })
                    // The original RecursiveASTVisitor deliberately did not descend into
                    // declaration statements, including their initializers.
                    .filter(|fact| {
                        !declarations.declarations.iter().any(|declaration| {
                            declaration.range.start <= fact.offset
                                && fact.offset < declaration.range.end
                        })
                    })
                    // TraverseForStmt visited the condition and body, but skipped the
                    // initializer and increment expressions.
                    .filter(|fact| {
                        !fact.inside_for_header
                            || syntax.nodes.iter().any(|node| {
                                node.kind == JavaSyntaxKind::For
                                    && node.condition.as_ref().is_some_and(|range| {
                                        range.start <= fact.offset && fact.offset < range.end
                                    })
                            })
                    })
                    .filter(|fact| !is_call_argument_separator(index, fact.offset))
                    .map(|fact| comma_expression_start(index, syntax, fact.offset)),
            ),
            Self::BooleanSwitchCondition => offsets.extend(
                syntax
                    .nodes
                    .iter()
                    .filter(|node| node.kind == JavaSyntaxKind::Switch)
                    .filter_map(|node| node.condition.as_ref())
                    .filter_map(|range| boolean_expression_offset(index, declarations, range.clone())),
            ),
            Self::GlobalLoopControl => offsets.extend(
                syntax
                    .nodes
                    .iter()
                    .filter(|node| {
                        matches!(
                            node.kind,
                            JavaSyntaxKind::While | JavaSyntaxKind::For | JavaSyntaxKind::Do
                        )
                    })
                    .filter_map(|node| node.condition.as_ref())
                    .filter_map(|range| global_loop_control_offset(index, declarations, range.clone())),
            ),
            Self::FloatingForInitializer | Self::NonLocalForInitializer => {
                for initializer in syntax
                    .nodes
                    .iter()
                    .filter(|node| node.kind == JavaSyntaxKind::For)
                    .filter_map(|node| node.initializer.as_ref())
                {
                    let function_id = declarations.functions.iter().position(|function| {
                        function.body.start <= initializer.start
                            && initializer.end <= function.body.end
                    });
                    if matches!(self, Self::FloatingForInitializer) {
                        offsets.extend(
                            declarations
                                .declarations
                                .iter()
                                .filter(|declaration| {
                                    initializer.start <= declaration.range.start
                                        && declaration.range.start < initializer.end
                                        && is_floating_type(&declaration.type_name)
                                })
                                .map(|declaration| declaration.range.start),
                        );
                    }
                    for assignment in index.facts.iter().filter(|fact| {
                        fact.kind == K::Assignment
                            && initializer.start <= fact.offset
                            && fact.offset < initializer.end
                            && index
                                .token_at(fact.offset)
                                .is_some_and(|token| token.text == "=")
                    }) {
                        let Some(name) = direct_assignment_lhs(index, assignment.offset) else {
                            continue;
                        };
                        let Some((ty, declaration_offset, is_local)) = resolve_variable(
                            declarations,
                            function_id,
                            name,
                            assignment.offset,
                        ) else {
                            continue;
                        };
                        if matches!(self, Self::FloatingForInitializer) && is_floating_type(&ty)
                            || matches!(self, Self::NonLocalForInitializer) && !is_local
                        {
                            offsets.push(declaration_offset);
                        }
                    }
                }
            }
            Self::CStyleCast => offsets.extend(c_style_cast_offsets(index, declarations)),
            Self::SizeofArrayParameter => {
                offsets.extend(sizeof_array_parameter_offsets(index, declarations))
            }
            Self::AddAssignStringOperationResult => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Assignment
                            && index
                                .token_at(fact.offset)
                                .is_some_and(|token| token.text == "+=")
                            && direct_rhs_call(index, fact.offset).is_some_and(|name| {
                                matches!(
                                    name,
                                    "sprintf" | "snprintf" | "read" | "strcpy" | "strcpy_s"
                                )
                            })
                            && declarations.functions.iter().any(|function| {
                                function.body.start <= fact.offset && fact.offset < function.body.end
                            })
                    })
                    .map(|fact| fact.offset),
            ),
            Self::CtypeSignedCharArgument => {
                offsets.extend(ctype_signed_char_argument_offsets(index, declarations))
            }
            Self::AbortAfterExitRegistration => {
                offsets.extend(abort_after_exit_registration_offsets(index, declarations))
            }
            Self::RelationalCharacterLiteralInCondition => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == K::Binary
                            && index.token_at(fact.offset).is_some_and(|token| {
                                matches!(token.text.as_str(), "<" | "<=" | ">" | ">=")
                            })
                            && index.inside_control_condition(fact.offset)
                            && relational_has_direct_character_literal(index, fact.offset)
                    })
                    .map(|fact| fact.offset),
            ),
            Self::StandalonePostfixUpdate => {
                offsets.extend(standalone_postfix_update_offsets(index, syntax))
            }
            Self::IncompatibleEnumComparison => {
                offsets.extend(incompatible_enum_comparison_offsets(index, declarations))
            }
            Self::EnumValueAssignedToNonEnum => {
                offsets.extend(enum_value_assignment_offsets(index, declarations))
            }
            Self::EnumCastOutsideDeclaredRange => {
                offsets.extend(enum_cast_outside_range_offsets(index, declarations))
            }
            Self::DirectAssignmentInSizeof => {
                offsets.extend(direct_assignment_in_sizeof_offsets(index))
            }
            Self::UncastAllocationCallResult => offsets.extend(
                index
                    .facts
                    .iter()
                    .filter(|fact| matches!(fact.kind, K::Assignment | K::Binary))
                    .filter_map(|fact| {
                        matches!(
                            direct_rhs_call(index, fact.offset),
                            Some("malloc" | "aligned_alloc" | "calloc" | "realloc")
                        )
                        .then_some(())?;
                        let operator = token_at_offset(index, fact.offset)?;
                        Some(index.tokens.get(operator + 1)?.start as usize)
                }),
            ),
            Self::BitwiseBooleanOperand => {
                offsets.extend(boolean_binary_offsets(index, declarations, &["&", "|", "^"]))
            }
            Self::BooleanAddShiftOrUpdate => {
                offsets.extend(boolean_binary_offsets(index, declarations, &["+", "-", "<<", ">>"]));
                offsets.extend(boolean_update_offsets(index, declarations));
            }
            Self::BooleanArithmeticOperand => {
                offsets.extend(boolean_binary_offsets(
                    index,
                    declarations,
                    &["+", "-", "*", "/", "%", "<<", ">>"],
                ));
                offsets.extend(boolean_update_offsets(index, declarations));
            }
            Self::FloatingEqualityEitherOperand => {
                offsets.extend(comparison_type_offsets(
                    index,
                    declarations,
                    &["==", "!="],
                    |left, right| {
                        *left == OperandType::Float || *right == OperandType::Float
                    },
                ));
            }
            Self::FloatingEqualityLeftOperand => {
                offsets.extend(comparison_type_offsets(
                    index,
                    declarations,
                    &["==", "!="],
                    |left, _| *left == OperandType::Float,
                ));
            }
            Self::UnsignedComparisonWithZero => {
                offsets.extend(unsigned_zero_comparison_offsets(index, declarations));
            }
            Self::MixedSignednessComparison => {
                offsets.extend(mixed_signedness_comparison_offsets(index, declarations));
            }
            Self::BooleanRelationalComparison => {
                offsets.extend(comparison_type_offsets(
                    index,
                    declarations,
                    &["<", "<=", ">", ">="],
                    |left, right| *left == OperandType::Bool || *right == OperandType::Bool,
                ));
            }
            Self::IncompleteEnumSwitchWithoutDefault => {
                offsets.extend(incomplete_enum_switch_offsets(index, declarations, syntax))
            }
            Self::UpdateUsedAsBinaryOrCallOperand => {
                offsets.extend(update_operand_offsets(index))
            }
            Self::RedundantVoidCastOfVoidCall => {
                offsets.extend(redundant_void_cast_offsets(index, declarations))
            }
            Self::NoOpExplicitConversion => offsets.extend(
                explicit_cast_facts(index, declarations)
                    .into_iter()
                    .filter(|cast| cast.destination == cast.source)
                    .map(|cast| cast.offset),
            ),
            Self::PointerIntegerExplicitCast => offsets.extend(
                explicit_cast_facts(index, declarations)
                    .into_iter()
                    .filter(|cast| {
                        is_pointer_type(&cast.destination) && is_integer_type(&cast.source)
                            || is_pointer_type(&cast.source)
                                && is_integer_type(&cast.destination)
                    })
                    .map(|cast| cast.offset),
            ),
            Self::ForcedCStylePointerCast => offsets.extend(
                explicit_cast_facts(index, declarations)
                    .into_iter()
                    .filter(|cast| {
                        cast.kind == ExplicitCastKind::CStyle
                            && is_pointer_type(&cast.destination)
                            && !is_pointer_type(&cast.source)
                            && !cast.source_is_zero
                    })
                    .map(|cast| cast.offset),
            ),
            Self::UnsafePointerTypeCast => offsets.extend(
                explicit_cast_facts(index, declarations)
                    .into_iter()
                    .filter(|cast| !cast.source_is_constant)
                    .filter(|cast| unsafe_pointer_cast(&cast.destination, &cast.source))
                    .map(|cast| cast.offset),
            ),
            Self::StaticCastBetweenRecordPointers => offsets.extend(
                explicit_cast_facts(index, declarations)
                    .into_iter()
                    .filter(|cast| cast.kind == ExplicitCastKind::Static)
                    .filter(|cast| distinct_record_pointer_types(declarations, &cast.destination, &cast.source))
                    .map(|cast| cast.offset),
            ),
            Self::AssignmentOrUpdateInSizeof => {
                offsets.extend(side_effecting_sizeof_offsets(index))
            }
            Self::StringLiteralToSignedOrUnsignedCharStorage => {
                offsets.extend(explicit_char_string_offsets(index, declarations))
            }
            Self::SignedOddEvenRepresentationAssumption => {
                offsets.extend(signed_odd_even_offsets(index, syntax))
            }
            Self::ConstantAllocationLengthWithoutSizeof => {
                offsets.extend(constant_allocation_length_offsets(index, declarations))
            }
            Self::LogicalNotIntegerLiteral => {
                offsets.extend(logical_not_integer_literal_offsets(index, declarations))
            }
            Self::StringLiteralAssignedToMutableCharPointer => {
                offsets.extend(mutable_char_pointer_string_offsets(index, declarations))
            }
            Self::MixedNarrowAndWideStringLiteral => {
                offsets.extend(mixed_string_literal_offsets(index, declarations, syntax))
            }
            Self::MisusedFunctionAddress => {
                offsets.extend(misused_function_address_offsets(index, declarations, syntax))
            }
            Self::EqualityLoopWithLargeStep => {
                offsets.extend(equality_loop_large_step_offsets(index, syntax))
            }
            Self::FunctionAddressAssignmentWithoutAddressOf => {
                offsets.extend(function_address_assignment_offsets(index, declarations))
            }
            Self::PointerParameterAssignment => {
                offsets.extend(pointer_parameter_assignment_offsets(
                    index,
                    declarations,
                    syntax,
                ))
            }
            Self::BuiltinLimitMacroInCondition => {
                offsets.extend(builtin_limit_macro_condition_offsets(index, syntax))
            }
            Self::ChainedRelationalOrEquality => {
                offsets.extend(chained_comparison_offsets(index, declarations))
            }
            Self::BitwiseMixedWithoutParentheses => {
                offsets.extend(bitwise_mixed_expression_offsets(index, declarations))
            }
            Self::ShiftOnSmallInteger => {
                offsets.extend(shift_on_small_integer_offsets(index, declarations))
            }
            Self::EofComparisonOnCharacterInput => {
                offsets.extend(eof_character_input_comparison_offsets(index, declarations))
            }
            Self::MultipleUngetSameStream => {
                offsets.extend(multiple_unget_same_stream_offsets(index, declarations))
            }
            Self::DeclarationBeforeFirstSwitchCase => {
                offsets.extend(declaration_before_first_switch_case_offsets(
                    declarations,
                    syntax,
                ))
            }
            Self::RawAllocationForClass => {
                offsets.extend(raw_allocation_for_class_offsets(index, declarations))
            }
            Self::StdFindOnSet => offsets.extend(std_find_on_set_offsets(index, declarations)),
            Self::ExitHandlerMustReturnNormally => {
                offsets.extend(exit_handler_abnormal_exit_offsets(index, declarations))
            }
            Self::DirectTimeArithmetic => {
                offsets.extend(direct_time_arithmetic_offsets(index, declarations))
            }
            Self::TooFewPrintfArguments => {
                offsets.extend(too_few_printf_argument_offsets(index))
            }
            Self::MissingPrintfStarArgument => {
                offsets.extend(printf_star_offsets(index, true))
            }
            Self::NonConstantPrintfStarArgument => {
                offsets.extend(printf_star_offsets(index, false))
            }
            Self::ScanfUnboundedString => {
                offsets.extend(scanf_unbounded_string_offsets(index))
            }
            Self::FsetposRequiresFgetposValue => {
                offsets.extend(fsetpos_without_fgetpos_offsets(index, declarations))
            }
            Self::InterleavedStreamIoWithoutPositioning => {
                offsets.extend(interleaved_stream_io_offsets(index, declarations))
            }
            Self::AliasedRestrictArguments => {
                offsets.extend(aliased_restrict_argument_offsets(index, declarations))
            }
            Self::ReadlinkLengthOutOfBounds => {
                offsets.extend(readlink_length_out_of_bounds_offsets(index, declarations))
            }
            Self::FileObjectCopy => {
                offsets.extend(file_object_copy_offsets(index, declarations))
            }
            Self::ErrnoReturnRequiresErrnoT => {
                offsets.extend(errno_return_type_offsets(index, declarations))
            }
            Self::ErrnoResultProtocol => {
                offsets.extend(errno_result_protocol_offsets(index, declarations, syntax))
            }
            Self::WriteToStringLiteral => {
                offsets.extend(const_storage_write_offsets(index, declarations, true))
            }
            Self::WriteThroughConstStorage => {
                offsets.extend(const_storage_write_offsets(index, declarations, false))
            }
            Self::SignedCharPromotionAssignment => {
                offsets.extend(signed_char_promotion_assignment_offsets(index, declarations))
            }
            Self::CtypeExplicitSignedCharArgument => {
                offsets.extend(ctype_explicit_signed_char_argument_offsets(index, declarations))
            }
            Self::VariableArrayInvalidSentinelSize => {
                offsets.extend(variable_array_invalid_sentinel_offsets(index, declarations))
            }
            Self::NullCharTraitsLengthArgument => {
                offsets.extend(null_char_traits_length_offsets(index))
            }
            Self::InvalidPrintfFormatSpecifier => {
                offsets.extend(invalid_printf_format_specifier_offsets(index))
            }
            Self::UnicodeOutputBufferSizeMismatch => {
                offsets.extend(unicode_mapping_offsets(index, true))
            }
            Self::UnicodeInputOutputAliasing => {
                offsets.extend(unicode_mapping_offsets(index, false))
            }
            Self::CaseInsensitiveLocalRedeclaration => {
                offsets.extend(case_insensitive_local_redeclaration_offsets(declarations, syntax))
            }
            Self::ConfusingLowerLAndOneNames => {
                offsets.extend(confusing_same_scope_name_offsets(declarations, syntax, 'l', '1'))
            }
            Self::ConfusingUpperOAndZeroNames => {
                offsets.extend(confusing_same_scope_name_offsets(declarations, syntax, 'O', '0'))
            }
            Self::VisuallyConfusingVariableNames => {
                offsets.extend(visually_confusing_variable_name_offsets(declarations, syntax))
            }
            Self::SignedBitFieldWidthAtMostOne => {
                offsets.extend(signed_bit_field_width_offsets(index, declarations))
            }
            Self::PlainCharArithmeticOperand => {
                offsets.extend(plain_char_arithmetic_operand_offsets(index, declarations))
            }
            Self::DoubleToFloatNonliteralAssignment => {
                offsets.extend(double_to_float_assignment_offsets(index, declarations))
            }
            Self::FloatingToIntegerInitialization => {
                offsets.extend(floating_to_integer_conversion_offsets(index, declarations, true))
            }
            Self::FloatingToIntegerAssignment => {
                offsets.extend(floating_to_integer_conversion_offsets(index, declarations, false))
            }
            Self::IntegerToPlainCharAssignment => {
                offsets.extend(integer_to_plain_char_assignment_offsets(index, declarations))
            }
            Self::IntegerArithmeticToFloatingAssignment => {
                offsets.extend(integer_arithmetic_to_floating_assignment_offsets(index, declarations))
            }
            Self::WiderIntegerTargetFromBinaryExpression => {
                offsets.extend(wider_integer_target_binary_offsets(index, declarations))
            }
            Self::NonzeroIntegerExplicitPointerCastAssignment => {
                offsets.extend(nonzero_integer_pointer_cast_assignment_offsets(index, declarations))
            }
            Self::NegatedComparisonIfCondition => {
                offsets.extend(negated_comparison_if_condition_offsets(index, syntax))
            }
            Self::CIfNonIntegerCondition => {
                offsets.extend(if_condition_type_offsets(index, declarations, syntax, false))
            }
            Self::CppIfNumericNonBooleanCondition => {
                offsets.extend(if_condition_type_offsets(index, declarations, syntax, true))
            }
            Self::CBooleanSwitchCondition => {
                offsets.extend(boolean_switch_type_offsets(index, declarations, syntax, false))
            }
            Self::CppBooleanSwitchCondition => {
                offsets.extend(boolean_switch_type_offsets(index, declarations, syntax, true))
            }
            Self::InnerBlockVariableRedefinition => {
                offsets.extend(inner_block_redefinition_offsets(declarations, syntax))
            }
            Self::PthreadMutexNormalType => {
                offsets.extend(pthread_mutex_normal_type_offsets(index))
            }
            Self::RecursiveCallInLocalInitializer => {
                offsets.extend(recursive_initializer_call_offsets(index, declarations))
            }
            Self::MixedShiftAndArithmeticVariable => {
                offsets.extend(mixed_shift_arithmetic_offsets(index, declarations, syntax))
            }
            Self::NegativeShiftCount => {
                offsets.extend(shift_rule_offsets(index, declarations, ShiftRule::NegativeCount))
            }
            Self::ShiftCountExceedsPromotedWidth => {
                offsets.extend(shift_rule_offsets(index, declarations, ShiftRule::ExceedsWidth))
            }
            Self::NonconstantSignedShift => {
                offsets.extend(shift_rule_offsets(index, declarations, ShiftRule::SignedNonconstant))
            }
            Self::PossiblyNegativeSignedToUnsignedAssignment => {
                offsets.extend(possibly_negative_unsigned_assignment_offsets(index, declarations))
            }
            Self::NonconstantIntegerNarrowingAssignment => {
                offsets.extend(nonconstant_integer_narrowing_offsets(index, declarations))
            }
            Self::ImplicitIntegerNarrowingMayOverflow => {
                offsets.extend(integer_narrowing_range_offsets(index, declarations, false))
            }
            Self::ExplicitIntegerNarrowingMayOverflow => {
                offsets.extend(integer_narrowing_range_offsets(index, declarations, true))
            }
            Self::InconsistentNumericAssignmentType => {
                offsets.extend(inconsistent_numeric_assignment_offsets(index, declarations))
            }
            Self::HardcodedCryptoKey => {
                offsets.extend(hardcoded_crypto_key_offsets(index, declarations, syntax))
            }
            Self::WeakOpenSslCrypto => {
                offsets.extend(weak_openssl_crypto_offsets(index, declarations, syntax))
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

fn hardcoded_crypto_key_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for fact in index.facts.iter().filter(|fact| fact.kind == K::Call) {
        let Some(name_at) = token_index_at_offset(index, fact.offset) else {
            continue;
        };
        let name = index.tokens[name_at].text.as_str();
        let key_argument = match name {
            "DES_set_key" | "AES_set_encrypt_key" | "AES_set_decrypt_key" => 0,
            "EVP_BytesToKey" => 2,
            _ => continue,
        };
        if !is_legacy_direct_call(index, declarations, syntax, name_at) {
            continue;
        }
        let Some(close) = index.matching_token_index(name_at + 1) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let Some((start, end)) = arguments.get(key_argument).copied() else {
            continue;
        };
        if let Some(literal_at) = string_literal_after_paren_casts(index, declarations, start, end) {
            offsets.push(index.tokens[literal_at].start as usize);
        }
    }
    offsets
}

fn weak_openssl_crypto_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    const FUNCTIONS: [&str; 12] = [
        "DES_set_key",
        "DES_set_odd_parity",
        "DES_ecb_encrypt",
        "RC2_encrypt",
        "RC2_set_key",
        "RC4_set_key",
        "MD5_Init",
        "MD5_Update",
        "MD5_Final",
        "SHA1_Init",
        "SHA1_Update",
        "SHA1_Final",
    ];

    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Call)
        .filter_map(|fact| {
            let name_at = token_index_at_offset(index, fact.offset)?;
            FUNCTIONS
                .contains(&index.tokens[name_at].text.as_str())
                .then_some(name_at)
        })
        .filter(|name_at| is_legacy_direct_call(index, declarations, syntax, *name_at))
        .map(|name_at| index.tokens[name_at].start as usize)
        .collect()
}

fn token_index_at_offset(index: &CExpressionIndex, offset: usize) -> Option<usize> {
    index
        .tokens
        .iter()
        .position(|token| token.start as usize == offset)
}

fn is_legacy_direct_call(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    name_at: usize,
) -> bool {
    let Some(name) = index.tokens.get(name_at) else {
        return false;
    };
    if name.kind != TokKind::Ident
        || index.tokens.get(name_at + 1).is_none_or(|token| token.text != "(")
        || index.matching_token_index(name_at + 1).is_none()
    {
        return false;
    }

    let offset = name.start as usize;

    // A function definition header is lexically call-shaped (`name(...)`) but
    // Clang's CallExpr checker never visits it as a call.
    if declarations.functions.iter().any(|function| {
        function.name == name.text
            && function.range.start <= offset
            && offset < function.body.start
    }) {
        return false;
    }

    // Function prototypes/declarators have the same token shape as calls.
    if declarations.declarations.iter().any(|declaration| {
        declaration.declarators.iter().any(|declarator| {
            declarator.name.as_deref() == Some(name.text.as_str())
                && matches!(declarator.derived.first(), Some(D::Function { .. }))
                && declarator.range.start <= offset
                && offset < declarator.range.end
        })
    }) {
        return false;
    }

    // getDirectCallee() is null for function-pointer/functor calls. Exclude a
    // visible non-function object that shadows the target spelling.
    !visible_nonfunction_callee(index, declarations, syntax, name_at)
}

fn visible_nonfunction_callee(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    name_at: usize,
) -> bool {
    let name = index.tokens[name_at].text.as_str();
    let offset = index.tokens[name_at].start as usize;
    let function_id = declarations.functions.iter().position(|function| {
        function.body.start <= offset && offset < function.body.end
    });
    let call_scope = c_lexical_scope(syntax, offset);

    let local_shadow = declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.enclosing_function == function_id)
        .filter(|declaration| declaration.range.start <= offset)
        .filter(|declaration| {
            let scope = c_lexical_scope(syntax, declaration.range.start);
            scope.start <= call_scope.start && call_scope.end <= scope.end
        })
        .flat_map(|declaration| &declaration.declarators)
        .filter(|declarator| declarator.name.as_deref() == Some(name))
        .max_by_key(|declarator| declarator.range.start);
    if local_shadow.is_some_and(|declarator| {
        !matches!(declarator.derived.first(), Some(D::Function { .. }))
    }) {
        return true;
    }

    if let Some(function_id) = function_id {
        let function = &declarations.functions[function_id];
        if declarations.parameters.iter().any(|parameter| {
            function.parameters.start <= parameter.range.start
                && parameter.range.end <= function.parameters.end
                && parameter.name.as_deref() == Some(name)
                && !matches!(parameter.derived.first(), Some(D::Function { .. }))
        }) {
            return true;
        }
    }

    declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.enclosing_function.is_none())
        .filter(|declaration| declaration.range.start <= offset)
        .flat_map(|declaration| &declaration.declarators)
        .filter(|declarator| declarator.name.as_deref() == Some(name))
        .max_by_key(|declarator| declarator.range.start)
        .is_some_and(|declarator| {
            !matches!(declarator.derived.first(), Some(D::Function { .. }))
        })
}

fn string_literal_after_paren_casts(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    mut start: usize,
    mut end: usize,
) -> Option<usize> {
    let known_names = declarations
        .aggregates
        .iter()
        .filter_map(|aggregate| aggregate.name.as_deref())
        .chain(
            declarations
                .declarations
                .iter()
                .filter(|declaration| declaration.storage.iter().any(|item| item == "typedef"))
                .flat_map(|declaration| &declaration.declarators)
                .filter_map(|declarator| declarator.name.as_deref()),
        )
        .collect::<HashSet<_>>();

    loop {
        (start, end) = trim_outer_group(index, start, end);
        if start >= end {
            return None;
        }

        // C-style cast: `(type) expression`.
        if index.tokens[start].text == "(" {
            if let Some(close) = index.matching_token_index(start) {
                if close + 1 < end
                    && cast_destination_type(&index.tokens[start + 1..close], &known_names).is_some()
                {
                    start = close + 1;
                    continue;
                }
            }
        }

        // C++ named casts are CastExpr nodes too and are stripped by
        // IgnoreParenCasts(). Accept exactly one cast operand here.
        if matches!(
            index.tokens[start].text.as_str(),
            "static_cast" | "dynamic_cast" | "reinterpret_cast" | "const_cast"
        ) && index.tokens.get(start + 1).is_some_and(|token| token.text == "<")
        {
            let Some(type_end) = (start + 2..end).find(|at| index.tokens[*at].text == ">") else {
                return None;
            };
            if cast_destination_type(&index.tokens[start + 2..type_end], &known_names).is_none()
                || index.tokens.get(type_end + 1).is_none_or(|token| token.text != "(")
            {
                return None;
            }
            let Some(close) = index.matching_token_index(type_end + 1) else {
                return None;
            };
            if close + 1 != end {
                return None;
            }
            start = type_end + 2;
            end = close;
            continue;
        }

        return (end == start + 1 && index.tokens[start].kind == TokKind::StringLit)
            .then_some(start);
    }
}

fn inconsistent_numeric_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        let target = canonical_type_text(&declaration.type_name);
        if !is_numeric_assignment_type(&target) {
            continue;
        }
        for initializer in declaration
            .declarators
            .iter()
            .filter_map(|declarator| declarator.initializer.as_ref())
        {
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if numeric_assignment_is_invalid(index, declarations, &target, start, end)
                && !expression_is_direct_integer_zero_after_casts(index, start, end)
            {
                offsets.push(initializer.start);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at)) else {
            continue;
        };
        let Some(target) = exact_operand_type(index, declarations, left)
            .map(|ty| canonical_type_text(&ty))
            .filter(|ty| is_numeric_assignment_type(ty))
        else {
            continue;
        };
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        if numeric_assignment_is_invalid(index, declarations, &target, operator + 1, end)
            && !expression_is_direct_integer_zero_after_casts(index, operator + 1, end)
        {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn numeric_assignment_is_invalid(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    target: &str,
    start: usize,
    end: usize,
) -> bool {
    let Some(source) = expression_numeric_type(index, declarations, start, end) else {
        return false;
    };
    if target == source {
        return false;
    }
    let target_integer = is_integral_or_enum_type(target);
    let source_integer = is_integral_or_enum_type(&source);
    let target_floating = is_floating_type(target);
    let source_floating = is_floating_type(&source);
    if target_integer != source_integer || target_floating != source_floating {
        return true;
    }
    if target_integer && source_integer {
        return evaluate_c_constant_integer(&index.tokens[start..end])
            .is_some_and(|value| value > integer_max_value(target));
    }
    false
}

fn is_numeric_assignment_type(ty: &str) -> bool {
    is_integral_or_enum_type(ty) || is_floating_type(ty)
}

fn integer_max_value(ty: &str) -> i128 {
    let width = integer_storage_width(ty).unwrap_or(32);
    if ty.starts_with("unsigned") {
        ((1u128 << width) - 1) as i128
    } else {
        (1i128 << (width - 1)) - 1
    }
}

fn integer_narrowing_range_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    explicit: bool,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    if explicit {
        let casts = explicit_cast_facts(index, declarations);
        for (start, end) in assignment_or_initializer_value_ranges(index, declarations) {
            let (root, _) = trim_outer_group(index, start, end);
            let Some(cast) = casts.iter().find(|cast| cast.offset == index.tokens[root].start as usize)
            else {
                continue;
            };
            let (Some(target_width), Some(source_width)) = (
                integer_storage_width(&cast.destination),
                integer_storage_width(&canonical_type_text(&cast.source)),
            ) else {
                continue;
            };
            if target_width >= source_width {
                continue;
            }
            let value = explicit_cast_source_range(index, root, end)
                .and_then(|(source_start, source_end)| {
                    evaluate_c_constant_integer(&index.tokens[source_start..source_end])
                });
            if value.is_none_or(|value| !integer_value_fits(&cast.destination, value)) {
                offsets.push(
                    explicit_cast_source_range(index, root, end)
                        .map_or(cast.offset, |(source_start, _)| index.tokens[source_start].start as usize),
                );
            }
        }
        return offsets;
    }
    for declaration in &declarations.declarations {
        let Some(target) = integer_assignment_type(&declaration.type_name) else {
            continue;
        };
        for initializer in declaration
            .declarators
            .iter()
            .filter_map(|declarator| declarator.initializer.as_ref())
        {
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if expression_starts_with_explicit_cast(index, start, end) {
                continue;
            }
            if integer_narrowing_value_may_overflow(index, declarations, &target, start, end) {
                offsets.push(initializer.start);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at)) else {
            continue;
        };
        let Some(target) = exact_operand_type(index, declarations, left)
            .and_then(|ty| integer_assignment_type(&ty))
        else {
            continue;
        };
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        if !expression_starts_with_explicit_cast(index, operator + 1, end)
            && integer_narrowing_value_may_overflow(
                index,
                declarations,
                &target,
                operator + 1,
                end,
            )
        {
            offsets.push(index.tokens[operator + 1].start as usize);
        }
    }
    offsets
}

fn assignment_or_initializer_value_ranges(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<(usize, usize)> {
    let mut ranges = declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter_map(|declarator| declarator.initializer.as_ref())
        .filter_map(|range| token_range_for_source_range(index, range))
        .collect::<Vec<_>>();
    let initializer_assignments = initializer_separators(index, declarations);
    ranges.extend(index.facts.iter().filter_map(|fact| {
        (fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset))
            .then_some(())?;
        let operator = token_at_offset(index, fact.offset)?;
        (index.tokens[operator].text == "=").then_some((
            operator + 1,
            direct_assignment_value_end(index, operator + 1, usize::MAX),
        ))
    }));
    ranges
}

fn explicit_cast_source_range(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    if index.tokens.get(start)?.text == "(" {
        let close = index.matching_token_index(start)?;
        return (close + 1 < end).then_some(trim_outer_group(index, close + 1, end));
    }
    None
}

fn expression_starts_with_explicit_cast(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    index.tokens.get(start).is_some_and(|token| token.text == "(")
        && index
            .matching_token_index(start)
            .is_some_and(|close| close < end - 1 && index.tokens[start + 1..close].iter().all(|token| {
                is_builtin_type_word(&token.text)
                    || matches!(token.text.as_str(), "const" | "volatile" | "*" | "&")
            }))
}

fn integer_assignment_type(ty: &str) -> Option<String> {
    let canonical = canonical_type_text(ty);
    integer_storage_width(&canonical).map(|_| canonical)
}

fn integer_narrowing_value_may_overflow(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    target: &str,
    start: usize,
    end: usize,
) -> bool {
    let Some(source) = expression_numeric_type(index, declarations, start, end) else {
        return false;
    };
    let (Some(target_width), Some(source_width)) = (
        integer_storage_width(target),
        integer_storage_width(&source),
    ) else {
        return false;
    };
    target_width < source_width
        && evaluate_c_constant_integer(&index.tokens[start..end])
            .is_none_or(|value| !integer_value_fits(target, value))
}

fn integer_value_fits(target: &str, value: i128) -> bool {
    let Some(width) = integer_storage_width(target) else {
        return false;
    };
    if target.starts_with("unsigned") {
        value >= 0 && (value as u128) <= (1u128 << width).saturating_sub(1)
    } else {
        let limit = 1i128 << (width - 1);
        -limit <= value && value < limit
    }
}

fn nonconstant_integer_narrowing_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        let Some(target_width) = integer_storage_width(&canonical_type_text(&declaration.type_name)) else {
            continue;
        };
        for initializer in declaration
            .declarators
            .iter()
            .filter_map(|declarator| declarator.initializer.as_ref())
        {
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if evaluate_c_constant_integer(&index.tokens[start..end]).is_some() {
                continue;
            }
            if expression_numeric_type(index, declarations, start, end)
                .as_deref()
                .and_then(integer_storage_width)
                .is_some_and(|source_width| target_width < source_width)
            {
                offsets.push(initializer.start);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at)) else {
            continue;
        };
        let Some(target_width) = exact_operand_type(index, declarations, left)
            .map(|ty| canonical_type_text(&ty))
            .as_deref()
            .and_then(integer_storage_width)
        else {
            continue;
        };
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        if evaluate_c_constant_integer(&index.tokens[operator + 1..end]).is_some() {
            continue;
        }
        if expression_numeric_type(index, declarations, operator + 1, end)
            .as_deref()
            .and_then(integer_storage_width)
            .is_some_and(|source_width| target_width < source_width)
        {
            offsets.push(index.tokens[operator + 1].start as usize);
        }
    }
    offsets
}

fn integer_storage_width(ty: &str) -> Option<u8> {
    match ty {
        "bool" => Some(1),
        "char" | "signed char" | "unsigned char" => Some(8),
        "short" | "unsigned short" => Some(16),
        "int" | "unsigned int" => Some(32),
        "long" | "unsigned long" | "long long" | "unsigned long long" => Some(64),
        ty if ty.starts_with("enum:") => Some(32),
        _ => None,
    }
}

fn possibly_negative_unsigned_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let initializer_assignments = initializer_separators(index, declarations);
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset))
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            (index.tokens[operator].text == "=").then_some(())?;
            let left = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at))?;
            let target = exact_operand_type(index, declarations, left)
                .map(|ty| canonical_type_text(&ty))?;
            matches!(target.as_str(), "unsigned char" | "unsigned short" | "unsigned int" | "unsigned long" | "unsigned long long")
                .then_some(())?;
            let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
            let source = expression_numeric_type(index, declarations, operator + 1, end)?;
            is_signed_integer_type(&source).then_some(())?;
            evaluate_c_constant_integer(&index.tokens[operator + 1..end])
                .is_none_or(|value| value < 0)
                .then_some(fact.offset)
        })
        .collect()
}

#[derive(Clone, Copy)]
enum ShiftRule {
    NegativeCount,
    ExceedsWidth,
    SignedNonconstant,
}

fn shift_rule_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    rule: ShiftRule,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for fact in index.facts.iter().filter(|fact| fact.kind == K::Binary) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if !matches!(index.tokens[operator].text.as_str(), "<<" | ">>") {
            continue;
        }
        let precedence = binary_precedence(index.tokens[operator].text.as_str())
            .map_or(0, |(precedence, _)| precedence);
        let (lower, upper) = index
            .smallest_group(fact.offset)
            .map_or((0, index.tokens.len()), |(open, close)| (open + 1, close));
        let left_start = left_operand_start(index, operator, lower, precedence);
        let right_end = right_operand_end(index, operator, upper, precedence);
        let right_value = evaluate_c_constant_integer(&index.tokens[operator + 1..right_end]);
        let matched = match rule {
            ShiftRule::NegativeCount => right_value.is_some_and(|value| value < 0),
            ShiftRule::ExceedsWidth => {
                let width = expression_numeric_type(index, declarations, left_start, operator)
                    .as_deref()
                    .and_then(promoted_integer_width);
                width.zip(right_value)
                    .is_some_and(|(width, count)| count >= 0 && count as u128 >= width as u128)
            }
            ShiftRule::SignedNonconstant => {
                expression_numeric_type(index, declarations, left_start, operator)
                    .as_deref()
                    .is_some_and(is_signed_integer_type)
                    && evaluate_c_constant_integer(&index.tokens[left_start..operator]).is_none()
            }
        };
        if matched {
            offsets.push(match rule {
                ShiftRule::NegativeCount => index.tokens[operator + 1].start as usize,
                ShiftRule::ExceedsWidth | ShiftRule::SignedNonconstant => fact.offset,
            });
        }
    }
    offsets
}

fn promoted_integer_width(ty: &str) -> Option<u8> {
    match ty {
        "bool" | "char" | "signed char" | "unsigned char" | "short" | "unsigned short"
        | "int" | "unsigned int" => Some(32),
        "long" | "unsigned long" | "long long" | "unsigned long long" => Some(64),
        ty if ty.starts_with("enum:") => Some(32),
        _ => None,
    }
}

fn is_signed_integer_type(ty: &str) -> bool {
    matches!(ty, "char" | "signed char" | "short" | "int" | "long" | "long long")
        || ty.starts_with("enum:")
}

fn mixed_shift_arithmetic_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut ignored = HashSet::new();
    let mut offsets = Vec::new();
    for node in syntax.nodes.iter().filter(|node| node.kind == JavaSyntaxKind::Other) {
        let mut shifted = HashMap::new();
        let mut arithmetic = HashMap::new();
        for fact in index.facts.iter().filter(|fact| {
            node.range.start <= fact.offset && fact.offset < node.range.end
        }) {
            let Some(operator) = token_at_offset(index, fact.offset) else {
                continue;
            };
            let text = index.tokens[operator].text.as_str();
            let left = operator
                .checked_sub(1)
                .and_then(|at| unwrap_left_operand(index, at));
            let right = unwrap_right_operand(index, operator + 1);
            if matches!(text, "<<" | ">>" | "<<=" | ">>=") {
                if let Some((identity, offset)) =
                    left.and_then(|at| variable_identity_at(index, declarations, at))
                {
                    shifted.entry(identity).or_insert(offset);
                }
            }
            if matches!(text, "+" | "-" | "*" | "/" | "%") {
                for operand in [left, right].into_iter().flatten() {
                    if let Some((identity, offset)) =
                        variable_identity_at(index, declarations, operand)
                    {
                        arithmetic.entry(identity).or_insert(offset);
                    }
                }
            } else if matches!(text, "+=" | "-=" | "*=" | "/=" | "%=") {
                if let Some((identity, offset)) =
                    left.and_then(|at| variable_identity_at(index, declarations, at))
                {
                    arithmetic.entry(identity).or_insert(offset);
                }
            }
        }
        for identity in shifted.keys().filter(|identity| arithmetic.contains_key(*identity)) {
            if ignored.insert(identity.clone()) {
                offsets.push(
                    shifted[identity]
                        .min(arithmetic[identity]),
                );
            }
        }
    }
    offsets
}

fn variable_identity_at(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    at: usize,
) -> Option<((String, usize), usize)> {
    let token = index.tokens.get(at)?;
    (token.kind == TokKind::Ident).then_some(())?;
    let function = declarations.functions.iter().position(|function| {
        function.body.start <= token.start as usize && token.end as usize <= function.body.end
    });
    let (_, declaration, _) = resolve_variable(
        declarations,
        function,
        token.text.as_str(),
        token.start as usize,
    )?;
    Some(((token.text.clone(), declaration), token.start as usize))
}

fn recursive_initializer_call_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.enclosing_function.is_some())
    {
        let function = &declarations.functions[declaration.enclosing_function.expect("filtered")];
        for initializer in declaration
            .declarators
            .iter()
            .filter_map(|declarator| declarator.initializer.as_ref())
        {
            offsets.extend(index.facts.iter().filter_map(|fact| {
                (fact.kind == K::Call
                    && initializer.start <= fact.offset
                    && fact.offset < initializer.end
                    && token_at_offset(index, fact.offset)
                        .is_some_and(|at| index.tokens[at].text == function.name))
                    .then_some(fact.offset)
            }));
        }
    }
    offsets
}

fn pthread_mutex_normal_type_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        if index.tokens[name_at].text != "pthread_mutexattr_settype"
            || name_at > 0 && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->" | "::")
        {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let Some((start, end)) = arguments.get(1).copied() else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if end == start + 1 && index.tokens[start].text == "PTHREAD_MUTEX_NORMAL" {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn inner_block_redefinition_offsets(
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let variables = declarations
        .declarations
        .iter()
        .filter_map(|declaration| {
            let function = declaration.enclosing_function?;
            Some(declaration.declarators.iter().filter_map(move |declarator| {
                if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                    return None;
                }
                Some((
                    declarator.name.as_deref()?,
                    declaration.range.start,
                    function,
                    c_lexical_scope(syntax, declarator.range.start),
                ))
            }))
        })
        .flatten()
        .collect::<Vec<_>>();
    variables
        .iter()
        .filter(|(name, offset, function, scope)| {
            variables.iter().any(|(outer_name, outer_offset, outer_function, outer_scope)| {
                outer_name == name
                    && outer_offset < offset
                    && outer_function == function
                    && outer_scope.start < scope.start
                    && scope.end < outer_scope.end
            })
        })
        .map(|(_, offset, _, _)| *offset)
        .collect()
}

fn boolean_switch_type_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    cpp: bool,
) -> Vec<usize> {
    syntax
        .nodes
        .iter()
        .filter(|node| node.kind == JavaSyntaxKind::Switch)
        .filter_map(|node| {
            let condition = node.condition.as_ref()?;
            if let Some(offset) = boolean_expression_offset(index, declarations, condition.clone()) {
                return Some(offset);
            }
            if !cpp {
                return None;
            }
            let (start, end) = token_range_for_source_range(index, condition)?;
            let (start, end) = trim_outer_group(index, start, end);
            (effective_condition_type(index, declarations, start, end).as_deref() == Some("bool"))
                .then_some(index.tokens[start].start as usize)
        })
        .collect()
}

fn if_condition_type_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    cpp: bool,
) -> Vec<usize> {
    syntax
        .nodes
        .iter()
        .filter(|node| node.kind == JavaSyntaxKind::If)
        .filter_map(|node| {
            let condition = node.condition.as_ref()?;
            let (start, end) = token_range_for_source_range(index, condition)?;
            let (start, end) = trim_outer_group(index, start, end);
            let ty = effective_condition_type(index, declarations, start, end)?;
            let invalid = if cpp {
                ty != "bool"
                    && (is_integer_type(&ty)
                        || ty.starts_with("enum:")
                        || matches!(ty.as_str(), "float" | "double" | "long double"))
            } else {
                !is_integer_type(&ty) || ty.starts_with("enum:")
            };
            invalid.then_some(index.tokens[start].start as usize)
        })
        .collect()
}

fn effective_condition_type(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    start: usize,
    end: usize,
) -> Option<String> {
    let (start, end) = trim_outer_group(index, start, end);
    if start >= end {
        return None;
    }
    if index.tokens[start].text == "!" {
        return Some("bool".to_string());
    }
    if root_operator(
        index,
        start,
        end,
        &["==", "!=", "<", "<=", ">", ">=", "&&", "||"],
    )
    .is_some()
    {
        return Some("bool".to_string());
    }
    if end == start + 1
        && index.tokens[start].kind == TokKind::Ident
        && operand_has_declared_enum_type(index, declarations, start)
    {
        return Some("enum:<declared>".to_string());
    }
    expression_numeric_type(index, declarations, start, end).or_else(|| {
        (end == start + 1)
            .then(|| exact_operand_type(index, declarations, start))
            .flatten()
            .map(|ty| canonical_type_text(&ty))
    })
}

fn operand_has_declared_enum_type(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    at: usize,
) -> bool {
    let token = &index.tokens[at];
    declarations.parameters.iter().any(|parameter| {
        parameter.name.as_deref() == Some(token.text.as_str())
            && parameter.range.start <= token.start as usize
            && parameter.type_name.split_whitespace().next() == Some("enum")
    }) || declarations.declarations.iter().any(|declaration| {
        declaration.range.start <= token.start as usize
            && declaration.type_name.split_whitespace().next() == Some("enum")
            && declaration
                .declarators
                .iter()
                .any(|declarator| declarator.name.as_deref() == Some(token.text.as_str()))
    })
}

fn negated_comparison_if_condition_offsets(
    index: &CExpressionIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    syntax
        .nodes
        .iter()
        .filter(|node| node.kind == JavaSyntaxKind::If)
        .filter_map(|node| {
            let condition = node.condition.as_ref()?;
            let (start, end) = token_range_for_source_range(index, condition)?;
            let (start, end) = trim_outer_group(index, start, end);
            (index.tokens.get(start)?.text == "!").then_some(())?;
            (index.tokens.get(start + 1)?.text == "("
                && index.matching_token_index(start + 1) == Some(end - 1))
                .then_some(())?;
            let (operand_start, operand_end) = trim_outer_group(index, start + 1, end);
            root_operator(
                index,
                operand_start,
                operand_end,
                &["==", "!=", "<", "<=", ">", ">="],
            )?;
            Some(index.tokens[start].start as usize)
        })
        .collect()
}

fn nonzero_integer_pointer_cast_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let casts = explicit_cast_facts(index, declarations);
    let initializer_assignments = initializer_separators(index, declarations);
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset))
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            (index.tokens[operator].text == "=").then_some(())?;
            let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
            let (start, end) = trim_outer_group(index, operator + 1, end);
            casts
                .iter()
                .any(|cast| {
                    cast.offset == index.tokens[start].start as usize
                        && cast.offset < index.tokens[end.saturating_sub(1)].end as usize
                        && is_pointer_type(&cast.destination)
                        && is_integer_type(&canonical_type_text(&cast.source))
                        && !cast.source_is_zero
                })
                .then_some(fact.offset)
        })
        .collect()
}

fn wider_integer_target_binary_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        let Some(target_rank) = c_integer_rank(&canonical_type_text(&declaration.type_name)) else {
            continue;
        };
        for declarator in &declaration.declarators {
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if integral_binary_expression_rank(index, declarations, start, end)
                .is_some_and(|source_rank| target_rank > source_rank)
            {
                offsets.push(initializer.start);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at)) else {
            continue;
        };
        let Some(target_rank) = exact_operand_type(index, declarations, left)
            .and_then(|ty| c_integer_rank(&canonical_type_text(&ty)))
        else {
            continue;
        };
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        if integral_binary_expression_rank(index, declarations, operator + 1, end)
            .is_some_and(|source_rank| target_rank > source_rank)
        {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn integral_binary_expression_rank(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    start: usize,
    end: usize,
) -> Option<u8> {
    let (start, end) = trim_outer_group(index, start, end);
    const BINARY_OPERATORS: &[&str] = &[
        "+", "-", "*", "/", "%", "<<", ">>", "<", "<=", ">", ">=", "==", "!=",
        "&", "^", "|", "&&", "||",
    ];
    let mut depth = 0usize;
    let mut binary = false;
    for at in start..end {
        match index.tokens[at].text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            operator if depth == 0 && BINARY_OPERATORS.contains(&operator) => binary = true,
            _ => {}
        }
    }
    if !binary {
        return None;
    }
    let mut rank = 3;
    let mut saw_integer = false;
    for at in start..end {
        let Some(ty) = exact_operand_type(index, declarations, at)
            .map(|ty| canonical_type_text(&ty))
        else {
            continue;
        };
        let Some(operand_rank) = c_integer_rank(&ty) else {
            if matches!(ty.as_str(), "float" | "double" | "long double") || ty.ends_with('*') {
                return None;
            }
            continue;
        };
        rank = rank.max(operand_rank);
        saw_integer = true;
    }
    saw_integer.then_some(rank)
}

fn c_integer_rank(ty: &str) -> Option<u8> {
    match ty {
        "bool" => Some(1),
        "char" | "signed char" | "unsigned char" => Some(2),
        "short" | "unsigned short" => Some(2),
        "int" | "unsigned int" => Some(3),
        "long" | "unsigned long" => Some(4),
        "long long" | "unsigned long long" => Some(5),
        ty if ty.starts_with("enum:") => Some(3),
        _ => None,
    }
}

fn integer_to_plain_char_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        if canonical_type_text(&declaration.type_name) != "char" {
            continue;
        }
        for declarator in &declaration.declarators {
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            let source = expression_numeric_type(index, declarations, start, end);
            if source.as_deref().is_some_and(is_integral_or_enum_type)
                && source.as_deref() != Some("char")
                && !expression_is_direct_integer_zero_after_casts(index, start, end)
            {
                offsets.push(initializer.start);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at)) else {
            continue;
        };
        if exact_operand_type(index, declarations, left)
            .is_none_or(|ty| canonical_type_text(&ty) != "char")
        {
            continue;
        }
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        let source = expression_numeric_type(index, declarations, operator + 1, end);
        if source.as_deref().is_some_and(is_integral_or_enum_type)
            && source.as_deref() != Some("char")
            && !expression_is_direct_integer_zero_after_casts(index, operator + 1, end)
        {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn integer_arithmetic_to_floating_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        if !matches!(canonical_type_text(&declaration.type_name).as_str(), "float" | "double" | "long double") {
            continue;
        }
        for declarator in &declaration.declarators {
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if expression_is_integral_arithmetic(index, declarations, start, end) {
                offsets.push(initializer.start);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at)) else {
            continue;
        };
        if exact_operand_type(index, declarations, left).is_none_or(|ty| {
            !matches!(canonical_type_text(&ty).as_str(), "float" | "double" | "long double")
        }) {
            continue;
        }
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        if expression_is_integral_arithmetic(index, declarations, operator + 1, end) {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn expression_is_integral_arithmetic(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    start: usize,
    end: usize,
) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    root_operator(index, start, end, &["+", "-", "*", "/", "%"]).is_some()
        && expression_numeric_type(index, declarations, start, end)
            .as_deref()
            .is_some_and(is_integral_or_enum_type)
}

fn expression_is_direct_integer_zero_after_casts(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> bool {
    let (mut start, end) = trim_outer_group(index, start, end);
    while start < end && index.tokens[start].text == "(" {
        let Some(close) = index.matching_token_index(start) else {
            break;
        };
        if close >= end - 1
            || !index.tokens[start + 1..close]
                .iter()
                .all(|token| is_builtin_type_word(&token.text) || matches!(token.text.as_str(), "const" | "volatile" | "*" | "&"))
        {
            break;
        }
        start = close + 1;
    }
    let (start, end) = trim_outer_group(index, start, end);
    end == start + 1 && token_integer_value(&index.tokens[start]) == Some(0)
}

fn is_integral_or_enum_type(ty: &str) -> bool {
    is_integer_type(ty) || ty.starts_with("enum:")
}

fn floating_to_integer_conversion_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    initialization: bool,
) -> Vec<usize> {
    if initialization {
        return declarations
            .declarations
            .iter()
            .filter(|declaration| is_integer_type(&canonical_type_text(&declaration.type_name)))
            .filter(|declaration| {
                declaration.declarators.iter().any(|declarator| {
                    let Some(initializer) = &declarator.initializer else {
                        return false;
                    };
                    token_range_for_source_range(index, initializer)
                        .and_then(|(start, end)| {
                            expression_numeric_type(index, declarations, start, end)
                        })
                        .is_some_and(|ty| matches!(ty.as_str(), "float" | "double" | "long double"))
                })
            })
            .map(|declaration| declaration.range.start)
            .collect();
    }
    let initializer_assignments = initializer_separators(index, declarations);
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset))
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            (index.tokens[operator].text == "=").then_some(())?;
            let left = operator.checked_sub(1).and_then(|at| unwrap_left_operand(index, at))?;
            let target = exact_operand_type(index, declarations, left)?;
            is_integer_type(&canonical_type_text(&target)).then_some(())?;
            let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
            expression_numeric_type(index, declarations, operator + 1, end)
                .is_some_and(|ty| matches!(ty.as_str(), "float" | "double" | "long double"))
                .then_some(fact.offset)
        })
        .collect()
}

fn double_to_float_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    let initializer_assignments = initializer_separators(index, declarations);
    for declaration in &declarations.declarations {
        if canonical_type_text(&declaration.type_name) != "float" {
            continue;
        }
        for declarator in &declaration.declarators {
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if !expression_is_direct_literal_after_casts(index, start, end)
                && expression_numeric_type(index, declarations, start, end).as_deref()
                    == Some("double")
            {
                offsets.push(declaration.range.start);
            }
        }
    }
    for fact in index.facts.iter().filter(|fact| fact.kind == K::Assignment) {
        if initializer_assignments.contains(&fact.offset) {
            continue;
        }
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = operator
            .checked_sub(1)
            .and_then(|at| unwrap_left_operand(index, at))
        else {
            continue;
        };
        if exact_operand_type(index, declarations, left)
            .is_none_or(|ty| canonical_type_text(&ty) != "float")
        {
            continue;
        }
        let end = direct_assignment_value_end(index, operator + 1, usize::MAX);
        if !expression_is_direct_literal_after_casts(index, operator + 1, end)
            && expression_numeric_type(index, declarations, operator + 1, end).as_deref()
                == Some("double")
        {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn expression_is_direct_literal_after_casts(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> bool {
    let (mut start, end) = trim_outer_group(index, start, end);
    while start < end && index.tokens[start].text == "(" {
        let Some(close) = index.matching_token_index(start) else {
            break;
        };
        if close >= end - 1
            || !index.tokens[start + 1..close]
                .iter()
                .all(|token| is_builtin_type_word(&token.text) || matches!(token.text.as_str(), "const" | "volatile" | "*" | "&"))
        {
            break;
        }
        start = close + 1;
    }
    let (start, end) = trim_outer_group(index, start, end);
    end == start + 1
        && matches!(
            index.tokens[start].kind,
            TokKind::IntLit | TokKind::FloatLit | TokKind::StringLit
        )
}

fn expression_numeric_type(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    start: usize,
    end: usize,
) -> Option<String> {
    let (start, end) = trim_outer_group(index, start, end);
    if start >= end {
        return None;
    }
    if index.tokens[start].text == "(" {
        if let Some(close) = index.matching_token_index(start).filter(|close| *close < end - 1) {
            let type_text = index.tokens[start + 1..close]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let canonical = canonical_type_text(&type_text);
            if is_integer_type(&canonical)
                || matches!(canonical.as_str(), "float" | "double" | "long double")
            {
                return Some(canonical);
            }
        }
    }
    if end == start + 1 {
        return exact_operand_type(index, declarations, start)
            .map(|ty| canonical_type_text(&ty));
    }
    let mut widest = None;
    let mut integral = None;
    for at in start..end {
        let Some(ty) = exact_operand_type(index, declarations, at)
            .map(|ty| canonical_type_text(&ty))
        else {
            continue;
        };
        if ty.ends_with('*') {
            return None;
        }
        if ty == "long double" {
            return Some(ty);
        }
        if ty == "double" {
            widest = Some(ty);
        } else if ty == "float" && widest.is_none() {
            widest = Some(ty);
        } else if is_integral_or_enum_type(&ty) && integral.is_none() {
            integral = Some(ty);
        }
    }
    widest.or(integral)
}

fn plain_char_arithmetic_operand_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for fact in index.facts.iter().filter(|fact| fact.kind == K::Binary) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if !matches!(index.tokens[operator].text.as_str(), "+" | "-" | "*" | "/" | "%") {
            continue;
        }
        let operands = [
            operator
                .checked_sub(1)
                .and_then(|at| unwrap_left_operand(index, at)),
            unwrap_right_operand(index, operator + 1),
        ];
        for operand in operands.into_iter().flatten() {
            if index.tokens[operand].kind == TokKind::Ident
                && exact_operand_type(index, declarations, operand)
                    .is_some_and(|ty| canonical_type_text(&ty) == "char")
            {
                offsets.push(index.tokens[operand].start as usize);
            }
        }
    }
    offsets
}

fn signed_bit_field_width_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    declarations
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.in_aggregate
                && !declaration.type_name.split_whitespace().any(|part| part == "unsigned")
                && declaration.type_name.split_whitespace().any(|part| {
                    matches!(part, "signed" | "char" | "short" | "int" | "long")
                })
        })
        .flat_map(|declaration| {
            declaration.declarators.iter().filter_map(|declarator| {
                declarator.bit_width.as_ref().is_some_and(|width| {
                    token_range_for_source_range(index, width)
                        .and_then(|(start, end)| {
                            evaluate_c_constant_integer(&index.tokens[start..end])
                        })
                        .is_some_and(|value| value <= 1)
                }).then_some(declarator.range.start)
            })
        })
        .collect()
}

fn visually_confusing_variable_name_offsets(
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let variables = declarations
        .declarations
        .iter()
        .filter(|declaration| {
            !declaration.in_aggregate
                && !declaration.storage.iter().any(|storage| storage == "typedef")
        })
        .flat_map(|declaration| {
            declaration.declarators.iter().filter_map(move |declarator| {
                if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                    return None;
                }
                Some((
                    declarator.name.as_deref()?,
                    declarator.range.start,
                    declaration.enclosing_function,
                    c_lexical_scope(syntax, declarator.range.start),
                ))
            })
        })
        .collect::<Vec<_>>();
    const CONFUSABLES: [(&str, &str); 7] = [
        ("O", "0"),
        ("l", "1"),
        ("Z", "2"),
        ("S", "5"),
        ("B", "8"),
        ("h", "n"),
        ("m", "rn"),
    ];
    variables
        .iter()
        .filter(|(name, _, function, scope)| {
            variables.iter().any(|(other, _, other_function, other_scope)| {
                name != other
                    && function == other_function
                    && scope == other_scope
                    && CONFUSABLES.iter().any(|(first, second)| {
                        fuzzy_name_pair_equivalent(name, other, first, second)
                    })
            })
        })
        .map(|(_, offset, _, _)| *offset)
        .collect()
}

fn fuzzy_name_pair_equivalent(left: &str, right: &str, first: &str, second: &str) -> bool {
    left != right
        && left.replace(first, "*").replace(second, "*")
            == right.replace(first, "*").replace(second, "*")
}

fn confusing_same_scope_name_offsets(
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    first: char,
    second: char,
) -> Vec<usize> {
    let variables = declarations
        .declarations
        .iter()
        .filter(|declaration| {
            (declaration.enclosing_function.is_some() || declaration.extern_c)
                && !declaration.in_aggregate
                && !declaration.storage.iter().any(|storage| storage == "typedef")
        })
        .flat_map(|declaration| {
            declaration.declarators.iter().filter_map(move |declarator| {
                if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                    return None;
                }
                let scope = declaration
                    .enclosing_function
                    .map(|_| c_lexical_scope(syntax, declarator.range.start));
                Some((
                    declarator.name.as_deref()?,
                    declarator.range.start,
                    declaration.enclosing_function,
                    scope,
                ))
            })
        })
        .collect::<Vec<_>>();
    variables
        .iter()
        .filter(|(name, _, function, scope)| {
            let normalized = name
                .chars()
                .map(|character| if character == first || character == second { '*' } else { character })
                .collect::<String>();
            variables.iter().any(|(other, _, other_function, other_scope)| {
                name != other
                    && function == other_function
                    && scope == other_scope
                    && other
                        .chars()
                        .map(|character| if character == first || character == second { '*' } else { character })
                        .eq(normalized.chars())
            })
        })
        .map(|(_, offset, _, _)| *offset)
        .collect()
}

fn case_insensitive_local_redeclaration_offsets(
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut locals = declarations
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.enclosing_function.is_some()
                && !declaration.storage.iter().any(|storage| storage == "typedef")
        })
        .flat_map(|declaration| {
            declaration.declarators.iter().filter_map(move |declarator| {
                if matches!(declarator.derived.first(), Some(D::Function { .. })) {
                    return None;
                }
                Some((
                    declarator.name.clone()?,
                    declarator.range.start,
                    declaration.enclosing_function?,
                    c_lexical_scope(syntax, declarator.range.start),
                ))
            })
        })
        .collect::<Vec<_>>();
    locals.sort_by_key(|(_, offset, _, _)| *offset);
    let mut offsets = Vec::new();
    for current in 0..locals.len() {
        let (name, offset, function, scope) = &locals[current];
        if locals[..current].iter().any(|(earlier_name, _, earlier_function, earlier_scope)| {
            earlier_function == function
                && earlier_name != name
                && earlier_name.eq_ignore_ascii_case(name)
                && earlier_scope.start <= scope.start
                && scope.end <= earlier_scope.end
        }) {
            offsets.push(*offset);
        }
    }
    offsets
}

fn c_lexical_scope(syntax: &JavaSyntax, offset: usize) -> std::ops::Range<usize> {
    syntax
        .nodes
        .iter()
        .filter(|node| {
            matches!(node.kind, JavaSyntaxKind::Block | JavaSyntaxKind::If | JavaSyntaxKind::For | JavaSyntaxKind::While | JavaSyntaxKind::Do)
                && node.range.start <= offset
                && offset < node.range.end
        })
        .min_by_key(|node| node.range.end - node.range.start)
        .map_or(offset..offset.saturating_add(1), |node| node.range.clone())
}

fn unicode_mapping_offsets(index: &CExpressionIndex, size_mismatch: bool) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        if !matches!(index.tokens[name_at].text.as_str(), "MultiByteToWideChar" | "WideCharToMultiByte")
            || name_at > 0 && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->" | "::")
        {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else { continue };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        if arguments.len() < 6 { continue; }
        let (out_start, out_end) = trim_outer_group(index, arguments[4].0, arguments[4].1);
        let matched = if size_mismatch {
            let (size_start, size_end) = trim_outer_group(index, arguments[5].0, arguments[5].1);
            is_null_pointer_tokens(index, out_start, out_end)
                && evaluate_c_constant_integer(&index.tokens[size_start..size_end]).is_some_and(|value| value != 0)
        } else {
            let (in_start, in_end) = trim_outer_group(index, arguments[2].0, arguments[2].1);
            in_start < in_end && out_start < out_end
                && index.tokens[in_start..in_end].iter().map(|token| token.text.as_str()).eq(
                    index.tokens[out_start..out_end].iter().map(|token| token.text.as_str())
                )
        };
        if matched { offsets.push(index.tokens[name_at].start as usize); }
    }
    offsets
}

fn is_null_pointer_tokens(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    end == start + 1
        && (matches!(index.tokens[start].text.as_str(), "nullptr" | "NULL" | "__null")
            || token_integer_value(&index.tokens[start]) == Some(0))
}

fn invalid_printf_format_specifier_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        let format_index = match index.tokens[name_at].text.as_str() {
            "printf" => 0,
            "fprintf" | "sprintf" => 1,
            "snprintf" => 2,
            _ => continue,
        };
        if name_at > 0
            && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->")
        {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let Some((start, end)) = arguments.get(format_index).copied() else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if start >= end
            || !index.tokens[start..end]
                .iter()
                .all(|token| token.kind == TokKind::StringLit)
        {
            continue;
        }
        if index.tokens[start..end]
            .iter()
            .any(|literal| literal_has_legacy_invalid_printf_specifier(&literal.text))
        {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn literal_has_legacy_invalid_printf_specifier(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    let mut at = 0usize;
    while at + 1 < bytes.len() {
        if bytes[at] != b'%' {
            at += 1;
            continue;
        }
        if !matches!(
            bytes[at + 1],
            b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'f' | b'F' | b'e' | b'E'
                | b'g' | b'G' | b'a' | b'A' | b'c' | b's' | b'p' | b'n' | b'C' | b'S'
                | b'%'
        ) {
            return true;
        }
        at += 2;
    }
    false
}

fn null_char_traits_length_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        if index.tokens[name_at].text != "length"
            || index.tokens.get(name_at + 1).is_none_or(|token| token.text != "(")
        {
            continue;
        }
        let mut char_traits_at = None;
        for at in (0..name_at).rev() {
            if matches!(index.tokens[at].text.as_str(), ";" | "{" | "}" | "," | "=") {
                break;
            }
            if index.tokens[at].text == "char_traits" {
                char_traits_at = Some(at);
                break;
            }
        }
        let Some(char_traits_at) = char_traits_at else {
            continue;
        };
        if char_traits_at < 2
            || index.tokens[char_traits_at - 2].text != "std"
            || index.tokens[char_traits_at - 1].text != "::"
            || !index.tokens[char_traits_at + 1..name_at]
                .iter()
                .any(|token| token.text == "::")
        {
            continue;
        }
        let open = name_at + 1;
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, open, close);
        let Some((start, end)) = arguments.first().copied() else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if end == start + 1
            && (matches!(index.tokens[start].text.as_str(), "nullptr" | "NULL" | "__null")
                || token_integer_value(&index.tokens[start]) == Some(0))
        {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn builtin_limit_macro_condition_offsets(
    index: &CExpressionIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for condition in syntax
        .nodes
        .iter()
        .filter_map(|node| node.condition.as_ref())
    {
        let Some((start, end)) = token_range_for_source_range(index, condition) else {
            continue;
        };
        let first = index
            .facts
            .iter()
            .filter(|fact| {
                fact.kind == K::Binary
                    && condition.start <= fact.offset
                    && fact.offset < condition.end
            })
            .filter_map(|fact| {
                let operator = token_at_offset(index, fact.offset)?;
                matches!(
                    index.tokens[operator].text.as_str(),
                    "<" | "<=" | ">" | ">="
                )
                .then_some(())?;
                direct_builtin_limit_macro(index, operator, start, end)
            })
            .next();
        offsets.extend(first);
    }
    offsets
}

fn direct_builtin_limit_macro(
    index: &CExpressionIndex,
    operator: usize,
    condition_start: usize,
    condition_end: usize,
) -> Option<usize> {
    let left = operator.checked_sub(1)?;
    if left >= condition_start
        && is_builtin_limit_macro(&index.tokens[left])
        && direct_relational_left_operand(index, left, condition_start)
    {
        return Some(index.tokens[left].start as usize);
    }
    let right = operator + 1;
    if right < condition_end
        && is_builtin_limit_macro(&index.tokens[right])
        && direct_relational_right_operand(index, right, condition_end)
    {
        return Some(index.tokens[right].start as usize);
    }
    None
}

fn direct_relational_left_operand(
    index: &CExpressionIndex,
    operand: usize,
    condition_start: usize,
) -> bool {
    let Some(previous) = operand.checked_sub(1).filter(|at| *at >= condition_start) else {
        return true;
    };
    let text = index.tokens[previous].text.as_str();
    !matches!(text, "!" | "~" | "++" | "--" | ")" | "]")
        && binary_precedence(text).is_none_or(|(precedence, _)| precedence < 7)
}

fn direct_relational_right_operand(
    index: &CExpressionIndex,
    operand: usize,
    condition_end: usize,
) -> bool {
    let next = operand + 1;
    if next >= condition_end {
        return true;
    }
    let text = index.tokens[next].text.as_str();
    !matches!(text, "++" | "--" | "(" | "[" | "." | "->" | "::")
        && binary_precedence(text).is_none_or(|(precedence, _)| precedence <= 7)
}

fn is_builtin_limit_macro(token: &Token) -> bool {
    token.kind == TokKind::Ident
        && matches!(
            token.text.as_str(),
            "SCHAR_MAX"
                | "SHRT_MAX"
                | "INT_MAX"
                | "LONG_MAX"
                | "SCHAR_MIN"
                | "SHRT_MIN"
                | "INT_MIN"
                | "LONG_MIN"
                | "UCHAR_MAX"
                | "USHRT_MAX"
                | "UINT_MAX"
                | "ULONG_MAX"
                | "MB_LEN_MAX"
                | "LLONG_MAX"
                | "LLONG_MIN"
                | "ULLONG_MAX"
                | "LONG_LONG_MAX"
                | "LONG_LONG_MIN"
                | "ULONG_LONG_MAX"
                | "CHAR_MAX"
                | "BOOL_WIDTH"
                | "CHAR_WIDTH"
                | "SCHAR_WIDTH"
                | "UCHAR_WIDTH"
                | "USHRT_WIDTH"
                | "SHRT_WIDTH"
                | "UINT_WIDTH"
                | "INT_WIDTH"
                | "ULONG_WIDTH"
                | "LONG_WIDTH"
                | "ULLONG_WIDTH"
                | "LLONG_WIDTH"
        )
}

fn chained_comparison_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            let (_, text) = binary_precedence(&index.tokens[operator].text)?;
            is_comparison_operator(text).then_some(())?;
            declarations
                .functions
                .iter()
                .any(|function| {
                    function.body.start <= fact.offset && fact.offset < function.body.end
                })
                .then_some(())?;
            let (lower, upper) = index
                .smallest_group(fact.offset)
                .map_or((0, index.tokens.len()), |(open, close)| (open + 1, close));
            let precedence = binary_precedence(text)?.0;
            let left = left_operand_start(index, operator, lower, precedence);
            let right = right_operand_end(index, operator, upper, precedence);
            (expression_root_is_comparison(index, left, operator)
                || expression_root_is_comparison(index, operator + 1, right))
            .then_some(fact.offset)
        })
        .collect()
}

fn left_operand_start(
    index: &CExpressionIndex,
    operator: usize,
    lower: usize,
    precedence: u8,
) -> usize {
    let mut at = operator;
    while at > lower {
        at -= 1;
        if matches!(index.tokens[at].text.as_str(), ")" | "]" | "}") {
            if let Some(open) = index.matching_token_index(at) {
                if open >= lower {
                    at = open;
                    continue;
                }
            }
            return lower;
        }
        if let Some((candidate, _)) = binary_precedence(&index.tokens[at].text) {
            if candidate < precedence {
                return at + 1;
            }
            continue;
        }
        if is_expression_boundary(&index.tokens[at].text) {
            return at + 1;
        }
    }
    lower
}

fn right_operand_end(
    index: &CExpressionIndex,
    operator: usize,
    upper: usize,
    precedence: u8,
) -> usize {
    let mut at = operator + 1;
    while at < upper {
        if matches!(index.tokens[at].text.as_str(), "(" | "[" | "{") {
            if let Some(close) = index.matching_token_index(at) {
                if close < upper {
                    at = close + 1;
                    continue;
                }
            }
            return upper;
        }
        if let Some((candidate, _)) = binary_precedence(&index.tokens[at].text) {
            if candidate <= precedence {
                return at;
            }
        } else if is_expression_boundary(&index.tokens[at].text) {
            return at;
        }
        at += 1;
    }
    upper
}

fn expression_root_is_comparison(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    expression_root_operator(index, start, end, true)
        .is_some_and(|at| is_comparison_operator(&index.tokens[at].text))
}

fn expression_root_operator(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
    ignore_outer_parentheses: bool,
) -> Option<usize> {
    let (start, end) = if ignore_outer_parentheses {
        trim_outer_group(index, start, end)
    } else {
        (start, end)
    };
    let mut root = None;
    let mut at = start;
    while at < end {
        if matches!(index.tokens[at].text.as_str(), "(" | "[" | "{") {
            if let Some(close) = index.matching_token_index(at) {
                if close < end {
                    at = close + 1;
                    continue;
                }
            }
        }
        if let Some((precedence, _)) = binary_precedence(&index.tokens[at].text) {
            if root.is_none_or(|(_, current)| precedence <= current) {
                root = Some((at, precedence));
            }
        }
        at += 1;
    }
    root.map(|(at, _)| at)
}

fn is_comparison_operator(operator: &str) -> bool {
    matches!(operator, "==" | "!=" | "<" | "<=" | ">" | ">=")
}

fn is_expression_boundary(token: &str) -> bool {
    matches!(
        token,
        "," | ";" | "?" | ":" | "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&="
            | "|=" | "^=" | "<<=" | ">>=" | "return" | "{" | "}"
    )
}

fn bitwise_mixed_expression_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            let text = index.tokens[operator].text.as_str();
            is_bitwise_operator(text).then_some(())?;
            declarations
                .functions
                .iter()
                .any(|function| {
                    function.body.start <= fact.offset && fact.offset < function.body.end
                })
                .then_some(())?;
            let precedence = binary_precedence(text)?.0;
            let (lower, upper) = index
                .smallest_group(fact.offset)
                .map_or((0, index.tokens.len()), |(open, close)| (open + 1, close));
            let left = left_operand_start(index, operator, lower, precedence);
            let right = right_operand_end(index, operator, upper, precedence);
            let mixed = expression_root_operator(index, left, operator, false)
                .is_some_and(|at| !is_bitwise_operator(&index.tokens[at].text))
                || expression_root_operator(index, operator + 1, right, false)
                    .is_some_and(|at| !is_bitwise_operator(&index.tokens[at].text));
            mixed.then_some(fact.offset)
        })
        .collect()
}

fn is_bitwise_operator(operator: &str) -> bool {
    matches!(operator, "&" | "|" | "^")
}

fn shift_on_small_integer_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            matches!(index.tokens[operator].text.as_str(), "<<" | ">>").then_some(())?;
            declarations
                .functions
                .iter()
                .any(|function| {
                    function.body.start <= fact.offset && fact.offset < function.body.end
                })
                .then_some(())?;
            let operand = direct_shift_left_operand(index, operator)?;
            let ty = exact_operand_type(index, declarations, operand)?;
            is_smaller_than_int_type(&canonical_type_text(&ty))
                .then_some(index.tokens[operand].start as usize)
        })
        .collect()
}

fn direct_shift_left_operand(index: &CExpressionIndex, operator: usize) -> Option<usize> {
    let mut operand = operator.checked_sub(1)?;
    while index.tokens.get(operand).is_some_and(|token| token.text == ")") {
        let open = index.matching_token_index(operand)?;
        if open + 2 != operand
            || open.checked_sub(1).is_some_and(|previous| {
                index.tokens[previous].kind == TokKind::Ident
                    || index.tokens[previous].text == ">"
            })
        {
            return None;
        }
        operand = open + 1;
    }
    let token = index.tokens.get(operand)?;
    if token.kind != TokKind::Ident {
        return None;
    }
    if let Some(previous) = operand.checked_sub(1) {
        let text = index.tokens[previous].text.as_str();
        if text == ")"
            || matches!(text, "+" | "-" | "!" | "*" | "&" | "++" | "--")
            || binary_precedence(text).is_some()
        {
            return None;
        }
    }
    Some(operand)
}

fn is_smaller_than_int_type(ty: &str) -> bool {
    matches!(
        ty,
        "bool" | "_Bool" | "char" | "signed char" | "unsigned char" | "char8_t"
            | "char16_t" | "short" | "unsigned short"
    )
}

#[derive(Clone)]
enum EofFlowEvent {
    Assign {
        offset: usize,
        target: String,
        value_start: usize,
        value_end: usize,
    },
    Compare {
        offset: usize,
        operator: usize,
    },
}

impl EofFlowEvent {
    fn offset(&self) -> usize {
        match self {
            Self::Assign { offset, .. } | Self::Compare { offset, .. } => *offset,
        }
    }
}

fn eof_character_input_comparison_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let initializer_assignments = initializer_separators(index, declarations);
    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let mut events = Vec::new();
        for declaration in declarations
            .declarations
            .iter()
            .filter(|declaration| {
                function.body.start <= declaration.range.start
                    && declaration.range.end <= function.body.end
            })
        {
            for declarator in &declaration.declarators {
                let (Some(target), Some(initializer)) =
                    (declarator.name.as_ref(), declarator.initializer.as_ref())
                else {
                    continue;
                };
                let Some((value_start, value_end)) =
                    token_range_for_source_range(index, initializer)
                else {
                    continue;
                };
                events.push(EofFlowEvent::Assign {
                    offset: initializer.start,
                    target: target.clone(),
                    value_start,
                    value_end,
                });
            }
        }
        for fact in index.facts.iter().filter(|fact| {
            function.body.start <= fact.offset && fact.offset < function.body.end
        }) {
            let Some(operator) = token_at_offset(index, fact.offset) else {
                continue;
            };
            if fact.kind == K::Assignment
                && !initializer_assignments.contains(&fact.offset)
                && index.tokens[operator].text == "="
            {
                let Some(target) = direct_assignment_lhs(index, fact.offset) else {
                    continue;
                };
                let value_start = operator + 1;
                let value_end = direct_assignment_value_end(index, value_start, function.body.end);
                events.push(EofFlowEvent::Assign {
                    offset: fact.offset,
                    target: target.to_string(),
                    value_start,
                    value_end,
                });
            } else if fact.kind == K::Binary
                && matches!(index.tokens[operator].text.as_str(), "==" | "!=")
            {
                events.push(EofFlowEvent::Compare {
                    offset: fact.offset,
                    operator,
                });
            }
        }
        events.sort_by_key(EofFlowEvent::offset);
        let mut tainted = HashSet::new();
        for event in events {
            match event {
                EofFlowEvent::Assign {
                    target,
                    value_start,
                    value_end,
                    ..
                } => {
                    if expression_is_character_input(index, value_start, value_end, &tainted) {
                        tainted.insert(target);
                    } else {
                        tainted.remove(&target);
                    }
                }
                EofFlowEvent::Compare { offset, operator } => {
                    let precedence = 6;
                    let (lower, upper) = index
                        .smallest_group(offset)
                        .map_or((0, index.tokens.len()), |(open, close)| (open + 1, close));
                    let left = left_operand_start(index, operator, lower, precedence);
                    let right = right_operand_end(index, operator, upper, precedence);
                    let left_is_input =
                        expression_is_character_input(index, left, operator, &tainted);
                    let right_is_input =
                        expression_is_character_input(index, operator + 1, right, &tainted);
                    if left_is_input && expression_is_eof(index, operator + 1, right)
                        || right_is_input && expression_is_eof(index, left, operator)
                    {
                        offsets.push(offset);
                    }
                }
            }
        }
    }
    offsets
}

fn direct_assignment_value_end(
    index: &CExpressionIndex,
    start: usize,
    function_end: usize,
) -> usize {
    let upper = index
        .tokens
        .iter()
        .position(|token| token.start as usize >= function_end)
        .unwrap_or(index.tokens.len());
    let mut at = start;
    while at < upper {
        if matches!(index.tokens[at].text.as_str(), "(" | "[" | "{") {
            if let Some(close) = index.matching_token_index(at) {
                if close < upper {
                    at = close + 1;
                    continue;
                }
            }
        }
        if matches!(index.tokens[at].text.as_str(), ";" | "," | ")" | "}") {
            return at;
        }
        at += 1;
    }
    upper
}

fn expression_is_character_input(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
    tainted: &HashSet<String>,
) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    if end == start + 1 && index.tokens[start].kind == TokKind::Ident {
        return tainted.contains(&index.tokens[start].text);
    }
    if start + 2 >= end || index.tokens[start].kind != TokKind::Ident {
        return false;
    }
    let open = start + 1;
    index.tokens[open].text == "("
        && index.matching_token_index(open) == Some(end - 1)
        && matches!(index.tokens[start].text.as_str(), "getchar" | "getwc")
}

fn expression_is_eof(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    if end == start + 1 {
        return index.tokens[start].kind == TokKind::Ident
            && matches!(index.tokens[start].text.as_str(), "EOF" | "WEOF");
    }
    end == start + 2
        && index.tokens[start].text == "-"
        && token_integer_value(&index.tokens[start + 1]) == Some(1)
}

fn multiple_unget_same_stream_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let mut stream_state = HashMap::new();
        for name_at in 0..index.tokens.len() {
            let name = &index.tokens[name_at];
            if (name.start as usize) < function.body.start
                || (name.start as usize) >= function.body.end
                || name.kind != TokKind::Ident
                || !matches!(name.text.as_str(), "ungetc" | "ungetwc")
                || index
                    .tokens
                    .get(name_at.wrapping_sub(1))
                    .is_some_and(|token| matches!(token.text.as_str(), "." | "->" | "::"))
            {
                continue;
            }
            let open = name_at + 1;
            if index.tokens.get(open).is_none_or(|token| token.text != "(") {
                continue;
            }
            let Some(close) = index.matching_token_index(open) else {
                continue;
            };
            let arguments = direct_call_argument_ranges(index, open, close);
            if arguments.len() != 2 {
                continue;
            }
            let (stream_start, stream_end) = arguments[1];
            let (stream_start, stream_end) = trim_outer_group(index, stream_start, stream_end);
            if stream_start >= stream_end
                || !index.tokens[stream_start..stream_end]
                    .iter()
                    .any(|token| token.kind == TokKind::Ident)
            {
                continue;
            }
            let key = index.tokens[stream_start..stream_end]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join("");
            match stream_state.get(&key).copied() {
                None => {
                    stream_state.insert(key, true);
                }
                Some(true) => {
                    offsets.push(index.tokens[stream_start].start as usize);
                    stream_state.insert(key, false);
                }
                Some(false) => {}
            }
        }
    }
    offsets
}

fn declaration_before_first_switch_case_offsets(
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for switch in syntax
        .nodes
        .iter()
        .filter(|node| node.kind == JavaSyntaxKind::Switch)
    {
        let Some(body) = &switch.body else {
            continue;
        };
        let first_case = syntax
            .nodes
            .iter()
            .filter(|group| {
                group.kind == JavaSyntaxKind::SwitchGroup
                    && group.label_is_case
                    && body.start < group.range.start
                    && group.range.end <= body.end
                    && !syntax.nodes.iter().any(|nested| {
                        nested.kind == JavaSyntaxKind::Switch
                            && switch.range.start < nested.range.start
                            && nested.range.end <= switch.range.end
                            && nested.range.start < group.range.start
                            && group.range.end <= nested.range.end
                    })
            })
            .min_by_key(|group| group.range.start);
        let Some(first_case) = first_case else {
            continue;
        };
        let declaration = declarations
            .declarations
            .iter()
            .filter(|declaration| {
                body.start < declaration.range.start
                    && declaration.range.start < first_case.range.start
                    && declaration.range.end <= body.end
                    && !declaration.in_aggregate
            })
            .filter(|declaration| {
                !syntax.nodes.iter().any(|block| {
                    block.kind == JavaSyntaxKind::Block
                        && body.start < block.range.start
                        && block.range.end <= body.end
                        && block.range.start <= declaration.range.start
                        && declaration.range.end <= block.range.end
                })
            })
            .min_by_key(|declaration| declaration.range.start);
        offsets.extend(declaration.map(|declaration| declaration.range.start));
    }
    offsets
}

fn raw_allocation_for_class_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let class_names = declarations
        .aggregates
        .iter()
        .filter(|aggregate| aggregate.kind == "class")
        .filter_map(|aggregate| aggregate.name.as_deref())
        .collect::<HashSet<_>>();
    if class_names.is_empty() {
        return Vec::new();
    }
    let known_names = declarations
        .aggregates
        .iter()
        .filter_map(|aggregate| aggregate.name.as_deref())
        .chain(
            declarations
                .declarations
                .iter()
                .filter(|declaration| declaration.storage.iter().any(|item| item == "typedef"))
                .flat_map(|declaration| &declaration.declarators)
                .filter_map(|declarator| declarator.name.as_deref()),
        )
        .collect::<HashSet<_>>();
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        if index.tokens[name_at].text == "free" {
            let Some((_, close)) = direct_call_expression(index, name_at) else {
                continue;
            };
            let arguments = direct_call_argument_ranges(index, name_at + 1, close);
            let Some((start, end)) = arguments.first().copied() else {
                continue;
            };
            let (start, end) = trim_outer_group(index, start, end);
            if end != start + 1 {
                continue;
            }
            let Some(ty) = exact_operand_type(index, declarations, start) else {
                continue;
            };
            if pointer_targets_class(&ty, &class_names) {
                offsets.push(index.tokens[start].start as usize);
            }
        }
        if index.tokens[name_at].text == "(" {
            let Some(cast_close) = index.matching_token_index(name_at) else {
                continue;
            };
            let Some(destination) =
                cast_destination_type(&index.tokens[name_at + 1..cast_close], &known_names)
            else {
                continue;
            };
            if !pointer_targets_class(&destination, &class_names) {
                continue;
            }
            let Some((callee, call_close)) = direct_call_expression(index, cast_close + 1) else {
                continue;
            };
            if is_raw_allocation_call(callee)
                && !direct_call_argument_ranges(index, cast_close + 2, call_close).is_empty()
            {
                offsets.push(index.tokens[cast_close + 1].start as usize);
            }
        }
        if matches!(
            index.tokens[name_at].text.as_str(),
            "static_cast" | "dynamic_cast" | "reinterpret_cast" | "const_cast"
        ) && index
            .tokens
            .get(name_at + 1)
            .is_some_and(|token| token.text == "<")
        {
            let Some(type_end) = (name_at + 2..index.tokens.len())
                .find(|candidate| index.tokens[*candidate].text == ">")
            else {
                continue;
            };
            let Some(destination) =
                cast_destination_type(&index.tokens[name_at + 2..type_end], &known_names)
            else {
                continue;
            };
            if !pointer_targets_class(&destination, &class_names)
                || index
                    .tokens
                    .get(type_end + 1)
                    .is_none_or(|token| token.text != "(")
            {
                continue;
            }
            let Some(cast_close) = index.matching_token_index(type_end + 1) else {
                continue;
            };
            let Some((callee, call_close)) = direct_call_expression(index, type_end + 2) else {
                continue;
            };
            if call_close + 1 == cast_close
                && is_raw_allocation_call(callee)
                && !direct_call_argument_ranges(index, type_end + 3, call_close).is_empty()
            {
                offsets.push(index.tokens[type_end + 2].start as usize);
            }
        }
    }
    offsets
}

fn pointer_targets_class(ty: &str, class_names: &HashSet<&str>) -> bool {
    let ty = canonical_type_text(ty);
    ty.ends_with('*')
        && class_names.contains(ty.trim_end_matches('*').trim_matches(':'))
}

fn is_raw_allocation_call(name: &str) -> bool {
    matches!(name, "malloc" | "calloc" | "realloc")
}

fn std_find_on_set_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for find_at in 2..index.tokens.len() {
        if index.tokens[find_at].text != "find"
            || index.tokens[find_at - 1].text != "::"
            || index.tokens[find_at - 2].text != "std"
            || index
                .tokens
                .get(find_at + 1)
                .is_none_or(|token| token.text != "(")
        {
            continue;
        }
        let open = find_at + 1;
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, open, close);
        if arguments.len() <= 2 {
            continue;
        }
        let (start, end) = trim_outer_group(index, arguments[0].0, arguments[0].1);
        if end != start + 5
            || index.tokens[start].kind != TokKind::Ident
            || !matches!(index.tokens[start + 1].text.as_str(), "." | "->")
            || index.tokens[start + 2].text != "begin"
            || index.tokens[start + 3].text != "("
            || index.matching_token_index(start + 3) != Some(start + 4)
        {
            continue;
        }
        let Some(ty) = exact_operand_type(index, declarations, start) else {
            continue;
        };
        let compact = ty.split_whitespace().collect::<String>();
        if compact == "std::set" || compact.starts_with("std::set<") {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn exit_handler_abnormal_exit_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let functions = declarations
        .functions
        .iter()
        .enumerate()
        .map(|(id, function)| (function.name.as_str(), id))
        .collect::<HashMap<_, _>>();
    let mut offsets = Vec::new();
    for call in index.facts.iter().filter(|fact| fact.kind == K::Call) {
        let Some(name_at) = token_at_offset(index, call.offset) else {
            continue;
        };
        if !matches!(
            index.tokens[name_at].text.as_str(),
            "atexit" | "at_quick_exit"
        ) || name_at > 0
            && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->" | "::")
        {
            continue;
        }
        let open = name_at + 1;
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, open, close);
        let Some((start, end)) = arguments.first().copied() else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if end != start + 1 || index.tokens[start].kind != TokKind::Ident {
            continue;
        }
        let Some(function) = functions.get(index.tokens[start].text.as_str()).copied() else {
            continue;
        };
        let mut visited = HashSet::new();
        if let Some(offset) = first_abnormal_exit_in_call_graph(
            index,
            declarations,
            &functions,
            function,
            &mut visited,
        ) {
            offsets.push(offset);
        }
    }
    offsets
}

fn first_abnormal_exit_in_call_graph(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    functions: &HashMap<&str, usize>,
    function: usize,
    visited: &mut HashSet<usize>,
) -> Option<usize> {
    if !visited.insert(function) {
        return None;
    }
    let body = &declarations.functions.get(function)?.body;
    for call in index.facts.iter().filter(|fact| {
        fact.kind == K::Call && body.start <= fact.offset && fact.offset < body.end
    }) {
        let name_at = token_at_offset(index, call.offset)?;
        if name_at > 0
            && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->" | "::")
        {
            continue;
        }
        let name = index.tokens[name_at].text.as_str();
        if matches!(name, "exit" | "_Exit" | "quick_exit" | "longjmp") {
            return Some(index.tokens[name_at].start as usize);
        }
        if let Some(callee) = functions.get(name).copied() {
            if let Some(offset) = first_abnormal_exit_in_call_graph(
                index,
                declarations,
                functions,
                callee,
                visited,
            ) {
                return Some(offset);
            }
        }
    }
    None
}

fn direct_time_arithmetic_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            let supported = match fact.kind {
                K::Binary => matches!(index.tokens[operator].text.as_str(), "+" | "-"),
                K::Assignment => matches!(index.tokens[operator].text.as_str(), "+=" | "-="),
                _ => false,
            };
            supported.then_some(())?;
            let left = operator
                .checked_sub(1)
                .and_then(|at| unwrap_left_operand(index, at));
            let right = unwrap_right_operand(index, operator + 1);
            for operand in [left, right].into_iter().flatten() {
                if exact_operand_type(index, declarations, operand)
                    .is_some_and(|ty| canonical_type_text(&ty) == "time_t")
                {
                    return Some(index.tokens[operand].start as usize);
                }
            }
            None
        })
        .collect()
}

fn too_few_printf_argument_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        let format_index = match index.tokens[name_at].text.as_str() {
            "printf" => 0,
            "fprintf" | "sprintf" => 1,
            "snprintf" => 2,
            _ => continue,
        };
        if name_at > 0 && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->") {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let Some((start, end)) = arguments.get(format_index).copied() else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if start >= end
            || !index.tokens[start..end]
                .iter()
                .all(|token| token.kind == TokKind::StringLit)
        {
            continue;
        }
        let required = index.tokens[start..end]
            .iter()
            .map(|token| printf_conversion_count(&token.text))
            .sum::<usize>();
        let supplied = arguments.len().saturating_sub(format_index + 1);
        if required > supplied {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn printf_conversion_count(literal: &str) -> usize {
    let bytes = literal.as_bytes();
    let mut conversions = 0usize;
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] != b'%' {
            at += 1;
            continue;
        }
        if bytes.get(at + 1) == Some(&b'%') {
            at += 2;
        } else {
            conversions += 1;
            at += 1;
        }
    }
    conversions
}

fn printf_star_offsets(index: &CExpressionIndex, missing_only: bool) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        let format_index = match index.tokens[name_at].text.as_str() {
            "printf" => 0,
            "fprintf" | "sprintf" => 1,
            "snprintf" => 2,
            _ => continue,
        };
        if name_at > 0 && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->") {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let Some((format_start, format_end)) = arguments.get(format_index).copied() else {
            continue;
        };
        let (format_start, format_end) = trim_outer_group(index, format_start, format_end);
        if format_start >= format_end
            || !index.tokens[format_start..format_end]
                .iter()
                .all(|token| token.kind == TokKind::StringLit)
        {
            continue;
        }
        let (required, star_arguments) =
            printf_star_requirements(&index.tokens[format_start..format_end]);
        let supplied = arguments.len().saturating_sub(format_index + 1);
        if missing_only {
            if required > supplied && !star_arguments.is_empty() {
                offsets.push(index.tokens[format_start].start as usize);
            }
            continue;
        }
        for relative in star_arguments {
            let Some((start, end)) = arguments.get(format_index + 1 + relative).copied() else {
                continue;
            };
            let (start, end) = trim_outer_group(index, start, end);
            if start >= end
                || evaluate_c_constant_integer(&index.tokens[start..end]).is_none()
            {
                offsets.push(
                    index
                        .tokens
                        .get(start)
                        .map_or(index.tokens[format_start].start as usize, |token| {
                            token.start as usize
                        }),
                );
            }
        }
    }
    offsets
}

fn printf_star_requirements(literals: &[Token]) -> (usize, Vec<usize>) {
    let mut required = 0usize;
    let mut star_arguments = Vec::new();
    for literal in literals {
        let bytes = literal.text.as_bytes();
        let mut at = 0usize;
        while at < bytes.len() {
            if bytes[at] != b'%' || at + 1 >= bytes.len() {
                at += 1;
                continue;
            }
            if bytes[at + 1] == b'%' {
                at += 2;
            } else if bytes[at + 1] == b'*' {
                star_arguments.push(required);
                required += 2;
                at += 2;
            } else if bytes[at + 1] == b'.'
                && bytes.get(at + 2) == Some(&b'*')
            {
                star_arguments.push(required);
                required += 2;
                at += 3;
            } else {
                required += 1;
                at += 1;
            }
        }
    }
    (required, star_arguments)
}

fn scanf_unbounded_string_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        if index.tokens[name_at].text != "scanf"
            || name_at > 0
                && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->")
        {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let Some((start, end)) = arguments.first().copied() else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if start < end
            && index.tokens[start..end]
                .iter()
                .all(|token| token.kind == TokKind::StringLit)
            && index.tokens[start..end]
                .iter()
                .any(|token| contains_unbounded_percent_s(&token.text))
        {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn contains_unbounded_percent_s(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    let mut at = 0usize;
    while at + 1 < bytes.len() {
        if bytes[at] != b'%' {
            at += 1;
        } else if bytes[at + 1] == b'%' {
            at += 2;
        } else if bytes[at + 1] == b's' {
            return true;
        } else {
            at += 1;
        }
    }
    false
}

fn fsetpos_without_fgetpos_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let mut known_positions = HashSet::new();
        for name_at in 0..index.tokens.len() {
            let token = &index.tokens[name_at];
            if (token.start as usize) < function.body.start
                || (token.start as usize) >= function.body.end
                || !matches!(token.text.as_str(), "fgetpos" | "fsetpos")
                || name_at > 0
                    && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->")
            {
                continue;
            }
            let Some((_, close)) = direct_call_expression(index, name_at) else {
                continue;
            };
            let arguments = direct_call_argument_ranges(index, name_at + 1, close);
            if arguments.len() < 2 {
                continue;
            }
            let Some((identity, offset)) = argument_object_identity(index, arguments[1]) else {
                continue;
            };
            if token.text == "fgetpos" {
                known_positions.insert(identity);
            } else if !known_positions.contains(&identity) {
                offsets.push(offset);
            }
        }
    }
    offsets
}

fn argument_object_identity(
    index: &CExpressionIndex,
    range: (usize, usize),
) -> Option<(String, usize)> {
    let (mut start, end) = trim_outer_group(index, range.0, range.1);
    while start < end && matches!(index.tokens[start].text.as_str(), "&" | "*") {
        start += 1;
    }
    let (start, end) = trim_outer_group(index, start, end);
    (start < end
        && index.tokens[start..end]
            .iter()
            .any(|token| token.kind == TokKind::Ident))
    .then(|| {
        (
            index.tokens[start..end]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join(""),
            index.tokens[start].start as usize,
        )
    })
}

fn interleaved_stream_io_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let mut states = HashMap::new();
        for name_at in 0..index.tokens.len() {
            let token = &index.tokens[name_at];
            if (token.start as usize) < function.body.start
                || (token.start as usize) >= function.body.end
                || name_at > 0
                    && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->")
            {
                continue;
            }
            let (stream_argument, next_state) = match token.text.as_str() {
                "fread" => (3, Some(1u8)),
                "fwrite" => (3, Some(2u8)),
                "fflush" | "fseek" | "fsetpos" | "rewind" => (0, None),
                _ => continue,
            };
            let Some((_, close)) = direct_call_expression(index, name_at) else {
                continue;
            };
            let arguments = direct_call_argument_ranges(index, name_at + 1, close);
            let Some(range) = arguments.get(stream_argument).copied() else {
                continue;
            };
            let Some((identity, offset)) = argument_object_identity(index, range) else {
                continue;
            };
            match next_state {
                None => {
                    states.remove(&identity);
                }
                Some(state) => {
                    if states
                        .get(&identity)
                        .is_some_and(|previous| *previous != state)
                    {
                        offsets.push(offset);
                    }
                    states.insert(identity, state);
                }
            }
        }
    }
    offsets
}

fn aliased_restrict_argument_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut signatures = HashMap::<&str, Vec<usize>>::new();
    for declaration in &declarations.declarations {
        for declarator in &declaration.declarators {
            let (Some(name), Some(D::Function { parameters })) =
                (declarator.name.as_deref(), declarator.derived.first())
            else {
                continue;
            };
            let restricted = restrict_parameter_indexes(index, declarations, parameters);
            if !restricted.is_empty() {
                signatures.insert(name, restricted);
            }
        }
    }
    for function in &declarations.functions {
        let restricted =
            restrict_parameter_indexes(index, declarations, &function.parameters);
        if !restricted.is_empty() {
            signatures.insert(function.name.as_str(), restricted);
        }
    }
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len() {
        let Some(restricted) = signatures.get(index.tokens[name_at].text.as_str()) else {
            continue;
        };
        if name_at > 0 && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->") {
            continue;
        }
        let Some((_, close)) = direct_call_expression(index, name_at) else {
            continue;
        };
        let arguments = direct_call_argument_ranges(index, name_at + 1, close);
        let mut identities = Vec::<(String, String)>::new();
        for parameter in restricted {
            let Some(range) = arguments.get(*parameter).copied() else {
                continue;
            };
            let Some((exact, offset)) = argument_object_identity(index, range) else {
                continue;
            };
            let root = argument_root_identity(index, range).unwrap_or_else(|| exact.clone());
            if identities.iter().any(|(previous_exact, previous_root)| {
                previous_exact == &exact
                    || previous_root == &root
                        && (exact.contains('[') || previous_exact.contains('['))
            }) {
                offsets.push(offset);
                break;
            }
            identities.push((exact, root));
        }
    }
    offsets
}

fn restrict_parameter_indexes(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    range: &std::ops::Range<usize>,
) -> Vec<usize> {
    declarations
        .parameters
        .iter()
        .filter(|parameter| {
            range.start <= parameter.range.start && parameter.range.end <= range.end
        })
        .enumerate()
        .filter_map(|(position, parameter)| {
            index
                .tokens
                .iter()
                .any(|token| {
                    parameter.range.start <= token.start as usize
                        && token.end as usize <= parameter.range.end
                        && token.text == "restrict"
                })
                .then_some(position)
        })
        .collect()
}

fn argument_root_identity(
    index: &CExpressionIndex,
    range: (usize, usize),
) -> Option<String> {
    let (start, end) = trim_outer_group(index, range.0, range.1);
    index.tokens[start..end]
        .iter()
        .find(|token| token.kind == TokKind::Ident)
        .map(|token| token.text.clone())
}

fn readlink_length_out_of_bounds_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let capacities = declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter_map(|declarator| {
            let name = declarator.name.as_ref()?;
            let size = declarator.derived.iter().find_map(|derived| match derived {
                D::Array { size } => Some(size),
                _ => None,
            })?;
            let (start, end) = token_range_for_source_range(index, size)?;
            let capacity = evaluate_c_constant_integer(&index.tokens[start..end])?;
            (capacity > 0).then(|| (name.clone(), capacity))
        })
        .collect::<HashMap<_, _>>();
    let mut lengths = HashMap::<String, Option<i128>>::new();
    for declaration in &declarations.declarations {
        for declarator in &declaration.declarators {
            let (Some(name), Some(initializer)) =
                (declarator.name.as_ref(), declarator.initializer.as_ref())
            else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if let Some(maximum) = readlink_maximum_argument(index, start, end) {
                lengths.insert(name.clone(), maximum);
            }
        }
    }
    let mut offsets = Vec::new();
    for buffer_at in 0..index.tokens.len() {
        let buffer = &index.tokens[buffer_at];
        let Some(capacity) = capacities.get(&buffer.text).copied() else {
            continue;
        };
        if index
            .tokens
            .get(buffer_at + 1)
            .is_none_or(|token| token.text != "[")
        {
            continue;
        }
        let open = buffer_at + 1;
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        let (start, end) = trim_outer_group(index, open + 1, close);
        if end == start + 1 && index.tokens[start].kind == TokKind::Ident {
            if let Some(maximum) = lengths.get(&index.tokens[start].text) {
                if maximum.is_none_or(|maximum| maximum > capacity) {
                    offsets.push(index.tokens[start].start as usize);
                }
            }
        } else if let Some(maximum) = readlink_maximum_argument(index, start, end) {
            if maximum.is_none_or(|maximum| maximum > capacity) {
                offsets.push(index.tokens[start].start as usize);
            }
        }
    }
    offsets
}

fn readlink_maximum_argument(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> Option<Option<i128>> {
    let (start, end) = trim_outer_group(index, start, end);
    if start + 2 >= end
        || index.tokens[start].text != "readlink"
        || index.tokens[start + 1].text != "("
        || index.matching_token_index(start + 1) != Some(end - 1)
    {
        return None;
    }
    let arguments = direct_call_argument_ranges(index, start + 1, end - 1);
    if arguments.len() < 3 {
        return None;
    }
    let (max_start, max_end) = arguments[2];
    Some(evaluate_c_constant_integer(
        &index.tokens[max_start..max_end],
    ))
}

fn file_object_copy_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        if canonical_type_text(&declaration.type_name) != "FILE" {
            continue;
        }
        for declarator in &declaration.declarators {
            if declarator
                .derived
                .iter()
                .any(|derived| matches!(derived, D::Pointer | D::MemberPointer))
            {
                continue;
            }
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            if evaluate_c_constant_integer(&index.tokens[start..end]).is_none() {
                offsets.push(index.tokens[start].start as usize);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = unwrap_left_operand(index, operator.saturating_sub(1)) else {
            continue;
        };
        if exact_operand_type(index, declarations, left)
            .is_some_and(|ty| canonical_type_text(&ty) == "FILE")
        {
            offsets.push(
                index
                    .tokens
                    .get(operator + 1)
                    .map_or(fact.offset, |token| token.start as usize),
            );
        }
    }
    offsets
}

fn errno_return_type_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    declarations
        .returns
        .iter()
        .filter_map(|returned| {
            let function = declarations.functions.get(returned.function)?;
            let return_type = canonical_type_text(&function.return_type);
            if return_type == "errno_t" || !is_integer_type(&return_type) {
                return None;
            }
            let mut start = index
                .tokens
                .iter()
                .position(|token| token.start as usize >= returned.range.start)?;
            let mut end = index
                .tokens
                .iter()
                .position(|token| token.start as usize >= returned.range.end)
                .unwrap_or(index.tokens.len());
            if index.tokens.get(start).is_some_and(|token| token.text == "return") {
                start += 1;
            }
            if end > start && index.tokens[end - 1].text == ";" {
                end -= 1;
            }
            (start, end) = trim_outer_group(index, start, end);
            if start < end && index.tokens[start].text == "(" {
                let cast_close = index.matching_token_index(start)?;
                if cast_close + 1 < end {
                    start = cast_close + 1;
                    (start, end) = trim_outer_group(index, start, end);
                }
            }
            (end == start + 1 && is_errno_name(&index.tokens[start]))
                .then_some(index.tokens[start].start as usize)
        })
        .collect()
}

fn errno_result_protocol_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    #[derive(Clone, Copy)]
    enum Event {
        ErrnoAssignment(bool),
        ErrnoSettingCall(usize),
        ErrnoCheck,
    }

    const ERRNO_FUNCTIONS: &[&str] = &[
        "ftell", "fgetpos", "fsetpos", "mbrtowc", "mbsrtowcs", "signal", "wcrtomb",
        "wcsrtombs", "mbrtoc16", "mbrtoc32", "c16rtomb", "cr32rtomb", "fgetwc",
        "fputwc", "strtol", "wcstol", "strtoll", "wcstoll", "strtoul", "wcstoul",
        "strtoull", "wcstoull", "strtoumax", "wcstoumax", "strtod", "wcstod",
        "strtof", "wcstof", "strtold", "wcstold", "strtoimax", "wcstoimax",
    ];

    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let shadows_errno = declarations.declarations.iter().any(|declaration| {
            function.body.start <= declaration.range.start
                && declaration.range.end <= function.body.end
                && declaration
                    .declarators
                    .iter()
                    .any(|declarator| declarator.name.as_deref() == Some("errno"))
        });
        let mut events = Vec::<(usize, Event)>::new();
        for fact in index.facts.iter().filter(|fact| {
            fact.kind == K::Assignment
                && function.body.start <= fact.offset
                && fact.offset < function.body.end
        }) {
            let Some(operator) = token_at_offset(index, fact.offset) else {
                continue;
            };
            if index.tokens[operator].text != "="
                || !is_errno_assignment_lhs(index, operator, shadows_errno)
            {
                continue;
            }
            let end = index
                .statement_range(fact.offset)
                .and_then(|range| {
                    (operator + 1..index.tokens.len()).find(|at| {
                        index.tokens[*at].start as usize >= range.end
                            || index.tokens[*at].text == ";"
                    })
                })
                .unwrap_or(index.tokens.len());
            let reset_to_zero = operator + 1 < end
                && evaluate_c_constant_integer(&index.tokens[operator + 1..end]) == Some(0);
            events.push((fact.offset, Event::ErrnoAssignment(reset_to_zero)));
        }
        for name_at in 0..index.tokens.len() {
            let token = &index.tokens[name_at];
            let offset = token.start as usize;
            if offset < function.body.start
                || offset >= function.body.end
                || !ERRNO_FUNCTIONS.contains(&token.text.as_str())
                || name_at > 0
                    && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->")
                || direct_call_expression(index, name_at).is_none()
            {
                continue;
            }
            events.push((offset, Event::ErrnoSettingCall(offset)));
        }
        for condition in syntax
            .nodes
            .iter()
            .filter_map(|node| node.condition.as_ref())
            .filter(|condition| {
                function.body.start <= condition.start && condition.end <= function.body.end
            })
        {
            let contains_errno = index.tokens.iter().any(|token| {
                condition.start <= token.start as usize
                    && token.end as usize <= condition.end
                    && ((!shadows_errno && token.text == "errno") || token.text == "_errno")
            });
            if contains_errno {
                events.push((condition.start, Event::ErrnoCheck));
            }
        }
        events.sort_by_key(|(offset, event)| {
            let priority = match event {
                Event::ErrnoAssignment(_) => 0,
                Event::ErrnoSettingCall(_) => 1,
                Event::ErrnoCheck => 2,
            };
            (*offset, priority)
        });

        let mut reset_to_zero = false;
        let mut unprepared_call = None;
        for (_, event) in events {
            match event {
                Event::ErrnoAssignment(is_zero) => {
                    reset_to_zero = is_zero;
                    unprepared_call = None;
                }
                Event::ErrnoSettingCall(offset) => {
                    unprepared_call = (!reset_to_zero).then_some(offset);
                    reset_to_zero = false;
                }
                Event::ErrnoCheck => {
                    if let Some(offset) = unprepared_call.take() {
                        offsets.push(offset);
                    }
                }
            }
        }
    }
    offsets
}

fn is_errno_assignment_lhs(
    index: &CExpressionIndex,
    operator: usize,
    shadows_errno: bool,
) -> bool {
    if !shadows_errno
        && operator > 0
        && index.tokens[operator - 1].kind == TokKind::Ident
        && index.tokens[operator - 1].text == "errno"
    {
        return true;
    }
    if operator == 0 || index.tokens[operator - 1].text != ")" {
        return false;
    }
    let Some(open) = index.matching_token_index(operator - 1) else {
        return false;
    };
    open > 1
        && index.tokens[open - 1].text == "_errno"
        && index.tokens[open - 2].text == "*"
}

fn const_storage_write_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    string_literal_only: bool,
) -> Vec<usize> {
    let initializer_assignments = named_initializer_separators(index, declarations);
    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let mut const_values = HashSet::new();
        let mut const_pointees = HashSet::new();
        let mut string_backed = HashSet::new();

        for parameter in declarations.parameters.iter().filter(|parameter| {
            function.parameters.start <= parameter.range.start
                && parameter.range.end <= function.parameters.end
        }) {
            let Some(name) = parameter.name.as_ref() else {
                continue;
            };
            let (base_const, _) = source_const_qualification(
                index,
                &parameter.range,
                name,
                &parameter.derived,
            );
            if base_const
                && parameter
                    .derived
                    .iter()
                    .any(|derived| matches!(derived, D::Pointer | D::Array { .. }))
            {
                const_pointees.insert(name.clone());
            }
        }
        let local_declarators = declarations
            .declarations
            .iter()
            .filter(|declaration| {
                function.body.start <= declaration.range.start
                    && declaration.range.end <= function.body.end
            })
            .flat_map(|declaration| {
                declaration
                    .declarators
                    .iter()
                    .map(move |declarator| (declaration, declarator))
            })
            .collect::<Vec<_>>();
        for (declaration, declarator) in &local_declarators {
            let Some(name) = declarator.name.as_ref() else {
                continue;
            };
            let (base_const, pointer_const) = source_const_qualification(
                index,
                &declaration.range,
                name,
                &declarator.derived,
            );
            if declarator
                .derived
                .iter()
                .any(|derived| matches!(derived, D::Pointer | D::Array { .. }))
            {
                if base_const {
                    const_pointees.insert(name.clone());
                }
                if pointer_const {
                    const_values.insert(name.clone());
                }
            } else if base_const {
                const_values.insert(name.clone());
            }
            if declarator
                .derived
                .iter()
                .any(|derived| matches!(derived, D::Pointer))
                && declarator.initializer.as_ref().is_some_and(|initializer| {
                    source_range_contains_string_literal(index, initializer)
                })
            {
                string_backed.insert(name.clone());
            }
        }

        // Preserve direct pointer aliases created by declarations. This mirrors the old
        // path-sensitive region identity without treating a reassignment of the pointer itself
        // as a write to the pointed-to storage.
        loop {
            let before = string_backed.len();
            for (_, declarator) in &local_declarators {
                let (Some(name), Some(initializer)) =
                    (declarator.name.as_ref(), declarator.initializer.as_ref())
                else {
                    continue;
                };
                if source_range_contains_identifier(index, initializer, &string_backed) {
                    string_backed.insert(name.clone());
                }
            }
            if string_backed.len() == before {
                break;
            }
        }

        for fact in index.facts.iter().filter(|fact| {
            function.body.start <= fact.offset
                && fact.offset < function.body.end
                && matches!(fact.kind, K::Assignment | K::Update)
                && !initializer_assignments.contains(&fact.offset)
        }) {
            let Some((start, end)) = write_target_token_range(index, fact) else {
                continue;
            };
            if string_literal_only {
                if let Some(offset) = write_to_readonly_string_offset(
                    index,
                    start,
                    end,
                    &string_backed,
                ) {
                    offsets.push(offset);
                }
            } else if let Some(offset) = write_to_const_storage_offset(
                index,
                start,
                end,
                &const_values,
                &const_pointees,
            ) {
                offsets.push(offset);
            }
        }
    }
    offsets
}

fn named_initializer_separators(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> HashSet<usize> {
    declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter(|declarator| declarator.name.is_some())
        .filter_map(|declarator| declarator.initializer.as_ref())
        .filter_map(|initializer| {
            index
                .tokens
                .iter()
                .rfind(|token| token.end as usize <= initializer.start && token.text == "=")
                .map(|token| token.start as usize)
        })
        .collect()
}

fn source_const_qualification(
    index: &CExpressionIndex,
    range: &std::ops::Range<usize>,
    name: &str,
    derived: &[D],
) -> (bool, bool) {
    let tokens = index
        .tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| {
            range.start <= token.start as usize && token.end as usize <= range.end
        })
        .collect::<Vec<_>>();
    let Some(name_at) = tokens
        .iter()
        .rposition(|(_, token)| token.kind == TokKind::Ident && token.text == name)
    else {
        return (false, false);
    };
    let first_pointer = tokens[..name_at]
        .iter()
        .position(|(_, token)| matches!(token.text.as_str(), "*" | "**"));
    let base_const = tokens[..name_at].iter().enumerate().any(|(at, (_, token))| {
        token.text == "const" && first_pointer.is_none_or(|pointer| at < pointer)
    });
    let pointer_const = derived
        .iter()
        .any(|item| matches!(item, D::Pointer | D::MemberPointer))
        && tokens[..name_at].iter().enumerate().any(|(at, (_, token))| {
            token.text == "const" && first_pointer.is_some_and(|pointer| at > pointer)
        });
    (base_const, pointer_const)
}

fn source_range_contains_string_literal(
    index: &CExpressionIndex,
    range: &std::ops::Range<usize>,
) -> bool {
    index.tokens.iter().any(|token| {
        range.start <= token.start as usize
            && token.end as usize <= range.end
            && token.kind == TokKind::StringLit
    })
}

fn source_range_contains_identifier(
    index: &CExpressionIndex,
    range: &std::ops::Range<usize>,
    names: &HashSet<String>,
) -> bool {
    index.tokens.iter().any(|token| {
        range.start <= token.start as usize
            && token.end as usize <= range.end
            && token.kind == TokKind::Ident
            && names.contains(&token.text)
    })
}

fn write_target_token_range(
    index: &CExpressionIndex,
    fact: &CExpressionFact,
) -> Option<(usize, usize)> {
    let operator = token_at_offset(index, fact.offset)?;
    match fact.kind {
        K::Assignment => {
            let statement = index.statement_range(fact.offset)?;
            let start = index
                .tokens
                .iter()
                .position(|token| token.start as usize >= statement.start)?;
            (start < operator).then_some((start, operator))
        }
        K::Update => {
            if index.tokens.get(operator + 1).is_some_and(|token| {
                token.kind == TokKind::Ident || matches!(token.text.as_str(), "*" | "(")
            }) {
                let end = (operator + 1..index.tokens.len())
                    .find(|at| {
                        matches!(index.tokens[*at].text.as_str(), ";" | ",")
                    })
                    .unwrap_or(index.tokens.len());
                (operator + 1 < end).then_some((operator + 1, end))
            } else {
                let statement = index.statement_range(fact.offset)?;
                let start = index
                    .tokens
                    .iter()
                    .position(|token| token.start as usize >= statement.start)?;
                (start < operator).then_some((start, operator))
            }
        }
        _ => None,
    }
}

fn write_to_readonly_string_offset(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
    string_backed: &HashSet<String>,
) -> Option<usize> {
    let has_indirection = index.tokens[start..end]
        .iter()
        .any(|token| matches!(token.text.as_str(), "[" | "*"));
    index.tokens[start..end]
        .iter()
        .find(|token| {
            token.kind == TokKind::StringLit
                || has_indirection
                    && token.kind == TokKind::Ident
                    && string_backed.contains(&token.text)
        })
        .map(|token| token.start as usize)
}

fn write_to_const_storage_offset(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
    const_values: &HashSet<String>,
    const_pointees: &HashSet<String>,
) -> Option<usize> {
    let has_indirection = index.tokens[start..end]
        .iter()
        .any(|token| matches!(token.text.as_str(), "[" | "*"));
    index.tokens[start..end]
        .iter()
        .find(|token| {
            token.kind == TokKind::Ident
                && (const_values.contains(&token.text)
                    || has_indirection && const_pointees.contains(&token.text))
        })
        .map(|token| token.start as usize)
}

fn signed_char_promotion_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        for declarator in &declaration.declarators {
            if !declarator.derived.is_empty()
                || !is_wider_integer_than_char(&canonical_type_text(&declaration.type_name))
            {
                continue;
            }
            let Some(initializer) = declarator.initializer.as_ref() else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            let (start, end) = trim_outer_group(index, start, end);
            if let Some(source_at) = direct_identifier_token(index, start, end) {
                if exact_operand_type(index, declarations, source_at)
                    .is_some_and(|ty| is_signed_character_type(&canonical_type_text(&ty)))
                {
                    offsets.push(index.tokens[source_at].start as usize);
                }
            }
        }
    }
    let initializer_assignments = named_initializer_separators(index, declarations);
    for fact in index.facts.iter().filter(|fact| {
        fact.kind == K::Assignment && !initializer_assignments.contains(&fact.offset)
    }) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = unwrap_left_operand(index, operator.saturating_sub(1)) else {
            continue;
        };
        let Some(destination) = exact_operand_type(index, declarations, left) else {
            continue;
        };
        if !is_wider_integer_than_char(&canonical_type_text(&destination)) {
            continue;
        }
        let end = index
            .statement_range(fact.offset)
            .and_then(|range| {
                (operator + 1..index.tokens.len()).find(|at| {
                    index.tokens[*at].start as usize >= range.end
                        || index.tokens[*at].text == ";"
                })
            })
            .unwrap_or(index.tokens.len());
        let (start, end) = trim_outer_group(index, operator + 1, end);
        let Some(source_at) = direct_identifier_token(index, start, end) else {
            continue;
        };
        if exact_operand_type(index, declarations, source_at)
            .is_some_and(|ty| is_signed_character_type(&canonical_type_text(&ty)))
        {
            offsets.push(index.tokens[source_at].start as usize);
        }
    }
    offsets
}

fn direct_identifier_token(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> Option<usize> {
    (end == start + 1 && index.tokens[start].kind == TokKind::Ident).then_some(start)
}

fn is_signed_character_type(ty: &str) -> bool {
    matches!(ty, "char" | "signed char")
}

fn is_wider_integer_than_char(ty: &str) -> bool {
    is_integer_type(ty) && !matches!(ty, "char" | "signed char" | "unsigned char" | "bool")
}

fn variable_array_invalid_sentinel_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    const INVALID_VLA_SIZE: i128 = 0x7fff_ffff;
    let mut offsets = Vec::new();
    let mut global_constants = HashMap::new();
    for declaration in declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.enclosing_function.is_none())
    {
        record_integer_declaration_values(index, declaration, &mut global_constants);
    }
    for (function_id, function) in declarations.functions.iter().enumerate() {
        let mut constants = global_constants.clone();
        let mut locals = declarations
            .declarations
            .iter()
            .filter(|declaration| {
                declaration.enclosing_function == Some(function_id)
                    && function.body.start <= declaration.range.start
                    && declaration.range.end <= function.body.end
            })
            .collect::<Vec<_>>();
        locals.sort_by_key(|declaration| declaration.range.start);
        for declaration in locals {
            for declarator in &declaration.declarators {
                for size in declarator.derived.iter().filter_map(|derived| match derived {
                    D::Array { size } => Some(size),
                    _ => None,
                }) {
                    let Some((start, end)) = token_range_for_source_range(index, size) else {
                        continue;
                    };
                    let (start, end) = trim_outer_group(index, start, end);
                    let Some(name_at) = direct_identifier_token(index, start, end) else {
                        continue;
                    };
                    if constants.get(&index.tokens[name_at].text) == Some(&INVALID_VLA_SIZE) {
                        offsets.push(declaration.range.start);
                    }
                }
            }
            record_integer_declaration_values(index, declaration, &mut constants);
        }
    }
    offsets
}

fn record_integer_declaration_values(
    index: &CExpressionIndex,
    declaration: &uniflow_parser_core::c_declarations::CDeclaration,
    constants: &mut HashMap<String, i128>,
) {
    for declarator in &declaration.declarators {
        let Some(name) = declarator.name.as_ref() else {
            continue;
        };
        let value = declarator
            .initializer
            .as_ref()
            .and_then(|initializer| token_range_for_source_range(index, initializer))
            .and_then(|(start, end)| evaluate_c_constant_integer(&index.tokens[start..end]));
        if let Some(value) = value {
            constants.insert(name.clone(), value);
        } else {
            constants.remove(name);
        }
    }
}

fn is_errno_name(token: &Token) -> bool {
    token.kind == TokKind::Ident
        && matches!(
            token.text.as_str(),
            "errno"
                | "EPERM" | "ENOENT" | "ESRCH" | "EINTR" | "EIO" | "ENXIO"
                | "E2BIG" | "ENOEXEC" | "EBADF" | "ECHILD" | "EAGAIN" | "ENOMEM"
                | "EACCES" | "EFAULT" | "ENOTBLK" | "EBUSY" | "EEXIST" | "EXDEV"
                | "ENODEV" | "ENOTDIR" | "EISDIR" | "EINVAL" | "ENFILE" | "EMFILE"
                | "ENOTTY" | "ETXTBSY" | "EFBIG" | "ENOSPC" | "ESPIPE" | "EROFS"
                | "EMLINK" | "EPIPE" | "EDOM" | "ERANGE" | "EDEADLK"
                | "ENAMETOOLONG" | "ENOLCK" | "ENOSYS" | "ENOTEMPTY" | "ELOOP"
                | "ENOMSG" | "EIDRM" | "ECHRNG" | "EL2NSYNC" | "EL3HLT" | "EL3RST"
                | "ELNRNG" | "EUNATCH" | "ENOCSI" | "EL2HLT" | "EBADE" | "EBADR"
                | "EXFULL" | "ENOANO" | "EBADRQC" | "EBADSLT" | "EBFONT" | "ENOSTR"
                | "ENODATA" | "ETIME" | "ENOSR" | "ENONET" | "ENOPKG" | "EREMOTE"
                | "ENOLINK" | "EADV" | "ESRMNT" | "ECOMM" | "EPROTO" | "EMULTIHOP"
                | "EDOTDOT" | "EBADMSG" | "EOVERFLOW" | "ENOTUNIQ" | "EBADFD"
                | "EREMCHG" | "ELIBACC" | "ELIBBAD" | "ELIBSCN" | "ELIBMAX"
                | "ELIBEXEC" | "EILSEQ" | "ERESTART" | "ESTRPIPE" | "EUSERS"
                | "ENOTSOCK" | "EDESTADDRREQ" | "EMSGSIZE" | "EPROTOTYPE"
                | "ENOPROTOOPT" | "EPROTONOSUPPORT" | "ESOCKTNOSUPPORT"
                | "EOPNOTSUPP" | "EPFNOSUPPORT" | "EAFNOSUPPORT" | "EADDRINUSE"
                | "EADDRNOTAVAIL" | "ENETDOWN" | "ENETUNREACH" | "ENETRESET"
                | "ECONNABORTED" | "ECONNRESET" | "ENOBUFS" | "EISCONN"
                | "ENOTCONN" | "ESHUTDOWN" | "ETOOMANYREFS" | "ETIMEDOUT"
                | "ECONNREFUSED" | "EHOSTDOWN" | "EHOSTUNREACH" | "EALREADY"
                | "EINPROGRESS" | "ESTALE" | "EUCLEAN" | "ENOTNAM" | "ENAVAIL"
                | "EISNAM" | "EREMOTEIO" | "EDQUOT" | "ENOMEDIUM" | "EMEDIUMTYPE"
                | "ECANCELED" | "ENOKEY" | "EKEYEXPIRED" | "EKEYREVOKED"
                | "EKEYREJECTED" | "EOWNERDEAD" | "ENOTRECOVERABLE"
        )
}

fn incompatible_enum_comparison_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            matches!(
                index.tokens[operator].text.as_str(),
                "==" | "!=" | "<" | "<=" | ">" | ">="
            )
            .then_some(())?;
            let left = operand_type(index, declarations, operator, false)?;
            let right = operand_type(index, declarations, operator, true)?;
            let has_enum = matches!(left, OperandType::Enum(_))
                || matches!(right, OperandType::Enum(_));
            (has_enum && left != right).then_some(fact.offset)
        })
        .collect()
}

fn enum_value_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            (index.tokens[operator].text == "=").then_some(())?;
            let left = operand_type(index, declarations, operator, false)?;
            let right = operand_type(index, declarations, operator, true)?;
            (!matches!(left, OperandType::Enum(_))
                && matches!(right, OperandType::Enum(_)))
            .then_some(fact.offset)
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OperandType {
    Enum(String),
    Bool,
    Float,
    SignedInt,
    UnsignedInt,
    Other,
}

fn token_at_offset(index: &CExpressionIndex, offset: usize) -> Option<usize> {
    index
        .tokens
        .iter()
        .position(|token| token.start as usize == offset)
}

fn operand_type(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    operator: usize,
    right: bool,
) -> Option<OperandType> {
    let token = if right {
        unwrap_right_operand(index, operator + 1)?
    } else {
        unwrap_left_operand(index, operator.checked_sub(1)?)?
    };
    Some(token_operand_type(index, declarations, token))
}

fn token_operand_type(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    token: usize,
) -> OperandType {
    if index.tokens[token].kind == TokKind::FloatLit {
        return OperandType::Float;
    }
    if index.tokens[token].kind == TokKind::IntLit {
        return if index.tokens[token]
            .text
            .trim_end_matches(|character: char| matches!(character, 'l' | 'L'))
            .ends_with(['u', 'U'])
        {
            OperandType::UnsignedInt
        } else {
            OperandType::SignedInt
        };
    }
    if index.tokens[token].kind != TokKind::Ident {
        return OperandType::Other;
    }
    let name = &index.tokens[token].text;
    if matches!(name.as_str(), "true" | "false") {
        return OperandType::Bool;
    }
    if let Some(enumerator) = declarations
        .enumerators
        .iter()
        .filter(|enumerator| {
            enumerator.name == *name
                && enumerator.range.start <= index.tokens[token].start as usize
        })
        .max_by_key(|enumerator| enumerator.range.start)
    {
        return OperandType::Enum(
            enumerator
                .enum_name
                .clone()
                .unwrap_or_else(|| format!("@{}", enumerator.enum_range.start)),
        );
    }
    if let Some(parameter) = declarations
        .parameters
        .iter()
        .filter(|parameter| {
            parameter.name.as_deref() == Some(name)
                && parameter.range.start <= index.tokens[token].start as usize
        })
        .max_by_key(|parameter| parameter.range.start)
    {
        return declared_operand_type(declarations, &parameter.type_name);
    }
    let declaration = declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.range.start <= index.tokens[token].start as usize)
        .filter(|declaration| {
            declaration
                .declarators
                .iter()
                .any(|declarator| declarator.name.as_deref() == Some(name))
        })
        .max_by_key(|declaration| declaration.range.start);
    match declaration {
        Some(declaration) => declared_operand_type(declarations, &declaration.type_name),
        None => OperandType::Other,
    }
}

fn declared_operand_type(declarations: &CDeclarationIndex, type_name: &str) -> OperandType {
    let normalized = type_name.split_whitespace().collect::<Vec<_>>().join(" ");
    if matches!(normalized.as_str(), "bool" | "_Bool") {
        OperandType::Bool
    } else if matches!(normalized.as_str(), "float" | "double" | "long double") {
        OperandType::Float
    } else if normalized.split_whitespace().any(|part| part == "unsigned") {
        OperandType::UnsignedInt
    } else if matches!(
        normalized.as_str(),
        "char" | "signed char" | "short" | "short int" | "signed short"
            | "signed short int" | "int" | "signed" | "signed int" | "long"
            | "long int" | "signed long" | "signed long int" | "long long"
            | "long long int" | "signed long long" | "signed long long int"
    ) {
        OperandType::SignedInt
    } else {
        enum_type_name(declarations, type_name)
            .map(OperandType::Enum)
            .unwrap_or(OperandType::Other)
    }
}

fn enum_type_name(declarations: &CDeclarationIndex, type_name: &str) -> Option<String> {
    let normalized = type_name
        .split_whitespace()
        .filter(|part| !matches!(*part, "const" | "volatile" | "enum"))
        .collect::<Vec<_>>()
        .join("")
        .trim_matches(':')
        .to_string();
    declarations
        .aggregates
        .iter()
        .filter(|aggregate| aggregate.kind == "enum")
        .filter_map(|aggregate| aggregate.name.as_ref())
        .find(|name| normalized == name.as_str() || normalized.ends_with(&format!("::{name}")))
        .cloned()
}

fn unwrap_left_operand(index: &CExpressionIndex, mut at: usize) -> Option<usize> {
    while index.tokens.get(at).is_some_and(|token| token.text == ")") {
        let open = index.matching_token_index(at)?;
        if open + 2 != at {
            return None;
        }
        at = open + 1;
    }
    index.tokens.get(at)?;
    Some(at)
}

fn unwrap_right_operand(index: &CExpressionIndex, mut at: usize) -> Option<usize> {
    while index.tokens.get(at).is_some_and(|token| token.text == "(") {
        let close = index.matching_token_index(at)?;
        if at + 2 != close {
            return None;
        }
        at += 1;
    }
    while index.tokens.get(at + 1).is_some_and(|token| token.text == "::")
        && index.tokens.get(at + 2).is_some()
    {
        at += 2;
    }
    index.tokens.get(at)?;
    Some(at)
}

fn enum_cast_outside_range_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let ranges = enum_value_ranges(declarations);
    let mut offsets = Vec::new();
    for open in 0..index.tokens.len() {
        if index.tokens[open].text != "(" {
            continue;
        }
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        let Some(enum_name) = enum_name_from_type_tokens(&index.tokens[open + 1..close], &ranges)
        else {
            continue;
        };
        let Some((minimum, maximum, scoped)) = ranges.get(&enum_name) else {
            continue;
        };
        if *scoped || close + 1 >= index.tokens.len() {
            continue;
        }
        if operand_type(index, declarations, close, true)
            == Some(OperandType::Enum(enum_name.clone()))
        {
            continue;
        }
        let value = cast_operand_tokens(index, close + 1)
            .and_then(evaluate_c_constant_integer);
        if value.is_none_or(|value| value < *minimum || value > *maximum) {
            offsets.push(index.tokens[open].start as usize);
        }
    }
    for at in 0..index.tokens.len() {
        if !matches!(
            index.tokens[at].text.as_str(),
            "static_cast" | "dynamic_cast" | "reinterpret_cast" | "const_cast"
        ) || index.tokens.get(at + 1).is_none_or(|token| token.text != "<")
        {
            continue;
        }
        let Some(type_end) = (at + 2..index.tokens.len())
            .find(|candidate| index.tokens[*candidate].text == ">")
        else {
            continue;
        };
        let Some(enum_name) = enum_name_from_type_tokens(&index.tokens[at + 2..type_end], &ranges)
        else {
            continue;
        };
        let Some((minimum, maximum, scoped)) = ranges.get(&enum_name) else {
            continue;
        };
        if *scoped || index.tokens.get(type_end + 1).is_none_or(|token| token.text != "(") {
            continue;
        }
        let Some(argument_end) = index.matching_token_index(type_end + 1) else {
            continue;
        };
        let argument = &index.tokens[type_end + 2..argument_end];
        let same_enum = argument.len() == 1
            && operand_type(index, declarations, type_end + 1, true)
                == Some(OperandType::Enum(enum_name));
        if same_enum {
            continue;
        }
        let value = evaluate_c_constant_integer(argument);
        if value.is_none_or(|value| value < *minimum || value > *maximum) {
            offsets.push(index.tokens[at].start as usize);
        }
    }
    offsets
}

fn boolean_binary_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    operators: &[&str],
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            operators
                .contains(&index.tokens[operator].text.as_str())
                .then_some(())?;
            let left = operand_type(index, declarations, operator, false);
            let right = operand_type(index, declarations, operator, true);
            (left == Some(OperandType::Bool) || right == Some(OperandType::Bool))
                .then_some(fact.offset)
        })
        .collect()
}

fn boolean_update_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Update)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            let operand = if index.tokens.get(operator + 1).is_some_and(|token| {
                token.kind == TokKind::Ident
            }) {
                operator + 1
            } else {
                operator.checked_sub(1)?
            };
            (token_operand_type(index, declarations, operand) == OperandType::Bool)
                .then_some(index.tokens[operand].start as usize)
        })
        .collect()
}

fn comparison_type_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    operators: &[&str],
    predicate: impl Fn(&OperandType, &OperandType) -> bool,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            operators
                .contains(&index.tokens[operator].text.as_str())
                .then_some(())?;
            let left = operand_type(index, declarations, operator, false)?;
            let right = operand_type(index, declarations, operator, true)?;
            predicate(&left, &right).then_some(fact.offset)
        })
        .collect()
}

fn unsigned_zero_comparison_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            let left_token = unwrap_left_operand(index, operator.checked_sub(1)?)?;
            let right_token = unwrap_right_operand(index, operator + 1)?;
            let left = token_operand_type(index, declarations, left_token);
            let right = token_operand_type(index, declarations, right_token);
            let left_zero = token_integer_value(&index.tokens[left_token]) == Some(0);
            let right_zero = token_integer_value(&index.tokens[right_token]) == Some(0);
            let matches = match index.tokens[operator].text.as_str() {
                ">" | "<=" => left_zero && right == OperandType::UnsignedInt,
                "<" | ">=" => right_zero && left == OperandType::UnsignedInt,
                _ => false,
            };
            matches.then_some(fact.offset)
        })
        .collect()
}

fn mixed_signedness_comparison_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Binary)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            matches!(
                index.tokens[operator].text.as_str(),
                "==" | "!=" | "<" | "<=" | ">" | ">="
            )
            .then_some(())?;
            let left_token = unwrap_left_operand(index, operator.checked_sub(1)?)?;
            let right_token = unwrap_right_operand(index, operator + 1)?;
            if is_literal_operand(&index.tokens[left_token])
                || is_literal_operand(&index.tokens[right_token])
            {
                return None;
            }
            let left = token_operand_type(index, declarations, left_token);
            let right = token_operand_type(index, declarations, right_token);
            matches!(
                (left, right),
                (OperandType::SignedInt, OperandType::UnsignedInt)
                    | (OperandType::UnsignedInt, OperandType::SignedInt)
            )
            .then_some(fact.offset)
        })
        .collect()
}

fn incomplete_enum_switch_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for switch in syntax
        .nodes
        .iter()
        .filter(|node| node.kind == JavaSyntaxKind::Switch)
    {
        let Some(condition) = switch.condition.clone() else {
            continue;
        };
        let condition_tokens = syntax.tokens_in(condition).collect::<Vec<_>>();
        let Some(condition_token) = condition_tokens
            .iter()
            .find(|token| token.kind == TokKind::Ident)
        else {
            continue;
        };
        let Some(token_at) = index.tokens.iter().position(|token| {
            token.start == condition_token.start && token.end == condition_token.end
        }) else {
            continue;
        };
        let OperandType::Enum(enum_name) = token_operand_type(index, declarations, token_at) else {
            continue;
        };
        let enumerator_count = declarations
            .enumerators
            .iter()
            .filter(|enumerator| enumerator.enum_name.as_deref() == Some(enum_name.as_str()))
            .count();
        if enumerator_count == 0 {
            continue;
        }
        let groups = syntax.nodes.iter().filter(|group| {
            group.kind == JavaSyntaxKind::SwitchGroup
                && switch.range.start < group.range.start
                && group.range.end <= switch.range.end
                && !syntax.nodes.iter().any(|nested| {
                    nested.kind == JavaSyntaxKind::Switch
                        && switch.range.start < nested.range.start
                        && nested.range.end <= switch.range.end
                        && nested.range.start < group.range.start
                        && group.range.end <= nested.range.end
                })
        });
        let (mut cases, mut has_default) = (0usize, false);
        for group in groups {
            if group.label_is_case {
                cases += 1;
            } else {
                has_default = true;
            }
        }
        if !has_default && cases < enumerator_count {
            offsets.push(switch.range.start);
        }
    }
    offsets
}

fn update_operand_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for fact in index.facts.iter().filter(|fact| fact.kind == K::Update) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        let (mut start, mut end) = if index
            .tokens
            .get(operator + 1)
            .is_some_and(|token| token.kind == TokKind::Ident)
        {
            (operator, operator + 2)
        } else if operator > 0 && index.tokens[operator - 1].kind == TokKind::Ident {
            (operator - 1, operator + 1)
        } else {
            continue;
        };
        loop {
            if start == 0 || index.tokens[start - 1].text != "(" {
                break;
            }
            let open = start - 1;
            if index.matching_token_index(open) != Some(end)
                || is_call_open(index, open)
            {
                break;
            }
            start = open;
            end += 1;
        }
        let direct_binary = start > 0 && is_non_assignment_binary(&index.tokens[start - 1].text)
            || index
                .tokens
                .get(end)
                .is_some_and(|token| is_non_assignment_binary(&token.text));
        let direct_call_argument = (0..start).rev().any(|open| {
            if index.tokens[open].text != "(" || !is_call_open(index, open) {
                return false;
            }
            let Some(close) = index.matching_token_index(open) else {
                return false;
            };
            if end > close {
                return false;
            }
            let mut segment_start = open + 1;
            let mut cursor = segment_start;
            while cursor < close {
                if matches!(index.tokens[cursor].text.as_str(), "(" | "[" | "{") {
                    cursor = index
                        .matching_token_index(cursor)
                        .map_or(cursor + 1, |mate| mate + 1);
                    continue;
                }
                if index.tokens[cursor].text == "," {
                    if segment_start == start && cursor == end {
                        return true;
                    }
                    segment_start = cursor + 1;
                }
                cursor += 1;
            }
            segment_start == start && close == end
        });
        if direct_binary || direct_call_argument {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn redundant_void_cast_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut void_functions = declarations
        .functions
        .iter()
        .filter(|function| function.returns_void)
        .map(|function| function.name.as_str())
        .collect::<HashSet<_>>();
    void_functions.extend(
        declarations
            .declarations
            .iter()
            .filter(|declaration| declaration.type_name.trim() == "void")
            .flat_map(|declaration| &declaration.declarators)
            .filter(|declarator| {
                declarator
                    .derived
                    .iter()
                    .any(|derived| matches!(derived, D::Function { .. }))
            })
            .filter_map(|declarator| declarator.name.as_deref()),
    );
    let mut offsets = Vec::new();
    for open in 0..index.tokens.len() {
        if index.tokens[open].text != "(" {
            continue;
        }
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        if close != open + 2 || index.tokens[open + 1].text != "void" {
            continue;
        }
        if let Some((name, _)) = direct_call_expression(index, close + 1) {
            if void_functions.contains(name) {
                offsets.push(index.tokens[open].start as usize);
            }
        }
    }
    for at in 0..index.tokens.len() {
        if index.tokens[at].text != "static_cast"
            || index.tokens.get(at + 1).is_none_or(|token| token.text != "<")
            || index.tokens.get(at + 2).is_none_or(|token| token.text != "void")
            || index.tokens.get(at + 3).is_none_or(|token| token.text != ">")
            || index.tokens.get(at + 4).is_none_or(|token| token.text != "(")
        {
            continue;
        }
        let Some(argument_close) = index.matching_token_index(at + 4) else {
            continue;
        };
        if let Some((name, call_close)) = direct_call_expression(index, at + 5) {
            if call_close + 1 == argument_close && void_functions.contains(name) {
                offsets.push(index.tokens[at].start as usize);
            }
        }
    }
    offsets
}

#[derive(Clone, Debug)]
struct ExplicitCastFact {
    offset: usize,
    destination: String,
    source: String,
    kind: ExplicitCastKind,
    source_is_zero: bool,
    source_is_constant: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExplicitCastKind {
    CStyle,
    Static,
    OtherNamed,
}

fn explicit_cast_facts(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<ExplicitCastFact> {
    let known_names = declarations
        .aggregates
        .iter()
        .filter_map(|aggregate| aggregate.name.as_deref())
        .chain(
            declarations
                .declarations
                .iter()
                .filter(|declaration| declaration.storage.iter().any(|item| item == "typedef"))
                .flat_map(|declaration| &declaration.declarators)
                .filter_map(|declarator| declarator.name.as_deref()),
        )
        .collect::<HashSet<_>>();
    let mut casts = Vec::new();
    for open in 0..index.tokens.len() {
        if index.tokens[open].text != "(" {
            continue;
        }
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        let Some(destination) = cast_destination_type(&index.tokens[open + 1..close], &known_names)
        else {
            continue;
        };
        let Some(source_at) = unwrap_right_operand(index, close + 1) else {
            continue;
        };
        let Some(source) = exact_operand_type(index, declarations, source_at) else {
            continue;
        };
        casts.push(ExplicitCastFact {
            offset: index.tokens[open].start as usize,
            destination,
            source,
            kind: ExplicitCastKind::CStyle,
            source_is_zero: token_integer_value(&index.tokens[source_at]) == Some(0),
            source_is_constant: is_literal_operand(&index.tokens[source_at]),
        });
    }
    for at in 0..index.tokens.len() {
        if !matches!(
            index.tokens[at].text.as_str(),
            "static_cast" | "dynamic_cast" | "reinterpret_cast" | "const_cast"
        ) || index.tokens.get(at + 1).is_none_or(|token| token.text != "<")
        {
            continue;
        }
        let Some(type_end) = (at + 2..index.tokens.len())
            .find(|candidate| index.tokens[*candidate].text == ">")
        else {
            continue;
        };
        let Some(destination) =
            cast_destination_type(&index.tokens[at + 2..type_end], &known_names)
        else {
            continue;
        };
        if index.tokens.get(type_end + 1).is_none_or(|token| token.text != "(") {
            continue;
        }
        let Some(argument_end) = index.matching_token_index(type_end + 1) else {
            continue;
        };
        if type_end + 3 != argument_end {
            continue;
        }
        let Some(source) = exact_operand_type(index, declarations, type_end + 2) else {
            continue;
        };
        casts.push(ExplicitCastFact {
            offset: index.tokens[at].start as usize,
            destination,
            source,
            kind: if index.tokens[at].text == "static_cast" {
                ExplicitCastKind::Static
            } else {
                ExplicitCastKind::OtherNamed
            },
            source_is_zero: token_integer_value(&index.tokens[type_end + 2]) == Some(0),
            source_is_constant: is_literal_operand(&index.tokens[type_end + 2]),
        });
    }
    casts
}

fn cast_destination_type(tokens: &[Token], known_names: &HashSet<&str>) -> Option<String> {
    let mut saw_type = false;
    let valid = tokens.iter().all(|token| match token.text.as_str() {
        "const" | "volatile" | "restrict" | "*" | "&" | "&&" | "::" | "enum"
        | "struct" | "union" | "class" => true,
        text if token.kind == TokKind::Ident
            && (is_builtin_type_word(text) || known_names.contains(text)) =>
        {
            saw_type = true;
            true
        }
        _ => false,
    });
    (valid && saw_type).then(|| {
        canonical_type_text(
            &tokens
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        )
    })
}

fn exact_operand_type(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    token: usize,
) -> Option<String> {
    let value = &index.tokens[token];
    match value.kind {
        TokKind::IntLit => {
            let lower = value.text.to_ascii_lowercase();
            return Some(if lower.ends_with('u') || lower.ends_with("ul") || lower.ends_with("ull") {
                "unsigned int".to_string()
            } else {
                "int".to_string()
            });
        }
        TokKind::FloatLit => {
            return Some(if value.text.ends_with(['f', 'F']) {
                "float".to_string()
            } else {
                "double".to_string()
            });
        }
        TokKind::StringLit if value.text.starts_with('\'') => return Some("char".to_string()),
        TokKind::StringLit => return Some("char*".to_string()),
        TokKind::Ident if matches!(value.text.as_str(), "true" | "false") => {
            return Some("bool".to_string())
        }
        TokKind::Ident => {}
        _ => return None,
    }
    if let Some(enumerator) = declarations
        .enumerators
        .iter()
        .filter(|enumerator| enumerator.name == value.text && enumerator.range.start <= value.start as usize)
        .max_by_key(|enumerator| enumerator.range.start)
    {
        return Some(format!(
            "enum:{}",
            enumerator
                .enum_name
                .as_deref()
                .unwrap_or("<anonymous>")
        ));
    }
    if let Some(parameter) = declarations
        .parameters
        .iter()
        .filter(|parameter| {
            parameter.name.as_deref() == Some(value.text.as_str())
                && parameter.range.start <= value.start as usize
        })
        .max_by_key(|parameter| parameter.range.start)
    {
        return Some(type_with_derived(&parameter.type_name, &parameter.derived));
    }
    declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.range.start <= value.start as usize)
        .filter_map(|declaration| {
            declaration
                .declarators
                .iter()
                .find(|declarator| declarator.name.as_deref() == Some(value.text.as_str()))
                .map(|declarator| (declaration, declarator))
        })
        .max_by_key(|(declaration, _)| declaration.range.start)
        .map(|(declaration, declarator)| type_with_derived(&declaration.type_name, &declarator.derived))
}

fn type_with_derived(type_name: &str, derived: &[D]) -> String {
    let mut ty = canonical_type_text(type_name);
    for derived in derived {
        match derived {
            D::Pointer | D::MemberPointer => ty.push('*'),
            D::Array { .. } => ty.push_str("[]"),
            D::Function { .. } => {}
        }
    }
    ty
}

fn canonical_type_text(type_name: &str) -> String {
    let compact = type_name
        .split_whitespace()
        .filter(|part| !matches!(*part, "const" | "volatile" | "restrict" | "enum" | "struct" | "union" | "class"))
        .collect::<String>();
    let pointer_count = compact.chars().filter(|character| *character == '*').count();
    let base = compact.replace(['*', '&'], "");
    let canonical = match base.as_str() {
        "signed" | "signedint" | "int" => "int",
        "unsigned" | "unsignedint" => "unsigned int",
        "signedchar" => "signed char",
        "unsignedchar" => "unsigned char",
        "short" | "shortint" | "signedshort" | "signedshortint" => "short",
        "unsignedshort" | "unsignedshortint" => "unsigned short",
        "long" | "longint" | "signedlong" | "signedlongint" => "long",
        "unsignedlong" | "unsignedlongint" => "unsigned long",
        "longlong" | "longlongint" | "signedlonglong" | "signedlonglongint" => "long long",
        "unsignedlonglong" | "unsignedlonglongint" => "unsigned long long",
        other => other,
    };
    format!("{canonical}{}", "*".repeat(pointer_count))
}

fn is_builtin_type_word(word: &str) -> bool {
    matches!(
        word,
        "void" | "char" | "short" | "int" | "long" | "float" | "double" | "signed"
            | "unsigned" | "bool" | "_Bool" | "wchar_t" | "char8_t" | "char16_t"
            | "char32_t" | "size_t" | "ptrdiff_t"
    )
}

fn is_pointer_type(ty: &str) -> bool {
    ty.ends_with('*')
}

fn is_integer_type(ty: &str) -> bool {
    matches!(
        ty,
        "char" | "signed char" | "unsigned char" | "short" | "unsigned short" | "int"
            | "unsigned int" | "long" | "unsigned long" | "long long"
            | "unsigned long long" | "bool"
    )
}

fn unsafe_pointer_cast(destination: &str, source: &str) -> bool {
    let destination_pointer = is_pointer_type(destination);
    let source_pointer = is_pointer_type(source);
    if destination_pointer && source_pointer {
        return destination != "void*"
            && source != "void*"
            && destination.trim_end_matches('*') != source.trim_end_matches('*');
    }
    destination_pointer && destination != "void*" && is_integer_type(source)
        || source_pointer && source != "void*" && is_integer_type(destination)
}

fn distinct_record_pointer_types(
    declarations: &CDeclarationIndex,
    destination: &str,
    source: &str,
) -> bool {
    if !is_pointer_type(destination) || !is_pointer_type(source) {
        return false;
    }
    let destination_record = destination.trim_end_matches('*').trim_matches(':');
    let source_record = source.trim_end_matches('*').trim_matches(':');
    destination_record != source_record
        && declarations.aggregates.iter().any(|aggregate| {
            matches!(aggregate.kind.as_str(), "class" | "struct")
                && aggregate.name.as_deref() == Some(destination_record)
        })
        && declarations.aggregates.iter().any(|aggregate| {
            matches!(aggregate.kind.as_str(), "class" | "struct")
                && aggregate.name.as_deref() == Some(source_record)
        })
}

fn direct_call_expression(index: &CExpressionIndex, name_at: usize) -> Option<(&str, usize)> {
    let name = index.tokens.get(name_at)?;
    if name.kind != TokKind::Ident
        || index
            .tokens
            .get(name_at + 1)
            .is_none_or(|token| token.text != "(")
    {
        return None;
    }
    Some((
        name.text.as_str(),
        index.matching_token_index(name_at + 1)?,
    ))
}

fn is_call_open(index: &CExpressionIndex, open: usize) -> bool {
    open > 0
        && (index.tokens[open - 1].kind == TokKind::Ident
            || matches!(index.tokens[open - 1].text.as_str(), ")" | "]"))
}

fn is_non_assignment_binary(operator: &str) -> bool {
    matches!(
        operator,
        "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "<" | "<=" | ">"
            | ">=" | "==" | "!=" | "&" | "|" | "^" | "&&" | "||"
    )
}

fn token_integer_value(token: &Token) -> Option<i128> {
    (token.kind == TokKind::IntLit)
        .then(|| parse_c_integer(&token.text))
        .flatten()
}

fn is_literal_operand(token: &Token) -> bool {
    matches!(
        token.kind,
        TokKind::IntLit | TokKind::FloatLit | TokKind::StringLit
    )
}

fn enum_name_from_type_tokens(
    tokens: &[Token],
    ranges: &HashMap<String, (i128, i128, bool)>,
) -> Option<String> {
    let normalized = tokens
        .iter()
        .filter(|token| !matches!(token.text.as_str(), "const" | "volatile" | "enum"))
        .map(|token| token.text.as_str())
        .collect::<String>()
        .trim_matches(':')
        .to_string();
    ranges
        .keys()
        .find(|name| normalized == name.as_str() || normalized.ends_with(&format!("::{name}")))
        .cloned()
}

fn cast_operand_tokens(index: &CExpressionIndex, at: usize) -> Option<&[Token]> {
    if index.tokens.get(at)?.text == "(" {
        let close = index.matching_token_index(at)?;
        return Some(&index.tokens[at..=close]);
    }
    let end = if matches!(index.tokens[at].text.as_str(), "+" | "-" | "!" | "~") {
        at + 2
    } else {
        at + 1
    };
    (end <= index.tokens.len()).then_some(&index.tokens[at..end])
}

fn enum_value_ranges(
    declarations: &CDeclarationIndex,
) -> HashMap<String, (i128, i128, bool)> {
    let mut ranges = HashMap::new();
    let mut group_start = 0usize;
    while group_start < declarations.enumerators.len() {
        let enum_range = declarations.enumerators[group_start].enum_range.clone();
        let group_end = declarations.enumerators[group_start..]
            .iter()
            .position(|enumerator| enumerator.enum_range != enum_range)
            .map_or(declarations.enumerators.len(), |relative| group_start + relative);
        let group = &declarations.enumerators[group_start..group_end];
        let mut names = HashMap::<String, i128>::new();
        let mut previous = None::<i128>;
        let mut values = Vec::new();
        for enumerator in group {
            let value = if let Some(initializer) = &enumerator.initializer {
                let mut tokens = declarations
                    .tokens_in(initializer.clone())
                    .cloned()
                    .collect::<Vec<_>>();
                for token in &mut tokens {
                    if let Some(value) = names.get(&token.text) {
                        token.kind = TokKind::IntLit;
                        token.text = value.to_string();
                    }
                }
                evaluate_c_constant_integer(&tokens)
            } else {
                previous.map_or(Some(0), |value| value.checked_add(1))
            };
            if let Some(value) = value {
                names.insert(enumerator.name.clone(), value);
                values.push(value);
            }
            previous = value;
        }
        if let (Some(name), Some(minimum), Some(maximum)) = (
            group[0].enum_name.clone(),
            values.iter().min(),
            values.iter().max(),
        ) {
            ranges.insert(name, (*minimum, *maximum, group[0].scoped));
        }
        group_start = group_end;
    }
    ranges
}

fn direct_assignment_in_sizeof_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for fact in index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment && fact.inside_sizeof)
    {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        let Some((mut begin, mut end, sizeof_offset)) = index
            .tokens
            .iter()
            .enumerate()
            .filter(|(at, token)| {
                token.text == "(" && index.matching_token_index(*at).is_some_and(|close| {
                    *at < operator
                        && operator < close
                        && index.tokens.get(at.wrapping_sub(1)).is_some_and(|previous| {
                            matches!(previous.text.as_str(), "sizeof" | "__sizeof__")
                        })
                })
            })
            .filter_map(|(open, _)| {
                index.matching_token_index(open).map(|close| {
                    (open + 1, close, index.tokens[open - 1].start as usize)
                })
            })
            .min_by_key(|(begin, end, _)| end - begin)
        else {
            continue;
        };
        loop {
            if begin < end
                && index.tokens[begin].text == "("
                && index.matching_token_index(begin) == Some(end - 1)
            {
                begin += 1;
                end -= 1;
            } else {
                break;
            }
        }
        let mut cursor = begin;
        let mut root_assignment = None;
        while cursor < end {
            if matches!(index.tokens[cursor].text.as_str(), "(" | "[" | "{") {
                cursor = index.matching_token_index(cursor).map_or(cursor + 1, |close| close + 1);
                continue;
            }
            if matches!(
                index.tokens[cursor].text.as_str(),
                "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=" | "&=" | "^=" | "|="
            ) {
                root_assignment = Some(cursor);
                break;
            }
            cursor += 1;
        }
        if root_assignment == Some(operator) {
            offsets.push(sizeof_offset);
        }
    }
    offsets
}

fn side_effecting_sizeof_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for keyword in 0..index.tokens.len() {
        if !matches!(index.tokens[keyword].text.as_str(), "sizeof" | "__sizeof__") {
            continue;
        }
        let Some(open) = index.tokens.get(keyword + 1).filter(|token| token.text == "(") else {
            continue;
        };
        let open_at = keyword + 1;
        let Some(close) = index.matching_token_index(open_at) else {
            continue;
        };
        if index.facts.iter().any(|fact| {
            matches!(fact.kind, K::Assignment | K::Update)
                && open.end as usize <= fact.offset
                && fact.offset < index.tokens[close].start as usize
        }) {
            offsets.push(
                index
                    .tokens
                    .get(open_at + 1)
                    .map_or(index.tokens[keyword].start as usize, |token| token.start as usize),
            );
        }
    }
    offsets
}

fn explicit_char_string_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        for declarator in &declaration.declarators {
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let ty = type_with_derived(&declaration.type_name, &declarator.derived);
            if !is_explicit_char_storage(&ty) {
                continue;
            }
            let tokens = index
                .tokens
                .iter()
                .filter(|token| {
                    initializer.start <= token.start as usize
                        && token.end as usize <= initializer.end
                })
                .collect::<Vec<_>>();
            if let [literal] = tokens.as_slice() {
                if literal.kind == TokKind::StringLit && literal.text.starts_with('"') {
                    offsets.push(literal.start as usize);
                }
            }
        }
    }
    for fact in index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment)
    {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = unwrap_left_operand(index, operator.saturating_sub(1)) else {
            continue;
        };
        let Some(right) = unwrap_right_operand(index, operator + 1) else {
            continue;
        };
        if exact_operand_type(index, declarations, left)
            .is_some_and(|ty| is_explicit_char_storage(&ty))
            && index.tokens[right].kind == TokKind::StringLit
            && index.tokens[right].text.starts_with('"')
        {
            offsets.push(index.tokens[right].start as usize);
        }
    }
    offsets
}

fn is_explicit_char_storage(ty: &str) -> bool {
    matches!(
        ty,
        "signedchar*" | "unsignedchar*" | "signedchar[]" | "unsignedchar[]"
            | "signed char*" | "unsigned char*" | "signed char[]" | "unsigned char[]"
    )
}

fn signed_odd_even_offsets(index: &CExpressionIndex, syntax: &JavaSyntax) -> Vec<usize> {
    syntax
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind,
                JavaSyntaxKind::If
                    | JavaSyntaxKind::While
                    | JavaSyntaxKind::For
                    | JavaSyntaxKind::Do
            )
        })
        .filter_map(|node| node.condition.as_ref())
        .filter_map(|condition| {
            let start = index
                .tokens
                .iter()
                .position(|token| token.start as usize >= condition.start)?;
            let end = index
                .tokens
                .iter()
                .position(|token| token.start as usize >= condition.end)
                .unwrap_or(index.tokens.len());
            (start < end && is_signed_odd_even_condition(index, start, end))
                .then_some(index.tokens[start].start as usize)
        })
        .collect()
}

fn is_signed_odd_even_condition(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    let (expression_start, expression_end) = trim_outer_group(index, start, end);
    let Some(equality) = root_operator(index, expression_start, expression_end, &["==", "!="])
    else {
        return false;
    };
    let left = trim_outer_group(index, expression_start, equality);
    let right = trim_outer_group(index, equality + 1, expression_end);
    (is_bit_one_expression(index, left.0, left.1)
        && is_zero_or_one_literal(index, right.0, right.1))
        || (is_bit_one_expression(index, right.0, right.1)
            && is_zero_or_one_literal(index, left.0, left.1))
}

fn is_bit_one_expression(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    let Some(operator) = root_operator(index, start, end, &["&"]) else {
        return false;
    };
    let left = trim_outer_group(index, start, operator);
    let right = trim_outer_group(index, operator + 1, end);
    (is_one_literal(index, left.0, left.1) && !is_integer_literal(index, right.0, right.1))
        || (is_one_literal(index, right.0, right.1)
            && !is_integer_literal(index, left.0, left.1))
}

fn is_zero_or_one_literal(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    end == start + 1
        && matches!(token_integer_value(&index.tokens[start]), Some(0 | 1))
}

fn is_one_literal(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    end == start + 1 && token_integer_value(&index.tokens[start]) == Some(1)
}

fn is_integer_literal(index: &CExpressionIndex, start: usize, end: usize) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    end == start + 1 && index.tokens[start].kind == TokKind::IntLit
}

fn trim_outer_group(index: &CExpressionIndex, mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end
        && index.tokens[start].text == "("
        && index.matching_token_index(start) == Some(end - 1)
    {
        start += 1;
        end -= 1;
    }
    (start, end)
}

fn root_operator(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
    operators: &[&str],
) -> Option<usize> {
    let mut depth = 0usize;
    let mut found = None;
    for at in start..end {
        match index.tokens[at].text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth = depth.saturating_sub(1),
            operator if depth == 0 && operators.contains(&operator) => {
                if found.is_some() {
                    return None;
                }
                found = Some(at);
            }
            _ => {}
        }
    }
    found
}

fn constant_allocation_length_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let known_names = declarations
        .aggregates
        .iter()
        .filter_map(|aggregate| aggregate.name.as_deref())
        .chain(
            declarations
                .declarations
                .iter()
                .filter(|declaration| declaration.storage.iter().any(|item| item == "typedef"))
                .flat_map(|declaration| &declaration.declarators)
                .filter_map(|declarator| declarator.name.as_deref()),
        )
        .collect::<HashSet<_>>();
    let mut offsets = Vec::new();
    for cast_open in 0..index.tokens.len() {
        if index.tokens[cast_open].text != "(" {
            continue;
        }
        let Some(cast_close) = index.matching_token_index(cast_open) else {
            continue;
        };
        let Some(destination) =
            cast_destination_type(&index.tokens[cast_open + 1..cast_close], &known_names)
        else {
            continue;
        };
        if !is_pointer_type(&destination) {
            continue;
        }
        let Some((callee, call_close)) = direct_call_expression(index, cast_close + 1) else {
            continue;
        };
        let wanted_argument = match callee {
            "malloc" => 0,
            "calloc" | "realloc" => 1,
            _ => continue,
        };
        let arguments = direct_call_argument_ranges(index, cast_close + 2, call_close);
        let Some((start, end)) = arguments.get(wanted_argument).copied() else {
            continue;
        };
        if structurally_constant_allocation_length(index, start, end) {
            offsets.push(index.tokens[start].start as usize);
        }
    }
    offsets
}

fn direct_call_argument_ranges(
    index: &CExpressionIndex,
    open: usize,
    close: usize,
) -> Vec<(usize, usize)> {
    if open + 1 >= close {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = open + 1;
    let mut at = start;
    while at < close {
        if matches!(index.tokens[at].text.as_str(), "(" | "[" | "{") {
            at = index.matching_token_index(at).map_or(at + 1, |mate| mate + 1);
            continue;
        }
        if index.tokens[at].text == "," {
            ranges.push((start, at));
            start = at + 1;
        }
        at += 1;
    }
    ranges.push((start, close));
    ranges
}

fn structurally_constant_allocation_length(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> bool {
    start < end
        && index.tokens[start..end].iter().all(|token| {
            matches!(
                token.kind,
                TokKind::IntLit | TokKind::FloatLit | TokKind::StringLit
            ) || matches!(
                token.text.as_str(),
                "true"
                    | "false"
                    | "("
                    | ")"
                    | "+"
                    | "-"
                    | "*"
                    | "/"
                    | "%"
                    | "<<"
                    | ">>"
                    | "<"
                    | "<="
                    | ">"
                    | ">="
                    | "=="
                    | "!="
                    | "&"
                    | "|"
                    | "^"
                    | "&&"
                    | "||"
                    | "!"
                    | "~"
                    | "?"
                    | ":"
            )
        })
}

fn logical_not_integer_literal_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for at in 0..index.tokens.len().saturating_sub(1) {
        if index.tokens[at].text != "!"
            || !declarations.functions.iter().any(|function| {
                function.body.start <= index.tokens[at].start as usize
                    && (index.tokens[at].start as usize) < function.body.end
            })
        {
            continue;
        }
        let mut start = at + 1;
        let mut end = start + 1;
        if index.tokens[start].text == "(" {
            let Some(close) = index.matching_token_index(start) else {
                continue;
            };
            end = close + 1;
        }
        (start, end) = trim_outer_group(index, start, end);
        if end == start + 1 && index.tokens[start].kind == TokKind::IntLit {
            offsets.push(index.tokens[at].start as usize);
        }
    }
    offsets
}

fn mutable_char_pointer_string_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &declarations.declarations {
        if !is_mutable_char_pointer_declaration(index, declaration) {
            continue;
        }
        for declarator in &declaration.declarators {
            if !declarator
                .derived
                .iter()
                .any(|derived| matches!(derived, D::Pointer | D::MemberPointer))
                || declarator
                    .derived
                    .iter()
                    .any(|derived| matches!(derived, D::Array { .. }))
            {
                continue;
            }
            let Some(initializer) = &declarator.initializer else {
                continue;
            };
            let Some((start, end)) = token_range_for_source_range(index, initializer) else {
                continue;
            };
            let (start, end) = trim_outer_group(index, start, end);
            if end == start + 1
                && index.tokens[start].kind == TokKind::StringLit
                && index.tokens[start].text.starts_with('"')
            {
                offsets.push(index.tokens[start].start as usize);
            }
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment)
        .filter(|fact| !initializer_assignments.contains(&fact.offset))
    {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(left) = unwrap_left_operand(index, operator.saturating_sub(1)) else {
            continue;
        };
        let Some(right) = unwrap_right_operand(index, operator + 1) else {
            continue;
        };
        if index.tokens[right].kind == TokKind::StringLit
            && index.tokens[right].text.starts_with('"')
            && mutable_char_pointer_name_at(index, declarations, left)
        {
            offsets.push(fact.offset);
        }
    }
    offsets
}

fn token_range_for_source_range(
    index: &CExpressionIndex,
    range: &std::ops::Range<usize>,
) -> Option<(usize, usize)> {
    let start = index
        .tokens
        .iter()
        .position(|token| token.start as usize >= range.start)?;
    let end = index
        .tokens
        .iter()
        .position(|token| token.start as usize >= range.end)
        .unwrap_or(index.tokens.len());
    (start < end).then_some((start, end))
}

fn is_mutable_char_pointer_declaration(
    index: &CExpressionIndex,
    declaration: &uniflow_parser_core::c_declarations::CDeclaration,
) -> bool {
    let words = declaration.type_name.split_whitespace().collect::<Vec<_>>();
    if !words.iter().any(|word| *word == "char") {
        return false;
    }
    let prefix = index
        .tokens
        .iter()
        .filter(|token| {
            declaration.range.start <= token.start as usize
                && (token.start as usize) < declaration.range.end
        })
        .take_while(|token| token.text != "*")
        .collect::<Vec<_>>();
    !prefix.iter().any(|token| token.text == "const")
}

fn mutable_char_pointer_name_at(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    token: usize,
) -> bool {
    let value = &index.tokens[token];
    value.kind == TokKind::Ident
        && declarations
            .declarations
            .iter()
            .filter(|declaration| declaration.range.start <= value.start as usize)
            .filter(|declaration| {
                declaration
                    .declarators
                    .iter()
                    .any(|declarator| declarator.name.as_deref() == Some(value.text.as_str()))
            })
            .max_by_key(|declaration| declaration.range.start)
            .is_some_and(|declaration| {
                is_mutable_char_pointer_declaration(index, declaration)
                    && declaration.declarators.iter().any(|declarator| {
                        declarator.name.as_deref() == Some(value.text.as_str())
                            && declarator
                                .derived
                                .iter()
                                .any(|derived| matches!(derived, D::Pointer | D::MemberPointer))
                            && !declarator
                                .derived
                                .iter()
                                .any(|derived| matches!(derived, D::Array { .. }))
                    })
            })
}

fn mixed_string_literal_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for initializer in declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter_map(|declarator| declarator.initializer.as_ref())
    {
        let Some((start, end)) = token_range_for_source_range(index, initializer) else {
            continue;
        };
        if mixed_string_literal_sequence(index, start, end).is_some() {
            offsets.push(initializer.start);
        }
    }
    let initializer_assignments = initializer_separators(index, declarations);
    for fact in index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment)
        .filter(|fact| !initializer_assignments.contains(&fact.offset))
    {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        if index.tokens[operator].text != "=" {
            continue;
        }
        let Some(range) = syntax
            .nodes
            .iter()
            .filter(|node| node.range.start <= fact.offset && fact.offset < node.range.end)
            .min_by_key(|node| node.range.end - node.range.start)
            .map(|node| node.range.clone())
            .or_else(|| index.statement_range(fact.offset))
        else {
            continue;
        };
        let end = (operator + 1..index.tokens.len())
            .find(|at| {
                index.tokens[*at].start as usize >= range.end || index.tokens[*at].text == ";"
            })
            .unwrap_or(index.tokens.len());
        if let Some(offset) = mixed_string_literal_sequence(index, operator + 1, end) {
            offsets.push(offset);
        }
    }
    offsets
}

fn mixed_string_literal_sequence(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> Option<usize> {
    let (mut at, end) = trim_outer_group(index, start, end);
    let first_offset = index.tokens.get(at)?.start as usize;
    let mut narrow = false;
    let mut wide = false;
    let mut literals = 0usize;
    while at < end {
        let mut separate_prefix = None;
        if index.tokens[at].kind == TokKind::Ident
            && matches!(index.tokens[at].text.as_str(), "L" | "u" | "U" | "u8")
        {
            separate_prefix = Some(index.tokens[at].text.as_str());
            at += 1;
        }
        let token = index.tokens.get(at)?;
        if token.kind != TokKind::StringLit || !token.text.contains('"') {
            return None;
        }
        let embedded = token.text.split_once('"').map_or("", |(prefix, _)| prefix);
        let prefix = if embedded.is_empty() {
            separate_prefix.unwrap_or_default()
        } else {
            embedded
        };
        if prefix == "L" {
            wide = true;
        } else if prefix.is_empty() {
            narrow = true;
        }
        literals += 1;
        at += 1;
    }
    (literals >= 2 && narrow && wide).then_some(first_offset)
}

fn misused_function_address_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let names = known_function_names(declarations);
    let mut offsets = Vec::new();
    for fact in index.facts.iter().filter(|fact| fact.kind == K::Binary) {
        let Some(operator) = token_at_offset(index, fact.offset) else {
            continue;
        };
        for operand in [
            operator
                .checked_sub(1)
                .and_then(|at| unwrap_left_operand(index, at)),
            unwrap_right_operand(index, operator + 1),
        ]
        .into_iter()
        .flatten()
        {
            if index.tokens[operand].kind == TokKind::Ident
                && names.contains(index.tokens[operand].text.as_str())
                && index
                    .tokens
                    .get(operand + 1)
                    .is_none_or(|token| token.text != "(")
            {
                offsets.push(index.tokens[operand].start as usize);
            }
        }
    }
    for condition in syntax
        .nodes
        .iter()
        .filter_map(|node| node.condition.as_ref())
    {
        let Some((start, end)) = token_range_for_source_range(index, condition) else {
            continue;
        };
        let (start, end) = trim_outer_group(index, start, end);
        if end == start + 2
            && index.tokens[start].text == "!"
            && index.tokens[start + 1].kind == TokKind::Ident
            && names.contains(index.tokens[start + 1].text.as_str())
        {
            offsets.push(index.tokens[start + 1].start as usize);
        }
    }
    offsets
}

fn known_function_names(declarations: &CDeclarationIndex) -> HashSet<&str> {
    declarations
        .functions
        .iter()
        .map(|function| function.name.as_str())
        .chain(declarations.declarations.iter().flat_map(|declaration| {
            declaration.declarators.iter().filter_map(|declarator| {
                matches!(declarator.derived.first(), Some(D::Function { .. }))
                    .then(|| declarator.name.as_deref())
                    .flatten()
            })
        }))
        .collect()
}

fn function_address_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let names = known_function_names(declarations);
    let initializer_assignments = initializer_separators(index, declarations);
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment)
        .filter(|fact| !initializer_assignments.contains(&fact.offset))
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            (index.tokens[operator].text == "=").then_some(())?;
            let function = direct_assignment_rhs_identifier(index, operator)?;
            names
                .contains(index.tokens[function].text.as_str())
                .then_some(fact.offset)
        })
        .collect()
}

fn direct_assignment_rhs_identifier(index: &CExpressionIndex, operator: usize) -> Option<usize> {
    let identifier = unwrap_right_operand(index, operator + 1)?;
    if index.tokens[identifier].kind != TokKind::Ident
        || index
            .tokens
            .get(identifier + 1)
            .is_some_and(|token| token.text == "(")
    {
        return None;
    }
    let mut after = identifier + 1;
    while index
        .tokens
        .get(after)
        .is_some_and(|token| token.text == ")")
        && index
            .matching_token_index(after)
            .is_some_and(|open| operator < open && open < identifier)
    {
        after += 1;
    }
    index.tokens.get(after).is_none_or(|token| {
        matches!(token.text.as_str(), ";" | "," | ")" | "]" | "}")
    })
    .then_some(identifier)
}

fn pointer_parameter_assignment_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    index
        .facts
        .iter()
        .filter(|fact| fact.kind == K::Assignment)
        .filter_map(|fact| {
            let operator = token_at_offset(index, fact.offset)?;
            (index.tokens[operator].text == "=").then_some(())?;
            let left = unwrap_left_operand(index, operator.checked_sub(1)?)?;
            (index.tokens[left].kind == TokKind::Ident
                && is_direct_assignment_lhs(index, left, operator))
            .then_some(())?;
            let name = index.tokens[left].text.as_str();
            let (function_id, function) = declarations
                .functions
                .iter()
                .enumerate()
                .filter(|(_, function)| {
                    function.body.start <= fact.offset && fact.offset < function.body.end
                })
                .min_by_key(|(_, function)| function.body.end - function.body.start)?;
            let pointer_parameter = declarations.parameters.iter().any(|parameter| {
                function.parameters.start <= parameter.range.start
                    && parameter.range.end <= function.parameters.end
                    && parameter.name.as_deref() == Some(name)
                    && parameter
                        .derived
                        .iter()
                        .any(|derived| matches!(derived, D::Pointer | D::Array { .. }))
            });
            if !pointer_parameter
                || local_declaration_shadows_parameter(
                    declarations,
                    syntax,
                    function_id,
                    name,
                    fact.offset,
                )
            {
                return None;
            }
            Some(fact.offset)
        })
        .collect()
}

fn local_declaration_shadows_parameter(
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    function_id: usize,
    name: &str,
    use_offset: usize,
) -> bool {
    declarations.declarations.iter().any(|declaration| {
        if declaration.enclosing_function != Some(function_id)
            || declaration.range.start >= use_offset
            || !declaration
                .declarators
                .iter()
                .any(|declarator| declarator.name.as_deref() == Some(name))
        {
            return false;
        }
        syntax
            .nodes
            .iter()
            .filter(|node| {
                node.kind == JavaSyntaxKind::Block
                    && node.range.start <= declaration.range.start
                    && declaration.range.end <= node.range.end
            })
            .min_by_key(|node| node.range.end - node.range.start)
            .is_some_and(|block| block.range.start <= use_offset && use_offset < block.range.end)
    })
}

fn is_direct_assignment_lhs(index: &CExpressionIndex, identifier: usize, operator: usize) -> bool {
    let mut boundary = identifier;
    let mut after = identifier + 1;
    while after < operator && index.tokens[after].text == ")" {
        let Some(open) = index.matching_token_index(after) else {
            return false;
        };
        if open >= boundary {
            return false;
        }
        boundary = open;
        after += 1;
    }
    if after != operator {
        return false;
    }
    index.tokens.get(boundary.wrapping_sub(1)).is_none_or(|token| {
        !matches!(token.text.as_str(), "*" | "&" | "." | "->" | "[" | "++" | "--")
    })
}

fn equality_loop_large_step_offsets(
    index: &CExpressionIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for node in syntax.nodes.iter().filter(|node| node.kind == JavaSyntaxKind::For) {
        let (Some(condition), Some(update)) = (&node.condition, &node.update) else {
            continue;
        };
        let Some((condition_start, condition_end)) = token_range_for_source_range(index, condition)
        else {
            continue;
        };
        let (condition_start, condition_end) =
            trim_outer_group(index, condition_start, condition_end);
        let Some(operator) = root_operator(
            index,
            condition_start,
            condition_end,
            &["==", "!="],
        ) else {
            continue;
        };
        let variables = [
            direct_identifier(index, condition_start, operator),
            direct_identifier(index, operator + 1, condition_end),
        ];
        let Some((update_start, update_end)) = token_range_for_source_range(index, update) else {
            continue;
        };
        if variables.into_iter().flatten().any(|variable| {
            update_changes_variable_by_more_than_one(index, update_start, update_end, variable)
        }) {
            offsets.push(index.tokens[operator].start as usize);
        }
    }
    offsets
}

fn direct_identifier<'a>(
    index: &'a CExpressionIndex,
    start: usize,
    end: usize,
) -> Option<&'a str> {
    let (start, end) = trim_outer_group(index, start, end);
    (end == start + 1 && index.tokens[start].kind == TokKind::Ident)
        .then_some(index.tokens[start].text.as_str())
}

fn update_changes_variable_by_more_than_one(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
    variable: &str,
) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    let Some(assignment) = root_operator(index, start, end, &["=", "+=", "-="]) else {
        return false;
    };
    if direct_identifier(index, start, assignment) != Some(variable) {
        return false;
    }
    let operator = index.tokens[assignment].text.as_str();
    if matches!(operator, "+=" | "-=") {
        return constant_magnitude_at_least_two(index, assignment + 1, end);
    }
    let (rhs_start, rhs_end) = trim_outer_group(index, assignment + 1, end);
    let Some(arithmetic) = root_operator(index, rhs_start, rhs_end, &["+", "-"]) else {
        return false;
    };
    direct_identifier(index, rhs_start, arithmetic) == Some(variable)
        && constant_magnitude_at_least_two(index, arithmetic + 1, rhs_end)
}

fn constant_magnitude_at_least_two(
    index: &CExpressionIndex,
    start: usize,
    end: usize,
) -> bool {
    let (start, end) = trim_outer_group(index, start, end);
    evaluate_c_constant_integer(&index.tokens[start..end])
        .is_some_and(|value| value >= 2 || value <= -2)
}

fn constant_assert_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    expected_truth: bool,
) -> Vec<usize> {
    let declared = declarations.functions.iter().any(|function| function.name == "assert")
        || declarations.declarations.iter().any(|declaration| {
            declaration.declarators.iter().any(|declarator| {
                declarator.name.as_deref() == Some("assert")
                    && matches!(declarator.derived.first(), Some(D::Function { .. }))
            })
        });
    if !declared {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    for at in 0..index.tokens.len().saturating_sub(2) {
        if index.tokens[at].text != "assert"
            || index.tokens[at + 1].text != "("
            || !declarations.functions.iter().any(|function| {
                function.body.start <= index.tokens[at].start as usize
                    && (index.tokens[at].start as usize) < function.body.end
            })
        {
            continue;
        }
        let mut depth = 1usize;
        let mut end = at + 2;
        let mut multiple_arguments = false;
        while end < index.tokens.len() {
            match index.tokens[end].text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                "," if depth == 1 => {
                    multiple_arguments = true;
                    break;
                }
                _ => {}
            }
            end += 1;
        }
        if multiple_arguments || end == at + 2 {
            continue;
        }
        if ConstantExpression::evaluate(&index.tokens[at + 2..end])
            .is_some_and(|value| (value != 0) == expected_truth)
        {
            offsets.push(index.tokens[at].start as usize);
        }
    }
    offsets
}

fn non_ascii_narrow_string_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    index
        .tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.kind == TokKind::StringLit)
        .filter(|(_, token)| {
            declarations.functions.iter().any(|function| {
                function.body.start <= token.start as usize
                    && (token.start as usize) < function.body.end
            })
        })
        .filter(|(at, token)| {
            let separate_prefix = at.checked_sub(1).and_then(|previous| {
                let previous = &index.tokens[previous];
                (previous.end == token.start).then_some(previous.text.as_str())
            });
            narrow_string_has_non_ascii(&token.text, separate_prefix)
        })
        .map(|(_, token)| token.start as usize)
        .collect()
}

fn narrow_string_has_non_ascii(text: &str, separate_prefix: Option<&str>) -> bool {
    let Some(quote) = text.find('"') else {
        return false;
    };
    let prefix = if quote == 0 {
        separate_prefix.unwrap_or_default()
    } else {
        &text[..quote]
    };
    if matches!(prefix, "L" | "u" | "U") {
        return false;
    }
    let content = text[quote + 1..].strip_suffix('"').unwrap_or(&text[quote + 1..]);
    let bytes = content.as_bytes();
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] >= 0x80 {
            return true;
        }
        if bytes[at] != b'\\' || at + 1 >= bytes.len() {
            at += 1;
            continue;
        }
        at += 1;
        match bytes[at] {
            b'x' => {
                at += 1;
                let start = at;
                while at < bytes.len() && bytes[at].is_ascii_hexdigit() {
                    at += 1;
                }
                if start < at
                    && u32::from_str_radix(&content[start..at], 16)
                        .is_ok_and(|value| value & 0xff > 0x7f)
                {
                    return true;
                }
            }
            b'u' | b'U' => {
                let digits = if bytes[at] == b'u' { 4 } else { 8 };
                at += 1;
                if at + digits <= bytes.len()
                    && u32::from_str_radix(&content[at..at + digits], 16)
                        .is_ok_and(|value| value > 0x7f)
                {
                    return true;
                }
                at = (at + digits).min(bytes.len());
            }
            b'0'..=b'7' => {
                let start = at;
                at += 1;
                while at < bytes.len()
                    && at - start < 3
                    && matches!(bytes[at], b'0'..=b'7')
                {
                    at += 1;
                }
                if u32::from_str_radix(&content[start..at], 8)
                    .is_ok_and(|value| value > 0x7f)
                {
                    return true;
                }
            }
            _ => at += 1,
        }
    }
    false
}

fn logical_not_constant_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for at in 0..index.tokens.len().saturating_sub(1) {
        if index.tokens[at].text != "!"
            || !declarations.functions.iter().any(|function| {
                function.body.start <= index.tokens[at].start as usize
                    && (index.tokens[at].start as usize) < function.body.end
            })
        {
            continue;
        }
        let Some(end) = unary_operand_end(&index.tokens, at + 1) else {
            continue;
        };
        if ConstantExpression::evaluate(&index.tokens[at + 1..end]).is_some() {
            offsets.push(index.tokens[at].start as usize);
        }
    }
    offsets
}

fn unary_operand_end(tokens: &[Token], start: usize) -> Option<usize> {
    let mut at = start;
    while tokens
        .get(at)
        .is_some_and(|token| matches!(token.text.as_str(), "!" | "~" | "+" | "-"))
    {
        at += 1;
    }
    if tokens.get(at)?.text != "(" {
        return Some(at + 1);
    }
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(at) {
        match token.text.as_str() {
            "(" => depth += 1,
            ")" => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn vfork_call_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let shadowed_by_function_pointer = declarations.declarations.iter().any(|declaration| {
        declaration.declarators.iter().any(|declarator| {
            declarator.name.as_deref() == Some("vfork")
                && matches!(declarator.derived.first(), Some(D::Pointer))
                && declarator
                    .derived
                    .iter()
                    .any(|derived| matches!(derived, D::Function { .. }))
        })
    });
    if shadowed_by_function_pointer {
        return Vec::new();
    }
    index
        .tokens
        .windows(3)
        .filter(|tokens| {
            tokens[0].kind == TokKind::Ident
                && tokens[0].text == "vfork"
                && tokens[1].text == "("
                && tokens[2].text == ")"
        })
        .filter(|tokens| {
            index
                .tokens
                .iter()
                .position(|token| std::ptr::eq(token, &tokens[0]))
                .and_then(|at| at.checked_sub(1))
                .and_then(|at| index.tokens.get(at))
                .is_none_or(|previous| !matches!(previous.text.as_str(), "." | "->" | "::"))
        })
        .map(|tokens| tokens[0].start as usize)
        .collect()
}

fn delete_this_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for at in 0..index.tokens.len() {
        if index.tokens[at].text != "delete" {
            continue;
        }
        let mut next = at + 1;
        if index.tokens.get(next).is_some_and(|token| token.text == "[")
            && index
                .tokens
                .get(next + 1)
                .is_some_and(|token| token.text == "]")
        {
            next += 2;
        }
        let mut parentheses = 0usize;
        while index.tokens.get(next).is_some_and(|token| token.text == "(") {
            parentheses += 1;
            next += 1;
        }
        if !index.tokens.get(next).is_some_and(|token| token.text == "this") {
            continue;
        }
        let operand_offset = index.tokens[next].start as usize;
        next += 1;
        let mut valid = true;
        for _ in 0..parentheses {
            if !index.tokens.get(next).is_some_and(|token| token.text == ")") {
                valid = false;
                break;
            }
            next += 1;
        }
        if valid
            && index.tokens.get(next).is_none_or(|token| {
                matches!(token.text.as_str(), ";" | "," | ")" | ":" | "}")
                    || token.kind == TokKind::Eof
            })
        {
            offsets.push(operand_offset);
        }
    }
    offsets
}

fn false_static_assert_offsets(index: &CExpressionIndex) -> Vec<usize> {
    let mut offsets = Vec::new();
    for at in 0..index.tokens.len().saturating_sub(1) {
        if !matches!(index.tokens[at].text.as_str(), "static_assert" | "_Static_assert")
            || index.tokens[at + 1].text != "("
        {
            continue;
        }
        let mut depth = 1usize;
        let mut end = at + 2;
        while end < index.tokens.len() {
            match index.tokens[end].text.as_str() {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                "," if depth == 1 => break,
                _ => {}
            }
            end += 1;
        }
        let expression = &index.tokens[at + 2..end];
        if !expression.is_empty() && ConstantExpression::evaluate(expression) == Some(0) {
            offsets.push(expression[0].start as usize);
        }
    }
    offsets
}

/// Deliberately conservative integer constant-expression evaluator. Unknown
/// names and unsupported constructs return `None`, mirroring Clang's checker:
/// it emits only when semantic constant evaluation succeeds and yields false.
struct ConstantExpression<'a> {
    tokens: &'a [Token],
    at: usize,
}

pub(crate) fn evaluate_c_constant_boolean(tokens: &[Token]) -> Option<bool> {
    if let Some(value) = ConstantExpression::evaluate(tokens) {
        return Some(value != 0);
    }
    let mut slice = tokens;
    loop {
        if slice.len() < 2 || slice[0].text != "(" || slice[slice.len() - 1].text != ")" {
            break;
        }
        let mut depth = 0usize;
        let mut outer = false;
        for (at, token) in slice.iter().enumerate() {
            match token.text.as_str() {
                "(" => depth += 1,
                ")" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        outer = at + 1 == slice.len();
                        break;
                    }
                }
                _ => {}
            }
        }
        if !outer {
            break;
        }
        slice = &slice[1..slice.len() - 1];
    }
    let token = slice.first().filter(|_| slice.len() == 1)?;
    match token.kind {
        TokKind::FloatLit => token
            .text
            .trim_end_matches(|ch: char| matches!(ch, 'f' | 'F' | 'l' | 'L'))
            .parse::<f64>()
            .ok()
            .map(|value| value != 0.0),
        TokKind::StringLit if token.text.contains('"') => Some(true),
        TokKind::StringLit if token.text.contains('\'') => {
            Some(!matches!(token.text.as_str(), "'\\0'" | "'\\x00'" | "'\\u0000'"))
        }
        _ => None,
    }
}

pub(crate) fn evaluate_c_constant_integer(tokens: &[Token]) -> Option<i128> {
    ConstantExpression::evaluate(tokens)
}

impl<'a> ConstantExpression<'a> {
    fn evaluate(tokens: &'a [Token]) -> Option<i128> {
        let mut parser = Self { tokens, at: 0 };
        let value = parser.conditional()?;
        (parser.at == tokens.len()).then_some(value)
    }

    fn conditional(&mut self) -> Option<i128> {
        let condition = self.binary(1)?;
        if !self.take("?") {
            return Some(condition);
        }
        let when_true = self.conditional()?;
        if !self.take(":") {
            return None;
        }
        let when_false = self.conditional()?;
        Some(if condition != 0 { when_true } else { when_false })
    }

    fn binary(&mut self, minimum_precedence: u8) -> Option<i128> {
        let mut left = self.unary()?;
        loop {
            let Some((precedence, operator)) = self
                .tokens
                .get(self.at)
                .and_then(|token| binary_precedence(&token.text))
            else {
                break;
            };
            if precedence < minimum_precedence {
                break;
            }
            self.at += 1;
            let right = self.binary(precedence + 1)?;
            left = apply_constant_binary(operator, left, right)?;
        }
        Some(left)
    }

    fn unary(&mut self) -> Option<i128> {
        if self.take("!") {
            return Some(i128::from(self.unary()? == 0));
        }
        if self.take("~") {
            return Some(!self.unary()?);
        }
        if self.take("+") {
            return self.unary();
        }
        if self.take("-") {
            return self.unary()?.checked_neg();
        }
        self.primary()
    }

    fn primary(&mut self) -> Option<i128> {
        if self.take("(") {
            let value = self.conditional()?;
            return self.take(")").then_some(value);
        }
        let token = self.tokens.get(self.at)?;
        let value = match (token.kind, token.text.as_str()) {
            (TokKind::Ident, "true") => Some(1),
            (TokKind::Ident, "false" | "nullptr") => Some(0),
            (TokKind::IntLit, text) => parse_c_integer(text),
            _ => None,
        }?;
        self.at += 1;
        Some(value)
    }

    fn take(&mut self, text: &str) -> bool {
        if self.tokens.get(self.at).is_some_and(|token| token.text == text) {
            self.at += 1;
            true
        } else {
            false
        }
    }
}

fn binary_precedence(operator: &str) -> Option<(u8, &str)> {
    let precedence = match operator {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | "<=" | ">" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    };
    Some((precedence, operator))
}

fn apply_constant_binary(operator: &str, left: i128, right: i128) -> Option<i128> {
    Some(match operator {
        "||" => i128::from(left != 0 || right != 0),
        "&&" => i128::from(left != 0 && right != 0),
        "|" => left | right,
        "^" => left ^ right,
        "&" => left & right,
        "==" => i128::from(left == right),
        "!=" => i128::from(left != right),
        "<" => i128::from(left < right),
        "<=" => i128::from(left <= right),
        ">" => i128::from(left > right),
        ">=" => i128::from(left >= right),
        "<<" => left.checked_shl(u32::try_from(right).ok()?)?,
        ">>" => left.checked_shr(u32::try_from(right).ok()?)?,
        "+" => left.checked_add(right)?,
        "-" => left.checked_sub(right)?,
        "*" => left.checked_mul(right)?,
        "/" => left.checked_div(right)?,
        "%" => left.checked_rem(right)?,
        _ => return None,
    })
}

fn parse_c_integer(text: &str) -> Option<i128> {
    let normalized = text.replace('_', "");
    let lower = normalized.to_ascii_lowercase();
    let body = lower.trim_end_matches(['u', 'l']);
    let (radix, digits) = if let Some(digits) = body.strip_prefix("0x") {
        (16, digits)
    } else if let Some(digits) = body.strip_prefix("0b") {
        (2, digits)
    } else if let Some(digits) = body.strip_prefix("0o") {
        (8, digits)
    } else if body.len() > 1 && body.starts_with('0') {
        (8, &body[1..])
    } else {
        (10, body)
    };
    if digits.is_empty() {
        return (body == "0").then_some(0);
    }
    i128::from_str_radix(digits, radix).ok()
}

fn initializer_separators(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> HashSet<usize> {
    declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter_map(|declarator| declarator.initializer.as_ref())
        .filter_map(|initializer| {
            index
                .tokens
                .iter()
                .rfind(|token| token.end as usize <= initializer.start && token.text == "=")
                .map(|token| token.start as usize)
        })
        .chain(
            declarations
                .enumerators
                .iter()
                .filter_map(|enumerator| enumerator.initializer.as_ref())
                .filter_map(|initializer| {
                    index
                        .tokens
                        .iter()
                        .rfind(|token| {
                            token.end as usize <= initializer.start && token.text == "="
                        })
                        .map(|token| token.start as usize)
                }),
        )
        .collect()
}

fn inside_expression_statement(
    fact: &CExpressionFact,
    declarations: &CDeclarationIndex,
    syntax: &JavaSyntax,
    index: &CExpressionIndex,
) -> bool {
    if declarations.declarations.iter().any(|declaration| {
        declaration.range.start <= fact.offset && fact.offset < declaration.range.end
    }) {
        return false;
    }
    let node_range = syntax
        .nodes
        .iter()
        .filter(|node| {
            node.kind == JavaSyntaxKind::Other
                && node.range.start <= fact.offset
                && fact.offset < node.range.end
        })
        .min_by_key(|node| node.range.end - node.range.start)
        .map(|node| node.range.clone())
        .or_else(|| index.statement_range(fact.offset));
    let Some(node_range) = node_range else {
        return false;
    };
    let Some(first) = index.tokens.iter().find(|token| {
        token.start as usize >= node_range.start && (token.end as usize) <= node_range.end
    }) else {
        return false;
    };
    !matches!(
        first.text.as_str(),
        "return" | "throw" | "goto" | "case" | "static_assert" | "_Static_assert"
    ) && index.tokens.iter().any(|token| {
        token.text == ";"
            && token.start as usize >= fact.offset
            && (token.end as usize) <= node_range.end
    })
}

fn expression_region_has(
    index: &CExpressionIndex,
    syntax: &JavaSyntax,
    offset: usize,
    wanted: K,
) -> bool {
    if let Some((open, close)) = index.smallest_group(offset) {
        let start = index.tokens[open].start as usize;
        let end = index.tokens[close].end as usize;
        return index
            .facts
            .iter()
            .any(|fact| fact.kind == wanted && start <= fact.offset && fact.offset < end);
    }
    let range = syntax
        .nodes
        .iter()
        .filter(|node| node.range.start <= offset && offset < node.range.end)
        .min_by_key(|node| node.range.end - node.range.start)
        .map(|node| node.range.clone())
        .or_else(|| index.statement_range(offset));
    range.is_some_and(|range| {
        index.facts.iter().any(|fact| {
            fact.kind == wanted && range.start <= fact.offset && fact.offset < range.end
        })
    })
}

fn is_separator_comma(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    offset: usize,
) -> bool {
    if declarations
        .functions
        .iter()
        .any(|function| function.parameters.start <= offset && offset < function.parameters.end)
        || declarations
            .parameters
            .iter()
            .any(|parameter| parameter.range.start <= offset && offset < parameter.range.end)
    {
        return true;
    }
    if let Some((open, _)) = index.smallest_group(offset) {
        if index.tokens[open].text == "{" {
            return true;
        }
        if index.tokens[open].text == "(" {
            return false;
        }
    }
    declarations
        .declarations
        .iter()
        .any(|declaration| declaration.range.start <= offset && offset < declaration.range.end)
}

fn is_call_argument_separator(index: &CExpressionIndex, offset: usize) -> bool {
    let Some((open, _)) = index.smallest_group(offset) else {
        return false;
    };
    if index.tokens[open].text != "(" || open == 0 {
        return false;
    }
    let previous = &index.tokens[open - 1];
    previous.kind == TokKind::Ident
        && !matches!(
            previous.text.as_str(),
            "if" | "for" | "while" | "switch" | "sizeof" | "alignof" | "_Alignof"
        )
}

fn comma_expression_start(index: &CExpressionIndex, syntax: &JavaSyntax, offset: usize) -> usize {
    if let Some((open, _)) = index.smallest_group(offset) {
        if matches!(index.tokens[open].text.as_str(), "(" | "[") {
            return index
                .tokens
                .get(open + 1)
                .map_or(offset, |token| token.start as usize);
        }
    }
    syntax
        .nodes
        .iter()
        .filter(|node| node.range.start <= offset && offset < node.range.end)
        .min_by_key(|node| node.range.end - node.range.start)
        .and_then(|node| {
            index.tokens.iter().find(|token| {
                token.start as usize >= node.range.start
                    && (token.end as usize) <= node.range.end
                    && !matches!(token.text.as_str(), "return" | "case")
            })
        })
        .map_or(offset, |token| token.start as usize)
}

fn boolean_expression_offset(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Option<usize> {
    let mut tokens = index
        .tokens
        .iter()
        .filter(|token| {
            token.kind != TokKind::Eof
                && token.start as usize >= range.start
                && (token.end as usize) <= range.end
        })
        .collect::<Vec<_>>();
    while tokens.len() >= 2
        && tokens.first().is_some_and(|token| token.text == "(")
        && tokens.last().is_some_and(|token| token.text == ")")
    {
        tokens.remove(0);
        tokens.pop();
    }
    let first = *tokens.first()?;
    let has_value_changing_operator = index.facts.iter().any(|fact| {
        range.start <= fact.offset
            && fact.offset < range.end
            && matches!(fact.kind, K::Binary | K::Assignment | K::Comma | K::Conditional)
    });
    if matches!(first.text.as_str(), "true" | "false") {
        return (!has_value_changing_operator).then_some(first.start as usize);
    }
    if first.kind != TokKind::Ident {
        return None;
    }
    let is_boolean_name = tokens.len() == 1 && declarations.declarations.iter().any(|declaration| {
        matches!(declaration.type_name.as_str(), "bool" | "_Bool")
            && declaration
                .declarators
                .iter()
                .any(|declarator| declarator.name.as_deref() == Some(first.text.as_str()))
    }) || declarations.parameters.iter().any(|parameter| {
        matches!(parameter.type_name.as_str(), "bool" | "_Bool")
            && parameter.name.as_deref() == Some(first.text.as_str())
    });
    let is_boolean_call = tokens.get(1).is_some_and(|token| token.text == "(")
        && tokens.last().is_some_and(|token| token.text == ")")
        && declarations.functions.iter().any(|function| {
            function.name == first.text
                && matches!(function.return_type.as_str(), "bool" | "_Bool")
        });
    (!has_value_changing_operator && (is_boolean_name || is_boolean_call))
        .then_some(first.start as usize)
}

fn global_loop_control_offset(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    range: std::ops::Range<usize>,
) -> Option<usize> {
    let function = declarations.functions.iter().find(|function| {
        function.body.start <= range.start && range.end <= function.body.end
    });
    let mut local_names = HashSet::new();
    if let Some(function) = function {
        for declaration in declarations.declarations.iter().filter(|declaration| {
            declaration.enclosing_function.is_some()
                && function.body.start <= declaration.range.start
                && declaration.range.end <= function.body.end
        }) {
            local_names.extend(
                declaration
                    .declarators
                    .iter()
                    .filter_map(|declarator| declarator.name.clone()),
            );
        }
        local_names.extend(
            declarations
                .parameters
                .iter()
                .filter(|parameter| {
                    function.parameters.start <= parameter.range.start
                        && parameter.range.end <= function.parameters.end
                })
                .filter_map(|parameter| parameter.name.clone()),
        );
    }
    let global_names = declarations
        .declarations
        .iter()
        .filter(|declaration| declaration.enclosing_function.is_none())
        .flat_map(|declaration| &declaration.declarators)
        .filter_map(|declarator| declarator.name.as_deref())
        .collect::<HashSet<_>>();
    let references = index.tokens.iter().filter(|token| {
        token.kind == TokKind::Ident
            && token.start as usize >= range.start
            && (token.end as usize) <= range.end
    });
    let references = references.collect::<Vec<_>>();
    if references
        .iter()
        .any(|token| local_names.contains(token.text.as_str()))
    {
        return None;
    }
    references
        .into_iter()
        .find(|token| global_names.contains(token.text.as_str()))
        .map(|token| token.start as usize)
}

fn direct_assignment_lhs(index: &CExpressionIndex, assignment_offset: usize) -> Option<&str> {
    let at = index
        .tokens
        .iter()
        .position(|token| token.start as usize == assignment_offset)?;
    let lhs = index.tokens.get(at.checked_sub(1)?)?;
    if lhs.kind != TokKind::Ident
        || at >= 2
            && matches!(index.tokens[at - 2].text.as_str(), "." | "->" | "::")
    {
        return None;
    }
    Some(lhs.text.as_str())
}

fn resolve_variable(
    declarations: &CDeclarationIndex,
    function_id: Option<usize>,
    name: &str,
    use_offset: usize,
) -> Option<(String, usize, bool)> {
    if let Some(function_id) = function_id {
        if let Some(declaration) = declarations
            .declarations
            .iter()
            .filter(|declaration| {
                declaration.enclosing_function == Some(function_id)
                    && is_known_declaration_type(declarations, &declaration.type_name)
                    && declaration.range.start <= use_offset
                    && declaration
                        .declarators
                        .iter()
                        .any(|declarator| declarator.name.as_deref() == Some(name))
            })
            .max_by_key(|declaration| declaration.range.start)
        {
            return Some((declaration.type_name.clone(), declaration.range.start, true));
        }
        let function = &declarations.functions[function_id];
        if let Some(parameter) = declarations.parameters.iter().find(|parameter| {
            function.parameters.start <= parameter.range.start
                && parameter.range.end <= function.parameters.end
                && parameter.name.as_deref() == Some(name)
        }) {
            return Some((parameter.type_name.clone(), parameter.range.start, false));
        }
    }
    declarations.declarations.iter().find_map(|declaration| {
        (declaration.enclosing_function.is_none()
            && is_known_declaration_type(declarations, &declaration.type_name)
            && declaration
                .declarators
                .iter()
                .any(|declarator| declarator.name.as_deref() == Some(name)))
        .then(|| (declaration.type_name.clone(), declaration.range.start, false))
    })
}

fn is_known_declaration_type(declarations: &CDeclarationIndex, ty: &str) -> bool {
    matches!(
        ty,
        "void" | "char" | "short" | "int" | "long" | "float" | "double" | "signed"
            | "unsigned" | "bool" | "_Bool" | "long double" | "signed char"
            | "unsigned char" | "signed int" | "unsigned int" | "long int"
            | "unsigned long" | "long long" | "unsigned long long"
    ) || ty.starts_with("struct ")
        || ty.starts_with("union ")
        || ty.starts_with("enum ")
        || ty.starts_with("class ")
        || declarations.declarations.iter().any(|declaration| {
            declaration.storage.iter().any(|item| item == "typedef")
                && declaration
                    .declarators
                    .iter()
                    .any(|declarator| declarator.name.as_deref() == Some(ty))
        })
        || declarations
            .aggregates
            .iter()
            .any(|aggregate| aggregate.name.as_deref() == Some(ty))
}

fn is_floating_type(ty: &str) -> bool {
    matches!(ty, "float" | "double" | "long double")
}

fn c_style_cast_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut known_types = [
        "void", "char", "short", "int", "long", "float", "double", "signed",
        "unsigned", "bool", "_Bool", "wchar_t", "char8_t", "char16_t", "char32_t",
        "size_t", "ptrdiff_t",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<HashSet<_>>();
    known_types.extend(
        declarations
            .declarations
            .iter()
            .filter(|declaration| declaration.storage.iter().any(|item| item == "typedef"))
            .flat_map(|declaration| &declaration.declarators)
            .filter_map(|declarator| declarator.name.clone()),
    );
    known_types.extend(
        declarations
            .aggregates
            .iter()
            .filter_map(|aggregate| aggregate.name.clone()),
    );
    let mut offsets = Vec::new();
    for open in 0..index.tokens.len() {
        if index.tokens[open].text != "(" {
            continue;
        }
        let Some(close) = index.matching_token_index(open) else {
            continue;
        };
        if close <= open + 1 || close + 1 >= index.tokens.len() {
            continue;
        }
        if index.tokens.get(open.wrapping_sub(1)).is_some_and(|token| {
            matches!(
                token.text.as_str(),
                "if" | "for" | "while" | "switch" | "sizeof" | "alignof" | "_Alignof"
                    | "decltype" | "catch"
            )
        }) {
            continue;
        }
        let type_tokens = &index.tokens[open + 1..close];
        let mut saw_type = false;
        let mut after_tag = false;
        let valid_type = type_tokens.iter().all(|token| match token.text.as_str() {
            "const" | "volatile" | "restrict" | "*" | "&" | "&&" | "::" | "["
            | "]" => true,
            "struct" | "union" | "enum" | "class" => {
                saw_type = true;
                after_tag = true;
                true
            }
            text if token.kind == TokKind::Ident
                && (known_types.contains(text) || after_tag) =>
            {
                saw_type = true;
                after_tag = false;
                true
            }
            _ => false,
        });
        if !valid_type || !saw_type {
            continue;
        }
        let operand = &index.tokens[close + 1];
        if operand.kind == TokKind::Eof
            || matches!(operand.text.as_str(), ";" | "," | ")" | "]" | "}" | ":")
        {
            continue;
        }
        let offset = index.tokens[open].start as usize;
        if declarations.functions.iter().any(|function| {
            function.body.start <= offset && offset < function.body.end
        }) {
            offsets.push(offset);
        }
    }
    offsets
}

fn sizeof_array_parameter_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let mut offsets = Vec::new();
    for function in &declarations.functions {
        let array_parameters = declarations
            .parameters
            .iter()
            .filter(|parameter| {
                function.parameters.start <= parameter.range.start
                    && parameter.range.end <= function.parameters.end
                    && parameter
                        .derived
                        .iter()
                        .any(|derived| matches!(derived, D::Array { .. }))
            })
            .filter_map(|parameter| parameter.name.as_deref())
            .collect::<HashSet<_>>();
        if array_parameters.is_empty() {
            continue;
        }
        let body_tokens = index
            .tokens
            .iter()
            .enumerate()
            .filter(|(_, token)| {
                function.body.start <= token.start as usize
                    && (token.end as usize) <= function.body.end
            })
            .collect::<Vec<_>>();
        for (position, (_, token)) in body_tokens.iter().enumerate() {
            if token.text != "sizeof" {
                continue;
            }
            let Some((next_index, next)) = body_tokens.get(position + 1).copied() else {
                continue;
            };
            if next.text != "(" {
                if next.kind == TokKind::Ident
                    && array_parameters.contains(next.text.as_str())
                    && body_tokens.get(position + 2).is_none_or(|(_, after)| {
                        !matches!(after.text.as_str(), "[" | "." | "->" | "(")
                    })
                {
                    offsets.push(next.start as usize);
                }
                continue;
            }
            let Some(close) = index.matching_token_index(next_index) else {
                continue;
            };
            let mut expression = &index.tokens[next_index + 1..close];
            loop {
                if expression.len() < 2
                    || expression[0].text != "("
                    || expression[expression.len() - 1].text != ")"
                    || index.matching_token_index(next_index + 1)
                        != Some(close.saturating_sub(1))
                {
                    break;
                }
                expression = &expression[1..expression.len() - 1];
            }
            if let [argument] = expression {
                if argument.kind == TokKind::Ident
                    && array_parameters.contains(argument.text.as_str())
                {
                    offsets.push(argument.start as usize);
                }
            }
        }
    }
    offsets
}

fn direct_rhs_call<'a>(index: &'a CExpressionIndex, operator_offset: usize) -> Option<&'a str> {
    let operator = index
        .tokens
        .iter()
        .position(|token| token.start as usize == operator_offset)?;
    let mut name = operator + 1;
    let mut wrappers = 0usize;
    while index.tokens.get(name).is_some_and(|token| token.text == "(") {
        wrappers += 1;
        name += 1;
    }
    let token = index.tokens.get(name)?;
    if token.kind != TokKind::Ident
        || name > 0 && matches!(index.tokens[name - 1].text.as_str(), "." | "->" | "::")
        || !index.tokens.get(name + 1).is_some_and(|token| token.text == "(")
    {
        return None;
    }
    let call_close = index.matching_token_index(name + 1)?;
    let mut after = call_close + 1;
    for _ in 0..wrappers {
        if !index.tokens.get(after).is_some_and(|token| token.text == ")") {
            return None;
        }
        after += 1;
    }
    if index.tokens.get(after).is_some_and(|token| {
        matches!(
            token.text.as_str(),
            "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&" | "|" | "^"
                | "&&" | "||" | "==" | "!=" | "<" | "<=" | ">" | ">=" | "?"
        )
    }) {
        return None;
    }
    Some(token.text.as_str())
}

fn ctype_signed_char_argument_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    ctype_character_argument_offsets(index, declarations, "char")
}

fn ctype_explicit_signed_char_argument_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    ctype_character_argument_offsets(index, declarations, "signed char")
}

fn ctype_character_argument_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
    expected_type: &str,
) -> Vec<usize> {
    const FUNCTIONS: &[&str] = &[
        "isalnum", "isalpha", "isascii", "isblank", "iscntrl", "isdigit", "isgraph",
        "islower", "isprint", "ispunct", "isspace", "isupper", "isxdigit", "toascii",
        "toupper", "tolower",
    ];
    let shadowed = declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter(|declarator| {
            declarator.name.as_deref().is_some_and(|name| FUNCTIONS.contains(&name))
                && declarator
                    .derived
                    .iter()
                    .any(|derived| matches!(derived, D::Pointer))
        })
        .filter_map(|declarator| declarator.name.as_deref())
        .collect::<HashSet<_>>();
    let mut offsets = Vec::new();
    for name_at in 0..index.tokens.len().saturating_sub(1) {
        let name = &index.tokens[name_at];
        if name.kind != TokKind::Ident
            || !FUNCTIONS.contains(&name.text.as_str())
            || shadowed.contains(name.text.as_str())
            || index.tokens[name_at + 1].text != "("
            || name_at > 0
                && matches!(index.tokens[name_at - 1].text.as_str(), "." | "->" | "::")
        {
            continue;
        }
        let Some(close) = index.matching_token_index(name_at + 1) else {
            continue;
        };
        let mut argument_end = close;
        let mut cursor = name_at + 2;
        while cursor < close {
            if index.tokens[cursor].text == "," {
                argument_end = cursor;
                break;
            }
            cursor = index
                .matching_token_index(cursor)
                .filter(|matched| *matched < close)
                .map_or(cursor + 1, |matched| matched + 1);
        }
        let mut argument = &index.tokens[name_at + 2..argument_end];
        while argument.len() >= 2
            && argument[0].text == "("
            && argument[argument.len() - 1].text == ")"
        {
            argument = &argument[1..argument.len() - 1];
        }
        let [argument] = argument else {
            continue;
        };
        if argument.kind != TokKind::Ident {
            continue;
        }
        let function_id = declarations.functions.iter().position(|function| {
            function.body.start <= name.start as usize
                && (name.end as usize) <= function.body.end
        });
        let resolved = resolve_variable(
            declarations,
            function_id,
            argument.text.as_str(),
            argument.start as usize,
        );
        if resolved
            .is_some_and(|(ty, _, _)| canonical_type_text(&ty) == expected_type)
        {
            offsets.push(argument.start as usize);
        }
    }
    offsets
}

fn abort_after_exit_registration_offsets(
    index: &CExpressionIndex,
    declarations: &CDeclarationIndex,
) -> Vec<usize> {
    let function_pointer_names = declarations
        .declarations
        .iter()
        .flat_map(|declaration| &declaration.declarators)
        .filter(|declarator| {
            declarator
                .derived
                .iter()
                .any(|derived| matches!(derived, D::Pointer))
                && declarator
                    .derived
                    .iter()
                    .any(|derived| matches!(derived, D::Function { .. }))
        })
        .filter_map(|declarator| declarator.name.as_deref())
        .collect::<HashSet<_>>();
    let mut registered = false;
    let mut offsets = Vec::new();
    for call in index.facts.iter().filter(|fact| fact.kind == K::Call) {
        let Some(at) = index
            .tokens
            .iter()
            .position(|token| token.start as usize == call.offset)
        else {
            continue;
        };
        let name = &index.tokens[at];
        if at > 0 && matches!(index.tokens[at - 1].text.as_str(), "." | "->" | "::")
            || function_pointer_names.contains(name.text.as_str())
        {
            continue;
        }
        match name.text.as_str() {
            "atexit" | "at_quick_exit" => registered = true,
            "assert" | "abort" if registered => offsets.push(name.start as usize),
            _ => {}
        }
    }
    offsets
}

fn relational_has_direct_character_literal(
    index: &CExpressionIndex,
    operator_offset: usize,
) -> bool {
    let Some(operator) = index
        .tokens
        .iter()
        .position(|token| token.start as usize == operator_offset)
    else {
        return false;
    };
    direct_character_operand(index, operator, false)
        || direct_character_operand(index, operator, true)
}

fn direct_character_operand(
    index: &CExpressionIndex,
    operator: usize,
    right: bool,
) -> bool {
    let operand_index = if right {
        operator + 1
    } else if let Some(previous) = operator.checked_sub(1) {
        previous
    } else {
        return false;
    };
    let Some(operand) = index.tokens.get(operand_index) else {
        return false;
    };
    let (literal, outside) = if right && operand.text == "(" {
        let Some(close) = index.matching_token_index(operand_index) else {
            return false;
        };
        let inner = &index.tokens[operand_index + 1..close];
        if inner.len() != 1 {
            return false;
        }
        (&inner[0], index.tokens.get(close + 1))
    } else if !right && operand.text == ")" {
        let Some(open) = index.matching_token_index(operand_index) else {
            return false;
        };
        let inner = &index.tokens[open + 1..operand_index];
        if inner.len() != 1 {
            return false;
        }
        (&inner[0], open.checked_sub(1).and_then(|at| index.tokens.get(at)))
    } else {
        let outside = if right {
            index.tokens.get(operand_index + 1)
        } else {
            operand_index.checked_sub(1).and_then(|at| index.tokens.get(at))
        };
        (operand, outside)
    };
    literal.kind == TokKind::StringLit
        && literal.text.contains('\'')
        && outside.is_none_or(|token| {
            !matches!(token.text.as_str(), "+" | "-" | "*" | "/" | "%" | "<<" | ">>")
        })
}

fn standalone_postfix_update_offsets(
    index: &CExpressionIndex,
    syntax: &JavaSyntax,
) -> Vec<usize> {
    let mut ranges = syntax
        .nodes
        .iter()
        .filter(|node| node.kind == JavaSyntaxKind::Other)
        .map(|node| node.range.clone())
        .chain(
            syntax
                .nodes
                .iter()
                .filter(|node| node.kind == JavaSyntaxKind::For)
                .filter_map(|node| node.update.clone()),
        )
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| (range.start, range.end));
    ranges.dedup();
    let mut offsets = Vec::new();
    for range in ranges {
        let tokens = index
            .tokens
            .iter()
            .filter(|token| {
                token.kind != TokKind::Eof
                    && token.start as usize >= range.start
                    && (token.end as usize) <= range.end
            })
            .collect::<Vec<_>>();
        let tokens = if tokens.last().is_some_and(|token| token.text == ";") {
            &tokens[..tokens.len() - 1]
        } else {
            &tokens[..]
        };
        let Some(operator) = tokens.last() else {
            continue;
        };
        if !matches!(operator.text.as_str(), "++" | "--")
            || tokens.len() < 2
            || index.facts.iter().any(|fact| {
                range.start <= fact.offset
                    && fact.offset < range.end
                    && matches!(
                        fact.kind,
                        K::Assignment | K::Binary | K::Comma | K::Conditional | K::Call
                    )
            })
        {
            continue;
        }
        offsets.push(tokens[0].start as usize);
    }
    offsets
}
