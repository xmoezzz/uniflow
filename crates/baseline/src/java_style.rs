use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uniflow_parser_core::java_syntax::{
    JavaDeclaration, JavaDeclarationKind as D, JavaSyntax, JavaSyntaxKind as K,
};
use uniflow_parser_core::{TokKind, Token};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaStyleCheck {
    EmptyBlock,
    EmptyIf,
    EmptyElse,
    EmptyLoop,
    EmptyMethod,
    EmptySynchronized,
    EmptyTry,
    EmptyInfiniteLoop,
    InfiniteLoop,
    AssignmentCondition,
    ConsecutiveSemicolons,
    DetachedIfBlock,
    MissingSwitchDefault,
    FinalCloneMethod,
    PrivateFinalize,
    RequestMappingMethodPublic,
    RewriteThreadRunMethod,
    DefaultConstructorExternalizable,
    EqualsHashcodeCheck,
    SerializeMethodSign,
    SerialVersionUidDefined,
    StaticFinalLogger,
    MultipleLogger,
    FieldNameAndClassNameSame,
    FieldNameAndMethodNameSame,
    FinalPublicStaticField,
    StaticPrivateFinalObjectstreamfield,
    StaticPublicFinalArray,
    StaticPublicFinalObject,
    ImmutableFinalField,
    ImmutablePublicFinalField,
    TransientFieldClass,
    StateholderRestorestateSavestate,
    StaticThreadNotSecObject,
    InnerClassImplementSerializable,
    RewriteCloneMethod,
    NextThrowNoSuchElementException,
    AnonymousInnerClassCallMethod,
    ClassInitializerUseThread,
    SelectInterpolation,
    SyncObjectIsFinal,
    SynchronizedObject,
    SyncObjectNotifyMethod,
    EmptyCaseBlock,
    SwitchCaseBreak,
    HashUrl,
    UnusedField,
    UnusedMethod,
    UnusedVariable,
    InnerClassUseOuterClassField,
    ImmutableField,
    CloneCallOverrideMethod,
    CtorCallOverrideMethod,
    CallSecuritymanagerCheckMethod,
    CloneMethodUseSecMethod,
    ReadobjectCallFinalMethod,
    NativeMethod,
    CloneWithoutCloneable,
    FinalizeWithoutSuper,
    ReturnGenericWildcard,
    AssertAlwaysFalse,
    AssertSideEffect,
    AssertValidatesParameter,
    MethodOverFiftyLines,
    NestedForOverThree,
    NestedIfOverThree,
    TryInsideLoop,
    ConstantName,
    SerializableMissingUid,
    SerializableSensitiveField,
    AppletPublicMutableField,
    AppletInnerClass,
    AppletReturnsPrivateArray,
    EqualsMissingTypeCheck,
    CustomX509TrustManager,
    MultipartUploadEndpoint,
    InclusiveArrayLengthLoop,
    ActivityMissingOnPause,
    ApplicationMissingProviderUpdate,
    SpringSecurityMissingCsp,
    SpringAntMatcherPermitAll,
    SpringAntMatcherUrlOrder,
    InsecureWebDataBinder,
    MemoryLeakNonStaticInnerClass,
    GetterSetterSynchronizationMismatch,
    WrongGetterSetterField,
    SynchronizeOnGetClass,
    SynchronizeOnConcurrencyObject,
    SerializableMissingSecurityCheck,
    SerializableDangerousMethodCall,
    InstanceLockProtectsStaticData,
    JavaStandardLibraryIdentifier,
    CaseInsensitivePackageComparison,
    JavaEeMainMethod,
    AndroidStaticCryptoSecret,
    SerializableParentMissingNoArgConstructor,
    MultipleServletStreamCommit,
    ExposeAliasedBuffer,
    HiddenInheritedMethod,
    MisleadingMethodSignature,
    UnsynchronizedOverride,
    IncreasedOverrideAccessibility,
    CollectionViewSynchronization,
    InvalidConstantRegex,
    SpringSecurityMissingDenyAll,
    DoubleCheckedLocking,
    StaticUnsafeFormatterField,
    StaticDatabaseConnection,
    ServletMutableInstanceField,
    ClassInitializationCycle,
    AndroidSharedStorageApkInstall,
    WrongParameterOrder,
    FixedInitializationVector,
    PublicPrivilegedMethod,
    StrutsAwareMapExposure,
    SpringSessionAttributes,
    SpringPersistedEntityBinding,
    UnsafeZipEntryExtraction,
    SessionFixation,
    PbeExternalSalt,
    CookieSecurityDecision,
    MissingXmlValidation,
    AxisMissingReturnType,
    FragmentInjection,
    JsonpSameOriginExecution,
    DeserializationBlacklist,
    HttpRequestSmugglingHeaders,
    ExcessiveMemoryAllocation,
    ExternalDivideByZero,
    ExternalArrayIndex,
    ExternalLoopBound,
    ExternalIntegerArithmetic,
}

impl JavaStyleCheck {
    pub(crate) fn offsets(self, source: &str, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        if matches!(
            self,
            C::AssertAlwaysFalse | C::AssertSideEffect | C::AssertValidatesParameter
        ) {
            return self.assert_offsets(syntax);
        }
        if matches!(self, C::InvalidConstantRegex) {
            return invalid_constant_regex_offsets(source, syntax);
        }
        if matches!(self, C::DoubleCheckedLocking) {
            return double_checked_locking_offsets(syntax);
        }
        if matches!(self, C::ClassInitializationCycle) {
            return class_initialization_cycle_offsets(syntax);
        }
        if matches!(self, C::AndroidSharedStorageApkInstall) {
            return android_shared_storage_apk_offsets(syntax);
        }
        if matches!(self, C::WrongParameterOrder) {
            return wrong_parameter_order_offsets(syntax);
        }
        if matches!(self, C::FixedInitializationVector) {
            return fixed_initialization_vector_offsets(source, syntax);
        }
        if matches!(
            self,
            C::MethodOverFiftyLines
                | C::ConstantName
                | C::SerializableMissingUid
                | C::SerializableSensitiveField
                | C::AppletPublicMutableField
                | C::AppletInnerClass
                | C::AppletReturnsPrivateArray
                | C::EqualsMissingTypeCheck
                | C::CustomX509TrustManager
                | C::MultipartUploadEndpoint
                | C::ActivityMissingOnPause
                | C::ApplicationMissingProviderUpdate
                | C::SpringSecurityMissingCsp
                | C::SpringAntMatcherPermitAll
                | C::SpringAntMatcherUrlOrder
                | C::InsecureWebDataBinder
                | C::MemoryLeakNonStaticInnerClass
                | C::GetterSetterSynchronizationMismatch
                | C::WrongGetterSetterField
                | C::JavaStandardLibraryIdentifier
                | C::JavaEeMainMethod
                | C::AndroidStaticCryptoSecret
                | C::SerializableParentMissingNoArgConstructor
                | C::ExposeAliasedBuffer
                | C::HiddenInheritedMethod
                | C::MisleadingMethodSignature
                | C::UnsynchronizedOverride
                | C::IncreasedOverrideAccessibility
                | C::SpringSecurityMissingDenyAll
                | C::StaticUnsafeFormatterField
                | C::StaticDatabaseConnection
                | C::ServletMutableInstanceField
                | C::PublicPrivilegedMethod
                | C::StrutsAwareMapExposure
                | C::SpringSessionAttributes
                | C::SpringPersistedEntityBinding
                | C::UnsafeZipEntryExtraction
                | C::SessionFixation
                | C::PbeExternalSalt
                | C::CookieSecurityDecision
                | C::MissingXmlValidation
                | C::AxisMissingReturnType
                | C::FragmentInjection
                | C::JsonpSameOriginExecution
                | C::DeserializationBlacklist
                | C::HttpRequestSmugglingHeaders
                | C::ExcessiveMemoryAllocation
                | C::ExternalDivideByZero
                | C::ExternalArrayIndex
                | C::ExternalLoopBound
                | C::ExternalIntegerArithmetic
        ) {
            return self.quality_declaration_offsets(source, syntax);
        }
        if matches!(
            self,
            C::NestedForOverThree | C::NestedIfOverThree | C::TryInsideLoop
        ) {
            return self.nesting_offsets(syntax);
        }
        if matches!(self, C::InstanceLockProtectsStaticData) {
            return instance_lock_static_data_offsets(syntax);
        }
        if matches!(self, C::CaseInsensitivePackageComparison) {
            return case_insensitive_package_offsets(source, syntax);
        }
        if matches!(self, C::MultipleServletStreamCommit) {
            return multiple_servlet_stream_commit_offsets(syntax);
        }
        if matches!(
            self,
            C::SyncObjectIsFinal
                | C::SynchronizedObject
                | C::SyncObjectNotifyMethod
                | C::SynchronizeOnGetClass
                | C::SynchronizeOnConcurrencyObject
                | C::CollectionViewSynchronization
        ) {
            return self.synchronization_offsets(syntax);
        }
        if matches!(self, C::HashUrl) {
            return hash_url_offsets(syntax);
        }
        if matches!(
            self,
            C::UnusedField
                | C::UnusedMethod
                | C::UnusedVariable
                | C::InnerClassUseOuterClassField
                | C::ImmutableField
        ) {
            return self.usage_offsets(syntax);
        }
        if matches!(
            self,
            C::CloneCallOverrideMethod
                | C::CtorCallOverrideMethod
                | C::CallSecuritymanagerCheckMethod
                | C::CloneMethodUseSecMethod
                | C::ReadobjectCallFinalMethod
                | C::SerializableMissingSecurityCheck
                | C::SerializableDangerousMethodCall
        ) {
            return self.member_call_offsets(syntax);
        }
        if matches!(
            self,
            C::FinalCloneMethod
                | C::PrivateFinalize
                | C::RequestMappingMethodPublic
                | C::RewriteThreadRunMethod
                | C::DefaultConstructorExternalizable
                | C::EqualsHashcodeCheck
                | C::SerializeMethodSign
                | C::SerialVersionUidDefined
                | C::StaticFinalLogger
                | C::MultipleLogger
                | C::FieldNameAndClassNameSame
                | C::FieldNameAndMethodNameSame
                | C::FinalPublicStaticField
                | C::StaticPrivateFinalObjectstreamfield
                | C::StaticPublicFinalArray
                | C::StaticPublicFinalObject
                | C::ImmutableFinalField
                | C::ImmutablePublicFinalField
                | C::TransientFieldClass
                | C::StateholderRestorestateSavestate
                | C::StaticThreadNotSecObject
                | C::InnerClassImplementSerializable
                | C::RewriteCloneMethod
                | C::NextThrowNoSuchElementException
                | C::AnonymousInnerClassCallMethod
                | C::ClassInitializerUseThread
                | C::SelectInterpolation
                | C::NativeMethod
                | C::CloneWithoutCloneable
                | C::FinalizeWithoutSuper
                | C::ReturnGenericWildcard
        ) {
            return self.declaration_offsets(source, syntax);
        }
        syntax
            .nodes
            .iter()
            .filter(|node| {
                let empty_body = || node.body.clone().is_some_and(|r| empty(source, r));
                let is_loop = matches!(node.kind, K::While | K::For | K::Do);
                match self {
                    C::EmptyBlock => node.kind == K::Block && empty(source, node.range.clone()),
                    C::EmptyIf => node.kind == K::If && empty_body(),
                    C::EmptyElse => {
                        node.kind == K::If
                            && node.alternative.clone().is_some_and(|r| empty(source, r))
                    }
                    C::EmptyLoop => is_loop && empty_body(),
                    C::EmptyMethod => node.kind == K::Method && empty_body(),
                    C::EmptySynchronized => node.kind == K::Synchronized && empty_body(),
                    C::EmptyTry => node.kind == K::Try && empty_body(),
                    C::EmptyInfiniteLoop | C::InfiniteLoop => {
                        is_loop
                            && (matches!(self, C::InfiniteLoop) || empty_body())
                            && node.body.as_ref().is_some_and(|r| {
                                let body = source[r.clone()].trim();
                                body == ";" || body.starts_with('{')
                            })
                            && node.condition.clone().is_some_and(|r| {
                                if node.kind == K::For {
                                    // Only for(;;), not for(init;;update).
                                    let end =
                                        node.body.as_ref().map_or(node.range.end, |b| b.start);
                                    syntax
                                        .tokens_in(node.range.start..end)
                                        .map(|t| t.text.as_str())
                                        .eq(["for", "(", ";", ";", ")"])
                                } else {
                                    syntax.tokens_in(r).map(|t| t.text.as_str()).eq(["true"])
                                }
                            })
                    }
                    C::AssignmentCondition => {
                        (is_loop || node.kind == K::If)
                            && node.condition.clone().is_some_and(|r| {
                                syntax.tokens_in(r).any(|t| {
                                    t.kind == TokKind::Symbol
                                        && matches!(
                                            t.text.as_str(),
                                            "=" | "+="
                                                | "-="
                                                | "*="
                                                | "/="
                                                | "%="
                                                | "&="
                                                | "|="
                                                | "^="
                                                | "<<="
                                                | ">>="
                                                | ">>>="
                                        )
                                })
                            })
                    }
                    C::ConsecutiveSemicolons => node.kind == K::Empty && node.follows_empty,
                    C::DetachedIfBlock => {
                        node.kind == K::If
                            && node.followed_by_block
                            && node
                                .body
                                .as_ref()
                                .is_some_and(|r| source[r.clone()].trim() == ";")
                            && node.alternative.is_none()
                    }
                    C::MissingSwitchDefault => {
                        node.kind == K::Switch
                            && node.body.clone().is_some_and(|r| {
                                let tokens = syntax.tokens_in(r).collect::<Vec<_>>();
                                !tokens.windows(2).any(|pair| {
                                    pair[0].kind == TokKind::Ident
                                        && pair[0].text == "default"
                                        && matches!(pair[1].text.as_str(), ":" | "->")
                                })
                            })
                    }
                    C::EmptyCaseBlock => {
                        node.kind == K::SwitchGroup
                            && node.label_is_case
                            && node
                                .body
                                .clone()
                                .is_some_and(|range| syntax.tokens_in(range).next().is_none())
                    }
                    C::SwitchCaseBreak => {
                        node.kind == K::SwitchGroup
                            && node.label_is_case
                            && !node.arrow_label
                            && node.body.clone().is_some_and(|range| {
                                let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
                                !tokens.is_empty()
                                    && !tokens.iter().any(|token| {
                                        token.kind == TokKind::Ident
                                            && matches!(
                                                token.text.as_str(),
                                                "break" | "return" | "throw"
                                            )
                                    })
                            })
                    }
                    C::InclusiveArrayLengthLoop => {
                        node.kind == K::For
                            && node.condition.clone().is_some_and(|range| {
                                let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
                                tokens.iter().any(|token| token.text == "<=")
                                    && tokens
                                        .windows(2)
                                        .any(|pair| pair[0].text == "." && pair[1].text == "length")
                            })
                    }
                    C::AssertAlwaysFalse
                    | C::AssertSideEffect
                    | C::AssertValidatesParameter
                    | C::MethodOverFiftyLines
                    | C::NestedForOverThree
                    | C::NestedIfOverThree
                    | C::TryInsideLoop
                    | C::ConstantName => false,
                    _ => false,
                }
            })
            .map(|node| node.range.start)
            .collect()
    }

    fn assert_offsets(self, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        syntax
            .nodes
            .iter()
            .filter(|node| node.kind == K::Other)
            .filter_map(|node| {
                let tokens = syntax.tokens_in(node.range.clone()).collect::<Vec<_>>();
                if tokens.first().is_none_or(|token| token.text != "assert") {
                    return None;
                }
                let expression = tokens
                    .iter()
                    .skip(1)
                    .take_while(|token| !matches!(token.text.as_str(), ":" | ";"))
                    .collect::<Vec<_>>();
                let matched = match self {
                    C::AssertAlwaysFalse => expression.len() == 1 && expression[0].text == "false",
                    C::AssertSideEffect => {
                        expression.iter().any(|token| {
                            matches!(
                                token.text.as_str(),
                                "=" | "+="
                                    | "-="
                                    | "*="
                                    | "/="
                                    | "%="
                                    | "&="
                                    | "|="
                                    | "^="
                                    | "++"
                                    | "--"
                            )
                        }) || expression.windows(2).any(|pair| {
                            matches!(
                                (pair[0].text.as_str(), pair[1].text.as_str()),
                                ("+", "+") | ("-", "-")
                            )
                        })
                    }
                    C::AssertValidatesParameter => syntax.declarations.iter().any(|declaration| {
                        declaration.kind == D::Method
                            && declaration.body.as_ref().is_some_and(|body| {
                                body.start <= node.range.start && node.range.end <= body.end
                            })
                            && declaration.parameters.clone().is_some_and(|parameters| {
                                assertion_parameter_names(syntax, parameters)
                                    .iter()
                                    .any(|name| expression.iter().any(|token| token.text == *name))
                            })
                    }),
                    _ => false,
                };
                matched.then_some(node.range.start)
            })
            .collect()
    }

    fn quality_declaration_offsets(self, source: &str, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        syntax
            .declarations
            .iter()
            .filter(|declaration| match self {
                C::MethodOverFiftyLines => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            source[body].bytes().filter(|byte| *byte == b'\n').count() + 1 > 50
                        })
                }
                C::ConstantName => {
                    declaration.kind == D::Field
                        && declaration.modifiers.iter().any(|value| value == "static")
                        && declaration.modifiers.iter().any(|value| value == "final")
                        && declaration.names.iter().any(|name| !constant_name(name))
                }
                C::SerializableMissingUid => {
                    declaration.kind == D::Class
                        && declaration
                            .interfaces
                            .iter()
                            .any(|base| base.rsplit('.').next() == Some("Serializable"))
                        && !syntax.declarations.iter().any(|field| {
                            field.owner
                                == syntax
                                    .declarations
                                    .iter()
                                    .position(|item| std::ptr::eq(item, *declaration))
                                && field.kind == D::Field
                                && field.names.iter().any(|name| name == "serialVersionUID")
                        })
                }
                C::SerializableSensitiveField => {
                    declaration.kind == D::Field
                        && !declaration
                            .modifiers
                            .iter()
                            .any(|value| matches!(value.as_str(), "transient" | "static"))
                        && declaration.owner.is_some_and(|owner| {
                            syntax.declarations[owner]
                                .interfaces
                                .iter()
                                .any(|base| base.rsplit('.').next() == Some("Serializable"))
                        })
                        && declaration.names.iter().any(|name| {
                            let name = name.to_ascii_lowercase();
                            [
                                "password",
                                "passwd",
                                "secret",
                                "token",
                                "credential",
                                "privatekey",
                            ]
                            .iter()
                            .any(|part| name.contains(part))
                        })
                }
                C::AppletPublicMutableField => {
                    declaration.kind == D::Field
                        && declaration.modifiers.iter().any(|value| value == "public")
                        && !declaration.modifiers.iter().any(|value| value == "final")
                        && declaration.owner.is_some_and(|owner| {
                            syntax.declarations[owner].superclass.rsplit('.').next()
                                == Some("Applet")
                        })
                }
                C::AppletInnerClass => {
                    matches!(
                        declaration.kind,
                        D::Class | D::Interface | D::Enum | D::Record
                    ) && declaration.owner.is_some_and(|owner| {
                        syntax.declarations[owner].superclass.rsplit('.').next() == Some("Applet")
                    })
                }
                C::AppletReturnsPrivateArray => {
                    declaration.kind == D::Method
                        && declaration.modifiers.iter().any(|value| value == "public")
                        && declaration.declared_type.contains('[')
                        && declaration.owner.is_some_and(|owner| {
                            let class = &syntax.declarations[owner];
                            class.superclass.rsplit('.').next() == Some("Applet")
                                && syntax.declarations.iter().any(|field| {
                                    field.owner == Some(owner)
                                        && field.kind == D::Field
                                        && field.declared_type.contains('[')
                                        && field.modifiers.iter().any(|value| value == "private")
                                        && field.names.iter().any(|name| {
                                            let tokens = syntax
                                                .tokens_in(declaration.range.clone())
                                                .collect::<Vec<_>>();
                                            tokens.windows(2).enumerate().any(|(index, pair)| {
                                                pair[0].text == "return"
                                                    && pair[1].text == *name
                                                    && tokens.get(index + 2).is_some_and(|next| {
                                                        next.text != "." && next.text != "["
                                                    })
                                            })
                                        })
                                })
                        })
                }
                C::EqualsMissingTypeCheck => {
                    declaration.kind == D::Method
                        && declaration.name == "equals"
                        && declaration.body.is_some()
                        && !syntax
                            .tokens_in(declaration.body.clone().unwrap())
                            .any(|token| matches!(token.text.as_str(), "instanceof" | "getClass"))
                }
                C::CustomX509TrustManager => {
                    declaration.kind == D::Class
                        && declaration
                            .interfaces
                            .iter()
                            .any(|base| base.rsplit('.').next() == Some("X509TrustManager"))
                }
                C::MultipartUploadEndpoint => {
                    declaration.kind == D::Method
                        && declaration.parameters.clone().is_some_and(|parameters| {
                            syntax.tokens_in(parameters).any(|token| {
                                token.kind == TokKind::Ident
                                    && matches!(token.text.as_str(), "MultipartFile" | "Part")
                            })
                        })
                        && declaration.annotations.iter().any(|annotation| {
                            matches!(
                                annotation.rsplit('.').next(),
                                Some("RequestMapping" | "PostMapping")
                            )
                        })
                }
                C::ActivityMissingOnPause => {
                    declaration.kind == D::Class
                        && declaration
                            .superclass
                            .rsplit('.')
                            .next()
                            .is_some_and(|base| base == "Activity" || base.ends_with("Activity"))
                        && !syntax.declarations.iter().any(|method| {
                            method.owner
                                == syntax
                                    .declarations
                                    .iter()
                                    .position(|item| std::ptr::eq(item, *declaration))
                                && method.kind == D::Method
                                && method.name == "onPause"
                        })
                }
                C::ApplicationMissingProviderUpdate => {
                    declaration.kind == D::Class
                        && declaration.superclass.rsplit('.').next() == Some("Application")
                        && !syntax.tokens_in(declaration.range.clone()).any(|token| {
                            matches!(
                                token.text.as_str(),
                                "installIfNeeded" | "installIfNeededAsync"
                            )
                        })
                }
                C::SpringSecurityMissingCsp => {
                    declaration.kind == D::Method
                        && declaration.name == "configure"
                        && declaration.parameters.clone().is_some_and(|parameters| {
                            syntax
                                .tokens_in(parameters)
                                .any(|token| token.text == "HttpSecurity")
                        })
                        && declaration.body.is_some()
                        && !syntax
                            .tokens_in(declaration.body.clone().unwrap())
                            .any(|token| token.text == "contentSecurityPolicy")
                }
                C::SpringSecurityMissingDenyAll => {
                    declaration.kind == D::Method
                        && declaration.name == "configure"
                        && declaration.parameters.clone().is_some_and(|parameters| {
                            syntax
                                .tokens_in(parameters)
                                .any(|token| token.text == "HttpSecurity")
                        })
                        && declaration.body.clone().is_some_and(|body| {
                            let has_specific_matcher = [
                                "mvcMatchers",
                                "antMatchers",
                                "requestMatchers",
                                "securityMatcher",
                            ]
                            .iter()
                            .any(|method| {
                                syntax.has_token_sequence(body.clone(), &[*method, "("])
                            });
                            has_specific_matcher
                                && !syntax.has_token_sequence(
                                    body,
                                    &["anyRequest", "(", ")", ".", "denyAll", "("],
                                )
                        })
                }
                C::SpringAntMatcherPermitAll => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            syntax.has_token_sequence(body.clone(), &["antMatchers", "("])
                                && syntax.has_token_sequence(
                                    body,
                                    &["anyRequest", "(", ")", ".", "permitAll"],
                                )
                        })
                }
                C::SpringAntMatcherUrlOrder => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let mut patterns = Vec::new();
                            for index in 0..tokens.len().saturating_sub(2) {
                                if tokens[index].text == "antMatchers"
                                    && tokens[index + 1].text == "("
                                    && tokens[index + 2].kind == TokKind::StringLit
                                {
                                    patterns
                                        .push(tokens[index + 2].text.trim_matches('"').to_string());
                                }
                            }
                            patterns.iter().enumerate().any(|(index, pattern)| {
                                pattern.ends_with("/**")
                                    && patterns[index + 1..].iter().any(|later| {
                                        later != pattern
                                            && later.starts_with(pattern.trim_end_matches("**"))
                                    })
                            })
                        })
                }
                C::InsecureWebDataBinder => {
                    declaration.kind == D::Method
                        && declaration
                            .annotations
                            .iter()
                            .any(|annotation| annotation.rsplit('.').next() == Some("InitBinder"))
                        && declaration.body.is_some()
                        && !syntax
                            .tokens_in(declaration.body.clone().unwrap())
                            .any(|token| {
                                matches!(
                                    token.text.as_str(),
                                    "setAllowedFields" | "setDisallowedFields"
                                )
                            })
                }
                C::MemoryLeakNonStaticInnerClass => {
                    matches!(declaration.kind, D::Class | D::AnonymousClass)
                        && declaration.owner.is_some_and(|owner| {
                            matches!(
                                syntax.declarations[owner].kind,
                                D::Class | D::AnonymousClass
                            )
                        })
                        && !declaration.modifiers.iter().any(|value| value == "static")
                }
                C::GetterSetterSynchronizationMismatch => {
                    declaration.kind == D::Method
                        && bean_property(&declaration.name).is_some_and(|(kind, property)| {
                            !method_is_synchronized(syntax, declaration)
                                && syntax.declarations.iter().any(|other| {
                                    other.owner == declaration.owner
                                        && other.kind == D::Method
                                        && bean_property(&other.name).is_some_and(
                                            |(other_kind, other_property)| {
                                                property == other_property
                                                    && kind != other_kind
                                                    && method_is_synchronized(syntax, other)
                                            },
                                        )
                                })
                        })
                }
                C::WrongGetterSetterField => {
                    declaration.kind == D::Method
                        && bean_property(&declaration.name).is_some_and(|(kind, property)| {
                            direct_bean_field(syntax, declaration, kind)
                                .is_some_and(|actual| actual != property)
                        })
                }
                C::JavaStandardLibraryIdentifier => {
                    matches!(
                        declaration.kind,
                        D::Class | D::Interface | D::Enum | D::Record
                    ) && is_java_standard_type_name(&declaration.name)
                }
                C::JavaEeMainMethod => {
                    declaration.kind == D::Method
                        && declaration.name == "main"
                        && declaration.modifiers.iter().any(|value| value == "public")
                        && declaration.modifiers.iter().any(|value| value == "static")
                        && declaration.owner.is_some_and(|owner| {
                            let class = &syntax.declarations[owner];
                            class.superclass.rsplit('.').next() == Some("HttpServlet")
                                || class.annotations.iter().any(|annotation| {
                                    matches!(
                                        annotation.rsplit('.').next(),
                                        Some("WebServlet" | "Controller" | "RestController")
                                    )
                                })
                        })
                }
                C::AndroidStaticCryptoSecret => {
                    declaration.kind == D::Field
                        && declaration.modifiers.iter().any(|value| value == "static")
                        && (declaration.names.iter().any(|name| {
                            let name = name.to_ascii_lowercase();
                            name.contains("secret")
                                || name.contains("privatekey")
                                || name.contains("encryptionkey")
                                || name.contains("cryptokey")
                        }) || matches!(
                            declaration.declared_type.rsplit('.').next(),
                            Some("SecretKey" | "PrivateKey" | "KeyPair")
                        ))
                }
                C::StaticUnsafeFormatterField => {
                    declaration.kind == D::Field
                        && declaration.modifiers.iter().any(|value| value == "static")
                        && matches!(
                            declaration.declared_type.rsplit('.').next(),
                            Some(
                                "Format"
                                    | "DateFormat"
                                    | "SimpleDateFormat"
                                    | "NumberFormat"
                                    | "DecimalFormat"
                                    | "MessageFormat"
                            )
                        )
                }
                C::StaticDatabaseConnection => {
                    declaration.kind == D::Field
                        && declaration.modifiers.iter().any(|value| value == "static")
                        && matches!(
                            declaration.declared_type.rsplit('.').next(),
                            Some("Connection" | "EntityManager" | "Session")
                        )
                }
                C::ServletMutableInstanceField => {
                    declaration.kind == D::Field
                        && !declaration.modifiers.iter().any(|value| value == "static")
                        && declaration.owner.is_some_and(|owner| {
                            let class = &syntax.declarations[owner];
                            matches!(
                                class.superclass.rsplit('.').next(),
                                Some("HttpServlet" | "GenericServlet" | "Action")
                            )
                        })
                        && !(declaration.modifiers.iter().any(|value| value == "final")
                            && matches!(
                                declaration.declared_type.rsplit('.').next(),
                                Some(
                                    "boolean"
                                        | "byte"
                                        | "short"
                                        | "int"
                                        | "long"
                                        | "float"
                                        | "double"
                                        | "char"
                                        | "String"
                                )
                            ))
                }
                C::PublicPrivilegedMethod => {
                    declaration.kind == D::Method
                        && declaration.modifiers.iter().any(|value| value == "public")
                        && declaration.body.clone().is_some_and(|body| {
                            syntax.has_token_sequence(
                                body,
                                &["AccessController", ".", "doPrivileged", "("],
                            )
                        })
                }
                C::StrutsAwareMapExposure => {
                    declaration.kind == D::Class
                        && declaration.interfaces.iter().any(|interface| {
                            matches!(
                                interface.rsplit('.').next(),
                                Some("ApplicationAware" | "RequestAware" | "SessionAware")
                            )
                        })
                        && !declaration.interfaces.iter().any(|interface| {
                            interface.rsplit('.').next() == Some("ParameterNameAware")
                        })
                        && syntax
                            .declarations
                            .iter()
                            .position(|candidate| std::ptr::eq(candidate, *declaration))
                            .is_some_and(|id| {
                                !syntax.declarations.iter().any(|method| {
                                    method.owner == Some(id)
                                        && method.kind == D::Method
                                        && method.name == "acceptableParameterName"
                                })
                            })
                }
                C::SpringSessionAttributes => {
                    declaration.kind == D::Class
                        && declaration.annotations.iter().any(|annotation| {
                            annotation.rsplit('.').next() == Some("SessionAttributes")
                        })
                        && syntax
                            .declarations
                            .iter()
                            .position(|candidate| std::ptr::eq(candidate, *declaration))
                            .is_some_and(|id| {
                                syntax.declarations.iter().any(|method| {
                                    method.owner == Some(id)
                                        && method.kind == D::Method
                                        && method.annotations.iter().any(|annotation| {
                                            matches!(
                                                annotation.rsplit('.').next(),
                                                Some(
                                                    "RequestMapping"
                                                        | "GetMapping"
                                                        | "PostMapping"
                                                        | "PutMapping"
                                                        | "PatchMapping"
                                                )
                                            )
                                        })
                                })
                            })
                }
                C::SpringPersistedEntityBinding => {
                    declaration.kind == D::Method
                        && declaration.annotations.iter().any(|annotation| {
                            matches!(
                                annotation.rsplit('.').next(),
                                Some(
                                    "RequestMapping"
                                        | "PostMapping"
                                        | "PutMapping"
                                        | "PatchMapping"
                                )
                            )
                        })
                        && parameter_bindings(syntax, declaration).iter().any(|(name, ty)| {
                            syntax.declarations.iter().any(|class| {
                                matches!(class.kind, D::Class | D::Record)
                                    && class.name == ty.rsplit('.').next().unwrap_or(ty)
                                    && class.annotations.iter().any(|annotation| {
                                        matches!(
                                            annotation.rsplit('.').next(),
                                            Some("Entity" | "Document" | "Table")
                                        )
                                    })
                            }) && declaration.body.clone().is_some_and(|body| {
                                let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                                tokens.windows(4).any(|window| {
                                    matches!(
                                        window[0].text.as_str(),
                                        "save" | "persist" | "merge"
                                    ) && window[1].text == "("
                                        && window[2].text == *name
                                }) || tokens.windows(6).any(|window| {
                                    window[1].text == "."
                                        && matches!(
                                            window[2].text.as_str(),
                                            "save" | "persist" | "merge"
                                        )
                                        && window[3].text == "("
                                        && window[4].text == *name
                                })
                            })
                        })
                }
                C::UnsafeZipEntryExtraction => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let entry_name = tokens.windows(2).any(|pair| {
                                pair[0].text == "getName" && pair[1].text == "("
                            });
                            let path_sink = tokens.windows(2).any(|pair| {
                                matches!(
                                    pair[0].text.as_str(),
                                    "File" | "get" | "resolve" | "copy" | "move"
                                ) && pair[1].text == "("
                            });
                            let normalized = tokens.iter().any(|token| {
                                matches!(
                                    token.text.as_str(),
                                    "getCanonicalPath" | "getCanonicalFile" | "normalize"
                                )
                            });
                            let containment_checked = tokens.iter().any(|token| {
                                matches!(token.text.as_str(), "startsWith" | "relativize")
                            });
                            entry_name && path_sink && !(normalized && containment_checked)
                        })
                }
                C::SessionFixation => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let Some(login) = tokens.windows(2).position(|pair| {
                                pair[0].text == "login" && pair[1].text == "("
                            }) else {
                                return false;
                            };
                            let authentication_context = parameter_bindings(syntax, declaration)
                                .iter()
                                .any(|(_, ty)| {
                                    matches!(
                                        ty.rsplit('.').next(),
                                        Some(
                                            "LoginContext"
                                                | "AuthenticationManager"
                                                | "UsernamePasswordAuthenticationToken"
                                        )
                                    )
                                });
                            let invalidated_first = tokens[..login].windows(2).any(|pair| {
                                pair[0].text == "invalidate" && pair[1].text == "("
                            });
                            authentication_context && !invalidated_first
                        })
                }
                C::PbeExternalSalt => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let pbe = tokens.windows(3).any(|window| {
                                window[0].text == "new"
                                    && window[1].text == "PBEParameterSpec"
                                    && window[2].text == "("
                            });
                            let external = tokens.windows(2).any(|pair| {
                                matches!(
                                    pair[0].text.as_str(),
                                    "getProperty" | "getParameter" | "readLine" | "nextLine"
                                ) && pair[1].text == "("
                            });
                            pbe && external
                        })
                }
                C::CookieSecurityDecision => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let reads_cookie = tokens.windows(2).any(|pair| {
                                matches!(pair[0].text.as_str(), "getCookies" | "getValue")
                                    && pair[1].text == "("
                            });
                            let security_value = tokens.iter().any(|token| {
                                let name = token.text.to_ascii_lowercase();
                                [
                                    "admin",
                                    "role",
                                    "privilege",
                                    "permission",
                                    "authenticated",
                                    "authorized",
                                ]
                                .iter()
                                .any(|needle| name.contains(needle))
                            });
                            reads_cookie
                                && security_value
                                && tokens.windows(2).any(|pair| {
                                    pair[0].text == "if" && pair[1].text == "("
                                })
                        })
                }
                C::MissingXmlValidation => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let parses_xml = tokens.windows(2).any(|pair| {
                                pair[0].text == "parse" && pair[1].text == "("
                            }) && (tokens.iter().any(|token| {
                                matches!(
                                    token.text.as_str(),
                                    "DocumentBuilderFactory"
                                        | "SAXParserFactory"
                                        | "DocumentBuilder"
                                        | "SAXParser"
                                        | "XMLReader"
                                )
                            }) || parameter_bindings(syntax, declaration).iter().any(|(_, ty)| {
                                matches!(
                                    ty.rsplit('.').next(),
                                    Some(
                                        "DocumentBuilderFactory"
                                            | "SAXParserFactory"
                                            | "DocumentBuilder"
                                            | "SAXParser"
                                            | "XMLReader"
                                    )
                                )
                            }));
                            let validation = tokens.windows(2).any(|pair| {
                                matches!(
                                    pair[0].text.as_str(),
                                    "setSchema" | "setValidating" | "setValidation"
                                ) && pair[1].text == "("
                            }) && !tokens.windows(3).any(|window| {
                                matches!(
                                    window[0].text.as_str(),
                                    "setValidating" | "setValidation"
                                ) && window[1].text == "("
                                    && window[2].text == "false"
                            });
                            parses_xml && !validation
                        })
                }
                C::AxisMissingReturnType => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            tokens.windows(2).any(|pair| {
                                pair[0].text == "invoke" && pair[1].text == "("
                            }) && tokens.iter().any(|token| token.text == "addParameter")
                                && !tokens.iter().any(|token| token.text == "setReturnType")
                        })
                }
                C::FragmentInjection => {
                    declaration.kind == D::Class
                        && declaration.superclass.rsplit('.').next()
                            == Some("PreferenceActivity")
                        && syntax
                            .declarations
                            .iter()
                            .position(|candidate| std::ptr::eq(candidate, *declaration))
                            .is_some_and(|id| {
                                !syntax.declarations.iter().any(|method| {
                                    method.owner == Some(id)
                                        && method.kind == D::Method
                                        && method.name == "isValidFragment"
                                })
                            })
                }
                C::JsonpSameOriginExecution => {
                    declaration.kind == D::Class
                        && declaration.superclass.rsplit('.').next()
                            == Some("AbstractJsonpResponseBodyAdvice")
                }
                C::DeserializationBlacklist => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            tokens.windows(3).any(|window| {
                                window[0].text == "createFilter"
                                    && window[1].text == "("
                                    && window[2].kind == TokKind::StringLit
                                    && window[2].text.trim_matches('"').starts_with('!')
                                    && window[2].text.contains('*')
                            })
                        })
                }
                C::HttpRequestSmugglingHeaders => {
                    declaration.kind == D::Method
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let header = |name: &str| {
                                tokens.iter().any(|token| {
                                    token.kind == TokKind::StringLit
                                        && token.text.trim_matches('"').eq_ignore_ascii_case(name)
                                })
                            };
                            header("Content-Length") && header("Transfer-Encoding")
                        })
                }
                C::ExcessiveMemoryAllocation => excessive_allocation_in(declaration, syntax),
                C::ExternalDivideByZero => {
                    external_numeric_use(declaration, syntax, NumericUse::Divisor)
                }
                C::ExternalArrayIndex => {
                    external_numeric_use(declaration, syntax, NumericUse::ArrayIndex)
                }
                C::ExternalLoopBound => {
                    external_numeric_use(declaration, syntax, NumericUse::LoopBound)
                }
                C::ExternalIntegerArithmetic => {
                    external_numeric_use(declaration, syntax, NumericUse::Arithmetic)
                }
                C::SerializableParentMissingNoArgConstructor => {
                    declaration.kind == D::Class
                        && declaration.interfaces.iter().any(|base| {
                            base.rsplit('.').next() == Some("Serializable")
                        })
                        && !declaration.superclass.is_empty()
                        && syntax.declarations.iter().enumerate().find(|(_, candidate)| {
                            candidate.kind == D::Class
                                && candidate.name
                                    == declaration
                                        .superclass
                                        .rsplit('.')
                                        .next()
                                        .unwrap_or(&declaration.superclass)
                        }).is_some_and(|(parent_id, parent)| {
                            !parent.interfaces.iter().any(|base| {
                                base.rsplit('.').next() == Some("Serializable")
                            }) && {
                                let constructors = syntax.declarations.iter().filter(|member| {
                                    member.owner == Some(parent_id)
                                        && member.kind == D::Constructor
                                }).collect::<Vec<_>>();
                                !constructors.is_empty()
                                    && !constructors.iter().any(|constructor| {
                                        constructor.parameters.clone().is_some_and(|range| {
                                            syntax.tokens_in(range).next().is_none()
                                        })
                                    })
                            }
                        })
                }
                C::ExposeAliasedBuffer => {
                    declaration.kind == D::Method
                        && declaration.modifiers.iter().any(|value| value == "public")
                        && declaration.declared_type.rsplit('.').next().is_some_and(|ty| {
                            matches!(
                                ty,
                                "Buffer" | "ByteBuffer" | "CharBuffer" | "DoubleBuffer"
                                    | "FloatBuffer" | "IntBuffer" | "LongBuffer" | "ShortBuffer"
                            )
                        })
                        && declaration.body.clone().is_some_and(|body| {
                            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
                            let aliased = tokens.windows(2).any(|pair| {
                                matches!(pair[0].text.as_str(), "wrap" | "duplicate")
                                    && pair[1].text == "("
                            });
                            let read_only = tokens.iter().any(|token| token.text == "asReadOnlyBuffer");
                            aliased && !read_only
                        })
                }
                C::HiddenInheritedMethod => {
                    declaration.kind == D::Method
                        && declaration.modifiers.iter().any(|value| value == "static")
                        && inherited_methods(syntax, declaration).iter().any(|parent| {
                            parent.modifiers.iter().any(|value| value == "static")
                                && method_signatures_equal(syntax, declaration, parent)
                        })
                }
                C::MisleadingMethodSignature => {
                    declaration.kind == D::Method
                        && !declaration.modifiers.iter().any(|value| value == "static")
                        && !declaration.annotations.iter().any(|annotation| {
                            annotation.rsplit('.').next() == Some("Override")
                        })
                        && inherited_methods(syntax, declaration).iter().any(|parent| {
                            !parent.modifiers.iter().any(|value| value == "static")
                                && parent.name == declaration.name
                                && method_parameter_types(syntax, parent).len()
                                    == method_parameter_types(syntax, declaration).len()
                                && !method_signatures_equal(syntax, declaration, parent)
                        })
                }
                C::UnsynchronizedOverride => {
                    declaration.kind == D::Method
                        && !method_is_synchronized(syntax, declaration)
                        && inherited_methods(syntax, declaration).iter().any(|parent| {
                            method_is_synchronized(syntax, parent)
                                && method_signatures_equal(syntax, declaration, parent)
                        })
                }
                C::IncreasedOverrideAccessibility => {
                    declaration.kind == D::Method
                        && inherited_methods(syntax, declaration).iter().any(|parent| {
                            method_signatures_equal(syntax, declaration, parent)
                                && method_visibility(syntax, declaration)
                                    > method_visibility(syntax, parent)
                        })
                }
                _ => false,
            })
            .map(|declaration| declaration.range.start)
            .collect()
    }

    fn nesting_offsets(self, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        syntax
            .nodes
            .iter()
            .filter(|node| {
                let target = match self {
                    C::NestedForOverThree => K::For,
                    C::NestedIfOverThree => K::If,
                    C::TryInsideLoop => K::Try,
                    _ => return false,
                };
                if node.kind != target {
                    return false;
                }
                let contains = |outer: &&uniflow_parser_core::java_syntax::JavaSyntaxNode| {
                    outer.range.start < node.range.start && node.range.end <= outer.range.end
                };
                match self {
                    C::NestedForOverThree => {
                        syntax
                            .nodes
                            .iter()
                            .filter(|outer| outer.kind == K::For)
                            .filter(contains)
                            .count()
                            >= 3
                    }
                    C::NestedIfOverThree => {
                        syntax
                            .nodes
                            .iter()
                            .filter(|outer| outer.kind == K::If)
                            .filter(contains)
                            .count()
                            >= 3
                    }
                    C::TryInsideLoop => syntax.nodes.iter().any(|outer| {
                        matches!(outer.kind, K::For | K::While | K::Do) && contains(&outer)
                    }),
                    _ => false,
                }
            })
            .map(|node| node.range.start)
            .collect()
    }

    fn declaration_offsets(self, source: &str, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        syntax
            .declarations
            .iter()
            .enumerate()
            .filter(|(id, declaration)| {
                let owner = declaration.owner.map(|id| &syntax.declarations[id]);
                let class_owner = owner.filter(|owner| owner.kind == D::Class);
                let modifier = |name: &str| declaration.modifiers.iter().any(|m| m == name);
                let method = declaration.kind == D::Method;
                let field = declaration.kind == D::Field;
                let interface = |name: &str| {
                    class_owner.is_some_and(|owner| {
                        owner
                            .interfaces
                            .iter()
                            .any(|base| base.rsplit('.').next() == Some(name))
                    })
                };
                let siblings = || {
                    syntax
                        .declarations
                        .iter()
                        .filter(|other| other.is_member && other.owner == declaration.owner)
                };
                let child_method = |name: &str| {
                    syntax.declarations.iter().any(|other| {
                        other.owner == Some(*id) && other.kind == D::Method && other.name == name
                    })
                };
                let logger = |ty: &str| ty == "Logger" || ty.ends_with(".Logger");
                match self {
                    C::FinalCloneMethod => {
                        method
                            && declaration.name == "clone"
                            && interface("Cloneable")
                            && !modifier("final")
                    }
                    C::PrivateFinalize => {
                        method
                            && declaration.name == "finalize"
                            && (modifier("public") || modifier("protected"))
                    }
                    C::RequestMappingMethodPublic => {
                        method
                            && !modifier("public")
                            && declaration
                                .annotations
                                .iter()
                                .any(|name| name.contains("RequestMapping"))
                    }
                    C::RewriteThreadRunMethod => {
                        declaration.kind == D::Class
                            && declaration.superclass.rsplit('.').next() == Some("Thread")
                            && !child_method("run")
                    }
                    C::DefaultConstructorExternalizable => {
                        declaration.kind == D::Class
                            && declaration
                                .interfaces
                                .iter()
                                .any(|base| base.contains("Externalizable"))
                            && !syntax.declarations.iter().any(|other| {
                                other.owner == Some(*id)
                                    && other.kind == D::Constructor
                                    && other.parameters.clone().is_some_and(|range| {
                                        syntax.tokens_in(range).next().is_none()
                                    })
                            })
                    }
                    C::EqualsHashcodeCheck => {
                        method
                            && owner.is_some_and(|owner| {
                                matches!(owner.kind, D::Class | D::AnonymousClass)
                            })
                            && matches!(declaration.name.as_str(), "equals" | "hashCode")
                            && !siblings().any(|other| {
                                other.kind == D::Method
                                    && other.name
                                        == if declaration.name == "equals" {
                                            "hashCode"
                                        } else {
                                            "equals"
                                        }
                            })
                    }
                    C::SerializeMethodSign => {
                        method
                            && !declaration.has_throws
                            && (declaration.name.contains("readObjectNoData")
                                || declaration.parameters.clone().is_some_and(|range| {
                                    (declaration.name.contains("writeObject")
                                        && source[range.clone()].contains("ObjectOutputStream"))
                                        || (declaration.name.contains("readObject")
                                            && source[range].contains("ObjectInputStream"))
                                }))
                    }
                    C::SerialVersionUidDefined => {
                        field
                            && interface("Serializable")
                            && declaration
                                .names
                                .iter()
                                .any(|name| name == "serialVersionUID")
                            && (!declaration.declared_type.contains("long")
                                || !modifier("static")
                                || !modifier("final"))
                    }
                    C::StaticFinalLogger => {
                        field
                            && logger(&declaration.declared_type)
                            && (!modifier("static") || !modifier("final"))
                    }
                    // Legacy `follows` without stopBy examines the immediately preceding member.
                    C::MultipleLogger => {
                        field
                            && logger(&declaration.declared_type)
                            && siblings()
                                .filter(|other| other.range.start < declaration.range.start)
                                .max_by_key(|other| other.range.start)
                                .is_some_and(|other| {
                                    other.kind == D::Field && logger(&other.declared_type)
                                })
                    }
                    C::FieldNameAndClassNameSame => {
                        field
                            && class_owner.is_some_and(|owner| {
                                declaration.names.iter().any(|name| name == &owner.name)
                            })
                    }
                    C::FieldNameAndMethodNameSame => {
                        field
                            && class_owner.is_some()
                            && siblings().any(|other| {
                                other.kind == D::Method && declaration.names.contains(&other.name)
                            })
                    }
                    C::FinalPublicStaticField => {
                        field && modifier("public") && modifier("static") && !modifier("final")
                    }
                    C::StaticPrivateFinalObjectstreamfield => {
                        field
                            && declaration
                                .names
                                .iter()
                                .any(|name| name == "serialPersistentFields")
                            && declaration
                                .declared_type
                                .rsplit('.')
                                .next()
                                .is_some_and(|ty| ty.starts_with("ObjectStreamField"))
                            && !(modifier("static")
                                && modifier("final")
                                && (modifier("private")
                                    || (!modifier("public") && !modifier("protected"))))
                    }
                    C::StaticPublicFinalArray => {
                        field
                            && modifier("public")
                            && modifier("static")
                            && modifier("final")
                            && declaration.declared_type.contains('[')
                    }
                    // The legacy rule has no object/reference type gate, despite its name.
                    C::StaticPublicFinalObject => {
                        field && modifier("public") && modifier("static") && modifier("final")
                    }
                    C::ImmutableFinalField | C::ImmutablePublicFinalField => {
                        field
                            && class_owner.is_some_and(|owner| {
                                owner
                                    .marker_annotations
                                    .iter()
                                    .any(|name| name.starts_with("Immutable"))
                            })
                            && if matches!(self, C::ImmutableFinalField) {
                                !modifier("final")
                            } else {
                                modifier("public")
                            }
                    }
                    C::TransientFieldClass => {
                        field
                            && modifier("transient")
                            && class_owner.is_some_and(|owner| {
                                owner.superclass.is_empty() && owner.interfaces.is_empty()
                            })
                    }
                    C::StateholderRestorestateSavestate => {
                        method
                            && matches!(declaration.name.as_str(), "restoreState" | "saveState")
                            && class_owner.is_some_and(|owner| {
                                owner
                                    .superclass
                                    .rsplit('.')
                                    .next()
                                    .is_some_and(|name| name.contains("StateHolder"))
                            })
                            && !siblings().any(|other| {
                                other.kind == D::Method
                                    && other.name
                                        == if declaration.name == "restoreState" {
                                            "saveState"
                                        } else {
                                            "restoreState"
                                        }
                            })
                    }
                    C::StaticThreadNotSecObject => {
                        field
                            && modifier("static")
                            && matches!(
                                declaration.declared_type.rsplit('.').next(),
                                Some("Calendar" | "XPath" | "SchemaFactory")
                            )
                    }
                    C::InnerClassImplementSerializable => {
                        declaration.kind == D::Class
                            && !modifier("static")
                            && declaration
                                .interfaces
                                .iter()
                                .any(|base| base.rsplit('.').next() == Some("Serializable"))
                            && declaration.owner.is_some_and(|mut owner| loop {
                                if matches!(syntax.declarations[owner].kind, D::Class) {
                                    break true;
                                }
                                match syntax.declarations[owner].owner {
                                    Some(next) => owner = next,
                                    None => break false,
                                }
                            })
                    }
                    C::RewriteCloneMethod => {
                        method
                            && declaration.name == "clone"
                            && declaration.body.is_some()
                            && !syntax.has_token_sequence(
                                declaration.range.clone(),
                                &["super", ".", "clone", "(", ")"],
                            )
                    }
                    C::NextThrowNoSuchElementException => {
                        method
                            && declaration.name == "next"
                            && declaration.body.is_some()
                            && declaration
                                .annotations
                                .iter()
                                .any(|name| name.contains("Override"))
                            && !syntax
                                .tokens_in(declaration.body.clone().unwrap())
                                .any(|token| token.text == "NoSuchElementException")
                    }
                    C::AnonymousInnerClassCallMethod => {
                        declaration.kind == D::AnonymousClass
                            && declaration
                                .parameters
                                .clone()
                                .is_some_and(|range| syntax.tokens_in(range).next().is_none())
                            && syntax
                                .declarations
                                .iter()
                                .filter(|other| {
                                    other.owner == Some(*id) && other.kind == D::Initializer
                                })
                                .any(|initializer| {
                                    contains_method_invocation(syntax, initializer.range.clone())
                                })
                    }
                    C::ClassInitializerUseThread => {
                        declaration.kind == D::Initializer
                            && modifier("static")
                            && syntax.has_token_sequence(
                                declaration.range.clone(),
                                &["new", "Thread", "("],
                            )
                    }
                    C::SelectInterpolation => {
                        method
                            && declaration
                                .annotation_arguments
                                .iter()
                                .any(|(name, arguments)| {
                                    name.rsplit('.').next() == Some("Select")
                                        && arguments.contains("${")
                                })
                    }
                    C::NativeMethod => method && modifier("native"),
                    C::CloneWithoutCloneable => {
                        method
                            && declaration.name == "clone"
                            && class_owner.is_some_and(|owner| {
                                !owner
                                    .interfaces
                                    .iter()
                                    .any(|base| base.rsplit('.').next() == Some("Cloneable"))
                            })
                    }
                    C::FinalizeWithoutSuper => {
                        method
                            && declaration.name == "finalize"
                            && declaration.body.is_some()
                            && !syntax.has_token_sequence(
                                declaration.range.clone(),
                                &["super", ".", "finalize", "(", ")"],
                            )
                    }
                    C::ReturnGenericWildcard => method && declaration.declared_type.contains('?'),
                    _ => false,
                }
            })
            .map(|(_, declaration)| declaration.range.start)
            .collect()
    }

    fn synchronization_offsets(self, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        let mut offsets = Vec::new();
        for node in syntax
            .nodes
            .iter()
            .filter(|node| node.kind == K::Synchronized)
        {
            let Some(condition) = node.condition.clone() else {
                continue;
            };
            let condition_tokens = syntax.tokens_in(condition).collect::<Vec<_>>();
            if matches!(self, C::SynchronizeOnGetClass) {
                if condition_tokens.windows(3).any(|window| {
                    window[0].text == "getClass" && window[1].text == "(" && window[2].text == ")"
                }) {
                    offsets.push(node.range.start);
                }
                continue;
            }
            if matches!(self, C::SyncObjectNotifyMethod) {
                let Some(body) = node.body.clone() else {
                    continue;
                };
                let mut sequence = condition_tokens
                    .iter()
                    .map(|token| token.text.as_str())
                    .collect::<Vec<_>>();
                sequence.extend([".", "notify", "(", ")"]);
                let tokens = syntax.tokens_in(body.clone()).collect::<Vec<_>>();
                for window in tokens.windows(sequence.len()) {
                    if window
                        .iter()
                        .map(|token| token.text.as_str())
                        .eq(sequence.iter().copied())
                    {
                        let offset = window[0].start as usize;
                        let crosses_nested_method = syntax.declarations.iter().any(|declaration| {
                            declaration.kind == D::Method
                                && declaration.range.start >= body.start
                                && declaration.range.end <= body.end
                                && declaration.range.contains(&offset)
                        });
                        if !crosses_nested_method {
                            offsets.push(offset);
                        }
                    }
                }
                continue;
            }
            if condition_tokens.len() != 1 || condition_tokens[0].kind != TokKind::Ident {
                continue;
            }
            let name = condition_tokens[0].text.as_str();
            if matches!(self, C::CollectionViewSynchronization) {
                let method = syntax
                    .declarations
                    .iter()
                    .filter(|declaration| {
                        matches!(declaration.kind, D::Method | D::Constructor)
                            && declaration.range.start <= node.range.start
                            && node.range.end <= declaration.range.end
                    })
                    .min_by_key(|declaration| declaration.range.end - declaration.range.start);
                if method.is_some_and(|method| {
                    collection_view_backing(syntax, method, name, node.range.start).is_some()
                }) {
                    offsets.push(node.range.start);
                }
                continue;
            }
            let owner = syntax
                .declarations
                .iter()
                .enumerate()
                .filter(|(_, declaration)| {
                    declaration.kind == D::Class
                        && declaration.range.start <= node.range.start
                        && declaration.range.end >= node.range.end
                })
                .min_by_key(|(_, declaration)| declaration.range.end - declaration.range.start)
                .map(|(id, _)| id);
            let field = syntax.declarations.iter().find(|declaration| {
                declaration.kind == D::Field
                    && declaration.owner == owner
                    && declaration.names.iter().any(|candidate| candidate == name)
            });
            let matches = match self {
                C::SyncObjectIsFinal => field.is_some_and(|field| {
                    !field.modifiers.iter().any(|modifier| modifier == "final")
                }),
                C::SynchronizedObject => field
                    .is_some_and(|field| field.declared_type.rsplit('.').next() == Some("String")),
                C::SynchronizeOnConcurrencyObject => {
                    let field_type = field.map(|field| field.declared_type.as_str());
                    let parameter_type = syntax
                        .declarations
                        .iter()
                        .filter(|declaration| {
                            declaration.kind == D::Method
                                && declaration.range.start <= node.range.start
                                && node.range.end <= declaration.range.end
                        })
                        .min_by_key(|declaration| declaration.range.end - declaration.range.start)
                        .and_then(|method| {
                            parameter_bindings(syntax, method)
                                .into_iter()
                                .find_map(|(parameter, ty)| (parameter == name).then_some(ty))
                        });
                    field_type
                        .map(str::to_string)
                        .or(parameter_type)
                        .is_some_and(|ty| {
                            matches!(
                                ty.rsplit('.').next(),
                                Some(
                                    "Lock"
                                        | "ReentrantLock"
                                        | "ReadWriteLock"
                                        | "ReentrantReadWriteLock"
                                        | "Condition"
                                )
                            )
                        })
                }
                _ => false,
            };
            if matches {
                offsets.push(node.range.start);
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    fn usage_offsets(self, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        let mut offsets = Vec::new();
        match self {
            C::UnusedField => {
                for declaration in syntax.declarations.iter().filter(|declaration| {
                    declaration.kind == D::Field && declaration.marker_annotations.is_empty()
                }) {
                    let Some(owner_id) = declaration.owner else {
                        continue;
                    };
                    let owner = &syntax.declarations[owner_id];
                    if owner.kind != D::Class || !owner.marker_annotations.is_empty() {
                        continue;
                    }
                    if declaration.names.iter().any(|name| {
                        !has_resolved_reference(
                            syntax,
                            owner.range.clone(),
                            name,
                            Some(declaration.range.clone()),
                        )
                    }) {
                        offsets.push(declaration.range.start);
                    }
                }
            }
            C::UnusedMethod => {
                for declaration in syntax.declarations.iter().filter(|declaration| {
                    declaration.kind == D::Method
                        && declaration
                            .modifiers
                            .iter()
                            .any(|modifier| modifier == "private")
                        && declaration.marker_annotations.is_empty()
                }) {
                    let Some(owner) = declaration.owner.map(|id| &syntax.declarations[id]) else {
                        continue;
                    };
                    let used = syntax.tokens_in(owner.range.clone()).any(|token| {
                        token.kind == TokKind::Ident
                            && token.text == declaration.name
                            && !declaration.range.contains(&(token.start as usize))
                            && !is_member_declaration_name(
                                syntax,
                                token.start as usize,
                                &declaration.name,
                            )
                    });
                    if !used {
                        offsets.push(declaration.range.start);
                    }
                }
            }
            C::UnusedVariable => {
                for node in syntax.nodes.iter().filter(|node| node.kind == K::Other) {
                    let tokens = syntax.tokens_in(node.range.clone()).collect::<Vec<_>>();
                    for pair in tokens.windows(2) {
                        if pair[0].kind != TokKind::Ident
                            || pair[1].text != "="
                            || looks_like_declaration_name(&tokens, pair[0].start as usize)
                        {
                            continue;
                        }
                        let name = pair[0].text.as_str();
                        let scope = enclosing_executable_range(syntax, node.range.start)
                            .or_else(|| enclosing_class_range(syntax, node.range.start));
                        let Some(scope) = scope else {
                            continue;
                        };
                        if !is_declared_before(syntax, scope.clone(), name, pair[0].start as usize)
                        {
                            continue;
                        }
                        if !syntax
                            .tokens_in(pair[1].end as usize..scope.end)
                            .any(|token| {
                                token.kind == TokKind::Ident
                                    && token.text == name
                                    && !inside_nested_type_or_lambda(
                                        syntax,
                                        token.start as usize,
                                        pair[1].end as usize,
                                        scope.end,
                                    )
                            })
                        {
                            offsets.push(pair[0].start as usize);
                        }
                    }
                }
            }
            C::InnerClassUseOuterClassField => {
                for field in syntax
                    .declarations
                    .iter()
                    .filter(|declaration| declaration.kind == D::Field)
                {
                    let Some(outer_id) = field.owner else {
                        continue;
                    };
                    for inner in syntax.declarations.iter().filter(|declaration| {
                        declaration.kind == D::Class
                            && declaration
                                .modifiers
                                .iter()
                                .any(|modifier| modifier == "public")
                            && is_descendant_of(syntax, declaration, outer_id)
                    }) {
                        if field.names.iter().any(|name| {
                            syntax
                                .declarations
                                .iter()
                                .filter(|method| {
                                    method.kind == D::Method
                                        && is_descendant_of_range(method, inner.range.clone())
                                })
                                .any(|method| {
                                    method.body.clone().is_some_and(|body| {
                                        has_unshadowed_name(syntax, method, body, name)
                                    })
                                })
                        }) {
                            offsets.push(field.range.start);
                            break;
                        }
                    }
                }
            }
            C::ImmutableField => {
                for field in syntax
                    .declarations
                    .iter()
                    .filter(|declaration| declaration.kind == D::Field)
                {
                    let Some(owner_id) = field.owner else {
                        continue;
                    };
                    let owner = &syntax.declarations[owner_id];
                    if owner.kind != D::Class
                        || !owner
                            .marker_annotations
                            .iter()
                            .any(|annotation| annotation.rsplit('.').next() == Some("Immutable"))
                    {
                        continue;
                    }
                    if field.names.iter().any(|name| {
                        syntax
                            .declarations
                            .iter()
                            .filter(|method| {
                                method.kind == D::Method
                                    && method.body.is_some()
                                    && is_descendant_of_range(method, owner.range.clone())
                            })
                            .any(|method| method_mutates_name(syntax, method, name))
                    }) {
                        offsets.push(field.range.start);
                    }
                }
            }
            _ => {}
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    fn member_call_offsets(self, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        let mut offsets = Vec::new();
        for (id, declaration) in syntax.declarations.iter().enumerate() {
            let Some(owner_id) = declaration.owner else {
                continue;
            };
            let owner = &syntax.declarations[owner_id];
            if owner.kind != D::Class {
                continue;
            }
            let modifier = |name: &str| declaration.modifiers.iter().any(|item| item == name);
            match self {
                C::CloneCallOverrideMethod
                    if declaration.kind == D::Method
                        && declaration.name == "clone"
                        && declaration.declared_type == "Object" =>
                {
                    for call in call_sites(syntax, declaration) {
                        if !matches!(
                            call.qualifier,
                            CallQualifier::Identifier | CallQualifier::Super
                        ) && member_methods(syntax, owner_id, &call.name)
                            .any(|method| !method.modifiers.iter().any(|item| item == "final"))
                        {
                            offsets.push(call.offset);
                        }
                    }
                }
                C::CtorCallOverrideMethod if declaration.kind == D::Constructor => {
                    for call in call_sites(syntax, declaration) {
                        if call.qualifier != CallQualifier::Identifier
                            && member_methods(syntax, owner_id, &call.name)
                                .any(|method| !method.modifiers.iter().any(|item| item == "final"))
                        {
                            offsets.push(call.offset);
                        }
                    }
                }
                C::CallSecuritymanagerCheckMethod
                    if declaration.kind == D::Method
                        && (modifier("public") || modifier("protected"))
                        && !modifier("final")
                        && !modifier("private") =>
                {
                    offsets.extend(
                        call_sites(syntax, declaration)
                            .into_iter()
                            .filter(|call| {
                                call.name.starts_with("check")
                                    && call.receiver.as_deref().is_some_and(|receiver| {
                                        receiver_has_type_at(
                                            syntax,
                                            declaration,
                                            receiver,
                                            &["SecurityManager"],
                                            call.offset,
                                        )
                                    })
                            })
                            .map(|call| call.offset),
                    );
                }
                C::CloneMethodUseSecMethod
                    if declaration.kind == D::Method
                        && declaration.name == "clone"
                        && owner
                            .interfaces
                            .iter()
                            .any(|base| base.rsplit('.').next() == Some("Cloneable")) =>
                {
                    let ctor_checks =
                        syntax
                            .declarations
                            .iter()
                            .enumerate()
                            .any(|(ctor_id, ctor)| {
                                ctor.owner == Some(owner_id)
                                    && ctor.kind == D::Constructor
                                    && reaches_security_check(
                                        syntax,
                                        owner_id,
                                        ctor_id,
                                        3,
                                        &mut Vec::new(),
                                    )
                            });
                    if ctor_checks
                        && !reaches_security_check(syntax, owner_id, id, 3, &mut Vec::new())
                    {
                        offsets.push(declaration.range.start);
                    }
                }
                C::ReadobjectCallFinalMethod
                    if declaration.kind == D::Method
                        && declaration.name == "readObject"
                        && !owner.modifiers.iter().any(|item| item == "final")
                        && parameter_bindings(syntax, declaration)
                            .iter()
                            .any(|(_, ty)| ty.rsplit('.').next() == Some("ObjectInputStream")) =>
                {
                    if reaches_non_final_member(syntax, owner_id, id, 4, &mut Vec::new()) {
                        offsets.push(declaration.range.start);
                    }
                }
                C::SerializableMissingSecurityCheck
                    if declaration.kind == D::Method
                        && matches!(
                            declaration.name.as_str(),
                            "readObject" | "readObjectNoData"
                        )
                        && owner
                            .interfaces
                            .iter()
                            .any(|base| base.rsplit('.').next() == Some("Serializable")) =>
                {
                    let constructor_checks = syntax.declarations.iter().enumerate().any(
                        |(constructor_id, constructor)| {
                            constructor.owner == Some(owner_id)
                                && constructor.kind == D::Constructor
                                && reaches_security_check(
                                    syntax,
                                    owner_id,
                                    constructor_id,
                                    3,
                                    &mut Vec::new(),
                                )
                        },
                    );
                    if constructor_checks
                        && !reaches_security_check(syntax, owner_id, id, 3, &mut Vec::new())
                    {
                        offsets.push(declaration.range.start);
                    }
                }
                C::SerializableDangerousMethodCall
                    if matches!(declaration.kind, D::Method | D::Constructor)
                        && owner
                            .interfaces
                            .iter()
                            .any(|base| base.rsplit('.').next() == Some("Serializable")) =>
                {
                    offsets.extend(
                        call_sites(syntax, declaration)
                            .into_iter()
                            .filter(|call| {
                                matches!(
                                    call.name.as_str(),
                                    "forName"
                                        | "newInstance"
                                        | "invoke"
                                        | "exec"
                                        | "loadClass"
                                        | "defineClass"
                                        | "getDeclaredMethod"
                                        | "getDeclaredField"
                                )
                            })
                            .map(|call| call.offset),
                    );
                }
                _ => {}
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
}

#[derive(Clone, Copy)]
enum NumericUse {
    Divisor,
    ArrayIndex,
    LoopBound,
    Arithmetic,
}

fn external_numeric_use(
    declaration: &JavaDeclaration,
    syntax: &JavaSyntax,
    usage: NumericUse,
) -> bool {
    if declaration.kind != D::Method {
        return false;
    }
    let Some(body) = declaration.body.clone() else {
        return false;
    };
    let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
    let mut names = HashSet::new();
    for index in 0..tokens.len() {
        if !matches!(tokens[index].text.as_str(), "parseInt" | "parseLong") {
            continue;
        }
        let external = tokens[index..tokens.len().min(index + 16)]
            .iter()
            .any(|token| {
                matches!(
                    token.text.as_str(),
                    "getParameter" | "readLine" | "nextLine" | "getQueryParameter"
                )
            });
        if !external {
            continue;
        }
        if let Some(equal) = (0..index).rev().find(|candidate| tokens[*candidate].text == "=") {
            if let Some(name) = tokens[..equal]
                .iter()
                .rev()
                .find(|token| token.kind == TokKind::Ident)
            {
                names.insert(name.text.clone());
            }
        }
    }
    names.into_iter().any(|name| {
        let bounded = tokens.windows(4).any(|window| {
            window[0].text == "if"
                && window.iter().any(|token| token.text == name)
                && window.iter().any(|token| matches!(token.text.as_str(), "<" | ">"))
        });
        if bounded {
            return false;
        }
        match usage {
            NumericUse::Divisor => tokens
                .windows(2)
                .any(|pair| matches!(pair[0].text.as_str(), "/" | "%") && pair[1].text == name),
            NumericUse::ArrayIndex => tokens.windows(3).any(|window| {
                window[0].text == "[" && window[1].text == name && window[2].text == "]"
            }),
            NumericUse::LoopBound => tokens.iter().enumerate().any(|(index, token)| {
                token.text == "for"
                    && tokens[index..tokens.len().min(index + 24)]
                        .iter()
                        .any(|candidate| candidate.text == name)
            }),
            NumericUse::Arithmetic => tokens.windows(3).any(|window| {
                (window[0].text == name
                    && matches!(window[1].text.as_str(), "+" | "-" | "*"))
                    || (matches!(window[1].text.as_str(), "+" | "-" | "*")
                        && window[2].text == name)
            }) && !tokens.iter().any(|token| {
                matches!(
                    token.text.as_str(),
                    "addExact" | "subtractExact" | "multiplyExact"
                )
            }),
        }
    })
}

fn excessive_allocation_in(declaration: &JavaDeclaration, syntax: &JavaSyntax) -> bool {
    if declaration.kind != D::Method {
        return false;
    }
    declaration.body.clone().is_some_and(|body| {
        let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
        tokens.iter().enumerate().any(|(index, token)| {
            if token.kind != TokKind::IntLit {
                return false;
            }
            let value = token.text.replace('_', "").parse::<u64>().unwrap_or(0);
            value >= 1024
                && tokens[index.saturating_sub(5)..index]
                    .iter()
                    .any(|previous| previous.text == "new")
        })
    })
}

fn assertion_parameter_names(syntax: &JavaSyntax, range: std::ops::Range<usize>) -> Vec<String> {
    let mut names = Vec::new();
    let mut last_identifier = None;
    for token in syntax.tokens_in(range) {
        if token.kind == TokKind::Ident {
            last_identifier = Some(token.text.clone());
        }
        if token.text == "," {
            if let Some(name) = last_identifier.take() {
                names.push(name);
            }
        }
    }
    if let Some(name) = last_identifier {
        names.push(name);
    }
    names
}

fn constant_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && name.bytes().any(|byte| byte.is_ascii_uppercase())
}

fn is_java_standard_type_name(name: &str) -> bool {
    matches!(
        name,
        "Appendable"
            | "AutoCloseable"
            | "Boolean"
            | "Byte"
            | "Character"
            | "CharSequence"
            | "Class"
            | "ClassLoader"
            | "Cloneable"
            | "Comparable"
            | "Double"
            | "Enum"
            | "Error"
            | "Exception"
            | "Float"
            | "Integer"
            | "Iterable"
            | "Long"
            | "Math"
            | "Number"
            | "Object"
            | "Process"
            | "Runtime"
            | "SecurityManager"
            | "Short"
            | "StackTraceElement"
            | "String"
            | "StringBuffer"
            | "StringBuilder"
            | "System"
            | "Thread"
            | "Throwable"
            | "Void"
            | "File"
            | "InputStream"
            | "OutputStream"
            | "Reader"
            | "Writer"
            | "IOException"
            | "Serializable"
            | "BigDecimal"
            | "BigInteger"
            | "URI"
            | "URL"
            | "Socket"
            | "Collection"
            | "Collections"
            | "Comparator"
            | "Deque"
            | "HashMap"
            | "HashSet"
            | "Iterator"
            | "LinkedHashMap"
            | "LinkedHashSet"
            | "LinkedList"
            | "List"
            | "Map"
            | "Optional"
            | "Queue"
            | "Set"
            | "SortedMap"
            | "SortedSet"
            | "TreeMap"
            | "TreeSet"
            | "Vector"
            | "Date"
            | "Calendar"
            | "Locale"
            | "Random"
            | "UUID"
            | "Arrays"
            | "Pattern"
            | "Matcher"
            | "Path"
            | "Paths"
            | "Files"
            | "Instant"
            | "Duration"
            | "LocalDate"
            | "LocalDateTime"
            | "ZoneId"
            | "Executor"
            | "ExecutorService"
            | "Future"
            | "Callable"
            | "Semaphore"
            | "CountDownLatch"
            | "Lock"
            | "Condition"
            | "AtomicInteger"
            | "Stream"
            | "Collectors"
            | "Connection"
            | "Statement"
            | "PreparedStatement"
            | "ResultSet"
    )
}

fn instance_lock_static_data_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for (owner_id, owner) in syntax
        .declarations
        .iter()
        .enumerate()
        .filter(|(_, declaration)| declaration.kind == D::Class)
    {
        let static_fields = syntax
            .declarations
            .iter()
            .filter(|field| {
                field.owner == Some(owner_id)
                    && field.kind == D::Field
                    && field.modifiers.iter().any(|modifier| modifier == "static")
            })
            .flat_map(|field| field.names.iter())
            .collect::<Vec<_>>();
        if static_fields.is_empty() {
            continue;
        }
        for method in syntax.declarations.iter().filter(|method| {
            method.owner == Some(owner_id)
                && method.kind == D::Method
                && method
                    .modifiers
                    .iter()
                    .any(|modifier| modifier == "synchronized")
                && !method.modifiers.iter().any(|modifier| modifier == "static")
        }) {
            if method.body.clone().is_some_and(|body| {
                static_fields.iter().any(|name| {
                    syntax
                        .tokens_in(body.clone())
                        .any(|token| token.text == name.as_str())
                })
            }) {
                offsets.push(method.range.start);
            }
        }
        let instance_locks = syntax
            .declarations
            .iter()
            .filter(|field| {
                field.owner == Some(owner_id)
                    && field.kind == D::Field
                    && !field.modifiers.iter().any(|modifier| modifier == "static")
            })
            .flat_map(|field| field.names.iter())
            .collect::<Vec<_>>();
        for node in syntax.nodes.iter().filter(|node| {
            node.kind == K::Synchronized
                && owner.range.start <= node.range.start
                && node.range.end <= owner.range.end
        }) {
            let Some(condition) = node.condition.clone() else {
                continue;
            };
            let lock_is_instance = syntax.tokens_in(condition).any(|token| {
                token.text == "this"
                    || instance_locks
                        .iter()
                        .any(|name| token.text == name.as_str())
            });
            let protects_static = node.body.clone().is_some_and(|body| {
                static_fields.iter().any(|name| {
                    syntax
                        .tokens_in(body.clone())
                        .any(|token| token.text == name.as_str())
                })
            });
            if lock_is_instance && protects_static {
                offsets.push(node.range.start);
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn case_insensitive_package_offsets(source: &str, syntax: &JavaSyntax) -> Vec<usize> {
    let tokens = syntax.tokens_in(0..source.len()).collect::<Vec<_>>();
    let mut offsets = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if token.text != "equalsIgnoreCase" {
            continue;
        }
        let start = index.saturating_sub(12);
        let end = (index + 13).min(tokens.len());
        if tokens[start..end].iter().any(|nearby| {
            let name = nearby.text.to_ascii_lowercase();
            name == "getpackagename" || name.contains("packagename") || name == "package_name"
        }) {
            offsets.push(token.start as usize);
        }
    }
    offsets
}

fn multiple_servlet_stream_commit_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for method in syntax
        .declarations
        .iter()
        .filter(|declaration| declaration.kind == D::Method && declaration.body.is_some())
    {
        let response_names = parameter_bindings(syntax, method)
            .into_iter()
            .filter_map(|(name, ty)| {
                (ty.rsplit('.').next() == Some("HttpServletResponse")).then_some(name)
            })
            .collect::<Vec<_>>();
        if response_names.is_empty() {
            continue;
        }
        let calls = call_sites(syntax, method);
        let mut accessor: Option<bool> = None;
        let mut committed = false;
        for call in calls {
            let on_response = call
                .receiver
                .as_ref()
                .is_some_and(|receiver| response_names.contains(receiver));
            if on_response && matches!(call.name.as_str(), "getOutputStream" | "getWriter") {
                let output_stream = call.name == "getOutputStream";
                if accessor.is_some_and(|previous| previous != output_stream) {
                    offsets.push(call.offset);
                }
                accessor = Some(output_stream);
                continue;
            }
            let response_commit = on_response
                && matches!(
                    call.name.as_str(),
                    "sendRedirect" | "flushBuffer" | "reset" | "resetBuffer"
                );
            let stream_commit = call.receiver.as_deref().is_some_and(|receiver| {
                receiver_has_type_at(
                    syntax,
                    method,
                    receiver,
                    &["OutputStream", "ServletOutputStream", "PrintWriter", "Writer"],
                    call.offset,
                )
            }) && matches!(call.name.as_str(), "flush" | "close");
            if response_commit {
                if committed {
                    offsets.push(call.offset);
                }
                committed = true;
            } else if stream_commit {
                committed = true;
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BeanMethodKind {
    Getter,
    Setter,
}

fn bean_property(name: &str) -> Option<(BeanMethodKind, String)> {
    let (kind, suffix) = if let Some(suffix) = name.strip_prefix("get") {
        (BeanMethodKind::Getter, suffix)
    } else if let Some(suffix) = name.strip_prefix("is") {
        (BeanMethodKind::Getter, suffix)
    } else if let Some(suffix) = name.strip_prefix("set") {
        (BeanMethodKind::Setter, suffix)
    } else {
        return None;
    };
    let mut characters = suffix.chars();
    let first = characters.next()?;
    if !first.is_ascii_uppercase() {
        return None;
    }
    let property = if suffix
        .chars()
        .nth(1)
        .is_some_and(|second| second.is_ascii_uppercase())
    {
        suffix.to_string()
    } else {
        first.to_ascii_lowercase().to_string() + characters.as_str()
    };
    Some((kind, property))
}

fn method_is_synchronized(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
) -> bool {
    declaration
        .modifiers
        .iter()
        .any(|modifier| modifier == "synchronized")
        || declaration.body.as_ref().is_some_and(|body| {
            syntax.nodes.iter().any(|node| {
                node.kind == K::Synchronized
                    && body.start <= node.range.start
                    && node.range.end <= body.end
            })
        })
}

fn direct_bean_field(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
    kind: BeanMethodKind,
) -> Option<String> {
    let owner = declaration.owner?;
    let body = declaration.body.clone()?;
    let fields = syntax
        .declarations
        .iter()
        .filter(|item| item.owner == Some(owner) && item.kind == D::Field)
        .flat_map(|item| item.names.iter())
        .collect::<Vec<_>>();
    let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
    match kind {
        BeanMethodKind::Getter => {
            let at = tokens.iter().position(|token| token.text == "return")?;
            let candidate = match tokens.get(at + 1..at + 4) {
                Some([this, dot, field]) if this.text == "this" && dot.text == "." => field,
                _ => tokens.get(at + 1)?,
            };
            fields
                .iter()
                .any(|field| *field == &candidate.text)
                .then(|| candidate.text.clone())
        }
        BeanMethodKind::Setter => {
            for window in tokens.windows(4) {
                if window[0].text == "this"
                    && window[1].text == "."
                    && window[2].kind == TokKind::Ident
                    && window[3].text == "="
                    && fields.iter().any(|field| *field == &window[2].text)
                {
                    return Some(window[2].text.clone());
                }
            }
            for pair in tokens.windows(2) {
                if pair[0].kind == TokKind::Ident
                    && pair[1].text == "="
                    && fields.iter().any(|field| *field == &pair[0].text)
                {
                    return Some(pair[0].text.clone());
                }
            }
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallQualifier {
    Implicit,
    This,
    Super,
    Identifier,
    Other,
}

#[derive(Clone, Debug)]
struct CallSite {
    name: String,
    receiver: Option<String>,
    qualifier: CallQualifier,
    offset: usize,
}

fn member_methods<'a>(
    syntax: &'a JavaSyntax,
    owner: usize,
    name: &'a str,
) -> impl Iterator<Item = &'a uniflow_parser_core::java_syntax::JavaDeclaration> + 'a {
    syntax.declarations.iter().filter(move |declaration| {
        declaration.owner == Some(owner)
            && declaration.kind == D::Method
            && declaration.name == name
    })
}

fn call_sites(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
) -> Vec<CallSite> {
    let Some(body) = declaration.body.clone() else {
        return Vec::new();
    };
    let tokens = syntax.tokens_in(body.clone()).collect::<Vec<_>>();
    let mut calls = Vec::new();
    for at in 0..tokens.len().saturating_sub(1) {
        if tokens[at].kind != TokKind::Ident || tokens[at + 1].text != "(" {
            continue;
        }
        if matches!(
            tokens[at].text.as_str(),
            "if" | "for"
                | "while"
                | "switch"
                | "catch"
                | "synchronized"
                | "new"
                | "return"
                | "throw"
                | "super"
                | "this"
        ) || at
            .checked_sub(1)
            .is_some_and(|previous| matches!(tokens[previous].text.as_str(), "new" | "@"))
        {
            continue;
        }
        let offset = tokens[at].start as usize;
        if syntax.declarations.iter().any(|nested| {
            nested.range.start >= body.start
                && nested.range.end <= body.end
                && nested.range.contains(&offset)
                && matches!(nested.kind, D::Method | D::Constructor)
        }) {
            continue;
        }
        let (qualifier, receiver) = if at >= 2 && tokens[at - 1].text == "." {
            let object = tokens[at - 2];
            let qualifier = match object.text.as_str() {
                "this" => CallQualifier::This,
                "super" => CallQualifier::Super,
                _ if object.kind == TokKind::Ident => CallQualifier::Identifier,
                _ => CallQualifier::Other,
            };
            (
                qualifier,
                (object.kind == TokKind::Ident).then(|| object.text.clone()),
            )
        } else {
            (CallQualifier::Implicit, None)
        };
        calls.push(CallSite {
            name: tokens[at].text.clone(),
            receiver,
            qualifier,
            offset,
        });
    }
    calls
}

fn parameter_bindings(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
) -> Vec<(String, String)> {
    let Some(range) = declaration.parameters.clone() else {
        return Vec::new();
    };
    let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
    let mut bindings = Vec::new();
    let mut segment = 0;
    let mut depth = 0i32;
    for at in 0..=tokens.len() {
        let word = tokens.get(at).map_or(",", |token| token.text.as_str());
        match word {
            "(" | "[" | "<" => depth += 1,
            ")" | "]" | ">" => depth -= 1,
            _ => {}
        }
        if word == "," && depth == 0 {
            if let Some(name_at) = (segment..at)
                .rev()
                .find(|&index| tokens[index].kind == TokKind::Ident)
            {
                let ty = tokens[segment..name_at]
                    .iter()
                    .filter(|token| token.text != "final" && token.text != "@")
                    .map(|token| token.text.as_str())
                    .collect();
                bindings.push((tokens[name_at].text.clone(), ty));
            }
            segment = at + 1;
        }
    }
    bindings
}

fn receiver_has_type_at(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
    receiver: &str,
    types: &[&str],
    before: usize,
) -> bool {
    let matches_type = |ty: &str| {
        types
            .iter()
            .any(|wanted| ty.rsplit('.').next() == Some(*wanted))
    };
    if let Some((_, ty)) = parameter_bindings(syntax, declaration)
        .into_iter()
        .find(|(name, _)| name == receiver)
    {
        return matches_type(&ty);
    }
    if let Some(body) = declaration.body.clone() {
        let tokens = syntax.tokens_in(body.start..before).collect::<Vec<_>>();
        if let Some(at) = tokens.iter().rposition(|token| {
            token.kind == TokKind::Ident
                && token.text == receiver
                && looks_like_declaration_name(&tokens, token.start as usize)
        }) {
            return at
                .checked_sub(1)
                .is_some_and(|type_at| matches_type(&tokens[type_at].text));
        }
    }
    declaration.owner.is_some_and(|owner| {
        syntax.declarations.iter().any(|field| {
            field.owner == Some(owner)
                && field.kind == D::Field
                && field.names.iter().any(|name| name == receiver)
                && matches_type(&field.declared_type)
        })
    })
}

fn reaches_security_check(
    syntax: &JavaSyntax,
    owner: usize,
    declaration_id: usize,
    remaining_edges: usize,
    visiting: &mut Vec<usize>,
) -> bool {
    if visiting.contains(&declaration_id) {
        return false;
    }
    visiting.push(declaration_id);
    let declaration = &syntax.declarations[declaration_id];
    for call in call_sites(syntax, declaration) {
        if call.name.starts_with("check")
            && call.receiver.as_deref().is_some_and(|receiver| {
                receiver_has_type_at(
                    syntax,
                    declaration,
                    receiver,
                    &["SecurityManager", "AccessController"],
                    call.offset,
                )
            })
        {
            visiting.pop();
            return true;
        }
        if remaining_edges > 0
            && !matches!(
                call.qualifier,
                CallQualifier::Identifier | CallQualifier::Super
            )
        {
            for (target_id, _) in syntax
                .declarations
                .iter()
                .enumerate()
                .filter(|(_, target)| {
                    target.owner == Some(owner)
                        && target.kind == D::Method
                        && target.name == call.name
                })
            {
                if reaches_security_check(syntax, owner, target_id, remaining_edges - 1, visiting) {
                    visiting.pop();
                    return true;
                }
            }
        }
    }
    visiting.pop();
    false
}

fn reaches_non_final_member(
    syntax: &JavaSyntax,
    owner: usize,
    declaration_id: usize,
    remaining_edges: usize,
    visiting: &mut Vec<usize>,
) -> bool {
    if visiting.contains(&declaration_id) {
        return false;
    }
    visiting.push(declaration_id);
    for call in call_sites(syntax, &syntax.declarations[declaration_id]) {
        for (target_id, target) in syntax
            .declarations
            .iter()
            .enumerate()
            .filter(|(_, target)| {
                target.owner == Some(owner) && target.kind == D::Method && target.name == call.name
            })
        {
            if !target.modifiers.iter().any(|modifier| modifier == "final") {
                visiting.pop();
                return true;
            }
            if remaining_edges > 0
                && reaches_non_final_member(syntax, owner, target_id, remaining_edges - 1, visiting)
            {
                visiting.pop();
                return true;
            }
        }
    }
    visiting.pop();
    false
}

fn enclosing_class_range(syntax: &JavaSyntax, offset: usize) -> Option<std::ops::Range<usize>> {
    syntax
        .declarations
        .iter()
        .filter(|declaration| declaration.kind == D::Class && declaration.range.contains(&offset))
        .min_by_key(|declaration| declaration.range.end - declaration.range.start)
        .map(|declaration| declaration.range.clone())
}

fn enclosing_executable_range(
    syntax: &JavaSyntax,
    offset: usize,
) -> Option<std::ops::Range<usize>> {
    syntax
        .declarations
        .iter()
        .filter(|declaration| {
            matches!(
                declaration.kind,
                D::Method | D::Constructor | D::Initializer
            ) && declaration.range.contains(&offset)
        })
        .min_by_key(|declaration| declaration.range.end - declaration.range.start)
        .map(|declaration| {
            declaration
                .body
                .clone()
                .unwrap_or_else(|| declaration.range.clone())
        })
}

fn is_descendant_of(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
    ancestor: usize,
) -> bool {
    let mut owner = declaration.owner;
    while let Some(id) = owner {
        if id == ancestor {
            return true;
        }
        owner = syntax.declarations[id].owner;
    }
    false
}

fn is_descendant_of_range(
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
    range: std::ops::Range<usize>,
) -> bool {
    declaration.range.start >= range.start && declaration.range.end <= range.end
}

fn is_member_declaration_name(syntax: &JavaSyntax, offset: usize, name: &str) -> bool {
    syntax.declarations.iter().any(|declaration| {
        declaration.range.contains(&offset)
            && declaration.name == name
            && matches!(
                declaration.kind,
                D::Method | D::Constructor | D::Class | D::Interface | D::Enum | D::Record
            )
            && syntax
                .tokens_in(declaration.range.start..offset.saturating_add(name.len() + 1))
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair[0].start as usize == offset && pair[1].text == "(")
    })
}

fn has_resolved_reference(
    syntax: &JavaSyntax,
    range: std::ops::Range<usize>,
    name: &str,
    declaring_field: Option<std::ops::Range<usize>>,
) -> bool {
    syntax.tokens_in(range).any(|token| {
        let offset = token.start as usize;
        token.kind == TokKind::Ident
            && token.text == name
            && !declaring_field
                .as_ref()
                .is_some_and(|field| field.contains(&offset))
            && !syntax.declarations.iter().any(|declaration| {
                declaration.kind == D::Field
                    && declaration.names.iter().any(|candidate| candidate == name)
                    && declaration.range.contains(&offset)
            })
            && !is_shadowed_at(syntax, offset, name)
    })
}

fn is_shadowed_at(syntax: &JavaSyntax, offset: usize, name: &str) -> bool {
    let Some(method) = syntax
        .declarations
        .iter()
        .filter(|declaration| {
            matches!(declaration.kind, D::Method | D::Constructor)
                && declaration.range.contains(&offset)
        })
        .min_by_key(|declaration| declaration.range.end - declaration.range.start)
    else {
        return false;
    };
    if parameter_names(syntax, method)
        .iter()
        .any(|candidate| candidate == name)
    {
        return true;
    }
    method
        .body
        .clone()
        .is_some_and(|body| is_local_declared_before(syntax, body, name, offset))
}

fn parameter_names(
    syntax: &JavaSyntax,
    declaration: &uniflow_parser_core::java_syntax::JavaDeclaration,
) -> Vec<String> {
    let Some(range) = declaration.parameters.clone() else {
        return Vec::new();
    };
    let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
    let mut names = Vec::new();
    let mut segment = 0;
    let mut depth = 0i32;
    for at in 0..=tokens.len() {
        let word = tokens.get(at).map_or(",", |token| token.text.as_str());
        match word {
            "(" | "[" | "<" => depth += 1,
            ")" | "]" | ">" => depth -= 1,
            _ => {}
        }
        if word == "," && depth == 0 {
            if let Some(name) = tokens[segment..at]
                .iter()
                .rev()
                .find(|token| token.kind == TokKind::Ident)
            {
                names.push(name.text.clone());
            }
            segment = at + 1;
        }
    }
    names
}

fn looks_like_declaration_name(tokens: &[&Token], offset: usize) -> bool {
    let Some(at) = tokens
        .iter()
        .position(|token| token.start as usize == offset)
    else {
        return false;
    };
    if at == 0 || tokens[at - 1].text == "." {
        return false;
    }
    let previous = tokens[at - 1].text.as_str();
    tokens[at - 1].kind == TokKind::Ident || matches!(previous, "]" | ">" | ">>" | ">>>")
}

fn is_local_declared_before(
    syntax: &JavaSyntax,
    range: std::ops::Range<usize>,
    name: &str,
    before: usize,
) -> bool {
    let tokens = syntax.tokens_in(range.start..before).collect::<Vec<_>>();
    tokens.iter().enumerate().any(|(at, token)| {
        token.kind == TokKind::Ident
            && token.text == name
            && looks_like_declaration_name(&tokens, tokens[at].start as usize)
    })
}

fn is_declared_before(
    syntax: &JavaSyntax,
    scope: std::ops::Range<usize>,
    name: &str,
    before: usize,
) -> bool {
    if syntax.declarations.iter().any(|declaration| {
        declaration.kind == D::Field
            && declaration.names.iter().any(|candidate| candidate == name)
            && declaration.range.start <= before
    }) {
        return true;
    }
    if let Some(method) = syntax
        .declarations
        .iter()
        .filter(|declaration| {
            matches!(declaration.kind, D::Method | D::Constructor)
                && declaration.range.contains(&before)
        })
        .min_by_key(|declaration| declaration.range.end - declaration.range.start)
    {
        if parameter_names(syntax, method)
            .iter()
            .any(|candidate| candidate == name)
        {
            return true;
        }
    }
    is_local_declared_before(syntax, scope, name, before)
}

fn inside_nested_type_or_lambda(
    syntax: &JavaSyntax,
    offset: usize,
    after: usize,
    scope_end: usize,
) -> bool {
    if syntax.declarations.iter().any(|declaration| {
        matches!(
            declaration.kind,
            D::Class | D::Interface | D::Enum | D::Record | D::AnonymousClass
        ) && declaration.range.start >= after
            && declaration.range.end <= scope_end
            && declaration.range.contains(&offset)
    }) {
        return true;
    }
    let tokens = syntax
        .tokens_in(after..offset.saturating_add(1))
        .collect::<Vec<_>>();
    tokens
        .iter()
        .rposition(|token| token.text == "->")
        .is_some_and(|arrow| !tokens[arrow + 1..].iter().any(|token| token.text == ";"))
}

fn has_unshadowed_name(
    syntax: &JavaSyntax,
    method: &uniflow_parser_core::java_syntax::JavaDeclaration,
    range: std::ops::Range<usize>,
    name: &str,
) -> bool {
    if parameter_names(syntax, method)
        .iter()
        .any(|candidate| candidate == name)
    {
        return false;
    }
    syntax.tokens_in(range).any(|token| {
        token.kind == TokKind::Ident
            && token.text == name
            && !is_local_declared_before(
                syntax,
                method.body.clone().unwrap(),
                name,
                token.start as usize,
            )
    })
}

fn method_mutates_name(
    syntax: &JavaSyntax,
    method: &uniflow_parser_core::java_syntax::JavaDeclaration,
    name: &str,
) -> bool {
    if parameter_names(syntax, method)
        .iter()
        .any(|candidate| candidate == name)
    {
        return false;
    }
    let body = method.body.clone().unwrap();
    let tokens = syntax.tokens_in(body.clone()).collect::<Vec<_>>();
    tokens.iter().enumerate().any(|(at, token)| {
        if token.kind != TokKind::Ident
            || token.text != name
            || is_local_declared_before(syntax, body.clone(), name, token.start as usize)
        {
            return false;
        }
        let next = tokens.get(at + 1).map(|token| token.text.as_str());
        let assignment = next.is_some_and(|word| {
            matches!(
                word,
                "=" | "+="
                    | "-="
                    | "*="
                    | "/="
                    | "%="
                    | "&="
                    | "|="
                    | "^="
                    | "<<="
                    | ">>="
                    | ">>>="
            )
        });
        let mutator = next == Some(".")
            && tokens.get(at + 2).is_some_and(|method| {
                let lower = method.text.to_ascii_lowercase();
                [
                    "add", "remove", "delete", "insert", "clean", "reset", "resize",
                ]
                .iter()
                .any(|candidate| lower.contains(candidate))
            })
            && tokens.get(at + 3).is_some_and(|token| token.text == "(");
        assignment || mutator
    })
}

fn hash_url_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    let mut offsets = Vec::new();
    for declaration in &syntax.declarations {
        if declaration.kind == D::Field && is_url_collection_type(&declaration.declared_type) {
            offsets.push(declaration.range.start);
        }
        if matches!(declaration.kind, D::Method | D::Constructor) {
            if let Some(range) = declaration.parameters.clone() {
                let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
                offsets.extend(url_collection_declarations(&tokens));
            }
        }
    }
    for node in &syntax.nodes {
        if node.kind == K::Other {
            let tokens = syntax.tokens_in(node.range.clone()).collect::<Vec<_>>();
            offsets.extend(url_collection_declarations(&tokens).into_iter().take(1));
        }
        if node.kind == K::For {
            if let Some(range) = node.initializer.clone() {
                let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
                offsets.extend(url_collection_declarations(&tokens).into_iter().take(1));
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn is_url_collection_type(ty: &str) -> bool {
    let compact = ty
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    let Some(open) = compact.find('<') else {
        return false;
    };
    let outer = compact[..open].rsplit('.').next().unwrap_or_default();
    if !matches!(outer, "Set" | "Map") {
        return false;
    }
    let first = compact[open + 1..]
        .split([',', '>'])
        .next()
        .unwrap_or_default();
    first.rsplit('.').next() == Some("URL")
}

fn url_collection_declarations(tokens: &[&Token]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut i = 0;
    while i + 3 < tokens.len() {
        if tokens[i].kind == TokKind::Ident
            && matches!(tokens[i].text.as_str(), "Set" | "Map")
            && tokens[i + 1].text == "<"
        {
            let mut depth = 1i32;
            let mut j = i + 2;
            let mut first_arg_last = None;
            let mut first_arg = true;
            while j < tokens.len() && depth > 0 {
                match tokens[j].text.as_str() {
                    "<" => depth += 1,
                    ">" => depth -= 1,
                    ">>" => depth -= 2,
                    ">>>" => depth -= 3,
                    "," if depth == 1 => first_arg = false,
                    _ if first_arg && depth == 1 && tokens[j].kind == TokKind::Ident => {
                        first_arg_last = Some(tokens[j].text.as_str())
                    }
                    _ => {}
                }
                j += 1;
            }
            while j + 1 < tokens.len() && tokens[j].text == "[" && tokens[j + 1].text == "]" {
                j += 2;
            }
            if depth <= 0
                && first_arg_last == Some("URL")
                && tokens
                    .get(j)
                    .is_some_and(|token| token.kind == TokKind::Ident)
            {
                let after_name = j + 1;
                if after_name == tokens.len()
                    || matches!(
                        tokens[after_name].text.as_str(),
                        "=" | "," | ";" | ")" | ":" | "["
                    )
                {
                    offsets.push(tokens[i].start as usize);
                    i = after_name;
                    continue;
                }
            }
        }
        i += 1;
    }
    offsets
}

fn inherited_methods<'a>(
    syntax: &'a JavaSyntax,
    method: &JavaDeclaration,
) -> Vec<&'a JavaDeclaration> {
    let Some(owner) = method.owner else {
        return Vec::new();
    };
    let mut pending = Vec::new();
    let class = &syntax.declarations[owner];
    if !class.superclass.is_empty() {
        pending.push(class.superclass.clone());
    }
    pending.extend(class.interfaces.iter().cloned());
    let mut owners = Vec::new();
    let mut visited = std::collections::HashSet::new();
    while let Some(name) = pending.pop() {
        let simple = name.rsplit('.').next().unwrap_or(&name);
        let Some((id, declaration)) = syntax
            .declarations
            .iter()
            .enumerate()
            .find(|(_, candidate)| {
                matches!(candidate.kind, D::Class | D::Interface)
                    && candidate.name == simple
            })
        else {
            continue;
        };
        if !visited.insert(id) {
            continue;
        }
        owners.push(id);
        if !declaration.superclass.is_empty() {
            pending.push(declaration.superclass.clone());
        }
        pending.extend(declaration.interfaces.iter().cloned());
    }
    syntax
        .declarations
        .iter()
        .filter(|candidate| {
            candidate.kind == D::Method
                && owners.contains(&candidate.owner.unwrap_or(usize::MAX))
                && candidate.name == method.name
        })
        .collect()
}

fn method_signatures_equal(
    syntax: &JavaSyntax,
    left: &JavaDeclaration,
    right: &JavaDeclaration,
) -> bool {
    left.name == right.name
        && method_parameter_types(syntax, left) == method_parameter_types(syntax, right)
}

fn method_parameter_types(syntax: &JavaSyntax, method: &JavaDeclaration) -> Vec<String> {
    let Some(range) = method.parameters.clone() else {
        return Vec::new();
    };
    let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
    if tokens.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut angle = 0i32;
    let mut paren = 0i32;
    let mut bracket = 0i32;
    for index in 0..=tokens.len() {
        let separator = index == tokens.len()
            || tokens[index].text == "," && angle == 0 && paren == 0 && bracket == 0;
        if separator {
            if start < index {
                result.push(parameter_type_key(&tokens[start..index]));
            }
            start = index + 1;
            continue;
        }
        match tokens[index].text.as_str() {
            "<" => angle += 1,
            ">" => angle = (angle - 1).max(0),
            ">>" => angle = (angle - 2).max(0),
            ">>>" => angle = (angle - 3).max(0),
            "(" => paren += 1,
            ")" => paren = (paren - 1).max(0),
            "[" => bracket += 1,
            "]" => bracket = (bracket - 1).max(0),
            _ => {}
        }
    }
    result
}

fn parameter_type_key(tokens: &[&Token]) -> String {
    let Some(name_index) = tokens.iter().rposition(|token| token.kind == TokKind::Ident) else {
        return String::new();
    };
    let mut type_tokens = Vec::new();
    let mut index = 0usize;
    while index < name_index {
        if tokens[index].text == "final" {
            index += 1;
            continue;
        }
        if tokens[index].text == "@" {
            index += 1;
            while index < name_index
                && (tokens[index].kind == TokKind::Ident || tokens[index].text == ".")
            {
                index += 1;
            }
            if index < name_index && tokens[index].text == "(" {
                let mut depth = 1i32;
                index += 1;
                while index < name_index && depth > 0 {
                    match tokens[index].text.as_str() {
                        "(" => depth += 1,
                        ")" => depth -= 1,
                        _ => {}
                    }
                    index += 1;
                }
            }
            continue;
        }
        type_tokens.push(tokens[index].text.as_str());
        index += 1;
    }
    // Java treats qualified and imported spellings of the same simple type alike
    // for this source-local inheritance check.
    type_tokens.join("").replace("java.lang.", "")
}

fn method_visibility(syntax: &JavaSyntax, method: &JavaDeclaration) -> u8 {
    if method.modifiers.iter().any(|value| value == "public")
        || method.owner.is_some_and(|owner| syntax.declarations[owner].kind == D::Interface)
    {
        3
    } else if method.modifiers.iter().any(|value| value == "protected") {
        2
    } else if method.modifiers.iter().any(|value| value == "private") {
        0
    } else {
        1
    }
}

fn collection_view_backing(
    syntax: &JavaSyntax,
    method: &JavaDeclaration,
    view: &str,
    before: usize,
) -> Option<String> {
    let body = method.body.clone()?;
    let tokens = syntax
        .tokens_in(body.start..before.min(body.end))
        .collect::<Vec<_>>();
    tokens.windows(6).rev().find_map(|window| {
        (window[0].kind == TokKind::Ident
            && window[0].text == view
            && window[1].text == "="
            && window[2].kind == TokKind::Ident
            && window[3].text == "."
            && matches!(
                window[4].text.as_str(),
                "keySet" | "values" | "entrySet" | "subList"
            )
            && window[5].text == "(")
            .then(|| window[2].text.clone())
    })
}

fn invalid_constant_regex_offsets(source: &str, syntax: &JavaSyntax) -> Vec<usize> {
    let tokens = syntax.tokens_in(0..source.len()).collect::<Vec<_>>();
    let mut offsets = Vec::new();
    for index in 0..tokens.len().saturating_sub(2) {
        let name = tokens[index].text.as_str();
        let pattern_api = name == "compile"
            && index >= 2
            && tokens[index - 1].text == "."
            && tokens[index - 2].text == "Pattern";
        let string_api = matches!(name, "matches" | "replaceAll" | "replaceFirst" | "split");
        if !(pattern_api || string_api)
            || tokens[index + 1].text != "("
            || tokens[index + 2].kind != TokKind::StringLit
        {
            continue;
        }
        let Some(pattern) = java_string_literal_value(&tokens[index + 2].text) else {
            continue;
        };
        if !is_valid_java_regex_shape(&pattern) {
            offsets.push(tokens[index].start as usize);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn double_checked_locking_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    let fields = syntax
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.kind == D::Field
                && declaration.modifiers.iter().any(|modifier| modifier == "static")
                && !declaration
                    .modifiers
                    .iter()
                    .any(|modifier| modifier == "volatile")
        })
        .flat_map(|declaration| declaration.names.iter().cloned())
        .collect::<Vec<_>>();
    let mut offsets = Vec::new();
    for outer in syntax.nodes.iter().filter(|node| node.kind == K::If) {
        let Some(outer_condition) = outer.condition.clone() else {
            continue;
        };
        let Some(field) = fields
            .iter()
            .find(|field| null_check_names(syntax, outer_condition.clone(), field))
        else {
            continue;
        };
        let Some(sync) = syntax.nodes.iter().find(|node| {
            node.kind == K::Synchronized
                && outer.range.start < node.range.start
                && node.range.end <= outer.range.end
        }) else {
            continue;
        };
        let Some(inner) = syntax.nodes.iter().find(|node| {
            node.kind == K::If
                && sync.range.start < node.range.start
                && node.range.end <= sync.range.end
                && node
                    .condition
                    .clone()
                    .is_some_and(|condition| null_check_names(syntax, condition, field))
        }) else {
            continue;
        };
        let tokens = syntax.tokens_in(inner.range.clone()).collect::<Vec<_>>();
        if tokens.windows(3).any(|window| {
            window[0].text == *field
                && window[1].text == "="
                && matches!(window[2].text.as_str(), "new" | "getInstance" | "create" | "build")
        }) {
            offsets.push(outer.range.start);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn class_initialization_cycle_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    let static_fields = syntax
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.kind == D::Field
                && declaration.modifiers.iter().any(|modifier| modifier == "static")
        })
        .collect::<Vec<_>>();
    let mut offsets = Vec::new();

    // A static initializer that directly reads a later field of the same class
    // observes that field's JVM default value.
    for field in &static_fields {
        let Some(owner) = field.owner else {
            continue;
        };
        let later_names = static_fields
            .iter()
            .filter(|candidate| {
                candidate.owner == Some(owner) && candidate.range.start > field.range.start
            })
            .flat_map(|candidate| candidate.names.iter())
            .collect::<Vec<_>>();
        let tokens = syntax.tokens_in(field.range.clone()).collect::<Vec<_>>();
        let direct_late_read = tokens.iter().any(|token| {
            token.kind == TokKind::Ident
                && later_names.iter().any(|name| token.text == name.as_str())
        });
        let constructs_owner = tokens.windows(2).any(|window| {
            window[0].text == "new" && window[1].text == syntax.declarations[owner].name
        });
        let constructor_reads_later = constructs_owner
            && syntax.declarations.iter().any(|constructor| {
                constructor.owner == Some(owner)
                    && constructor.kind == D::Constructor
                    && constructor.body.clone().is_some_and(|body| {
                        syntax.tokens_in(body).any(|token| {
                            token.kind == TokKind::Ident
                                && later_names.iter().any(|name| token.text == name.as_str())
                        })
                    })
            });
        if direct_late_read || constructor_reads_later {
            offsets.push(field.range.start);
        }
    }

    // Build class-to-class static initializer edges and report both ends of a
    // direct cycle. Longer cycles are found by the transitive reachability walk.
    let mut edges = std::collections::HashMap::<usize, std::collections::HashSet<usize>>::new();
    let mut edge_field = std::collections::HashMap::<(usize, usize), usize>::new();
    for field in &static_fields {
        let Some(owner) = field.owner else {
            continue;
        };
        let tokens = syntax.tokens_in(field.range.clone()).collect::<Vec<_>>();
        for window in tokens.windows(3) {
            if window[0].kind != TokKind::Ident
                || window[1].text != "."
                || window[2].kind != TokKind::Ident
            {
                continue;
            }
            let Some((target, _)) = syntax.declarations.iter().enumerate().find(|(_, class)| {
                matches!(class.kind, D::Class | D::Interface)
                    && class.name == window[0].text
            }) else {
                continue;
            };
            if target != owner {
                edges.entry(owner).or_default().insert(target);
                edge_field.entry((owner, target)).or_insert(field.range.start);
            }
        }
    }
    for (&from, targets) in &edges {
        for &to in targets {
            if class_dependency_reaches(&edges, to, from) {
                if let Some(offset) = edge_field.get(&(from, to)) {
                    offsets.push(*offset);
                }
            }
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn class_dependency_reaches(
    edges: &std::collections::HashMap<usize, std::collections::HashSet<usize>>,
    start: usize,
    wanted: usize,
) -> bool {
    let mut pending = vec![start];
    let mut seen = std::collections::HashSet::new();
    while let Some(node) = pending.pop() {
        if node == wanted {
            return true;
        }
        if seen.insert(node) {
            pending.extend(edges.get(&node).into_iter().flatten().copied());
        }
    }
    false
}

fn android_shared_storage_apk_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    syntax
        .declarations
        .iter()
        .filter(|declaration| matches!(declaration.kind, D::Method | D::Constructor))
        .filter_map(|declaration| {
            let body = declaration.body.clone()?;
            let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
            let shared_storage = tokens.iter().any(|token| {
                matches!(
                    token.text.as_str(),
                    "getExternalStorageDirectory" | "getExternalStoragePublicDirectory"
                )
            });
            let apk_install = tokens.iter().any(|token| {
                token.kind == TokKind::StringLit
                    && token.text.contains("application/vnd.android.package-archive")
            }) && tokens.iter().any(|token| token.text == "startActivity");
            (shared_storage && apk_install).then_some(declaration.range.start)
        })
        .collect()
}

fn wrong_parameter_order_offsets(syntax: &JavaSyntax) -> Vec<usize> {
    let signatures = syntax
        .declarations
        .iter()
        .filter(|declaration| declaration.kind == D::Method)
        .filter_map(|declaration| {
            let parameters = parameter_names(syntax, declaration);
            (parameters.len() >= 2).then(|| (declaration.name.clone(), parameters))
        })
        .collect::<Vec<_>>();
    let mut offsets = Vec::new();
    for caller in syntax
        .declarations
        .iter()
        .filter(|declaration| matches!(declaration.kind, D::Method | D::Constructor))
    {
        let Some(body) = caller.body.clone() else {
            continue;
        };
        let tokens = syntax.tokens_in(body).collect::<Vec<_>>();
        let mut index = 0usize;
        while index + 1 < tokens.len() {
            if tokens[index].kind != TokKind::Ident || tokens[index + 1].text != "(" {
                index += 1;
                continue;
            }
            if index >= 1 && tokens[index - 1].text == "."
                && !(index >= 2 && tokens[index - 2].text == "this")
            {
                index += 1;
                continue;
            }
            let name = tokens[index].text.as_str();
            let mut depth = 1i32;
            let mut cursor = index + 2;
            let mut segment = cursor;
            let mut arguments = Vec::new();
            let mut valid = true;
            while cursor < tokens.len() && depth > 0 {
                match tokens[cursor].text.as_str() {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => {
                        depth -= 1;
                        if depth == 0 {
                            if segment < cursor {
                                if cursor - segment == 1
                                    && tokens[segment].kind == TokKind::Ident
                                {
                                    arguments.push(tokens[segment].text.clone());
                                } else {
                                    valid = false;
                                }
                            }
                            break;
                        }
                    }
                    "," if depth == 1 => {
                        if cursor - segment == 1 && tokens[segment].kind == TokKind::Ident {
                            arguments.push(tokens[segment].text.clone());
                        } else {
                            valid = false;
                        }
                        segment = cursor + 1;
                    }
                    _ => {}
                }
                cursor += 1;
            }
            if valid
                && signatures.iter().any(|(candidate, parameters)| {
                    candidate == name
                        && arguments.len() == parameters.len()
                        && arguments != *parameters
                        && arguments.iter().all(|argument| parameters.contains(argument))
                        && parameters.iter().all(|parameter| arguments.contains(parameter))
                })
            {
                offsets.push(tokens[index].start as usize);
            }
            index = cursor.max(index + 1);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn fixed_initialization_vector_offsets(source: &str, syntax: &JavaSyntax) -> Vec<usize> {
    let tokens = syntax.tokens_in(0..source.len()).collect::<Vec<_>>();
    let mut offsets = Vec::new();
    for index in 0..tokens.len().saturating_sub(3) {
        if tokens[index].text != "new"
            || tokens[index + 1].text != "IvParameterSpec"
            || tokens[index + 2].text != "("
        {
            continue;
        }
        let argument = &tokens[index + 3];
        let fixed = if argument.kind == TokKind::StringLit {
            true
        } else if argument.text == "new" {
            tokens.get(index + 4).is_some_and(|token| token.text == "byte")
        } else if argument.kind == TokKind::Ident {
            let name = argument.text.as_str();
            let before = &tokens[..index];
            let securely_filled = before.windows(4).any(|window| {
                window[0].text == "nextBytes"
                    && window[1].text == "("
                    && window[2].text == name
                    && window[3].text == ")"
            }) || before.windows(3).any(|window| {
                window[0].text == name
                    && window[1].text == "="
                    && window[2].text == "generateSeed"
            }) || before.windows(5).any(|window| {
                window[0].text == name
                    && window[1].text == "="
                    && window[2].text == "secureRandom"
                    && window[3].text == "."
                    && window[4].text == "generateSeed"
            });
            let fixed_initializer = before.windows(3).any(|window| {
                window[0].text == name
                    && window[1].text == "="
                    && (window[2].text == "{" || window[2].kind == TokKind::StringLit)
            }) || before.windows(5).any(|window| {
                window[0].text == name
                    && window[1].text == "="
                    && window[2].text == "new"
                    && window[3].text == "byte"
                    && window[4].text == "["
            });
            fixed_initializer && !securely_filled
        } else {
            false
        };
        if fixed {
            offsets.push(tokens[index].start as usize);
        }
    }
    offsets
}

fn null_check_names(
    syntax: &JavaSyntax,
    range: std::ops::Range<usize>,
    name: &str,
) -> bool {
    let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
    tokens.windows(3).any(|window| {
        (window[0].text == name
            && window[1].text == "=="
            && window[2].text == "null")
            || (window[0].text == "null"
                && window[1].text == "=="
                && window[2].text == name)
    })
}

fn java_string_literal_value(literal: &str) -> Option<String> {
    let body = literal.strip_prefix('"')?.strip_suffix('"')?;
    let mut chars = body.chars().peekable();
    let mut output = String::new();
    while let Some(character) = chars.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            'b' => output.push('\u{0008}'),
            't' => output.push('\t'),
            'n' => output.push('\n'),
            'f' => output.push('\u{000c}'),
            'r' => output.push('\r'),
            '"' => output.push('"'),
            '\'' => output.push('\''),
            '\\' => output.push('\\'),
            'u' => {
                let digits = (0..4).map(|_| chars.next()).collect::<Option<String>>()?;
                output.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            '0'..='7' => {
                // The exact code point is irrelevant to regex structure.
                output.push('x');
                for _ in 0..2 {
                    if chars.peek().is_some_and(|next| matches!(next, '0'..='7')) {
                        chars.next();
                    }
                }
            }
            // Invalid Java escapes are compiler errors rather than regex errors.
            _ => return None,
        }
    }
    Some(output)
}

fn is_valid_java_regex_shape(pattern: &str) -> bool {
    let chars = pattern.chars().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut parens = 0usize;
    let mut in_class = false;
    let mut class_has_atom = false;
    let mut can_quantify = false;
    let mut previous_quantifier = false;
    let mut quoted = false;
    while index < chars.len() {
        let character = chars[index];
        if quoted {
            if character == '\\' && chars.get(index + 1) == Some(&'E') {
                quoted = false;
                index += 2;
            } else {
                index += 1;
            }
            can_quantify = true;
            continue;
        }
        if character == '\\' {
            let Some(&escaped) = chars.get(index + 1) else {
                return false;
            };
            if escaped == 'Q' {
                quoted = true;
                index += 2;
                continue;
            }
            if matches!(escaped, 'p' | 'P') && chars.get(index + 2) == Some(&'{') {
                let Some(close) = chars[index + 3..].iter().position(|value| *value == '}') else {
                    return false;
                };
                if close == 0 {
                    return false;
                }
                index += close + 4;
            } else {
                index += 2;
            }
            if in_class {
                class_has_atom = true;
            }
            can_quantify = true;
            previous_quantifier = false;
            continue;
        }
        if in_class {
            if character == ']' {
                if !class_has_atom {
                    return false;
                }
                in_class = false;
                can_quantify = true;
            } else {
                class_has_atom = true;
            }
            index += 1;
            continue;
        }
        match character {
            '[' => {
                in_class = true;
                class_has_atom = false;
                can_quantify = false;
                previous_quantifier = false;
            }
            '(' => {
                parens += 1;
                can_quantify = false;
                previous_quantifier = false;
            }
            ')' => {
                if parens == 0 {
                    return false;
                }
                parens -= 1;
                can_quantify = true;
                previous_quantifier = false;
            }
            '*' | '+' | '?' => {
                let group_prefix = character == '?'
                    && index > 0
                    && chars[index - 1] == '('
                    && parens > 0;
                if !can_quantify && !group_prefix && !previous_quantifier {
                    return false;
                }
                can_quantify = !group_prefix;
                previous_quantifier = !group_prefix;
            }
            '{' => {
                if !can_quantify {
                    return false;
                }
                let Some(relative_close) = chars[index + 1..].iter().position(|value| *value == '}')
                else {
                    return false;
                };
                let close = index + 1 + relative_close;
                let body = chars[index + 1..close].iter().collect::<String>();
                let valid = body
                    .split_once(',')
                    .map_or_else(|| !body.is_empty() && body.chars().all(|c| c.is_ascii_digit()), |(low, high)| {
                        !low.is_empty()
                            && low.chars().all(|c| c.is_ascii_digit())
                            && (high.is_empty() || high.chars().all(|c| c.is_ascii_digit()))
                    });
                if !valid {
                    return false;
                }
                index = close;
                previous_quantifier = true;
            }
            '}' => return false,
            '|' | '^' | '$' => {
                can_quantify = false;
                previous_quantifier = false;
            }
            '.' => {
                can_quantify = true;
                previous_quantifier = false;
            }
            _ => {
                can_quantify = true;
                previous_quantifier = false;
            }
        }
        index += 1;
    }
    !in_class && parens == 0 && !quoted
}

fn contains_method_invocation(syntax: &JavaSyntax, range: std::ops::Range<usize>) -> bool {
    let tokens = syntax.tokens_in(range).collect::<Vec<_>>();
    tokens.windows(2).enumerate().any(|(index, pair)| {
        pair[0].kind == TokKind::Ident
            && pair[1].text == "("
            && !matches!(
                pair[0].text.as_str(),
                "if" | "for" | "while" | "switch" | "catch" | "synchronized"
            )
            && !index
                .checked_sub(1)
                .is_some_and(|previous| tokens[previous].text == "new")
    })
}

// Legacy rules treat line-comment-only blocks as empty, but deliberately do
// not treat block-comment-only bodies or an empty statement inside braces as empty.
fn empty(source: &str, range: std::ops::Range<usize>) -> bool {
    let text = source[range].trim();
    if text == ";" {
        return true;
    }
    let Some(body) = text.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return false;
    };
    body.lines().all(|line| {
        let line = line.trim();
        line.is_empty() || line.starts_with("//")
    })
}
