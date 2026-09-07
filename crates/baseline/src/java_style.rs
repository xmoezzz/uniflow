use serde::{Deserialize, Serialize};
use uniflow_parser_core::java_syntax::{JavaDeclarationKind as D, JavaSyntax, JavaSyntaxKind as K};
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
}

impl JavaStyleCheck {
    pub(crate) fn offsets(self, source: &str, syntax: &JavaSyntax) -> Vec<usize> {
        use JavaStyleCheck as C;
        if matches!(
            self,
            C::SyncObjectIsFinal | C::SynchronizedObject | C::SyncObjectNotifyMethod
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
            let Some(field) = syntax.declarations.iter().find(|declaration| {
                declaration.kind == D::Field
                    && declaration.owner == owner
                    && declaration.names.iter().any(|candidate| candidate == name)
            }) else {
                continue;
            };
            let matches = match self {
                C::SyncObjectIsFinal => !field.modifiers.iter().any(|modifier| modifier == "final"),
                C::SynchronizedObject => field.declared_type.rsplit('.').next() == Some("String"),
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
                _ => {}
            }
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
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
