use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uniflow_parser_core::{
    c_declarations::CDeclarationIndex,
    c_expressions::{CExpressionFact, CExpressionFactKind as K, CExpressionIndex},
    java_syntax::{JavaSyntax, JavaSyntaxKind},
    TokKind,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CExpressionCheck {
    AssignmentOutsideStatement,
    UpdateInExpression,
    SideEffectInSizeof,
    CommaExpression,
    AssignmentInIf,
    ConditionalExpression,
    BinaryInConditional,
    DangerousRegistryAccessMacro,
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
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }
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
