mod c_style;
mod hir_scan;
mod java_config;
mod java_style;
mod migration;
mod semgrep_compat;
pub use c_style::CStyleCheck;
mod c_preprocessor;
pub use c_preprocessor::CMacroCheck;
mod c_declaration_rules;
pub use c_declaration_rules::CDeclarationCheck;
mod c_expression_rules;
pub use c_expression_rules::CExpressionCheck;
mod sql_style;
pub use java_config::{JavaConfigCheck, JavaProjectCheck};
pub use java_style::JavaStyleCheck;
pub use sql_style::{OracleFormsBlock, OracleFormsMetadata, SqlStyleCheck};

pub use migration::{
    audit_legacy_rule_tree, classify_legacy_asset, decrypt_legacy_rule_asset,
    decrypt_legacy_rule_tree, legacy_encryption_profile, LegacyAsset, LegacyAssetAudit,
    LegacyAssetKind, LegacyDecryptedAsset, LegacyDecryptionReport, LegacyEncryptionProfile,
};
pub use migration::{legacy_cpp_inventory, LegacyRuleEntry, LegacyRuleInventory, MigrationState};

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use uniflow_hir::Language;

#[derive(Clone, Copy, Debug)]
pub struct LegacyRawRuleAsset {
    pub path: &'static str,
    pub bytes: &'static [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyJavaPackageRule {
    pub id: &'static str,
    pub message_id: &'static str,
    pub purl: &'static str,
    pub import_regex: &'static str,
    pub testcase: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyJavaAstRule {
    pub id: &'static str,
    pub message_id: &'static str,
    pub source: &'static str,
    pub native_rule_id: Option<&'static str>,
    pub testcase: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyCAstRule {
    pub id: &'static str,
    pub message_id: &'static str,
    pub source: &'static str,
    pub native_rule_id: Option<&'static str>,
    pub testcase: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyCSharpAstRule {
    pub id: &'static str,
    pub message_id: &'static str,
    pub source: &'static str,
    pub native_rule_id: Option<&'static str>,
    pub testcase: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacySqlRule {
    pub id: &'static str,
    pub source: &'static str,
    pub native_rule_id: Option<&'static str>,
    pub testcase: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacySemgrepRule {
    pub id: &'static str,
    pub source: &'static str,
    pub language: &'static str,
    pub mode: &'static str,
    pub native_rule_id: Option<&'static str>,
    pub native_taint_rule_id: Option<&'static str>,
    pub testcase: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct LegacySemgrepSearchCompatRule {
    pub native_rule_id: &'static str,
    pub source: &'static str,
    pub language: &'static str,
    pub title: &'static str,
    pub message: &'static str,
    pub severity: &'static str,
    pub rule_yaml: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/legacy_raw_assets.rs"));

pub fn bundled_legacy_raw_assets() -> &'static [LegacyRawRuleAsset] {
    BUNDLED_LEGACY_RAW_ASSETS
}

pub fn bundled_java_package_rules() -> &'static [LegacyJavaPackageRule] {
    BUNDLED_JAVA_PACKAGE_RULES
}

pub fn bundled_java_ast_rules() -> &'static [LegacyJavaAstRule] {
    BUNDLED_JAVA_AST_RULES
}

pub fn bundled_java_ast_metadata_report() -> &'static str {
    include_str!("../../../rules/legacy/java-ast-metadata-report.json")
}

pub fn bundled_c_ast_rules() -> &'static [LegacyCAstRule] {
    BUNDLED_C_AST_RULES
}

pub fn bundled_csharp_ast_rules() -> &'static [LegacyCSharpAstRule] {
    BUNDLED_CSHARP_AST_RULES
}

pub fn bundled_sql_rules() -> &'static [LegacySqlRule] {
    BUNDLED_SQL_RULES
}

pub fn bundled_semgrep_rules() -> &'static [LegacySemgrepRule] {
    BUNDLED_SEMGREP_RULES
}

pub fn bundled_semgrep_search_compat_rules() -> &'static [LegacySemgrepSearchCompatRule] {
    BUNDLED_SEMGREP_SEARCH_COMPAT_RULES
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselinePack {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub rules: Vec<BaselineRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineRule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub languages: Vec<Language>,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Source-level regex. In HIR mode this is evaluated only for rules that do
    /// not declare a structured matcher, preventing duplicate reports.
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub matcher: BaselineMatcher,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub standards: Vec<String>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub translations: RuleTranslations,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuleTranslations {
    #[serde(default, rename = "zh-CN")]
    pub zh_cn: Option<LocalizedRuleText>,
    #[serde(default)]
    pub en: Option<LocalizedRuleText>,
    #[serde(default, rename = "zh-TW")]
    pub zh_tw: Option<LocalizedRuleText>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LocalizedRuleText {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub message: String,
}

impl RuleTranslations {
    pub fn is_empty(&self) -> bool {
        self.zh_cn.is_none() && self.en.is_none() && self.zh_tw.is_none()
    }

    pub fn get(&self, locale: &str) -> Option<&LocalizedRuleText> {
        match locale.to_ascii_lowercase().replace('_', "-").as_str() {
            "zh" | "zh-cn" | "zh-hans" => self.zh_cn.as_ref(),
            "en" | "en-us" | "en-gb" => self.en.as_ref(),
            "zh-tw" | "zh-hk" | "zh-hant" => self.zh_tw.as_ref(),
            _ => None,
        }
    }
}

impl BaselineRule {
    pub fn localized_title(&self, locale: &str) -> &str {
        self.translations
            .get(locale)
            .map(|text| text.title.as_str())
            .filter(|text| !text.trim().is_empty())
            .unwrap_or(&self.title)
    }

    pub fn localized_message(&self, locale: &str) -> &str {
        self.translations
            .get(locale)
            .map(|text| text.message.as_str())
            .filter(|text| !text.trim().is_empty())
            .or_else(|| (!self.message.trim().is_empty()).then_some(self.message.as_str()))
            .unwrap_or(&self.title)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineMatcher {
    /// Metadata-only marker for rules whose executable implementation lives in
    /// the unified native dataflow engine. Such rules are bundled in the
    /// baseline pack for rule metadata/localization, but the baseline frontend
    /// must not attempt to execute them a second time.
    pub native_dataflow: bool,
    /// Alternative call signatures for one rule. Each alternative carries its
    /// own receiver, arity and argument constraints; findings are emitted once.
    pub call_alternatives: Vec<BaselineMatcher>,
    /// Java structural source check. Uses the shared token/statement index,
    /// independently of HIR type resolution and without executing legacy DSLs.
    pub java_style: Option<JavaStyleCheck>,
    /// Structured checks for Java project auxiliary files such as
    /// AndroidManifest.xml. These files are not parsed as Java source.
    pub java_config: Option<JavaConfigCheck>,
    /// Cross-file Java/framework configuration check evaluated once per project.
    pub java_project: Option<JavaProjectCheck>,
    pub c_style: Option<CStyleCheck>,
    pub c_macro: Option<CMacroCheck>,
    pub c_declaration: Option<CDeclarationCheck>,
    pub c_expression: Option<CExpressionCheck>,
    /// Oracle SQL/PLSQL structural source check backed by the shared balanced
    /// SQL token, IF-branch and BEGIN-block index.
    pub sql_style: Option<SqlStyleCheck>,
    /// XPath 1.0 expression evaluated against the normalized SQL syntax tree
    /// when `sql_style` is `xpath`. An empty query keeps the template disabled.
    pub sql_xpath_query: String,
    /// Optional finding message for a configured SQL XPath template.
    pub sql_xpath_message: String,
    /// C# method-attribute check using balanced declarations, not a source regex.
    pub csharp_http_post_without_antiforgery: bool,
    /// Regex matched against source code after both comments and literals are
    /// masked. This is intended for lexical constructs such as `goto` and
    /// preprocessor directives that do not have a portable HIR node.
    pub code_pattern: String,
    /// Original Semgrep search rule executed by UniFlow's bundled pure-Rust
    /// compatibility matcher. The build embeds the source rule into the binary.
    pub semgrep_compat_yaml: String,
    /// Optional regex restricting the source path for this matcher.
    pub path_pattern: String,
    /// Regex that must occur somewhere in the same comment-free source file as
    /// the structured match, for module/import context such as `require 'jwt'`.
    pub required_file_pattern: String,
    /// Structured match is disabled when any source or auxiliary project file
    /// contains this regex (for example, a required Android permission).
    pub forbidden_project_pattern: String,
    /// Regex matched against a normalized Java import path.
    pub import_path_pattern: String,
    /// Regex matched against one lexical token of the selected kind. Unlike a
    /// source regex this never crosses token boundaries and therefore cannot
    /// mistake comments or surrounding syntax for the requested AST leaf.
    pub lexical_pattern: String,
    pub lexical_kind: Option<LexicalKind>,
    /// Optional regex that rejects an individual source match. This models
    /// negative constraints scoped to the matched node rather than the line.
    pub matched_text_not_pattern: String,
    /// Do not evaluate `code_pattern` on preprocessor directive lines. This
    /// mirrors Clang checkers that suppress diagnostics originating in macros.
    pub exclude_preprocessor: bool,
    /// Minimum number of `#`/`##` preprocessing tokens in a macro body. A
    /// `##` pair counts as one token, matching Clang's token stream.
    pub macro_hash_min: Option<usize>,
    /// Report a macro whose final preprocessing token is a semicolon.
    pub macro_trailing_semicolon: bool,
    /// Report an unwrapped macro body that contains a semicolon followed by
    /// another token, preserving the legacy multi-statement heuristic.
    pub macro_unwrapped_multiple_statements: bool,
    /// Restrict a macro matcher to function-like macros with at least one
    /// parameter (the legacy Clang checker ignores empty parameter lists).
    pub macro_requires_parameters: bool,
    /// Regex matched against the normalized callee name.
    pub callee: String,
    /// Optional regex matched against the statically known receiver type.
    pub receiver_type_pattern: String,
    /// Optional regex matched against the resolved receiver symbol/field path.
    pub receiver_path_pattern: String,
    /// Require an instance receiver rather than a static/free function call.
    pub requires_receiver: bool,
    /// Require a free/static call with no receiver expression.
    pub forbids_receiver: bool,
    /// Require a qualifier written in source, excluding an implicit `this` receiver.
    pub requires_explicit_qualifier: bool,
    /// Regexes for nested receiver calls, ordered from the immediate receiver
    /// outwards. This preserves AST call-chain structure without source text.
    pub receiver_callee_chain: Vec<String>,
    /// Field chain from immediate receiver outwards, before receiver call-chain checks.
    pub receiver_field_chain: Vec<String>,
    pub receiver_chain_root_path_pattern: String,
    /// Regex matched against the normalized allocated type for `new`/object
    /// construction expressions.
    pub constructor_type: String,
    /// Restrict the number of arguments.
    pub min_args: Option<usize>,
    pub max_args: Option<usize>,
    /// Argument indexes that must be literal values.
    pub literal_args: Vec<usize>,
    /// Argument indexes that must be floating-point literals.
    pub float_args: Vec<usize>,
    /// Argument indexes that must not be literal values.
    pub non_literal_args: Vec<usize>,
    /// Argument indexes that may be any expression except a string literal.
    /// Unlike `non_literal_args`, numeric/boolean/null literals remain eligible.
    pub non_string_literal_args: Vec<usize>,
    /// Reject calls containing a string literal at any argument position.
    pub forbids_string_literal_args: bool,
    /// Argument indexes that must be the null literal.
    pub null_args: Vec<usize>,
    /// Constructor/call arguments accepting either null or an empty string.
    pub null_or_empty_string_args: Vec<usize>,
    /// Call arguments accepting either boolean false or integer zero, used by
    /// legacy APIs that represent the same unsafe mode with both encodings.
    pub false_or_zero_args: Vec<usize>,
    /// Regex constraints for positional string-literal arguments.
    pub string_arg_patterns: BTreeMap<usize, String>,
    /// Regex constraints accepting either a direct string literal or a symbol
    /// most recently assigned a string literal in the same function.
    pub string_constant_arg_patterns: BTreeMap<usize, String>,
    /// Regex constraint for the final string-literal argument. This preserves
    /// variadic source patterns such as `postMessage(..., "*")` without
    /// guessing how many arguments precede the sentinel.
    pub last_string_arg_pattern: String,
    /// Regex constraints satisfied by any nested string literal in an argument expression.
    pub descendant_string_arg_patterns: BTreeMap<usize, String>,
    /// Positional arguments that must be string literals not matching the
    /// supplied regex (typically an allowlist encoded as one expression).
    pub string_arg_not_patterns: BTreeMap<usize, String>,
    /// Exact constraints for positional integer arguments.
    pub int_arg_values: BTreeMap<usize, i64>,
    /// Inclusive lower/upper bounds for positional integer arguments.
    pub int_arg_min_values: BTreeMap<usize, i64>,
    pub int_arg_max_values: BTreeMap<usize, i64>,
    /// Exact constraints for positional boolean arguments.
    pub bool_arg_values: BTreeMap<usize, bool>,
    /// Exact constraint for the final boolean argument of a variadic call.
    pub last_bool_arg_value: Option<bool>,
    /// Named boolean argument constraints, for example `shell: true`.
    pub named_bool_args: BTreeMap<String, bool>,
    /// Regex constraints for named string-literal arguments.
    pub named_string_arg_patterns: BTreeMap<String, String>,
    /// Regex constraints for the statically known types of positional
    /// arguments, including symbols, resolved fields and explicit casts.
    pub arg_type_patterns: BTreeMap<usize, String>,
    /// Select a referenced declaration inside an argument (including compound
    /// expressions), rather than guessing the type of the whole argument.
    pub argument_references: BTreeMap<usize, ArgumentReferenceConstraint>,
    pub any_argument_reference: Option<ArgumentReferenceConstraint>,
    /// Positional call arguments that must directly reference a formal
    /// parameter of the enclosing function.
    pub parameter_args: Vec<usize>,
    /// Call must occur within a catch body; nested functions start a new context.
    pub inside_catch: bool,
    /// Report only when this receiver has not previously received the named call.
    pub missing_prior_receiver_call: String,
    /// Regex constraints for qualified identifier/field paths in positional arguments.
    pub arg_path_patterns: BTreeMap<usize, String>,
    /// Regex over a positional argument's comment-free token spelling.
    pub argument_token_patterns: BTreeMap<usize, String>,
    /// Positional argument pairs that must be the same resolved HIR expression.
    pub equal_arg_pairs: Vec<[usize; 2]>,
    /// Require at least one parameter of the enclosing function to match this type.
    pub enclosing_param_type_pattern: String,
    /// Report only when the return value is discarded.
    pub ignored_return: bool,
    /// Regex over the declared type of the variable receiving this call's
    /// result. Discarded, returned, and compound-expression uses do not match.
    pub assigned_target_type_pattern: String,
    /// Report calls only when they are not nested in a loop statement.
    pub outside_loop: bool,
    /// Report calls only when nested in a loop statement.
    pub inside_loop: bool,
    /// Report a return statement nested in a finally block. Lambda bodies are
    /// separate control-flow regions and do not inherit the enclosing finally.
    pub return_in_finally: bool,
    /// Report a throw statement nested in a finally block.
    pub throw_in_finally: bool,
    /// Report a null return when the enclosing method name and/or return type
    /// match the configured regexes.
    pub null_return_method_name_pattern: String,
    pub null_return_type_pattern: String,
    /// Combine the configured null-return context patterns with OR instead of
    /// the default AND.
    pub null_return_match_any: bool,
    /// A return of the exact symbol assigned null by the preceding statement
    /// in the same block. Comments do not count as intervening statements.
    pub return_preceded_by_null_assignment: bool,
    /// Report a declaration/assignment immediately overwritten in the same block
    /// when the replacement RHS does not depend on the previous value.
    pub redundant_reassignment: bool,
    /// Report query-builder calls that consume a String parameter or a String
    /// symbol most recently assigned an SQL wildcard fragment (`'%` or `%'`).
    pub sql_wildcard_query_argument: bool,
    /// Regex selecting resource variable types for function-scoped close analysis.
    pub unreleased_resource_type_pattern: String,
    /// Report receiver use after close/release/recycle for variables of this type.
    pub resource_use_after_release_type_pattern: String,
    /// Require a call to occur within an `if` condition (not merely any loop condition).
    pub inside_if_condition: bool,
    /// Report a call only when execution has a later lexical statement in its method.
    pub call_not_last_statement: bool,
    /// Report plain `s = ... + s + ...` assignments to String variables declared outside the current loop.
    pub string_self_concatenation_in_loop: bool,
    /// Type constraint applied after consuming receiver_callee_chain.
    pub receiver_chain_root_type_pattern: String,
    /// Regex selecting a field/property read in HIR.
    pub field_name_pattern: String,
    /// Optional static type constraint for the field/property receiver.
    pub field_receiver_type_pattern: String,
    /// Optional resolved path constraint for the field/property receiver.
    pub field_receiver_path_pattern: String,
    /// Regex selecting the resolved variable/field path on the left side of an
    /// assignment or initialized declaration.
    pub assignment_target_path_pattern: String,
    /// Restrict assignment targets to properties/fields rather than variables.
    pub assignment_requires_field: bool,
    /// Require the assigned value to be a specific boolean literal.
    pub assignment_bool_value: Option<bool>,
    /// Reject assignments whose value is a string literal while retaining all
    /// other literal and non-literal expression kinds.
    pub assignment_value_non_string_literal: bool,
    /// Reject an assignment only when its string-literal value matches this
    /// regex; non-string expressions remain eligible.
    pub assignment_value_not_string_pattern: String,
    /// Regex for the declared catch-clause exception type.
    pub catch_type_pattern: String,
    /// Report matching catches that do not rethrow the caught symbol.
    pub catch_must_rethrow: bool,
    /// Report matching catches whose body has no executable statements.
    pub catch_must_handle: bool,
    /// Report catch clauses whose body has no executable HIR statements.
    pub empty_catch: bool,
    /// Report equals/compareTo/Comparator.compare implementations that never
    /// test their contract parameter(s) against null.
    pub missing_contract_null_check: bool,
    /// Report only for direct self-assignment, such as `p = realloc(p, n)`.
    pub self_assignment: bool,
    /// Argument indexes that must be references to automatic variables
    /// declared in the current function (including parameters).
    pub automatic_var_args: Vec<usize>,
    /// Report a logical `&&`/`||` whose direct left or right operand is an
    /// assignment expression. This is an AST/HIR matcher, not a source regex.
    pub assignment_operand_in_logical: bool,
    /// Report equality/inequality comparisons where either direct operand's
    /// qualified field path matches this regex.
    pub equality_operand_path_pattern: String,
    /// Regex matched against the statically known type of either direct
    /// equality operand.
    pub equality_operand_type_pattern: String,
    /// Suppress an equality matcher when either operand is the null literal.
    pub equality_exclude_null: bool,
    /// Restrict an equality matcher to comparisons with a null literal.
    pub equality_require_null: bool,
    /// Required compile-time result for an equality/inequality expression.
    pub equality_constant_result: Option<bool>,
    /// Restrict equality operands to direct resolved identifiers (no fields/calls/literals).
    pub equality_require_identifier_operands: bool,
    /// An equality/inequality whose direct operand is another equality.
    pub nested_equality: bool,
    /// Report integer division or remainder whose denominator is constant zero.
    pub division_by_literal_zero: bool,
    /// Report array/index access with a constant negative index.
    pub negative_literal_array_index: bool,
    /// Report Optional.get unless the receiver is guarded by isPresent in the current branch.
    pub optional_get_without_is_present: bool,
    pub lock_acquired_twice_type_pattern: String,
    pub lock_released_twice_type_pattern: String,
    pub unreleased_lock_type_pattern: String,
    /// Report Thread.sleep calls while an explicit Lock is held in the same function.
    pub sleep_while_lock_held: bool,
    /// Report File.createTempFile results that are not deleted in the function.
    pub temporary_file_not_deleted: bool,
    /// Report the racy createTempFile/delete/mkdir directory construction sequence.
    pub temp_file_directory_conversion: bool,
    /// Report member/index access through a symbol proven null on the current path.
    pub definite_null_dereference: bool,
    /// Report unchecked dereference of a known nullable API result.
    pub nullable_return_dereference: bool,
    /// Report a null comparison made redundant by a prior allocation or dereference.
    pub redundant_null_check: bool,
    /// Report explicit primitive numeric casts to a narrower representation.
    pub numeric_narrowing_cast: bool,
    /// Report int/long to float and long to double precision-losing casts.
    pub integer_to_float_precision_loss: bool,
    /// Report ObjectOutputStream.writeObject for a known project class that is not Serializable.
    pub serialize_non_serializable_argument: bool,
    /// Report when this zero-based argument is a known project class that does not implement Serializable.
    pub non_serializable_arg: Option<usize>,
    /// Report equals calls on a known project class that does not override equals.
    pub receiver_class_missing_equals: bool,
    /// Report assignment to the enhanced-for iteration symbol.
    pub foreach_item_reassigned: bool,
    /// Report Process.waitFor when stdout/stderr cannot be proven redirected or drained.
    pub external_process_wait_without_io_drain: bool,
    /// Report a write followed by another access to the same symbol in one expression.
    pub conflicting_side_effects_in_expression: bool,
    /// Report unsafe console/stack-trace logging of security exceptions.
    pub unsafe_security_exception_logging: bool,
    /// Type of a declared variable directly compared in a loop condition.
    pub loop_condition_type_pattern: String,
    pub loop_condition_exclude_parameters: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArgumentReferenceConstraint {
    pub type_pattern: String,
    /// When nonempty, a local/field declaration must have a member-access
    /// initializer rooted here; formal parameters remain eligible. This models
    /// legacy declaration provenance, not transitive taint propagation.
    pub parameter_or_initializer_roots: Vec<String>,
    pub allow_index_initializer: bool,
    /// Exclude symbols referenced by an enclosing or earlier sibling if check.
    /// Legacy structural validation heuristic, not proof of sanitization.
    pub exclude_if_checked: bool,
    /// Exclude symbols whose named field is assigned true in an enclosing block.
    pub exclude_when_field_true: String,
    pub direct_identifier: bool,
    pub parameter_or_catch_only: bool,
}

impl BaselineMatcher {
    pub(crate) fn is_structured(&self) -> bool {
        self.native_dataflow
            || self.java_style.is_some()
            || self.java_config.is_some()
            || self.java_project.is_some()
            || self.c_style.is_some()
            || self.c_macro.is_some()
            || self.c_declaration.is_some()
            || self.c_expression.is_some()
            || self.sql_style.is_some()
            || self.csharp_http_post_without_antiforgery
            || !self.code_pattern.is_empty()
            || !self.semgrep_compat_yaml.is_empty()
            || !self.import_path_pattern.is_empty()
            || self.lexical_kind.is_some()
            || !self.matched_text_not_pattern.is_empty()
            || self.macro_hash_min.is_some()
            || self.macro_trailing_semicolon
            || self.macro_unwrapped_multiple_statements
            || self.requires_hir()
    }

    pub(crate) fn requires_hir(&self) -> bool {
        !self.call_alternatives.is_empty()
            || self.nested_equality
            || self.division_by_literal_zero
            || self.negative_literal_array_index
            || self.optional_get_without_is_present
            || !self.lock_acquired_twice_type_pattern.is_empty()
            || !self.lock_released_twice_type_pattern.is_empty()
            || !self.unreleased_lock_type_pattern.is_empty()
            || self.sleep_while_lock_held
            || self.temporary_file_not_deleted
            || self.temp_file_directory_conversion
            || self.definite_null_dereference
            || self.nullable_return_dereference
            || self.redundant_null_check
            || self.numeric_narrowing_cast
            || self.integer_to_float_precision_loss
            || self.serialize_non_serializable_argument
            || self.non_serializable_arg.is_some()
            || self.receiver_class_missing_equals
            || self.foreach_item_reassigned
            || self.external_process_wait_without_io_drain
            || self.conflicting_side_effects_in_expression
            || self.unsafe_security_exception_logging
            || self.equality_constant_result.is_some()
            || self.equality_require_identifier_operands
            || !self.loop_condition_type_pattern.is_empty()
            || !self.callee.is_empty()
            || !self.missing_prior_receiver_call.is_empty()
            || !self.constructor_type.is_empty()
            || !self.receiver_type_pattern.is_empty()
            || !self.receiver_path_pattern.is_empty()
            || self.requires_receiver
            || self.forbids_receiver
            || self.requires_explicit_qualifier
            || !self.receiver_callee_chain.is_empty()
            || !self.receiver_field_chain.is_empty()
            || !self.receiver_chain_root_path_pattern.is_empty()
            || self.min_args.is_some()
            || self.max_args.is_some()
            || !self.literal_args.is_empty()
            || !self.float_args.is_empty()
            || !self.non_literal_args.is_empty()
            || !self.non_string_literal_args.is_empty()
            || self.forbids_string_literal_args
            || !self.null_args.is_empty()
            || !self.null_or_empty_string_args.is_empty()
            || !self.false_or_zero_args.is_empty()
            || !self.string_arg_patterns.is_empty()
            || !self.string_constant_arg_patterns.is_empty()
            || !self.last_string_arg_pattern.is_empty()
            || !self.descendant_string_arg_patterns.is_empty()
            || !self.string_arg_not_patterns.is_empty()
            || !self.int_arg_values.is_empty()
            || !self.int_arg_min_values.is_empty()
            || !self.int_arg_max_values.is_empty()
            || !self.bool_arg_values.is_empty()
            || self.last_bool_arg_value.is_some()
            || !self.named_bool_args.is_empty()
            || !self.named_string_arg_patterns.is_empty()
            || !self.arg_type_patterns.is_empty()
            || !self.argument_references.is_empty()
            || self.any_argument_reference.is_some()
            || !self.parameter_args.is_empty()
            || self.inside_catch
            || !self.arg_path_patterns.is_empty()
            || !self.argument_token_patterns.is_empty()
            || !self.equal_arg_pairs.is_empty()
            || !self.enclosing_param_type_pattern.is_empty()
            || self.ignored_return
            || !self.assigned_target_type_pattern.is_empty()
            || self.outside_loop
            || self.inside_loop
            || self.return_in_finally
            || self.throw_in_finally
            || !self.null_return_method_name_pattern.is_empty()
            || !self.null_return_type_pattern.is_empty()
            || self.return_preceded_by_null_assignment
            || self.redundant_reassignment
            || self.sql_wildcard_query_argument
            || !self.unreleased_resource_type_pattern.is_empty()
            || !self.resource_use_after_release_type_pattern.is_empty()
            || self.inside_if_condition
            || self.call_not_last_statement
            || self.string_self_concatenation_in_loop
            || !self.receiver_chain_root_type_pattern.is_empty()
            || !self.field_name_pattern.is_empty()
            || !self.assignment_target_path_pattern.is_empty()
            || !self.field_receiver_type_pattern.is_empty()
            || !self.field_receiver_path_pattern.is_empty()
            || !self.catch_type_pattern.is_empty()
            || self.empty_catch
            || self.missing_contract_null_check
            || self.self_assignment
            || !self.automatic_var_args.is_empty()
            || self.assignment_operand_in_logical
            || !self.equality_operand_path_pattern.is_empty()
            || !self.equality_operand_type_pattern.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LexicalKind {
    Identifier,
    StringLiteral,
    NullLiteral,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Note,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub snippet: String,
    pub message: String,
    pub cwe: Vec<String>,
    pub standards: Vec<String>,
    #[serde(default, skip_serializing_if = "RuleTranslations::is_empty")]
    pub translations: RuleTranslations,
}

#[derive(Clone, Debug, Default)]
pub struct BaselineScanOptions {
    pub oracle_forms_metadata: Option<OracleFormsMetadata>,
}

impl BaselinePack {
    pub fn from_yaml_str(text: &str) -> Result<Self> {
        let pack: Self = serde_yaml::from_str(text)?;
        pack.validate()?;
        Ok(pack)
    }

    pub fn merge(
        id: impl Into<String>,
        title: impl Into<String>,
        packs: impl IntoIterator<Item = BaselinePack>,
    ) -> Result<Self> {
        let mut merged = Self {
            id: id.into(),
            title: title.into(),
            rules: Vec::new(),
        };
        for pack in packs {
            merged.rules.extend(pack.rules);
        }
        merged.validate()?;
        Ok(merged)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.id.trim().is_empty(), "baseline pack id is empty");
        anyhow::ensure!(
            !self.title.trim().is_empty(),
            "baseline pack title is empty"
        );
        let mut ids = HashSet::new();
        for rule in &self.rules {
            anyhow::ensure!(!rule.id.trim().is_empty(), "baseline rule id is empty");
            if rule.matcher.c_style.is_some()
                || rule.matcher.c_macro.is_some()
                || rule.matcher.c_declaration.is_some()
                || rule.matcher.c_expression.is_some()
            {
                let mode = if rule.matcher.c_style.is_some() {
                    "c_style"
                } else if rule.matcher.c_macro.is_some() {
                    "c_macro"
                } else if rule.matcher.c_declaration.is_some() {
                    "c_declaration"
                } else {
                    "c_expression"
                };
                let value = serde_json::to_value(&rule.matcher)?;
                let default = serde_json::to_value(BaselineMatcher::default())?;
                anyhow::ensure!(
                    !rule.languages.is_empty()
                        && rule
                            .languages
                            .iter()
                            .all(|language| matches!(language, Language::C | Language::Cpp))
                        && rule.pattern.is_empty()
                        && value
                            .as_object()
                            .unwrap()
                            .iter()
                            .all(|(key, value)| key == mode
                                || key == "path_pattern"
                                || Some(value) == default.get(key)),
                    "baseline rule {} mixes C-family statement checks with another matcher",
                    rule.id
                );
            }
            if !rule.matcher.call_alternatives.is_empty() {
                let value = serde_json::to_value(&rule.matcher)?;
                let default = serde_json::to_value(BaselineMatcher::default())?;
                anyhow::ensure!(
                    rule.pattern.is_empty()
                        && value
                            .as_object()
                            .unwrap()
                            .iter()
                            .all(|(key, value)| key == "call_alternatives"
                                || Some(value) == default.get(key)),
                    "baseline rule {} cannot mix call alternatives and outer predicates",
                    rule.id
                );
                for matcher in &rule.matcher.call_alternatives {
                    anyhow::ensure!(
                        matcher.call_alternatives.is_empty()
                            && !matcher.callee.is_empty()
                            && matcher.constructor_type.is_empty()
                            && matcher.java_style.is_none()
                            && !matcher.csharp_http_post_without_antiforgery
                            && matcher.code_pattern.is_empty(),
                        "baseline rule {} has a non-call or nested alternative",
                        rule.id
                    );
                    let mut alternative = rule.clone();
                    alternative.matcher = matcher.clone();
                    Self {
                        id: self.id.clone(),
                        title: self.title.clone(),
                        rules: vec![alternative],
                    }
                    .validate()?;
                }
            }
            if rule.matcher.csharp_http_post_without_antiforgery {
                anyhow::ensure!(
                    rule.languages == [Language::CSharp]
                        && !rule.matcher.requires_hir()
                        && rule.matcher.java_style.is_none()
                        && rule.matcher.code_pattern.is_empty()
                        && rule.pattern.is_empty(),
                    "baseline rule {} mixes C# method attributes with another matcher",
                    rule.id
                );
            }
            if rule.matcher.java_style.is_some() {
                anyhow::ensure!(
                    !rule.matcher.requires_hir()
                        && rule.matcher.lexical_kind.is_none()
                        && rule.matcher.code_pattern.is_empty()
                        && rule.matcher.import_path_pattern.is_empty()
                        && rule.pattern.is_empty(),
                    "baseline rule {} cannot mix a Java style check with another matcher mode",
                    rule.id
                );
                anyhow::ensure!(
                    rule.languages
                        .iter()
                        .all(|language| *language == Language::Java),
                    "baseline rule {} uses a Java style check for another language",
                    rule.id
                );
            }
            if rule.matcher.sql_style.is_some() {
                let value = serde_json::to_value(&rule.matcher)?;
                let default = serde_json::to_value(BaselineMatcher::default())?;
                anyhow::ensure!(
                    rule.languages == [Language::Sql]
                        && rule.pattern.is_empty()
                        && value
                            .as_object()
                            .unwrap()
                            .iter()
                            .all(|(key, value)| key == "sql_style"
                                || key == "path_pattern"
                                || key == "sql_xpath_query"
                                || key == "sql_xpath_message"
                                || Some(value) == default.get(key)),
                    "baseline rule {} mixes a SQL style check with another matcher mode",
                    rule.id
                );
            }
            if !rule.matcher.sql_xpath_query.is_empty() {
                anyhow::ensure!(
                    rule.matcher.sql_style == Some(SqlStyleCheck::XPath),
                    "baseline rule {} has sql_xpath_query without sql_style: xpath",
                    rule.id
                );
                sql_style::validate_xpath(&rule.matcher.sql_xpath_query).map_err(|error| {
                    anyhow::anyhow!(
                        "invalid SQL XPath query for baseline rule {}: {error}",
                        rule.id
                    )
                })?;
            }
            anyhow::ensure!(
                rule.matcher.sql_xpath_message.is_empty()
                    || rule.matcher.sql_style == Some(SqlStyleCheck::XPath),
                "baseline rule {} has sql_xpath_message without sql_style: xpath",
                rule.id
            );
            anyhow::ensure!(
                ids.insert(rule.id.as_str()),
                "duplicate baseline rule id {}",
                rule.id
            );
            anyhow::ensure!(
                !rule.title.trim().is_empty(),
                "baseline rule {} has an empty title",
                rule.id
            );
            anyhow::ensure!(
                !rule.pattern.is_empty() || rule.matcher.is_structured(),
                "baseline rule {} has neither a source pattern nor a structured matcher",
                rule.id
            );
            if !rule.pattern.is_empty() {
                Regex::new(&rule.pattern).with_context(|| {
                    format!("invalid source regex for baseline rule {}", rule.id)
                })?;
            }
            if !rule.matcher.code_pattern.is_empty() {
                Regex::new(&rule.matcher.code_pattern)
                    .with_context(|| format!("invalid code regex for baseline rule {}", rule.id))?;
            }
            if !rule.matcher.semgrep_compat_yaml.is_empty() {
                anyhow::ensure!(
                    rule.pattern.is_empty() && rule.matcher.code_pattern.is_empty(),
                    "baseline rule {} mixes Semgrep compatibility matching with a source regex",
                    rule.id
                );
                semgrep_compat::validate(&rule.matcher.semgrep_compat_yaml)
                    .with_context(|| format!("invalid Semgrep compatibility rule {}", rule.id))?;
            }
            if !rule.matcher.callee.is_empty() {
                Regex::new(&rule.matcher.callee).with_context(|| {
                    format!("invalid callee regex for baseline rule {}", rule.id)
                })?;
            }
            if !rule.matcher.constructor_type.is_empty() {
                Regex::new(&rule.matcher.constructor_type).with_context(|| {
                    format!("invalid constructor regex for baseline rule {}", rule.id)
                })?;
            }
            if !rule.matcher.receiver_type_pattern.is_empty() {
                Regex::new(&rule.matcher.receiver_type_pattern).with_context(|| {
                    format!("invalid receiver type regex for baseline rule {}", rule.id)
                })?;
            }
            anyhow::ensure!(
                rule.matcher.callee.is_empty() || rule.matcher.constructor_type.is_empty(),
                "baseline rule {} cannot match both calls and constructors",
                rule.id
            );
            anyhow::ensure!(
                !(rule.matcher.requires_receiver && rule.matcher.forbids_receiver),
                "baseline rule {} both requires and forbids a receiver",
                rule.id
            );
            anyhow::ensure!(
                !(rule.matcher.inside_loop && rule.matcher.outside_loop),
                "baseline rule {} both requires and forbids a loop context",
                rule.id
            );
            anyhow::ensure!(
                !rule.matcher.assignment_target_path_pattern.is_empty()
                    || (!rule.matcher.assignment_requires_field
                        && rule.matcher.assignment_bool_value.is_none()
                        && !rule.matcher.assignment_value_non_string_literal
                        && rule.matcher.assignment_value_not_string_pattern.is_empty()),
                "baseline rule {} has assignment predicates without an assignment target",
                rule.id
            );
            if !rule.matcher.path_pattern.is_empty() {
                Regex::new(&rule.matcher.path_pattern)
                    .with_context(|| format!("invalid path regex for baseline rule {}", rule.id))?;
            }
            if !rule.matcher.required_file_pattern.is_empty() {
                Regex::new(&rule.matcher.required_file_pattern).with_context(|| {
                    format!("invalid required-file regex for baseline rule {}", rule.id)
                })?;
            }
            if !rule.matcher.forbidden_project_pattern.is_empty() {
                Regex::new(&rule.matcher.forbidden_project_pattern).with_context(|| {
                    format!("invalid forbidden-project regex for baseline rule {}", rule.id)
                })?;
            }
            if !rule.matcher.equality_operand_path_pattern.is_empty() {
                Regex::new(&rule.matcher.equality_operand_path_pattern).with_context(|| {
                    format!(
                        "invalid equality operand regex for baseline rule {}",
                        rule.id
                    )
                })?;
            }
            if !rule.matcher.equality_operand_type_pattern.is_empty() {
                Regex::new(&rule.matcher.equality_operand_type_pattern).with_context(|| {
                    format!(
                        "invalid equality operand type regex for baseline rule {}",
                        rule.id
                    )
                })?;
            }
            for pattern in &rule.matcher.receiver_callee_chain {
                Regex::new(pattern).with_context(|| {
                    format!(
                        "invalid receiver call-chain regex for baseline rule {}",
                        rule.id
                    )
                })?;
            }
            anyhow::ensure!(
                !(rule.matcher.equality_require_null && rule.matcher.equality_exclude_null),
                "baseline rule {} both requires and excludes null operands",
                rule.id
            );
            for pattern in [
                &rule.matcher.null_return_method_name_pattern,
                &rule.matcher.null_return_type_pattern,
                &rule.matcher.catch_type_pattern,
                &rule.matcher.loop_condition_type_pattern,
                &rule.matcher.enclosing_param_type_pattern,
                &rule.matcher.unreleased_resource_type_pattern,
                &rule.matcher.resource_use_after_release_type_pattern,
                &rule.matcher.lock_acquired_twice_type_pattern,
                &rule.matcher.lock_released_twice_type_pattern,
                &rule.matcher.unreleased_lock_type_pattern,
                &rule.matcher.receiver_chain_root_type_pattern,
                &rule.matcher.receiver_path_pattern,
                &rule.matcher.field_name_pattern,
                &rule.matcher.field_receiver_type_pattern,
                &rule.matcher.field_receiver_path_pattern,
                &rule.matcher.assignment_target_path_pattern,
                &rule.matcher.assignment_value_not_string_pattern,
                &rule.matcher.receiver_chain_root_path_pattern,
            ] {
                if !pattern.is_empty() {
                    Regex::new(pattern).with_context(|| {
                        format!("invalid null-return regex for baseline rule {}", rule.id)
                    })?;
                }
            }
            for pattern in rule
                .matcher
                .string_arg_patterns
                .values()
                .chain(rule.matcher.string_constant_arg_patterns.values())
                .chain(
                    (!rule.matcher.last_string_arg_pattern.is_empty())
                        .then_some(&rule.matcher.last_string_arg_pattern),
                )
                .chain(rule.matcher.descendant_string_arg_patterns.values())
                .chain(rule.matcher.string_arg_not_patterns.values())
                .chain(rule.matcher.named_string_arg_patterns.values())
                .chain(rule.matcher.arg_type_patterns.values())
                .chain(rule.matcher.arg_path_patterns.values())
                .chain(rule.matcher.argument_token_patterns.values())
            {
                Regex::new(pattern).with_context(|| {
                    format!(
                        "invalid string argument regex for baseline rule {}",
                        rule.id
                    )
                })?;
            }
            for constraint in rule
                .matcher
                .argument_references
                .values()
                .chain(rule.matcher.any_argument_reference.iter())
            {
                anyhow::ensure!(
                    !constraint.type_pattern.is_empty(),
                    "baseline rule {} has an argument reference without a type constraint",
                    rule.id
                );
                Regex::new(&constraint.type_pattern)
                    .with_context(|| format!("invalid argument reference type for {}", rule.id))?;
            }
            if !rule.matcher.import_path_pattern.is_empty() {
                Regex::new(&rule.matcher.import_path_pattern).with_context(|| {
                    format!("invalid import-path regex for baseline rule {}", rule.id)
                })?;
            }
            match rule.matcher.lexical_kind {
                Some(_) => {
                    anyhow::ensure!(
                        !rule.matcher.lexical_pattern.is_empty(),
                        "baseline rule {} has lexical_kind without lexical_pattern",
                        rule.id
                    );
                    Regex::new(&rule.matcher.lexical_pattern).with_context(|| {
                        format!("invalid lexical regex for baseline rule {}", rule.id)
                    })?;
                }
                None => anyhow::ensure!(
                    rule.matcher.lexical_pattern.is_empty(),
                    "baseline rule {} has lexical_pattern without lexical_kind",
                    rule.id
                ),
            }
            if !rule.matcher.matched_text_not_pattern.is_empty() {
                Regex::new(&rule.matcher.matched_text_not_pattern).with_context(|| {
                    format!(
                        "invalid matched-text exclusion for baseline rule {}",
                        rule.id
                    )
                })?;
            }
            if let (Some(min), Some(max)) = (rule.matcher.min_args, rule.matcher.max_args) {
                anyhow::ensure!(
                    min <= max,
                    "baseline rule {} has min_args > max_args",
                    rule.id
                );
            }
            for index in rule
                .matcher
                .int_arg_min_values
                .keys()
                .filter(|index| rule.matcher.int_arg_max_values.contains_key(index))
            {
                anyhow::ensure!(
                    rule.matcher.int_arg_min_values[index]
                        <= rule.matcher.int_arg_max_values[index],
                    "baseline rule {} has an invalid integer argument range at index {}",
                    rule.id,
                    index
                );
            }
        }
        Ok(())
    }

    /// Regex-only scan. This is useful when parsing is unavailable. Comments
    /// are masked while strings and byte offsets are preserved.
    pub fn scan_text(
        &self,
        language: &Language,
        path: &Path,
        source: &str,
    ) -> Vec<BaselineFinding> {
        self.scan_text_with_options(language, path, source, &BaselineScanOptions::default())
    }

    pub fn scan_text_with_options(
        &self,
        language: &Language,
        path: &Path,
        source: &str,
        options: &BaselineScanOptions,
    ) -> Vec<BaselineFinding> {
        self.scan_source_rules(language, path, source, false, options)
    }

    pub(crate) fn scan_source_rules(
        &self,
        language: &Language,
        path: &Path,
        source: &str,
        unstructured_only: bool,
        options: &BaselineScanOptions,
    ) -> Vec<BaselineFinding> {
        let sanitized = strip_comments_preserve_layout(language, source);
        let code_only = strip_literals_preserve_layout(&sanitized);
        let java_imports = collect_java_imports(&code_only);
        let java_syntax = (*language == Language::Java
            && path.extension().and_then(|value| value.to_str()) == Some("java")
            && self
                .rules
                .iter()
                .any(|rule| rule.matcher.java_style.is_some()))
        .then(|| uniflow_parser_core::java_syntax::JavaSyntax::parse(source));
        let sql_syntax = (*language == Language::Sql
            && self
                .rules
                .iter()
                .any(|rule| rule.matcher.sql_style.is_some()))
        .then(|| uniflow_parser_core::sql_syntax::SqlSyntax::parse(source));
        let original_lines = source.lines().collect::<Vec<_>>();
        let c_macros = (matches!(language, Language::C | Language::Cpp)
            && self.rules.iter().any(|rule| rule.matcher.c_macro.is_some()))
        .then(|| c_preprocessor::CPreprocessor::parse(source));
        let c_declarations = (matches!(language, Language::C | Language::Cpp)
            && self.rules.iter().any(|rule| {
                rule.matcher.c_declaration.is_some() || rule.matcher.c_expression.is_some()
            }))
        .then(|| {
            let masked = c_style::mask_directives(source, &code_only);
            uniflow_parser_core::c_declarations::CDeclarationIndex::parse(&masked)
        });
        let c_expressions = (matches!(language, Language::C | Language::Cpp)
            && self
                .rules
                .iter()
                .any(|rule| rule.matcher.c_expression.is_some()))
        .then(|| {
            let masked = c_style::mask_directives(source, &code_only);
            uniflow_parser_core::c_expressions::CExpressionIndex::parse(&masked)
        });
        let c_syntax = (matches!(language, Language::C | Language::Cpp)
            && self
                .rules
                .iter()
                .any(|rule| rule.matcher.c_style.is_some() || rule.matcher.c_expression.is_some()))
        .then(|| {
            let masked = c_style::mask_directives(source, &code_only);
            uniflow_parser_core::java_syntax::JavaSyntax::parse_c_family_statements(&masked)
        });
        let csharp_declarations = (*language == Language::CSharp
            && self
                .rules
                .iter()
                .any(|rule| rule.matcher.csharp_http_post_without_antiforgery))
        .then(|| uniflow_parser_core::java_syntax::JavaSyntax::parse_csharp_declarations(source));
        let mut findings = Vec::new();
        for rule in &self.rules {
            if unstructured_only && rule.matcher.requires_hir() {
                continue;
            }
            if !rule.languages.is_empty() && !rule.languages.iter().any(|item| item == language) {
                continue;
            }
            if !rule_path_matches(rule, &path.display().to_string()) {
                continue;
            }
            if let Some(check) = rule.matcher.java_style {
                if let Some(syntax) = &java_syntax {
                    findings.extend(
                        check
                            .offsets(source, syntax)
                            .into_iter()
                            .map(|offset| finding_at_offset(rule, path, source, offset)),
                    );
                }
                continue;
            }
            if let Some(check) = rule.matcher.java_config {
                findings.extend(
                    check
                        .offsets(path, source)
                        .into_iter()
                        .map(|offset| finding_at_offset(rule, path, source, offset)),
                );
                continue;
            }
            if let Some(check) = rule.matcher.sql_style {
                if let Some(syntax) = &sql_syntax {
                    findings.extend(
                        check
                            .matches(
                                syntax,
                                options.oracle_forms_metadata.as_ref(),
                                &rule.matcher.sql_xpath_query,
                                &rule.matcher.sql_xpath_message,
                            )
                            .into_iter()
                            .map(|(offset, message)| {
                                let mut finding = finding_at_offset(rule, path, source, offset);
                                if let Some(message) = message {
                                    finding.message = message;
                                }
                                finding
                            }),
                    );
                }
                continue;
            }
            if let Some(check) = rule.matcher.c_style {
                if let Some(syntax) = &c_syntax {
                    findings.extend(
                        check
                            .offsets(source, syntax)
                            .into_iter()
                            .map(|offset| finding_at_offset(rule, path, source, offset)),
                    );
                }
                continue;
            }
            if let Some(check) = rule.matcher.c_macro {
                if let Some(macros) = &c_macros {
                    findings.extend(
                        macros
                            .offsets(check)
                            .into_iter()
                            .map(|offset| finding_at_offset(rule, path, source, offset)),
                    );
                }
                continue;
            }
            if let Some(check) = rule.matcher.c_declaration {
                if let Some(index) = &c_declarations {
                    findings.extend(
                        check
                            .offsets(source, index)
                            .into_iter()
                            .map(|offset| finding_at_offset(rule, path, source, offset)),
                    );
                }
                continue;
            }
            if let Some(check) = rule.matcher.c_expression {
                if let (Some(index), Some(declarations), Some(syntax)) =
                    (&c_expressions, &c_declarations, &c_syntax)
                {
                    findings.extend(
                        check
                            .offsets(source, index, declarations, syntax)
                            .into_iter()
                            .map(|offset| {
                                let mut finding = finding_at_offset(rule, path, source, offset);
                                let arguments = check.message_arguments(
                                    source,
                                    offset,
                                    index,
                                    declarations,
                                    syntax,
                                );
                                if !arguments.is_empty() {
                                    interpolate_finding_message(&mut finding, &arguments);
                                }
                                finding
                            }),
                    );
                }
                continue;
            }
            if rule.matcher.csharp_http_post_without_antiforgery {
                if let Some(syntax) = &csharp_declarations {
                    use uniflow_parser_core::java_syntax::JavaDeclarationKind;
                    for method in syntax.declarations.iter().filter(|declaration| {
                        declaration.kind == JavaDeclarationKind::Method
                            && declaration
                                .marker_annotations
                                .iter()
                                .any(|name| name == "HttpPost")
                            && !declaration
                                .marker_annotations
                                .iter()
                                .any(|name| name == "ValidateAntiForgeryToken")
                    }) {
                        findings.push(finding_at_offset(rule, path, source, method.range.start));
                    }
                }
                continue;
            }
            if let Some(minimum) = rule.matcher.macro_hash_min {
                findings.extend(scan_macro_hash_rule(
                    rule, path, source, &code_only, minimum,
                ));
                continue;
            }
            if !rule.matcher.import_path_pattern.is_empty() {
                findings.extend(scan_java_import_rule(rule, path, source, &java_imports));
                continue;
            }
            if rule.matcher.lexical_kind.is_some() {
                findings.extend(scan_lexical_rule(rule, path, source, &sanitized));
                continue;
            }
            if rule.matcher.macro_trailing_semicolon {
                findings.extend(scan_macro_trailing_semicolon_rule(
                    rule, path, source, &code_only,
                ));
                continue;
            }
            if rule.matcher.macro_unwrapped_multiple_statements {
                findings.extend(scan_unwrapped_multistatement_macro_rule(
                    rule, path, source, &code_only,
                ));
                continue;
            }
            if !rule.matcher.semgrep_compat_yaml.is_empty() {
                findings.extend(
                    semgrep_compat::matching_offsets(
                        &rule.matcher.semgrep_compat_yaml,
                        &path.display().to_string(),
                        &sanitized,
                    )
                    .into_iter()
                    .map(|offset| finding_at_offset(rule, path, source, offset)),
                );
                continue;
            }
            let (pattern, searchable) = if !rule.matcher.code_pattern.is_empty() {
                (rule.matcher.code_pattern.as_str(), code_only.as_str())
            } else {
                (rule.pattern.as_str(), sanitized.as_str())
            };
            if pattern.is_empty() {
                continue;
            }
            let Ok(regex) = Regex::new(pattern) else {
                continue;
            };
            let matched_text_exclusion = (!rule.matcher.matched_text_not_pattern.is_empty())
                .then(|| Regex::new(&rule.matcher.matched_text_not_pattern).ok())
                .flatten();
            for (line_index, line) in searchable.lines().enumerate() {
                if rule.matcher.exclude_preprocessor && line.trim_start().starts_with('#') {
                    continue;
                }
                for matched in regex.find_iter(line) {
                    if matched_text_exclusion
                        .as_ref()
                        .is_some_and(|exclude| exclude.is_match(matched.as_str()))
                    {
                        continue;
                    }
                    findings.push(BaselineFinding {
                        rule_id: rule.id.clone(),
                        title: rule.title.clone(),
                        severity: rule.severity.clone(),
                        confidence: rule.confidence.clone(),
                        path: path.display().to_string(),
                        line: line_index + 1,
                        column: matched.start() + 1,
                        snippet: original_lines
                            .get(line_index)
                            .copied()
                            .unwrap_or_default()
                            .trim()
                            .to_string(),
                        message: rule_message(rule),
                        cwe: rule.cwe.clone(),
                        standards: rule.standards.clone(),
                        translations: rule.translations.clone(),
                    });
                }
            }
        }
        deduplicate_findings(findings)
    }
}

#[derive(Clone, Copy)]
struct LexicalToken<'a> {
    kind: LexicalKind,
    text: &'a str,
    offset: usize,
}

fn scan_lexical_rule(
    rule: &BaselineRule,
    path: &Path,
    source: &str,
    comment_free_source: &str,
) -> Vec<BaselineFinding> {
    let Some(expected_kind) = rule.matcher.lexical_kind else {
        return Vec::new();
    };
    let Ok(regex) = Regex::new(&rule.matcher.lexical_pattern) else {
        return Vec::new();
    };
    lexical_tokens(comment_free_source)
        .into_iter()
        .filter(|token| token.kind == expected_kind && regex.is_match(token.text))
        .map(|token| finding_at_offset(rule, path, source, token.offset))
        .collect()
}

fn lexical_tokens(source: &str) -> Vec<LexicalToken<'_>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let start = index;
            let triple =
                index + 2 < bytes.len() && bytes[index + 1] == b'"' && bytes[index + 2] == b'"';
            index += if triple { 3 } else { 1 };
            let mut escaped = false;
            while index < bytes.len() {
                if triple {
                    if index + 2 < bytes.len()
                        && bytes[index] == b'"'
                        && bytes[index + 1] == b'"'
                        && bytes[index + 2] == b'"'
                    {
                        index += 3;
                        break;
                    }
                    index += 1;
                } else if escaped {
                    escaped = false;
                    index += 1;
                } else if bytes[index] == b'\\' {
                    escaped = true;
                    index += 1;
                } else {
                    let byte = bytes[index];
                    index += 1;
                    if byte == b'"' || matches!(byte, b'\n' | b'\r') {
                        break;
                    }
                }
            }
            tokens.push(LexicalToken {
                kind: LexicalKind::StringLiteral,
                text: &source[start..index],
                offset: start,
            });
            continue;
        }
        if is_java_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_java_identifier_continue(bytes[index]) {
                index += 1;
            }
            let text = &source[start..index];
            tokens.push(LexicalToken {
                kind: if text == "null" {
                    LexicalKind::NullLiteral
                } else {
                    LexicalKind::Identifier
                },
                text,
                offset: start,
            });
            continue;
        }
        index += 1;
    }
    tokens
}

fn is_java_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
}

fn is_java_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn finding_at_offset(
    rule: &BaselineRule,
    path: &Path,
    source: &str,
    offset: usize,
) -> BaselineFinding {
    let before = &source[..offset.min(source.len())];
    let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = before.rfind('\n').map_or(0, |index| index + 1);
    BaselineFinding {
        rule_id: rule.id.clone(),
        title: rule.title.clone(),
        severity: rule.severity.clone(),
        confidence: rule.confidence.clone(),
        path: path.display().to_string(),
        line,
        column: offset.saturating_sub(line_start) + 1,
        snippet: source
            .lines()
            .nth(line.saturating_sub(1))
            .unwrap_or_default()
            .trim()
            .to_string(),
        message: rule_message(rule),
        cwe: rule.cwe.clone(),
        standards: rule.standards.clone(),
        translations: rule.translations.clone(),
    }
}

fn interpolate_finding_message(finding: &mut BaselineFinding, arguments: &[String]) {
    fn interpolate(message: &mut String, arguments: &[String]) {
        for (index, argument) in arguments.iter().enumerate() {
            let positional = format!("{{{index}}}");
            if message.contains(&positional) {
                *message = message.replace(&positional, argument);
            } else {
                *message = message.replacen("{}", argument, 1);
            }
        }
    }

    interpolate(&mut finding.message, arguments);
    for localized in [
        finding.translations.zh_cn.as_mut(),
        finding.translations.en.as_mut(),
        finding.translations.zh_tw.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        interpolate(&mut localized.message, arguments);
    }
}

fn collect_java_imports(source: &str) -> Vec<(String, usize)> {
    let bytes = source.as_bytes();
    let mut imports = Vec::new();
    let mut index = 0;
    while index + "import".len() <= bytes.len() {
        let Some(relative) = source[index..].find("import") else {
            break;
        };
        index += relative;
        let end = index + "import".len();
        let boundary_before = index == 0 || !is_identifier_byte(bytes[index - 1]);
        let boundary_after = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if !boundary_before || !boundary_after {
            index = end;
            continue;
        }
        let Some(semicolon_relative) = source[end..].find(';') else {
            break;
        };
        let declaration = &source[end..end + semicolon_relative];
        let declaration = declaration.trim();
        let declaration = declaration
            .strip_prefix("static")
            .filter(|rest| rest.starts_with(char::is_whitespace))
            .map(str::trim_start)
            .unwrap_or(declaration);
        let normalized = declaration
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        if !normalized.is_empty() {
            imports.push((normalized, index));
        }
        index = end + semicolon_relative + 1;
    }
    imports
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn scan_java_import_rule(
    rule: &BaselineRule,
    path: &Path,
    source: &str,
    imports: &[(String, usize)],
) -> Vec<BaselineFinding> {
    let Ok(regex) = Regex::new(&rule.matcher.import_path_pattern) else {
        return Vec::new();
    };
    imports
        .iter()
        .filter(|(import, _)| regex.is_match(import))
        .map(|(_, offset)| {
            let before = &source[..(*offset).min(source.len())];
            let line = before.bytes().filter(|byte| *byte == b'\n').count() + 1;
            let line_start = before.rfind('\n').map_or(0, |index| index + 1);
            let snippet = source
                .lines()
                .nth(line.saturating_sub(1))
                .unwrap_or_default()
                .trim()
                .to_string();
            BaselineFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                confidence: rule.confidence.clone(),
                path: path.display().to_string(),
                line,
                column: offset.saturating_sub(line_start) + 1,
                snippet,
                message: rule_message(rule),
                cwe: rule.cwe.clone(),
                standards: rule.standards.clone(),
                translations: rule.translations.clone(),
            }
        })
        .collect()
}

pub fn bundled_java_package_pack() -> Result<BaselinePack> {
    let rules = bundled_java_package_rules()
        .iter()
        .map(|legacy| {
            let title = format!("Java component import: {}", legacy.id);
            let localized = LocalizedRuleText {
                title: title.clone(),
                message: legacy.purl.to_string(),
            };
            BaselineRule {
                id: format!("LEGACY-JAVA-PKG-{}", legacy.id),
                title,
                languages: vec![Language::Java],
                severity: Severity::Warning,
                confidence: Confidence::High,
                pattern: String::new(),
                matcher: BaselineMatcher {
                    import_path_pattern: legacy.import_regex.to_string(),
                    ..BaselineMatcher::default()
                },
                cwe: Vec::new(),
                standards: vec![legacy.message_id.to_string()],
                message: legacy.purl.to_string(),
                translations: RuleTranslations {
                    zh_cn: Some(localized.clone()),
                    en: Some(localized.clone()),
                    zh_tw: Some(localized),
                },
            }
        })
        .collect();
    let pack = BaselinePack {
        id: "legacy-java-packages".to_string(),
        title: "Legacy Java component import rules".to_string(),
        rules,
    };
    pack.validate()?;
    Ok(pack)
}

fn scan_macro_hash_rule(
    rule: &BaselineRule,
    path: &Path,
    source: &str,
    code_only: &str,
    minimum: usize,
) -> Vec<BaselineFinding> {
    let original_lines = source.lines().collect::<Vec<_>>();
    logical_preprocessor_lines(code_only)
        .into_iter()
        .filter_map(|(line_index, _, directive)| {
            let (has_parameters, body) = parse_macro_definition(&directive)?;
            if rule.matcher.macro_requires_parameters && !has_parameters {
                return None;
            }
            (count_hash_tokens(body) >= minimum).then(|| BaselineFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                confidence: rule.confidence.clone(),
                path: path.display().to_string(),
                line: line_index + 1,
                column: original_lines
                    .get(line_index)
                    .and_then(|line| line.find('#'))
                    .map_or(1, |column| column + 1),
                snippet: original_lines
                    .get(line_index)
                    .copied()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                message: rule_message(rule),
                cwe: rule.cwe.clone(),
                standards: rule.standards.clone(),
                translations: rule.translations.clone(),
            })
        })
        .collect()
}

fn scan_macro_trailing_semicolon_rule(
    rule: &BaselineRule,
    path: &Path,
    source: &str,
    code_only: &str,
) -> Vec<BaselineFinding> {
    let original_lines = source.lines().collect::<Vec<_>>();
    logical_preprocessor_lines(code_only)
        .into_iter()
        .filter_map(|(_, end_line, directive)| {
            let (_, body) = parse_macro_definition(&directive)?;
            body.trim_end().ends_with(';').then(|| BaselineFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                confidence: rule.confidence.clone(),
                path: path.display().to_string(),
                line: end_line + 1,
                column: original_lines
                    .get(end_line)
                    .and_then(|line| line.rfind(';'))
                    .map_or(1, |column| column + 1),
                snippet: original_lines
                    .get(end_line)
                    .copied()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                message: rule_message(rule),
                cwe: rule.cwe.clone(),
                standards: rule.standards.clone(),
                translations: rule.translations.clone(),
            })
        })
        .collect()
}

fn scan_unwrapped_multistatement_macro_rule(
    rule: &BaselineRule,
    path: &Path,
    source: &str,
    code_only: &str,
) -> Vec<BaselineFinding> {
    let original_lines = source.lines().collect::<Vec<_>>();
    let control_keyword = Regex::new(r"\b(?:do|while|for|switch|case|if|virtual)\b")
        .expect("valid macro control-keyword regex");
    logical_preprocessor_lines(code_only)
        .into_iter()
        .filter_map(|(start_line, _, directive)| {
            let (_, body) = parse_macro_definition(&directive)?;
            if body.contains('{') || control_keyword.is_match(body) {
                return None;
            }
            let semicolon = body.find(';')?;
            (!body[semicolon + 1..].trim().is_empty()).then(|| BaselineFinding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity.clone(),
                confidence: rule.confidence.clone(),
                path: path.display().to_string(),
                line: start_line + 1,
                column: original_lines
                    .get(start_line)
                    .and_then(|line| line.find('#'))
                    .map_or(1, |column| column + 1),
                snippet: original_lines
                    .get(start_line)
                    .copied()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                message: rule_message(rule),
                cwe: rule.cwe.clone(),
                standards: rule.standards.clone(),
                translations: rule.translations.clone(),
            })
        })
        .collect()
}

fn logical_preprocessor_lines(source: &str) -> Vec<(usize, usize, String)> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut directives = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !lines[index].trim_start().starts_with('#') {
            index += 1;
            continue;
        }
        let start = index;
        let mut logical = lines[index].to_string();
        while logical.trim_end().ends_with('\\') && index + 1 < lines.len() {
            let trimmed_len = logical.trim_end().len();
            logical.truncate(trimmed_len.saturating_sub(1));
            logical.push(' ');
            index += 1;
            logical.push_str(lines[index]);
        }
        directives.push((start, index, logical));
        index += 1;
    }
    directives
}

fn parse_macro_definition(directive: &str) -> Option<(bool, &str)> {
    let rest = directive.trim_start().strip_prefix('#')?.trim_start();
    let rest = rest.strip_prefix("define")?;
    if rest
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        return None;
    }
    let rest = rest.trim_start();
    let name_end = rest
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
        .map(|(index, ch)| index + ch.len_utf8())
        .last()?;
    let suffix = &rest[name_end..];
    if !suffix.starts_with('(') {
        return Some((false, suffix));
    }
    let close = suffix.find(')')?;
    let has_parameters = !suffix[1..close].trim().is_empty();
    Some((has_parameters, &suffix[close + 1..]))
}

fn count_hash_tokens(body: &str) -> usize {
    let bytes = body.as_bytes();
    let mut count = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'#' {
            count += 1;
            index += usize::from(index + 1 < bytes.len() && bytes[index + 1] == b'#') + 1;
        } else {
            index += 1;
        }
    }
    count
}

pub(crate) fn rule_path_matches(rule: &BaselineRule, path: &str) -> bool {
    rule.matcher.path_pattern.is_empty()
        || Regex::new(&rule.matcher.path_pattern).is_ok_and(|regex| regex.is_match(path))
}

fn strip_literals_preserve_layout(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    while index < bytes.len() {
        if let Some(current_quote) = quote {
            if !matches!(bytes[index], b'\n' | b'\r') {
                output[index] = b' ';
            }
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == current_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            quote = Some(bytes[index]);
            output[index] = b' ';
        }
        index += 1;
    }
    String::from_utf8(output).expect("literal masking preserves UTF-8")
}

pub(crate) fn rule_message(rule: &BaselineRule) -> String {
    if rule.message.is_empty() {
        rule.title.clone()
    } else {
        rule.message.clone()
    }
}

pub(crate) fn deduplicate_findings(findings: Vec<BaselineFinding>) -> Vec<BaselineFinding> {
    let mut seen = HashSet::new();
    findings
        .into_iter()
        .filter(|finding| {
            seen.insert((
                finding.rule_id.clone(),
                finding.path.clone(),
                finding.line,
                finding.column,
            ))
        })
        .collect()
}

fn strip_comments_preserve_layout(language: &Language, source: &str) -> String {
    match language {
        Language::Ruby => strip_ruby_comments(source),
        Language::Python | Language::Shell => strip_python_comments(source),
        Language::Php => strip_python_comments(&strip_c_like_comments(source)),
        Language::Sql => strip_sql_comments(source),
        Language::C
        | Language::Cpp
        | Language::CSharp
        | Language::ObjC
        | Language::ObjCpp
        | Language::Java
        | Language::Kotlin
        | Language::Swift
        | Language::Go
        | Language::JavaScript
        | Language::Jsp
        | Language::Rust => strip_c_like_comments(source),
        Language::Unknown => source.to_string(),
    }
}

fn strip_sql_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote = None;
    let mut block_comment = false;
    while index < bytes.len() {
        if block_comment {
            if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                output[index] = b' ';
                output[index + 1] = b' ';
                block_comment = false;
                index += 2;
            } else {
                if !matches!(bytes[index], b'\n' | b'\r') {
                    output[index] = b' ';
                }
                index += 1;
            }
            continue;
        }
        if let Some(current_quote) = quote {
            if bytes[index] == current_quote {
                if index + 1 < bytes.len() && bytes[index + 1] == current_quote {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"' | b'`') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output[index] = b' ';
            output[index + 1] = b' ';
            block_comment = true;
            index += 2;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'-' && bytes[index + 1] == b'-' {
            while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8")
}

fn strip_c_like_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut block_comment = false;
    while index < bytes.len() {
        if block_comment {
            if index + 1 < bytes.len() && bytes[index] == b'*' && bytes[index + 1] == b'/' {
                output[index] = b' ';
                output[index + 1] = b' ';
                block_comment = false;
                index += 2;
            } else {
                if bytes[index] != b'\n' && bytes[index] != b'\r' {
                    output[index] = b' ';
                }
                index += 1;
            }
            continue;
        }
        if let Some(current_quote) = quote {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == current_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
            output[index] = b' ';
            output[index + 1] = b' ';
            block_comment = true;
            index += 2;
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8")
}

fn strip_python_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote: Option<(u8, bool)> = None;
    let mut escaped = false;
    while index < bytes.len() {
        if let Some((current_quote, triple)) = quote {
            if escaped && !triple {
                escaped = false;
                index += 1;
                continue;
            }
            if !triple && bytes[index] == b'\\' {
                escaped = true;
                index += 1;
                continue;
            }
            if triple {
                if index + 2 < bytes.len()
                    && bytes[index] == current_quote
                    && bytes[index + 1] == current_quote
                    && bytes[index + 2] == current_quote
                {
                    quote = None;
                    index += 3;
                } else {
                    index += 1;
                }
            } else if bytes[index] == current_quote {
                quote = None;
                index += 1;
            } else {
                index += 1;
            }
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'') {
            let current = bytes[index];
            let triple = index + 2 < bytes.len()
                && bytes[index + 1] == current
                && bytes[index + 2] == current;
            quote = Some((current, triple));
            index += if triple { 3 } else { 1 };
            continue;
        }
        if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8")
}

fn strip_ruby_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut quote = None;
    let mut escaped = false;
    while index < bytes.len() {
        if let Some(current_quote) = quote {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == current_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(bytes[index], b'"' | b'\'' | b'`') {
            quote = Some(bytes[index]);
            index += 1;
            continue;
        }
        if bytes[index] == b'#' {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("Ruby comment masking preserves UTF-8")
}

fn bundled_semgrep_search_compat_pack() -> Result<BaselinePack> {
    let rules = BUNDLED_SEMGREP_SEARCH_COMPAT_RULES
        .iter()
        .map(|rule| BaselineRule {
            id: rule.native_rule_id.to_string(),
            title: rule.title.to_string(),
            languages: vec![match rule.language {
                "javascript" => Language::JavaScript,
                "ruby" => Language::Ruby,
                other => unreachable!("unsupported bundled Semgrep search language {other}"),
            }],
            severity: match rule.severity.to_ascii_lowercase().as_str() {
                "error" => Severity::Error,
                "info" | "note" => Severity::Note,
                _ => Severity::Warning,
            },
            confidence: Confidence::Medium,
            pattern: String::new(),
            matcher: BaselineMatcher {
                semgrep_compat_yaml: rule.rule_yaml.to_string(),
                ..Default::default()
            },
            cwe: Vec::new(),
            standards: vec![rule.source.to_string()],
            message: rule.message.to_string(),
            translations: RuleTranslations::default(),
        })
        .collect();
    let pack = BaselinePack {
        id: "legacy-semgrep-search-compat".to_string(),
        title: "Bundled Semgrep search compatibility rules".to_string(),
        rules,
    };
    pack.validate()?;
    Ok(pack)
}

pub fn builtin_security_pack() -> Result<BaselinePack> {
    BaselinePack::merge(
        "uniflow-security-1.0",
        "UniFlow security baseline",
        [
            BaselinePack::from_yaml_str(include_str!("../../../rules/baseline/cert-c-cpp.yml"))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/python-security.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!("../../../rules/baseline/java-security.yml"))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/common-security.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/swift-security.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/legacy-java-ast.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/legacy-js-semgrep-regex.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/legacy-ruby-semgrep.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!("../../../rules/baseline/legacy-c-ast.yml"))?,
            BaselinePack::from_yaml_str(include_str!(
                "../../../rules/baseline/legacy-csharp-ast.yml"
            ))?,
            BaselinePack::from_yaml_str(include_str!("../../../rules/baseline/legacy-sql.yml"))?,
            bundled_java_package_pack()?,
            bundled_semgrep_search_compat_pack()?,
        ],
    )
}

pub fn builtin_pack_manifest() -> &'static str {
    include_str!("../../../rules/baseline/manifest.json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use uniflow_lang_frontends::parse_file;

    #[test]
    fn builtin_pack_is_valid_and_has_expected_rule_count() {
        let pack = builtin_security_pack().expect("built-in baseline pack");
        assert_eq!(pack.id, "uniflow-security-1.0");
        assert_eq!(pack.rules.len(), 1761);
        let mut ids = HashSet::new();
        assert!(pack.rules.iter().all(|rule| ids.insert(rule.id.as_str())));
    }

    #[test]
    fn migrated_swift_rules_cover_all_four_legacy_cases() {
        let source = r#"
func audit(sql: String) {
    let weak = Int.random(in: 0..<10)
    UserDefaults.standard.set("api_key", forKey: "credential")
    sqlite3_exec(database, sql, nil, nil, nil)
    preferences.javaScriptCanOpenWindowsAutomatically = true
}
"#;
        let program = parse_file(Language::Swift, "audit.swift", source).expect("parse Swift");
        let source_by_path = HashMap::from([("audit.swift".to_string(), source.to_string())]);
        let pack = builtin_security_pack().expect("built-in rules");
        let findings = pack.scan_hir(&program, &source_by_path);
        for id in [
            "insecure-random",
            "swift-user-defaults",
            "swift-potential-sqlite-injection",
            "swift-webview-config-allows-js-open-windows",
        ] {
            assert!(
                findings.iter().any(|finding| finding.rule_id == id),
                "missing migrated Swift finding {id}: {findings:#?}"
            );
        }
    }

    #[test]
    fn source_scan_ignores_comments_but_not_strings() {
        let pack = BaselinePack::from_yaml_str(
            r#"
id: test
title: Test
rules:
  - id: TEST-GETS
    title: gets
    languages: [c]
    severity: error
    confidence: high
    pattern: '\bgets\s*\('
"#,
        )
        .expect("pack");
        let source = "// gets(commented);\nconst char *s = \"gets(string)\";\ngets(buffer);\n";
        let findings = pack.scan_text(&Language::C, Path::new("demo.c"), source);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[1].line, 3);
    }

    #[test]
    fn baseline_rules_preserve_simplified_english_traditional_presentations() {
        let pack = BaselinePack::from_yaml_str(
            r#"
id: localized
title: Localized rules
rules:
  - id: LOCALIZED-GETS
    title: Unsafe input function
    languages: [c]
    severity: error
    confidence: high
    pattern: '\bgets\s*\('
    message: Replace gets with a bounded input API.
    translations:
      zh-CN:
        title: 不安全的输入函数
        message: 请使用有边界检查的输入接口替换 gets。
      en:
        title: Unsafe input function
        message: Replace gets with a bounded input API.
      zh-TW:
        title: 不安全的輸入函式
        message: 請使用有邊界檢查的輸入介面替換 gets。
"#,
        )
        .expect("localized pack");
        let rule = &pack.rules[0];
        assert_eq!(rule.localized_title("zh-Hans"), "不安全的输入函数");
        assert_eq!(rule.localized_title("en-US"), "Unsafe input function");
        assert_eq!(rule.localized_title("zh-Hant"), "不安全的輸入函式");

        let findings = pack.scan_text(&Language::C, Path::new("demo.c"), "gets(buffer);");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0]
                .translations
                .zh_tw
                .as_ref()
                .expect("traditional translation")
                .message,
            "請使用有邊界檢查的輸入介面替換 gets。"
        );
        let json = serde_json::to_string(&findings[0]).expect("finding JSON");
        let simplified = json.find("zh-CN").expect("simplified locale");
        let english = json.find("\"en\"").expect("English locale");
        let traditional = json.find("zh-TW").expect("traditional locale");
        assert!(simplified < english && english < traditional, "{json}");
    }

    #[test]
    fn merge_rejects_duplicate_rule_ids() {
        let rule = BaselineRule {
            id: "DUPLICATE".to_string(),
            title: "Duplicate".to_string(),
            languages: vec![],
            severity: Severity::Warning,
            confidence: Confidence::High,
            pattern: "x".to_string(),
            matcher: BaselineMatcher::default(),
            cwe: vec![],
            standards: vec![],
            message: String::new(),
            translations: RuleTranslations::default(),
        };
        let first = BaselinePack {
            id: "first".to_string(),
            title: "First".to_string(),
            rules: vec![rule.clone()],
        };
        let second = BaselinePack {
            id: "second".to_string(),
            title: "Second".to_string(),
            rules: vec![rule],
        };
        assert!(BaselinePack::merge("merged", "Merged", [first, second]).is_err());
    }

    #[test]
    fn common_rules_cover_every_supported_language() {
        let pack = builtin_security_pack().expect("built-in baseline pack");
        let languages = [
            Language::C,
            Language::Cpp,
            Language::CSharp,
            Language::ObjC,
            Language::ObjCpp,
            Language::Java,
            Language::Kotlin,
            Language::Swift,
            Language::Python,
            Language::Go,
            Language::JavaScript,
            Language::Jsp,
            Language::Sql,
            Language::Php,
            Language::Ruby,
            Language::Rust,
            Language::Shell,
        ];
        for language in languages {
            let findings = pack.scan_text(
                &language,
                Path::new("secret.txt"),
                "api_key = \"this-is-a-secret\"",
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == "UF-COMMON-HARDCODED-PASSWORD"),
                "common rule did not run for {language:?}"
            );
        }
    }

    #[test]
    fn sql_line_comments_are_masked_without_masking_string_literals() {
        let pack = builtin_security_pack().expect("built-in baseline pack");
        let findings = pack.scan_text(
            &Language::Sql,
            Path::new("query.sql"),
            "-- api_key = 'comment-secret'\nSELECT \"api_key = 'real-secret'\";",
        );
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == "UF-COMMON-HARDCODED-PASSWORD")
                .count(),
            1
        );
        assert_eq!(findings[0].line, 2);
    }
}
