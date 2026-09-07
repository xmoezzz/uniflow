use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let source_root = manifest_dir.join("../../rules/legacy/source");
    let java_ast_pack = manifest_dir.join("../../rules/baseline/legacy-java-ast.yml");
    let c_ast_pack = manifest_dir.join("../../rules/baseline/legacy-c-ast.yml");
    println!("cargo:rerun-if-changed={}", source_root.display());
    println!("cargo:rerun-if-changed={}", java_ast_pack.display());
    println!("cargo:rerun-if-changed={}", c_ast_pack.display());

    let mut files = Vec::new();
    collect_files(&source_root, &mut files);
    files.sort();

    let mut generated =
        String::from("pub static BUNDLED_LEGACY_RAW_ASSETS: &[LegacyRawRuleAsset] = &[\n");
    for file in files {
        let relative = file
            .strip_prefix(&source_root)
            .expect("legacy asset below source root")
            .to_string_lossy()
            .replace('\\', "/");
        generated.push_str("    LegacyRawRuleAsset { path: ");
        generated.push_str(&format!("{relative:?}"));
        generated.push_str(", bytes: include_bytes!(");
        generated.push_str(&format!("{:?}", file.to_string_lossy()));
        generated.push_str(") },\n");
    }
    generated.push_str("];\n");

    let java_ast_pack_text = fs::read_to_string(&java_ast_pack)
        .unwrap_or_else(|error| panic!("read {}: {error}", java_ast_pack.display()));
    let java_ast_pack_yaml: serde_yaml::Value = serde_yaml::from_str(&java_ast_pack_text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", java_ast_pack.display()));
    let migrated_java_ast_ids = java_ast_pack_yaml["rules"]
        .as_sequence()
        .expect("legacy Java AST pack rules")
        .iter()
        .map(|rule| yaml_string(rule, &["id"], &java_ast_pack))
        .filter_map(|id| {
            if let Some(id) = id.strip_prefix("LEGACY-JAVA-AST-") {
                Some(id.to_string())
            } else if id.starts_with("LEGACY-JAVA-RULEMAP-") {
                // Product ruleMap checkers are source-backed by the bundled
                // dataflow/java/rules catalogs and audited independently.
                None
            } else {
                panic!("unexpected migrated Java rule id {id}")
            }
        })
        .collect::<BTreeSet<_>>();

    let java_ast_root = source_root.join("ast/java");
    let mut java_ast_files = Vec::new();
    collect_files(&java_ast_root, &mut java_ast_files);
    java_ast_files.sort();
    let mut seen_java_ast_ids = BTreeSet::new();
    generated.push_str("pub static BUNDLED_JAVA_AST_RULES: &[LegacyJavaAstRule] = &[\n");
    for file in java_ast_files {
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        let value: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|error| panic!("parse {}: {error}", file.display()));
        let id = yaml_string(&value, &["id"], &file);
        let message_id = yaml_string(&value, &["message"], &file);
        assert!(
            seen_java_ast_ids.insert(id.clone()),
            "duplicate Java AST rule id {id}"
        );
        let relative = file
            .strip_prefix(&source_root)
            .expect("Java AST rule below source root")
            .to_string_lossy()
            .replace('\\', "/");
        let migrated = migrated_java_ast_ids.contains(&id);
        let native_rule_id = migrated.then(|| format!("LEGACY-JAVA-AST-{id}"));
        let testcase = migrated.then_some(match id.as_str() {
            "clone-call-override-method" | "ctor-call-override-method"
            | "call-securitymanager-check-method" | "clone-method-use-sec-method"
            | "readobject-call-final-method" => {
                "crates/baseline/tests/java_member_call_rules.rs::migrated_java_member_call_rules"
            }
            "unused-field" | "unused-method" | "unused-variable"
            | "inner-class-use-outer-class-field" | "immutable-field" => {
                "crates/baseline/tests/java_usage_rules.rs::migrated_java_usage_rules"
            }
            "redirect-exec-other-code" => {
                "crates/baseline/tests/java_control_context_rules.rs::migrated_java_control_context_rules"
            }
            "sec-check-use-dns-name" => {
                "crates/baseline/tests/java_control_context_rules.rs::migrated_java_control_context_rules"
            }
            "stringbuild-in-loop" => {
                "crates/baseline/tests/java_control_context_rules.rs::migrated_java_control_context_rules"
            }
            "unreleased-db-resource" => {
                "crates/baseline/tests/java_resource_rules.rs::migrated_java_resource_release_rules"
            }
            "unreleased-file" => {
                "crates/baseline/tests/java_resource_rules.rs::migrated_java_resource_release_rules"
            }
            "unreleased-socket" => {
                "crates/baseline/tests/java_resource_rules.rs::migrated_java_resource_release_rules"
            }
            "unreleased-stream" => {
                "crates/baseline/tests/java_resource_rules.rs::migrated_java_resource_release_rules"
            }
            "sql-query-with-hibernate" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_hibernate_query_fragments_track_latest_assignment"
            }
            "invalid-var-init" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_invalid_variable_initialization"
            }
            "hash-url" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_hash_url_declarations"
            }
            "empty-case-block" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_switch_group_rules"
            }
            "switch-case-break" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_switch_group_rules"
            }
            "sync-object-is-final" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_synchronization_rules"
            }
            "synchronized-object" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_synchronization_rules"
            }
            "sync-object-notify-method" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_synchronization_rules"
            }
            "sync-object-notify-method-ydt" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_synchronization_rules"
            }
            "compare-base-object" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_boxed_session_and_select_rules"
            }
            "session-timeout-infinite" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_boxed_session_and_select_rules"
            }
            "sql-query-with-ibatis" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_boxed_session_and_select_rules"
            }
            "sql-query-with-mybatis" => {
                "crates/baseline/tests/java_remaining_semantics.rs::migrated_java_boxed_session_and_select_rules"
            }
            "disable-ldap" => {
                "crates/baseline/tests/java_contextual_call_rules.rs::migrated_java_contextual_call_and_constructor_rules"
            }
            "weak-password" => {
                "crates/baseline/tests/java_contextual_call_rules.rs::migrated_java_contextual_call_and_constructor_rules"
            }
            "http-servlet-use-socket" => {
                "crates/baseline/tests/java_contextual_call_rules.rs::migrated_java_contextual_call_and_constructor_rules"
            }
            "http-servlet-use-thread" => {
                "crates/baseline/tests/java_contextual_call_rules.rs::migrated_java_contextual_call_and_constructor_rules"
            }
            "next-throw-nosuchelementexception" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_next_throw_no_such_element_exception"
            }
            "anonymous-inner-class-call-method" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_anonymous_inner_class_call_method"
            }
            "class-initializer-use-thread" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_class_initializer_use_thread"
            }
            "static-thread-not-sec-object" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_static_thread_not_sec_object"
            }
            "inner-class-implement-serializable" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_inner_class_implement_serializable"
            }
            "inner-class-implement-serializable-ydt" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_inner_class_implement_serializable"
            }
            "rewrite-clone-method" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_rewrite_clone_method"
            }
            "final-public-static-field" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_final_public_static_field"
            }
            "static-private-final-objectstreamfield" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_static_private_final_objectstreamfield"
            }
            "static-public-final-array" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_static_public_final_array"
            }
            "static-public-final-object" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_static_public_final_object"
            }
            "immutable-final-field" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_immutable_final_field"
            }
            "immutable-public-final-field" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_immutable_public_final_field"
            }
            "transient-field-class" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_transient_field_class"
            }
            "stateholder-restorestate-savestate" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_stateholder_restorestate_savestate"
            }
            "final-clone-method" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_final_clone_method"
            }
            "private-finalize" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_private_finalize"
            }
            "request-mapping-method-public" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_request_mapping_method_public"
            }
            "rewrite-thread-run-method" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_rewrite_thread_run_method"
            }
            "default-ctor--externalizable" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_default_constructor_externalizable"
            }
            "equals-hashcode-check" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_equals_hashcode_check"
            }
            "serialize-method-sign" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_serialize_method_sign"
            }
            "serial-version-uid-defined" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_serial_version_uid_defined"
            }
            "static-final-logger" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_static_final_logger"
            }
            "mult-logger" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_multiple_logger"
            }
            "field-name-and-class-name-same" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_field_name_and_class_name_same"
            }
            "field-name-and-method-name-same" => {
                "crates/baseline/tests/java_declaration_rules.rs::migrated_java_field_name_and_method_name_same"
            }
            "overly-board-throws"
            | "hardcode-file-delimiter"
            | "identifier-invalid-char"
            | "weakyear-date"
            | "hard-code-ip" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_ast_lexical_rules_respect_token_boundaries"
            }
            "finally_block_return" | "finally_block_throw" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_finally_rules_use_hir_control_flow_context"
            }
            "bigdecimal-ctor-use-floating-param"
            | "byte-to-string-encode"
            | "content-length"
            | "unchecked-return-value" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_typed_argument_rules_preserve_positive_and_negative_cases"
            }
            "compare-nan" | "compare-nan-ydt" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_nan_comparison_rules_use_hir_operands"
            }
            "string-compare" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_string_comparison_rule_uses_static_operand_types"
            }
            "compare-class-name" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_class_name_rule_uses_nested_hir_call_chain"
            }
            "string-clone-null" => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_null_return_rule_uses_enclosing_function_context"
            }
            "empty-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_block"
            }
            "empty-if-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_if"
            }
            "empty-else-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_else"
            }
            "empty-loop-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_loop"
            }
            "empty-method-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_method"
            }
            "empty-sync-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_synchronized"
            }
            "empty-try-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_try"
            }
            "empty-infinity-loop" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_empty_infinite_loop"
            }
            "empty-infinity-loop-ydt" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_infinite_loop"
            }
            "error-cond-stmt" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_assignment_condition"
            }
            "invalid-semicolon" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_consecutive_semicolons"
            }
            "error-block" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_detached_if_block"
            }
            "switch-default" => {
                "crates/baseline/tests/java_style_rules.rs::migrated_java_missing_switch_default"
            }
            "float-loop-var" | "float-loop-var-ydt" => {
                "crates/baseline/tests/java_semantic_regressions.rs::migrated_java_floating_loop_variables_use_declared_types_and_scope"
            }
            "error-compare" => {
                "crates/baseline/tests/java_semantic_regressions.rs::migrated_java_nested_equality_preserves_parentheses_and_associativity"
            }
            "expression_always_true" | "expression_always_false" => {
                "crates/baseline/tests/java_semantic_regressions.rs::migrated_java_constant_equality_results_use_hir_structure"
            }
            "optional-null" => {
                "crates/baseline/tests/java_semantic_regressions.rs::migrated_java_optional_null_checks_returns_and_typed_operands"
            }
            "null-password" => {
                "crates/baseline/tests/java_semantic_regressions.rs::migrated_java_null_assignment_return_requires_adjacent_same_symbol"
            }
            "overly-board-catch" => {
                "crates/baseline/tests/java_semantic_regressions.rs::migrated_java_broad_catch_preserves_clause_types_and_scope"
            }
            _ => {
                "crates/baseline/tests/structured_matchers.rs::migrated_java_ast_call_rules_use_hir_callees_and_arguments"
            }
        });
        generated.push_str("    LegacyJavaAstRule { id: ");
        generated.push_str(&format!("{id:?}"));
        generated.push_str(", message_id: ");
        generated.push_str(&format!("{message_id:?}"));
        generated.push_str(", source: ");
        generated.push_str(&format!("{relative:?}"));
        generated.push_str(", native_rule_id: ");
        generated.push_str(&format!("{native_rule_id:?}"));
        generated.push_str(", testcase: ");
        generated.push_str(&format!("{testcase:?}"));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");
    let missing = migrated_java_ast_ids
        .difference(&seen_java_ast_ids)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "migrated Java AST rules missing legacy sources: {missing:?}"
    );

    let c_ast_pack_text = fs::read_to_string(&c_ast_pack)
        .unwrap_or_else(|error| panic!("read {}: {error}", c_ast_pack.display()));
    let c_ast_pack_yaml: serde_yaml::Value = serde_yaml::from_str(&c_ast_pack_text)
        .unwrap_or_else(|error| panic!("parse {}: {error}", c_ast_pack.display()));
    let migrated_c_ast_ids = c_ast_pack_yaml["rules"]
        .as_sequence()
        .expect("legacy C AST pack rules")
        .iter()
        .map(|rule| yaml_string(rule, &["id"], &c_ast_pack))
        .map(|id| {
            id.strip_prefix("LEGACY-C-AST-")
                .unwrap_or_else(|| panic!("unexpected migrated C AST rule id {id}"))
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let c_ast_root = source_root.join("ast/c");
    let mut c_ast_files = Vec::new();
    collect_files(&c_ast_root, &mut c_ast_files);
    c_ast_files.sort();
    let mut seen_c_ast_ids = BTreeSet::new();
    generated.push_str("pub static BUNDLED_C_AST_RULES: &[LegacyCAstRule] = &[\n");
    for file in c_ast_files {
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        let value: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|error| panic!("parse {}: {error}", file.display()));
        let id = yaml_string(&value, &["id"], &file);
        let message_id = yaml_string(&value, &["message"], &file);
        assert!(
            seen_c_ast_ids.insert(id.clone()),
            "duplicate C AST rule id {id}"
        );
        let relative = file
            .strip_prefix(&source_root)
            .expect("C AST rule below source root")
            .to_string_lossy()
            .replace('\\', "/");
        let migrated = migrated_c_ast_ids.contains(&id);
        let native_rule_id = migrated.then(|| format!("LEGACY-C-AST-{id}"));
        let testcase = migrated.then_some(if matches!(id.as_str(),
            "nullptr-zero" | "no-assignment-outside-statement" | "no-unary-in-expressions"
            | "no-side-effect-in-sizeof" | "no-comma-expression" | "no-assignment-in-if-condition"
            | "no-conditional-expression" | "conditional-braces" | "no-dangerous-macro-in-reg-calls"
        ) {
            "crates/baseline/tests/c_expression_rules.rs::migrated_c_expression_rules_preserve_source_boundaries"
        } else if matches!(id.as_str(),
            "void-fn-must-not-return-value" | "non-void-fn-must-return" | "non-void-fn-must-return-value"
            | "func-decl-empty" | "no-unnamed-argument" | "no-unnamed-struct"
            | "no-union-declaration-in-struct" | "array-declaration-must-be-sized"
            | "no-extern-declaration-in-function" | "no-init-in-extern-declaration"
        ) {
            "crates/baseline/tests/c_declaration_rules.rs::migrated_c_declaration_rules_preserve_source_boundaries"
        } else if matches!(id.as_str(),
            "function-like-macros-must-have-braces" | "no-redefine-keyword" | "no-concat-in-macros"
            | "no-concat-twice-in-macros" | "no-macro-to-basic-type" | "no-semicolon-after-macro"
        ) {
            "crates/baseline/tests/c_preprocessor_rules.rs::migrated_c_macro_rules_preserve_source_boundaries"
        } else if matches!(id.as_str(),
            "if-else-braces"
            | "loop-body-braces"
            | "if-else-if-must-have-else"
            | "no-empty-switch"
            | "switch-must-have-case"
            | "no-empty-statement"
            | "no-semicolon-after-for-if-while"
            | "no-break-in-loops"
            | "no-constant-in-loop-condition"
        ) {
            "crates/baseline/tests/c_statement_rules.rs::migrated_c_statement_rule_boundaries"
        } else if matches!(
            id.as_str(),
            "no-gets" | "no-exit-abort" | "no-setjmp-longjmp"
        ) {
            "crates/baseline/tests/structured_matchers.rs::migrated_c_ast_call_rules_use_structured_hir_calls"
        } else if matches!(id.as_str(), "no-overload-comma" | "no-overload-logical-and-or") {
            "crates/baseline/tests/structured_matchers.rs::migrated_cpp_operator_rules_reject_only_operator_declarations"
        } else {
            "crates/baseline/tests/structured_matchers.rs::migrated_c_ast_token_rules_preserve_lexical_and_path_constraints"
        });
        generated.push_str("    LegacyCAstRule { id: ");
        generated.push_str(&format!("{id:?}"));
        generated.push_str(", message_id: ");
        generated.push_str(&format!("{message_id:?}"));
        generated.push_str(", source: ");
        generated.push_str(&format!("{relative:?}"));
        generated.push_str(", native_rule_id: ");
        generated.push_str(&format!("{native_rule_id:?}"));
        generated.push_str(", testcase: ");
        generated.push_str(&format!("{testcase:?}"));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");
    let missing = migrated_c_ast_ids
        .difference(&seen_c_ast_ids)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "migrated C AST rules missing legacy sources: {missing:?}"
    );

    let csharp_ast_root = source_root.join("ast/csharp");
    let mut csharp_ast_files = Vec::new();
    collect_files(&csharp_ast_root, &mut csharp_ast_files);
    csharp_ast_files.sort();
    generated.push_str("pub static BUNDLED_CSHARP_AST_RULES: &[LegacyCSharpAstRule] = &[\n");
    for file in csharp_ast_files {
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        let value: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|error| panic!("parse {}: {error}", file.display()));
        let id = yaml_string(&value, &["id"], &file);
        let message_id = yaml_string(&value, &["message"], &file);
        let relative = file
            .strip_prefix(&source_root)
            .expect("C# AST rule below source root")
            .to_string_lossy()
            .replace('\\', "/");
        let native_rule_id = migrated_csharp_native_id(&relative);
        let testcase = native_rule_id.map(|id| match id {
            "LEGACY-CS-AST-SCS0002" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_sql_adapter_requires_declared_source_provenance",
            "LEGACY-CS-AST-security_risky_sql_query" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_sql_adapter_requires_declared_source_provenance",
            "LEGACY-CS-AST-SCS0003" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_typed_query_rules_match_nested_declaration_references",
            "LEGACY-CS-AST-input_validation_and_representation_linq" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_typed_query_rules_match_nested_declaration_references",
            "LEGACY-CS-AST-input_validation_and_representation_nhibernate" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_typed_query_rules_match_nested_declaration_references",
            "LEGACY-CS-AST-input_validation_and_representation_xquery_injection" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_typed_query_rules_match_nested_declaration_references",
            "LEGACY-CS-AST-input_validation_and_representation_log_forging" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_log_forging_distinguishes_parameters_and_initializers",
            "LEGACY-CS-AST-SCS0016" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_antiforgery_attributes_are_owned_by_the_method",
            "LEGACY-CS-AST-SCS0018" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_file_paths_use_each_apis_argument_position",
            "LEGACY-CS-AST-SCS0027" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_redirect_and_cookie_preserve_legacy_if_exclusions",
            "LEGACY-CS-AST-input_validation_and_representation_cookies" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_redirect_and_cookie_preserve_legacy_if_exclusions",
            "LEGACY-CS-AST-security_websocket_hacking" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_websocket_options_preserve_same_symbol_exclusion",
            "LEGACY-CS-AST-xss_protection" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_xss_header_uses_structural_receiver_and_argument_tokens",
            "LEGACY-CS-AST-encapsulation_external" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_exception_disclosure_requires_catch_receiver_and_exception",
            "LEGACY-CS-AST-encapsulation_internal" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_exception_disclosure_requires_catch_receiver_and_exception",
            "LEGACY-CS-AST-encapsulation_system_information_leak" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_exception_disclosure_requires_catch_receiver_and_exception",
            "LEGACY-CS-AST-input_validation_and_representation_castle_activerecord" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_upload_encoding_and_template_rules_have_negative_cases",
            "LEGACY-CS-AST-input_validation_and_representation_subsonic" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_upload_encoding_and_template_rules_have_negative_cases",
            "LEGACY-CS-AST-input_validation_and_representation_razor" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_upload_encoding_and_template_rules_have_negative_cases",
            "LEGACY-CS-AST-input_validation_and_representation_poor_validation" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_upload_encoding_and_template_rules_have_negative_cases",
            "LEGACY-CS-AST-input_validation_and_representation_file_upload_1" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_upload_encoding_and_template_rules_have_negative_cases",
            "LEGACY-CS-AST-input_validation_and_representation_file_upload_2" =>
                "crates/baseline/tests/csharp_taintish_ast_rules.rs::migrated_csharp_upload_encoding_and_template_rules_have_negative_cases",
            _ => "crates/baseline/tests/structured_matchers.rs::migrated_csharp_ast_rules_match_typed_calls_and_constructors",
        });
        generated.push_str("    LegacyCSharpAstRule { id: ");
        generated.push_str(&format!("{id:?}"));
        generated.push_str(", message_id: ");
        generated.push_str(&format!("{message_id:?}"));
        generated.push_str(", source: ");
        generated.push_str(&format!("{relative:?}"));
        generated.push_str(", native_rule_id: ");
        generated.push_str(&format!("{native_rule_id:?}"));
        generated.push_str(", testcase: ");
        generated.push_str(&format!("{testcase:?}"));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");

    generated.push_str("pub static BUNDLED_SEMGREP_RULES: &[LegacySemgrepRule] = &[\n");
    let mut semgrep_compat_entries = String::new();
    let mut generated_semgrep_ids = BTreeSet::new();
    for language in ["javascript", "ruby"] {
        let semgrep_root = source_root.join("semgrep").join(language);
        let mut semgrep_files = Vec::new();
        collect_files(&semgrep_root, &mut semgrep_files);
        semgrep_files.retain(|file| file.extension().is_some_and(|ext| ext == "yaml"));
        semgrep_files.sort();
        for file in semgrep_files {
            let text = fs::read_to_string(&file)
                .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
            let value: serde_yaml::Value = serde_yaml::from_str(&text)
                .unwrap_or_else(|error| panic!("parse {}: {error}", file.display()));
            let relative = file
                .strip_prefix(&source_root)
                .expect("Semgrep rule below source root")
                .to_string_lossy()
                .replace('\\', "/");
            let rules = value["rules"]
                .as_sequence()
                .unwrap_or_else(|| panic!("{} has no Semgrep rules sequence", file.display()));
            for rule in rules {
                let id = yaml_string(rule, &["id"], &file);
                let mode = rule["mode"].as_str().unwrap_or("search");
                let migrated_native_rule_id = migrated_semgrep_native_id(&relative, &id);
                let generated_native_rule_id = (mode != "taint"
                    && migrated_native_rule_id.is_none())
                    .then(|| generated_semgrep_search_id(language, &relative, &id));
                let native_rule_id = migrated_native_rule_id
                    .map(str::to_string)
                    .or_else(|| generated_native_rule_id.clone());
                let native_taint_rule_id = migrated_semgrep_taint_native_id(&relative, &id);
                let testcase = if native_taint_rule_id.is_some() {
                    if language == "ruby" {
                        Some(match id.as_str() {
                            "divide-by-zero" => "crates/taint/tests/ruby_semgrep_taint.rs::ruby_divide_by_zero_uses_integer_constant_flow_and_zero_denominator",
                            "avoid-session-manipulation" | "sequel-sqli" => "crates/taint/tests/ruby_semgrep_taint.rs::ruby_index_taint_rules_match_only_the_named_read_base",
                            _ => "crates/taint/tests/ruby_semgrep_taint.rs::every_ruby_semgrep_call_and_composition_taint_rule_executes",
                        })
                    } else {
                        Some(match id.as_str() {
                        "md5-used-as-password" => "crates/taint/tests/javascript_semgrep_taint.rs::md5_digest_flows_through_crypto_chain_to_password_calls_only",
                        "insecure-object-assign" => "crates/taint/tests/javascript_semgrep_taint.rs::nonconstant_json_parse_flows_to_object_assign",
                        "detect-child-process" if relative == "semgrep/javascript/lang/security/detect-child-process.yaml" => "crates/taint/tests/javascript_semgrep_taint.rs::commonjs_module_provenance_limits_child_process_and_bluebird_sinks",
                        "detect-child-process" if relative == "semgrep/javascript/aws-lambda/security/detect-child-process.yaml" => "crates/taint/tests/javascript_semgrep_taint.rs::aws_lambda_handler_identity_limits_event_taint",
                        "tainted-eval" if relative == "semgrep/javascript/aws-lambda/security/tainted-eval.yaml" => "crates/taint/tests/javascript_semgrep_taint.rs::aws_lambda_handler_identity_limits_event_taint",
                        "dynamodb-request-object" | "knex-sqli" | "mysql-sqli" | "pg-sqli" | "sequelize-sqli" | "vm-runincontext-injection"
                            if relative.starts_with("semgrep/javascript/aws-lambda/security/") =>
                                "crates/taint/tests/javascript_semgrep_taint.rs::aws_lambda_service_rules_preserve_package_provenance",
                        "tainted-html-response" | "tainted-html-string" | "tainted-sql-string"
                            if relative.starts_with("semgrep/javascript/aws-lambda/security/") =>
                                "crates/taint/tests/javascript_semgrep_taint.rs::aws_lambda_expression_rules_use_composition_semantics",
                        "js-open-redirect-from-function" | "js-open-redirect" | "detect-eval-with-expression" | "raw-html-concat" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::browser_location_sources_drive_redirect_eval_and_html_rules",
                        "detect-angular-element-methods" | "detect-angular-element-taint" | "detect-angular-trust-as-method" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::angular_scope_and_browser_sources_reach_only_matching_angular_sinks",
                        "hardcoded-jwt-secret" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::jsonwebtoken_hardcoded_secret_requires_constant_and_package_provenance",
                        "code-string-concat" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::web_request_first_argument_reaches_eval_but_response_and_constants_do_not",
                        "node-knex-sqli" | "path-join-resolve-traversal" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::knex_and_path_rules_preserve_package_provenance_and_sanitizers",
                        "unsafe-formatstring" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::unsafe_formatstring_requires_dynamic_composition_and_a_substitution_argument",
                        "dangerous-spawn-shell" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::dangerous_spawn_shell_requires_shell_command_and_child_process_provenance",
                        "deno-dangerous-run" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::deno_run_tracks_only_the_command_payload_of_the_options_map",
                        "express-path-join-resolve-traversal" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_path_rule_preserves_request_role_package_and_sanitizer",
                        "express-res-sendfile" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_sendfile_rule_requires_one_argument_and_request_data",
                        "express-ssrf" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_ssrf_rule_preserves_request_package_provenance",
                        "express-open-redirect" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_open_redirect_requires_response_receiver_role",
                        "express-vm-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_vm_rule_preserves_node_vm_package_provenance",
                        "express-wkhtmltopdf-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_wkhtml_rule_preserves_callable_package_alias",
                        "require-request" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_require_rule_tracks_only_request_role",
                        "res-render-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_render_rule_requires_response_receiver_role",
                        "express-sequelize-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_sequelize_rule_preserves_package_provenance",
                        "express-xml2json-xxe" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_xml2json_rule_preserves_parser_package_provenance",
                        "express-third-party-object-deserialization" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_deserialization_rule_limits_unsafe_packages",
                        "express-insecure-template-usage" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_template_rule_limits_supported_template_packages",
                        "direct-response-write" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::direct_response_write_requires_response_role_and_honors_html_sanitizer",
                        "raw-html-format"
                            if relative == "semgrep/javascript/express/security/injection/raw-html-format.yaml" =>
                                "crates/taint/tests/javascript_semgrep_taint.rs::express_html_composition_requires_html_literal_context",
                        "tainted-sql-string"
                            if relative == "semgrep/javascript/express/security/injection/tainted-sql-string.yaml" =>
                                "crates/taint/tests/javascript_semgrep_taint.rs::express_sql_composition_requires_sql_keyword_context",
                        "unsafe-argon2-config" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::unsafe_argon2_config_rejects_non_id_variant_and_accepts_argon2id",
                        "chrome-remote-interface-compilescript-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::chrome_remote_interface_rule_selects_sensitive_map_fields_and_package_provenance",
                        "cors-misconfiguration" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::cors_header_rule_supports_direct_map_and_write_head_forms",
                        "detect-non-literal-fs-filename" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::node_fs_rule_models_both_path_positions_without_tainting_file_contents",
                        "express-data-exfiltration" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_data_exfiltration_requires_request_data_at_object_assign",
                        "express-expat-xxe" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_expat_rule_tracks_parser_instances_from_node_expat",
                        "express-libxml-noent" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_libxml_rule_requires_noent_and_libxml_package_provenance",
                        "express-phantom-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_phantom_rule_tracks_page_objects_from_the_phantom_package",
                        "express-puppeteer-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_puppeteer_rule_tracks_page_objects_from_the_puppeteer_package",
                        "express-sandbox-code-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_sandbox_rule_tracks_instances_from_sandbox_package",
                        "express-vm2-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::express_vm2_rule_tracks_constructors_and_instances_from_vm2",
                        "express-xml2json-xxe-event" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::xml2json_event_rule_requires_request_data_inside_a_callback",
                        "hardcoded-passport-secret" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::passport_secret_rule_requires_constant_secret_field_and_passport_package",
                        "remote-property-injection" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::remote_property_injection_tracks_only_direct_request_controlled_store_indices",
                        "x-frame-options-misconfiguration" =>
                            "crates/taint/tests/javascript_semgrep_taint.rs::x_frame_header_rule_supports_direct_map_and_write_head_forms",
                        "tofastproperties-code-execution" => "crates/taint/tests/javascript_semgrep_taint.rs::commonjs_module_provenance_limits_child_process_and_bluebird_sinks",
                        "node-mysql-sqli" | "node-mssql-sqli" | "node-postgres-sqli" => "crates/taint/tests/javascript_semgrep_taint.rs::database_client_provenance_scopes_mysql_mssql_and_postgres_taint",
                        _ => "crates/taint/tests/javascript_semgrep_taint.rs::function_arguments_flow_to_dynamic_require_and_regexp_sinks",
                        })
                    }
                } else if generated_native_rule_id.is_some() {
                    Some(if language == "ruby" {
                        "crates/baseline/tests/semgrep_compat.rs::every_bundled_ruby_semgrep_search_rule_has_a_native_compatibility_model"
                    } else {
                        "crates/baseline/tests/semgrep_compat.rs::every_bundled_javascript_semgrep_search_rule_has_a_native_compatibility_model"
                    })
                } else {
                    native_rule_id.as_deref().map(|_| {
                    if language == "ruby"
                        && matches!(
                            relative.as_str(),
                            "semgrep/ruby/lang/security/dangerous-open.yaml"
                                | "semgrep/ruby/lang/security/dangerous-open3-pipeline.yaml"
                                | "semgrep/ruby/jwt/security/audit/jwt-decode-without-verify.yaml"
                                | "semgrep/ruby/jwt/security/audit/jwt-exposed-data.yaml"
                                | "semgrep/ruby/jwt/security/jwt-hardcode.yaml"
                                | "semgrep/ruby/jwt/security/jwt-none-alg.yaml"
                                | "semgrep/ruby/lang/security/jruby-xml.yaml"
                                | "semgrep/ruby/lang/security/nested-attributes.yaml"
                                | "semgrep/ruby/rails/security/brakeman/check-permit-attributes-high.yaml"
                                | "semgrep/ruby/rails/security/brakeman/check-permit-attributes-medium.yaml"
                        )
                    {
                        "crates/baseline/tests/ruby_semgrep_search.rs::migrated_ruby_structural_search_rules_preserve_argument_and_assignment_semantics"
                    } else if language == "ruby" {
                        "crates/baseline/tests/builtin.rs::migrated_ruby_semgrep_search_rules_ignore_comments_and_strings"
                    } else if matches!(relative.as_str(),
                        "semgrep/javascript/angular/security/detect-angular-sce-disabled.yaml"
                        | "semgrep/javascript/angular/security/detect-angular-open-redirect.yaml"
                        | "semgrep/javascript/audit/detect-replaceall-sanitization.yaml"
                        | "semgrep/javascript/browser/security/eval-detected.yaml"
                        | "semgrep/javascript/browser/security/insecure-innerhtml.yaml"
                        | "semgrep/javascript/browser/security/wildcard-postmessage-configuration.yaml"
                        | "semgrep/javascript/buf/rule-buffer-noassert.yaml"
                        | "semgrep/javascript/fbjs/security/audit/insecure-createnodesfrommarkup.yaml"
                        | "semgrep/javascript/express/security/audit/xss/mustache/explicit-unescape.yaml"
                        | "semgrep/javascript/express/security/audit/xss/pug/explicit-unescape.yaml"
                        | "semgrep/javascript/express/security/audit/xss/pug/var-in-script-tag.yaml"
                        | "semgrep/javascript/jquery/security/audit/prohibit-jquery-html.yaml"
                        | "semgrep/javascript/lang/best-practice/leftover_debugging.yaml"
                        | "semgrep/javascript/lang/best-practice/assigned-undefined.yaml"
                        | "semgrep/javascript/lang/correctness/no-replaceall.yaml"
                        | "semgrep/javascript/lang/security/detect-buffer-noassert.yaml"
                        | "semgrep/javascript/lang/security/detect-disable-mustache-escape.yaml"
                        | "semgrep/javascript/lang/security/audit/incomplete-sanitization.yaml"
                        | "semgrep/javascript/lang/security/detect-pseudoRandomBytes.yaml"
                        | "semgrep/javascript/random/rule-pseudo-random-bytes.yaml"
                        | "semgrep/javascript/require/rule-non-literal-require.yaml")
                    {
                        "crates/baseline/tests/javascript_semgrep_search.rs::migrated_javascript_structural_search_rules_preserve_variadic_and_receiver_semantics"
                    } else {
                        "crates/baseline/tests/builtin.rs::migrated_javascript_template_regex_rules_preserve_paths_and_exclusions"
                    }
                    })
                };
                if let Some(native_id) = &generated_native_rule_id {
                    assert!(
                        generated_semgrep_ids.insert(native_id.clone()),
                        "duplicate generated Semgrep compatibility id {native_id}"
                    );
                    let title = id.replace(['-', '_'], " ");
                    let message = rule["message"].as_str().unwrap_or(&title);
                    let severity = rule["severity"].as_str().unwrap_or("WARNING");
                    let rule_yaml = serde_yaml::to_string(rule)
                        .unwrap_or_else(|error| panic!("serialize {relative}:{id}: {error}"));
                    semgrep_compat_entries.push_str(
                        "    LegacySemgrepSearchCompatRule { native_rule_id: ",
                    );
                    semgrep_compat_entries.push_str(&format!("{native_id:?}"));
                    semgrep_compat_entries.push_str(", source: ");
                    semgrep_compat_entries.push_str(&format!("{relative:?}"));
                    semgrep_compat_entries.push_str(", language: ");
                    semgrep_compat_entries.push_str(&format!("{language:?}"));
                    semgrep_compat_entries.push_str(", title: ");
                    semgrep_compat_entries.push_str(&format!("{title:?}"));
                    semgrep_compat_entries.push_str(", message: ");
                    semgrep_compat_entries.push_str(&format!("{message:?}"));
                    semgrep_compat_entries.push_str(", severity: ");
                    semgrep_compat_entries.push_str(&format!("{severity:?}"));
                    semgrep_compat_entries.push_str(", rule_yaml: ");
                    semgrep_compat_entries.push_str(&format!("{rule_yaml:?}"));
                    semgrep_compat_entries.push_str(" },\n");
                }
                generated.push_str("    LegacySemgrepRule { id: ");
                generated.push_str(&format!("{id:?}"));
                generated.push_str(", source: ");
                generated.push_str(&format!("{relative:?}"));
                generated.push_str(", language: ");
                generated.push_str(&format!("{language:?}"));
                generated.push_str(", mode: ");
                generated.push_str(&format!("{mode:?}"));
                generated.push_str(", native_rule_id: ");
                generated.push_str(&format!("{native_rule_id:?}"));
                generated.push_str(", native_taint_rule_id: ");
                generated.push_str(&format!("{native_taint_rule_id:?}"));
                generated.push_str(", testcase: ");
                generated.push_str(&format!("{testcase:?}"));
                generated.push_str(" },\n");
            }
        }
    }
    generated.push_str("];\n");
    generated.push_str(
        "pub static BUNDLED_SEMGREP_SEARCH_COMPAT_RULES: &[LegacySemgrepSearchCompatRule] = &[\n",
    );
    generated.push_str(&semgrep_compat_entries);
    generated.push_str("];\n");

    let sql_root = source_root.join("sql");
    let mut sql_files = Vec::new();
    collect_files(&sql_root, &mut sql_files);
    sql_files.sort();
    generated.push_str("pub static BUNDLED_SQL_RULES: &[LegacySqlRule] = &[\n");
    for file in sql_files {
        let id = file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_else(|| panic!("invalid SQL rule file {}", file.display()));
        let relative = file
            .strip_prefix(&source_root)
            .expect("SQL rule below source root")
            .to_string_lossy()
            .replace('\\', "/");
        let migrated = matches!(
            id,
            "CharacterDatatypeUsage"
                | "ComparisonWithBoolean"
                | "ComparisonWithNull"
                | "DbmsOutputPut"
                | "EmptyStringAssignment"
                | "InequalityUsage"
                | "InsertWithoutColumns"
                | "NvlWithNullParameter"
                | "SelectAllColumns"
                | "ToDateWithoutFormat"
                | "ToCharInOrderBy"
                | "UnnecessaryLike"
                | "AddParenthesesInNestedExpression"
                | "CollapsibleIfStatements"
                | "ConcatenationWithNull"
                | "DeclareSectionWithoutDeclarations"
                | "DuplicateConditionIfElsif"
                | "DuplicatedValueInIn"
                | "EmptyBlock"
                | "ExplicitInParameter"
                | "FunctionWithOutParameter"
                | "IdenticalExpression"
                | "IfWithExit"
                | "ReturnOfBooleanExpression"
                | "SameBranch"
                | "SameCondition"
                | "SelectWithRownumAndOrderBy"
                | "UnnecessaryElse"
                | "UnnecessaryNullStatement"
                | "UselessParenthesis"
                | "VariableInitializationWithFunctionCall"
                | "VariableInitializationWithNull"
                | "CommitRollback"
                | "ColumnsShouldHaveTableName"
                | "CursorBodyInPackageSpec"
                | "DeadCode"
                | "DisabledTest"
                | "NotASelectedExpression"
                | "NotFound"
                | "ParsingError"
                | "QueryWithoutExceptionHandling"
                | "RaiseStandardException"
                | "RedundantExpectation"
                | "TooManyRowsHandler"
                | "UnhandledUserDefinedException"
                | "UnnecessaryAliasInQuery"
                | "UnusedCursor"
                | "UnusedParameter"
                | "UnusedVariable"
                | "VariableHiding"
                | "VariableInCount"
                | "VariableName"
                | "InvalidReferenceToObject"
                | "XPath"
        );
        let native_rule_id = migrated.then(|| format!("LEGACY-SQL-{id}"));
        let testcase = migrated.then_some(if id == "InvalidReferenceToObject" {
            "crates/baseline/tests/sql_style_rules.rs::invalid_reference_to_object_uses_forms_metadata_and_exact_call_contract"
        } else if id == "XPath" {
            "crates/baseline/tests/sql_style_rules.rs::xpath_template_supports_nodes_booleans_and_ignores_scalar_results"
        } else if matches!(id,
            "CharacterDatatypeUsage" | "ComparisonWithBoolean" | "ComparisonWithNull"
                | "DbmsOutputPut" | "EmptyStringAssignment" | "InequalityUsage"
                | "InsertWithoutColumns" | "NvlWithNullParameter" | "SelectAllColumns"
                | "ToDateWithoutFormat" | "ToCharInOrderBy" | "UnnecessaryLike") {
            "crates/baseline/tests/builtin.rs::migrated_sql_rules_detect_noncompliant_constructs_without_comments"
        } else if matches!(id, "AddParenthesesInNestedExpression" | "CollapsibleIfStatements"
            | "ConcatenationWithNull" | "DeclareSectionWithoutDeclarations"
            | "DuplicateConditionIfElsif" | "DuplicatedValueInIn" | "EmptyBlock"
            | "ExplicitInParameter" | "FunctionWithOutParameter" | "IdenticalExpression"
            | "IfWithExit" | "ReturnOfBooleanExpression" | "SameBranch" | "SameCondition"
            | "SelectWithRownumAndOrderBy" | "UnnecessaryElse" | "UnnecessaryNullStatement"
            | "UselessParenthesis" | "VariableInitializationWithFunctionCall"
            | "VariableInitializationWithNull") {
            "crates/baseline/tests/sql_style_rules.rs::sql_structural_rules_have_positive_safe_and_non_code_cases"
        } else {
            "crates/baseline/tests/sql_style_rules.rs::sql_control_flow_symbol_and_query_rules_have_focused_cases"
        });
        generated.push_str("    LegacySqlRule { id: ");
        generated.push_str(&format!("{id:?}"));
        generated.push_str(", source: ");
        generated.push_str(&format!("{relative:?}"));
        generated.push_str(", native_rule_id: ");
        generated.push_str(&format!("{native_rule_id:?}"));
        generated.push_str(", testcase: ");
        generated.push_str(&format!("{testcase:?}"));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");

    let package_root = source_root.join("ast/java-pkg");
    let mut package_files = Vec::new();
    collect_files(&package_root, &mut package_files);
    package_files.sort();
    generated.push_str("pub static BUNDLED_JAVA_PACKAGE_RULES: &[LegacyJavaPackageRule] = &[\n");
    for file in package_files {
        let text = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("read {}: {error}", file.display()));
        let value: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|error| panic!("parse {}: {error}", file.display()));
        let id = yaml_string(&value, &["id"], &file);
        let message = yaml_string(&value, &["message"], &file);
        let purl = yaml_string(&value, &["metadata", "purl"], &file);
        let import_regex = yaml_string(&value, &["rule", "regex"], &file);
        generated.push_str("    LegacyJavaPackageRule { id: ");
        generated.push_str(&format!("{id:?}"));
        generated.push_str(", message_id: ");
        generated.push_str(&format!("{message:?}"));
        generated.push_str(", purl: ");
        generated.push_str(&format!("{purl:?}"));
        generated.push_str(", import_regex: ");
        generated.push_str(&format!("{import_regex:?}"));
        generated.push_str(", testcase: ");
        generated.push_str(&format!(
            "{:?}",
            "crates/baseline/tests/java_package_rules.rs::every_bundled_java_package_rule_has_positive_and_non_code_witnesses"
        ));
        generated.push_str(" },\n");
    }
    generated.push_str("];\n");

    let output =
        PathBuf::from(env::var_os("OUT_DIR").expect("out dir")).join("legacy_raw_assets.rs");
    fs::write(output, generated).expect("write bundled legacy asset table");
}

fn generated_semgrep_search_id(language: &str, source: &str, id: &str) -> String {
    let prefix = if language == "ruby" {
        "LEGACY-RUBY-SEMGREP"
    } else {
        "LEGACY-JS-SEMGREP"
    };
    let source = source
        .strip_prefix(&format!("semgrep/{language}/"))
        .unwrap_or(source)
        .strip_suffix(".yaml")
        .unwrap_or(source);
    let mut slug = String::new();
    let mut previous_dash = false;
    for ch in source.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            previous_dash = false;
        } else if !previous_dash {
            slug.push('-');
            previous_dash = true;
        }
    }
    let slug = slug.trim_matches('-');
    format!("{prefix}-{id}--{slug}")
}

fn migrated_semgrep_taint_native_id(source: &str, id: &str) -> Option<&'static str> {
    match (source, id) {
        ("semgrep/ruby/aws-lambda/security/activerecord-sqli.yaml", "activerecord-sqli") => Some("LEGACY-RUBY-SEMGREP-TAINT-aws-activerecord-sqli"),
        ("semgrep/ruby/aws-lambda/security/mysql2-sqli.yaml", "mysql2-sqli") => Some("LEGACY-RUBY-SEMGREP-TAINT-aws-mysql2-sqli"),
        ("semgrep/ruby/aws-lambda/security/pg-sqli.yaml", "pg-sqli") => Some("LEGACY-RUBY-SEMGREP-TAINT-aws-pg-sqli"),
        ("semgrep/ruby/aws-lambda/security/sequel-sqli.yaml", "sequel-sqli") => Some("LEGACY-RUBY-SEMGREP-TAINT-aws-sequel-sqli"),
        ("semgrep/ruby/aws-lambda/security/tainted-deserialization.yaml", "tainted-deserialization") => Some("LEGACY-RUBY-SEMGREP-TAINT-aws-tainted-deserialization"),
        ("semgrep/ruby/aws-lambda/security/tainted-sql-string.yaml", "tainted-sql-string") => Some("LEGACY-RUBY-SEMGREP-TAINT-aws-tainted-sql-string"),
        ("semgrep/ruby/lang/security/bad-deserialization.yaml", "bad-deserialization") => Some("LEGACY-RUBY-SEMGREP-TAINT-bad-deserialization"),
        ("semgrep/ruby/lang/security/dangerous-exec.yaml", "dangerous-exec") => Some("LEGACY-RUBY-SEMGREP-TAINT-dangerous-exec"),
        ("semgrep/ruby/lang/security/divide-by-zero.yaml", "divide-by-zero") => Some("LEGACY-RUBY-SEMGREP-TAINT-divide-by-zero"),
        ("semgrep/ruby/lang/security/json-encoding.yaml", "json-encoding") => Some("LEGACY-RUBY-SEMGREP-TAINT-json-encoding"),
        ("semgrep/ruby/lang/security/md5-used-as-password.yaml", "md5-used-as-password") => Some("LEGACY-RUBY-SEMGREP-TAINT-md5-used-as-password"),
        ("semgrep/ruby/lang/security/no-eval.yaml", "ruby-eval") => Some("LEGACY-RUBY-SEMGREP-TAINT-ruby-eval"),
        ("semgrep/ruby/rails/correctness/rails-no-render-after-save.yaml", "rails-no-render-after-save") => Some("LEGACY-RUBY-SEMGREP-TAINT-rails-no-render-after-save"),
        ("semgrep/ruby/rails/security/audit/avoid-session-manipulation.yaml", "avoid-session-manipulation") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-session-manipulation"),
        ("semgrep/ruby/rails/security/audit/avoid-tainted-file-access.yaml", "avoid-tainted-file-access") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-tainted-file-access"),
        ("semgrep/ruby/rails/security/audit/avoid-tainted-ftp-call.yaml", "avoid-tainted-ftp-call") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-tainted-ftp-call"),
        ("semgrep/ruby/rails/security/audit/avoid-tainted-http-request.yaml", "avoid-tainted-http-request") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-tainted-http-request"),
        ("semgrep/ruby/rails/security/audit/avoid-tainted-shell-call.yaml", "avoid-tainted-shell-call") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-tainted-shell-call"),
        ("semgrep/ruby/rails/security/audit/dynamic-finders.yaml", "dynamic-finders") => Some("LEGACY-RUBY-SEMGREP-TAINT-dynamic-finders"),
        ("semgrep/ruby/rails/security/audit/number-to-currency.yaml", "number-to-currency") => Some("LEGACY-RUBY-SEMGREP-TAINT-number-to-currency"),
        ("semgrep/ruby/rails/security/audit/quote-table-name.yaml", "quote-table-name") => Some("LEGACY-RUBY-SEMGREP-TAINT-quote-table-name"),
        ("semgrep/ruby/rails/security/audit/sqli/ruby-pg-sqli.yaml", "ruby-pg-sqli") => Some("LEGACY-RUBY-SEMGREP-TAINT-ruby-pg-sqli"),
        ("semgrep/ruby/rails/security/audit/xss/avoid-link-to.yaml", "avoid-link-to") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-link-to"),
        ("semgrep/ruby/rails/security/audit/xss/avoid-redirect.yaml", "avoid-redirect") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-redirect"),
        ("semgrep/ruby/rails/security/audit/xss/avoid-render-dynamic-path.yaml", "avoid-render-dynamic-path") => Some("LEGACY-RUBY-SEMGREP-TAINT-avoid-render-dynamic-path"),
        ("semgrep/ruby/rails/security/brakeman/check-redirect-to.yaml", "check-redirect-to") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-redirect-to"),
        ("semgrep/ruby/rails/security/brakeman/check-regex-dos.yaml", "check-regex-dos") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-regex-dos"),
        ("semgrep/ruby/rails/security/brakeman/check-render-local-file-include.yaml", "check-render-local-file-include") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-render-local-file-include"),
        ("semgrep/ruby/rails/security/brakeman/check-send-file.yaml", "check-send-file") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-send-file"),
        ("semgrep/ruby/rails/security/brakeman/check-sql.yaml", "check-sql") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-sql"),
        ("semgrep/ruby/rails/security/brakeman/check-unsafe-reflection-methods.yaml", "check-unsafe-reflection-methods") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-unsafe-reflection-methods"),
        ("semgrep/ruby/rails/security/brakeman/check-unsafe-reflection.yaml", "check-unsafe-reflection") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-unsafe-reflection"),
        ("semgrep/ruby/rails/security/brakeman/check-unscoped-find.yaml", "check-unscoped-find") => Some("LEGACY-RUBY-SEMGREP-TAINT-check-unscoped-find"),
        ("semgrep/ruby/rails/security/injection/raw-html-format.yaml", "raw-html-format") => Some("LEGACY-RUBY-SEMGREP-TAINT-raw-html-format"),
        ("semgrep/ruby/rails/security/injection/tainted-sql-string.yaml", "tainted-sql-string") => Some("LEGACY-RUBY-SEMGREP-TAINT-rails-tainted-sql-string"),
        ("semgrep/ruby/rails/security/injection/tainted-url-host.yaml", "tainted-url-host") => Some("LEGACY-RUBY-SEMGREP-TAINT-tainted-url-host"),
        (
            "semgrep/javascript/lang/security/audit/detect-non-literal-require.yaml",
            "detect-non-literal-require",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-non-literal-require"),
        (
            "semgrep/javascript/lang/security/audit/detect-non-literal-regexp.yaml",
            "detect-non-literal-regexp",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-non-literal-regexp"),
        (
            "semgrep/javascript/lang/security/audit/md5-used-as-password.yaml",
            "md5-used-as-password",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-md5-used-as-password"),
        (
            "semgrep/javascript/lang/security/insecure-object-assign.yaml",
            "insecure-object-assign",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-insecure-object-assign"),
        (
            "semgrep/javascript/lang/security/detect-child-process.yaml",
            "detect-child-process",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-child-process"),
        (
            "semgrep/javascript/bluebird/security/audit/tofastproperties-code-execution.yaml",
            "tofastproperties-code-execution",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-tofastproperties-code-execution"),
        (
            "semgrep/javascript/lang/security/audit/sqli/node-mysql-sqli.yaml",
            "node-mysql-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-node-mysql-sqli"),
        (
            "semgrep/javascript/lang/security/audit/sqli/node-mssql-sqli.yaml",
            "node-mssql-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-node-mssql-sqli"),
        (
            "semgrep/javascript/lang/security/audit/sqli/node-postgres-sqli.yaml",
            "node-postgres-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-node-postgres-sqli"),
        (
            "semgrep/javascript/aws-lambda/security/detect-child-process.yaml",
            "detect-child-process",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-detect-child-process"),
        (
            "semgrep/javascript/aws-lambda/security/tainted-eval.yaml",
            "tainted-eval",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-tainted-eval"),
        (
            "semgrep/javascript/aws-lambda/security/dynamodb-request-object.yaml",
            "dynamodb-request-object",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-dynamodb-request-object"),
        (
            "semgrep/javascript/aws-lambda/security/knex-sqli.yaml",
            "knex-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-knex-sqli"),
        (
            "semgrep/javascript/aws-lambda/security/mysql-sqli.yaml",
            "mysql-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-mysql-sqli"),
        (
            "semgrep/javascript/aws-lambda/security/pg-sqli.yaml",
            "pg-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-pg-sqli"),
        (
            "semgrep/javascript/aws-lambda/security/sequelize-sqli.yaml",
            "sequelize-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-sequelize-sqli"),
        (
            "semgrep/javascript/aws-lambda/security/vm-runincontext-injection.yaml",
            "vm-runincontext-injection",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-vm-runincontext-injection"),
        (
            "semgrep/javascript/aws-lambda/security/tainted-html-response.yaml",
            "tainted-html-response",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-response"),
        (
            "semgrep/javascript/aws-lambda/security/tainted-html-string.yaml",
            "tainted-html-string",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-tainted-html-string"),
        (
            "semgrep/javascript/aws-lambda/security/tainted-sql-string.yaml",
            "tainted-sql-string",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-aws-tainted-sql-string"),
        (
            "semgrep/javascript/browser/security/open-redirect-from-function.yaml",
            "js-open-redirect-from-function",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-js-open-redirect-from-function"),
        (
            "semgrep/javascript/browser/security/open-redirect.yaml",
            "js-open-redirect",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-js-open-redirect"),
        (
            "semgrep/javascript/lang/security/detect-eval-with-expression.yaml",
            "detect-eval-with-expression",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-eval-with-expression"),
        (
            "semgrep/javascript/browser/security/raw-html-concat.yaml",
            "raw-html-concat",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-raw-html-concat"),
        (
            "semgrep/javascript/angular/security/detect-angular-element-methods.yaml",
            "detect-angular-element-methods",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-angular-element-methods"),
        (
            "semgrep/javascript/angular/security/detect-angular-element-taint.yaml",
            "detect-angular-element-taint",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-angular-element-taint"),
        (
            "semgrep/javascript/angular/security/detect-angular-trust-as-method.yaml",
            "detect-angular-trust-as-method",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-detect-angular-trust-as-method"),
        (
            "semgrep/javascript/jsonwebtoken/security/jwt-hardcode.yaml",
            "hardcoded-jwt-secret",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-hardcoded-jwt-secret"),
        (
            "semgrep/javascript/lang/security/audit/code-string-concat.yaml",
            "code-string-concat",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-code-string-concat"),
        (
            "semgrep/javascript/lang/security/audit/sqli/node-knex-sqli.yaml",
            "node-knex-sqli",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-node-knex-sqli"),
        (
            "semgrep/javascript/lang/security/audit/path-traversal/path-join-resolve-traversal.yaml",
            "path-join-resolve-traversal",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-path-join-resolve-traversal"),
        (
            "semgrep/javascript/lang/security/audit/unsafe-formatstring.yaml",
            "unsafe-formatstring",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-unsafe-formatstring"),
        (
            "semgrep/javascript/lang/security/audit/dangerous-spawn-shell.yaml",
            "dangerous-spawn-shell",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-dangerous-spawn-shell"),
        (
            "semgrep/javascript/deno/security/audit/deno-dangerous-run.yaml",
            "deno-dangerous-run",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-deno-dangerous-run"),
        (
            "semgrep/javascript/express/security/audit/express-path-join-resolve-traversal.yaml",
            "express-path-join-resolve-traversal",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-path-join-resolve-traversal"),
        (
            "semgrep/javascript/express/security/audit/express-res-sendfile.yaml",
            "express-res-sendfile",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-res-sendfile"),
        (
            "semgrep/javascript/express/security/audit/express-ssrf.yaml",
            "express-ssrf",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-ssrf"),
        (
            "semgrep/javascript/express/security/audit/express-open-redirect.yaml",
            "express-open-redirect",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-open-redirect"),
        (
            "semgrep/javascript/express/security/express-vm-injection.yaml",
            "express-vm-injection",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-vm-injection"),
        (
            "semgrep/javascript/express/security/express-wkhtml-injection.yaml",
            "express-wkhtmltopdf-injection",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-wkhtmltopdf-injection"),
        (
            "semgrep/javascript/express/security/require-request.yaml",
            "require-request",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-require-request"),
        (
            "semgrep/javascript/express/security/audit/res-render-injection.yaml",
            "res-render-injection",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-res-render-injection"),
        (
            "semgrep/javascript/sequelize/security/audit/sequelize-injection-express.yaml",
            "express-sequelize-injection",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-sequelize-injection"),
        (
            "semgrep/javascript/express/security/express-xml2json-xxe.yaml",
            "express-xml2json-xxe",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-xml2json-xxe"),
        (
            "semgrep/javascript/express/security/audit/express-third-party-object-deserialization.yaml",
            "express-third-party-object-deserialization",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-third-party-object-deserialization"),
        (
            "semgrep/javascript/express/security/express-insecure-template-usage.yaml",
            "express-insecure-template-usage",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-insecure-template-usage"),
        (
            "semgrep/javascript/express/security/audit/xss/direct-response-write.yaml",
            "direct-response-write",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-direct-response-write"),
        (
            "semgrep/javascript/express/security/injection/raw-html-format.yaml",
            "raw-html-format",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-raw-html-format"),
        (
            "semgrep/javascript/express/security/injection/tainted-sql-string.yaml",
            "tainted-sql-string",
        ) => Some("LEGACY-JS-SEMGREP-TAINT-express-tainted-sql-string"),
        ("semgrep/javascript/argon2/security/unsafe-argon2-config.yaml", "unsafe-argon2-config") =>
            Some("LEGACY-JS-SEMGREP-TAINT-unsafe-argon2-config"),
        ("semgrep/javascript/chrome-remote-interface/security/audit/chrome-remote-interface-compilescript-injection.yaml", "chrome-remote-interface-compilescript-injection") =>
            Some("LEGACY-JS-SEMGREP-TAINT-chrome-remote-interface-compilescript-injection"),
        ("semgrep/javascript/express/security/cors-misconfiguration.yaml", "cors-misconfiguration") =>
            Some("LEGACY-JS-SEMGREP-TAINT-cors-misconfiguration"),
        ("semgrep/javascript/lang/security/audit/detect-non-literal-fs-filename.yaml", "detect-non-literal-fs-filename") =>
            Some("LEGACY-JS-SEMGREP-TAINT-detect-non-literal-fs-filename"),
        ("semgrep/javascript/express/security/express-data-exfiltration.yaml", "express-data-exfiltration") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-data-exfiltration"),
        ("semgrep/javascript/express/security/express-expat-xxe.yaml", "express-expat-xxe") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-expat-xxe"),
        ("semgrep/javascript/express/security/audit/express-libxml-noent.yaml", "express-libxml-noent") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-libxml-noent"),
        ("semgrep/javascript/express/security/express-phantom-injection.yaml", "express-phantom-injection") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-phantom-injection"),
        ("semgrep/javascript/express/security/express-puppeteer-injection.yaml", "express-puppeteer-injection") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-puppeteer-injection"),
        ("semgrep/javascript/express/security/express-sandbox-injection.yaml", "express-sandbox-code-injection") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-sandbox-code-injection"),
        ("semgrep/javascript/express/security/express-vm2-injection.yaml", "express-vm2-injection") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-vm2-injection"),
        ("semgrep/javascript/express/security/audit/express-xml2json-xxe-event.yaml", "express-xml2json-xxe-event") =>
            Some("LEGACY-JS-SEMGREP-TAINT-express-xml2json-xxe-event"),
        ("semgrep/javascript/passport-jwt/security/passport-hardcode.yaml", "hardcoded-passport-secret") =>
            Some("LEGACY-JS-SEMGREP-TAINT-hardcoded-passport-secret"),
        ("semgrep/javascript/express/security/audit/remote-property-injection.yaml", "remote-property-injection") =>
            Some("LEGACY-JS-SEMGREP-TAINT-remote-property-injection"),
        ("semgrep/javascript/express/security/x-frame-options-misconfiguration.yaml", "x-frame-options-misconfiguration") =>
            Some("LEGACY-JS-SEMGREP-TAINT-x-frame-options-misconfiguration"),
        _ => None,
    }
}

fn migrated_semgrep_native_id(source: &str, id: &str) -> Option<&'static str> {
    if source == "semgrep/javascript/lang/best-practice/leftover_debugging.yaml" {
        return match id {
            "javascript-alert" => Some("LEGACY-JS-SEMGREP-javascript-alert"),
            "javascript-debugger" => Some("LEGACY-JS-SEMGREP-javascript-debugger"),
            "javascript-confirm" => Some("LEGACY-JS-SEMGREP-javascript-confirm"),
            "javascript-prompt" => Some("LEGACY-JS-SEMGREP-javascript-prompt"),
            _ => None,
        };
    }
    match source {
        "semgrep/javascript/angular/security/detect-angular-sce-disabled.yaml" => {
            Some("LEGACY-JS-SEMGREP-detect-angular-sce-disabled")
        }
        "semgrep/javascript/angular/security/detect-angular-open-redirect.yaml" => {
            Some("LEGACY-JS-SEMGREP-detect-angular-open-redirect")
        }
        "semgrep/javascript/audit/detect-replaceall-sanitization.yaml" => {
            Some("LEGACY-JS-SEMGREP-detect-replaceall-sanitization")
        }
        "semgrep/javascript/browser/security/eval-detected.yaml" => {
            Some("LEGACY-JS-SEMGREP-eval-detected")
        }
        "semgrep/javascript/browser/security/insecure-innerhtml.yaml" => {
            Some("LEGACY-JS-SEMGREP-insecure-innerhtml")
        }
        "semgrep/javascript/browser/security/wildcard-postmessage-configuration.yaml" => {
            Some("LEGACY-JS-SEMGREP-wildcard-postmessage-configuration")
        }
        "semgrep/javascript/buf/rule-buffer-noassert.yaml" => {
            Some("LEGACY-JS-SEMGREP-javascript_buf_rule-buffer-noassert")
        }
        "semgrep/javascript/fbjs/security/audit/insecure-createnodesfrommarkup.yaml" => {
            Some("LEGACY-JS-SEMGREP-insecure-createnodesfrommarkup")
        }
        "semgrep/javascript/express/security/audit/xss/ejs/explicit-unescape.yaml" => {
            Some("LEGACY-JS-SEMGREP-ejs-explicit-unescape")
        }
        "semgrep/javascript/express/security/audit/xss/ejs/var-in-href.yaml" => {
            Some("LEGACY-JS-SEMGREP-ejs-var-in-href")
        }
        "semgrep/javascript/express/security/audit/xss/mustache/var-in-href.yaml" => {
            Some("LEGACY-JS-SEMGREP-mustache-var-in-href")
        }
        "semgrep/javascript/express/security/audit/xss/mustache/explicit-unescape.yaml" => {
            Some("LEGACY-JS-SEMGREP-mustache-explicit-unescape")
        }
        "semgrep/javascript/express/security/audit/xss/pug/and-attributes.yaml" => {
            Some("LEGACY-JS-SEMGREP-pug-and-attributes")
        }
        "semgrep/javascript/express/security/audit/xss/pug/explicit-unescape.yaml" => {
            Some("LEGACY-JS-SEMGREP-pug-explicit-unescape")
        }
        "semgrep/javascript/express/security/audit/xss/pug/var-in-href.yaml" => {
            Some("LEGACY-JS-SEMGREP-pug-var-in-href")
        }
        "semgrep/javascript/express/security/audit/xss/pug/var-in-script-tag.yaml" => {
            Some("LEGACY-JS-SEMGREP-pug-var-in-script-tag")
        }
        "semgrep/javascript/jquery/security/audit/prohibit-jquery-html.yaml" => {
            Some("LEGACY-JS-SEMGREP-prohibit-jquery-html")
        }
        "semgrep/javascript/lang/correctness/no-replaceall.yaml" => {
            Some("LEGACY-JS-SEMGREP-no-replaceall")
        }
        "semgrep/javascript/lang/best-practice/assigned-undefined.yaml" => {
            Some("LEGACY-JS-SEMGREP-assigned-undefined")
        }
        "semgrep/javascript/lang/security/detect-buffer-noassert.yaml" => {
            Some("LEGACY-JS-SEMGREP-detect-buffer-noassert")
        }
        "semgrep/javascript/lang/security/detect-disable-mustache-escape.yaml" => {
            Some("LEGACY-JS-SEMGREP-detect-disable-mustache-escape")
        }
        "semgrep/javascript/lang/security/audit/incomplete-sanitization.yaml" => {
            Some("LEGACY-JS-SEMGREP-incomplete-sanitization")
        }
        "semgrep/javascript/lang/security/detect-insecure-websocket.yaml" => {
            Some("LEGACY-JS-SEMGREP-insecure-websocket")
        }
        "semgrep/javascript/lang/security/detect-pseudoRandomBytes.yaml" => {
            Some("LEGACY-JS-SEMGREP-detect-pseudoRandomBytes")
        }
        "semgrep/javascript/random/rule-pseudo-random-bytes.yaml" => {
            Some("LEGACY-JS-SEMGREP-javascript_random_rule-pseudo-random-bytes")
        }
        "semgrep/javascript/require/rule-non-literal-require.yaml" => {
            Some("LEGACY-JS-SEMGREP-javascript_require_rule-non-literal-require")
        }
        "semgrep/javascript/vue/security/audit/xss/templates/avoid-v-html.yaml" => {
            Some("LEGACY-JS-SEMGREP-vue-v-html")
        }
        "semgrep/ruby/lang/security/cookie-serialization.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-cookie-serialization")
        }
        "semgrep/ruby/jwt/security/audit/jwt-decode-without-verify.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-ruby-jwt-decode-without-verify")
        }
        "semgrep/ruby/jwt/security/audit/jwt-exposed-data.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-ruby-jwt-exposed-data")
        }
        "semgrep/ruby/jwt/security/jwt-hardcode.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-ruby-jwt-hardcoded-secret")
        }
        "semgrep/ruby/jwt/security/jwt-none-alg.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-ruby-jwt-none-alg")
        }
        "semgrep/ruby/lang/security/dangerous-syscall.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-dangerous-syscall")
        }
        "semgrep/ruby/lang/security/dangerous-open.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-dangerous-open")
        }
        "semgrep/ruby/lang/security/dangerous-open3-pipeline.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-dangerous-open3-pipeline")
        }
        "semgrep/ruby/lang/security/file-disclosure.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-file-disclosure")
        }
        "semgrep/ruby/lang/security/force-ssl-false.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-force-ssl-false")
        }
        "semgrep/ruby/lang/security/json-entity-escape.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-json-entity-escape")
        }
        "semgrep/ruby/lang/security/jruby-xml.yaml" => Some("LEGACY-RUBY-SEMGREP-jruby-xml"),
        "semgrep/ruby/lang/security/model-attributes-attr-protected.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-model-attributes-attr-protected")
        }
        "semgrep/ruby/lang/security/nested-attributes-bypass.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-nested-attributes-bypass")
        }
        "semgrep/ruby/lang/security/nested-attributes.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-nested-attributes")
        }
        "semgrep/ruby/lang/security/ssl-mode-no-verify.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-ssl-mode-no-verify")
        }
        "semgrep/ruby/lang/security/timing-attack.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-timing-attack")
        }
        "semgrep/ruby/lang/security/weak-hashes-md5.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-weak-hashes-md5")
        }
        "semgrep/ruby/lang/security/weak-hashes-sha1.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-weak-hashes-sha1")
        }
        "semgrep/ruby/lang/security/yaml-parsing.yaml" => Some("LEGACY-RUBY-SEMGREP-yaml-parsing"),
        "semgrep/ruby/rails/security/audit/rails-skip-forgery-protection.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-skip-forgery-protection")
        }
        "semgrep/ruby/rails/security/audit/xss/avoid-content-tag.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-avoid-content-tag")
        }
        "semgrep/ruby/rails/security/audit/xss/avoid-html-safe.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-avoid-html-safe")
        }
        "semgrep/ruby/rails/security/audit/xss/avoid-raw.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-avoid-raw")
        }
        "semgrep/ruby/rails/security/audit/xss/avoid-render-inline.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-avoid-render-inline")
        }
        "semgrep/ruby/rails/security/audit/xss/avoid-render-text.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-avoid-render-text")
        }
        "semgrep/ruby/rails/security/audit/xss/manual-template-creation.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-manual-template-creation")
        }
        "semgrep/ruby/rails/security/audit/xxe/libxml-backend.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-libxml-backend")
        }
        "semgrep/ruby/rails/security/brakeman/check-permit-attributes-high.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-check-permit-attributes-high")
        }
        "semgrep/ruby/rails/security/brakeman/check-permit-attributes-medium.yaml" => {
            Some("LEGACY-RUBY-SEMGREP-check-permit-attributes-medium")
        }
        _ => None,
    }
}

fn migrated_csharp_native_id(source: &str) -> Option<&'static str> {
    match source {
        "ast/csharp/encapsulation_external.yaml" => Some("LEGACY-CS-AST-encapsulation_external"),
        "ast/csharp/encapsulation_internal.yml" => Some("LEGACY-CS-AST-encapsulation_internal"),
        "ast/csharp/encapsulation_system_information_leak.yml" => {
            Some("LEGACY-CS-AST-encapsulation_system_information_leak")
        }
        "ast/csharp/security_websocket_hacking.yml" => {
            Some("LEGACY-CS-AST-security_websocket_hacking")
        }
        "ast/csharp/input_validation_and_representation_linq.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_linq")
        }
        "ast/csharp/input_validation_and_representation_log_forging.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_log_forging")
        }
        "ast/csharp/input_validation_and_representation_nhibernate.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_nhibernate")
        }
        "ast/csharp/input_validation_and_representation_xquery_injection.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_xquery_injection")
        }
        "ast/csharp/security_risky_sql_query.yml" => Some("LEGACY-CS-AST-security_risky_sql_query"),
        "ast/csharp/xss_protection.yml" => Some("LEGACY-CS-AST-xss_protection"),
        "ast/csharp/input_validation_and_representation_castle_activerecord.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_castle_activerecord")
        }
        "ast/csharp/input_validation_and_representation_cookies.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_cookies")
        }
        "ast/csharp/input_validation_and_representation_file_upload_1.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_file_upload_1")
        }
        "ast/csharp/input_validation_and_representation_file_upload_2.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_file_upload_2")
        }
        "ast/csharp/input_validation_and_representation_poor_validation.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_poor_validation")
        }
        "ast/csharp/input_validation_and_representation_razor.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_razor")
        }
        "ast/csharp/input_validation_and_representation_subsonic.yml" => {
            Some("LEGACY-CS-AST-input_validation_and_representation_subsonic")
        }
        "ast/csharp/SCS0002.yml" => Some("LEGACY-CS-AST-SCS0002"),
        "ast/csharp/SCS0003.yml" => Some("LEGACY-CS-AST-SCS0003"),
        "ast/csharp/SCS0005.yml" => Some("LEGACY-CS-AST-SCS0005"),
        "ast/csharp/SCS0010.yml" => Some("LEGACY-CS-AST-SCS0010"),
        "ast/csharp/SCS0016.yml" => Some("LEGACY-CS-AST-SCS0016"),
        "ast/csharp/SCS0018.yml" => Some("LEGACY-CS-AST-SCS0018"),
        "ast/csharp/SCS0027.yml" => Some("LEGACY-CS-AST-SCS0027"),
        "ast/csharp/encapsulation_overly_permissive_cors_policy_1.yml" => {
            Some("LEGACY-CS-AST-encapsulation_overly_permissive_cors_policy_1")
        }
        "ast/csharp/encapsulation_overly_permissive_cors_policy_2.yml" => {
            Some("LEGACY-CS-AST-encapsulation_overly_permissive_cors_policy_2")
        }
        "ast/csharp/security_features_header_checking_disabled.yml" => {
            Some("LEGACY-CS-AST-security_features_header_checking_disabled")
        }
        "ast/csharp/security_features_inadequate_rsa_padding_1.yml" => {
            Some("LEGACY-CS-AST-security_features_inadequate_rsa_padding_1")
        }
        "ast/csharp/security_features_inadequate_rsa_padding_2.yml" => {
            Some("LEGACY-CS-AST-security_features_inadequate_rsa_padding_2")
        }
        "ast/csharp/security_features_inadequate_rsa_padding_3.yml" => {
            Some("LEGACY-CS-AST-security_features_inadequate_rsa_padding_3")
        }
        "ast/csharp/security_features_null_password_1.yml" => {
            Some("LEGACY-CS-AST-security_features_null_password_1")
        }
        "ast/csharp/security_features_null_password_2.yml" => {
            Some("LEGACY-CS-AST-security_features_null_password_2")
        }
        "ast/csharp/security_features_insufficient_key_size.yml" => {
            Some("LEGACY-CS-AST-security_features_insufficient_key_size")
        }
        _ => None,
    }
}

fn yaml_string(value: &serde_yaml::Value, path: &[&str], file: &Path) -> String {
    let mut current = value;
    for key in path {
        current = current.get(*key).unwrap_or_else(|| {
            panic!(
                "{} is missing YAML field {}",
                file.display(),
                path.join(".")
            )
        });
    }
    current
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "{} YAML field {} is not a string",
                file.display(),
                path.join(".")
            )
        })
        .to_string()
}

fn collect_files(directory: &Path, output: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("read legacy asset entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_files(&path, output);
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name != ".DS_Store")
        {
            output.push(path);
        }
    }
}
