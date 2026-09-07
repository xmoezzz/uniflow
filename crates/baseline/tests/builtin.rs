use sha2::{Digest, Sha256};
use std::path::Path;
use uniflow_baseline::{
    builtin_security_pack, bundled_c_ast_rules, bundled_csharp_ast_rules, bundled_java_ast_rules,
    bundled_java_package_pack, bundled_java_package_rules, bundled_legacy_raw_assets,
    bundled_semgrep_rules, bundled_sql_rules,
};
use uniflow_hir::Language;

#[derive(serde::Deserialize)]
struct Manifest {
    rule_count: usize,
    packs: Vec<ManifestPack>,
}

#[derive(serde::Deserialize)]
struct ManifestPack {
    id: String,
    rule_count: usize,
}

#[derive(serde::Deserialize)]
struct LegacyModelManifest {
    catalogs: Vec<LegacyModelCatalog>,
}

#[derive(serde::Deserialize)]
struct LegacyModelCatalog {
    language: String,
    file: String,
    sha256: String,
    sources: usize,
    #[serde(default)]
    function_sources: usize,
    sinks: usize,
    propagators: usize,
    deferred_features: usize,
}

#[test]
fn detects_c_gets() {
    let pack = builtin_security_pack().expect("built-in pack must load");
    let findings = pack.scan_text(&Language::C, Path::new("demo.c"), "gets(buffer);\n");
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "UF-C-STR-GETS"));
}

#[test]
fn executable_pack_count_matches_manifest_sum() {
    let manifest: Manifest = serde_json::from_str(uniflow_baseline::builtin_pack_manifest())
        .expect("parse built-in manifest");
    let sum = manifest
        .packs
        .iter()
        .map(|pack| pack.rule_count)
        .sum::<usize>();
    assert_eq!(sum, manifest.rule_count, "manifest pack counts disagree");
    let pack = builtin_security_pack().expect("built-in pack");
    assert_eq!(pack.rules.len(), manifest.rule_count);
    let mut ids = manifest
        .packs
        .iter()
        .map(|pack| pack.id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        manifest.packs.len(),
        "duplicate manifest pack id"
    );
}

#[test]
fn generated_taint_catalog_hashes_and_completion_flags_match_manifest() {
    let manifest: LegacyModelManifest =
        serde_json::from_str(include_str!("../../../rules/legacy/manifest.json"))
            .expect("parse legacy model manifest");
    assert_eq!(manifest.catalogs.len(), 8);
    for catalog in manifest.catalogs {
        assert!(!catalog.language.is_empty());
        assert!(
            catalog.sources > 0 || catalog.function_sources > 0,
            "{} has no sources",
            catalog.language
        );
        assert!(catalog.sinks > 0, "{} has no sinks", catalog.language);
        assert_eq!(
            catalog.deferred_features, 0,
            "{} still has deferred model features",
            catalog.language
        );
        if catalog.language != "go"
            && catalog.language != "csharp"
            && catalog.language != "javascript-semgrep"
        {
            assert!(
                catalog.propagators > 0,
                "{} unexpectedly has no propagators",
                catalog.language
            );
        }
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules/legacy")
            .join(&catalog.file);
        let bytes = std::fs::read(&path).expect("read generated taint catalog");
        let actual = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            actual,
            catalog.sha256,
            "hash mismatch for {}",
            path.display()
        );
    }
}

#[test]
fn detects_python_eval() {
    let pack = builtin_security_pack().expect("built-in pack must load");
    let findings = pack.scan_text(
        &Language::Python,
        Path::new("demo.py"),
        "eval(user_input)\n",
    );
    assert!(findings
        .iter()
        .any(|finding| finding.rule_id == "UF-PY-EVAL"));
}

#[test]
fn ignores_rules_for_other_languages() {
    let pack = builtin_security_pack().expect("built-in pack must load");
    let findings = pack.scan_text(&Language::Java, Path::new("Demo.java"), "gets(buffer);\n");
    assert!(findings.is_empty());
}

#[test]
fn bundles_every_repository_legacy_source_asset() {
    let assets = bundled_legacy_raw_assets();
    assert_eq!(assets.len(), 1_858);
    for required in [
        "ast/c/c/number-literal-suffix-must-be-upper-case.yaml",
        "ast/csharp/SCS0002.yml",
        "ast/java/gbt/hard-code-ip.yaml",
        "dataflow/java/rules/java_a.yaml",
        "go/rules.yaml",
        "python/models/sast_django.pysa",
        "semgrep/javascript/thenify/security/audit/multiargs-code-execution.yaml",
        "semgrep/ruby/jwt/security/jwt-none-alg.yaml",
        "semgrep/swift/lang/crypto/insecure-random.yaml",
        "sql/ComparisonWithNull.md",
        "clang-checkers/Checkers/DisableGotoChecker.cpp",
    ] {
        assert!(
            assets
                .iter()
                .any(|asset| asset.path == required && !asset.bytes.is_empty()),
            "missing bundled legacy asset {required}"
        );
    }
}

#[test]
fn compiles_all_legacy_java_package_rules() {
    let source_rules = bundled_java_package_rules();
    assert_eq!(source_rules.len(), 544);
    assert!(source_rules.iter().all(|rule| {
        !rule.id.is_empty()
            && !rule.message_id.is_empty()
            && rule.purl.starts_with("pkg:maven/")
            && !rule.import_regex.is_empty()
            && rule.testcase
                == "crates/baseline/tests/java_package_rules.rs::every_bundled_java_package_rule_has_positive_and_non_code_witnesses"
    }));
    let pack = bundled_java_package_pack().expect("compiled Java package rules");
    assert_eq!(pack.rules.len(), 544);
}

#[test]
fn java_ast_migration_inventory_is_source_backed_and_tested() {
    let inventory = bundled_java_ast_rules();
    assert_eq!(inventory.len(), 130);
    assert!(inventory.iter().all(|rule| {
        !rule.id.is_empty()
            && !rule.message_id.is_empty()
            && rule.source.starts_with("ast/java/")
            && rule.source.ends_with(".yaml")
            && rule.native_rule_id.is_some() == rule.testcase.is_some()
    }));

    let pack = builtin_security_pack().expect("built-in pack");
    let migrated = inventory
        .iter()
        .filter(|rule| rule.native_rule_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(migrated.len(), 130);
    for rule in migrated {
        let native_id = rule.native_rule_id.expect("migrated native id");
        assert!(
            pack.rules.iter().any(|candidate| candidate.id == native_id),
            "migrated Java AST rule {native_id} is absent from the executable pack"
        );
        assert!(
            rule.testcase
                .is_some_and(|testcase| testcase.contains("migrated_java_")),
            "migrated Java AST rule {native_id} has no focused testcase"
        );
        let (file, function) = rule.testcase.unwrap().rsplit_once("::").unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(file);
        let source = std::fs::read_to_string(&path).expect("referenced testcase must exist");
        assert!(
            source.contains(&format!("fn {function}(")),
            "{native_id} references missing test function {function}"
        );
        assert!(
            source.contains(native_id),
            "{native_id} must have an explicit assertion in its testcase file"
        );
    }
}

#[test]
fn java_ast_knowledge_metadata_audit_preserves_source_gaps_and_completes_presentations() {
    let report: serde_json::Value =
        serde_json::from_str(uniflow_baseline::bundled_java_ast_metadata_report()).unwrap();
    let pack = builtin_security_pack().unwrap();
    let java = pack
        .rules
        .iter()
        .filter(|rule| rule.id.starts_with("LEGACY-JAVA-AST-"))
        .collect::<Vec<_>>();
    assert_eq!(java.len(), 130);
    let chinese = java
        .iter()
        .filter(|rule| {
            rule.translations
                .zh_cn
                .as_ref()
                .is_some_and(|text| !text.message.is_empty())
        })
        .count();
    assert_eq!(chinese, 130);
    assert_eq!(report["chinese_messages"].as_u64(), Some(chinese as u64));
    assert_eq!(report["source_chinese_messages"], 130);
    assert_eq!(report["source_english_messages"], 49);
    assert_eq!(report["source_enriched_sinks"], 130);
    assert_eq!(report["mapped_sinks"], 130);
    assert!(report["unresolved_knowledge_ids"]
        .as_array()
        .is_some_and(|ids| !ids.is_empty()));
    assert!(java.iter().all(|rule| {
        rule.translations.en.as_ref().is_some_and(|text| !text.message.is_empty())
            && rule.translations.zh_tw.as_ref().is_some_and(|text| !text.message.is_empty())
    }));
    let known = java
        .iter()
        .find(|rule| rule.id == "LEGACY-JAVA-AST-disable-ldap")
        .unwrap();
    assert!(known
        .translations
        .zh_cn
        .as_ref()
        .unwrap()
        .message
        .contains("LDAP"));
    let thread_stop = java
        .iter()
        .find(|rule| rule.id == "LEGACY-JAVA-AST-call-unsafe-threadstop-method")
        .expect("Thread.stop checker");
    assert!(thread_stop
        .standards
        .contains(&"cert:02000010141105".to_string()));
    assert!(known
        .standards
        .iter()
        .any(|standard| standard.starts_with("LEGACY-MSG-")));
}

#[test]
fn c_ast_migration_inventory_is_source_backed_and_tested() {
    let inventory = bundled_c_ast_rules();
    assert_eq!(inventory.len(), 53);
    assert!(inventory.iter().all(|rule| {
        !rule.id.is_empty()
            && !rule.message_id.is_empty()
            && rule.source.starts_with("ast/c/")
            && rule.native_rule_id.is_some() == rule.testcase.is_some()
    }));
    let migrated = inventory
        .iter()
        .filter(|rule| rule.native_rule_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(migrated.len(), 53);
    let pack = builtin_security_pack().expect("built-in pack");
    for rule in migrated {
        assert!(rule.testcase.is_some());
        assert!(pack
            .rules
            .iter()
            .any(|candidate| { Some(candidate.id.as_str()) == rule.native_rule_id }));
        let (file, function) = rule.testcase.unwrap().rsplit_once("::").unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(file);
        let source = std::fs::read_to_string(path).expect("referenced C testcase must exist");
        assert!(
            source.contains(&format!("fn {function}(")),
            "missing {function}"
        );
        assert!(
            source.contains(rule.native_rule_id.unwrap()),
            "missing rule assertion"
        );
        let candidate = pack
            .rules
            .iter()
            .find(|candidate| Some(candidate.id.as_str()) == rule.native_rule_id)
            .unwrap();
        if candidate.matcher.c_macro.is_some()
            || candidate.matcher.c_declaration.is_some()
            || candidate.matcher.c_expression.is_some()
        {
            assert!(rule.message_id.split(',').all(|message| candidate
                .standards
                .iter()
                .any(|standard| standard == message)));
            assert!(candidate
                .translations
                .zh_cn
                .as_ref()
                .is_some_and(|text| !text.message.is_empty()));
            assert!(candidate
                .translations
                .en
                .as_ref()
                .is_some_and(|text| !text.message.is_empty()));
            assert!(candidate
                .translations
                .zh_tw
                .as_ref()
                .is_some_and(|text| !text.message.is_empty()));
        }
    }
}

#[test]
fn csharp_ast_migration_inventory_is_source_backed_and_tested() {
    let inventory = bundled_csharp_ast_rules();
    assert_eq!(inventory.len(), 33);
    assert!(inventory.iter().all(|rule| {
        !rule.id.is_empty()
            && !rule.message_id.is_empty()
            && rule.source.starts_with("ast/csharp/")
            && rule.native_rule_id.is_some() == rule.testcase.is_some()
    }));
    let migrated = inventory
        .iter()
        .filter(|rule| rule.native_rule_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(migrated.len(), 33);
    let pack = builtin_security_pack().expect("built-in pack");
    let mut native_ids = std::collections::HashSet::new();
    for rule in migrated {
        let candidate = pack
            .rules
            .iter()
            .find(|candidate| Some(candidate.id.as_str()) == rule.native_rule_id)
            .expect("executable rule must be present");
        assert!(
            native_ids.insert(candidate.id.as_str()),
            "duplicate executable mapping: {}",
            candidate.id
        );
        assert!(
            candidate
                .standards
                .contains(&format!("LEGACY-MSG-{}", rule.message_id)),
            "{} lost its source message id {}",
            candidate.id,
            rule.message_id
        );
        let (file, function) = rule
            .testcase
            .expect("focused testcase")
            .rsplit_once("::")
            .unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(file);
        let source = std::fs::read_to_string(path).unwrap();
        assert!(
            source.contains(&format!("fn {function}(")),
            "missing testcase for {}",
            candidate.id
        );
        assert!(
            source.contains(&candidate.id),
            "testcase lacks explicit rule id {}",
            candidate.id
        );
    }
}

#[test]
fn detects_bundled_java_package_imports_without_matching_comments_or_strings() {
    let source = r#"
// import com.alibaba.fastjson.JSON;
class Text { String value = "import com.alibaba.fastjson.JSON;"; }
import
    com.alibaba.fastjson.JSON;
"#;
    let pack = bundled_java_package_pack().expect("compiled Java package rules");
    let findings = pack.scan_text(&Language::Java, Path::new("Component.java"), source);
    let matches = findings
        .iter()
        .filter(|finding| finding.rule_id == "LEGACY-JAVA-PKG-com.alibaba.fastjson")
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "{findings:#?}");
    assert_eq!(matches[0].line, 4);
    assert_eq!(matches[0].message, "pkg:maven/com.alibaba/fastjson");
}

#[test]
fn migrated_javascript_template_regex_rules_preserve_paths_and_exclusions() {
    let pack = builtin_security_pack().expect("built-in pack");
    let cases = [
        (
            "view.ejs",
            "<%- user.name %>\n<%- include('partial') %>\n<a href=x<%= target %>>x</a>",
            vec![
                "LEGACY-JS-SEMGREP-ejs-explicit-unescape",
                "LEGACY-JS-SEMGREP-ejs-var-in-href",
            ],
        ),
        (
            "view.mustache",
            "<a href={{target}}>x</a>",
            vec!["LEGACY-JS-SEMGREP-mustache-var-in-href"],
        ),
        (
            "view.pug",
            "div&attributes(values)\na(href=target)",
            vec![
                "LEGACY-JS-SEMGREP-pug-and-attributes",
                "LEGACY-JS-SEMGREP-pug-var-in-href",
            ],
        ),
        (
            "socket.js",
            "const endpoint = 'ws://example.test/events';",
            vec!["LEGACY-JS-SEMGREP-insecure-websocket"],
        ),
        (
            "component.vue",
            "<section v-html=\"content\"></section>",
            vec!["LEGACY-JS-SEMGREP-vue-v-html"],
        ),
    ];
    for (path, source, expected_ids) in cases {
        let findings = pack.scan_text(&Language::JavaScript, Path::new(path), source);
        for expected_id in expected_ids {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == expected_id),
                "{path} is missing {expected_id}: {findings:#?}"
            );
        }
    }

    let wrong_path = pack.scan_text(
        &Language::JavaScript,
        Path::new("view.js"),
        "<%- user.name %>",
    );
    assert!(!wrong_path
        .iter()
        .any(|finding| finding.rule_id == "LEGACY-JS-SEMGREP-ejs-explicit-unescape"));
}

#[test]
fn semgrep_migration_inventory_tracks_search_and_taint_rules() {
    let inventory = bundled_semgrep_rules();
    assert_eq!(
        inventory
            .iter()
            .filter(|rule| rule.language == "javascript")
            .count(),
        185
    );
    assert_eq!(
        inventory
            .iter()
            .filter(|rule| rule.language == "ruby")
            .count(),
        111
    );
    let javascript_taint = inventory
        .iter()
        .filter(|rule| rule.language == "javascript" && rule.mode == "taint")
        .collect::<Vec<_>>();
    assert_eq!(javascript_taint.len(), 64);
    assert!(javascript_taint
        .iter()
        .all(|rule| rule.native_taint_rule_id.is_some() && rule.testcase.is_some()));
    let javascript_search = inventory
        .iter()
        .filter(|rule| rule.language == "javascript" && rule.mode == "search")
        .collect::<Vec<_>>();
    assert_eq!(javascript_search.len(), 121);
    assert!(javascript_search
        .iter()
        .all(|rule| rule.native_rule_id.is_some() && rule.testcase.is_some()));
    let ruby_search = inventory
        .iter()
        .filter(|rule| rule.language == "ruby" && rule.mode == "search")
        .collect::<Vec<_>>();
    assert_eq!(ruby_search.len(), 75);
    assert!(ruby_search
        .iter()
        .all(|rule| rule.native_rule_id.is_some() && rule.testcase.is_some()));
    let ruby_taint = inventory
        .iter()
        .filter(|rule| rule.language == "ruby" && rule.mode == "taint")
        .collect::<Vec<_>>();
    assert_eq!(ruby_taint.len(), 36);
    assert!(ruby_taint
        .iter()
        .all(|rule| rule.native_taint_rule_id.is_some() && rule.testcase.is_some()));
    assert!(inventory.iter().all(|rule| {
        !(rule.native_rule_id.is_some() && rule.native_taint_rule_id.is_some())
            && (rule.native_rule_id.is_some() || rule.native_taint_rule_id.is_some())
                == rule.testcase.is_some()
    }));
    let migrated = inventory
        .iter()
        .filter(|rule| rule.native_rule_id.is_some() || rule.native_taint_rule_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(migrated.len(), 296);
    let pack = builtin_security_pack().expect("built-in pack");
    for rule in migrated {
        assert!(!rule.id.is_empty());
        assert!(
            rule.source.starts_with("semgrep/javascript/")
                || rule.source.starts_with("semgrep/ruby/")
        );
        assert!(rule.testcase.is_some());
        if let Some(native_id) = rule.native_rule_id {
            assert!(pack.rules.iter().any(|candidate| candidate.id == native_id));
        }
        let (file, function) = rule.testcase.unwrap().rsplit_once("::").unwrap();
        let source = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(file),
        )
        .expect("referenced Semgrep testcase must exist");
        assert!(
            source.contains(&format!("fn {function}(")),
            "missing {function}"
        );
        let native_id = rule
            .native_rule_id
            .or(rule.native_taint_rule_id)
            .expect("migrated Semgrep native id");
        if !rule.testcase.unwrap().ends_with("native_compatibility_model")
            && !rule.testcase.unwrap().contains("ruby_semgrep_taint.rs::")
        {
            assert!(
                source.contains(native_id),
                "testcase lacks explicit native rule id {native_id}"
            );
        }
    }
}

#[test]
fn migrated_ruby_semgrep_search_rules_ignore_comments_and_strings() {
    let source = r#"
Rails.application.config.action_dispatch.cookies_serializer = :marshal
syscall(1)
config.serve_static_assets = true
config.force_ssl = false
ActiveSupport.escape_html_entities_in_json = false
attr_protected :secret
accepts_nested_attributes_for :items, allow_destroy: false
OpenSSL::SSL::VERIFY_NONE
http_basic_authenticate_with name: user
ActionController::Base.param_parsers[Mime::YAML] = :yaml
skip_forgery_protection
content_tag(:div, value)
value.html_safe
raw(value)
render inline: template
render text: value
ERB.new(template)
ActiveSupport::XmlMini.backend = "LibXML"
Digest::MD5.hexdigest(value)
OpenSSL::HMAC.digest("sha1", key, value)
# syscall(2)
ignored = "skip_forgery_protection syscall force_ssl = false"
"#;
    let findings = builtin_security_pack().expect("built-in pack").scan_text(
        &Language::Ruby,
        Path::new("security.rb"),
        source,
    );
    for rule_id in [
        "LEGACY-RUBY-SEMGREP-cookie-serialization",
        "LEGACY-RUBY-SEMGREP-dangerous-syscall",
        "LEGACY-RUBY-SEMGREP-file-disclosure",
        "LEGACY-RUBY-SEMGREP-force-ssl-false",
        "LEGACY-RUBY-SEMGREP-json-entity-escape",
        "LEGACY-RUBY-SEMGREP-model-attributes-attr-protected",
        "LEGACY-RUBY-SEMGREP-nested-attributes-bypass",
        "LEGACY-RUBY-SEMGREP-ssl-mode-no-verify",
        "LEGACY-RUBY-SEMGREP-timing-attack",
        "LEGACY-RUBY-SEMGREP-yaml-parsing",
        "LEGACY-RUBY-SEMGREP-skip-forgery-protection",
        "LEGACY-RUBY-SEMGREP-avoid-content-tag",
        "LEGACY-RUBY-SEMGREP-avoid-html-safe",
        "LEGACY-RUBY-SEMGREP-avoid-raw",
        "LEGACY-RUBY-SEMGREP-avoid-render-inline",
        "LEGACY-RUBY-SEMGREP-avoid-render-text",
        "LEGACY-RUBY-SEMGREP-manual-template-creation",
        "LEGACY-RUBY-SEMGREP-libxml-backend",
        "LEGACY-RUBY-SEMGREP-weak-hashes-md5",
        "LEGACY-RUBY-SEMGREP-weak-hashes-sha1",
    ] {
        assert!(
            findings.iter().any(|finding| finding.rule_id == rule_id),
            "missing {rule_id}: {findings:#?}"
        );
    }
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-RUBY-SEMGREP-dangerous-syscall")
            .count(),
        1
    );
}

#[test]
fn migrated_sql_rules_detect_noncompliant_constructs_without_comments() {
    let source = r#"
declare
  name varchar(20);
begin
  if enabled = true then null; end if;
  if value = null then null; end if;
  dbms_output.put_line(name);
  name := '';
  if left_value != right_value then null; end if;
  insert into users values (1, 'name');
  select * from users;
  day := to_date('2026-09-03');
  if name like 'Smith' then null; end if;
  fallback := nvl(name, '');
  select empno from emp order by to_char(empno);
  -- select * from ignored;
end;
"#;
    let findings = builtin_security_pack().expect("built-in pack").scan_text(
        &Language::Sql,
        Path::new("legacy.sql"),
        source,
    );
    for suffix in [
        "CharacterDatatypeUsage",
        "ComparisonWithBoolean",
        "ComparisonWithNull",
        "DbmsOutputPut",
        "EmptyStringAssignment",
        "InequalityUsage",
        "InsertWithoutColumns",
        "SelectAllColumns",
        "ToDateWithoutFormat",
        "UnnecessaryLike",
        "NvlWithNullParameter",
        "ToCharInOrderBy",
    ] {
        let rule_id = format!("LEGACY-SQL-{suffix}");
        assert!(
            findings.iter().any(|finding| finding.rule_id == rule_id),
            "missing {rule_id}: {findings:#?}"
        );
    }
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "LEGACY-SQL-SelectAllColumns")
            .count(),
        1
    );
}

#[test]
fn sql_migration_inventory_is_source_backed_and_tested() {
    let inventory = bundled_sql_rules();
    assert_eq!(inventory.len(), 54);
    assert!(inventory.iter().all(|rule| {
        !rule.id.is_empty()
            && rule.source.starts_with("sql/")
            && rule.source.ends_with(".md")
            && rule.native_rule_id.is_some() == rule.testcase.is_some()
    }));
    let migrated = inventory
        .iter()
        .filter(|rule| rule.native_rule_id.is_some())
        .collect::<Vec<_>>();
    assert_eq!(migrated.len(), 54);
    let pack = builtin_security_pack().expect("built-in pack");
    for rule in migrated {
        assert!(rule.testcase.is_some());
        assert!(pack
            .rules
            .iter()
            .any(|candidate| { Some(candidate.id.as_str()) == rule.native_rule_id }));
    }
}
