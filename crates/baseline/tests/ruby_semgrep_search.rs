use std::collections::HashMap;

use uniflow_baseline::builtin_security_pack;
use uniflow_hir::Language;

#[test]
fn migrated_ruby_structural_search_rules_preserve_argument_and_assignment_semantics() {
    let source = r#"
require 'jwt'
def audit(command, dynamic_backend, params, other)
  open(command)
  open(1)
  open("fixed")
  other.open(command)

  Open3.pipeline(command)
  Open3.pipeline(command, "fixed")
  Other.pipeline(command)

  accepts_nested_attributes_for :items

  XmlMini.backend = dynamic_backend
  XmlMini.backend = "Nokogiri"
  XmlMini.backend = "REXML"
  other.backend = dynamic_backend

  params.permit(:admin)
  params.permit(:account_id)
  params.permit(:role)
  params.permit(:banned)
  params.permit(:name)
  permit(:admin)

  JWT.decode(params, dynamic_backend, false)
  JWT.decode(params, dynamic_backend, true)
  JWT.encode(params, dynamic_backend, "none")
  JWT.encode(params, dynamic_backend, "HS256")
  JWT.encode(params, "hardcoded", "HS256")
  hardcoded_secret = "assigned-secret"
  JWT.decode(params, hardcoded_secret, true)
  JWT.encode(params, nil, "HS256")
  JWT.encode("fixed-payload", dynamic_backend, "HS256")
  Other.encode(params, "hardcoded", "none")
end
"#;
    let path = "security.rb";
    let program = uniflow_lang_frontends::parse_file(Language::Ruby, path, source)
        .expect("Ruby fixture must parse");
    let findings = builtin_security_pack().expect("built-in pack").scan_hir(
        &program,
        &HashMap::from([(path.to_owned(), source.to_owned())]),
    );

    for (rule_id, expected) in [
        ("LEGACY-RUBY-SEMGREP-dangerous-open", 2),
        ("LEGACY-RUBY-SEMGREP-dangerous-open3-pipeline", 1),
        ("LEGACY-RUBY-SEMGREP-nested-attributes", 1),
        ("LEGACY-RUBY-SEMGREP-jruby-xml", 2),
        ("LEGACY-RUBY-SEMGREP-check-permit-attributes-high", 2),
        ("LEGACY-RUBY-SEMGREP-check-permit-attributes-medium", 2),
        ("LEGACY-RUBY-SEMGREP-ruby-jwt-decode-without-verify", 1),
        ("LEGACY-RUBY-SEMGREP-ruby-jwt-none-alg", 1),
        ("LEGACY-RUBY-SEMGREP-ruby-jwt-hardcoded-secret", 3),
        ("LEGACY-RUBY-SEMGREP-ruby-jwt-exposed-data", 4),
    ] {
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .count(),
            expected,
            "unexpected findings for {rule_id}: {findings:#?}"
        );
    }
}
