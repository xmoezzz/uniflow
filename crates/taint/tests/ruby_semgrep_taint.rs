use uniflow_frontend::parse_source;
use uniflow_hir::Language;
use uniflow_lowering::lower_program;
use uniflow_models::legacy_models_for;
use uniflow_rules::RuleSet;
use uniflow_taint::analyze;
use uniflow_value_flow::build;

const PREFIX: &str = "LEGACY-RUBY-SEMGREP-TAINT-";

fn findings_for(rule: &str, source: &str) -> Vec<uniflow_taint::TaintFinding> {
    let id = format!("{PREFIX}{rule}");
    let mut rules = legacy_models_for(Language::Ruby).expect("bundled Ruby taint models");
    rules
        .retain_reportable_ids(std::slice::from_ref(&id))
        .expect("select Ruby rule");
    let hir = parse_source(Language::Ruby, "rule.rb", source).expect("parse Ruby testcase");
    let graph = build(&lower_program(&hir), &rules);
    analyze(&graph, &rules)
        .into_iter()
        .filter(|finding| finding.sink_rule_id == id)
        .collect()
}

#[test]
fn every_ruby_semgrep_call_and_composition_taint_rule_executes() {
    let cases = [
        ("aws-activerecord-sqli", "def h(event, context)\n ActiveRecord::Base.connection.execute(event)\nend"),
        ("aws-mysql2-sqli", "def h(event, context)\n client.query(event)\nend"),
        ("aws-pg-sqli", "def h(event, context)\n connection.exec_params(event)\nend"),
        ("aws-sequel-sqli", "def h(event, context)\n DB.run(event)\nend"),
        ("aws-tainted-deserialization", "def h(event, context)\n Marshal.load(event)\nend"),
        ("aws-tainted-sql-string", "def h(event, context)\n query = \"SELECT #{event}\"\nend"),
        ("bad-deserialization", "def h\n Marshal.load(params[:body])\nend"),
        ("dangerous-exec", "def h(command)\n Process.spawn(command)\nend"),
        ("json-encoding", "def h\n params[:user].to_json\nend"),
        ("md5-used-as-password", "def h(user, input)\n user.set_password(Digest::MD5.hexdigest(input))\nend"),
        ("ruby-eval", "def h\n eval(params[:code])\nend"),
        ("rails-no-render-after-save", "def h\n article.save\n render(article)\nend"),
        ("avoid-tainted-file-access", "def h\n File.open(params[:path])\nend"),
        ("avoid-tainted-ftp-call", "def h\n Net::FTP.open(params[:host])\nend"),
        ("avoid-tainted-http-request", "def h\n Net::HTTP.get(params[:url])\nend"),
        ("avoid-tainted-shell-call", "def h\n Shell.open(params[:path])\nend"),
        ("dynamic-finders", "def h\n User.find_by_token(params[:token])\nend"),
        ("number-to-currency", "def h\n number_to_currency(1.0, unit: params[:currency])\nend"),
        ("quote-table-name", "def h\n quote_table_name(params[:table])\nend"),
        ("ruby-pg-sqli", "def h\n connection.exec(params[:query])\nend"),
        ("avoid-link-to", "def h\n link_to(params[:url], profile_path())\nend"),
        ("avoid-redirect", "def h\n redirect_to(params[:url])\nend"),
        ("avoid-render-dynamic-path", "def h\n render(action: params[:action])\nend"),
        ("check-redirect-to", "def h\n redirect_to(params[:host])\nend"),
        ("check-regex-dos", "def h\n Regexp.new(params[:regex])\nend"),
        ("check-render-local-file-include", "def h\n render(file: params[:page])\nend"),
        ("check-send-file", "def h\n send_file(params[:file])\nend"),
        ("check-sql", "def h\n Product.where(params[:clause])\nend"),
        ("check-unsafe-reflection-methods", "def h\n Kernel.method(params[:method])\nend"),
        ("check-unsafe-reflection", "def h\n params[:klass].constantize\nend"),
        ("check-unscoped-find", "def h\n User.find(params[:id])\nend"),
        ("raw-html-format", "def h\n body = \"<div>#{params[:name]}</div>\"\nend"),
        ("rails-tainted-sql-string", "def h\n User.where(\"id = #{params[:id]}\")\nend"),
        ("tainted-url-host", "def h\n url = \"https://#{params[:host]}/path\"\nend"),
    ];
    for (rule, source) in cases {
        let findings = findings_for(rule, source);
        assert!(
            !findings.is_empty(),
            "Ruby rule {rule} did not execute for its positive testcase"
        );
        assert!(findings.iter().all(|finding| finding.analysis_complete));
    }
}

#[test]
fn ruby_index_taint_rules_match_only_the_named_read_base() {
    let session = findings_for(
        "avoid-session-manipulation",
        "def h\n value = session[params[:key]]\n safe = cache[params[:key]]\nend",
    );
    assert_eq!(session.len(), 1, "session key must be the only matching read");

    let sequel = findings_for(
        "aws-sequel-sqli",
        "def h(event, context)\n bad = DB[event]\n safe = CACHE[event]\nend",
    );
    assert_eq!(sequel.len(), 1, "DB query index must be the only matching read");
}

#[test]
fn ruby_divide_by_zero_uses_integer_constant_flow_and_zero_denominator() {
    let findings = findings_for(
        "divide-by-zero",
        "def h\n integer = 3\n zero = 0\n bad = integer / zero\n safe_float = 1.0 / zero\n safe_divisor = integer / 2\nend",
    );
    assert_eq!(findings.len(), 1, "only integer division by zero is reportable");
}

#[test]
fn ruby_frontend_preserves_security_api_callee_names() {
    let source = r#"
def handler(event, context)
  ActiveRecord::Base.connection.execute(event)
  client.query(event)
  PG::Connection.open(event)
  Net::HTTP.get(event)
  File.open(event)
  Process.spawn(event)
  user.set_password(Digest::MD5.hexdigest(event))
  redirect_to(event)
  event.to_json
  query = "SELECT #{event}"
  number_to_currency(1.0, unit: params[:currency])
end
"#;
    let hir = parse_source(Language::Ruby, "security_apis.rb", source).expect("parse Ruby APIs");
    let ir = lower_program(&hir);
    let graph = build(&ir, &RuleSet::default());
    let names = graph
        .call_report()
        .into_iter()
        .filter_map(|call| call.callee_name)
        .collect::<Vec<_>>();
    for suffix in [
        "execute",
        "query",
        "open",
        "get",
        "spawn",
        "set_password",
        "hexdigest",
        "redirect_to",
        "to_json",
        "__uniflow.compose.string",
    ] {
        assert!(
            names.iter().any(|name| name.ends_with(suffix)),
            "missing {suffix}: {names:#?}"
        );
    }
}
