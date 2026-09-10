use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const CASES: &[(&str, &str)] = &[
    (
        "aws-activerecord-sqli",
        "def h(event, context)\n ActiveRecord::Base.connection.execute(event)\nend",
    ),
    (
        "aws-mysql2-sqli",
        "def h(event, context)\n client.query(event)\nend",
    ),
    (
        "aws-pg-sqli",
        "def h(event, context)\n connection.exec_params(event)\nend",
    ),
    (
        "aws-sequel-sqli",
        "def h(event, context)\n DB.run(event)\nend",
    ),
    (
        "aws-tainted-deserialization",
        "def h(event, context)\n Marshal.load(event)\nend",
    ),
    (
        "aws-tainted-sql-string",
        "def h(event, context)\n sql = \"SELECT #{event}\"\nend",
    ),
    (
        "bad-deserialization",
        "def h\n Marshal.load(params[:body])\nend",
    ),
    (
        "dangerous-exec",
        "def h(command)\n Process.spawn(command)\nend",
    ),
    (
        "divide-by-zero",
        "def h\n integer = 3\n zero = 0\n result = integer / zero\nend",
    ),
    ("json-encoding", "def h\n params[:user].to_json\nend"),
    (
        "md5-used-as-password",
        "def h(user, input)\n user.set_password(Digest::MD5.hexdigest(input))\nend",
    ),
    ("ruby-eval", "def h\n eval(params[:code])\nend"),
    (
        "rails-no-render-after-save",
        "def h\n article.save\n render(article)\nend",
    ),
    (
        "avoid-session-manipulation",
        "def h\n value = session[params[:key]]\nend",
    ),
    (
        "avoid-tainted-file-access",
        "def h\n File.open(params[:path])\nend",
    ),
    (
        "avoid-tainted-ftp-call",
        "def h\n Net::FTP.open(params[:host])\nend",
    ),
    (
        "avoid-tainted-http-request",
        "def h\n Net::HTTP.get(params[:url])\nend",
    ),
    (
        "avoid-tainted-shell-call",
        "def h\n Shell.open(params[:path])\nend",
    ),
    (
        "dynamic-finders",
        "def h\n User.find_by_token(params[:token])\nend",
    ),
    (
        "number-to-currency",
        "def h\n number_to_currency(1.0, unit: params[:currency])\nend",
    ),
    (
        "quote-table-name",
        "def h\n quote_table_name(params[:table])\nend",
    ),
    (
        "ruby-pg-sqli",
        "def h\n connection.exec(params[:query])\nend",
    ),
    (
        "avoid-link-to",
        "def h\n link_to(params[:url], profile_path())\nend",
    ),
    ("avoid-redirect", "def h\n redirect_to(params[:url])\nend"),
    (
        "avoid-render-dynamic-path",
        "def h\n render(action: params[:action])\nend",
    ),
    (
        "check-redirect-to",
        "def h\n redirect_to(params[:host])\nend",
    ),
    ("check-regex-dos", "def h\n Regexp.new(params[:regex])\nend"),
    (
        "check-render-local-file-include",
        "def h\n render(file: params[:page])\nend",
    ),
    ("check-send-file", "def h\n send_file(params[:file])\nend"),
    ("check-sql", "def h\n Product.where(params[:clause])\nend"),
    (
        "check-unsafe-reflection-methods",
        "def h\n Kernel.method(params[:method])\nend",
    ),
    (
        "check-unsafe-reflection",
        "def h\n params[:klass].constantize\nend",
    ),
    ("check-unscoped-find", "def h\n User.find(params[:id])\nend"),
    (
        "raw-html-format",
        "def h\n html = \"<div>#{params[:name]}</div>\"\nend",
    ),
    (
        "rails-tainted-sql-string",
        "def h\n User.where(\"id = #{params[:id]}\")\nend",
    ),
    (
        "tainted-url-host",
        "def h\n url = \"https://#{params[:host]}/path\"\nend",
    ),
];

fn assert_rules_execute_from_isolated_binary(cases: &[(&str, &str)]) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "uniflow-ruby-taint-{}-{unique}",
        std::process::id()
    )));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("ruby-taint.rb");
    let binary = scratch.0.join(if cfg!(windows) {
        "uniflow.exe"
    } else {
        "uniflow"
    });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());

    for (rule, source) in cases {
        std::fs::write(&fixture, source).unwrap();
        let expected = format!("LEGACY-RUBY-SEMGREP-TAINT-{rule}");
        let output = Command::new(&binary)
            .current_dir(&scratch.0)
            .args([
                "analyze-source",
                "--language",
                "ruby",
                "--use-default-models",
                "--rule-id",
                &expected,
                "--input",
            ])
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{expected}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| {
                panic!(
                    "{expected}: {error}: {}",
                    String::from_utf8_lossy(&output.stdout)
                )
            });
        let actual = findings
            .iter()
            .filter_map(|finding| finding["sink_rule_id"].as_str())
            .collect::<HashSet<_>>();
        assert!(
            actual.contains(expected.as_str()),
            "missing {expected}: {actual:#?}"
        );
        assert!(findings
            .iter()
            .all(|finding| finding["analysis_complete"] == true));
    }
}

#[test]
fn ruby_semgrep_taint_rules_01_09_execute_from_isolated_binary() {
    assert_rules_execute_from_isolated_binary(&CASES[..9]);
}

#[test]
fn ruby_semgrep_taint_rules_10_18_execute_from_isolated_binary() {
    assert_rules_execute_from_isolated_binary(&CASES[9..18]);
}

#[test]
fn ruby_semgrep_taint_rules_19_27_execute_from_isolated_binary() {
    assert_rules_execute_from_isolated_binary(&CASES[18..27]);
}

#[test]
fn ruby_semgrep_taint_rules_28_36_execute_from_isolated_binary() {
    assert_rules_execute_from_isolated_binary(&CASES[27..]);
}
