//! Proves the new `uniflow_lang_go` frontend's qualifier mechanism fires
//! against REAL content from `rules/legacy/go-taint.yml` (1733 rules) when
//! driven through the compiled `uniflow` binary end to end — mirroring
//! `javascript_taint_bundled_rules.rs`'s structure/scale for the JS
//! frontend.
//!
//! `--rule-id` filters `RuleSet::retain_reportable_ids` against a rule's own
//! `id:` field from the `sources:`/`sinks:` blocks (confirmed against
//! `crates/rules/src/lib.rs`'s `retain_reportable_ids`, which builds its
//! "known id" set from `self.sources`/`self.sinks` — NOT from a separate
//! `metadata:`-block id namespace; in this pack the same id string is
//! reused for both, e.g. `legacy.go.sink.16.0.0` names the executable sink
//! rule (in `sinks:`) and its metadata (title/message) entry alike).
//!
//! `retain_reportable_ids` also keeps every SOURCE unconditionally whenever
//! the pack declares no `model_dependencies` closure for the requested ids
//! (true for `go-taint.yml`, which has none) — so passing only a sink id
//! still lets every real source in the pack fire, exactly like
//! `javascript_taint_bundled_rules.rs`'s sink-only tests already rely on.
//! In practice this also means a single real call site (e.g.
//! `r.FormValue(...)`) matches SEVERAL sibling source rules that share an
//! identical matcher but tag a different `kind` (`legacy.go.source.0.0.web`
//! *and* `legacy.go.source.0.0.xss` both match the exact same call) — each
//! produces its own finding for the same sink. Assertions below therefore
//! check for the specific (source, sink) PAIR this frontend is meant to
//! prove, rather than asserting a sink's total finding count is exactly
//! one.
//!
//! Every fixture exercises one of the two qualifier mechanisms this
//! frontend depends on: a `Selector` off a package name bound by `import`
//! (`os.Getenv`, `exec.Command`) or a `Selector` off a value whose
//! *declared parameter type* resolved to a qualified name (`r *http.Request`
//! -> `r.FormValue(...)` -> `net/http.Request.FormValue`) — the latter is
//! the single most important case, since it's structurally what the real
//! rule catalog depends on for every `net/http`/`database/sql`-shaped rule.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bundled_findings(source: &str, rule_ids: &[&str]) -> Vec<serde_json::Value> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let scratch = Scratch(std::env::temp_dir().join(format!("uniflow-go-taint-{}-{unique}", std::process::id())));
    std::fs::create_dir(&scratch.0).unwrap();
    let fixture = scratch.0.join("taint.go");
    std::fs::write(&fixture, source).unwrap();
    let binary = scratch.0.join(if cfg!(windows) { "uniflow.exe" } else { "uniflow" });
    std::fs::copy(env!("CARGO_BIN_EXE_uniflow"), &binary).unwrap();
    assert!(!scratch.0.join("rules").exists());

    let mut command = Command::new(&binary);
    command.current_dir(&scratch.0).args(["analyze-source", "--language", "go", "--use-default-models"]);
    for rule_id in rule_ids {
        command.args(["--rule-id", rule_id]);
    }
    let output = command.args(["--input"]).arg(&fixture).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
}

/// Asserts that exactly one finding pairs `source_id` with `sink_id` (a
/// sibling source rule sharing the same real-world call site but a
/// different `kind` tag may ALSO legitimately fire for the same sink — see
/// the module-level docs — so this deliberately filters on the pair, not
/// the sink alone), and that it completed analysis.
fn assert_source_reaches_sink(findings: &[serde_json::Value], source_id: &str, sink_id: &str) {
    let matching = findings.iter().filter(|finding| finding["sink_rule_id"] == sink_id && finding["source_rule_id"] == source_id).collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "expected exactly one ({source_id} -> {sink_id}) finding: {findings:#?}");
    assert!(matching[0]["analysis_complete"] == true, "{findings:#?}");
}

#[test]
fn typed_http_request_form_value_flows_into_exec_command() {
    // The single most important case: `legacy.go.source.0.0.web` matches a
    // qualified callee of `net/http.Request.FormValue` — reachable ONLY if
    // `r`'s declared `*http.Request` parameter type resolved to
    // `net/http.Request`, then combined with the called method's own name.
    let source_id = "legacy.go.source.0.0.web";
    let sink_id = "legacy.go.sink.16.0.0";
    let findings = bundled_findings(
        r#"
package main

import (
	"net/http"
	"os/exec"
)

func handle(r *http.Request) {
	cmd := r.FormValue("cmd")
	exec.Command(cmd)
	exec.Command("fixed-binary")
}
"#,
        &[source_id, sink_id],
    );
    assert_source_reaches_sink(&findings, source_id, sink_id);
}

#[test]
fn os_getenv_flows_into_exec_command_context() {
    let source_id = "legacy.go.source.1.0.environment";
    let sink_id = "legacy.go.sink.17.0.0";
    let findings = bundled_findings(
        r#"
package main

import (
	"os"
	"os/exec"
)

func run() {
	cmd := os.Getenv("CMD")
	exec.CommandContext(nil, cmd)
	exec.CommandContext(nil, "fixed")
}
"#,
        &[source_id, sink_id],
    );
    assert_source_reaches_sink(&findings, source_id, sink_id);
}

#[test]
fn os_getenv_flows_into_a_typed_database_sql_receiver_query() {
    // `db *sql.DB` -> `db.Query(...)`: the SAME typed-parameter mechanism as
    // the `net/http.Request` case above, exercised against a second
    // stdlib package (`database/sql`).
    let source_id = "legacy.go.source.1.0.environment";
    let sink_id = "legacy.go.sink.13.0.0";
    let findings = bundled_findings(
        r#"
package main

import (
	"database/sql"
	"os"
)

func run(db *sql.DB) {
	query := os.Getenv("QUERY")
	db.Query(query)
	db.Query("SELECT 1")
}
"#,
        &[source_id, sink_id],
    );
    assert_source_reaches_sink(&findings, source_id, sink_id);
}

// NOTE: `legacy.go.source.57.0.network` (`encoding/json.NewDecoder`) and
// `legacy.go.sink.0.0.0` (`html`/`html/template` `Escape`-family functions)
// are deliberately NOT exercised here. Both resolve to the exact right
// qualified callee name (confirmed via `--dump-hir`) and both fire
// correctly in isolation (a hand-built two-rule YAML reproduces the same
// fixture and DOES produce a finding), but consistently produce ZERO
// findings once loaded as part of the REAL, full 1733-rule
// `rules/legacy/go-taint.yml` catalog — with or without `--rule-id`
// narrowing. This reproduces with plain `--rules rules/legacy/go-taint.yml`
// too, so it is a pre-existing `crates/value_flow`/`crates/rules` engine
// interaction at catalog scale, not a `uniflow_lang_go` frontend defect;
// out of scope here per this task's own guidance to note, not chase, a
// pre-existing orthogonal rule-loading/filtering issue.

#[test]
fn os_getenv_flows_into_os_mkdir_and_crypto_rc4_newcipher() {
    let source_id = "legacy.go.source.1.0.environment";
    let mkdir_sink = "legacy.go.sink.3.0.0";
    let rc4_sink = "legacy.go.sink.329.0.0";
    let findings = bundled_findings(
        r#"
package main

import (
	"crypto/rc4"
	"os"
)

func run() {
	path := os.Getenv("PATH_VALUE")
	os.Mkdir(path, 0755)
	os.Mkdir("fixed", 0755)

	key := os.Getenv("KEY")
	rc4.NewCipher(key)
	rc4.NewCipher("fixed-key")
}
"#,
        &[source_id, mkdir_sink, rc4_sink],
    );
    assert_source_reaches_sink(&findings, source_id, mkdir_sink);
    assert_source_reaches_sink(&findings, source_id, rc4_sink);
}

#[test]
fn a_package_level_zero_import_helper_still_reaches_a_bundled_sink() {
    // Proves the cross-file/package-scope qualified-naming convention
    // (`decl::lower_file`'s pass 0/`project_index`) doesn't interfere with
    // ordinary single-file bundled-rule matching: a same-file helper
    // function is called with zero qualifier, and the real sink is still
    // reached through it.
    let source_id = "legacy.go.source.1.0.environment";
    let sink_id = "legacy.go.sink.16.0.0";
    let findings = bundled_findings(
        r#"
package main

import (
	"os"
	"os/exec"
)

func runCommand(cmd string) {
	exec.Command(cmd)
}

func handle() {
	value := os.Getenv("CMD")
	runCommand(value)
	runCommand("fixed")
}
"#,
        &[source_id, sink_id],
    );
    assert_source_reaches_sink(&findings, source_id, sink_id);
}
