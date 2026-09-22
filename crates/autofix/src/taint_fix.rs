//! Stage 4/5 (智能修复/结果核验) for taint/SAST findings — the counterpart to
//! `apply_dependency_fix` for the class of findings that has no mechanical
//! template (a SQL-injection sink isn't a version number to bump). The only
//! path here is an explicitly-configured LLM draft, reusing
//! `uniflow_reasoning_oracle::LlmOracle` exactly as `crates/cli`'s
//! `ReviewCode` command does: never constructed implicitly, always an
//! explicit endpoint/key/model the caller supplies. A drafted fix is never
//! trusted on its own say-so — it's applied to the real file, then the same
//! deterministic scan used for detection (`uniflow_core::scan_source_paths`)
//! re-runs over that file; if the original finding (or any new one) is
//! still there, the file is rolled back to its original content and the
//! fix is reported unresolved.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use uniflow_reasoning_oracle::{LlmOracle, LlmOracleConfig, Oracle, SemanticQuery};

/// The minimal, source-agnostic description of a taint/checker finding a
/// caller needs to request a fix for. Deliberately not `TaintFinding`
/// itself — the caller (an embedding adapter like `cosmos-agent`) already
/// has one and extracts these fields; keeping this crate free of a
/// dependency on `uniflow-taint`'s much larger type keeps the fix path
/// usable for `CheckerFinding`-shaped input too.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SourceFinding {
    pub path: String,
    pub line: usize,
    pub rule_id: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LlmFixConfig {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// How many lines of context above/below the finding's line to show
    /// the LLM and allow it to rewrite. A vulnerability rarely fits on
    /// exactly one line (the taint source may be a few lines up), but a
    /// wide window risks the model rewriting unrelated code.
    #[serde(default = "default_context_lines")]
    pub context_lines: usize,
}

fn default_timeout_ms() -> u64 {
    15_000
}

fn default_context_lines() -> usize {
    3
}

#[derive(Debug, Clone, Serialize)]
pub struct TaintFixResult {
    pub diff: String,
    /// 1-indexed line number of the first line in `original_snippet`/
    /// `updated_snippet`, so a caller can render both with correct line
    /// numbers instead of always starting from 1.
    pub start_line: usize,
    /// The context window as it was before the fix — same lines the LLM
    /// was shown, kept even when `resolved` is false so a caller can still
    /// show what was attempted.
    pub original_snippet: String,
    /// The context window after the fix. Equal to `original_snippet` when
    /// `resolved` is false (the file was rolled back, so nothing changed).
    pub updated_snippet: String,
    pub language: String,
    pub explanation: String,
    pub confidence: f32,
    pub resolved: bool,
    pub remaining_findings: usize,
    pub note: Option<String>,
}

pub fn apply_taint_fix_and_reverify(finding: &SourceFinding, config: &LlmFixConfig) -> Result<TaintFixResult> {
    let path = Path::new(&finding.path);
    let original = std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let lines: Vec<&str> = original.lines().collect();
    anyhow::ensure!(
        finding.line >= 1 && finding.line <= lines.len(),
        "finding line {} is out of range for {} ({} lines)",
        finding.line,
        path.display(),
        lines.len()
    );

    let start = finding.line.saturating_sub(1 + config.context_lines);
    let end = (finding.line - 1 + config.context_lines).min(lines.len().saturating_sub(1));
    let window_text = lines[start..=end].join("\n");
    let language = language_from_extension(path);

    let mut oracle_config = LlmOracleConfig::new(&config.endpoint, &config.api_key, &config.model);
    oracle_config.timeout = Duration::from_millis(config.timeout_ms.clamp(1, 120_000));
    let oracle = LlmOracle::new(oracle_config);

    let question = format!(
        "This code has a {} finding (CWE: {}): {}\n\n\
         Rewrite the ENTIRE snippet above into a corrected version that removes the vulnerability \
         while preserving its behavior for legitimate input.\n\n\
         Put the full corrected snippet, and ONLY the corrected snippet, directly in the top-level \
         \"answer\" field as a plain string — do not JSON-encode it again inside \"answer\", and do not \
         wrap it in markdown code fences. The \"rationale\" field must explain what changed and why it \
         fixes the vulnerability.",
        finding.rule_id,
        if finding.cwe.is_empty() { "none".to_string() } else { finding.cwe.join(", ") },
        finding.message,
    );
    let answer = oracle
        .interpret_semantics(&SemanticQuery { language: language.clone(), code_snippet: window_text.clone(), question })
        .map_err(|error| anyhow::anyhow!("LLM fix drafting failed: {error}"))?;
    let replacement = strip_markdown_fence(answer.answer.trim());
    anyhow::ensure!(!replacement.trim().is_empty(), "LLM returned an empty replacement");

    let mut new_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    new_lines.splice(start..=end, replacement.lines().map(str::to_string));
    let updated = new_lines.join("\n") + if original.ends_with('\n') { "\n" } else { "" };

    let diff = format!(
        "--- {}\n@@ lines {}-{} @@\n{}\n+++ replacement\n{}",
        path.display(),
        start + 1,
        end + 1,
        window_text,
        replacement
    );

    std::fs::write(path, &updated).with_context(|| format!("failed to write {}", path.display()))?;

    let rescan = uniflow_core::scan_source_paths(&[path.to_path_buf()]);
    let still_present = match &rescan {
        Ok(outcome) => outcome
            .taint_findings
            .iter()
            .any(|f| f.sink_rule_id == finding.rule_id || f.source_rule_id == finding.rule_id),
        Err(_) => true, // a re-scan failure (e.g. the drafted replacement doesn't parse) counts as unresolved, not a false "fixed"
    };

    if still_present {
        std::fs::write(path, &original).with_context(|| format!("failed to roll back {}", path.display()))?;
        return Ok(TaintFixResult {
            diff,
            start_line: start + 1,
            original_snippet: window_text.clone(),
            updated_snippet: window_text,
            language,
            explanation: answer.rationale,
            confidence: answer.confidence,
            resolved: false,
            remaining_findings: rescan.map(|o| o.taint_findings.len()).unwrap_or(0),
            note: Some("the drafted fix did not clear the finding on re-scan; the file was rolled back to its original content".to_string()),
        });
    }

    Ok(TaintFixResult {
        diff,
        start_line: start + 1,
        original_snippet: window_text,
        updated_snippet: replacement,
        language,
        explanation: answer.rationale,
        confidence: answer.confidence,
        resolved: true,
        remaining_findings: 0,
        note: None,
    })
}

/// Defensive cleanup for models that wrap the answer in a markdown code
/// fence despite being told not to (real local models do this often enough
/// that relying on instruction-following alone isn't enough) — strips a
/// leading ```lang / trailing ``` pair if present, otherwise returns the
/// text unchanged.
fn strip_markdown_fence(text: &str) -> String {
    let trimmed = text.trim();
    let Some(after_open) = trimmed.strip_prefix("```") else { return trimmed.to_string() };
    // Skip an optional language tag right after the opening fence (```python\n...).
    let body = match after_open.find('\n') {
        Some(newline_idx) if after_open[..newline_idx].chars().all(|c| c.is_alphanumeric()) => &after_open[newline_idx + 1..],
        _ => after_open,
    };
    match body.rfind("```") {
        Some(close_idx) => body[..close_idx].trim_end().to_string(),
        None => body.trim_end().to_string(),
    }
}

pub fn language_from_extension(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("py") => "python",
        Some("js" | "jsx" | "mjs") => "javascript",
        Some("ts" | "tsx") => "typescript",
        Some("java") => "java",
        Some("go") => "go",
        Some("rb") => "ruby",
        Some("php") => "php",
        Some("cs") => "csharp",
        Some("c" | "h") => "c",
        Some("cpp" | "cc" | "hpp") => "cpp",
        _ => "unknown",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_on_an_out_of_range_line() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.py");
        std::fs::write(&file, "x = 1\n").unwrap();
        let finding = SourceFinding {
            path: file.display().to_string(),
            line: 50,
            rule_id: "py-db-exec".to_string(),
            cwe: vec!["CWE-89".to_string()],
            message: "sql injection".to_string(),
        };
        let config = LlmFixConfig {
            endpoint: "https://example.invalid".to_string(),
            api_key: "key".to_string(),
            model: "model".to_string(),
            timeout_ms: 1000,
            context_lines: 3,
        };
        let result = apply_taint_fix_and_reverify(&finding, &config);
        assert!(result.is_err());
    }

    #[test]
    fn language_from_extension_covers_common_cases() {
        assert_eq!(language_from_extension(Path::new("app.py")), "python");
        assert_eq!(language_from_extension(Path::new("app.go")), "go");
        assert_eq!(language_from_extension(Path::new("app.unknownext")), "unknown");
    }

    #[test]
    fn strip_markdown_fence_removes_a_language_tagged_fence() {
        assert_eq!(strip_markdown_fence("```python\nx = 1\ny = 2\n```"), "x = 1\ny = 2");
    }

    #[test]
    fn strip_markdown_fence_removes_a_bare_fence() {
        assert_eq!(strip_markdown_fence("```\nx = 1\n```"), "x = 1");
    }

    #[test]
    fn strip_markdown_fence_leaves_unfenced_text_untouched() {
        assert_eq!(strip_markdown_fence("x = 1\ny = 2"), "x = 1\ny = 2");
    }

    /// Starts a one-shot mock OpenAI-compatible chat-completions endpoint on
    /// an ephemeral port that answers every request with `answer_json`
    /// wrapped as the SemanticAnswer's `answer` field — real, in-process,
    /// no network egress, no external test-server dependency.
    fn spawn_mock_llm(replacement: &str) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let answer_payload = serde_json::json!({
            "answer": replacement,
            "confidence": 0.9,
            "rationale": "removed the tainted value from the sink call",
        });
        let openai_body = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": answer_payload.to_string() } }]
        })
        .to_string();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 16384];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    openai_body.len(),
                    openai_body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        format!("http://{addr}/v1/chat/completions")
    }

    const VULNERABLE_FLASK_APP: &str = r#"import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "ok"
"#;

    fn flask_finding(path: &std::path::Path) -> SourceFinding {
        SourceFinding {
            path: path.display().to_string(),
            line: 10,
            rule_id: "python-os-system".to_string(),
            cwe: vec!["CWE-78".to_string()],
            message: "Taint reaches sink 'python-os-system' from source 'python-flask-request-args-get'".to_string(),
        }
    }

    #[test]
    fn a_genuine_fix_clears_the_finding_on_reverify_and_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.py");
        std::fs::write(&file, VULNERABLE_FLASK_APP).unwrap();

        // Breaks the taint flow for real: the sink no longer receives the
        // tainted `cmd` value at all.
        let fixed_snippet = "@app.route(\"/run\")\ndef run_command():\n    cmd = request.args.get(\"cmd\")\n    os.system(\"echo safe\")\n    return \"ok\"";
        let endpoint = spawn_mock_llm(fixed_snippet);

        let finding = flask_finding(&file);
        let config = LlmFixConfig { endpoint, api_key: "test-key".to_string(), model: "test-model".to_string(), timeout_ms: 5000, context_lines: 3 };

        let result = apply_taint_fix_and_reverify(&finding, &config).expect("fix request should succeed");
        assert!(result.resolved, "{result:?}");
        assert_eq!(result.remaining_findings, 0);

        let on_disk = std::fs::read_to_string(&file).unwrap();
        assert!(on_disk.contains("echo safe"), "the accepted fix should be kept on disk");
        assert!(!on_disk.contains("os.system(cmd)"), "the vulnerable call should be gone");
    }

    #[test]
    fn a_cosmetic_non_fix_is_rolled_back_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.py");
        std::fs::write(&file, VULNERABLE_FLASK_APP).unwrap();

        // Renames the variable but still passes the tainted value straight
        // into the sink — a real scanner must still flag this.
        let cosmetic_snippet =
            "@app.route(\"/run\")\ndef run_command():\n    user_cmd = request.args.get(\"cmd\")\n    os.system(user_cmd)\n    return \"ok\"";
        let endpoint = spawn_mock_llm(cosmetic_snippet);

        let finding = flask_finding(&file);
        let config = LlmFixConfig { endpoint, api_key: "test-key".to_string(), model: "test-model".to_string(), timeout_ms: 5000, context_lines: 3 };

        let result = apply_taint_fix_and_reverify(&finding, &config).expect("fix request should succeed");
        assert!(!result.resolved, "{result:?}");
        assert!(result.note.is_some());

        let on_disk = std::fs::read_to_string(&file).unwrap();
        assert_eq!(on_disk, VULNERABLE_FLASK_APP, "an unresolved fix must roll back to the exact original bytes");
    }
}
