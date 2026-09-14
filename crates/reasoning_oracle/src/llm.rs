//! An [`crate::Oracle`] backend that delegates all three query shapes to an
//! external LLM API. This is the "semantic understanding" complement to
//! [`crate::LeanOracle`]'s formal decision procedures — it can attempt
//! [`crate::ConstraintQuery`], [`crate::DynamicTargetQuery`], and
//! [`crate::SemanticQuery`] alike, at the cost of being a probabilistic
//! judgment rather than a proof.
//!
//! **Never enabled implicitly.** Every call here sends the query's code/text
//! content to a configured external endpoint over the network — a real
//! privacy/security consideration for a static-analysis tool reading a
//! user's source code. An [`LlmOracle`] only exists when a caller
//! constructs one explicitly with a real endpoint/key
//! ([`LlmOracleConfig`]); nothing in this crate reaches for one on its own,
//! and [`crate::CompositeOracle`] never includes an LLM backend unless the
//! caller adds it itself.

use serde::{Deserialize, Serialize};

use crate::error::{OracleError, OracleResult};
use crate::oracle::Oracle;
use crate::query::{ConstraintQuery, Decision, DynamicTargetQuery, SemanticAnswer, SemanticQuery, TargetSuggestion};

#[derive(Clone, Debug)]
pub struct LlmOracleConfig {
    /// A full chat-completions-style endpoint URL (OpenAI-compatible: most
    /// self-hosted and hosted providers, including Anthropic's own
    /// OpenAI-compatible endpoint, speak this shape).
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub timeout: std::time::Duration,
}

impl LlmOracleConfig {
    pub fn new(endpoint: impl Into<String>, api_key: impl Into<String>, model: impl Into<String>) -> Self {
        Self { endpoint: endpoint.into(), api_key: api_key.into(), model: model.into(), timeout: std::time::Duration::from_secs(30) }
    }
}

pub struct LlmOracle {
    config: LlmOracleConfig,
    agent: ureq::Agent,
}

impl LlmOracle {
    pub fn new(config: LlmOracleConfig) -> Self {
        let agent = ureq::Agent::config_builder().timeout_global(Some(config.timeout)).build().into();
        Self { config, agent }
    }

    fn complete(&self, system_prompt: &str, user_prompt: &str) -> OracleResult<String> {
        let body = ChatRequest {
            model: self.config.model.clone(),
            messages: vec![ChatMessage { role: "system".to_string(), content: system_prompt.to_string() }, ChatMessage { role: "user".to_string(), content: user_prompt.to_string() }],
            temperature: 0.0,
        };
        let response = self
            .agent
            .post(&self.config.endpoint)
            .header("Authorization", &format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .send_json(&body)
            .map_err(|error| OracleError::BackendUnavailable(error.to_string()))?;
        let parsed: ChatResponse = response.into_body().read_json().map_err(|error| OracleError::Other(format!("failed to parse LLM response: {error}")))?;
        parsed.choices.into_iter().next().map(|choice| choice.message.content).ok_or_else(|| OracleError::Other("LLM response contained no choices".to_string()))
    }
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

impl Oracle for LlmOracle {
    fn name(&self) -> &str {
        "llm"
    }

    fn decide_constraint(&self, query: &ConstraintQuery) -> OracleResult<Decision> {
        let prompt = format!(
            "Constraint kind: {:?}\nDomain: {:?}\nLanguage: {}\nlhs: {}\nrhs: {}\nContext: {:?}\n\nRespond with exactly one word: one of Satisfiable, Unsatisfiable, Equivalent, NotEquivalent, Implies, DoesNotImply, Unknown.",
            query.kind, query.domain, query.language, query.lhs, query.rhs.as_deref().unwrap_or("<none>"), query.context
        );
        let text = self.complete("You are a precise program-analysis assistant deciding a formal constraint. Answer with a single word only.", &prompt)?;
        parse_decision(&text)
    }

    fn resolve_dynamic_target(&self, query: &DynamicTargetQuery) -> OracleResult<TargetSuggestion> {
        let prompt = format!(
            "Language: {}\nCall site: {}\nKnown literal fragments: {:?}\nCandidate targets already enumerated structurally: {:?}\n\n\
             Respond as JSON: {{\"targets\": [[\"qualified.name\", 0.0..1.0], ...], \"rationale\": \"...\"}}. \
             If `candidate_targets` is non-empty, only suggest names from that list.",
            query.language, query.call_site_text, query.known_literals, query.candidate_targets
        );
        let text = self.complete("You resolve dynamic/reflective call targets in source code. Respond with strict JSON only, no prose outside the JSON object.", &prompt)?;
        serde_json::from_str(&text).map_err(|error| OracleError::Other(format!("failed to parse LLM target suggestion: {error}; raw: {text}")))
    }

    fn interpret_semantics(&self, query: &SemanticQuery) -> OracleResult<SemanticAnswer> {
        let prompt = format!(
            "Language: {}\nCode:\n```\n{}\n```\nQuestion: {}\n\n\
             Respond as JSON: {{\"answer\": \"...\", \"confidence\": 0.0..1.0, \"rationale\": \"...\"}}.",
            query.language, query.code_snippet, query.question
        );
        let text = self.complete("You answer targeted semantic questions about a code snippet for a security analysis tool. Respond with strict JSON only.", &prompt)?;
        let answer: SemanticAnswer = serde_json::from_str(&text)
            .map_err(|error| OracleError::Other(format!("failed to parse LLM semantic answer: {error}; raw: {text}")))?;
        validate_semantic_answer(answer)
    }
}

/// Keep an untrusted remote response from silently becoming a malformed
/// analyzer result.  This is intentionally structural validation only: a
/// syntactically valid answer remains *advisory* until a deterministic
/// UniFlow rule/flow check independently establishes it.
fn validate_semantic_answer(answer: SemanticAnswer) -> OracleResult<SemanticAnswer> {
    if answer.answer.trim().is_empty() {
        return Err(OracleError::Other("LLM semantic answer was empty".to_string()));
    }
    if answer.rationale.trim().is_empty() {
        return Err(OracleError::Other("LLM semantic rationale was empty".to_string()));
    }
    if !answer.confidence.is_finite() || !(0.0..=1.0).contains(&answer.confidence) {
        return Err(OracleError::Other(format!(
            "LLM semantic confidence must be finite and in [0, 1], got {}",
            answer.confidence
        )));
    }
    Ok(answer)
}

fn parse_decision(text: &str) -> OracleResult<Decision> {
    match text.trim() {
        "Satisfiable" => Ok(Decision::Satisfiable),
        "Unsatisfiable" => Ok(Decision::Unsatisfiable),
        "Equivalent" => Ok(Decision::Equivalent),
        "NotEquivalent" => Ok(Decision::NotEquivalent),
        "Implies" => Ok(Decision::Implies),
        "DoesNotImply" => Ok(Decision::DoesNotImply),
        "Unknown" => Ok(Decision::Unknown),
        other => Err(OracleError::Other(format!("unrecognized LLM decision text: {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_known_decision_word() {
        assert_eq!(parse_decision("Satisfiable").unwrap(), Decision::Satisfiable);
        assert_eq!(parse_decision(" Unknown \n").unwrap(), Decision::Unknown);
    }

    #[test]
    fn rejects_unrecognized_decision_text() {
        assert!(parse_decision("maybe?").is_err());
    }

    #[test]
    fn config_defaults_to_a_thirty_second_timeout() {
        let config = LlmOracleConfig::new("https://example.invalid/v1/chat/completions", "key", "model");
        assert_eq!(config.timeout, std::time::Duration::from_secs(30));
    }

    #[test]
    fn rejects_malformed_semantic_answers() {
        let base = SemanticAnswer {
            answer: "possible SQL injection".to_string(),
            confidence: 0.8,
            rationale: "request data is concatenated into query text".to_string(),
        };
        assert!(validate_semantic_answer(base.clone()).is_ok());
        assert!(validate_semantic_answer(SemanticAnswer { answer: String::new(), ..base.clone() }).is_err());
        assert!(validate_semantic_answer(SemanticAnswer { confidence: f32::NAN, ..base.clone() }).is_err());
        assert!(validate_semantic_answer(SemanticAnswer { confidence: 1.1, ..base }).is_err());
    }
}
