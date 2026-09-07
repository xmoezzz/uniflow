use uniflow_checker_api::{
    event_kind, export_checker, Checker, CheckerEvent, CheckerFinding, CheckerLocation,
    CheckerManifest, CheckerRule,
};

#[derive(Default)]
struct BannedFunctionChecker;

impl Checker for BannedFunctionChecker {
    fn manifest(&self) -> CheckerManifest {
        let mut manifest = CheckerManifest::new(
            "example.banned-function",
            "Banned Function Checker",
            env!("CARGO_PKG_VERSION"),
        );
        manifest.description =
            "Reports calls to unsafe C string-copy functions such as strcpy and strcat."
                .to_string();
        manifest.event_kinds = vec![event_kind::CALL.to_string()];
        let mut rule = CheckerRule::new("dangerous-call", "Call to a banned function");
        rule.description =
            "Reports calls to functions that cannot enforce destination buffer bounds.".to_string();
        rule.tags = vec!["security".to_string(), "correctness".to_string()];
        manifest.rules = vec![rule];
        manifest
    }

    fn on_event(&mut self, event: &CheckerEvent) -> Vec<CheckerFinding> {
        if event.kind != event_kind::CALL {
            return Vec::new();
        }
        let Some(callee) = event
            .payload
            .get("callee_name")
            .and_then(|value| value.as_str())
        else {
            return Vec::new();
        };
        let simple_name = callee
            .rsplit(['.', ':'])
            .find(|part| !part.is_empty())
            .unwrap_or(callee);
        if !matches!(simple_name, "strcpy" | "strcat" | "gets") {
            return Vec::new();
        }

        let location = event
            .payload
            .get("location")
            .and_then(|value| value.as_str())
            .map(parse_location)
            .unwrap_or_default();
        let mut finding = CheckerFinding::new(
            "dangerous-call",
            format!("Call to banned function '{callee}'"),
            CheckerLocation {
                label: format!("call to {callee}"),
                ..location
            },
        );
        finding.level = "warning".to_string();
        finding
            .properties
            .insert("callee".to_string(), serde_json::json!(callee));
        vec![finding]
    }
}

fn parse_location(text: &str) -> CheckerLocation {
    let trimmed = text.trim().trim_start_matches('@');
    let mut parts = trimmed.rsplitn(3, ':');
    let column = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let line = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    let uri = parts.next().unwrap_or(trimmed).to_string();
    CheckerLocation {
        uri,
        line,
        column,
        label: String::new(),
    }
}

export_checker!(BannedFunctionChecker);
