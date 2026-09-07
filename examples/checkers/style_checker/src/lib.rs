use uniflow_checker_api::{
    event_kind, export_checker, Checker, CheckerEvent, CheckerFinding, CheckerKind,
    CheckerLocation, CheckerManifest, CheckerRule,
};

#[derive(Default)]
struct StyleChecker;

impl Checker for StyleChecker {
    fn manifest(&self) -> CheckerManifest {
        let mut manifest = CheckerManifest::new(
            "example.source-style",
            "Source Style Checker",
            env!("CARGO_PKG_VERSION"),
        );
        manifest.description =
            "Reports trailing horizontal whitespace directly from source text.".to_string();
        manifest.kind = CheckerKind::Frontend;
        manifest.event_kinds = vec![event_kind::SOURCE_FILE.to_string()];
        let mut rule = CheckerRule::new("trailing-whitespace", "Trailing horizontal whitespace");
        rule.description =
            "Reports spaces or tabs that appear immediately before a line ending.".to_string();
        rule.tags = vec!["style".to_string(), "readability".to_string()];
        manifest.rules = vec![rule];
        manifest
    }

    fn on_event(&mut self, event: &CheckerEvent) -> Vec<CheckerFinding> {
        if event.kind != event_kind::SOURCE_FILE {
            return Vec::new();
        }
        let Some(path) = event.payload.get("path").and_then(|value| value.as_str()) else {
            return Vec::new();
        };
        let Some(source) = event.payload.get("source").and_then(|value| value.as_str()) else {
            return Vec::new();
        };
        source
            .lines()
            .enumerate()
            .filter_map(|(line_index, line)| {
                let trimmed = line.trim_end_matches([' ', '\t']);
                (trimmed.len() != line.len()).then(|| {
                    CheckerFinding::new(
                        "trailing-whitespace",
                        "Remove trailing horizontal whitespace",
                        CheckerLocation {
                            uri: path.to_string(),
                            line: (line_index + 1) as u32,
                            column: (trimmed.chars().count() + 1) as u32,
                            label: "trailing whitespace starts here".to_string(),
                        },
                    )
                })
            })
            .collect()
    }
}

export_checker!(StyleChecker);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frontend_manifest_and_source_finding_are_stable() {
        let mut checker = StyleChecker;
        let manifest = checker.manifest();
        assert_eq!(manifest.kind, CheckerKind::Frontend);
        assert_eq!(manifest.event_kinds, vec![event_kind::SOURCE_FILE]);
        assert_eq!(manifest.rules.len(), 1);
        assert_eq!(manifest.rules[0].id, "trailing-whitespace");

        let findings = checker.on_event(&CheckerEvent {
            kind: event_kind::SOURCE_FILE.to_string(),
            sequence: 1,
            payload: json!({
                "path": "sample.rs",
                "language": "rust",
                "source": "fn clean() {}\nfn dirty() {}  \n",
            }),
        });
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "trailing-whitespace");
        assert_eq!(findings[0].location.line, 2);
        assert_eq!(findings[0].location.column, 14);
    }
}
