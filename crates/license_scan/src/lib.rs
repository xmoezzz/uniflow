mod corpus;

use askalono::{ScanStrategy, Store, TextData};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LicenseFinding {
    pub path: String,
    pub license: String,
    pub confidence: f32,
}

/// Filenames worth full-text scanning — matches the common `LICENSE`/
/// `COPYING`/`NOTICE` naming conventions (with or without an extension)
/// rather than scanning every file in a project, which would be both slow
/// and noisy (a source file merely mentioning a license in a comment is not
/// the same claim as a repository's actual license file).
pub fn is_license_file_name(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or(&lower);
    matches!(stem, "license" | "licence" | "copying" | "notice" | "unlicense")
}

fn store() -> &'static Store {
    static STORE: OnceLock<Store> = OnceLock::new();
    STORE.get_or_init(|| {
        let mut store = Store::new();
        for (name, text) in corpus::entries() {
            store.add_license((*name).to_string(), TextData::new(text));
        }
        store
    })
}

/// Scans `text` (the contents of a file `is_license_file_name` already said
/// is worth checking) against the bundled corpus, returning `None` if
/// nothing scored above the confidence threshold.
pub fn scan_text(path: &str, text: &str) -> Option<LicenseFinding> {
    let strategy = ScanStrategy::new(store()).confidence_threshold(0.9);
    let result = strategy.scan(&TextData::new(text)).ok()?;
    let license = result.license?;
    Some(LicenseFinding {
        path: path.to_string(),
        license: license.name.to_string(),
        confidence: result.score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_common_license_file_names() {
        assert!(is_license_file_name("LICENSE"));
        assert!(is_license_file_name("LICENSE.txt"));
        assert!(is_license_file_name("LICENSE.md"));
        assert!(is_license_file_name("COPYING"));
        assert!(is_license_file_name("NOTICE"));
        assert!(!is_license_file_name("license_agreement_notes.md"));
        assert!(!is_license_file_name("readme.md"));
    }

    #[test]
    fn identifies_a_verbatim_mit_license() {
        let finding = scan_text("LICENSE", corpus::MIT).expect("MIT license should be recognized");
        assert_eq!(finding.license, "MIT");
        assert!(finding.confidence > 0.9, "{}", finding.confidence);
    }

    #[test]
    fn identifies_a_verbatim_apache_license_with_a_real_copyright_header() {
        let text = format!("Copyright 2024 Example Corp\n\n{}", corpus::APACHE_2_0);
        let finding = scan_text("LICENSE", &text).expect("Apache-2.0 license should be recognized");
        assert_eq!(finding.license, "Apache-2.0");
    }

    #[test]
    fn does_not_match_unrelated_text() {
        assert!(scan_text("LICENSE", "This is just a README, not a license.").is_none());
    }
}
