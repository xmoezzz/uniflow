use std::path::Path;
use uniflow_sca_core::{Dependency, ManifestParser};

/// Most Gradle projects declare dependencies directly in `build.gradle`(.kts)
/// — an arbitrary Groovy/Kotlin script, not a data format, so reliably
/// extracting a version from it (which may come from a variable, a
/// property file, or string concatenation) isn't attempted here. This
/// instead reads Gradle's own opt-in dependency-locking output,
/// `gradle.lockfile`, which is a plain, fully-resolved text format —
/// the deterministic-lockfile equivalent of `package-lock.json` for Gradle,
/// when a project has locking enabled.
pub struct GradleLockParser;

impl ManifestParser for GradleLockParser {
    fn ecosystem(&self) -> &'static str {
        // Gradle dependencies are Maven coordinates (group:artifact:version)
        // resolved from Maven repositories, so they share the same
        // vulnerability namespace as `deps_maven`'s pom.xml findings.
        "maven"
    }

    fn manifest_file_names(&self) -> &'static [&'static str] {
        &["gradle.lockfile"]
    }

    fn parse(&self, manifest_path: &Path) -> anyhow::Result<Vec<Dependency>> {
        let text = std::fs::read_to_string(manifest_path)?;
        let manifest_path = manifest_path.display().to_string();
        let mut deps = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("empty=") {
                continue;
            }
            let coordinates = line.split('=').next().unwrap_or_default();
            let mut parts = coordinates.splitn(3, ':');
            let (Some(group), Some(artifact), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            deps.push(Dependency {
                ecosystem: "maven".to_string(),
                name: format!("{group}:{artifact}"),
                version: version.to_string(),
                manifest_path: manifest_path.clone(),
                direct: false,
            });
        }
        Ok(deps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_locked_coordinates_and_skips_comments_and_empty_entries() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("gradle.lockfile");
        std::fs::write(
            &path,
            "# This is a Gradle generated file for dependency locking.\ncom.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\norg.apache.commons:commons-lang3:3.12.0=compileClasspath\nempty=annotationProcessor\n",
        )
        .expect("write fixture");

        let deps = GradleLockParser.parse(&path).expect("parse");
        assert_eq!(deps.len(), 2, "{deps:?}");
        assert!(deps.iter().any(|dep| dep.name == "com.google.guava:guava" && dep.version == "31.1-jre"));
        assert!(deps.iter().all(|dep| dep.ecosystem == "maven"));
    }
}
