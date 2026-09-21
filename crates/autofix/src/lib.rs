mod taint_fix;

pub use taint_fix::{apply_taint_fix_and_reverify, LlmFixConfig, SourceFinding, TaintFixResult};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uniflow_sca_core::DependencyFinding;
use uniflow_sca_orchestrator::scan_directory;

/// Stage 4 (智能修复) for dependency findings: deterministic, template-based
/// version bumps only. There is no LLM in this path — the "fix" is a literal
/// text substitution in the manifest — and stage 5 (结果核验) always re-runs
/// the same deterministic scanner used for detection before a finding is
/// reported resolved, so a fix is never trusted on its own say-so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixRequest {
    pub manifest_path: String,
    pub package: String,
    pub current_version: String,
    pub to_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub diff: String,
    pub remaining_findings: Vec<DependencyFinding>,
    pub resolved: bool,
    pub note: Option<String>,
}

pub fn apply_dependency_fix(request: &FixRequest) -> Result<FixResult> {
    let path = Path::new(&request.manifest_path);
    let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
    anyhow::ensure!(
        file_name == "package.json",
        "only package.json direct-dependency fixes are supported today; {file_name} is a lockfile and needs its package manager re-run instead"
    );

    let original = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest {}", path.display()))?;
    let updated = replace_dependency_version(
        &original,
        &request.package,
        &request.current_version,
        &request.to_version,
    )
    .with_context(|| {
        format!(
            "could not find \"{}\": \"{}\" in {}",
            request.package,
            request.current_version,
            path.display()
        )
    })?;
    std::fs::write(path, &updated)
        .with_context(|| format!("failed to write manifest {}", path.display()))?;

    let diff = format!(
        "- \"{}\": \"{}\"\n+ \"{}\": \"{}\"",
        request.package, request.current_version, request.package, request.to_version
    );

    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let rescanned = scan_directory(root)?;
    let remaining_findings: Vec<_> = rescanned
        .dependency_findings
        .into_iter()
        .filter(|finding| finding.package == request.package)
        .collect();
    let resolved = remaining_findings.is_empty();
    let note = (!resolved).then(|| {
        "the manifest was updated but a lockfile in this directory still resolves the old \
         version; re-run the package manager's install command to regenerate it"
            .to_string()
    });

    Ok(FixResult { diff, remaining_findings, resolved, note })
}

fn replace_dependency_version(source: &str, package: &str, current: &str, to: &str) -> Option<String> {
    let needle = format!("\"{package}\": \"{current}\"");
    if !source.contains(&needle) {
        return None;
    }
    let replacement = format!("\"{package}\": \"{to}\"");
    Some(source.replacen(&needle, &replacement, 1))
}
