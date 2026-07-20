use crate::{CompileCommandDatabase, FrontendOptions};
use anyhow::{Context, Result};
use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::Language;

const MAX_HEADER_FILES: usize = 512;
const MAX_HEADER_DEPTH: usize = 32;
const MAX_HEADER_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
struct PendingHeader {
    path: PathBuf,
    depth: usize,
    include_paths: Vec<PathBuf>,
}

/// Recursively discover project headers referenced by C/C++ translation units.
///
/// The index deliberately avoids unrestricted system-header traversal: only quoted includes and
/// headers resolvable through explicitly configured `-I`, `-isystem`, or `/I` paths are followed.
/// Cycles, excessive depth, oversized generated headers, and duplicate canonical paths are bounded.
pub fn collect_project_headers(
    language: Language,
    roots: &[PathBuf],
    options: &FrontendOptions,
    database: Option<&CompileCommandDatabase>,
) -> Result<Vec<PathBuf>> {
    if !matches!(language, Language::C | Language::Cpp) {
        return Ok(Vec::new());
    }

    let mut discovered = BTreeSet::<PathBuf>::new();
    let mut scanned = BTreeSet::<PathBuf>::new();
    let mut queue = VecDeque::<PendingHeader>::new();

    for root in roots {
        let resolved = options.with_compile_command(
            database.and_then(|database| database.options_for(root.as_path())),
        );
        queue.push_back(PendingHeader {
            path: root.clone(),
            depth: 0,
            include_paths: resolved.include_paths,
        });
    }

    while let Some(pending) = queue.pop_front() {
        if pending.depth > MAX_HEADER_DEPTH || discovered.len() >= MAX_HEADER_FILES {
            continue;
        }
        let canonical = canonical_or_normalized(&pending.path);
        if !scanned.insert(canonical.clone()) {
            continue;
        }
        let metadata = match fs::metadata(&canonical) {
            Ok(metadata) if metadata.is_file() && metadata.len() <= MAX_HEADER_BYTES => metadata,
            _ => continue,
        };
        let _ = metadata;
        let source = fs::read_to_string(&canonical)
            .with_context(|| format!("failed to read included header {}", canonical.display()))?;
        let parent = canonical.parent().unwrap_or_else(|| Path::new("."));

        for include in parse_includes(&source) {
            let resolved = resolve_include(parent, &pending.include_paths, &include.path, include.quoted);
            let Some(path) = resolved else { continue };
            if !is_header_path(&path) {
                continue;
            }
            let normalized = canonical_or_normalized(&path);
            if discovered.insert(normalized.clone()) {
                queue.push_back(PendingHeader {
                    path: normalized,
                    depth: pending.depth + 1,
                    include_paths: pending.include_paths.clone(),
                });
            }
        }
    }

    for root in roots {
        discovered.remove(&canonical_or_normalized(root));
    }
    Ok(discovered.into_iter().collect())
}

#[derive(Clone, Debug)]
struct IncludeDirective {
    path: String,
    quoted: bool,
}

fn parse_includes(source: &str) -> Vec<IncludeDirective> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line.strip_prefix('#')?.trim_start();
            let rest = rest.strip_prefix("include")?.trim_start();
            if let Some(rest) = rest.strip_prefix('"') {
                let end = rest.find('"')?;
                return Some(IncludeDirective {
                    path: rest[..end].to_string(),
                    quoted: true,
                });
            }
            if let Some(rest) = rest.strip_prefix('<') {
                let end = rest.find('>')?;
                return Some(IncludeDirective {
                    path: rest[..end].to_string(),
                    quoted: false,
                });
            }
            None
        })
        .collect()
}

fn resolve_include(
    parent: &Path,
    include_paths: &[PathBuf],
    include: &str,
    quoted: bool,
) -> Option<PathBuf> {
    let include = Path::new(include);
    let mut candidates = Vec::new();
    if quoted {
        candidates.push(parent.join(include));
    }
    candidates.extend(include_paths.iter().map(|base| base.join(include)));
    candidates.into_iter().find(|candidate| candidate.is_file())
}

fn is_header_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).map(str::to_ascii_lowercase).as_deref(),
        Some("h" | "hh" | "hpp" | "hxx" | "inc" | "inl" | "ipp" | "tpp")
    )
}

fn canonical_or_normalized(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                other => normalized.push(other.as_os_str()),
            }
        }
        normalized
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn follows_local_and_configured_headers_without_cycles() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("uniflow-header-index-{unique}"));
        let include = root.join("include");
        fs::create_dir_all(&include).expect("mkdir");
        fs::write(root.join("main.cpp"), "#include \"local.hpp\"\n#include <sdk.hpp>\n")
            .expect("main");
        fs::write(root.join("local.hpp"), "#include <sdk.hpp>\n").expect("local");
        fs::write(include.join("sdk.hpp"), "#include \"sdk.hpp\"\n").expect("sdk");

        let mut options = FrontendOptions::default();
        options.include_paths.push(include.clone());
        let headers = collect_project_headers(
            Language::Cpp,
            &[root.join("main.cpp")],
            &options,
            None,
        )
        .expect("headers");
        assert_eq!(headers.len(), 2);
        assert!(headers.iter().any(|path| path.ends_with("local.hpp")));
        assert!(headers.iter().any(|path| path.ends_with("sdk.hpp")));

        let _ = fs::remove_dir_all(root);
    }
}
