use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_frontend::parse_source;
use uniflow_hir::{Language, Program};

const CACHE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedUnit {
    pub path: String,
    pub content_hash: String,
    pub program: Program,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectCache {
    pub version: u32,
    pub language: Language,
    pub units: Vec<CachedUnit>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CachePlan {
    #[serde(default)]
    pub reused: Vec<String>,
    #[serde(default)]
    pub reparsed: Vec<String>,
    #[serde(default)]
    pub added: Vec<String>,
    #[serde(default)]
    pub removed: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CachedBuildResult {
    pub program: Program,
    pub cache: ProjectCache,
    pub plan: CachePlan,
}

pub fn load_project_cache(path: &Path) -> Result<ProjectCache> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read cache from {}", path.display()))?;
    let cache = serde_json::from_str::<ProjectCache>(&text)
        .with_context(|| format!("failed to decode cache from {}", path.display()))?;
    Ok(cache)
}

pub fn save_project_cache(path: &Path, cache: &ProjectCache) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create cache directory {}", parent.display()))?;
        }
    }
    let text = serde_json::to_string_pretty(cache).context("failed to encode project cache")?;
    fs::write(path, text)
        .with_context(|| format!("failed to write cache to {}", path.display()))
}

pub fn build_project_with_cache(
    language: Language,
    files: &[PathBuf],
    existing: Option<&ProjectCache>,
) -> Result<CachedBuildResult> {
    if files.is_empty() {
        bail!("no supported source files found");
    }

    let reusable = existing
        .filter(|cache| cache.version == CACHE_VERSION && cache.language == language)
        .map(index_units)
        .unwrap_or_default();

    let mut merged = Program::empty(language.clone());
    let mut units = Vec::new();
    let mut plan = CachePlan::default();
    let mut current_paths = BTreeSet::new();

    for path in files {
        let normalized = normalize_path(path);
        current_paths.insert(normalized.clone());

        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read source from {}", path.display()))?;
        let content_hash = digest_text(&source);

        let (program, reused_hit) = match reusable.get(&normalized) {
            Some(unit) if unit.content_hash == content_hash => (unit.program.clone(), true),
            _ => (parse_source(language.clone(), &normalized, &source)?, false),
        };

        if reused_hit {
            plan.reused.push(normalized.clone());
        } else {
            plan.reparsed.push(normalized.clone());
            if !reusable.contains_key(&normalized) {
                plan.added.push(normalized.clone());
            }
        }

        merged.merge(program.clone());
        units.push(CachedUnit {
            path: normalized,
            content_hash,
            program,
        });
    }

    if let Some(cache) = existing {
        for old in &cache.units {
            if !current_paths.contains(&old.path) {
                plan.removed.push(old.path.clone());
            }
        }
    }

    plan.reused.sort();
    plan.reused.dedup();
    plan.reparsed.sort();
    plan.reparsed.dedup();
    plan.added.sort();
    plan.added.dedup();
    plan.removed.sort();
    plan.removed.dedup();

    Ok(CachedBuildResult {
        program: merged,
        cache: ProjectCache {
            version: CACHE_VERSION,
            language,
            units,
        },
        plan,
    })
}

fn index_units(cache: &ProjectCache) -> BTreeMap<String, CachedUnit> {
    cache.units
        .iter()
        .cloned()
        .map(|unit| (unit.path.clone(), unit))
        .collect()
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn digest_text(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    format!("{digest:x}")
}
