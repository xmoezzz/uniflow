use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_frontend::{
    parse_project_sources_with_options, parse_source_with_options, FrontendOptions,
};
use uniflow_hir::{Language, Program};

// v8 also separates JavaScript's keyword set from Kotlin/Go/Rust words such as
// `data`, `go` and `defer`, so older JavaScript HIR must not be reused.
// v7 added Kotlin constructor/type normalization and JSP implicit-object and
// top-level call semantics to the cached HIR/IR contract.
// v6 remaps dynamic/resolved call targets during multi-file HIR merge and
// distinguishes Python function objects from unknown factory return values.
// It also includes ScriptEngine/XPath/DocumentBuilder and NIO Path signatures.
// v5 added Java prefix/postfix updates, including expression-position writes.
const CACHE_VERSION: u32 = 8;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedUnit {
    pub path: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<Program>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProjectCache {
    pub version: u32,
    pub language: Language,
    #[serde(default)]
    pub platform: uniflow_platform::PlatformProfile,
    #[serde(default)]
    pub frontend_options: FrontendOptions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_program: Option<Program>,
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

#[derive(Clone, Debug)]
struct SourceSnapshot {
    path: String,
    content_hash: String,
    source: String,
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
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create cache directory {}", parent.display())
            })?;
        }
    }
    let text = serde_json::to_string_pretty(cache).context("failed to encode project cache")?;
    fs::write(path, text).with_context(|| format!("failed to write cache to {}", path.display()))
}

pub fn build_project_with_cache(
    language: Language,
    files: &[PathBuf],
    existing: Option<&ProjectCache>,
) -> Result<CachedBuildResult> {
    build_project_with_cache_options(language, files, existing, &FrontendOptions::default())
}

pub fn build_project_with_cache_options(
    language: Language,
    files: &[PathBuf],
    existing: Option<&ProjectCache>,
    options: &FrontendOptions,
) -> Result<CachedBuildResult> {
    if files.is_empty() {
        bail!("no supported source files found");
    }

    let snapshots = read_snapshots(files)?;
    let compatible = existing.filter(|cache| {
        cache.version == CACHE_VERSION
            && cache.language == language
            && cache.platform == options.platform
            && cache.frontend_options == *options
    });

    if matches!(language, Language::Java | Language::Python) {
        build_project_indexed(language, snapshots, existing, compatible, options)
    } else {
        build_per_file(language, snapshots, existing, compatible, options)
    }
}

fn build_project_indexed(
    language: Language,
    snapshots: Vec<SourceSnapshot>,
    existing: Option<&ProjectCache>,
    compatible: Option<&ProjectCache>,
    options: &FrontendOptions,
) -> Result<CachedBuildResult> {
    let current_paths = snapshots
        .iter()
        .map(|snapshot| snapshot.path.clone())
        .collect::<BTreeSet<_>>();
    let compatible_units = compatible.map(index_units).unwrap_or_default();
    let exact_hit = compatible
        .and_then(|cache| cache.project_program.as_ref())
        .filter(|_| compatible_units.len() == snapshots.len())
        .filter(|_| {
            snapshots.iter().all(|snapshot| {
                compatible_units
                    .get(&snapshot.path)
                    .is_some_and(|unit| unit.content_hash == snapshot.content_hash)
            })
        });

    let mut plan = CachePlan::default();
    let program = if let Some(program) = exact_hit {
        plan.reused = snapshots
            .iter()
            .map(|snapshot| snapshot.path.clone())
            .collect();
        (*program).clone()
    } else {
        plan.reparsed = snapshots
            .iter()
            .map(|snapshot| snapshot.path.clone())
            .collect();
        let entries = snapshots
            .iter()
            .map(|snapshot| (snapshot.path.clone(), snapshot.source.clone()))
            .collect::<Vec<_>>();
        parse_project_sources_with_options(language.clone(), &entries, options)?
    };

    populate_added_removed(&mut plan, &snapshots, existing, &current_paths);
    normalize_plan(&mut plan);

    let units = snapshots
        .into_iter()
        .map(|snapshot| CachedUnit {
            path: snapshot.path,
            content_hash: snapshot.content_hash,
            program: None,
        })
        .collect();

    Ok(CachedBuildResult {
        program: program.clone(),
        cache: ProjectCache {
            version: CACHE_VERSION,
            language,
            platform: options.platform.clone(),
            frontend_options: options.clone(),
            project_program: Some(program),
            units,
        },
        plan,
    })
}

fn build_per_file(
    language: Language,
    snapshots: Vec<SourceSnapshot>,
    existing: Option<&ProjectCache>,
    compatible: Option<&ProjectCache>,
    options: &FrontendOptions,
) -> Result<CachedBuildResult> {
    let reusable = compatible.map(index_units).unwrap_or_default();
    let current_paths = snapshots
        .iter()
        .map(|snapshot| snapshot.path.clone())
        .collect::<BTreeSet<_>>();
    let old_paths = existing
        .map(|cache| {
            cache
                .units
                .iter()
                .map(|unit| unit.path.clone())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let mut merged = Program::empty(language.clone());
    let mut units = Vec::with_capacity(snapshots.len());
    let mut plan = CachePlan::default();

    for snapshot in snapshots {
        let cached_program = reusable
            .get(&snapshot.path)
            .filter(|unit| unit.content_hash == snapshot.content_hash)
            .and_then(|unit| unit.program.as_ref());

        let (program, reused_hit) = match cached_program {
            Some(program) => ((*program).clone(), true),
            None => (
                parse_source_with_options(
                    language.clone(),
                    &snapshot.path,
                    &snapshot.source,
                    options,
                )?,
                false,
            ),
        };

        if reused_hit {
            plan.reused.push(snapshot.path.clone());
        } else {
            plan.reparsed.push(snapshot.path.clone());
            if !old_paths.contains(&snapshot.path) {
                plan.added.push(snapshot.path.clone());
            }
        }

        merged.merge(program.clone());
        units.push(CachedUnit {
            path: snapshot.path,
            content_hash: snapshot.content_hash,
            program: Some(program),
        });
    }

    if let Some(cache) = existing {
        for old in &cache.units {
            if !current_paths.contains(&old.path) {
                plan.removed.push(old.path.clone());
            }
        }
    }
    normalize_plan(&mut plan);

    Ok(CachedBuildResult {
        program: merged,
        cache: ProjectCache {
            version: CACHE_VERSION,
            language,
            platform: options.platform.clone(),
            frontend_options: options.clone(),
            project_program: None,
            units,
        },
        plan,
    })
}

fn read_snapshots(files: &[PathBuf]) -> Result<Vec<SourceSnapshot>> {
    let mut snapshots = Vec::with_capacity(files.len());
    for path in files {
        let normalized = normalize_path(path);
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read source from {}", path.display()))?;
        snapshots.push(SourceSnapshot {
            path: normalized,
            content_hash: digest_text(&source),
            source,
        });
    }
    Ok(snapshots)
}

fn populate_added_removed(
    plan: &mut CachePlan,
    snapshots: &[SourceSnapshot],
    existing: Option<&ProjectCache>,
    current_paths: &BTreeSet<String>,
) {
    let old_paths = existing
        .map(|cache| {
            cache
                .units
                .iter()
                .map(|unit| unit.path.clone())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    for snapshot in snapshots {
        if !old_paths.contains(&snapshot.path) {
            plan.added.push(snapshot.path.clone());
        }
    }
    for old_path in old_paths {
        if !current_paths.contains(&old_path) {
            plan.removed.push(old_path);
        }
    }
}

fn normalize_plan(plan: &mut CachePlan) {
    plan.reused.sort();
    plan.reused.dedup();
    plan.reparsed.sort();
    plan.reparsed.dedup();
    plan.added.sort();
    plan.added.dedup();
    plan.removed.sort();
    plan.removed.dedup();
}

fn index_units(cache: &ProjectCache) -> BTreeMap<String, CachedUnit> {
    cache
        .units
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_project(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "uniflow-cache-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temporary project directory should be created");
        path
    }

    #[test]
    fn java_numeric_updates_invalidate_v4_cache_and_roundtrip_current() {
        let root = temp_project("java-numeric-updates");
        let source = root.join("Updates.java");
        fs::write(&source, "class Updates { int f(int i) { return i++; } }").unwrap();
        let files = vec![source];
        let first = build_project_with_cache(Language::Java, &files, None).unwrap();
        let mut old = first.cache.clone();
        old.version = 4;
        // Poison the old parsed program, not the source hash: compatibility
        // must reject the cache even when every file appears unchanged.
        old.project_program.as_mut().unwrap().modules.clear();
        let rebuilt = build_project_with_cache(Language::Java, &files, Some(&old)).unwrap();
        assert_eq!(rebuilt.plan.reparsed.len(), 1);
        assert!(rebuilt.plan.reused.is_empty());
        assert!(!rebuilt.program.modules.is_empty());
        let json = serde_json::to_string(&rebuilt.cache).unwrap();
        assert!(json.contains("PostIncrement"));
        let restored = serde_json::from_str(&json).unwrap();
        let reused = build_project_with_cache(Language::Java, &files, Some(&restored)).unwrap();
        assert_eq!(reused.plan.reused.len(), 1);
        assert!(reused.plan.reparsed.is_empty());
        assert_eq!(serde_json::to_value(reused.program).unwrap(), serde_json::to_value(rebuilt.program).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn python_callback_binding_invalidates_v5_cache() {
        let root = temp_project("python-callback-binding");
        let app = root.join("app.py");
        let repo = root.join("repo.py");
        fs::write(&repo, "def pick(handlers):\n    return handlers[0]\n").unwrap();
        fs::write(&app, "from repo import pick\ndef handle(handlers, arg):\n    cb = pick(handlers)\n    return cb(arg)\n").unwrap();
        let files = vec![repo, app];
        let first = build_project_with_cache(Language::Python, &files, None).unwrap();
        let mut old = first.cache;
        old.version = 5;
        old.project_program.as_mut().unwrap().modules.clear();
        let rebuilt = build_project_with_cache(Language::Python, &files, Some(&old)).unwrap();
        assert_eq!(rebuilt.plan.reparsed.len(), 2);
        assert!(rebuilt.plan.reused.is_empty());
        assert_eq!(rebuilt.cache.version, CACHE_VERSION);
        assert_eq!(serde_json::to_value(&rebuilt.program).unwrap(), serde_json::to_value(&first.program).unwrap());
        let restored = serde_json::from_str(&serde_json::to_string(&rebuilt.cache).unwrap()).unwrap();
        let reused = build_project_with_cache(Language::Python, &files, Some(&restored)).unwrap();
        assert_eq!(reused.plan.reused.len(), 2);
        assert_eq!(serde_json::to_value(&reused.program).unwrap(), serde_json::to_value(&first.program).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn python_cache_reuses_only_complete_project_programs() {
        let root = temp_project("python-project");
        let app = root.join("app.py");
        let repo = root.join("repo.py");
        fs::write(&app, "from repo import load\nvalue = load()\n")
            .expect("app source should be written");
        fs::write(&repo, "def load():\n    return input()\n")
            .expect("repo source should be written");
        let files = vec![app.clone(), repo.clone()];

        let first = build_project_with_cache(Language::Python, &files, None)
            .expect("first project build should succeed");
        assert!(first.cache.project_program.is_some());
        assert!(first.cache.units.iter().all(|unit| unit.program.is_none()));
        assert_eq!(first.plan.reparsed.len(), 2);

        let second = build_project_with_cache(Language::Python, &files, Some(&first.cache))
            .expect("unchanged project should reuse its cached program");
        assert_eq!(second.plan.reused.len(), 2);
        assert!(second.plan.reparsed.is_empty());

        fs::write(&repo, "def load():\n    return 'changed'\n")
            .expect("repo source should be updated");
        let third = build_project_with_cache(Language::Python, &files, Some(&second.cache))
            .expect("changed project should be rebuilt");
        assert!(third.plan.reused.is_empty());
        assert_eq!(third.plan.reparsed.len(), 2);

        fs::remove_dir_all(root).expect("temporary project directory should be removed");
    }

    #[test]
    fn platform_change_invalidates_per_file_cache() {
        let root = temp_project("platform");
        let source = root.join("main.c");
        fs::write(
            &source,
            "#ifdef _WIN32\nint platform(void) { return 1; }\n#else\nint platform(void) { return 2; }\n#endif\n",
        )
        .expect("C source should be written");
        let files = vec![source];

        let windows = FrontendOptions {
            platform: uniflow_platform::PlatformProfile::windows_x86_64_msvc(),
            ..FrontendOptions::default()
        };
        let linux = FrontendOptions {
            platform: uniflow_platform::PlatformProfile::linux_x86_64_gnu(),
            ..FrontendOptions::default()
        };
        let first = build_project_with_cache_options(Language::C, &files, None, &windows)
            .expect("Windows-profile build should succeed");
        let second =
            build_project_with_cache_options(Language::C, &files, Some(&first.cache), &linux)
                .expect("Linux-profile build should succeed");

        assert!(second.plan.reused.is_empty());
        assert_eq!(second.plan.reparsed.len(), 1);
        assert_eq!(second.cache.platform, linux.platform);

        fs::remove_dir_all(root).expect("temporary project directory should be removed");
    }
}
