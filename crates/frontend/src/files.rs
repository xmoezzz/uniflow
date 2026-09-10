use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::Language;

const DEFAULT_IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".gradle",
    ".idea",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "venv",
];

pub fn collect_source_files(language: Language, inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_one(language.clone(), input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Collect non-source project inputs consumed by structured baseline checkers.
/// They are deliberately kept out of `collect_source_files` so a Java parser
/// never receives XML, properties, build descriptors, or container recipes.
pub fn collect_auxiliary_files(language: Language, inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if language != Language::Java {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for input in inputs {
        collect_auxiliary_one(input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_auxiliary_one(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_auxiliary_path(input) {
            out.push(input.to_path_buf());
        }
        return Ok(());
    }
    if input.is_dir() {
        for entry in fs::read_dir(input)
            .with_context(|| format!("failed to read directory {}", input.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() && is_default_ignored_directory(&entry.file_name()) {
                continue;
            }
            collect_auxiliary_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

pub fn supports_auxiliary_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    name == "Dockerfile"
        || matches!(
            extension,
            "xml" | "xmi" | "xsd" | "properties" | "yml" | "yaml" | "gradle"
        )
}

fn collect_one(language: Language, input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_path(&language, input) {
            out.push(input.to_path_buf());
        }
        return Ok(());
    }

    if input.is_dir() {
        for entry in fs::read_dir(input)
            .with_context(|| format!("failed to read directory {}", input.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() && is_default_ignored_directory(&entry.file_name()) {
                continue;
            }
            collect_one(language.clone(), &entry.path(), out)?;
        }
    }
    Ok(())
}

fn is_default_ignored_directory(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    DEFAULT_IGNORED_DIRECTORIES.contains(&name)
}

pub fn supports_path(language: &Language, path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    language
        .extensions()
        .iter()
        .any(|supported| *supported == ext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_project(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "uniflow-frontend-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create temp project");
        root
    }

    #[test]
    fn recognizes_every_product_language_extension() {
        let cases = [
            (Language::C, "a.c"),
            (Language::Cpp, "a.cpp"),
            (Language::CSharp, "a.cs"),
            (Language::ObjC, "a.m"),
            (Language::ObjCpp, "a.mm"),
            (Language::Java, "a.java"),
            (Language::Kotlin, "a.kt"),
            (Language::Swift, "a.swift"),
            (Language::Python, "a.py"),
            (Language::Go, "a.go"),
            (Language::JavaScript, "a.js"),
            (Language::JavaScript, "a.ejs"),
            (Language::JavaScript, "a.mustache"),
            (Language::JavaScript, "a.hbs"),
            (Language::JavaScript, "a.html"),
            (Language::JavaScript, "a.pug"),
            (Language::Jsp, "a.jsp"),
            (Language::Sql, "a.sql"),
            (Language::Php, "a.php"),
            (Language::Ruby, "a.rb"),
            (Language::Rust, "a.rs"),
            (Language::Shell, "a.sh"),
        ];
        for (language, path) in cases {
            assert!(supports_path(&language, Path::new(path)), "{path}");
        }
        assert!(supports_path(&Language::ObjC, Path::new("bridge.h")));
        assert!(supports_path(&Language::ObjCpp, Path::new("bridge.hpp")));
    }

    #[test]
    fn java_auxiliary_files_are_separate_from_java_sources() {
        for path in [
            "AndroidManifest.xml",
            "web.xml",
            "ibm-web-ext.xmi",
            "service.xsd",
            "application.properties",
            "application.yml",
            "build.gradle",
            "Dockerfile",
        ] {
            assert!(supports_auxiliary_path(Path::new(path)), "{path}");
            assert!(!supports_path(&Language::Java, Path::new(path)), "{path}");
        }
        assert!(!supports_auxiliary_path(Path::new("Application.java")));
    }

    #[test]
    fn project_collection_prunes_generated_dependency_and_vcs_directories() {
        let root = temp_project("prune-defaults");
        let source_dir = root.join("src");
        fs::create_dir_all(&source_dir).unwrap();
        fs::write(source_dir.join("main.rs"), "fn main() {}\n").unwrap();

        for ignored in ["target", "node_modules", ".git", ".venv", "__pycache__"] {
            let dir = root.join(ignored).join("nested");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("ignored.rs"), "fn ignored() {}\n").unwrap();
        }

        let files = collect_source_files(Language::Rust, &[root.clone()]).unwrap();
        assert_eq!(files, vec![source_dir.join("main.rs")]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_ignored_directory_root_is_still_scannable() {
        let root = temp_project("explicit-target");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        let source = target.join("generated.rs");
        fs::write(&source, "fn generated() {}\n").unwrap();

        let files = collect_source_files(Language::Rust, &[target]).unwrap();
        assert_eq!(files, vec![source]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn java_auxiliary_collection_uses_the_same_pruning_policy() {
        let root = temp_project("aux-prune");
        fs::write(root.join("application.yml"), "server: {}\n").unwrap();
        let ignored = root.join("target").join("generated");
        fs::create_dir_all(&ignored).unwrap();
        fs::write(ignored.join("application.yml"), "generated: true\n").unwrap();

        let files = collect_auxiliary_files(Language::Java, &[root.clone()]).unwrap();
        assert_eq!(files, vec![root.join("application.yml")]);

        fs::remove_dir_all(root).unwrap();
    }
}
