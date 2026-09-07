use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::Language;

pub fn collect_source_files(language: Language, inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_one(language.clone(), input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
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
            collect_one(language.clone(), &entry.path(), out)?;
        }
    }
    Ok(())
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
}
