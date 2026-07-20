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
    match language {
        Language::C => matches!(ext, "c" | "h"),
        Language::Cpp => matches!(ext, "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx"),
        Language::Java => ext == "java",
        Language::Python => ext == "py",
        Language::Unknown => false,
    }
}
