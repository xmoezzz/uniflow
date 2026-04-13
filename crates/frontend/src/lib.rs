use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::{Language, Program};
use uniflow_lang_c::CParser;
use uniflow_lang_cpp::CppParser;
use uniflow_lang_java::{parse_project_sources as parse_java_project_sources, JavaParser};
use uniflow_lang_python::{parse_project_sources as parse_python_project_sources, PythonParser};
use uniflow_parser_core::SourceParser;

pub fn parse_source(language: Language, path: &str, source: &str) -> Result<Program> {
    match language {
        Language::C => CParser::default().parse_file(path, source),
        Language::Cpp => CppParser::default().parse_file(path, source),
        Language::Java => JavaParser::default().parse_file(path, source),
        Language::Python => PythonParser::default().parse_file(path, source),
        Language::Unknown => bail!("language must be specified"),
    }
}

pub fn parse_source_file(language: Language, path: &Path) -> Result<Program> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read source from {}", path.display()))?;
    parse_source(language, &path.to_string_lossy(), &source)
}

pub fn parse_project_paths(language: Language, inputs: &[PathBuf]) -> Result<Program> {
    let files = collect_source_files(language.clone(), inputs)?;
    if files.is_empty() {
        bail!("no supported source files found")
    }

    if matches!(language, Language::Java | Language::Python) {
        let mut entries = Vec::new();
        for file in files {
            let source = fs::read_to_string(&file)
                .with_context(|| format!("failed to read source from {}", file.display()))?;
            entries.push((file.to_string_lossy().to_string(), source));
        }
        return match language {
            Language::Java => parse_java_project_sources(&entries),
            Language::Python => parse_python_project_sources(&entries),
            _ => unreachable!(),
        };
    }

    let mut project = Program::empty(language.clone());
    for file in files {
        let parsed = parse_source_file(language.clone(), &file)?;
        project.merge(parsed);
    }
    Ok(project)
}

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
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    match language {
        Language::C => matches!(ext, "c" | "h"),
        Language::Cpp => matches!(ext, "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx"),
        Language::Java => ext == "java",
        Language::Python => ext == "py",
        Language::Unknown => false,
    }
}
