use crate::{
    collect_project_headers, collect_source_files, conditionals::prepare_source, CompileCommandDatabase, FrontendOptions,
};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_hir::{Language, Program};
use uniflow_lang_c::CParser;
use uniflow_lang_cpp::CppParser;
use uniflow_lang_java::{parse_project_sources as parse_java_project_sources, JavaParser};
use uniflow_lang_python::{parse_project_sources as parse_python_project_sources, PythonParser};
use uniflow_parser_core::SourceParser;

fn load_compile_database(options: &FrontendOptions) -> Result<Option<CompileCommandDatabase>> {
    options
        .compile_commands
        .as_deref()
        .map(CompileCommandDatabase::load)
        .transpose()
}

pub fn parse_source(language: Language, path: &str, source: &str) -> Result<Program> {
    parse_source_with_options(language, path, source, &FrontendOptions::default())
}

pub fn parse_source_with_options(
    language: Language,
    path: &str,
    source: &str,
    options: &FrontendOptions,
) -> Result<Program> {
    let database = load_compile_database(options)?;
    let resolved = options.with_compile_command(
        database
            .as_ref()
            .and_then(|database| database.options_for(Path::new(path))),
    );
    let prepared = prepare_source(&language, source, &resolved);
    parse_prepared_source(language, path, prepared.as_ref())
}

fn parse_prepared_source(language: Language, path: &str, source: &str) -> Result<Program> {
    match language {
        Language::C => CParser::default().parse_file(path, source),
        Language::Cpp => CppParser::default().parse_file(path, source),
        Language::Java => JavaParser::default().parse_file(path, source),
        Language::Python => PythonParser::default().parse_file(path, source),
        Language::Unknown => bail!("language must be specified"),
    }
}

pub fn parse_source_file(language: Language, path: &Path) -> Result<Program> {
    parse_source_file_with_options(language, path, &FrontendOptions::default())
}

pub fn parse_source_file_with_options(
    language: Language,
    path: &Path,
    options: &FrontendOptions,
) -> Result<Program> {
    if matches!(language, Language::C | Language::Cpp) {
        return parse_project_files_with_options(language, &[path.to_path_buf()], options);
    }
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read source from {}", path.display()))?;
    parse_source_with_options(language, &path.to_string_lossy(), &source, options)
}

pub fn parse_project_sources(language: Language, entries: &[(String, String)]) -> Result<Program> {
    parse_project_sources_with_options(language, entries, &FrontendOptions::default())
}

pub fn parse_project_sources_with_options(
    language: Language,
    entries: &[(String, String)],
    options: &FrontendOptions,
) -> Result<Program> {
    if entries.is_empty() {
        bail!("no supported source files found");
    }

    let database = load_compile_database(options)?;
    let prepared_entries = entries
        .iter()
        .map(|(path, source)| {
            let resolved = options.with_compile_command(
                database
                    .as_ref()
                    .and_then(|database| database.options_for(Path::new(path))),
            );
            (
                path.clone(),
                prepare_source(&language, source, &resolved).into_owned(),
            )
        })
        .collect::<Vec<_>>();

    match language {
        Language::Java => parse_java_project_sources(&prepared_entries),
        Language::Python => parse_python_project_sources(&prepared_entries),
        Language::C | Language::Cpp => {
            let mut project = Program::empty(language.clone());
            for (path, source) in &prepared_entries {
                let parsed = parse_prepared_source(language.clone(), path, source)?;
                project.merge(parsed);
            }
            Ok(project)
        }
        Language::Unknown => bail!("language must be specified"),
    }
}

pub fn parse_project_files(language: Language, files: &[PathBuf]) -> Result<Program> {
    parse_project_files_with_options(language, files, &FrontendOptions::default())
}

pub fn parse_project_files_with_options(
    language: Language,
    files: &[PathBuf],
    options: &FrontendOptions,
) -> Result<Program> {
    if files.is_empty() {
        bail!("no supported source files found");
    }

    let database = load_compile_database(options)?;
    let headers = collect_project_headers(language.clone(), files, options, database.as_ref())?;
    let mut all_files = files.to_vec();
    for header in headers {
        if !all_files.iter().any(|existing| existing == &header) {
            all_files.push(header);
        }
    }

    let mut entries = Vec::with_capacity(all_files.len());
    for file in &all_files {
        let source = fs::read_to_string(file)
            .with_context(|| format!("failed to read source from {}", file.display()))?;
        entries.push((file.to_string_lossy().to_string(), source));
    }
    parse_project_sources_with_options(language, &entries, options)
}

pub fn parse_project_paths(language: Language, inputs: &[PathBuf]) -> Result<Program> {
    parse_project_paths_with_options(language, inputs, &FrontendOptions::default())
}

pub fn parse_project_paths_with_options(
    language: Language,
    inputs: &[PathBuf],
    options: &FrontendOptions,
) -> Result<Program> {
    let files = collect_source_files(language.clone(), inputs)?;
    parse_project_files_with_options(language, &files, options)
}
