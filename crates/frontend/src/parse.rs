use crate::{
    collect_project_headers, collect_source_files, conditionals::prepare_source,
    CompileCommandDatabase, FrontendOptions,
};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use uniflow_hir::{Language, Program, ProgramMerger};
use uniflow_lang_c::CParser;
use uniflow_lang_cpp::CppParser;
use uniflow_lang_frontends::{
    parse_file as parse_descriptor_file, parse_project_sources as parse_descriptor_project_sources,
};
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
        Language::CSharp
        | Language::ObjC
        | Language::ObjCpp
        | Language::Kotlin
        | Language::Swift
        | Language::Go
        | Language::JavaScript
        | Language::Jsp
        | Language::Sql
        | Language::Php
        | Language::Ruby
        | Language::Rust
        | Language::Shell => parse_descriptor_file(language, path, source),
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
    if matches!(
        language,
        Language::C | Language::Cpp | Language::ObjC | Language::ObjCpp
    ) {
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
        Language::C | Language::Cpp => parse_c_family_project_sources(language, &prepared_entries),
        Language::CSharp
        | Language::ObjC
        | Language::ObjCpp
        | Language::Kotlin
        | Language::Swift
        | Language::Go
        | Language::JavaScript
        | Language::Jsp
        | Language::Sql
        | Language::Php
        | Language::Ruby
        | Language::Rust
        | Language::Shell => parse_descriptor_project_sources(language, &prepared_entries),
        Language::Unknown => bail!("language must be specified"),
    }
}

fn parse_c_family_project_sources(
    language: Language,
    entries: &[(String, String)],
) -> Result<Program> {
    let worker_count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(entries.len());
    parse_c_family_project_sources_with_workers(language, entries, worker_count)
}

fn parse_c_family_project_sources_with_workers(
    language: Language,
    entries: &[(String, String)],
    worker_count: usize,
) -> Result<Program> {
    let worker_count = worker_count.max(1).min(entries.len().max(1));
    if worker_count <= 1 || entries.len() <= 1 {
        let mut project = ProgramMerger::new(language.clone());
        for (path, source) in entries {
            project.merge(parse_prepared_source(language.clone(), path, source)?);
        }
        return Ok(project.finish());
    }

    let chunk_size = entries.len().div_ceil(worker_count);
    let mut parsed = thread::scope(|scope| -> Result<Vec<(usize, Result<Program>)>> {
        let mut handles = Vec::with_capacity(worker_count);
        for (chunk_index, chunk) in entries.chunks(chunk_size).enumerate() {
            let worker_language = language.clone();
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .enumerate()
                    .map(|(offset, (path, source))| {
                        (
                            chunk_index * chunk_size + offset,
                            parse_prepared_source(worker_language.clone(), path, source),
                        )
                    })
                    .collect::<Vec<_>>()
            }));
        }

        let mut parsed = Vec::with_capacity(entries.len());
        for handle in handles {
            let mut batch = handle
                .join()
                .map_err(|_| anyhow::anyhow!("C-family parser worker panicked"))?;
            parsed.append(&mut batch);
        }
        Ok(parsed)
    })?;
    parsed.sort_by_key(|(index, _)| *index);

    let mut project = ProgramMerger::new(language);
    for (_, unit) in parsed {
        project.merge(unit?);
    }
    Ok(project.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_frontend_dispatches_all_descriptor_languages() {
        let cases = [
            (
                Language::CSharp,
                "string run(string x) { return x; }",
                "a.cs",
            ),
            (Language::ObjC, "char *run(char *x) { return x; }", "a.m"),
            (Language::ObjCpp, "char *run(char *x) { return x; }", "a.mm"),
            (Language::Kotlin, "fun run(x) { return x\n }", "a.kt"),
            (Language::Swift, "func run(x) { return x\n }", "a.swift"),
            (Language::Go, "func run(x) { return x\n }", "a.go"),
            (
                Language::JavaScript,
                "function run(x) { return x; }",
                "a.js",
            ),
            (Language::Jsp, "<% int run(int x) { return x; } %>", "a.jsp"),
            (Language::Sql, "SELECT value FROM items;", "a.sql"),
            (
                Language::Php,
                "<?php function run($x) { return $x; } ?>",
                "a.php",
            ),
            (Language::Ruby, "def run(x)\n return x\nend\n", "a.rb"),
            (Language::Rust, "fn run(x) { return x; }", "a.rs"),
            (Language::Shell, "function run() { echo $x\n }", "a.sh"),
        ];
        for (language, source, path) in cases {
            let program = parse_source(language.clone(), path, source).expect(path);
            assert_eq!(program.language, language, "{path}");
            assert!(!program.modules.is_empty(), "{path}");
        }
    }

    #[test]
    fn c_family_parallel_project_parse_preserves_input_file_order() {
        let entries = (0..8)
            .map(|index| {
                (
                    format!("unit_{index}.c"),
                    format!("int value_{index}(void) {{ return {index}; }}"),
                )
            })
            .collect::<Vec<_>>();

        let program = parse_c_family_project_sources_with_workers(Language::C, &entries, 4)
            .expect("parallel C project parse");
        let paths = program
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        let expected = entries
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>();

        assert_eq!(paths, expected);
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
