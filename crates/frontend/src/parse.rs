use crate::{
    collect_project_headers, collect_source_files, conditionals::prepare_source,
    CompileCommandDatabase, FrontendOptions,
};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use uniflow_hir::{Language, Program, ProgramMerger};
use uniflow_lang_c::CParser;
use uniflow_lang_cpp::CppParser;
use uniflow_lang_frontends::{
    parse_file as parse_descriptor_file, parse_project_sources as parse_descriptor_project_sources,
};
use uniflow_lang_java::{
    parse_project_sources_with_progress as parse_java_project_sources_with_progress, JavaParser,
};
use uniflow_lang_javascript::{
    parse_project_sources_with_progress as parse_javascript_project_sources_with_progress, JavaScriptParser,
};
use uniflow_lang_go::{
    parse_project_sources_with_progress as parse_go_project_sources_with_progress, GoParser,
};
use uniflow_lang_rust::{
    parse_project_sources_with_progress as parse_rust_project_sources_with_progress, RustParser,
};
use uniflow_lang_ruby::{
    parse_project_sources_with_progress as parse_ruby_project_sources_with_progress, RubyParser,
};
use uniflow_lang_python::{
    parse_project_owned_sources_with_progress as parse_python_project_owned_sources_with_progress,
    PythonParser,
};
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

/// `Language::JavaScript` is a catch-all for every extension a JS-ish
/// template toolchain might use (`.vue`, `.ejs`, `.mustache`, `.hbs`,
/// `.html`, `.pug` — see `Language::extensions`), not just real JS/TS
/// source. The new `oxc`-based frontend is a strict, spec-conformant
/// parser (matching exactly the extensions `oxc_span::SourceType::from_path`
/// itself accepts) and correctly fails outright on genuine template-engine
/// syntax (`{{ ... }}` is not valid JS) — those extensions must keep
/// going through the older, template-tolerant descriptor engine.
fn is_pure_javascript_or_typescript(path: &str) -> bool {
    let Some(extension) = Path::new(path).extension().and_then(|ext| ext.to_str()) else { return false };
    matches!(extension.to_ascii_lowercase().as_str(), "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx")
}

fn parse_prepared_source(language: Language, path: &str, source: &str) -> Result<Program> {
    match language {
        Language::C => CParser::default().parse_file(path, source),
        Language::Cpp => CppParser::default().parse_file(path, source),
        Language::Java => JavaParser::default().parse_file(path, source),
        Language::JavaScript if is_pure_javascript_or_typescript(path) => JavaScriptParser::default().parse_file(path, source),
        Language::JavaScript => parse_descriptor_file(language, path, source),
        Language::Python => PythonParser::default().parse_file(path, source),
        Language::Go => GoParser::default().parse_file(path, source),
        Language::Rust => RustParser::default().parse_file(path, source),
        Language::Ruby => RubyParser::default().parse_file(path, source),
        Language::CSharp
        | Language::ObjC
        | Language::ObjCpp
        | Language::Kotlin
        | Language::Swift
        | Language::Jsp
        | Language::Sql
        | Language::Php
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
    // The borrowed public API cannot take ownership of the caller's sources,
    // but the parser must own them while building Java/Python project indexes.
    // Route through the owned implementation so preprocessing replaces each
    // owned source buffer instead of materializing a second prepared vector.
    parse_project_owned_sources_with_options_and_progress(language, entries.to_vec(), options, &|| {})
}

fn parse_project_owned_sources_with_options_and_progress(
    language: Language,
    mut entries: Vec<(String, String)>,
    options: &FrontendOptions,
    on_file_parsed: &(dyn Fn() + Sync),
) -> Result<Program> {
    if entries.is_empty() {
        bail!("no supported source files found");
    }

    let database = load_compile_database(options)?;
    for (path, source) in &mut entries {
        let resolved = options.with_compile_command(
            database
                .as_ref()
                .and_then(|database| database.options_for(Path::new(path))),
        );
        if let std::borrow::Cow::Owned(prepared) = prepare_source(&language, source, &resolved) {
            *source = prepared;
        }
    }

    // Python and JavaScript both use the source path as their module
    // identity. Passing absolute paths made a project at
    // `/work/api/reader.py` appear as `work.api.reader`, so user rules and
    // system-boundary facts using `api.reader` could not match (and for a
    // real filesystem scan, the qualified name would be different — and
    // unpredictable — on every machine/checkout). Normalize once at the
    // project boundary to the common source root; package directories
    // remain part of the resulting module identity. The helper's logic
    // itself is language-agnostic despite its name (it predates JavaScript
    // needing the same treatment).
    if matches!(language, Language::Python | Language::JavaScript | Language::Rust | Language::Ruby) {
        normalize_python_project_entry_paths(&mut entries);
    }

    match language {
        Language::Java => parse_java_project_sources_with_progress(&entries, on_file_parsed),
        Language::JavaScript => parse_javascript_project_sources(entries, on_file_parsed),
        Language::Python => parse_python_project_owned_sources_with_progress(entries, on_file_parsed),
        Language::Go => parse_go_project_sources_with_progress(&entries, on_file_parsed),
        Language::Rust => parse_rust_project_sources_with_progress(&entries, on_file_parsed),
        Language::Ruby => parse_ruby_project_sources_with_progress(&entries, on_file_parsed),
        Language::C | Language::Cpp => parse_c_family_project_sources(language, &entries),
        Language::CSharp
        | Language::ObjC
        | Language::ObjCpp
        | Language::Kotlin
        | Language::Swift
        | Language::Jsp
        | Language::Sql
        | Language::Php
        | Language::Shell => parse_descriptor_project_sources(language, &entries),
        Language::Unknown => bail!("language must be specified"),
    }
}

/// Splits a `Language::JavaScript`-bucketed project between the new
/// `oxc`-based frontend (real `.js`/`.mjs`/`.cjs`/`.jsx`/`.ts`/`.tsx`, ...
/// source, which can carry real cross-file `import`/`require` resolution)
/// and the older, template-tolerant descriptor engine (`.vue`, `.ejs`,
/// `.mustache`, `.hbs`, `.html`, `.pug` — see
/// `is_pure_javascript_or_typescript`), merging both halves' results. Either
/// half may be empty for an all-one-kind project.
fn parse_javascript_project_sources(entries: Vec<(String, String)>, on_file_parsed: &(dyn Fn() + Sync)) -> Result<Program> {
    let (pure_js, template_engine): (Vec<_>, Vec<_>) = entries.into_iter().partition(|(path, _)| is_pure_javascript_or_typescript(path));

    let mut project = ProgramMerger::new(Language::JavaScript);
    if !pure_js.is_empty() {
        project.merge(parse_javascript_project_sources_with_progress(&pure_js, on_file_parsed)?);
    }
    if !template_engine.is_empty() {
        project.merge(parse_descriptor_project_sources(Language::JavaScript, &template_engine)?);
    }
    Ok(project.finish())
}

fn normalize_python_project_entry_paths(entries: &mut [(String, String)]) {
    let paths = entries.iter().map(|(path, _)| Path::new(path)).collect::<Vec<_>>();
    if paths.is_empty() || !paths.iter().all(|path| path.is_absolute()) {
        return;
    }
    let Some(mut root) = paths.first().and_then(|path| path.parent()).map(Path::to_path_buf) else {
        return;
    };
    for path in paths.iter().skip(1) {
        while !path.starts_with(&root) {
            if !root.pop() {
                return;
            }
        }
    }
    for (path, _) in entries {
        if let Ok(relative) = Path::new(path).strip_prefix(&root) {
            *path = relative.to_string_lossy().to_string();
        }
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
    fn python_project_module_names_are_relative_to_the_common_source_root() {
        let program = parse_project_sources(
            Language::Python,
            &[
                ("/tmp/uniflow-project/api/reader.py".to_string(), "def load():\n    pass\n".to_string()),
                ("/tmp/uniflow-project/jobs/writer.py".to_string(), "def store():\n    pass\n".to_string()),
            ],
        )
        .expect("parse Python project");
        let names = program
            .modules
            .iter()
            .flat_map(|module| &module.items)
            .filter_map(|item| match item {
                uniflow_hir::Item::Function(function) => Some(function.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(names.contains(&"api.reader.load"), "{names:?}");
        assert!(names.contains(&"jobs.writer.store"), "{names:?}");
    }

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
            (Language::Shell, "function run() { echo $x\n }", "a.sh"),
        ];
        for (language, source, path) in cases {
            let program = parse_source(language.clone(), path, source).expect(path);
            assert_eq!(program.language, language, "{path}");
            assert!(!program.modules.is_empty(), "{path}");
        }
    }

    /// `Language::Rust` now has a real, strict `syn`-based frontend (see
    /// `uniflow_lang_rust`) rather than the lenient descriptor engine the
    /// other cases above still use — unlike those, its source must be
    /// syntactically valid Rust (e.g. a parameter needs a real type
    /// annotation), so it gets its own dispatch assertion instead of
    /// sharing the loose fixture style above.
    #[test]
    fn public_frontend_dispatches_rust_through_its_real_frontend() {
        let program = parse_source(Language::Rust, "a.rs", "fn run(x: i32) -> i32 { return x; }").expect("a.rs");
        assert_eq!(program.language, Language::Rust);
        assert!(!program.modules.is_empty());
    }

    /// `Language::Ruby` now has a real `lib-ruby-parser`-based frontend (see
    /// `uniflow_lang_ruby`) rather than the lenient descriptor engine the
    /// cases above still use — given its own dispatch assertion for the same
    /// reason Rust's got pulled out above.
    #[test]
    fn public_frontend_dispatches_ruby_through_its_real_frontend() {
        let program = parse_source(Language::Ruby, "a.rb", "def run(x)\n  x\nend\n").expect("a.rb");
        assert_eq!(program.language, Language::Ruby);
        assert!(!program.modules.is_empty());
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

    #[test]
    fn file_backed_descriptor_project_parse_merges_each_input_file() {
        let fixture_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures");
        let files = vec![
            fixture_root.join("streaming_a.js"),
            fixture_root.join("streaming_b.js"),
        ];
        let program = parse_project_files_with_options(
            Language::JavaScript,
            &files,
            &FrontendOptions::default(),
        )
        .expect("file-backed descriptor project parse");

        assert_eq!(program.files.len(), 2);
        let paths = program
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        // JavaScript (like Python) relativizes each entry path to the
        // project's common source root before parsing — an absolute path
        // would otherwise make the qualified module name unpredictable
        // across machines/checkouts (see the call site's comment) — so the
        // stored `SourceFile.path` is the file's own name, not the original
        // absolute fixture path this test constructed it from.
        assert_eq!(paths, vec!["streaming_a.js", "streaming_b.js"]);
    }

    #[test]
    fn file_backed_streaming_ruby_project_uses_project_relative_identities() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "uniflow-ruby-relative-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("services")).expect("create project fixture");
        let first = root.join("services/client.rb");
        let second = root.join("worker.rb");
        std::fs::write(&first, "def send_value(value)\n  value\nend\n").expect("write client");
        std::fs::write(&second, "def consume(value)\n  value\nend\n").expect("write worker");
        let program = parse_project_files_with_options(
            Language::Ruby,
            &[first, second],
            &FrontendOptions::default(),
        )
        .expect("streaming Ruby project parse");
        let paths = program.files.iter().map(|file| file.path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, vec!["services/client.rb", "worker.rb"]);
        let functions = program
            .modules
            .iter()
            .flat_map(|module| &module.items)
            .filter_map(|item| match item {
                uniflow_hir::Item::Function(function) => Some(function.name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(functions.contains(&"services.client.send_value"), "{functions:?}");
        assert!(functions.contains(&"worker.consume"), "{functions:?}");
        std::fs::remove_dir_all(root).expect("remove project fixture");
    }

    #[test]
    fn file_backed_streaming_project_parse_preserves_order_and_reports_every_file() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "uniflow-streaming-project-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("create project fixture");
        let files = (0..48)
            .map(|index| {
                let path = root.join(format!("unit_{index:03}.js"));
                std::fs::write(
                    &path,
                    format!("function unit_{index}(value) {{ return value; }}\n"),
                )
                .expect("write source fixture");
                path
            })
            .collect::<Vec<_>>();
        let completed = std::sync::atomic::AtomicUsize::new(0);
        let program = parse_project_files_with_options_and_progress(
            Language::JavaScript,
            &files,
            &FrontendOptions::default(),
            &|| {
                completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            },
        )
        .expect("streaming project parse");
        let actual = program
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        // Same relativization as the test above — every file here shares
        // one common parent (`root`), so each relativizes to its own bare
        // file name.
        let expected = files
            .iter()
            .map(|file| file.file_name().expect("file name").to_string_lossy())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(completed.load(std::sync::atomic::Ordering::Relaxed), files.len());
        std::fs::remove_dir_all(root).expect("remove project fixture");
    }

    #[test]
    fn indexed_project_languages_preserve_all_modules_after_owned_preprocessing() {
        let cases = [
            (
                Language::Java,
                vec![
                    ("First.java".to_string(), "class First {}".to_string()),
                    ("Second.java".to_string(), "class Second {}".to_string()),
                ],
            ),
            (
                Language::Python,
                vec![
                    ("first.py".to_string(), "def first():\n    return 1\n".to_string()),
                    ("second.py".to_string(), "def second():\n    return 2\n".to_string()),
                ],
            ),
        ];
        for (language, entries) in cases {
            let program = parse_project_sources_with_options(
                language,
                &entries,
                &FrontendOptions::default(),
            )
            .expect("indexed project parse");
            assert_eq!(program.files.len(), entries.len());
        }
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
    parse_project_files_with_options_and_progress(language, files, options, &|| {})
}

/// File-backed project parsing with per-file completion notification.  The
/// callback is intentionally tiny and may be called concurrently by indexed
/// language frontends, so CLI progress can advance without serializing work.
pub fn parse_project_files_with_options_and_progress(
    language: Language,
    files: &[PathBuf],
    options: &FrontendOptions,
    on_file_parsed: &(dyn Fn() + Sync),
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

    // Most frontends do not need a whole-project source snapshot: their
    // project parser is exactly a `ProgramMerger` over independently parsed
    // files.  Keeping `Vec<(path, source)>` here used one copy for the raw
    // sources and another for preprocessed entries, which made even a normal
    // project scan retain the entire repository in memory.  Stream these
    // languages one file at a time instead. Java and Python deliberately stay
    // on their indexed path below because their project indices resolve
    // imports/types across files before any module is parsed.
    if streams_project_files(&language) {
        return parse_streaming_project_files_parallel(
            language,
            &all_files,
            options,
            database.as_ref(),
            on_file_parsed,
        );
    }

    let mut entries = Vec::with_capacity(all_files.len());
    for file in &all_files {
        let source = fs::read_to_string(file)
            .with_context(|| format!("failed to read source from {}", file.display()))?;
        entries.push((file.to_string_lossy().to_string(), source));
    }
    parse_project_owned_sources_with_options_and_progress(language, entries, options, on_file_parsed)
}

/// Parse independent file-backed translation units concurrently while merging
/// completed HIRs in input order.  The bounded channel is important: retaining
/// one `Program` per source file until the end recreates the high-RSS behavior
/// this streaming path is meant to avoid on large polyglot projects.
fn parse_streaming_project_files_parallel(
    language: Language,
    files: &[PathBuf],
    options: &FrontendOptions,
    database: Option<&CompileCommandDatabase>,
    on_file_parsed: &(dyn Fn() + Sync),
) -> Result<Program> {
    // Streaming languages must retain the same stable, checkout-independent
    // module identity as indexed languages.  In particular, Ruby and the
    // descriptor frontends derive qualified functions from this path; using
    // `/var/folders/.../project/app.rb` made both user rules and recovered
    // system-boundary mappings depend on the host's temporary directory.
    let source_root = common_absolute_source_root(files);
    let worker_count = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .min(files.len().max(1));
    if worker_count <= 1 || files.len() <= 1 {
        let mut project = ProgramMerger::new(language.clone());
        for file in files {
            project.merge(parse_streaming_project_file(
                language.clone(),
                file,
                options,
                database,
                source_root.as_deref(),
            )?);
            on_file_parsed();
        }
        return Ok(project.finish());
    }

    let next_file = AtomicUsize::new(0);
    let queue_bound = worker_count.saturating_mul(2).max(1);
    thread::scope(|scope| -> Result<Program> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(queue_bound);
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let sender = sender.clone();
            let worker_language = language.clone();
            let worker_source_root = source_root.clone();
            let next_file = &next_file;
            handles.push(scope.spawn(move || -> Result<()> {
                loop {
                    let index = next_file.fetch_add(1, Ordering::Relaxed);
                    let Some(file) = files.get(index) else {
                        break;
                    };
                    let parsed = parse_streaming_project_file(
                        worker_language.clone(),
                        file,
                        options,
                        database,
                        worker_source_root.as_deref(),
                    )?;
                    sender
                        .send((index, parsed))
                        .map_err(|_| anyhow::anyhow!("streaming project parser receiver stopped early"))?;
                    on_file_parsed();
                }
                Ok(())
            }));
        }
        drop(sender);

        let mut project = ProgramMerger::new(language);
        let mut next_to_merge = 0usize;
        let mut pending = BTreeMap::new();
        for _ in 0..files.len() {
            let (index, parsed) = receiver
                .recv()
                .map_err(|_| anyhow::anyhow!("streaming project parser stopped before producing every file"))?;
            pending.insert(index, parsed);
            while let Some(parsed) = pending.remove(&next_to_merge) {
                project.merge(parsed);
                next_to_merge += 1;
            }
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("streaming project parser worker panicked"))??;
        }
        Ok(project.finish())
    })
}

fn parse_streaming_project_file(
    language: Language,
    file: &Path,
    options: &FrontendOptions,
    database: Option<&CompileCommandDatabase>,
    source_root: Option<&Path>,
) -> Result<Program> {
    let source = fs::read_to_string(file)
        .with_context(|| format!("failed to read source from {}", file.display()))?;
    let resolved = options.with_compile_command(
        database
            .and_then(|database| database.options_for(file)),
    );
    let prepared = prepare_source(&language, &source, &resolved);
    let source_identity = source_root
        .and_then(|root| file.strip_prefix(root).ok())
        .unwrap_or(file)
        .to_string_lossy()
        .to_string();
    parse_prepared_source(language, &source_identity, prepared.as_ref())
}

/// The deepest shared parent of a collection of absolute source files. A
/// relative input intentionally stays untouched: it is already portable and
/// callers may have assigned it a meaningful virtual identity.
fn common_absolute_source_root(files: &[PathBuf]) -> Option<PathBuf> {
    let paths = files.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    if paths.is_empty() || !paths.iter().all(|path| path.is_absolute()) {
        return None;
    }
    let mut root = paths.first()?.parent()?.to_path_buf();
    for path in paths.iter().skip(1) {
        while !path.starts_with(&root) {
            if !root.pop() {
                return None;
            }
        }
    }
    Some(root)
}

/// Languages whose public project parsing contract is a merge of independent
/// translation units. Java, Python, JavaScript, and Go are intentionally
/// excluded: their project indices need to inspect all modules before
/// parsing either one (for JavaScript, resolving a relative `import`/
/// `require` specifier to the exporting file's own qualified function name —
/// see `uniflow_lang_javascript`'s `project_index` module; for Go, resolving
/// a same-package sibling file's free functions/types with zero import — see
/// `uniflow_lang_go`'s `project_index` module; for Rust, finding the
/// project's crate root once up front so every file resolves a `crate::`
/// path the same way — see `uniflow_lang_rust`'s `project_index` module).
fn streams_project_files(language: &Language) -> bool {
    matches!(
        language,
        Language::C
            | Language::Cpp
            | Language::CSharp
            | Language::ObjC
            | Language::ObjCpp
            | Language::Kotlin
            | Language::Swift
            | Language::Jsp
            | Language::Sql
            | Language::Php
            | Language::Ruby
            | Language::Shell
    )
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
