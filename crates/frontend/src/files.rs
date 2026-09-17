use anyhow::{Context, Result};
use std::collections::HashMap;
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

/// Collect source files from a polyglot project and retain the frontend that
/// owns each path.  A mixed project is intentionally split before parsing:
/// each frontend produces a language-specific HIR and no file is ever fed to
/// an unrelated parser.
pub fn collect_mixed_source_files(inputs: &[PathBuf]) -> Result<Vec<(Language, PathBuf)>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_mixed_one(input, &mut out)?;
    }
    route_ambiguous_c_family_headers(&mut out);
    out.sort_by(|(left_language, left_path), (right_language, right_path)| {
        left_path
            .cmp(right_path)
            .then_with(|| left_language.as_str().cmp(right_language.as_str()))
    });
    out.dedup();
    Ok(out)
}

/// Route `.h`/C++ header extensions using nearby implementation files.  The
/// same header extension is shared by C, C++, Objective-C and Objective-C++,
/// so a global priority ordering cannot be correct for a mixed checkout.  A
/// sibling implementation is the strongest available signal; when headers
/// live in `include/`, walk toward the project root and use the nearest parent
/// containing implementation files.  With no usable context, fall back to C
/// for `.h` and C++ for C++-specific header extensions.
fn route_ambiguous_c_family_headers(files: &mut [(Language, PathBuf)]) {
    let mut implementations_by_dir = HashMap::<PathBuf, Vec<Language>>::new();
    for (_, path) in files.iter() {
        let Some(language) = implementation_language_for_path(path) else {
            continue;
        };
        if let Some(parent) = path.parent() {
            let languages = implementations_by_dir.entry(parent.to_path_buf()).or_default();
            if !languages.contains(&language) {
                languages.push(language);
            }
        }
    }

    for (language, path) in files.iter_mut() {
        let Some(fallback) = ambiguous_header_fallback(path) else {
            continue;
        };
        *language = nearest_header_language(path.parent(), &implementations_by_dir)
            .unwrap_or(fallback);
    }
}

fn implementation_language_for_path(path: &Path) -> Option<Language> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("c") => Some(Language::C),
        Some("cpp" | "cc" | "cxx" | "ino") => Some(Language::Cpp),
        Some("m") => Some(Language::ObjC),
        Some("mm" | "M") => Some(Language::ObjCpp),
        _ => None,
    }
}

fn ambiguous_header_fallback(path: &Path) -> Option<Language> {
    match path.extension().and_then(|value| value.to_str()) {
        Some("h") => Some(Language::C),
        Some("hpp" | "hh" | "hxx") => Some(Language::Cpp),
        _ => None,
    }
}

fn nearest_header_language(
    parent: Option<&Path>,
    implementations_by_dir: &HashMap<PathBuf, Vec<Language>>,
) -> Option<Language> {
    let mut current = parent;
    while let Some(directory) = current {
        if let Some(languages) = implementations_by_dir.get(directory) {
            // `mm` subsumes Objective-C and C++ syntax; prefer it when a
            // directory genuinely contains several C-family source kinds.
            for language in [Language::ObjCpp, Language::ObjC, Language::Cpp, Language::C] {
                if languages.contains(&language) {
                    return Some(language);
                }
            }
        }
        current = directory.parent();
    }
    None
}

/// Collect `.jar`/`.war` archive inputs (Java bytecode dependencies and
/// deployable web archives). Kept separate from `collect_source_files`/
/// `collect_mixed_source_files` since archives are binary containers, not
/// text sources a language frontend can parse directly.
pub fn collect_archive_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_archive_one(input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Collect Java bytecode inputs, including standalone `.class` files emitted
/// into build output directories as well as JAR/WAR containers.  Keep this
/// separate from source collection: classfiles are binary IR inputs rather
/// than Java frontend text.
pub fn collect_java_bytecode_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_java_bytecode_one(input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_archive_one(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_archive_path(input) {
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
            collect_archive_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

fn collect_java_bytecode_one(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_java_bytecode_path(input) {
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
            collect_java_bytecode_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

/// Build-tool bootstrap archives checked into virtually every Gradle/Maven
/// repository by convention (e.g. `gradle/wrapper/gradle-wrapper.jar`,
/// `.mvn/wrapper/maven-wrapper.jar`). These vendor the build tool itself, not
/// the analyzed project's own code, so they are never analysis targets.
const BUILD_TOOL_WRAPPER_ARCHIVE_NAMES: &[&str] = &["gradle-wrapper.jar", "maven-wrapper.jar"];

pub fn supports_archive_path(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !matches!(extension, "jar" | "war") {
        return false;
    }
    let is_wrapper_archive = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| BUILD_TOOL_WRAPPER_ARCHIVE_NAMES.contains(&name));
    !is_wrapper_archive
}

pub fn supports_java_bytecode_path(path: &Path) -> bool {
    supports_archive_path(path)
        || path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|extension| extension == "class")
}

/// Collect .NET CIL bytecode inputs (`.dll`/`.exe`), mirroring
/// `collect_java_bytecode_files`'s shape for the JVM.
pub fn collect_dotnet_bytecode_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_dotnet_bytecode_one(input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_dotnet_bytecode_one(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_dotnet_bytecode_path(input) {
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
            collect_dotnet_bytecode_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

pub fn supports_dotnet_bytecode_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| matches!(extension.to_ascii_lowercase().as_str(), "dll" | "exe"))
}

/// Collect CPython bytecode inputs (`.pyc`). Unlike every other collector
/// here, this one must walk *into* `__pycache__` directories — the
/// standard, ubiquitous location `.pyc` files live in a real Python
/// checkout — even though `__pycache__` is in `DEFAULT_IGNORED_DIRECTORIES`
/// for *source* collection (where its contents are irrelevant noise).
pub fn collect_python_bytecode_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_python_bytecode_one(input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_python_bytecode_one(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_python_bytecode_path(input) {
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
            if file_type.is_dir() && is_ignored_directory_for_python_bytecode(&entry.file_name()) {
                continue;
            }
            collect_python_bytecode_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

fn is_ignored_directory_for_python_bytecode(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name != "__pycache__" && DEFAULT_IGNORED_DIRECTORIES.contains(&name)
}

pub fn supports_python_bytecode_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension == "pyc")
}

/// Collect WASM bytecode inputs (`.wasm`). Unlike Java/.NET/Python
/// bytecode, WASM has no owning source `Language` — a module is a genuine
/// cross-language compilation target — so this collector is invoked
/// unconditionally wherever bytecode collection runs at all, regardless of
/// which source language(s) are active for that scan.
pub fn collect_wasm_bytecode_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for input in inputs {
        collect_wasm_bytecode_one(input, &mut out)?;
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_wasm_bytecode_one(input: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if input.is_file() {
        if supports_wasm_bytecode_path(input) {
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
            collect_wasm_bytecode_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

pub fn supports_wasm_bytecode_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension == "wasm")
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

fn collect_mixed_one(input: &Path, out: &mut Vec<(Language, PathBuf)>) -> Result<()> {
    if input.is_file() {
        if let Some(language) = language_for_path(input) {
            out.push((language, input.to_path_buf()));
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
            collect_mixed_one(&entry.path(), out)?;
        }
    }
    Ok(())
}

/// Return the default source frontend for a file in a mixed project.  JSP
/// must win over HTML-like JavaScript templates. C-family headers do not have
/// a unique language by extension, so this function supplies a C/C++ fallback
/// which [`collect_mixed_source_files`] refines from neighboring sources.
pub fn language_for_path(path: &Path) -> Option<Language> {
    if let Some(language) = ambiguous_header_fallback(path) {
        return Some(language);
    }
    [
        Language::ObjCpp,
        Language::ObjC,
        Language::CSharp,
        Language::Cpp,
        Language::C,
        Language::Java,
        Language::Kotlin,
        Language::Swift,
        Language::Python,
        Language::Go,
        Language::Jsp,
        Language::JavaScript,
        Language::Sql,
        Language::Php,
        Language::Ruby,
        Language::Rust,
        Language::Shell,
    ]
    .into_iter()
    .find(|language| supports_path(language, path))
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
    fn mixed_router_selects_exactly_one_frontend_for_every_product_language() {
        let cases = [
            (Language::C, "fixture.c"),
            (Language::Cpp, "fixture.cpp"),
            (Language::CSharp, "fixture.cs"),
            (Language::ObjC, "fixture.m"),
            (Language::ObjCpp, "fixture.mm"),
            (Language::Java, "fixture.java"),
            (Language::Kotlin, "fixture.kt"),
            (Language::Swift, "fixture.swift"),
            (Language::Python, "fixture.py"),
            (Language::Go, "fixture.go"),
            (Language::JavaScript, "fixture.js"),
            (Language::Jsp, "fixture.jsp"),
            (Language::Sql, "fixture.sql"),
            (Language::Php, "fixture.php"),
            (Language::Ruby, "fixture.rb"),
            (Language::Rust, "fixture.rs"),
            (Language::Shell, "fixture.sh"),
        ];

        for (expected, path) in cases {
            assert_eq!(language_for_path(Path::new(path)), Some(expected), "{path}");
        }
    }

    #[test]
    fn mixed_collection_assigns_each_file_to_its_own_frontend() {
        let root = temp_project("mixed-collection");
        for (path, source) in [
            ("Main.java", "class Main {}"),
            ("app.py", "print('ok')"),
            ("query.sql", "select 1"),
            ("web.jsp", "<% out.print(1); %>"),
            ("web.ts", "console.log(1)"),
        ] {
            fs::write(root.join(path), source).unwrap();
        }
        fs::create_dir_all(root.join("target")).unwrap();
        fs::write(root.join("target").join("ignored.rs"), "fn main() {}\n").unwrap();

        let files = collect_mixed_source_files(&[root.clone()]).unwrap();
        assert_eq!(
            files,
            vec![
                (Language::Java, root.join("Main.java")),
                (Language::Python, root.join("app.py")),
                (Language::Sql, root.join("query.sql")),
                (Language::Jsp, root.join("web.jsp")),
                (Language::JavaScript, root.join("web.ts")),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_collection_routes_c_family_headers_from_nearby_implementation_files() {
        let root = temp_project("mixed-c-family-headers");
        for (path, source) in [
            ("c/main.c", "int main(void) { return 0; }"),
            ("c/api.h", "int api(void);"),
            ("cpp/main.cpp", "int main() { return 0; }"),
            ("cpp/api.hpp", "int api();"),
            ("objc/main.m", "int main(void) { return 0; }"),
            ("objc/api.h", "int api(void);"),
            ("objcpp/main.mm", "int main() { return 0; }"),
            ("objcpp/api.hpp", "int api();"),
            ("standalone.h", "int fallback(void);"),
            ("standalone.hpp", "int fallback();"),
        ] {
            let file = root.join(path);
            fs::create_dir_all(file.parent().unwrap()).unwrap();
            fs::write(file, source).unwrap();
        }

        let languages_by_path = collect_mixed_source_files(&[root.clone()])
            .unwrap()
            .into_iter()
            .map(|(language, path)| {
                (
                    path.strip_prefix(&root)
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                    language,
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(languages_by_path["c/api.h"], Language::C);
        assert_eq!(languages_by_path["cpp/api.hpp"], Language::Cpp);
        assert_eq!(languages_by_path["objc/api.h"], Language::ObjC);
        assert_eq!(languages_by_path["objcpp/api.hpp"], Language::ObjCpp);
        assert_eq!(languages_by_path["standalone.h"], Language::C);
        assert_eq!(languages_by_path["standalone.hpp"], Language::Cpp);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn java_bytecode_collection_includes_classfiles_and_archives() {
        let root = temp_project("java-bytecode-collection");
        for path in ["classes/App.class", "lib/dependency.jar", "web/app.war"] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
        fs::write(root.join("ignored.txt"), "not bytecode").unwrap();

        let files = collect_java_bytecode_files(&[root.clone()]).unwrap();
        assert_eq!(
            files,
            vec![
                root.join("classes/App.class"),
                root.join("lib/dependency.jar"),
                root.join("web/app.war"),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dotnet_bytecode_collection_includes_dll_and_exe() {
        let root = temp_project("dotnet-bytecode-collection");
        for path in ["bin/App.dll", "bin/App.exe"] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
        fs::write(root.join("ignored.txt"), "not bytecode").unwrap();

        let files = collect_dotnet_bytecode_files(&[root.clone()]).unwrap();
        assert_eq!(files, vec![root.join("bin/App.dll"), root.join("bin/App.exe")]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn python_bytecode_collection_walks_into_pycache_directories() {
        let root = temp_project("python-bytecode-collection");
        for path in ["__pycache__/mod.cpython-39.pyc", "pkg/__pycache__/sub.pyc"] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"fixture").unwrap();
        }
        fs::write(root.join("mod.py"), "not bytecode").unwrap();

        let files = collect_python_bytecode_files(&[root.clone()]).unwrap();
        assert_eq!(
            files,
            vec![
                root.join("__pycache__/mod.cpython-39.pyc"),
                root.join("pkg/__pycache__/sub.pyc"),
            ]
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wasm_bytecode_collection_finds_modules_regardless_of_directory() {
        let root = temp_project("wasm-bytecode-collection");
        let path = root.join("build/module.wasm");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"fixture").unwrap();
        fs::write(root.join("ignored.txt"), "not bytecode").unwrap();

        let files = collect_wasm_bytecode_files(&[root.clone()]).unwrap();
        assert_eq!(files, vec![path]);
        fs::remove_dir_all(root).unwrap();
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
    fn archive_collection_finds_jars_and_wars_but_not_sources() {
        let root = temp_project("archive-collection");
        fs::write(root.join("Main.java"), "class Main {}").unwrap();
        fs::write(root.join("lib.jar"), b"PK\x03\x04").unwrap();
        fs::write(root.join("app.war"), b"PK\x03\x04").unwrap();
        let files = collect_archive_files(&[root.clone()]).unwrap();
        assert_eq!(files, vec![root.join("app.war"), root.join("lib.jar")]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_collection_skips_gradle_and_maven_wrapper_jars() {
        let root = temp_project("archive-collection-wrapper");
        fs::write(root.join("lib.jar"), b"PK\x03\x04").unwrap();
        let gradle_wrapper = root.join("gradle/wrapper/gradle-wrapper.jar");
        fs::create_dir_all(gradle_wrapper.parent().unwrap()).unwrap();
        fs::write(&gradle_wrapper, b"PK\x03\x04").unwrap();
        let maven_wrapper = root.join(".mvn/wrapper/maven-wrapper.jar");
        fs::create_dir_all(maven_wrapper.parent().unwrap()).unwrap();
        fs::write(&maven_wrapper, b"PK\x03\x04").unwrap();

        let files = collect_archive_files(&[root.clone()]).unwrap();
        assert_eq!(files, vec![root.join("lib.jar")]);

        let bytecode_files = collect_java_bytecode_files(&[root.clone()]).unwrap();
        assert_eq!(bytecode_files, vec![root.join("lib.jar")]);
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
