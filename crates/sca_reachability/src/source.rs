//! First-party source discovery and the *lexical* analyzer: per-file
//! imports, alias bindings, and qualified call/reference sites, for every
//! supported language. This layer always runs — it's cheap (one pass per
//! file, parallel), tolerant of code the full parsers reject, and it's
//! the only source of accurate import *line numbers* (HIR import spans are
//! not populated by every frontend). The HIR layer (`crate::hir`) then adds
//! higher-confidence resolved call targets and a call graph on top.
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Lang {
    Python,
    JavaScript,
    Java,
    Go,
    Rust,
    Ruby,
}

impl Lang {
    pub fn as_str(&self) -> &'static str {
        match self {
            Lang::Python => "python",
            Lang::JavaScript => "javascript",
            Lang::Java => "java",
            Lang::Go => "go",
            Lang::Rust => "rust",
            Lang::Ruby => "ruby",
        }
    }

    pub fn for_ecosystem(ecosystem: &str) -> Option<Lang> {
        Some(match ecosystem {
            "pypi" => Lang::Python,
            "npm" => Lang::JavaScript,
            "maven" => Lang::Java,
            "go" => Lang::Go,
            "cargo" => Lang::Rust,
            "rubygems" => Lang::Ruby,
            _ => return None,
        })
    }

    fn for_path(path: &Path) -> Option<Lang> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "py" | "pyw" => Lang::Python,
            "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" | "vue" | "svelte" => Lang::JavaScript,
            // JVM languages share Java's import syntax closely enough for
            // the lexical layer, and they consume the same Maven artifacts.
            "java" | "kt" | "kts" | "scala" | "groovy" => Lang::Java,
            "go" => Lang::Go,
            "rs" => Lang::Rust,
            "rb" => Lang::Ruby,
            _ => return None,
        })
    }
}

/// Default directories never treated as first-party source: dependency
/// install trees, build output, VCS metadata, virtualenvs.
pub const DEFAULT_EXCLUDED_DIRS: &[&str] = &[
    "node_modules", "bower_components", "jspm_packages", "vendor", "third_party", "third-party", "target", "build",
    "dist", "out", ".next", ".nuxt", ".git", ".hg", ".svn", ".venv", "venv", "env", ".tox", ".nox", "site-packages",
    "__pycache__", ".mypy_cache", ".gradle", ".idea", ".m2", "Pods", "coverage", ".terraform",
];

/// Whether a path is test code: test code still counts as evidence, but
/// it doesn't ship, so a package used *only* from tests is deprioritized.
pub fn is_test_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase().replace('\\', "/");
    let segments: Vec<&str> = lower.split('/').collect();
    let dirs = &segments[..segments.len().saturating_sub(1)];
    if dirs.iter().any(|d| matches!(*d, "test" | "tests" | "__tests__" | "spec" | "specs" | "testdata" | "testing" | "e2e" | "__mocks__" | "fixtures")) {
        return true;
    }
    let file = segments.last().copied().unwrap_or_default();
    // JVM test classes are recognized by their case-sensitive suffix
    // (`UserServiceTest.java`), so `Latest.java` isn't one.
    let original_file = rel.rsplit(['/', '\\']).next().unwrap_or(rel);
    if [".java", ".kt", ".scala", ".groovy"].iter().any(|ext| {
        original_file.strip_suffix(ext).is_some_and(|stem| stem.ends_with("Test") || stem.ends_with("Tests") || stem.ends_with("IT") || stem.ends_with("Spec"))
    }) {
        return true;
    }
    file.ends_with("_test.go")
        || file.starts_with("test_") && file.ends_with(".py")
        || file.ends_with("_test.py")
        || file == "conftest.py"
        || [".test.", ".spec."].iter().any(|m| file.contains(m))
        || file.ends_with("_spec.rb")
        || file.ends_with("_test.rb")
}

#[derive(Clone, Debug)]
pub struct Import {
    /// Canonical module path as written: `yaml`, `lodash/merge`,
    /// `github.com/x/y`, `org.a.B` (Java class or package), Rust crate root.
    pub module: String,
    pub line: u32,
    /// Java `.*` / Go `.` / Rust `::*` import — brings unqualified names in.
    pub wildcard: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UseKind {
    Call,
    Reference,
}

#[derive(Clone, Debug)]
pub struct Use {
    /// Fully qualified name after resolving the head through this file's
    /// import bindings (`y.load` with `import yaml as y` → `yaml.load`), or
    /// the chain as written when the head isn't bound.
    pub name: String,
    /// Whether the head was resolved through an import binding (or the
    /// chain was already fully qualified at the call site).
    pub bound: bool,
    pub line: u32,
    pub kind: UseKind,
}

#[derive(Clone, Debug)]
pub struct SourceFile {
    pub lang: Lang,
    /// Path relative to the scan root, `/`-separated.
    pub rel: String,
    pub abs: PathBuf,
    pub in_test: bool,
    pub imports: Vec<Import>,
    pub uses: Vec<Use>,
    /// Receiverless-resolvable method calls (`x.readValue(`, `).parse(`):
    /// (method name, line) — matched by name only, low confidence.
    pub method_calls: Vec<(String, u32)>,
    /// `importlib.import_module(`, `require(variable)`, `Class.forName(`,
    /// ... — a hint that "not imported" might be wrong.
    pub dynamic_import: bool,
    pub lines: Vec<String>,
}

pub struct SourceTree {
    pub files: Vec<SourceFile>,
    pub skipped_large: usize,
}

pub fn collect(root: &Path, langs: &[Lang], excluded: &[String], max_file_bytes: u64) -> SourceTree {
    let mut candidates: Vec<(Lang, PathBuf, String)> = Vec::new();
    let mut skipped_large = 0;
    let walker = walkdir::WalkDir::new(root).sort_by_file_name().into_iter().filter_entry(|entry| {
        if entry.depth() == 0 || !entry.file_type().is_dir() {
            return true;
        }
        let name = entry.file_name().to_str().unwrap_or_default();
        !excluded.iter().any(|e| e == name) && !name.ends_with(".dist-info") && !name.ends_with(".egg-info")
    });
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(lang) = Lang::for_path(entry.path()) else { continue };
        if !langs.contains(&lang) {
            continue;
        }
        let name = entry.file_name().to_str().unwrap_or_default();
        // Minified bundles are build output even outside `dist/`.
        if name.ends_with(".min.js") || name.ends_with(".bundle.js") || name.ends_with(".d.ts") {
            continue;
        }
        if entry.metadata().map(|m| m.len() > max_file_bytes).unwrap_or(true) {
            skipped_large += 1;
            continue;
        }
        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path()).to_string_lossy().replace('\\', "/");
        candidates.push((lang, entry.path().to_path_buf(), rel));
    }

    let files = candidates
        .into_par_iter()
        .filter_map(|(lang, abs, rel)| {
            let bytes = std::fs::read(&abs).ok()?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            Some(analyze_file(lang, abs, rel, &text))
        })
        .collect();
    SourceTree { files, skipped_large }
}

pub fn analyze_file(lang: Lang, abs: PathBuf, rel: String, text: &str) -> SourceFile {
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let (imports, bindings, wildcard_dynamic) = match lang {
        Lang::Python => python_imports(&lines),
        Lang::JavaScript => js_imports(&lines),
        Lang::Java => java_imports(&lines),
        Lang::Go => go_imports(&lines),
        Lang::Rust => rust_imports(&lines),
        Lang::Ruby => ruby_imports(&lines),
    };
    let cleaned = strip_comments_and_strings(lang, &lines);
    let dynamic_import = wildcard_dynamic || cleaned.iter().any(|line| dynamic_import_pattern(lang).is_match(line));
    let (uses, method_calls) = extract_uses(lang, &cleaned, &bindings);
    let in_test = is_test_path(&rel);
    SourceFile { lang, rel, abs, in_test, imports, uses, method_calls, dynamic_import, lines }
}

type ImportScan = (Vec<Import>, HashMap<String, String>, bool);

fn re(pattern: &'static str, cell: &'static OnceLock<Regex>) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

fn dynamic_import_pattern(lang: Lang) -> &'static Regex {
    static PY: OnceLock<Regex> = OnceLock::new();
    static JS: OnceLock<Regex> = OnceLock::new();
    static JAVA: OnceLock<Regex> = OnceLock::new();
    static NONE: OnceLock<Regex> = OnceLock::new();
    match lang {
        Lang::Python => re(r"\b(importlib\.import_module|__import__)\s*\(", &PY),
        // `require(x)` / `import(x)` with a non-literal argument (literals
        // were blanked by `strip_comments_and_strings`, leaving `("")`).
        Lang::JavaScript => re(r#"\b(require|import)\s*\(\s*[A-Za-z_$]"#, &JS),
        Lang::Java => re(r"\b(Class\.forName|ClassLoader\.loadClass|\.loadClass)\s*\(", &JAVA),
        // `\b\B` can never match (unlike `$^`, which matches every empty line).
        _ => re(r"\b\B", &NONE),
    }
}

/// Joins a statement that continues across lines (Python parenthesized
/// `from x import (...)`, JS `import {\n a,\n b } from 'x'`, Rust
/// `use a::{\n b };`) into one logical line, keeping the first line number.
fn logical_statements(lines: &[String], starts: impl Fn(&str) -> bool, ends: impl Fn(&str) -> bool) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if starts(trimmed) {
            let start = i;
            let mut joined = trimmed.to_string();
            while !ends(&joined) && i + 1 < lines.len() && i - start < 50 {
                i += 1;
                joined.push(' ');
                joined.push_str(lines[i].trim());
            }
            out.push((start as u32 + 1, joined));
        }
        i += 1;
    }
    out
}

fn balanced(s: &str, open: char, close: char) -> bool {
    s.matches(open).count() <= s.matches(close).count()
}

fn python_imports(lines: &[String]) -> ImportScan {
    static FROM: OnceLock<Regex> = OnceLock::new();
    static IMPORT: OnceLock<Regex> = OnceLock::new();
    let from_re = re(r"^from\s+([\w.]+)\s+import\s+(.+)$", &FROM);
    let import_re = re(r"^import\s+(.+)$", &IMPORT);
    let mut imports = Vec::new();
    let mut bindings = HashMap::new();
    let statements = logical_statements(
        lines,
        |l| l.starts_with("import ") || l.starts_with("from "),
        |l| balanced(l, '(', ')') && !l.trim_end().ends_with('\\'),
    );
    for (line, statement) in statements {
        let statement = statement.split('#').next().unwrap_or_default().replace(['\\', '(', ')'], " ");
        let statement = statement.trim();
        if let Some(caps) = from_re.captures(statement) {
            let module = &caps[1];
            if module.starts_with('.') {
                continue; // relative import = first-party
            }
            imports.push(Import { module: module.to_string(), line, wildcard: caps[2].trim() == "*" });
            for item in caps[2].split(',') {
                let mut parts = item.split_whitespace();
                let Some(name) = parts.next() else { continue };
                if name == "*" {
                    continue;
                }
                let alias = match (parts.next(), parts.next()) {
                    (Some("as"), Some(alias)) => alias,
                    _ => name,
                };
                bindings.insert(alias.to_string(), format!("{module}.{name}"));
            }
        } else if let Some(caps) = import_re.captures(statement) {
            for item in caps[1].split(',') {
                let mut parts = item.split_whitespace();
                let Some(module) = parts.next() else { continue };
                imports.push(Import { module: module.to_string(), line, wildcard: false });
                match (parts.next(), parts.next()) {
                    (Some("as"), Some(alias)) => {
                        bindings.insert(alias.to_string(), module.to_string());
                    }
                    // `import a.b.c` binds `a`; uses are written `a.b.c.f`.
                    _ => {
                        let head = module.split('.').next().unwrap_or(module);
                        bindings.insert(head.to_string(), head.to_string());
                    }
                }
            }
        }
    }
    (imports, bindings, false)
}

fn js_imports(lines: &[String]) -> ImportScan {
    static FROM: OnceLock<Regex> = OnceLock::new();
    static BARE: OnceLock<Regex> = OnceLock::new();
    static REQUIRE: OnceLock<Regex> = OnceLock::new();
    static DYN: OnceLock<Regex> = OnceLock::new();
    let from_re = re(r#"^(?:import|export)\s+(?:type\s+)?(.*?)\s*from\s*['"]([^'"]+)['"]"#, &FROM);
    let bare_re = re(r#"^import\s*['"]([^'"]+)['"]"#, &BARE);
    let require_re = re(r#"(?:(?:const|let|var)\s+([\w$]+|\{[^}]*\})\s*=\s*)?\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)"#, &REQUIRE);
    let dyn_re = re(r#"\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)"#, &DYN);
    let mut imports = Vec::new();
    let mut bindings = HashMap::new();

    let bind_clause = |clause: &str, module: &str, bindings: &mut HashMap<String, String>| {
        let clause = clause.trim();
        let (default_part, named_part) = match clause.find('{') {
            Some(brace) => (&clause[..brace], Some(clause[brace + 1..].trim_end_matches('}'))),
            None => (clause, None),
        };
        for piece in default_part.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let alias = piece.strip_prefix("* as ").or_else(|| piece.strip_prefix("*as ")).unwrap_or(piece).trim();
            if alias.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$') && !alias.is_empty() {
                bindings.insert(alias.to_string(), module.to_string());
            }
        }
        if let Some(named) = named_part {
            for item in named.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                let item = item.trim_start_matches("type ").trim();
                // ES `a as b`, CommonJS destructuring `a: b`.
                let (name, alias) = item.split_once(" as ").or_else(|| item.split_once(':')).map(|(n, a)| (n.trim(), a.trim())).unwrap_or((item, item));
                if !name.is_empty() && !alias.is_empty() {
                    bindings.insert(alias.to_string(), format!("{module}.{name}"));
                }
            }
        }
    };

    let statements = logical_statements(
        lines,
        |l| l.starts_with("import") || l.starts_with("export"),
        |l| balanced(l, '{', '}') && (l.contains(" from ") || l.contains("from'") || l.contains("from\"") || l.contains('\'') || l.contains('"') || !l.contains('{')),
    );
    for (line, statement) in statements {
        if let Some(caps) = from_re.captures(&statement) {
            imports.push(Import { module: caps[2].to_string(), line, wildcard: false });
            bind_clause(&caps[1], &caps[2], &mut bindings);
        } else if let Some(caps) = bare_re.captures(&statement) {
            imports.push(Import { module: caps[1].to_string(), line, wildcard: false });
        }
    }
    for (index, raw) in lines.iter().enumerate() {
        let line = index as u32 + 1;
        for caps in require_re.captures_iter(raw) {
            imports.push(Import { module: caps[2].to_string(), line, wildcard: false });
            if let Some(target) = caps.get(1) {
                bind_clause(target.as_str(), &caps[2], &mut bindings);
            }
        }
        for caps in dyn_re.captures_iter(raw) {
            imports.push(Import { module: caps[1].to_string(), line, wildcard: false });
        }
    }
    // Relative specifiers (`./x`, `../x`, `/abs`) are first-party files.
    imports.retain(|i| !i.module.starts_with('.') && !i.module.starts_with('/'));
    bindings.retain(|_, module| !module.starts_with('.') && !module.starts_with('/'));
    (imports, bindings, false)
}

fn java_imports(lines: &[String]) -> ImportScan {
    static IMPORT: OnceLock<Regex> = OnceLock::new();
    let import_re = re(r"^import\s+(static\s+)?([\w.]+?)(\.\*)?\s*(?:as\s+(\w+))?\s*;?\s*$", &IMPORT);
    let mut imports = Vec::new();
    let mut bindings = HashMap::new();
    for (index, raw) in lines.iter().enumerate() {
        let Some(caps) = import_re.captures(raw.trim()) else { continue };
        let path = caps[2].to_string();
        let wildcard = caps.get(3).is_some();
        imports.push(Import { module: path.clone(), line: index as u32 + 1, wildcard });
        if !wildcard {
            let simple = caps.get(4).map(|m| m.as_str()).unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path));
            bindings.insert(simple.to_string(), path.clone());
        }
    }
    (imports, bindings, false)
}

/// Go's implicit package name for an import path: the last element, minus
/// a major-version suffix (`/v2`, `gopkg.in/yaml.v3`) and the common `go-`
/// / `-go` decorations (`github.com/dgrijalva/jwt-go` declares `package
/// jwt`). A heuristic — the real name is only in the imported package's
/// source — which is why explicit aliases are always preferred.
pub fn go_default_package_name(path: &str) -> String {
    let mut segments: Vec<&str> = path.split('/').collect();
    if segments.len() > 1 && segments.last().is_some_and(|s| s.len() > 1 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit())) {
        segments.pop();
    }
    let mut last = segments.last().copied().unwrap_or(path).to_string();
    if let Some((base, version)) = last.rsplit_once(".v") {
        if version.chars().all(|c| c.is_ascii_digit()) && !version.is_empty() {
            last = base.to_string();
        }
    }
    let last = last.strip_prefix("go-").unwrap_or(&last).to_string();
    let last = last.strip_suffix("-go").or_else(|| last.strip_suffix(".go")).unwrap_or(&last).to_string();
    last.replace(['-', '.'], "")
}

fn go_imports(lines: &[String]) -> ImportScan {
    static SPEC: OnceLock<Regex> = OnceLock::new();
    let spec_re = re(r#"^(?:import\s+)?([\w.]+\s+)?"([^"]+)"\s*$"#, &SPEC);
    let mut imports = Vec::new();
    let mut bindings = HashMap::new();
    let mut in_block = false;
    for (index, raw) in lines.iter().enumerate() {
        let trimmed = raw.split("//").next().unwrap_or_default().trim();
        if trimmed.starts_with("import (") {
            in_block = true;
            continue;
        }
        if in_block && trimmed.starts_with(')') {
            in_block = false;
            continue;
        }
        if !(in_block || trimmed.starts_with("import ")) {
            continue;
        }
        let Some(caps) = spec_re.captures(trimmed) else { continue };
        let path = caps[2].to_string();
        let alias = caps.get(1).map(|m| m.as_str().trim().to_string());
        imports.push(Import { module: path.clone(), line: index as u32 + 1, wildcard: alias.as_deref() == Some(".") });
        match alias.as_deref() {
            Some("_") => {}
            // Dot-imports bring names in unqualified; recorded as a
            // wildcard import above, nothing to bind.
            Some(".") => {}
            Some(alias) => {
                bindings.insert(alias.to_string(), path.clone());
            }
            None => {
                bindings.insert(go_default_package_name(&path), path.clone());
            }
        }
    }
    (imports, bindings, false)
}

/// Expands one Rust `use` tree (`a::b::{c, d as e, f::{g, self}}`) into
/// (full path, bound name) pairs, `::` flattened to `.`.
fn expand_use_tree(prefix: &str, tree: &str, out: &mut Vec<(String, Option<String>)>) {
    let tree = tree.trim();
    if let Some(brace) = tree.find('{') {
        let head = tree[..brace].trim().trim_end_matches("::");
        let inner = tree[brace + 1..].trim().strip_suffix('}').unwrap_or(&tree[brace + 1..]);
        let base = join_path(prefix, head);
        let mut depth = 0;
        let mut start = 0;
        for (i, c) in inner.char_indices() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                ',' if depth == 0 => {
                    expand_use_tree(&base, &inner[start..i], out);
                    start = i + 1;
                }
                _ => {}
            }
        }
        expand_use_tree(&base, &inner[start..], out);
        return;
    }
    if tree.is_empty() {
        return;
    }
    let (path, alias) = match tree.split_once(" as ") {
        Some((path, alias)) => (path.trim(), Some(alias.trim().to_string())),
        None => (tree, None),
    };
    if path == "self" {
        let name = prefix.rsplit('.').next().unwrap_or(prefix).to_string();
        out.push((prefix.to_string(), Some(alias.unwrap_or(name))));
        return;
    }
    let full = join_path(prefix, path);
    if path == "*" {
        out.push((full.trim_end_matches(".*").to_string(), None));
        return;
    }
    let name = full.rsplit('.').next().unwrap_or(&full).to_string();
    out.push((full, Some(alias.unwrap_or(name))));
}

fn join_path(prefix: &str, rest: &str) -> String {
    let rest = rest.trim().replace("::", ".");
    match (prefix.is_empty(), rest.is_empty()) {
        (true, _) => rest,
        (_, true) => prefix.to_string(),
        _ => format!("{prefix}.{rest}"),
    }
}

const RUST_NON_CRATE_ROOTS: &[&str] = &["crate", "self", "super", "std", "core", "alloc", "Self"];

fn rust_imports(lines: &[String]) -> ImportScan {
    static EXTERN: OnceLock<Regex> = OnceLock::new();
    let extern_re = re(r"^extern\s+crate\s+(\w+)(?:\s+as\s+(\w+))?\s*;", &EXTERN);
    let mut imports = Vec::new();
    let mut bindings = HashMap::new();
    let statements = logical_statements(
        lines,
        |l| l.starts_with("use ") || l.starts_with("pub use ") || l.starts_with("pub(crate) use ") || l.starts_with("extern crate "),
        |l| l.contains(';'),
    );
    for (line, statement) in statements {
        if let Some(caps) = extern_re.captures(&statement) {
            imports.push(Import { module: caps[1].to_string(), line, wildcard: false });
            bindings.insert(caps.get(2).map(|m| m.as_str()).unwrap_or(&caps[1]).to_string(), caps[1].to_string());
            continue;
        }
        let body = statement.split_once("use ").map(|(_, b)| b).unwrap_or_default();
        let body = body.split(';').next().unwrap_or_default().trim().trim_start_matches("::");
        let mut expanded = Vec::new();
        expand_use_tree("", body, &mut expanded);
        for (path, alias) in expanded {
            let root = path.split('.').next().unwrap_or_default();
            if RUST_NON_CRATE_ROOTS.contains(&root) {
                continue;
            }
            imports.push(Import { module: path.clone(), line, wildcard: alias.is_none() });
            if let Some(alias) = alias {
                bindings.insert(alias, path);
            }
        }
    }
    (imports, bindings, false)
}

fn ruby_imports(lines: &[String]) -> ImportScan {
    static REQUIRE: OnceLock<Regex> = OnceLock::new();
    let require_re = re(r#"^\s*require\s*\(?\s*['"]([^'"]+)['"]"#, &REQUIRE);
    let imports = lines
        .iter()
        .enumerate()
        .filter_map(|(i, raw)| require_re.captures(raw).map(|caps| Import { module: caps[1].to_string(), line: i as u32 + 1, wildcard: false }))
        .collect();
    (imports, HashMap::new(), false)
}

/// Blanks comments and string/char literal *contents* (keeping the quotes
/// and line structure), so call extraction never matches inside either.
/// A per-language state machine, not a parser: good enough for "is this
/// identifier chain code", which is all the lexical layer needs.
pub fn strip_comments_and_strings(lang: Lang, lines: &[String]) -> Vec<String> {
    let hash_comments = matches!(lang, Lang::Python | Lang::Ruby);
    let slash_comments = !hash_comments;
    let mut out = Vec::with_capacity(lines.len());
    let mut in_block_comment = false;
    let mut in_triple: Option<&'static str> = None;
    for raw in lines {
        let chars: Vec<char> = raw.chars().collect();
        let mut line = String::with_capacity(raw.len());
        let mut i = 0;
        let mut in_string: Option<char> = None;
        while i < chars.len() {
            let c = chars[i];
            let next = chars.get(i + 1).copied();
            if in_block_comment {
                if c == '*' && next == Some('/') {
                    in_block_comment = false;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(delim) = in_triple {
                if raw[raw.char_indices().nth(i).map(|(b, _)| b).unwrap_or(raw.len())..].starts_with(delim) {
                    in_triple = None;
                    line.push_str(delim);
                    i += 3;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(quote) = in_string {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == quote {
                    in_string = None;
                    line.push(c);
                }
                i += 1;
                continue;
            }
            if lang == Lang::Python && (c == '"' || c == '\'') && next == Some(c) && chars.get(i + 2) == Some(&c) {
                in_triple = Some(if c == '"' { "\"\"\"" } else { "'''" });
                line.push_str(if c == '"' { "\"\"\"" } else { "'''" });
                i += 3;
                continue;
            }
            if hash_comments && c == '#' {
                break;
            }
            if slash_comments && c == '/' && next == Some('/') {
                break;
            }
            if slash_comments && c == '/' && next == Some('*') {
                in_block_comment = true;
                i += 2;
                continue;
            }
            // Rust lifetimes (`'a`) aren't char literals; only treat `'` as
            // a quote when a closing one follows closely.
            if c == '"' || c == '`' || (c == '\'' && (lang != Lang::Rust || chars[i + 1..].iter().take(4).any(|&x| x == '\''))) {
                in_string = Some(c);
                line.push(c);
                i += 1;
                continue;
            }
            line.push(c);
            i += 1;
        }
        out.push(line);
    }
    out
}

fn extract_uses(lang: Lang, cleaned: &[String], bindings: &HashMap<String, String>) -> (Vec<Use>, Vec<(String, u32)>) {
    static CHAIN: OnceLock<Regex> = OnceLock::new();
    static AFTER_CALL: OnceLock<Regex> = OnceLock::new();
    // An identifier chain (`.` or `::` separated), optionally followed by
    // Rust turbofish generics, then optionally `(`.
    let chain_re = re(r"(?:^|[^\w$.@:])((?:[A-Za-z_$][\w$]*)(?:\s*(?:\.|::)\s*[A-Za-z_$][\w$]*)*)(\s*(?:::<[^>]*>)?\s*\()?", &CHAIN);
    let after_call_re = re(r"\)\s*\.\s*([A-Za-z_$][\w$]*)\s*\(", &AFTER_CALL);
    let mut uses = Vec::new();
    let mut methods = Vec::new();
    for (index, line) in cleaned.iter().enumerate() {
        let line_no = index as u32 + 1;
        let trimmed = line.trim_start();
        // Import statements themselves are reported via `imports`.
        if trimmed.starts_with("import ") || trimmed.starts_with("from ") && lang == Lang::Python || trimmed.starts_with("use ") && lang == Lang::Rust || trimmed.starts_with("package ") {
            continue;
        }
        for caps in chain_re.captures_iter(line) {
            let chain: String = caps[1].split_whitespace().collect();
            let chain = chain.replace("::", ".");
            let is_call = caps.get(2).is_some();
            let mut segments = chain.split('.');
            let head = segments.next().unwrap_or_default();
            let rest: Vec<&str> = segments.collect();
            match bindings.get(head) {
                Some(target) => {
                    let name = if rest.is_empty() { target.clone() } else { format!("{target}.{}", rest.join(".")) };
                    uses.push(Use { name, bound: true, line: line_no, kind: if is_call { UseKind::Call } else { UseKind::Reference } });
                }
                None if !rest.is_empty() => {
                    // Unbound head: either an already fully-qualified name
                    // (Java FQCN, Rust `crate::path`, Go never), or a method
                    // call on a local value — both kept; matching decides.
                    uses.push(Use { name: chain.clone(), bound: false, line: line_no, kind: if is_call { UseKind::Call } else { UseKind::Reference } });
                    if is_call {
                        methods.push((rest.last().unwrap().to_string(), line_no));
                    }
                }
                None => {}
            }
        }
        for caps in after_call_re.captures_iter(line) {
            methods.push((caps[1].to_string(), line_no));
        }
    }
    (uses, methods)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(lang: Lang, text: &str) -> SourceFile {
        analyze_file(lang, PathBuf::from("x"), "src/x".into(), text)
    }

    fn names(f: &SourceFile) -> Vec<&str> {
        f.uses.iter().filter(|u| u.bound).map(|u| u.name.as_str()).collect()
    }

    #[test]
    fn python_bindings() {
        let f = file(Lang::Python, "import yaml\nimport requests as rq\nfrom jinja2 import (\n    Template,\n    Environment as Env,\n)\nfrom . import local\n\nyaml.load(x)  # yaml.dump(y)\nrq.get(u)\nTemplate(s).render()\ns = \"yaml.safe_load(z)\"\n");
        let modules: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
        assert_eq!(modules, vec!["yaml", "requests", "jinja2"]);
        assert_eq!(f.imports[2].line, 3);
        let n = names(&f);
        assert!(n.contains(&"yaml.load"));
        assert!(n.contains(&"requests.get"));
        assert!(n.contains(&"jinja2.Template"));
        assert!(!n.contains(&"yaml.dump"), "comment content must not count");
        assert!(!n.contains(&"yaml.safe_load"), "string content must not count");
    }

    #[test]
    fn javascript_bindings() {
        let f = file(
            Lang::JavaScript,
            "import _ from 'lodash';\nimport { template as tpl, merge } from \"lodash\";\nimport * as mm from 'minimist';\nconst { parse } = require('qs');\nconst local = require('./local');\nimport {\n  a,\n  b,\n} from '@scope/pkg';\n_.template(x); tpl(y); mm(z); parse(q); a();\n",
        );
        let modules: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
        assert!(modules.contains(&"lodash") && modules.contains(&"minimist") && modules.contains(&"qs") && modules.contains(&"@scope/pkg"));
        assert!(!modules.contains(&"./local"));
        let n = names(&f);
        for expected in ["lodash.template", "minimist", "qs.parse", "@scope/pkg.a"] {
            assert!(n.contains(&expected), "{expected} missing from {n:?}");
        }
        assert_eq!(n.iter().filter(|x| **x == "lodash.template").count(), 2, "alias `tpl` resolves to lodash.template too");
    }

    #[test]
    fn java_bindings_fqcn_and_methods() {
        let f = file(
            Lang::Java,
            "package a;\nimport org.apache.commons.text.StringSubstitutor;\nimport com.fasterxml.jackson.databind.*;\nclass A { void h(String s) {\n StringSubstitutor.replaceSystemProperties(s);\n new ObjectMapper().readValue(s, X.class);\n org.yaml.snakeyaml.Yaml.load(s);\n}}\n",
        );
        assert!(f.imports[1].wildcard);
        let n = names(&f);
        assert!(n.contains(&"org.apache.commons.text.StringSubstitutor.replaceSystemProperties"));
        assert!(f.uses.iter().any(|u| u.name == "org.yaml.snakeyaml.Yaml.load" && !u.bound));
        assert!(f.method_calls.iter().any(|(m, _)| m == "readValue"));
    }

    #[test]
    fn go_default_names_and_aliases() {
        assert_eq!(go_default_package_name("github.com/dgrijalva/jwt-go"), "jwt");
        assert_eq!(go_default_package_name("gopkg.in/yaml.v3"), "yaml");
        assert_eq!(go_default_package_name("github.com/go-chi/chi/v5"), "chi");
        assert_eq!(go_default_package_name("golang.org/x/net/html"), "html");
        let f = file(Lang::Go, "package main\nimport (\n  \"fmt\"\n  j \"github.com/golang-jwt/jwt/v4\"\n  \"golang.org/x/net/html\"\n)\nfunc main() { j.Parse(s, nil); html.Parse(r) }\n");
        let n = names(&f);
        assert!(n.contains(&"github.com/golang-jwt/jwt/v4.Parse"));
        assert!(n.contains(&"golang.org/x/net/html.Parse"));
    }

    #[test]
    fn rust_use_trees_and_paths() {
        let f = file(Lang::Rust, "use hyper::{Server, body::{self, to_bytes as tb}};\nuse std::fmt;\nfn main() { let _ = time::now(); Server::bind(&a); tb(b); fmt::format(x); let s: &'a str = \"x\"; }\n");
        let modules: Vec<&str> = f.imports.iter().map(|i| i.module.as_str()).collect();
        assert_eq!(modules, vec!["hyper.Server", "hyper.body", "hyper.body.to_bytes"]);
        let n = names(&f);
        assert!(n.contains(&"hyper.Server.bind"));
        assert!(n.contains(&"hyper.body.to_bytes"));
        assert!(f.uses.iter().any(|u| u.name == "time.now" && !u.bound));
    }

    #[test]
    fn languages_without_dynamic_import_patterns_never_flag() {
        // Regression: the placeholder pattern `$^` matched blank lines.
        assert!(!file(Lang::Go, "package main\n\nfunc main() {}\n").dynamic_import);
    }

    #[test]
    fn dynamic_imports_are_flagged() {
        assert!(file(Lang::Python, "import importlib\nm = importlib.import_module(name)\n").dynamic_import);
        assert!(file(Lang::JavaScript, "const m = require(name)\n").dynamic_import);
        assert!(!file(Lang::JavaScript, "const m = require('lodash')\n").dynamic_import);
    }

    #[test]
    fn test_paths() {
        for p in ["tests/test_app.py", "pkg/foo_test.go", "src/test/java/ATest.java", "web/__tests__/a.js", "a.spec.ts", "src/app.test.tsx"] {
            assert!(is_test_path(p), "{p}");
        }
        for p in ["src/app.py", "cmd/main.go", "src/main/java/Latest.java", "contest/run.py"] {
            assert!(!is_test_path(p), "{p}");
        }
    }
}
