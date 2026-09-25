//! SCA reachability: for each vulnerable-dependency finding, does
//! first-party code actually use the vulnerable part of the package?
//!
//! Verdicts, strongest first (`uniflow_sca_core::ReachabilityLevel`):
//! - **reachable** — a call/reference to one of the advisory's affected
//!   symbols exists in shipped first-party code;
//! - **imported** — the package's modules are imported, but the advisory
//!   names no symbols, or none of its symbols is referenced;
//! - **unreachable** — no first-party source of the package's language
//!   imports it at all (typical for transitive dependencies), or only test
//!   code does;
//! - **unknown** — the ecosystem isn't analyzable, or there's no
//!   first-party source to analyze.
//!
//! Two evidence layers feed every verdict: `source` (lexical, every
//! language, always on) and `hir` (uniflow's frontends, resolved calls +
//! call graph, only for findings that carry symbols). See ADR-0008 in the
//! Cosmos repo for the design and its limits.
pub mod hir;
pub mod modules;
pub mod source;

use modules::{module_mapping, InstalledMetadata, ModuleMapping};
use serde::{Deserialize, Serialize};
use source::{Lang, SourceFile, UseKind};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Instant;
use uniflow_sca_core::{
    risk_score, Confidence, DependencyFinding, EvidenceKind, Reachability, ReachabilityEvidence, ReachabilityLevel, ScanWarning,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Options {
    /// Directory *names* never treated as first-party source.
    pub exclude_dirs: Vec<String>,
    /// Files above this size are skipped (generated/minified code).
    pub max_file_bytes: u64,
    /// Run uniflow's frontends for call-level precision + call paths.
    pub use_hir: bool,
    /// Above this many files of one language, skip the HIR layer for it
    /// (lexical results only) to keep large-monorepo scans bounded.
    pub max_hir_files: usize,
    /// Cap on evidence entries kept per finding.
    pub max_evidence: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            exclude_dirs: source::DEFAULT_EXCLUDED_DIRS.iter().map(|d| d.to_string()).collect(),
            max_file_bytes: 1_500_000,
            use_hir: true,
            max_hir_files: 4_000,
            max_evidence: 8,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    /// First-party files analyzed, per language.
    pub files_analyzed: BTreeMap<String, usize>,
    /// Languages where the HIR (call-level) layer ran successfully.
    pub hir_languages: Vec<String>,
    pub counts: BTreeMap<String, usize>,
    pub warnings: Vec<ScanWarning>,
    pub duration_ms: u128,
}

type Params = std::collections::BTreeMap<String, String>;

fn params(pairs: &[(&str, String)]) -> Params {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

/// Canonical form a symbol is compared in: `::`, `#` and (for npm)
/// `/`-subpaths flattened to `.`, call parens / Java signatures dropped.
fn canonical(ecosystem: &str, raw: &str) -> String {
    let mut s = raw.trim().replace("::", ".").replace('#', ".");
    if let Some(paren) = s.find('(') {
        s.truncate(paren);
    }
    s = s.trim_end_matches(".<init>").trim_end_matches('.').to_string();
    if ecosystem == "npm" {
        s = s.replace('/', ".");
    }
    if ecosystem == "cargo" {
        // Crate names are written with `-` in advisories but `_` in code.
        if let Some((head, rest)) = s.split_once('.') {
            s = format!("{}.{rest}", head.replace('-', "_"));
        } else {
            s = s.replace('-', "_");
        }
    }
    s
}

/// Advisory symbols are sometimes module-qualified (`yaml.load`) and
/// sometimes relative to the package (OSV Go `imports[].symbols` are bare
/// `Parse` under an import path). Qualify bare ones with every module.
fn qualified_symbols(finding: &DependencyFinding, mapping: &ModuleMapping) -> Vec<String> {
    let eco = finding.ecosystem.as_str();
    let modules: Vec<String> = mapping.modules.iter().map(|m| canonical(eco, m)).collect();
    let mut out = BTreeSet::new();
    for symbol in &finding.affected_symbols {
        let sym = canonical(eco, symbol);
        if sym.is_empty() {
            continue;
        }
        if modules.iter().any(|m| sym == *m || sym.starts_with(&format!("{m}.")) || sym.starts_with(&format!("{m}/"))) {
            out.insert(sym);
        } else {
            for m in &modules {
                out.insert(format!("{m}.{sym}"));
            }
        }
    }
    out.into_iter().collect()
}

/// `name` refers to `symbol` if it's the symbol itself or a member of it
/// (calling any method of an affected class counts).
fn matches_symbol(name: &str, symbol: &str) -> bool {
    name == symbol || name.starts_with(symbol) && name[symbol.len()..].starts_with('.')
}

/// Does an import of `module` (as written in source) bring in package
/// module `prefix`?
fn import_matches(lang: Lang, module: &str, prefix: &str) -> bool {
    if module == prefix {
        return true;
    }
    match lang {
        Lang::JavaScript | Lang::Go | Lang::Ruby => module.starts_with(&format!("{prefix}/")),
        // Java: `import a.b.C` where the package is `a.b`; also a wildcard
        // `import a.b.*` of the package itself (handled by equality).
        Lang::Python | Lang::Java | Lang::Rust => module.starts_with(&format!("{prefix}.")),
    }
}

struct Candidate {
    kind: EvidenceKind,
    file: usize,
    line: u32,
    symbol: String,
    matched: Option<String>,
    confidence: Confidence,
    call_path: Vec<String>,
}

fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    }
}

/// Analyzes `root` and fills in `reachability` and `risk` on every
/// finding in `findings` (in place). Never fails: anything that can't be
/// analyzed becomes an `unknown` verdict and/or a report warning.
pub fn analyze(root: &Path, findings: &mut [DependencyFinding], options: &Options) -> Report {
    let started = Instant::now();
    let mut report = Report::default();

    let langs: BTreeSet<Lang> = findings.iter().filter_map(|f| Lang::for_ecosystem(&f.ecosystem)).collect();
    let langs: Vec<Lang> = langs.into_iter().collect();
    let tree = source::collect(root, &langs, &options.exclude_dirs, options.max_file_bytes);
    if tree.skipped_large > 0 {
        report.warnings.push(ScanWarning::new(
            "reachability_skipped_files",
            None,
            format!("{} source files over {} bytes were not analyzed for reachability", tree.skipped_large, options.max_file_bytes),
            &[("count", tree.skipped_large.to_string()), ("bytes", options.max_file_bytes.to_string())],
        ));
    }
    let files = tree.files;
    let mut by_lang: HashMap<Lang, Vec<usize>> = HashMap::new();
    for (index, file) in files.iter().enumerate() {
        by_lang.entry(file.lang).or_default().push(index);
    }
    for (lang, indices) in &by_lang {
        report.files_analyzed.insert(lang.as_str().to_string(), indices.len());
    }

    // HIR only where it can change a verdict: a language with at least one
    // finding that names affected symbols.
    let mut hir_by_lang: HashMap<Lang, hir::HirFacts> = HashMap::new();
    if options.use_hir {
        let wanted: BTreeSet<Lang> =
            findings.iter().filter(|f| !f.affected_symbols.is_empty()).filter_map(|f| Lang::for_ecosystem(&f.ecosystem)).collect();
        for lang in wanted {
            let Some(indices) = by_lang.get(&lang) else { continue };
            if indices.len() > options.max_hir_files {
                report.warnings.push(ScanWarning::new(
                    "reachability_lexical_only",
                    None,
                    format!(
                        "{} {} files exceed the call-graph limit ({}); {} reachability used import/call-site analysis only",
                        indices.len(),
                        lang.as_str(),
                        options.max_hir_files,
                        lang.as_str()
                    ),
                    &[("count", indices.len().to_string()), ("language", lang.as_str().to_string()), ("limit", options.max_hir_files.to_string())],
                ));
                continue;
            }
            let facts = hir::analyze(lang, &files, indices);
            if let Some(error) = &facts.error {
                report.warnings.push(ScanWarning::new(
                    "reachability_error",
                    None,
                    format!("{} call-graph analysis failed ({error}); fell back to import/call-site analysis", lang.as_str()),
                    &[("language", lang.as_str().to_string())],
                ));
            } else if !facts.calls.is_empty() {
                report.hir_languages.push(lang.as_str().to_string());
            }
            hir_by_lang.insert(lang, facts);
        }
    }

    let installed = InstalledMetadata::discover(root);
    // Findings for the same package share one analysis (a package with
    // five advisories is imported the same way five times).
    let mut cache: HashMap<(String, String, String, Vec<String>), Reachability> = HashMap::new();
    for finding in findings.iter_mut() {
        let mut symbols = finding.affected_symbols.clone();
        symbols.sort();
        let key = (finding.ecosystem.clone(), finding.package.clone(), finding.version.clone(), symbols);
        let verdict = cache
            .entry(key)
            .or_insert_with(|| judge(finding, &files, &by_lang, &hir_by_lang, &installed, options))
            .clone();
        *report.counts.entry(verdict.level.as_str().to_string()).or_default() += 1;
        finding.reachability = Some(verdict);
        finding.risk = Some(risk_score(finding));
    }
    report.duration_ms = started.elapsed().as_millis();
    report
}

fn judge(
    finding: &DependencyFinding,
    files: &[SourceFile],
    by_lang: &HashMap<Lang, Vec<usize>>,
    hir_by_lang: &HashMap<Lang, hir::HirFacts>,
    installed: &InstalledMetadata,
    options: &Options,
) -> Reachability {
    let unknown = |code: &str, reason: String, params: Params| Reachability {
        level: ReachabilityLevel::Unknown,
        confidence: Confidence::Low,
        reason,
        reason_code: code.to_string(),
        reason_params: params,
        analyzer: None,
        evidence: vec![],
    };
    let Some(lang) = Lang::for_ecosystem(&finding.ecosystem) else {
        return unknown(
            "unsupported_ecosystem",
            format!("reachability analysis does not cover the {} ecosystem", finding.ecosystem),
            params(&[("ecosystem", finding.ecosystem.clone())]),
        );
    };
    let Some(indices) = by_lang.get(&lang).filter(|i| !i.is_empty()) else {
        return unknown(
            "no_source",
            format!("no first-party {} source was found to analyze", lang.as_str()),
            params(&[("language", lang.as_str().to_string())]),
        );
    };
    let mapping = module_mapping(&finding.ecosystem, &finding.package, &finding.version, installed);
    if mapping.modules.is_empty() {
        return unknown(
            "no_module_mapping",
            format!("could not determine which modules {} provides", finding.package),
            params(&[("package", finding.package.clone())]),
        );
    }
    let eco = finding.ecosystem.as_str();
    let prefixes: Vec<String> = mapping.modules.clone();
    let canon_prefixes: Vec<String> = prefixes.iter().map(|p| canonical(eco, p)).collect();
    let symbols = qualified_symbols(finding, &mapping);
    let symbol_leaves: BTreeSet<String> = symbols.iter().map(|s| s.rsplit('.').next().unwrap_or(s).to_string()).collect();

    let mut candidates: Vec<Candidate> = Vec::new();
    let mut importing_files: BTreeSet<usize> = BTreeSet::new();
    let mut dynamic = false;

    for &index in indices {
        let file = &files[index];
        dynamic |= file.dynamic_import;
        for import in &file.imports {
            if prefixes.iter().any(|p| import_matches(lang, &import.module, p)) {
                importing_files.insert(index);
                candidates.push(Candidate {
                    kind: EvidenceKind::Import,
                    file: index,
                    line: import.line,
                    symbol: import.module.clone(),
                    matched: None,
                    confidence: Confidence::High,
                    call_path: vec![],
                });
            }
        }
        for used in &file.uses {
            let name = canonical(eco, &used.name);
            let in_package = canon_prefixes.iter().any(|p| matches_symbol(&name, p));
            if !in_package {
                continue;
            }
            // An unbound fully-qualified chain (`org.x.Y.z(...)`, Rust
            // `time::now()`) is itself a use of the package, import or not.
            importing_files.insert(index);
            match symbols.iter().find(|s| matches_symbol(&name, s)) {
                Some(symbol) => candidates.push(Candidate {
                    kind: EvidenceKind::Call,
                    file: index,
                    line: used.line,
                    symbol: used.name.clone(),
                    matched: Some(symbol.clone()),
                    confidence: Confidence::Medium,
                    call_path: vec![],
                }),
                None if used.kind == UseKind::Call || !used.bound => candidates.push(Candidate {
                    kind: EvidenceKind::Reference,
                    file: index,
                    line: used.line,
                    symbol: used.name.clone(),
                    matched: None,
                    confidence: Confidence::High,
                    call_path: vec![],
                }),
                None => {}
            }
        }
    }

    // HIR: resolved call targets (high confidence) + call paths.
    if let Some(facts) = hir_by_lang.get(&lang) {
        for call in &facts.calls {
            let name = canonical(eco, &call.target);
            let Some(symbol) = symbols.iter().find(|s| matches_symbol(&name, s)) else { continue };
            let call_path = call
                .function
                .map(|node| {
                    let mut path = facts.graph.path_to(node);
                    path.push(call.target.clone());
                    path
                })
                .unwrap_or_default();
            // Upgrade a lexical hit on the same line instead of duplicating it.
            if let Some(existing) =
                candidates.iter_mut().find(|c| c.kind == EvidenceKind::Call && c.file == call.file && c.line == call.line)
            {
                existing.confidence = Confidence::High;
                existing.call_path = call_path;
                continue;
            }
            importing_files.insert(call.file);
            candidates.push(Candidate {
                kind: EvidenceKind::Call,
                file: call.file,
                line: call.line,
                symbol: call.target.clone(),
                matched: Some(symbol.clone()),
                confidence: Confidence::High,
                call_path,
            });
        }
    }

    // Last resort for receiver-typed calls neither layer can resolve
    // (`mapper.readValue(...)` where `mapper` is a local): same method
    // name as an affected symbol, in a file that imports the package.
    if !symbols.is_empty() && !candidates.iter().any(|c| c.kind == EvidenceKind::Call) {
        for &index in &importing_files {
            for (method, line) in &files[index].method_calls {
                if symbol_leaves.contains(method) {
                    let matched = symbols.iter().find(|s| s.ends_with(&format!(".{method}"))).cloned();
                    candidates.push(Candidate {
                        kind: EvidenceKind::Call,
                        file: index,
                        line: *line,
                        symbol: method.clone(),
                        matched,
                        confidence: Confidence::Low,
                        call_path: vec![],
                    });
                }
            }
        }
    }

    // Order: shipped code first, calls before references before imports,
    // most confident first, then path/line — deterministic output.
    let kind_rank = |k: EvidenceKind| match k {
        EvidenceKind::Call => 0,
        EvidenceKind::Reference => 1,
        EvidenceKind::Import => 2,
    };
    candidates.sort_by(|a, b| {
        (files[a.file].in_test, kind_rank(a.kind), confidence_rank(a.confidence), &files[a.file].rel, a.line).cmp(&(
            files[b.file].in_test,
            kind_rank(b.kind),
            confidence_rank(b.confidence),
            &files[b.file].rel,
            b.line,
        ))
    });
    candidates.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.kind == b.kind);

    let shipped: Vec<&Candidate> = candidates.iter().filter(|c| !files[c.file].in_test).collect();
    let call = shipped.iter().find(|c| c.kind == EvidenceKind::Call);
    let package = &finding.package;
    let (level, confidence, reason, code, mut reason_params) = if let Some(call) = call {
        let callers = shipped.iter().filter(|c| c.kind == EvidenceKind::Call).count();
        let symbol = call.matched.clone().unwrap_or_else(|| call.symbol.clone());
        (
            ReachabilityLevel::Reachable,
            call.confidence,
            format!("first-party code calls vulnerable {symbol} ({callers} call site{})", if callers == 1 { "" } else { "s" }),
            "calls_symbol",
            params(&[("symbol", symbol), ("count", callers.to_string())]),
        )
    } else if !shipped.is_empty() {
        if symbols.is_empty() {
            (
                ReachabilityLevel::Imported,
                Confidence::High,
                format!("{package} is imported; the advisory does not name vulnerable functions, so call-level reachability can't be decided"),
                "imported_no_symbols",
                params(&[("package", package.clone())]),
            )
        } else {
            let names = symbol_leaves.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
            (
                ReachabilityLevel::Imported,
                // Dynamic dispatch/reflection can call a symbol no static
                // layer sees; say so through confidence.
                if dynamic { Confidence::Low } else { Confidence::Medium },
                format!(
                    "{package} is imported, but none of its {} vulnerable function{} ({names}) is called",
                    symbols.len(),
                    if symbols.len() == 1 { "" } else { "s" },
                ),
                "imported_symbols_not_called",
                params(&[("package", package.clone()), ("count", symbols.len().to_string()), ("symbols", names)]),
            )
        }
    } else if !candidates.is_empty() {
        (
            ReachabilityLevel::Unreachable,
            Confidence::Medium,
            format!("{package} is only used from test code, which doesn't ship"),
            "test_only",
            params(&[("package", package.clone())]),
        )
    } else {
        let confidence = match (mapping.authoritative, dynamic) {
            (true, false) => Confidence::High,
            (false, false) | (true, true) => Confidence::Medium,
            (false, true) => Confidence::Low,
        };
        let mut reason = format!("no first-party {} code imports {package}", lang.as_str());
        if !finding.direct {
            reason.push_str(" (it is only a transitive dependency)");
        }
        (
            ReachabilityLevel::Unreachable,
            confidence,
            reason,
            "not_imported",
            params(&[("package", package.clone()), ("language", lang.as_str().to_string()), ("transitive", (!finding.direct).to_string())]),
        )
    };
    if dynamic && level != ReachabilityLevel::Reachable {
        reason_params.insert("dynamic".into(), "true".into());
    }
    let reason = if dynamic && level == ReachabilityLevel::Unreachable {
        format!("{reason}; dynamic imports exist, so this is not certain")
    } else {
        reason
    };

    let evidence = candidates
        .iter()
        .take(options.max_evidence)
        .map(|c| {
            let file = &files[c.file];
            ReachabilityEvidence {
                kind: c.kind,
                path: file.rel.clone(),
                line: c.line,
                symbol: c.symbol.clone(),
                matched_symbol: c.matched.clone(),
                snippet: file.lines.get(c.line.saturating_sub(1) as usize).map(|l| l.trim().chars().take(240).collect()),
                call_path: c.call_path.clone(),
                in_test: file.in_test,
            }
        })
        .collect();
    Reachability { level, confidence, reason, reason_code: code.to_string(), reason_params, analyzer: Some(lang.as_str().to_string()), evidence }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_forms() {
        assert_eq!(canonical("cargo", "time::now"), "time.now");
        assert_eq!(canonical("cargo", "tokio-util::codec::Framed"), "tokio_util.codec.Framed");
        assert_eq!(canonical("maven", "org.a.B#m(java.lang.String)"), "org.a.B.m");
        assert_eq!(canonical("npm", "lodash/merge"), "lodash.merge");
    }

    #[test]
    fn symbol_matching_is_segment_aware() {
        assert!(matches_symbol("yaml.load", "yaml.load"));
        assert!(matches_symbol("org.a.B.m", "org.a.B"));
        assert!(!matches_symbol("yaml.load_all", "yaml.load"));
    }
}
