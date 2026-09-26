//! Every taint sink a scan can report must resolve to at least one CWE —
//! through its rule metadata, its sink kind, or the weakness its title /
//! message names (the same order `uniflow_taint` uses at report time). A
//! CWE-less finding can't be grouped, scored, gated on or placed in a
//! standards book, so a new rule pack that introduces one fails this test.
use uniflow_hir::Language;
use uniflow_rules::vuln_class::{classify_category, for_sink_kind};

fn uncovered(language: Language) -> Vec<String> {
    let mut rules = uniflow_models::load_with_defaults_for_analysis(language.clone(), None).expect("rule packs load");
    // What `uniflow_core::run_taint_analysis` hydrates before reporting.
    let ids: std::collections::HashSet<String> =
        rules.sinks.iter().map(|s| rules.report_id_for_sink(&s.id).to_string()).chain(rules.sinks.iter().map(|s| s.id.clone())).collect();
    uniflow_models::attach_legacy_metadata_for_ids(&language, &mut rules, &ids).expect("legacy metadata decodes");
    let metadata: std::collections::HashMap<&str, &uniflow_rules::RuleMetadata> = rules.metadata.iter().map(|m| (m.id.as_str(), m)).collect();
    let report_ids: std::collections::HashMap<&str, &str> =
        rules.sink_reports.iter().map(|r| (r.sink_rule_id.as_str(), r.report_rule_id.as_str())).collect();
    let mut out = Vec::new();
    for sink in &rules.sinks {
        let reported = report_ids.get(sink.id.as_str()).copied().unwrap_or(sink.id.as_str());
        let meta = metadata.get(reported).or_else(|| metadata.get(sink.id.as_str()));
        let covered = meta.is_some_and(|m| !m.cwe.is_empty())
            || for_sink_kind(&sink.kind).is_some()
            || meta.is_some_and(|m| classify_category(&format!("{} {}", m.title, m.message)).is_some())
            || classify_category(&format!("{} {}", sink.kind, reported)).is_some();
        if !covered {
            out.push(format!("{reported} (kind {})", sink.kind));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The legacy backlog that still names no weakness (2026-09, after CWEs
/// were derived from Pysa kinds, Go sign checks and rule-id text). A
/// ceiling, not a target: lower it when a change classifies more; a *new*
/// uncovered sink fails immediately. C/C++ (vendor category names such as
/// `Security.Dataflow.CppSetSystem`) and JavaScript (`legacy.javascript.sink.*`
/// with generic kinds) are the remaining bulk.
const ALLOWED_UNCOVERED: &[(Language, usize)] = &[
    (Language::Python, 13),
    (Language::Go, 5),
    (Language::Java, 83),
    (Language::JavaScript, 293),
    (Language::C, 1391),
    (Language::Cpp, 1391),
    (Language::CSharp, 1),
    (Language::Ruby, 2),
];

#[test]
fn every_reportable_sink_has_a_cwe() {
    let mut report = Vec::new();
    for (language, ceiling) in ALLOWED_UNCOVERED {
        let missing = uncovered(language.clone());
        if missing.len() > *ceiling {
            report.push(format!("{language:?}: {} sinks without CWE (ceiling {ceiling}), e.g. {:?}", missing.len(), &missing[..missing.len().min(8)]));
        }
    }
    assert!(report.is_empty(), "{}", report.join("\n"));
}

#[test]
#[ignore = "diagnostic: prints the uncovered sinks' kinds and metadata"]
fn dump_uncovered() {
    for language in [Language::Python, Language::Go, Language::Cpp] {
        let mut rules = uniflow_models::load_with_defaults_for_analysis(language.clone(), None).unwrap();
        let ids: std::collections::HashSet<String> = rules.sinks.iter().map(|s| rules.report_id_for_sink(&s.id).to_string()).collect();
        uniflow_models::attach_legacy_metadata_for_ids(&language, &mut rules, &ids).unwrap();
        let mut kinds: std::collections::BTreeMap<String, (usize, String)> = Default::default();
        for sink in &rules.sinks {
            let reported = rules.report_id_for_sink(&sink.id).to_string();
            let meta = rules.metadata_for(&reported);
            let covered = meta.is_some_and(|m| !m.cwe.is_empty()) || for_sink_kind(&sink.kind).is_some()
                || meta.is_some_and(|m| classify_category(&format!("{} {}", m.title, m.message)).is_some())
                || classify_category(&format!("{} {}", sink.kind, reported)).is_some();
            if !covered {
                let e = kinds.entry(sink.kind.clone()).or_insert((0, String::new()));
                e.0 += 1;
                if e.1.is_empty() { e.1 = format!("{reported} | title={:?} matcher={:?}", meta.map(|m| m.title.clone()), sink.matcher.exact.clone().or(sink.matcher.method_name.clone())); }
            }
        }
        for (k, (n, ex)) in kinds.iter().filter(|(_, (n, _))| *n > 3) { println!("{language:?} {n:5} kind={k} ex={ex}"); }
    }
}
