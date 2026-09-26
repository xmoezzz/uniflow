// Temporary developer probe (sast2-py stream): scan files, print findings.
fn main() {
    let paths: Vec<std::path::PathBuf> = std::env::args().skip(1).map(Into::into).collect();
    let started = std::time::Instant::now();
    let outcome = uniflow_core::scan_source_paths(&paths).unwrap();
    for t in &outcome.taint_findings {
        println!("TAINT {} {:?} {}", t.sink_location, t.cwe, t.sink_rule_id);
    }
    for c in &outcome.checker_findings {
        println!("CHECK {:?} {} {:?}", c.location.uri, c.rule_id, c.properties.get("cwe"));
    }
    for m in &outcome.misuse_findings {
        println!("MISUSE {}:{} {:?} {}", m.path, m.line, m.cwe, m.rule_id);
    }
    eprintln!("{:.1}s", started.elapsed().as_secs_f64());
}
