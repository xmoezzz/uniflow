//! JAR/WAR archive traversal: enumerates `.class` entries (recursing into
//! nested `WEB-INF/lib/*.jar` archives for WAR files), pairing each entry's
//! bytes with a provenance string of the form `"{archive path}!{internal
//! path}"` (the conventional `jar:...!/entry` scheme), so decoded classes
//! keep a trail back to the archive/source they came from.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

pub const MAX_CLASSFILE_BYTES: u64 = 64 * 1024 * 1024;

/// Resource limits for archive ingestion.  The bytecode parser works on one
/// complete class at a time, so accepting an unbounded compressed member would
/// let a ZIP bomb turn a scan into an out-of-memory kill.  These limits cover
/// only decompressed class data and nested WAR libraries; ordinary archives
/// with non-class resources do not consume this budget.
#[derive(Clone, Copy, Debug)]
struct ArchiveLimits {
    max_class_bytes: u64,
    max_nested_archive_bytes: u64,
    max_total_decoded_bytes: u64,
    max_nested_depth: usize,
}

impl ArchiveLimits {
    const DEFAULT: Self = Self {
        // Individual JVM classfiles are normally measured in KiB.  64 MiB
        // keeps unusually generated classes supported while protecting the
        // scanner from pathological input.
        max_class_bytes: MAX_CLASSFILE_BYTES,
        // A WAR can legitimately carry many dependencies, but a single
        // nested member this large should not be materialized implicitly.
        max_nested_archive_bytes: 256 * 1024 * 1024,
        // Bound all class/nested-jar bytes retained during one archive's
        // decode. This is deliberately separate from the outer zip size.
        max_total_decoded_bytes: 512 * 1024 * 1024,
        max_nested_depth: 8,
    };
}

#[derive(Debug)]
pub struct ArchiveEntry {
    pub provenance: String,
    pub bytes: Vec<u8>,
}

pub fn read_archive_class_entries(path: &Path) -> Result<Vec<ArchiveEntry>> {
    read_archive_class_entries_with_limits(path, ArchiveLimits::DEFAULT)
}

fn read_archive_class_entries_with_limits(
    path: &Path,
    limits: ArchiveLimits,
) -> Result<Vec<ArchiveEntry>> {
    let archive_label = path.to_string_lossy().to_string();
    let file = std::fs::File::open(path)
        .with_context(|| format!("failed to open archive {}", path.display()))?;
    let mut entries = Vec::new();
    let mut total_decoded_bytes = 0;
    collect_from_zip_reader(
        file,
        &archive_label,
        &mut entries,
        limits,
        0,
        &mut total_decoded_bytes,
    )?;
    Ok(entries)
}

fn collect_from_zip_reader<R: Read + std::io::Seek>(
    reader: R,
    archive_label: &str,
    out: &mut Vec<ArchiveEntry>,
    limits: ArchiveLimits,
    depth: usize,
    total_decoded_bytes: &mut u64,
) -> Result<()> {
    let mut zip = zip::ZipArchive::new(reader)
        .with_context(|| format!("failed to open zip archive {archive_label}"))?;
    let multi_release = zip
        .by_name("META-INF/MANIFEST.MF")
        .ok()
        .and_then(|mut manifest| {
            let mut text = String::new();
            manifest.read_to_string(&mut text).ok().map(|_| text)
        })
        .is_some_and(|text| {
            text.lines().any(|line| {
                line.trim()
                    .eq_ignore_ascii_case("Multi-Release: true")
            })
        });
    // Logical class path -> (selected release, decoded entry).  A
    // Multi-Release JAR must expose one implementation per class, not every
    // historical implementation under META-INF/versions.
    let mut classes = BTreeMap::<String, (u32, ArchiveEntry)>::new();
    for index in 0..zip.len() {
        let mut file = zip
            .by_index(index)
            .with_context(|| format!("failed to read entry {index} of {archive_label}"))?;
        if file.is_dir() {
            continue;
        }
        let name = file.name().to_string();
        if name.ends_with(".class") {
            if name == "module-info.class" || name.ends_with("/module-info.class") {
                continue;
            }
            let (logical_name, release) = match multi_release_class_path(&name) {
                Some((release, logical_name)) if multi_release => (logical_name.to_string(), release),
                Some(_) => continue,
                None => (name.clone(), 0),
            };
            reserve_decoded_bytes(
                total_decoded_bytes,
                file.size(),
                limits.max_class_bytes,
                limits.max_total_decoded_bytes,
                "class entry",
                &name,
                archive_label,
            )?;
            let mut contents = Vec::new();
            file.read_to_end(&mut contents)
                .with_context(|| format!("failed to read {name} from {archive_label}"))?;
            let entry = ArchiveEntry {
                provenance: format!("{archive_label}!{name}"),
                bytes: contents,
            };
            match classes.get(&logical_name) {
                Some((selected_release, _)) if *selected_release >= release => {}
                _ => {
                    classes.insert(logical_name, (release, entry));
                }
            }
        } else if name.starts_with("WEB-INF/lib/") && name.ends_with(".jar") {
            anyhow::ensure!(
                depth < limits.max_nested_depth,
                "nested archive depth exceeds {} while reading {archive_label}!{name}",
                limits.max_nested_depth
            );
            reserve_decoded_bytes(
                total_decoded_bytes,
                file.size(),
                limits.max_nested_archive_bytes,
                limits.max_total_decoded_bytes,
                "nested archive",
                &name,
                archive_label,
            )?;
            let mut nested = Vec::new();
            file.read_to_end(&mut nested)
                .with_context(|| format!("failed to read nested jar {name} from {archive_label}"))?;
            let nested_label = format!("{archive_label}!{name}");
            collect_from_zip_reader(
                std::io::Cursor::new(nested),
                &nested_label,
                out,
                limits,
                depth + 1,
                total_decoded_bytes,
            )?;
        }
    }
    out.extend(classes.into_values().map(|(_, entry)| entry));
    Ok(())
}

/// Returns `(release, logical_class_path)` for a versioned multi-release
/// entry. Invalid version directory names are intentionally treated as normal
/// resources and therefore ignored by the class collector.
fn multi_release_class_path(name: &str) -> Option<(u32, &str)> {
    let suffix = name.strip_prefix("META-INF/versions/")?;
    let (release, logical_name) = suffix.split_once('/')?;
    let release = release.parse::<u32>().ok()?;
    (!logical_name.is_empty() && logical_name.ends_with(".class"))
        .then_some((release, logical_name))
}

fn reserve_decoded_bytes(
    total: &mut u64,
    size: u64,
    per_entry_limit: u64,
    total_limit: u64,
    kind: &str,
    name: &str,
    archive_label: &str,
) -> Result<()> {
    anyhow::ensure!(
        size <= per_entry_limit,
        "{kind} {archive_label}!{name} declares {size} uncompressed bytes, exceeding the {per_entry_limit}-byte safety limit"
    );
    let next_total = total
        .checked_add(size)
        .context("archive decoded-byte counter overflow")?;
    anyhow::ensure!(
        next_total <= total_limit,
        "archive {archive_label} exceeds the {total_limit}-byte decoded-byte safety limit"
    );
    *total = next_total;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_zip(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let mut writer = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, contents) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(contents).unwrap();
        }
        writer.finish().unwrap();
    }

    #[test]
    fn reads_class_entries_and_skips_module_info() {
        let dir = std::env::temp_dir().join(format!("uniflow-jar-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let jar_path = dir.join("lib.jar");
        write_zip(
            &jar_path,
            &[
                ("com/example/Foo.class", b"FOO".as_slice()),
                ("module-info.class", b"MOD".as_slice()),
            ],
        );
        let entries = read_archive_class_entries(&jar_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].provenance.ends_with("!com/example/Foo.class"));
        assert_eq!(entries[0].bytes, b"FOO");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recurses_into_nested_web_inf_lib_jars() {
        let dir = std::env::temp_dir().join(format!("uniflow-war-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let nested_path = dir.join("dep.jar");
        write_zip(&nested_path, &[("com/dep/Dep.class", b"DEP".as_slice())]);
        let nested_bytes = std::fs::read(&nested_path).unwrap();

        let war_path = dir.join("app.war");
        write_zip(
            &war_path,
            &[
                ("WEB-INF/classes/com/app/App.class", b"APP".as_slice()),
                ("WEB-INF/lib/dep.jar", nested_bytes.as_slice()),
            ],
        );
        let entries = read_archive_class_entries(&war_path).unwrap();
        let provenances: Vec<&str> = entries.iter().map(|entry| entry.provenance.as_str()).collect();
        assert!(provenances.iter().any(|p| p.ends_with("!WEB-INF/classes/com/app/App.class")));
        assert!(provenances
            .iter()
            .any(|p| p.contains("WEB-INF/lib/dep.jar!") && p.ends_with("com/dep/Dep.class")));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn refuses_entries_that_exceed_the_decoded_byte_budget_before_allocation() {
        let dir = std::env::temp_dir().join(format!("uniflow-jar-limit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let jar_path = dir.join("oversized.jar");
        write_zip(&jar_path, &[("Example.class", b"too-large".as_slice())]);

        let error = read_archive_class_entries_with_limits(
            &jar_path,
            ArchiveLimits {
                max_class_bytes: 2,
                max_nested_archive_bytes: 2,
                max_total_decoded_bytes: 2,
                max_nested_depth: 1,
            },
        )
        .expect_err("declared class size must be checked before decompression");
        assert!(error.to_string().contains("safety limit"), "{error:#}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn selects_only_the_highest_class_implementation_from_a_multi_release_jar() {
        let dir = std::env::temp_dir().join(format!("uniflow-mrjar-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let jar_path = dir.join("multi-release.jar");
        write_zip(
            &jar_path,
            &[
                ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\nMulti-Release: true\n".as_slice()),
                ("com/example/Api.class", b"BASE".as_slice()),
                ("META-INF/versions/9/com/example/Api.class", b"JAVA9".as_slice()),
                ("META-INF/versions/17/com/example/Api.class", b"JAVA17".as_slice()),
            ],
        );
        let entries = read_archive_class_entries(&jar_path).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].provenance.ends_with("!META-INF/versions/17/com/example/Api.class"));
        assert_eq!(entries[0].bytes, b"JAVA17");
        std::fs::remove_dir_all(&dir).ok();
    }
}
