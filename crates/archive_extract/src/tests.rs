use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use crate::{extract_archives_recursively, ExtractOptions};

fn write_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (name, contents) in entries {
        writer.start_file(*name, options).expect("start zip entry");
        writer.write_all(contents).expect("write zip entry contents");
    }
    writer.finish().expect("finish zip").into_inner()
}

fn write_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, contents) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, *name, *contents)
            .expect("append tar entry");
    }
    builder.into_inner().expect("finish tar")
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn xz(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    lzma_rs::xz_compress(&mut Cursor::new(bytes), &mut output).expect("xz compress");
    output
}

fn one_shot_extract(dir: &Path, options: &ExtractOptions) -> crate::ExtractionReport {
    let (guard, report) = extract_archives_recursively(&[dir.to_path_buf()], options)
        .expect("extraction succeeds")
        .expect("at least one archive was found");
    // Leak the guard for the duration of the assertions the caller still
    // needs to make against `report.extraction_root`.
    std::mem::forget(guard);
    report
}

#[test]
fn round_trips_a_plain_zip_archive() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("payload.zip"),
        write_zip(&[("hello.txt", b"hello from zip")]),
    )
    .expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1);
    assert!(!report.truncated);
    let files = find_all_files(&report.extraction_root);
    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.txt")
        .unwrap_or_else(|| panic!("hello.txt not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), b"hello from zip");
}

#[test]
fn zip_slip_entries_are_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("payload.zip"),
        write_zip(&[
            ("safe.txt", b"safe contents"),
            ("../../evil.txt", b"escaped contents"),
        ]),
    )
    .expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    assert!(
        files.iter().any(|path| path.file_name().unwrap() == "safe.txt"),
        "{files:?}"
    );
    assert!(
        files.iter().all(|path| path.file_name().unwrap() != "evil.txt"),
        "a zip-slip entry escaped extraction: {files:?}"
    );
    // Nothing must have been written outside the scratch directory tree.
    for path in &files {
        assert!(path.starts_with(&report.extraction_root), "{path:?}");
    }
}

#[test]
fn a_decompression_bomb_trips_the_byte_cap() {
    let dir = tempfile::tempdir().expect("temp dir");
    // Highly compressible: a real bomb would decompress to megabytes from a
    // tiny gzip stream.
    let huge = vec![b'A'; 8 * 1024 * 1024];
    fs::write(dir.path().join("bomb.gz"), gzip(&huge)).expect("write fixture");

    let options = ExtractOptions {
        max_entry_bytes: 1024,
        max_total_bytes: 1024,
        ..ExtractOptions::default()
    };
    let report = one_shot_extract(dir.path(), &options);
    assert!(report.truncated, "expected the byte cap to trip");
    assert!(
        report.bytes_written <= 1024,
        "wrote {} bytes past the cap",
        report.bytes_written
    );
}

#[test]
fn nested_zip_inside_a_tar_gz_is_extracted_recursively() {
    let dir = tempfile::tempdir().expect("temp dir");
    let inner_zip = write_zip(&[("deep.txt", b"buried treasure")]);
    let tar_bytes = write_tar(&[("nested.zip", &inner_zip)]);
    fs::write(dir.path().join("outer.tar.gz"), gzip(&tar_bytes)).expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert!(report.archives_found >= 2, "{report:?}");
    let files = find_all_files(&report.extraction_root);
    let deep = files
        .iter()
        .find(|path| path.file_name().unwrap() == "deep.txt")
        .unwrap_or_else(|| panic!("deep.txt not found in {files:?}"));
    assert_eq!(fs::read(deep).unwrap(), b"buried treasure");
}

#[test]
fn round_trips_plain_tar_and_tar_gz() {
    for (name, bytes) in [
        ("payload.tar", write_tar(&[("hello.txt", b"hi from tar")])),
        (
            "payload.tar.gz",
            gzip(&write_tar(&[("hello.txt", b"hi from tar")])),
        ),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join(name), &bytes).expect("write fixture");
        let report = one_shot_extract(dir.path(), &ExtractOptions::default());
        let files = find_all_files(&report.extraction_root);
        let hello = files
            .iter()
            .find(|path| path.file_name().unwrap() == "hello.txt")
            .unwrap_or_else(|| panic!("{name}: hello.txt not found in {files:?}"));
        assert_eq!(fs::read(hello).unwrap(), b"hi from tar", "{name}");
    }
}

#[test]
fn round_trips_tar_xz_via_lzma_rs_compression() {
    let dir = tempfile::tempdir().expect("temp dir");
    let tar_bytes = write_tar(&[("hello.txt", b"hi from tar.xz")]);
    fs::write(dir.path().join("payload.tar.xz"), xz(&tar_bytes)).expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.txt")
        .unwrap_or_else(|| panic!("hello.txt not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), b"hi from tar.xz");
}

#[test]
fn round_trips_standalone_gz_and_xz() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("plain.gz"), gzip(b"gzipped payload")).expect("write fixture");
    fs::write(dir.path().join("plain.xz"), xz(b"xzipped payload")).expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 2, "{report:?}");
    let files = find_all_files(&report.extraction_root);
    let plains: Vec<_> = files
        .iter()
        .filter(|path| path.file_name().unwrap() == "plain")
        .collect();
    assert_eq!(plains.len(), 2, "{files:?}");
    let contents: Vec<Vec<u8>> = plains.iter().map(|path| fs::read(path).unwrap()).collect();
    assert!(contents.contains(&b"gzipped payload".to_vec()), "{contents:?}");
    assert!(contents.contains(&b"xzipped payload".to_vec()), "{contents:?}");
}

#[test]
fn round_trips_bzip2_and_zstd_fixtures() {
    const SAMPLE_BZ2: &[u8] = include_bytes!("../tests/fixtures/sample.txt.bz2");
    const SAMPLE_ZST: &[u8] = include_bytes!("../tests/fixtures/sample.txt.zst");
    const TAR_BZ2: &[u8] = include_bytes!("../tests/fixtures/payload.tar.bz2");
    const TAR_ZST: &[u8] = include_bytes!("../tests/fixtures/payload.tar.zst");

    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("sample.bz2"), SAMPLE_BZ2).expect("write fixture");
    fs::write(dir.path().join("sample.zst"), SAMPLE_ZST).expect("write fixture");
    fs::write(dir.path().join("payload.tar.bz2"), TAR_BZ2).expect("write fixture");
    fs::write(dir.path().join("payload.tar.zst"), TAR_ZST).expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 4, "{report:?}");
    let files = find_all_files(&report.extraction_root);

    let sample_outputs: Vec<_> = files
        .iter()
        .filter(|path| path.file_name().unwrap() == "sample")
        .collect();
    assert_eq!(sample_outputs.len(), 2, "{files:?}");
    for path in sample_outputs {
        assert_eq!(fs::read(path).unwrap(), b"hello from a bzip2 stream");
    }

    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.txt")
        .unwrap_or_else(|| panic!("hello.txt not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), b"hello from inside a tarball");
}

#[test]
fn extensionless_file_is_classified_via_the_magic_fallback() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("mystery"), gzip(b"found via magic")).expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1, "{report:?}");
    let files = find_all_files(&report.extraction_root);
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(fs::read(&files[0]).unwrap(), b"found via magic");
}

#[test]
fn jar_and_war_files_are_left_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(
        dir.path().join("App.jar"),
        write_zip(&[("App.class", b"not real bytecode")]),
    )
    .expect("write fixture");

    let result = extract_archives_recursively(&[dir.path().to_path_buf()], &ExtractOptions::default())
        .expect("extraction succeeds");
    assert!(
        result.is_none(),
        "a .jar should not be treated as a generic archive to extract: {result:?}"
    );
}

fn find_all_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    visit(root, &mut out);
    out
}

fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit(&path, out);
        } else {
            out.push(path);
        }
    }
}
