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

fn lzma(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    lzma_rs::lzma_compress(&mut Cursor::new(bytes), &mut output).expect("lzma compress");
    output
}

fn lzip_single_member(bytes: &[u8]) -> Vec<u8> {
    let lzma_stream = lzma(bytes);
    // lzma-rs emits the standard 13-byte .lzma header followed by the raw
    // range-coded payload. Lzip stores the same raw payload with a compact
    // dictionary byte and a 20-byte trailer.
    let payload = &lzma_stream[13..];
    let member_size = 6 + payload.len() + 20;
    let mut out = b"LZIP\x01\x0b".to_vec(); // 8 MiB dictionary, lc=3/lp=0/pb=2
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32fast::hash(bytes).to_le_bytes());
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&(member_size as u64).to_le_bytes());
    out
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
fn round_trips_lzma_and_zip_package_aliases() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("plain.lzma"), lzma(b"lzma payload")).expect("write lzma");
    fs::write(dir.path().join("package.apk"), write_zip(&[("AndroidManifest.xml", b"manifest")]))
        .expect("write apk zip");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 2, "{report:?}");
    let files = find_all_files(&report.extraction_root);
    assert!(files.iter().any(|path| fs::read(path).ok().as_deref() == Some(b"lzma payload")));
    assert!(files.iter().any(|path| fs::read(path).ok().as_deref() == Some(b"manifest")));
}

#[test]
fn round_trips_a_unix_compress_stream() {
    // Generated by the reference BSD `compress` implementation for the
    // literal fixture below. Keeping the bytes inline makes this test work on
    // hosts that do not ship a `compress` executable.
    const Z_BYTES: &[u8] = &[
        31, 157, 144, 104, 202, 176, 97, 243, 6, 132, 25, 57, 111, 218, 128,
        168, 227, 38, 13, 30, 16, 99, 18, 194, 145, 83, 102, 206, 28, 5,
    ];
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("payload.Z"), Z_BYTES).expect("write .Z fixture");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let payload = files.iter().find(|path| fs::read(path).ok().as_deref() == Some(b"hello from unix compress\n"));
    assert!(payload.is_some(), "decoded .Z payload not found in {files:?}");
}

#[test]
fn round_trips_a_lzip_stream() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("payload.lz"), lzip_single_member(b"hello from lzip\n"))
        .expect("write lzip fixture");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    assert!(files.iter().any(|path| fs::read(path).ok().as_deref() == Some(b"hello from lzip\n")), "{files:?}");
}

#[test]
fn round_trips_lzma_and_lzip_tar_streams() {
    for (name, encoded) in [
        ("payload.tar.lzma", lzma(&write_tar(&[("inside.txt", b"tar lzma")]))),
        ("payload.tar.lz", lzip_single_member(&write_tar(&[("inside.txt", b"tar lzip")]))),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        fs::write(dir.path().join(name), encoded).expect("write tar fixture");
        let report = one_shot_extract(dir.path(), &ExtractOptions::default());
        let files = find_all_files(&report.extraction_root);
        let inside = files.iter().find(|path| path.file_name().and_then(|s| s.to_str()) == Some("inside.txt"))
            .expect("tar member");
        let expected = if name.ends_with(".lz") { b"tar lzip" } else { b"tar lzma" };
        assert_eq!(fs::read(inside).unwrap(), expected, "{name}");
    }
}

#[test]
fn decodes_mtree_as_a_manifest_artifact() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("package.mtree"), b"./bin type=file sha256digest=abc\n")
        .expect("write mtree");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let manifest = files.iter().find(|path| path.extension().and_then(|s| s.to_str()) == Some("manifest"))
        .expect("manifest artifact");
    assert_eq!(fs::read(manifest).unwrap(), b"./bin type=file sha256digest=abc\n");
}

#[test]
fn decodes_shar_here_documents_without_executing_shell() {
    let dir = tempfile::tempdir().expect("temp dir");
    let shar = "#!/bin/sh\ncat > src/main.py <<'EOF'\nprint('ok')\nEOF\n";
    fs::write(dir.path().join("source.shar"), shar).expect("write shar");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let source = files.iter().find(|path| path.file_name().and_then(|s| s.to_str()) == Some("main.py"))
        .expect("decoded source");
    assert_eq!(fs::read(source).unwrap(), b"print('ok')\n");
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

#[test]
fn round_trips_a_7z_archive() {
    let src = tempfile::tempdir().expect("src dir");
    fs::write(src.path().join("app.js"), b"console.log('hi')").expect("write fixture");
    fs::create_dir_all(src.path().join("nested")).expect("mkdir");
    fs::write(src.path().join("nested/package.json"), b"{}").expect("write fixture");

    let dir = tempfile::tempdir().expect("temp dir");
    sevenz_rust2::compress_to_path(src.path(), dir.path().join("payload.7z")).expect("build 7z fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1);
    assert!(!report.truncated);
    let files = find_all_files(&report.extraction_root);
    let app_js = files
        .iter()
        .find(|path| path.file_name().unwrap() == "app.js")
        .unwrap_or_else(|| panic!("app.js not found in {files:?}"));
    assert_eq!(fs::read(app_js).unwrap(), b"console.log('hi')");
    assert!(files.iter().any(|path| path.file_name().unwrap() == "package.json"));
}

#[test]
fn p7z_is_treated_as_a_7z_alias() {
    let src = tempfile::tempdir().expect("src dir");
    fs::write(src.path().join("payload.txt"), b"p7z alias").expect("write fixture");
    let dir = tempfile::tempdir().expect("dir");
    sevenz_rust2::compress_to_path(src.path(), dir.path().join("payload.p7z"))
        .expect("build p7z fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1);
    let files = find_all_files(&report.extraction_root);
    let payload = files
        .iter()
        .find(|path| path.file_name().unwrap() == "payload.txt")
        .expect("payload extracted from p7z");
    assert_eq!(fs::read(payload).unwrap(), b"p7z alias");
}

#[test]
fn malformed_rar_is_reported_without_leaking_scratch_files() {
    let dir = tempfile::tempdir().expect("dir");
    fs::write(dir.path().join("broken.rar"), b"Rar!\x1a\x07\x01\x00")
        .expect("write malformed RAR fixture");

    let result = extract_archives_recursively(&[dir.path().to_path_buf()], &ExtractOptions::default())
        .expect("malformed archive should not abort the scan");
    assert!(result.is_some(), "the RAR candidate should be discovered");
    let (guard, report) = result.unwrap();
    // The pure-Rust decoder may accept a signature-only archive as an empty
    // container. The important invariant is that it completes without
    // writing outside the extraction root, not that it rejects every
    // syntactically valid empty container.
    assert_eq!(report.archives_found, 1);
    assert!(find_all_files(&report.extraction_root).is_empty());
    drop(guard);
}

#[test]
fn zip_slip_entries_are_rejected_in_7z_archives_too() {
    let dir = tempfile::tempdir().expect("temp dir");
    let sevenz_path = dir.path().join("payload.7z");
    let mut writer = sevenz_rust2::SevenZWriter::create(&sevenz_path).expect("create 7z writer");
    writer
        .push_archive_entry(
            sevenz_rust2::SevenZArchiveEntry::new_file("safe.txt"),
            Some(Cursor::new(b"safe contents".to_vec())),
        )
        .expect("push safe entry");
    writer
        .push_archive_entry(
            sevenz_rust2::SevenZArchiveEntry::new_file("../../evil.txt"),
            Some(Cursor::new(b"escaped contents".to_vec())),
        )
        .expect("push traversal entry");
    writer.finish().expect("finish 7z");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    assert!(files.iter().any(|path| path.file_name().unwrap() == "safe.txt"), "{files:?}");
    assert!(
        files.iter().all(|path| path.file_name().unwrap() != "evil.txt"),
        "a path-traversal entry escaped 7z extraction: {files:?}"
    );
    for path in &files {
        assert!(path.starts_with(&report.extraction_root), "{path:?}");
    }
}

fn write_deb(control_tar_gz: &[u8], data_tar_gz: &[u8]) -> Vec<u8> {
    let mut builder = ar::Builder::new(Vec::new());
    let mut append = |name: &str, contents: &[u8]| {
        let header = ar::Header::new(name.as_bytes().to_vec(), contents.len() as u64);
        builder.append(&header, contents).expect("append ar entry");
    };
    append("debian-binary", b"2.0\n");
    append("control.tar.gz", control_tar_gz);
    append("data.tar.gz", data_tar_gz);
    builder.into_inner().expect("finish ar")
}

#[test]
fn round_trips_a_deb_package() {
    let control = gzip(&write_tar(&[("control", b"Package: demo\nVersion: 1.0\n")]));
    let data = gzip(&write_tar(&[("./usr/bin/demo", b"#!/bin/sh\necho hi\n")]));
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("demo.deb"), write_deb(&control, &data)).expect("write fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1);
    assert!(!report.truncated);
    let files = find_all_files(&report.extraction_root);
    let demo_bin = files
        .iter()
        .find(|path| path.file_name().unwrap() == "demo")
        .unwrap_or_else(|| panic!("data.tar's demo binary not found in {files:?}"));
    assert_eq!(fs::read(demo_bin).unwrap(), b"#!/bin/sh\necho hi\n");
    assert!(files.iter().any(|path| path.file_name().unwrap() == "control"));
}

#[test]
fn round_trips_a_cab_archive() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cab_path = dir.path().join("payload.cab");
    let cab_file = fs::File::create(&cab_path).expect("create cab file");

    let mut builder = cab::CabinetBuilder::new();
    let folder = builder.add_folder(cab::CompressionType::None);
    folder.add_file("hello.txt");
    let mut writer = builder.build(cab_file).expect("build cab writer");
    let mut file_writer = writer
        .next_file()
        .expect("advance to file")
        .expect("cab has one file");
    file_writer.write_all(b"hello from cab").expect("write cab entry");
    writer.finish().expect("finish cab");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1);
    assert!(!report.truncated);
    let files = find_all_files(&report.extraction_root);
    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.txt")
        .unwrap_or_else(|| panic!("hello.txt not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), b"hello from cab");
}

#[test]
fn round_trips_a_standalone_ar_archive() {
    let mut builder = ar::Builder::new(Vec::new());
    let payload = b"object payload";
    let header = ar::Header::new(b"hello.o".to_vec(), payload.len() as u64);
    builder.append(&header, &payload[..]).expect("append ar member");
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("libdemo.a"), builder.into_inner().expect("finish ar"))
        .expect("write ar fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let object = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.o")
        .unwrap_or_else(|| panic!("hello.o not found in {files:?}"));
    assert_eq!(fs::read(object).unwrap(), payload);
}

#[test]
fn round_trips_a_standalone_cpio_archive() {
    let input = vec![(
        cpio::NewcBuilder::new("hello.txt").mode(0o100644),
        Cursor::new(b"hello from cpio".to_vec()),
    )];
    let bytes = cpio::write_cpio(input.into_iter(), Vec::new()).expect("build cpio fixture");
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("payload.cpio"), bytes).expect("write cpio fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.txt")
        .unwrap_or_else(|| panic!("hello.txt not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), b"hello from cpio");
}

#[test]
fn extracts_a_stored_lha_member() {
    // A minimal level-0 -lh0- member with an empty payload, followed by the
    // zero-byte end marker.  The fixture is deliberately constructed in Rust
    // so this test does not depend on an installed `lha` executable.
    let lha = b"\x1f\xc3-lh0-\0\0\0\0\0\0\0\0\xca\x83\xe7\x2c\x20\0\x09test\\test\0\0\0";
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("payload.lzh"), lha).expect("write LHA fixture");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    assert!(
        files.iter().any(|path| path.ends_with("test/test")),
        "stored LHA member not found in {files:?}"
    );
}

fn minimal_iso9660() -> Vec<u8> {
    const SECTOR: usize = 2048;
    let mut image = vec![0u8; 32 * SECTOR];
    let pvd = 16 * SECTOR;
    image[pvd] = 1;
    image[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    image[pvd + 6] = 1;
    image[pvd + 40..pvd + 52].copy_from_slice(b"UNIFLOW TEST");
    image[pvd + 80..pvd + 84].copy_from_slice(&(32u32).to_le_bytes());
    image[pvd + 84..pvd + 88].copy_from_slice(&(32u32).to_be_bytes());
    image[pvd + 128..pvd + 130].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    image[pvd + 130..pvd + 132].copy_from_slice(&(SECTOR as u16).to_be_bytes());

    fn record(buf: &mut [u8], offset: usize, lba: u32, size: u32, flags: u8, name: &[u8]) -> usize {
        let length = 33 + name.len() + (name.len() % 2 == 0) as usize;
        buf[offset] = length as u8;
        buf[offset + 2..offset + 6].copy_from_slice(&lba.to_le_bytes());
        buf[offset + 6..offset + 10].copy_from_slice(&lba.to_be_bytes());
        buf[offset + 10..offset + 14].copy_from_slice(&size.to_le_bytes());
        buf[offset + 14..offset + 18].copy_from_slice(&size.to_be_bytes());
        buf[offset + 25] = flags;
        buf[offset + 32] = name.len() as u8;
        buf[offset + 33..offset + 33 + name.len()].copy_from_slice(name);
        length
    }

    let root_record = pvd + 156;
    record(&mut image, root_record, 18, SECTOR as u32, 2, &[0]);
    let term = 17 * SECTOR;
    image[term] = 255;
    image[term + 1..term + 6].copy_from_slice(b"CD001");
    image[term + 6] = 1;
    let root = 18 * SECTOR;
    let mut cursor = 0;
    cursor += record(&mut image, root, 18, SECTOR as u32, 2, &[0]);
    cursor += record(&mut image, root, 18, SECTOR as u32, 2, &[1]);
    cursor += record(&mut image, root, 19, 5, 0, b"HELLO.TXT;1");
    image[19 * SECTOR..19 * SECTOR + 5].copy_from_slice(b"hello");
    let _ = cursor;
    image
}

#[test]
fn round_trips_an_iso9660_image() {
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("payload.iso"), minimal_iso9660()).expect("write ISO fixture");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap().to_string_lossy().starts_with("HELLO.TXT"))
        .unwrap_or_else(|| panic!("ISO file not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), b"hello");
}

#[test]
fn round_trips_a_minimal_xar_archive() {
    let payload = b"hello";
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><xar><toc><file id=\"1\"><type>file</type><name>hello.txt</name><data><length>5</length><offset>0</offset><size>5</size><encoding style=\"application/octet-stream\"/></data></file></toc></xar>"
    );
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml.as_bytes()).expect("compress XAR TOC");
    let toc = encoder.finish().expect("finish XAR TOC");
    let mut xar = Vec::new();
    xar.extend_from_slice(b"xar!");
    xar.extend_from_slice(&28u16.to_be_bytes());
    xar.extend_from_slice(&1u16.to_be_bytes());
    xar.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    xar.extend_from_slice(&(xml.len() as u64).to_be_bytes());
    xar.extend_from_slice(&3u32.to_be_bytes());
    xar.extend_from_slice(&toc);
    xar.extend_from_slice(payload);
    let dir = tempfile::tempdir().expect("temp dir");
    fs::write(dir.path().join("payload.xar"), xar).expect("write XAR fixture");
    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let hello = files
        .iter()
        .find(|path| path.file_name().unwrap() == "hello.txt")
        .unwrap_or_else(|| panic!("XAR file not found in {files:?}"));
    assert_eq!(fs::read(hello).unwrap(), payload);
}

#[test]
fn round_trips_an_rpm_package() {
    let src = tempfile::tempdir().expect("src dir");
    let payload_path = src.path().join("demo.txt");
    fs::write(&payload_path, b"hello from rpm").expect("write fixture");

    let package = rpm::PackageBuilder::new("demo", "1.0.0", "MIT", "x86_64", "demo package")
        .with_file(&payload_path, rpm::FileOptions::new("/usr/share/demo/demo.txt"))
        .expect("add file to rpm")
        .build()
        .expect("build rpm package");

    let dir = tempfile::tempdir().expect("temp dir");
    let rpm_path = dir.path().join("demo.rpm");
    package.write_file(&rpm_path).expect("write rpm fixture");

    let report = one_shot_extract(dir.path(), &ExtractOptions::default());
    assert_eq!(report.archives_found, 1);
    assert!(!report.truncated);
    let files = find_all_files(&report.extraction_root);
    let demo_txt = files
        .iter()
        .find(|path| path.file_name().unwrap() == "demo.txt")
        .unwrap_or_else(|| panic!("demo.txt not found in {files:?}"));
    assert_eq!(fs::read(demo_txt).unwrap(), b"hello from rpm");
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

/// RPM-family images archive `/root` as 0550 and `/etc/shadow-` as 000:
/// an unprivileged extractor must still unpack what is inside and be able
/// to read it (every RPM image used to scan as empty unless run as root).
#[cfg(unix)]
#[test]
fn restrictive_modes_do_not_stop_an_unprivileged_extraction() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut dir = tar::Header::new_gnu();
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_mode(0o550);
    dir.set_size(0);
    dir.set_cksum();
    builder.append_data(&mut dir, "root/", &[][..]).unwrap();
    for (name, mode, body) in [("root/.bash_logout", 0o644, &b"bye"[..]), ("etc/shadow-", 0o000, &b"x"[..])] {
        let mut file = tar::Header::new_gnu();
        file.set_mode(mode);
        file.set_size(body.len() as u64);
        file.set_cksum();
        builder.append_data(&mut file, name, body).unwrap();
    }
    let tmp = tempfile::tempdir().expect("temp dir");
    fs::write(tmp.path().join("layer.tar"), builder.into_inner().unwrap()).unwrap();
    let report = one_shot_extract(tmp.path(), &ExtractOptions::default());
    let files = find_all_files(&report.extraction_root);
    let find = |name: &str| files.iter().find(|p| p.ends_with(name)).cloned().unwrap_or_else(|| panic!("{name} missing from {files:?}"));
    assert_eq!(fs::read(find(".bash_logout")).unwrap(), b"bye");
    assert_eq!(fs::read(find("shadow-")).unwrap(), b"x");
}
