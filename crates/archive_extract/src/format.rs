//! Archive format classification: extension-based dispatch first (cheap,
//! correct for the vast majority of real files), falling back to pure-Rust
//! magic sniffing (`pure-magic` + the `magic-db` bundled rule database —
//! compiled into this binary at build time, nothing loaded from disk at
//! runtime) only for files with no extension at all.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Zip,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarZst,
    /// GNU lzip-compressed tar stream.
    TarLzip,
    /// Standalone LZMA-compressed tar stream.
    TarLzma,
    /// Unix `compress` (.Z) tar stream.
    TarZ,
    /// Standalone LZMA stream.
    Lzma,
    /// Standalone lzip stream.
    Lzip,
    /// Standalone Unix `compress` stream.
    Z,
    Gz,
    Bz2,
    Xz,
    Zst,
    /// 7z's own container format, decoded with `sevenz-rust2` (pure Rust:
    /// LZMA/LZMA2/COPY, no external `7z`/`7za` binary).
    SevenZ,
    /// A Debian package: an `ar` archive containing `control.tar.*` and
    /// `data.tar.*` members, each reusing this crate's existing tar/gzip/
    /// bzip2/xz/zstd decoders.
    Deb,
    /// An RPM package: read via the `rpm` crate for the header + compressed
    /// payload, decompressed with this crate's existing decoders, then
    /// unpacked as a cpio (`newc`) stream.
    Rpm,
    /// A Microsoft Cabinet file, read via the pure-Rust `cab` crate.
    Cab,
    /// LHA/LZH archive decoded by the pure-Rust `delharc` reader.
    Lha,
    /// ISO9660 filesystem image read by the pure-Rust `iso9660_simple` reader.
    Iso,
    /// XAR archive (macOS package container) decoded by UniFlow's pure-Rust
    /// bounded XML/heap reader.
    Xar,
    /// Standalone Unix `ar` archive (including static `.a` libraries).
    Ar,
    /// Standalone SVR4 `newc` cpio archive.
    Cpio,
    /// BSD mtree manifest. It is data, not executable code, and is copied
    /// into the extraction tree for SCA/metadata consumers.
    Mtree,
    /// Shell archive decoded as data (never executed).
    Shar,
    /// A RAR4/RAR5 archive decoded directly by the pure-Rust `unrar-rs`
    /// streaming backend under UniFlow's extraction budgets.
    Rar,
}

/// `.jar`/`.war`/`.class` are left alone: `uniflow_lang_java_bytecode` already
/// reads them directly (in-memory, preserving `foo.jar!com/Bar.class`
/// provenance naming) wherever they're found on disk — extracting them here
/// too would just scatter their `.class` files as loose files, losing that
/// naming for no benefit.
fn is_reserved_for_another_frontend(lower_name: &str) -> bool {
    lower_name.ends_with(".jar") || lower_name.ends_with(".war") || lower_name.ends_with(".class")
}

pub(crate) fn classify(path: &Path) -> Option<Format> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if is_reserved_for_another_frontend(&name) {
        return None;
    }
    if let Some(format) = classify_by_extension(&name) {
        return Some(format);
    }
    if !name.contains('.') {
        return classify_by_magic(path);
    }
    None
}

fn classify_by_extension(lower_name: &str) -> Option<Format> {
    // Compound `tar.*` suffixes must be checked before the plain
    // single-extension forms they end with (e.g. `.tar.gz` before `.gz`).
    if lower_name.ends_with(".tar.gz") || lower_name.ends_with(".tgz") {
        Some(Format::TarGz)
    } else if lower_name.ends_with(".tar.bz2")
        || lower_name.ends_with(".tbz2")
        || lower_name.ends_with(".tbz")
    {
        Some(Format::TarBz2)
    } else if lower_name.ends_with(".tar.xz") || lower_name.ends_with(".txz") {
        Some(Format::TarXz)
    } else if lower_name.ends_with(".tar.zst") || lower_name.ends_with(".tzst") {
        Some(Format::TarZst)
    } else if lower_name.ends_with(".tar.lz") || lower_name.ends_with(".tlz") {
        Some(Format::TarLzip)
    } else if lower_name.ends_with(".tar.lzma") || lower_name.ends_with(".tlzma") {
        Some(Format::TarLzma)
    } else if lower_name.ends_with(".tar.z") || lower_name.ends_with(".taz") {
        Some(Format::TarZ)
    } else if lower_name.ends_with(".tar") {
        Some(Format::Tar)
    } else if lower_name.ends_with(".zip")
        || lower_name.ends_with(".apk")
        || lower_name.ends_with(".aab")
        || lower_name.ends_with(".ipa")
        || lower_name.ends_with(".nupkg")
        || lower_name.ends_with(".vsix")
        || lower_name.ends_with(".appx")
        || lower_name.ends_with(".msix")
        || lower_name.ends_with(".whl")
        || lower_name.ends_with(".egg")
        || lower_name.ends_with(".crx")
    {
        Some(Format::Zip)
    } else if lower_name.ends_with(".gz") {
        Some(Format::Gz)
    } else if lower_name.ends_with(".bz2") {
        Some(Format::Bz2)
    } else if lower_name.ends_with(".xz") {
        Some(Format::Xz)
    } else if lower_name.ends_with(".lzma") {
        Some(Format::Lzma)
    } else if lower_name.ends_with(".lz") {
        Some(Format::Lzip)
    } else if lower_name.ends_with(".z") {
        Some(Format::Z)
    } else if lower_name.ends_with(".zst") {
        Some(Format::Zst)
    } else if lower_name.ends_with(".7z") || lower_name.ends_with(".p7z") {
        Some(Format::SevenZ)
    } else if lower_name.ends_with(".deb") {
        Some(Format::Deb)
    } else if lower_name.ends_with(".rpm") {
        Some(Format::Rpm)
    } else if lower_name.ends_with(".cab") {
        Some(Format::Cab)
    } else if lower_name.ends_with(".lha") || lower_name.ends_with(".lzh") {
        Some(Format::Lha)
    } else if lower_name.ends_with(".iso")
        || lower_name.ends_with(".iso9660")
        || lower_name.ends_with(".img")
    {
        Some(Format::Iso)
    } else if lower_name.ends_with(".xar") || lower_name.ends_with(".pkg") {
        Some(Format::Xar)
    } else if lower_name.ends_with(".cpio") {
        Some(Format::Cpio)
    } else if lower_name.ends_with(".mtree") {
        Some(Format::Mtree)
    } else if lower_name.ends_with(".shar") {
        Some(Format::Shar)
    } else if lower_name.ends_with(".a") || lower_name.ends_with(".ar") {
        Some(Format::Ar)
    } else if is_primary_rar_volume(lower_name) {
        Some(Format::Rar)
    } else {
        None
    }
}

static MAGIC_DB: OnceLock<Option<pure_magic::MagicDb>> = OnceLock::new();

fn bundled_magic_database() -> Option<&'static pure_magic::MagicDb> {
    MAGIC_DB
        .get_or_init(|| match magic_db::load() {
            Ok(db) => Some(db),
            Err(error) => {
                eprintln!("uniflow: failed to load the bundled magic database: {error}");
                None
            }
        })
        .as_ref()
}

fn classify_by_magic(path: &Path) -> Option<Format> {
    // The bundled magic database intentionally only runs for extensionless
    // files.  RAR signatures are cheap to recognize directly and this also
    // covers extensionless RAR volumes without adding a system dependency.
    let mut header = [0u8; 8];
    if File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_ok()
    {
        if is_rar_signature(&header) {
            return Some(Format::Rar);
        }
    }
    let mut iso_header = [0u8; 5];
    if File::open(path)
        .and_then(|mut file| {
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0x8001))?;
            file.read_exact(&mut iso_header)
        })
        .is_ok()
        && iso_header == *b"CD001"
    {
        return Some(Format::Iso);
    }
    let mut signature = [0u8; 8];
    if File::open(path)
        .and_then(|mut file| file.read_exact(&mut signature))
        .is_ok()
    {
        if &signature[..4] == b"xar!" {
            return Some(Format::Xar);
        }
        if &signature == b"!<arch>\n" {
            return Some(Format::Ar);
        }
        if &signature[..6] == b"070701" || &signature[..6] == b"070702" {
            return Some(Format::Cpio);
        }
        if signature[..2] == [0x1f, 0x9d] {
            return Some(Format::Z);
        }
        if &signature[..4] == b"LZIP" {
            return Some(Format::Lzip);
        }
    }
    let db = bundled_magic_database()?;
    let magic = db.first_magic_file(path).ok()?;
    match magic.mime_type() {
        "application/zip" => Some(Format::Zip),
        "application/x-tar" | "application/x-gtar" | "application/x-ustar" => Some(Format::Tar),
        "application/gzip" => Some(Format::Gz),
        "application/x-bzip2" => Some(Format::Bz2),
        "application/x-xz" => Some(Format::Xz),
        "application/zstd" => Some(Format::Zst),
        "application/x-7z-compressed" => Some(Format::SevenZ),
        "application/vnd.debian.binary-package" => Some(Format::Deb),
        "application/x-rpm" | "application/x-redhat-package-manager" => Some(Format::Rpm),
        "application/vnd.ms-cab-compressed" => Some(Format::Cab),
        "application/x-lha" | "application/x-lzh" => Some(Format::Lha),
        "application/x-iso9660-image" => Some(Format::Iso),
        "application/x-xar" => Some(Format::Xar),
        "application/x-archive" | "application/x-ar" => Some(Format::Ar),
        "application/x-cpio" => Some(Format::Cpio),
        _ => None,
    }
}

fn is_rar_signature(header: &[u8; 8]) -> bool {
    // RAR 4.x: 52 61 72 21 1a 07 00
    // RAR 5.x: 52 61 72 21 1a 07 01 00
    header[..7] == *b"Rar!\x1a\x07\x00" || header == b"Rar!\x1a\x07\x01\x00"
}

/// Only the first volume is a scan candidate.  Later `.partNN.rar` files
/// carry the same signature and would otherwise be extracted a second time.
/// The legacy `.r00`/`.r01` names are deliberately not classified: they are
/// continuation volumes and have no standalone entry point.
fn is_primary_rar_volume(lower_name: &str) -> bool {
    if !lower_name.ends_with(".rar") {
        return false;
    }
    let stem = &lower_name[..lower_name.len() - ".rar".len()];
    let Some(part) = stem.rfind(".part") else {
        return true;
    };
    let suffix = &stem[part + ".part".len()..];
    !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit()) && suffix.parse::<u64>().ok() == Some(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;

    fn classify_name(name: &str) -> Option<Format> {
        classify_by_extension(&name.to_ascii_lowercase())
    }

    #[test]
    fn recognizes_compound_tar_extensions_before_the_plain_form() {
        assert_eq!(classify_name("a.tar.gz"), Some(Format::TarGz));
        assert_eq!(classify_name("a.tgz"), Some(Format::TarGz));
        assert_eq!(classify_name("a.tar.bz2"), Some(Format::TarBz2));
        assert_eq!(classify_name("a.tbz2"), Some(Format::TarBz2));
        assert_eq!(classify_name("a.tar.xz"), Some(Format::TarXz));
        assert_eq!(classify_name("a.txz"), Some(Format::TarXz));
        assert_eq!(classify_name("a.tar.zst"), Some(Format::TarZst));
        assert_eq!(classify_name("a.tzst"), Some(Format::TarZst));
        assert_eq!(classify_name("a.tar"), Some(Format::Tar));
    }

    #[test]
    fn recognizes_standalone_compressed_and_zip_extensions() {
        assert_eq!(classify_name("a.zip"), Some(Format::Zip));
        for name in ["app.apk", "bundle.aab", "ios.ipa", "pkg.nupkg", "ext.vsix", "app.appx", "lib.whl", "browser.crx"] {
            assert_eq!(classify_name(name), Some(Format::Zip), "ZIP alias {name}");
        }
        assert_eq!(classify_name("a.gz"), Some(Format::Gz));
        assert_eq!(classify_name("a.bz2"), Some(Format::Bz2));
        assert_eq!(classify_name("a.xz"), Some(Format::Xz));
        assert_eq!(classify_name("a.lzma"), Some(Format::Lzma));
        assert_eq!(classify_name("a.lz"), Some(Format::Lzip));
        assert_eq!(classify_name("a.Z"), Some(Format::Z));
        assert_eq!(classify_name("a.tar.lzma"), Some(Format::TarLzma));
        assert_eq!(classify_name("a.tar.lz"), Some(Format::TarLzip));
        assert_eq!(classify_name("a.tar.Z"), Some(Format::TarZ));
        assert_eq!(classify_name("a.zst"), Some(Format::Zst));
        assert_eq!(classify_name("a.p7z"), Some(Format::SevenZ));
        assert_eq!(classify_name("a.lha"), Some(Format::Lha));
        assert_eq!(classify_name("a.lzh"), Some(Format::Lha));
        assert_eq!(classify_name("a.iso"), Some(Format::Iso));
        assert_eq!(classify_name("a.iso9660"), Some(Format::Iso));
        assert_eq!(classify_name("a.xar"), Some(Format::Xar));
        assert_eq!(classify_name("a.pkg"), Some(Format::Xar));
        assert_eq!(classify_name("a.cpio"), Some(Format::Cpio));
        assert_eq!(classify_name("a.mtree"), Some(Format::Mtree));
        assert_eq!(classify_name("a.shar"), Some(Format::Shar));
        assert_eq!(classify_name("libfoo.a"), Some(Format::Ar));
    }

    #[test]
    fn recognizes_only_the_first_rar_volume() {
        assert_eq!(classify_name("bundle.rar"), Some(Format::Rar));
        assert_eq!(classify_name("bundle.part1.rar"), Some(Format::Rar));
        assert_eq!(classify_name("bundle.part01.rar"), Some(Format::Rar));
        assert_eq!(classify_name("bundle.part2.rar"), None);
        assert_eq!(classify_name("bundle.r00"), None);
    }

    #[test]
    fn recognizes_extensionless_rar_by_signature() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("payload");
        std::fs::write(&path, b"Rar!\x1a\x07\x01\x00").expect("write RAR signature");
        assert_eq!(classify(&path), Some(Format::Rar));
    }


    #[test]
    fn magic_database_recognizes_common_extensionless_containers() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let mut cases: Vec<(&str, Vec<u8>, Format)> = Vec::new();

        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("payload.txt", zip::write::SimpleFileOptions::default())
            .expect("start zip entry");
        zip.write_all(b"zip").expect("write zip entry");
        cases.push(("zip", zip.finish().expect("finish zip").into_inner(), Format::Zip));

        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(3);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "payload.txt", &b"tar"[..])
            .expect("append tar entry");
        cases.push(("tar", tar.into_inner().expect("finish tar"), Format::Tar));

        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(b"gzip").expect("write gzip");
        cases.push(("gzip", gzip.finish().expect("finish gzip"), Format::Gz));

        cases.push((
            "bzip2",
            include_bytes!("../tests/fixtures/sample.txt.bz2").to_vec(),
            Format::Bz2,
        ));
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(b"xz"), &mut xz).expect("compress xz");
        cases.push(("xz", xz, Format::Xz));
        cases.push((
            "zstd",
            include_bytes!("../tests/fixtures/sample.txt.zst").to_vec(),
            Format::Zst,
        ));

        let sevenz_source = dir.path().join("seven");
        std::fs::create_dir_all(&sevenz_source).expect("create 7z source");
        std::fs::write(sevenz_source.join("payload.txt"), b"7z").expect("write 7z source");
        let sevenz_path = dir.path().join("sevenz.archive");
        sevenz_rust2::compress_to_path(&sevenz_source, &sevenz_path).expect("build 7z fixture");
        cases.push(("7z", std::fs::read(&sevenz_path).expect("read 7z"), Format::SevenZ));

        let mut iso = vec![0u8; 0x8001 + 5];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        cases.push(("iso", iso, Format::Iso));
        cases.push(("xar", b"xar!\0\x1c\0\x01".to_vec(), Format::Xar));
        cases.push(("ar", b"!<arch>\n".to_vec(), Format::Ar));
        cases.push(("cpio", b"070701".to_vec(), Format::Cpio));
        cases.push(("compress", vec![0x1f, 0x9d, 0x90, 0, 0, 0, 0, 0], Format::Z));
        cases.push(("lzip", b"LZIP\x01\x0b\0\0".to_vec(), Format::Lzip));

        for (name, bytes, expected) in cases {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).expect("write magic fixture");
            assert_eq!(classify(&path), Some(expected), "magic classification for {name}");
        }
    }

    #[test]
    fn leaves_jar_war_class_for_the_java_bytecode_frontend() {
        assert_eq!(classify(&PathBuf::from("App.jar")), None);
        assert_eq!(classify(&PathBuf::from("App.war")), None);
        assert_eq!(classify(&PathBuf::from("App.class")), None);
    }

    #[test]
    fn does_not_misclassify_an_unrelated_dotted_name() {
        assert_eq!(classify(&PathBuf::from("README.md")), None);
        assert_eq!(classify(&PathBuf::from("archive.tar.example")), None);
    }
}
