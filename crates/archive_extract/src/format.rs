//! Archive format classification: extension-based dispatch first (cheap,
//! correct for the vast majority of real files), falling back to pure-Rust
//! magic sniffing (`pure-magic` + the `magic-db` bundled rule database —
//! compiled into this binary at build time, nothing loaded from disk at
//! runtime) only for files with no extension at all.

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
    Gz,
    Bz2,
    Xz,
    Zst,
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
    } else if lower_name.ends_with(".tar") {
        Some(Format::Tar)
    } else if lower_name.ends_with(".zip") {
        Some(Format::Zip)
    } else if lower_name.ends_with(".gz") {
        Some(Format::Gz)
    } else if lower_name.ends_with(".bz2") {
        Some(Format::Bz2)
    } else if lower_name.ends_with(".xz") {
        Some(Format::Xz)
    } else if lower_name.ends_with(".zst") {
        Some(Format::Zst)
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
    let db = bundled_magic_database()?;
    let magic = db.first_magic_file(path).ok()?;
    match magic.mime_type() {
        "application/zip" => Some(Format::Zip),
        "application/x-tar" | "application/x-gtar" | "application/x-ustar" => Some(Format::Tar),
        "application/gzip" => Some(Format::Gz),
        "application/x-bzip2" => Some(Format::Bz2),
        "application/x-xz" => Some(Format::Xz),
        "application/zstd" => Some(Format::Zst),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(classify_name("a.gz"), Some(Format::Gz));
        assert_eq!(classify_name("a.bz2"), Some(Format::Bz2));
        assert_eq!(classify_name("a.xz"), Some(Format::Xz));
        assert_eq!(classify_name("a.zst"), Some(Format::Zst));
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
