//! Pinned benchmark corpora: every archive is identified by an exact URL
//! (a commit tarball or a versioned release file) *and* the sha256 of its
//! bytes, recorded in `corpora.lock.json` next to this crate. A run on a
//! different machine or month therefore scans byte-identical inputs, or
//! refuses to run — a silently changed corpus would make a score
//! regression look like an engine regression (or hide one).
//!
//! Archives live in a cache directory (`$UNIFLOW_BENCH_CACHE`, default
//! `~/.cache/uniflow-bench`), never in the repository: several corpora are
//! GPL-licensed test code we run against but do not redistribute.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const LOCK_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/corpora.lock.json");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pin {
    pub url: String,
    pub sha256: String,
    /// `tar.gz` (a GitHub commit tarball: one top-level directory, stripped
    /// on extraction) or `zip` (extracted as-is).
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Lock {
    pub corpora: BTreeMap<String, Pin>,
}

impl Lock {
    pub fn load() -> Result<Self> {
        match fs::read_to_string(LOCK_FILE) {
            Ok(text) => Ok(serde_json::from_str(&text).with_context(|| format!("parsing {LOCK_FILE}"))?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error).with_context(|| format!("reading {LOCK_FILE}")),
        }
    }

    /// Read-merge-write: suites run as parallel processes, each pinning its
    /// own corpora, so a plain overwrite would drop another run's pins.
    /// This process's entries win for the ids it touched.
    pub fn save(&self) -> Result<()> {
        let mut merged = Self::load()?;
        for (id, pin) in &self.corpora {
            merged.corpora.insert(id.clone(), pin.clone());
        }
        let mut text = serde_json::to_string_pretty(&merged)?;
        text.push('\n');
        fs::write(LOCK_FILE, text).with_context(|| format!("writing {LOCK_FILE}"))
    }
}

pub fn cache_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("UNIFLOW_BENCH_CACHE") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").context("HOME is not set (or set UNIFLOW_BENCH_CACHE)")?;
    Ok(PathBuf::from(home).join(".cache").join("uniflow-bench"))
}

/// A GitHub commit tarball URL — immutable content for a given commit.
pub fn github_tarball(repo: &str, commit: &str) -> String {
    format!("https://codeload.github.com/{repo}/tar.gz/{commit}")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn download(url: &str, dest: &Path) -> Result<()> {
    let tmp = dest.with_extension("partial");
    let response = ureq::get(url).call().with_context(|| format!("GET {url}"))?;
    let mut reader = response.into_body().into_reader();
    let mut out = fs::File::create(&tmp)?;
    std::io::copy(&mut reader, &mut out).with_context(|| format!("downloading {url}"))?;
    out.flush()?;
    fs::rename(&tmp, dest)?;
    Ok(())
}

/// Makes corpus `id` available and returns its extracted root. Downloads
/// on first use; verifies the archive's sha256 against the lock every
/// time (cheap next to a scan). `url`/`kind` describe the wanted archive;
/// with `update_lock`, a new or changed pin is written back to the lock
/// instead of failing — only ever done deliberately, when a corpus is
/// added or intentionally bumped.
pub fn ensure(lock: &mut Lock, id: &str, url: &str, kind: &str, note: &str, update_lock: bool) -> Result<PathBuf> {
    let cache = cache_dir()?;
    let safe = id.replace(['/', ':'], "__");
    let archive = cache.join("downloads").join(format!("{safe}.{kind}"));
    let root = cache.join("src").join(&safe);
    fs::create_dir_all(archive.parent().unwrap())?;

    let pinned = lock.corpora.get(id).cloned();
    if let Some(pin) = &pinned {
        if pin.url != url && !update_lock {
            bail!("corpus {id}: the lock pins {} but the suite asks for {url} — rerun with --update-lock if the bump is intentional", pin.url);
        }
    }
    if !archive.exists() {
        eprintln!("fetching {id} from {url}");
        download(url, &archive)?;
    }
    let actual = sha256_file(&archive)?;
    match &pinned {
        Some(pin) if pin.url == url && pin.sha256 == actual => {}
        Some(pin) if !update_lock => {
            bail!(
                "corpus {id}: sha256 mismatch (lock {}, file {actual}) — delete {} to re-download, or rerun with --update-lock if the upstream bytes changed on purpose",
                pin.sha256,
                archive.display()
            )
        }
        _ if !update_lock => bail!("corpus {id} is not in {LOCK_FILE} — rerun with --update-lock to pin it"),
        _ => {
            lock.corpora.insert(id.to_string(), Pin { url: url.to_string(), sha256: actual.clone(), kind: kind.to_string(), note: note.to_string() });
        }
    }

    let marker = root.join(".uniflow-bench-sha256");
    if fs::read_to_string(&marker).ok().as_deref() != Some(actual.as_str()) {
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(&root)?;
        extract(&archive, kind, &root).with_context(|| format!("extracting {id}"))?;
        fs::write(&marker, &actual)?;
    }
    Ok(root)
}

fn extract(archive: &Path, kind: &str, dest: &Path) -> Result<()> {
    match kind {
        "tar.gz" => {
            let gz = flate2::read::GzDecoder::new(fs::File::open(archive)?);
            let mut tar = tar::Archive::new(gz);
            for entry in tar.entries()? {
                let mut entry = entry?;
                if !matches!(entry.header().entry_type(), tar::EntryType::Regular | tar::EntryType::Directory) {
                    continue;
                }
                let path = entry.path()?.into_owned();
                // GitHub tarballs wrap everything in `<repo>-<sha>/`.
                let stripped: PathBuf = path.components().skip(1).collect();
                if stripped.as_os_str().is_empty() || stripped.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                    continue;
                }
                let out = dest.join(&stripped);
                if entry.header().entry_type() == tar::EntryType::Directory {
                    fs::create_dir_all(&out)?;
                } else {
                    fs::create_dir_all(out.parent().unwrap())?;
                    entry.unpack(&out)?;
                }
            }
        }
        "zip" => {
            let mut zip = zip::ZipArchive::new(fs::File::open(archive)?)?;
            for i in 0..zip.len() {
                let mut file = zip.by_index(i)?;
                let Some(name) = file.enclosed_name() else { continue };
                let out = dest.join(name);
                if file.is_dir() {
                    fs::create_dir_all(&out)?;
                } else {
                    fs::create_dir_all(out.parent().unwrap())?;
                    std::io::copy(&mut file, &mut fs::File::create(&out)?)?;
                }
            }
        }
        other => bail!("unknown archive kind {other}"),
    }
    Ok(())
}
