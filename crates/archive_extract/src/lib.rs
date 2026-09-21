//! Recursive archive extraction for SAST project scans.
//!
//! `uniflow` has no on-disk archive extraction today: `.jar`/`.war` are read
//! as zip entries fully in-memory by `uniflow_lang_java_bytecode`, and the
//! `crates/frontend` file collectors only ever match paths by extension —
//! nothing else ever gets unpacked. This crate fills that gap for the
//! general-purpose archive/compression containers and package formats most
//! likely to carry source code or dependency metadata: zip, tar (and its
//! gzip/bzip2/xz/zstd/LZMA/lzip/Unix-compress-compressed forms), 7z, `.deb`,
//! `.rpm`, `.cab`, LHA/LZH, ISO9660, XAR, ar/static libraries, cpio, mtree,
//! shar, and RAR. Common ZIP package aliases (`.apk`, `.aab`, `.ipa`,
//! `.nupkg`, `.vsix`, `.appx`, `.whl`, `.egg`, `.crx`) are dispatched to the
//! same bounded ZIP reader.
//! RAR4/RAR5 are decoded by a pure-Rust streaming backend; no host `unrar`
//! command, shared library, or C/C++ archive backend is invoked. Filesystem/
//! firmware images and legacy formats not listed here remain out of scope
//! until they have a bounded streaming backend. All formats listed above use
//! Rust readers/codecs and feed decoded bytes through the same extraction
//! budget and path-safety checks.
//!
//! File-type detection is extension-based first, falling back to pure-Rust
//! magic sniffing (`pure-magic` + `magic-db`, compiled into this binary at
//! build time — no external magic file is ever loaded at runtime) only for
//! extension-less files, to avoid paying a sniff cost for every file in a
//! large source tree. See [`format::classify`].
//!
//! Safety budgets (nested-depth, per-entry/total decompressed bytes, total
//! extracted file count) are enforced by wrapping every decompression stream
//! in a byte-counting reader/writer (see [`budget`]) that errors as soon as
//! more data would be produced than allowed — catching a decompression bomb
//! regardless of what a container's own metadata claims — rather than
//! trusting declared sizes. Zip-slip protection uses the `zip` crate's own
//! `enclosed_name()` and the `tar` crate's own `unpack_in()`, both of which
//! already refuse to write outside the destination directory.

mod budget;
mod extract;
mod format;
mod walk;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tempfile::TempDir;

use budget::Budget;

/// Tunable safety limits for one recursive-extraction run.
#[derive(Clone, Debug)]
pub struct ExtractOptions {
    /// How many levels of nested archives to extract (an archive found
    /// inside an already-extracted archive counts as one level deeper).
    pub max_depth: usize,
    /// Cumulative decompressed-byte budget across the entire run.
    pub max_total_bytes: u64,
    /// Per-extracted-file byte cap.
    pub max_entry_bytes: u64,
    /// Cap on the total number of files written across the entire run.
    pub max_entries: u64,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_entry_bytes: 512 * 1024 * 1024,
            max_entries: 200_000,
        }
    }
}

/// Summary of one recursive-extraction run.
#[derive(Clone, Debug)]
pub struct ExtractionReport {
    /// Scratch directory everything was unpacked into. Merge this into the
    /// same root-path list handed to the project's file collectors.
    pub extraction_root: PathBuf,
    pub archives_found: usize,
    pub bytes_written: u64,
    /// `true` if a safety budget was hit and extraction stopped early.
    /// Extracted content up to that point is still valid and usable.
    pub truncated: bool,
}

/// Recursively finds and extracts every supported archive under `roots`
/// (each either a file or a directory to walk) into a fresh scratch
/// directory, then recurses into any further supported archives found
/// inside that freshly-extracted content, up to `options.max_depth`.
///
/// Returns `Ok(None)` if no supported archive was found anywhere under
/// `roots` — nothing for the caller to merge in. Otherwise returns the
/// scratch directory (as a [`TempDir`] guard the caller must keep alive for
/// as long as anything still needs to read from it — it deletes itself on
/// drop) alongside a report of what happened.
pub fn extract_archives_recursively(
    roots: &[PathBuf],
    options: &ExtractOptions,
) -> Result<Option<(TempDir, ExtractionReport)>> {
    let mut frontier = walk::find_archives(roots).context("failed to scan for archives")?;
    if frontier.is_empty() {
        return Ok(None);
    }

    let scratch = tempfile::Builder::new()
        .prefix("uniflow-extract-")
        .tempdir()
        .context("failed to create archive-extraction scratch directory")?;

    let mut budget = Budget::new(options);
    let mut archives_found = 0usize;
    let mut counter = 0u64;

    for depth in 0..options.max_depth {
        if frontier.is_empty() || budget.truncated() {
            break;
        }
        let batch = std::mem::take(&mut frontier);
        let mut next_roots = Vec::new();
        for (path, format) in batch {
            if budget.truncated() {
                break;
            }
            counter += 1;
            let entry_dir = scratch.path().join(format!("{counter:06}_{}", sanitized_stem(&path)));
            if let Err(error) = fs::create_dir_all(&entry_dir) {
                eprintln!("uniflow: failed to create extraction directory for {}: {error}", path.display());
                continue;
            }
            match extract::extract_one(&path, format, &entry_dir, &mut budget) {
                Ok(()) => {
                    archives_found += 1;
                    if depth + 1 < options.max_depth {
                        next_roots.push(entry_dir);
                    }
                }
                Err(error) => {
                    eprintln!("uniflow: failed to extract {}: {error:#}", path.display());
                }
            }
        }
        frontier = if next_roots.is_empty() {
            Vec::new()
        } else {
            walk::find_archives(&next_roots).context("failed to scan extracted content for nested archives")?
        };
    }

    if budget.truncated() {
        eprintln!(
            "uniflow: archive extraction stopped early after hitting its size/entry-count budget; \
             results may be partial (see ExtractOptions to raise the limits)"
        );
    }

    let extraction_root = scratch.path().to_path_buf();
    Ok(Some((
        scratch,
        ExtractionReport {
            extraction_root,
            archives_found,
            bytes_written: budget.bytes_written(),
            truncated: budget.truncated(),
        },
    )))
}

fn sanitized_stem(path: &std::path::Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("archive");
    stem.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests;
