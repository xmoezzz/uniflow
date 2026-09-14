//! Per-format extraction. Every decompression path routes its decoded bytes
//! through the shared [`crate::budget`] capping machinery before they touch
//! disk; a cap trip is treated as "stop extracting this one archive" rather
//! than a hard failure of the whole run (see [`extract_one`]'s error
//! handling at the bottom of this file).

use std::fs::{self, File};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::budget::{is_cap_exceeded, Budget, CappedReader, CappedWriter};
use crate::format::Format;

/// Extracts one archive into `dest` (already created, empty). Returns
/// `Ok(())` whether or not a budget cap was tripped mid-archive — a trip
/// just stops that archive early and marks `budget` truncated; it is not
/// treated as this function failing, since everything extracted before the
/// trip is still legitimate, usable content.
pub(crate) fn extract_one(
    path: &Path,
    format: Format,
    dest: &Path,
    budget: &mut Budget,
) -> Result<()> {
    let result = match format {
        Format::Zip => extract_zip(path, dest, budget),
        Format::Tar => extract_tar_from_reader(File::open(path)?, dest, budget),
        Format::TarGz => {
            extract_tar_from_reader(flate2::read::GzDecoder::new(File::open(path)?), dest, budget)
        }
        Format::TarBz2 => extract_tar_from_reader(
            bzip2_rs::DecoderReader::new(File::open(path)?),
            dest,
            budget,
        ),
        Format::TarXz => {
            let cap = budget.cap_for_next_entry();
            decompress_xz_to_spool(path, cap)
                .and_then(|spooled| extract_tar_from_reader(spooled, dest, budget))
        }
        Format::TarZst => zstd_reader(path).and_then(|decoder| {
            extract_tar_from_reader(decoder, dest, budget)
        }),
        Format::Gz => extract_single_stream(
            flate2::read::GzDecoder::new(File::open(path)?),
            path,
            dest,
            budget,
        ),
        Format::Bz2 => extract_single_stream(
            bzip2_rs::DecoderReader::new(File::open(path)?),
            path,
            dest,
            budget,
        ),
        Format::Xz => {
            if !budget.note_entry() {
                Ok(())
            } else {
                let cap = budget.cap_for_next_entry();
                decompress_xz_to_spool(path, cap).and_then(|mut spooled| {
                    let written = spooled.metadata()?.len();
                    let mut out_file = File::create(single_stream_out_path(path, dest))?;
                    io::copy(&mut spooled, &mut out_file)?;
                    budget.account(written);
                    Ok(())
                })
            }
        }
        Format::Zst => {
            zstd_reader(path).and_then(|decoder| extract_single_stream(decoder, path, dest, budget))
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let cap_exceeded = error
                .chain()
                .any(|cause| cause.downcast_ref::<io::Error>().is_some_and(is_cap_exceeded));
            if cap_exceeded {
                budget.mark_truncated();
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn zstd_reader(path: &Path) -> Result<impl io::Read> {
    ruzstd::decoding::StreamingDecoder::new(io::BufReader::new(File::open(path)?))
        .map_err(|error| anyhow::anyhow!("invalid zstd stream: {error}"))
}

fn extract_zip(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let file = File::open(path)?;
    let mut archive = zip::ZipArchive::new(file).context("not a valid zip archive")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_symlink() {
            continue;
        }
        let Some(enclosed) = entry.enclosed_name() else {
            continue;
        };
        if enclosed.as_os_str().is_empty() {
            continue;
        }
        let out_path = dest.join(&enclosed);
        if entry.is_dir() {
            fs::create_dir_all(&out_path)?;
            continue;
        }
        if !budget.note_entry() {
            return Ok(());
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let cap = budget.cap_for_next_entry();
        let mut capped = CappedReader::new(&mut entry, cap);
        let mut out_file = File::create(&out_path)?;
        io::copy(&mut capped, &mut out_file)?;
        budget.account(capped.bytes_read());
    }
    Ok(())
}

/// Unpacks a (possibly already decompressed) tar byte stream. `reader` is
/// wrapped in its own [`CappedReader`] here so this one function accounts
/// for every tar variant uniformly, whether `reader` is the raw file (plain
/// `.tar`), a streaming decompressor (gzip/bzip2/zstd), or an
/// already-spooled-and-capped scratch file (xz — see [`decompress_xz_to_spool`],
/// whose own cap makes this second wrapping a no-op, not a double limit).
fn extract_tar_from_reader<R: io::Read>(reader: R, dest: &Path, budget: &mut Budget) -> Result<()> {
    let cap = budget.cap_for_next_entry();
    let mut capped = CappedReader::new(reader, cap);
    let outcome = (|| -> io::Result<()> {
        let mut archive = tar::Archive::new(&mut capped);
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !budget.note_entry() {
                break;
            }
            if matches!(
                entry.header().entry_type(),
                tar::EntryType::Symlink | tar::EntryType::Link
            ) {
                continue;
            }
            entry.unpack_in(dest)?;
        }
        Ok(())
    })();
    budget.account(capped.bytes_read());
    outcome.map_err(anyhow::Error::new)
}

/// `lzma-rs` decompresses xz/lzma in one call into an arbitrary [`io::Write`]
/// rather than exposing a lazy [`io::Read`] adapter, so the only way to
/// bound its memory/disk usage is to cap the destination it writes into.
/// Spilling to an anonymous temp file (rather than a `Vec<u8>`) keeps a
/// legitimately large, non-bomb archive from being fully buffered in RAM.
fn decompress_xz_to_spool(path: &Path, cap: u64) -> Result<File> {
    let mut input = io::BufReader::new(File::open(path)?);
    let scratch = tempfile::tempfile().context("failed to create extraction scratch file")?;
    let mut capped = CappedWriter::new(scratch, cap);
    lzma_rs::xz_decompress(&mut input, &mut capped).map_err(|error| match error {
        lzma_rs::error::Error::IoError(io_error) => anyhow::Error::new(io_error),
        other => anyhow::anyhow!("invalid xz stream: {other}"),
    })?;
    let mut scratch = capped.into_inner();
    scratch.seek(SeekFrom::Start(0))?;
    Ok(scratch)
}

fn extract_single_stream<R: io::Read>(
    reader: R,
    original: &Path,
    dest: &Path,
    budget: &mut Budget,
) -> Result<()> {
    if !budget.note_entry() {
        return Ok(());
    }
    let cap = budget.cap_for_next_entry();
    let mut capped = CappedReader::new(reader, cap);
    let out_path = single_stream_out_path(original, dest);
    let mut out_file = File::create(out_path)?;
    io::copy(&mut capped, &mut out_file)?;
    budget.account(capped.bytes_read());
    Ok(())
}

fn single_stream_out_path(original: &Path, dest: &Path) -> PathBuf {
    let stem = original.file_stem().unwrap_or_else(|| std::ffi::OsStr::new("data"));
    dest.join(stem)
}
