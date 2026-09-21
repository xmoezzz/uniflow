//! Per-format extraction. Every decompression path routes its decoded bytes
//! through the shared [`crate::budget`] capping machinery before they touch
//! disk; a cap trip is treated as "stop extracting this one archive" rather
//! than a hard failure of the whole run (see [`extract_one`]'s error
//! handling at the bottom of this file).

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

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
            decompress_xz_to_spool(io::BufReader::new(File::open(path)?), cap)
                .and_then(|spooled| extract_tar_from_reader(spooled, dest, budget))
        }
        Format::TarZst => zstd_reader(path).and_then(|decoder| {
            extract_tar_from_reader(decoder, dest, budget)
        }),
        Format::TarLzma => decompress_lzma_to_spool(io::BufReader::new(File::open(path)?), budget.cap_for_next_entry())
            .and_then(|spooled| extract_tar_from_reader(spooled, dest, budget)),
        Format::TarLzip => extract_lzip_tar(path, dest, budget),
        Format::TarZ => extract_unix_compress_tar(path, dest, budget),
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
                decompress_xz_to_spool(io::BufReader::new(File::open(path)?), cap).and_then(|mut spooled| {
                    let written = spooled.metadata()?.len();
                    let mut out_file = File::create(single_stream_out_path(path, dest))?;
                    io::copy(&mut spooled, &mut out_file)?;
                    budget.account(written);
                    Ok(())
                })
            }
        }
        Format::Lzma => extract_lzma(path, dest, budget),
        Format::Lzip => extract_lzip(path, dest, budget),
        Format::Z => extract_unix_compress(path, dest, budget),
        Format::Zst => {
            zstd_reader(path).and_then(|decoder| extract_single_stream(decoder, path, dest, budget))
        }
        Format::SevenZ => extract_sevenz(path, dest, budget),
        Format::Deb => extract_deb(path, dest, budget),
        Format::Rpm => extract_rpm(path, dest, budget),
        Format::Cab => extract_cab(path, dest, budget),
        Format::Lha => extract_lha(path, dest, budget),
        Format::Iso => extract_iso(path, dest, budget),
        Format::Xar => extract_xar(path, dest, budget),
        Format::Ar => extract_ar(path, dest, budget),
        Format::Cpio => extract_cpio(path, dest, budget),
        Format::Mtree => extract_mtree(path, dest, budget),
        Format::Shar => extract_shar(path, dest, budget),
        Format::Rar => extract_rar(path, dest, budget),
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
fn decompress_xz_to_spool(mut input: impl io::BufRead, cap: u64) -> Result<File> {
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

/// Decompresses a standalone `.lzma` stream into a bounded scratch file.
/// `lzma-rs` is a no-unsafe, pure-Rust decoder and reads the stream lazily;
/// the scratch file keeps the decoded bytes out of the process heap.
fn decompress_lzma_to_spool(mut input: impl io::BufRead, cap: u64) -> Result<File> {
    let scratch = tempfile::tempfile().context("failed to create extraction scratch file")?;
    let mut capped = CappedWriter::new(scratch, cap);
    lzma_rs::lzma_decompress(&mut input, &mut capped).map_err(|error| match error {
        lzma_rs::error::Error::IoError(io_error) => anyhow::Error::new(io_error),
        other => anyhow::anyhow!("invalid LZMA stream: {other}"),
    })?;
    let mut scratch = capped.into_inner();
    scratch.seek(SeekFrom::Start(0))?;
    Ok(scratch)
}

fn extract_lzma(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    if !budget.note_entry() {
        return Ok(());
    }
    let cap = budget.cap_for_next_entry();
    let mut decoded = decompress_lzma_to_spool(io::BufReader::new(File::open(path)?), cap)?;
    let written = decoded.metadata()?.len();
    let mut out = File::create(single_stream_out_path(path, dest))?;
    io::copy(&mut decoded, &mut out)?;
    budget.account(written);
    Ok(())
}

/// A lzip member has a six-byte header, raw LZMA payload and a twenty-byte
/// footer. We support the normal single-member stream (the form emitted by
/// package/build tooling) without buffering compressed input. The declared
/// uncompressed size only terminates the raw decoder; the shared
/// `CappedWriter` remains the authoritative bomb guard.
fn decode_lzip_to_writer<W: io::Write>(file: &mut File, output: &mut CappedWriter<W>) -> Result<()> {
    let file_len = file.metadata()?.len();
    let offset = 0u64;
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 6];
    file.read_exact(&mut header)?;
    if &header[..4] != b"LZIP" || header[4] != 1 {
        return Err(anyhow::anyhow!("invalid lzip header"));
    }
    let dict_code = header[5];
    let exponent = u32::from(dict_code & 0x1f);
    if exponent > 19 {
        return Err(anyhow::anyhow!("lzip dictionary is too large"));
    }
    // The high three bits select a fractional reduction. Rounding down is
    // conservative for memory and remains a valid dictionary size.
    let base = 1u32.checked_shl(exponent + 12).ok_or_else(|| anyhow::anyhow!("invalid lzip dictionary"))?;
    let fraction = u32::from(dict_code >> 5);
    let dict_size = base.saturating_sub((base / 16).saturating_mul(fraction));
    if dict_size < 4096 {
        return Err(anyhow::anyhow!("invalid lzip dictionary size"));
    }

    if file_len - offset < 26 {
        return Err(anyhow::anyhow!("truncated lzip member"));
    }
    file.seek(SeekFrom::Start(file_len - 20))?;
    let mut footer = [0u8; 20];
    file.read_exact(&mut footer)?;
    let expected_crc = u32::from_le_bytes(footer[..4].try_into().unwrap());
    let member_size = u64::from_le_bytes(footer[12..20].try_into().unwrap());
    if member_size != file_len - offset || member_size < 26 {
        return Err(anyhow::anyhow!("concatenated or invalid lzip members are not supported"));
    }
    file.seek(SeekFrom::Start(file_len - 20))?;
    file.read_exact(&mut footer)?;
    let unpacked_size = u64::from_le_bytes(footer[4..12].try_into().unwrap());
    let compressed_len = member_size - 26;
    file.seek(SeekFrom::Start(offset + 6))?;
    let limited = file.by_ref().take(compressed_len);
    let mut input = io::BufReader::new(limited);
    let params = lzma_rs::decompress::raw::LzmaParams::new(
        lzma_rs::decompress::raw::LzmaProperties { lc: 3, lp: 0, pb: 2 },
        dict_size,
        Some(unpacked_size),
    );
    let mut decoder = lzma_rs::decompress::raw::LzmaDecoder::new(params, None)
        .map_err(|error| anyhow::anyhow!("invalid lzip decoder parameters: {error}"))?;
    let mut checksum = CrcWriter::new(output);
    decoder
        .decompress(&mut input, &mut checksum)
        .map_err(|error| anyhow::anyhow!("invalid lzip payload: {error}"))?;
    if checksum.finish() != expected_crc {
        return Err(anyhow::anyhow!("lzip member CRC32 mismatch"));
    }
    Ok(())
}

struct CrcWriter<'a, W: io::Write> {
    inner: &'a mut CappedWriter<W>,
    hasher: crc32fast::Hasher,
}

impl<'a, W: io::Write> CrcWriter<'a, W> {
    fn new(inner: &'a mut CappedWriter<W>) -> Self {
        Self { inner, hasher: crc32fast::Hasher::new() }
    }

    fn finish(self) -> u32 {
        self.hasher.finalize()
    }
}

impl<W: io::Write> io::Write for CrcWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn extract_lzip(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    if !budget.note_entry() {
        return Ok(());
    }
    let cap = budget.cap_for_next_entry();
    let out_path = single_stream_out_path(path, dest);
    let mut writer = CappedWriter::new(File::create(out_path)?, cap);
    let result = decode_lzip_to_writer(&mut File::open(path)?, &mut writer);
    let written = writer.bytes_written();
    budget.account(written);
    if let Err(error) = result {
        if writer.exceeded() {
            budget.mark_truncated();
            return Ok(());
        }
        return Err(error);
    }
    Ok(())
}

fn extract_lzip_tar(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let cap = budget.cap_for_next_entry();
    let mut scratch = tempfile::tempfile().context("failed to create extraction scratch file")?;
    {
        let mut writer = CappedWriter::new(&mut scratch, cap);
        let result = decode_lzip_to_writer(&mut File::open(path)?, &mut writer);
        if let Err(error) = result {
            if writer.exceeded() {
                budget.mark_truncated();
                return Ok(());
            }
            return Err(error);
        }
    }
    scratch.seek(SeekFrom::Start(0))?;
    extract_tar_from_reader(scratch, dest, budget)
}

/// Decode classic Unix `compress` streams.  The implementation intentionally
/// keeps the compressed input bounded by the caller's entry cap; the pure-Rust
/// LZW decoder itself is isolated in this small helper so `.Z` and `tar.Z`
/// share exactly the same validation path.
fn decode_unix_compress(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let mut input = Vec::new();
    let metadata = fs::metadata(path)?;
    // The legacy .Z decoder below uses compact in-memory dictionary tables and
    // a Vec output. Keep its compressed input bounded independently of the
    // much larger decompressed-entry budget so a large hostile input cannot
    // turn into an unbounded allocation.
    if metadata.len() > 64 * 1024 * 1024 {
        return Err(anyhow::anyhow!("compressed .Z input exceeds safe bound"));
    }
    File::open(path)?.read_to_end(&mut input)?;
    if input.len() < 3 || input[..2] != [0x1f, 0x9d] {
        return Err(anyhow::anyhow!("invalid Unix compress header"));
    }
    let max_bits = input[2] & 0x1f;
    if !(9..=16).contains(&max_bits) {
        return Err(anyhow::anyhow!("invalid Unix compress bit width"));
    }
    let block_mode = input[2] & 0x80 != 0;
    // This compact decoder follows the original .Z block packing.  It writes
    // into a Vec only after enforcing the caller's output cap.
    let mut output = Vec::new();
    let mut prefix = vec![0u16; 1 << max_bits];
    let mut suffix = vec![0u8; 1 << max_bits];
    let mut stack = Vec::new();
    let mut bit_pos = 0usize;
    let mut width = 9usize;
    let mut next_code = if block_mode { 257usize } else { 256usize };
    let clear = 256usize;
    let mut read_code = |width: usize| -> Option<usize> {
        if bit_pos + width > (input.len() - 3) * 8 { return None; }
        let mut value = 0usize;
        for i in 0..width {
            value |= usize::from((input[3 + (bit_pos + i) / 8] >> ((bit_pos + i) % 8)) & 1) << i;
        }
        bit_pos += width;
        Some(value)
    };
    let Some(first) = read_code(width) else { return Ok(output) };
    if first > 255 { return Err(anyhow::anyhow!("invalid first .Z code")); }
    let mut old = first;
    let mut first_char = first as u8;
    output.push(first_char);
    if output.len() as u64 > cap { return Err(anyhow::anyhow!(".Z output exceeds extraction budget")); }
    while let Some(code_in) = read_code(width) {
        if code_in == clear && block_mode {
            prefix.fill(0);
            next_code = 257;
            width = 9;
            let Some(next) = read_code(width) else { break };
            if next > 255 { return Err(anyhow::anyhow!("invalid .Z clear code")); }
            first_char = next as u8;
            output.push(first_char);
            if output.len() as u64 > cap { return Err(anyhow::anyhow!(".Z output exceeds extraction budget")); }
            old = next;
            continue;
        }
        let mut code = code_in;
        if code >= next_code {
            if code != next_code { return Err(anyhow::anyhow!("invalid .Z dictionary code")); }
            stack.push(first_char);
            code = old;
        }
        while code >= 256 {
            stack.push(suffix[code]);
            code = prefix[code] as usize;
        }
        first_char = code as u8;
        output.push(first_char);
        while let Some(ch) = stack.pop() { output.push(ch); }
        if output.len() as u64 > cap { return Err(anyhow::anyhow!(".Z output exceeds extraction budget")); }
        if next_code < (1usize << max_bits) {
            prefix[next_code] = old as u16;
            suffix[next_code] = first_char;
            next_code += 1;
            if next_code == (1usize << width) && width < usize::from(max_bits) { width += 1; }
        }
        old = code_in;
    }
    Ok(output)
}

fn extract_unix_compress(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    if !budget.note_entry() { return Ok(()); }
    let output = decode_unix_compress(path, budget.cap_for_next_entry())?;
    let out_path = single_stream_out_path(path, dest);
    fs::write(out_path, &output)?;
    budget.account(output.len() as u64);
    Ok(())
}

fn extract_unix_compress_tar(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let output = decode_unix_compress(path, budget.cap_for_next_entry())?;
    extract_tar_from_reader(io::Cursor::new(output), dest, budget)
}

fn extract_mtree(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    // mtree is a manifest, not a payload container. Preserve it as a
    // non-recognized manifest artifact so SCA consumers can inspect hashes,
    // modes and ownership without treating it as an archive again.
    if !budget.note_entry() {
        return Ok(());
    }
    let bytes = fs::read(path)?;
    let cap = budget.cap_for_next_entry();
    if bytes.len() as u64 > cap {
        budget.mark_truncated();
        return Ok(());
    }
    let stem = path.file_name().and_then(|name| name.to_str()).unwrap_or("manifest");
    let out = dest.join(format!("{stem}.manifest"));
    fs::write(out, &bytes)?;
    budget.account(bytes.len() as u64);
    Ok(())
}

fn shell_word(raw: &str) -> Option<String> {
    let word = raw.trim().trim_end_matches(';').trim();
    if word.is_empty() { return None; }
    let unquoted = word
        .strip_prefix("'").and_then(|s| s.strip_suffix("'"))
        .or_else(|| word.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(word);
    Some(unquoted.replace("\\'", "'").replace("\\\"", "\""))
}

/// Decode the data-bearing subset emitted by common `shar` implementations.
/// No command is ever executed: here-documents and simple echo/printf writes
/// are copied as bytes, while shell logic, chmod and uuencode directives are
/// ignored safely.
fn extract_shar(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > budget.max_entry_bytes().saturating_mul(2).max(16 * 1024 * 1024) {
        budget.mark_truncated();
        return Ok(());
    }
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let mut index = 0usize;
    while index < lines.len() && !budget.truncated() {
        let line = lines[index];
        let Some(marker_pos) = line.find("<<") else {
            // Handle `echo 'payload' > file` and `printf '%s' 'payload' > file`.
            if let Some(gt) = line.rfind('>') {
                let target = shell_word(&line[gt + 1..]);
                let payload = if let Some(rest) = line.strip_prefix("echo ") {
                    shell_word(rest.split('>').next().unwrap_or(rest)).map(|value| format!("{value}\n").into_bytes())
                } else if let Some(rest) = line.strip_prefix("printf ") {
                    shell_word(rest.split('>').next().unwrap_or(rest)).map(|value| value.into_bytes())
                } else { None };
                if let (Some(target), Some(payload)) = (target, payload) {
                    write_shar_entry(dest, &target, &payload, budget)?;
                }
            }
            index += 1;
            continue;
        };
        let delimiter = line[marker_pos + 2..].split_whitespace().next().and_then(shell_word);
        let Some(delimiter) = delimiter else { index += 1; continue };
        let before = &line[..marker_pos];
        let target = before.rsplit_once('>').and_then(|(_, raw)| shell_word(raw));
        let Some(target) = target else { index += 1; continue };
        let strip_x = before.contains("s/^X//") || before.contains("sed");
        let start = index + 1;
        let mut end = start;
        while end < lines.len() && lines[end].trim_end() != delimiter { end += 1; }
        if end >= lines.len() { break; }
        let mut payload = Vec::new();
        for content in &lines[start..end] {
            let content = if strip_x { content.strip_prefix('X').unwrap_or(content) } else { content };
            payload.extend_from_slice(content.as_bytes());
            payload.push(b'\n');
        }
        write_shar_entry(dest, &target, &payload, budget)?;
        index = end + 1;
    }
    Ok(())
}

fn write_shar_entry(dest: &Path, name: &str, bytes: &[u8], budget: &mut Budget) -> Result<()> {
    let Some(out_path) = safe_join(dest, name) else { return Ok(()); };
    if bytes.len() as u64 > budget.cap_for_next_entry() || !budget.note_entry() {
        budget.mark_truncated();
        return Ok(());
    }
    if let Some(parent) = out_path.parent() { fs::create_dir_all(parent)?; }
    fs::write(out_path, bytes)?;
    budget.account(bytes.len() as u64);
    Ok(())
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

/// Zip-slip protection for the formats below, whose crates (unlike `zip` and
/// `tar`) don't already refuse to write outside `dest` themselves: rejects
/// any entry name containing an absolute path or a `..` component instead of
/// joining it onto `dest` unchecked.
fn safe_join(dest: &Path, raw_name: &str) -> Option<PathBuf> {
    let normalized = raw_name.replace('\\', "/");
    let mut out = dest.to_path_buf();
    let mut joined_any = false;
    for component in Path::new(&normalized).components() {
        match component {
            std::path::Component::Normal(part) => {
                out.push(part);
                joined_any = true;
            }
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    joined_any.then_some(out)
}

/// Decodes a 7z archive with `sevenz-rust2` (pure Rust — LZMA/LZMA2/COPY, no
/// external `7z`/`7za` binary). Each entry's decompressed reader is routed
/// through the same [`CappedReader`] budget as every other format; hitting
/// the cap stops this archive (via returning `Ok(false)` to
/// `for_each_entries`) rather than propagating an error, since a partial
/// extraction is still legitimate, usable content.
fn extract_sevenz(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let mut reader = sevenz_rust2::SevenZReader::open(path, sevenz_rust2::Password::empty())
        .context("not a valid 7z archive")?;
    reader
        .for_each_entries(|entry, entry_reader| {
            if budget.truncated() {
                return Ok(false);
            }
            if entry.is_directory() {
                return Ok(true);
            }
            let Some(out_path) = safe_join(dest, entry.name()) else {
                return Ok(true);
            };
            if !budget.note_entry() {
                return Ok(false);
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(sevenz_rust2::Error::io)?;
            }
            let cap = budget.cap_for_next_entry();
            let mut capped = CappedReader::new(entry_reader, cap);
            let mut out_file = File::create(&out_path).map_err(sevenz_rust2::Error::io)?;
            let copied = io::copy(&mut capped, &mut out_file);
            let bytes_read = capped.bytes_read();
            budget.account(bytes_read);
            match copied {
                Ok(_) => Ok(true),
                Err(error) if is_cap_exceeded(&error) => {
                    budget.mark_truncated();
                    Ok(false)
                }
                Err(error) => Err(sevenz_rust2::Error::io(error)),
            }
        })
        .map_err(|error| anyhow::anyhow!("failed to extract 7z archive: {error}"))
}

/// Decode RAR4/RAR5 members directly into bounded writers with the pure-Rust
/// `unrar-rs` decoder.  No temporary extraction tree is needed: every decoded
/// byte is checked by the same shared budget used by the other archive
/// formats, and only sanitized relative paths are ever created below `dest`.
fn extract_rar(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let mut archive = unrar_rs::RarArchive::open(File::open(path)?)
        .map_err(|error| anyhow::anyhow!("failed to open RAR archive: {error}"))?;
    let volumes = unrar_rs::StaticVolumeProvider::from_ordered(rar_volume_paths(path));
    for index in 0..archive.len() {
        if budget.truncated() {
            break;
        }
        let entry = archive
            .by_index_via(index, &volumes)
            .map_err(|error| anyhow::anyhow!("failed to read RAR member {index}: {error}"))?;
        if entry.is_dir() {
            entry
                .skip()
                .map_err(|error| anyhow::anyhow!("failed to skip RAR directory: {error}"))?;
            continue;
        }
        let name = entry.name().to_owned();
        let declared_size = entry.size();
        let Some(target) = safe_join(dest, &name) else {
            entry
                .skip()
                .map_err(|error| anyhow::anyhow!("failed to skip unsafe RAR member: {error}"))?;
            continue;
        };
        let cap = budget.cap_for_next_entry();
        if declared_size.is_some_and(|size| size > cap || size > budget.max_entry_bytes()) {
            budget.mark_truncated();
            entry
                .skip()
                .map_err(|error| anyhow::anyhow!("failed to skip oversized RAR member: {error}"))?;
            break;
        }
        if !budget.note_entry() {
            break;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let out_file = File::create(&target)?;
        let mut capped = CappedWriter::new(out_file, cap);
        let result = entry.copy_to(&mut capped);
        let written = capped.bytes_written();
        budget.account(written);
        match result {
            Ok(_) => {}
            Err(_error) if capped.exceeded() => {
                budget.mark_truncated();
                break;
            }
            Err(error) => {
                return Err(anyhow::anyhow!("failed to decode RAR member {name}: {error}"));
            }
        }
    }
    Ok(())
}

/// Return the on-disk volume set in the numbering used by `unrar-rs`.
///
/// RAR has two common naming conventions: `name.rar`, `name.r00`, ... and
/// `name.part01.rar`, `name.part02.rar`, ... .  Only the first member is sent
/// through archive discovery, so this bounded sibling probe lets the decoder
/// fetch continuation volumes without treating them as independent archives.
fn rar_volume_paths(first: &Path) -> Vec<PathBuf> {
    let Some(file_name) = first.file_name().and_then(|name| name.to_str()) else {
        return vec![first.to_path_buf()];
    };
    let lower = file_name.to_ascii_lowercase();
    let mut paths = vec![first.to_path_buf()];
    if lower.ends_with(".rar") {
        let stem = &file_name[..file_name.len() - 4];
        if let Some(marker) = stem.to_ascii_lowercase().rfind(".part") {
            let number = &stem[marker + 5..];
            if number == "1" || (number.len() > 1 && number.starts_with('0') && number.parse::<u64>().ok() == Some(1)) {
                let prefix = &stem[..marker];
                let width = number.len();
                for volume in 2..=10_000u32 {
                    let candidate_name = format!("{prefix}.part{volume:0width$}.rar", width = width);
                    let candidate = first.parent().unwrap_or_else(|| Path::new(".")).join(candidate_name);
                    if !candidate.is_file() {
                        break;
                    }
                    paths.push(candidate);
                }
            }
        } else {
            for volume in 0..=10_000u32 {
                let candidate = first.with_extension(format!("r{volume:02}"));
                if !candidate.is_file() {
                    break;
                }
                paths.push(candidate);
            }
        }
    }
    paths
}


/// A `.deb` is an `ar` archive whose members are `control.tar.*` and
/// `data.tar.*` — this decodes the `ar` container with the pure-Rust `ar`
/// crate, then hands each member to this crate's own tar/gzip/bzip2/xz/zstd
/// decoders exactly as if it were a standalone tarball.
fn extract_deb(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let file = File::open(path)?;
    let mut archive = ar::Archive::new(file);
    while let Some(entry) = archive.next_entry() {
        if budget.truncated() {
            break;
        }
        let mut entry = entry.context("invalid entry in .deb (ar) archive")?;
        let raw_name = String::from_utf8_lossy(entry.header().identifier()).into_owned();
        let name = raw_name.trim_end_matches('/').to_string();
        if !(name.starts_with("control.tar") || name.starts_with("data.tar")) {
            continue;
        }
        let subdest = dest.join(name.split('.').next().unwrap_or("member"));
        fs::create_dir_all(&subdest)?;
        if name.ends_with(".gz") {
            extract_tar_from_reader(flate2::read::GzDecoder::new(&mut entry), &subdest, budget)?;
        } else if name.ends_with(".bz2") {
            extract_tar_from_reader(bzip2_rs::DecoderReader::new(&mut entry), &subdest, budget)?;
        } else if name.ends_with(".xz") {
            let cap = budget.cap_for_next_entry();
            let spooled = decompress_xz_to_spool(io::BufReader::new(&mut entry), cap)?;
            extract_tar_from_reader(spooled, &subdest, budget)?;
        } else if name.ends_with(".zst") {
            let decoder = ruzstd::decoding::StreamingDecoder::new(io::BufReader::new(&mut entry))
                .map_err(|error| anyhow::anyhow!("invalid zstd stream in .deb member {name}: {error}"))?;
            extract_tar_from_reader(decoder, &subdest, budget)?;
        } else {
            extract_tar_from_reader(&mut entry, &subdest, budget)?;
        }
    }
    Ok(())
}

/// An RPM's payload (whatever compression its `RPMTAG_PAYLOADCOMPRESSOR`
/// header names) is a cpio (`newc`) stream. The `rpm` crate parses the
/// header and hands back the still-compressed payload bytes; decompression
/// reuses this crate's own decoders and the cpio unpacking below is a
/// from-scratch pure-Rust reader (via the `cpio` crate), so no `rpm2cpio`/
/// `cpio` binary is ever invoked.
fn extract_rpm(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let package = rpm::Package::open(path).context("not a valid rpm package")?;
    let compressor = package
        .metadata
        .get_payload_compressor()
        .unwrap_or(rpm::CompressionType::None);
    let payload = package.payload;
    match compressor {
        rpm::CompressionType::None => extract_cpio_from_reader(io::Cursor::new(payload), dest, budget),
        rpm::CompressionType::Gzip => extract_cpio_from_reader(
            flate2::read::GzDecoder::new(io::Cursor::new(payload)),
            dest,
            budget,
        ),
        rpm::CompressionType::Bzip2 => extract_cpio_from_reader(
            bzip2_rs::DecoderReader::new(io::Cursor::new(payload)),
            dest,
            budget,
        ),
        rpm::CompressionType::Zstd => {
            let decoder = ruzstd::decoding::StreamingDecoder::new(io::Cursor::new(payload))
                .map_err(|error| anyhow::anyhow!("invalid zstd rpm payload: {error}"))?;
            extract_cpio_from_reader(decoder, dest, budget)
        }
        rpm::CompressionType::Xz => {
            let cap = budget.cap_for_next_entry();
            let spooled = decompress_xz_to_spool(io::BufReader::new(io::Cursor::new(payload)), cap)?;
            extract_cpio_from_reader(spooled, dest, budget)
        }
    }
}

const CPIO_DIR_MODE_MASK: u32 = 0o170000;
const CPIO_DIR_MODE: u32 = 0o040000;

fn extract_cpio_from_reader<R: io::Read>(reader: R, dest: &Path, budget: &mut Budget) -> Result<()> {
    let mut remainder = reader;
    loop {
        if budget.truncated() {
            break;
        }
        let entry_reader = cpio::newc::Reader::new(remainder).context("invalid cpio stream")?;
        if entry_reader.entry().is_trailer() {
            entry_reader.finish().context("failed to finish cpio stream")?;
            break;
        }
        let is_dir = entry_reader.entry().mode() & CPIO_DIR_MODE_MASK == CPIO_DIR_MODE;
        let name = entry_reader.entry().name().to_string();
        let Some(out_path) = safe_join(dest, &name) else {
            remainder = entry_reader.finish().context("failed to skip unsafe cpio entry")?;
            continue;
        };
        if is_dir {
            fs::create_dir_all(&out_path)?;
            remainder = entry_reader.finish().context("failed to finish cpio directory entry")?;
            continue;
        }
        if !budget.note_entry() {
            break;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let cap = budget.cap_for_next_entry();
        let mut capped = CappedReader::new(entry_reader, cap);
        let mut out_file = File::create(&out_path)?;
        let copied = io::copy(&mut capped, &mut out_file);
        let bytes_read = capped.bytes_read();
        budget.account(bytes_read);
        let entry_reader = capped.into_inner();
        match copied {
            Ok(_) => {}
            Err(error) if is_cap_exceeded(&error) => {
                budget.mark_truncated();
                let _ = entry_reader.finish();
                break;
            }
            Err(error) => return Err(error.into()),
        }
        remainder = entry_reader.finish().context("failed to finish cpio file entry")?;
    }
    Ok(())
}

/// Reads a Microsoft Cabinet file with the pure-Rust `cab` crate.
fn extract_cab(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let file = File::open(path)?;
    let mut cabinet = cab::Cabinet::new(file).context("not a valid cab archive")?;
    let names: Vec<String> = cabinet
        .folder_entries()
        .flat_map(|folder| folder.file_entries())
        .map(|entry| entry.name().to_string())
        .collect();
    for name in names {
        if budget.truncated() {
            break;
        }
        let Some(out_path) = safe_join(dest, &name) else {
            continue;
        };
        if !budget.note_entry() {
            break;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let cap = budget.cap_for_next_entry();
        let mut reader = cabinet
            .read_file(&name)
            .with_context(|| format!("failed to read {name} from cab archive"))?;
        let mut capped = CappedReader::new(&mut reader, cap);
        let mut out_file = File::create(&out_path)?;
        io::copy(&mut capped, &mut out_file)?;
        budget.account(capped.bytes_read());
    }
    Ok(())
}

/// Extracts LHA/LZH members with `delharc`, keeping the decoder streaming and
/// applying the shared output budget before any bytes reach the project tree.
fn extract_lha(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let mut archive = delharc::parse_file(path).context("not a valid LHA/LZH archive")?;
    loop {
        if budget.truncated() {
            break;
        }
        let header = archive.header().clone();
        let name = header.parse_pathname_to_str();
        if header.is_directory() {
            if let Some(out_path) = safe_join(dest, &name) {
                fs::create_dir_all(out_path)?;
            }
        } else if !archive.is_decoder_supported() {
            // The next header is still reachable without decoding this member.
        } else if header.original_size > budget.cap_for_next_entry() {
            budget.mark_truncated();
        } else if let Some(out_path) = safe_join(dest, &name) {
            if !budget.note_entry() {
                break;
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut capped = CappedWriter::new(File::create(out_path)?, budget.cap_for_next_entry());
            let copied = io::copy(&mut archive, &mut capped);
            let written = capped.bytes_written();
            budget.account(written);
            match copied {
                Ok(_) => {
                    archive
                        .crc_check()
                        .map_err(|error| anyhow::anyhow!("LHA member CRC check failed: {error}"))?;
                }
                Err(_error) if capped.exceeded() => {
                    budget.mark_truncated();
                }
                Err(error) => return Err(error.into()),
            }
        }
        if budget.truncated() || !archive.seek_next_file()? {
            break;
        }
    }
    Ok(())
}

struct IsoDevice {
    file: File,
}

impl iso9660_simple::Read for IsoDevice {
    fn read(&mut self, position: usize, buffer: &mut [u8]) -> Option<()> {
        self.file.seek(SeekFrom::Start(position as u64)).ok()?;
        std::io::Read::read_exact(&mut self.file, buffer).ok()
    }
}

/// ISO9660 is a filesystem image rather than an archive stream.  The pure-Rust
/// reader exposes directory entries and extent reads, so traversal is explicit
/// and each file is copied in small chunks under the normal budget.
fn extract_iso(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let mut iso = iso9660_simple::ISO9660::from_device(IsoDevice {
        file: File::open(path)?,
    })
    .ok_or_else(|| anyhow::anyhow!("not a valid ISO9660 image"))?;
    let root_lba = iso.root().lba.get() as usize;
    let mut pending = vec![(root_lba, PathBuf::new(), 0u32)];
    while let Some((lba, prefix, depth)) = pending.pop() {
        if budget.truncated() {
            break;
        }
        let directory = iso.read_directory(lba);
        let mut entries = Vec::new();
        for entry in &directory {
            if entries.len() >= 100_000 {
                budget.mark_truncated();
                break;
            }
            entries.push(entry);
        }
        for entry in entries {
            if entry.name == "." || entry.name == ".." {
                continue;
            }
            let relative = prefix.join(&entry.name);
            let Some(out_path) = safe_join(dest, &relative.to_string_lossy()) else {
                continue;
            };
            if entry.is_folder() {
                fs::create_dir_all(&out_path)?;
                if depth < 64 {
                    pending.push((entry.lsb_position() as usize, relative, depth + 1));
                }
                continue;
            }
            let size = entry.file_size() as u64;
            if size > budget.cap_for_next_entry() {
                budget.mark_truncated();
                break;
            }
            if !budget.note_entry() {
                break;
            }
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out_file = File::create(out_path)?;
            let mut offset = 0usize;
            let mut buffer = vec![0u8; 64 * 1024];
            while offset < size as usize {
                let requested = (size as usize - offset).min(buffer.len());
                let count = iso
                    .read_file(&entry, offset, &mut buffer[..requested])
                    .ok_or_else(|| anyhow::anyhow!("failed to read ISO9660 extent"))?;
                if count == 0 {
                    return Err(anyhow::anyhow!("short ISO9660 file extent"));
                }
                std::io::Write::write_all(&mut out_file, &buffer[..count])?;
                offset += count;
            }
            budget.account(size);
        }
    }
    Ok(())
}

fn extract_ar(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    let mut archive = ar::Archive::new(File::open(path)?);
    while let Some(entry) = archive.next_entry() {
        if budget.truncated() {
            break;
        }
        let mut entry = entry.context("invalid ar archive member")?;
        let name = String::from_utf8_lossy(entry.header().identifier())
            .trim()
            .trim_end_matches('/')
            .to_string();
        if name.is_empty() || name == "/" || name == "//" || name.starts_with("__.SYMDEF") {
            continue;
        }
        let Some(out_path) = safe_join(dest, &name) else {
            continue;
        };
        if !budget.note_entry() {
            break;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut capped = CappedReader::new(&mut entry, budget.cap_for_next_entry());
        let mut out_file = File::create(out_path)?;
        let copied = io::copy(&mut capped, &mut out_file);
        budget.account(capped.bytes_read());
        match copied {
            Ok(_) => {}
            Err(error) if is_cap_exceeded(&error) => {
                budget.mark_truncated();
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn extract_cpio(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    extract_cpio_from_reader(File::open(path)?, dest, budget)
}

#[derive(Debug, Deserialize)]
struct XarDocument {
    toc: XarToc,
}

#[derive(Debug, Deserialize)]
struct XarToc {
    #[serde(rename = "file", default)]
    files: Vec<XarFile>,
}

#[derive(Debug, Deserialize)]
struct XarFile {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    data: Option<XarData>,
    #[serde(rename = "file", default)]
    children: Vec<XarFile>,
}

#[derive(Debug, Deserialize)]
struct XarData {
    offset: u64,
    size: u64,
    length: u64,
    encoding: XarEncoding,
}

#[derive(Debug, Deserialize)]
struct XarEncoding {
    #[serde(rename = "@style")]
    style: String,
}

/// Decode XAR's big-endian header and zlib-compressed XML TOC directly.  The
/// heap reader seeks to each member's bounded extent and dispatches only the
/// documented XAR encodings, all implemented with Rust codecs.
fn extract_xar(path: &Path, dest: &Path, budget: &mut Budget) -> Result<()> {
    const XAR_HEADER_SIZE: usize = 28;
    const MAX_TOC_BYTES: u64 = 64 * 1024 * 1024;
    let mut file = File::open(path)?;
    let mut header = [0u8; XAR_HEADER_SIZE];
    std::io::Read::read_exact(&mut file, &mut header)?;
    if &header[..4] != b"xar!" {
        return Err(anyhow::anyhow!("invalid XAR signature"));
    }
    let header_size = u16::from_be_bytes([header[4], header[5]]) as usize;
    if header_size < XAR_HEADER_SIZE || header_size > 4096 {
        return Err(anyhow::anyhow!("invalid XAR header size"));
    }
    if header_size > XAR_HEADER_SIZE {
        let mut extra = vec![0u8; header_size - XAR_HEADER_SIZE];
        std::io::Read::read_exact(&mut file, &mut extra)?;
    }
    let toc_compressed = u64::from_be_bytes(header[8..16].try_into().unwrap());
    if toc_compressed > MAX_TOC_BYTES || toc_compressed > budget.max_entry_bytes() {
        budget.mark_truncated();
        return Ok(());
    }
    let mut compressed = vec![0u8; toc_compressed as usize];
    std::io::Read::read_exact(&mut file, &mut compressed)?;
    let toc_cap = MAX_TOC_BYTES.min(budget.max_entry_bytes());
    let decoder = flate2::read::ZlibDecoder::new(io::Cursor::new(compressed));
    let mut toc_reader = CappedReader::new(decoder, toc_cap);
    let mut toc_xml = Vec::new();
    io::copy(&mut toc_reader, &mut toc_xml)?;
    let document: XarDocument = quick_xml::de::from_reader(io::Cursor::new(toc_xml))
        .context("invalid XAR table of contents")?;
    let heap_start = file.stream_position()?;
    extract_xar_files(
        &mut file,
        heap_start,
        document.toc.files,
        Path::new(""),
        dest,
        budget,
        0,
    )
}

fn extract_xar_files(
    file: &mut File,
    heap_start: u64,
    files: Vec<XarFile>,
    prefix: &Path,
    dest: &Path,
    budget: &mut Budget,
    depth: u32,
) -> Result<()> {
    if depth > 64 {
        budget.mark_truncated();
        return Ok(());
    }
    for entry in files {
        if budget.truncated() {
            break;
        }
        let name = entry.name.unwrap_or_default();
        let relative = prefix.join(name);
        let Some(out_path) = safe_join(dest, &relative.to_string_lossy()) else {
            continue;
        };
        if entry.kind.as_deref() == Some("directory") {
            fs::create_dir_all(&out_path)?;
            extract_xar_files(file, heap_start, entry.children, &relative, dest, budget, depth + 1)?;
            continue;
        }
        if !entry.children.is_empty() {
            extract_xar_files(file, heap_start, entry.children, &relative, dest, budget, depth + 1)?;
        }
        let Some(data) = entry.data else {
            continue;
        };
        if data.size > budget.cap_for_next_entry() {
            budget.mark_truncated();
            break;
        }
        if !budget.note_entry() {
            break;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let start = heap_start
            .checked_add(data.offset)
            .ok_or_else(|| anyhow::anyhow!("XAR data offset overflow"))?;
        file.seek(SeekFrom::Start(start))?;
        let source = file.by_ref().take(data.length);
        let mut out_file = File::create(out_path)?;
        let written = match data.encoding.style.as_str() {
            "application/octet-stream" => {
                let mut capped = CappedReader::new(source, data.size);
                let result = io::copy(&mut capped, &mut out_file);
                let bytes = capped.bytes_read();
                if let Err(error) = result {
                    if is_cap_exceeded(&error) {
                        budget.mark_truncated();
                    } else {
                        return Err(error.into());
                    }
                }
                bytes
            }
            "application/x-gzip" => {
                let decoder = flate2::read::ZlibDecoder::new(source);
                let mut capped = CappedReader::new(decoder, data.size);
                let result = io::copy(&mut capped, &mut out_file);
                let bytes = capped.bytes_read();
                if let Err(error) = result {
                    if is_cap_exceeded(&error) {
                        budget.mark_truncated();
                    } else {
                        return Err(error.into());
                    }
                }
                bytes
            }
            "application/x-bzip2" => {
                let decoder = bzip2_rs::DecoderReader::new(source);
                let mut capped = CappedReader::new(decoder, data.size);
                let result = io::copy(&mut capped, &mut out_file);
                let bytes = capped.bytes_read();
                if let Err(error) = result {
                    if is_cap_exceeded(&error) {
                        budget.mark_truncated();
                    } else {
                        return Err(error.into());
                    }
                }
                bytes
            }
            "application/x-lzma" | "application/x-xz" => {
                let mut capped = CappedWriter::new(out_file, data.size);
                lzma_rs::xz_decompress(&mut io::BufReader::new(source), &mut capped)
                    .map_err(|error| anyhow::anyhow!("invalid XAR xz member: {error}"))?;
                capped.bytes_written()
            }
            encoding => return Err(anyhow::anyhow!("unsupported XAR encoding: {encoding}")),
        };
        budget.account(written);
    }
    Ok(())
}
