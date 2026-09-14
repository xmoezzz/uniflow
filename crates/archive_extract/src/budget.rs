//! Decompression-bomb defense: every decoded byte, regardless of format,
//! flows through a [`CappedReader`]/[`CappedWriter`] before it is ever
//! written to disk, so an oversized decompressed stream is caught as soon as
//! it happens rather than trusting a container's own declared size.

use std::io::{self, Read, Write};

use crate::ExtractOptions;

const CAP_EXCEEDED: &str = "decompressed size exceeds the configured extraction budget";

/// Tracks the shared, cumulative extraction budget across an entire
/// recursive-extraction run (all archives, all nesting depths).
pub(crate) struct Budget {
    max_entry_bytes: u64,
    remaining_total: u64,
    remaining_entries: u64,
    bytes_written: u64,
    truncated: bool,
}

impl Budget {
    pub(crate) fn new(options: &ExtractOptions) -> Self {
        Self {
            max_entry_bytes: options.max_entry_bytes,
            remaining_total: options.max_total_bytes,
            remaining_entries: options.max_entries,
            bytes_written: 0,
            truncated: false,
        }
    }

    pub(crate) fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub(crate) fn truncated(&self) -> bool {
        self.truncated
    }

    /// Reserves budget for one more extracted file. Returns `false` (and
    /// marks the run truncated) once `max_entries` is exhausted.
    pub(crate) fn note_entry(&mut self) -> bool {
        if self.remaining_entries == 0 {
            self.truncated = true;
            return false;
        }
        self.remaining_entries -= 1;
        true
    }

    /// The byte cap to apply to the next entry: the smaller of the
    /// per-entry cap and whatever remains of the total budget.
    pub(crate) fn cap_for_next_entry(&self) -> u64 {
        self.max_entry_bytes.min(self.remaining_total)
    }

    /// Records that `bytes` were actually written for the entry just
    /// extracted (after the fact, from a [`CappedReader`]/[`CappedWriter`]'s
    /// own count), deducting them from the running total budget.
    pub(crate) fn account(&mut self, bytes: u64) {
        self.bytes_written += bytes;
        self.remaining_total = self.remaining_total.saturating_sub(bytes);
    }

    pub(crate) fn mark_truncated(&mut self) {
        self.truncated = true;
    }
}

/// Wraps a decompression [`Read`] stream, erroring as soon as more than
/// `cap` bytes would be produced — instead of silently stopping (like
/// `Read::take`), so the caller can distinguish "the archive legitimately
/// ended right at the cap" from "this stream was cut off".
pub(crate) struct CappedReader<R> {
    inner: R,
    remaining: u64,
    read: u64,
}

impl<R: Read> CappedReader<R> {
    pub(crate) fn new(inner: R, cap: u64) -> Self {
        Self {
            inner,
            remaining: cap,
            read: 0,
        }
    }

    pub(crate) fn bytes_read(&self) -> u64 {
        self.read
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            // Distinguish "the stream legitimately ends exactly at the cap"
            // from "there is more data we are refusing to decode".
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(CAP_EXCEEDED)),
            };
        }
        let allowed = (buf.len() as u64).min(self.remaining) as usize;
        let n = self.inner.read(&mut buf[..allowed])?;
        self.remaining -= n as u64;
        self.read += n as u64;
        Ok(n)
    }
}

/// Same idea as [`CappedReader`] but for sinks: used with decompressors
/// (`lzma-rs`) that decompress in one call into an arbitrary [`Write`]
/// rather than exposing a lazy [`Read`] adapter, so the only way to bound
/// their memory/disk usage is to cap the destination they write into.
pub(crate) struct CappedWriter<W> {
    inner: W,
    remaining: u64,
}

impl<W: Write> CappedWriter<W> {
    pub(crate) fn new(inner: W, cap: u64) -> Self {
        Self { inner, remaining: cap }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() as u64 > self.remaining {
            return Err(io::Error::other(CAP_EXCEEDED));
        }
        let n = self.inner.write(buf)?;
        self.remaining -= n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `true` if `error` (or one of its sources) is the cap-exceeded sentinel
/// this module raises — callers use this to turn a hard error into a
/// graceful "stop extracting this one archive, mark the run truncated".
pub(crate) fn is_cap_exceeded(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.to_string() == CAP_EXCEEDED)
}
