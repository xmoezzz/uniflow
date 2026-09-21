# RAR decoder notice

UniFlow uses `unrar-rs` as a pure-Rust RAR4/RAR5 reader and streaming decoder.
It does not link to `libarchive`, the C/C++ UnRAR sources, a shared library, or
a host `unrar` executable.

The upstream crate's license is GPLv3-or-later with the RARLAB UnRAR
restriction: the decoder may be used to handle existing RAR archives, but must
not be used to develop a RAR/WinRAR-compatible archiver or to re-create the RAR
compression algorithm. The complete upstream text is preserved in the
dependency and is available at:
https://docs.rs/crate/unrar-rs/latest/source/LICENSE

This license must be reviewed before shipping a proprietary/commercial binary;
the pure-Rust implementation removes the native C/C++ build dependency but
does not by itself change the upstream license obligations.
