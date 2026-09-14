//! A source-level Ruby frontend backed by the pure-Rust `lib-ruby-parser`
//! crate. Mirrors `uniflow_lang_rust`'s shape: `RubyParser` implements
//! `uniflow_parser_core::SourceParser` for single-file parsing, and
//! `parse_project_sources`/`parse_project_sources_with_progress` merge an
//! independently-parsed-per-file project (see `frontend::project_index`'s
//! module doc comment for why Ruby needs no whole-project view up front).

mod frontend;

pub use frontend::{parse_project_sources, parse_project_sources_with_progress, RubyParser};
