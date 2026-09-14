mod decl;
mod env;
mod expr;
mod functions;
mod project_index;
mod stmt;
#[cfg(test)]
mod tests;

use anyhow::Result;
use uniflow_hir::{Language, Program};
use uniflow_parser_core::SourceParser;

pub use project_index::{parse_project_sources, parse_project_sources_with_progress};

#[derive(Default)]
pub struct RubyParser;

impl SourceParser for RubyParser {
    fn language(&self) -> Language {
        Language::Ruby
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<Program> {
        project_index::parse_file_standalone(path, source)
    }
}
