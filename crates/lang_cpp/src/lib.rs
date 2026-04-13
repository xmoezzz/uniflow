use anyhow::Result;
use uniflow_hir::Language;
use uniflow_lang_c::parse_c_like_file;
use uniflow_parser_core::SourceParser;

#[derive(Default)]
pub struct CppParser;

impl SourceParser for CppParser {
    fn language(&self) -> Language {
        Language::Cpp
    }

    fn parse_file(&self, path: &str, source: &str) -> Result<uniflow_hir::Program> {
        parse_c_like_file(Language::Cpp, path, source)
    }
}
