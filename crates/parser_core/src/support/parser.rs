
pub trait SourceParser {
    fn language(&self) -> Language;
    fn parse_file(&self, path: &str, source: &str) -> Result<Program>;
}

