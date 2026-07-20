mod clang_ast;
mod conditionals;
mod config;
mod compile_commands;
mod files;
mod header_index;
mod parse;

pub use clang_ast::{clang_translation_unit_args, dump_clang_ast_json, ClangAstOptions};
pub use conditionals::simulate_c_family_conditionals;
pub use compile_commands::{CompileCommandDatabase, CompileCommandOptions};
pub use config::FrontendOptions;
pub use files::{collect_source_files, supports_path};
pub use header_index::collect_project_headers;
pub use parse::{
    parse_project_files, parse_project_files_with_options, parse_project_paths,
    parse_project_paths_with_options, parse_project_sources, parse_project_sources_with_options,
    parse_source, parse_source_file, parse_source_file_with_options, parse_source_with_options,
};
