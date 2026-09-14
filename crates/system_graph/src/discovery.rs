//! A small, shared directory walker used by [`crate::docker_compose`] and
//! [`crate::kubernetes`] to find their own candidate files under a set of
//! scan roots. This repo has no `walkdir` dependency anywhere outside the
//! unrelated `sca-main` product — `crates/frontend/src/files.rs`'s own
//! collectors are all hand-rolled `fs::read_dir` recursion too — so this
//! matches that existing convention rather than introducing one.

use std::path::{Path, PathBuf};

const IGNORED_DIR_NAMES: &[&str] = &[
    ".git", ".hg", ".svn", ".cache", ".gradle", ".idea", ".next", ".nuxt", ".pytest_cache",
    ".mypy_cache", ".tox", ".venv", "__pycache__", "node_modules", "target", "venv",
];

/// Walks every root (a file or a directory) in `roots`, collecting every
/// file for which `matches` returns `true`. Symlinks and common
/// dependency/build directories are skipped, matching
/// `crates/frontend/src/files.rs`'s own walking policy.
pub fn find_files(roots: &[PathBuf], matches: impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in roots {
        visit(root, &matches, &mut found);
    }
    found
}

fn visit(path: &Path, matches: &impl Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else { return };
    if metadata.is_symlink() {
        return;
    }
    if metadata.is_file() {
        if matches(path) {
            out.push(path.to_path_buf());
        }
        return;
    }
    if metadata.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else { return };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else { continue };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() && entry.file_name().to_str().is_some_and(|name| IGNORED_DIR_NAMES.contains(&name)) {
                continue;
            }
            visit(&entry.path(), matches, out);
        }
    }
}
