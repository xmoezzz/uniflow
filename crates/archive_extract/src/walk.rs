//! Finds candidate archive files under a set of root paths. This repo has no
//! `walkdir` dependency anywhere outside the unrelated `sca-main` product;
//! `crates/frontend/src/files.rs`'s own collectors are all hand-rolled
//! `fs::read_dir` recursion, so this matches that existing convention rather
//! than introducing a new dependency for one small walk.

use std::path::{Path, PathBuf};
use std::{fs, io};

use crate::format::{classify, Format};

/// Mirrors `crates/frontend/src/files.rs`'s `is_default_ignored_directory`
/// list: directories that never carry anything worth extracting into, so
/// walking into them (which can be enormous, e.g. `node_modules`) is wasted
/// work — nothing extracted from inside them would be seen by the source
/// collectors either, since they skip these same names.
const IGNORED_DIR_NAMES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".cache",
    ".gradle",
    ".idea",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "venv",
];

fn is_ignored_directory(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(|name| IGNORED_DIR_NAMES.contains(&name))
}

pub(crate) fn find_archives(roots: &[PathBuf]) -> io::Result<Vec<(PathBuf, Format)>> {
    let mut found = Vec::new();
    for root in roots {
        visit(root, &mut found)?;
    }
    Ok(found)
}

fn visit(path: &Path, out: &mut Vec<(PathBuf, Format)>) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        // A root that doesn't exist (or a dangling entry seen mid-walk) is
        // not this crate's problem to report; the downstream file collectors
        // will surface it if it matters.
        Err(_) => return Ok(()),
    };
    if metadata.is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if let Some(format) = classify(path) {
            out.push((path.to_path_buf(), format));
        }
        return Ok(());
    }
    if metadata.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() && is_ignored_directory(&entry.file_name()) {
                continue;
            }
            visit(&entry.path(), out)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_archives_and_skips_ignored_directories() {
        let dir = tempfile::tempdir().expect("create temp dir");
        std::fs::write(dir.path().join("payload.zip"), b"not a real zip, just for extension matching")
            .expect("write file");
        let ignored = dir.path().join("node_modules");
        std::fs::create_dir(&ignored).expect("create node_modules");
        std::fs::write(ignored.join("also.zip"), b"should never be found").expect("write file");

        let found = find_archives(&[dir.path().to_path_buf()]).expect("walk succeeds");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, dir.path().join("payload.zip"));
    }
}
