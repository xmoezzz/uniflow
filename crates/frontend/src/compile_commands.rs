use crate::FrontendOptions;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompileCommandOptions {
    pub defines: BTreeMap<String, Option<String>>,
    pub undefines: BTreeSet<String>,
    pub include_paths: Vec<PathBuf>,
    pub language_standard: Option<String>,
    pub target_triple: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CompileCommandDatabase {
    entries: BTreeMap<PathBuf, CompileCommandOptions>,
}

#[derive(Debug, Deserialize)]
struct RawCompileCommand {
    directory: PathBuf,
    file: PathBuf,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    arguments: Option<Vec<String>>,
}

impl CompileCommandDatabase {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read compile database from {}", path.display()))?;
        let raw = serde_json::from_str::<Vec<RawCompileCommand>>(&text)
            .with_context(|| format!("failed to decode compile database from {}", path.display()))?;
        let mut entries = BTreeMap::new();
        for command in raw {
            let file = if command.file.is_absolute() {
                command.file.clone()
            } else {
                command.directory.join(&command.file)
            };
            let args = command
                .arguments
                .unwrap_or_else(|| shell_words(command.command.as_deref().unwrap_or_default()));
            entries.insert(
                normalize_path(&file),
                parse_compile_arguments(&command.directory, &args),
            );
        }
        Ok(Self { entries })
    }

    pub fn options_for(&self, file: &Path) -> Option<&CompileCommandOptions> {
        let normalized = normalize_path(file);
        self.entries.get(&normalized).or_else(|| {
            normalized.file_name().and_then(|name| {
                let mut matches = self
                    .entries
                    .iter()
                    .filter(|(candidate, _)| candidate.file_name() == Some(name));
                let first = matches.next()?;
                matches.next().is_none().then_some(first.1)
            })
        })
    }
}

impl FrontendOptions {
    pub fn with_compile_command(&self, command: Option<&CompileCommandOptions>) -> Self {
        let mut out = self.clone();
        out.compile_commands = None;
        if let Some(command) = command {
            out.defines.extend(command.defines.clone());
            out.undefines.extend(command.undefines.clone());
            for include in &command.include_paths {
                if !out.include_paths.iter().any(|existing| existing == include) {
                    out.include_paths.push(include.clone());
                }
            }
            if command.language_standard.is_some() {
                out.language_standard = command.language_standard.clone();
            }
            if command.target_triple.is_some() {
                out.target_triple = command.target_triple.clone();
            }
        }
        out
    }
}

fn parse_compile_arguments(directory: &Path, args: &[String]) -> CompileCommandOptions {
    let mut out = CompileCommandOptions::default();
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = arg.strip_prefix("-D").or_else(|| arg.strip_prefix("/D")) {
            let value = if value.is_empty() {
                index += 1;
                args.get(index).map(String::as_str).unwrap_or_default()
            } else {
                value
            };
            if let Some((name, value)) = value.split_once('=') {
                out.defines.insert(name.to_string(), Some(value.to_string()));
            } else if !value.is_empty() {
                out.defines.insert(value.to_string(), None);
            }
        } else if let Some(value) = arg.strip_prefix("-U").or_else(|| arg.strip_prefix("/U")) {
            let value = if value.is_empty() {
                index += 1;
                args.get(index).map(String::as_str).unwrap_or_default()
            } else {
                value
            };
            if !value.is_empty() {
                out.undefines.insert(value.to_string());
            }
        } else if arg == "-I" || arg == "-isystem" || arg == "/I" {
            index += 1;
            if let Some(path) = args.get(index) {
                out.include_paths.push(resolve_path(directory, path));
            }
        } else if let Some(path) = arg.strip_prefix("-I").filter(|path| !path.is_empty()) {
            out.include_paths.push(resolve_path(directory, path));
        } else if let Some(path) = arg.strip_prefix("/I").filter(|path| !path.is_empty()) {
            out.include_paths.push(resolve_path(directory, path.trim_matches('"')));
        } else if let Some(standard) = arg.strip_prefix("-std=").or_else(|| arg.strip_prefix("/std:")) {
            out.language_standard = Some(standard.to_string());
        } else if let Some(target) = arg.strip_prefix("--target=") {
            out.target_triple = Some(target.to_string());
        } else if arg == "-target" {
            index += 1;
            out.target_triple = args.get(index).cloned();
        }
        index += 1;
    }
    out.include_paths.sort();
    out.include_paths.dedup();
    out
}

fn resolve_path(directory: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    let resolved = if path.is_absolute() {
        path
    } else {
        directory.join(path)
    };
    normalize_path(&resolved)
}

fn normalize_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn shell_words(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ch if ch.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gnu_and_msvc_compile_flags() {
        let args = shell_words("clang++ -DDEBUG=1 -UOLD -I include -isystem '/sdk headers' -std=c++20 --target=x86_64-linux-gnu main.cpp");
        let parsed = parse_compile_arguments(Path::new("/project"), &args);
        assert_eq!(parsed.defines.get("DEBUG"), Some(&Some("1".to_string())));
        assert!(parsed.undefines.contains("OLD"));
        assert_eq!(parsed.language_standard.as_deref(), Some("c++20"));
        assert_eq!(parsed.target_triple.as_deref(), Some("x86_64-linux-gnu"));
        assert_eq!(parsed.include_paths.len(), 2);

        let msvc = parse_compile_arguments(
            Path::new("C:/project"),
            &["cl.exe".into(), "/DWIN32".into(), "/Iinclude".into(), "/std:c++latest".into()],
        );
        assert!(msvc.defines.contains_key("WIN32"));
        assert_eq!(msvc.language_standard.as_deref(), Some("c++latest"));
    }
}
