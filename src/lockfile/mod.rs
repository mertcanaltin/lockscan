//! Lockfile readers. Each one turns a lockfile into the set of registry
//! packages it installs: a name as the registry knows it and an exact version.
//!
//! What is left out is left out on purpose, because it cannot be looked up in
//! a vulnerability database by name and version: workspace packages, links,
//! local directories and tarballs, and git dependencies.

mod npm;
mod pnpm;
mod yarn;

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// A package as the registry knows it. An alias (`"my-lodash": "npm:lodash@4"`)
/// is reported under the real name, since that is the name advisories use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Package {
    pub name: String,
    pub version: String,
}

impl Package {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Package {
            name: name.into(),
            version: version.into(),
        }
    }
}

impl fmt::Display for Package {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Npm,
    Pnpm,
    Yarn,
}

impl Kind {
    /// The kind a file name says, or None for a name this tool does not read.
    pub fn from_file_name(name: &str) -> Option<Kind> {
        match name {
            "package-lock.json" | "npm-shrinkwrap.json" => Some(Kind::Npm),
            "pnpm-lock.yaml" => Some(Kind::Pnpm),
            "yarn.lock" => Some(Kind::Yarn),
            _ => None,
        }
    }
}

/// The lockfiles looked for in a directory, in this order. npm's shrinkwrap
/// wins over its lockfile, as it does for npm itself.
const CANDIDATES: [&str; 4] = [
    "npm-shrinkwrap.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

/// The lockfile to read for `path`: the file itself, or the first lockfile
/// found in it when it is a directory.
pub fn locate(path: &Path) -> Result<(PathBuf, Kind), String> {
    if path.is_dir() {
        for name in CANDIDATES {
            let file = path.join(name);
            if file.is_file() {
                return Ok((file, Kind::from_file_name(name).expect("a known name")));
            }
        }
        return Err(format!(
            "no lockfile in {} (looked for {})",
            path.display(),
            CANDIDATES.join(", ")
        ));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    match Kind::from_file_name(name) {
        Some(kind) => Ok((path.to_path_buf(), kind)),
        None => Err(format!(
            "{} is not a lockfile this tool reads ({})",
            path.display(),
            CANDIDATES.join(", ")
        )),
    }
}

/// The registry packages a lockfile installs, each once.
pub fn parse(kind: Kind, text: &str) -> Result<BTreeSet<Package>, String> {
    match kind {
        Kind::Npm => npm::parse(text),
        Kind::Pnpm => pnpm::parse(text),
        Kind::Yarn => yarn::parse(text),
    }
}

/// Whether a version string is a published version rather than a URL, a
/// path or a git reference written where a version would be.
pub(crate) fn is_registry_version(version: &str) -> bool {
    version.chars().next().is_some_and(|c| c.is_ascii_digit())
}

/// Splits `name@rest` where the name may be scoped (`@scope/name@rest`).
/// None when there is no separator after the name.
pub(crate) fn split_name(spec: &str) -> Option<(&str, &str)> {
    let from = usize::from(spec.starts_with('@'));
    let at = spec[from..].find('@')? + from;
    if at == 0 {
        return None;
    }
    Some((&spec[..at], &spec[at + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_plain_and_scoped_names() {
        assert_eq!(split_name("lodash@4.17.21"), Some(("lodash", "4.17.21")));
        assert_eq!(
            split_name("@babel/core@^7.0.0"),
            Some(("@babel/core", "^7.0.0"))
        );
        assert_eq!(split_name("@babel/core"), None);
        assert_eq!(split_name("lodash"), None);
    }

    #[test]
    fn tells_versions_from_urls_and_paths() {
        assert!(is_registry_version("1.2.3"));
        assert!(is_registry_version("0.0.1-beta.1"));
        assert!(!is_registry_version("https://example.com/a.tgz"));
        assert!(!is_registry_version("file:../a"));
        assert!(!is_registry_version("link:../a"));
        assert!(!is_registry_version(""));
    }

    #[test]
    fn knows_lockfile_names() {
        assert_eq!(Kind::from_file_name("package-lock.json"), Some(Kind::Npm));
        assert_eq!(Kind::from_file_name("npm-shrinkwrap.json"), Some(Kind::Npm));
        assert_eq!(Kind::from_file_name("pnpm-lock.yaml"), Some(Kind::Pnpm));
        assert_eq!(Kind::from_file_name("yarn.lock"), Some(Kind::Yarn));
        assert_eq!(Kind::from_file_name("package.json"), None);
    }
}
