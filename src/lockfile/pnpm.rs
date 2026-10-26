//! `pnpm-lock.yaml`.
//!
//! The installed packages are the keys of the top-level `packages:` map, and
//! their form changed across lockfile versions:
//!
//! - 5.x:  `/name/1.2.3`, `/@scope/name/1.2.3`, peers as `_peer@1.0.0`
//! - 6.x:  `/name@1.2.3`, `/@scope/name@1.2.3`, peers as `(peer@1.0.0)`
//! - 9.x:  `name@1.2.3`, the same without the leading slash
//!
//! A lockfile is machine-written, one key per line at two spaces of indent,
//! so the keys are read line by line rather than through a YAML parser.

use super::{is_registry_version, split_name, Package};
use std::collections::BTreeSet;

pub fn parse(text: &str) -> Result<BTreeSet<Package>, String> {
    let version = lockfile_version(text).ok_or("no lockfileVersion in pnpm-lock.yaml")?;
    let slash_form = version.starts_with('5');
    let mut out = BTreeSet::new();
    let mut in_packages = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // A key is indented by exactly two spaces and ends with a colon.
        let Some(key) = line.strip_prefix("  ") else {
            continue;
        };
        if key.starts_with(' ') {
            continue;
        }
        let Some(key) = key.trim_end().strip_suffix(':') else {
            continue;
        };
        let key = unquote(key);
        let parsed = if slash_form {
            slash_key(key)
        } else {
            at_key(key)
        };
        if let Some(p) = parsed {
            out.insert(p);
        }
    }
    Ok(out)
}

fn lockfile_version(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|l| l.strip_prefix("lockfileVersion:"))
        .map(|v| unquote(v.trim()))
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(s)
}

/// `/name/1.2.3_peer@1.0.0`, the 5.x form.
fn slash_key(key: &str) -> Option<Package> {
    let key = key.strip_prefix('/')?;
    let slash = key.rfind('/')?;
    let (name, version) = (&key[..slash], &key[slash + 1..]);
    let version = version.split('_').next()?;
    (is_registry_version(version) && !name.is_empty()).then(|| Package::new(name, version))
}

/// `/name@1.2.3(peer@1.0.0)` (6.x) or `name@1.2.3(peer@1.0.0)` (9.x).
fn at_key(key: &str) -> Option<Package> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next()?;
    let (name, version) = split_name(key)?;
    is_registry_version(version).then(|| Package::new(name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(set: &BTreeSet<Package>) -> Vec<String> {
        set.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn reads_v9_keys_and_ignores_snapshots() {
        let text = "\
lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.20

packages:
  '@babel/core@7.24.0':
    resolution: {integrity: sha512-x}
  lodash@4.17.20:
    resolution: {integrity: sha512-y}
  react-dom@18.2.0:
    resolution: {integrity: sha512-z}
  tarball@https://example.com/t.tgz:
    resolution: {tarball: https://example.com/t.tgz}

snapshots:
  react-dom@18.2.0(react@18.2.0):
    dependencies:
      react: 18.2.0
  other@1.0.0: {}
";
        assert_eq!(
            names(&parse(text).unwrap()),
            ["@babel/core@7.24.0", "lodash@4.17.20", "react-dom@18.2.0"]
        );
    }

    #[test]
    fn reads_v6_keys_with_peers() {
        let text = "\
lockfileVersion: '6.0'

packages:

  /@types/node@20.11.0:
    resolution: {integrity: sha512-a}
    dev: true

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-b}
";
        assert_eq!(
            names(&parse(text).unwrap()),
            ["@types/node@20.11.0", "react-dom@18.2.0"]
        );
    }

    #[test]
    fn reads_v5_slash_keys() {
        let text = "\
lockfileVersion: 5.4

packages:

  /@babel/core/7.24.0:
    resolution: {integrity: sha512-a}

  /react-dom/17.0.2_react@17.0.2:
    resolution: {integrity: sha512-b}
";
        assert_eq!(
            names(&parse(text).unwrap()),
            ["@babel/core@7.24.0", "react-dom@17.0.2"]
        );
    }

    #[test]
    fn needs_a_lockfile_version() {
        assert!(parse("packages:\n  a@1.0.0:\n").is_err());
    }
}
