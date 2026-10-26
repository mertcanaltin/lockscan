//! `package-lock.json` and `npm-shrinkwrap.json`.
//!
//! Versions 2 and 3 list every installed directory under `packages`, keyed by
//! its path: `node_modules/a/node_modules/@b/c`. Version 1 has no such map,
//! only a `dependencies` tree that nests where npm nested the directories.
//! A version 2 file carries both; the `packages` map is the one npm reads.

use super::{is_registry_version, split_name, Package};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub fn parse(text: &str) -> Result<BTreeSet<Package>, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
    let root = root
        .as_object()
        .ok_or("the lockfile is not a JSON object")?;
    let mut out = BTreeSet::new();
    if let Some(packages) = root.get("packages").and_then(Value::as_object) {
        from_packages(packages, &mut out);
    } else if let Some(deps) = root.get("dependencies").and_then(Value::as_object) {
        from_dependencies(deps, &mut out);
    } else {
        return Err("neither `packages` nor `dependencies` in the lockfile".into());
    }
    Ok(out)
}

const NODE_MODULES: &str = "node_modules/";

fn from_packages(packages: &Map<String, Value>, out: &mut BTreeSet<Package>) {
    for (key, entry) in packages {
        // The root project is "", and a workspace member is its own directory
        // ("packages/app"): neither is installed from the registry.
        let Some(at) = key.rfind(NODE_MODULES) else {
            continue;
        };
        let Some(entry) = entry.as_object() else {
            continue;
        };
        // A symlink to a workspace member or a local directory.
        if entry.get("link").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        if let Some(resolved) = entry.get("resolved").and_then(Value::as_str) {
            if is_local_or_git(resolved) {
                continue;
            }
        }
        // An aliased install keeps the alias as its directory and records the
        // real name in `name`.
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&key[at + NODE_MODULES.len()..]);
        if !name.is_empty() && is_registry_version(version) {
            out.insert(Package::new(name, version));
        }
    }
}

fn from_dependencies(deps: &Map<String, Value>, out: &mut BTreeSet<Package>) {
    for (name, entry) in deps {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        if let Some(version) = entry.get("version").and_then(Value::as_str) {
            // An alias records `npm:real-name@version` as its version.
            let (name, version) = match version.strip_prefix("npm:").and_then(split_name) {
                Some((real, v)) => (real, v),
                None => (name.as_str(), version),
            };
            let local = entry
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(is_local_or_git);
            if !local && is_registry_version(version) {
                out.insert(Package::new(name, version));
            }
        }
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            from_dependencies(nested, out);
        }
    }
}

/// A `resolved` that points at a directory, a local tarball or a git host
/// rather than a registry tarball.
fn is_local_or_git(resolved: &str) -> bool {
    resolved.starts_with("file:")
        || resolved.starts_with("git")
        || resolved.starts_with("github:")
        || resolved.starts_with("link:")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(set: &BTreeSet<Package>) -> Vec<String> {
        set.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn reads_the_packages_map_of_v3() {
        let text = r#"{
          "name": "app", "lockfileVersion": 3,
          "packages": {
            "": { "name": "app", "version": "1.0.0" },
            "node_modules/lodash": { "version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
            "node_modules/@babel/core": { "version": "7.24.0" },
            "node_modules/a/node_modules/lodash": { "version": "3.10.1" },
            "node_modules/my-lodash": { "name": "lodash", "version": "4.17.21" },
            "node_modules/app-ui": { "resolved": "packages/ui", "link": true },
            "packages/ui": { "name": "app-ui", "version": "0.0.1" },
            "node_modules/local": { "version": "1.0.0", "resolved": "file:../local" },
            "node_modules/from-git": { "version": "1.0.0", "resolved": "git+ssh://git@github.com/a/b.git#abc" }
          }
        }"#;
        assert_eq!(
            names(&parse(text).unwrap()),
            [
                "@babel/core@7.24.0",
                "lodash@3.10.1",
                "lodash@4.17.20",
                "lodash@4.17.21"
            ]
        );
    }

    #[test]
    fn prefers_packages_over_dependencies_in_v2() {
        let text = r#"{
          "lockfileVersion": 2,
          "packages": { "node_modules/a": { "version": "1.0.0" } },
          "dependencies": { "b": { "version": "2.0.0" } }
        }"#;
        assert_eq!(names(&parse(text).unwrap()), ["a@1.0.0"]);
    }

    #[test]
    fn walks_the_nested_tree_of_v1() {
        let text = r#"{
          "lockfileVersion": 1,
          "dependencies": {
            "a": { "version": "1.0.0", "dependencies": { "b": { "version": "2.0.0" } } },
            "b": { "version": "3.0.0" },
            "alias": { "version": "npm:@scope/real@1.2.3" },
            "local": { "version": "file:../local" },
            "gitdep": { "version": "1.0.0", "resolved": "github:a/b#abc" }
          }
        }"#;
        assert_eq!(
            names(&parse(text).unwrap()),
            ["@scope/real@1.2.3", "a@1.0.0", "b@2.0.0", "b@3.0.0"]
        );
    }

    #[test]
    fn rejects_what_is_not_a_lockfile() {
        assert!(parse("[]").is_err());
        assert!(parse("{}").is_err());
        assert!(parse("not json").is_err());
    }
}
