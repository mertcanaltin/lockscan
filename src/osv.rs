//! The OSV.dev API: which advisories affect each package, then the details of
//! each advisory (summary, severity, the versions that fix it).
//!
//! `POST /v1/querybatch` answers up to 1000 packages per request with the ids
//! of the advisories that affect them, and nothing else; `GET /v1/vulns/{id}`
//! gives the rest. Each advisory is fetched once however many packages it
//! affects, on a few threads.

use crate::lockfile::Package;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub const DEFAULT_URL: &str = "https://api.osv.dev";
const BATCH: usize = 1000;
const THREADS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Moderate,
    Low,
    Unknown,
}

impl Severity {
    fn from_label(label: &str) -> Severity {
        match label.to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Moderate,
            "LOW" => Severity::Low,
            _ => Severity::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Moderate => "MODERATE",
            Severity::Low => "LOW",
            Severity::Unknown => "UNKNOWN",
        }
    }
}

/// One advisory that affects one installed package.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub name: String,
    pub version: String,
    pub id: String,
    pub aliases: Vec<String>,
    pub severity: Severity,
    pub summary: String,
    /// The lowest version above the installed one that the advisory lists as
    /// fixed, or None when it lists none.
    pub fixed: Option<String>,
}

pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base: &str) -> Client {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("lockscan/", env!("CARGO_PKG_VERSION")))
            .build();
        Client {
            base: base.trim_end_matches('/').to_string(),
            agent,
        }
    }

    pub fn scan(&self, packages: &BTreeSet<Package>) -> Result<Vec<Finding>, String> {
        let packages: Vec<&Package> = packages.iter().collect();
        let mut hits: BTreeMap<String, Vec<&Package>> = BTreeMap::new();
        for chunk in packages.chunks(BATCH) {
            for (pkg, ids) in chunk.iter().zip(self.query_batch(chunk)?) {
                for id in ids {
                    hits.entry(id).or_default().push(pkg);
                }
            }
        }
        let ids: Vec<&String> = hits.keys().collect();
        let details = self.fetch_all(&ids)?;
        let mut findings = Vec::new();
        for (id, pkgs) in &hits {
            let vuln = &details[id];
            for pkg in pkgs {
                findings.push(finding(pkg, id, vuln));
            }
        }
        findings.sort_by(|a, b| {
            (&a.severity, &a.name, &a.version, &a.id).cmp(&(
                &b.severity,
                &b.name,
                &b.version,
                &b.id,
            ))
        });
        Ok(findings)
    }

    /// The advisory ids for each package of `chunk`, in order.
    fn query_batch(&self, chunk: &[&Package]) -> Result<Vec<Vec<String>>, String> {
        let queries: Vec<Value> = chunk
            .iter()
            .map(|p| json!({ "package": { "name": p.name, "ecosystem": "npm" }, "version": p.version }))
            .collect();
        let body: Value = self
            .agent
            .post(&format!("{}/v1/querybatch", self.base))
            .send_json(json!({ "queries": queries }))
            .map_err(|e| format!("OSV query failed: {e}"))?
            .into_json()
            .map_err(|e| format!("OSV answered with something that is not JSON: {e}"))?;
        let results = body
            .get("results")
            .and_then(Value::as_array)
            .ok_or("OSV answer has no results")?;
        if results.len() != chunk.len() {
            return Err(format!(
                "OSV answered {} results for {} packages",
                results.len(),
                chunk.len()
            ));
        }
        let mut out = Vec::with_capacity(results.len());
        for (i, result) in results.iter().enumerate() {
            let mut ids = ids_of(result);
            // A package with many advisories is paged; the rest come from
            // querying it alone with the token.
            let mut token = next_token(result);
            while let Some(t) = token {
                let page: Value = self
                    .agent
                    .post(&format!("{}/v1/query", self.base))
                    .send_json(json!({
                        "package": { "name": chunk[i].name, "ecosystem": "npm" },
                        "version": chunk[i].version,
                        "page_token": t,
                    }))
                    .map_err(|e| format!("OSV query failed: {e}"))?
                    .into_json()
                    .map_err(|e| format!("OSV answered with something that is not JSON: {e}"))?;
                ids.extend(ids_of(&page));
                token = next_token(&page);
            }
            out.push(ids);
        }
        Ok(out)
    }

    fn fetch_all(&self, ids: &[&String]) -> Result<BTreeMap<String, Vuln>, String> {
        let per = ids.len().div_ceil(THREADS).max(1);
        std::thread::scope(|s| {
            let handles: Vec<_> = ids
                .chunks(per)
                .map(|part| {
                    s.spawn(move || {
                        part.iter()
                            .map(|id| self.fetch(id).map(|v| ((*id).clone(), v)))
                            .collect::<Result<Vec<_>, String>>()
                    })
                })
                .collect();
            let mut out = BTreeMap::new();
            for h in handles {
                out.extend(
                    h.join()
                        .map_err(|_| "a fetch thread panicked".to_string())??,
                );
            }
            Ok(out)
        })
    }

    fn fetch(&self, id: &str) -> Result<Vuln, String> {
        self.agent
            .get(&format!("{}/v1/vulns/{}", self.base, id))
            .call()
            .map_err(|e| format!("fetching {id} failed: {e}"))?
            .into_json()
            .map_err(|e| format!("{id}: not an OSV record: {e}"))
    }
}

fn ids_of(result: &Value) -> Vec<String> {
    result
        .get("vulns")
        .and_then(Value::as_array)
        .map(|vs| {
            vs.iter()
                .filter_map(|v| v.get("id").and_then(Value::as_str).map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn next_token(result: &Value) -> Option<String> {
    result
        .get("next_page_token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(String::from)
}

/// The parts of an OSV record this tool reads.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Vuln {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub database_specific: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Affected {
    #[serde(default)]
    pub package: AffectedPackage,
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub database_specific: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AffectedPackage {
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Range {
    #[serde(default)]
    pub events: Vec<Value>,
}

pub fn finding(pkg: &Package, id: &str, vuln: &Vuln) -> Finding {
    let summary = if vuln.summary.is_empty() {
        vuln.details.lines().next().unwrap_or_default().to_string()
    } else {
        vuln.summary.clone()
    };
    Finding {
        name: pkg.name.clone(),
        version: pkg.version.clone(),
        id: id.to_string(),
        aliases: vuln.aliases.clone(),
        severity: severity(vuln),
        summary,
        fixed: fixed_version(pkg, vuln),
    }
}

/// GitHub's advisories carry a label (`"severity": "HIGH"`); records from
/// other databases often carry none, and are reported as unknown rather than
/// guessed from a CVSS vector.
fn severity(vuln: &Vuln) -> Severity {
    let label = vuln
        .database_specific
        .get("severity")
        .and_then(Value::as_str)
        .or_else(|| {
            vuln.affected
                .iter()
                .find_map(|a| a.database_specific.get("severity").and_then(Value::as_str))
        });
    label.map_or(Severity::Unknown, Severity::from_label)
}

/// The lowest version above the installed one in a `fixed` event of a range
/// for this package. Versions that are not semver are ignored.
pub fn fixed_version(pkg: &Package, vuln: &Vuln) -> Option<String> {
    let installed = semver::Version::parse(&pkg.version).ok()?;
    vuln.affected
        .iter()
        .filter(|a| a.package.ecosystem == "npm" && a.package.name == pkg.name)
        .flat_map(|a| &a.ranges)
        .flat_map(|r| &r.events)
        .filter_map(|e| e.get("fixed").and_then(Value::as_str))
        .filter_map(|f| semver::Version::parse(f).ok())
        .filter(|f| *f > installed)
        .min()
        .map(|v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(json: Value) -> Vuln {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn picks_the_nearest_fix_above_the_installed_version() {
        let v = vuln(json!({
            "affected": [
                { "package": { "ecosystem": "npm", "name": "lodash" },
                  "ranges": [{ "type": "SEMVER", "events": [
                      { "introduced": "0" }, { "fixed": "3.10.2" },
                      { "introduced": "4.0.0" }, { "fixed": "4.17.21" } ] }] },
                { "package": { "ecosystem": "npm", "name": "lodash-es" },
                  "ranges": [{ "type": "SEMVER", "events": [{ "fixed": "4.17.18" }] }] }
            ]
        }));
        assert_eq!(
            fixed_version(&Package::new("lodash", "4.17.15"), &v).as_deref(),
            Some("4.17.21")
        );
        assert_eq!(
            fixed_version(&Package::new("lodash", "3.10.1"), &v).as_deref(),
            Some("3.10.2")
        );
        assert_eq!(fixed_version(&Package::new("lodash", "5.0.0"), &v), None);
        assert_eq!(
            fixed_version(&Package::new("lodash-es", "4.17.15"), &v).as_deref(),
            Some("4.17.18")
        );
    }

    #[test]
    fn reads_severity_labels() {
        assert_eq!(
            severity(&vuln(
                json!({ "database_specific": { "severity": "HIGH" } })
            )),
            Severity::High
        );
        assert_eq!(
            severity(&vuln(
                json!({ "database_specific": { "severity": "MODERATE" } })
            )),
            Severity::Moderate
        );
        assert_eq!(
            severity(&vuln(
                json!({ "affected": [{ "database_specific": { "severity": "low" } }] })
            )),
            Severity::Low
        );
        assert_eq!(severity(&vuln(json!({}))), Severity::Unknown);
    }

    #[test]
    fn orders_severities_most_severe_first() {
        let mut s = vec![
            Severity::Low,
            Severity::Unknown,
            Severity::Critical,
            Severity::Moderate,
            Severity::High,
        ];
        s.sort();
        assert_eq!(
            s,
            [
                Severity::Critical,
                Severity::High,
                Severity::Moderate,
                Severity::Low,
                Severity::Unknown
            ]
        );
    }

    #[test]
    fn falls_back_to_the_first_line_of_details() {
        let f = finding(
            &Package::new("a", "1.0.0"),
            "GHSA-x",
            &vuln(json!({ "details": "First line.\nMore." })),
        );
        assert_eq!(f.summary, "First line.");
    }
}
