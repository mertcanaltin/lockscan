//! lockscan: check the packages a JavaScript lockfile installs against the
//! OSV vulnerability database.
//!
//! Exit status: 0 when nothing reported affects the lockfile, 1 when
//! something does, 2 when the scan could not be completed.

mod lockfile;
mod osv;

use clap::Parser;
use osv::{Finding, Severity};
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Check the packages a JavaScript lockfile installs against OSV.dev"
)]
struct Args {
    /// A lockfile (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml,
    /// yarn.lock) or a directory holding one.
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Print the result as JSON.
    #[arg(long)]
    json: bool,

    /// Only report advisories at this severity or above.
    #[arg(long, value_name = "LEVEL", value_parser = ["low", "moderate", "high", "critical"])]
    min_severity: Option<String>,

    /// Leave out an advisory, by its id or one of its aliases (repeatable).
    #[arg(long, value_name = "ID")]
    ignore: Vec<String>,

    /// Print the packages read from the lockfile and query nothing.
    #[arg(long)]
    list: bool,

    /// The OSV API to query.
    #[arg(long, value_name = "URL", default_value = osv::DEFAULT_URL)]
    osv_url: String,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(found) => ExitCode::from(u8::from(found)),
        Err(e) => {
            eprintln!("lockscan: {e}");
            ExitCode::from(2)
        }
    }
}

/// Whether anything reported affects the lockfile.
fn run(args: &Args) -> Result<bool, String> {
    let (file, kind) = lockfile::locate(&args.path)?;
    let text = std::fs::read_to_string(&file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let packages = lockfile::parse(kind, &text).map_err(|e| format!("{}: {e}", file.display()))?;

    let mut out = io::stdout().lock();
    if args.list {
        for p in &packages {
            writeln!(out, "{p}").map_err(|e| e.to_string())?;
        }
        return Ok(false);
    }

    let floor = args.min_severity.as_deref().map(severity_floor);
    let findings: Vec<Finding> = osv::Client::new(&args.osv_url)
        .scan(&packages)?
        .into_iter()
        .filter(|f| {
            !args
                .ignore
                .iter()
                .any(|i| *i == f.id || f.aliases.contains(i))
        })
        .filter(|f| floor.as_ref().map_or(true, |floor| f.severity <= *floor))
        .collect();

    let written = if args.json {
        let doc = json!({
            "lockfile": file.display().to_string(),
            "packages": packages.len(),
            "findings": findings,
        });
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&doc).expect("serializable")
        )
    } else {
        write_report(&mut out, &file.display().to_string(), &packages, &findings)
    };
    written.map_err(|e| e.to_string())?;
    Ok(!findings.is_empty())
}

fn severity_floor(level: &str) -> Severity {
    match level {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "moderate" => Severity::Moderate,
        _ => Severity::Low,
    }
}

fn write_report(
    out: &mut impl Write,
    file: &str,
    packages: &BTreeSet<lockfile::Package>,
    findings: &[Finding],
) -> io::Result<()> {
    let affected: BTreeSet<(&str, &str)> = findings
        .iter()
        .map(|f| (f.name.as_str(), f.version.as_str()))
        .collect();
    if findings.is_empty() {
        return writeln!(
            out,
            "{file}: {} packages, no known advisories",
            packages.len()
        );
    }
    writeln!(
        out,
        "{file}: {} packages, {} {} in {} {}\n",
        packages.len(),
        findings.len(),
        plural(findings.len(), "advisory", "advisories"),
        affected.len(),
        plural(affected.len(), "package", "packages"),
    )?;
    let width = findings
        .iter()
        .map(|f| f.name.len() + f.version.len() + 1)
        .max()
        .unwrap_or(0);
    for f in findings {
        let pkg = format!("{}@{}", f.name, f.version);
        let fix = f.fixed.as_deref().map_or_else(
            || "no fixed version".to_string(),
            |v| format!("fixed in {v}"),
        );
        writeln!(
            out,
            "{:<9} {:<width$}  {:<20} {}  ({})",
            f.severity.label(),
            pkg,
            f.id,
            f.summary,
            fix,
        )?;
    }
    Ok(())
}

fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 {
        one
    } else {
        many
    }
}
