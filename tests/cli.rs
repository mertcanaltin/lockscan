//! The binary end to end, against a stand-in for the OSV API served on a
//! local port, so the tests run offline and the answers are fixed.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

/// Serves the OSV endpoints lockscan calls until the test process ends.
/// lodash 4.17.20 is affected by one advisory, everything else by none.
fn fake_osv() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let answer = answer(&request_line, &body);
            let text = answer.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                text.len(),
                text
            )
            .unwrap();
        }
    });
    url
}

fn answer(request_line: &str, body: &[u8]) -> Value {
    if request_line.starts_with("POST /v1/querybatch") {
        let req: Value = serde_json::from_slice(body).unwrap();
        let results: Vec<Value> = req["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                if q["package"]["name"] == "lodash" && q["version"] == "4.17.20" {
                    json!({ "vulns": [{ "id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z" }] })
                } else {
                    json!({})
                }
            })
            .collect();
        return json!({ "results": results });
    }
    if request_line.starts_with("GET /v1/vulns/GHSA-35jh-r3h4-6jhm") {
        return json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "summary": "Command Injection in lodash",
            "aliases": ["CVE-2021-23337"],
            "database_specific": { "severity": "HIGH" },
            "affected": [{
                "package": { "ecosystem": "npm", "name": "lodash" },
                "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "4.17.21" }] }]
            }]
        });
    }
    json!({ "error": "unexpected request" })
}

/// Writes `text` as `name` in a directory of its own for `test`: the tests run
/// in parallel, and two of them writing the same path let one read the other's
/// half-written file.
fn fixture(test: &str, name: &str, text: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lockscan-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(name);
    std::fs::write(&file, text).unwrap();
    file
}

const NPM: &str = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app" },
    "node_modules/lodash": { "version": "4.17.20" },
    "node_modules/left-pad": { "version": "1.3.0" }
  }
}"#;

fn lockscan(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lockscan"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn reports_an_affected_package_and_exits_1() {
    let url = fake_osv();
    let file = fixture("affected", "package-lock.json", NPM);
    let out = lockscan(&[file.to_str().unwrap(), "--osv-url", &url]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("2 packages, 1 advisory in 1 package"),
        "{stdout}"
    );
    assert!(stdout.contains("HIGH"), "{stdout}");
    assert!(stdout.contains("lodash@4.17.20"), "{stdout}");
    assert!(stdout.contains("fixed in 4.17.21"), "{stdout}");
}

#[test]
fn writes_json() {
    let url = fake_osv();
    let file = fixture("json", "package-lock.json", NPM);
    let out = lockscan(&[file.to_str().unwrap(), "--osv-url", &url, "--json"]);
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["packages"], 2);
    assert_eq!(doc["findings"][0]["id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(doc["findings"][0]["severity"], "HIGH");
    assert_eq!(doc["findings"][0]["fixed"], "4.17.21");
    assert_eq!(doc["findings"][0]["aliases"][0], "CVE-2021-23337");
}

#[test]
fn ignores_by_alias_and_filters_by_severity() {
    let url = fake_osv();
    let file = fixture("ignore", "package-lock.json", NPM);
    let ignored = lockscan(&[
        file.to_str().unwrap(),
        "--osv-url",
        &url,
        "--ignore",
        "CVE-2021-23337",
    ]);
    assert_eq!(ignored.status.code(), Some(0));
    let critical_only = lockscan(&[
        file.to_str().unwrap(),
        "--osv-url",
        &url,
        "--min-severity",
        "critical",
    ]);
    assert_eq!(critical_only.status.code(), Some(0));
    let high = lockscan(&[
        file.to_str().unwrap(),
        "--osv-url",
        &url,
        "--min-severity",
        "high",
    ]);
    assert_eq!(high.status.code(), Some(1));
}

#[test]
fn finds_the_lockfile_in_a_directory_and_lists_packages() {
    let file = fixture(
        "listdir",
        "yarn.lock",
        "lodash@^4.17.0:\n  version \"4.17.20\"\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n",
    );
    let out = lockscan(&[file.parent().unwrap().to_str().unwrap(), "--list"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "left-pad@1.3.0\nlodash@4.17.20\n"
    );
}

#[test]
fn exits_2_when_it_cannot_scan() {
    let out = lockscan(&["/definitely/not/here"]);
    assert_eq!(out.status.code(), Some(2));
    let unreachable = fixture("unreachable", "package-lock.json", NPM);
    let out = lockscan(&[
        unreachable.to_str().unwrap(),
        "--osv-url",
        "http://127.0.0.1:1",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("OSV query failed"));
}
