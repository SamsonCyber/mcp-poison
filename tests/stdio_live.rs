//! Live stdio path: spawn a tiny NDJSON mock MCP server, inventory + scan.

use mcpdoctor::scan::{scan_stdio, ScanOptions};
use std::path::PathBuf;
use std::time::Duration;

fn mock_server_script() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    dir.join("mock_mcp_server.py")
}

#[test]
fn stdio_ndjson_mock_detects_poison() {
    let script = mock_server_script();
    assert!(script.is_file(), "missing {}", script.display());

    let py = if cfg!(windows) {
        // Prefer py launcher then python
        which_python()
    } else {
        "python3".into()
    };

    let opts = ScanOptions {
        untrusted: true,
        timeout: Duration::from_secs(15),
        ..ScanOptions::default()
    };
    let report = scan_stdio(
        &py,
        &[script.to_string_lossy().into_owned()],
        &[],
        None,
        &opts,
    )
    .expect("stdio inventory");

    assert_eq!(report.summary.tools, 1);
    assert!(
        report.summary.findings > 0,
        "expected poison findings, got {:?}",
        report.findings
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.detector == "D01" || f.detector == "D02" || f.severity
                >= mcpdoctor::Severity::High),
        "findings: {:?}",
        report.findings.iter().map(|f| &f.detector).collect::<Vec<_>>()
    );
}

fn which_python() -> String {
    for cand in ["python", "py", "python3"] {
        if std::process::Command::new(cand)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return cand.into();
        }
    }
    "python".into()
}
