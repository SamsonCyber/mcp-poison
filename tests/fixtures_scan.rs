use mcp_poison::scan::{scan_from_tools_list, ScanOptions};
use mcp_poison::types::Severity;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
}

#[test]
fn t3_line_jump_critical() {
    let report = scan_from_tools_list(
        &fixture("t3_line_jump.json"),
        &ScanOptions::default(),
        Some("t3"),
    )
    .expect("scan");
    assert!(report.summary.findings > 0);
    assert!(report
        .findings
        .iter()
        .any(|f| f.detector == "D03" || f.severity == Severity::Critical));
}

#[test]
fn clean_calculator_ok() {
    let report = scan_from_tools_list(
        &fixture("clean_calculator.json"),
        &ScanOptions {
            untrusted: false,
            ..ScanOptions::default()
        },
        Some("clean"),
    )
    .expect("scan");
    assert_eq!(
        report.summary.findings, 0,
        "unexpected: {:?}",
        report.findings
    );
}

#[test]
fn t6_param_names() {
    let report = scan_from_tools_list(
        &fixture("t6_param_names.json"),
        &ScanOptions::default(),
        Some("t6"),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| f.detector == "D08"));
}

#[test]
fn t1_description_poison() {
    let report = scan_from_tools_list(
        &fixture("t1_description_poison.json"),
        &ScanOptions::default(),
        Some("t1"),
    )
    .expect("scan");
    assert!(report.findings.iter().any(|f| {
        f.detector == "D01" || f.detector == "D02" || f.severity >= Severity::High
    }));
}

#[test]
fn t8_ansi() {
    let report = scan_from_tools_list(
        &fixture("t8_ansi.json"),
        &ScanOptions::default(),
        Some("t8"),
    )
    .expect("scan");
    assert!(
        report.findings.iter().any(|f| f.detector == "D06"),
        "expected ANSI detector, got {:?}",
        report
            .findings
            .iter()
            .map(|f| &f.detector)
            .collect::<Vec<_>>()
    );
}

#[test]
fn pin_then_rugpull() {
    use mcp_poison::pin::{diff_pins, make_pins};
    use mcp_poison::types::{ToolDef, ToolsListResult};

    let clean: ToolsListResult = serde_json::from_str(
        &std::fs::read_to_string(fixture("clean_calculator.json")).unwrap(),
    )
    .unwrap();
    let pins = make_pins("calc", &clean.tools, None, vec![], Some("calc".into()));

    let poisoned: ToolsListResult = serde_json::from_str(
        &std::fs::read_to_string(fixture("t1_description_poison.json")).unwrap(),
    )
    .unwrap();
    // Same tool name "add" with different description
    let findings = diff_pins(&poisoned.tools, &pins, None, &[]);
    assert!(
        findings.iter().any(|f| f.detector == "D20" || f.detector == "D21"),
        "expected rugpull finding: {findings:?}"
    );
    let _ = ToolDef {
        name: "x".into(),
        title: None,
        description: None,
        input_schema: None,
        output_schema: None,
        extra: Default::default(),
    };
}
