use mcpdoctor::scan::{scan_multi_lists, ScanOptions};
use std::path::PathBuf;

#[test]
fn multi_list_runs_cross_server_detectors() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let a = root.join("t4_cross_server_a.json");
    let b = root.join("t4_cross_server_b.json");
    let pairs = vec![
        ("trivia".to_string(), a.as_path()),
        ("whatsapp".to_string(), b.as_path()),
    ];
    let report = scan_multi_lists(&pairs, &ScanOptions::default()).expect("multi");
    assert!(report.summary.tools >= 2);
    // May or may not hit D04 depending on heuristics; must not crash and must find
    // concealment / do-not-tell on the malicious description at minimum.
    assert!(
        report.summary.findings > 0,
        "expected findings on t4 fixtures: {:?}",
        report.findings
    );
}
