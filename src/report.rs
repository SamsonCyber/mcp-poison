use crate::types::{Finding, ProofClass, ScanSummary, Severity, TargetInfo, ToolDef, ToolPins};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub scan_id: String,
    pub scanned_at: DateTime<Utc>,
    pub target: TargetInfo,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
    pub pins: ToolPins,
    /// Current inventory (used by pin/check). Omitted from compact exports if empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDef>,
}

impl ScanReport {
    pub fn new(
        target: TargetInfo,
        findings: Vec<Finding>,
        pins: ToolPins,
        tools: Vec<ToolDef>,
    ) -> Self {
        let max_severity = findings.iter().map(|f| f.severity).max();
        let tool_count = tools.len();
        let scan_id = format!(
            "{}_{}",
            Utc::now().format("%Y%m%dT%H%M%SZ"),
            &uuid::Uuid::new_v4().to_string()[..8]
        );
        Self {
            schema_version: "0.1.0".into(),
            scan_id,
            scanned_at: Utc::now(),
            target,
            summary: ScanSummary {
                tools: tool_count,
                findings: findings.len(),
                max_severity,
                server_hash: pins.server_hash.clone(),
            },
            findings,
            pins,
            tools,
        }
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.summary.max_severity
    }

    pub fn fails_threshold(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= threshold)
    }

    /// Short terminal-friendly summary (default human output).
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        let max = self
            .summary
            .max_severity
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into());
        let name = self
            .target
            .server_name
            .as_deref()
            .unwrap_or(self.target.transport.as_str());
        if self.findings.is_empty() {
            out.push_str(&format!(
                "CLEAN  {name}  tools={}  hash={}\n",
                self.summary.tools, self.summary.server_hash
            ));
            return out;
        }
        out.push_str(&format!(
            "FINDINGS  {name}  tools={}  findings={}  max={max}\n",
            self.summary.tools, self.summary.findings
        ));
        for f in &self.findings {
            out.push_str(&format!(
                "  {}  [{:8}]  {}  {}  {}\n",
                f.id, f.severity, f.detector, f.tool_name, f.title
            ));
            out.push_str(&format!("    path: {}\n", f.json_path));
        }
        out.push_str(&format!(
            "hash={}  (use --json or -o for full report)\n",
            self.summary.server_hash
        ));
        out
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# mcpdoctor scan report\n\n");
        md.push_str(&format!("- scan_id: `{}`\n", self.scan_id));
        md.push_str(&format!("- proof_class: {}\n", self.target.proof_class));
        md.push_str(&format!("- tools: {}\n", self.summary.tools));
        md.push_str(&format!("- findings: {}\n", self.summary.findings));
        md.push_str(&format!(
            "- max_severity: {}\n",
            self.summary
                .max_severity
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".into())
        ));
        md.push_str(&format!("- server_hash: `{}`\n\n", self.summary.server_hash));

        if self.findings.is_empty() {
            md.push_str("No findings.\n");
            return md;
        }

        md.push_str("| ID | Sev | Detector | Tool | Title |\n");
        md.push_str("|----|-----|----------|------|-------|\n");
        for f in &self.findings {
            md.push_str(&format!(
                "| {} | {} | {} | `{}` | {} |\n",
                f.id,
                f.severity,
                f.detector,
                f.tool_name,
                f.title.replace('|', "\\|")
            ));
        }
        md.push('\n');
        for f in &self.findings {
            md.push_str(&format!("## {}\n\n", f.id));
            md.push_str(&format!("**{}** ({})\n\n", f.title, f.severity));
            md.push_str(&format!("{}\n\n", f.detail));
            md.push_str(&format!("- technique: {}\n", f.technique));
            md.push_str(&format!("- path: `{}`\n", f.json_path));
            md.push_str(&format!(
                "- snippet: `{}`\n",
                f.evidence.snippet.replace('`', "'")
            ));
            md.push_str(&format!("- remediation: {}\n\n", f.remediation));
        }
        md
    }
}

pub fn proof_class_for_transport(from_list: bool, _has_command: bool) -> ProofClass {
    if from_list {
        ProofClass::Fixture
    } else {
        ProofClass::Local
    }
}
