use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse_threshold(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofClass {
    Fixture,
    Local,
    Live,
}

impl fmt::Display for ProofClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fixture => write!(f, "fixture"),
            Self::Local => write!(f, "local"),
            Self::Live => write!(f, "live"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
    #[serde(rename = "outputSchema", default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
    /// Preserve unknown fields for hashing/evidence.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsListResult {
    pub tools: Vec<ToolDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub snippet: String,
    pub snippet_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub detector: String,
    pub technique: String,
    pub owasp: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub atlas: Vec<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub tool_name: String,
    pub json_path: String,
    pub title: String,
    pub detail: String,
    pub evidence: Evidence,
    pub remediation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    pub transport: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    pub proof_class: ProofClass,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub tools: usize,
    pub findings: usize,
    pub max_severity: Option<Severity>,
    pub server_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolPins {
    pub server_hash: String,
    pub tools: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PinStore {
    pub schema_version: String,
    pub servers: BTreeMap<String, ToolPins>,
}

impl PinStore {
    pub fn new() -> Self {
        Self {
            schema_version: "0.1.0".into(),
            servers: BTreeMap::new(),
        }
    }
}

/// One string leaf extracted from a tool schema for static analysis.
#[derive(Debug, Clone)]
pub struct StringLeaf {
    pub tool_name: String,
    pub json_path: String,
    pub value: String,
}
