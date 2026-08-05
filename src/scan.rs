use crate::client::{inventory_stdio, Framing, StdioTarget};
use crate::detectors::{detect_cross_server_shadow, scan_tools, StaticScanOptions};
use crate::hash::server_hash;
use crate::pin::{diff_pins, make_pins};
use crate::report::{proof_class_for_transport, ScanReport};
use crate::types::{
    Finding, ProofClass, TargetInfo, ToolDef, ToolPins, ToolsListResult,
};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Refuse multi-hundred-MB "tools lists" that are DoS, not inventories.
pub const MAX_LIST_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_TOOLS: usize = 5_000;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub untrusted: bool,
    pub timeout: Duration,
    pub framing: Framing,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            untrusted: true,
            timeout: Duration::from_secs(30),
            framing: Framing::Ndjson,
        }
    }
}

/// Offline scan from a tools/list JSON file or `{"tools":[...]}` document.
pub fn scan_from_tools_list(
    path: &Path,
    opts: &ScanOptions,
    label: Option<&str>,
) -> Result<ScanReport> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.len() > MAX_LIST_BYTES {
        bail!(
            "tools list {} is {} bytes (max {})",
            path.display(),
            meta.len(),
            MAX_LIST_BYTES
        );
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("read tools list {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text).context("parse tools list JSON")?;
    let tools = extract_tools(&value)?;
    if tools.len() > MAX_TOOLS {
        bail!("tools list has {} tools (max {})", tools.len(), MAX_TOOLS);
    }
    let static_opts = StaticScanOptions {
        untrusted: opts.untrusted,
    };
    let findings = scan_tools(&tools, &static_opts);
    let pins = make_pins(
        label.unwrap_or("offline"),
        &tools,
        None,
        vec![],
        label.map(|s| s.to_string()),
    );
    let target = TargetInfo {
        transport: "offline".into(),
        server_name: label.map(|s| s.to_string()),
        server_version: None,
        command: None,
        args: vec![],
        proof_class: ProofClass::Fixture,
    };
    Ok(ScanReport::new(target, findings, pins, tools))
}

/// Scan several inventories together (cross-server shadow detection).
pub fn scan_multi_lists(
    paths: &[(String, &Path)],
    opts: &ScanOptions,
) -> Result<ScanReport> {
    let mut inventories: Vec<(String, ToolsListResult)> = Vec::new();
    let mut all_tools: Vec<ToolDef> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let static_opts = StaticScanOptions {
        untrusted: opts.untrusted,
    };
    for (sid, path) in paths {
        let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if meta.len() > MAX_LIST_BYTES {
            bail!("tools list {} too large", path.display());
        }
        let text = fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&text)?;
        let tools = extract_tools(&value)?;
        findings.extend(scan_tools(&tools, &static_opts));
        inventories.push((
            sid.clone(),
            ToolsListResult {
                tools: tools.clone(),
                next_cursor: None,
            },
        ));
        all_tools.extend(tools);
    }
    let mut next_id = findings.len() + 1;
    detect_cross_server_shadow(&inventories, &mut findings, &mut next_id);
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = format!("F-{:03}", i + 1);
    }
    let pins = make_pins("multi", &all_tools, None, vec![], Some("multi".into()));
    let target = TargetInfo {
        transport: "offline-multi".into(),
        server_name: Some("multi".into()),
        server_version: None,
        command: None,
        args: vec![],
        proof_class: ProofClass::Fixture,
    };
    Ok(ScanReport::new(target, findings, pins, all_tools))
}

pub fn scan_tools_value(
    tools: &[ToolDef],
    target: TargetInfo,
    opts: &ScanOptions,
) -> ScanReport {
    let static_opts = StaticScanOptions {
        untrusted: opts.untrusted,
    };
    let findings = scan_tools(tools, &static_opts);
    let pins = make_pins(
        target.server_name.as_deref().unwrap_or("server"),
        tools,
        target.command.clone(),
        target.args.clone(),
        target.server_name.clone(),
    );
    ScanReport::new(target, findings, pins, tools.to_vec())
}

/// Live stdio inventory + static scan (non-mutating: no tools/call).
pub fn scan_stdio(
    command: &str,
    args: &[String],
    env: &[(String, String)],
    cwd: Option<&str>,
    opts: &ScanOptions,
) -> Result<ScanReport> {
    let target = StdioTarget {
        command: command.into(),
        args: args.to_vec(),
        env: env.to_vec(),
        cwd: cwd.map(|s| s.to_string()),
        timeout: opts.timeout,
        framing: opts.framing,
    };
    let inv = inventory_stdio(&target)?;
    let mut report = scan_tools_value(
        &inv.tools,
        TargetInfo {
            transport: "stdio".into(),
            server_name: Some(inv.initialize.server_info.name.clone()),
            server_version: Some(inv.initialize.server_info.version.clone()),
            command: Some(command.into()),
            args: args.to_vec(),
            proof_class: proof_class_for_transport(false, true),
        },
        opts,
    );
    // Ensure pins match live inventory
    report.pins = make_pins(
        &inv.initialize.server_info.name,
        &inv.tools,
        Some(command.into()),
        args.to_vec(),
        Some(inv.initialize.server_info.name.clone()),
    );
    report.tools = inv.tools;
    report.summary.server_hash = server_hash(&report.tools);
    report.summary.tools = report.tools.len();
    Ok(report)
}

pub fn check_against_pins(
    tools: &[ToolDef],
    pins: &ToolPins,
    command: Option<&str>,
    args: &[String],
    base: ScanReport,
) -> ScanReport {
    let mut findings = base.findings;
    findings.extend(diff_pins(tools, pins, command, args));
    for (i, f) in findings.iter_mut().enumerate() {
        f.id = format!("F-{:03}", i + 1);
    }
    let target = base.target;
    let new_pins = make_pins(
        target.server_name.as_deref().unwrap_or("server"),
        tools,
        target.command.clone(),
        target.args.clone(),
        target.server_name.clone(),
    );
    ScanReport::new(target, findings, new_pins, tools.to_vec())
}

fn extract_tools(value: &serde_json::Value) -> Result<Vec<ToolDef>> {
    if let Some(arr) = value.as_array() {
        let tools: Vec<ToolDef> = serde_json::from_value(serde_json::Value::Array(arr.clone()))
            .context("parse tools array")?;
        return Ok(tools);
    }
    if value.get("tools").is_some() {
        let list: ToolsListResult =
            serde_json::from_value(value.clone()).context("parse ToolsListResult")?;
        return Ok(list.tools);
    }
    if value.get("result").and_then(|r| r.get("tools")).is_some() {
        let list: ToolsListResult = serde_json::from_value(
            value
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
        .context("parse result.tools")?;
        return Ok(list.tools);
    }
    anyhow::bail!("JSON must be tools/list result, {{tools:[...]}}, or a bare tools array")
}
