use super::{InitializeResult, Inventory};
use crate::types::{ToolDef, ToolsListResult};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tracing::{debug, warn};

/// Wire framing for MCP stdio.
///
/// - **Ndjson**: Python `mcp` SDK / FastMCP (`json + "\n"`)
/// - **ContentLength**: LSP-style headers (TypeScript SDK, some clients)
#[derive(Debug, Clone, Copy, Default)]
pub enum Framing {
    #[default]
    Ndjson,
    ContentLength,
}

#[derive(Debug, Clone)]
pub struct StdioTarget {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub timeout: Duration,
    pub framing: Framing,
}

struct McpChild {
    child: Child,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    timeout: Duration,
    framing: Framing,
}

impl McpChild {
    fn spawn(target: &StdioTarget) -> Result<Self> {
        let mut cmd = Command::new(&target.command);
        cmd.args(&target.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Never pipe stderr without a drain — FastMCP logs deadlock the child.
            .stderr(Stdio::null());
        if let Some(cwd) = &target.cwd {
            cmd.current_dir(cwd);
        }
        for (k, v) in &target.env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn MCP server: {} {:?}", target.command, target.args))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("child stdout missing"))?;
        Ok(Self {
            child,
            stdout: BufReader::new(stdout),
            next_id: 1,
            timeout: target.timeout,
            framing: target.framing,
        })
    }

    fn write_message(&mut self, body: &Value) -> Result<()> {
        let payload = serde_json::to_vec(body)?;
        let stdin = self
            .child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("child stdin closed"))?;
        match self.framing {
            Framing::Ndjson => {
                stdin.write_all(&payload)?;
                stdin.write_all(b"\n")?;
            }
            Framing::ContentLength => {
                let header = format!("Content-Length: {}\r\n\r\n", payload.len());
                stdin.write_all(header.as_bytes())?;
                stdin.write_all(&payload)?;
            }
        }
        stdin.flush()?;
        Ok(())
    }

    fn read_message_blocking(&mut self) -> Result<Value> {
        let buf = self.stdout.fill_buf().context("read MCP stdout")?;
        if buf.is_empty() {
            bail!("MCP server closed stdout before responding");
        }

        // Accept either framing on read (servers may differ from client write mode).
        if buf.starts_with(b"Content-Length:") || buf.starts_with(b"content-length:") {
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                let n = self.stdout.read_line(&mut line).context("read header line")?;
                if n == 0 {
                    bail!("EOF in MCP headers");
                }
                if line == "\r\n" || line == "\n" {
                    break;
                }
                headers.push(line);
                if headers.len() > 64 {
                    bail!("too many MCP header lines");
                }
            }
            let mut content_length: Option<usize> = None;
            for line in &headers {
                let lower = line.to_ascii_lowercase();
                if let Some(rest) = lower.strip_prefix("content-length:") {
                    content_length = Some(
                        rest.trim()
                            .trim_end_matches(['\r', '\n'])
                            .parse()
                            .context("parse Content-Length")?,
                    );
                }
            }
            let len =
                content_length.ok_or_else(|| anyhow!("missing Content-Length in MCP response"))?;
            if len > 16 * 1024 * 1024 {
                bail!("MCP body too large: {len}");
            }
            let mut body = vec![0u8; len];
            self.stdout
                .read_exact(&mut body)
                .context("read MCP body")?;
            return serde_json::from_slice(&body)
                .with_context(|| format!("parse MCP JSON: {}", String::from_utf8_lossy(&body)));
        }

        // NDJSON
        let mut line = String::new();
        self.stdout
            .read_line(&mut line)
            .context("read NDJSON line")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            bail!("empty NDJSON line from MCP server");
        }
        serde_json::from_str(trimmed).with_context(|| format!("parse NDJSON: {trimmed}"))
    }

    fn read_message(&mut self) -> Result<Value> {
        let timeout = self.timeout;
        let (tx, rx) = mpsc::channel::<()>();
        let pid_hint = self.child.id();
        let killer = thread::spawn(move || {
            if rx.recv_timeout(timeout).is_err() {
                warn!(pid = pid_hint, "MCP handshake timed out; killing child");
                #[cfg(windows)]
                {
                    let _ = Command::new("taskkill")
                        .args(["/PID", &pid_hint.to_string(), "/T", "/F"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                #[cfg(not(windows))]
                {
                    let _ = Command::new("kill")
                        .args(["-9", &pid_hint.to_string()])
                        .status();
                }
            }
        });

        let result = self.read_message_blocking();
        let _ = tx.send(());
        let _ = killer.join();
        result
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        debug!(%method, id, "mcp request");
        self.write_message(&req)?;

        for _ in 0..32 {
            let msg = self.read_message()?;
            if msg.get("method").is_some() && msg.get("id").is_none() {
                debug!(notification = ?msg.get("method"), "skip notification");
                continue;
            }
            if msg.get("id") == Some(&json!(id)) {
                if let Some(err) = msg.get("error") {
                    bail!("MCP error on {method}: {err}");
                }
                return msg
                    .get("result")
                    .cloned()
                    .ok_or_else(|| anyhow!("MCP response missing result for {method}"));
            }
            warn!(?msg, "unexpected MCP message while waiting for id={id}");
        }
        bail!("too many MCP messages without matching id for {method}")
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let note = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.write_message(&note)
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Connect over stdio, initialize, list all tools (with cursor pagination).
pub fn inventory_stdio(target: &StdioTarget) -> Result<Inventory> {
    let mut child = McpChild::spawn(target)?;

    let result = (|| {
        let init_params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": { "listChanged": false },
                "sampling": {}
            },
            "clientInfo": {
                "name": "mcpdoctor",
                "version": env!("CARGO_PKG_VERSION")
            }
        });
        let init_val = child.request("initialize", init_params)?;
        let initialize: InitializeResult =
            serde_json::from_value(init_val.clone()).context("decode initialize result")?;

        let _ = child.notify("notifications/initialized", json!({}));

        let mut tools: Vec<ToolDef> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut last_raw = json!({});
        loop {
            let params = match &cursor {
                Some(c) => json!({ "cursor": c }),
                None => json!({}),
            };
            let list_val = child.request("tools/list", params)?;
            last_raw = list_val.clone();
            let page: ToolsListResult =
                serde_json::from_value(list_val).context("decode tools/list")?;
            tools.extend(page.tools);
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
            if tools.len() > 10_000 {
                bail!("tools/list pagination exceeded 10000 tools");
            }
        }

        Ok(Inventory {
            initialize,
            tools,
            raw_tools_list: last_raw,
        })
    })();

    child.kill();
    result
}
