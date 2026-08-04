mod stdio;

pub use stdio::{inventory_stdio, Framing, StdioTarget};

use crate::types::{ToolDef, ToolsListResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: Value,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone)]
pub struct Inventory {
    pub initialize: InitializeResult,
    pub tools: Vec<ToolDef>,
    pub raw_tools_list: Value,
}

impl Inventory {
    pub fn tools_list_result(&self) -> ToolsListResult {
        ToolsListResult {
            tools: self.tools.clone(),
            next_cursor: None,
        }
    }
}
