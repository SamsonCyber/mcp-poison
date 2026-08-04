use crate::normalize::canonical_json;
use crate::types::ToolDef;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn tool_hash(tool: &ToolDef) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), serde_json::Value::String(tool.name.clone()));
    if let Some(t) = &tool.title {
        obj.insert("title".into(), serde_json::Value::String(t.clone()));
    }
    if let Some(d) = &tool.description {
        obj.insert("description".into(), serde_json::Value::String(d.clone()));
    }
    if let Some(s) = &tool.input_schema {
        obj.insert("inputSchema".into(), s.clone());
    }
    if let Some(s) = &tool.output_schema {
        obj.insert("outputSchema".into(), s.clone());
    }
    for (k, v) in &tool.extra {
        // Skip noisy/non-semantic keys if any appear later.
        obj.insert(k.clone(), v.clone());
    }
    let canon = canonical_json(&serde_json::Value::Object(obj));
    sha256_hex(canon)
}

pub fn server_hash(tools: &[ToolDef]) -> String {
    let mut map = BTreeMap::new();
    for t in tools {
        map.insert(t.name.clone(), tool_hash(t));
    }
    let canon = canonical_json(&serde_json::to_value(&map).expect("btree map serializes"));
    sha256_hex(canon)
}

pub fn tool_pin_map(tools: &[ToolDef]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for t in tools {
        map.insert(t.name.clone(), tool_hash(t));
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_tool_hash() {
        let t = ToolDef {
            name: "add".into(),
            title: None,
            description: Some("Adds two numbers".into()),
            input_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "b": {"type": "integer"},
                    "a": {"type": "integer"}
                }
            })),
            output_schema: None,
            extra: BTreeMap::new(),
        };
        let h1 = tool_hash(&t);
        let h2 = tool_hash(&t);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }
}
