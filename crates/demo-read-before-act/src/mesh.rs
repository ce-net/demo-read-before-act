//! The local mesh: ce-net-local-dev-sim (`cenet_mock.py`), the offline mock of the ce-net MCP
//! server. `up` joins it as an agent, publishes the three cells with `app_publish`, finds them
//! again with `apps_search` and routes every page call through `mcp_use`, the way an agent reaches
//! a cell on the live network. Without the sim, calls go to the cells directly and the page says so.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{Value, json};

/// POST `body` as JSON to `http://<host:port><path>` and return the JSON answer. Plain HTTP/1.1
/// to a local address only: the sim and the cells run on 127.0.0.1.
pub fn post_json(url: &str, body: &Value, bearer: Option<&str>) -> Result<Value, String> {
    let rest = url.strip_prefix("http://").ok_or_else(|| format!("{url}: only local http:// urls"))?;
    let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let mut s = TcpStream::connect(hostport).map_err(|e| format!("{hostport}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let data = body.to_string();
    let auth = bearer.map(|k| format!("Authorization: Bearer {k}\r\n")).unwrap_or_default();
    write!(s, "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{auth}Connection: close\r\n\r\n{data}", data.len())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&out);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    if !head.starts_with("HTTP/1.") || !head.split_whitespace().nth(1).is_some_and(|c| c == "200") {
        return Err(format!("{url}: {}", head.lines().next().unwrap_or("")));
    }
    serde_json::from_str(body).map_err(|e| format!("{url}: {e}"))
}

/// One JSON-RPC `tools/call` and its `structuredContent`, or the tool's error text.
pub fn tool_call(url: &str, tool: &str, args: Value, bearer: Option<&str>) -> Result<Value, String> {
    let msg = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": tool, "arguments": args } });
    let out = post_json(url, &msg, bearer)?;
    result_of(&out["result"])
}

fn result_of(r: &Value) -> Result<Value, String> {
    if r["isError"] == json!(true) {
        return Err(r["content"][0]["text"].as_str().unwrap_or("tool error").to_string());
    }
    Ok(r["structuredContent"].clone())
}

/// A session on the sim.
#[derive(Clone)]
pub struct Sim {
    pub url: String,
    pub key: String,
}

impl Sim {
    /// Join the sim at `url` (e.g. `http://127.0.0.1:7878/mcp`) as an agent.
    pub fn join(url: &str, name: &str) -> Result<Sim, String> {
        let out = tool_call(url, "agent_join", json!({ "name": name, "about": "read before you act: msg.notice, act.approve, cal.explain" }), None)?;
        let key = out["key"].as_str().ok_or("agent_join gave no key")?.to_string();
        Ok(Sim { url: url.into(), key })
    }

    pub fn publish(&self, name: &str, url: &str, what: &str) -> Result<Value, String> {
        tool_call(&self.url, "app_publish", json!({ "name": name, "url": url, "what": what }), Some(&self.key))
    }

    /// The url the sim lists for app `name`.
    pub fn find(&self, name: &str) -> Result<String, String> {
        let out = tool_call(&self.url, "apps_search", json!({ "q": name }), None)?;
        out["apps"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["name"] == json!(name)))
            .and_then(|x| x["url"].as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("apps_search found no '{name}'"))
    }

    /// Call `tool` on the cell at `cell_url` through the sim's `mcp_use`.
    pub fn use_tool(&self, cell_url: &str, tool: &str, args: Value) -> Result<Value, String> {
        let out = tool_call(&self.url, "mcp_use", json!({ "url": cell_url, "tool": tool, "arguments": args }), Some(&self.key))?;
        result_of(&out["answer"])
    }
}
