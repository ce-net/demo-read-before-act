//! `up`: the three cells as MCP endpoints, Bob's client, and the page, on 127.0.0.1.
//!
//! - `POST /mcp/msg.notice`, `/mcp/act.approve`, `/mcp/cal.explain`: each cell's JSON-RPC
//!   (`initialize`, `tools/list`, `tools/call`). With the local mesh up they are published to it and
//!   every call below goes through its `mcp_use`.
//! - `GET /`: the page. `GET /api/state`, `POST /api/approve` (Bob presses approve),
//!   `POST /api/open` (Bob opens the notice), `POST /api/verify` (anyone pastes evidence),
//!   `POST /api/reset`.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use act_approve::{ApproveCell, Presented};
use msg_notice::{Notice, NoticeCell, Receipt};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Response, Server};

use crate::mesh::Sim;
use crate::{CHANGE_BODY, Client, KEY_DAYS, NOTICE_BODY, NOTICE_ID, NOTICE_TITLE, cal_source, desk_node, ed_bytes, explain_text, key, mint, refs, seed};

pub const PAGE: &str = include_str!("../../../index.html");
/// The recorded run, for the page's "load recorded call" buttons.
pub const TRANSCRIPT: &str = include_str!("../../../proof/transcript.json");

pub const CELLS: [(&str, &str); 3] = [
    ("msg.notice", "stores notices; opening one makes the reader's device sign a read receipt for its exact text"),
    ("act.approve", "a guarded approve: checks the CAL chain, the use request, the read receipt and the co-signature"),
    ("cal.explain", "returns the CAL clause that decided a verdict; verifies pasted evidence offline"),
];

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

struct State {
    notices: NoticeCell,
    desk: ApproveCell,
    notice: Notice,
    token: String,
    source: String,
    receipt: Option<Receipt>,
    nonce: u64,
    log: Vec<Value>,
}

impl State {
    fn new() -> Result<State, String> {
        let mut notices = NoticeCell::new(&seed("bob-phone"), key("bob"));
        let notice = notices.post(NOTICE_ID, "person:alice", NOTICE_TITLE, NOTICE_BODY);
        let t = now();
        let source = cal_source(&notice.sha256, t + KEY_DAYS * 86_400);
        let token = mint(&source, t)?;
        Ok(State { notices, desk: ApproveCell::new(&ed_bytes(&key("change-desk")), refs()), notice, token, source, receipt: None, nonce: 0, log: Vec::new() })
    }
}

pub struct App {
    state: Mutex<State>,
    sim: Option<Sim>,
    cell_urls: BTreeMap<String, String>,
}

fn tools(cell: &str) -> Value {
    let obj = |props: Value, req: Value| json!({ "type": "object", "properties": props, "required": req });
    let s = json!({ "type": "string" });
    match cell {
        "msg.notice" => json!([
            { "name": "list", "description": "The notices addressed to this reader.", "inputSchema": obj(json!({}), json!([])) },
            { "name": "open", "description": "Open a notice: returns its text and the read receipt the device signs.", "inputSchema": obj(json!({ "id": s }), json!(["id"])) },
        ]),
        "act.approve" => json!([
            { "name": "approve", "description": "Approve a change: token, request, proofs (hex) and body.", "inputSchema": obj(json!({ "token": s, "request": s, "proofs": s, "body": s }), json!(["token", "request", "proofs", "body"])) },
        ]),
        _ => json!([
            { "name": "explain", "description": "The CAL clause that decided a verdict.", "inputSchema": obj(json!({ "token": s, "reason": s }), json!(["token"])) },
            { "name": "verify", "description": "Verify pasted evidence {token, request, proofs, body, node, refs, now} and explain the verdict.", "inputSchema": obj(json!({ "evidence": { "type": "object" } }), json!(["evidence"])) },
        ]),
    }
}

impl App {
    /// The cell side: one tool call, run here.
    fn cell(&self, cell: &str, tool: &str, a: &Value) -> Result<Value, String> {
        let s = |k: &str| a[k].as_str().map(str::to_string).ok_or_else(|| format!("missing '{k}'"));
        match (cell, tool) {
            ("msg.notice", "list") => {
                let st = self.state.lock().unwrap();
                Ok(json!({ "notices": st.notices.list() }))
            }
            ("msg.notice", "open") => {
                let mut st = self.state.lock().unwrap();
                let (n, r) = st.notices.open(&s("id")?, now())?;
                st.receipt = Some(r.clone());
                Ok(json!({ "notice": n, "receipt": r.summary() }))
            }
            ("act.approve", "approve") => {
                let p = Presented { token: s("token")?, request: s("request")?, proofs: s("proofs")?, body: s("body")? };
                let mut st = self.state.lock().unwrap();
                let v = st.desk.approve(&p, now());
                Ok(json!({ "verdict": v, "approved": st.desk.approved.len() }))
            }
            ("cal.explain", "explain") => {
                let ex = cal_explain::explain(&s("token")?, &refs(), a["reason"].as_str())?;
                Ok(serde_json::to_value(ex).unwrap())
            }
            ("cal.explain", "verify") => {
                let e = &a["evidence"];
                let g = |k: &str| e[k].as_str().map(str::to_string).ok_or_else(|| format!("evidence is missing '{k}'"));
                let p = Presented { token: g("token")?, request: g("request")?, proofs: g("proofs")?, body: g("body")? };
                let r = if e["refs"].is_object() { e["refs"].clone() } else { refs() };
                let node = e["node"].as_str().map(str::to_string).unwrap_or_else(desk_node);
                let at = e["now"].as_u64().ok_or("evidence is missing 'now' (unix seconds of the use)")?;
                let v = act_approve::verify(&node, &r, &p, at)?;
                let ex = cal_explain::explain(&p.token, &r, v.reason.as_deref())?;
                Ok(json!({ "verdict": v, "clauses": ex.clauses, "source": ex.source, "checked_at": at }))
            }
            _ => Err(format!("{cell} has no tool '{tool}'")),
        }
    }

    /// The caller side: reach a cell through the mesh when it is up, else directly.
    fn route(&self, cell: &str, tool: &str, args: Value) -> Result<Value, String> {
        match (&self.sim, self.cell_urls.get(cell)) {
            (Some(sim), Some(url)) => sim.use_tool(url, tool, args),
            _ => self.cell(cell, tool, &args),
        }
    }

    fn route_name(&self) -> String {
        match &self.sim {
            Some(s) => format!("local mesh: ce-net-local-dev-sim at {} (apps_search + mcp_use)", s.url),
            None => "direct (no local mesh found; start ce-net-local-dev-sim to route through it)".into(),
        }
    }

    fn state_json(&self) -> Value {
        let st = self.state.lock().unwrap();
        json!({
            "notice": { "id": st.notice.id, "from": st.notice.from, "title": st.notice.title, "sha256": st.notice.sha256, "opened": st.notice_opened(),
                "body": st.notice_opened().map(|_| st.notice.body.clone()) },
            "cal": st.source,
            "token": st.token,
            "explain": explain_text(&st.token).unwrap_or_default(),
            "receipt": st.receipt.as_ref().map(|r| r.summary()),
            "route": self.route_name(),
            "cells": self.cell_urls,
            "log": st.log,
            "change": CHANGE_BODY,
        })
    }

    fn approve(&self) -> Result<Value, String> {
        let (token, receipt, nonce) = {
            let mut st = self.state.lock().unwrap();
            st.nonce += 1;
            (st.token.clone(), st.receipt.clone(), st.nonce)
        };
        let bob = Client::new("bob");
        let at = now();
        let req = bob.request(&token, &key("change-desk"), CHANGE_BODY, at, nonce)?;
        let p = bob.present(&token, &req, receipt.as_ref(), CHANGE_BODY);
        let out = self.route("act.approve", "approve", serde_json::to_value(&p).unwrap())?;
        let v = &out["verdict"];
        let ex = self.route("cal.explain", "explain", json!({ "token": token, "reason": v["reason"] }))?;
        let evidence = json!({ "token": p.token, "request": p.request, "proofs": p.proofs, "body": p.body, "node": desk_node(), "refs": refs(), "now": at });
        let entry = json!({ "call": "act.approve.approve", "at": at, "with_receipt": receipt.is_some(), "allowed": v["allowed"], "reason": v["reason"], "clauses": ex["clauses"] });
        self.state.lock().unwrap().log.push(entry);
        Ok(json!({ "verdict": v, "clauses": ex["clauses"], "evidence": evidence, "route": self.route_name() }))
    }

    fn open(&self) -> Result<Value, String> {
        let out = self.route("msg.notice", "open", json!({ "id": NOTICE_ID }))?;
        let mut st = self.state.lock().unwrap();
        st.log.push(json!({ "call": "msg.notice.open", "at": out["receipt"]["at"], "receipt": out["receipt"]["receipt_hex"] }));
        Ok(out)
    }

    fn verify(&self, evidence: Value) -> Result<Value, String> {
        self.route("cal.explain", "verify", json!({ "evidence": evidence }))
    }

    fn reset(&self) -> Result<Value, String> {
        *self.state.lock().unwrap() = State::new()?;
        Ok(json!({ "reset": true }))
    }
}

impl State {
    fn notice_opened(&self) -> Option<u64> {
        self.notices.get(NOTICE_ID).and_then(|n| n.opened_at)
    }
}

fn rpc(app: &App, cell: &str, msg: &Value) -> Value {
    let id = msg["id"].clone();
    let res = match msg["method"].as_str().unwrap_or("") {
        "initialize" => json!({ "protocolVersion": "2025-06-18", "capabilities": { "tools": {} }, "serverInfo": { "name": cell, "version": env!("CARGO_PKG_VERSION") } }),
        "tools/list" => json!({ "tools": tools(cell) }),
        "tools/call" => match app.cell(cell, msg["params"]["name"].as_str().unwrap_or(""), &msg["params"]["arguments"]) {
            Ok(out) => json!({ "content": [{ "type": "text", "text": out.to_string() }], "structuredContent": out }),
            Err(e) => json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
        },
        "ping" => json!({}),
        m => return json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": format!("no method {m}") } }),
    };
    json!({ "jsonrpc": "2.0", "id": id, "result": res })
}

fn json_response(v: &Value, code: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(v.to_string().into_bytes())
        .with_status_code(code)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
}

fn handle(app: &App, mut rq: tiny_http::Request) {
    let url = rq.url().split('?').next().unwrap_or("/").to_string();
    let mut body = String::new();
    let _ = rq.as_reader().take(1 << 20).read_to_string(&mut body);
    let arg: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let answer = |r: Result<Value, String>| match r {
        Ok(v) => json_response(&v, 200),
        Err(e) => json_response(&json!({ "error": e }), 400),
    };
    let resp = match (rq.method(), url.as_str()) {
        (Method::Get, "/") | (Method::Get, "/index.html") => {
            Response::from_data(PAGE.as_bytes().to_vec()).with_header(Header::from_bytes("Content-Type", "text/html; charset=utf-8").unwrap())
        }
        (Method::Get, "/proof/transcript.json") => {
            Response::from_data(TRANSCRIPT.as_bytes().to_vec()).with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        }
        (Method::Get, "/api/state") => json_response(&app.state_json(), 200),
        (Method::Post, "/api/approve") => answer(app.approve()),
        (Method::Post, "/api/open") => answer(app.open()),
        (Method::Post, "/api/verify") => answer(app.verify(arg.get("evidence").cloned().unwrap_or(arg))),
        (Method::Post, "/api/reset") => answer(app.reset()),
        (Method::Post, p) if p.starts_with("/mcp/") => {
            let cell = &p["/mcp/".len()..];
            if CELLS.iter().any(|(c, _)| *c == cell) { json_response(&rpc(app, cell, &arg), 200) } else { json_response(&json!({ "error": "no such cell" }), 404) }
        }
        _ => json_response(&json!({ "error": "not found" }), 404),
    };
    let _ = rq.respond(resp);
}

/// Start the server on `port` and, if `sim_url` answers, publish the cells to it.
pub fn up(port: u16, sim_url: &str) -> Result<(), String> {
    let server = Arc::new(Server::http(("127.0.0.1", port)).map_err(|e| format!("127.0.0.1:{port}: {e}"))?);
    let base = format!("http://127.0.0.1:{port}");
    let state = State::new()?;
    let sim = match Sim::join(sim_url, "demo-read-before-act") {
        Ok(sim) => {
            for (c, what) in CELLS {
                sim.publish(c, &format!("{base}/mcp/{c}"), what)?;
            }
            Some(sim)
        }
        Err(e) => {
            eprintln!("no local mesh at {sim_url} ({e}); the cells are called directly");
            None
        }
    };
    let mut cell_urls = BTreeMap::new();
    if let Some(s) = &sim {
        for (c, _) in CELLS {
            cell_urls.insert(c.to_string(), s.find(c)?);
        }
    }
    let app = Arc::new(App { state: Mutex::new(state), sim, cell_urls });
    println!("demo-read-before-act is up: open {base}/");
    println!("  route: {}", app.route_name());
    for (c, u) in &app.cell_urls {
        println!("  {c} -> {u}");
    }
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let (server, app) = (server.clone(), app.clone());
            std::thread::spawn(move || {
                while let Ok(rq) = server.recv() {
                    handle(&app, rq);
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}
