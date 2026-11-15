//! `act.approve`: a guarded action. It approves a change only when the caller presents a v3
//! capability chain that grants `change.approve:approve` at this node, the exact use request, and
//! proofs that meet every condition of every link (for this demo: a signed read receipt and the
//! holder's co-signature over the request).
//!
//! The verdict is ce-net-proto's: this cell calls `cal::api` `verify` (which runs
//! `authorize_use_v3`, CAPABILITY-PROGRAMS.md section 5.2) and adds only what a real node adds around
//! it: a replay log of request ids it has executed, and the record of what it approved.

use std::collections::HashSet;

use ce_net_proto::cal::api;
use ce_net_proto::v3::{UseRequest, request_id};
use serde::Serialize;
use serde_json::{Value, json};

/// The ability the action needs.
pub const ACTION: &str = "change.approve:approve";

/// One verdict, as the page and the transcript show it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Verdict {
    pub allowed: bool,
    /// The verifier's own refusal text (`None` when allowed).
    pub reason: Option<String>,
    /// Plain-English explanation, one sentence per entry.
    pub why: Vec<String>,
}

/// What a caller presents with one approve call. Every field is hex except `body`, the change
/// request's bytes as text.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Presented {
    pub token: String,
    pub request: String,
    pub proofs: String,
    pub body: String,
}

/// One approved change.
#[derive(Debug, Clone, Serialize)]
pub struct Approved {
    pub request_id: String,
    pub by: String,
    pub body: String,
    pub at: u64,
}

pub struct ApproveCell {
    /// This node, `node:<64 hex>`.
    node: String,
    /// The ref book (roots and names) the node verifies with: public keys only.
    refs: Value,
    seen: HashSet<[u8; 32]>,
    pub approved: Vec<Approved>,
}

/// Run ce-net-proto's verifier for one presented use, as `node` would at `now`. Pure: no replay
/// log. This is what anyone can run on their own machine with the same inputs.
pub fn verify(node: &str, refs: &Value, p: &Presented, now: u64) -> Result<Verdict, String> {
    let req_bytes = hex::decode(p.request.trim()).map_err(|_| "request is not hex".to_string())?;
    let ur: UseRequest = bincode::deserialize(&req_bytes).map_err(|e| format!("malformed use request: {e}"))?;
    let who = msg_key(&ur.requester);
    let call = json!({
        "token": p.token.trim(),
        "refs": refs,
        "node": node,
        "as": who,
        "do": ACTION,
        "now": now,
        "request": p.request.trim(),
        "proofs": p.proofs.trim(),
        "body": hex::encode(p.body.as_bytes()),
    });
    let out: Value = serde_json::from_str(&api::call("verify", &call.to_string())).map_err(|e| e.to_string())?;
    if out["ok"] != json!(true) {
        return Err(out["error"]["message"].as_str().unwrap_or("verify failed").to_string());
    }
    Ok(Verdict {
        allowed: out["allowed"].as_bool().unwrap_or(false),
        reason: out["reason"].as_str().map(str::to_string),
        why: out["why"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default(),
    })
}

fn msg_key(k: &ce_net_proto::v3::Key) -> String {
    match k {
        ce_net_proto::v3::Key::Ed25519(b) => format!("ed25519:{}", hex::encode(b)),
        ce_net_proto::v3::Key::P256(b) => format!("p256:{}", hex::encode(b)),
    }
}

impl ApproveCell {
    pub fn new(node_id: &[u8; 32], refs: Value) -> ApproveCell {
        ApproveCell { node: format!("node:{}", hex::encode(node_id)), refs, seen: HashSet::new(), approved: Vec::new() }
    }

    pub fn node(&self) -> &str {
        &self.node
    }

    /// The guarded action: verify, refuse a replayed request, then approve and record.
    pub fn approve(&mut self, p: &Presented, now: u64) -> Verdict {
        let v = match verify(&self.node, &self.refs, p, now) {
            Ok(v) => v,
            Err(e) => return Verdict { allowed: false, reason: Some(e.clone()), why: vec![format!("The call could not be read: {e}.")] },
        };
        if !v.allowed {
            return v;
        }
        let ur: UseRequest = bincode::deserialize(&hex::decode(p.request.trim()).unwrap_or_default()).expect("verified above");
        let id = request_id(&ur);
        if !self.seen.insert(id) {
            return Verdict {
                allowed: false,
                reason: Some("request replayed".into()),
                why: vec!["This exact request was already approved here; a node executes each request id once.".into()],
            };
        }
        self.approved.push(Approved { request_id: hex::encode(id), by: msg_key(&ur.requester), body: p.body.clone(), at: now });
        v
    }
}
