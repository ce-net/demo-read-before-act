//! Read it before you can act.
//!
//! Alice sends Bob a change notice and gives him a key to approve the change. The key carries one
//! CAL clause: `require read notice:thread/<id>@<sha256 of the text> by node:bob-phone within 1d`.
//! Bob's approve is refused until his device signs a read receipt for that exact notice; then the
//! same call goes through, and anyone holding the chain, the request and the proofs gets the same
//! verdict on their own machine.
//!
//! This crate holds the story's parties (fixed demo keys), the chain, Bob's client, the scripted
//! run that writes the transcript and the golden vectors, and the local server (`up`).

pub mod mesh;
pub mod server;

use act_approve::{ApproveCell, Presented, Verdict};
use ce_net_proto::cal::api;
use ce_net_proto::v3::sign::Signer;
use ce_net_proto::v3::{CapabilityV3, Key, Link, Proof, TokenV3, UseRequest, cap_id, cosign_bytes, encode_proofs};
use msg_notice::{NoticeCell, Receipt, key_text, sign_receipt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub use act_approve::ACTION;

/// The notice of the story.
pub const NOTICE_ID: &str = "chg-42";
pub const NOTICE_TITLE: &str = "CHG-42: the billing database moves to the new cluster";
pub const NOTICE_BODY: &str = "Saturday 02:00 to 02:30 UTC. Writes pause for up to 20 minutes; reads stay up. \
Rollback: point billing-db back at the old primary, which stays warm until Monday. \
Approve only if your team can keep invoices queued during the pause.";
/// The change request Bob approves (the use request's body is its SHA-256).
pub const CHANGE_BODY: &str = "approve CHG-42: move billing-db to cluster b, Saturday 02:00 UTC";

/// The scripted run's clock (unix seconds): 2027-01-15 08:00 UTC.
pub const T0: u64 = 1_800_000_000;
/// The key is valid for 30 days.
pub const KEY_DAYS: u64 = 30;

/// A fixed demo key: Ed25519 secret = SHA-256("demo-read-before-act/<name>"). These keys sign
/// demo chains only; they are public on purpose so every run and every vector is reproducible.
pub fn seed(name: &str) -> [u8; 32] {
    Sha256::digest(format!("demo-read-before-act/{name}").as_bytes()).into()
}

pub fn signer(name: &str) -> Signer {
    Signer::ed25519(&seed(name))
}

pub fn key(name: &str) -> Key {
    signer(name).key()
}

pub fn ed_bytes(k: &Key) -> [u8; 32] {
    match k {
        Key::Ed25519(b) => *b,
        Key::P256(_) => unreachable!("demo keys are Ed25519"),
    }
}

/// The ref book every party uses: names to public keys, and the root the desk accepts (Alice).
pub fn refs() -> Value {
    json!({
        "principals": {
            "person:alice": [key_text(&key("alice"))],
            "person:bob": [key_text(&key("bob"))],
            "person:carol": [key_text(&key("carol"))],
        },
        "nodes": {
            "change-desk": [hex::encode(ed_bytes(&key("change-desk")))],
            "bob-phone": [hex::encode(ed_bytes(&key("bob-phone")))],
        },
        "roots": ["person:alice"],
    })
}

/// The approve key Alice gives Bob, as CAL.
pub fn cal_source(notice_sha: &str, until: u64) -> String {
    format!(
        "# Alice lets Bob approve change CHG-42 at the change desk, only after his phone has signed a\n\
         # read receipt for the exact notice text, at most a day before; every use co-signed by Bob.\n\
         cal 1\n\
         \n\
         person:alice grants person:bob {{\n  \
           can {ACTION}\n  \
           on node:change-desk\n  \
           until @{until}\n  \
           require read {src}:thread/{NOTICE_ID}@{notice_sha} by node:bob-phone within 1d\n  \
           cosign person:bob\n  \
           nonce 4242\n\
         }}\n",
        src = msg_notice::SOURCE,
    )
}

fn api_call(op: &str, req: Value) -> Result<Value, String> {
    let out: Value = serde_json::from_str(&api::call(op, &req.to_string())).map_err(|e| e.to_string())?;
    if out["ok"] != json!(true) {
        return Err(format!("{op}: {}", out["error"]));
    }
    Ok(out)
}

/// Compile the CAL source and sign it with Alice's key: the token.
pub fn mint(source: &str, now: u64) -> Result<String, String> {
    let draft = api_call("compile", json!({ "source": source, "refs": refs(), "now": now }))?["draft"].clone();
    let signed = api_call("sign", json!({ "draft": draft, "key": format!("ed25519:{}", hex::encode(seed("alice"))) }))?;
    signed["token"].as_str().map(str::to_string).ok_or_else(|| "the chain is not fully signed".to_string())
}

/// `ce-cal explain` of a token.
pub fn explain_text(token: &str) -> Result<String, String> {
    Ok(api_call("explain", json!({ "token": token, "refs": refs() }))?["text"].as_str().unwrap_or_default().to_string())
}

pub fn leaf_of(token: &str) -> Result<([u8; 32], CapabilityV3), String> {
    let t = TokenV3::from_hex(token).map_err(|e| e.0)?;
    match t.links.last() {
        Some(Link::V3 { cap, .. }) => Ok((cap_id(cap), cap.clone())),
        _ => Err("not a v3 chain".into()),
    }
}

/// Bob's client: builds the exact use request for one approve and co-signs it with his key.
pub struct Client {
    pub who: Signer,
}

impl Client {
    pub fn new(name: &str) -> Client {
        Client { who: signer(name) }
    }

    pub fn request(&self, token: &str, node: &Key, body: &str, at: u64, nonce: u64) -> Result<UseRequest, String> {
        let (leaf, _) = leaf_of(token)?;
        Ok(UseRequest {
            leaf,
            node: ed_bytes(node),
            requester: self.who.key(),
            action: ACTION.into(),
            body: Sha256::digest(body.as_bytes()).into(),
            at,
            nonce,
        })
    }

    pub fn cosign(&self, r: &UseRequest) -> Proof {
        Proof::CoSigned { by: self.who.key(), sig: self.who.sign_bytes(&cosign_bytes(r)) }
    }

    /// Everything one approve call carries: the token, the request, the proofs (the receipt, when
    /// Bob has one, and his co-signature) and the body.
    pub fn present(&self, token: &str, r: &UseRequest, receipt: Option<&Receipt>, body: &str) -> Presented {
        let mut proofs: Vec<Proof> = receipt.map(|x| vec![x.proof()]).unwrap_or_default();
        proofs.push(self.cosign(r));
        Presented {
            token: token.into(),
            request: hex::encode(bincode::serialize(r).expect("bincode of a use request")),
            proofs: hex::encode(encode_proofs(&proofs)),
            body: body.into(),
        }
    }
}

/// The desk's node reference as the verifier takes it.
pub fn desk_node() -> String {
    format!("node:{}", hex::encode(ed_bytes(&key("change-desk"))))
}

/// Verdict plus the clause that decided it.
pub fn judged(token: &str, v: &Verdict) -> Value {
    let ex = cal_explain::explain(token, &refs(), v.reason.as_deref());
    let (clauses, err) = match ex {
        Ok(e) => (serde_json::to_value(e.clauses).unwrap_or_default(), Value::Null),
        Err(e) => (json!([]), json!(e)),
    };
    json!({ "allowed": v.allowed, "reason": v.reason, "why": v.why, "clauses": clauses, "explain_error": err })
}

/// The scripted story at fixed times: the transcript (three calls plus the third person's check).
pub fn story() -> Result<Value, String> {
    let mut notices = NoticeCell::new(&seed("bob-phone"), key("bob"));
    let notice = notices.post(NOTICE_ID, "person:alice", NOTICE_TITLE, NOTICE_BODY);
    let source = cal_source(&notice.sha256, T0 + KEY_DAYS * 86_400);
    let token = mint(&source, T0)?;
    let mut desk = ApproveCell::new(&ed_bytes(&key("change-desk")), refs());
    let bob = Client::new("bob");
    let req = bob.request(&token, &key("change-desk"), CHANGE_BODY, T0 + 10, 1)?;

    // Call 1: approve without a receipt.
    let p1 = bob.present(&token, &req, None, CHANGE_BODY);
    let v1 = desk.approve(&p1, T0 + 10);
    // Call 2: Bob opens the notice; his phone signs the receipt.
    let (_, receipt) = notices.open(NOTICE_ID, T0 + 40)?;
    // Call 3: the same request, now with the receipt.
    let p3 = bob.present(&token, &req, Some(&receipt), CHANGE_BODY);
    let v3 = desk.approve(&p3, T0 + 70);
    // The third person: a fresh verifier, nothing but the pasted evidence.
    let v4 = act_approve::verify(&desk_node(), &refs(), &p3, T0 + 70)?;

    Ok(json!({
        "demo": "demo-read-before-act",
        "about": "Recorded by `cargo run -p demo-read-before-act -- record` at fixed times with the fixed demo keys; `cargo test` checks it byte for byte.",
        "notice": { "id": notice.id, "title": notice.title, "body": notice.body, "sha256": notice.sha256 },
        "cal": source,
        "token": token,
        "calls": [
            { "n": 1, "cell": "act.approve", "tool": "approve", "at": T0 + 10, "by": "person:bob", "presented": p1, "verdict": judged(&token, &v1) },
            { "n": 2, "cell": "msg.notice", "tool": "open", "at": T0 + 40, "by": "person:bob", "receipt": receipt.summary() },
            { "n": 3, "cell": "act.approve", "tool": "approve", "at": T0 + 70, "by": "person:bob", "presented": p3, "verdict": judged(&token, &v3) },
        ],
        "third_person": { "cell": "cal.explain", "tool": "verify", "at": T0 + 70, "verdict": judged(&token, &v4) },
    }))
}

/// The human-readable transcript.
pub fn transcript_text(t: &Value) -> String {
    let mut s = String::new();
    s.push_str("demo-read-before-act: recorded transcript (fixed demo keys, fixed clock)\n\n");
    s.push_str(&format!("Notice {}: {}\n  sha256 {}\n\n", t["notice"]["id"].as_str().unwrap_or(""), t["notice"]["title"].as_str().unwrap_or(""), t["notice"]["sha256"].as_str().unwrap_or("")));
    s.push_str("The key Alice gives Bob (CAL):\n");
    for l in t["cal"].as_str().unwrap_or("").lines() {
        s.push_str(&format!("  {l}\n"));
    }
    s.push('\n');
    for c in t["calls"].as_array().into_iter().flatten() {
        s.push_str(&format!("call {} at {}: {}.{} by {}\n", c["n"], c["at"], c["cell"].as_str().unwrap_or(""), c["tool"].as_str().unwrap_or(""), c["by"].as_str().unwrap_or("")));
        if let Some(r) = c.get("receipt") {
            s.push_str(&format!("  RECEIPT SIGNED by {} about {}\n  read notice {} through {} at {}\n", r["witness"].as_str().unwrap_or(""), r["subject"].as_str().unwrap_or(""), r["notice"].as_str().unwrap_or(""), r["read_through"].as_str().unwrap_or(""), r["at"]));
        }
        if let Some(v) = c.get("verdict") {
            verdict_text(v, &mut s);
        }
        s.push('\n');
    }
    s.push_str("third person, a fresh verifier with only the pasted chain, request and proofs:\n");
    verdict_text(&t["third_person"]["verdict"], &mut s);
    s
}

fn verdict_text(v: &Value, s: &mut String) {
    if v["allowed"] == json!(true) {
        s.push_str("  ACCEPTED\n");
    } else {
        s.push_str(&format!("  REFUSED: {}\n", v["reason"].as_str().unwrap_or("")));
    }
    for c in v["clauses"].as_array().into_iter().flatten() {
        s.push_str(&format!("  clause (link {}, line {}): {}\n", c["link"], c["line"], c["text"].as_str().unwrap_or("")));
    }
    for w in v["why"].as_array().into_iter().flatten() {
        s.push_str(&format!("  why: {}\n", w.as_str().unwrap_or("")));
    }
}

/// One golden vector case.
fn case(name: &str, what: &str, token: &str, p: &Presented, requester: &Key, now: u64) -> Result<Value, String> {
    let v = act_approve::verify(&desk_node(), &refs(), p, now)?;
    let clauses = cal_explain::explain(token, &refs(), v.reason.as_deref()).map(|e| e.clauses).unwrap_or_default();
    Ok(json!({
        "name": name,
        "what": what,
        "token": p.token,
        "requester": key_text(requester),
        "action": ACTION,
        "request": p.request,
        "proofs": p.proofs,
        "body_sha256": hex::encode(Sha256::digest(p.body.as_bytes())),
        "now": now,
        "expect": { "allowed": v.allowed, "reason": v.reason, "clause": clauses.first().map(|c| c.text.clone()) },
    }))
}

/// The golden vectors: the chain, the receipt and the expected verdicts, for any verifier.
pub fn vectors() -> Result<Value, String> {
    let mut notices = NoticeCell::new(&seed("bob-phone"), key("bob"));
    let notice = notices.post(NOTICE_ID, "person:alice", NOTICE_TITLE, NOTICE_BODY);
    let until = T0 + KEY_DAYS * 86_400;
    let source = cal_source(&notice.sha256, until);
    let token = mint(&source, T0)?;
    let desk = key("change-desk");
    let bob = Client::new("bob");
    let carol = Client::new("carol");
    let (_, receipt) = notices.open(NOTICE_ID, T0 + 40)?;
    let req = bob.request(&token, &desk, CHANGE_BODY, T0 + 10, 1)?;
    let at = |t: u64| bob.request(&token, &desk, CHANGE_BODY, t, 1);
    let mut cases = Vec::new();

    cases.push(case("refused-without-receipt", "Bob approves before opening the notice", &token, &bob.present(&token, &req, None, CHANGE_BODY), &bob.who.key(), T0 + 10)?);
    cases.push(case("accepted-with-receipt", "the same request with his phone's receipt", &token, &bob.present(&token, &req, Some(&receipt), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    let edited = msg_notice::Notice::hash_of(NOTICE_TITLE, "Saturday, writes pause for an hour.");
    let r_edit = sign_receipt(&signer("bob-phone"), key("bob"), NOTICE_ID, &edited, T0 + 40);
    cases.push(case("receipt-for-other-text", "a receipt for a different text of the notice", &token, &bob.present(&token, &req, Some(&r_edit), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    let r_other = sign_receipt(&signer("bob-phone"), key("bob"), "chg-41", &notice.sha256, T0 + 40);
    cases.push(case("receipt-for-other-notice", "a receipt for another notice id", &token, &bob.present(&token, &req, Some(&r_other), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    let r_self = sign_receipt(&signer("bob"), key("bob"), NOTICE_ID, &notice.sha256, T0 + 40);
    cases.push(case("receipt-not-by-device", "the receipt is signed by Bob's own key, not his phone", &token, &bob.present(&token, &req, Some(&r_self), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    let r_carol = sign_receipt(&signer("bob-phone"), key("carol"), NOTICE_ID, &notice.sha256, T0 + 40);
    cases.push(case("receipt-about-someone-else", "the phone says Carol read it, not Bob", &token, &bob.present(&token, &req, Some(&r_carol), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    let late = T0 + 40 + 86_400 + 60;
    cases.push(case("receipt-too-old", "the receipt is more than a day old at use", &token, &bob.present(&token, &at(late)?, Some(&receipt), CHANGE_BODY), &bob.who.key(), late)?);

    let r_future = sign_receipt(&signer("bob-phone"), key("bob"), NOTICE_ID, &notice.sha256, T0 + 500);
    cases.push(case("receipt-from-the-future", "the receipt is dated after the use", &token, &bob.present(&token, &req, Some(&r_future), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    // No co-signature: the receipt alone.
    let p_nocos = Presented {
        token: token.clone(),
        request: hex::encode(bincode::serialize(&req).unwrap()),
        proofs: hex::encode(encode_proofs(&[receipt.proof()])),
        body: CHANGE_BODY.into(),
    };
    cases.push(case("no-cosign", "the receipt without Bob's co-signature", &token, &p_nocos, &bob.who.key(), T0 + 70)?);

    let creq = carol.request(&token, &desk, CHANGE_BODY, T0 + 10, 1)?;
    cases.push(case("carol-presents-bobs-key", "Carol presents Bob's chain and receipt as herself", &token, &carol.present(&token, &creq, Some(&receipt), CHANGE_BODY), &carol.who.key(), T0 + 70)?);

    let p_body = bob.present(&token, &req, Some(&receipt), "approve CHG-43: drop the billing database");
    cases.push(case("other-change-body", "the request was signed for CHG-42, the body is another change", &token, &p_body, &bob.who.key(), T0 + 70)?);

    let expired = until + 10;
    cases.push(case("key-expired", "the key is used after its 30 days", &token, &bob.present(&token, &at(expired)?, Some(&sign_receipt(&signer("bob-phone"), key("bob"), NOTICE_ID, &notice.sha256, expired - 30)), CHANGE_BODY), &bob.who.key(), expired)?);

    // The token ends with the root's signature and then an empty program list (16 hex digits):
    // flip the signature's last byte.
    let mut tampered = token.clone().into_bytes();
    let i = tampered.len() - 17;
    tampered[i] = if tampered[i] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).unwrap();
    cases.push(case("tampered-chain", "one byte of Alice's signature flipped", &tampered, &bob.present(&tampered, &req, Some(&receipt), CHANGE_BODY), &bob.who.key(), T0 + 70)?);

    let (leaf, _) = leaf_of(&token)?;
    Ok(json!({
        "about": "Golden vectors of demo-read-before-act: one CAL chain (ce-net-proto token v3), Bob's read receipt, and the verdict each use must get. Generated by `cargo run -p demo-read-before-act -- vectors`.",
        "format": "ce-net-proto CAPABILITY-PROGRAMS.md: token = hex(TokenV3); request = hex(bincode UseRequest); proofs = hex(bincode seq<Proof>); a use is authorize_use_v3 of a plain call.",
        "roots": [key_text(&key("alice"))],
        "node": hex::encode(ed_bytes(&desk)),
        "node_tags": [],
        "cell_keys": {},
        "cal": source,
        "token": token,
        "leaf": hex::encode(leaf),
        "receipt": receipt.hex(),
        "cases": cases,
    }))
}
