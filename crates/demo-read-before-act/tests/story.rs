//! The proof: the scripted story gives refused (with the clause), receipt signed, accepted; the
//! third person's fresh verifier agrees; the checked-in transcript and vectors are exactly what
//! the code produces; and every vector's expected verdict is what ce-net-proto decides.

use demo_read_before_act::{desk_node, refs, story, transcript_text, vectors};
use serde_json::{Value, json};

fn file(rel: &str) -> String {
    std::fs::read_to_string(format!("{}/../../{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|e| panic!("{rel}: {e} (run `cargo run -p demo-read-before-act -- record` / `vectors`)"))
}

#[test]
fn three_calls_refused_receipt_accepted() {
    let t = story().unwrap();
    let c = t["calls"].as_array().unwrap();
    assert_eq!(c.len(), 3);
    assert_eq!(c[0]["verdict"]["allowed"], json!(false));
    assert_eq!(c[0]["verdict"]["reason"], json!("condition not met: requires"));
    let clause = c[0]["verdict"]["clauses"][0]["text"].as_str().unwrap();
    assert!(clause.starts_with("require read notice:thread/chg-42@"), "{clause}");
    assert!(clause.contains("by node:bob-phone") && clause.ends_with("within 1d"), "{clause}");
    assert_eq!(c[1]["tool"], json!("open"));
    assert!(c[1]["receipt"]["receipt_hex"].as_str().unwrap().len() > 100);
    assert_eq!(c[2]["verdict"]["allowed"], json!(true), "{}", c[2]);
    // The same request both times: only the proofs differ.
    assert_eq!(c[0]["presented"]["request"], c[2]["presented"]["request"]);
    assert_ne!(c[0]["presented"]["proofs"], c[2]["presented"]["proofs"]);
    assert_eq!(t["third_person"]["verdict"]["allowed"], json!(true));
}

#[test]
fn transcript_is_checked_in() {
    let t = story().unwrap();
    assert_eq!(file("proof/transcript.json"), serde_json::to_string_pretty(&t).unwrap() + "\n");
    assert_eq!(file("proof/transcript.txt"), transcript_text(&t));
}

#[test]
fn vectors_are_checked_in_and_hold() {
    let v = vectors().unwrap();
    assert_eq!(file("proof/vectors.json"), serde_json::to_string_pretty(&v).unwrap() + "\n");
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 10);
    let allowed: Vec<&str> = cases.iter().filter(|c| c["expect"]["allowed"] == json!(true)).map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(allowed, ["accepted-with-receipt"]);
    for c in cases {
        let p = act_approve::Presented {
            token: c["token"].as_str().unwrap().into(),
            request: c["request"].as_str().unwrap().into(),
            proofs: c["proofs"].as_str().unwrap().into(),
            body: body_for(c),
        };
        let got = act_approve::verify(&desk_node(), &refs(), &p, c["now"].as_u64().unwrap()).unwrap();
        assert_eq!(json!(got.allowed), c["expect"]["allowed"], "{}", c["name"]);
        assert_eq!(json!(got.reason), c["expect"]["reason"], "{}", c["name"]);
    }
}

fn body_for(c: &Value) -> String {
    if c["name"] == json!("other-change-body") { "approve CHG-43: drop the billing database".into() } else { demo_read_before_act::CHANGE_BODY.into() }
}

#[test]
fn replay_is_refused() {
    use demo_read_before_act::*;
    let mut notices = msg_notice::NoticeCell::new(&seed("bob-phone"), key("bob"));
    let n = notices.post(NOTICE_ID, "person:alice", NOTICE_TITLE, NOTICE_BODY);
    let token = mint(&cal_source(&n.sha256, T0 + 86_400), T0).unwrap();
    let (_, r) = notices.open(NOTICE_ID, T0 + 5).unwrap();
    let bob = Client::new("bob");
    let req = bob.request(&token, &key("change-desk"), CHANGE_BODY, T0 + 10, 7).unwrap();
    let p = bob.present(&token, &req, Some(&r), CHANGE_BODY);
    let mut desk = act_approve::ApproveCell::new(&ed_bytes(&key("change-desk")), refs());
    assert!(desk.approve(&p, T0 + 10).allowed);
    let again = desk.approve(&p, T0 + 11);
    assert_eq!(again.reason.as_deref(), Some("request replayed"));
}
