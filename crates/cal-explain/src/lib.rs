//! `cal.explain`: given a chain and a verdict, return the CAL clause that decided it.
//!
//! The chain is decompiled to CAL by ce-net-proto (`cal::api` `decompile`), so the clause is read
//! from the signed bytes, never from whatever source text the issuer kept. The verifier's refusal
//! reason names the kind of check that failed; this cell maps it to the clause that sets that check
//! and returns its text, the link it sits in and its line in the decompiled chain.

use ce_net_proto::cal::api;
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Clause {
    /// The clause as CAL writes it (trimmed), e.g. `require read notice:thread/chg-42@... by node:bob-phone ... within 1d`.
    pub text: String,
    /// 1-based line in `source`.
    pub line: usize,
    /// Index of the link (0 = root) the clause belongs to.
    pub link: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Explained {
    /// The clause that decided the verdict (for an allowed use: the conditions it met).
    pub clauses: Vec<Clause>,
    /// The whole chain as CAL.
    pub source: String,
}

/// Decompile `token` with the ref book `refs` (for readable names) to CAL source.
pub fn decompile(token: &str, refs: &Value) -> Result<String, String> {
    let out: Value = serde_json::from_str(&api::call("decompile", &json!({ "token": token.trim(), "refs": refs }).to_string()))
        .map_err(|e| e.to_string())?;
    if out["ok"] != json!(true) {
        return Err(out["error"]["message"].as_str().unwrap_or("decompile failed").to_string());
    }
    Ok(out["source"].as_str().unwrap_or_default().to_string())
}

/// The clause keywords that set the check a refusal `reason` names. `None` = allowed.
fn keywords(reason: Option<&str>) -> Vec<&'static str> {
    let Some(r) = reason else { return vec!["require", "cosign", "via"] };
    if r.contains("condition not met: requires") {
        vec!["require"]
    } else if r.contains("condition not met: cosign") {
        vec!["cosign"]
    } else if r.contains("condition not met: via") {
        vec!["via"]
    } else if r.contains("expired") {
        vec!["until", "for"]
    } else if r.contains("not yet valid") {
        vec!["not"]
    } else if r.contains("does not grant") {
        vec!["can"]
    } else if r.contains("resource does not match") {
        vec!["on"]
    } else if r.contains("does not root") || r.contains("not held by the request sender") || r.contains("invalid signature") {
        vec!["grants"]
    } else {
        vec![]
    }
}

/// The deciding clauses of `source` for `reason`. An empty list means no single clause decides
/// it (for example a malformed request); the verifier's reason then stands alone.
pub fn deciding(source: &str, reason: Option<&str>) -> Vec<Clause> {
    let want = keywords(reason);
    let mut out = Vec::new();
    let mut link: Option<usize> = None;
    for (i, raw) in source.lines().enumerate() {
        let t = raw.trim();
        let first = t.split_whitespace().next().unwrap_or("");
        if t.ends_with('{') && t.contains(" grants ") {
            link = Some(link.map_or(0, |l| l + 1));
            if want.contains(&"grants") && !out.iter().any(|c: &Clause| c.link == link.unwrap()) {
                out.push(Clause { text: t.trim_end_matches('{').trim().to_string(), line: i + 1, link: link.unwrap() });
            }
            continue;
        }
        let Some(l) = link else { continue };
        if want.contains(&first) && first != "grants" {
            out.push(Clause { text: t.to_string(), line: i + 1, link: l });
        }
    }
    // A child repeats its parent's conditions: the clause that decides is the first (the root's).
    let mut seen = std::collections::HashSet::new();
    out.retain(|c| seen.insert(strip_link_local(&c.text)));
    out
}

fn strip_link_local(t: &str) -> String {
    t.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The cell's one call: decompile `token`, pick the clause that decided `reason`.
pub fn explain(token: &str, refs: &Value, reason: Option<&str>) -> Result<Explained, String> {
    let source = decompile(token, refs)?;
    Ok(Explained { clauses: deciding(&source, reason), source })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "cal 1\n\nperson:alice ed25519:aa grants person:bob ed25519:bb {\n  can change.approve:approve\n  on node:desk ed25519:cc\n  until 2027-02-14\n  require read notice:thread/chg-42@ff by node:bob-phone ed25519:dd within 1d\n  cosign person:bob ed25519:bb\n  nonce 1\n}\n";

    #[test]
    fn picks_the_clause_per_reason() {
        let r = deciding(SRC, Some("condition not met: requires"));
        assert_eq!(r.len(), 1);
        assert!(r[0].text.starts_with("require read notice:thread/chg-42@ff"));
        assert_eq!((r[0].line, r[0].link), (7, 0));
        assert_eq!(deciding(SRC, Some("condition not met: cosign"))[0].text, "cosign person:bob ed25519:bb");
        assert_eq!(deciding(SRC, Some("link 0: capability has expired"))[0].text, "until 2027-02-14");
        assert_eq!(deciding(SRC, Some("capability does not grant 'x'"))[0].text, "can change.approve:approve");
        assert!(deciding(SRC, Some("leaf capability is not held by the request sender"))[0].text.starts_with("person:alice"));
        assert_eq!(deciding(SRC, None).len(), 2);
        assert!(deciding(SRC, Some("use request is malformed")).is_empty());
    }
}
