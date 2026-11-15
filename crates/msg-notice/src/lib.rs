//! `msg.notice`: a cell that stores notices and, when the reader opens one, signs a read receipt
//! with the reader's device key.
//!
//! A receipt is a ce-net-proto v3 `Attestation`: the device key (witness) states that the reader's
//! key (subject) has read thread `<id>` of source `notice` through message `<sha256 of the text>`,
//! at a given time. Any capability link that says `require read notice:thread/<id>@<sha> by <device>`
//! accepts it, and nothing else does: the signature is over the domain-tagged attestation bytes, so
//! it cannot be replayed as a link, a co-signature or a receipt for another notice or another text.

use std::collections::BTreeMap;

use ce_net_proto::v3::sign::Signer;
use ce_net_proto::v3::{Attestation, AttestationBody, Claim, Key, Proof, attest_bytes};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The `source` a notice receipt names (`notice:thread/<id>` in CAL).
pub const SOURCE: &str = "notice";

/// One stored notice. `sha256` is what a receipt names as the message read through, so a receipt
/// proves the reader saw exactly this text.
#[derive(Debug, Clone, Serialize)]
pub struct Notice {
    pub id: String,
    pub from: String,
    pub title: String,
    pub body: String,
    pub sha256: String,
    /// Unix seconds the reader opened it (None until then).
    pub opened_at: Option<u64>,
}

impl Notice {
    /// The hash a receipt names: SHA-256 of `title \n body`.
    pub fn hash_of(title: &str, body: &str) -> String {
        hex::encode(Sha256::digest(format!("{title}\n{body}").as_bytes()))
    }
}

/// A signed read receipt and the wire forms the rest of the mesh needs.
#[derive(Debug, Clone)]
pub struct Receipt {
    pub attestation: Attestation,
}

impl Receipt {
    /// The receipt as one `Proof::Attested`.
    pub fn proof(&self) -> Proof {
        Proof::Attested(self.attestation.clone())
    }

    /// The receipt alone as canonical proof bytes (`seq<Proof>` with one entry), hex.
    pub fn hex(&self) -> String {
        hex::encode(ce_net_proto::v3::encode_proofs(&[self.proof()]))
    }

    /// A short JSON summary for pages and transcripts.
    pub fn summary(&self) -> serde_json::Value {
        let b = &self.attestation.body;
        let (thread, upto) = match &b.claim {
            Claim::ReadThrough { thread, upto_msg, .. } => (thread.clone(), upto_msg.clone()),
            Claim::Fact { name, .. } => (name.clone(), None),
        };
        serde_json::json!({
            "witness": key_text(&b.witness),
            "subject": key_text(&b.subject),
            "notice": thread,
            "read_through": upto,
            "at": b.at,
            "receipt_hex": self.hex(),
        })
    }
}

/// `ed25519:<hex>` or `p256:<hex>`, as CAL writes a key.
pub fn key_text(k: &Key) -> String {
    match k {
        Key::Ed25519(b) => format!("ed25519:{}", hex::encode(b)),
        Key::P256(b) => format!("p256:{}", hex::encode(b)),
    }
}

/// The cell as it runs on the reader's device: the notices addressed to the reader, and the
/// device key that signs receipts.
pub struct NoticeCell {
    device: Signer,
    reader: Key,
    notices: BTreeMap<String, Notice>,
}

impl NoticeCell {
    /// `device_seed` is the device's Ed25519 secret; `reader` is the key the receipt is about (the
    /// key that holds the capability that needs the receipt).
    pub fn new(device_seed: &[u8; 32], reader: Key) -> NoticeCell {
        NoticeCell { device: Signer::ed25519(device_seed), reader, notices: BTreeMap::new() }
    }

    pub fn device_key(&self) -> Key {
        self.device.key()
    }

    /// Store a notice; returns it with its hash. Re-posting an id replaces it (and its new text
    /// has a new hash, so an old receipt no longer proves it was read).
    pub fn post(&mut self, id: &str, from: &str, title: &str, body: &str) -> Notice {
        let n = Notice {
            id: id.into(),
            from: from.into(),
            title: title.into(),
            body: body.into(),
            sha256: Notice::hash_of(title, body),
            opened_at: None,
        };
        self.notices.insert(id.into(), n.clone());
        n
    }

    pub fn get(&self, id: &str) -> Option<&Notice> {
        self.notices.get(id)
    }

    pub fn list(&self) -> Vec<&Notice> {
        self.notices.values().collect()
    }

    /// The reader opens notice `id` at `now`: the device signs a receipt for exactly that text.
    pub fn open(&mut self, id: &str, now: u64) -> Result<(Notice, Receipt), String> {
        let n = self.notices.get_mut(id).ok_or_else(|| format!("no notice '{id}'"))?;
        n.opened_at = Some(now);
        let n = n.clone();
        let receipt = sign_receipt(&self.device, self.reader, &n.id, &n.sha256, now);
        Ok((n, receipt))
    }
}

/// Sign a receipt: `signer` states that `subject` read notice `id` through text `sha256` at `at`.
/// Exposed so tests and vectors can also make the wrong receipts a verifier must refuse.
pub fn sign_receipt(signer: &Signer, subject: Key, id: &str, sha256: &str, at: u64) -> Receipt {
    let body = AttestationBody {
        witness: signer.key(),
        subject,
        claim: Claim::ReadThrough { source: SOURCE.into(), thread: id.into(), upto_msg: Some(sha256.into()) },
        at,
    };
    let sig = signer.sign_bytes(&attest_bytes(&body));
    Receipt { attestation: Attestation { body, sig } }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_names_the_exact_text_and_verifies() {
        let reader = Signer::ed25519(&[2; 32]).key();
        let mut cell = NoticeCell::new(&[3; 32], reader);
        let n = cell.post("chg-1", "alice", "Change", "Swap the db");
        let (_, r) = cell.open("chg-1", 100).unwrap();
        let b = &r.attestation.body;
        assert_eq!(b.subject, reader);
        assert_eq!(b.witness, cell.device_key());
        assert_eq!(b.claim, Claim::ReadThrough { source: "notice".into(), thread: "chg-1".into(), upto_msg: Some(n.sha256.clone()) });
        let bytes = hex::decode(r.hex()).unwrap();
        assert_eq!(ce_net_proto::v3::decode_proofs(&bytes).unwrap().len(), 1);
        // Editing the notice changes its hash.
        let n2 = cell.post("chg-1", "alice", "Change", "Swap the db tonight");
        assert_ne!(n.sha256, n2.sha256);
        assert!(cell.open("nope", 1).is_err());
    }
}
