# Read it before you can act

Alice sends Bob a change notice and gives him a key to approve the change. The key carries one clause:
**only after a signed read receipt for this notice**. Bob presses approve and it is refused, and the page shows the
exact clause that refused it. Bob opens the notice, his phone signs a read receipt, and the same approve call now
goes through. A third person pastes the chain, the request and the proofs into the page and gets the same verdict on
their own machine; a one-file Python verifier gets it too, offline.

Built from three reusable cells and two public dependencies: [ce-net-proto](https://github.com/ce-net/ce-net-proto)
(Apache-2.0: capability chains, CAL and the verifier) and [ce-net-local-dev-sim](https://github.com/ce-net/ce-net-local-dev-sim)
(a local mesh). Static copy of the page with the recorded run: https://ce-net.github.io/demo-read-before-act/

## Run it (under 5 minutes)

Needs git, Rust 1.85 or newer, Python 3.8 or newer and curl.

```sh
git clone https://github.com/ce-net/demo-read-before-act
git clone https://github.com/ce-net/ce-net-local-dev-sim
python3 ce-net-local-dev-sim/cenet_mock.py 7878 &
cd demo-read-before-act
cargo run -p demo-read-before-act -- up
```

```
demo-read-before-act is up: open http://127.0.0.1:7400/
  route: local mesh: ce-net-local-dev-sim at http://127.0.0.1:7878/mcp (apps_search + mcp_use)
  act.approve -> http://127.0.0.1:7400/mcp/act.approve
  cal.explain -> http://127.0.0.1:7400/mcp/cal.explain
  msg.notice -> http://127.0.0.1:7400/mcp/msg.notice
```

Open http://127.0.0.1:7400/ and:

1. Press **Approve as Bob**. Refused: `condition not met: requires`, with the `require read ...` line of the key
   highlighted.
2. Press **Open the notice**. Bob's phone signs a receipt for the exact text.
3. Press **Approve as Bob** again. Accepted.
4. The evidence of the last call is now in the box under *Check it on your own machine*. Press **Verify**: the same
   verdict from a verifier that knows nothing but what was pasted.

On startup `up` joins the sim as an agent, publishes the three cells with `app_publish`, finds them again with
`apps_search`, and every call the page makes goes through the sim's `mcp_use`, as an agent reaches a cell on the
live network. Without the sim it calls the cells directly and says so. The same run from the terminal:
`scripts/mesh-smoke.sh` (CI runs it).

## The key

What Alice signs, as CAL ([the cell auth language](https://github.com/ce-net/ce-net-proto/blob/main/docs/CAL.md)):

```
person:alice grants person:bob {
  can change.approve:approve
  on node:change-desk
  until @1802592000
  require read notice:thread/chg-42@b5d148ca3816805b648a5e1173c4f224be5d68f6b9a1c7103eaf19a87d846431 by node:bob-phone within 1d
  cosign person:bob
  nonce 4242
}
```

- `require read notice:thread/chg-42@<sha256>`: before every use, a receipt that the requester read notice
  `chg-42` through the text whose SHA-256 is pinned here. Edit the notice and an old receipt proves nothing.
- `by node:bob-phone`: only Bob's phone key can sign that receipt. A receipt signed by Bob's own key is refused.
- `within 1d`: the receipt is at most a day old at the moment of use.
- `cosign person:bob`: every use is signed by Bob over its exact request (chain, node, action, body, time), so a
  copied chain plus receipt does nothing for anyone else.

## The proof

**Recorded transcript**, [`proof/transcript.txt`](proof/transcript.txt) (and `.json`), fixed keys and clock, three
calls (excerpt, hashes shortened):

```
call 1 at 1800000010: act.approve.approve by person:bob
  REFUSED: condition not met: requires
  clause (link 0, line 7): require read notice:thread/chg-42@b5d148ca...846431 by node:bob-phone ed25519:557bda33...e0cf1c within 1d
call 2 at 1800000040: msg.notice.open by person:bob
  RECEIPT SIGNED by ed25519:557bda33...e0cf1c about ed25519:c728493b...4aead6
call 3 at 1800000070: act.approve.approve by person:bob
  ACCEPTED
third person, a fresh verifier with only the pasted chain, request and proofs:
  ACCEPTED
```

Calls 1 and 3 carry the same request bytes; only the proofs differ. `cargo test` regenerates the transcript and
fails if one byte differs from the file.

**Golden vectors**, [`proof/vectors.json`](proof/vectors.json): the chain, Bob's receipt and 13 uses with the verdict
each must get. ce-net-capability-verify (Python, one file, no ce-net code) reproduces every one offline:

```sh
git clone https://github.com/ce-net/ce-net-capability-verify
python3 ce-net-capability-verify/verify.py use demo-read-before-act/proof/vectors.json
```

```
ok   refused-without-receipt            refused: condition not met: requires
ok   accepted-with-receipt              allowed
ok   receipt-for-other-text             refused: condition not met: requires
ok   receipt-for-other-notice           refused: condition not met: requires
ok   receipt-not-by-device              refused: condition not met: requires
ok   receipt-about-someone-else         refused: condition not met: requires
ok   receipt-too-old                    refused: condition not met: requires
ok   receipt-from-the-future            refused: condition not met: requires
ok   no-cosign                          refused: condition not met: cosign
ok   carol-presents-bobs-key            refused: leaf capability is not held by the request sender
ok   other-change-body                  refused: use request is not this use (body)
ok   key-expired                        refused: link 0: capability has expired
ok   tampered-chain                     refused: link 0: invalid signature
13/13 use vectors pass
```

(It needs only the Python standard library for these Ed25519 vectors.)

**CI** ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) starts from a fresh clone of this commit and the
public dependencies, runs the tests, re-records the transcript and vectors and requires no diff, runs the Python
verifier on the vectors, and plays the story on the local mesh.

## The cells

| Cell | Crate | Tools | Does |
|---|---|---|---|
| `msg.notice` | [`crates/msg-notice`](crates/msg-notice) | `list`, `open {id}` | Stores notices; opening one makes the reader's device key sign a read receipt (a ce-net-proto `Attestation`, `ReadThrough { "notice", id, sha256 }`) |
| `act.approve` | [`crates/act-approve`](crates/act-approve) | `approve {token, request, proofs, body}` | The guarded action: ce-net-proto's `authorize_use_v3` through `cal::api` `verify`, plus a replay log of request ids |
| `cal.explain` | [`crates/cal-explain`](crates/cal-explain) | `explain {token, reason}`, `verify {evidence}` | Decompiles the signed chain to CAL and returns the clause that decided the verdict; verifies pasted evidence |

Each is a plain library with no server code; [`crates/demo-read-before-act`](crates/demo-read-before-act) serves them
as MCP endpoints (`POST /mcp/<cell>`), holds Bob's client (builds and co-signs the request) and the page.

```
cargo run -p demo-read-before-act -- record    # rewrite proof/transcript.{json,txt}
cargo run -p demo-read-before-act -- vectors   # rewrite proof/vectors.json
cargo run -p demo-read-before-act -- explain   # the key in plain English (ce-cal explain)
cargo test --workspace
```

## What it does not claim

- A receipt says the `msg.notice` cell on Bob's phone showed him that exact text at that time. It cannot prove a
  person read it with attention.
- The keys are fixed demo keys (`SHA-256("demo-read-before-act/<name>")`) so every run and vector is reproducible.
  They are public: never use them for anything else.
- In `up` all parties run in one process on one machine; on a real mesh `msg.notice` runs on Bob's phone with a key
  that never leaves it, and `act.approve` on the desk node.

## License

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)).
