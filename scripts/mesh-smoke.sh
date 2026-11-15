#!/usr/bin/env bash
# The story end to end on the local mesh: start ce-net-local-dev-sim and `up`, then
# approve (refused, with the clause) -> open the notice (receipt signed) -> approve (accepted)
# -> a third person verifies the pasted evidence. Prints each step; exits 1 on any surprise.
#   SIM=path/to/cenet_mock.py (default ../ce-net-local-dev-sim/cenet_mock.py), PORT (default 7400)
set -euo pipefail
cd "$(dirname "$0")/.."
SIM=${SIM:-../ce-net-local-dev-sim/cenet_mock.py}
PORT=${PORT:-7400}
SIM_PORT=${SIM_PORT:-7878}
BIN="${CARGO_TARGET_DIR:-target}/debug/demo-read-before-act"
[ -x "$BIN" ] || cargo build -q -p demo-read-before-act
python3 "$SIM" "$SIM_PORT" >/dev/null & SIM_PID=$!
sleep 1
"$BIN" up --port "$PORT" --sim "http://127.0.0.1:$SIM_PORT/mcp" & UP_PID=$!
trap 'kill $SIM_PID $UP_PID 2>/dev/null || true' EXIT
B="http://127.0.0.1:$PORT"
for _ in $(seq 50); do curl -sf "$B/api/state" >/dev/null && break; sleep 0.2; done
fail() { echo "FAIL: $*"; exit 1; }
field() { python3 -c "import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1].split('.'): v=v[int(k)] if k.isdigit() else v[k]
print(v if isinstance(v,str) else json.dumps(v))" "$1"; }

state=$(curl -s "$B/api/state")
echo "route: $(field route <<<"$state")"
grep -q "local mesh" <<<"$state" || fail "not routed through the local mesh"

a1=$(curl -s -X POST "$B/api/approve" -d '{}')
[ "$(field verdict.allowed <<<"$a1")" = false ] || fail "call 1 was not refused"
echo "call 1 act.approve: REFUSED: $(field verdict.reason <<<"$a1")"
echo "  clause: $(field clauses.0.text <<<"$a1")"
field clauses.0.text <<<"$a1" | grep -q '^require read notice:thread/chg-42@' || fail "wrong clause"

o=$(curl -s -X POST "$B/api/open" -d '{}')
echo "call 2 msg.notice.open: RECEIPT SIGNED by $(field receipt.witness <<<"$o") at $(field receipt.at <<<"$o")"

a2=$(curl -s -X POST "$B/api/approve" -d '{}')
[ "$(field verdict.allowed <<<"$a2")" = true ] || fail "call 3 was not accepted: $a2"
echo "call 3 act.approve: ACCEPTED"

ev=$(python3 -c "import json,sys; print(json.dumps({'evidence': json.load(sys.stdin)['evidence']}))" <<<"$a2")
v=$(curl -s -X POST "$B/api/verify" -d "$ev")
[ "$(field verdict.allowed <<<"$v")" = true ] || fail "third person got another verdict"
echo "third person cal.explain.verify: ACCEPTED (checked at $(field checked_at <<<"$v"))"
ev1=$(python3 -c "import json,sys; print(json.dumps({'evidence': json.load(sys.stdin)['evidence']}))" <<<"$a1")
v1=$(curl -s -X POST "$B/api/verify" -d "$ev1")
[ "$(field verdict.reason <<<"$v1")" = "condition not met: requires" ] || fail "third person, call 1: $v1"
echo "third person, call 1 evidence: REFUSED: condition not met: requires"
echo "ok: refused with the clause, receipt signed, accepted, same verdicts on a fresh verifier"
