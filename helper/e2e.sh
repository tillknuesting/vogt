#!/bin/sh
# End-to-end check of the Swift helper against a development daemon, with
# real Secure Enclave keys (no Touch ID: --insecure-test). It covers:
#   - pairing and daemon pinning
#   - policy approval signed with Secure Enclave ML-DSA-65 + P-256
#   - opening Go's HPKE MLKEM768-P256 DEK wraps inside the Secure Enclave
#     (spike S1) and returning them over X-Wing
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d /tmp/vogt-e2e.XXXX)
export HOME="$tmp"
vogt="$tmp/vogt"
cleanup() {
	if [ "${ok:-}" != 1 ]; then echo "--- daemon log"; tail -20 "$tmp/daemon.log" 2>/dev/null; echo "--- helper log"; tail -20 "$tmp/helper.log" 2>/dev/null; fi
	[ -n "${dpid:-}" ] && kill "$dpid" 2>/dev/null || true
	[ -n "${hpid:-}" ] && kill "$hpid" 2>/dev/null || true
	rm -rf "$keydir"
	rm -rf "$tmp"
}
keydir=""
trap cleanup EXIT

(cd "$root" && go build -o "$vogt" ./cmd/vogt)
[ -x "$root/helper/build/Vogt Helper.app/Contents/MacOS/VogtHelper" ] || "$root/helper/build.sh" >/dev/null
helper="$root/helper/build/Vogt Helper.app/Contents/MacOS/VogtHelper"
sock="$tmp/.vogt-dev/run/helper.sock"

"$vogt" daemon --dev --proxy 127.0.0.1:0 >"$tmp/daemon.log" 2>&1 &
dpid=$!
sleep 1

# Fresh Secure Enclave test keys for this run. The helper finds its
# Application Support folder through the user database, not $HOME.
keydir="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory | awk '{print $2}')/Library/Application Support/Vogt Helper (test)"
rm -rf "$keydir"
bundle=$("$helper" --insecure-test --keys 2>/dev/null)
"$vogt" pair --state "$tmp/.vogt-dev/state" "$bundle" >/dev/null

"$helper" --insecure-test --socket "$sock" >"$tmp/helper.log" 2>&1 &
hpid=$!
sleep 1

"$vogt" policy init >"$tmp/policy.json"
"$vogt" policy load "$tmp/policy.json"
printf 'sk-high-tier-secret' | "$vogt" secret add openai --provider static --tier high 2>/dev/null >/dev/null
printf 'hf_low_tier_secret' | "$vogt" secret add huggingface-read --provider static --tier low 2>/dev/null >/dev/null

"$vogt" run --name e2e -- sh -c "'$vogt' grant openai.api >'$tmp/high.env' && '$vogt' grant hf.hub.read >'$tmp/low.env'" 2>/dev/null
grep -q "export OPENAI_API_KEY='vogt_p_" "$tmp/high.env"
grep -q "export HF_TOKEN='vogt_p_" "$tmp/low.env"
if grep -q "sk-high-tier-secret\|hf_low_tier_secret" "$tmp/high.env" "$tmp/low.env"; then
	echo "FAIL: a real key reached the agent" >&2
	exit 1
fi
"$vogt" audit verify
ok=1
echo "ok: Swift helper with Secure Enclave keys approved a policy, a high-tier grant and a low-tier grant"
