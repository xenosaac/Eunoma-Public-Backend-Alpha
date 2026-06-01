#!/usr/bin/env bash
# CP1 circuit gate: ASP v-next withdraw circuit positive + adversarial verification.
#   POSITIVE: a valid dual-LeanIMT 2-proof (commitment ∈ state AND ∈ ASP) must prove + verify.
#   NEGATIVE: each of 7 forgeries must be REJECTED (witness-gen asserts), proving the hardened
#             LeanIMT actualDepth binding + dual-inclusion soundness.
# Requires generated/withdrawal_proof_final.zkey + _vk.json (run setup_asp.sh first).
set -uo pipefail
cd "$(dirname "$0")/.."
GEN=generated
WJS=$GEN/withdrawal_proof_js
ZKEY=$GEN/withdrawal_proof_final.zkey
VK=$GEN/withdrawal_proof_vk.json
TMP=$(mktemp -d)
fail=0

gen_and_witness() {
  local mode=$1
  node scripts/build_asp_witness_test.mjs --forge "$mode" --output "$TMP/in_$mode.json" 2>/dev/null || return 1
  node "$WJS/generate_witness.js" "$WJS/withdrawal_proof.wasm" "$TMP/in_$mode.json" "$TMP/w_$mode.wtns"
}

echo "=== POSITIVE: valid 2-proof must prove + verify ==="
if gen_and_witness valid >/dev/null 2>&1; then
  if snarkjs groth16 prove "$ZKEY" "$TMP/w_valid.wtns" "$TMP/proof.json" "$TMP/public.json" >/dev/null 2>&1 \
     && snarkjs groth16 verify "$VK" "$TMP/public.json" "$TMP/proof.json" 2>&1 | grep -q "OK"; then
    echo "  PASS: valid proof VERIFIED"
  else echo "  FAIL: valid proof did not verify"; fail=1; fi
else echo "  FAIL: valid witness-gen errored"; fail=1; fi

echo "=== NEGATIVE: each forgery must be REJECTED at witness-gen ==="
for mode in asp_nonmember wrong_asp_root wrong_state_root forge_shallow fake_zero_sibling depth_zero depth_overflow; do
  if gen_and_witness "$mode" >/dev/null 2>&1; then
    echo "  FAIL: $mode was ACCEPTED (should be rejected)"; fail=1
  else
    echo "  PASS: $mode rejected"
  fi
done

rm -rf "$TMP"
if [ $fail -eq 0 ]; then echo "ALL CIRCUIT GATE TESTS PASS"; else echo "CIRCUIT GATE FAILED"; exit 1; fi
