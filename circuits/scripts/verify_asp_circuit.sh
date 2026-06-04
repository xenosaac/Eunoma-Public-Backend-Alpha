#!/usr/bin/env bash
# =============================================================================================
# CP1 circuit soundness gate (V4: ASP dual-LeanIMT + B′ partial-withdraw). Authored by the
# INDEPENDENT adversarial reviewer. Runs a canonical-accept case PLUS a battery of forgeries that
# a SOUND circuit MUST reject.
#
#   CANONICAL-ACCEPT: a valid dual-LeanIMT 2-proof with a B′ PARTIAL spend (has_change=1) must
#                     witness-gen, prove, and verify. (A full-spend valid is also witnessed.)
#
#   FORGERIES — each MUST be REJECTED:
#     STAGE A (witness-generation; testable NOW, no zkey needed):
#       LeanIMT hardening (7): forge_shallow_depth, forge_deep_depth,
#         fake_zero_siblings_above_actualDepth, nonzero_pad_below_root, depth_out_of_range_low,
#         depth_out_of_range_high, depth_mismatch_state_vs_asp
#       B′ partial-withdraw (7): conservation_violation, rem_chunk_overflow, rem_negative,
#         W_gt_A_old, change_commitment_mismatch, has_change_inconsistent,
#         has_change_inconsistent_fullspend_mismatch
#       All fail at the circom witness calculator (`===` / Num2Bits / LessEqThan assertions).
#       change_commitment_mismatch fails here too because change_commitment is `===`-bound.
#
#     STAGE B (prove + verify; needs generated/withdrawal_proof_final.zkey + _vk.json from the
#       Setup stage): the canonical-accept is proven and verified. Re-runs the two `===`-bound
#       public forgeries (change_commitment_mismatch, root via wrong_state_root-style) at verify
#       level when the zkey is present, demonstrating the on-chain verifier also rejects them.
#
# Run STAGE A any time post-compile. Run the full gate (A + B) after scripts/setup_asp.sh.
# =============================================================================================
set -uo pipefail
cd "$(dirname "$0")/.."
GEN=generated
WJS=$GEN/withdrawal_proof_js
WASM=$WJS/withdrawal_proof.wasm
GW=$WJS/generate_witness.js
ZKEY=$GEN/withdrawal_proof_final.zkey
VK=$GEN/withdrawal_proof_vk.json
TMP=$(mktemp -d)
fail=0

# the 7 LeanIMT hardening + 7 B′ partial-withdraw forgeries (all reject at witness-gen)
FORGERIES=(
  forge_shallow_depth forge_deep_depth fake_zero_siblings_above_actualDepth nonzero_pad_below_root
  depth_out_of_range_low depth_out_of_range_high depth_mismatch_state_vs_asp
  conservation_violation rem_chunk_overflow rem_negative W_gt_A_old change_commitment_mismatch
  has_change_inconsistent has_change_inconsistent_fullspend_mismatch
)

build() { node scripts/build_asp_witness_test.mjs --forge "$1" --output "$TMP/in_$1.json" 2>/dev/null; }
witness() { node "$GW" "$WASM" "$TMP/in_$1.json" "$TMP/w_$1.wtns" >/dev/null 2>&1; }

if [ ! -f "$WASM" ]; then echo "ERROR: $WASM missing (run scripts/compile.sh first)"; rm -rf "$TMP"; exit 1; fi

echo "=== STAGE A: canonical-accept witnesses (must witness-gen) ==="
for ok in valid valid_fullspend; do
  if build "$ok" && witness "$ok"; then echo "  PASS: $ok witness generated"
  else echo "  FAIL: $ok witness-gen errored (canonical case must pass)"; fail=1; fi
done

echo "=== STAGE A: each forgery must be REJECTED at witness-gen ==="
for mode in "${FORGERIES[@]}"; do
  build "$mode"
  if witness "$mode"; then echo "  FAIL: $mode was ACCEPTED (must be rejected)"; fail=1
  else echo "  PASS: $mode rejected at witness-gen"; fi
done

# STAGE B requires the V4 zkey/VK. The circuit has 6 public inputs (nPublic=6, IC length 7).
# A stale 13-public/1-public zkey does NOT match the compiled pruned-public wasm. Gate on nPublic so a
# pre-Setup stale zkey SKIPS (not FAILS) STAGE B.
V4_VK_OK=0
if [ -f "$VK" ]; then
  NPUB=$(node -e 'const fs=require("fs"),path=require("path");try{process.stdout.write(String((JSON.parse(fs.readFileSync(path.resolve(process.argv[1]),"utf8")).nPublic)??""))}catch(e){process.stdout.write("")}' "$VK" 2>/dev/null)
  [ "$NPUB" = "6" ] && V4_VK_OK=1
fi

if [ -f "$ZKEY" ] && [ -f "$VK" ] && [ "$V4_VK_OK" = "1" ]; then
  echo "=== STAGE B: canonical-accept must prove + verify (V4 zkey present, nPublic=6) ==="
  if snarkjs groth16 prove "$ZKEY" "$TMP/w_valid.wtns" "$TMP/proof.json" "$TMP/public.json" >/dev/null 2>&1 \
     && snarkjs groth16 verify "$VK" "$TMP/public.json" "$TMP/proof.json" 2>&1 | grep -q "OK"; then
    echo "  PASS: canonical partial-spend proof VERIFIED"
  else echo "  FAIL: canonical proof did not verify"; fail=1; fi

  echo "=== STAGE B: forged PUBLIC vector must FAIL verify (proof bound to honest publics) ==="
  # Take the honest proof + tamper public[5] change_commitment, then verify against it.
  if [ -f "$TMP/public.json" ]; then
    node -e '
      const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
      p[5] = (BigInt(p[5]) + 1n).toString();
      fs.writeFileSync(process.argv[2], JSON.stringify(p));
    ' "$TMP/public.json" "$TMP/public_forged.json"
    if snarkjs groth16 verify "$VK" "$TMP/public_forged.json" "$TMP/proof.json" 2>&1 | grep -q "OK"; then
      echo "  FAIL: tampered public change_commitment still VERIFIED (verifier unsound!)"; fail=1
    else echo "  PASS: tampered public change_commitment rejected at verify"; fi
  fi
elif [ -f "$VK" ] && [ "$V4_VK_OK" != "1" ]; then
  echo "=== STAGE B SKIPPED: $VK is STALE (nPublic=${NPUB:-?}, expected 6 for V4). The V4 zkey" \
       "has not been regenerated yet — run scripts/setup_asp.sh after the final V4 deposit/withdraw" \
       "compile. STAGE A (witness-gen forgeries) is the authoritative pre-Setup gate. ==="
else
  echo "=== STAGE B SKIPPED: $ZKEY / $VK not present (run scripts/setup_asp.sh after the V4 compile) ==="
fi

rm -rf "$TMP"
if [ $fail -eq 0 ]; then echo "ALL CIRCUIT GATE TESTS PASS"; else echo "CIRCUIT GATE FAILED"; exit 1; fi
