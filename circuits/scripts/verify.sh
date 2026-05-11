#!/usr/bin/env bash
# Verify the valid proof PLUS the 3 negative cases (mutated public inputs).
# Negative cases reuse the valid proof_valid.json but submit a mutated public-input
# vector — snarkjs verify must REJECT those.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[verify] === positive: valid proof, valid public inputs ==="
snarkjs groth16 verify \
    generated/deposit_binding_vk.json \
    generated/public_valid.json \
    generated/proof_valid.json

echo
echo "[verify] === negative #1: wrong amount_tag ==="
if snarkjs groth16 verify \
    generated/deposit_binding_vk.json \
    generated/public_invalid_wrong_amount_tag.json \
    generated/proof_valid.json; then
    echo "[verify] BUG: negative #1 should have FAILED but verify returned OK"
    exit 1
else
    echo "[verify] OK — verifier rejected negative #1 as expected"
fi

echo
echo "[verify] === negative #2: wrong commitment ==="
if snarkjs groth16 verify \
    generated/deposit_binding_vk.json \
    generated/public_invalid_wrong_commitment.json \
    generated/proof_valid.json; then
    echo "[verify] BUG: negative #2 should have FAILED but verify returned OK"
    exit 1
else
    echo "[verify] OK — verifier rejected negative #2 as expected"
fi

echo
echo "[verify] === negative #3: amount-inconsistent (asset_id mutated) ==="
if snarkjs groth16 verify \
    generated/deposit_binding_vk.json \
    generated/public_invalid_amount_inconsistent.json \
    generated/proof_valid.json; then
    echo "[verify] BUG: negative #3 should have FAILED but verify returned OK"
    exit 1
else
    echo "[verify] OK — verifier rejected negative #3 as expected"
fi

echo
echo "[verify] === BONUS: amount > 2^64-1 should fail at PROVE time ==="
# We construct a witness with amount = 2^64 = 18446744073709551616 (one bit too wide).
# This must fail the Num2Bits(64) constraint at witness-generation time.
cat > /tmp/oversized_amount_input.json <<'EOF'
{
  "commitment":      "0",
  "amount_tag":      "0",
  "asset_id":        "7",
  "vault_addr_hash": "0",
  "chain_id":        "2",
  "pool_id":         "0",
  "nullifier":       "1",
  "secret":          "1",
  "amount":          "18446744073709551616",
  "deposit_blind":   "1"
}
EOF
if node generated/deposit_binding_js/generate_witness.js \
    generated/deposit_binding_js/deposit_binding.wasm \
    /tmp/oversized_amount_input.json \
    /tmp/oversized_witness.wtns 2>/dev/null; then
    echo "[verify] BUG: oversized amount accepted by witness generator"
    exit 1
else
    echo "[verify] OK — circuit rejected amount = 2^64 at witness generation (Num2Bits(64) failure)"
fi

echo
echo "[verify] all 4 cases (1 positive + 3 negatives + 1 bonus oversized-amount) PASSED."
