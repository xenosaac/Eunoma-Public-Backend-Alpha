pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — deposit-binding circuit (Gate 4a).
//
// Spec ref: HANDOFF Section 5.1.
//
// Public inputs (in declaration order; this is the snarkjs convention and
// drives the order of the on-chain `public_inputs` Fr vector + the
// `vk_uvw_gamma_g1` vector length = 1 + 6 = 7):
//   commitment       — Poseidon-derived note commitment binding (nullifier, secret,
//                      asset_id, amount, pool_id).
//   amount_tag       — Poseidon-derived tag binding (amount, deposit_blind, asset_id,
//                      vault_addr_hash, chain_id). Operators reveal amount via
//                      the tag-blind tuple; this proof guarantees the disclosed
//                      amount is the SAME amount baked into `commitment`.
//   asset_id         — domain field (e.g., a Poseidon hash of the asset metadata
//                      address; the bridge picks the canonical id).
//   vault_addr_hash  — Poseidon-style 32-byte LE hash of the vault address.
//   chain_id         — Aptos chain id.
//   pool_id          — bridge pool identifier.
//
// Private inputs:
//   nullifier        — random 254-bit field element; user retains.
//   secret           — random 254-bit field element; user retains.
//   amount           — u64 deposit amount.
//   deposit_blind    — random blinding for amount_tag.
//
// Constraints:
//   1. amount fits in 64 bits (Num2Bits with 64 bits).
//   2. commitment == compose5(nullifier, secret, asset_id, amount, pool_id).
//   3. amount_tag == compose5(amount, deposit_blind, asset_id, vault_addr_hash, chain_id).
//
// Poseidon arity composition (matches Move-side Poseidon_Research/aptos_move/sources/poseidon_bn254.move):
//   Move side has hash_2(t=3) and hash_3(t=4); circomlib's Poseidon template
//   accepts arities 1..16 and matches the iden3 reference (Poseidon([0, ...inputs])
//   with capacity 0 in the t-input case). circomlibjs's poseidon() and the Move
//   poseidon_bn254::hash_n produce bit-identical outputs (validated by
//   Poseidon_Research's 30+ test vectors and re-confirmed in our parity script).
//
//   For the 5-input hash we compose:
//     compose5(a, b, c, d, e) = hash_2(hash_3(a, b, c), hash_2(d, e))
//
//   This requires only hash_2 and hash_3 on the Move side. The Move-side bridge
//   code (Gate 4b) MUST recompute commitment and amount_tag using the SAME
//   composition.

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// 5-input Poseidon composed from hash_3 + hash_2.
template Compose5() {
    signal input in[5];
    signal output out;

    component lo = Poseidon(3);
    lo.inputs[0] <== in[0];
    lo.inputs[1] <== in[1];
    lo.inputs[2] <== in[2];

    component hi = Poseidon(2);
    hi.inputs[0] <== in[3];
    hi.inputs[1] <== in[4];

    component top = Poseidon(2);
    top.inputs[0] <== lo.out;
    top.inputs[1] <== hi.out;

    out <== top.out;
}

template DepositBinding() {
    // -------- public inputs --------
    signal input commitment;
    signal input amount_tag;
    signal input asset_id;
    signal input vault_addr_hash;
    signal input chain_id;
    signal input pool_id;

    // -------- private inputs --------
    signal input nullifier;
    signal input secret;
    signal input amount;
    signal input deposit_blind;

    // 1. Range-check: amount fits in 64 bits.
    component amount_bits = Num2Bits(64);
    amount_bits.in <== amount;

    // 2. commitment = compose5(nullifier, secret, asset_id, amount, pool_id)
    component cmt = Compose5();
    cmt.in[0] <== nullifier;
    cmt.in[1] <== secret;
    cmt.in[2] <== asset_id;
    cmt.in[3] <== amount;
    cmt.in[4] <== pool_id;
    cmt.out === commitment;

    // 3. amount_tag = compose5(amount, deposit_blind, asset_id, vault_addr_hash, chain_id)
    component tag = Compose5();
    tag.in[0] <== amount;
    tag.in[1] <== deposit_blind;
    tag.in[2] <== asset_id;
    tag.in[3] <== vault_addr_hash;
    tag.in[4] <== chain_id;
    tag.out === amount_tag;
}

// Public inputs in this order: commitment, amount_tag, asset_id,
// vault_addr_hash, chain_id, pool_id.
component main { public [commitment, amount_tag, asset_id, vault_addr_hash, chain_id, pool_id] } = DepositBinding();
