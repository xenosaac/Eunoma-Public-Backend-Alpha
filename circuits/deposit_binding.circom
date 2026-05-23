pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — deposit-binding circuit (Gate 4a, A6 binding).
//
// Spec ref: HANDOFF Section 5.1 + plans/continue-from-the-jazzy-ocean.md (A6 design).
//
// 2026-05-23 (Stage 2 A6 + Approach 4):
//   - Replaced plaintext `amount` in commitment + amount_tag with `amount_p_digest`,
//     a Poseidon8 over 8 × 128-bit little-endian limbs of the 4 × 32B Ristretto
//     compressed amount_p points (Aptos CA σ-proto's Pedersen commitments of
//     amount chunks). This makes commitment leaf carry the SAME amount_p that the
//     framework σ-proto will later verify against the vault's CA balance flow.
//     Withdraw circuit's Merkle inclusion + Move byte-cross-check of amount_p
//     together force withdraw amount == deposit amount (Pedersen DL binding).
//   - Why limbs: compressed Ristretto bytes are not guaranteed < BN254 Fr prime
//     (~2^253.5), so we split each 32B into 2 × 16B (< 2^128 fits Fr trivially)
//     before Poseidon hashing.
//   - Eunoma deposit Move bridge recomputes amount_p_digest from the 14-CA-args
//     amount_p (same limb split + Poseidon8) and passes as public input.
//
// Public inputs (in declaration order; snarkjs convention drives on-chain
// `public_inputs` Fr vector + `vk_uvw_gamma_g1` length = 1 + 5 = 6):
//   commitment       — Poseidon Compose5(nullifier, secret, asset_id, amount_p_digest, pool_id)
//   amount_tag       — Poseidon Compose5(amount_p_digest, deposit_blind, asset_id, vault_addr_hash, chain_id)
//   asset_id         — Poseidon-derived id from VaultPublicInputsV2
//   vault_addr_hash  — Poseidon-style 32-byte LE hash of vault address
//   amount_p_digest  — Poseidon8 over 8 × 128-bit limbs of 4 × 32B Ristretto amount_p (NEW)
//
// Private inputs:
//   nullifier        — random 254-bit field; user retains
//   secret           — random 254-bit field; user retains
//   deposit_blind    — random blinding for amount_tag
//   amount_p_limbs[8]— 4 amount_p points × 2 limbs each (lo,hi) of 128 bits
//                      Order: [amount_p[0]_lo, amount_p[0]_hi, amount_p[1]_lo, amount_p[1]_hi, ...]
//
// Constraints:
//   1. Each amount_p_limbs[i] fits in 128 bits.
//   2. amount_p_digest == Poseidon8(amount_p_limbs[0..7]).
//   3. commitment == Compose5(nullifier, secret, asset_id, amount_p_digest, pool_id).
//   4. amount_tag == Compose5(amount_p_digest, deposit_blind, asset_id, vault_addr_hash, chain_id).
//
// NOTE: plaintext `amount` REMOVED from circuit. Framework σ-proto + Bulletproofs
//       on the 14 CA args binds amount_p to actual transferred amount (range +
//       balance flow). Eunoma layer only enforces amount_p_digest consistency.

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Phase F W3 — chain_id and pool_id are hardcoded compile-time constants
// declared inside the template (circom 2.x requires var inside templates/functions).
// This VK is testnet-only (CHAIN_ID = 2 = Aptos testnet, POOL_ID = 0 = frozen pool).

// 5-input Poseidon composed from hash_3 + hash_2.
// compose5(a, b, c, d, e) = hash_2(hash_3(a, b, c), hash_2(d, e))
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

// 8-input Poseidon composed from 3× hash_3 + 1× hash_2 (Move parity).
// compose8(a..h) = hash_3(hash_3(a,b,c), hash_3(d,e,f), hash_2(g,h))
// Move-side (poseidon_bn254 only exposes hash_2/hash_3) computes the same value:
//   a = hash_3(in[0], in[1], in[2])
//   b = hash_3(in[3], in[4], in[5])
//   c = hash_2(in[6], in[7])
//   digest = hash_3(a, b, c)
// This is NOT the same as circomlib Poseidon(8) which uses t=9 fixed-arity Poseidon.
template Compose8() {
    signal input in[8];
    signal output out;

    component a = Poseidon(3);
    a.inputs[0] <== in[0];
    a.inputs[1] <== in[1];
    a.inputs[2] <== in[2];

    component b = Poseidon(3);
    b.inputs[0] <== in[3];
    b.inputs[1] <== in[4];
    b.inputs[2] <== in[5];

    component c = Poseidon(2);
    c.inputs[0] <== in[6];
    c.inputs[1] <== in[7];

    component top = Poseidon(3);
    top.inputs[0] <== a.out;
    top.inputs[1] <== b.out;
    top.inputs[2] <== c.out;

    out <== top.out;
}

template DepositBinding() {
    // Phase F W3 — hardcoded chain_id + pool_id (testnet variant).
    var CHAIN_ID = 2;
    var POOL_ID  = 0;

    // -------- public inputs (5) --------
    signal input commitment;
    signal input amount_tag;
    signal input asset_id;
    signal input vault_addr_hash;
    signal input amount_p_digest;

    // -------- private inputs --------
    signal input nullifier;
    signal input secret;
    signal input deposit_blind;
    // 4 × 32B compressed Ristretto amount_p split into 2 × 128-bit LE limbs each.
    // Index order MUST match Move-side compute_amount_p_digest (file:line tbd in Stage 3).
    signal input amount_p_limbs[8];

    // 1. Range-check each limb fits in 128 bits (compressed Ristretto byte halves).
    component limb_bits[8];
    for (var i = 0; i < 8; i++) {
        limb_bits[i] = Num2Bits(128);
        limb_bits[i].in <== amount_p_limbs[i];
    }

    // 2. amount_p_digest = Compose8(amount_p_limbs[0..7]) — uses hash_3/hash_2 tree
    //    matching Move's eunoma_pool::poseidon_bn254 (only exposes hash_2 + hash_3).
    component digest = Compose8();
    for (var i = 0; i < 8; i++) {
        digest.in[i] <== amount_p_limbs[i];
    }
    digest.out === amount_p_digest;

    // 3. commitment = Compose5(nullifier, secret, asset_id, amount_p_digest, POOL_ID).
    component cmt = Compose5();
    cmt.in[0] <== nullifier;
    cmt.in[1] <== secret;
    cmt.in[2] <== asset_id;
    cmt.in[3] <== amount_p_digest;
    cmt.in[4] <== POOL_ID;
    cmt.out === commitment;

    // 4. amount_tag = Compose5(amount_p_digest, deposit_blind, asset_id, vault_addr_hash, CHAIN_ID).
    component tag = Compose5();
    tag.in[0] <== amount_p_digest;
    tag.in[1] <== deposit_blind;
    tag.in[2] <== asset_id;
    tag.in[3] <== vault_addr_hash;
    tag.in[4] <== CHAIN_ID;
    tag.out === amount_tag;
}

// Public inputs in this order: commitment, amount_tag, asset_id, vault_addr_hash, amount_p_digest.
component main { public [commitment, amount_tag, asset_id, vault_addr_hash, amount_p_digest] } = DepositBinding();
