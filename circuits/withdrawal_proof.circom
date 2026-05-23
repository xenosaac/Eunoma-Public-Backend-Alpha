pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — withdraw circuit (Gate 6 / A6 binding).
//
// Spec ref: HANDOFF Section 4 (withdraw flow) + Section 5.2 (circuit)
//           + plans/continue-from-the-jazzy-ocean.md (A6 design).
//
// 2026-05-23 (Stage 2 A6 + Approach 4):
//   - Replaced plaintext `amount` in commitment + amount_tag with `amount_p_digest`
//     (matches deposit_binding.circom). Withdraw user provides amount_p_limbs[8]
//     (from note); circuit recomputes the digest + the Compose5 commitment + the
//     Compose6 amount_tag. Move bridge byte-cross-checks Groth16 public output
//     amount_p_digest vs digest recomputed from the 14-CA-args amount_p.
//   - Pedersen binding (same blind from HKDF(note_secret) at deposit + withdraw)
//     ensures withdraw σ-proto amount_p_wd byte-equals deposit amount_p_dep, which
//     equals leaf's amount_p_digest pre-image — forcing withdraw amount = deposit
//     amount (vote conservation).
//
// Public inputs (in declaration order; snarkjs convention drives on-chain
// `public_inputs` Fr vector + `vk_uvw_gamma_g1` length = 1 + 9 = 10):
//   root              — must equal a value in `RootHistory.root_history`
//   nullifier_hash    — Poseidon(nullifier); marked spent on success
//   asset_id          — same Poseidon-derived id as deposit
//   recipient_hash    — Poseidon-of-recipient-address; binds payout target
//   amount_tag        — Compose5(amount_p_digest, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence)
//                       — NOTE: was Compose6(amount, ...); now Compose6(amount_p_digest, ...)
//   ca_payload_hash   — keccak256 of CA outbound payload; binds operator attestation
//   request_hash      — Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id)
//   vault_sequence    — anti-replay counter; bridge enforces strict +1
//   amount_p_digest   — Poseidon8 over 8 × 128-bit limbs of 4 × 32B Ristretto amount_p (NEW)
//
// Private inputs:
//   nullifier         — random 254-bit field; user retains
//   secret            — random 254-bit field; user retains
//   withdraw_blind    — random blinding for amount_tag
//   merkle_path[20]   — sibling node at each tree level
//   merkle_indices[20]— left/right (0/1) at each level
//   amount_p_limbs[8] — 4 amount_p points × 2 limbs each (lo,hi) of 128 bits
//
// Constants (must match Move-side aptosshield::confidential_bridge):
//   POOL_ID_VALUE = 0
//   TREE_DEPTH = 20
//
// Constraints:
//   1. Each amount_p_limbs[i] fits in 128 bits.
//   2. amount_p_digest = Poseidon8(amount_p_limbs[0..7]).
//   3. commitment = Compose5(nullifier, secret, asset_id, amount_p_digest, POOL_ID) (matches deposit).
//   4. Merkle inclusion: leaf=commitment, path, indices → equals public root.
//   5. nullifier_hash = Poseidon(nullifier).
//   6. amount_tag = Compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence).
//   7. request_hash = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id).
//
// NOTE: plaintext `amount` REMOVED from circuit. Same rationale as deposit_binding.

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// 5-input Poseidon (matches deposit_binding.circom Compose5 exactly).
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

// 6-input Poseidon: compose6(a,b,c,d,e,f) = hash_2(hash_3(a,b,c), hash_3(d,e,f))
template Compose6() {
    signal input in[6];
    signal output out;

    component lo = Poseidon(3);
    lo.inputs[0] <== in[0];
    lo.inputs[1] <== in[1];
    lo.inputs[2] <== in[2];

    component hi = Poseidon(3);
    hi.inputs[0] <== in[3];
    hi.inputs[1] <== in[4];
    hi.inputs[2] <== in[5];

    component top = Poseidon(2);
    top.inputs[0] <== lo.out;
    top.inputs[1] <== hi.out;

    out <== top.out;
}

// 8-input Poseidon composed from 3× hash_3 + 1× hash_2 (Move parity).
// compose8(a..h) = hash_3(hash_3(a,b,c), hash_3(d,e,f), hash_2(g,h))
// Matches deposit_binding.circom Compose8 + Move eunoma_pool::poseidon_bn254 path.
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

// Merkle inclusion verifier (binary tree, Poseidon hash_2 nodes).
template MerkleInclusion(depth) {
    signal input leaf;
    signal input root;
    signal input path[depth];
    signal input path_index[depth];

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hashers[depth];
    component sw[depth];

    for (var i = 0; i < depth; i++) {
        path_index[i] * (path_index[i] - 1) === 0;

        sw[i] = Switcher();
        sw[i].sel <== path_index[i];
        sw[i].L   <== cur[i];
        sw[i].R   <== path[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== sw[i].outL;
        hashers[i].inputs[1] <== sw[i].outR;
        cur[i + 1] <== hashers[i].out;
    }

    cur[depth] === root;
}

template WithdrawProof() {
    // Phase F W3 — hardcoded chain_id (testnet variant).
    var CHAIN_ID = 2;

    // -------- public inputs (9) --------
    signal input root;
    signal input nullifier_hash;
    signal input asset_id;
    signal input recipient_hash;
    signal input amount_tag;
    signal input ca_payload_hash;
    signal input request_hash;
    signal input vault_sequence;
    signal input amount_p_digest;

    // -------- private inputs --------
    signal input nullifier;
    signal input secret;
    signal input withdraw_blind;
    signal input merkle_path[20];
    signal input merkle_indices[20];
    signal input amount_p_limbs[8];

    // ====================== Constraints ======================

    // 1. Range-check each amount_p limb fits in 128 bits.
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

    // 3. Recompute commitment = Compose5(nullifier, secret, asset_id, amount_p_digest, POOL_ID).
    //    Matches deposit_binding.circom Compose5 exactly. POOL_ID hardcoded 0 (frozen testnet pool).
    component cmt = Compose5();
    cmt.in[0] <== nullifier;
    cmt.in[1] <== secret;
    cmt.in[2] <== asset_id;
    cmt.in[3] <== amount_p_digest;
    cmt.in[4] <== 0;

    // 4. Merkle inclusion: cmt.out at indexed leaf must hash up to root.
    component merkle = MerkleInclusion(20);
    merkle.leaf <== cmt.out;
    merkle.root <== root;
    for (var i = 0; i < 20; i++) {
        merkle.path[i]       <== merkle_path[i];
        merkle.path_index[i] <== merkle_indices[i];
    }

    // 5. nullifier_hash = Poseidon([nullifier]).
    component nh = Poseidon(1);
    nh.inputs[0] <== nullifier;
    nh.out === nullifier_hash;

    // 6. amount_tag = Compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, CHAIN_ID, vault_sequence).
    component tag = Compose6();
    tag.in[0] <== amount_p_digest;
    tag.in[1] <== withdraw_blind;
    tag.in[2] <== recipient_hash;
    tag.in[3] <== asset_id;
    tag.in[4] <== CHAIN_ID;
    tag.in[5] <== vault_sequence;
    tag.out === amount_tag;

    // 7. request_hash = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, CHAIN_ID).
    component req = Compose6();
    req.in[0] <== amount_tag;
    req.in[1] <== recipient_hash;
    req.in[2] <== ca_payload_hash;
    req.in[3] <== asset_id;
    req.in[4] <== vault_sequence;
    req.in[5] <== CHAIN_ID;
    req.out === request_hash;
}

// Public inputs in this order: root, nullifier_hash, asset_id, recipient_hash,
// amount_tag, ca_payload_hash, request_hash, vault_sequence, amount_p_digest.
component main { public [
    root,
    nullifier_hash,
    asset_id,
    recipient_hash,
    amount_tag,
    ca_payload_hash,
    request_hash,
    vault_sequence,
    amount_p_digest
] } = WithdrawProof();
