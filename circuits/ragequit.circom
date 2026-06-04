pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — RAGEQUIT circuit (transparent original-path exit).
//
// 2026-05-30 (ASP): the exit path for a deposit that is NOT in the ASP set (never approved /
// revoked / owner doesn't want to wait). The ORIGINAL depositor reclaims their funds back to
// the original deposit address — transparent (commitment revealed), no ASP inclusion.
//
// Differs from withdraw: (a) NO ASP inclusion; (b) commitment is a PUBLIC input (the deposit↔exit
// link is intentionally public — that is what makes this a non-private, anti-laundering exit);
// (c) the Move `ragequit` entry enforces recipient == deposit_sender[commitment]. Amount stays
// CONFIDENTIAL (amount_p_digest is private; the CA transfer back is confidential).
//
// The circuit binds the revealed commitment to its nullifier (so you can only mark-spent the
// nullifier of the commitment you actually reclaim) and proves the commitment is a real deposit
// (state-tree inclusion). Shared templates in eunoma_templates.circom.
//
// Public inputs (5 → IC length 6... NOTE: 4 publics → on-chain public_inputs len = 1 + 4 = 5):
//   [0] commitment       — REVEALED (transparent deposit↔exit link)
//   [1] nullifier_hash    — Poseidon(nullifier); marked spent on success
//   [2] root              — state tree root; must ∈ RootHistory window
//   [3] state_tree_depth  — actual depth of the state LeanIMT
//
// Private inputs:
//   nullifier, secret, asset_id, amount_p_digest   — commitment preimage (amount stays private)
//   label_scope[3], label_nonce                    — V4 D6 stable-label inputs (recompute secret_bound)
//   state_siblings[MAX_DEPTH], state_leaf_index     — state LeanIMT co-path
//
// V4 D6: the ragequit commitment recompute MUST fold the SAME stable label as the deposit circuit
// (secret_bound = hash_2(secret, hash_2(hash_3(label_scope), label_nonce))) so every V4 deposit can
// ragequit — the recomputed commitment must match the deposit leaf BYTE-FOR-BYTE.

include "eunoma_templates.circom";

template RagequitProof() {
    var POOL_ID  = 0;
    var MAX_DEPTH = 32;

    // -------- public inputs (4) --------
    signal input commitment;          // REVEALED
    signal input nullifier_hash;
    signal input root;
    signal input state_tree_depth;

    // -------- private inputs --------
    signal input nullifier;
    signal input secret;              // RAW secret entropy (same as deposit); folded with label below.
    signal input asset_id;
    signal input amount_p_digest;     // stays private (amount confidential)
    signal input label_scope[3];      // V4 D6 stable-label scope (PRIVATE; IC stays 5)
    signal input label_nonce;         // V4 D6 per-deposit label nonce (PRIVATE)
    signal input state_siblings[MAX_DEPTH];
    signal input state_leaf_index;

    // 1a. V4 D6: recompute the SAME label-bound secret the deposit circuit committed.
    //     secret_bound = hash_2(secret, label); label = hash_2(hash_3(label_scope), label_nonce).
    component bind = BindSecretWithLabel();
    bind.secret_raw <== secret;
    bind.label_scope[0] <== label_scope[0];
    bind.label_scope[1] <== label_scope[1];
    bind.label_scope[2] <== label_scope[2];
    bind.label_nonce <== label_nonce;

    // 1b. commitment = Compose5(nullifier, secret_bound, asset_id, amount_p_digest, POOL_ID).
    //     Binds the revealed commitment to (nullifier, secret, label) so the nullifier can't be swapped.
    component cmt = Compose5();
    cmt.in[0] <== nullifier;
    cmt.in[1] <== bind.secret_bound;
    cmt.in[2] <== asset_id;
    cmt.in[3] <== amount_p_digest;
    cmt.in[4] <== POOL_ID;
    cmt.out === commitment;

    // 2. nullifier_hash = Poseidon([nullifier]).
    component nh = Poseidon(1);
    nh.inputs[0] <== nullifier;
    nh.out === nullifier_hash;

    // 3. State-tree inclusion: commitment ∈ state tree (root === public root). NO ASP inclusion.
    component state_incl = HardenedLeanIMTInclusion(MAX_DEPTH);
    state_incl.leaf <== commitment;
    state_incl.leafIndex <== state_leaf_index;
    state_incl.actualDepth <== state_tree_depth;
    for (var i = 0; i < MAX_DEPTH; i++) {
        state_incl.siblings[i] <== state_siblings[i];
    }
    state_incl.root === root;
}

component main { public [
    commitment,
    nullifier_hash,
    root,
    state_tree_depth
] } = RagequitProof();
