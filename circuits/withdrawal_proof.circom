pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — withdraw circuit (v-next: ASP + hardened LeanIMT).
//
// 2026-05-30 (ASP curated-private-exit): replaced the single fixed-depth-20 MerkleInclusion
// with TWO hardened dynamic-depth LeanIMT inclusions sharing the SAME leaf (= the commitment,
// label≡commitment): (1) commitment ∈ state tree, (2) commitment ∈ ASP tree. Added 3 public
// inputs (asp_root, state_tree_depth, asp_tree_depth): 9 → 12 publics; on-chain public_inputs
// Fr vector + VK IC length = 1 + 12 = 13. deposit_binding.circom FROZEN. Confidential amount
// preserved (amount_p_digest, not plaintext). Shared templates in eunoma_templates.circom.
//
// Public inputs (declaration order — MUST byte-match Move publics vector + VK IC + publish entry):
//   [0]  root              — state tree root; must ∈ RootHistory window
//   [1]  nullifier_hash    — Poseidon(nullifier); marked spent on success
//   [2]  asset_id          — Poseidon-derived id (same as deposit)
//   [3]  recipient_hash    — Poseidon-of-recipient; binds payout target
//   [4]  amount_tag        — Compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence)
//   [5]  ca_payload_hash   — keccak256 of CA outbound payload
//   [6]  request_hash      — Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id)
//   [7]  vault_sequence    — anti-replay counter
//   [8]  amount_p_digest   — Poseidon8 over 8 × 128-bit amount_p limbs
//   [9]  asp_root          — ASP tree root; must ∈ KnownASPRoots recent window      (NEW)
//   [10] state_tree_depth  — actual depth of the state LeanIMT                       (NEW)
//   [11] asp_tree_depth    — actual depth of the ASP LeanIMT                         (NEW)

include "eunoma_templates.circom";

template WithdrawProof() {
    var CHAIN_ID = 2;        // Phase F W3 — hardcoded testnet chain id
    var POOL_ID  = 0;        // frozen testnet pool
    var MAX_DEPTH = 32;      // LeanIMT max depth (0xbow parity)

    // -------- public inputs (12) --------
    signal input root;
    signal input nullifier_hash;
    signal input asset_id;
    signal input recipient_hash;
    signal input amount_tag;
    signal input ca_payload_hash;
    signal input request_hash;
    signal input vault_sequence;
    signal input amount_p_digest;
    signal input asp_root;            // NEW
    signal input state_tree_depth;    // NEW
    signal input asp_tree_depth;      // NEW

    // -------- private inputs --------
    signal input nullifier;
    signal input secret;
    signal input withdraw_blind;
    signal input amount_p_limbs[8];
    signal input state_siblings[MAX_DEPTH];
    signal input state_leaf_index;
    signal input asp_siblings[MAX_DEPTH];
    signal input asp_leaf_index;

    // 1. Range-check each amount_p limb fits in 128 bits.
    component limb_bits[8];
    for (var i = 0; i < 8; i++) {
        limb_bits[i] = Num2Bits(128);
        limb_bits[i].in <== amount_p_limbs[i];
    }

    // 2. amount_p_digest = Compose8(amount_p_limbs[0..7]).
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

    // 4. State-tree inclusion: commitment ∈ state tree (root === public root).
    component state_incl = HardenedLeanIMTInclusion(MAX_DEPTH);
    state_incl.leaf <== cmt.out;
    state_incl.leafIndex <== state_leaf_index;
    state_incl.actualDepth <== state_tree_depth;
    for (var i = 0; i < MAX_DEPTH; i++) {
        state_incl.siblings[i] <== state_siblings[i];
    }
    state_incl.root === root;

    // 5. ASP-tree inclusion: SAME commitment ∈ ASP tree (root === public asp_root).
    component asp_incl = HardenedLeanIMTInclusion(MAX_DEPTH);
    asp_incl.leaf <== cmt.out;
    asp_incl.leafIndex <== asp_leaf_index;
    asp_incl.actualDepth <== asp_tree_depth;
    for (var i = 0; i < MAX_DEPTH; i++) {
        asp_incl.siblings[i] <== asp_siblings[i];
    }
    asp_incl.root === asp_root;

    // 6. nullifier_hash = Poseidon([nullifier]).
    component nh = Poseidon(1);
    nh.inputs[0] <== nullifier;
    nh.out === nullifier_hash;

    // 7. amount_tag = Compose6(amount_p_digest, withdraw_blind, recipient_hash, asset_id, CHAIN_ID, vault_sequence).
    component tag = Compose6();
    tag.in[0] <== amount_p_digest;
    tag.in[1] <== withdraw_blind;
    tag.in[2] <== recipient_hash;
    tag.in[3] <== asset_id;
    tag.in[4] <== CHAIN_ID;
    tag.in[5] <== vault_sequence;
    tag.out === amount_tag;

    // 8. request_hash = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, CHAIN_ID).
    component req = Compose6();
    req.in[0] <== amount_tag;
    req.in[1] <== recipient_hash;
    req.in[2] <== ca_payload_hash;
    req.in[3] <== asset_id;
    req.in[4] <== vault_sequence;
    req.in[5] <== CHAIN_ID;
    req.out === request_hash;
}

component main { public [
    root,
    nullifier_hash,
    asset_id,
    recipient_hash,
    amount_tag,
    ca_payload_hash,
    request_hash,
    vault_sequence,
    amount_p_digest,
    asp_root,
    state_tree_depth,
    asp_tree_depth
] } = WithdrawProof();
