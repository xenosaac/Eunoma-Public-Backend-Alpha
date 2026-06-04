pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — withdraw circuit (V4: ASP + hardened LeanIMT + partial-withdraw).
//
// 2026-05-30 (ASP curated-private-exit): replaced the single fixed-depth-20 MerkleInclusion
// with TWO hardened dynamic-depth LeanIMT inclusions sharing the SAME leaf (= the commitment):
// (1) commitment ∈ state tree, (2) commitment ∈ ASP tree. Added 3 public inputs
// (asp_root, state_tree_depth, asp_tree_depth): 9 → 12 publics.
//
// 2026-06-02 (V4 B′ partial-withdraw): use a pruned 5-public verifier to stay at deposit-level
// verifier cost. Publics are root, nullifier_hash, request_hash, asp_root, change_commitment.
// Move recomputes request_hash from public route args before verification, while the circuit
// constrains request_hash against private amount_tag/recipient_hash/ca_payload_hash/asset_id/
// vault_sequence. amount_p_digest and depths remain witness inputs constrained through
// amount_tag/commitment/LeanIMT.
// amount-conservation (B′): A_old = W + A_rem over 16-bit chunks, 2× LessEqThan(64), remainder-digest
// binding, and a fresh change-note Compose5. has_change gates full-spend (change_commitment = 0,
// W = A_old) vs partial-spend (emit a fresh change leaf). The change note reuses the SAME asset_id
// (same-asset change) and inherits the parent stable-label lineage — the parent ASP inclusion above
// already proves approval, so NO label is recomputed in withdraw (label stays PRIVATE + zero-cost;
// the spent note's `secret` private is already the deposit-time label-bound secret). Confidential
// amount preserved (amount_p_digest, not plaintext). Shared templates in eunoma_templates.circom.
//
// Public inputs (declaration order — MUST byte-match Move publics vector + VK IC + publish entry):
//   [0]  root              — state tree root; must ∈ RootHistory window
//   [1]  nullifier_hash    — Poseidon(nullifier); marked spent on success
//   [2]  request_hash      — Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id)
//   [3]  amount_p_digest   — Poseidon8 over 8 × 128-bit amount_p limbs (spent note's digest)
//   [4]  asp_root          — ASP tree root; must ∈ KnownASPRoots recent window
//   [5]  change_commitment — partial-withdraw change-note leaf; canonical empty value 0 when
//                            has_change=0 (full spend). Fresh Compose5(new_nullifier, new_secret,
//                            asset_id, amount_p_digest_rem, POOL_ID).

include "eunoma_templates.circom";

template WithdrawProof() {
    var CHAIN_ID = 2;        // Phase F W3 — hardcoded testnet chain id
    var POOL_ID  = 0;        // frozen testnet pool
    var MAX_DEPTH = 32;      // LeanIMT max depth (0xbow parity)
    var EMPTY_CHANGE = 0;    // V4 canonical empty change_commitment (LeanIMT empty-leaf sentinel;
                             // Poseidon outputs are ~never 0, so 0 unambiguously means "no change note")

    // -------- public inputs (5) --------
    signal input root;
    signal input nullifier_hash;
    signal input request_hash;
    signal input amount_p_digest;
    signal input asp_root;
    signal input change_commitment;   // NEW V4 (append-only public[12])

    // -------- private inputs --------
    signal input asset_id;
    signal input recipient_hash;
    signal input amount_tag;
    signal input ca_payload_hash;
    signal input vault_sequence;
    signal input state_tree_depth;
    signal input asp_tree_depth;
    signal input nullifier;
    signal input secret;
    signal input withdraw_blind;
    signal input amount_p_limbs[8];
    signal input state_siblings[MAX_DEPTH];
    signal input state_leaf_index;
    signal input asp_siblings[MAX_DEPTH];
    signal input asp_leaf_index;

    // -------- V4 partial-withdraw (B′) private inputs --------
    signal input new_nullifier;            // fresh change-note nullifier (≠ spent parent)
    signal input new_secret;               // fresh change-note secret
    signal input wd_amount_p_limbs[8];     // 8 × 128-bit limbs of the WITHDRAWN amount_p (W)
    signal input rem_amount_p_limbs[8];    // 8 × 128-bit limbs of the REMAINDER amount_p (A_rem)
    signal input old_amount_chunks[4];     // 4 × 16-bit base-2^16 chunks of A_old (spent note amount)
    signal input wd_chunks[4];             // 4 × 16-bit base-2^16 chunks of W (withdrawn amount)
    signal input rem_chunks[4];            // 4 × 16-bit base-2^16 chunks of A_rem (remainder amount)
    signal input has_change;               // bool: 1 ⇒ emit change note; 0 ⇒ full spend

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

    // ==========================================================================================
    // 9. V4 PARTIAL-WITHDRAW CONSERVATION (B′) — A_old = W + A_rem over base-2^16 chunks.
    //
    // A_old (the spent note's amount), W (withdrawn), A_rem (remainder) are each reconstructed from
    // 4 × 16-bit chunks = a 64-bit base-unit value. Num2Bits(16) range-checks every chunk into [0,2^16).
    // The base-2^16 recompose folds them into the 64-bit field values. has_change gates full vs partial.
    // ==========================================================================================

    // 9a. Range-check each chunk into [0, 2^16) and recompose the three 64-bit amounts.
    component old_bits[4];
    component wd_bits[4];
    component rem_bits[4];
    signal A_old_acc[5];
    signal W_acc[5];
    signal A_rem_acc[5];
    A_old_acc[0] <== 0;
    W_acc[0] <== 0;
    A_rem_acc[0] <== 0;
    for (var i = 0; i < 4; i++) {
        old_bits[i] = Num2Bits(16);
        old_bits[i].in <== old_amount_chunks[i];
        wd_bits[i] = Num2Bits(16);
        wd_bits[i].in <== wd_chunks[i];
        rem_bits[i] = Num2Bits(16);
        rem_bits[i].in <== rem_chunks[i];
        // base-2^16 little-endian recompose: acc += chunk[i] * 2^(16*i)
        A_old_acc[i + 1] <== A_old_acc[i] + old_amount_chunks[i] * (1 << (16 * i));
        W_acc[i + 1]     <== W_acc[i]     + wd_chunks[i]        * (1 << (16 * i));
        A_rem_acc[i + 1] <== A_rem_acc[i] + rem_chunks[i]       * (1 << (16 * i));
    }
    signal A_old;
    signal W;
    signal A_rem;
    A_old <== A_old_acc[4];
    W     <== W_acc[4];
    A_rem <== A_rem_acc[4];

    // 9b. Conservation: A_old === W + A_rem (linear; no field-overflow since all three < 2^64).
    A_old === W + A_rem;

    // 9c. W <= A_old AND A_rem <= A_old (defence-in-depth alongside the linear equality; blocks any
    //     wraparound-style forgery and pins both parts non-negative within [0, A_old]).
    component w_le = LessEqThan(64);
    w_le.in[0] <== W;
    w_le.in[1] <== A_old;
    w_le.out === 1;
    component rem_le = LessEqThan(64);
    rem_le.in[0] <== A_rem;
    rem_le.in[1] <== A_old;
    rem_le.out === 1;

    // 10. Remainder digest binding: amount_p_digest_rem = Compose8(rem_amount_p_limbs).
    component rem_digest = Compose8();
    for (var i = 0; i < 8; i++) {
        rem_digest.in[i] <== rem_amount_p_limbs[i];
    }
    signal amount_p_digest_rem;
    amount_p_digest_rem <== rem_digest.out;

    // 11. Fresh change-note commitment = Compose5(new_nullifier, new_secret, asset_id,
    //     amount_p_digest_rem, POOL_ID). Reuses the SAME asset_id signal (same-asset change) and
    //     inherits the parent stable-label lineage (parent ASP inclusion already proved approval).
    component change_cmt = Compose5();
    change_cmt.in[0] <== new_nullifier;
    change_cmt.in[1] <== new_secret;
    change_cmt.in[2] <== asset_id;
    change_cmt.in[3] <== amount_p_digest_rem;
    change_cmt.in[4] <== POOL_ID;

    // 12. has_change gating.
    //   - has_change ∈ {0,1}.
    //   - has_change = 1 (partial spend): change_commitment === change_cmt.out (emit the fresh leaf).
    //   - has_change = 0 (full spend):    change_commitment === EMPTY_CHANGE (0)  AND  W === A_old
    //                                     (⇒ A_rem === 0, no value re-committed).
    has_change * (has_change - 1) === 0;
    // change_commitment = has_change ? change_cmt.out : EMPTY_CHANGE
    change_commitment === EMPTY_CHANGE + has_change * (change_cmt.out - EMPTY_CHANGE);
    // full-spend forces W === A_old: (1 - has_change) * (A_old - W) === 0.
    (1 - has_change) * (A_old - W) === 0;
}

component main { public [
    root,
    nullifier_hash,
    request_hash,
    amount_p_digest,
    asp_root,
    change_commitment
] } = WithdrawProof();
