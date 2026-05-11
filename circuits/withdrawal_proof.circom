pragma circom 2.1.6;

// ConfidentialAPT shielded-bridge — withdraw circuit (Gate 6 / Mode C v2).
//
// Spec ref: HANDOFF Section 4 (withdraw flow) + Section 5.2 (circuit).
//
// Public inputs (in declaration order; snarkjs convention drives on-chain
// `public_inputs` Fr vector + `vk_uvw_gamma_g1` length = 1 + 9 = 10):
//   root              — must equal a value in `RootHistory.root_history`
//   nullifier_hash    — Poseidon(nullifier); marked spent on success
//   asset_id          — same Poseidon-derived id as deposit (matches VaultConfigCache)
//   recipient_hash    — Poseidon-of-recipient-address; binds payout target
//   amount_tag        — Poseidon-derived tag binding amount + recipient (see compose6)
//   ca_payload_hash   — keccak256 of CA outbound payload; binds operator attestation
//   request_hash      — Poseidon-derived binding (amount_tag + ca_payload + sequence)
//   vault_sequence    — anti-replay counter; bridge enforces strict +1
//   chain_id          — Aptos chain id (testnet=2)
//
// Private inputs:
//   nullifier         — random 254-bit field; user retains
//   secret            — random 254-bit field; user retains
//   amount            — u64 withdrawal amount
//   withdraw_blind    — random blinding for amount_tag
//   merkle_path[20]   — sibling node at each tree level
//   merkle_indices[20]— left/right (0/1) at each level (LSB-first bit decomposition of leaf index)
//
// ⚠️ Spec deviation note (intentional, documented):
//   HANDOFF §5.2 says "Recompute commitment from nullifier, secret, asset_id, amount" (4 inputs).
//   Actual deposit circuit (deposit_binding.circom) uses Compose5(nullifier, secret,
//   asset_id, amount, pool_id) — 5 inputs including pool_id. Withdraw MUST recompute
//   the same 5-input commitment (otherwise Merkle inclusion under root fails).
//   pool_id is HARDCODED here as POOL_ID_VALUE (currently 0) to keep public inputs at
//   HANDOFF's 9 mandatory; multi-pool support would require respec.
//
// Constants (must match Move-side aptosshield::confidential_bridge):
//   POOL_ID_VALUE = 0           (line ~92 in confidential_bridge.move)
//   TREE_DEPTH = 20             (matches batch_updater.ts + spike batch_root_update)
//
// Constraints (per HANDOFF §5.2):
//   1. amount fits in 64 bits (Num2Bits)
//   2. commitment = Compose5(nullifier, secret, asset_id, amount, pool_id) (matches deposit)
//   3. Merkle inclusion: leaf=commitment, path, indices → equals public root
//   4. nullifier_hash = Poseidon(nullifier) (1-input Poseidon, hash_1)
//   5. amount_tag = Compose6(amount, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence)
//   6. request_hash = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id)
//   7. Public input equality wires (handled implicitly by signal === checks above)

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/switcher.circom";

// 5-input Poseidon (matches deposit_binding.circom Compose5 exactly).
// compose5(a,b,c,d,e) = hash_2(hash_3(a,b,c), hash_2(d,e))
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
// Uses 2× hash_3 + 1× hash_2 = 3 Poseidon calls. Off-chain operator code
// (build_testnet_withdraw_proof.ts) MUST use the SAME composition.
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

// Merkle inclusion verifier (binary tree, Poseidon hash_2 nodes).
// At each level: if path_index[i] == 0, current is LEFT child → next = poseidon2(current, sibling)
//                if path_index[i] == 1, current is RIGHT child → next = poseidon2(sibling, current)
// Matches batch_updater.ts frontierInsert convention (hash_2 over (left, right)).
template MerkleInclusion(depth) {
    signal input leaf;
    signal input root;
    signal input path[depth];
    signal input path_index[depth];  // each must be 0 or 1

    signal cur[depth + 1];
    cur[0] <== leaf;

    component hashers[depth];
    // Phase F W4: switch from 4-mul branch-free mux to circomlib Switcher (1 mul/level).
    //   Switcher: aux = (R-L)*sel; outL = aux+L; outR = -aux+R
    // Same semantics as before: path_index==0 -> (cur, sibling); path_index==1 -> (sibling, cur).
    component sw[depth];

    for (var i = 0; i < depth; i++) {
        // Force path_index to be 0 or 1 (Switcher does NOT enforce this).
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
    // -------- public inputs (10 total: 9 mandatory per HANDOFF + pool_id is hardcoded constant) --------
    signal input root;
    signal input nullifier_hash;
    signal input asset_id;
    signal input recipient_hash;
    signal input amount_tag;
    signal input ca_payload_hash;
    signal input request_hash;
    signal input vault_sequence;
    signal input chain_id;

    // -------- private inputs --------
    signal input nullifier;
    signal input secret;
    signal input amount;
    signal input withdraw_blind;
    signal input merkle_path[20];
    signal input merkle_indices[20];

    // ====================== Constraints ======================

    // 1. amount fits in 64 bits.
    component amount_bits = Num2Bits(64);
    amount_bits.in <== amount;

    // 2. Recompute commitment using the SAME formula as deposit_binding.circom Compose5.
    //    pool_id is HARDCODED as POOL_ID_VALUE (= 0 currently per Move-side
    //    `aptosshield::confidential_bridge::POOL_ID_VALUE`). If pool_id ever changes,
    //    this circuit must be regenerated and old commitments will not be withdrawable.
    component cmt = Compose5();
    cmt.in[0] <== nullifier;
    cmt.in[1] <== secret;
    cmt.in[2] <== asset_id;
    cmt.in[3] <== amount;
    cmt.in[4] <== 0;  // POOL_ID_VALUE = 0 (frozen testnet pool)
    // cmt.out is the leaf for Merkle inclusion below (no public-input check;
    // commitment value is private here — only the root inclusion is public).

    // 3. Merkle inclusion: cmt.out at indexed leaf position must hash up to root.
    component merkle = MerkleInclusion(20);
    merkle.leaf <== cmt.out;
    merkle.root <== root;
    for (var i = 0; i < 20; i++) {
        merkle.path[i]       <== merkle_path[i];
        merkle.path_index[i] <== merkle_indices[i];
    }

    // 4. nullifier_hash = Poseidon([nullifier]) (1-input Poseidon = hash_1; circomlib supports arity 1)
    component nh = Poseidon(1);
    nh.inputs[0] <== nullifier;
    nh.out === nullifier_hash;

    // 5. amount_tag = Compose6(amount, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence)
    component tag = Compose6();
    tag.in[0] <== amount;
    tag.in[1] <== withdraw_blind;
    tag.in[2] <== recipient_hash;
    tag.in[3] <== asset_id;
    tag.in[4] <== chain_id;
    tag.in[5] <== vault_sequence;
    tag.out === amount_tag;

    // 6. request_hash = Compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id)
    component req = Compose6();
    req.in[0] <== amount_tag;
    req.in[1] <== recipient_hash;
    req.in[2] <== ca_payload_hash;
    req.in[3] <== asset_id;
    req.in[4] <== vault_sequence;
    req.in[5] <== chain_id;
    req.out === request_hash;

    // (7. Public input equality is enforced implicitly by `===` constraints above.)
}

// Public inputs in this order: root, nullifier_hash, asset_id, recipient_hash,
// amount_tag, ca_payload_hash, request_hash, vault_sequence, chain_id.
component main { public [
    root,
    nullifier_hash,
    asset_id,
    recipient_hash,
    amount_tag,
    ca_payload_hash,
    request_hash,
    vault_sequence,
    chain_id
] } = WithdrawProof();
