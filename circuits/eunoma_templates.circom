pragma circom 2.1.6;

// Eunoma shared circuit templates — single source of truth for the Poseidon composers
// and the hardened LeanIMT inclusion proof. Included by withdrawal_proof.circom AND
// ragequit.circom so the two circuits CANNOT diverge on the security-critical LeanIMT.
//
// Compose5/6/8 are byte-parity with deposit_binding.circom (FROZEN) + Move
// eunoma_pool::poseidon_bn254 (hash_2 / hash_3 only).

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// 5-input Poseidon: compose5(a,b,c,d,e) = hash_2(hash_3(a,b,c), hash_2(d,e))
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

// 8-input Poseidon: compose8(a..h) = hash_3(hash_3(a,b,c), hash_3(d,e,f), hash_2(g,h))
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

// =============================================================================================
// DepositLabel — V4 0xbow STABLE-LABEL gadget (D6, 2026-06-01).
//
// LOCKED SPEC — deposit_binding.circom + ragequit.circom MUST instantiate this template with the
// SAME signal wiring, and the off-chain ASP builder + Move recompute MUST replicate it byte-for-byte
// (Poseidon hash_3 then hash_2 ONLY — uses the existing circomlib Poseidon(3)/Poseidon(2) gadgets;
// NO keccak in-circuit). Move side mirrors via eunoma_pool::poseidon_bn254::{hash_3,hash_2}, which
// are Poseidon([0,a,b,c]) / Poseidon([0,a,b]) — byte-identical to circomlib Poseidon(3)/Poseidon(2).
//
//   label = hash_2( hash_3(label_scope0, label_scope1, label_scope2), label_nonce )
//
//   - The inner Poseidon(3) hashes a 3-element DEPOSIT-SCOPE tuple
//     (label_scope0, label_scope1, label_scope2). The scope identifies the pool/epoch/domain
//     under which the deposit was approved (0xbow "pool_scope"); it is the same for every deposit
//     curated under one ASP scope.
//   - The outer Poseidon(2) folds in label_nonce — the per-DEPOSIT nonce that makes each deposit's
//     label unique and unlinkable. Fixed once at deposit time; every descendant (change note) of a
//     deposit shares ONE label so a still-approved label is re-listed in every fresh ASP set
//     (honest users never age out) and revocation = OMIT the label (descendants die automatically).
//
// FOLD RULE (how `label` enters the commitment so the V4 commitment preimage breaks
// label≡commitment while keeping the withdraw circuit's Compose5 BYTE-IDENTICAL):
//
//   secret_bound = hash_2(secret_raw, label)              // bind the label into the secret slot
//   commitment   = Compose5(nullifier, secret_bound, asset_id, amount_p_digest, POOL_ID)
//
//   * The depositor PERSISTS `secret_bound` as the note's `secret` field. WITHDRAW then feeds
//     `secret_bound` directly into its UNCHANGED Compose5 (no label gadget, no label recompute in
//     withdraw → label stays PRIVATE and zero-cost in withdraw, matching CP0). DEPOSIT and RAGEQUIT
//     both instantiate BindSecretWithLabel from raw (secret_raw, label_scope[3], label_nonce) so
//     their commitment recompute matches the deposit leaf byte-for-byte.
//   * `label` is a deposit-scoped PRIVATE input in deposit + ragequit (deposit publics stay 5 / IC 6;
//     ragequit publics stay 4 / IC 5). The ASP builder recomputes each per-deposit label off-chain
//     from (label_scope, label_nonce) to populate the ASP set leaves.
//
// CONSTRAINT COST: one Poseidon(3) + one Poseidon(2) for the label, plus one Poseidon(2) for the
// secret fold. Measured upper-bound delta (CP0 deposit_label probe) = +1,122 over base Compose5.
template DepositLabel() {
    signal input label_scope[3];
    signal input label_nonce;
    signal output label;

    component inner = Poseidon(3);   // hash_3 over the deposit-scope tuple
    inner.inputs[0] <== label_scope[0];
    inner.inputs[1] <== label_scope[1];
    inner.inputs[2] <== label_scope[2];

    component outer = Poseidon(2);   // hash_2 folding in the per-deposit nonce
    outer.inputs[0] <== inner.out;
    outer.inputs[1] <== label_nonce;

    label <== outer.out;
}

// BindSecretWithLabel — folds the stable label into the secret slot of the Compose5 commitment
// preimage. `secret_bound` is what the depositor persists as the note secret; the withdraw circuit
// consumes it directly. deposit_binding.circom + ragequit.circom instantiate this; the witness
// builders (CP3) mirror `hash_2(secret_raw, hash_2(hash_3(scope), nonce))` byte-for-byte.
template BindSecretWithLabel() {
    signal input secret_raw;
    signal input label_scope[3];
    signal input label_nonce;
    signal output secret_bound;
    signal output label;

    component lbl = DepositLabel();
    lbl.label_scope[0] <== label_scope[0];
    lbl.label_scope[1] <== label_scope[1];
    lbl.label_scope[2] <== label_scope[2];
    lbl.label_nonce <== label_nonce;
    label <== lbl.label;

    component fold = Poseidon(2);   // hash_2(secret_raw, label)
    fold.inputs[0] <== secret_raw;
    fold.inputs[1] <== lbl.label;
    secret_bound <== fold.out;
}

// Hardened LeanIMT inclusion (dynamic depth, Poseidon hash_2 nodes).
//
// LeanIMT semantics: a node whose sibling is empty (==0) propagates up unchanged; a node
// with a real sibling hashes Poseidon(left,right) ordered by the path bit. Poseidon outputs
// are ~never 0, so a 0 sibling unambiguously marks an empty (frontier / above-root) position.
//
// HARDENING (vs 0xbow merkleTree.circom whose actualDepth is "// unused" + zero-sibling
// short-circuit): actualDepth ∈ [1,maxDepth] range-checked AND bound — for every level
// i ≥ actualDepth, sibling[i] === 0 AND path_bit[i] === 0 (leafIndex < 2^actualDepth).
// This blocks the "claim a shallower depth + smuggle non-empty siblings to forge a different
// root" attack; above actualDepth every level carries unchanged so node[maxDepth] == the root.
template HardenedLeanIMTInclusion(maxDepth) {
    signal input leaf;
    signal input leafIndex;
    signal input siblings[maxDepth];
    signal input actualDepth;
    signal output root;

    // actualDepth ∈ [1, maxDepth]
    component dLo = GreaterEqThan(8);
    dLo.in[0] <== actualDepth;
    dLo.in[1] <== 1;
    dLo.out === 1;
    component dHi = LessEqThan(8);
    dHi.in[0] <== actualDepth;
    dHi.in[1] <== maxDepth;
    dHi.out === 1;

    // path bits (little-endian: bit i selects left/right at level i)
    component idx = Num2Bits(maxDepth);
    idx.in <== leafIndex;

    signal node[maxDepth + 1];
    node[0] <== leaf;

    component active[maxDepth];
    component sibZero[maxDepth];
    component h[maxDepth];
    signal left[maxDepth];
    signal right[maxDepth];
    signal hashed[maxDepth];
    signal climbed[maxDepth];
    signal isActive[maxDepth];
    signal notEmpty[maxDepth];

    for (var i = 0; i < maxDepth; i++) {
        // isActive = (i < actualDepth)
        active[i] = LessThan(8);
        active[i].in[0] <== i;
        active[i].in[1] <== actualDepth;
        isActive[i] <== active[i].out;

        // ordered pair by path bit: bit 0 → (node, sib); bit 1 → (sib, node)
        left[i]  <== node[i] + idx.out[i] * (siblings[i] - node[i]);
        right[i] <== siblings[i] + idx.out[i] * (node[i] - siblings[i]);
        h[i] = Poseidon(2);
        h[i].inputs[0] <== left[i];
        h[i].inputs[1] <== right[i];
        hashed[i] <== h[i].out;

        // empty sibling (==0) → propagate node[i]; else → hashed
        sibZero[i] = IsZero();
        sibZero[i].in <== siblings[i];
        notEmpty[i] <== 1 - sibZero[i].out;
        climbed[i] <== node[i] + notEmpty[i] * (hashed[i] - node[i]);

        // above actualDepth → carry node[i] unchanged; else → climbed
        node[i + 1] <== node[i] + isActive[i] * (climbed[i] - node[i]);

        // HARDENING: above actualDepth, sibling and path bit must both be 0
        (1 - isActive[i]) * siblings[i] === 0;
        (1 - isActive[i]) * idx.out[i] === 0;
    }

    root <== node[maxDepth];
}
