#!/usr/bin/env node
// Build a valid withdraw input (leaf at index 0, empty siblings).
// Output: inputs/withdraw_valid_input.json

const path = require('path');
const fs = require('fs');
const { buildPoseidon } = require('circomlibjs');

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const h2 = (a, b) => F.toObject(poseidon([a, b]));
    const h3 = (a, b, c) => F.toObject(poseidon([a, b, c]));
    const h1 = (a) => F.toObject(poseidon([a]));

    const compose5 = (a, b, c, d, e) => h2(h3(a, b, c), h2(d, e));
    const compose6 = (a, b, c, d, e, f) => h2(h3(a, b, c), h3(d, e, f));

    // ----- private witness (matches deposit input) -----
    const nullifier      = 12345678901234567890123456789012345678901234567890n;
    const secret         = 98765432109876543210987654321098765432109876543210n;
    const amount         = 1_000_000_000n;
    const deposit_blind  = 11111111111111111111111111111111111111111111111111n; // unused for withdraw, but for ref
    const withdraw_blind = 22222222222222222222222222222222222222222222222222n;

    const asset_id        = 7n;
    const chain_id        = 2n;
    const POOL_ID         = 0n;
    const vault_sequence  = 1n;

    // recipient_hash + ca_payload_hash: arbitrary fixed field elements (treated as opaque publics)
    const recipient_hash  = 33333333333333333333333333333333333333333333333333n;
    const ca_payload_hash = 44444444444444444444444444444444444444444444444444n;

    // 1. commitment (compose5 with pool_id=0)
    const commitment = compose5(nullifier, secret, asset_id, amount, POOL_ID);

    // 2. merkle: leaf at index 0, all siblings = "zero" subtree.
    //    For Aptos-style Poseidon-2 frontier tree starting empty, sibling at level k = ZERO_HASH[k]
    //    where ZERO_HASH[0] = 0 and ZERO_HASH[k+1] = h2(ZERO_HASH[k], ZERO_HASH[k]).
    //    BUT our root is computed as path from leaf=commitment up. With leaf at index 0:
    //      cur[0] = commitment
    //      sibling[k] = ZERO_HASH[k]  (the empty subtree to the right)
    //      path_index[k] = 0  (we're always the LEFT child)
    //      cur[k+1] = h2(cur[k], sibling[k])
    //    Root = cur[20].
    const DEPTH = 20;
    const ZERO_HASH = new Array(DEPTH);
    ZERO_HASH[0] = 0n;
    for (let k = 1; k < DEPTH; k++) {
        ZERO_HASH[k] = h2(ZERO_HASH[k - 1], ZERO_HASH[k - 1]);
    }

    let cur = commitment;
    const merkle_path = new Array(DEPTH);
    const merkle_indices = new Array(DEPTH);
    for (let k = 0; k < DEPTH; k++) {
        merkle_path[k] = ZERO_HASH[k];
        merkle_indices[k] = 0n;
        cur = h2(cur, ZERO_HASH[k]);
    }
    const root = cur;

    // 3. publics
    const nullifier_hash = h1(nullifier);
    const amount_tag = compose6(amount, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence);
    const request_hash = compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id);

    const input = {
        // publics
        root: root.toString(),
        nullifier_hash: nullifier_hash.toString(),
        asset_id: asset_id.toString(),
        recipient_hash: recipient_hash.toString(),
        amount_tag: amount_tag.toString(),
        ca_payload_hash: ca_payload_hash.toString(),
        request_hash: request_hash.toString(),
        vault_sequence: vault_sequence.toString(),
        chain_id: chain_id.toString(),
        // privates
        nullifier: nullifier.toString(),
        secret: secret.toString(),
        amount: amount.toString(),
        withdraw_blind: withdraw_blind.toString(),
        merkle_path: merkle_path.map((x) => x.toString()),
        merkle_indices: merkle_indices.map((x) => x.toString()),
    };

    const dir = path.resolve(__dirname, '..', 'inputs');
    fs.mkdirSync(dir, { recursive: true });
    const outPath = path.join(dir, 'withdraw_valid_input.json');
    fs.writeFileSync(outPath, JSON.stringify(input, null, 2));
    console.log(`[build_withdraw_input] wrote ${outPath}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
