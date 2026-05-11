#!/usr/bin/env node
// Build a consistent (private, public) input pair for the deposit-binding circuit.
//
// Generates:
//   inputs/valid_input.json       — valid pair (commitment + amount_tag computed via circomlibjs)
//   inputs/invalid_input_*.json   — mutated public inputs (will fail snarkjs verify after we
//                                   keep the same proof_a/b/c but submit a wrong public
//                                   input vector — see verify_negative.sh).
//
// This is the canonical place where commitment/amount_tag are derived OFF-circuit
// using circomlibjs's Poseidon. The CIRCUIT then re-derives them (via Poseidon
// constraints) and compares to the public inputs.
const path = require('path');
const fs = require('fs');
const { buildPoseidon } = require('circomlibjs');

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Helper: compose5 = hash_2(hash_3(a,b,c), hash_2(d,e)). Returns a BigInt-like field element.
    const compose5 = (a, b, c, d, e) =>
        F.toObject(poseidon([
            F.toObject(poseidon([a, b, c])),
            F.toObject(poseidon([d, e])),
        ]));

    // ---------- Valid sample input ----------
    // Field elements as decimal strings (snarkjs convention). circomlibjs accepts BigInt or string.
    const nullifier      = 12345678901234567890123456789012345678901234567890n;
    const secret         = 98765432109876543210987654321098765432109876543210n;
    const amount         = 1_000_000_000n; // 1 APT (in octas), well within u64.
    const deposit_blind  = 11111111111111111111111111111111111111111111111111n;

    const asset_id        = 7n;        // canonical bridge id for "APT"
    const vault_addr_hash = 0x0BEEF0BEEFCAFEDEADBEEFCAFEDEADBEEFCAFEDEADBEEFCAFEDEADBEEFCAFEDn;
    const chain_id        = 2n;        // testnet id (placeholder)
    const pool_id         = 0n;

    const commitment = compose5(nullifier, secret, asset_id, amount, pool_id);
    const amount_tag = compose5(amount, deposit_blind, asset_id, vault_addr_hash, chain_id);

    const validInput = {
        commitment:      commitment.toString(),
        amount_tag:      amount_tag.toString(),
        asset_id:        asset_id.toString(),
        vault_addr_hash: vault_addr_hash.toString(),
        chain_id:        chain_id.toString(),
        pool_id:         pool_id.toString(),
        nullifier:       nullifier.toString(),
        secret:          secret.toString(),
        amount:          amount.toString(),
        deposit_blind:   deposit_blind.toString(),
    };

    const dir = path.resolve(__dirname, '..', 'inputs');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'valid_input.json'), JSON.stringify(validInput, null, 2));
    console.log('[build_inputs] wrote inputs/valid_input.json');

    // For the negative tests we DON'T regenerate proofs — we keep the valid proof
    // but submit a mutated public-input vector. The mutation is applied in
    // scripts/verify_negative.sh. We dump the mutations as JSON for clarity.
    const dump = (name, public_signals) => {
        fs.writeFileSync(
            path.join(__dirname, '..', 'generated', name),
            JSON.stringify(public_signals, null, 2),
        );
        console.log(`[build_inputs] wrote generated/${name}`);
    };

    // public_signals are returned by snarkjs in the SAME ORDER as the public inputs
    // declared on `component main { public [...] }`. Our order is:
    //   [commitment, amount_tag, asset_id, vault_addr_hash, chain_id, pool_id]
    fs.mkdirSync(path.resolve(__dirname, '..', 'generated'), { recursive: true });

    const validPub = [
        commitment.toString(),
        amount_tag.toString(),
        asset_id.toString(),
        vault_addr_hash.toString(),
        chain_id.toString(),
        pool_id.toString(),
    ];

    // Negative #1: wrong amount_tag (flip a bit).
    const neg1 = [...validPub];
    neg1[1] = (BigInt(neg1[1]) ^ 1n).toString();
    dump('public_invalid_wrong_amount_tag.json', neg1);

    // Negative #2: wrong commitment (mutate).
    const neg2 = [...validPub];
    neg2[0] = (BigInt(neg2[0]) ^ 0xFn).toString();
    dump('public_invalid_wrong_commitment.json', neg2);

    // Negative #3: amount tampering — equivalent to "amount changed without matching
    // commitment". We mutate asset_id (a public input) which makes the whole
    // proof inconsistent with the witness, simulating an operator/user trying to
    // claim a different asset for the same commitment. Same proof bytes will fail.
    const neg3 = [...validPub];
    neg3[2] = (BigInt(neg3[2]) + 1n).toString();
    dump('public_invalid_amount_inconsistent.json', neg3);

    console.log('[build_inputs] all inputs ready.');
}

main().catch(e => { console.error(e); process.exit(1); });
