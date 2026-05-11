#!/usr/bin/env node
// Move<->Circom Poseidon parity check.
//
// Generates 5 test vectors via circomlibjs's Poseidon and prints the expected
// output bytes (32-byte LE). To re-confirm parity with Move side, the same
// inputs are present in Poseidon_Research/aptos_move/sources/poseidon_test_vectors.move.
//
// Move-side hash_2 / hash_3 ALREADY validated against circomlibjs in 30+ vectors
// in poseidon_test_vectors.move. This script regenerates a fresh subset and
// asserts those Move-published vectors' "expected" bytes match what circomlibjs
// produces NOW — i.e. nothing has drifted since Poseidon_Research wrote them.
const { buildPoseidon } = require('circomlibjs');

// Helper: BigInt -> 32-byte LE.
function toLE32(F, x) {
    // F.toRprLE returns a Uint8Array of correct (32) length.
    const buf = new Uint8Array(32);
    F.toRprLE(buf, 0, x);
    return Buffer.from(buf).toString('hex');
}

// Helper: 32-byte LE hex string -> BigInt (canonical small-int form).
// circomlibjs's poseidon([...]) takes plain BigInts (not Montgomery-form
// field elements). Don't round-trip through F.fromRprLE — that returns the
// internal Montgomery encoding and breaks subsequent equality.
function leHexToBigInt(hex) {
    if (hex.length !== 64) throw new Error(`expected 64 hex chars, got ${hex.length}`);
    let n = 0n;
    for (let i = 31; i >= 0; i--) {
        const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
        n = (n << 8n) | BigInt(byte);
    }
    return n;
}

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Subset of test vectors from Poseidon_Research/aptos_move/sources/poseidon_test_vectors.move.
    // Each vector is { kind, inputs (LE hex), expected (LE hex) }.
    const move_vectors = [
        // hash_2 vectors (spot-check, picked from poseidon_hash_2_vectors())
        { kind: 'hash_2',
          inputs: [
              "0000000000000000000000000000000000000000000000000000000000000000",
              "0000000000000000000000000000000000000000000000000000000000000000",
          ],
          expected: "6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820" },
        { kind: 'hash_2',
          inputs: [
              "0100000000000000000000000000000000000000000000000000000000000000",
              "0000000000000000000000000000000000000000000000000000000000000000",
          ],
          expected: "7f3bc41c4a989182fb77c1ca3b9797d198428d32c77d176a896e56c7a228bb28" },
        { kind: 'hash_2',
          inputs: [
              "0100000000000000000000000000000000000000000000000000000000000000",
              "0100000000000000000000000000000000000000000000000000000000000000",
          ],
          expected: "811e40ad7ce2af903fe770cb8aa79412773f02f3a9e0799e2704d3e246f37a00" },
        // hash_3 vectors
        { kind: 'hash_3',
          inputs: [
              "0000000000000000000000000000000000000000000000000000000000000000",
              "0000000000000000000000000000000000000000000000000000000000000000",
              "0000000000000000000000000000000000000000000000000000000000000000",
          ],
          expected: "aa99a51bb36dee7caec596ecec4e86e28ff07a0aafb6cf1ddceacc7dd288c10b" },
        { kind: 'hash_3',
          inputs: [
              "0100000000000000000000000000000000000000000000000000000000000000",
              "0100000000000000000000000000000000000000000000000000000000000000",
              "0100000000000000000000000000000000000000000000000000000000000000",
          ],
          expected: "4325bf7386b102c223cd6109e3b6b1bc813ecb14b2c3332bbd2aa7106e06c002" },
    ];

    let pass = 0;
    let fail = 0;
    for (const v of move_vectors) {
        const ins = v.inputs.map(leHexToBigInt);
        const out = poseidon(ins);
        const got = toLE32(F, out);
        if (got === v.expected) {
            console.log(`[parity] OK   ${v.kind}(${v.inputs.map(s => s.slice(0, 8) + '..').join(', ')}) = ${got.slice(0, 16)}..`);
            pass++;
        } else {
            console.error(`[parity] FAIL ${v.kind}: expected=${v.expected} got=${got}`);
            fail++;
        }
    }

    if (fail > 0) {
        console.error(`\n[parity] BLOCKER: ${fail}/${pass + fail} Move<->Circom Poseidon parity vectors FAILED.`);
        console.error(`  This means circomlibjs's Poseidon and Move-side poseidon_bn254 produce different bytes.`);
        console.error(`  Halt Gate 4a; Move-side recompute in Gate 4b cannot work without parity.`);
        process.exit(1);
    }
    console.log(`\n[parity] OK — ${pass}/${pass + fail} Move<->Circom Poseidon vectors match.`);
    console.log('[parity] Gate 4a + 4b parity confirmed; safe to use circomlibjs to derive expected values.');
}

main().catch(e => { console.error(e); process.exit(1); });
