#!/usr/bin/env node
// Export VK + valid proof + public inputs to the Move byte format expected by
// `aptosshield::groth16_bn254::verify_proof<bn254_algebra::G1, G2, Gt, Fr>`.
//
// Move-side byte formats (per LOCAL_CONFIRMATION 8.7 + groth16_example test code):
//   - G1 uncompressed (FormatG1Uncompr): 64 bytes = bcs::to_bytes(x as u256) || bcs::to_bytes(y as u256)
//                                         (BCS-u256 is 32 bytes LE, so this is x_LE32 || y_LE32)
//   - G2 uncompressed (FormatG2Uncompr): 128 bytes = x_c0_LE32 || x_c1_LE32 || y_c0_LE32 || y_c1_LE32
//                                         (snarkjs arr layout: [[x0,x1],[y0,y1]] — same order)
//   - Fr (FormatFrLsb):                  32 bytes LE
//
// We use UNCOMPRESSED format because it eliminates ambiguity around the y-sign
// flag bit and exactly matches the existing groth16_example::test_verify_circom_proof
// pattern (which uses bcs::to_bytes<u256>(&x) || bcs::to_bytes<u256>(&y)).
//
// Outputs:
//   generated/move_fixtures/vk_bytes.json
//   generated/move_fixtures/proof_valid_bytes.json
//   generated/move_fixtures/move_constants.move    — ready-to-paste Move literals
//
// snarkjs JSON points are decimal strings of affine coordinates on BN254 (a prime
// field, so each coord is one BigInt < p). G2 coords are pairs [c0, c1] with the
// snarkjs convention "Fp2 = c0 + c1*u".
const fs = require('fs');
const path = require('path');

// ---- helpers ----
function bigToLE32hex(x) {
    let n = BigInt(x);
    if (n < 0n) throw new Error('negative coordinate');
    const out = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
        out[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    if (n !== 0n) throw new Error(`coordinate exceeds 32 bytes (was ${BigInt(x).toString(16)})`);
    return out.toString('hex');
}

// G1 uncompressed: x_LE32 || y_LE32 (skip the projective z=1 trailing element).
function g1Uncompr(arr) {
    if (arr.length < 2) throw new Error(`G1 array too short: ${JSON.stringify(arr)}`);
    return bigToLE32hex(arr[0]) + bigToLE32hex(arr[1]);
}

// G2 uncompressed: x_c0 || x_c1 || y_c0 || y_c1 (each LE32). snarkjs gives
// [[x0,x1],[y0,y1],[1,0]]; we drop the projective row.
function g2Uncompr(arr) {
    const [x, y] = arr;
    if (!x || !y || x.length < 2 || y.length < 2) throw new Error(`G2 shape unexpected: ${JSON.stringify(arr)}`);
    return bigToLE32hex(x[0]) + bigToLE32hex(x[1]) + bigToLE32hex(y[0]) + bigToLE32hex(y[1]);
}

// Fr scalar: 32-byte LE.
function frLE32(x) {
    return bigToLE32hex(x);
}

// ---- main ----
function main() {
    const root = path.resolve(__dirname, '..');
    const gen  = path.join(root, 'generated');
    const out  = path.join(gen, 'move_fixtures');
    fs.mkdirSync(out, { recursive: true });

    const vk = JSON.parse(fs.readFileSync(path.join(gen, 'deposit_binding_vk.json'), 'utf8'));
    const proof = JSON.parse(fs.readFileSync(path.join(gen, 'proof_valid.json'), 'utf8'));
    const publicSignals = JSON.parse(fs.readFileSync(path.join(gen, 'public_valid.json'), 'utf8'));
    const negAmtTag = JSON.parse(fs.readFileSync(path.join(gen, 'public_invalid_wrong_amount_tag.json'), 'utf8'));
    const negCmt    = JSON.parse(fs.readFileSync(path.join(gen, 'public_invalid_wrong_commitment.json'), 'utf8'));
    const negAmtIn  = JSON.parse(fs.readFileSync(path.join(gen, 'public_invalid_amount_inconsistent.json'), 'utf8'));

    if (vk.curve !== 'bn128') {
        console.error(`[export] WARNING: VK.curve = ${vk.curve}, expected bn128/bn254`);
    }
    if (vk.protocol !== 'groth16') {
        throw new Error(`unexpected VK.protocol = ${vk.protocol}`);
    }
    if (vk.nPublic !== 6) {
        throw new Error(`expected 6 public inputs, VK.nPublic = ${vk.nPublic}`);
    }
    if (vk.IC.length !== 7) {
        throw new Error(`expected vk.IC length 7 (= 1 + n_public_inputs), got ${vk.IC.length}`);
    }

    // ---------- VK bytes ----------
    const vk_bytes = {
        // alpha_g1 in snarkjs is `vk_alpha_1`. Layout per snarkjs: [x, y, 1].
        alpha_g1: g1Uncompr(vk.vk_alpha_1),
        beta_g2:  g2Uncompr(vk.vk_beta_2),
        gamma_g2: g2Uncompr(vk.vk_gamma_2),
        delta_g2: g2Uncompr(vk.vk_delta_2),
        ic:       vk.IC.map(g1Uncompr),
    };

    // ---------- Proof bytes ----------
    const proof_bytes = {
        a: g1Uncompr(proof.pi_a),
        b: g2Uncompr(proof.pi_b),
        c: g1Uncompr(proof.pi_c),
    };

    // ---------- Public inputs ----------
    const pub_valid = publicSignals.map(frLE32);
    const pub_neg_amt_tag = negAmtTag.map(frLE32);
    const pub_neg_cmt     = negCmt.map(frLE32);
    const pub_neg_amt_in  = negAmtIn.map(frLE32);

    fs.writeFileSync(path.join(out, 'vk_bytes.json'),       JSON.stringify(vk_bytes, null, 2));
    fs.writeFileSync(path.join(out, 'proof_valid_bytes.json'), JSON.stringify(proof_bytes, null, 2));
    fs.writeFileSync(path.join(out, 'public_valid_bytes.json'), JSON.stringify(pub_valid, null, 2));
    fs.writeFileSync(path.join(out, 'public_negative_bytes.json'), JSON.stringify({
        wrong_amount_tag: pub_neg_amt_tag,
        wrong_commitment: pub_neg_cmt,
        amount_inconsistent: pub_neg_amt_in,
    }, null, 2));

    // ---------- Move literal helpers (paste-ready) ----------
    const moveOut = [];
    moveOut.push('// Auto-generated by circuits/scripts/export_to_move.js. DO NOT EDIT BY HAND.');
    moveOut.push('// Regenerate after re-running the trusted setup: bash scripts/all_local.sh');
    moveOut.push('//');
    moveOut.push('// Format: every G1 is 64 bytes (x_LE32 || y_LE32), every G2 is 128 bytes');
    moveOut.push('// (x_c0_LE32 || x_c1_LE32 || y_c0_LE32 || y_c1_LE32), every Fr is 32 bytes LE.');
    moveOut.push('// These literals are designed to be passed to');
    moveOut.push('//   crypto_algebra::deserialize<bn254_algebra::G1, bn254_algebra::FormatG1Uncompr>(...)');
    moveOut.push('// and friends.');
    moveOut.push('');

    const emit = (name, hex) => moveOut.push(`    // ${name}\n    public fun ${name}(): vector<u8> { x"${hex}" }\n`);
    moveOut.push('module aptosshield::groth16_test_fixtures {');
    moveOut.push('    // ---- VK ----');
    emit('vk_alpha_g1', vk_bytes.alpha_g1);
    emit('vk_beta_g2',  vk_bytes.beta_g2);
    emit('vk_gamma_g2', vk_bytes.gamma_g2);
    emit('vk_delta_g2', vk_bytes.delta_g2);
    vk_bytes.ic.forEach((hex, i) => emit(`vk_ic_${i}`, hex));

    moveOut.push('    // ---- Valid proof ----');
    emit('proof_valid_a', proof_bytes.a);
    emit('proof_valid_b', proof_bytes.b);
    emit('proof_valid_c', proof_bytes.c);

    moveOut.push('    // ---- Valid public inputs (commitment, amount_tag, asset_id, vault_addr_hash, chain_id, pool_id) ----');
    pub_valid.forEach((hex, i) => emit(`public_valid_${i}`, hex));

    moveOut.push('    // ---- Negative public inputs (same valid proof; should be REJECTED) ----');
    pub_neg_amt_tag.forEach((hex, i) => emit(`public_neg_amt_tag_${i}`, hex));
    pub_neg_cmt.forEach((hex, i) => emit(`public_neg_cmt_${i}`, hex));
    pub_neg_amt_in.forEach((hex, i) => emit(`public_neg_amt_in_${i}`, hex));

    moveOut.push('}');
    fs.writeFileSync(path.join(out, 'move_constants.move'), moveOut.join('\n'));

    // Plain text version for paste-into-test.
    const txt = [
        `// VK alpha_g1 (64 bytes uncompressed)`, `x"${vk_bytes.alpha_g1}"`,
        `// VK beta_g2 (128 bytes uncompressed)`, `x"${vk_bytes.beta_g2}"`,
        `// VK gamma_g2 (128 bytes)`, `x"${vk_bytes.gamma_g2}"`,
        `// VK delta_g2 (128 bytes)`, `x"${vk_bytes.delta_g2}"`,
        `// VK IC (${vk_bytes.ic.length} G1 points, 64 bytes each)`,
        ...vk_bytes.ic.map((h, i) => `// IC[${i}]\nx"${h}"`),
        `// proof.a (G1)`, `x"${proof_bytes.a}"`,
        `// proof.b (G2)`, `x"${proof_bytes.b}"`,
        `// proof.c (G1)`, `x"${proof_bytes.c}"`,
        `// public_valid (Fr 32-byte LE):`,
        ...pub_valid.map((h, i) => `// public[${i}]\nx"${h}"`),
    ].join('\n');
    fs.writeFileSync(path.join(out, 'fixtures.txt'), txt);

    console.log('[export] wrote:');
    for (const f of fs.readdirSync(out)) {
        const p = path.join(out, f);
        const sz = fs.statSync(p).size;
        console.log(`  ${p} (${sz} bytes)`);
    }

    // Print VK byte sizes for the REPORT.
    console.log('\n[export] sizes:');
    console.log(`  vk.alpha_g1 = ${vk_bytes.alpha_g1.length / 2} B  (G1 uncompressed)`);
    console.log(`  vk.beta_g2  = ${vk_bytes.beta_g2.length / 2} B  (G2 uncompressed)`);
    console.log(`  vk.gamma_g2 = ${vk_bytes.gamma_g2.length / 2} B`);
    console.log(`  vk.delta_g2 = ${vk_bytes.delta_g2.length / 2} B`);
    console.log(`  vk.IC length= ${vk_bytes.ic.length} (each ${vk_bytes.ic[0].length / 2} B)`);
    console.log(`  proof.a + b + c = ${proof_bytes.a.length / 2 + proof_bytes.b.length / 2 + proof_bytes.c.length / 2} B (uncompressed)`);
}

main();
