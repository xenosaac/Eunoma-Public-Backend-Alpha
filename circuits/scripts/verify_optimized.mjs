import { groth16 } from 'snarkjs';
import fs from 'node:fs';
const input = JSON.parse(fs.readFileSync('inputs/withdraw_valid_input.json'));
const wasm = 'generated_w4/withdrawal_proof_js/withdrawal_proof.wasm';
const zkey = 'generated_w4/withdrawal_proof_final.zkey';
console.log('proving optimized...');
const { proof, publicSignals } = await groth16.fullProve(input, wasm, zkey);
console.log('exporting vk...');
const vk = await import('snarkjs').then(m => m.default ?? m).then(s => s.zKey.exportVerificationKey(zkey)).catch(() => null);
// alt: use snarkjs CLI
import { execSync } from 'node:child_process';
fs.writeFileSync('/tmp/proof.json', JSON.stringify(proof));
fs.writeFileSync('/tmp/public.json', JSON.stringify(publicSignals));
execSync('npx snarkjs zkey export verificationkey generated_w4/withdrawal_proof_final.zkey /tmp/vk.json', { stdio: 'inherit' });
const ok = execSync('npx snarkjs groth16 verify /tmp/vk.json /tmp/public.json /tmp/proof.json', { encoding: 'utf-8' });
console.log(ok);

// Negative test: mutate a public signal, expect verify to fail
const badPublics = [...publicSignals];
badPublics[0] = '1';  // tamper with root
fs.writeFileSync('/tmp/public_bad.json', JSON.stringify(badPublics));
try {
    execSync('npx snarkjs groth16 verify /tmp/vk.json /tmp/public_bad.json /tmp/proof.json', { encoding: 'utf-8', stdio: 'pipe' });
    console.error('SOUNDNESS FAIL: tampered publics verified!');
    process.exit(2);
} catch (e) {
    const out = (e.stdout || '') + (e.stderr || '');
    if (out.includes('Invalid proof') || out.toLowerCase().includes('invalid') || e.status !== 0) {
        console.log('NEGATIVE TEST OK: tampered root rejected');
    } else {
        console.error('UNEXPECTED:', out);
        process.exit(3);
    }
}
process.exit(0);
