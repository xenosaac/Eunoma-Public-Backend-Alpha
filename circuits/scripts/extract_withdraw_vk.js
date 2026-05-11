// Quick extractor: withdrawal_proof_vk.json → hex strings ready for
// publish_withdraw_proof_vk admin entry args. Mirrors export_to_move.js conventions.
const fs = require('fs');
const path = require('path');

function bigToLE32hex(x) {
  let n = BigInt(x);
  if (n < 0n) throw new Error('negative');
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error(`coord exceeds 32 bytes: ${BigInt(x).toString(16)}`);
  return out.toString('hex');
}
function g1Uncompr(arr) { return bigToLE32hex(arr[0]) + bigToLE32hex(arr[1]); }
function g2Uncompr(arr) {
  const [x, y] = arr;
  return bigToLE32hex(x[0]) + bigToLE32hex(x[1]) + bigToLE32hex(y[0]) + bigToLE32hex(y[1]);
}

const vkPath = path.resolve(__dirname, '..', 'generated', 'withdrawal_proof_vk.json');
const vk = JSON.parse(fs.readFileSync(vkPath, 'utf8'));
if (vk.protocol !== 'groth16') throw new Error(`bad protocol: ${vk.protocol}`);
// Phase F W3: chain_id hardcoded → publics 9 → 8, IC length 10 → 9.
if (vk.nPublic !== 8) throw new Error(`expected 8 publics, got ${vk.nPublic}`);
if (vk.IC.length !== 9) throw new Error(`expected IC length 9, got ${vk.IC.length}`);

const out = {
  alpha_g1: g1Uncompr(vk.vk_alpha_1),
  beta_g2:  g2Uncompr(vk.vk_beta_2),
  gamma_g2: g2Uncompr(vk.vk_gamma_2),
  delta_g2: g2Uncompr(vk.vk_delta_2),
  ic: vk.IC.map(g1Uncompr),
};

console.log(JSON.stringify(out, null, 2));
