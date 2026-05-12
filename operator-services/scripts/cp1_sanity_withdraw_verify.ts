// CP1 sanity — proves the refactored shared canonical / Groth16 verify path is
// byte-faithful and that the new 256B↔snarkjs-JSON round-trip preserves verify=true.
//
// Scope note: the withdrawal circuit's on-disk zkey (May 8) is out of sync with
// the regenerated wasm + VK (May 11) — circuit team didn't finish the regen
// loop after Phase F W3 removed the chain_id public input. We cannot generate
// a fresh, verify=true withdrawal proof until that's fixed (deferred to CP5 /
// circuits team). For CP1 we exercise the new shared code path against the
// fully-aligned DEPOSIT pipeline (proof_valid.json + public_valid.json +
// deposit_binding_vk.json) — the only thing different between deposit and
// withdraw at the verifier level is which VK is loaded. compact256ToSnarkjsProof,
// g1ToBytes, g2ToBytes, and the verify-via-snarkjs wrapper are exercised here
// against a real, verify=true proof.
//
// Additionally we load the withdrawal VK and confirm it parses with nPublic=8
// (matches the W3 circuit). The withdrawal compose6/derive helpers are unit-
// validated against snapshot vectors captured from the prior script-inline
// implementation.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import {
  g1ToBytes,
  g2ToBytes,
  compose6,
  deriveRecipientHash,
  deriveAmountTag,
  deriveRequestHash,
  le32ToDec,
  decToLe32,
} from '../shared/src/withdraw_canonical.js';
import {
  compact256ToSnarkjsProof,
  loadDepositBindingVk,
  loadWithdrawalProofVk,
  verifyGroth16Proof,
} from '../shared/src/proof_verify.js';
import {
  hash2,
  hash3,
} from '../shared/src/poseidon_mirror.js';
import {
  bytesToFieldLe32,
  u64ToFieldLe32,
  u8ToFieldLe32,
  bytesToHex,
  bytesEqual,
} from '../shared/src/hex.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, '..', '..', 'circuits');
const GEN_DIR = path.join(CIRCUITS_DIR, 'generated');

function step(name: string, body: () => void | Promise<void>): Promise<void> {
  return Promise.resolve().then(async () => {
    process.stdout.write(`[cp1] ${name} ... `);
    try {
      await body();
      process.stdout.write('OK\n');
    } catch (err: any) {
      process.stdout.write('FAIL\n');
      console.error(err?.stack ?? String(err));
      process.exit(1);
    }
  });
}

// Inline reference of the pre-refactor compose6 / deriveRecipientHash that
// lived in build_testnet_withdraw_proof.ts. Byte-equality vs the shared
// helpers guarantees the refactor is a pure code-move (no semantic drift).
const POSEIDON_DOMAIN_RECIPIENT_HASH_REF = new TextEncoder().encode(
  'APTOSHIELD_RECIPIENT_HASH_V1',
);

async function refCompose6(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
  d: Uint8Array,
  e: Uint8Array,
  f: Uint8Array,
): Promise<Uint8Array> {
  const lo = await hash3(a, b, c);
  const hi = await hash3(d, e, f);
  return hash2(lo, hi);
}

function padToFr32(src: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  out.set(src, 0);
  return out;
}

async function refDeriveRecipientHash(addr32: Uint8Array): Promise<Uint8Array> {
  const hi = padToFr32(addr32.slice(0, 16));
  const lo = padToFr32(addr32.slice(16, 32));
  const domain = padToFr32(POSEIDON_DOMAIN_RECIPIENT_HASH_REF);
  return hash3(domain, hi, lo);
}

async function main(): Promise<void> {
  await step('shared compose6 byte-equal to inline reference (random vector)', async () => {
    // Hand-picked but representative 32-byte LE Fr values (all <2^254, well below Fr order).
    const a = new Uint8Array(32).fill(0x11);
    const b = new Uint8Array(32).fill(0x22);
    const c = new Uint8Array(32).fill(0x33);
    const d = new Uint8Array(32).fill(0x44);
    const e = new Uint8Array(32).fill(0x55);
    const f = new Uint8Array(32).fill(0x66);
    // Zero top byte so each fits Fr (< modulus). All Fr modulus has top byte 0x30...
    for (const v of [a, b, c, d, e, f]) v[31] = 0;
    const shared = await compose6(a, b, c, d, e, f);
    const ref = await refCompose6(a, b, c, d, e, f);
    if (!bytesEqual(shared, ref)) {
      throw new Error(`mismatch: shared=${bytesToHex(shared)} ref=${bytesToHex(ref)}`);
    }
  });

  await step('shared deriveRecipientHash byte-equal to inline reference', async () => {
    const recipient = new Uint8Array(32);
    // Use a concrete address pattern: 0x00..01 stretching across.
    for (let i = 0; i < 32; i++) recipient[i] = (i * 7 + 3) & 0xff;
    const shared = await deriveRecipientHash(recipient);
    const ref = await refDeriveRecipientHash(recipient);
    if (!bytesEqual(shared, ref)) {
      throw new Error(`mismatch: shared=${bytesToHex(shared)} ref=${bytesToHex(ref)}`);
    }
  });

  await step('deriveAmountTag matches inline compose6 expansion', async () => {
    const recipient_hash = new Uint8Array(32).fill(0xa1);
    recipient_hash[31] = 0;
    const withdraw_blind = new Uint8Array(32).fill(0xb2);
    withdraw_blind[31] = 0;
    const asset_id_le32 = new Uint8Array(32).fill(0xc3);
    asset_id_le32[31] = 0;
    const amount = 1_234_567_890n;
    const chain_id = 2;
    const vault_sequence = 42n;

    const shared = await deriveAmountTag({
      amount,
      withdraw_blind,
      recipient_hash,
      asset_id_le32,
      chain_id,
      vault_sequence,
    });
    const ref = await refCompose6(
      u64ToFieldLe32(amount),
      withdraw_blind,
      recipient_hash,
      asset_id_le32,
      u8ToFieldLe32(chain_id),
      u64ToFieldLe32(vault_sequence),
    );
    if (!bytesEqual(shared, ref)) {
      throw new Error(`amount_tag mismatch: shared=${bytesToHex(shared)} ref=${bytesToHex(ref)}`);
    }
  });

  await step('deriveRequestHash matches inline compose6 expansion', async () => {
    const amount_tag = new Uint8Array(32).fill(0xd4);
    amount_tag[31] = 0;
    const recipient_hash = new Uint8Array(32).fill(0xe5);
    recipient_hash[31] = 0;
    const ca_payload_hash = new Uint8Array(32).fill(0xf6);
    ca_payload_hash[31] = 0;
    const asset_id_le32 = new Uint8Array(32).fill(0xc3);
    asset_id_le32[31] = 0;
    const vault_sequence = 42n;
    const chain_id = 2;

    const shared = await deriveRequestHash({
      amount_tag,
      recipient_hash,
      ca_payload_hash,
      asset_id_le32,
      vault_sequence,
      chain_id,
    });
    const ref = await refCompose6(
      amount_tag,
      recipient_hash,
      ca_payload_hash,
      asset_id_le32,
      u64ToFieldLe32(vault_sequence),
      u8ToFieldLe32(chain_id),
    );
    if (!bytesEqual(shared, ref)) {
      throw new Error(`request_hash mismatch: shared=${bytesToHex(shared)} ref=${bytesToHex(ref)}`);
    }
  });

  await step('le32ToDec ↔ decToLe32 round-trip', () => {
    const samples = [
      0n,
      1n,
      0xffffffffffffffffn,
      1234567890123456789012345678901234n,
    ];
    for (const n of samples) {
      const buf = decToLe32(n.toString());
      const back = le32ToDec(buf);
      if (back !== n.toString()) throw new Error(`round-trip fail: ${n} → ${back}`);
    }
  });

  // --- Real verify=true round-trip using the aligned DEPOSIT pipeline. ---
  const depositProofPath = path.join(GEN_DIR, 'proof_valid.json');
  const depositPublicPath = path.join(GEN_DIR, 'public_valid.json');
  if (!fs.existsSync(depositProofPath) || !fs.existsSync(depositPublicPath)) {
    console.error(
      `\n[cp1] missing deposit fixtures (${depositProofPath} / ${depositPublicPath}). ` +
      `Run circuits/scripts/prove.sh first.`,
    );
    process.exit(1);
  }
  const depositProof = JSON.parse(fs.readFileSync(depositProofPath, 'utf-8'));
  const depositPublic = JSON.parse(fs.readFileSync(depositPublicPath, 'utf-8')) as string[];

  let packed256: Uint8Array = new Uint8Array(0);
  await step('pack deposit proof → 256B via shared g1ToBytes/g2ToBytes', () => {
    const a = g1ToBytes(depositProof.pi_a);
    const b = g2ToBytes(depositProof.pi_b);
    const c = g1ToBytes(depositProof.pi_c);
    if (a.length !== 64 || b.length !== 128 || c.length !== 64) {
      throw new Error(`bad slice lens: a=${a.length} b=${b.length} c=${c.length}`);
    }
    packed256 = new Uint8Array(256);
    packed256.set(a, 0);
    packed256.set(b, 64);
    packed256.set(c, 64 + 128);
  });

  await step('round-trip 256B → snarkjs JSON via compact256ToSnarkjsProof preserves coords', () => {
    const unpacked = compact256ToSnarkjsProof(packed256);
    if (unpacked.pi_a[0] !== depositProof.pi_a[0] || unpacked.pi_a[1] !== depositProof.pi_a[1]) {
      throw new Error(`pi_a mismatch`);
    }
    if (
      unpacked.pi_b[0][0] !== depositProof.pi_b[0][0] ||
      unpacked.pi_b[0][1] !== depositProof.pi_b[0][1] ||
      unpacked.pi_b[1][0] !== depositProof.pi_b[1][0] ||
      unpacked.pi_b[1][1] !== depositProof.pi_b[1][1]
    ) {
      throw new Error(`pi_b mismatch`);
    }
    if (unpacked.pi_c[0] !== depositProof.pi_c[0] || unpacked.pi_c[1] !== depositProof.pi_c[1]) {
      throw new Error(`pi_c mismatch`);
    }
  });

  await step('verifyGroth16Proof(roundTrippedDepositProof, publics) === true', async () => {
    const unpacked = compact256ToSnarkjsProof(packed256);
    const ok = await verifyGroth16Proof(unpacked, depositPublic);
    if (ok !== true) throw new Error('verify returned false on round-tripped valid deposit proof');
  });

  await step('control: direct snarkjs.verify on original JSON proof === true', async () => {
    const vk = loadDepositBindingVk();
    const ok = await snarkjs.groth16.verify(vk, depositPublic, depositProof);
    if (ok !== true) throw new Error('control verify failed — fixture pipeline broken');
  });

  await step('tamper detection: flip 1 byte → verify === false', async () => {
    const tampered = new Uint8Array(packed256);
    tampered[0] ^= 0x01;
    const proof = compact256ToSnarkjsProof(tampered);
    const ok = await verifyGroth16Proof(proof, depositPublic);
    if (ok !== false) throw new Error('tampered proof verified — verifier is broken');
  });

  await step('loadWithdrawalProofVk parses + nPublic === 8 (W3 alignment)', () => {
    const vk = loadWithdrawalProofVk();
    if (vk.protocol !== 'groth16') throw new Error(`bad protocol: ${vk.protocol}`);
    if (vk.curve !== 'bn128') throw new Error(`bad curve: ${vk.curve}`);
    if (vk.nPublic !== 8) throw new Error(`expected nPublic=8, got ${vk.nPublic}`);
  });

  console.log('\n[cp1] all sanity checks PASS');
  console.log(
    '[cp1] NOTE: full withdrawal verify=true sanity blocked by stale zkey ' +
    '(circuits/generated/withdrawal_proof_final.zkey May 8 vs wasm/VK May 11). ' +
    'Deferred to CP5 E2E gate — circuit team must regenerate zkey before then.',
  );
}

main().catch((err) => {
  console.error('[cp1] unexpected failure:', err);
  process.exit(2);
});
