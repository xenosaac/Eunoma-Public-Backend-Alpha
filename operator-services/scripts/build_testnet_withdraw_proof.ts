/**
 * Phase 2 / Gate 6 — build a withdraw Groth16 proof against REAL testnet state.
 *
 * Inputs (caller supplies; mostly read from testnet_state.json deposit witness):
 *   - nullifier, secret, amount, deposit_blind (private deposit witness)
 *   - asset_id_le32, vault_addr_hash_le32 (cached values; bridge VaultConfigCache)
 *   - root (from on-chain RootHistory.current_finalized_root)
 *   - leaf_index (where this commitment was placed in pool, e.g. 0 for B.4)
 *   - withdraw_blind (random; binds amount_tag for THIS withdraw)
 *   - recipient (address; binds proof to specific recipient)
 *   - vault_sequence (current chain value; bridge enforces match)
 *   - chain_id (testnet = 2)
 *
 * Computed publics (matches Move-side `assert_valid_withdraw_proof` wire order):
 *   [root, nullifier_hash, asset_id, recipient_hash, amount_tag, ca_payload_hash,
 *    request_hash, vault_sequence, chain_id]
 *
 * Steps:
 *   1. Recompute commitment via compose5(nullifier, secret, asset_id, amount, POOL_ID=0).
 *      MUST match the deposit-side commitment exactly (same formula as deposit_binding.circom).
 *   2. Compute merkle inclusion path/indices for `leaf_index` (currently single-leaf at 0).
 *      Sibling at level k = empty_subtree[k] when leaf is at index 0.
 *   3. Compute nullifier_hash = Poseidon(1)(nullifier).
 *   4. Compute recipient_hash via derive_recipient_hash(recipient).
 *   5. Compute amount_tag via compose6(amount, withdraw_blind, recipient_hash, asset_id, chain_id, vault_sequence).
 *   6. Compute request_hash via compose6(amount_tag, recipient_hash, ca_payload_hash, asset_id, vault_sequence, chain_id).
 *   7. Write circom input JSON, run witness gen + snarkjs prove.
 *   8. Convert proof bytes to Move uncompressed (256B = a||b||c).
 *   9. Sanity-check public inputs against snarkjs `public.json`.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  getPoseidon,
  hash2,
  hash3,
  compose5,
} from '../shared/src/poseidon_mirror.js';
import { POOL_ID_VALUE } from '../shared/src/types.js';
import { u64ToFieldLe32, u8ToFieldLe32 } from '../shared/src/hex.js';
import { computeMerklePath } from './build_merkle_path.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, '..', '..', 'circuits');
const GEN_DIR = path.join(CIRCUITS_DIR, 'generated');
const TMP_DIR = path.join(__dirname, '.withdraw-proof-tmp');

const TREE_DEPTH = 20;
const ZERO32 = new Uint8Array(32);

const POSEIDON_DOMAIN_RECIPIENT_HASH = new TextEncoder().encode(
  'APTOSHIELD_RECIPIENT_HASH_V1',
);

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') ? s.slice(2) : s;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function le32ToDec(buf: Uint8Array): string {
  if (buf.length !== 32) throw new Error(`expected 32-byte buffer; got ${buf.length}`);
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(buf[i]);
  return n.toString();
}
function decToLe32(dec: string): Uint8Array {
  let n = BigInt(dec);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error(`Fr exceeds 32 bytes: ${dec}`);
  return out;
}
function g1ToBytes(arr: string[]): Uint8Array {
  const out = new Uint8Array(64);
  out.set(decToLe32(arr[0]), 0);
  out.set(decToLe32(arr[1]), 32);
  return out;
}
function g2ToBytes(arr: string[][]): Uint8Array {
  const [x, y] = arr;
  const out = new Uint8Array(128);
  out.set(decToLe32(x[0]), 0);
  out.set(decToLe32(x[1]), 32);
  out.set(decToLe32(y[0]), 64);
  out.set(decToLe32(y[1]), 96);
  return out;
}

/** Pad arbitrary <=32 byte buffer into 32-byte LE Fr buffer. */
function padToFr(src: Uint8Array): Uint8Array {
  if (src.length > 32) throw new Error(`>32 bytes: ${src.length}`);
  const out = new Uint8Array(32);
  out.set(src, 0);
  return out;
}

/** 6-input Poseidon: compose6(a,b,c,d,e,f) = hash2(hash3(a,b,c), hash3(d,e,f)).
 * Mirror of the circuit's Compose6 template; bytes-identical because the
 * underlying Poseidon hash_2/hash_3 are circomlibjs (matches Move-side A2-frozen). */
async function compose6(
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

/** Mirror of Move's `derive_recipient_hash`: hash3(domain, hi, lo). */
async function deriveRecipientHash(addr32: Uint8Array): Promise<Uint8Array> {
  if (addr32.length !== 32) throw new Error('recipient must be 32 bytes');
  const hi = padToFr(addr32.slice(0, 16));
  const lo = padToFr(addr32.slice(16, 32));
  const domain = padToFr(POSEIDON_DOMAIN_RECIPIENT_HASH);
  return hash3(domain, hi, lo);
}

/** Phase 2.X legacy fallback: 1-leaf tree where the only leaf sits at index 0
 * (used when caller does not supply `allLeaves`).
 *
 * Sibling convention (per WORK_LOG.md errata R6-4 and spike's `frontierInsert`
 * at `operator/batch_updater.ts:214-228`): bridge's `pool_batch_root_update`
 * and the spike use **literal ZERO32** as the right-side filler at every
 * level, NOT `empty_subtree[k] = hash_recursive(Z)`. So root for a 1-leaf
 * tree at index 0 = poseidon2(...poseidon2(poseidon2(leaf, Z), Z)...) and the
 * inclusion path is path[k]=ZERO32, indices[k]=0 for all k.
 *
 * For N>=2 leaves OR leafIndex>0, callers must supply `allLeaves` and the
 * proof builder routes to `computeMerklePath` (build_merkle_path.ts) instead.
 */
function merklePathFor1LeafTree(
  leafIndex: number,
  depth: number,
): { path: Uint8Array[]; indices: number[] } {
  if (leafIndex !== 0) {
    throw new Error(
      `merklePathFor1LeafTree: only supports leaf_index=0 (got ${leafIndex}); ` +
      `pass allLeaves to buildWithdrawProof to use computeMerklePath instead`,
    );
  }
  const path: Uint8Array[] = [];
  const indices: number[] = [];
  for (let i = 0; i < depth; i++) {
    path.push(ZERO32);
    indices.push(0);
  }
  return { path, indices };
}

export interface WithdrawProofInputs {
  nullifier: Uint8Array;       // 32-byte LE Fr (from deposit witness)
  secret: Uint8Array;          // 32-byte LE Fr (from deposit witness)
  amountOctas: bigint;         // u64 (from deposit witness)
  withdrawBlind: Uint8Array;   // 32-byte LE Fr (random per withdraw)
  recipient: Uint8Array;       // 32-byte address (where to send funds)
  assetIdLe32: Uint8Array;     // 32-byte LE Fr (from VaultConfigCache)
  root: Uint8Array;            // 32-byte LE Fr (from RootHistory.current_finalized_root)
  leafIndex: number;           // pool position of the deposit (0 for B.4, 1 for B.5, ...)
  vaultSequence: bigint;       // current cfg.vault_sequence
  chainId: number;             // u8 = 2 testnet
  caPayloadHash: Uint8Array;   // 32-byte (keccak256 of CA outbound payload)
  /**
   * Optional (W.2): ordered list of all 32-byte commitments currently in
   * the pool, indexed by leaf position. When provided, the proof builder
   * routes through `computeMerklePath` to support arbitrary `leafIndex`
   * and `leaves.length >= 1`.
   *
   * Backward-compat: when omitted AND `leafIndex === 0`, falls back to
   * the Phase 2.X 1-leaf tree path (path[k]=ZERO32, indices[k]=0).
   * Omitting with `leafIndex > 0` will throw.
   */
  allLeaves?: Uint8Array[];
}

export interface WithdrawProofResult {
  // Public inputs (32-byte LE Fr)
  rootLe32: Uint8Array;
  nullifierHash: Uint8Array;
  assetIdLe32: Uint8Array;
  recipientHash: Uint8Array;
  amountTag: Uint8Array;
  caPayloadHash: Uint8Array;
  requestHash: Uint8Array;
  vaultSequenceLe32: Uint8Array;
  chainIdLe32: Uint8Array;
  // Computed commitment (must match on-chain pool acc_history[leafIndex+1] derivation)
  commitment: Uint8Array;
  // Proof bytes (256 = 64+128+64)
  proofBytes: Uint8Array;
  // Debug paths
  inputJsonPath: string;
  proofJsonPath: string;
  publicJsonPath: string;
}

export async function buildWithdrawProof(inputs: WithdrawProofInputs): Promise<WithdrawProofResult> {
  await getPoseidon(); // init

  // ---- 1. Recompute commitment (must match deposit's compose5) ----
  const amountLe32 = u64ToFieldLe32(inputs.amountOctas);
  const poolIdLe32 = u64ToFieldLe32(POOL_ID_VALUE); // 0n
  const commitment = await compose5(
    inputs.nullifier,
    inputs.secret,
    inputs.assetIdLe32,
    amountLe32,
    poolIdLe32,
  );
  console.log(`[wproof] computed commitment = 0x${hex(commitment)}`);

  // ---- 2. Merkle path for leaf_index ----
  // W.2: prefer multi-leaf path when caller supplies `allLeaves`; fall back
  // to the 1-leaf-tree shortcut for legacy callers (only valid at leafIndex=0).
  let merklePath: Uint8Array[];
  let merkleIndices: number[];
  if (inputs.allLeaves !== undefined) {
    if (inputs.leafIndex >= inputs.allLeaves.length) {
      throw new Error(
        `buildWithdrawProof: leafIndex ${inputs.leafIndex} >= allLeaves.length ` +
        `${inputs.allLeaves.length} — leaf must already be inserted`,
      );
    }
    // Sanity: caller-claimed commitment at leafIndex must equal the one we
    // just recomputed from the deposit witness (compose5).
    const claimed = inputs.allLeaves[inputs.leafIndex];
    if (claimed.length !== 32) {
      throw new Error(
        `buildWithdrawProof: allLeaves[${inputs.leafIndex}] must be 32 bytes; ` +
        `got ${claimed.length}`,
      );
    }
    let mismatch = false;
    for (let i = 0; i < 32; i++) {
      if (claimed[i] !== commitment[i]) { mismatch = true; break; }
    }
    if (mismatch) {
      throw new Error(
        `buildWithdrawProof: allLeaves[${inputs.leafIndex}] ` +
        `(=0x${hex(claimed)}) does not match recomputed commitment ` +
        `(=0x${hex(commitment)}) — witness/leaves out of sync`,
      );
    }
    const r = await computeMerklePath(inputs.allLeaves, inputs.leafIndex, TREE_DEPTH);
    merklePath = r.path;
    merkleIndices = r.pathIndices;
    console.log(
      `[wproof] merkle_path[0..${TREE_DEPTH - 1}] computed via computeMerklePath ` +
      `(leafIndex=${inputs.leafIndex}, leaves.length=${inputs.allLeaves.length})`,
    );
  } else {
    const r = merklePathFor1LeafTree(inputs.leafIndex, TREE_DEPTH);
    merklePath = r.path;
    merkleIndices = r.indices;
    console.log(
      `[wproof] merkle_path[0..${TREE_DEPTH - 1}] computed via 1-leaf fallback ` +
      `(legacy single-leaf path; leafIndex=${inputs.leafIndex})`,
    );
  }

  // ---- 3. Public-input derivations ----
  const { hash1 } = await import('../shared/src/poseidon_mirror.js')
    .then((m: any) => m.getPoseidon ? import('../shared/src/poseidon_mirror.js') : m)
    .catch(() => ({ hash1: undefined as any }));

  // hash1 (1-input Poseidon) — use circomlibjs Poseidon directly since shared lib
  // exposes hash2/hash3 only. ESM-safe dynamic import (replaces stale require()).
  const { buildPoseidon } = (await import('circomlibjs')) as any;
  const pos: any = await buildPoseidon();
  const bytesLEToBigInt = (b: Uint8Array): bigint => {
    let x = 0n;
    for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
    return x;
  };
  const poseidon1 = (a: Uint8Array): Uint8Array => {
    const out = pos([bytesLEToBigInt(a)]);
    const buf = new Uint8Array(32);
    pos.F.toRprLE(buf, 0, out);
    return buf;
  };

  const nullifierHash = poseidon1(inputs.nullifier);
  const recipientHash = await deriveRecipientHash(inputs.recipient);
  const vaultSequenceLe32 = u64ToFieldLe32(inputs.vaultSequence);
  const chainIdLe32 = u8ToFieldLe32(inputs.chainId);

  const amountTag = await compose6(
    amountLe32,
    inputs.withdrawBlind,
    recipientHash,
    inputs.assetIdLe32,
    chainIdLe32,
    vaultSequenceLe32,
  );
  const requestHash = await compose6(
    amountTag,
    recipientHash,
    inputs.caPayloadHash,
    inputs.assetIdLe32,
    vaultSequenceLe32,
    chainIdLe32,
  );

  console.log(`[wproof] nullifier_hash  = 0x${hex(nullifierHash)}`);
  console.log(`[wproof] recipient_hash  = 0x${hex(recipientHash)}`);
  console.log(`[wproof] amount_tag      = 0x${hex(amountTag)}`);
  console.log(`[wproof] request_hash    = 0x${hex(requestHash)}`);

  // ---- 4. Write circom input JSON ----
  // Phase F W3: chain_id is baked into the withdraw circuit as compile-time
  // constant CHAIN_ID = 2. No longer part of witness inputs. `chainIdLe32`
  // is still computed above because the off-circuit compose6 cross-check
  // needs the 32-byte LE Fr representation.
  fs.mkdirSync(TMP_DIR, { recursive: true });
  const circomInput: Record<string, any> = {
    root: le32ToDec(inputs.root),
    nullifier_hash: le32ToDec(nullifierHash),
    asset_id: le32ToDec(inputs.assetIdLe32),
    recipient_hash: le32ToDec(recipientHash),
    amount_tag: le32ToDec(amountTag),
    ca_payload_hash: le32ToDec(inputs.caPayloadHash),
    request_hash: le32ToDec(requestHash),
    vault_sequence: le32ToDec(vaultSequenceLe32),
    nullifier: le32ToDec(inputs.nullifier),
    secret: le32ToDec(inputs.secret),
    amount: inputs.amountOctas.toString(),
    withdraw_blind: le32ToDec(inputs.withdrawBlind),
    merkle_path: merklePath.map(le32ToDec),
    merkle_indices: merkleIndices.map(String),
  };
  const inputPath = path.join(TMP_DIR, 'input_testnet.json');
  fs.writeFileSync(inputPath, JSON.stringify(circomInput, null, 2));

  // ---- 5. Generate witness ----
  const witnessPath = path.join(TMP_DIR, 'witness_testnet.wtns');
  const wasmPath = path.join(GEN_DIR, 'withdrawal_proof_js', 'withdrawal_proof.wasm');
  const witnessGenScript = path.join(GEN_DIR, 'withdrawal_proof_js', 'generate_witness.js');
  console.log('[wproof] generating witness ...');
  execSync(
    `node "${witnessGenScript}" "${wasmPath}" "${inputPath}" "${witnessPath}"`,
    { stdio: 'inherit' },
  );

  // ---- 6. Generate Groth16 proof ----
  const proofPath = path.join(TMP_DIR, 'proof_testnet.json');
  const publicPath = path.join(TMP_DIR, 'public_testnet.json');
  const zkeyPath = path.join(GEN_DIR, 'withdrawal_proof_final.zkey');
  console.log('[wproof] running snarkjs groth16 prove ...');
  execSync(
    `npx --prefix "${CIRCUITS_DIR}" snarkjs groth16 prove "${zkeyPath}" "${witnessPath}" "${proofPath}" "${publicPath}"`,
    { stdio: 'inherit', cwd: CIRCUITS_DIR },
  );

  // ---- 7. Convert snarkjs proof to Move uncompressed bytes ----
  const proof = JSON.parse(fs.readFileSync(proofPath, 'utf-8'));
  const aBytes = g1ToBytes(proof.pi_a);
  const bBytes = g2ToBytes(proof.pi_b);
  const cBytes = g1ToBytes(proof.pi_c);
  const proofBytes = new Uint8Array(64 + 128 + 64);
  proofBytes.set(aBytes, 0);
  proofBytes.set(bBytes, 64);
  proofBytes.set(cBytes, 64 + 128);

  // ---- 8. Sanity check public inputs ----
  // Phase F W3: 9 → 8 publics (chain_id removed — circuit constant).
  const pub = JSON.parse(fs.readFileSync(publicPath, 'utf-8')) as string[];
  const expected = [
    le32ToDec(inputs.root),
    le32ToDec(nullifierHash),
    le32ToDec(inputs.assetIdLe32),
    le32ToDec(recipientHash),
    le32ToDec(amountTag),
    le32ToDec(inputs.caPayloadHash),
    le32ToDec(requestHash),
    le32ToDec(vaultSequenceLe32),
  ];
  for (let i = 0; i < 8; i++) {
    if (pub[i] !== expected[i]) {
      throw new Error(`public[${i}] mismatch: snarkjs=${pub[i]} expected=${expected[i]}`);
    }
  }
  console.log('[wproof] public inputs sanity check OK');

  return {
    rootLe32: inputs.root,
    nullifierHash,
    assetIdLe32: inputs.assetIdLe32,
    recipientHash,
    amountTag,
    caPayloadHash: inputs.caPayloadHash,
    requestHash,
    vaultSequenceLe32,
    chainIdLe32,
    commitment,
    proofBytes,
    inputJsonPath: inputPath,
    proofJsonPath: proofPath,
    publicJsonPath: publicPath,
  };
}
