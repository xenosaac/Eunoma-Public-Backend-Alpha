/**
 * Build a deposit-binding Groth16 proof against REAL testnet public inputs:
 *   asset_id       = poseidon_bn254.hash_3(POSEIDON_DOMAIN_ASSET_ID, addr_hi_16B, addr_lo_16B)
 *   vault_addr_hash = same recipe over the vault resource-account address
 *
 * (No `DepositBindingTestOverride` resource is installed on testnet, so the
 * Move bridge computes these via the production Poseidon path.)
 *
 * Steps:
 *   1. Compute asset_id, vault_addr_hash via shared/poseidon_mirror.
 *   2. Build circom input JSON.
 *   3. Shell `node generate_witness.js` (circuits/generated/deposit_binding_js).
 *   4. Shell `snarkjs groth16 prove` against the existing zkey.
 *   5. Convert proof to Move uncompressed bytes (a||b||c, total 256B).
 *   6. Convert each public input to 32-byte LE.
 *   7. Return everything plus the user's chosen secret/nullifier/blind.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  deriveAssetId,
  deriveVaultAddrHash,
  compose5,
} from '../shared/src/poseidon_mirror.js';
import {
  POOL_ID_VALUE,
  FR_BYTES,
} from '../shared/src/types.js';
import { u64ToFieldLe32, u8ToFieldLe32 } from '../shared/src/hex.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = path.resolve(__dirname, '..', '..', 'circuits');
const GEN_DIR = path.join(CIRCUITS_DIR, 'generated');
const TMP_DIR = path.join(__dirname, '.deposit-proof-tmp');

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') ? s.slice(2) : s;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

/** Convert a 32-byte LE Fr buffer into a decimal-string BigInt for snarkjs input JSON. */
function le32ToDec(buf: Uint8Array): string {
  if (buf.length !== 32) throw new Error(`expected 32-byte buffer; got ${buf.length}`);
  let n = 0n;
  for (let i = buf.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(buf[i]);
  return n.toString();
}
/** Convert decimal-string Fr into 32-byte LE buffer. */
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

/** Convert a snarkjs-format G1 affine point [x,y,1] to 64-byte uncompressed (x_LE32 || y_LE32). */
function g1ToBytes(arr: string[]): Uint8Array {
  if (arr.length < 2) throw new Error(`G1 array too short: ${JSON.stringify(arr)}`);
  const out = new Uint8Array(64);
  out.set(decToLe32(arr[0]), 0);
  out.set(decToLe32(arr[1]), 32);
  return out;
}
/** Convert a snarkjs-format G2 affine point [[x0,x1],[y0,y1],...] to 128 bytes (x_c0||x_c1||y_c0||y_c1). */
function g2ToBytes(arr: string[][]): Uint8Array {
  const [x, y] = arr;
  if (!x || !y || x.length < 2 || y.length < 2)
    throw new Error(`G2 shape unexpected: ${JSON.stringify(arr)}`);
  const out = new Uint8Array(128);
  out.set(decToLe32(x[0]), 0);
  out.set(decToLe32(x[1]), 32);
  out.set(decToLe32(y[0]), 64);
  out.set(decToLe32(y[1]), 96);
  return out;
}

export interface DepositProofInputs {
  assetTypeAddr: Uint8Array; // 32 bytes (e.g. APT FA metadata 0xa zero-padded)
  vaultAddr: Uint8Array; // 32 bytes
  amountOctas: bigint; // u64
  nullifier: Uint8Array; // 32-byte LE Fr (caller-supplied secret)
  secret: Uint8Array; // 32-byte LE Fr (caller-supplied secret)
  depositBlind: Uint8Array; // 32-byte LE Fr
  chainId: number; // u8
}

export interface DepositProofResult {
  // Public inputs as 32-byte LE Fr buffers
  commitment: Uint8Array;
  amountTag: Uint8Array;
  assetIdLe32: Uint8Array;
  vaultAddrHashLe32: Uint8Array;
  chainIdLe32: Uint8Array;
  poolIdLe32: Uint8Array;
  // Proof bytes (256 = 64+128+64)
  proofBytes: Uint8Array;
  // For debugging / state file
  inputJsonPath: string;
  proofJsonPath: string;
  publicJsonPath: string;
}

export async function buildDepositProof(
  inputs: DepositProofInputs,
): Promise<DepositProofResult> {
  // ---- 1. Compute the 4 derived public inputs ----
  const assetIdLe32 = await deriveAssetId(inputs.assetTypeAddr);
  const vaultAddrHashLe32 = await deriveVaultAddrHash(inputs.vaultAddr);
  const chainIdLe32 = u8ToFieldLe32(inputs.chainId);
  const poolIdLe32 = u64ToFieldLe32(POOL_ID_VALUE); // 0n

  // ---- 2. Compute commitment + amount_tag via compose5 (matches circuit + Move) ----
  const amountLe32 = u64ToFieldLe32(inputs.amountOctas);
  const commitment = await compose5(
    inputs.nullifier,
    inputs.secret,
    assetIdLe32,
    amountLe32,
    poolIdLe32,
  );
  const amountTag = await compose5(
    amountLe32,
    inputs.depositBlind,
    assetIdLe32,
    vaultAddrHashLe32,
    chainIdLe32,
  );

  // ---- 3. Write circom input JSON ----
  fs.mkdirSync(TMP_DIR, { recursive: true });
  const circomInput = {
    commitment: le32ToDec(commitment),
    amount_tag: le32ToDec(amountTag),
    asset_id: le32ToDec(assetIdLe32),
    vault_addr_hash: le32ToDec(vaultAddrHashLe32),
    chain_id: le32ToDec(chainIdLe32),
    pool_id: le32ToDec(poolIdLe32),
    nullifier: le32ToDec(inputs.nullifier),
    secret: le32ToDec(inputs.secret),
    amount: inputs.amountOctas.toString(),
    deposit_blind: le32ToDec(inputs.depositBlind),
  };
  const inputPath = path.join(TMP_DIR, 'input_testnet.json');
  fs.writeFileSync(inputPath, JSON.stringify(circomInput, null, 2));

  // ---- 4. Generate witness ----
  const witnessPath = path.join(TMP_DIR, 'witness_testnet.wtns');
  const wasmPath = path.join(GEN_DIR, 'deposit_binding_js', 'deposit_binding.wasm');
  const witnessGenScript = path.join(GEN_DIR, 'deposit_binding_js', 'generate_witness.js');
  console.log('[proof] generating witness ...');
  execSync(
    `node "${witnessGenScript}" "${wasmPath}" "${inputPath}" "${witnessPath}"`,
    { stdio: 'inherit' },
  );

  // ---- 5. Generate Groth16 proof ----
  const proofPath = path.join(TMP_DIR, 'proof_testnet.json');
  const publicPath = path.join(TMP_DIR, 'public_testnet.json');
  const zkeyPath = path.join(GEN_DIR, 'deposit_binding_final.zkey');
  console.log('[proof] running snarkjs groth16 prove ...');
  execSync(
    `npx --prefix "${CIRCUITS_DIR}" snarkjs groth16 prove "${zkeyPath}" "${witnessPath}" "${proofPath}" "${publicPath}"`,
    { stdio: 'inherit', cwd: CIRCUITS_DIR },
  );

  // ---- 6. Convert snarkjs proof to Move uncompressed bytes ----
  const proof = JSON.parse(fs.readFileSync(proofPath, 'utf-8'));
  const aBytes = g1ToBytes(proof.pi_a);
  const bBytes = g2ToBytes(proof.pi_b);
  const cBytes = g1ToBytes(proof.pi_c);
  const proofBytes = new Uint8Array(64 + 128 + 64);
  proofBytes.set(aBytes, 0);
  proofBytes.set(bBytes, 64);
  proofBytes.set(cBytes, 64 + 128);

  // Sanity: confirm public_testnet.json matches our computed values.
  const pub = JSON.parse(fs.readFileSync(publicPath, 'utf-8')) as string[];
  const expected = [
    le32ToDec(commitment),
    le32ToDec(amountTag),
    le32ToDec(assetIdLe32),
    le32ToDec(vaultAddrHashLe32),
    le32ToDec(chainIdLe32),
    le32ToDec(poolIdLe32),
  ];
  for (let i = 0; i < 6; i++) {
    if (pub[i] !== expected[i]) {
      throw new Error(
        `public[${i}] mismatch: snarkjs=${pub[i]} expected=${expected[i]}`,
      );
    }
  }

  return {
    commitment,
    amountTag,
    assetIdLe32,
    vaultAddrHashLe32,
    chainIdLe32,
    poolIdLe32,
    proofBytes,
    inputJsonPath: inputPath,
    proofJsonPath: proofPath,
    publicJsonPath: publicPath,
  };
}
