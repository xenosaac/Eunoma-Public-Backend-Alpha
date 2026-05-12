// snarkjs Groth16 verifier wrapper.
//
// Loads the Gate 4a-exported VK from `circuits/generated/deposit_binding_vk.json`
// and verifies a proof+publics tuple via snarkjs.groth16.verify. Returns
// boolean. This validates that the same VK + circuit produces consistent
// verify results across snarkjs (off-chain) and Move's `crypto_algebra` BN254
// natives (on-chain) — Gate 4a confirmed the on-chain side; Gate 4c confirms
// the off-chain side independently.

import * as snarkjs from "snarkjs";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { decToLe32, le32ToDec } from "./withdraw_canonical.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

function defaultDepositVkPath(): string {
  return resolve(__dirname, "../../../circuits/generated/deposit_binding_vk.json");
}

function defaultWithdrawalVkPath(): string {
  return resolve(__dirname, "../../../circuits/generated/withdrawal_proof_vk.json");
}

let cachedDepositVk: any | null = null;
let cachedWithdrawalVk: any | null = null;

export function loadDepositBindingVk(path?: string): any {
  if (cachedDepositVk && !path) return cachedDepositVk;
  const vkPath = path ?? defaultDepositVkPath();
  const raw = readFileSync(vkPath, "utf-8");
  const vk = JSON.parse(raw);
  if (!path) cachedDepositVk = vk;
  return vk;
}

export function loadWithdrawalProofVk(path?: string): any {
  if (cachedWithdrawalVk && !path) return cachedWithdrawalVk;
  const vkPath = path ?? defaultWithdrawalVkPath();
  const raw = readFileSync(vkPath, "utf-8");
  const vk = JSON.parse(raw);
  if (!path) cachedWithdrawalVk = vk;
  return vk;
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

export async function verifyGroth16Proof(
  proof: Groth16Proof,
  publicInputs: string[],
  vkOverride?: any,
): Promise<boolean> {
  const vk = vkOverride ?? loadDepositBindingVk();
  try {
    return await snarkjs.groth16.verify(vk, publicInputs, proof);
  } catch (err) {
    return false;
  }
}

/// Decode a 256-byte uncompressed Groth16 proof (Move on-chain representation:
/// `a_x_le32 || a_y_le32 || b_x0_le32 || b_x1_le32 || b_y0_le32 || b_y1_le32 ||
///  c_x_le32 || c_y_le32`) into the snarkjs JSON shape used by `groth16.verify`.
///
/// snarkjs expects projective coords with the affine `z = 1`. For G1 z = "1";
/// for G2 z = ["1", "0"] (Fp2 element with c0 = 1, c1 = 0). Inverse of
/// `g1ToBytes` / `g2ToBytes` in `withdraw_canonical.ts`.
export function compact256ToSnarkjsProof(proofBytes: Uint8Array): Groth16Proof {
  if (proofBytes.length !== 256) {
    throw new Error(
      `compact256ToSnarkjsProof: expected 256 bytes (a||b||c), got ${proofBytes.length}`,
    );
  }
  const a_x = le32ToDec(proofBytes.subarray(0, 32));
  const a_y = le32ToDec(proofBytes.subarray(32, 64));
  const b_x0 = le32ToDec(proofBytes.subarray(64, 96));
  const b_x1 = le32ToDec(proofBytes.subarray(96, 128));
  const b_y0 = le32ToDec(proofBytes.subarray(128, 160));
  const b_y1 = le32ToDec(proofBytes.subarray(160, 192));
  const c_x = le32ToDec(proofBytes.subarray(192, 224));
  const c_y = le32ToDec(proofBytes.subarray(224, 256));
  return {
    pi_a: [a_x, a_y, "1"],
    pi_b: [
      [b_x0, b_x1],
      [b_y0, b_y1],
      ["1", "0"],
    ],
    pi_c: [c_x, c_y, "1"],
    protocol: "groth16",
    curve: "bn128",
  };
}

/// Verify a withdrawal Groth16 proof against the cached withdrawal VK.
///
/// `proofBytes`: 256-byte uncompressed proof (same shape the Move bridge sees).
/// `publicInputs`: 8 decimal-string field elements in circuit order
///   [root, nullifier_hash, asset_id, recipient_hash, amount_tag,
///    ca_payload_hash, request_hash, vault_sequence]
/// (see `withdrawal_proof.circom:224-233`).
export async function verifyWithdrawalGroth16Proof(
  proofBytes: Uint8Array,
  publicInputs: string[],
  vkOverride?: any,
): Promise<boolean> {
  if (publicInputs.length !== 8) {
    return false;
  }
  let proof: Groth16Proof;
  try {
    proof = compact256ToSnarkjsProof(proofBytes);
  } catch {
    return false;
  }
  const vk = vkOverride ?? loadWithdrawalProofVk();
  try {
    return await snarkjs.groth16.verify(vk, publicInputs, proof);
  } catch {
    return false;
  }
}

// Re-export the LE32 ↔ decimal helpers so callers that already pull from
// `@eunoma/shared/proof_verify` don't need a second import path.
export { le32ToDec, decToLe32 };
