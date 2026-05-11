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

const __dirname = dirname(fileURLToPath(import.meta.url));

// Default VK location — repo-relative. Operators can override via env.
function defaultVkPath(): string {
  // src/proof_verify.ts -> operator-services/shared/src -> operator-services/shared
  // -> operator-services -> ConfidentialAPT -> circuits/generated/deposit_binding_vk.json
  return resolve(__dirname, "../../../circuits/generated/deposit_binding_vk.json");
}

let cachedVk: any | null = null;

export function loadDepositBindingVk(path?: string): any {
  if (cachedVk && !path) return cachedVk;
  const vkPath = path ?? defaultVkPath();
  const raw = readFileSync(vkPath, "utf-8");
  const vk = JSON.parse(raw);
  if (!path) cachedVk = vk;
  return vk;
}

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol: string;
  curve: string;
}

/// Verify a Groth16 proof. `publicInputs` is an array of decimal-string field
/// elements (snarkjs convention). Returns true iff the proof is valid.
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
