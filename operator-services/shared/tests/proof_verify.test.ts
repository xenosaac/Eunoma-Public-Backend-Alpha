// Snarkjs Groth16 verify test (Pass criterion #6).
//
// Loads Gate 4a's exported VK + proof + public-input fixtures from
// circuits/generated/ and asserts:
//   - Valid proof + valid publics  => snarkjs.groth16.verify == true
//   - Valid proof + mutated publics => false (3 negatives, mirroring Gate 4b's
//     Move-side negatives: wrong amount_tag, wrong commitment, wrong amount).

import { describe, it, expect } from "vitest";
import { verifyGroth16Proof, loadDepositBindingVk } from "../src/proof_verify.js";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CIRCUITS_DIR = resolve(__dirname, "../../../circuits/generated");

function loadJson(p: string): any {
  return JSON.parse(readFileSync(resolve(CIRCUITS_DIR, p), "utf-8"));
}

describe("snarkjs Groth16 — deposit-binding circuit", () => {
  const proofValid = loadJson("proof_valid.json");
  const publicValid = loadJson("public_valid.json");
  const publicNegAmtTag = loadJson("public_invalid_wrong_amount_tag.json");
  const publicNegCmt = loadJson("public_invalid_wrong_commitment.json");
  const publicNegAmtIn = loadJson("public_invalid_amount_inconsistent.json");
  const vk = loadDepositBindingVk();

  it("groth16_verify_positive_accepts_valid_proof", async () => {
    const ok = await verifyGroth16Proof(proofValid, publicValid, vk);
    expect(ok).toBe(true);
  });

  it("groth16_verify_negative_wrong_amount_tag_rejects", async () => {
    const ok = await verifyGroth16Proof(proofValid, publicNegAmtTag, vk);
    expect(ok).toBe(false);
  });

  it("groth16_verify_negative_wrong_commitment_rejects", async () => {
    const ok = await verifyGroth16Proof(proofValid, publicNegCmt, vk);
    expect(ok).toBe(false);
  });

  it("groth16_verify_negative_amount_inconsistent_rejects", async () => {
    const ok = await verifyGroth16Proof(proofValid, publicNegAmtIn, vk);
    expect(ok).toBe(false);
  });
});
