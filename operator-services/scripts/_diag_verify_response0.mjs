#!/usr/bin/env node
// Verify the σ-proof identity at index 0 against persisted finalize artifact:
//
//   vault_ek · s[0] ?= aggregated[0] + e · H
//
// where:
//   - vault_ek = 0x462d5083... (chain-stored, equivalently H · dk_REAL^-1 verified by _diag_verify_dk_binding.mjs)
//   - s[0]     = aggregated response (Σ λⱼ · partial_response_j) reconstructed by coordinator
//   - aggregated[0] = α[0] · vault_ek (chain expects this)
//   - e        = Fiat-Shamir challenge over the 30 commitments
//
// Also verify aggregated s[0] = Σ λⱼ · partial_response_j byte-canonically.

import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";
import { mod, invert } from "@noble/curves/abstract/modular";
import { H_RISTRETTO, RistrettoPoint } from "@aptos-labs/confidential-asset";

const finalizePath = process.argv[2];
if (!finalizePath) {
  console.error("usage: node scripts/_diag_verify_response0.mjs <finalize.json>");
  process.exit(2);
}

const ED_N = ed25519.CURVE.n;
function hexToScalarLE(hex) {
  const b = Buffer.from(hex.replace(/^0x/, ""), "hex");
  let x = 0n; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return mod(x, ED_N);
}
function scalarToHexLE(s) {
  let v = mod(s, ED_N); const o = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) { o[i] = Number(v & 0xffn); v >>= 8n; }
  return o.toString("hex");
}
function rp(hex) { return RistrettoPoint.fromHex(Buffer.from(hex.replace(/^0x/, ""), "hex")); }
function bhex(p) { return Buffer.from(p.toRawBytes()).toString("hex"); }
function lagrangeAtZero(slots) {
  const xs = slots.map((s) => BigInt(s + 1));
  return xs.map((xj) => {
    let n = 1n, d = 1n;
    for (const xm of xs) {
      if (xm === xj) continue;
      n = mod(n * mod(-xm, ED_N), ED_N);
      d = mod(d * mod(xj - xm, ED_N), ED_N);
    }
    return mod(n * invert(d, ED_N), ED_N);
  });
}

const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const a = fin.mpccaWithdrawFinalizeArtifact;
const e = hexToScalarLE(a.challengeHex);
const sAgg = hexToScalarLE(a.sigmaResponseHex[0]);
const aggC0 = rp(a.aggregatedSigmaCommitmentsHex[0]);
const vaultEkHex = "462d5083eee9b2ffb296fab1f925b9e261ad4caf6cb468b660df8fbc17249070";
const vaultEk = rp(vaultEkHex);
const H = H_RISTRETTO;

console.log("challenge e (LE) =", a.challengeHex);
console.log("aggregated[0]    =", a.aggregatedSigmaCommitmentsHex[0]);
console.log("aggregated s[0]  =", a.sigmaResponseHex[0]);

// === Check 1: vault_ek · s[0] == aggregated[0] + e · H
const lhs = vaultEk.multiply(sAgg);
const rhs = aggC0.add(H.multiply(e));
const ok1 = bhex(lhs) === bhex(rhs);
console.log(`\n[verifier identity] vault_ek · s[0] == aggregated[0] + e · H : ${ok1 ? "PASS" : "FAIL"}`);
console.log(`  LHS = ${bhex(lhs)}`);
console.log(`  RHS = ${bhex(rhs)}`);

// === Check 2: aggregated s[0] = Σ λⱼ · partial_response_j
const selectedSlots = a.perSlotContributions.map((c) => c.slot);
const lambdas = lagrangeAtZero(selectedSlots);
console.log(`\nselectedSlots: ${JSON.stringify(selectedSlots)}`);
let sReconstructed = 0n;
for (let i = 0; i < selectedSlots.length; i++) {
  const partial = hexToScalarLE(a.perSlotContributions[i].partialResponseDkHex);
  sReconstructed = mod(sReconstructed + lambdas[i] * partial, ED_N);
  const lamSigned = lambdas[i] < ED_N / 2n ? lambdas[i] : lambdas[i] - ED_N;
  console.log(`  λ[${i}]=${lamSigned} · partial[${selectedSlots[i]}]=${a.perSlotContributions[i].partialResponseDkHex.slice(0, 16)}…`);
}
const reconstructedHex = scalarToHexLE(sReconstructed);
const ok2 = reconstructedHex === a.sigmaResponseHex[0];
console.log(`\n[threshold reconstruction] Σ λⱼ · partial_j == aggregated s[0] : ${ok2 ? "PASS" : "FAIL"}`);
console.log(`  reconstructed = ${reconstructedHex}`);
console.log(`  aggregated    = ${a.sigmaResponseHex[0]}`);
