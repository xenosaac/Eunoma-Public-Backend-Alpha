#!/usr/bin/env node
// M8-p — Verify CA DKG V2 dk-binding to chain vault_ek.
//
// Reads dk_share from slots {0,1,2,3,4}/ca_dkg_share_v2.json, Lagrange-reconstructs
// dk_REAL at x=0 over ed25519 scalar field (slot i ↔ x = i+1 per
// crypto-worker-rust/src/lib.rs:1091), then compares H_RISTRETTO · (dk_REAL)^-1
// against chain vault_ek.
//
// If byte-equal: σ-proof response[0] verifies on chain → withdraw works.
// If divergent: the MPC vault_ek derivation does NOT realize ek = H·dk^-1 under
// the same dk_REAL = Σ λⱼ dk_shareⱼ. That is the protocol-level structural gap.

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519";
import { mod, invert } from "@noble/curves/abstract/modular";
import { H_RISTRETTO, RistrettoPoint } from "@aptos-labs/confidential-asset";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const stateRoot = resolve(scriptDir, "..", ".agent-local", "eunoma-v2");
const expectedVaultEkHex = process.env.EXPECTED_VAULT_EK_HEX
  ?? "462d5083eee9b2ffb296fab1f925b9e261ad4caf6cb468b660df8fbc17249070";
const selectedSlots = [0, 1, 2, 3, 4];

const ED_N = ed25519.CURVE.n;

function hexToScalarLE(hex) {
  // dk_share is stored as 32-byte little-endian per Curve25519/Ristretto convention.
  const bytes = Buffer.from(hex.replace(/^0x/, ""), "hex");
  if (bytes.length !== 32) throw new Error(`expected 32 bytes, got ${bytes.length}`);
  let x = 0n;
  for (let i = 31; i >= 0; i--) {
    x = (x << 8n) | BigInt(bytes[i]);
  }
  return mod(x, ED_N);
}

function scalarToHex32LE(s) {
  let v = mod(s, ED_N);
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out.toString("hex");
}

function lagrangeAtZero(slots) {
  // slot i ↔ x = i+1
  const xs = slots.map((s) => BigInt(s + 1));
  return xs.map((xj) => {
    let num = 1n;
    let den = 1n;
    for (const xm of xs) {
      if (xm === xj) continue;
      num = mod(num * mod(-xm, ED_N), ED_N);
      den = mod(den * mod(xj - xm, ED_N), ED_N);
    }
    return mod(num * invert(den, ED_N), ED_N);
  });
}

const dkShares = selectedSlots.map((slot) => {
  const path = resolve(stateRoot, `slot-${slot}`, "ca_dkg_share_v2.json");
  const json = JSON.parse(readFileSync(path, "utf8"));
  if (json.slot !== slot) throw new Error(`slot mismatch at ${path}`);
  return { slot, dkShare: hexToScalarLE(json.dkShare) };
});

const lambdas = lagrangeAtZero(selectedSlots);
console.log("Lagrange coefficients at x=0 for slots [0,1,2,3,4]:");
selectedSlots.forEach((s, i) => {
  // Print decimal mod L for readability
  const dec = lambdas[i] < ED_N / 2n ? lambdas[i] : lambdas[i] - ED_N;
  console.log(`  λ[slot=${s}, x=${s + 1}] = ${dec.toString()} (mod L)`);
});

let dkReal = 0n;
for (let i = 0; i < selectedSlots.length; i++) {
  dkReal = mod(dkReal + lambdas[i] * dkShares[i].dkShare, ED_N);
}
console.log(`\ndk_REAL (mod L, LE hex) = ${scalarToHex32LE(dkReal)}`);

// Sanity: dk_REAL must be non-zero
if (dkReal === 0n) {
  console.error("FATAL: dk_REAL reconstructed to zero — DKG broken or wrong slot mapping");
  process.exit(1);
}

// Compute candidate ek = H · dk_REAL^-1
const dkInv = invert(dkReal, ED_N);
const candidateEk = H_RISTRETTO.multiply(dkInv);
const candidateEkHex = Buffer.from(candidateEk.toRawBytes()).toString("hex");

console.log(`\nH · dk_REAL^-1  = ${candidateEkHex}`);
console.log(`chain vault_ek  = ${expectedVaultEkHex}`);

const matches = candidateEkHex === expectedVaultEkHex.replace(/^0x/, "");
console.log(`\nMATCH: ${matches ? "YES — dk-binding holds; σ-proof response[0] will verify" : "NO — MPC vault_ek does NOT equal H·dk_REAL^-1 under same dk_REAL semantics"}`);

if (!matches) {
  // Try a couple of alternate sign / endian conventions in case storage convention differs.
  // Variant A: dk_share is BIG-endian
  function hexToScalarBE(hex) {
    const bytes = Buffer.from(hex.replace(/^0x/, ""), "hex");
    let x = 0n;
    for (let i = 0; i < 32; i++) x = (x << 8n) | BigInt(bytes[i]);
    return mod(x, ED_N);
  }
  const dkSharesBE = selectedSlots.map((slot) => {
    const path = resolve(stateRoot, `slot-${slot}`, "ca_dkg_share_v2.json");
    const json = JSON.parse(readFileSync(path, "utf8"));
    return hexToScalarBE(json.dkShare);
  });
  let dkRealBE = 0n;
  for (let i = 0; i < selectedSlots.length; i++) {
    dkRealBE = mod(dkRealBE + lambdas[i] * dkSharesBE[i], ED_N);
  }
  const candidateEkBE = H_RISTRETTO.multiply(invert(dkRealBE, ED_N));
  const ehexBE = Buffer.from(candidateEkBE.toRawBytes()).toString("hex");
  console.log(`\n[Variant BE] H · dk_REAL^-1 = ${ehexBE}  (match=${ehexBE === expectedVaultEkHex.replace(/^0x/, "")})`);

  // Variant B: use x = slot (not slot+1)
  function lagrangeAtZeroSlotX(slots) {
    const xs = slots.map((s) => BigInt(s === 0 ? 7 : s)); // try slot=0 → x=7 (peer count) as a sanity
    return xs.map((xj) => {
      let num = 1n, den = 1n;
      for (const xm of xs) {
        if (xm === xj) continue;
        num = mod(num * mod(-xm, ED_N), ED_N);
        den = mod(den * mod(xj - xm, ED_N), ED_N);
      }
      return mod(num * invert(den, ED_N), ED_N);
    });
  }
  // skip variant B — slot=0 must map to a non-zero x in any sane scheme, and lib.rs:1091 says slot+1.
}
