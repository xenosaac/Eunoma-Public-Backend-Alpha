#!/usr/bin/env node
// Replicate the SDK's verifyTransfer σ check per-position to identify which
// position(s) fail. CA TransferV1 with ell=8, N=4, no auditor, the verifier
// has 30 positions (1+e+e+1+t+t+t = 1+8+8+1+4+4+4 = 30).

import { readFileSync } from "node:fs";
import {
  RistrettoPoint,
  H_RISTRETTO,
  bcsSerializeTransferSession,
  sigmaProtocolFiatShamir,
  APTOS_FRAMEWORK_ADDRESS,
} from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";
import { mod } from "@noble/curves/abstract/modular";

const round2Path = process.argv[2];
const finalizePath = process.argv[3];
if (!round2Path || !finalizePath) {
  console.error("usage: ...");
  process.exit(2);
}

const ED_N = ed25519.CURVE.n;
function hexBytes(h) { return Buffer.from(h.replace(/^0x/, ""), "hex"); }
function rp(h) { return RistrettoPoint.fromHex(hexBytes(h)); }
function bytesToScalarLE(b) {
  let x = 0n; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return mod(x, ED_N);
}
function pointsEqual(a, b) {
  return Buffer.from(a.toRawBytes()).equals(Buffer.from(b.toRawBytes()));
}

const r2 = JSON.parse(readFileSync(round2Path, "utf8"));
const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const a = fin.mpccaWithdrawFinalizeArtifact;
const si = r2.statementInputs;

const G = RistrettoPoint.BASE;
const H = H_RISTRETTO;
const ek_src = rp(r2.vaultEk);
const ek_dst = rp(si.recipientEk);
const ell = si.oldBalanceC.length;   // 8
const N = si.transferAmountC.length; // 4

const oldBC = si.oldBalanceC.map(rp);
const oldBD = si.oldBalanceD.map(rp);
const newBC = si.newBalanceC.map(rp);
const newBD = si.newBalanceD.map(rp);
const txC   = si.transferAmountC.map(rp);
const txDS  = si.transferAmountDSender.map(rp);
const txDR  = si.transferAmountDRecipient.map(rp);

// Layout: G, H, ek_src, ek_dst, oldBC[0..ell-1], oldBD[..], newBC[..], newBD[..], txC[..], txDS[..], txDR[..]
const points = [G, H, ek_src, ek_dst, ...oldBC, ...oldBD, ...newBC, ...newBD, ...txC, ...txDS, ...txDR];
const compressedPoints = points.map((p) => p.toRawBytes());

const stmt = { points, compressedPoints, scalars: [] };
const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";
const PROTOCOL_ID = "AptosConfidentialAsset/TransferV1";
const senderBytes = hexBytes(r2.senderAddress);
const recipientBytes = hexBytes(r2.recipient);
const assetBytes = hexBytes(r2.assetType);

const sessionId = bcsSerializeTransferSession(senderBytes, recipientBytes, assetBytes, ell, N, false, 0);
const dst = { contractAddress: APTOS_FRAMEWORK_ADDRESS, chainId: r2.chainId, protocolId: new TextEncoder().encode(PROTOCOL_ID), sessionId };

const compressedA = a.aggregatedSigmaCommitmentsHex.map((h) => hexBytes(h));
const { e } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, compressedA, 25);
console.log("Fiat-Shamir e (local) =", e.toString(16).padStart(64, "0"));
console.log("challenge persisted   =", a.challengeHex);

// Verify challenge matches persisted
const eBytes = (() => { const b = Buffer.alloc(32); let v = e; for (let i = 0; i < 32; i++) { b[i] = Number(v & 0xffn); v >>= 8n; } return b.toString("hex"); })();
if (eBytes !== a.challengeHex) {
  console.error("FATAL: locally derived e does NOT match persisted challengeHex");
  console.error(" local:", eBytes);
  console.error(" disk :", a.challengeHex);
  process.exit(1);
}
console.log("[challenge] LOCAL == DISK : PASS");

// Parse responses (25 scalars: m, d[0..ell-1], u[0..ell-1], c[0..N-1], y[0..N-1])
const responses = a.sigmaResponseHex.map((h) => bytesToScalarLE(hexBytes(h)));
const m = responses[0];
const d = responses.slice(1, 1 + ell);
const u = responses.slice(1 + ell, 1 + 2 * ell);
const c = responses.slice(1 + 2 * ell, 1 + 2 * ell + N);
const y = responses.slice(1 + 2 * ell + N, 1 + 2 * ell + 2 * N);

// Build expected lhs[] per the jt(K, D, B, P) function
function powers(k) {
  const base = 1n << 16n;
  const arr = [1n];
  for (let i = 1; i < k; i++) arr.push(mod(arr[i - 1] * base, ED_N));
  return arr;
}

const lhs = [];
lhs.push(ek_src.multiply(m)); // index 0
for (let i = 0; i < ell; i++) lhs.push(G.multiply(d[i]).add(H.multiply(u[i]))); // indices 1..ell
for (let i = 0; i < ell; i++) lhs.push(ek_src.multiply(u[i])); // indices 1+ell..1+2*ell-1

// Aggregate S at index 17. Per SDK: B = Oe(e) = $+e = 4+e starts at oldBalanceD (NOT oldBalanceC).
// Layout: G(0), H(1), ek_src(2), ek_dst(3), oldBalanceC[0..ell-1] @ 4..ell+3, oldBalanceD[0..ell-1] @ ell+4..2ell+3
// So o.points[B+l] = oldBalanceD[l].
//   S = Σ_l oldBalanceD[l] * (m * powEll[l]) + Σ_l G * (d[l] * powEll[l]) + Σ_j G * (c[j] * powN[j])
const powEll = powers(ell);
const powN = powers(N);
let S = RistrettoPoint.ZERO;
for (let i = 0; i < ell; i++) S = S.add(oldBD[i].multiply(mod(m * powEll[i], ED_N)));
for (let i = 0; i < ell; i++) S = S.add(G.multiply(mod(d[i] * powEll[i], ED_N)));
for (let j = 0; j < N; j++) S = S.add(G.multiply(mod(c[j] * powN[j], ED_N)));
lhs.push(S); // index 1+2*ell = 17

for (let j = 0; j < N; j++) lhs.push(G.multiply(c[j]).add(H.multiply(y[j]))); // indices 18..21
for (let j = 0; j < N; j++) lhs.push(ek_src.multiply(y[j]));                  // indices 22..25
for (let j = 0; j < N; j++) lhs.push(ek_dst.multiply(y[j]));                  // indices 26..29

// Build expected rhs[] per Ve(K, D, B, P)
const rhs = [];
rhs.push(H);                          // 0
for (let i = 0; i < ell; i++) rhs.push(newBC[i]); // 1..8
for (let i = 0; i < ell; i++) rhs.push(newBD[i]); // 9..16
// aggregate rhs at index 17 per SDK Ve(): Σ o.points[$+l] * powEll[l]  where $=4 = oldBalanceC start.
let cAgg = RistrettoPoint.ZERO;
for (let i = 0; i < ell; i++) cAgg = cAgg.add(oldBC[i].multiply(powEll[i]));
rhs.push(cAgg);                       // 17 — uses oldBalanceC per the verifier's Ve()
for (let j = 0; j < N; j++) rhs.push(txC[j]); // 18..21
for (let j = 0; j < N; j++) rhs.push(txDS[j]); // 22..25
for (let j = 0; j < N; j++) rhs.push(txDR[j]); // 26..29

if (lhs.length !== 30 || rhs.length !== 30) {
  console.error(`length mismatch: lhs=${lhs.length} rhs=${rhs.length}`);
  process.exit(1);
}

console.log(`\nVerifying ${lhs.length} positions: lhs[i] ?= commitment[i] + e · rhs[i]`);
const commitments = compressedA.map((b) => RistrettoPoint.fromHex(b));
let fails = 0;
for (let i = 0; i < 30; i++) {
  const expected = commitments[i].add(rhs[i].multiply(e));
  const ok = pointsEqual(lhs[i], expected);
  if (!ok) {
    fails++;
    console.log(`  [${String(i).padStart(2)}] FAIL  lhs=${Buffer.from(lhs[i].toRawBytes()).toString("hex").slice(0, 16)}…  expected=${Buffer.from(expected.toRawBytes()).toString("hex").slice(0, 16)}…`);
  } else {
    console.log(`  [${String(i).padStart(2)}] OK`);
  }
}
console.log(`\nfails=${fails}/30`);
