#!/usr/bin/env node
// Run BOTH the SDK's verifyTransfer AND my hand-rolled per-position verifier
// against the SAME inputs in one script to ensure they share input shape.
// If SDK says false but local says true, there's a SDK input-shape bug.

import { readFileSync } from "node:fs";
import {
  verifyTransfer,
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

const ED_N = ed25519.CURVE.n;
function hexBytes(h) { return Buffer.from(h.replace(/^0x/, ""), "hex"); }
function rp(h) { return RistrettoPoint.fromHex(hexBytes(h)); }
function bytesToScalarLE(b) { let x = 0n; for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return mod(x, ED_N); }
function pointsEqual(a, b) { return Buffer.from(a.toRawBytes()).equals(Buffer.from(b.toRawBytes())); }

const r2 = JSON.parse(readFileSync(round2Path, "utf8"));
const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const a = fin.mpccaWithdrawFinalizeArtifact;
const si = r2.statementInputs;

const ell = si.oldBalanceC.length;
const N = si.transferAmountC.length;

const sdkInput = {
  senderAddress: hexBytes(r2.senderAddress),
  recipientAddress: hexBytes(r2.recipient),
  tokenAddress: hexBytes(r2.assetType),
  chainId: r2.chainId,
  ekSidBytes: hexBytes(r2.vaultEk),
  ekRidBytes: hexBytes(si.recipientEk),
  oldBalanceC: si.oldBalanceC.map(rp),
  oldBalanceD: si.oldBalanceD.map(rp),
  newBalanceC: si.newBalanceC.map(rp),
  newBalanceD: si.newBalanceD.map(rp),
  transferAmountC: si.transferAmountC.map(rp),
  transferAmountDSender: si.transferAmountDSender.map(rp),
  transferAmountDRecipient: si.transferAmountDRecipient.map(rp),
  hasEffectiveAuditor: false,
  auditorEkBytes: [],
  newBalanceDAud: [],
  transferAmountDAud: [],
  proof: {
    commitment: a.aggregatedSigmaCommitmentsHex,
    response: a.sigmaResponseHex.map((h) => hexBytes(h)),
  },
};

const sdkResult = verifyTransfer(sdkInput);
console.log("SDK verifyTransfer =", sdkResult);

// Now my local per-position verifier with EXACTLY the same intermediate values
const G = RistrettoPoint.BASE;
const H = H_RISTRETTO;
const ek_src = rp(r2.vaultEk);
const ek_dst = rp(si.recipientEk);
const oldBC = si.oldBalanceC.map(rp);
const oldBD = si.oldBalanceD.map(rp);
const newBC = si.newBalanceC.map(rp);
const newBD = si.newBalanceD.map(rp);
const txC = si.transferAmountC.map(rp);
const txDS = si.transferAmountDSender.map(rp);
const txDR = si.transferAmountDRecipient.map(rp);
const points = [G, H, ek_src, ek_dst, ...oldBC, ...oldBD, ...newBC, ...newBD, ...txC, ...txDS, ...txDR];
const compressedPoints = points.map((p) => p.toRawBytes());
const stmt = { points, compressedPoints, scalars: [] };
const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";
const PROTOCOL_ID = "AptosConfidentialAsset/TransferV1";
const sessionId = bcsSerializeTransferSession(hexBytes(r2.senderAddress), hexBytes(r2.recipient), hexBytes(r2.assetType), ell, N, false, 0);
const dst = { contractAddress: APTOS_FRAMEWORK_ADDRESS, chainId: r2.chainId, protocolId: new TextEncoder().encode(PROTOCOL_ID), sessionId };
const compressedA = a.aggregatedSigmaCommitmentsHex.map((h) => hexBytes(h));
const { e } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, compressedA, 25);

const responses = a.sigmaResponseHex.map((h) => bytesToScalarLE(hexBytes(h)));
const m = responses[0];
const d = responses.slice(1, 1 + ell);
const u = responses.slice(1 + ell, 1 + 2 * ell);
const c = responses.slice(1 + 2 * ell, 1 + 2 * ell + N);
const y = responses.slice(1 + 2 * ell + N, 1 + 2 * ell + 2 * N);

function powers(k) {
  const base = 1n << 16n;
  const arr = [1n];
  for (let i = 1; i < k; i++) arr.push(mod(arr[i - 1] * base, ED_N));
  return arr;
}
const powEll = powers(ell), powN = powers(N);

const lhs = [];
lhs.push(ek_src.multiply(m));
for (let i = 0; i < ell; i++) lhs.push(G.multiply(d[i]).add(H.multiply(u[i])));
for (let i = 0; i < ell; i++) lhs.push(ek_src.multiply(u[i]));
let S = RistrettoPoint.ZERO;
for (let i = 0; i < ell; i++) S = S.add(oldBD[i].multiply(mod(m * powEll[i], ED_N)));
for (let i = 0; i < ell; i++) S = S.add(G.multiply(mod(d[i] * powEll[i], ED_N)));
for (let j = 0; j < N; j++) S = S.add(G.multiply(mod(c[j] * powN[j], ED_N)));
lhs.push(S);
for (let j = 0; j < N; j++) lhs.push(G.multiply(c[j]).add(H.multiply(y[j])));
for (let j = 0; j < N; j++) lhs.push(ek_src.multiply(y[j]));
for (let j = 0; j < N; j++) lhs.push(ek_dst.multiply(y[j]));

const rhs = [];
rhs.push(H);
for (let i = 0; i < ell; i++) rhs.push(newBC[i]);
for (let i = 0; i < ell; i++) rhs.push(newBD[i]);
let cAgg = RistrettoPoint.ZERO;
for (let i = 0; i < ell; i++) cAgg = cAgg.add(oldBC[i].multiply(powEll[i]));
rhs.push(cAgg);
for (let j = 0; j < N; j++) rhs.push(txC[j]);
for (let j = 0; j < N; j++) rhs.push(txDS[j]);
for (let j = 0; j < N; j++) rhs.push(txDR[j]);

const commitments = compressedA.map((b) => RistrettoPoint.fromHex(b));
let allOk = true;
for (let i = 0; i < 30; i++) {
  const expected = commitments[i].add(rhs[i].multiply(e));
  const ok = pointsEqual(lhs[i], expected);
  if (!ok) { allOk = false; console.log(`  [${i}] FAIL`); }
}
console.log("Local 30-pos =", allOk);

// Final reconciliation: if SDK !== local, dig into responses parsing
console.log("\n[Comparison]");
console.log(`  SDK: ${sdkResult}`);
console.log(`  Loc: ${allOk}`);
if (sdkResult !== allOk) {
  console.log("\nDIVERGENT. Logging SDK-side `e`:");
  // Try to compute e from the SDK call exactly the same way as my local code.
  // If 'e' matches between SDK and local, the bug is downstream (response parse / lhs/rhs).
  console.log("  local e:", e.toString(16).padStart(64, "0"));
  // Compute via the SDK's path
  const sdkE = (() => {
    // Replicate verifyTransfer's stmt construction.
    const G = RistrettoPoint.BASE;
    const H = H_RISTRETTO;
    const D = rp(r2.vaultEk);
    const P = rp(si.recipientEk);
    const z = [G, H, D, P];
    const V = [G.toRawBytes(), H.toRawBytes(), hexBytes(r2.vaultEk), hexBytes(si.recipientEk)];
    for (let i = 0; i < ell; i++) { z.push(oldBC[i]); V.push(oldBC[i].toRawBytes()); }
    for (let i = 0; i < ell; i++) { z.push(oldBD[i]); V.push(oldBD[i].toRawBytes()); }
    for (let i = 0; i < ell; i++) { z.push(newBC[i]); V.push(newBC[i].toRawBytes()); }
    for (let i = 0; i < ell; i++) { z.push(newBD[i]); V.push(newBD[i].toRawBytes()); }
    for (let i = 0; i < N; i++) { z.push(txC[i]); V.push(txC[i].toRawBytes()); }
    for (let i = 0; i < N; i++) { z.push(txDS[i]); V.push(txDS[i].toRawBytes()); }
    for (let i = 0; i < N; i++) { z.push(txDR[i]); V.push(txDR[i].toRawBytes()); }
    const Y = { points: z, compressedPoints: V, scalars: [] };
    const W = bcsSerializeTransferSession(hexBytes(r2.senderAddress), hexBytes(r2.recipient), hexBytes(r2.assetType), ell, N, false, 0);
    const et = { contractAddress: APTOS_FRAMEWORK_ADDRESS, chainId: r2.chainId, protocolId: new TextEncoder().encode(PROTOCOL_ID), sessionId: W };
    const { e } = sigmaProtocolFiatShamir(et, TYPE_NAME, Y, compressedA, 25);
    return e;
  })();
  console.log("  sdk-path e:", sdkE.toString(16).padStart(64, "0"));
  console.log("  e matches?", e === sdkE);
}
