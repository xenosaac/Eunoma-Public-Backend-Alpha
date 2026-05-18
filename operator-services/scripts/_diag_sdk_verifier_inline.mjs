#!/usr/bin/env node
// Direct inline of the SDK's verifyTransfer with per-position logging.

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
import { bytesToNumberLE } from "@noble/curves/abstract/utils";

const round2Path = process.argv[2];
const finalizePath = process.argv[3];

const ED_N = ed25519.CURVE.n;
function hexBytes(h) { return Buffer.from(h.replace(/^0x/, ""), "hex"); }
function rp(h) { return RistrettoPoint.fromHex(hexBytes(h)); }

const r2 = JSON.parse(readFileSync(round2Path, "utf8"));
const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const a = fin.mpccaWithdrawFinalizeArtifact;
const si = r2.statementInputs;

const G = RistrettoPoint.BASE;
const H = H_RISTRETTO;
const ek_src = rp(r2.vaultEk);
const ek_dst = rp(si.recipientEk);
const ell = si.oldBalanceC.length;
const N = si.transferAmountC.length;
const oldBC = si.oldBalanceC.map(rp);
const oldBD = si.oldBalanceD.map(rp);
const newBC = si.newBalanceC.map(rp);
const newBD = si.newBalanceD.map(rp);
const txC = si.transferAmountC.map(rp);
const txDS = si.transferAmountDSender.map(rp);
const txDR = si.transferAmountDRecipient.map(rp);
const points = [G, H, ek_src, ek_dst, ...oldBC, ...oldBD, ...newBC, ...newBD, ...txC, ...txDS, ...txDR];
const V = points.map((p) => p.toRawBytes());
const Y = { points, compressedPoints: V, scalars: [] };
const W = bcsSerializeTransferSession(hexBytes(r2.senderAddress), hexBytes(r2.recipient), hexBytes(r2.assetType), ell, N, false, 0);
const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";
const PROTOCOL_ID = "AptosConfidentialAsset/TransferV1";
const dst = { contractAddress: APTOS_FRAMEWORK_ADDRESS, chainId: r2.chainId, protocolId: new TextEncoder().encode(PROTOCOL_ID), sessionId: W };

const commitments = a.aggregatedSigmaCommitmentsHex.map((h) => hexBytes(h));
const responses = a.sigmaResponseHex.map((h) => hexBytes(h));

// Replicate SDK X():
const { e } = sigmaProtocolFiatShamir(dst, TYPE_NAME, Y, commitments, responses.length);
console.log("e =", e.toString(16).padStart(64, "0"));

// y = responses.map(a => bytesToNumberLE(a))
const y = responses.map((b) => bytesToNumberLE(b));
console.log("response scalars (first 3):", y.slice(0, 3).map((s) => s.toString(16).padStart(64, "0")));

// jt(8, 4, false, 0)
function jt_call(s_resp) {
  const m_scalar = s_resp[0];
  const d_resp = s_resp.slice(1, 1 + ell);
  const u_resp = s_resp.slice(1 + ell, 1 + 2 * ell);
  const c_resp = s_resp.slice(1 + 2 * ell, 1 + 2 * ell + N);
  const y_resp = s_resp.slice(1 + 2 * ell + N, 1 + 2 * ell + 2 * N);
  const p = Y.points[0]; // G
  const f = Y.points[1]; // H
  const g = Y.points[2]; // ek_src
  const ii = Y.points[3]; // ek_dst
  const arr = [];
  arr.push(g.multiply(m_scalar));
  for (let l = 0; l < ell; l++) arr.push(p.multiply(d_resp[l]).add(f.multiply(u_resp[l])));
  for (let l = 0; l < ell; l++) arr.push(g.multiply(u_resp[l]));
  // Skip auditor (n=false)
  function powers(k) {
    const base = 1n << 16n;
    const arr2 = [1n];
    for (let i = 1; i < k; i++) arr2.push(mod(arr2[i - 1] * base, ED_N));
    return arr2;
  }
  const E_pow = powers(ell), C_pow = powers(N);
  let S = RistrettoPoint.ZERO;
  const B = 4 + ell;  // Oe(e) = $+e = 4+e
  for (let l = 0; l < ell; l++) S = S.add(Y.points[B + l].multiply(mod(m_scalar * E_pow[l], ED_N)));
  for (let l = 0; l < ell; l++) S = S.add(p.multiply(mod(d_resp[l] * E_pow[l], ED_N)));
  for (let l = 0; l < N; l++) S = S.add(p.multiply(mod(c_resp[l] * C_pow[l], ED_N)));
  arr.push(S);
  for (let l = 0; l < N; l++) arr.push(p.multiply(c_resp[l]).add(f.multiply(y_resp[l])));
  for (let l = 0; l < N; l++) arr.push(g.multiply(y_resp[l]));
  for (let l = 0; l < N; l++) arr.push(ii.multiply(y_resp[l]));
  return arr;
}
function Ve_call() {
  const arr = [];
  arr.push(Y.points[1]); // H
  const m_ofs = 4 + 2 * ell;  // He(e) = $+2e
  for (let i = 0; i < ell; i++) arr.push(Y.points[m_ofs + i]);
  const d_ofs = 4 + 3 * ell;  // We(e) = $+3e
  for (let i = 0; i < ell; i++) arr.push(Y.points[d_ofs + i]);
  // No auditor
  function powers(k) {
    const base = 1n << 16n;
    const arr2 = [1n];
    for (let i = 1; i < k; i++) arr2.push(mod(arr2[i - 1] * base, ED_N));
    return arr2;
  }
  const u_pow = powers(ell);
  let c_sum = RistrettoPoint.ZERO;
  for (let i = 0; i < ell; i++) c_sum = c_sum.add(Y.points[4 + i].multiply(u_pow[i]));
  arr.push(c_sum);
  const y_ofs = 4 + 4 * ell;  // Fe(e)
  for (let i = 0; i < N; i++) arr.push(Y.points[y_ofs + i]);
  const p_ofs = 4 + 4 * ell + N;  // Le(e,t)
  for (let i = 0; i < N; i++) arr.push(Y.points[p_ofs + i]);
  const f_ofs = 4 + 4 * ell + 2 * N;  // Ge(e,t)
  for (let i = 0; i < N; i++) arr.push(Y.points[f_ofs + i]);
  return arr;
}

const lhs = jt_call(y);
const rhs = Ve_call();
console.log(`lhs.length=${lhs.length}  rhs.length=${rhs.length}  commitments=${commitments.length}`);

const m_points = commitments.map((b) => RistrettoPoint.fromHex(b));
let fails = 0;
for (let i = 0; i < m_points.length; i++) {
  const E = m_points[i].add(rhs[i].multiply(e));
  const ok = Buffer.from(lhs[i].toRawBytes()).equals(Buffer.from(E.toRawBytes()));
  if (!ok) { fails++; console.log(`  [${i}] FAIL`); }
  else { console.log(`  [${i}] OK`); }
}
console.log("fails=", fails);
