#!/usr/bin/env node
// Run @aptos-labs/confidential-asset's verifyTransfer locally against the
// persisted finalize artifact + round2 statement inputs. This is the
// same σ-proof verifier the chain runs (the Move framework's σ verifier
// is byte-identical to this once compiled).

import { readFileSync } from "node:fs";
import {
  verifyTransfer,
  RistrettoPoint,
} from "@aptos-labs/confidential-asset";

const round2Path = process.argv[2];
const finalizePath = process.argv[3];
if (!round2Path || !finalizePath) {
  console.error("usage: node _diag_verify_transfer_local.mjs <round2.json> <finalize.json>");
  process.exit(2);
}

const r2 = JSON.parse(readFileSync(round2Path, "utf8"));
const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const a = fin.mpccaWithdrawFinalizeArtifact;
const si = r2.statementInputs;

function hexBytes(hex) { return Buffer.from(hex.replace(/^0x/, ""), "hex"); }
function rp(hex) { return RistrettoPoint.fromHex(hexBytes(hex)); }

// Per SDK signature:
//   verifyTransfer({ senderAddress, recipientAddress, tokenAddress, chainId,
//     ekSidBytes, ekRidBytes,
//     oldBalanceC, oldBalanceD,            (Ristretto[])
//     newBalanceC, newBalanceD,            (Ristretto[])
//     transferAmountC, transferAmountDSender, transferAmountDRecipient,   (Ristretto[])
//     hasEffectiveAuditor, auditorEkBytes, newBalanceDAud, transferAmountDAud,
//     proof: { commitment: hex[], response: hex[] } })
const input = {
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
    commitment: a.aggregatedSigmaCommitmentsHex.map((h) => hexBytes(h)),
    response: a.sigmaResponseHex.map((h) => hexBytes(h)),
  },
};

console.log("ell (chunks per balance):", si.oldBalanceC.length);
console.log("N (chunks per amount)   :", si.transferAmountC.length);
console.log("commitments length      :", a.aggregatedSigmaCommitmentsHex.length);
console.log("responses length        :", a.sigmaResponseHex.length);
console.log("");

try {
  const ok = verifyTransfer(input);
  console.log(`verifyTransfer = ${ok}`);
  if (!ok) {
    console.log("\n→ σ-proof FAILS locally. Chain rejection is from σ-proof check.");
    console.log("  Investigate per-position to identify which i fails.");
  } else {
    console.log("\n→ σ-proof PASSES locally. Chain rejection is NOT from σ-proof.");
    console.log("  Investigate: Bulletproofs / chunked balance state / chain CA store state / recipient_ek / auditor flag.");
  }
} catch (e) {
  console.error("verifyTransfer threw:", e.message);
  console.error(e.stack?.split("\n").slice(0, 6).join("\n"));
  process.exit(1);
}
