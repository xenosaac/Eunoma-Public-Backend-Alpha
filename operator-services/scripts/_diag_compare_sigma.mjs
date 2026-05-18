#!/usr/bin/env node
// Compare aggregated sigma commitment[17] from the chain-bound finalize
// artifact against what proveTransfer would have produced, to confirm whether
// the threshold reconstruction is byte-canonical.
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const finalizePath = process.argv[2];
const round2Path = process.argv[3];
if (!finalizePath || !round2Path) {
  console.error("usage: node scripts/_diag_compare_sigma.mjs <finalize.json> <round2.json>");
  process.exit(2);
}
const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const r2 = JSON.parse(readFileSync(round2Path, "utf8"));
const agg = fin.mpccaWithdrawFinalizeArtifact.aggregatedSigmaCommitmentsHex;
const userParts = r2.userProofArtifacts.userSigmaCommitmentsHex;
console.log(`aggregated[0]  = ${agg[0]}`);
console.log(`aggregated[17] = ${agg[17]}`);
console.log(`userPart[16] (= position 17) = ${userParts[16]}`);
console.log(`userPart count = ${userParts.length} (expect 29)`);

// Per psi_transfer line 410-417, position 17 has:
//   α[0]·Σ_i b^i·old_R[i] (worker)
// + Σ_i G·α_new_a[i]·b^i (user)
// + Σ_j G·α_v[j]·b^j     (user)
// So aggregated[17] = userPart[16] + (α[0]·Σ_i b^i·old_R[i]). We can compute the
// worker contribution as agg[17] - userPart[16] (modulo Ristretto group ops).

import { RistrettoPoint } from "@aptos-labs/confidential-asset";
function rp(hex) {
  return RistrettoPoint.fromHex(Buffer.from(hex.replace(/^0x/,""), "hex"));
}
function bhex(p) {
  return Buffer.from(p.toRawBytes()).toString("hex");
}
const agg17 = rp(agg[17]);
const up17 = rp(userParts[16]);
const workerContribution = agg17.subtract(up17);
console.log(`worker contribution at [17] (= aggregated − user) = ${bhex(workerContribution)}`);
// And aggregated[0] should be pure worker — α[0]·ek_sid
console.log(`worker contribution at [0]  = ${agg[0]}`);
