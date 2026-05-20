#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const finalizePath = process.argv[2];
if (!finalizePath) {
  console.error("usage: node scripts/_diag_print_args.mjs <finalize.json>");
  process.exit(2);
}
const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const args = fin.withdrawV2CallArgsFields;
const { encodeCallArgs } = await import(`${serviceRoot}/relayer/dist/server.js`);
const positional = encodeCallArgs(args);
const order = [
  "root","nullifierHash","recipient","recipientHash","amountTag","caPayloadHash","requestHash",
  "vaultSequence","withdrawProof","expirySecs","groupSignature","fallbackBitmap","fallbackSignatures",
  "newBalanceP","newBalanceR","newBalanceREffAud","amountP","amountRSender","amountRRecip",
  "amountREffAud","ekVolunAuds","amountRVolunAuds","zkrpNewBalance","zkrpAmount",
  "sigmaProtoComm","sigmaProtoResp","memo",
];
console.log(`got ${positional.length} args (expected 27):`);
positional.forEach((arg, i) => {
  const preview = arg.length > 100 ? `${arg.slice(0, 50)}...${arg.slice(-20)} (len=${arg.length})` : arg;
  console.log(`  [${i}] ${order[i] ?? "?"} = ${preview}`);
});
