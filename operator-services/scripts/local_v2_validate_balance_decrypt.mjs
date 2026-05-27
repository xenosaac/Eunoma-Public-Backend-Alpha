#!/usr/bin/env node
// WD-VALIDATE: one-shot 32-bit BSGS local re-decode against the live testnet vault.
//
// Disambiguates the three hypotheses for `bsgs_decode_failed_at_chunk_0`:
//   H2: chunk overflow > 2^16 (32-bit decode succeeds, plaintext > 65536)
//   H3: wrong dk / forged partial (32-bit decode also fails)
//   H4: C/D pairing mismatch (32-bit decode also fails — but for a different reason)
//
// Triggers no chain mutations. Only reads chain + posts /v2/balance/decrypt.
//
// Run from parent repo root (where node_modules is installed):
//   COORDINATOR_BEARER_TOKEN=<token> node operator-services/scripts/local_v2_validate_balance_decrypt.mjs

import { RistrettoPoint } from "@aptos-labs/confidential-asset";
import { recoverBalanceChunks, bsgsDecodeChunk } from "../../circuits/scripts/recover_balance_chunks.mjs";

const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:14200";
const COORDINATOR_BEARER_TOKEN = process.env.COORDINATOR_BEARER_TOKEN ?? "1762293f1e193cd8527d215fb69d4fad48d1ad324591050e676672b48563d552";
const APTOS_NODE_URL = process.env.APTOS_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com";
const VAULT_ADDRESS = process.env.VAULT_ADDRESS ?? "0xbbb0957ec8c26ab2652280c946dc35381dde6613b8ee9041ad6f467331dcd12a";
const ASSET_TYPE = process.env.ASSET_TYPE ?? "0xa";
const DKG_EPOCH = process.env.DKG_EPOCH ?? "1";

function hexToBytes(hex) {
  const norm = hex.replace(/^0x/i, "");
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < norm.length; i += 2) out[i / 2] = parseInt(norm.slice(i, i + 2), 16);
  return out;
}
function bytesToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function bytesToBigLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}
function normalizeHex(hex) { return hex.replace(/^0x/i, "").toLowerCase(); }
function addr32(hex) { return "0x" + normalizeHex(hex).padStart(64, "0"); }

console.log("=== WD-VALIDATE: 32-bit BSGS local re-decode ===");
console.log(`COORDINATOR_URL=${COORDINATOR_URL}`);
console.log(`VAULT_ADDRESS=${VAULT_ADDRESS}`);
console.log(`ASSET_TYPE=${ASSET_TYPE}`);
console.log(`DKG_EPOCH=${DKG_EPOCH}`);
console.log();

// Step 1: fetch chain available_balance
console.log("--- Step 1: fetch chain get_available_balance ---");
async function fetchAvailable() {
  const res = await fetch(`${APTOS_NODE_URL}/v1/view`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: "0x1::confidential_asset::get_available_balance",
      type_arguments: [],
      arguments: [addr32(VAULT_ADDRESS), addr32(ASSET_TYPE)],
    }),
  });
  if (!res.ok) {
    throw new Error(`get_available_balance: ${res.status} ${await res.text()}`);
  }
  const b = await res.json();
  return {
    C: b[0].P.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
    D: b[0].R.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
    rawC: b[0].P.map((x) => x.data),
    rawD: b[0].R.map((x) => x.data),
  };
}
const oldBalanceCt = await fetchAvailable();
console.log(`got ${oldBalanceCt.C.length} C-chunks, ${oldBalanceCt.D.length} D-chunks`);
console.log("D chunks hex preview:", oldBalanceCt.rawD.map((h, i) => `[${i}]=${h.slice(0, 16)}...`).join(", "));
console.log();

// Step 2: POST coordinator /v2/balance/decrypt
console.log("--- Step 2: POST /v2/balance/decrypt ---");
const requestId = "wd-validate-" + Date.now();
const decryptResp = await fetch(`${COORDINATOR_URL}/v2/balance/decrypt`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
  },
  body: JSON.stringify({
    dkgEpoch: DKG_EPOCH,
    vaultAddress: addr32(VAULT_ADDRESS),
    assetType: addr32(ASSET_TYPE),
    oldBalanceDHex: oldBalanceCt.D.map((p) => bytesToHex(p.toRawBytes())),
    requestId,
  }),
});
if (!decryptResp.ok) {
  console.error(`balance_decrypt_failed: ${decryptResp.status} ${await decryptResp.text()}`);
  process.exit(2);
}
const decryptJson = await decryptResp.json();
console.log(`got ${decryptJson.slots.length} slots + ${decryptJson.lagrangeCoeffs.length} lagrange coeffs`);
console.log(`slot ids returned: [${decryptJson.slots.map((s) => s.slot).join(", ")}]`);
console.log(`partials per slot (length): [${decryptJson.slots.map((s) => s.partial_hex.length).join(", ")}]`);
console.log();

// Step 3: parse partials + lagrange (same as local_v2_withdraw_full.mjs)
const partialsFromSlots = decryptJson.slots.map((s) => ({
  slot: s.slot,
  partials: s.partial_hex.map((h) => RistrettoPoint.fromHex(hexToBytes(h))),
}));
const lagrangeCoeffs = decryptJson.lagrangeCoeffs.map((h) => bytesToBigLE(hexToBytes(h)));

// Step 4: attempt BSGS with chunkBits=16 (frontend's actual setting)
console.log("--- Step 4: attempt BSGS chunkBits=16 (matches frontend) ---");
let result16 = null;
try {
  result16 = recoverBalanceChunks({
    oldBalanceC: oldBalanceCt.C,
    oldBalanceD: oldBalanceCt.D,
    partialsFromSlots,
    lagrangeCoeffs,
    chunkBits: 16,
  });
  console.log("UNEXPECTED: 16-bit decode succeeded:");
  for (let k = 0; k < result16.chunks.length; k++) {
    console.log(`  chunk[${k}] = ${result16.chunks[k]}`);
  }
} catch (e) {
  console.log(`16-bit decode FAILED: ${e.message}`);
}
console.log();

// Step 5: attempt BSGS with chunkBits=32 (codex F6 validation)
console.log("--- Step 5: attempt BSGS chunkBits=32 (codex F6 validation, may take 30-60s) ---");
let result32 = null;
let result32Error = null;
try {
  result32 = recoverBalanceChunks({
    oldBalanceC: oldBalanceCt.C,
    oldBalanceD: oldBalanceCt.D,
    partialsFromSlots,
    lagrangeCoeffs,
    chunkBits: 32,
  });
  console.log("32-bit decode SUCCEEDED:");
  for (let k = 0; k < result32.chunks.length; k++) {
    const v = result32.chunks[k];
    const over16 = v >= 65536n ? "  ⚠ EXCEEDS 2^16" : "";
    console.log(`  chunk[${k}] = ${v}${over16}`);
  }
} catch (e) {
  result32Error = e.message;
  console.log(`32-bit decode FAILED: ${e.message}`);
}
console.log();

// Step 6: verdict
console.log("=== VERDICT ===");
if (result32) {
  const exceeds16 = result32.chunks.some((v) => v >= 65536n);
  if (exceeds16) {
    console.log("✅ H2 CONFIRMED: vault available chunk(s) exceed 2^16; framework normalize required.");
    console.log("   Pivot direction → A (normalize ceremony/delegate/bundled/frontend 32-bit BSGS)");
    const max = result32.chunks.reduce((a, b) => (b > a ? b : a), 0n);
    console.log(`   Max chunk value = ${max}`);
    const sum = result32.chunks.reduce(
      (a, c, i) => a + c * (1n << BigInt(16 * i)),
      0n,
    );
    console.log(`   Reconstructed total balance (octas) = ${sum}`);
  } else {
    console.log("⚠️ UNEXPECTED: 32-bit succeeded but no chunk exceeds 2^16.");
    console.log("   This is inconsistent with 16-bit failing. Check BSGS implementation or table loading on frontend.");
  }
} else {
  console.log("❌ H2 REJECTED: 32-bit BSGS also failed.");
  console.log(`   32-bit error: ${result32Error}`);
  console.log("   Real root cause is either:");
  console.log("     H3: wrong dk / forged partial / stale share (worker has correct epoch+slot but wrong DK)");
  console.log("     H4: C/D pairing mismatch (frontend sent stale C with current D)");
  console.log("   Next: spawn agent to inspect worker DK derivation + rotate_deoperator_config_v2 history,");
  console.log("         and compare what frontend's getCaAvailableBalanceCiphertext returns vs what we just fetched.");
}
