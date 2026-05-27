#!/usr/bin/env node
// =============================================================================================
// V2 normalize — end-to-end orchestrator that wires Agent B's normalize proof builder + Agent C's
// coordinator threshold-s[0] route into a single `aptos move run` call that submits
// `operator_normalize_vault_balance_via_delegate` (or the admin variant `_v2`).
//
// Pipeline (matches the NORMALIZE plan, 2026-05-27):
//   1. Idempotency gate: 0x1::confidential_asset::is_normalized(vault, asset_type). If true, exit 0.
//   2. Fetch chain `get_available_balance(vault, asset_type)` → 8 C + 8 D Twisted ElGamal points.
//   3. POST coordinator /v2/balance/decrypt → quorum slots + Lagrange coeffs.
//   4. recoverBalanceChunks(chunkBits=16) → 8 × 16-bit plaintext chunks (NO logging of values).
//   5. Reconstruct total = Σ chunk_k · 2^(16·k); re-chunk into 4 × 16-bit.
//   6. Fetch vault ek (chain) + auditor ek (chain, may be absent on testnet APT).
//   7. buildNormalizeProofBundle(...) → 6 Move args + α[0] + e (local only).
//   8. Split α[0] into additive shares, HPKE-seal one share per worker, then
//      POST coordinator /v2/normalize/sigma/s0 with (e, sealed shares) → s[0]_threshold.
//   9. Assemble sigma_proto_resp = [s0_threshold, ...responseTail].
//  10. Preflight verify via Agent B's verifyWithdrawSigmaProof.
//  11. If --dry-run, log proof shapes and exit. Else build aptos CLI args and spawn.
//  12. Parse tx hash, poll fullnode for confirmation.
//
// Privacy:
//   * Never log plaintext chunks or chunk sums.
//   * Never write plaintext to side-car files.
//   * Default log surface: chunk counts, dkg epoch, total bit width, tx hash, coordinator
//     status code, error code names. Plaintext gated behind EUNOMA_LOCAL_DEBUG_BALANCE=1
//     (interactive operator diagnostics only).
//
// CLI:
//   --bridge-package-address HEX          required
//   --vault-address HEX                   default: env BRIDGE_VAULT_ADDRESS
//   --asset-type HEX                      default: env BRIDGE_ASSET_TYPE
//   --admin-profile NAME                  default: testnet-admin (used in admin path)
//   --via-delegate                        switch to delegate path
//   --delegate-profile NAME               default: testnet-relayer (used with --via-delegate)
//   --coordinator-url URL                 default: env COORDINATOR_URL or http://127.0.0.1:4200
//   --coordinator-bearer-token TOK        default: env COORDINATOR_BEARER_TOKEN
//   --aptos-node-url URL                  default: env APTOS_NODE_URL or testnet
//   --max-gas N                           default: 300000
//   --gas-unit-price N                    default: 100
//   --dry-run                             build + verify, skip submit
//
// Exit codes (mirror local_rollover_vault_pending.mjs):
//   0   success (submitted + confirmed, OR already normalized no-op, OR dry-run)
//   2   usage / arg error
//   30  chain confirmation failed (tx reverted)
//   31  aptos CLI spawn / non-zero exit / sigma preflight verify failure
//   32  fullnode unreachable
//   33  coordinator unreachable / threshold-s[0] failure
// =============================================================================================
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  RistrettoPoint,
  TwistedEd25519PublicKey,
} from "@aptos-labs/confidential-asset";

import { caDkgV2RosterHash } from "@eunoma/deop-protocol";
import {
  NORMALIZE_ALPHA_SHARE_INFO,
  buildNormalizeProofBundle,
  normalizeAlphaShareAad,
  splitNormalizeAlphaShares,
} from "./_lib/normalize_proof_builder.mjs";
import { verifyWithdrawSigmaProof } from "./_lib/withdraw_sigma_reference.mjs";
import { aptosView } from "./_lib/aptos_view.mjs";
import { hexVectorArg, hexArg } from "./_lib/format_aptos_args.mjs";
import { recoverBalanceChunks } from "../../circuits/scripts/recover_balance_chunks.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
// Mirrors local_rollover_vault_pending.mjs:36-40: aptos CLI requires
// .aptos/config.yaml in cwd. operator-services/.aptos/config.yaml holds the
// testnet-* profiles on alpha box, so spawn the CLI from there regardless of
// the wrapper's cwd.
const serviceRoot = resolve(scriptDir, "..");
const HPKE_SEAL_BIN = resolve(serviceRoot, "crypto-worker-rust/target/release/hpke_seal_ingress");

// ---- Exit codes ----------------------------------------------------------------------------
const EXIT_SUCCESS = 0;
const EXIT_USAGE = 2;
const EXIT_CHAIN_REVERTED = 30;
const EXIT_APTOS_SPAWN = 31;
const EXIT_FULLNODE_UNREACHABLE = 32;
const EXIT_COORDINATOR_UNREACHABLE = 33;

// ---- Args + env ---------------------------------------------------------------------------
const args = process.argv.slice(2);
let bridgePackageAddress;
let vaultAddress = process.env.BRIDGE_VAULT_ADDRESS;
let assetType = process.env.BRIDGE_ASSET_TYPE;
let adminProfile = "testnet-admin";
let delegateProfile = "testnet-relayer";
let viaDelegate = false;
let coordinatorUrl = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
let coordinatorBearerToken = process.env.COORDINATOR_BEARER_TOKEN;
let aptosNodeUrl = process.env.APTOS_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com";
let maxGas = "300000";
let gasUnitPrice = "100";
let dryRun = false;
const requestId = `normalize-${Date.now()}`;

for (let i = 0; i < args.length; ++i) {
  const a = args[i];
  switch (a) {
    case "--bridge-package-address": bridgePackageAddress = args[++i]; break;
    case "--vault-address": vaultAddress = args[++i]; break;
    case "--asset-type": assetType = args[++i]; break;
    case "--admin-profile": adminProfile = args[++i]; break;
    case "--via-delegate": viaDelegate = true; break;
    case "--delegate-profile": delegateProfile = args[++i]; break;
    case "--coordinator-url": coordinatorUrl = args[++i]; break;
    case "--coordinator-bearer-token": coordinatorBearerToken = args[++i]; break;
    case "--aptos-node-url": aptosNodeUrl = args[++i]; break;
    case "--max-gas": maxGas = args[++i]; break;
    case "--gas-unit-price": gasUnitPrice = args[++i]; break;
    case "--dry-run": dryRun = true; break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_v2_normalize_full --bridge-package-address HEX \\\n" +
          "          [--vault-address HEX] [--asset-type HEX]\\\n" +
          "          [--via-delegate] [--delegate-profile NAME=testnet-relayer]\\\n" +
          "          [--admin-profile NAME=testnet-admin]\\\n" +
          "          [--coordinator-url URL] [--coordinator-bearer-token TOK]\\\n" +
          "          [--aptos-node-url URL] [--max-gas N=300000]\\\n" +
          "          [--gas-unit-price N=100] [--dry-run]",
      );
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${a}`);
      process.exit(EXIT_USAGE);
  }
}

function requireArg(name, value) {
  if (!value) {
    console.error(`${name} is required`);
    process.exit(EXIT_USAGE);
  }
}
requireArg("--bridge-package-address", bridgePackageAddress);
requireArg("--vault-address / env BRIDGE_VAULT_ADDRESS", vaultAddress);
requireArg("--asset-type / env BRIDGE_ASSET_TYPE", assetType);
requireArg("--coordinator-bearer-token / env COORDINATOR_BEARER_TOKEN", coordinatorBearerToken);

// ---- Helpers --------------------------------------------------------------------------------
function bytesToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const norm = hex.replace(/^0x/i, "");
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < norm.length; i += 2) out[i / 2] = parseInt(norm.slice(i, i + 2), 16);
  return out;
}
function normalizeHex(hex) {
  return String(hex).replace(/^0x/i, "").toLowerCase();
}
function addr32(hex) {
  return normalizeHex(hex).padStart(64, "0");
}
function bytesToBigLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

const CHAIN_ID = Number(process.env.CHAIN_ID ?? "2");
const debugBalance = process.env.EUNOMA_LOCAL_DEBUG_BALANCE === "1";

// Read CA DKG V2 roster to extract `dkgEpoch` for the coordinator routes. Mirrors
// local_v2_withdraw_full.mjs:223+289-290 — the coordinator validates that the
// caller's dkgEpoch matches its configured roster.
function loadCaDkgRoster() {
  const rosterPath = process.env.CA_DKG_V2_ROSTER_JSON_PATH;
  if (!rosterPath) {
    console.error("env CA_DKG_V2_ROSTER_JSON_PATH is required (path to roster JSON containing { dkgEpoch })");
    process.exit(EXIT_USAGE);
  }
  if (!existsSync(rosterPath)) {
    console.error(`CA DKG V2 roster file not found at ${rosterPath}`);
    process.exit(EXIT_USAGE);
  }
  try {
    const roster = JSON.parse(readFileSync(rosterPath, "utf8"));
    if (typeof roster.dkgEpoch !== "string" || !/^[0-9]+$/.test(roster.dkgEpoch)) {
      console.error(`roster.dkgEpoch must be a decimal string (got ${roster.dkgEpoch})`);
      process.exit(EXIT_USAGE);
    }
    return roster;
  } catch (err) {
    console.error(`failed to parse CA DKG V2 roster: ${err?.message ?? err}`);
    process.exit(EXIT_USAGE);
  }
}
const caDkgRoster = loadCaDkgRoster();
const dkgEpochStr = caDkgRoster.dkgEpoch;
const caDkgRosterHash = normalizeHex(caDkgRoster.caDkgV2RosterHash ?? caDkgV2RosterHash(caDkgRoster));

// ---- Functional ID + signer profile -------------------------------------------------------
let functionId;
let signerProfile;
if (viaDelegate) {
  functionId = `${bridgePackageAddress}::eunoma_bridge::operator_normalize_vault_balance_via_delegate`;
  signerProfile = delegateProfile;
} else {
  functionId = `${bridgePackageAddress}::eunoma_bridge::operator_normalize_vault_balance_v2`;
  signerProfile = adminProfile;
}
console.error(`[normalize] function_id=${functionId} signer=${signerProfile} via_delegate=${viaDelegate}`);

// ---- Step 1: idempotency gate -------------------------------------------------------------
async function isNormalized() {
  try {
    const j = await aptosView(
      aptosNodeUrl,
      "0x1::confidential_asset::is_normalized",
      [],
      [addr32(vaultAddress), addr32(assetType)],
    );
    return Array.isArray(j) ? Boolean(j[0]) : Boolean(j);
  } catch (err) {
    console.error(`[normalize] is_normalized view failed: ${err?.message ?? err}`);
    process.exit(EXIT_FULLNODE_UNREACHABLE);
  }
}

const alreadyNormalized = await isNormalized();
if (alreadyNormalized) {
  console.log(
    JSON.stringify({
      ok: true,
      status: "already_normalized",
      vaultAddress: addr32(vaultAddress),
      assetType: addr32(assetType),
    }),
  );
  process.exit(EXIT_SUCCESS);
}
console.error(`[normalize] is_normalized=false; proceeding with normalize pipeline`);

// ---- Step 2: fetch chain available_balance ------------------------------------------------
async function fetchAvailable() {
  const j = await aptosView(
    aptosNodeUrl,
    "0x1::confidential_asset::get_available_balance",
    [],
    [vaultAddress, assetType],
  );
  const body = j[0];
  return {
    C: body.P.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
    D: body.R.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
  };
}
let oldBalanceCt;
try {
  oldBalanceCt = await fetchAvailable();
} catch (err) {
  console.error(`[normalize] get_available_balance failed: ${err?.message ?? err}`);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}
const ell = oldBalanceCt.C.length;
if (ell !== oldBalanceCt.D.length || ell === 0) {
  console.error(`[normalize] balance shape malformed: C=${ell} D=${oldBalanceCt.D.length}`);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}
console.error(`[normalize] fetched chain available_balance: chunkCount=${ell}`);

// ---- Step 3: coordinator /v2/balance/decrypt ----------------------------------------------
// Quoting M10-l (codex P1): no `aptosNodeUrl` in the body. The coordinator
// (and each worker) reads its own configured Aptos REST URL from env. A
// request-controlled URL would let a caller point the workers at an
// attacker-hosted `/v1/view`, returning chosen D' matching `oldBalanceDHex`,
// turning each `dk_share_i · D'` into a chosen-D threshold decryption oracle.
let decryptJson;
try {
  const decryptResp = await fetch(`${coordinatorUrl}/v2/balance/decrypt`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${coordinatorBearerToken}`,
    },
    body: JSON.stringify({
      dkgEpoch: dkgEpochStr,
      vaultAddress: addr32(vaultAddress),
      assetType: addr32(assetType),
      oldBalanceDHex: oldBalanceCt.D.map((p) => bytesToHex(p.toRawBytes())),
      requestId,
    }),
  });
  console.error(`[normalize] coordinator /v2/balance/decrypt status=${decryptResp.status}`);
  if (!decryptResp.ok) {
    const errBody = await decryptResp.text();
    console.error(`[normalize] balance_decrypt_failed status=${decryptResp.status}`);
    // Avoid surfacing the raw stderr body — could contain caller-controlled
    // identifiers we don't want to plumb into operator log capture.
    if (debugBalance) console.error(`[normalize] balance_decrypt_failed body=${errBody}`);
    process.exit(EXIT_COORDINATOR_UNREACHABLE);
  }
  decryptJson = await decryptResp.json();
} catch (err) {
  console.error(`[normalize] coordinator decrypt unreachable: ${err?.message ?? err}`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}
if (!Array.isArray(decryptJson.slots) || !Array.isArray(decryptJson.lagrangeCoeffs)) {
  console.error(`[normalize] decrypt response shape invalid (missing slots/lagrangeCoeffs)`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}
const partialsFromSlots = decryptJson.slots.map((s) => ({
  slot: s.slot,
  partials: s.partial_hex.map((h) => RistrettoPoint.fromHex(hexToBytes(h))),
}));
const selectedSlots = decryptJson.slots.map((s) => Number(s.slot)).sort((a, b) => a - b);
// M10-c encodes scalars via `scalarHexFromBigint` (32-byte LITTLE-endian hex,
// see deop-protocol/src/vault_ek_derivation.ts:448). `BigInt("0x" + h)` would
// parse it as BIG-endian — wrong scalar. Use bytesToBigLE on the decoded bytes.
const lagrangeCoeffs = decryptJson.lagrangeCoeffs.map((h) => bytesToBigLE(hexToBytes(h)));
console.error(`[normalize] decrypt quorum: slots=${decryptJson.slots.length} lagrangeCount=${lagrangeCoeffs.length}`);

// ---- Step 4: recover plaintext chunks (NO plaintext logged by default) --------------------
const CHUNK_BITS_OLD = 16; // chain uses 16-bit chunks; @aptos-labs/confidential-asset CHUNK_BITS=16
let balanceChunks;
try {
  const recovered = recoverBalanceChunks({
    oldBalanceC: oldBalanceCt.C,
    oldBalanceD: oldBalanceCt.D,
    partialsFromSlots,
    lagrangeCoeffs,
    chunkBits: CHUNK_BITS_OLD,
  });
  balanceChunks = recovered.chunks;
} catch (err) {
  // err.message may contain "bsgs_decode_failed_at_chunk_K" — no plaintext leak.
  console.error(`[normalize] recoverBalanceChunks failed: ${err?.message ?? err}`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}
if (balanceChunks.length !== ell) {
  console.error(`[normalize] recovered chunk count ${balanceChunks.length} != ell=${ell}`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}
console.error(`[normalize] recovered balance: chunkCount=${balanceChunks.length} (plaintext gated; set EUNOMA_LOCAL_DEBUG_BALANCE=1 to log)`);

// ---- Step 5: reconstruct total + re-chunk to 4 × 16-bit -----------------------------------
let total = 0n;
for (let k = 0; k < balanceChunks.length; k++) {
  total += balanceChunks[k] * (1n << BigInt(CHUNK_BITS_OLD * k));
}
// Re-chunk to 4 × 16-bit. The post-normalize Aptos CA framework expects
// 4 chunks (TRANSFER_AMOUNT_CHUNK_COUNT semantic — i.e., one chunk for each
// of the up-to-2^64-1 octa range), each in [0, 2^16).
const NEW_CHUNK_COUNT = 4;
const NEW_CHUNK_BITS = 16;
const NEW_CHUNK_MASK = (1n << BigInt(NEW_CHUNK_BITS)) - 1n;
const NEW_CHUNK_RADIX = 1n << BigInt(NEW_CHUNK_BITS);

const meaningfulNewBalanceChunks = new Array(NEW_CHUNK_COUNT).fill(0n);
{
  let remainder = total;
  for (let k = 0; k < NEW_CHUNK_COUNT; k++) {
    meaningfulNewBalanceChunks[k] = remainder & NEW_CHUNK_MASK;
    remainder >>= BigInt(NEW_CHUNK_BITS);
  }
  if (remainder !== 0n) {
    // The total exceeded 2^(NEW_CHUNK_COUNT*NEW_CHUNK_BITS) = 2^64. That's a
    // legitimate balance-vs-cap violation — fail closed.
    const detail = debugBalance ? ` (total=${total})` : "";
    console.error(`[normalize] reconstructed total exceeds 2^${NEW_CHUNK_COUNT * NEW_CHUNK_BITS} re-chunk cap${detail}`);
    process.exit(EXIT_USAGE);
  }
}
// Sanity: each new chunk < 2^16; sum reconstructs total.
let sanitySum = 0n;
for (let k = 0; k < NEW_CHUNK_COUNT; k++) {
  if (meaningfulNewBalanceChunks[k] < 0n || meaningfulNewBalanceChunks[k] > NEW_CHUNK_MASK) {
    console.error(`[normalize] re-chunk[${k}] out of range`);
    process.exit(EXIT_USAGE);
  }
  sanitySum += meaningfulNewBalanceChunks[k] * (1n << BigInt(NEW_CHUNK_BITS * k));
}
if (sanitySum !== total) {
  const detail = debugBalance ? ` (sanity=${sanitySum} total=${total})` : "";
  console.error(`[normalize] re-chunk sanity sum mismatch${detail}`);
  process.exit(EXIT_USAGE);
}
const totalBitWidth = total === 0n ? 0 : total.toString(2).length;
const newBalanceChunks = [
  ...meaningfulNewBalanceChunks,
  ...new Array(Math.max(0, ell - NEW_CHUNK_COUNT)).fill(0n),
];
if (newBalanceChunks.length !== ell) {
  console.error(`[normalize] padded chunk count ${newBalanceChunks.length} != ell=${ell}`);
  process.exit(EXIT_USAGE);
}
console.error(`[normalize] re-chunked: chunk_count_in=${ell} meaningful_chunks=${NEW_CHUNK_COUNT} padded_chunks=${newBalanceChunks.length} total_octas_bits=${totalBitWidth}`);

// ---- Step 6: fetch vault ek + auditor ek --------------------------------------------------
async function fetchVaultEk() {
  const j = await aptosView(
    aptosNodeUrl,
    "0x1::confidential_asset::get_encryption_key",
    [],
    [addr32(vaultAddress), addr32(assetType)],
  );
  // get_encryption_key returns `[{ point: { data: "0x..." } }]` or `[{ data: "0x..." }]`
  // depending on framework version. Both worker code paths handle this.
  const ent = j[0];
  if (typeof ent === "string") return normalizeHex(ent);
  if (ent && typeof ent.data === "string") return normalizeHex(ent.data);
  if (ent && ent.point && typeof ent.point.data === "string") return normalizeHex(ent.point.data);
  throw new Error(`get_encryption_key response shape unrecognized: ${JSON.stringify(j).slice(0, 200)}`);
}

async function fetchAuditorEk() {
  // Mirrors @aptos-labs/confidential-asset getAssetAuditorEncryptionKey:
  //   get_effective_auditor_config(token) -> { ek: { vec: [<32B>] } | { vec: [] } }
  // Returns null when the asset has no effective auditor (testnet APT case).
  try {
    const j = await aptosView(
      aptosNodeUrl,
      "0x1::confidential_asset::get_effective_auditor_config",
      [],
      [addr32(assetType)],
    );
    const cfg = j[0]?.config ?? j[0] ?? null;
    const ekVec = cfg?.ek?.vec;
    if (!Array.isArray(ekVec) || ekVec.length === 0) return null;
    const ent = ekVec[0];
    if (typeof ent === "string") return normalizeHex(ent);
    if (ent && typeof ent.data === "string") return normalizeHex(ent.data);
    return null;
  } catch (err) {
    // If the view doesn't exist or returns malformed data, default to no-auditor
    // (the typical testnet-APT case). Fail-loud only on the explicit fetch path
    // when the operator-supplied asset_type is actually configured with an
    // auditor whose view we can't decode.
    console.error(`[normalize] get_effective_auditor_config failed (treating as no-auditor): ${err?.message ?? err}`);
    return null;
  }
}

let vaultEkHex;
try {
  vaultEkHex = await fetchVaultEk();
} catch (err) {
  console.error(`[normalize] fetchVaultEk failed: ${err?.message ?? err}`);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}
const vaultEkPub = new TwistedEd25519PublicKey(`0x${vaultEkHex}`);
const auditorEkHex = await fetchAuditorEk();
const auditorEkPub = auditorEkHex ? new TwistedEd25519PublicKey(`0x${auditorEkHex}`) : null;
console.error(`[normalize] vault_ek=0x${vaultEkHex.slice(0, 16)}... auditor=${auditorEkPub ? "present" : "absent"}`);

// ---- Step 7: build normalize proof bundle (Agent B) ---------------------------------------
const senderAddressBytes = hexToBytes(addr32(vaultAddress));
const tokenAddressBytes = hexToBytes(addr32(assetType));

let bundle;
try {
  bundle = await buildNormalizeProofBundle({
    oldBalanceC: oldBalanceCt.C,
    oldBalanceD: oldBalanceCt.D,
    newBalanceChunks,
    vaultEkPub,
    auditorEkPub,
    senderAddress: senderAddressBytes,
    tokenAddress: tokenAddressBytes,
    chainId: CHAIN_ID,
  });
} catch (err) {
  console.error(`[normalize] buildNormalizeProofBundle failed: ${err?.message ?? err}`);
  process.exit(EXIT_APTOS_SPAWN);
}
console.error(`[normalize] proof bundle built: newBalanceP=${bundle.newBalanceP.length} sigmaCommHex=${bundle.sigmaCommHex.length} responseTail=${bundle.sigmaRespS0NeedsThreshold.responseTail.length} zkrpBytes=${bundle.zkrpNewBalance.length}`);

function hpkeSealNormalize(recipientPubKeyHex, aadBytes, plaintextBytes) {
  if (!existsSync(HPKE_SEAL_BIN)) {
    throw new Error(
      `hpke_seal_ingress binary not found at ${HPKE_SEAL_BIN}. ` +
        "Build it: cd operator-services/crypto-worker-rust && cargo build --release --bin hpke_seal_ingress",
    );
  }
  const req = {
    recipientPubKeyHex: normalizeHex(recipientPubKeyHex),
    aadHex: bytesToHex(aadBytes),
    plaintextHex: bytesToHex(plaintextBytes),
    infoString: NORMALIZE_ALPHA_SHARE_INFO,
  };
  const r = spawnSync(HPKE_SEAL_BIN, [], {
    input: JSON.stringify(req),
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  if (r.status !== 0) {
    throw new Error(`hpke_seal_ingress normalize exit=${r.status}: ${r.stderr || r.stdout || "no output"}`);
  }
  return JSON.parse(r.stdout.trim());
}

// ---- Step 8: coordinator /v2/normalize/sigma/s0 (Agent C) ---------------------------------
const fiatShamirChallengeHex = bytesToHex(bundle.sigmaRespS0NeedsThreshold.fiatShamirChallenge);
let alphaShareEnvelopes;
try {
  const nodeBySlot = new Map(caDkgRoster.nodes.map((node) => [Number(node.slot), node]));
  const shares = splitNormalizeAlphaShares(
    bundle.sigmaRespS0NeedsThreshold.alphaZero,
    selectedSlots,
  );
  alphaShareEnvelopes = shares.map(({ slot, alphaShare }) => {
    const node = nodeBySlot.get(slot);
    if (!node) throw new Error(`selected slot ${slot} missing from CA DKG roster`);
    const aad = normalizeAlphaShareAad({
      requestId,
      dkgEpoch: dkgEpochStr,
      rosterHash: caDkgRosterHash,
      vaultAddress: addr32(vaultAddress),
      assetType: addr32(assetType),
      fiatShamirChallengeHex,
      selectedSlots,
      slot,
    });
    return { slot, hpke: hpkeSealNormalize(node.hpkePublicKey, aad, alphaShare) };
  });
} catch (err) {
  console.error(`[normalize] alpha-share HPKE seal failed: ${err?.message ?? err}`);
  process.exit(EXIT_APTOS_SPAWN);
}

let s0Json;
try {
  const s0Resp = await fetch(`${coordinatorUrl}/v2/normalize/sigma/s0`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${coordinatorBearerToken}`,
    },
    body: JSON.stringify({
      dkgEpoch: dkgEpochStr,
      vaultAddress: addr32(vaultAddress),
      assetType: addr32(assetType),
      fiatShamirChallengeHex,
      rosterHash: caDkgRosterHash,
      selectedSlots,
      alphaShareEnvelopes,
      requestId,
    }),
  });
  console.error(`[normalize] coordinator /v2/normalize/sigma/s0 status=${s0Resp.status}`);
  if (!s0Resp.ok) {
    const errBody = await s0Resp.text();
    console.error(`[normalize] s0_failed status=${s0Resp.status}`);
    if (debugBalance) console.error(`[normalize] s0_failed body=${errBody}`);
    process.exit(EXIT_COORDINATOR_UNREACHABLE);
  }
  s0Json = await s0Resp.json();
} catch (err) {
  console.error(`[normalize] coordinator s0 unreachable: ${err?.message ?? err}`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}
if (typeof s0Json.sigmaResponseS0Hex !== "string" || s0Json.sigmaResponseS0Hex.length === 0) {
  console.error(`[normalize] s0 response missing sigmaResponseS0Hex`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}
const s0ThresholdBytes = hexToBytes(s0Json.sigmaResponseS0Hex);
if (s0ThresholdBytes.length !== 32) {
  console.error(`[normalize] s0 response wrong length ${s0ThresholdBytes.length} (expected 32)`);
  process.exit(EXIT_COORDINATOR_UNREACHABLE);
}

// ---- Step 9: assemble final sigma_proto_resp ---------------------------------------------
const assembledResp = [s0ThresholdBytes, ...bundle.sigmaRespS0NeedsThreshold.responseTail];
const expectedRespLen = 1 + 2 * ell;
if (assembledResp.length !== expectedRespLen) {
  console.error(`[normalize] assembled response length ${assembledResp.length} != ${expectedRespLen}`);
  process.exit(EXIT_APTOS_SPAWN);
}

// ---- Step 10: preflight verify (Agent B) -------------------------------------------------
// We need to reconstruct the new_balance C/D points the verifier expects.
// They're encoded in bundle.newBalanceP / bundle.newBalanceR as 32-byte
// compressed Ristretto points. Decompress + pass through.
const newBalanceCPoints = bundle.newBalanceP.map((b) => RistrettoPoint.fromHex(b));
const newBalanceDPoints = bundle.newBalanceR.map((b) => RistrettoPoint.fromHex(b));
const newBalanceDAudPoints = auditorEkPub
  ? bundle.newBalanceRAud.map((b) => RistrettoPoint.fromHex(b))
  : null;

try {
  const preflight = verifyWithdrawSigmaProof({
    proof: {
      commitment: bundle.sigmaCommHex,
      response: assembledResp,
    },
    oldBalanceC: oldBalanceCt.C,
    oldBalanceD: oldBalanceCt.D,
    newBalanceC: newBalanceCPoints,
    newBalanceD: newBalanceDPoints,
    vaultEkPub,
    auditorEkPub,
    newBalanceDAud: newBalanceDAudPoints,
    chainId: CHAIN_ID,
    amount: 0n, // normalize == withdraw with v=0
    senderAddress: senderAddressBytes,
    tokenAddress: tokenAddressBytes,
  });
  console.error(`[normalize] preflight verify OK: ell=${preflight.ell} hasAuditor=${preflight.hasAuditor} challenge=${preflight.challengeHex.slice(0, 16)}...`);
} catch (err) {
  console.error(`[normalize] preflight verify FAILED: ${err?.message ?? err}`);
  // No plaintext in this error path — verifier emits position_<i>_<name>.
  process.exit(EXIT_APTOS_SPAWN);
}

// ---- Step 11: dry-run short-circuit ------------------------------------------------------
if (dryRun) {
  console.log(
    JSON.stringify({
      ok: true,
      status: "dry_run",
      functionId,
      signerProfile,
      shapes: {
        newBalanceP: bundle.newBalanceP.length,
        newBalanceR: bundle.newBalanceR.length,
        newBalanceRAud: bundle.newBalanceRAud.length,
        zkrpNewBalance: bundle.zkrpNewBalance.length,
        sigmaCommHex: bundle.sigmaCommHex.length,
        sigmaRespLen: assembledResp.length,
      },
      totalOctasBits: totalBitWidth,
      dkgEpoch: dkgEpochStr,
    }),
  );
  process.exit(EXIT_SUCCESS);
}

// ---- Step 12: build aptos CLI args + spawn ----------------------------------------------
const newBalancePHex = bundle.newBalanceP.map((b) => bytesToHex(b));
const newBalanceRHex = bundle.newBalanceR.map((b) => bytesToHex(b));
const newBalanceRAudHex = bundle.newBalanceRAud.map((b) => bytesToHex(b));
const zkrpHex = bytesToHex(bundle.zkrpNewBalance);
const sigmaCommHexArr = bundle.sigmaCommHex.map((b) => bytesToHex(b));
const sigmaRespHexArr = assembledResp.map((b) => bytesToHex(b));

const cliArgs = [
  "move",
  "run",
  "--function-id",
  functionId,
  "--profile",
  signerProfile,
  "--assume-yes",
  "--url",
  aptosNodeUrl,
  "--max-gas",
  maxGas,
  "--gas-unit-price",
  gasUnitPrice,
  "--args",
  hexVectorArg(newBalancePHex),
  hexVectorArg(newBalanceRHex),
  hexVectorArg(newBalanceRAudHex),
  hexArg(zkrpHex),
  hexVectorArg(sigmaCommHexArr),
  hexVectorArg(sigmaRespHexArr),
];
// Log the function-id + profile only — never the args themselves
// (sigma commitments + zkrp could theoretically aid a side-channel attacker,
// though the on-chain tx surfaces them anyway).
console.error(`[normalize] aptos move run --function-id ${functionId} --profile ${signerProfile} --max-gas ${maxGas} --gas-unit-price ${gasUnitPrice}`);

const run = spawnSync("aptos", cliArgs, {
  cwd: serviceRoot,
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
  env: process.env,
});
if (run.error) {
  console.error(`[normalize] failed to spawn aptos CLI: ${run.error.message}`);
  process.exit(EXIT_APTOS_SPAWN);
}
// stderr from aptos CLI is non-secret diagnostics about the submission flow.
process.stderr.write(run.stderr || "");
if (run.status !== 0) {
  console.error(`[normalize] aptos CLI exited with status ${run.status}`);
  process.stdout.write(run.stdout || "");
  process.exit(EXIT_APTOS_SPAWN);
}

function extractTxHash(text) {
  const m = text.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/);
  return m ? m[1] : null;
}
const txHash = extractTxHash(run.stdout || "");
if (!txHash) {
  console.error(`[normalize] could not parse transaction_hash from aptos CLI output`);
  process.stdout.write(run.stdout || "");
  process.exit(EXIT_APTOS_SPAWN);
}
console.error(`[normalize] submitted tx ${txHash}; polling for chain confirmation`);

async function fetchWithRetry(url, init, retries = 2) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, init);
      return res;
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
    }
  }
  throw lastErr;
}

async function pollTx(hash, timeoutMs = 90_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetchWithRetry(
        `${aptosNodeUrl}/v1/transactions/by_hash/${hash}`,
        { method: "GET", headers: { accept: "application/json" } },
        2,
      );
      if (res.status === 404) {
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const body = await res.json();
      if (body?.type === "pending_transaction") {
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      return body;
    } catch (err) {
      console.error(`[normalize] [poll] retry: ${err?.message ?? err}`);
      await new Promise((r) => setTimeout(r, 2500));
    }
  }
  return null;
}

const tx = await pollTx(txHash);
if (!tx) {
  console.error(`[normalize] chain confirmation timed out for tx ${txHash}`);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}
if (tx.success !== true || (tx.vm_status && tx.vm_status !== "Executed successfully")) {
  console.error(`[normalize] tx ${txHash} reverted: success=${tx.success} vm_status=${tx.vm_status}`);
  process.exit(EXIT_CHAIN_REVERTED);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      status: "normalized",
      txHash,
      version: tx.version,
      gasUsed: tx.gas_used,
      vmStatus: tx.vm_status,
      functionId,
      coordinatorUrl,
    },
    null,
    2,
  ),
);
process.exit(EXIT_SUCCESS);
