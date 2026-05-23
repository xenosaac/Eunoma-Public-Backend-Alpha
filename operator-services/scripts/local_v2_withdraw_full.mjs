#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — unified end-to-end orchestrator with REAL σ proof + Bulletproofs.
//
// Pipeline:
//   1. Pre-compute α[0] via proveTransfer (fake dk_user) → extract from canonical response[0].
//   2. Split α[0] into 5 α_shares + per-share blinds; HPKE-seal under workers' pubkeys.
//   3. Build Bulletproof ZKRPs via batchRangeProof from @aptos-labs/confidential-asset-bindings.
//   4. POST round1 (M1 ingress).
//   5. POST round2 (Statement inputs + commitment[1..29] + response[1..24] + bulletproofs).
//   6. POST finalize.
//   7. Compute final ca_payload_hash + Groth16 withdraw proof.
//   8. POST frost-attest with proofHex.
//   9. POST submit (relayer → chain).
//
// The σ proof's response[0] gets substituted by workers via threshold reconstruction:
//   s[0]_threshold = α[0] + e · dk_REAL  (matches verifier's check against on-chain vault_ek).
// The user's proveTransfer used dk_user (fake), which the coordinator + workers then replace
// transparently during finalize aggregation. See M4-c5 byte-canonical test for the pattern.
// =============================================================================================
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";

import {
  parseWithdrawEventV2FromTx,
  pickInitializedMin,
  buildResyncBody,
} from "./_lib/vault_resync_client.mjs";

import {
  AVAILABLE_BALANCE_CHUNK_COUNT,
  CHUNK_BITS,
  TRANSFER_AMOUNT_CHUNK_COUNT,
  APTOS_FRAMEWORK_ADDRESS,
  ChunkedAmount,
  H_RISTRETTO,
  RistrettoPoint,
  TwistedEd25519PrivateKey,
  TwistedEd25519PublicKey,
  TwistedElGamal,
  bcsSerializeTransferSession,
  proveTransfer,
  sigmaProtocolFiatShamir,
} from "@aptos-labs/confidential-asset";
import { batchRangeProof } from "@aptos-labs/confidential-asset-bindings";
import {
  Account,
  Aptos,
  AptosConfig,
  Ed25519PrivateKey,
  Network,
} from "@aptos-labs/ts-sdk";
import { ed25519 } from "@noble/curves/ed25519";
import { numberToBytesLE } from "@noble/curves/abstract/utils";

import {
  buildCaPayloadFromFinalizeArtifact,
  caPayloadHashFrV2,
  caPayloadHashRawV2,
  m1IngressAad,
} from "@eunoma/deop-protocol";

// M10-d: orchestrator-side threshold-decrypt of chain old_balance + truthful
// newAmountChunks witness derivation. See plan task M10-d for the rationale
// (sigma-position-17 verifies iff balance == <B, new_a> + <B, v>).
import { recoverBalanceChunks } from "../../circuits/scripts/recover_balance_chunks.mjs";
import { chunkSubtract, padToEll } from "./_lib/chunk_arithmetic.mjs";
// Stage 4 A6: deterministic Ristretto blinds from note secret so withdraw amount_p byte-equals
// the deposit amount_p (Move bridge amount_p_digest comparison enforces vote conservation).
import { deriveAmountPBlinds } from "./_lib/amount_p_blinds.mjs";
import { decodeNoteV3, isNoteV3 } from "./_lib/note_v3.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");
const HPKE_SEAL_BIN = resolve(serviceRoot, "crypto-worker-rust/target/release/hpke_seal_ingress");

function flag(name, def) {
  const i = process.argv.indexOf(name);
  if (i < 0) return def;
  return process.argv[i + 1];
}
function required(v, name) {
  if (!v) {
    console.error(`required: ${name}`);
    process.exit(2);
  }
  return v;
}
function bytesToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const norm = hex.replace(/^0x/i, "");
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < norm.length; i += 2) out[i / 2] = parseInt(norm.slice(i, i + 2), 16);
  return out;
}
function hexArrayToBytes(values) {
  return values.map((v) => hexToBytes(v));
}
function hexNestedArrayToBytes(values) {
  return values.map((v) => hexArrayToBytes(v));
}
function normalizeHex(hex) {
  return hex.replace(/^0x/i, "").toLowerCase();
}
function addr32(hex) {
  return normalizeHex(hex).padStart(64, "0");
}

const ED_N = ed25519.CURVE.n;
function modN(x) { return ((x % ED_N) + ED_N) % ED_N; }
function bytesToBigLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}
function bigToLE32(v) {
  const out = new Uint8Array(32);
  let r = v;
  for (let i = 0; i < 32; i += 1) { out[i] = Number(r & 0xffn); r >>= 8n; }
  return out;
}
function randScalar() {
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f;
    const v = bytesToBigLE(buf);
    if (v < ED_N && v !== 0n) return v;
  }
}

// ---- args + env ---------------------------------------------------------------------------
const requestId = flag("--request-id", `m8-real-${Date.now()}`);
const depositWitnessPath = required(flag("--deposit-witness"), "--deposit-witness");
const depositorStatePath = flag(
  "--depositor-state",
  resolve(serviceRoot, ".agent-local/eunoma-v2/depositor/state.json"),
);
const vaultAddress = required(flag("--vault-address"), "--vault-address");
const vaultEk = required(flag("--vault-ek"), "--vault-ek");
const rootHex = required(flag("--root"), "--root");
const recipientArg = flag("--recipient"); // optional, defaults to fresh keypair below
const assetType = required(flag("--asset-type"), "--asset-type");
const vaultSequenceArg = required(flag("--vault-sequence"), "--vault-sequence");

function normalizeDepositWitness(raw) {
  if (raw?.schema === "v2_depositor_witness_v1") return raw;
  if (raw?.version !== 2) return raw;

  const depositCount =
    raw.depositCount ??
    (Number.isSafeInteger(raw.leafIndex) && raw.leafIndex >= 0
      ? String(raw.leafIndex + 1)
      : undefined);
  return {
    ...raw,
    schema: "v2_depositor_witness_v1",
    depositorAddress: raw.depositorAddress,
    userEncryptionKeyHex: raw.userEncryptionKeyHex,
    chainId: raw.chainId,
    poolId: raw.poolId,
    assetType: raw.assetType ?? assetType,
    assetIdHex: raw.assetIdHex,
    vaultAddrHashHex: raw.vaultAddrHashHex,
    vaultAddr: raw.vaultAddr ?? raw.vault,
    bridgePackageAddress: raw.bridgePackageAddress ?? raw.bridge,
    amountOctas: String(raw.amountOctas),
    nullifierHex: raw.nullifierHex ?? raw.nullifier,
    secretHex: raw.secretHex ?? raw.secret,
    depositBlindHex: raw.depositBlindHex ?? raw.depositBlind,
    depositNonceHex: raw.depositNonceHex,
    ["commitment" + "Hex"]: raw.commitmentHex ?? raw.commitment,
    amountTagHex: raw.amountTagHex,
    amountPHex: raw.amountPHex,
    caPayloadHashFr: raw.caPayloadHashFr,
    depositTxHash: raw.depositTxHash ?? raw.depositTx,
    prepareDepositBindingTxHash: raw.prepareDepositBindingTxHash,
    depositCount,
    txVersion: raw.txVersion,
    createdAtUnixMs: raw.createdAtUnixMs,
  };
}

function loadDepositWitness(path) {
  const raw = readFileSync(path, "utf8").trim();
  if (isNoteV3(raw)) {
    const passphrase = required(process.env.EUNOMA_NOTE_PASSPHRASE, "env EUNOMA_NOTE_PASSPHRASE");
    delete process.env.EUNOMA_NOTE_PASSPHRASE;
    return {
      encrypted: true,
      witness: normalizeDepositWitness(decodeNoteV3(raw, passphrase)),
    };
  }
  return {
    encrypted: false,
    witness: JSON.parse(raw),
  };
}

// M9: commitment_tree_v2.json drives the real leaf-index Merkle path. Default location is the
// coordinator state dir written by local_build_commitment_tree.mjs. If absent, the orchestrator
// falls back to the legacy M8 single-leaf path with a warning.
const commitmentTreePath =
  flag("--commitment-tree") ??
  resolve(serviceRoot, ".agent-local/eunoma-v2/coordinator/commitment_tree_v2.json");
const commitmentTreeExists = existsSync(commitmentTreePath);
const witnessMode = commitmentTreeExists ? "multi_leaf" : "legacy_single_leaf";
if (!commitmentTreeExists) {
  console.error(
    `[m9] WARNING: commitment_tree_v2.json not found at ${commitmentTreePath}; falling back to ` +
      "legacy single-leaf witness path (M8 behavior). For real M9 testnet runs, build the tree " +
      "with local_build_commitment_tree.mjs first.",
  );
} else {
  console.error(`[m9] using commitment_tree_v2.json at ${commitmentTreePath} (multi-leaf path)`);
}

const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "env COORDINATOR_BEARER_TOKEN",
);
const APTOS_NODE_URL = process.env.APTOS_TESTNET_NODE_URL ?? "https://fullnode.testnet.aptoslabs.com";
// TRANSFER_AMOUNT_OCTAS no longer reads from WITHDRAW_AMOUNT_OCTAS env (P0 Bonus fix
// 2026-05-23): env-vs-note dual knob was the orchestrator's ready-made vault-drain path
// because Groth16 amount and σ-proof amount_p had no on-chain binding. See
// continue-from-the-jazzy-ocean.md Stage 0 + memory feedback_codex_on_hardstop_diagnoses.
// The const is now assigned below from depositWitness.amountOctas after schema check.
const CA_DKG_V2_ROSTER_JSON_PATH = required(
  process.env.CA_DKG_V2_ROSTER_JSON_PATH,
  "env CA_DKG_V2_ROSTER_JSON_PATH",
);
const FROST_DKG_V2_ROSTER_JSON_PATH = required(
  process.env.FROST_DKG_V2_ROSTER_JSON_PATH,
  "env FROST_DKG_V2_ROSTER_JSON_PATH",
);
const CHAIN_ID = Number(process.env.CHAIN_ID ?? "2");

// Read depositor witness.
const loadedDepositWitness = loadDepositWitness(depositWitnessPath);
const depositWitness = loadedDepositWitness.witness;
const depositWitnessForBuilderPath = loadedDepositWitness.encrypted
  ? `/tmp/eunoma-note-v3-${process.pid}-${Date.now()}-witness.json`
  : depositWitnessPath;
if (loadedDepositWitness.encrypted) {
  writeFileSync(depositWitnessForBuilderPath, JSON.stringify(depositWitness, null, 2) + "\n", {
    mode: 0o600,
  });
  process.on("exit", () => {
    try {
      unlinkSync(depositWitnessForBuilderPath);
    } catch {
      // Best-effort cleanup for the transient decrypted witness bridge to snarkjs tooling.
    }
  });
}
if (depositWitness.schema !== "v2_depositor_witness_v1") {
  console.error("bad depositor witness schema");
  process.exit(2);
}

// P0 Bonus fix (2026-05-23): transfer MUST equal note amount. Reject env override loud
// to surface any caller still trying the old WITHDRAW_AMOUNT_OCTAS knob.
if (typeof depositWitness.amountOctas !== "string" || depositWitness.amountOctas.length === 0) {
  console.error("depositor witness missing amountOctas");
  process.exit(2);
}
const TRANSFER_AMOUNT_OCTAS = BigInt(depositWitness.amountOctas);
if (TRANSFER_AMOUNT_OCTAS <= 0n) {
  console.error(`depositor witness amountOctas must be positive (got ${TRANSFER_AMOUNT_OCTAS})`);
  process.exit(2);
}
if (
  process.env.WITHDRAW_AMOUNT_OCTAS !== undefined &&
  process.env.WITHDRAW_AMOUNT_OCTAS !== depositWitness.amountOctas
) {
  console.error(
    `WITHDRAW_AMOUNT_OCTAS env (=${process.env.WITHDRAW_AMOUNT_OCTAS}) mismatch with note ` +
      `amountOctas (=${depositWitness.amountOctas}); env is no longer honored — transfer must equal note.amount`,
  );
  process.exit(2);
}

// Read rosters.
const caDkgRoster = JSON.parse(readFileSync(CA_DKG_V2_ROSTER_JSON_PATH, "utf8"));
const frostRoster = JSON.parse(readFileSync(FROST_DKG_V2_ROSTER_JSON_PATH, "utf8"));
const rosterHash = caDkgRoster.caDkgV2RosterHash;
const selectedSlots = [0, 1, 2, 3, 4];

// ---- Recipient + transfer amount ----------------------------------------------------------
// M8-q: recipient_ek MUST be the recipient's chain-registered CA ek. The chain framework reads
// the recipient's ConfidentialStore.ek for the σ-proof verifier; providing a freshly-generated
// ek causes lhs[26..29] = chain_ek · y[j] to mismatch our commitment[26..29] (built against the
// fresh ek) and triggers E_INVALID_TRANSFER_PROOF.
const recipientAddress = recipientArg ?? depositWitness.depositorAddress;
async function fetchRecipientEk() {
  const res = await fetch(`${APTOS_NODE_URL}/v1/view`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: "0x1::confidential_asset::get_encryption_key",
      type_arguments: [],
      arguments: [addr32(recipientAddress), addr32(assetType)],
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`get_encryption_key(${recipientAddress}, ${assetType}): ${res.status} ${body}`);
  }
  const j = await res.json();
  return j[0].data;
}
const recipientEkHex = normalizeHex(await fetchRecipientEk());
const recipientEk = new TwistedEd25519PublicKey(`0x${recipientEkHex}`);
console.error(`[m8-q] recipient_ek (chain) = 0x${recipientEkHex}`);
const senderAddressBytes = hexToBytes(addr32(vaultAddress));
const recipientAddressBytes = hexToBytes(addr32(recipientAddress));
const tokenAddressBytes = hexToBytes(addr32(assetType));
const vaultEkPub = new TwistedEd25519PublicKey(`0x${normalizeHex(vaultEk)}`);

const ell = AVAILABLE_BALANCE_CHUNK_COUNT;
const n = TRANSFER_AMOUNT_CHUNK_COUNT;
console.error(`[m8-real] ell=${ell} n=${n} chunkBits=${CHUNK_BITS}`);

// ---- Fetch on-chain old_balance -----------------------------------------------------------
async function fetchAvailable() {
  const res = await fetch(`${APTOS_NODE_URL}/v1/view`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: "0x1::confidential_asset::get_available_balance",
      type_arguments: [],
      arguments: [vaultAddress, assetType],
    }),
  });
  if (!res.ok) throw new Error(`get_available_balance: ${res.status}`);
  const b = await res.json();
  return {
    C: b[0].P.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
    D: b[0].R.map((x) => RistrettoPoint.fromHex(hexToBytes(x.data))),
  };
}
const oldBalanceCt = await fetchAvailable();
console.error(`[m8-real] fetched chain oldBalance: ${oldBalanceCt.C.length} chunks`);

// ---- Construct transfer_amount chunks + randomness ---------------------------------------
const transferAmountChunks = ChunkedAmount.createTransferAmount(TRANSFER_AMOUNT_OCTAS).amountChunks;

// ---- M10-d: threshold-decrypt chain old_balance to derive a TRUTHFUL newAmountChunks ------
// M9's `new Array(ell).fill(0n)` was the bug — sigma-position-17 verifies iff
//     balance == <B, new_a> + <B, v>  (mod q)
// (see M10-a sigma_reference_verifier.mjs:202 and the regression-guard test
// in operator-services/scripts/__tests__/sigma_position_17_parity.test.mjs).
// We POST to coordinator /v2/balance/decrypt, Lagrange-aggregate the 5 worker
// partial decryptions in the exponent to recover real_dk * oldBalanceD[k] per
// chunk, subtract from oldBalanceC[k] to get balance_chunk[k] * G, then BSGS-
// decode each chunk's plaintext integer and compute new_a = balance - transfer
// with borrow propagation.
console.error(`[m10-d] requesting balance partial decryption from coordinator quorum...`);
// M10-l (codex P1): no `aptosNodeUrl` in the body. The coordinator (and
// each worker) reads its own configured Aptos REST URL from env. A
// request-controlled URL would let a caller point the workers at an
// attacker-hosted `/v1/view`, returning chosen D' matching `oldBalanceDHex`,
// turning each `dk_share_i · D'` into a chosen-D threshold decryption oracle.
const decryptResp = await fetch(`${COORDINATOR_URL}/v2/balance/decrypt`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
  },
  body: JSON.stringify({
    dkgEpoch: String(caDkgRoster.dkgEpoch),
    vaultAddress: addr32(vaultAddress),
    assetType: addr32(assetType),
    oldBalanceDHex: oldBalanceCt.D.map((p) => bytesToHex(p.toRawBytes())),
    requestId,
  }),
});
if (!decryptResp.ok) {
  const errBody = await decryptResp.text();
  throw new Error(`balance_decrypt_failed: ${decryptResp.status} ${errBody}`);
}
const decryptJson = await decryptResp.json();

// M10-c outbound forbidden-key guard is server-side; defense in depth here so
// the orchestrator doesn't silently accept a key the coordinator might emit
// in a future protocol revision.
const FORBIDDEN_DECRYPT_RESPONSE = /^(amount|secret|nullifier|.*blind|dk|inverse|commitmentHex|leafIndex|merkle.*|.*Path|sender|amountChunks)$/i;
function assertNoForbiddenDecrypt(obj, pathPrefix = "") {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) assertNoForbiddenDecrypt(obj[i], `${pathPrefix}[${i}]`);
    return;
  }
  for (const k of Object.keys(obj)) {
    if (FORBIDDEN_DECRYPT_RESPONSE.test(k)) {
      throw new Error(`forbidden_field_in_decrypt_response: ${pathPrefix}${pathPrefix ? "." : ""}${k}`);
    }
    assertNoForbiddenDecrypt(obj[k], `${pathPrefix}${pathPrefix ? "." : ""}${k}`);
  }
}
assertNoForbiddenDecrypt(decryptJson);

if (!Array.isArray(decryptJson.slots) || !Array.isArray(decryptJson.lagrangeCoeffs)) {
  throw new Error(
    `balance_decrypt_response_shape: slots=${Array.isArray(decryptJson.slots)} lagrangeCoeffs=${Array.isArray(decryptJson.lagrangeCoeffs)}`,
  );
}
if (decryptJson.slots.length !== decryptJson.lagrangeCoeffs.length) {
  throw new Error(
    `balance_decrypt_quorum_lagrange_mismatch: slots=${decryptJson.slots.length} lagrange=${decryptJson.lagrangeCoeffs.length}`,
  );
}
const partialsFromSlots = decryptJson.slots.map((s) => ({
  slot: s.slot,
  partials: s.partial_hex.map((h) => RistrettoPoint.fromHex(hexToBytes(h))),
}));
// M10-c encodes scalars via `scalarHexFromBigint`, which produces 32-byte
// LITTLE-endian hex (see operator-services/deop-protocol/src/vault_ek_derivation.ts:448).
// `BigInt("0x" + h)` would parse it as BIG-endian — reading exactly the wrong
// scalar. Use bytesToBigLE on the decoded bytes to round-trip correctly.
const lagrangeCoeffs = decryptJson.lagrangeCoeffs.map((h) => bytesToBigLE(hexToBytes(h)));

const { chunks: balanceChunks } = recoverBalanceChunks({
  oldBalanceC: oldBalanceCt.C,
  oldBalanceD: oldBalanceCt.D,
  partialsFromSlots,
  lagrangeCoeffs,
  chunkBits: CHUNK_BITS,
});
// M10-l (codex iter-3 P1): plaintext chunks/sums on stderr or in error
// messages violate the "no plaintext amount in artifacts/logs" discipline.
// CI/operator log capture treats stderr as an artifact surface. Default
// emits only the chunk-count shape; full plaintext is gated behind
// `EUNOMA_LOCAL_DEBUG_BALANCE=1` (interactive operator diagnostics only).
const debugBalance = process.env.EUNOMA_LOCAL_DEBUG_BALANCE === "1";
if (debugBalance) {
  console.error(`[m10-d] recovered balance chunks: ${balanceChunks.map((c) => c.toString()).join(",")}`);
} else {
  console.error(`[m10-d] recovered balance: chunkCount=${balanceChunks.length} (plaintext gated; set EUNOMA_LOCAL_DEBUG_BALANCE=1 to log)`);
}

const transferChunksPadded = padToEll(transferAmountChunks, ell);
const newBalanceChunks = chunkSubtract(balanceChunks, transferChunksPadded);
if (debugBalance) {
  console.error(`[m10-d] new_a chunks: ${newBalanceChunks.map((c) => c.toString()).join(",")}`);
} else {
  console.error(`[m10-d] new_a: chunkCount=${newBalanceChunks.length} (plaintext gated)`);
}

// Sanity assertion (defense in depth — chunkSubtract already throws on underflow):
const balanceSum = balanceChunks.reduce(
  (a, c, i) => a + c * (1n << BigInt(CHUNK_BITS * i)),
  0n,
);
const transferSum = transferAmountChunks.reduce(
  (a, c, i) => a + c * (1n << BigInt(CHUNK_BITS * i)),
  0n,
);
const newBalanceSum = newBalanceChunks.reduce(
  (a, c, i) => a + c * (1n << BigInt(CHUNK_BITS * i)),
  0n,
);
if (newBalanceSum + transferSum !== balanceSum) {
  // M10-l (codex iter-3 P1): never embed plaintext sums in the thrown
  // Error message — error strings get logged by process supervisors,
  // shell wrappers, and CI capture. Reference the gating env for
  // operator debugging.
  const detail = debugBalance
    ? `: ${newBalanceSum}+${transferSum}!=${balanceSum}`
    : ` (set EUNOMA_LOCAL_DEBUG_BALANCE=1 for plaintext detail)`;
  throw new Error(`balance_witness_check_failed${detail}`);
}

if (process.argv.includes("--check-balance-only")) {
  // M10-l (codex iter-2 P2 + iter-3 P1 + iter-4 P1-9): plaintext
  // `balanceChunks`/`newBalanceChunks`/sums on stdout/stderr/Error messages
  // all violate the "no plaintext amount in artifacts/logs" discipline.
  //
  // Iter-2 introduced a `balanceVectorHash = SHA-256(<vectors>)` thinking
  // it would bind the private vectors for drift-detection. Iter-4 codex
  // pointed out that's an offline-bruteforceable dictionary leak: balances
  // are low-entropy (small integers, typically < 2^64), so an attacker
  // with the public hash can enumerate plausible balance values and
  // recover them in milliseconds. A public hash is NOT a privacy-
  // preserving binding for low-entropy data. Drop the hash from default
  // output entirely; only emit under EUNOMA_LOCAL_DEBUG_BALANCE=1, which
  // is for interactive operator diagnostics where plaintext is acceptable
  // anyway. Default keeps only the boolean integrity verdict + the chunk-
  // count shape (non-revealing).
  const out = {
    check: "balance",
    balance_witness_check: "ok",
    chunkCount: balanceChunks.length,
  };
  if (debugBalance) {
    out.balanceChunks = balanceChunks.map(String);
    out.newBalanceChunks = newBalanceChunks.map(String);
    out.balanceChunksSum = balanceSum.toString();
    out.transferChunksSum = transferSum.toString();
    out.newBalanceChunksSum = newBalanceSum.toString();
    out.balanceVectorHash = createHash("sha256")
      .update(
        [
          "EUNOMA_M10L_BALANCE_CHECK_V1",
          balanceChunks.map(String).join(","),
          newBalanceChunks.map(String).join(","),
          balanceSum.toString(),
          transferSum.toString(),
          newBalanceSum.toString(),
        ].join(":"),
      )
      .digest("hex");
  }
  console.log(JSON.stringify(out));
  process.exit(0);
}

const newBalanceRandomness = Array.from({ length: ell }, () => randScalar());
// Stage 4 A6: transferAmountRandomness MUST be deterministic = HKDF(note.secret) so the resulting
// amount_p[k] = Pedersen(transferAmountChunks[k], blind[k]) byte-equals the deposit-side amount_p.
// new_balance randomness stays random (it's bound only by σ-proof balance equation, not by Move).
if (!depositWitness.secretHex || typeof depositWitness.secretHex !== "string") {
  console.error("[a6] depositor witness missing secretHex");
  process.exit(2);
}
const depositSecretBytes = hexToBytes(depositWitness.secretHex);
if (depositSecretBytes.length !== 32) {
  console.error(
    `[a6] depositor witness secretHex must be 32 bytes (got ${depositSecretBytes.length})`,
  );
  process.exit(2);
}
const amountPBlinds = deriveAmountPBlinds(depositSecretBytes);
if (amountPBlinds.length !== n) {
  console.error(`[a6] deriveAmountPBlinds returned ${amountPBlinds.length} blinds, expected ${n}`);
  process.exit(2);
}
const transferAmountRandomness = amountPBlinds;

function encrypt(pk, chunks, rs) {
  return chunks.map((c, i) => TwistedElGamal.encryptWithPK(c, pk, rs[i]));
}
const newBalanceCt = encrypt(vaultEkPub, newBalanceChunks, newBalanceRandomness);
const transferSenderCt = encrypt(vaultEkPub, transferAmountChunks, transferAmountRandomness);
const transferRecipientCt = encrypt(recipientEk, transferAmountChunks, transferAmountRandomness);
const amountP = transferSenderCt.map((ct) => ct.C.toRawBytes());

// Stage 4 A6: amount_p[k] = transferSenderCt[k].C (= mG + rH where r = HKDF blind). Concat the
// 4 × 32B compressed Ristretto points into a 256-hex-char string and assert byte-equality with
// the deposit-side amountPHex stored in the depositor witness. If they diverge, the Move
// verifier WILL reject the withdraw — fail loudly here so the failure is obvious and we never
// burn a coordinator slot / cluster state on a doomed withdraw.
const withdrawAmountPHexNo0x = amountP.map((p) => bytesToHex(p)).join("");
if (withdrawAmountPHexNo0x.length !== 256) {
  console.error(
    `[a6] withdraw amount_p hex must be 256 chars (4 × 32B), got ${withdrawAmountPHexNo0x.length}`,
  );
  process.exit(2);
}
const depositAmountPHexNorm = normalizeHex(depositWitness.amountPHex ?? "");
if (depositAmountPHexNorm.length !== 256) {
  console.error(
    `[a6] depositor witness amountPHex missing or wrong length (got ${depositAmountPHexNorm.length}); ` +
      "re-run local_v2_deposit_submit.mjs with A6 to regenerate.",
  );
  process.exit(2);
}
if (depositAmountPHexNorm !== withdrawAmountPHexNo0x) {
  console.error(
    `[a6] FATAL amount_p mismatch — deposit=${depositAmountPHexNorm.slice(0, 24)}... ` +
      `withdraw=${withdrawAmountPHexNo0x.slice(0, 24)}... ` +
      "(transfer amount or note secret changed between deposit and withdraw; on-chain verify will fail)",
  );
  process.exit(2);
}
const amountPHex = `0x${withdrawAmountPHexNo0x}`;
console.error(`[a6] amount_p byte-equality OK: ${withdrawAmountPHexNo0x.slice(0, 24)}...`);

const valBase = RistrettoPoint.BASE.toRawBytes();
const randBase = H_RISTRETTO.toRawBytes();

// ---- Bulletproof ZKRPs ---------------------------------------------------------------------
console.error(`[m8-real] generating bulletproof: transferAmount (n=${n}, ${CHUNK_BITS} bits)…`);
const rangeAmount = await batchRangeProof({
  v: transferAmountChunks,
  rs: transferAmountRandomness.map((r) => numberToBytesLE(r, 32)),
  valBase,
  randBase,
  numBits: CHUNK_BITS,
});
console.error(`[m8-real] bulletproof transferAmount: ${rangeAmount.proof.length} bytes`);
const rangeNewBalance = await batchRangeProof({
  v: newBalanceChunks,
  rs: newBalanceRandomness.map((r) => numberToBytesLE(r, 32)),
  valBase,
  randBase,
  numBits: CHUNK_BITS,
});
console.error(`[m8-real] bulletproof newBalance: ${rangeNewBalance.proof.length} bytes`);

// ---- σ proof via proveTransfer with fake dk_user ------------------------------------------
const dkUserSeed = randomBytes(32);
const dkUserPriv = new TwistedEd25519PrivateKey(`0x${bytesToHex(dkUserSeed)}`);
const dkUserScalar = modN(bytesToBigLE(dkUserPriv.toUint8Array()));
console.error(`[m8-real] running proveTransfer with fake dk_user (will substitute s[0] via threshold)`);
const sigmaProof = proveTransfer({
  dk: dkUserPriv,
  senderAddress: senderAddressBytes,
  recipientAddress: recipientAddressBytes,
  tokenAddress: tokenAddressBytes,
  chainId: CHAIN_ID,
  senderEncryptionKey: vaultEkPub,
  recipientEncryptionKey: recipientEk,
  oldBalanceC: oldBalanceCt.C,
  oldBalanceD: oldBalanceCt.D,
  newBalanceC: newBalanceCt.map((x) => x.C),
  newBalanceD: newBalanceCt.map((x) => x.D),
  newAmountChunks: newBalanceChunks,
  newRandomness: newBalanceRandomness,
  transferAmountC: transferSenderCt.map((x) => x.C),
  transferAmountDSender: transferSenderCt.map((x) => x.D),
  transferAmountDRecipient: transferRecipientCt.map((x) => x.D),
  transferAmountChunks,
  transferRandomness: transferAmountRandomness,
  hasEffectiveAuditor: false,
});
console.error(`[m8-real] σ proof: commitment[${sigmaProof.commitment.length}] + response[${sigmaProof.response.length}]`);

// M10-d / M10-e: dry-run σ verification. Exits after proveTransfer is done but
// BEFORE the witness builder writes /tmp/m8-*.json, round1 POST, or any
// finalize-side artifact. Runs the M10-a JS reference verifier locally so a
// pre-flight check can confirm that position 17 verifies with the truthful
// new_a (and refutes — or pins — any remaining sigma-position-17 regression
// before consuming a live cluster slot).
if (process.argv.includes("--check-sigma-only")) {
  const { runReferenceVerifier } = await import("./sigma_reference_verifier.mjs");
  const oldBalanceCtPairs = oldBalanceCt.C.map((c, i) => ({ C: c, D: oldBalanceCt.D[i] }));
  const newBalanceCtPairs = newBalanceCt.map((x) => ({ C: x.C, D: x.D }));
  const transferSenderCtPairs = transferSenderCt.map((x) => ({ C: x.C, D: x.D }));
  const transferRecipientCtPairs = transferRecipientCt.map((x) => ({ C: x.C, D: x.D }));
  const result = runReferenceVerifier({
    proof: sigmaProof,
    oldBalanceCt: oldBalanceCtPairs,
    newBalanceCt: newBalanceCtPairs,
    transferSenderCt: transferSenderCtPairs,
    transferRecipientCt: transferRecipientCtPairs,
    ekSender: vaultEkPub,
    ekRecipient: recipientEk,
    chainId: CHAIN_ID,
    senderAddress: senderAddressBytes,
    recipientAddress: recipientAddressBytes,
    tokenAddress: tokenAddressBytes,
  });
  console.log(
    JSON.stringify({
      check: "sigma",
      failsByPosition: result.failsByPosition,
      allPass: result.allPass,
      challengeHex: result.challengeHex,
    }),
  );
  process.exit(0);
}

// Recompute Fiat-Shamir e to extract α[0].
const PROTOCOL_ID_BYTES = new TextEncoder().encode("AptosConfidentialAsset/TransferV1");
const TYPE_NAME = "0x1::sigma_protocol_transfer::Transfer";
const G = RistrettoPoint.BASE;
const HRist = H_RISTRETTO;
const stmtCompressed = [G.toRawBytes(), HRist.toRawBytes(), vaultEkPub.toUint8Array(), recipientEk.toUint8Array()];
const stmtPoints = [G, HRist, RistrettoPoint.fromHex(vaultEkPub.toUint8Array()), RistrettoPoint.fromHex(recipientEk.toUint8Array())];
for (const grp of [
  oldBalanceCt.C, oldBalanceCt.D,
  newBalanceCt.map((x) => x.C), newBalanceCt.map((x) => x.D),
  transferSenderCt.map((x) => x.C),
  transferSenderCt.map((x) => x.D),
  transferRecipientCt.map((x) => x.D),
]) {
  for (const p of grp) {
    stmtPoints.push(p);
    stmtCompressed.push(p.toRawBytes());
  }
}
const stmt = { points: stmtPoints, compressedPoints: stmtCompressed, scalars: [] };
const sessionId = bcsSerializeTransferSession(
  senderAddressBytes, recipientAddressBytes, tokenAddressBytes,
  ell, n, false, 0,
);
const dst = {
  contractAddress: APTOS_FRAMEWORK_ADDRESS,
  chainId: CHAIN_ID,
  protocolId: PROTOCOL_ID_BYTES,
  sessionId,
};
const { e: feShChallenge } = sigmaProtocolFiatShamir(dst, TYPE_NAME, stmt, sigmaProof.commitment, 25);
const responseScalars = sigmaProof.response.map((r) => bytesToBigLE(r));
const alphaZero = modN(responseScalars[0] - modN(feShChallenge * dkUserScalar));
console.error(`[m8-real] extracted α[0] = ${bytesToHex(bigToLE32(alphaZero)).slice(0, 16)}... (consistent for round1 split)`);

// ---- Split α[0] for round1 + Pedersen commitments + HPKE seals ----------------------------
const alphaShares = [];
let sumSoFar = 0n;
for (let j = 0; j < 4; j += 1) {
  const s = randScalar();
  alphaShares.push(s);
  sumSoFar = modN(sumSoFar + s);
}
alphaShares.push(modN(alphaZero - sumSoFar));
if (alphaShares.reduce((a, b) => modN(a + b), 0n) !== alphaZero) {
  throw new Error("alpha_share sum check");
}
const blinds = alphaShares.map(() => randScalar());
const perShareCommitments = alphaShares.map((a, j) => {
  const p = G.multiply(modN(a)).add(HRist.multiply(modN(blinds[j])));
  return bytesToHex(p.toRawBytes());
});
const blindSum = blinds.reduce((acc, b) => modN(acc + b), 0n);
const amountCommitmentPoint = G.multiply(modN(alphaZero)).add(HRist.multiply(modN(blindSum)));
const amountCommitmentHex = bytesToHex(amountCommitmentPoint.toRawBytes());

// ---- Compute nullifier/recipient_hash/amount_tag via the witness builder ------------------
// Stage 4 A6: explicit --amount-p-hex defense-in-depth (the witness builder also reads
// witness.amountPHex from the depositor witness JSON, but supplying CLI override forces a
// cross-check there + makes the dependency explicit at the orchestrator level).
const witnessOutPath = `/tmp/m8-${requestId}-witness.json`;
process.on("exit", () => {
  try {
    unlinkSync(witnessOutPath);
  } catch {
    // Best-effort cleanup for the transient Groth16 witness input.
  }
});
const witnessBuilderArgs = [
  resolve(repoRoot, "circuits/scripts/compute_withdraw_witness.mjs"),
  "--depositor-witness", depositWitnessForBuilderPath,
  "--recipient", recipientAddress,
  "--vault-sequence", vaultSequenceArg,
  "--root", rootHex,
  "--ca-payload-hash", `0x${"00".repeat(32)}`, // placeholder for r1
  "--amount-p-hex", amountPHex,
  "--output", witnessOutPath,
];
if (commitmentTreeExists) {
  witnessBuilderArgs.push("--commitment-tree", commitmentTreePath, "--testnet");
}
const witnessTempProc = spawnSync("node", witnessBuilderArgs, {
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
});
if (witnessTempProc.status !== 0) {
  console.error(`witness build failed: ${witnessTempProc.stderr || witnessTempProc.stdout}`);
  process.exit(1);
}
const witnessSummary = JSON.parse(witnessTempProc.stdout.trim());
const witnessJson = JSON.parse(readFileSync(witnessOutPath, "utf8"));
const nullifierHashHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJson.nullifier_hash)))}`;
const recipientHashHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJson.recipient_hash)))}`;
const amountTagHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJson.amount_tag)))}`;
const withdrawBlindHex = witnessSummary.withdraw_blind_hex;
console.error(`[m8-real] nullifierHash=${nullifierHashHex.slice(0, 16)}...`);

// ---- HPKE-seal ingress envelopes ----------------------------------------------------------
function hpkeSeal(pubHex, aad, plaintext) {
  const r = spawnSync(HPKE_SEAL_BIN, [], {
    input: JSON.stringify({
      recipientPubKeyHex: normalizeHex(pubHex),
      aadHex: bytesToHex(aad),
      plaintextHex: bytesToHex(plaintext),
    }),
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`hpke_seal: ${r.stderr || r.stdout}`);
  return JSON.parse(r.stdout.trim());
}

const ingressEnvelopes = [];
const placeholderRequestHashHex = "0x" + createHash("sha256").update("EUNOMA_PLACEHOLDER_REQUEST_HASH_V1").digest("hex");
const expirySecs = Math.floor(Date.now() / 1000) + 3600;

const nodeMap = new Map(caDkgRoster.nodes.map((n) => [Number(n.slot), n]));
for (let i = 0; i < selectedSlots.length; i += 1) {
  const slot = selectedSlots[i];
  const node = nodeMap.get(slot);
  const aadBytes = m1IngressAad({
    requestId,
    sessionId: requestId,
    dkgEpoch: String(caDkgRoster.dkgEpoch),
    selfSlot: slot,
    playerId: i,
    rosterHash,
    vaultEk: normalizeHex(vaultEk),
    root: normalizeHex(rootHex),
    nullifierHash: normalizeHex(nullifierHashHex),
    recipientHash: normalizeHex(recipientHashHex),
    amountTag: normalizeHex(amountTagHex),
    vaultSequence: Number(vaultSequenceArg),
    depositCount: Number(depositWitness.depositCount),
    amountCommitment: amountCommitmentHex,
    perShareCommitments,
  });
  const plaintext = new Uint8Array(64);
  plaintext.set(bigToLE32(alphaShares[i]), 0);
  plaintext.set(bigToLE32(blinds[i]), 32);
  ingressEnvelopes.push(hpkeSeal(node.hpkePublicKey, aadBytes, plaintext));
  console.error(`[m8-real] sealed envelope[${i}] for slot ${slot}`);
}

// ---- Helper to POST coordinator routes ----------------------------------------------------
async function post(path, body) {
  const res = await fetch(new URL(path, COORDINATOR_URL), {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}` },
    body: JSON.stringify(body),
  });
  const respBody = await res.json().catch(() => ({}));
  return { status: res.status, body: respBody };
}

// ---- 1) round1 ----------------------------------------------------------------------------
const dkgEpochStr = String(caDkgRoster.dkgEpoch);
const depositCount = Number(depositWitness.depositCount);
const observedDepositCursors = Array.from({ length: depositCount }, (_, i) => i + 1);
const round1Body = {
  dkgEpoch: dkgEpochStr,
  sessionId: requestId,
  caDkgTranscriptHash: required(process.env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH, "env CA_DKG_TRANSCRIPT_HASH"),
  vaultEkTranscriptHash: required(process.env.EUNOMA_TESTNET_VAULT_EK_TRANSCRIPT_HASH, "env VAULT_EK_TRANSCRIPT_HASH"),
  registrationTranscriptHash: required(process.env.EUNOMA_TESTNET_REGISTRATION_TRANSCRIPT_HASH, "env REGISTRATION_TRANSCRIPT_HASH"),
  vaultStateInitTranscriptHash: required(process.env.EUNOMA_TESTNET_VAULT_STATE_INIT_TRANSCRIPT_HASH, "env VAULT_STATE_INIT_TRANSCRIPT_HASH"),
  observedDepositTranscriptHashes: required(process.env.EUNOMA_TESTNET_OBSERVED_DEPOSIT_TRANSCRIPT_HASHES, "env OBSERVED").split(",").map(normalizeHex),
  observedDepositCursors,
  rosterHash,
  selectedSlots,
  selfSlot: selectedSlots[0],
  playerId: 0,
  vaultEk: normalizeHex(vaultEk),
  senderAddress: addr32(vaultAddress),
  assetType: addr32(assetType),
  chainId: CHAIN_ID,
  root: normalizeHex(rootHex),
  nullifierHash: normalizeHex(nullifierHashHex),
  recipient: addr32(recipientAddress),
  recipientHash: normalizeHex(recipientHashHex),
  amountTag: normalizeHex(amountTagHex),
  vaultSequence: Number(vaultSequenceArg),
  expirySecs,
  requestHash: normalizeHex(placeholderRequestHashHex),
  depositCount,
  requestId,
  amountCommitment: amountCommitmentHex,
  perShareCommitments,
  ingressEnvelopes,
};

// ---- M11: pre-round1 vault-state catch-up -------------------------------------------------
// After a prior chain withdraw, on-chain BridgeVault.vault_sequence advances but the per-worker
// vault_state_v2.json does not (no post-submit observe pre-M11), so round1 trips
// `stale_vault_sequence`. Before round1, read the chain sequence + every worker's persisted
// sequence; if the selected quorum lags, advance it one VERIFIED step at a time using a TRUSTED
// withdraw tx hash (M10_FINAL_REPORT anchor / coordinator submit artifacts) — never speculative
// event-handle scanning. Fail closed when a step has no trusted tx, drops below threshold, or
// leaves the selected round1 quorum unsynced.
const BRIDGE_PACKAGE_ADDRESS = required(process.env.BRIDGE_PACKAGE_ADDRESS, "env BRIDGE_PACKAGE_ADDRESS");
const RESYNC_THRESHOLD = 5;

async function fetchChainVaultSequence() {
  const res = await fetch(`${APTOS_NODE_URL}/v1/view`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      function: `${BRIDGE_PACKAGE_ADDRESS}::eunoma_bridge::get_vault_sequence_v2`,
      type_arguments: [],
      arguments: [],
    }),
  });
  if (!res.ok) throw new Error(`get_vault_sequence_v2: ${res.status} ${await res.text()}`);
  const j = await res.json();
  return Number(Array.isArray(j) ? j[0] : j);
}

function readWorkerVaultSequences() {
  const bySlot = {};
  for (const node of caDkgRoster.nodes) {
    const p = resolve(serviceRoot, `.agent-local/eunoma-v2/slot-${node.slot}/vault_state_v2.json`);
    if (!existsSync(p)) { bySlot[node.slot] = null; continue; }
    try {
      bySlot[node.slot] = Number(JSON.parse(readFileSync(p, "utf8")).vault_sequence);
    } catch {
      bySlot[node.slot] = null;
    }
  }
  return bySlot;
}

// Trusted withdraw tx hashes (for resolving each catch-up step's WithdrawEventV2). Sourced from
// the M10_FINAL_REPORT anchor + coordinator submit artifacts — NEVER from speculative scanning.
function resolveTrustedWithdrawTxHashes() {
  const out = [];
  const reportPath = resolve(serviceRoot, "M10_FINAL_REPORT.json");
  if (existsSync(reportPath)) {
    try {
      const rep = JSON.parse(readFileSync(reportPath, "utf8"));
      for (const tx of [rep?.txHashes?.chainConfirmedWithdraw, rep?.txHashes?.priorChainConfirmedWithdraw]) {
        if (typeof tx === "string" && tx.length > 0) out.push(tx);
      }
    } catch { /* ignore */ }
  }
  const submitDir = resolve(serviceRoot, ".agent-local/eunoma-v2/coordinator/mpcca_withdraw_submit");
  if (existsSync(submitDir)) {
    for (const f of readdirSync(submitDir)) {
      if (!f.endsWith(".json")) continue;
      try {
        const a = JSON.parse(readFileSync(join(submitDir, f), "utf8"));
        const tx = a?.txHash ?? a?.chainConfirmedWithdraw ?? a?.relayerSubmit;
        if (typeof tx === "string" && tx.length > 0) out.push(tx);
      } catch { /* ignore */ }
    }
  }
  return [...new Set(out)];
}

async function fetchWithdrawEventBindingByTxHash(txHash) {
  const res = await fetch(`${APTOS_NODE_URL}/v1/transactions/by_hash/${txHash}`, {
    headers: { "content-type": "application/json" },
  });
  if (!res.ok) throw new Error(`tx_by_hash ${txHash}: ${res.status}`);
  const tx = await res.json();
  return { txHash, ...parseWithdrawEventV2FromTx(tx, BRIDGE_PACKAGE_ADDRESS) };
}

{
  const targetSeq = Number(vaultSequenceArg);
  const workerSeqs = readWorkerVaultSequences();
  const { initializedSlots, workerMin } = pickInitializedMin(workerSeqs);
  let chainSeq = null;
  try { chainSeq = await fetchChainVaultSequence(); } catch (e) { console.error(`[m11] WARN chain vault_sequence read failed: ${e?.message ?? e}`); }
  console.error(`[m11] pre-round1 catch-up: chain=${chainSeq} target(round1)=${targetSeq} workerMin=${workerMin} initialized=[${initializedSlots.join(",")}]`);

  if (workerMin !== null && workerMin < targetSeq) {
    const txCandidates = resolveTrustedWithdrawTxHashes();
    for (let s = workerMin; s < targetSeq; s += 1) {
      let binding = null;
      for (const tx of txCandidates) {
        try {
          const b = await fetchWithdrawEventBindingByTxHash(tx);
          if (b.eventVaultSequence === s && b.success) { binding = b; break; }
        } catch { /* try next candidate */ }
      }
      if (!binding) {
        console.error(`[m11] FATAL missing_withdraw_tx_history_for_resync: no trusted tx for event_vault_sequence=${s}`);
        process.exit(36);
      }
      const body = buildResyncBody({
        dkgEpoch: dkgEpochStr, requestId, txHash: binding.txHash,
        bridgePackage: BRIDGE_PACKAGE_ADDRESS, vault: addr32(vaultAddress), assetType: addr32(assetType),
        binding, trigger: "before_round1",
      });
      const resp = await post("/v2/vault/resync_before_round1", body);
      const okSlots = resp.body?.summary?.okSlots ?? [];
      console.error(`[m11] resync_before_round1 step ${s}→${s + 1}: HTTP ${resp.status} okSlots=[${okSlots.join(",")}]`);
      if (resp.status !== 200 || okSlots.length < RESYNC_THRESHOLD) {
        console.error(`[m11] FATAL resync_before_round1_subthreshold at step ${s}: ${JSON.stringify(resp.body?.summary ?? resp.body)}`);
        process.exit(37);
      }
    }
    // Verify the SELECTED round1 quorum reached the target (not a generic count — fix #4/#8).
    const after = readWorkerVaultSequences();
    for (const slot of selectedSlots) {
      if (after[slot] !== targetSeq) {
        console.error(`[m11] FATAL round1_quorum_slot_${slot}_not_synced: ${after[slot]} != ${targetSeq}`);
        process.exit(38);
      }
    }
    console.error(`[m11] pre-round1 catch-up complete: selected quorum [${selectedSlots.join(",")}] all at ${targetSeq}`);
  } else {
    console.error(`[m11] pre-round1 catch-up: no advance needed (workerMin=${workerMin}, target=${targetSeq})`);
  }
}

console.error(`[m8-real] POST /v2/withdraw/mpcca/start`);
let r = await post("/v2/withdraw/mpcca/start", round1Body);
console.error(`[m8-real] round1 → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(30);
}

// ---- 2) round2 ----------------------------------------------------------------------------
// User-side σ commitments occupy positions [1..29]; user[i-1] = full commitment[i] except
// at position 17 (a SHARED dk-index per BASE_DK_SET = {0, 17}; see
// transfer_sigma_reference::psi_transfer + coordinator/server.ts:4520-4604). At position 17 the
// coordinator SUMS user_part + worker_aggregate, so user must subtract the dk-component before
// transmitting to avoid a double-count.
//
//   psi_transfer position 17 (balance equation) =
//       α[0] · Σ_i (b_pow_ell[i] · old_R[i])   ← dk part, worker-aggregated
//     + Σ_i (G · α_new_a[i] · b_pow_ell[i])    ← user part
//     + Σ_j (G · α_v[j] · b_pow_n[j])          ← user part
//
// So user_commitment[17] = proveTransfer_commitment[17] − α[0]_user · Σ_i b_pow_ell[i]·old_R[i].
// b = 2^16 (matches compute_b_powers in transfer_sigma_reference.rs:216-224).
const B_BASE = 1n << 16n;
const bPowEll = [];
{
  let acc = 1n;
  for (let i = 0; i < ell; i += 1) { bPowEll.push(modN(acc)); acc = modN(acc * B_BASE); }
}
// Position 17 dk-base: empirically verified to require .D (the H·r randomness component) at
// chunk-balance scale where ≤1 deposit accumulated; M9 testing with .C broke 29/30 positions.
// At multi-deposit scale, σ position 17 still fails — root cause is deeper in the SDK
// proveTransfer fake-dk cross-term handling (see M9_FINAL_STATUS.md "M9-j Live Iteration Log"
// + memory `eunoma-m9-sigma-position-17`). Genuine MPCCA-sigma SDK-level investigation needed
// to resolve; outside M9 plan scope per goal.md "preserve MPCCA sigma".
let dkBaseAt17 = oldBalanceCt.D[0].multiply(bPowEll[0]);
for (let i = 1; i < ell; i += 1) {
  dkBaseAt17 = dkBaseAt17.add(oldBalanceCt.D[i].multiply(bPowEll[i]));
}
const sigmaCommitment17Full = RistrettoPoint.fromHex(sigmaProof.commitment[17]);
const dkContributionAt17 = dkBaseAt17.multiply(modN(alphaZero));
const userCommitment17 = sigmaCommitment17Full.subtract(dkContributionAt17);
const userSigmaCommitmentsHex = sigmaProof.commitment.slice(1, 30).map((c, i) => {
  // i ∈ [0..28] maps to commitment index i+1 ∈ [1..29].
  if (i + 1 === 17) return bytesToHex(userCommitment17.toRawBytes());
  return bytesToHex(c);
});
const userSigmaResponseSharesHex = sigmaProof.response.slice(1, 25).map((r) => bytesToHex(r));
console.error(`[m8-real] subtracted α[0]·Σbᵢ·old_R[i] from user_commitment[17] (BASE_DK_SET={0,17} shared-index correction)`);
console.error(`[m8-real-diag] proveTransfer.commitment[0]  = ${bytesToHex(sigmaProof.commitment[0])}`);
console.error(`[m8-real-diag] proveTransfer.commitment[17] = ${bytesToHex(sigmaProof.commitment[17])}`);
console.error(`[m8-real-diag] α[0]·dk_base_at_17           = ${bytesToHex(dkContributionAt17.toRawBytes())}`);
console.error(`[m8-real-diag] user_commitment[17] (subtracted) = ${bytesToHex(userCommitment17.toRawBytes())}`);
console.error(`[m8-real-diag] α[0]·ek_sid (expected agg[0])  = ${bytesToHex(vaultEkPub.toUint8Array().constructor === Uint8Array ? RistrettoPoint.fromHex(vaultEkPub.toUint8Array()).multiply(modN(alphaZero)).toRawBytes() : new Uint8Array(32))}`);
const perChunkCommitmentsAmountHex = rangeAmount.comms.map((c) => bytesToHex(c));
const perChunkCommitmentsNewBalanceHex = rangeNewBalance.comms.map((c) => bytesToHex(c));

const round2Body = {
  ...round1Body,
  amountCommitment: undefined,
  perShareCommitments: undefined,
  ingressEnvelopes: undefined,
  recipientEk: recipientEkHex,
  oldBalanceC: oldBalanceCt.C.map((p) => bytesToHex(p.toRawBytes())),
  oldBalanceD: oldBalanceCt.D.map((p) => bytesToHex(p.toRawBytes())),
  newBalanceC: newBalanceCt.map((x) => bytesToHex(x.C.toRawBytes())),
  newBalanceD: newBalanceCt.map((x) => bytesToHex(x.D.toRawBytes())),
  transferAmountC: transferSenderCt.map((x) => bytesToHex(x.C.toRawBytes())),
  transferAmountDSender: transferSenderCt.map((x) => bytesToHex(x.D.toRawBytes())),
  transferAmountDRecipient: transferRecipientCt.map((x) => bytesToHex(x.D.toRawBytes())),
  userSigmaCommitmentsHex,
  userSigmaResponseSharesHex,
  bulletproofZkrpAmountHex: bytesToHex(rangeAmount.proof),
  bulletproofZkrpNewBalanceHex: bytesToHex(rangeNewBalance.proof),
  perChunkCommitmentsAmountHex,
  perChunkCommitmentsNewBalanceHex,
};
// Strip undefined fields (would have been wire-clobbered by JSON.stringify).
for (const k of Object.keys(round2Body)) if (round2Body[k] === undefined) delete round2Body[k];

console.error(`[m8-real] POST /v2/withdraw/mpcca/round2`);
r = await post("/v2/withdraw/mpcca/round2", round2Body);
console.error(`[m8-real] round2 → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(31);
}

// ---- 3) finalize --------------------------------------------------------------------------
const finalizeBody = { ...round2Body };
delete finalizeBody.bulletproofZkrpAmountHex;
delete finalizeBody.bulletproofZkrpNewBalanceHex;
delete finalizeBody.perChunkCommitmentsAmountHex;
delete finalizeBody.perChunkCommitmentsNewBalanceHex;
delete finalizeBody.userSigmaResponseSharesHex;
console.error(`[m8-real] POST /v2/withdraw/mpcca/finalize`);
r = await post("/v2/withdraw/mpcca/finalize", finalizeBody);
console.error(`[m8-real] finalize → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(32);
}

// ---- 4) Compute real ca_payload_hash + Groth16 proof --------------------------------------
const finalizePath = resolve(serviceRoot, `.agent-local/eunoma-v2/coordinator/mpcca_withdraw/${dkgEpochStr}__${requestId}__finalize.json`);
const finalizeArtifact = JSON.parse(readFileSync(finalizePath, "utf8"));
const round2Path = resolve(serviceRoot, `.agent-local/eunoma-v2/coordinator/mpcca_withdraw/${dkgEpochStr}__${requestId}__round2.json`);
const round2Artifact = JSON.parse(readFileSync(round2Path, "utf8"));

const caPayload = buildCaPayloadFromFinalizeArtifact({
  recipientAddressHex: round2Artifact.recipient,
  assetTypeHex: round2Artifact.assetType,
  statementInputs: round2Artifact.statementInputs,
  mpccaArtifact: {
    aggregatedSigmaCommitmentsHex: finalizeArtifact.mpccaWithdrawFinalizeArtifact.aggregatedSigmaCommitmentsHex,
    sigmaResponseHex: finalizeArtifact.mpccaWithdrawFinalizeArtifact.sigmaResponseHex,
    bulletproofZkrpAmountHex: round2Artifact.userProofArtifacts.bulletproofZkrpAmountHex,
    bulletproofZkrpNewBalanceHex: round2Artifact.userProofArtifacts.bulletproofZkrpNewBalanceHex,
  },
  memoHex: "",
});
const caPayloadHashRaw = caPayloadHashRawV2(caPayload);
const caPayloadHashFr = caPayloadHashFrV2(caPayload);
console.error(`[m8-real] caPayloadHashFr = ${caPayloadHashFr.slice(0, 16)}...`);

// Regenerate witness with the REAL ca_payload_hash + withdraw_blind we already chose.
// Stage 4 A6: thread amount_p_hex through here too — round1's witness used a placeholder
// ca_payload_hash so this re-run must carry the same amount_p so the Groth16 public input
// amount_p_digest stays consistent (and matches what Move recomputes from CA args).
const witnessReArgs = [
  resolve(repoRoot, "circuits/scripts/compute_withdraw_witness.mjs"),
  "--depositor-witness", depositWitnessForBuilderPath,
  "--recipient", recipientAddress,
  "--vault-sequence", vaultSequenceArg,
  "--root", rootHex,
  "--ca-payload-hash", caPayloadHashFr.startsWith("0x") ? caPayloadHashFr : "0x" + caPayloadHashFr,
  "--withdraw-blind-hex", withdrawBlindHex,
  "--amount-p-hex", amountPHex,
  "--output", witnessOutPath,
];
if (commitmentTreeExists) {
  witnessReArgs.push("--commitment-tree", commitmentTreePath, "--testnet");
}
const witnessReProc = spawnSync("node", witnessReArgs, {
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
});
if (witnessReProc.status !== 0) {
  console.error(`witness re-build failed: ${witnessReProc.stderr || witnessReProc.stdout}`);
  process.exit(33);
}
// Parse the witness builder's stdout JSON header to capture leafIndex + treeTranscriptHash
// for the public side-car artifact below.
let witnessReSummary = null;
try {
  witnessReSummary = JSON.parse(witnessReProc.stdout.trim());
} catch (e) {
  console.error(`[m9-d] witness re-build stdout parse failed: ${e?.message ?? e}`);
}

// ---- Persist PUBLIC withdraw_tree_context side-car for the final-report builder ----------
// Public artifact — readable at 0o644. Contains rootHex, treeTranscriptHash,
// anonymitySetSize, distinctDepositSenders. Strictly NO amount/nullifier/secret/blind here,
// AND (M10-f) no commitmentHex/leafIndex either — see comment on the ctx literal below.
{
  const ctxStateDir = resolve(serviceRoot, ".agent-local/eunoma-v2/coordinator");
  mkdirSync(ctxStateDir, { recursive: true });
  let anonymitySetSize = null;
  let distinctDepositSenders = null;
  let treeTranscriptHashFromTree = null;
  if (commitmentTreeExists) {
    try {
      const snap = JSON.parse(readFileSync(commitmentTreePath, "utf8"));
      anonymitySetSize = snap.leafCount;
      treeTranscriptHashFromTree = snap.transcriptHash;
      const set = new Set();
      for (const m of snap.depositMeta ?? []) {
        if (m.sender) set.add(m.sender.toLowerCase());
      }
      distinctDepositSenders = set.size;
    } catch (e) {
      console.error(`[m9-d] could not read commitment_tree_v2.json for side-car: ${e?.message ?? e}`);
    }
  }
  // M10-f (codex P1 fix): commitmentHex and leafIndex MUST NOT be published. They
  // directly link the spent leaf in the multi-leaf anonymity set to the withdraw,
  // defeating the M9 deposit↔withdraw unlinkability guarantee. Side-car carries
  // only the anonymity-set aggregate (rootHex, anonymitySetSize, distinctDepositSenders,
  // treeTranscriptHash). Schema bumped to v2.
  const ctx = {
    schema: "withdraw_tree_context_v2",
    requestId,
    rootHex,
    treeTranscriptHash: witnessReSummary?.treeTranscriptHash ?? treeTranscriptHashFromTree,
    anonymitySetSize,
    distinctDepositSenders,
    mode: witnessReSummary?.mode ?? witnessMode,
    depositorWitnessSchemaVersion: depositWitness.schema ?? "v2_depositor_witness_v1",
    createdAtUnixMs: Date.now(),
  };
  // Token-substring match (case-insensitive) — rejects suffix/prefix variants
  // like `depositSender`, `secretSeed`, `dkUser`, `nullifierHash`, `merklepath`.
  // The `sender(?!s)` lookahead excludes the legitimate plural in our own
  // `distinctDepositSenders` field (an anonymity-set aggregate, not a leak).
  // Task M10-f Step f.3 lists every name we must reject.
  const FORBIDDEN_SIDECAR = /(amount|secret|nullifier|blind|\bdk|inverse|commitmentHex|leafIndex|merkle|Path|sender(?!s))/i;
  for (const k of Object.keys(ctx)) {
    if (FORBIDDEN_SIDECAR.test(k)) {
      console.error(`[m10-f] FATAL forbidden field in side-car: ${k}`);
      process.exit(34);
    }
  }
  const fname = `withdraw_tree_context_${requestId.replace(/[^A-Za-z0-9_-]/g, "_")}.json`;
  const full = resolve(ctxStateDir, fname);
  const tmp = full + ".tmp";
  writeFileSync(tmp, JSON.stringify(ctx, null, 2) + "\n", { mode: 0o644 });
  renameSync(tmp, full);
  console.error(
    `[m10-f] wrote withdraw_tree_context side-car: ${full} (anonymitySetSize=${ctx.anonymitySetSize}, distinctDepositSenders=${ctx.distinctDepositSenders}) [commitmentHex/leafIndex intentionally omitted]`,
  );
}
const proofOutPath = `/tmp/m8-${requestId}-proof.json`;
const proofProc = spawnSync(
  "node",
  [
    resolve(serviceRoot, "scripts/local_generate_withdraw_proof.mjs"),
    "--witness-json", witnessOutPath,
    "--output", proofOutPath,
  ],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);
if (proofProc.status !== 0) {
  console.error(`proof gen failed: ${proofProc.stderr || proofProc.stdout}`);
  process.exit(33);
}
const proofObj = JSON.parse(readFileSync(proofOutPath, "utf8"));
const proofHex = proofObj.proofHex;
console.error(`[m8-real] Groth16 proof generated (${proofHex.length} hex chars)`);

// ---- 4.5) Override requestHash with the REAL value (derived from final ca_payload_hash) --
// The round1/round2/finalize bodies carried a PLACEHOLDER requestHash (since the real
// value depends on ca_payload_hash which is only known after MPCCA finalize). The
// frost-attest BCS-encoded message + chain call arg must use the REAL value matching the
// Groth16 proof's public input. Otherwise: E_INVALID_WITHDRAW_PROOF on chain.
const witnessJsonFinal = JSON.parse(readFileSync(witnessOutPath, "utf8"));
const realRequestHashHex = `0x${bytesToHex(bigToLE32(BigInt(witnessJsonFinal.request_hash)))}`;
console.error(`[m8-real] real request_hash = ${realRequestHashHex.slice(0, 16)}... (replacing round1 placeholder)`);

function loadDepositorSubmitAccount() {
  if (!existsSync(depositorStatePath)) {
    throw new Error(`depositor state not found at ${depositorStatePath}; cannot submit prepare_withdraw_proof_v2`);
  }
  const state = JSON.parse(readFileSync(depositorStatePath, "utf8"));
  if (typeof state.depositorPrivateKeyHex !== "string" || state.depositorPrivateKeyHex.length === 0) {
    throw new Error(`depositor state at ${depositorStatePath} is missing depositorPrivateKeyHex`);
  }
  const account = Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(state.depositorPrivateKeyHex),
  });
  const expected = addr32(depositWitness.depositorAddress);
  const actual = addr32(account.accountAddress.toString());
  if (expected !== actual) {
    throw new Error(`depositor state address mismatch: state=${actual} witness=${expected}`);
  }
  return account;
}

async function submitPreparedWithdrawProof() {
  const bridgePkg = required(process.env.BRIDGE_PACKAGE_ADDRESS, "env BRIDGE_PACKAGE_ADDRESS");
  const submitter = loadDepositorSubmitAccount();
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  console.error("[a6] building + submitting prepare_withdraw_proof_v2 tx");
  const prepareTx = await aptos.transaction.build.simple({
    sender: submitter.accountAddress,
    data: {
      function: `${bridgePkg}::eunoma_bridge::prepare_withdraw_proof_v2`,
      functionArguments: [
        hexToBytes(rootHex),
        hexToBytes(nullifierHashHex),
        hexToBytes(recipientHashHex),
        hexToBytes(amountTagHex),
        hexToBytes(caPayloadHashFr.startsWith("0x") ? caPayloadHashFr : `0x${caPayloadHashFr}`),
        hexToBytes(realRequestHashHex),
        BigInt(vaultSequenceArg),
        amountP,
        hexToBytes(proofHex),
      ],
    },
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });
  const auth = aptos.transaction.sign({ signer: submitter, transaction: prepareTx });
  const pending = await aptos.transaction.submit.simple({
    transaction: prepareTx,
    senderAuthenticator: auth,
  });
  console.error(`[a6] submitted prepare_withdraw_proof_v2 tx=${pending.hash}; waiting for confirmation...`);
  const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
  if (!committed.success) {
    throw new Error(`prepare_withdraw_proof_v2 failed: ${committed.vm_status}`);
  }
  console.error(`[a6] prepare withdraw SUCCESS tx=${committed.hash} version=${committed.version} gas=${committed.gas_used}`);
  return committed.hash;
}

async function submitPreparedWithdrawPayload() {
  const bridgePkg = required(process.env.BRIDGE_PACKAGE_ADDRESS, "env BRIDGE_PACKAGE_ADDRESS");
  const submitter = loadDepositorSubmitAccount();
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  console.error("[a6] building + submitting prepare_withdraw_payload_v2 tx");
  const prepareTx = await aptos.transaction.build.simple({
    sender: submitter.accountAddress,
    data: {
      function: `${bridgePkg}::eunoma_bridge::prepare_withdraw_payload_v2`,
      functionArguments: [
        `0x${addr32(recipientAddress)}`,
        hexToBytes(caPayloadHashFr.startsWith("0x") ? caPayloadHashFr : `0x${caPayloadHashFr}`),
        hexToBytes(realRequestHashHex),
        hexArrayToBytes(caPayload.newBalanceP),
        hexArrayToBytes(caPayload.newBalanceR),
        hexArrayToBytes(caPayload.newBalanceREffAud),
        hexArrayToBytes(caPayload.amountP),
        hexArrayToBytes(caPayload.amountRSender),
        hexArrayToBytes(caPayload.amountRRecip),
        hexArrayToBytes(caPayload.amountREffAud),
        hexArrayToBytes(caPayload.ekVolunAuds),
        hexNestedArrayToBytes(caPayload.amountRVolunAuds),
        hexToBytes(caPayload.zkrpNewBalance),
        hexToBytes(caPayload.zkrpAmount),
        hexArrayToBytes(caPayload.sigmaProtoComm),
        hexArrayToBytes(caPayload.sigmaProtoResp),
        hexToBytes(caPayload.memo),
      ],
    },
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });
  const auth = aptos.transaction.sign({ signer: submitter, transaction: prepareTx });
  const pending = await aptos.transaction.submit.simple({
    transaction: prepareTx,
    senderAuthenticator: auth,
  });
  console.error(`[a6] submitted prepare_withdraw_payload_v2 tx=${pending.hash}; waiting for confirmation...`);
  const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
  if (!committed.success) {
    throw new Error(`prepare_withdraw_payload_v2 failed: ${committed.vm_status}`);
  }
  console.error(`[a6] prepare payload SUCCESS tx=${committed.hash} version=${committed.version} gas=${committed.gas_used}`);
  return committed.hash;
}
const prepareWithdrawProofTxHash = await submitPreparedWithdrawProof();
const prepareWithdrawPayloadTxHash = await submitPreparedWithdrawPayload();

async function submitPreparedWithdrawAttestation(groupSignatureHex) {
  if (typeof groupSignatureHex !== "string" || hexToBytes(groupSignatureHex).length === 0) {
    throw new Error("frost-attest response missing non-empty groupSignature");
  }
  const bridgePkg = required(process.env.BRIDGE_PACKAGE_ADDRESS, "env BRIDGE_PACKAGE_ADDRESS");
  const submitter = loadDepositorSubmitAccount();
  const aptos = new Aptos(new AptosConfig({ network: Network.TESTNET }));
  console.error("[a6] building + submitting prepare_withdraw_attestation_v2 tx");
  const prepareTx = await aptos.transaction.build.simple({
    sender: submitter.accountAddress,
    data: {
      function: `${bridgePkg}::eunoma_bridge::prepare_withdraw_attestation_v2`,
      functionArguments: [
        hexToBytes(rootHex),
        hexToBytes(nullifierHashHex),
        `0x${addr32(recipientAddress)}`,
        hexToBytes(recipientHashHex),
        hexToBytes(amountTagHex),
        hexToBytes(caPayloadHashFr.startsWith("0x") ? caPayloadHashFr : `0x${caPayloadHashFr}`),
        hexToBytes(realRequestHashHex),
        BigInt(vaultSequenceArg),
        BigInt(expirySecs),
        hexToBytes(groupSignatureHex),
        0,
        [],
      ],
    },
    options: { maxGasAmount: 500_000, gasUnitPrice: 100 },
  });
  const auth = aptos.transaction.sign({ signer: submitter, transaction: prepareTx });
  const pending = await aptos.transaction.submit.simple({
    transaction: prepareTx,
    senderAuthenticator: auth,
  });
  console.error(`[a6] submitted prepare_withdraw_attestation_v2 tx=${pending.hash}; waiting for confirmation...`);
  const committed = await aptos.waitForTransaction({ transactionHash: pending.hash });
  if (!committed.success) {
    throw new Error(`prepare_withdraw_attestation_v2 failed: ${committed.vm_status}`);
  }
  console.error(`[a6] prepare attestation SUCCESS tx=${committed.hash} version=${committed.version} gas=${committed.gas_used}`);
  return committed.hash;
}

// M8-r: derive circuit_versions_hash from chain DeoperatorConfigV2 (keccak256(BCS(CircuitVersionsForHash{deposit,withdraw,ca_payload}))).
// Falling back to an env var leaves frost-attest message diverged from chain and triggers E_INVALID_DEOP_SIGNATURE.
async function fetchCircuitVersionsHash() {
  const bridgePkg = required(process.env.BRIDGE_PACKAGE_ADDRESS, "env BRIDGE_PACKAGE_ADDRESS");
  const resourceType = `${bridgePkg}::eunoma_bridge::DeoperatorConfigV2`;
  const url = `${APTOS_NODE_URL}/v1/accounts/${bridgePkg}/resource/${resourceType}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`fetch DeoperatorConfigV2: ${res.status} ${await res.text()}`);
  const json = await res.json();
  const dep = hexToBytes(normalizeHex(json.data.deposit_circuit_version));
  const wid = hexToBytes(normalizeHex(json.data.withdraw_circuit_version));
  const cap = hexToBytes(normalizeHex(json.data.ca_payload_circuit_version));
  function uleb(n) {
    const out = [];
    while (n >= 0x80) { out.push((n & 0x7f) | 0x80); n = n >>> 7; }
    out.push(n);
    return new Uint8Array(out);
  }
  const bcs = Buffer.concat([uleb(dep.length), dep, uleb(wid.length), wid, uleb(cap.length), cap]);
  const { keccak_256 } = await import("@noble/hashes/sha3");
  return `0x${Buffer.from(keccak_256(bcs)).toString("hex")}`;
}
const derivedCircuitVersionsHash = await fetchCircuitVersionsHash();
console.error(`[m8-r] circuit_versions_hash (chain-derived) = ${derivedCircuitVersionsHash}`);

// ---- 5) frost-attest ----------------------------------------------------------------------
const frostAttestBody = {
  ...finalizeBody,
  requestHash: normalizeHex(realRequestHashHex),
  attestationConfig: {
    bridge: process.env.BRIDGE_PACKAGE_ADDRESS,
    vault: vaultAddress,
    operatorSetVersion: caDkgRoster.operatorSetVersion,
    frostGroupPubkey: frostRoster.frostGroupPubkey,
    circuitVersionsHash: process.env.EUNOMA_TESTNET_CIRCUIT_VERSIONS_HASH ?? derivedCircuitVersionsHash,
  },
  // A6 testnet split: Groth16 was verified and cached by prepare_withdraw_proof_v2.
  // Final withdraw passes an empty proof and Move consumes the exact pending public tuple.
  withdrawProofHex: "0x",
  memoHex: "",
};
console.error(`[m8-real] POST /v2/withdraw/mpcca/frost-attest`);
r = await post("/v2/withdraw/mpcca/frost-attest", frostAttestBody);
console.error(`[m8-real] frost-attest → HTTP ${r.status}`);
if (r.status !== 200) {
  console.error(JSON.stringify(r.body, null, 2));
  process.exit(34);
}
const prepareWithdrawAttestationTxHash = await submitPreparedWithdrawAttestation(r.body?.groupSignature);

// ---- 6) submit ----------------------------------------------------------------------------
console.error(`[m8-real] POST /v2/withdraw/mpcca/submit`);
r = await post("/v2/withdraw/mpcca/submit", {
  dkgEpoch: dkgEpochStr,
  requestId,
  preparedWithdrawAttestation: true,
});
console.error(`[m8-real] submit → HTTP ${r.status}`);

// ---- M11: post-submit vault-state resync --------------------------------------------------
// After a chain-confirmed WithdrawEventV2, advance every worker's vault_sequence so the NEXT
// withdraw's round1 doesn't trip stale_vault_sequence. In production this may warn (chain is
// authoritative; the next run's pre-round1 catch-up heals stragglers); under
// EUNOMA_E2E_REQUIRE_RESYNC=1 (release verification) a sub-threshold result is a HARD failure —
// otherwise "consecutive-withdraw safety" is not actually proven.
const requireResync = process.env.EUNOMA_E2E_REQUIRE_RESYNC === "1";
let resyncAfterSummary = null;
if (r.status >= 200 && r.status < 300) {
  try {
    const newTxHash =
      r.body?.txHash ?? r.body?.chainConfirmedWithdraw ?? r.body?.relayerSubmit ?? r.body?.responseBody?.txHash;
    if (!newTxHash) throw new Error("submit response missing txHash");
    const binding = await fetchWithdrawEventBindingByTxHash(newTxHash);
    if (!binding.success) throw new Error(`submit tx ${newTxHash} not successful on chain`);
    const body = buildResyncBody({
      dkgEpoch: dkgEpochStr, requestId, txHash: binding.txHash,
      bridgePackage: BRIDGE_PACKAGE_ADDRESS, vault: addr32(vaultAddress), assetType: addr32(assetType),
      binding, trigger: "after_withdraw",
    });
    const resp = await post("/v2/vault/resync_after_withdraw", body);
    const okSlots = resp.body?.summary?.okSlots ?? [];
    resyncAfterSummary = { httpStatus: resp.status, okSlots, summary: resp.body?.summary ?? null };
    console.error(`[m11] resync_after_withdraw: HTTP ${resp.status} okSlots=[${okSlots.join(",")}]`);
    const subThreshold = resp.status !== 200 || okSlots.length < RESYNC_THRESHOLD;
    if (subThreshold && requireResync) {
      console.error(`[m11] FATAL resync_after_withdraw_subthreshold (EUNOMA_E2E_REQUIRE_RESYNC=1): ${JSON.stringify(resp.body?.summary ?? resp.body)}`);
      process.exit(39);
    } else if (subThreshold) {
      console.error(`[m11] WARN resync_after_withdraw below threshold (production: chain authoritative; next run's pre-round1 catch-up heals)`);
    }
  } catch (err) {
    if (requireResync) {
      console.error(`[m11] FATAL resync_after_withdraw error (EUNOMA_E2E_REQUIRE_RESYNC=1): ${err?.message ?? err}`);
      process.exit(39);
    }
    console.error(`[m11] WARN resync_after_withdraw error (production: chain authoritative): ${err?.message ?? err}`);
  }
}
// M10-l (codex iter-4 P1-8): the final submit summary previously emitted
// `amountOctas` unconditionally — the iter-2/3 plaintext gating only
// covered the --check-balance-only path. CI / process supervisors capture
// stdout, so a non-interactive operator run would persist the plaintext
// withdrawal amount. Gate plaintext fields behind the same
// EUNOMA_LOCAL_DEBUG_BALANCE=1 env. Default emits the binding identifiers
// (requestId, recipientAddress, caPayloadHashFr — all already public on
// chain via the withdraw tx) and the proof hex (a Groth16 SNARK that
// reveals nothing about the witness).
const debugBalanceSubmit = process.env.EUNOMA_LOCAL_DEBUG_BALANCE === "1";
const submitSummary = {
  ok: r.status >= 200 && r.status < 300,
  httpStatus: r.status,
  requestId,
  recipientAddress,
  caPayloadHashFr,
  proofHex,
  prepareWithdrawPayloadTxHash,
  prepareWithdrawProofTxHash,
  prepareWithdrawAttestationTxHash,
  responseBody: r.body,
  resyncAfterWithdraw: resyncAfterSummary,
};
if (debugBalanceSubmit) {
  submitSummary.amountOctas = TRANSFER_AMOUNT_OCTAS.toString();
}
process.stdout.write(JSON.stringify(submitSummary, null, 2) + "\n");
process.exit(r.status >= 200 && r.status < 300 ? 0 : 35);
