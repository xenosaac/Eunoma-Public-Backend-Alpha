#!/usr/bin/env node
// =============================================================================================
// V2 withdraw — round1 smoke driver (M8 Task 5, phase 1).
//
// Drives POST /v2/withdraw/mpcca/start against the live coordinator with REAL cryptographic
// inputs:
//   - amountCommitment + perShareCommitments[5] = Pedersen commitments over Ristretto
//     (commitment = a·G + b·H_RISTRETTO; same formula the workers verify).
//   - α_shares[5] split such that Σ α_share_j = α[0] (the user-side α scalar that the
//     workers cooperatively complete in round2/finalize).
//   - ingressEnvelopes[5] = HPKE seals via the eunoma-crypto-worker `hpke_seal_ingress` Rust
//     binary, byte-identical to what the workers' run_round1_v2 will accept on decryption.
//
// This script focuses ONLY on round1. If it succeeds (HTTP 200 + ingressTranscriptHash for all
// 5 slots), the next phase (round2 → finalize → frost-attest → submit) can build on top.
//
// Inputs (env + args):
//   COORDINATOR_URL                    default http://127.0.0.1:4200
//   COORDINATOR_BEARER_TOKEN           required
//   CA_DKG_V2_ROSTER_JSON_PATH         required — path to .agent-local/eunoma-v2/cluster/ca-dkg-v2-roster.json
//   --deposit-witness PATH             required — v2_depositor_witness_v1 JSON
//   --recipient HEX                    optional — defaults to depositorAddress (self-withdraw)
//   --vault-address HEX                required — 0x554cd5... (bridge vault resource)
//   --vault-ek HEX                     required — bridge vault EK from chain
//   --root HEX                         required — depth-20 Merkle root containing the deposit commitment
//   --vault-sequence N                 required — u64 from BridgeVault.vault_sequence
//   --asset-id-fr HEX                  required — VaultPublicInputsV2.asset_id_fr (LE Fr)
//   --vault-addr-hash-fr HEX           required — VaultPublicInputsV2.vault_addr_hash_fr (LE Fr)
//   --request-id ID                    optional, auto-generated
//   --expiry-secs N                    optional, default = now + 3600
//   --withdraw-blind HEX               optional, auto-generated
//
// Output: JSON with request body summary + coordinator response.
// Exit codes: 0 success, 1 generic failure, 2 usage, 30 coordinator non-2xx.
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";

import { RistrettoPoint, H_RISTRETTO } from "@aptos-labs/confidential-asset";
import { ed25519 } from "@noble/curves/ed25519";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

const HPKE_SEAL_BIN = resolve(
  serviceRoot,
  "crypto-worker-rust/target/release/hpke_seal_ingress",
);

// ----------- helpers -----------------------------------------------------------------
function bytesToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const norm = hex.replace(/^0x/i, "");
  if (norm.length % 2) throw new Error("odd hex length");
  const out = new Uint8Array(norm.length / 2);
  for (let i = 0; i < norm.length; i += 2) out[i / 2] = parseInt(norm.slice(i, i + 2), 16);
  return out;
}
function normalizeHex(hex) {
  return hex.replace(/^0x/i, "").toLowerCase();
}
function addr32Pad(hex) {
  const n = normalizeHex(hex);
  return n.padStart(64, "0");
}

const ED_N = ed25519.CURVE.n;
function modN(x) {
  return ((x % ED_N) + ED_N) % ED_N;
}
function bytesToBigIntLE(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}
function bigIntToBytesLE(v, len) {
  const out = new Uint8Array(len);
  let r = v;
  for (let i = 0; i < len; i += 1) {
    out[i] = Number(r & 0xffn);
    r >>= 8n;
  }
  return out;
}
function randScalar() {
  // Ed25519 canonical scalar < n. Use rejection sampling with bias-free reduction.
  while (true) {
    const buf = randomBytes(32);
    buf[31] &= 0x7f; // top bit clear
    const v = bytesToBigIntLE(buf);
    if (v < ED_N && v !== 0n) return v;
  }
}

function pedersenCommit(a, b) {
  // commitment = a·G + b·H (Ristretto). G = RistrettoPoint.BASE.
  const aBytes = bigIntToBytesLE(modN(a), 32);
  const bBytes = bigIntToBytesLE(modN(b), 32);
  const aG = RistrettoPoint.BASE.multiply(modN(a));
  const bH = H_RISTRETTO.multiply(modN(b));
  return aG.add(bH);
}

function ristrettoCompressed(point) {
  return bytesToHex(point.toRawBytes());
}

function perShareCommitmentsHashHex(perShareCommitmentsHex) {
  // Match Rust `per_share_commitments_hash_hex`: sha256 over concat of UTF-8-encoded hex
  // strings (normalized lowercase, no 0x prefix).
  const hasher = createHash("sha256");
  const enc = new TextEncoder();
  for (const c of perShareCommitmentsHex) hasher.update(enc.encode(normalizeHex(c)));
  return hasher.digest("hex");
}

function canonicalJsonStringify(obj) {
  // Match Rust `m1_ingress_aad`: sorted keys, no whitespace, JSON strings.
  const keys = Object.keys(obj).sort();
  const parts = [];
  for (const k of keys) parts.push(JSON.stringify(k) + ":" + JSON.stringify(obj[k]));
  return "{" + parts.join(",") + "}";
}

function m1IngressAad({
  requestId,
  sessionId,
  dkgEpoch,
  selfSlot,
  playerId,
  rosterHash,
  vaultEk,
  root,
  nullifierHash,
  recipientHash,
  amountTag,
  vaultSequence,
  depositCount,
  amountCommitment,
  perShareCommitments,
}) {
  const aad = {
    amountCommitmentHex: normalizeHex(amountCommitment),
    amountTag: normalizeHex(amountTag),
    depositCount: String(depositCount),
    dkgEpoch: String(dkgEpoch),
    domain: "EUNOMA_M1_AMOUNT_INGRESS_V1",
    nullifierHash: normalizeHex(nullifierHash),
    perShareCommitmentsHashHex: perShareCommitmentsHashHex(perShareCommitments),
    playerId: String(playerId),
    recipientHash: normalizeHex(recipientHash),
    requestId: String(requestId),
    root: normalizeHex(root),
    rosterHash: normalizeHex(rosterHash),
    selfSlot: String(selfSlot),
    sessionId: String(sessionId),
    vaultEk: normalizeHex(vaultEk),
    vaultSequence: String(vaultSequence),
  };
  return new TextEncoder().encode(canonicalJsonStringify(aad));
}

function hpkeSealIngress(recipientPubKeyHex, aadBytes, plaintextBytes) {
  if (!existsSync(HPKE_SEAL_BIN)) {
    throw new Error(
      `hpke_seal_ingress binary not found at ${HPKE_SEAL_BIN}. ` +
        "Build it: cd crypto-worker-rust && cargo build --release --bin hpke_seal_ingress",
    );
  }
  const req = {
    recipientPubKeyHex: normalizeHex(recipientPubKeyHex),
    aadHex: bytesToHex(aadBytes),
    plaintextHex: bytesToHex(plaintextBytes),
  };
  const r = spawnSync(HPKE_SEAL_BIN, [], {
    input: JSON.stringify(req),
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  });
  if (r.status !== 0) {
    throw new Error(
      `hpke_seal_ingress exit=${r.status}: ${r.stderr || r.stdout || "no output"}`,
    );
  }
  return JSON.parse(r.stdout.trim());
}

// ----------- args + env --------------------------------------------------------------
const args = process.argv.slice(2);
function flag(name, def) {
  const i = args.indexOf(name);
  if (i < 0) return def;
  return args[i + 1];
}
function required(value, name) {
  if (!value) {
    console.error(`required: ${name}`);
    process.exit(2);
  }
  return value;
}

const COORDINATOR_URL = process.env.COORDINATOR_URL ?? "http://127.0.0.1:4200";
const COORDINATOR_BEARER_TOKEN = required(
  process.env.COORDINATOR_BEARER_TOKEN,
  "env COORDINATOR_BEARER_TOKEN",
);
const CA_DKG_V2_ROSTER_JSON_PATH = required(
  process.env.CA_DKG_V2_ROSTER_JSON_PATH,
  "env CA_DKG_V2_ROSTER_JSON_PATH",
);

const depositWitnessPath = required(flag("--deposit-witness"), "--deposit-witness");
const vaultAddress = required(flag("--vault-address"), "--vault-address");
const vaultEk = required(flag("--vault-ek"), "--vault-ek");
const rootHex = required(flag("--root"), "--root");
const vaultSequenceArg = required(flag("--vault-sequence"), "--vault-sequence");
const assetIdFr = required(flag("--asset-id-fr"), "--asset-id-fr");
const vaultAddrHashFr = required(flag("--vault-addr-hash-fr"), "--vault-addr-hash-fr");
const requestId = flag("--request-id", `m8-r1-${Date.now()}`);
const expirySecs = Number.parseInt(
  flag("--expiry-secs", String(Math.floor(Date.now() / 1000) + 3600)),
  10,
);
const withdrawBlindArg = flag("--withdraw-blind");

const depositWitness = JSON.parse(readFileSync(depositWitnessPath, "utf8"));
if (depositWitness.schema !== "v2_depositor_witness_v1") {
  console.error(`unexpected schema: ${depositWitness.schema}`);
  process.exit(2);
}

const recipientArg = flag("--recipient", depositWitness.depositorAddress);

const roster = JSON.parse(readFileSync(CA_DKG_V2_ROSTER_JSON_PATH, "utf8"));
if (roster.caDkgScheme !== "ca_dkg_v2") {
  console.error(`expected caDkgScheme=ca_dkg_v2; got ${roster.caDkgScheme}`);
  process.exit(2);
}
const rosterHash = roster.caDkgV2RosterHash ?? roster.rosterHash;
if (!rosterHash) {
  console.error(
    `roster JSON missing caDkgV2RosterHash; regenerate via npm run local:cluster:config`,
  );
  process.exit(2);
}

const selectedSlots = [0, 1, 2, 3, 4];
const nodeMap = new Map(roster.nodes.map((n) => [Number(n.slot), n]));
for (const s of selectedSlots) {
  if (!nodeMap.has(s)) {
    console.error(`roster missing slot ${s}`);
    process.exit(2);
  }
}

// ----------- compute withdraw witness publics (nullifier_hash, amount_tag, recipient_hash) -----
// Spawn compute_withdraw_witness as a subprocess to get nullifier_hash, amount_tag, recipient_hash
// (and validate against the depositor witness in one shot). We need these BEFORE round1 because
// they go into the m1IngressAad binding.
const witnessOutPath = `/tmp/m8-r1-witness-${requestId}.json`;
const witnessProc = spawnSync(
  "node",
  [
    resolve(repoRoot, "circuits/scripts/compute_withdraw_witness.mjs"),
    "--depositor-witness",
    depositWitnessPath,
    "--recipient",
    recipientArg,
    "--vault-sequence",
    vaultSequenceArg,
    "--root",
    rootHex,
    "--ca-payload-hash",
    // We don't know the final ca_payload_hash yet (it's set after MPCCA finalize). Round1's
    // AAD doesn't bind ca_payload_hash; we use a placeholder for the witness compute but the
    // values that go into AAD (nullifier_hash, amount_tag, recipient_hash, root, vault_sequence)
    // don't depend on ca_payload_hash.
    `0x${"00".repeat(32)}`,
    ...(withdrawBlindArg ? ["--withdraw-blind-hex", withdrawBlindArg] : []),
    "--output",
    witnessOutPath,
  ],
  { encoding: "utf8", maxBuffer: 10 * 1024 * 1024 },
);
if (witnessProc.status !== 0) {
  console.error(`compute_withdraw_witness failed: ${witnessProc.stderr || witnessProc.stdout}`);
  process.exit(1);
}
// compute_withdraw_witness emits a single multi-line JSON object to stdout.
const witnessSummary = JSON.parse(witnessProc.stdout.trim());
const witnessJson = JSON.parse(readFileSync(witnessOutPath, "utf8"));

const nullifierHashHex = "0x" + bigIntToBytesLE(BigInt(witnessJson.nullifier_hash), 32).reduce((acc, b) => acc + b.toString(16).padStart(2, "0"), "");
const recipientHashHex = "0x" + bigIntToBytesLE(BigInt(witnessJson.recipient_hash), 32).reduce((acc, b) => acc + b.toString(16).padStart(2, "0"), "");
const amountTagHex = "0x" + bigIntToBytesLE(BigInt(witnessJson.amount_tag), 32).reduce((acc, b) => acc + b.toString(16).padStart(2, "0"), "");
const withdrawBlindUsed = witnessSummary.withdraw_blind_hex;

console.error(`[round1] computed nullifierHash=${nullifierHashHex.slice(0, 16)}... amountTag=${amountTagHex.slice(0, 16)}... recipientHash=${recipientHashHex.slice(0, 16)}...`);

// ----------- α[0] split into 5 shares + blinds + Pedersen commitments + amountCommitment -----
const amountOctas = BigInt(depositWitness.amountOctas);
const depositCount = Number(depositWitness.depositCount);

// α[0] arbitrary random scalar; workers will use it via the threshold response s[0] = α[0] + e·dk_real.
const alphaZero = randScalar();
const alphaShares = [];
let sumSoFar = 0n;
for (let j = 0; j < 4; j += 1) {
  const s = randScalar();
  alphaShares.push(s);
  sumSoFar = modN(sumSoFar + s);
}
alphaShares.push(modN(alphaZero - sumSoFar));
const sumCheck = alphaShares.reduce((a, b) => modN(a + b), 0n);
if (sumCheck !== alphaZero) throw new Error("alpha_share sum check failed");

const blinds = alphaShares.map(() => randScalar());

const perShareCommitments = alphaShares.map((a, j) =>
  ristrettoCompressed(pedersenCommit(a, blinds[j])),
);
console.error(`[round1] per-share commits: ${perShareCommitments.map((h) => h.slice(0, 12)).join(", ")}`);

// amountCommitment = Σ perShareCommitments = (Σ α_share_j)·G + (Σ b_j)·H = α[0]·G + B·H
// where B = Σ blinds[j]. The workers' ingress aggregate-check enforces this sum-binding so
// no party (incl. coordinator) can substitute a different α[0] post-ingress. amountOctas is
// NOT in the M1 ingress — it enters via the CA TransferV1 σ proof at round2/finalize.
const blindSum = blinds.reduce((acc, b) => modN(acc + b), 0n);
const amountCommitmentHex = ristrettoCompressed(pedersenCommit(alphaZero, blindSum));
console.error(`[round1] amountCommitment=${amountCommitmentHex.slice(0, 16)}... (= Σ perShareCommitments)`);
// Sanity: recompute Σ perShareCommitments client-side and assert equality.
const sumPoint = perShareCommitments
  .map((h) => RistrettoPoint.fromHex(hexToBytes(h)))
  .reduce((acc, p, i) => (i === 0 ? p : acc.add(p)));
if (ristrettoCompressed(sumPoint) !== amountCommitmentHex) {
  throw new Error(
    `[round1] internal: amountCommitment != Σ perShareCommitments (client-side sanity check)`,
  );
}

// ----------- build ingress envelopes (HPKE-seal under each worker's HPKE pubkey) -----
const sessionId = requestId; // Same as requestId per protocol convention.
const ingressEnvelopes = [];
for (let i = 0; i < selectedSlots.length; i += 1) {
  const slot = selectedSlots[i];
  const node = nodeMap.get(slot);
  const playerId = i; // 0..4 per the selectedSlots ordering
  const aadBytes = m1IngressAad({
    requestId,
    sessionId,
    dkgEpoch: roster.dkgEpoch,
    selfSlot: slot,
    playerId,
    rosterHash,
    vaultEk,
    root: rootHex,
    nullifierHash: nullifierHashHex,
    recipientHash: recipientHashHex,
    amountTag: amountTagHex,
    vaultSequence: Number(vaultSequenceArg),
    depositCount,
    amountCommitment: amountCommitmentHex,
    perShareCommitments,
  });

  // Plaintext: a (α_share_j) || b (blind_j) — 64 bytes total.
  const plaintext = new Uint8Array(64);
  plaintext.set(bigIntToBytesLE(alphaShares[i], 32), 0);
  plaintext.set(bigIntToBytesLE(blinds[i], 32), 32);

  const env = hpkeSealIngress(node.hpkePublicKey, aadBytes, plaintext);
  ingressEnvelopes.push(env);
  console.error(`[round1] sealed envelope[${i}] for slot ${slot} (enc=${env.enc.slice(0, 12)}...)`);
}

// ----------- compute requestHash placeholder (not bound at round1) ---------------------
// The chain enforces request_hash via Groth16 proof + FROST attest, both of which use the
// FINAL request_hash computed after MPCCA finalize. Round1 doesn't verify it.
const placeholderHasher = createHash("sha256");
placeholderHasher.update("EUNOMA_PLACEHOLDER_REQUEST_HASH_V1");
const placeholderRequestHashHex = "0x" + placeholderHasher.digest("hex");

// ----------- build round1 body --------------------------------------------------------
const caDkgTranscriptHash =
  process.env.EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH ??
  depositWitness.caDkgTranscriptHash ??
  flag("--ca-dkg-transcript-hash");
if (!caDkgTranscriptHash) {
  console.error(
    "caDkgTranscriptHash required — set EUNOMA_TESTNET_CA_DKG_TRANSCRIPT_HASH or --ca-dkg-transcript-hash",
  );
  process.exit(2);
}
const body = {
  dkgEpoch: roster.dkgEpoch,
  caDkgTranscriptHash: normalizeHex(caDkgTranscriptHash),
  vaultEk: normalizeHex(vaultEk),
  senderAddress: normalizeHex(addr32Pad(vaultAddress)), // CA sender = bridge vault
  assetType: normalizeHex(addr32Pad(depositWitness.assetType)),
  chainId: depositWitness.chainId,
  root: normalizeHex(rootHex),
  nullifierHash: normalizeHex(nullifierHashHex),
  recipient: normalizeHex(addr32Pad(recipientArg)),
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
console.error(`[round1] POST /v2/withdraw/mpcca/start (requestId=${requestId}, bodyKeys=${Object.keys(body).length})`);

const res = await fetch(new URL("/v2/withdraw/mpcca/start", COORDINATOR_URL), {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${COORDINATOR_BEARER_TOKEN}`,
  },
  body: JSON.stringify(body),
});
const responseBody = await res.json().catch(() => ({}));
console.error(`[round1] HTTP ${res.status}`);

const result = {
  ok: res.status >= 200 && res.status < 300,
  httpStatus: res.status,
  requestId,
  selectedSlots,
  alphaZeroHex: "0x" + bigIntToBytesLE(alphaZero, 32).reduce((acc, b) => acc + b.toString(16).padStart(2, "0"), ""),
  amountCommitmentHex,
  perShareCommitments,
  publics: {
    nullifierHash: nullifierHashHex,
    recipientHash: recipientHashHex,
    amountTag: amountTagHex,
    root: rootHex,
    vaultSequence: Number(vaultSequenceArg),
  },
  withdrawBlindHex: withdrawBlindUsed,
  responseBody,
};
process.stdout.write(JSON.stringify(result, null, 2) + "\n");
if (!result.ok) process.exit(30);
process.exit(0);
