#!/usr/bin/env node
// Operator-driven script that rolls the Eunoma bridge singleton to a fresh vault resource
// account via `rollover_vault_with_ca_registration_v2` (Move). It consumes the V2 CA
// registration transcript for the *new* vault address, validates it off-chain via the
// Aptos CA SDK's verifyRegistration, and submits the entry under operator approval.
//
// Tested against Aptos CLI 3.5+. Env vars required:
//   APTOS_NODE_URL          e.g. https://fullnode.testnet.aptoslabs.com/v1
//   BRIDGE_PACKAGE_ADDRESS  the eunoma_bridge module address on chain
//   ADMIN_PROFILE           aptos CLI profile with the admin signer (required for --submit)
//   RELAYER_SUBMIT_ENABLED  must be "1" for --submit to actually broadcast
//
// Inputs:
//   --ca-registration-artifact <path>  Coordinator-persisted ca_registration_v2 artifact JSON
//                                       (contains vaultEk, aggregateCommitment, aggregateResponse,
//                                       challenge, transcriptHash, rosterHash, dkgEpoch,
//                                       senderAddress, assetType, chainId).
//   --snapshot <path>                  Operator snapshot of immutable on-chain config fields:
//                                       { operatorSetVersion, dkgEpoch, vaultEk, vaultSeed,
//                                         assetType, depositCircuitVersion,
//                                         withdrawCircuitVersion, caPayloadCircuitVersion,
//                                         fallbackPubkeys[7] }.
//   --roster <path>                    Full CA DKG V2 roster JSON (cluster/dkg-roster.json).
//                                       Used for rosterHash verification.
//   --frost-roster <path>              FROST DKG V2 roster JSON (cluster/frost-roster.json).
//                                       Provides frost_group_pubkey.
//
// CLI:
//   testnet_vault_rollover.mjs --ca-registration-artifact <p> --snapshot <p> --roster <p> \
//     --frost-roster <p> [--submit]
//
// Default mode is --simulate. Submission gated by both --submit AND RELAYER_SUBMIT_ENABLED=1.
//
// Exit codes:
//   0   success
//   2   usage / missing-arg
//   3   aptos CLI spawn failure
//   4   could not parse tx hash from submit output
//   5   submit confirmed but reverted (vm_status != Executed successfully)
//   6   submit confirmed but post-chain state diverged from local expectation
//   10  STALE_ARTIFACT_VAULT_EK_MISMATCH (artifact.vaultEk != snapshot.vaultEk)
//   11  STALE_ARTIFACT_DKG_EPOCH_MISMATCH
//   12  STALE_ARTIFACT_ROSTER_HASH_MISMATCH
//   13  STALE_FROST_ROSTER_DKG_EPOCH_MISMATCH
//   14  VAULT_NOT_INITIALIZED (chain has no BridgeVault to roll over)
//   15  REGISTRATION_PROOF_REJECTED (Aptos SDK verifyRegistration returned false)
//   16  INVALID_FALLBACK_PUBKEYS (count != 7 or not 32-byte hex)
//   17  AGGREGATE_COMMITMENT_RESPONSE_SHAPE (not 32-byte hex)
//   18  VAULT_ADDRESS_MISMATCH (snapshot.vaultSeed does not derive artifact.senderAddress)
//   19  VAULT_TABLES_ALREADY_INITIALIZED (fresh table resource already exists)
//   20  ASSET_TYPE_MISMATCH (artifact.assetType != snapshot.assetType)

import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  TwistedEd25519PrivateKey,
  verifyRegistration,
} from "@aptos-labs/confidential-asset";
import { AccountAddress, createResourceAddress } from "@aptos-labs/ts-sdk";
import { caDkgV2RosterHash, frostDkgV2RosterHash } from "@eunoma/deop-protocol";
import { hexArg, hexVectorArg, u64Arg } from "./_lib/format_aptos_args.mjs";

const EXIT_USAGE = 2;
const EXIT_APTOS_SPAWN = 3;
const EXIT_TX_HASH_PARSE = 4;
const EXIT_TX_REVERTED = 5;
const EXIT_CHAIN_STATE_DIVERGED = 6;
const EXIT_ARTIFACT_VAULT_EK_MISMATCH = 10;
const EXIT_ARTIFACT_DKG_EPOCH_MISMATCH = 11;
const EXIT_ARTIFACT_ROSTER_HASH_MISMATCH = 12;
const EXIT_FROST_DKG_EPOCH_MISMATCH = 13;
const EXIT_VAULT_NOT_INITIALIZED = 14;
const EXIT_REGISTRATION_PROOF_REJECTED = 15;
const EXIT_INVALID_FALLBACK_PUBKEYS = 16;
const EXIT_AGGREGATE_SHAPE = 17;
const EXIT_VAULT_ADDRESS_MISMATCH = 18;
const EXIT_VAULT_TABLES_ALREADY_INITIALIZED = 19;
const EXIT_ASSET_TYPE_MISMATCH = 20;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let artifactPath = null;
let snapshotPath = null;
let rosterPath = null;
let frostRosterPath = null;
let submit = false;
let outputPath = null;
for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === "--ca-registration-artifact") {
    artifactPath = args[i + 1];
    i += 1;
  } else if (arg === "--snapshot") {
    snapshotPath = args[i + 1];
    i += 1;
  } else if (arg === "--roster") {
    rosterPath = args[i + 1];
    i += 1;
  } else if (arg === "--frost-roster") {
    frostRosterPath = args[i + 1];
    i += 1;
  } else if (arg === "--submit") {
    submit = true;
  } else if (arg === "--output") {
    outputPath = args[i + 1];
    i += 1;
  } else {
    console.error(`unknown arg: ${arg}`);
    process.exit(EXIT_USAGE);
  }
}
if (!artifactPath || !snapshotPath || !rosterPath || !frostRosterPath) {
  console.error(
    "usage: testnet_vault_rollover.mjs --ca-registration-artifact <path> --snapshot <path> --roster <path> --frost-roster <path> [--submit] [--output <path>]",
  );
  process.exit(EXIT_USAGE);
}

const aptosNodeUrl = process.env.APTOS_NODE_URL;
const bridgePackage = process.env.BRIDGE_PACKAGE_ADDRESS;
const adminProfile = process.env.ADMIN_PROFILE;
const relayerSubmitEnabled = process.env.RELAYER_SUBMIT_ENABLED === "1";
if (!aptosNodeUrl) {
  console.error("APTOS_NODE_URL is required");
  process.exit(EXIT_USAGE);
}
if (!bridgePackage) {
  console.error("BRIDGE_PACKAGE_ADDRESS is required");
  process.exit(EXIT_USAGE);
}
if (submit && !adminProfile) {
  console.error("ADMIN_PROFILE is required for --submit");
  process.exit(EXIT_USAGE);
}
if (submit && !relayerSubmitEnabled) {
  console.error(
    "--submit requires RELAYER_SUBMIT_ENABLED=1 in env to actually broadcast (defense-in-depth gate)",
  );
  process.exit(EXIT_USAGE);
}

const artifact = parseJsonFile(artifactPath, "ca-registration-artifact");
const snapshot = parseJsonFile(snapshotPath, "snapshot");
const dkgRoster = parseJsonFile(rosterPath, "roster");
const frostRoster = parseJsonFile(frostRosterPath, "frost-roster");

assertSnapshotShape(snapshot);
assertCaRegistrationArtifactShape(artifact);

const expectedVaultAddress = deriveResourceAddress(bridgePackage, snapshot.vaultSeed);
if (normalizeHex(artifact.senderAddress) !== normalizeHex(expectedVaultAddress)) {
  console.error(
    `VAULT_ADDRESS_MISMATCH: artifact.senderAddress=${artifact.senderAddress} expected=${expectedVaultAddress} from snapshot.vaultSeed`,
  );
  process.exit(EXIT_VAULT_ADDRESS_MISMATCH);
}
if (
  snapshot.vaultAddress !== undefined &&
  normalizeHex(snapshot.vaultAddress) !== normalizeHex(expectedVaultAddress)
) {
  console.error(
    `VAULT_ADDRESS_MISMATCH: snapshot.vaultAddress=${snapshot.vaultAddress} expected=${expectedVaultAddress} from snapshot.vaultSeed`,
  );
  process.exit(EXIT_VAULT_ADDRESS_MISMATCH);
}
console.log(`pre-flight: vaultSeed derives new vault address ${expectedVaultAddress}`);
if (normalizeHex(artifact.assetType) !== normalizeHex(snapshot.assetType)) {
  console.error(
    `ASSET_TYPE_MISMATCH: artifact.assetType=${artifact.assetType} snapshot.assetType=${snapshot.assetType}`,
  );
  process.exit(EXIT_ASSET_TYPE_MISMATCH);
}

// Pre-flight 1: artifact.vaultEk must match snapshot.vaultEk.
if (normalizeHex(artifact.vaultEk) !== normalizeHex(snapshot.vaultEk)) {
  console.error(
    `STALE_ARTIFACT_VAULT_EK_MISMATCH: artifact.vaultEk=${artifact.vaultEk} snapshot.vaultEk=${snapshot.vaultEk}`,
  );
  process.exit(EXIT_ARTIFACT_VAULT_EK_MISMATCH);
}

// Pre-flight 2: artifact.dkgEpoch must match snapshot.dkgEpoch.
if (String(artifact.dkgEpoch) !== String(snapshot.dkgEpoch)) {
  console.error(
    `STALE_ARTIFACT_DKG_EPOCH_MISMATCH: artifact.dkgEpoch=${artifact.dkgEpoch} snapshot.dkgEpoch=${snapshot.dkgEpoch}`,
  );
  process.exit(EXIT_ARTIFACT_DKG_EPOCH_MISMATCH);
}

// Pre-flight 3: rosterHash recomputed from dkgRoster must match artifact.rosterHash.
let dkgRosterHashComputed;
try {
  dkgRosterHashComputed = caDkgV2RosterHash(dkgRoster);
} catch (err) {
  console.error(
    `roster validation failed: ${err instanceof Error ? err.message : String(err)}`,
  );
  process.exit(EXIT_USAGE);
}
if (normalizeHex(dkgRosterHashComputed) !== normalizeHex(artifact.rosterHash)) {
  console.error(
    `STALE_ARTIFACT_ROSTER_HASH_MISMATCH: computed=${dkgRosterHashComputed} artifact.rosterHash=${artifact.rosterHash}`,
  );
  process.exit(EXIT_ARTIFACT_ROSTER_HASH_MISMATCH);
}

// Pre-flight 4: frost roster's dkgEpoch must match snapshot's.
if (String(frostRoster.dkgEpoch) !== String(snapshot.dkgEpoch)) {
  console.error(
    `STALE_FROST_ROSTER_DKG_EPOCH_MISMATCH: frostRoster.dkgEpoch=${frostRoster.dkgEpoch} snapshot.dkgEpoch=${snapshot.dkgEpoch}`,
  );
  process.exit(EXIT_FROST_DKG_EPOCH_MISMATCH);
}
const frostRosterHashComputed = frostDkgV2RosterHash(frostRoster);
console.log(
  `pre-flight: dkgRosterHash=${dkgRosterHashComputed} frostRosterHash=${frostRosterHashComputed} dkgEpoch=${snapshot.dkgEpoch}`,
);

// Pre-flight 5: aptos SDK verifyRegistration sanity-check. The chain's register_raw runs the
// same verification — failing here means the chain would reject too, so don't waste gas.
const senderAddrBytes = hexToBytes(artifact.senderAddress);
const assetTypeBytes = hexToBytes(artifact.assetType);
const ekBytes = hexToBytes(artifact.vaultEk);
const commitmentBytes = hexToBytes(artifact.aggregateCommitment);
const responseBytes = hexToBytes(artifact.aggregateResponse);
const proof = {
  commitment: [commitmentBytes],
  response: [responseBytes],
};
const proofOk = verifyRegistration({
  ek: ekBytes,
  senderAddress: senderAddrBytes,
  tokenAddress: assetTypeBytes,
  chainId: artifact.chainId,
  proof,
});
if (!proofOk) {
  console.error(
    "REGISTRATION_PROOF_REJECTED: Aptos SDK verifyRegistration returned false. The on-chain register_raw would also reject. Re-derive the registration proof before submitting.",
  );
  process.exit(EXIT_REGISTRATION_PROOF_REJECTED);
}
console.log("pre-flight: Aptos SDK verifyRegistration accepted the assembled proof");

// Pre-flight 6: chain state — rollover requires an existing BridgeVault singleton.
const bridgeVaultType = `${bridgePackage}::eunoma_bridge::BridgeVault`;
const bridgeVaultResource = await getResource(aptosNodeUrl, bridgePackage, bridgeVaultType);
if (bridgeVaultResource.status === 404) {
  console.error("VAULT_NOT_INITIALIZED: chain has no BridgeVault to roll over.");
  process.exit(EXIT_VAULT_NOT_INITIALIZED);
}
if (bridgeVaultResource.status !== 200) {
  console.error(
    `pre-flight BridgeVault resource read failed: status=${bridgeVaultResource.status} body=${JSON.stringify(bridgeVaultResource.body)}`,
  );
  process.exit(EXIT_USAGE);
}
const previousVaultAddress = bridgeVaultResource.body?.data?.vault_addr;
console.log(`pre-flight: existing BridgeVault.vault_addr=${stringify(previousVaultAddress)}`);
const bridgeVaultTablesType = `${bridgePackage}::eunoma_bridge::BridgeVaultTablesV2`;
const preTablesResource = await getResource(aptosNodeUrl, bridgePackage, bridgeVaultTablesType);
if (preTablesResource.status === 200) {
  console.error(
    "VAULT_TABLES_ALREADY_INITIALIZED: BridgeVaultTablesV2 already exists; this one-shot rollover would not create fresh nonce/nullifier/root tables.",
  );
  process.exit(EXIT_VAULT_TABLES_ALREADY_INITIALIZED);
}
if (preTablesResource.status !== 404) {
  console.error(
    `pre-flight BridgeVaultTablesV2 read failed: status=${preTablesResource.status} body=${JSON.stringify(preTablesResource.body)}`,
  );
  process.exit(EXIT_USAGE);
}
console.log("pre-flight: no BridgeVaultTablesV2 exists; rollover will create fresh tables");

// Build Move call args.
const moveArgs = [
  hexArg(snapshot.vaultSeed),
  // asset_type is an Aptos `Object<fungible_asset::Metadata>` — the CLI accepts it as
  // `address:<hex>` for the underlying account address.
  `address:${normalizePrefixed(snapshot.assetType)}`,
  u64Arg(String(snapshot.operatorSetVersion)),
  u64Arg(String(snapshot.dkgEpoch)),
  hexArg(dkgRosterHashComputed),
  hexArg(frostRoster.frostGroupPubkey),
  hexArg(artifact.vaultEk),
  hexVectorArg([artifact.aggregateCommitment]),
  hexVectorArg([artifact.aggregateResponse]),
  hexArg(snapshot.depositCircuitVersion),
  hexArg(snapshot.withdrawCircuitVersion),
  hexArg(snapshot.caPayloadCircuitVersion),
  hexVectorArg(snapshot.fallbackPubkeys),
];

const cliArgs = [
  "move",
  "run",
  "--function-id",
  `${bridgePackage}::eunoma_bridge::rollover_vault_with_ca_registration_v2`,
];
for (const a of moveArgs) cliArgs.push("--args", a);
if (adminProfile) {
  cliArgs.push("--profile", adminProfile);
}
if (!submit) {
  cliArgs.push("--simulate");
}

console.log(`aptos ${cliArgs.join(" ")}`);

const run = spawnSync("aptos", cliArgs, {
  cwd: serviceRoot,
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
  env: process.env,
});
if (run.error) {
  console.error(`failed to spawn aptos CLI: ${run.error.message}`);
  console.error("Is the aptos CLI installed and on PATH? Run `aptos --version` to verify.");
  process.exit(EXIT_APTOS_SPAWN);
}
process.stdout.write(run.stdout || "");
process.stderr.write(run.stderr || "");
if (run.status !== 0) {
  console.error(`aptos CLI exited with status ${run.status}`);
  process.exit(run.status ?? 1);
}

if (!submit) {
  console.log("");
  console.log(
    "simulate complete. Re-run with --submit AND RELAYER_SUBMIT_ENABLED=1 to actually roll the vault on-chain.",
  );
  console.log(
    `Expected post-submit: BridgeVault.vault_addr=${expectedVaultAddress} dkgEpoch=${snapshot.dkgEpoch} rosterHash=${dkgRosterHashComputed}`,
  );
  process.exit(0);
}

const txHash = extractTxHash(run.stdout || "");
if (!txHash) {
  console.error("submit: unable to parse tx hash from aptos CLI output");
  process.exit(EXIT_TX_HASH_PARSE);
}
console.log(`submit: tx hash ${txHash}; polling for confirmation`);
const confirmation = await waitForTx(aptosNodeUrl, txHash, 120_000);
if (!confirmation.success) {
  console.error(`submit: tx ${txHash} reverted: ${confirmation.vmStatus ?? "unknown"}`);
  process.exit(EXIT_TX_REVERTED);
}
console.log(`submit: tx ${txHash} confirmed; re-viewing chain state`);

const postCfgResource = await getResource(
  aptosNodeUrl,
  bridgePackage,
  `${bridgePackage}::eunoma_bridge::DeoperatorConfigV2`,
);
const postVaultResource = await getResource(aptosNodeUrl, bridgePackage, bridgeVaultType);
const postTablesResource = await getResource(aptosNodeUrl, bridgePackage, bridgeVaultTablesType);
if (postCfgResource.status !== 200 || postVaultResource.status !== 200 || postTablesResource.status !== 200) {
  console.error(
    `submit: missing post-rollover resources: config=${postCfgResource.status} vault=${postVaultResource.status} tables=${postTablesResource.status}`,
  );
  process.exit(EXIT_CHAIN_STATE_DIVERGED);
}
const postCfg = postCfgResource.body?.data ?? {};
const postVault = postVaultResource.body?.data ?? {};
const postOperatorSetVersion = stringify(postCfg.operator_set_version);
const postDkgEpoch = stringify(postCfg.dkg_epoch);
const postThreshold = stringify(postCfg.threshold);
const postRosterHash = stringify(postCfg.roster_hash);
const postFrostGroupPubkey = stringify(postCfg.frost_group_pubkey);
const postVaultEk = stringify(postCfg.vault_ek);
const postVaultAddress = stringify(postVault.vault_addr);

const mismatches = [];
if (normalizeHex(postVaultAddress) !== normalizeHex(expectedVaultAddress)) {
  mismatches.push(
    `vaultAddress: chain=${normalizeHex(postVaultAddress)} local=${normalizeHex(expectedVaultAddress)}`,
  );
}
if (String(postOperatorSetVersion) !== String(snapshot.operatorSetVersion)) {
  mismatches.push(
    `operatorSetVersion: chain=${postOperatorSetVersion} local=${snapshot.operatorSetVersion}`,
  );
}
if (String(postDkgEpoch) !== String(snapshot.dkgEpoch)) {
  mismatches.push(`dkgEpoch: chain=${postDkgEpoch} local=${snapshot.dkgEpoch}`);
}
if (String(postThreshold) !== "5") {
  mismatches.push(`threshold: chain=${postThreshold} local=5 (strict 5-of-7)`);
}
if (normalizeHex(postRosterHash) !== normalizeHex(dkgRosterHashComputed)) {
  mismatches.push(
    `rosterHash: chain=${normalizeHex(postRosterHash)} local=${normalizeHex(dkgRosterHashComputed)}`,
  );
}
if (normalizeHex(postFrostGroupPubkey) !== normalizeHex(frostRoster.frostGroupPubkey)) {
  mismatches.push(
    `frostGroupPubkey: chain=${normalizeHex(postFrostGroupPubkey)} local=${normalizeHex(frostRoster.frostGroupPubkey)}`,
  );
}
if (normalizeHex(postVaultEk) !== normalizeHex(snapshot.vaultEk)) {
  mismatches.push(
    `vaultEk: chain=${normalizeHex(postVaultEk)} local=${normalizeHex(snapshot.vaultEk)}`,
  );
}
if (mismatches.length > 0) {
  console.error("submit: chain state diverged from local expectation after tx confirmation:");
  for (const m of mismatches) console.error(`  ${m}`);
  process.exit(EXIT_CHAIN_STATE_DIVERGED);
}
console.log("submit: chain state matches local computation");

const artifactOut = {
  scheme: "testnet_vault_rollover_v1",
  txHash,
  dkgEpoch: snapshot.dkgEpoch,
  operatorSetVersion: snapshot.operatorSetVersion,
  rosterHash: dkgRosterHashComputed,
  frostGroupPubkey: frostRoster.frostGroupPubkey,
  previousVaultAddress,
  vaultAddress: expectedVaultAddress,
  freshTablesResource: bridgeVaultTablesType,
  vaultEk: snapshot.vaultEk,
  caRegistrationTranscriptHash: artifact.transcriptHash,
  caRegistrationTranscriptPath: artifactPath,
  bridgePackage,
  submittedAtUnixMs: Date.now(),
};
const outPathResolved = outputPath
  ? resolve(outputPath)
  : resolve(
      serviceRoot,
      ".agent-local/eunoma-v2",
      "coordinator",
      "testnet_vault_rollover",
      `${snapshot.dkgEpoch}__rollover.json`,
    );
mkdirSync(dirname(outPathResolved), { recursive: true, mode: 0o700 });
atomicWriteJson(outPathResolved, artifactOut);
console.log(`submit: persisted init artifact to ${outPathResolved}`);

process.exit(0);

// =============================================================================================
// Helpers
// =============================================================================================

function parseJsonFile(path, label) {
  let raw;
  try {
    raw = readFileSync(resolve(path), "utf8");
  } catch (err) {
    console.error(
      `${label}: cannot read ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(EXIT_USAGE);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error(
      `${label}: cannot parse JSON at ${path}: ${err instanceof Error ? err.message : String(err)}`,
    );
    process.exit(EXIT_USAGE);
  }
}

function atomicWriteJson(path, value) {
  const tmpPath = `${path}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, path);
}

function assertSnapshotShape(snap) {
  const required = [
    "operatorSetVersion",
    "dkgEpoch",
    "vaultEk",
    "vaultSeed",
    "assetType",
    "depositCircuitVersion",
    "withdrawCircuitVersion",
    "caPayloadCircuitVersion",
    "fallbackPubkeys",
  ];
  for (const key of required) {
    if (!(key in snap)) {
      throw new Error(`snapshot missing field: ${key}`);
    }
  }
  if (!Array.isArray(snap.fallbackPubkeys) || snap.fallbackPubkeys.length !== 7) {
    console.error("INVALID_FALLBACK_PUBKEYS: snapshot.fallbackPubkeys must be an array of 7 hex strings");
    process.exit(EXIT_INVALID_FALLBACK_PUBKEYS);
  }
  for (let i = 0; i < snap.fallbackPubkeys.length; i += 1) {
    const v = snap.fallbackPubkeys[i];
    if (typeof v !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(v)) {
      console.error(`INVALID_FALLBACK_PUBKEYS: snapshot.fallbackPubkeys[${i}] must be 32-byte hex`);
      process.exit(EXIT_INVALID_FALLBACK_PUBKEYS);
    }
  }
  for (const hexField of [
    "vaultEk",
    "depositCircuitVersion",
    "withdrawCircuitVersion",
    "caPayloadCircuitVersion",
  ]) {
    const v = snap[hexField];
    if (typeof v !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(v)) {
      throw new Error(`snapshot.${hexField} must be 32-byte hex, got ${typeof v === "string" ? v : typeof v}`);
    }
  }
  if (typeof snap.assetType !== "string" || !/^(0x)?[0-9a-fA-F]{1,64}$/.test(snap.assetType)) {
    throw new Error("snapshot.assetType must be a hex address");
  }
  if (typeof snap.vaultSeed !== "string" || !/^(0x)?[0-9a-fA-F]+$/.test(snap.vaultSeed)) {
    throw new Error("snapshot.vaultSeed must be hex");
  }
}

function assertCaRegistrationArtifactShape(art) {
  const required = [
    "vaultEk",
    "aggregateCommitment",
    "aggregateResponse",
    "rosterHash",
    "dkgEpoch",
    "senderAddress",
    "assetType",
    "chainId",
    "transcriptHash",
  ];
  for (const key of required) {
    if (!(key in art)) {
      throw new Error(`ca-registration-artifact missing field: ${key}`);
    }
  }
  for (const hexField of ["vaultEk", "aggregateCommitment", "aggregateResponse", "rosterHash", "transcriptHash"]) {
    const v = art[hexField];
    if (typeof v !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(v)) {
      console.error(`AGGREGATE_COMMITMENT_RESPONSE_SHAPE: ca-registration-artifact.${hexField} must be 32-byte hex, got ${typeof v === "string" ? v : typeof v}`);
      process.exit(EXIT_AGGREGATE_SHAPE);
    }
  }
}

function normalizeHex(value) {
  if (value === undefined || value === null) return "";
  return String(value).replace(/^0x/i, "").toLowerCase();
}

function normalizePrefixed(value) {
  const clean = normalizeHex(value);
  return `0x${clean}`;
}

function deriveResourceAddress(sourceAddress, seedHex) {
  const source = AccountAddress.from(normalizePrefixed(sourceAddress));
  return createResourceAddress(source, hexToBytes(seedHex)).toStringLong();
}

function hexToBytes(hex) {
  const clean = normalizeHex(hex);
  if (clean.length % 2 !== 0) {
    throw new Error(`hex string must be even-length: ${hex}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function stringify(v) {
  if (typeof v === "string") return v;
  if (v && typeof v === "object" && "value" in v) return v.value;
  if (v && typeof v === "object" && "inner" in v) return v.inner;
  return String(v);
}

async function getResource(nodeUrl, address, resourceType) {
  const base = String(nodeUrl).replace(/\/+$/, "");
  const root = base.endsWith("/v1") ? base : `${base}/v1`;
  const url = `${root}/accounts/${normalizePrefixed(address)}/resource/${encodeURIComponent(resourceType)}`;
  const res = await fetch(url);
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

function extractTxHash(text) {
  const jsonMatch = text.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/);
  if (jsonMatch) return jsonMatch[1];
  const plainMatch = text.match(/(?:hash|Hash)[^0-9a-fA-Fx]*?(0x[0-9a-fA-F]{64})/);
  if (plainMatch) return plainMatch[1];
  return null;
}

async function waitForTx(nodeUrl, txHash, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  const url = new URL(`/v1/transactions/by_hash/${txHash}`, nodeUrl).toString();
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        const body = await res.json();
        if (body && body.type === "pending_transaction") {
          // keep polling
        } else if (body && typeof body.success === "boolean") {
          return { success: body.success, vmStatus: body.vm_status };
        }
      } else if (res.status !== 404) {
        const text = await res.text();
        throw new Error(`tx poll ${url} -> ${res.status}: ${text}`);
      }
    } catch (err) {
      if (!(err instanceof TypeError)) throw err;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`tx ${txHash} did not confirm within ${timeoutMs}ms`);
}
