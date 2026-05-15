#!/usr/bin/env node
// Operator-driven script that rotates DeoperatorConfigV2.frost_group_pubkey
// on Aptos testnet/mainnet via rotate_deoperator_config_v2.
//
// Tested against Aptos CLI 3.5+. Env vars required:
//   APTOS_NODE_URL        e.g. https://fullnode.testnet.aptoslabs.com/v1
//   BRIDGE_PACKAGE_ADDRESS the eunoma module address on chain
//   ADMIN_PROFILE         aptos CLI profile name with admin signer
//
// Snapshot file format (cluster/deoperator-config-snapshot.json):
//   {
//     "operatorSetVersion": "1",
//     "dkgEpoch": "1",
//     "vaultEk": "<hex32>",
//     "depositCircuitVersion": "<hex32>",
//     "withdrawCircuitVersion": "<hex32>",
//     "caPayloadCircuitVersion": "<hex32>",
//     "fallbackPubkeys": ["<hex32>", ... 7 entries]
//   }
//
// CLI:
//   testnet_rotate_frost_config.mjs --dkg-artifact <path> --snapshot <path> [--submit]
//
// Default mode is --simulate (no --submit). Submission is operator-driven and
// out of CI scope; --submit is supported but exercised manually.
import { spawnSync } from "node:child_process";
import { chmodSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applyFrostRotationToRoster } from "@eunoma/deop-protocol";
import { aptosView } from "./_lib/aptos_view.mjs";
import { hexArg, hexVectorArg, u64Arg } from "./_lib/format_aptos_args.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let artifactPath = null;
let snapshotPath = null;
let newDkgEpochOverride = null;
let submit = false;
for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === "--dkg-artifact") {
    artifactPath = args[i + 1];
    i += 1;
  } else if (arg === "--snapshot") {
    snapshotPath = args[i + 1];
    i += 1;
  } else if (arg === "--new-dkg-epoch") {
    newDkgEpochOverride = args[i + 1];
    i += 1;
  } else if (arg === "--submit") {
    submit = true;
  } else {
    console.error(`unknown arg: ${arg}`);
    process.exit(2);
  }
}
if (!artifactPath || !snapshotPath) {
  console.error(
    "usage: testnet_rotate_frost_config.mjs --dkg-artifact <path> --snapshot <path> [--new-dkg-epoch <decimal>] [--submit]",
  );
  process.exit(2);
}

const aptosNodeUrl = process.env.APTOS_NODE_URL;
const bridgePackage = process.env.BRIDGE_PACKAGE_ADDRESS;
const adminProfile = process.env.ADMIN_PROFILE;
if (!aptosNodeUrl) {
  console.error("APTOS_NODE_URL is required");
  process.exit(2);
}
if (!bridgePackage) {
  console.error("BRIDGE_PACKAGE_ADDRESS is required");
  process.exit(2);
}
if (submit && !adminProfile) {
  console.error("ADMIN_PROFILE is required for --submit");
  process.exit(2);
}

const artifact = JSON.parse(readFileSync(resolve(artifactPath), "utf8"));
const snapshot = JSON.parse(readFileSync(resolve(snapshotPath), "utf8"));

assertSnapshotShape(snapshot);
if (!Array.isArray(artifact.workerArtifactHashes) || artifact.workerArtifactHashes.length !== 7) {
  console.error("DKG artifact missing 7-slot workerArtifactHashes");
  process.exit(2);
}
if (typeof artifact.groupPublicKey !== "string") {
  console.error("DKG artifact missing groupPublicKey");
  process.exit(2);
}

// 1. View on-chain config and assert snapshot is fresh.
console.log(`view: ${bridgePackage}::eunoma_bridge::get_deoperator_config_v2`);
const view = await aptosView(
  aptosNodeUrl,
  `${bridgePackage}::eunoma_bridge::get_deoperator_config_v2`,
  [],
  [],
);
if (!Array.isArray(view) || view.length < 6) {
  throw new Error(`unexpected /view response shape: ${JSON.stringify(view)}`);
}
const [
  chainOperatorSetVersion,
  chainDkgEpoch,
  _chainThreshold,
  chainRosterHash,
  chainFrostGroupPubkey,
  chainVaultEk,
] = view.map(stringify);

if (String(snapshot.operatorSetVersion) !== String(chainOperatorSetVersion)) {
  throw new Error(
    `snapshot.operatorSetVersion=${snapshot.operatorSetVersion} != chain=${chainOperatorSetVersion} — snapshot stale`,
  );
}
if (String(snapshot.dkgEpoch) !== String(chainDkgEpoch)) {
  throw new Error(`snapshot.dkgEpoch=${snapshot.dkgEpoch} != chain=${chainDkgEpoch} — snapshot stale`);
}
if (normalizeHex(snapshot.vaultEk) !== normalizeHex(chainVaultEk)) {
  throw new Error(`snapshot.vaultEk mismatch vs chain — snapshot stale`);
}
console.log(
  `chain: operatorSetVersion=${chainOperatorSetVersion} dkgEpoch=${chainDkgEpoch} rosterHash=${chainRosterHash} frostGroupPubkey=${chainFrostGroupPubkey}`,
);

// 2. Reconstruct DeoperatorRoster from snapshot + chain view, then rotate.
const baseRoster = {
  operatorSetVersion: String(chainOperatorSetVersion),
  dkgEpoch: String(chainDkgEpoch),
  caDkgScheme: "ca_dkg_v2",
  threshold: 5,
  nodes: artifact.workerArtifactHashes.map((entry) => ({
    slot: entry.slot,
    // Identity fields below are NOT verified on-chain; rotation only mutates frostVerifyingShare,
    // frostGroupPubkey, and dkgEpoch in the canonical roster digest. The chain only checks rosterHash.
    nodeId: `chain-deop-${entry.slot}`,
    endpoint: `chain://deop-${entry.slot}`,
    hpkePublicKey: "00".repeat(32),
    transcriptPublicKey: "00".repeat(32),
    frostVerifyingShare: "00".repeat(32),
  })),
  frostGroupPubkey: normalizeHex(chainFrostGroupPubkey),
  vaultEk: normalizeHex(chainVaultEk),
  circuitVersions: {
    depositBinding: normalizeHex(snapshot.depositCircuitVersion),
    withdraw: normalizeHex(snapshot.withdrawCircuitVersion),
    caPayload: normalizeHex(snapshot.caPayloadCircuitVersion),
  },
};

const newDkgEpoch = newDkgEpochOverride ?? String(Number(baseRoster.dkgEpoch) + 1);
const rotation = applyFrostRotationToRoster(baseRoster, {
  groupPublicKey: artifact.groupPublicKey,
  dkgEpoch: newDkgEpoch,
  workerArtifacts: artifact.workerArtifactHashes,
});

console.log(
  `rotation: newDkgEpoch=${rotation.roster.dkgEpoch} newGroupPubkey=${rotation.roster.frostGroupPubkey} newRosterHash=${rotation.rosterHash}`,
);

// 3. Build aptos move run invocation.
const fallback = snapshot.fallbackPubkeys.map(normalizeHex);
const moveArgs = [
  u64Arg(baseRoster.operatorSetVersion),
  u64Arg(rotation.roster.dkgEpoch),
  hexArg(rotation.rosterHash),
  hexArg(rotation.roster.frostGroupPubkey),
  hexArg(baseRoster.vaultEk),
  hexArg(snapshot.depositCircuitVersion),
  hexArg(snapshot.withdrawCircuitVersion),
  hexArg(snapshot.caPayloadCircuitVersion),
  hexVectorArg(fallback),
];

const cliArgs = [
  "move",
  "run",
  "--function-id",
  `${bridgePackage}::eunoma_bridge::rotate_deoperator_config_v2`,
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
  process.exit(3);
}
process.stdout.write(run.stdout || "");
process.stderr.write(run.stderr || "");
if (run.status !== 0) {
  console.error(`aptos CLI exited with status ${run.status}`);
  process.exit(run.status ?? 1);
}

if (!submit) {
  console.log("");
  console.log("simulate complete. Re-run with --submit to actually rotate the on-chain frost_group_pubkey.");
  console.log(`Expected post-submit: dkgEpoch=${rotation.roster.dkgEpoch} rosterHash=${rotation.rosterHash}`);
  process.exit(0);
}

// --submit branch: parse tx hash, wait for confirmation, re-view chain state,
// and update the snapshot. Failure modes are loud; partial state is not silently accepted.
const txHash = extractTxHash(run.stdout || "");
if (!txHash) {
  console.error("submit: unable to parse tx hash from aptos CLI output. Re-view manually before re-submitting.");
  process.exit(4);
}
console.log(`submit: tx hash ${txHash}; polling for confirmation`);
const confirmation = await waitForTx(aptosNodeUrl, txHash, 120_000);
if (!confirmation.success) {
  console.error(`submit: tx ${txHash} reverted: ${confirmation.vmStatus ?? "unknown"}`);
  process.exit(5);
}
console.log(`submit: tx ${txHash} confirmed; re-viewing chain state`);

const postView = await aptosView(
  aptosNodeUrl,
  `${bridgePackage}::eunoma_bridge::get_deoperator_config_v2`,
  [],
  [],
);
const [
  postOperatorSetVersion,
  postDkgEpoch,
  _postThreshold,
  postRosterHash,
  postFrostGroupPubkey,
  postVaultEk,
] = postView.map(stringify);

const mismatches = [];
if (String(postDkgEpoch) !== rotation.roster.dkgEpoch) {
  mismatches.push(`dkgEpoch: chain=${postDkgEpoch} local=${rotation.roster.dkgEpoch}`);
}
if (normalizeHex(postRosterHash) !== normalizeHex(rotation.rosterHash)) {
  mismatches.push(`rosterHash: chain=${normalizeHex(postRosterHash)} local=${normalizeHex(rotation.rosterHash)}`);
}
if (normalizeHex(postFrostGroupPubkey) !== normalizeHex(rotation.roster.frostGroupPubkey)) {
  mismatches.push(
    `frostGroupPubkey: chain=${normalizeHex(postFrostGroupPubkey)} local=${normalizeHex(rotation.roster.frostGroupPubkey)}`,
  );
}
if (mismatches.length > 0) {
  console.error("submit: chain state diverged from local expectation after tx confirmation:");
  for (const m of mismatches) console.error(`  ${m}`);
  process.exit(6);
}
console.log("submit: chain state matches local computation");

// Atomic snapshot update: only dkgEpoch changes; immutable fields untouched.
const updatedSnapshot = {
  ...snapshot,
  dkgEpoch: rotation.roster.dkgEpoch,
};
const snapshotResolved = resolve(snapshotPath);
const tmpPath = `${snapshotResolved}.tmp`;
writeFileSync(tmpPath, `${JSON.stringify(updatedSnapshot, null, 2)}\n`, { mode: 0o600 });
chmodSync(tmpPath, 0o600);
renameSync(tmpPath, snapshotResolved);
console.log(`submit: snapshot at ${snapshotResolved} updated to dkgEpoch=${rotation.roster.dkgEpoch}`);
console.log(`submit: rotation complete. operatorSetVersion=${postOperatorSetVersion} dkgEpoch=${postDkgEpoch}`);

function extractTxHash(text) {
  // Aptos CLI typically emits a "transaction_hash" field in JSON output, or "Hash: 0x..." in plain.
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
      // network blip — retry
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(`tx ${txHash} did not confirm within ${timeoutMs}ms`);
}

function assertSnapshotShape(snap) {
  const required = [
    "operatorSetVersion",
    "dkgEpoch",
    "vaultEk",
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
    throw new Error("snapshot.fallbackPubkeys must be an array of 7 hex strings");
  }
}

function normalizeHex(value) {
  return String(value).replace(/^0x/i, "").toLowerCase();
}

function stringify(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}
