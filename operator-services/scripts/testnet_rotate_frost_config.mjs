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
import { readFileSync } from "node:fs";
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

// --submit branch handled in step 8.
console.error("--submit path is implemented but verification of post-submit state is deferred to step 8.");
process.exit(0);

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
