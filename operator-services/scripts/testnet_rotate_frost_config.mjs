#!/usr/bin/env node
// Operator-driven script that rotates DeoperatorConfigV2.frost_group_pubkey
// on Aptos testnet/mainnet via rotate_deoperator_config_v2.
//
// Tested against Aptos CLI 3.5+. Env vars required:
//   APTOS_NODE_URL        e.g. https://fullnode.testnet.aptoslabs.com/v1
//   BRIDGE_PACKAGE_ADDRESS the eunoma module address on chain
//   ADMIN_PROFILE         aptos CLI profile name with admin signer (only for --submit)
//
// Inputs:
//   --dkg-artifact <path>  FROST DKG-A artifact (groupPublicKey + 7 worker artifact hashes).
//   --snapshot <path>      Operator-maintained snapshot of immutable config fields:
//     {
//       "operatorSetVersion": "1",
//       "dkgEpoch": "1",
//       "vaultEk": "<hex32>",
//       "depositCircuitVersion": "<hex32>",
//       "withdrawCircuitVersion": "<hex32>",
//       "caPayloadCircuitVersion": "<hex32>",
//       "fallbackPubkeys": ["<hex32>", ... 7 entries]
//     }
//   --roster <path>        Full DeoperatorRoster JSON (the file written by
//                          local_cluster_config.mjs to cluster/roster.json). Required:
//                          rosterHash(currentRoster) must equal chain.roster_hash, otherwise
//                          rotate_deoperator_config_v2 would commit to a roster digest that
//                          the operator can't actually verify off-chain. See prepareFrostRotationTx.
//
// CLI:
//   testnet_rotate_frost_config.mjs --dkg-artifact <path> --snapshot <path> --roster <path> \
//     [--new-dkg-epoch <decimal>] [--submit]
//
// Default mode is --simulate (no --submit). Submission is operator-driven and out of CI scope.
// On --submit confirmation, the script atomically rewrites --roster and --snapshot to the
// rotated state. Operators then run scripts/local_frost_rotation_apply.mjs --dkg-artifact <path>
// to propagate rotated keys to local env files + cluster JSON.
import { spawnSync } from "node:child_process";
import { chmodSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  prepareFrostRotationTx,
  StaleRotationStateError,
  validateRoster,
} from "@eunoma/deop-protocol";
import { aptosView } from "./_lib/aptos_view.mjs";
import { hexArg, hexVectorArg, u64Arg } from "./_lib/format_aptos_args.mjs";

const STALE_EXIT_CODE = {
  STALE_ROSTER_HASH: 10,
  STALE_CHAIN_OPERATOR_SET_VERSION: 11,
  STALE_CHAIN_DKG_EPOCH: 12,
  STALE_CHAIN_VAULT_EK: 13,
  STALE_CHAIN_FROST_GROUP_PUBKEY: 14,
  STALE_SNAPSHOT_OPERATOR_SET_VERSION: 15,
  STALE_SNAPSHOT_DKG_EPOCH: 16,
  STALE_SNAPSHOT_VAULT_EK: 17,
  INVALID_FALLBACK_PUBKEYS: 18,
  INVALID_DKG_ARTIFACT: 19,
};

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let artifactPath = null;
let snapshotPath = null;
let rosterPath = null;
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
  } else if (arg === "--roster") {
    rosterPath = args[i + 1];
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
if (!artifactPath || !snapshotPath || !rosterPath) {
  console.error(
    "usage: testnet_rotate_frost_config.mjs --dkg-artifact <path> --snapshot <path> --roster <path> [--new-dkg-epoch <decimal>] [--submit]",
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

const artifact = parseJsonFile(artifactPath, "dkg-artifact");
const snapshot = parseJsonFile(snapshotPath, "snapshot");
const currentRoster = parseJsonFile(rosterPath, "roster");

assertSnapshotShape(snapshot);
try {
  validateRoster(currentRoster);
} catch (err) {
  console.error(`roster validation failed: ${(err instanceof Error ? err.message : String(err))}`);
  process.exit(2);
}

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

console.log(
  `chain: operatorSetVersion=${chainOperatorSetVersion} dkgEpoch=${chainDkgEpoch} rosterHash=${chainRosterHash} frostGroupPubkey=${chainFrostGroupPubkey}`,
);

let output;
try {
  output = prepareFrostRotationTx({
    currentRoster,
    chainView: {
      operatorSetVersion: String(chainOperatorSetVersion),
      dkgEpoch: String(chainDkgEpoch),
      rosterHash: String(chainRosterHash),
      frostGroupPubkey: String(chainFrostGroupPubkey),
      vaultEk: String(chainVaultEk),
    },
    snapshot,
    dkgArtifact: {
      groupPublicKey: artifact.groupPublicKey,
      workerArtifactHashes: artifact.workerArtifactHashes,
    },
    ...(newDkgEpochOverride ? { newDkgEpoch: newDkgEpochOverride } : {}),
  });
} catch (err) {
  if (err instanceof StaleRotationStateError) {
    console.error(`rotation refused: ${err.code} — ${err.message}`);
    const exit = STALE_EXIT_CODE[err.code] ?? 1;
    process.exit(exit);
  }
  throw err;
}

console.log(
  `rotation: newDkgEpoch=${output.rotatedRoster.dkgEpoch} newGroupPubkey=${output.rotatedRoster.frostGroupPubkey} newRosterHash=${output.rotatedRosterHash}`,
);

const { moveCallArgs } = output;
const moveArgs = [
  u64Arg(moveCallArgs.operatorSetVersion),
  u64Arg(moveCallArgs.newDkgEpoch),
  hexArg(moveCallArgs.rotatedRosterHash),
  hexArg(moveCallArgs.rotatedFrostGroupPubkey),
  hexArg(moveCallArgs.vaultEk),
  hexArg(moveCallArgs.depositCircuitVersion),
  hexArg(moveCallArgs.withdrawCircuitVersion),
  hexArg(moveCallArgs.caPayloadCircuitVersion),
  hexVectorArg(moveCallArgs.fallbackPubkeys),
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
  console.log(`Expected post-submit: dkgEpoch=${output.rotatedRoster.dkgEpoch} rosterHash=${output.rotatedRosterHash}`);
  process.exit(0);
}

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
  _postVaultEk,
] = postView.map(stringify);

const mismatches = [];
if (String(postDkgEpoch) !== output.rotatedRoster.dkgEpoch) {
  mismatches.push(`dkgEpoch: chain=${postDkgEpoch} local=${output.rotatedRoster.dkgEpoch}`);
}
if (normalizeHex(postRosterHash) !== normalizeHex(output.rotatedRosterHash)) {
  mismatches.push(
    `rosterHash: chain=${normalizeHex(postRosterHash)} local=${normalizeHex(output.rotatedRosterHash)}`,
  );
}
if (normalizeHex(postFrostGroupPubkey) !== normalizeHex(output.rotatedRoster.frostGroupPubkey)) {
  mismatches.push(
    `frostGroupPubkey: chain=${normalizeHex(postFrostGroupPubkey)} local=${normalizeHex(output.rotatedRoster.frostGroupPubkey)}`,
  );
}
if (mismatches.length > 0) {
  console.error("submit: chain state diverged from local expectation after tx confirmation:");
  for (const m of mismatches) console.error(`  ${m}`);
  process.exit(6);
}
console.log("submit: chain state matches local computation");

const rosterResolved = resolve(rosterPath);
atomicWriteJson(rosterResolved, output.rotatedRoster);
console.log(`submit: roster at ${rosterResolved} updated to dkgEpoch=${output.rotatedRoster.dkgEpoch}`);

const updatedSnapshot = {
  ...snapshot,
  dkgEpoch: output.rotatedRoster.dkgEpoch,
};
const snapshotResolved = resolve(snapshotPath);
atomicWriteJson(snapshotResolved, updatedSnapshot);
console.log(`submit: snapshot at ${snapshotResolved} updated to dkgEpoch=${output.rotatedRoster.dkgEpoch}`);

console.log(`submit: rotation complete. operatorSetVersion=${postOperatorSetVersion} dkgEpoch=${postDkgEpoch}`);
console.log("");
console.log("submit: chain rotated. To propagate rotated keys to local services (env files, cluster JSON):");
console.log(`  node scripts/local_frost_rotation_apply.mjs --dkg-artifact ${resolve(artifactPath)}`);
console.log("Then restart coordinator + nodes (workers stay alive).");

function parseJsonFile(path, label) {
  let raw;
  try {
    raw = readFileSync(resolve(path), "utf8");
  } catch (err) {
    console.error(`${label}: cannot read ${path}: ${(err instanceof Error ? err.message : String(err))}`);
    process.exit(2);
  }
  try {
    return JSON.parse(raw);
  } catch (err) {
    console.error(`${label}: cannot parse JSON at ${path}: ${(err instanceof Error ? err.message : String(err))}`);
    process.exit(2);
  }
}

function atomicWriteJson(path, value) {
  const tmpPath = `${path}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmpPath, 0o600);
  renameSync(tmpPath, path);
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
