#!/usr/bin/env node
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applyFrostRotationToRoster } from "@eunoma/deop-protocol";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const args = process.argv.slice(2);
let artifactPath = null;
let stateRootArg = null;
let newDkgEpochOverride = null;
let dryRun = false;
for (let i = 0; i < args.length; i += 1) {
  const arg = args[i];
  if (arg === "--dkg-artifact") {
    artifactPath = args[i + 1];
    i += 1;
  } else if (arg === "--state-root") {
    stateRootArg = args[i + 1];
    i += 1;
  } else if (arg === "--new-dkg-epoch") {
    newDkgEpochOverride = args[i + 1];
    i += 1;
  } else if (arg === "--dry-run") {
    dryRun = true;
  } else {
    console.error(`unknown arg: ${arg}`);
    process.exit(2);
  }
}
if (!artifactPath) {
  console.error(
    "usage: local_frost_rotation_apply.mjs --dkg-artifact <path> [--state-root <path>] [--new-dkg-epoch <decimal>] [--dry-run]",
  );
  process.exit(2);
}

const stateRoot = resolve(
  serviceRoot,
  stateRootArg ?? process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const clusterDir = resolve(stateRoot, "cluster");
const planPath = resolve(clusterDir, "local-cluster.json");
const rosterPath = resolve(clusterDir, "roster.json");

const plan = JSON.parse(readFileSync(planPath, "utf8"));
const artifact = JSON.parse(readFileSync(resolve(artifactPath), "utf8"));

if (!Array.isArray(artifact.workerArtifactHashes) || artifact.workerArtifactHashes.length !== 7) {
  console.error("DKG artifact missing 7-slot workerArtifactHashes");
  process.exit(2);
}
if (typeof artifact.groupPublicKey !== "string") {
  console.error("DKG artifact missing groupPublicKey");
  process.exit(2);
}
if (typeof artifact.dkgEpoch !== "string") {
  console.error("DKG artifact missing dkgEpoch — was the artifact produced before step 1 surfaced it?");
  process.exit(2);
}

// Auto-bump to current + 1 unless caller picks an explicit target. The artifact's
// own dkgEpoch is informational — operator picks the rotation target.
const currentEpoch = Number(plan.roster.dkgEpoch);
const newDkgEpoch = newDkgEpochOverride ?? String(currentEpoch + 1);

const rotation = applyFrostRotationToRoster(plan.roster, {
  groupPublicKey: artifact.groupPublicKey,
  dkgEpoch: newDkgEpoch,
  workerArtifacts: artifact.workerArtifactHashes,
});

const rotatedRosterJson = JSON.stringify(rotation.roster);
const patchedPlan = {
  ...plan,
  roster: rotation.roster,
  rosterHash: rotation.rosterHash,
  coordinator: {
    ...plan.coordinator,
    env: { ...plan.coordinator.env, DEOPERATOR_ROSTER_JSON: rotatedRosterJson },
  },
  nodes: plan.nodes.map((node) => ({
    ...node,
    env: { ...node.env, DEOPERATOR_ROSTER_JSON: rotatedRosterJson },
  })),
};

const diff = {
  previousDkgEpoch: rotation.previousDkgEpoch,
  newDkgEpoch: rotation.roster.dkgEpoch,
  previousGroupPublicKey: rotation.previousGroupPublicKey,
  newGroupPublicKey: rotation.roster.frostGroupPubkey,
  previousRosterHash: rotation.previousRosterHash,
  newRosterHash: rotation.rosterHash,
};
console.log(JSON.stringify({ ok: true, dryRun, ...diff }, null, 2));

if (dryRun) {
  console.log("dry run — no files written. Re-run without --dry-run to apply.");
  process.exit(0);
}

// Stage all writes as .tmp first, then rename in a tight loop so a mid-write interrupt
// leaves the cluster either fully rotated or untouched at the file level.
const writes = [];
writes.push([
  planPath,
  `${JSON.stringify(patchedPlan, null, 2)}\n`,
  0o600,
]);
writes.push([
  rosterPath,
  `${JSON.stringify({ ...rotation.roster, rosterHash: rotation.rosterHash }, null, 2)}\n`,
  0o644,
]);
const envPaths = renderEnvWritesStaged(patchedPlan, clusterDir);
for (const [path, content, mode] of envPaths) {
  writes.push([path, content, mode]);
}

mkdirSync(clusterDir, { recursive: true, mode: 0o700 });
const tmpPaths = [];
for (const [path, content, mode] of writes) {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, content, { mode });
  chmodSync(tmp, mode);
  tmpPaths.push([tmp, path]);
}
for (const [tmp, path] of tmpPaths) {
  renameSync(tmp, path);
}

console.log("");
console.log("apply complete. Restart coordinator + 7 nodes to pick up rotated roster.");
console.log("Workers stay alive — their rotated frost_key_package.json on disk is already in use.");
console.log("");
console.log("  pkill -f \"@eunoma/coordinator\" && pkill -f \"@eunoma/deoperator-node\"");
console.log("  npm run local:cluster:start");

function renderEnvWritesStaged(plan, dir) {
  // Mirrors renderEnvFiles in @eunoma/deop-protocol but returns staged writes
  // so we can fold them into the same atomic .tmp+rename batch as the JSON files.
  const out = [];
  out.push([resolve(dir, "coordinator.env"), serializeEnv(plan.coordinator.env), 0o600]);
  out.push([resolve(dir, "relayer.env"), serializeEnv(plan.relayer.env), 0o600]);
  for (const node of plan.nodes) {
    out.push([resolve(dir, `node-${node.slot}.env`), serializeEnv(node.env), 0o600]);
  }
  return out;
}

function serializeEnv(env) {
  const lines = Object.entries(env).map(([key, value]) => `${key}=${shellQuote(value)}`);
  return `${lines.join("\n")}\n`;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}
