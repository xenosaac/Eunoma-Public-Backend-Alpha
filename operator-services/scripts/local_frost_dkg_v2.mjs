#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const stateRoot = resolve(
  serviceRoot,
  process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2",
);
const planPath = resolve(stateRoot, "cluster/local-cluster.json");

if (!existsSync(planPath)) {
  console.error("local cluster config not found. Run `npm run local:cluster:config -- --force` first.");
  process.exit(2);
}

const plan = JSON.parse(readFileSync(planPath, "utf8"));
if (!plan.frostDkgV2Roster || !plan.frostDkgV2RosterHash) {
  console.error("local cluster config is missing frost_dkg_v2 roster. Re-run `npm run local:cluster:config -- --force`.");
  process.exit(2);
}

const coordinatorUrl = process.env.COORDINATOR_URL ?? `http://127.0.0.1:${plan.coordinator.port}`;
const token = process.env.COORDINATOR_BEARER_TOKEN ?? plan.coordinator.env.COORDINATOR_BEARER_TOKEN;
const requestId = process.env.REQUEST_ID ?? `frost-dkg-v2-${Date.now()}`;
const sessionId =
  process.env.SESSION_ID ??
  `${plan.frostDkgV2Roster.operatorSetVersion}:${plan.frostDkgV2Roster.dkgEpoch}:${plan.frostDkgV2RosterHash}`;

const res = await fetch(new URL("/v2/dkg/frost/v2/start", coordinatorUrl), {
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
  },
  body: JSON.stringify({
    requestId,
    sessionId,
  }),
});

const body = await res.json().catch(() => ({}));
if (!res.ok) {
  console.error(JSON.stringify(body, null, 2));
  process.exit(1);
}

const artifactDir = resolve(stateRoot, "cluster/frost_dkg");
mkdirSync(artifactDir, { recursive: true });
const artifactPath = resolve(artifactDir, `${requestId}.json`);
writeFileSync(
  artifactPath,
  `${JSON.stringify(
    {
      ...body,
      frostDkgV2RosterHash: plan.frostDkgV2RosterHash,
      note: "frost_dkg_v2 four-phase DKG completed; rotated frost_key_package.json written per slot",
    },
    null,
    2,
  )}\n`,
  { mode: 0o644 },
);

console.warn(
  "WARN: rotation not propagated to coordinator/node/Move; live attestations still use seeded key. " +
    "Future step adds rotate_deoperator_config_v2 admin tx + service restart.",
);

console.log(JSON.stringify({ ...body, artifactPath }, null, 2));
