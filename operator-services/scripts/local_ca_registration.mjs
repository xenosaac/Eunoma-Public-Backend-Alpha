#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
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
const coordinatorUrl =
  process.env.COORDINATOR_URL ?? `http://127.0.0.1:${plan.coordinator.port}`;
const coordinatorToken =
  process.env.COORDINATOR_BEARER_TOKEN ?? plan.coordinator.env.COORDINATOR_BEARER_TOKEN;
const requestId = process.env.REQUEST_ID ?? `ca-registration-${Date.now()}`;
const senderAddress = normalizeAddressHex(
  process.env.VAULT_ADDR_HEX ?? process.env.SENDER_ADDRESS_HEX ?? "",
  "VAULT_ADDR_HEX",
);
const assetType = normalizeAddressHex(process.env.ASSET_TYPE_HEX ?? "0xa", "ASSET_TYPE_HEX");
const chainId = u8Env(process.env.CHAIN_ID ?? "2", "CHAIN_ID");
const quorumSlots = quorumFromEnv(process.env.REGISTRATION_QUORUM_SLOTS ?? "0,1,2,3,4");

await assertCoordinatorReady();

const commitments = [];
const noncesBySlot = new Map();
for (const slot of quorumSlots) {
  const result = await proxy(slot, "nonce-commit", { requestId });
  commitments.push({ slot, commitment: result.commitment });
  noncesBySlot.set(slot, result.nonce_id);
}

const challenge = await proxy(quorumSlots[0], "challenge", {
  vaultEk: plan.roster.vaultEk,
  senderAddress,
  assetType,
  chainId,
  commitments,
});

const responses = [];
for (const slot of quorumSlots) {
  const result = await proxy(slot, "partial", {
    nonceId: noncesBySlot.get(slot),
    challenge: challenge.challenge,
  });
  responses.push({ slot, response: result.response });
}

const proof = await proxy(quorumSlots[0], "aggregate", {
  vaultEk: plan.roster.vaultEk,
  senderAddress,
  assetType,
  chainId,
  commitments,
  responses,
});

console.log(JSON.stringify({
  ok: true,
  requestId,
  coordinatorUrl,
  vaultEk: plan.roster.vaultEk,
  senderAddress,
  assetType,
  chainId,
  quorumSlots,
  sigma_proto_comm: proof.sigma_proto_comm,
  sigma_proto_resp: proof.sigma_proto_resp,
  challenge: proof.challenge,
  proof_hash: proof.proof_hash,
  transcript_hash: proof.transcript_hash,
}, null, 2));

async function proxy(slot, step, body) {
  const res = await fetch(`${coordinatorUrl}/v2/proxy/ca/registration/${slot}/${step}`, {
    method: "POST",
    headers: headers(),
    body: JSON.stringify(body),
  });
  const json = await parseJson(res);
  if (!res.ok || !json.accepted || !json.forwarded?.body) {
    throw new Error(`registration ${step} slot ${slot} failed: ${JSON.stringify(json)}`);
  }
  return json.forwarded.body;
}

async function assertCoordinatorReady() {
  const res = await fetch(`${coordinatorUrl}/v2/health`);
  if (!res.ok) {
    throw new Error(`coordinator is not ready at ${coordinatorUrl}: ${res.status}`);
  }
}

async function parseJson(res) {
  try {
    return await res.json();
  } catch {
    return { error: "non_json_response", status: res.status };
  }
}

function headers() {
  const out = { "content-type": "application/json" };
  if (coordinatorToken) out.authorization = `Bearer ${coordinatorToken}`;
  return out;
}

function normalizeAddressHex(value, name) {
  const raw = value.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]+$/.test(raw) || raw.length > 64) {
    throw new Error(`${name} must be an Aptos address hex value`);
  }
  return raw.padStart(64, "0");
}

function u8Env(value, name) {
  if (!/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be a u8 integer`);
  }
  const parsed = Number.parseInt(value, 10);
  if (parsed < 0 || parsed > 255) {
    throw new Error(`${name} must be a u8 integer`);
  }
  return parsed;
}

function quorumFromEnv(value) {
  const slots = value.split(",").map((item) => Number.parseInt(item.trim(), 10));
  if (
    slots.length !== 5 ||
    slots.some((slot) => !Number.isInteger(slot) || slot < 0 || slot > 6) ||
    new Set(slots).size !== slots.length
  ) {
    throw new Error("REGISTRATION_QUORUM_SLOTS must contain five unique slots from 0-6");
  }
  return slots;
}
