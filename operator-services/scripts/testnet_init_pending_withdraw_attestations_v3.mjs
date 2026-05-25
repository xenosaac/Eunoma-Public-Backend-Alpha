#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
const submit = args.includes("--submit");
const aptosNodeUrl = process.env.APTOS_NODE_URL;
const bridgePackage = process.env.BRIDGE_PACKAGE_ADDRESS;
const adminProfile = process.env.ADMIN_PROFILE;
const relayerSubmitEnabled = process.env.RELAYER_SUBMIT_ENABLED === "1";

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
if (submit && !relayerSubmitEnabled) {
  console.error("--submit requires RELAYER_SUBMIT_ENABLED=1");
  process.exit(2);
}

const resourceType = `${bridgePackage}::eunoma_bridge::PendingWithdrawAttestationsV3`;
const existing = await getResource(aptosNodeUrl, bridgePackage, resourceType);
if (existing.status === 200) {
  console.log("PendingWithdrawAttestationsV3 already initialized");
  process.exit(0);
}
if (existing.status !== 404) {
  console.error(`resource preflight failed: status=${existing.status} body=${JSON.stringify(existing.body)}`);
  process.exit(2);
}

const cliArgs = [
  "move",
  "run",
  "--function-id",
  `${bridgePackage}::eunoma_bridge::init_pending_withdraw_attestations_v3`,
];
if (adminProfile) cliArgs.push("--profile", adminProfile);
if (!submit) {
  cliArgs.push("--local");
} else {
  cliArgs.push("--assume-yes");
}

console.log(`aptos ${cliArgs.join(" ")}`);
const run = spawnSync("aptos", cliArgs, {
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
  env: process.env,
});
if (run.error) {
  console.error(`failed to spawn aptos CLI: ${run.error.message}`);
  process.exit(3);
}
process.stdout.write(run.stdout || "");
process.stderr.write(run.stderr || "");
if (run.status !== 0) process.exit(run.status ?? 1);
if (!submit) {
  console.log("local simulation complete. Re-run with --submit AND RELAYER_SUBMIT_ENABLED=1.");
  process.exit(0);
}

const txHash = extractTxHash(run.stdout || "");
if (txHash) console.log(`submit: tx hash ${txHash}`);
const post = await getResource(aptosNodeUrl, bridgePackage, resourceType);
if (post.status !== 200) {
  console.error(`post-submit resource missing: status=${post.status}`);
  process.exit(4);
}
console.log("PendingWithdrawAttestationsV3 initialized");

async function getResource(nodeUrl, address, type) {
  const base = String(nodeUrl).replace(/\/+$/, "");
  const root = base.endsWith("/v1") ? base : `${base}/v1`;
  const url = `${root}/accounts/${address}/resource/${encodeURIComponent(type)}`;
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
  return plainMatch?.[1] ?? null;
}
