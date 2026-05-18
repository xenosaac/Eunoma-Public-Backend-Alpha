#!/usr/bin/env node
// Diagnostic: simulate withdraw_to_recipient_v2 using the persisted finalize
// artifact's withdrawV2CallArgsFields. Captures stdout + stderr so the chain
// rejection reason is visible without needing the relayer's stderr.
//
// Usage: node scripts/_diag_withdraw_simulate.mjs <finalize.json>
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const finalizePath = process.argv[2];
if (!finalizePath) {
  console.error("usage: node scripts/_diag_withdraw_simulate.mjs <finalize.json>");
  process.exit(2);
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");

const fin = JSON.parse(readFileSync(finalizePath, "utf8"));
const args = fin.withdrawV2CallArgsFields;
if (!args) {
  console.error("no withdrawV2CallArgsFields in finalize.json");
  process.exit(2);
}

const BRIDGE = process.env.BRIDGE_PACKAGE_ADDRESS ?? "0xa08850b1ca22cc5aa3a3a3fb1179cf3f1f169312cea8038ff1b1e3b4ace79ec1";
const PROFILE = process.env.ADMIN_PROFILE ?? "testnet-admin";
const SIMULATE = process.env.SIMULATE !== "0";

const { encodeCallArgs } = await import(`${serviceRoot}/relayer/dist/server.js`).catch(() => ({}));
let positional;
if (encodeCallArgs) {
  positional = encodeCallArgs(args);
} else {
  console.error("relayer dist not available; falling back to encode call");
  process.exit(3);
}

const cliArgs = [
  "move", "run",
  "--function-id", `${BRIDGE}::eunoma_bridge::withdraw_to_recipient_v2`,
  "--profile", PROFILE,
  "--assume-yes",
  ...(SIMULATE ? ["--simulate"] : []),
  "--args",
  ...positional,
];

console.error(`[diag] running: aptos ${cliArgs.slice(0,6).join(" ")} <... 27 args ...>`);
const r = spawnSync("aptos", cliArgs, { encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
console.log("===== STDOUT =====");
console.log(r.stdout || "(empty)");
console.log("===== STDERR =====");
console.log(r.stderr || "(empty)");
console.log(`===== EXIT CODE: ${r.status} =====`);
process.exit(r.status ?? 1);
