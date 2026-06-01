#!/usr/bin/env node
// One-shot VK provisioning for the fresh ASP testnet deploy. Publishes the 3 full VKs
// (deposit 6-IC frozen / withdraw 13-IC v3_asp / ragequit 5-IC) + derives their 3 prepared
// forms (the V3 split prepare path + ragequit verify against the *Prepared* VK resources).
//
// Idempotent: a publish that aborts with E_ALREADY_INITIALIZED is treated as already-done.
// Records every tx hash to <stateRoot>/coordinator/vk_provision_state.json.
//
// Env: BRIDGE_PACKAGE_ADDRESS, ADMIN_PROFILE (aptos CLI profile), EUNOMA_LOCAL_STATE_ROOT.
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");
const BRIDGE = process.env.BRIDGE_PACKAGE_ADDRESS;
const PROFILE = process.env.ADMIN_PROFILE || "testnet-asp-admin";
const STATE_ROOT = resolve(serviceRoot, process.env.EUNOMA_LOCAL_STATE_ROOT ?? ".agent-local/eunoma-v2-asp");
if (!BRIDGE) { console.error("BRIDGE_PACKAGE_ADDRESS required"); process.exit(2); }

const vkArgs = (extractor) => {
  const j = JSON.parse(execFileSync("node", [resolve(repoRoot, "circuits/scripts", extractor)], { encoding: "utf8" }));
  const all = [j.alpha_g1, j.beta_g2, j.gamma_g2, j.delta_g2, ...j.ic];
  return all.map((h) => `hex:0x${h}`);
};

const run = (entry, args) => {
  const fn = `${BRIDGE}::eunoma_bridge::${entry}`;
  const cli = ["move", "run", "--function-id", fn, "--profile", PROFILE, "--assume-yes"];
  if (args && args.length) { cli.push("--args", ...args); }
  try {
    const out = execFileSync("aptos", cli, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    const j = JSON.parse(out.slice(out.indexOf("{")));
    const r = j.Result ?? {};
    return { entry, ok: r.success === true, txHash: r.transaction_hash, gas: r.gas_used, vmStatus: r.vm_status };
  } catch (e) {
    const blob = `${e.stdout ?? ""}${e.stderr ?? ""}`;
    if (/E_ALREADY_INITIALIZED|ALREADY_INITIALIZED|0x80003|RESOURCE_ALREADY_EXISTS/.test(blob)) {
      return { entry, ok: true, skipped: "already_published" };
    }
    return { entry, ok: false, error: blob.split("\n").filter(Boolean).slice(-4).join(" | ").slice(0, 400) };
  }
};

const steps = [
  ["publish_deposit_binding_vk_v2_a6", vkArgs("extract_deposit_binding_vk.js")],
  ["publish_prepared_deposit_binding_vk_v2", null],
  ["publish_withdraw_proof_vk_v3_asp", vkArgs("extract_withdraw_vk.js")],
  ["publish_prepared_withdraw_proof_vk_v2", null],
  ["publish_ragequit_proof_vk", vkArgs("extract_ragequit_vk.js")],
  ["publish_prepared_ragequit_proof_vk", null],
];

const results = [];
for (const [entry, args] of steps) {
  process.stderr.write(`-> ${entry}${args ? ` (${args.length} args)` : ""} ... `);
  const r = run(entry, args);
  process.stderr.write(`${r.ok ? (r.skipped ? "SKIP(exists)" : `OK ${r.txHash?.slice(0, 14)} gas=${r.gas}`) : "FAIL"}\n`);
  results.push(r);
  if (!r.ok) { console.error(`  ${r.error}`); break; }
}

const outDir = join(STATE_ROOT, "coordinator");
mkdirSync(outDir, { recursive: true });
const statePath = join(outDir, "vk_provision_state.json");
const prev = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : {};
writeFileSync(statePath, JSON.stringify({ ...prev, bridge: BRIDGE, results }, null, 2) + "\n");
process.stdout.write(JSON.stringify({ allOk: results.every((r) => r.ok), statePath, results }, null, 2) + "\n");
process.exit(results.every((r) => r.ok) ? 0 : 1);
