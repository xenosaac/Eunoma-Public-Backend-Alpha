#!/usr/bin/env node
// =============================================================================================
// R7-OPS-2 — submit a rollover of the bridge vault's CA pending balance to its available
// balance. Deposits flow into pending; only available is what the withdraw threshold-decrypt
// path subtracts from. Without this rollover, withdraw chunkSubtract underflows even though
// the user's note is valid and rooted in known_roots.
//
// Two signing paths:
//   --via-delegate --delegate-profile NAME  → operator_rollover_vault_pending_via_delegate(delegate)
//                                              (the alpha-box auto path; needs OPS-1 RecorderDelegate
//                                              addr previously set to delegate's address)
//   default                                 → operator_rollover_vault_pending_v2(admin)
//                                              (legacy admin path; needs --admin-profile)
//
// Inputs:
//   --bridge-package-address HEX     required
//   --admin-profile NAME             default: testnet-admin (used only without --via-delegate)
//   --delegate-profile NAME          required when --via-delegate
//   --via-delegate                   switch to delegate path
//   --aptos-node-url URL             default: https://fullnode.testnet.aptoslabs.com/v1
//   --max-gas N                      default: 80000 (CA rollover ~3-15k gas typically)
//   --gas-unit-price N               default: 100
//   --dry-run                        skip the tx submit
//
// Exit codes:
//   0   success (rollover submitted + chain-confirmed, or dry run)
//   2   usage / required-arg error
//   30  chain confirmation failed (tx reverted on chain)
//   31  aptos CLI spawn or non-zero exit
//   32  fullnode unreachable
// =============================================================================================
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
// Mirrors local_record_known_root_v2.mjs: aptos CLI requires .aptos/config.yaml
// in cwd. operator-services/.aptos/config.yaml holds the testnet-* profiles on
// alpha box, so spawn the CLI from there regardless of the wrapper's cwd.
const serviceRoot = resolve(scriptDir, "..");

const EXIT_SUCCESS = 0;
const EXIT_USAGE = 2;
const EXIT_CHAIN_REVERTED = 30;
const EXIT_APTOS_SPAWN = 31;
const EXIT_FULLNODE_UNREACHABLE = 32;

const args = process.argv.slice(2);
let bridgePackageAddress;
let adminProfile = "testnet-admin";
let delegateProfile;
let viaDelegate = false;
let aptosNodeUrl = "https://fullnode.testnet.aptoslabs.com/v1";
let maxGas = "80000";
let gasUnitPrice = "100";
let dryRun = false;

for (let i = 0; i < args.length; ++i) {
  const a = args[i];
  switch (a) {
    case "--bridge-package-address":
      bridgePackageAddress = args[++i];
      break;
    case "--admin-profile":
      adminProfile = args[++i];
      break;
    case "--delegate-profile":
      delegateProfile = args[++i];
      break;
    case "--via-delegate":
      viaDelegate = true;
      break;
    case "--aptos-node-url":
      aptosNodeUrl = args[++i];
      break;
    case "--max-gas":
      maxGas = args[++i];
      break;
    case "--gas-unit-price":
      gasUnitPrice = args[++i];
      break;
    case "--dry-run":
      dryRun = true;
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_rollover_vault_pending --bridge-package-address HEX \\\n" +
          "                                    [--via-delegate --delegate-profile NAME] \\\n" +
          "                                    [--admin-profile NAME=testnet-admin] \\\n" +
          "                                    [--aptos-node-url URL] [--max-gas N=80000] \\\n" +
          "                                    [--gas-unit-price N=100] [--dry-run]",
      );
      process.exit(EXIT_SUCCESS);
    default:
      console.error(`unknown arg: ${a}`);
      process.exit(EXIT_USAGE);
  }
}

function requireArg(name, value) {
  if (!value) {
    console.error(`${name} is required`);
    process.exit(EXIT_USAGE);
  }
}
requireArg("--bridge-package-address", bridgePackageAddress);

let functionId;
let signerProfile;
if (viaDelegate) {
  if (!delegateProfile) {
    console.error("--via-delegate requires --delegate-profile NAME");
    process.exit(EXIT_USAGE);
  }
  functionId = `${bridgePackageAddress}::eunoma_bridge::operator_rollover_vault_pending_via_delegate`;
  signerProfile = delegateProfile;
} else {
  functionId = `${bridgePackageAddress}::eunoma_bridge::operator_rollover_vault_pending_v2`;
  signerProfile = adminProfile;
}

if (dryRun) {
  console.log(
    JSON.stringify({ ok: true, status: "dry_run", functionId, signerProfile }, null, 2),
  );
  process.exit(EXIT_SUCCESS);
}

const cliArgs = [
  "move",
  "run",
  "--function-id",
  functionId,
  "--profile",
  signerProfile,
  "--assume-yes",
  "--url",
  aptosNodeUrl,
  "--max-gas",
  maxGas,
  "--gas-unit-price",
  gasUnitPrice,
];
console.error(`aptos ${cliArgs.join(" ")}`);
const run = spawnSync("aptos", cliArgs, {
  cwd: serviceRoot,
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
  env: process.env,
});
if (run.error) {
  console.error(`failed to spawn aptos CLI: ${run.error.message}`);
  process.exit(EXIT_APTOS_SPAWN);
}
process.stderr.write(run.stderr || "");

function extractTxHash(text) {
  const m =
    text.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/) ??
    text.match(/\/txn\/(0x[0-9a-fA-F]+)(?:\?|$)/);
  return m ? m[1] : null;
}
const combinedOutput = `${run.stdout || ""}\n${run.stderr || ""}`;
const txHash = extractTxHash(combinedOutput);
if (run.status !== 0) {
  if (/E_NOTHING_TO_ROLLOVER|There are no pending transfers to roll over/i.test(combinedOutput)) {
    console.log(
      JSON.stringify(
        {
          ok: true,
          status: "nothing_to_rollover",
          txHash,
          functionId,
        },
        null,
        2,
      ),
    );
    process.exit(EXIT_SUCCESS);
  }
  console.error(`aptos CLI exited with status ${run.status}`);
  process.stdout.write(run.stdout || "");
  process.exit(EXIT_APTOS_SPAWN);
}
if (!txHash) {
  console.error("could not parse transaction_hash from aptos CLI output");
  process.stdout.write(run.stdout || "");
  process.exit(EXIT_APTOS_SPAWN);
}
console.error(`submitted tx ${txHash}; polling for chain confirmation`);

async function fetchWithRetry(url, init, retries = 2) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, init);
      return res;
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
    }
  }
  throw lastErr;
}

async function pollTx(hash, timeoutMs = 90_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetchWithRetry(
        `${aptosNodeUrl}/transactions/by_hash/${hash}`,
        { method: "GET", headers: { accept: "application/json" } },
        2,
      );
      if (res.status === 404) {
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const body = await res.json();
      if (body?.type === "pending_transaction") {
        await new Promise((r) => setTimeout(r, 1500));
        continue;
      }
      return body;
    } catch (err) {
      console.error(`[poll] retry: ${err?.message ?? err}`);
      await new Promise((r) => setTimeout(r, 2500));
    }
  }
  return null;
}

const tx = await pollTx(txHash);
if (!tx) {
  console.error(`chain confirmation timed out for tx ${txHash}`);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}
if (tx.success !== true || (tx.vm_status && tx.vm_status !== "Executed successfully")) {
  console.error(
    `tx ${txHash} reverted on chain: success=${tx.success} vm_status=${tx.vm_status}`,
  );
  process.exit(EXIT_CHAIN_REVERTED);
}

console.log(
  JSON.stringify(
    {
      ok: true,
      status: "rolled_over",
      txHash,
      version: tx.version,
      gasUsed: tx.gas_used,
      vmStatus: tx.vm_status,
      functionId,
    },
    null,
    2,
  ),
);
process.exit(EXIT_SUCCESS);
