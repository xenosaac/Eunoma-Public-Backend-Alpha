#!/usr/bin/env node
// =============================================================================================
// V2 admin CLI — submit `record_known_root_v2(admin, root)` against Aptos testnet.
//
// Goal:
//   The on-chain bridge stores a Move Table<vector<u8>, bool> of "known" Merkle roots that the
//   withdraw flow verifies the deposit commitment's Merkle inclusion against. Before any
//   withdraw can succeed, the admin must record the root via this entry function. Idempotent on
//   chain (Move dedups on Table::contains); we additionally short-circuit if the root is already
//   recorded to save a tx fee.
//
// Inputs:
//   --deposit-witness-path PATH      required — depositor witness JSON (carries commitmentHex)
//   --bridge-package-address HEX     required
//   --admin-profile NAME             default: testnet-admin
//   --aptos-node-url URL             default: https://fullnode.testnet.aptoslabs.com/v1
//   --depth N                        default: 20 (must match withdrawal_proof.circom TREE_DEPTH)
//   --dry-run                        compute root + exit 0 without submitting
//   --root-override HEX              override computed root (negative tests only)
//
// Output: JSON to stdout
//   { ok, root, depositCommitment, txHash?, status: "recorded" | "already_recorded" | "dry_run",
//     vmStatus?, version?, eventVerified? }
//
// Exit codes:
//   0    success (recorded, already_recorded, or dry_run).
//   1    generic failure.
//   2    usage / required-arg error.
//  30    chain confirmation failed (tx reverted on chain).
//  31    aptos CLI spawn or non-zero exit.
//  32    fullnode unreachable / 5xx after retries.
//  33    chain returned tx without RootRecordedV2 event (mismatch).
// =============================================================================================
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE = 2;
const EXIT_CHAIN_REVERTED = 30;
const EXIT_APTOS_SPAWN = 31;
const EXIT_FULLNODE_UNREACHABLE = 32;
const EXIT_EVENT_MISSING = 33;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");

const args = process.argv.slice(2);
let depositWitnessPath;
let bridgePackageAddress;
let adminProfile = "testnet-admin";
let aptosNodeUrl = "https://fullnode.testnet.aptoslabs.com/v1";
let depthStr = "20";
let dryRun = false;
let rootOverride;

for (let i = 0; i < args.length; ++i) {
  const a = args[i];
  switch (a) {
    case "--deposit-witness-path":
      depositWitnessPath = args[++i];
      break;
    case "--bridge-package-address":
      bridgePackageAddress = args[++i];
      break;
    case "--admin-profile":
      adminProfile = args[++i];
      break;
    case "--aptos-node-url":
      aptosNodeUrl = args[++i];
      break;
    case "--depth":
      depthStr = args[++i];
      break;
    case "--dry-run":
      dryRun = true;
      break;
    case "--root-override":
      rootOverride = args[++i];
      break;
    case "--help":
    case "-h":
      console.log(
        "usage: local_record_known_root_v2 --deposit-witness-path PATH \\\n" +
          "                                  --bridge-package-address HEX \\\n" +
          "                                  [--admin-profile NAME=testnet-admin] \\\n" +
          "                                  [--aptos-node-url URL] [--depth N=20] \\\n" +
          "                                  [--dry-run] [--root-override HEX]",
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
requireArg("--deposit-witness-path", depositWitnessPath);
requireArg("--bridge-package-address", bridgePackageAddress);
const depth = Number.parseInt(depthStr, 10);
if (!Number.isInteger(depth) || depth < 1 || depth > 40) {
  console.error("--depth must be an integer in [1, 40]");
  process.exit(EXIT_USAGE);
}
if (!/^0x[0-9a-fA-F]{1,64}$/.test(bridgePackageAddress)) {
  console.error("--bridge-package-address must be 0x-prefixed hex");
  process.exit(EXIT_USAGE);
}

// Load depositor witness.
let witness;
try {
  witness = JSON.parse(readFileSync(depositWitnessPath, "utf8"));
} catch (err) {
  console.error(`failed to read --deposit-witness-path ${depositWitnessPath}: ${err?.message ?? err}`);
  process.exit(EXIT_USAGE);
}
if (witness?.schema !== "v2_depositor_witness_v1") {
  console.error(
    `unexpected depositor witness schema: ${witness?.schema} (expected v2_depositor_witness_v1)`,
  );
  process.exit(EXIT_USAGE);
}
const commitmentHex = witness.commitmentHex;
if (!/^0x[0-9a-fA-F]{64}$/.test(commitmentHex)) {
  console.error(`commitmentHex malformed in depositor witness: ${commitmentHex}`);
  process.exit(EXIT_USAGE);
}

// Resolve circuits-side Merkle helper.
const merkleHelperPath = resolve(repoRoot, "circuits/scripts/poseidon_merkle.mjs");
if (!existsSync(merkleHelperPath)) {
  console.error(`circuits/scripts/poseidon_merkle.mjs not found at ${merkleHelperPath}`);
  process.exit(EXIT_GENERIC_FAILURE);
}
const { hexToLE32, leBytesToBig, le32ToHex, computeMerkleRootAndPathSingleLeaf } = await import(
  `file://${merkleHelperPath}`
);

// Compute Merkle root.
let rootHex;
let depositCommitment = commitmentHex;
if (rootOverride) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(rootOverride)) {
    console.error("--root-override must be 0x-prefixed 32-byte hex");
    process.exit(EXIT_USAGE);
  }
  rootHex = rootOverride;
  console.error(
    `[warn] using --root-override ${rootHex} — for negative tests only; chain will reject if unrelated to the deposit commitment ${depositCommitment}`,
  );
} else {
  const leafLE = hexToLE32(commitmentHex);
  const leafBig = leBytesToBig(leafLE);
  const { rootLE32 } = await computeMerkleRootAndPathSingleLeaf(leafBig, depth);
  rootHex = le32ToHex(rootLE32);
}
console.error(`computed Merkle root (depth=${depth}, leaf=0, zero-siblings): ${rootHex}`);

if (dryRun) {
  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        root: rootHex,
        depositCommitment,
        depth,
        status: "dry_run",
      },
      null,
      2,
    )}\n`,
  );
  process.exit(EXIT_SUCCESS);
}

// Check whether the root is already on chain via the BridgeVault.known_roots table.
async function fetchWithRetry(url, init, attempts = 3, backoffMs = 500) {
  let lastErr;
  for (let i = 0; i < attempts; ++i) {
    try {
      const res = await fetch(url, init);
      if (res.status >= 500) {
        lastErr = new Error(`HTTP ${res.status}`);
      } else {
        return res;
      }
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, backoffMs * Math.pow(2, i)));
  }
  throw lastErr ?? new Error("fetch_failed");
}

let knownRootsHandle = null;
try {
  const vaultUrl = `${aptosNodeUrl}/accounts/${bridgePackageAddress}/resource/${encodeURIComponent(
    `${bridgePackageAddress}::eunoma_bridge::BridgeVault`,
  )}`;
  const res = await fetchWithRetry(vaultUrl, { method: "GET", headers: { accept: "application/json" } });
  if (res.ok) {
    const body = await res.json();
    knownRootsHandle = body?.data?.known_roots?.handle ?? null;
  } else if (res.status !== 404) {
    console.error(`[warn] BridgeVault GET returned ${res.status}; continuing without membership pre-check`);
  }
} catch (err) {
  console.error(`[warn] failed to read BridgeVault for membership pre-check: ${err?.message ?? err}`);
}

if (knownRootsHandle) {
  try {
    const tableUrl = `${aptosNodeUrl}/tables/${knownRootsHandle}/item`;
    const res = await fetchWithRetry(
      tableUrl,
      {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ key_type: "vector<u8>", value_type: "bool", key: rootHex }),
      },
      2,
    );
    if (res.ok) {
      // Table item returned — root is already recorded.
      const body = await res.json();
      console.error(`root already on chain (table item = ${JSON.stringify(body)})`);
      process.stdout.write(
        `${JSON.stringify(
          {
            ok: true,
            root: rootHex,
            depositCommitment,
            depth,
            status: "already_recorded",
            tableHandle: knownRootsHandle,
          },
          null,
          2,
        )}\n`,
      );
      process.exit(EXIT_SUCCESS);
    } else if (res.status === 404) {
      // Not in table — we need to submit. Fall through.
    } else {
      console.error(`[warn] known_roots table item GET returned ${res.status}; submitting anyway`);
    }
  } catch (err) {
    console.error(`[warn] known_roots membership probe failed: ${err?.message ?? err}; submitting anyway`);
  }
}

// Submit `record_known_root_v2(admin, root)` via aptos CLI.
const cliArgs = [
  "move",
  "run",
  "--function-id",
  `${bridgePackageAddress}::eunoma_bridge::record_known_root_v2`,
  "--args",
  `hex:${rootHex}`,
  "--profile",
  adminProfile,
  "--assume-yes",
  "--url",
  aptosNodeUrl,
  "--max-gas",
  "50000",
  "--gas-unit-price",
  "100",
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
if (run.status !== 0) {
  console.error(`aptos CLI exited with status ${run.status}`);
  process.stdout.write(run.stdout || "");
  process.exit(EXIT_APTOS_SPAWN);
}

function extractTxHash(text) {
  const m = text.match(/"transaction_hash"\s*:\s*"(0x[0-9a-fA-F]+)"/);
  return m ? m[1] : null;
}
const txHash = extractTxHash(run.stdout || "");
if (!txHash) {
  console.error("could not parse transaction_hash from aptos CLI output");
  process.stdout.write(run.stdout || "");
  process.exit(EXIT_APTOS_SPAWN);
}
console.error(`submitted tx ${txHash}; polling for chain confirmation`);

// Poll for chain confirmation.
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
  throw new Error(`tx ${hash} did not confirm within ${timeoutMs}ms`);
}

let txDetail;
try {
  txDetail = await pollTx(txHash);
} catch (err) {
  console.error(err?.message ?? err);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}
const vmStatus = txDetail?.vm_status ?? null;
const success = txDetail?.success === true;
if (!success || vmStatus !== "Executed successfully") {
  console.error(`tx ${txHash} reverted: success=${success} vm_status=${vmStatus}`);
  process.stdout.write(
    `${JSON.stringify(
      {
        ok: false,
        root: rootHex,
        depositCommitment,
        txHash,
        vmStatus,
        status: "reverted",
      },
      null,
      2,
    )}\n`,
  );
  process.exit(EXIT_CHAIN_REVERTED);
}

// Verify RootRecordedV2 event.
const events = Array.isArray(txDetail?.events) ? txDetail.events : [];
const expectedType = `${bridgePackageAddress}::eunoma_bridge::RootRecordedV2`;
const evt = events.find((e) => {
  const t = typeof e?.type === "string" ? e.type : "";
  // Aptos may render addresses with leading zeros normalized; do a loose compare.
  return t === expectedType || t.endsWith("::eunoma_bridge::RootRecordedV2");
});
if (!evt) {
  console.error(
    `tx ${txHash} confirmed but no RootRecordedV2 event found; events seen: ${events
      .map((e) => e?.type ?? "?")
      .join(", ")}`,
  );
  process.exit(EXIT_EVENT_MISSING);
}
const eventRoot = evt?.data?.root ?? null;
const eventRootNormalized =
  typeof eventRoot === "string" ? (eventRoot.startsWith("0x") ? eventRoot : `0x${eventRoot}`) : null;
const rootHexNormalized = rootHex.toLowerCase();
if (eventRootNormalized?.toLowerCase() !== rootHexNormalized) {
  console.error(
    `RootRecordedV2 event root mismatch: expected ${rootHex} got ${eventRoot}`,
  );
  process.exit(EXIT_EVENT_MISSING);
}

process.stdout.write(
  `${JSON.stringify(
    {
      ok: true,
      root: rootHex,
      depositCommitment,
      depth,
      txHash,
      version: txDetail?.version ?? null,
      vmStatus,
      status: "recorded",
      eventVerified: true,
    },
    null,
    2,
  )}\n`,
);
process.exit(EXIT_SUCCESS);
