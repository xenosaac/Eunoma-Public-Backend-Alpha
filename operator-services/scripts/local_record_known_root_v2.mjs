#!/usr/bin/env node
// =============================================================================================
// V2/V4 admin CLI — submit `record_known_root_v2` or `record_known_root_v4` against Aptos testnet.
//
// Goal:
//   The on-chain bridge stores a Move Table<vector<u8>, bool> of "known" Merkle roots that the
//   withdraw flow verifies the deposit commitment's Merkle inclusion against. Before any
//   withdraw can succeed, the admin must record the root via this entry function. Idempotent on
//   chain (Move dedups on Table::contains); we additionally short-circuit if the root is already
//   recorded to save a tx fee.
//
// Inputs (M9: prefer --commitment-tree for testnet; --deposit-witness-path is local-fixture only):
//   --commitment-tree PATH           M9 PRIMARY — reads multi-leaf tree artifact (commitment_tree_v2.json)
//                                    and records the latestRootHex it contains. Enforces
//                                    leafCount >= --min-anonymity-set.
//   --deposit-witness-path PATH      LEGACY (single-leaf, M8) — only honored under EUNOMA_LOCAL_SMOKE=1
//                                    + --allow-local-smoke-anonymity. Computes a single-leaf root for
//                                    one depositor commitment with all-zero siblings. Rejected on
//                                    testnet paths.
//   --bridge-package-address HEX     required
//   --admin-profile NAME             default: testnet-admin
//   --aptos-node-url URL             default: https://fullnode.testnet.aptoslabs.com/v1
//   --depth N                        default: 20 (must match withdrawal_proof.circom TREE_DEPTH)
//   --min-anonymity-set N            M9 anonymity gate. Defaults to env EUNOMA_MIN_ANONYMITY_SET or 8.
//                                    With --commitment-tree, reject if leafCount < min.
//   --allow-local-smoke-anonymity    Bypass the anonymity gate / accept single-leaf fixture path,
//                                    only when env EUNOMA_LOCAL_SMOKE=1. Local-only.
//   --state-dir PATH                 default: operator-services/.agent-local/eunoma-v2/coordinator
//                                    side-car artifact written here on success.
//   --dry-run                        compute root + exit 0 without submitting
//   --root-override HEX              override computed root (negative tests only)
//   --v4                             use BridgeTablesV4 + record_known_root_v4 selectors
//
// Output: JSON to stdout
//   { ok, root, depositCommitment, txHash?, status: "recorded" | "already_recorded" | "dry_run",
//     vmStatus?, version?, eventVerified? }
//
// Exit codes:
//   0    success (recorded, already_recorded, or dry_run).
//   1    generic failure.
//   2    usage / required-arg error.
//   3    anonymity_set_too_small (M9 gate; leafCount < --min-anonymity-set without local smoke flag).
//   4    legacy_single_leaf_rejected_on_testnet (M9 gate; --deposit-witness-path without local smoke).
//  30    chain confirmation failed (tx reverted on chain).
//  31    aptos CLI spawn or non-zero exit.
//  32    fullnode unreachable / 5xx after retries.
//  33    chain returned tx without RootRecordedV2 event (mismatch).
// =============================================================================================
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runAptosCliWithRetry } from "./_lib/aptos_cli_retry.mjs";

const EXIT_SUCCESS = 0;
const EXIT_GENERIC_FAILURE = 1;
const EXIT_USAGE = 2;
const EXIT_ANONYMITY_SET_TOO_SMALL = 3;
const EXIT_LEGACY_SINGLE_LEAF_REJECTED = 4;
const EXIT_CHAIN_REVERTED = 30;
const EXIT_APTOS_SPAWN = 31;
const EXIT_FULLNODE_UNREACHABLE = 32;
const EXIT_EVENT_MISSING = 33;

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = resolve(scriptDir, "..");
const repoRoot = resolve(serviceRoot, "..");
const aptosCliCwd = process.env.APTOS_CLI_CWD ? resolve(process.env.APTOS_CLI_CWD) : serviceRoot;

const args = process.argv.slice(2);
let depositWitnessPath;
let commitmentTreePath;
let bridgePackageAddress;
let adminProfile = "testnet-admin";
let aptosNodeUrl = "https://fullnode.testnet.aptoslabs.com/v1";
let depthStr = "20";
let dryRun = false;
let rootOverride;
let minAnonymitySetStr =
  process.env.EUNOMA_MIN_ANONYMITY_SET ?? "8";
let allowLocalSmokeAnonymity = false;
let stateDir = join(serviceRoot, ".agent-local", "eunoma-v2", "coordinator");
let useV4 = process.env.EUNOMA_RECORD_KNOWN_ROOT_V4 === "1";
const submitOnPrecheckFailure =
  process.env.EUNOMA_RECORD_KNOWN_ROOT_SUBMIT_ON_PRECHECK_FAILURE === "1";
// R7-OPS-1: --via-delegate switches function-id to record_known_root_v2_via_delegate
// (signed by delegate, not admin). --delegate-profile selects the Aptos CLI profile.
// Both flags must be present together; otherwise script uses legacy admin path.
let viaDelegate = false;
let delegateProfile;

for (let i = 0; i < args.length; ++i) {
  const a = args[i];
  switch (a) {
    case "--commitment-tree":
      commitmentTreePath = args[++i];
      break;
    case "--deposit-witness-path":
      depositWitnessPath = args[++i];
      break;
    case "--bridge-package-address":
      bridgePackageAddress = args[++i];
      break;
    case "--admin-profile":
      adminProfile = args[++i];
      break;
    case "--via-delegate":
      viaDelegate = true;
      break;
    case "--delegate-profile":
      delegateProfile = args[++i];
      break;
    case "--aptos-node-url":
      aptosNodeUrl = args[++i];
      break;
    case "--depth":
      depthStr = args[++i];
      break;
    case "--min-anonymity-set":
      minAnonymitySetStr = args[++i];
      break;
    case "--allow-local-smoke-anonymity":
      allowLocalSmokeAnonymity = true;
      break;
    case "--state-dir":
      stateDir = args[++i];
      break;
    case "--v4":
      useV4 = true;
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
        "usage: local_record_known_root_v2 --commitment-tree PATH (M9 testnet) \\\n" +
          "                                | --deposit-witness-path PATH (legacy local fixture)\n" +
          "                                  --bridge-package-address HEX \\\n" +
          "                                  [--admin-profile NAME=testnet-admin] \\\n" +
          "                                  [--aptos-node-url URL] [--depth N=20] \\\n" +
          "                                  [--min-anonymity-set N=$EUNOMA_MIN_ANONYMITY_SET|8] \\\n" +
          "                                  [--allow-local-smoke-anonymity (needs EUNOMA_LOCAL_SMOKE=1)] \\\n" +
          "                                  [--state-dir PATH] \\\n" +
          "                                  [--dry-run] [--root-override HEX] [--v4]",
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

const minAnonymitySet = Number.parseInt(minAnonymitySetStr, 10);
if (!Number.isInteger(minAnonymitySet) || minAnonymitySet < 1) {
  console.error(`--min-anonymity-set must be positive integer, got ${minAnonymitySetStr}`);
  process.exit(EXIT_USAGE);
}
const localSmokeAllowed =
  allowLocalSmokeAnonymity && process.env.EUNOMA_LOCAL_SMOKE === "1";

if (!commitmentTreePath && !depositWitnessPath) {
  console.error(
    "supply --commitment-tree PATH (M9 testnet path) or --deposit-witness-path PATH (legacy local fixture)",
  );
  process.exit(EXIT_USAGE);
}
if (commitmentTreePath && depositWitnessPath) {
  console.error(
    "cannot pass both --commitment-tree and --deposit-witness-path; pick one",
  );
  process.exit(EXIT_USAGE);
}
const depth = Number.parseInt(depthStr, 10);
if (!Number.isInteger(depth) || depth < 1 || depth > 40) {
  console.error("--depth must be an integer in [1, 40]");
  process.exit(EXIT_USAGE);
}
if (!/^0x[0-9a-fA-F]{1,64}$/.test(bridgePackageAddress)) {
  console.error("--bridge-package-address must be 0x-prefixed hex");
  process.exit(EXIT_USAGE);
}

// Resolve circuits-side Merkle helpers.
const merkleHelperPath = resolve(repoRoot, "circuits/scripts/poseidon_merkle.mjs");
const treeHelperPath = resolve(repoRoot, "circuits/scripts/commitment_tree_v2.mjs");
const leanTreeHelperPath = resolve(repoRoot, "circuits/scripts/leanimt_tree.mjs");
if (!existsSync(merkleHelperPath)) {
  console.error(`circuits/scripts/poseidon_merkle.mjs not found at ${merkleHelperPath}`);
  process.exit(EXIT_GENERIC_FAILURE);
}
const { hexToLE32, leBytesToBig, le32ToHex, computeMerkleRootAndPathSingleLeaf } = await import(
  `file://${merkleHelperPath}`
);
let CommitmentTreeV2;
if (existsSync(treeHelperPath)) {
  ({ CommitmentTreeV2 } = await import(`file://${treeHelperPath}`));
}
let LeanIMTTree;
let LEANIMT_TREE_SCHEME;
if (existsSync(leanTreeHelperPath)) {
  ({ LeanIMTTree, LEANIMT_TREE_SCHEME } = await import(`file://${leanTreeHelperPath}`));
}

// Compute Merkle root. Branch: M9 multi-leaf (commitmentTreePath) vs. M8 legacy single-leaf.
let rootHex;
let depositCommitment = null;
let mode;
let leafCount = null;
let treeTranscriptHash = null;
let depositTxHashes = null;

if (rootOverride) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(rootOverride)) {
    console.error("--root-override must be 0x-prefixed 32-byte hex");
    process.exit(EXIT_USAGE);
  }
  rootHex = rootOverride;
  mode = "root_override";
  console.error(
    `[warn] using --root-override ${rootHex} — for negative tests only; chain will reject if unrelated to any recorded leaf`,
  );
} else if (commitmentTreePath) {
  // M9 PRIMARY — multi-leaf commitment tree path. Auto-detects the artifact scheme:
  //   - "eunoma_leanimt_tree_v1" → dynamic-depth LeanIMT state tree (NEW source of truth; the
  //      recorded on-chain state root is this snapshot's latestRootHex). treeDepth is dynamic, so
  //      the fixed `--depth` check is SKIPPED for LeanIMT artifacts.
  //   - "commitment_tree_v2"     → legacy fixed-depth-20 snapshot (depth check enforced).
  let snapshot;
  try {
    snapshot = JSON.parse(readFileSync(commitmentTreePath, "utf8"));
  } catch (err) {
    console.error(`failed to read --commitment-tree ${commitmentTreePath}: ${err?.message ?? err}`);
    process.exit(EXIT_USAGE);
  }
  const isLeanImt = LEANIMT_TREE_SCHEME && snapshot?.scheme === LEANIMT_TREE_SCHEME;
  let tree;
  if (isLeanImt) {
    if (!LeanIMTTree) {
      console.error(`leanimt_tree.mjs not found at ${leanTreeHelperPath}; required for LeanIMT artifact`);
      process.exit(EXIT_GENERIC_FAILURE);
    }
    try {
      tree = await LeanIMTTree.deserialize(snapshot);
    } catch (err) {
      console.error(`state_leanimt_tree deserialize failed: ${err?.message ?? err}`);
      process.exit(EXIT_USAGE);
    }
    mode = "leanimt_state_tree";
  } else {
    if (!CommitmentTreeV2) {
      console.error(`commitment_tree_v2.mjs not found at ${treeHelperPath}; required for --commitment-tree`);
      process.exit(EXIT_GENERIC_FAILURE);
    }
    try {
      tree = await CommitmentTreeV2.deserialize(snapshot);
    } catch (err) {
      console.error(`commitment_tree deserialize failed: ${err?.message ?? err}`);
      process.exit(EXIT_USAGE);
    }
    mode = "multi_leaf";
  }
  leafCount = tree.leaves.length;
  // Fixed-depth check only applies to the legacy fixed-20 snapshot; LeanIMT depth is dynamic.
  if (!isLeanImt && snapshot.treeDepth !== depth) {
    console.error(
      `tree depth mismatch: artifact treeDepth=${snapshot.treeDepth}, --depth=${depth}`,
    );
    process.exit(EXIT_USAGE);
  }
  if (leafCount < minAnonymitySet) {
    if (!localSmokeAllowed) {
      console.error(
        JSON.stringify({
          error: "anonymity_set_too_small",
          leafCount,
          minAnonymitySet,
          hint: "for local smoke set EUNOMA_LOCAL_SMOKE=1 and pass --allow-local-smoke-anonymity",
        }),
      );
      process.exit(EXIT_ANONYMITY_SET_TOO_SMALL);
    }
    console.error(
      `[local-smoke] leafCount=${leafCount} below minAnonymitySet=${minAnonymitySet}; allowed by EUNOMA_LOCAL_SMOKE=1`,
    );
  }
  rootHex = snapshot.latestRootHex;
  treeTranscriptHash = snapshot.transcriptHash;
  depositTxHashes = snapshot.depositMeta.map((m) => m.depositTxHash);
  // `mode` was set above per the detected scheme (leanimt_state_tree | multi_leaf).
  const reportedDepth = isLeanImt ? snapshot.treeDepth : depth;
  console.error(
    `${mode} root (depth=${reportedDepth}, leafCount=${leafCount}, transcriptHash=${treeTranscriptHash}): ${rootHex}`,
  );
} else {
  // LEGACY single-leaf path — only allowed under EUNOMA_LOCAL_SMOKE=1 + --allow-local-smoke-anonymity.
  if (!localSmokeAllowed) {
    console.error(
      JSON.stringify({
        error: "legacy_single_leaf_rejected_on_testnet",
        hint: "use --commitment-tree PATH; --deposit-witness-path is fixture-only and requires EUNOMA_LOCAL_SMOKE=1 + --allow-local-smoke-anonymity",
      }),
    );
    process.exit(EXIT_LEGACY_SINGLE_LEAF_REJECTED);
  }
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
  depositCommitment = commitmentHex;
  const leafLE = hexToLE32(commitmentHex);
  const leafBig = leBytesToBig(leafLE);
  const { rootLE32 } = await computeMerkleRootAndPathSingleLeaf(leafBig, depth);
  rootHex = le32ToHex(rootLE32);
  mode = "legacy_single_leaf";
  console.error(
    `[local-smoke] legacy single-leaf root (depth=${depth}, leaf=0, zero-siblings): ${rootHex}`,
  );
}

if (dryRun) {
  process.stdout.write(
    `${JSON.stringify(
      {
        ok: true,
        root: rootHex,
        mode,
        leafCount,
        treeTranscriptHash,
        depositCommitment,
        depth,
        minAnonymitySet,
        status: "dry_run",
      },
      null,
      2,
    )}\n`,
  );
  process.exit(EXIT_SUCCESS);
}

function parsePositiveIntEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseNonNegativeIntEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function isRetryableFullnodeStatus(status) {
  return status === 429 || status >= 500;
}

// Check whether the root is already on chain via the selected known_roots table.
async function fetchWithRetry(url, init, attempts = 3, backoffMs = 500) {
  let lastErr;
  for (let i = 0; i < attempts; ++i) {
    try {
      const res = await fetch(url, init);
      if (isRetryableFullnodeStatus(res.status)) {
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

const precheckRetryAttempts = parsePositiveIntEnv("EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_ATTEMPTS", 8);
const precheckRetryDelayMs = parseNonNegativeIntEnv("EUNOMA_KNOWN_ROOT_PRECHECK_RETRY_DELAY_MS", 1_500);

function failKnownRootPrecheck(message) {
  if (submitOnPrecheckFailure) {
    console.error(`[warn] ${message}; submitting anyway because EUNOMA_RECORD_KNOWN_ROOT_SUBMIT_ON_PRECHECK_FAILURE=1`);
    return;
  }
  console.error(`[defer] ${message}; not submitting duplicate-prone record_known_root tx`);
  process.exit(EXIT_FULLNODE_UNREACHABLE);
}

let knownRootsHandle = null;
try {
  const tablesStruct = useV4 ? "BridgeTablesV4" : "BridgeVaultTablesV2";
  const tablesUrl = `${aptosNodeUrl}/accounts/${bridgePackageAddress}/resource/${encodeURIComponent(
    `${bridgePackageAddress}::eunoma_bridge::${tablesStruct}`,
  )}`;
  const res = await fetchWithRetry(
    tablesUrl,
    { method: "GET", headers: { accept: "application/json" } },
    precheckRetryAttempts,
    precheckRetryDelayMs,
  );
  if (res.ok) {
    const body = await res.json();
    knownRootsHandle = body?.data?.known_roots?.handle ?? null;
  } else if (res.status !== 404) {
    failKnownRootPrecheck(`${tablesStruct} GET returned ${res.status}`);
  }
} catch (err) {
  failKnownRootPrecheck(`failed to read known roots table for membership pre-check: ${err?.message ?? err}`);
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
      precheckRetryAttempts,
      precheckRetryDelayMs,
    );
    if (res.ok) {
      // Table item returned — root is already recorded.
      const body = await res.json();
      console.error(`root already on chain (table item = ${JSON.stringify(body)})`);
      writeKnownRootSidecar({
        rootHex,
        leafCount,
        depositTxHashes,
        treeTranscriptHash,
        txHash: null,
        status: "already_recorded",
        mode,
      });
      process.stdout.write(
        `${JSON.stringify(
          {
            ok: true,
            root: rootHex,
            mode,
            leafCount,
            treeTranscriptHash,
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
      failKnownRootPrecheck(`known_roots table item GET returned ${res.status}`);
    }
  } catch (err) {
    failKnownRootPrecheck(`known_roots membership probe failed: ${err?.message ?? err}`);
  }
}

// R7-OPS-1: choose function-id + signer profile based on --via-delegate flag.
// Legacy admin path: record_known_root_v2(admin, root) signed by --admin-profile.
// Delegate path: record_known_root_v2_via_delegate(delegate, root) signed by
// --delegate-profile (admin must have previously called admin_set_recorder_delegate).
let functionId;
let signerProfile;
if (viaDelegate) {
  if (!delegateProfile) {
    console.error("--via-delegate requires --delegate-profile NAME");
    process.exit(EXIT_USAGE);
  }
  functionId = `${bridgePackageAddress}::eunoma_bridge::${useV4 ? "record_known_root_v4_via_delegate" : "record_known_root_v2_via_delegate"}`;
  signerProfile = delegateProfile;
} else {
  functionId = `${bridgePackageAddress}::eunoma_bridge::${useV4 ? "record_known_root_v4" : "record_known_root_v2"}`;
  signerProfile = adminProfile;
}
const cliArgs = [
  "move",
  "run",
  "--function-id",
  functionId,
  "--args",
  `hex:${rootHex}`,
  "--profile",
  signerProfile,
  "--assume-yes",
  "--url",
  aptosNodeUrl,
  "--max-gas",
  "50000",
  "--gas-unit-price",
  "100",
];
console.error(`aptos ${cliArgs.join(" ")}`);
const { run, stderrText, stdoutText, txHash } = await runAptosCliWithRetry(cliArgs, {
  cwd: aptosCliCwd,
  env: process.env,
  label: "record-known-root",
});
if (run.error) {
  console.error(`failed to spawn aptos CLI: ${run.error.message}`);
  process.exit(EXIT_APTOS_SPAWN);
}
process.stderr.write(stderrText || "");
if (run.status !== 0) {
  console.error(`aptos CLI exited with status ${run.status}`);
  process.stdout.write(stdoutText || "");
  process.exit(EXIT_APTOS_SPAWN);
}
if (!txHash) {
  console.error("could not parse transaction_hash from aptos CLI output");
  process.stdout.write(stdoutText || "");
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

writeKnownRootSidecar({
  rootHex,
  leafCount,
  depositTxHashes,
  treeTranscriptHash,
  txHash,
  status: "recorded",
  mode,
});

process.stdout.write(
  `${JSON.stringify(
    {
      ok: true,
      root: rootHex,
      mode,
      leafCount,
      treeTranscriptHash,
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

function writeKnownRootSidecar({ rootHex, leafCount, depositTxHashes, treeTranscriptHash, txHash, status, mode }) {
  try {
    mkdirSync(stateDir, { recursive: true });
  } catch {
    // best-effort; if mkdir fails, the write will surface the real error
  }
  const sidecar = {
    scheme: "known_root_v2_sidecar_v1",
    rootHex,
    leafCount,
    depositTxHashes,
    treeTranscriptHash,
    txHash,
    status,
    mode,
    recordedAtUnixMs: Date.now(),
  };
  const fname = `known_root_v2_${rootHex.replace(/^0x/, "").slice(0, 8)}.json`;
  const full = join(stateDir, fname);
  const tmp = full + ".tmp";
  try {
    writeFileSync(tmp, JSON.stringify(sidecar, null, 2) + "\n", { mode: 0o644 });
    renameSync(tmp, full);
    console.error(`wrote known-root side-car: ${full}`);
  } catch (e) {
    console.error(`[warn] failed to write known-root side-car at ${full}: ${e?.message ?? e}`);
  }
}
