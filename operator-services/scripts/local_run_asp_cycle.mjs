#!/usr/bin/env node
// ASP re-fork cycle runner (one epoch). Reads the persisted approved-set state + any new deposits,
// screens via Chainalysis (real, deposit-side), rebuilds the ASP LeanIMT, publishes the full set
// to IPFS, persists the new state, and emits {rootHex, cid, recordArgs} so the caller records the
// root on-chain via the asp-recorder delegate (record_asp_root_via_delegate). Off-chain → 0 gas.
//
// Usage:
//   node local_run_asp_cycle.mjs --state PATH [--new-deposits PATH] [--change-notes PATH]
//                                [--bridge 0x..] [--record] [--asp-set-out PATH | --state-dir DIR]
//   --record (optional) actually submits the on-chain record via `aptos move run` using the
//            EUNOMA_ASP_RECORDER_PROFILE aptos CLI profile (the low-priv delegate). Without it,
//            only prints recordArgs (CP3/dev mode).
//   --change-notes PATH (optional) V4 partial-withdraw CHANGE notes to merge by LABEL INHERITANCE.
//            Each entry: { commitment, label, parentCommitment? } and carries NO plaintext sender —
//            it is merged WITHOUT any screenAddress call (the parent's withdraw proof already proved
//            parent ∈ ASP; the change inherits that approval). Withdraw/change paths make ZERO KYT calls.
//   --asp-set-out PATH  explicit path for the public ASP-set artifact the coordinator serves.
//   --state-dir DIR     when set, the ASP-set artifact is written to
//                       <DIR>/coordinator/asp_set.json (the path GET /v2/asp-set + /v2/asp-root-current
//                       read). --asp-set-out wins if both are supplied.
import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runAspReforkEpoch, aspRecordCliArgs } from "./local_asp_refork.mjs";
import { runAptosCliWithRetry } from "./_lib/aptos_cli_retry.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const serviceRoot = dirname(scriptDir);
const aptosCliCwd = process.env.APTOS_CLI_CWD ? resolve(process.env.APTOS_CLI_CWD) : serviceRoot;

const args = process.argv.slice(2);
const getArg = (n, req = false) => { const i = args.indexOf(n); if (i < 0) { if (req) { console.error(`missing ${n}`); process.exit(2); } return undefined; } return args[i + 1]; };
const has = (n) => args.includes(n);

const statePath = getArg("--state", true);
const newDepositsPath = getArg("--new-deposits");
const changeNotesPath = getArg("--change-notes");
const bridge = getArg("--bridge");
const doRecord = has("--record");
const aspSetOut = getArg("--asp-set-out");
const stateDir = getArg("--state-dir");
const aptosNodeUrl = normalizeAptosNodeUrl(
  process.env.APTOS_NODE_URL || "https://fullnode.testnet.aptoslabs.com/v1",
);

const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : { approved: [] };
const newDeposits = newDepositsPath && existsSync(newDepositsPath) ? JSON.parse(readFileSync(newDepositsPath, "utf8")) : [];
// V4 change notes are merged by LABEL INHERITANCE inside runAspReforkEpoch (NO screenAddress call).
const changeNotes = changeNotesPath && existsSync(changeNotesPath) ? JSON.parse(readFileSync(changeNotesPath, "utf8")) : [];

const r = await runAspReforkEpoch({ state, newDeposits, changeNotes });

// persist the PUBLIC ASP-set artifact so the coordinator can serve it at /v2/asp-set +
// /v2/asp-root-current. r.artifact already carries { scheme, treeDepth, rootHex, commitments,
// ipfsCid } (commitments only — no secrets; LeanIMTTree's forbidden-field gate enforces this).
const aspSetPath = aspSetOut
  ? aspSetOut
  : stateDir
    ? join(stateDir, "coordinator", "asp_set.json")
    : null;

const recordArgs = bridge ? aspRecordCliArgs({ bridgeAddr: bridge, rootHex: r.rootHex, cid: r.cid }) : null;

let recordResult = null;
if (doRecord) {
  if (!bridge) { console.error("--record requires --bridge"); process.exit(2); }
  recordResult = await recordAspRootOrExit({ recordArgs, rootHex: r.rootHex, cid: r.cid });
  r.artifact.updatedAtUnix = Math.floor(Date.now() / 1000);
}

// In --record mode, only persist the newly-approved state + public ASP artifact after the on-chain
// ASP root record is confirmed. This prevents serving a root that Move will reject with
// E_INVALID_ASP_ROOT. In no-record/dev mode, keep the existing artifact-only behavior.
writeFileSync(statePath, JSON.stringify({ approved: r.approved }, null, 2) + "\n");

if (aspSetPath) {
  mkdirSync(dirname(aspSetPath), { recursive: true });
  const tmp = aspSetPath + ".tmp";
  writeFileSync(tmp, JSON.stringify(r.artifact, null, 2) + "\n", { mode: 0o644 });
  renameSync(tmp, aspSetPath);

  // CP5 RC6(A): also snapshot this epoch's set into the HISTORY dir keyed by root hex, so the
  // coordinator's GET /v2/asp-set/at/:rootHex can serve a recently-superseded root inside the
  // ASP_ROOT_TTL window (an in-flight withdraw, or a change note minted in epoch N that is owned
  // immediately but only re-listed/withdrawable next epoch, may still reference the prior root).
  // The artifact carries updatedAtUnix (the record time the TTL is measured against). Snapshots are
  // immutable per-root; the coordinator decides 200 vs 410 by age, so no pruning is required here.
  const rootHexBare = String(r.rootHex).replace(/^0x/i, "").toLowerCase();
  if (/^[0-9a-f]{64}$/.test(rootHexBare)) {
    const historyDir = join(dirname(aspSetPath), "asp_set_history");
    mkdirSync(historyDir, { recursive: true });
    const histPath = join(historyDir, `${rootHexBare}.json`);
    const histTmp = histPath + ".tmp";
    writeFileSync(histTmp, JSON.stringify(r.artifact, null, 2) + "\n", { mode: 0o644 });
    renameSync(histTmp, histPath);
  }
}

let recordSidecar = null;
if (recordResult) {
  recordSidecar = writeAspRecordSidecar({
    aspSetPath,
    statePath,
    rootHex: r.rootHex,
    cid: r.cid,
    approvedCount: r.approved.length,
    labelCount: Array.isArray(r.labels) ? r.labels.length : null,
    txHash: recordResult.txHash,
    version: recordResult.version,
    vmStatus: recordResult.vmStatus,
  });
}

process.stdout.write(JSON.stringify({
  ok: true,
  rootHex: r.rootHex,
  depth: r.depth,
  cid: r.cid,
  ipfsSource: r.ipfsSource,
  approvedCount: r.approved.length,
  // labelCount = the D6 LABEL-set pinned to IPFS (the approval/revocation unit). A still-approved
  // label is re-listed every epoch so honest users never age out; revocation omits the label.
  labelCount: Array.isArray(r.labels) ? r.labels.length : null,
  revokedCount: r.revoked.length,
  rejectedNewCount: r.rejectedNew.length,
  // change notes merged by inheritance (0 KYT calls); rejected = unknown/revoked/not-yet-approved parent label.
  changeNotesRejectedCount: Array.isArray(r.changeNotesRejected) ? r.changeNotesRejected.length : 0,
  aspSetFile: aspSetPath,
  recordArgs,
  recordTx: recordResult?.txHash ?? null,
  recordStatus: recordResult ? "recorded" : null,
  recordSidecar,
}, null, 2) + "\n");

// CLI: exit cleanly even if the KYT provider's HTTP keep-alive socket (undici global agent)
// would otherwise hold the event loop open.
process.exit(0);

function normalizeAptosNodeUrl(raw) {
  const base = String(raw || "").trim().replace(/\/+$/, "");
  if (!base) return "https://fullnode.testnet.aptoslabs.com/v1";
  return base.endsWith("/v1") ? base : `${base}/v1`;
}

async function fetchWithRetry(url, init, attempts = 3, backoffMs = 500) {
  let lastErr = null;
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetch(url, init);
      if (res.status >= 500 || res.status === 429) {
        lastErr = new Error(`HTTP ${res.status}`);
      } else {
        return res;
      }
    } catch (err) {
      lastErr = err;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, backoffMs * Math.pow(2, i)));
  }
  throw lastErr ?? new Error("fetch_failed");
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
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 1500));
        continue;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      if (body?.type === "pending_transaction") {
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 1500));
        continue;
      }
      return body;
    } catch (err) {
      console.error(`[asp-record-poll] retry: ${err?.message ?? err}`);
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 2500));
    }
  }
  throw new Error(`tx ${hash} did not confirm within ${timeoutMs}ms`);
}

function normalizeHex32(value) {
  if (typeof value !== "string") return null;
  const s = value.startsWith("0x") ? value.slice(2) : value;
  if (!/^[0-9a-fA-F]{64}$/.test(s)) return null;
  return `0x${s.toLowerCase()}`;
}

async function recordAspRootOrExit({ recordArgs, rootHex, cid }) {
  const profile = process.env.EUNOMA_ASP_RECORDER_PROFILE || "asp-recorder";
  const cliArgs = [
    ...recordArgs,
    "--profile",
    profile,
    "--url",
    aptosNodeUrl,
  ];
  console.error(`aptos ${cliArgs.join(" ")}`);
  const { run, stderrText, stdoutText, txHash } = await runAptosCliWithRetry(cliArgs, {
    cwd: aptosCliCwd,
    env: process.env,
    label: "asp-record",
  });
  if (run.error) {
    console.error(`failed to spawn aptos CLI: ${run.error.message}`);
    process.exit(31);
  }
  process.stderr.write(stderrText || "");
  if (run.status !== 0) {
    process.stdout.write(stdoutText || "");
    console.error(`aptos CLI exited with status ${run.status}`);
    process.exit(31);
  }
  if (!txHash) {
    process.stdout.write(stdoutText || "");
    console.error("could not parse transaction_hash from aptos CLI output");
    process.exit(31);
  }

  let txDetail;
  try {
    txDetail = await pollTx(txHash);
  } catch (err) {
    console.error(err?.message ?? err);
    process.exit(32);
  }
  const vmStatus = txDetail?.vm_status ?? null;
  if (txDetail?.success !== true || vmStatus !== "Executed successfully") {
    console.error(`ASP root record tx ${txHash} reverted: success=${txDetail?.success === true} vm_status=${vmStatus}`);
    process.exit(30);
  }

  const expectedRoot = normalizeHex32(rootHex);
  const events = Array.isArray(txDetail?.events) ? txDetail.events : [];
  const evt = events.find((e) => {
    const t = typeof e?.type === "string" ? e.type : "";
    return t.endsWith("::eunoma_bridge::ASPRootRecorded");
  });
  if (!evt) {
    console.error(
      `ASP root record tx ${txHash} confirmed but no ASPRootRecorded event found; events seen: ${events
        .map((e) => e?.type ?? "?")
        .join(", ")}`,
    );
    process.exit(33);
  }
  const eventRoot = normalizeHex32(evt?.data?.root);
  if (eventRoot !== expectedRoot) {
    console.error(`ASPRootRecorded root mismatch: expected ${rootHex} got ${evt?.data?.root}`);
    process.exit(33);
  }
  const eventCid = typeof evt?.data?.ipfs_cid === "string" ? evt.data.ipfs_cid : null;
  return {
    txHash,
    version: txDetail?.version ?? null,
    vmStatus,
    eventCid,
    cid,
  };
}

function writeAspRecordSidecar({ aspSetPath, statePath, rootHex, cid, approvedCount, labelCount, txHash, version, vmStatus }) {
  const rootBare = String(rootHex).replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(rootBare)) return null;
  const sidecarDir = aspSetPath ? dirname(aspSetPath) : dirname(statePath);
  mkdirSync(sidecarDir, { recursive: true });
  const full = join(sidecarDir, `asp_root_recorded_${rootBare.slice(0, 8)}.json`);
  const tmp = full + ".tmp";
  const sidecar = {
    scheme: "asp_root_record_sidecar_v1",
    rootHex: `0x${rootBare}`,
    cid,
    approvedCount,
    labelCount,
    txHash,
    version,
    vmStatus,
    status: "recorded",
    recordedAtUnixMs: Date.now(),
  };
  writeFileSync(tmp, JSON.stringify(sidecar, null, 2) + "\n", { mode: 0o644 });
  renameSync(tmp, full);
  return full;
}
